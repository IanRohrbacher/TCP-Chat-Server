/*
 * server_client_handler.hpp
 * 
 * Main client connection handler - coordinates message receiving and processing.
 * Manages the client's lifecycle from connection to disconnection.
 */

#ifndef SERVER_CLIENT_HANDLER_HPP
#define SERVER_CLIENT_HANDLER_HPP

#include <iostream>
#include <string>
#include <string.h>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/common.hpp"
#include "server_utils.hpp"
#include "server_message_handlers.hpp"

// External references to global state (defined in server.cpp)
extern std::string SERVER_NAME;
extern std::unordered_map<std::string, int> client_sockets;
extern std::unordered_map<std::string, std::chrono::steady_clock::time_point> client_last_activity;
extern std::mutex clients_mutex;
extern std::unordered_set<std::string> session_admins;
extern std::mutex admin_mutex;
extern std::atomic<bool> server_running;
extern std::atomic<int> server_timeout_minutes;
extern std::atomic<int> active_client_threads;

/**
 * @brief Main client connection handler thread.
 *
 * This function runs in a dedicated thread for each connected client.
 * It performs the receive loop: reading protocol messages, dispatching
 * them to the appropriate server-side handlers, enforcing per-client
 * timeouts, and performing orderly cleanup when the client disconnects
 * or the server instructs termination.
 *
 * Behavior and guarantees:
 * - The function returns when the client disconnects or when the server
 *   is shutting down. It decrements the global `active_client_threads`
 *   counter before exiting.
 * - It updates `client_last_activity` for the user on incoming activity.
 * - It is responsible for removing the user from `client_sockets` if
 *   the disconnection is local and broadcasting a LEAVE notification
 *   when appropriate.
 *
 * @param client_socket Socket file descriptor for this client (owned by this thread)
 * @param username The authenticated username for this client
 *
 * @note The function assumes `buffer` contents are null-terminated when
 *       used with string helpers; handlers rely on correct protocol
 *       formatting. This is a long-running blocking loop and must be
 *       run in its own thread.
 */
inline void handle_client(int client_socket, std::string username) {
    const int BUFFER_SIZE = 1024;
    char buffer[BUFFER_SIZE];
    
    while(server_running) {
        // Check for client inactivity timeout
        int timeout_value = server_timeout_minutes.load();
        if(timeout_value > 0) {
            auto now = std::chrono::steady_clock::now();
            auto last_activity = std::chrono::steady_clock::time_point::min();
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                auto it = client_last_activity.find(username);
                if(it != client_last_activity.end()) {
                    last_activity = it->second;
                }
            }
            
            auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - last_activity).count();
            if(elapsed >= timeout_value) {
                logMessage(getTimestamp() + "TIMEOUT: '" + username + "' timed out after " + 
                         std::to_string(elapsed) + " minutes of inactivity (limit: " + 
                         std::to_string(timeout_value) + " minutes)");
                
                // Send timeout notification
                std::string timeout_msg = buildMessage(MessageHeader::KICK, SERVER_NAME);
                send(client_socket, timeout_msg.c_str(), timeout_msg.length(), 0);
                break;  // Exit handler
            }
        }
        
        // Wait for data with short timeout
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  // 100ms
        
        int activity = select(client_socket + 1, &readfds, NULL, NULL, &tv);
        
        if(activity < 0) {
            logMessage(getTimestamp() + "ERROR: Select error for client '" + username + "'");
            break;
        }
        
        if(activity == 0) {
            continue;  // Timeout - no data available
        }
        
        // Data is available - receive message
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        
        if(bytes_received <= 0) {
            if(bytes_received == 0) {
                logMessage(getTimestamp() + "DISCONNECT: '" + username + "' disconnected (connection closed by client)");
            } else {
                logMessage(getTimestamp() + "ERROR: Receive error from client '" + username + "'");
            }
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        // Update client activity timestamp
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            client_last_activity[username] = std::chrono::steady_clock::now();
        }
        
        // Check for [SUDO] wrapper - unwrap if present
        bool is_sudo_command = false;
        if(bytes_received >= HEADER_LENGTH) {
            std::string sudo_header = std::string(buffer, HEADER_LENGTH);
            if(sudo_header == headerToString(MessageHeader::SUDO)) {
                is_sudo_command = true;
                
                // Unwrap: shift buffer left to remove [SUDO] header
                size_t remaining = bytes_received - HEADER_LENGTH;
                memmove(buffer, buffer + HEADER_LENGTH, remaining);
                buffer[remaining] = '\0';
                bytes_received = remaining;
            }
        }
        
        // Extract message header
        if(bytes_received < HEADER_LENGTH) {
            continue;  // Invalid message
        }
        
        MessageHeader header = stringToHeader(std::string(buffer, HEADER_LENGTH));
        
        // Process message based on type
        bool should_continue = true;
        
        switch(header) {
            case MessageHeader::SUDO_SU:
                should_continue = handleSudoSu(client_socket, buffer, BUFFER_SIZE, username);
                break;
                
            case MessageHeader::SUDO_HELP:
                should_continue = handleSudoHelp(client_socket, buffer, BUFFER_SIZE, username);
                break;
                
            case MessageHeader::TIMEOUT:
                should_continue = handleTimeout(client_socket, buffer, username, is_sudo_command);
                break;
                
            case MessageHeader::SERVERTIMEOUT:
                should_continue = handleServerTimeout(client_socket, buffer, username, is_sudo_command);
                break;
                
            case MessageHeader::WHITELIST:
                should_continue = handleWhitelist(client_socket, buffer, username, is_sudo_command);
                break;
                
            case MessageHeader::ADMIN:
                should_continue = handleAdmin(client_socket, buffer, username, is_sudo_command);
                break;
                
            case MessageHeader::SHUTDOWN:
                should_continue = handleShutdown(client_socket, buffer, username, is_sudo_command);
                break;
                
            case MessageHeader::HELP_REQUEST:
                should_continue = handleHelpRequest(client_socket, username);
                break;
                
            case MessageHeader::LIST_REQUEST:
                should_continue = handleListRequest(client_socket, username);
                break;
                
            case MessageHeader::CLOSE_REQUEST:
                should_continue = handleCloseRequest(client_socket, buffer, username, is_sudo_command);
                break;
                
            case MessageHeader::CLOSEALL_REQUEST:
                should_continue = handleCloseAllRequest(client_socket, buffer, username, is_sudo_command);
                break;
                
            case MessageHeader::MSG:
                should_continue = handleMsg(client_socket, buffer);
                break;
                
            case MessageHeader::LEAVE: {
                // Client requested to leave
                logMessage(getTimestamp() + "DISCONNECT: '" + username + "' requested to leave");

                // Send acknowledgement
                std::string ack = buildMessage(MessageHeader::RESPONSE, "Goodbye!");
                send(client_socket, ack.c_str(), ack.length(), 0);

                should_continue = false;
                break;
            }
                
            case MessageHeader::USER:
                should_continue = handleUserMessage(client_socket, buffer, username);
                break;
                
            default:
                logMessage(getTimestamp() + "ERROR: Unknown message type from client '" + username + "'");
                break;
        }
        
        if(!should_continue) {
            break;  // Exit handler
        }
    }
    
    // Cleanup: Remove from tracking maps
    bool should_broadcast_leave = false;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        // Only broadcast if user is still in the map (wasn't already removed by /close)
        if(client_sockets.find(username) != client_sockets.end()) {
            should_broadcast_leave = true;
            client_sockets.erase(username);
            client_last_activity.erase(username);
        }
    }
    
    // Remove from session admins if present
    {
        std::lock_guard<std::mutex> admin_lock(admin_mutex);
        session_admins.erase(username);
    }
    
    // Only broadcast leave notification if user wasn't already removed
    if(should_broadcast_leave) {
        std::string leave_notification = buildMessage(MessageHeader::LEAVE, username);
        broadcast(leave_notification.c_str(), username);
    }
    
    close(client_socket);
    active_client_threads--;
    
    logMessage(getTimestamp() + "HANDLER: Handler for '" + username + "' ended. Active threads: " + 
             std::to_string(active_client_threads.load()));
}

#endif // SERVER_CLIENT_HANDLER_HPP
