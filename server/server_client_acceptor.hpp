/*
 * server_acceptor.hpp
 * 
 * Connection acceptor for chat server.
 * Handles new client connections, username validation, and password authentication.
 */

#ifndef SERVER_ACCEPTOR_HPP
#define SERVER_ACCEPTOR_HPP

#include <iostream>
#include <string>
#include <string.h>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../common/common.hpp"
#include "server_utils.hpp"
#include "server_client_handler.hpp"

// External references to global state (defined in server.cpp)
extern std::string SERVER_NAME;
extern std::unordered_map<std::string, int> client_sockets;
extern std::unordered_map<std::string, std::chrono::steady_clock::time_point> client_last_activity;
extern std::mutex clients_mutex;
extern std::mutex admin_mutex;
extern std::atomic<bool> server_running;
extern std::atomic<int> active_client_threads;

/**
 * @brief Main connection acceptor thread.
 *
 * Listens for incoming connections on the server socket, performs the
 * initial credential exchange (expects an [ENTR] message with username
 * and optional [PASS] password), enforces whitelist/admin rules, and
 * spawns a `handle_client` thread for each accepted client.
 *
 * The acceptor uses select() with a short timeout so it can poll the
 * `server_running` flag and exit promptly during shutdown.
 *
 * @param server_fd Server's listening socket file descriptor
 *
 * @note This function is typically run in a detached or joinable thread
 *       started from `main()`. It performs I/O on `server_fd` and opens
 *       new client sockets which are then managed by client handler threads.
 */
inline void accept_clients(int server_fd) {
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    while(server_running) {
        // Use select() with timeout to check server_running periodically
        fd_set readfds;
        struct timeval timeout;
        
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0 && server_running) {
            perror("select");
            break;
        }
        
        if (activity == 0 || !server_running) {
            continue;  // Timeout or shutting down
        }
        
        // Accept new connection
        int new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        
        if (new_socket < 0) {
            if(server_running) perror("accept");
            continue;
        }
        
        if(!server_running) {
            close(new_socket);
            break;
        }
        
        // Set receive timeout for initial connection message (10 seconds)
        struct timeval recv_timeout;
        recv_timeout.tv_sec = 10;
        recv_timeout.tv_usec = 0;
        if (setsockopt(new_socket, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout)) < 0) {
            logMessage(getTimestamp() + "WARNING: Could not set receive timeout");
        }
        
        // Receive username and password from client (first message must be [ENTR]username[PASS]password)
        char username_buffer[256] = {0};
        int bytes_read = read(new_socket, username_buffer, sizeof(username_buffer));
        
        // Reset socket timeout to default (blocking)
        recv_timeout.tv_sec = 0;
        recv_timeout.tv_usec = 0;
        setsockopt(new_socket, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
        
        // Validate that we received a message
        if(bytes_read <= 0) {
            logMessage(getTimestamp() + "CONNECTION REJECTED: No credentials received (timeout or disconnect)");
            std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                "Connection denied: No credentials received (timeout).\nPlease try again.");
            send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            close(new_socket);
            continue;
        }
        
        std::string username = "";
        std::string provided_password = "";
        
        std::string message(username_buffer);
        
        // Validate message format: must start with [ENTR]username
        MessageHeader msg_header = extractHeader(username_buffer, bytes_read);
        if(msg_header != MessageHeader::ENTER) {
            logMessage(getTimestamp() + "CONNECTION REJECTED: Invalid connection message format");
            std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                "Connection denied: Invalid connection format.\nExpected credentials. Please try again.");
            send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            close(new_socket);
            continue;
        }
        
        // Extract username from: [ENTR]username
        username = message.substr(HEADER_LENGTH);
        
        // Validate username is not empty
        if(username.empty()) {
            logMessage(getTimestamp() + "CONNECTION REJECTED: Empty username");
            std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                "Connection denied: Username cannot be empty.\nPlease try again with a valid username.");
            send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            close(new_socket);
            continue;
        }
        
        // Validate username is not already taken
        bool username_taken = false;
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            username_taken = (client_sockets.find(username) != client_sockets.end());
        }
        
        if(username_taken) {
            // Reject connection - username already in use
            logMessage(getTimestamp() + "CONNECTION REJECTED: Username '" + username + "' is already taken");
            std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                "Connection denied: Username '" + username + "' is already taken.\nPlease try again with a different username.");
            send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            close(new_socket);
            continue;
        }
        
        // Determine if password is required and validate
        bool password_valid = false;
        bool is_admin = false;
        bool needs_password = false;
        
        if(AdminConfig::isAdmin(username)) {
            // Admin user - needs password
            needs_password = true;
            is_admin = true;
        } else if(WhitelistConfig::isEnabled()) {
            // Whitelist mode - check if user is whitelisted
            if(!WhitelistConfig::isWhitelisted(username)) {
                logMessage(getTimestamp() + "CONNECTION REJECTED: User '" + username + "' is not whitelisted");
                std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                    "Connection denied: User '" + username + "' is not whitelisted.\nAccess denied.");
                send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                close(new_socket);
                continue;
            }
            needs_password = true;
        } else {
            // Open mode - no password needed
            password_valid = true;
        }
        
        // If password is needed, send challenge and wait for response (up to 3 attempts)
        if(needs_password) {
            const int MAX_ATTEMPTS = 3;
            
            for(int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                std::string prompt = "Enter password: ";
                if(attempt > 1) {
                    // Do not reveal remaining or total attempts to the client.
                    // Keep the prompt generic to avoid leaking attempt counts.
                    prompt = "password: ";
                }
                
                std::string challenge_msg = buildMessage(MessageHeader::PASSWORD_CHALLENGE, prompt);
                send(new_socket, challenge_msg.c_str(), challenge_msg.length(), 0);
                
                // Wait for password response
                char password_buffer[1024] = {0};
                int pwd_bytes = recv(new_socket, password_buffer, sizeof(password_buffer), 0);
                
                if(pwd_bytes <= 0) {
                    logMessage(getTimestamp() + "CONNECTION REJECTED: No password received from '" + username + "'");
                    std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                        "Connection denied: Connection timeout. No password received.\nPlease try again.");
                    send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    close(new_socket);
                    break;
                }
                
                std::string password_message(password_buffer);
                MessageHeader pwd_header = extractHeader(password_buffer, pwd_bytes);
                if(pwd_header != MessageHeader::PASSWORD_RESPONSE) {
                    logMessage(getTimestamp() + "CONNECTION REJECTED: Invalid password response from '" + username + "'");
                    std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                        "Connection denied: Invalid password response.\nConnection denied.");
                    send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    close(new_socket);
                    break;
                }
                
                provided_password = password_message.substr(HEADER_LENGTH);
                
                // Validate password
                if(is_admin) {
                    std::string expected_password = AdminConfig::getPassword(username);
                    password_valid = (provided_password == expected_password);
                    
                    if(password_valid) {
                        logMessage(getTimestamp() + "AUTH SUCCESS: Admin '" + username + "' authenticated successfully");
                        break;
                    } else if(attempt == MAX_ATTEMPTS) {
                        logMessage(getTimestamp() + "AUTH FAILED: Admin '" + username + 
                                  "' failed authentication after " + std::to_string(MAX_ATTEMPTS) + " attempts");
                        std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                            "Invalid password for admin account. Maximum attempts exceeded. Connection denied.");
                        send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        close(new_socket);
                    }
                } else if(WhitelistConfig::isEnabled()) {
                    std::string expected_password = WhitelistConfig::getPassword(username);
                    password_valid = (provided_password == expected_password);
                    
                    if(password_valid) {
                        logMessage(getTimestamp() + "AUTH SUCCESS: Whitelisted user '" + username + "' authenticated successfully");
                        break;
                    } else if(attempt == MAX_ATTEMPTS) {
                        logMessage(getTimestamp() + "AUTH FAILED: Whitelisted user '" + username + 
                                  "' failed authentication after " + std::to_string(MAX_ATTEMPTS) + " attempts");
                        std::string denial_msg = buildMessage(MessageHeader::REJECT, 
                            "Invalid password for whitelisted user. Maximum attempts exceeded. Connection denied.");
                        send(new_socket, denial_msg.c_str(), denial_msg.length(), 0);
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        close(new_socket);
                    }
                }
            }
            
            // If password still not valid after loop, skip to next connection
            if(!password_valid) {
                continue;
            }
        }
        
        // At this point, authentication is successful
        
        // Accept connection - username is available and password is valid
        std::string welcome_msg = "Connection successful. Welcome to the chat!";
        if(is_admin) {
            welcome_msg += "\n[You are logged in as an admin]";
        }
        welcome_msg += "\nType /help to see available commands.";
        std::string confirm_msg = buildMessage(MessageHeader::ACCEPT, welcome_msg);
        send(new_socket, confirm_msg.c_str(), confirm_msg.length(), 0);
        
        logMessage(getTimestamp() + "CONNECTION: '" + username + "' connected" + 
                  (is_admin ? " (admin)" : " (client)") + ". Total connected: " + 
                  std::to_string(client_sockets.size() + 1));
        
        // Add client to tracking map
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            client_sockets[username] = new_socket;
            client_last_activity[username] = std::chrono::steady_clock::now();
        }
        
        // Notify all existing users that a new user has joined
        std::string join_notification = buildMessage(MessageHeader::ENTER, username);
        broadcast(join_notification.c_str(), username);
        
        // Increment active thread counter
        active_client_threads++;
        
        // Spawn dedicated thread for this client
        std::thread client_thread(handle_client, new_socket, username);
        client_thread.detach();
    }
}

#endif // SERVER_ACCEPTOR_HPP
