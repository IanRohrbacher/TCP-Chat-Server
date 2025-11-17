/*
 * client_message_handler.hpp
 * 
 * Message handling for chat client.
 * Processes incoming messages from server and displays appropriate responses.
 */

#ifndef CLIENT_MESSAGE_HANDLER_HPP
#define CLIENT_MESSAGE_HANDLER_HPP

#include <iostream>
#include <string>
#include <string.h>
#include <mutex>
#include <atomic>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/common.hpp"

// External references to global state (defined in client.cpp)
extern std::atomic<bool> running;
extern std::atomic<bool> password_prompt_active;
extern std::mutex stdin_mutex;

/**
 * @brief Process and display a received message from the server.
 *
 * Parses the protocol header and dispatches handling for each message
 * type (password challenge, kick/shutdown notifications, list
 * responses, chat messages, etc.). This function may perform
 * interactive prompts (for password entry) and will close the socket on
 * terminal events.
 *
 * @param buffer Pointer to the raw null-terminated protocol message received from the server
 * @param socket_fd The socket descriptor connected to the server (used for close/send)
 *
 * @note The buffer is expected to be NUL-terminated; handlers extract
 *       substrings using HEADER_LENGTH offsets. When a PASSWORD_CHALLENGE
 *       is received, this function reads password input from stdin while
 *       setting `password_prompt_active` to block the send thread.
 */
void handleMessage(const char* buffer, int socket_fd) {
    MessageHeader header = extractHeader(buffer, strlen(buffer));
    
    switch(header) {
        case MessageHeader::PASSWORD_CHALLENGE: {
            // Server is requesting a password
            password_prompt_active = true;  // Block pushMessages from reading
            
            std::string prompt(buffer + HEADER_LENGTH);
            std::cout << prompt;  // Server sends prompt like "Enter password: "
            
            std::string password;
            {
                std::lock_guard<std::mutex> lock(stdin_mutex);
                std::getline(std::cin, password);
            }
            
            // Send password response back to server
            std::string msg = buildMessage(MessageHeader::PASSWORD_RESPONSE, password);
            send(socket_fd, msg.c_str(), msg.length(), 0);
            
            password_prompt_active = false;  // Resume normal input
            break;
        }
        
        case MessageHeader::KICK: {
            // Server is force-disconnecting this client
            std::string closing_user = extractUsername(buffer, HEADER_LENGTH);
            std::cout << closing_user + " has closed your session.\n";
            running = false;
            close(socket_fd);
            break;
        }
        
        case MessageHeader::SHUTDOWN: {
            // Server is shutting down
            std::cout << "Server is shutting down.\n";
            running = false;
            close(socket_fd);
            break;
        }
        
        case MessageHeader::LEAVE: {
            // Someone disconnected (could be by server or client kick or another user leaving)
            std::string leaving_user = extractUsername(buffer, HEADER_LENGTH);
            std::cout << leaving_user << " has left the chat.\n";
            // Note: If it's this client being kicked, the connection will close in the receive loop
            break;
        }
        
        case MessageHeader::ENTER: {
            // New user joined the chat
            std::string entering_user = extractUsername(buffer, HEADER_LENGTH);
            std::cout << entering_user << " has joined the chat.\n";
            break;
        }
        
        case MessageHeader::RESPONSE: {
            // Response message (e.g., from /msg or /close commands)
            password_prompt_active = false;  // Clear flag if we got response instead of password prompt
            std::string confirmation(buffer + HEADER_LENGTH);
            std::cout << confirmation << std::endl;
            break;
        }
        
        case MessageHeader::REJECT: {
            // Rejection message (e.g., invalid password)
            password_prompt_active = false;  // Clear flag after rejection
            std::string rejection(buffer + HEADER_LENGTH);
            std::cout << rejection << std::endl;
            break;
        }
        
        case MessageHeader::LIST_RESPONSE: {
            // Response to /list command - display all connected users with roles
            std::vector<std::pair<std::string, std::string>> users_with_roles;
            if(parseListResponse(buffer, users_with_roles)) {
                std::cout << "Connected users (" << users_with_roles.size() << "):\n";
                for(const auto& user_role : users_with_roles) {
                    std::cout << "  - " << user_role.first << " (" << user_role.second << ")\n";
                }
            }
            break;
        }
        
        case MessageHeader::USER: {
            // Regular chat message from a user
            std::string full_message(buffer + HEADER_LENGTH);
            const std::string mesg_header = headerToString(MessageHeader::MESSAGE);
            size_t mesg_pos = full_message.find(mesg_header);
            if(mesg_pos != std::string::npos) {
                std::string msg_username = full_message.substr(0, mesg_pos);
                std::string msg_content = full_message.substr(mesg_pos + HEADER_LENGTH);
                std::cout << msg_username << ": " << msg_content << std::endl;
            }
            break;
        }
        
        default:
            // Unknown message type
            break;
    }
}

#endif // CLIENT_MESSAGE_HANDLER_HPP
