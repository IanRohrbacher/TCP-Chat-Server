/*
 * client_send.hpp
 * 
 * Send thread for chat client.
 * Handles user input and sends messages/commands to server.
 */

#ifndef CLIENT_SEND_HPP
#define CLIENT_SEND_HPP

#include <iostream>
#include <string>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include "../common/common.hpp"

// External references to global state (defined in client.cpp)
extern std::atomic<bool> running;
extern std::atomic<bool> password_prompt_active;
extern std::chrono::steady_clock::time_point lastActivityTime;
extern std::mutex stdin_mutex;

/**
 * @brief Read user input and send messages/commands to the server.
 *
 * Runs in a dedicated send thread. Reads newline-terminated input from
 * stdin (skips input while `password_prompt_active` is true), updates
 * the local activity timestamp, parses client-side commands with
 * `parseCommand`, builds protocol messages and sends them to the server.
 *
 * @param socket_fd Socket descriptor connected to the server
 * @param username This client's username (used as the sender in protocol messages)
 *
 * @note When a PASSWORD_CHALLENGE is issued by the server the receive
 *       thread sets `password_prompt_active = true` and this function
 *       will temporarily avoid reading from stdin to allow safe
 *       password entry. The function sets `running = false` when the
 *       user issues a quit command and exits the loop.
 */
void pushMessages(int socket_fd, const std::string& username) {
    while(running) {
        // Skip reading if password prompt is active (handleMessage is reading instead)
        if(password_prompt_active) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        std::string input;
        {
            std::lock_guard<std::mutex> lock(stdin_mutex);
            std::getline(std::cin, input);
        }
        
        // Update activity time (only sending counts as activity, not receiving)
        lastActivityTime = std::chrono::steady_clock::now();
        
        if(!running) break;
        
        std::string msg;
        
        // Process commands using switch statement
        Command cmd = parseCommand(input);
        
        switch(cmd) {
            case Command::QUIT:
                // Disconnect this client only
                msg = buildMessage(MessageHeader::LEAVE, username);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                running = false;
                break;
            
            case Command::SUDO_SU: {
                // /sudo su - server will prompt for password if needed
                password_prompt_active = true;  // Expect password prompt from server
                msg = buildMessage(MessageHeader::SUDO_SU, username);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            }
            
            case Command::SUDO_HELP: {
                // /sudo help - server will prompt for password if needed
                password_prompt_active = true;  // Expect password prompt from server
                msg = buildMessage(MessageHeader::SUDO_HELP, username);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            }
            
            case Command::SUDO: {
                // Generic sudo command wrapper: /sudo <command> <args...>
                std::string sudo_cmd = commandToString(Command::SUDO);
                if(input.length() > sudo_cmd.length() + 1) { // +1 for space after /sudo
                    std::string sudo_rest = input.substr(sudo_cmd.length() + 1); // Everything after "/sudo "
                    
                    // Parse the command to determine which header to use
                    size_t cmd_space = sudo_rest.find(' ');
                    std::string inner_cmd = (cmd_space == std::string::npos) ? sudo_rest : sudo_rest.substr(0, cmd_space);
                    std::string args = (cmd_space == std::string::npos) ? "" : sudo_rest.substr(cmd_space + 1);
                    
                    // Parse inner command (stringToCommand handles prefix automatically)
                    Command inner_command = stringToCommand(inner_cmd);
                    
                    switch(inner_command) {
                        case Command::CLOSE:
                            // /sudo close user1,user2 - wrapped with [SUDO] for server authentication
                            password_prompt_active = true;  // Server will prompt for password
                            msg = buildMessage(MessageHeader::SUDO, "") +
                                  buildMessage(MessageHeader::CLOSE_REQUEST, username) + 
                                  buildMessage(MessageHeader::USER, args);
                            send(socket_fd, msg.c_str(), msg.length(), 0);
                            break;
                        
                        case Command::CLOSEALL:
                            // /sudo closeall - wrapped with [SUDO] for server authentication
                            password_prompt_active = true;  // Server will prompt for password
                            msg = buildMessage(MessageHeader::SUDO, "") +
                                  buildMessage(MessageHeader::CLOSEALL_REQUEST, username);
                            send(socket_fd, msg.c_str(), msg.length(), 0);
                            break;
                        
                        case Command::SHUTDOWN:
                            // /sudo shutdown - wrapped with [SUDO] for server authentication
                            password_prompt_active = true;  // Server will prompt for password
                            msg = buildMessage(MessageHeader::SUDO, "") +
                                  buildMessage(MessageHeader::SHUTDOWN, username);
                            send(socket_fd, msg.c_str(), msg.length(), 0);
                            break;
                        
                        case Command::TIMEOUT:
                            // /sudo timeout 10 - wrapped with [SUDO] for server authentication
                            password_prompt_active = true;  // Server will prompt for password
                            msg = buildMessage(MessageHeader::SUDO, "") +
                                  buildMessage(MessageHeader::TIMEOUT, args);
                            send(socket_fd, msg.c_str(), msg.length(), 0);
                            break;
                        
                        case Command::SERVERTIMEOUT:
                            // /sudo servertimeout 30 - wrapped with [SUDO] for server authentication
                            password_prompt_active = true;  // Server will prompt for password
                            msg = buildMessage(MessageHeader::SUDO, "") +
                                  buildMessage(MessageHeader::SERVERTIMEOUT, args);
                            send(socket_fd, msg.c_str(), msg.length(), 0);
                            break;
                        
                        case Command::WHITELIST:
                            // /sudo whitelist ... - wrapped with [SUDO] for server authentication
                            password_prompt_active = true;  // Server will prompt for password
                            msg = buildMessage(MessageHeader::SUDO, "") +
                                  buildMessage(MessageHeader::WHITELIST, args);
                            send(socket_fd, msg.c_str(), msg.length(), 0);
                            break;
                        
                        case Command::ADMIN:
                            // /sudo admin ... - wrapped with [SUDO] for server authentication
                            password_prompt_active = true;  // Server will prompt for password
                            msg = buildMessage(MessageHeader::SUDO, "") +
                                  buildMessage(MessageHeader::ADMIN, args);
                            send(socket_fd, msg.c_str(), msg.length(), 0);
                            break;
                        
                        default:
                            // Unknown admin command - send to server for proper error message
                            password_prompt_active = true;
                            msg = buildMessage(MessageHeader::SUDO_HELP, username);
                            send(socket_fd, msg.c_str(), msg.length(), 0);
                            break;
                    }
                } else {
                    // No command after /sudo - request help from server
                    password_prompt_active = true;
                    msg = buildMessage(MessageHeader::SUDO_HELP, username);
                    send(socket_fd, msg.c_str(), msg.length(), 0);
                }
                break;
            }
            
            case Command::TIMEOUT: {
                // Set or query client timeout
                std::string timeout_cmd = commandToString(Command::TIMEOUT);
                if(input.length() > timeout_cmd.length() + 1) { // +1 for space after /timeout
                    // Setting timeout value
                    std::string minutes = input.substr(timeout_cmd.length() + 1);
                    msg = buildMessage(MessageHeader::TIMEOUT, minutes);
                    send(socket_fd, msg.c_str(), msg.length(), 0);
                } else {
                    // Query current timeout value - send empty request to server
                    msg = buildMessage(MessageHeader::TIMEOUT, "");
                    send(socket_fd, msg.c_str(), msg.length(), 0);
                }
                break;
            }
            
            case Command::SERVERTIMEOUT: {
                // Set or query server timeout
                std::string servertimeout_cmd = commandToString(Command::SERVERTIMEOUT);
                if(input.length() > servertimeout_cmd.length() + 1) { // +1 for space after /servertimeout
                    // Setting timeout value
                    std::string minutes = input.substr(servertimeout_cmd.length() + 1);
                    msg = buildMessage(MessageHeader::SERVERTIMEOUT, minutes);
                    send(socket_fd, msg.c_str(), msg.length(), 0);
                } else {
                    // Query current timeout value - send empty request to server
                    msg = buildMessage(MessageHeader::SERVERTIMEOUT, "");
                    send(socket_fd, msg.c_str(), msg.length(), 0);
                }
                break;
            }
            
            case Command::WHITELIST: {
                // Manage whitelist configuration
                std::string whitelist_cmd = commandToString(Command::WHITELIST);
                std::string args = "";
                if(input.length() > whitelist_cmd.length()) {
                    // Extract arguments after /whitelist
                    args = input.substr(whitelist_cmd.length());
                    // Trim leading space if present
                    if(!args.empty() && args[0] == ' ') {
                        args = args.substr(1);
                    }
                }
                msg = buildMessage(MessageHeader::WHITELIST, args);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            }
            
            case Command::ADMIN: {
                // Manage admin configuration
                std::string admin_cmd = commandToString(Command::ADMIN);
                std::string args = "";
                if(input.length() > admin_cmd.length()) {
                    // Extract arguments after /admin
                    args = input.substr(admin_cmd.length());
                    // Trim leading space if present
                    if(!args.empty() && args[0] == ' ') {
                        args = args.substr(1);
                    }
                }
                msg = buildMessage(MessageHeader::ADMIN, args);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            }
            
            case Command::CLOSEALL: {
                // Request server to close all client sessions
                msg = buildMessage(MessageHeader::CLOSEALL_REQUEST, username);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            }
            
            case Command::CLOSE: {
                // Request server to close specific users' sessions
                std::string close_cmd = commandToString(Command::CLOSE);
                std::string usernames = "";
                if(input.length() > close_cmd.length() + 1) { // +1 for space after /close
                    usernames = input.substr(close_cmd.length() + 1);
                }
                msg = buildMessage(MessageHeader::CLOSE_REQUEST, username) + 
                      buildMessage(MessageHeader::USER, usernames);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            }
            
            case Command::SHUTDOWN: {
                // Request server shutdown
                msg = buildMessage(MessageHeader::SHUTDOWN, username);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            }
            
            case Command::HELP:
                // Request help from server (will show commands based on role)
                msg = buildMessage(MessageHeader::HELP_REQUEST, username);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            
            case Command::LIST:
                // Request list of connected users from server
                msg = buildMessage(MessageHeader::LIST_REQUEST, username);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
            
            case Command::MSG: {
                // Send direct message to specific users
                // Format: /msg username1,username2,... message
                std::string msg_cmd = commandToString(Command::MSG);
                if(input.length() > msg_cmd.length() + 1) { // +1 for space after /msg
                    std::string rest = input.substr(msg_cmd.length() + 1);
                    size_t space_pos = rest.find(' ');
                    
                    std::string usernames_str = "";
                    std::string message = "";
                    
                    if(space_pos != std::string::npos) {
                        usernames_str = rest.substr(0, space_pos);
                        message = rest.substr(space_pos + 1);
                    } else {
                        // No space found - treat entire rest as usernames (empty message)
                        usernames_str = rest;
                    }
                    
                    std::vector<std::string> recipients = parseUsernames(usernames_str);
                    msg = buildMsgMessage(username, recipients, message);
                    send(socket_fd, msg.c_str(), msg.length(), 0);
                } else {
                    // Empty /msg - send to server, let it reject with usage
                    msg = buildMsgMessage(username, std::vector<std::string>(), "");
                    send(socket_fd, msg.c_str(), msg.length(), 0);
                }
                break;
            }
            
            case Command::UNKNOWN:
            default:
                // Unknown command or regular message - send everything to server
                // Server will either process it as a command or treat as regular message
                msg = buildUserMessage(username, input);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                break;
        }
        
        // Handle quit command break
        if(cmd == Command::QUIT) {
            break;
        }
    }
}

#endif // CLIENT_SEND_HPP
