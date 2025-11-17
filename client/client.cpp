/*
 * client.cpp
 * 
 * Multi-threaded TCP chat client with role-based command access.
 * 
 * Key Features:
 * - Username-based connection with uniqueness validation by server
 * - Real-time bidirectional messaging (send and receive simultaneously)
 * - Direct messaging to specific users via /msg command
 * - Role-based command access: regular users vs admin users
 * - Privilege escalation via /sudo commands (requires password)
 * - Self-managed inactivity timeout (auto-disconnect after idle period)
 * - Multi-threaded architecture:
 *   - Main thread: Connection setup and coordination
 *   - Receive thread: Continuously listens for server messages
 *   - Send thread: Handles user input and sends to server
 * - Graceful disconnect handling for all scenarios
 * 
 * Admin Features:
 * - Preregistered admins (e.g., "admin", "root"): Instant admin status
 * - Session admins: Regular users can become admin via /sudo su <password>
 * - Admin commands: /close, /closeall, /shutdown, /timeout, /servertimeout
 * - Non-admins can use /sudo <command> <password> for one-time admin actions
 */

#include <iostream>       // Console I/O
#include <string.h>       // C-string functions (memset, strlen)
#include <cstdlib>        // exit(), EXIT_FAILURE, _Exit()
#include <thread>         // Multi-threading support
#include <mutex>          // Thread synchronization for stdin
#include <atomic>         // Thread-safe atomic variables
#include <chrono>         // Time tracking for inactivity timeout
// Network programming headers
#include <sys/socket.h>   // Socket functions (socket, connect, send, read)
#include <arpa/inet.h>    // Internet address conversion (inet_pton)
#include <unistd.h>       // POSIX functions (close, read)
#include "../common/common.hpp"     // Shared protocol definitions and utilities
// Client-specific headers (refactored modules)
#include "client_message_handler.hpp"  // handleMessage()
#include "client_receive_message.hpp"          // pullMessages()
#include "client_send_message.hpp"             // pushMessages()

// ============================================================================
// GLOBAL STATE
// ============================================================================

// Controls both send and receive threads (set to false to disconnect and exit)
std::atomic<bool> running(true);

// Flag to pause user input when server is requesting password
std::atomic<bool> password_prompt_active(false);

// Tracks last time user sent a message (for inactivity timeout calculation)
// Only outgoing messages count as activity (receiving doesn't reset the timer)
std::chrono::steady_clock::time_point lastActivityTime;

// Mutex to protect stdin access (prevents both threads from reading simultaneously)
std::mutex stdin_mutex;

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    // Get username from user
    std::string username;
    std::cout << "Create a username: ";
    std::cin >> username;
    std::cin.ignore();  // Clear newline from input buffer

    // Create TCP socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    std::cout << "Connected to server.\n";

    // Send username to server (just username, no password yet)
    std::string msg = buildMessage(MessageHeader::ENTER, username);
    send(sock, msg.c_str(), msg.length(), 0);

    // Wait for server response
    char response_buffer[1024] = {0};
    int bytes_received = read(sock, response_buffer, sizeof(response_buffer));
    
    if(bytes_received <= 0) {
        std::cout << "Connection closed by server.\n";
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    std::string response(response_buffer);
    MessageHeader response_header = extractHeader(response_buffer, bytes_received);
    
    // Handle password challenge if server requests it
    if(response_header == MessageHeader::PASSWORD_CHALLENGE) {
        // Loop: server may ask for the password multiple times (up to its max attempts)
        while(true) {
            std::string prompt = response.substr(HEADER_LENGTH);
            std::cout << prompt;  // Server sends full prompt

            std::string password;
            std::getline(std::cin, password);

            // Send password response
            msg = buildMessage(MessageHeader::PASSWORD_RESPONSE, password);
            send(sock, msg.c_str(), msg.length(), 0);

            // Wait for server reply (either another challenge, ACCEPT, or REJECT)
            memset(response_buffer, 0, sizeof(response_buffer));
            bytes_received = read(sock, response_buffer, sizeof(response_buffer));

            if(bytes_received <= 0) {
                std::cout << "Connection closed by server.\n";
                close(sock);
                exit(EXIT_FAILURE);
            }

            response = std::string(response_buffer);
            response_header = extractHeader(response_buffer, bytes_received);

            // If server sent another PASSWORD_CHALLENGE, loop and prompt again
            if(response_header == MessageHeader::PASSWORD_CHALLENGE) {
                continue;
            }

            // Otherwise break and let the authentication-result switch handle it
            break;
        }
    }
    
    // Process authentication result
    switch(response_header) {
        case MessageHeader::REJECT:
            {
                // Connection was rejected - server sends full message
                std::string message = response.substr(HEADER_LENGTH);
                std::cout << message << std::endl;
                close(sock);
                exit(EXIT_FAILURE);
            }
            break;
        
        case MessageHeader::ACCEPT:
            {
                // Connection was accepted - server sends full welcome message
                std::string message = response.substr(HEADER_LENGTH);
                std::cout << message << std::endl;
            }
            break;
        
        default:
            // Unexpected response
            std::cout << "Unexpected response from server.\n";
            close(sock);
            exit(EXIT_FAILURE);
            break;
    }

    // Initialize activity timestamp
    lastActivityTime = std::chrono::steady_clock::now();

    // Start receive thread (joinable - we wait for it to finish)
    std::thread receive_thread([sock, &username]() {
        pullMessages(sock, username);
    });

    // Start send thread (detached - runs independently)
    std::thread send_thread([sock, &username]() {
        pushMessages(sock, username);
    });
    send_thread.detach();
    
    // Wait for receive thread to complete (happens on disconnect)
    receive_thread.join();
    close(sock);
    
    std::cout << "Disconnected from server.\n";
    std::cout.flush();
    
    // Force immediate exit (don't wait for detached send thread)
    _Exit(0);
}
