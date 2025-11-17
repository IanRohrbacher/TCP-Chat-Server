/*
 * server.cpp
 * 
 * Multi-threaded TCP chat server with role-based access control.
 * Supports admin commands, timeouts, and various messaging modes.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdlib>
#include <unordered_map>
#include <unordered_set>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../common/common.hpp"
#include "server_utils.hpp"
#include "server_message_handlers.hpp"
#include "server_client_handler.hpp"
#include "server_client_acceptor.hpp"
#include "server_command_handler.hpp"

// ============================================================================
// GLOBAL STATE
// ============================================================================

std::string SERVER_NAME = "Server";

// Client tracking
std::unordered_map<std::string, int> client_sockets;
std::unordered_map<std::string, std::chrono::steady_clock::time_point> client_last_activity;
std::mutex clients_mutex;

// Admin tracking
std::unordered_set<std::string> session_admins;
std::mutex admin_mutex;

// Logging
std::ofstream log_file;
std::mutex log_mutex;
std::atomic<bool> console_logging_enabled(true);
std::mutex console_output_mutex;

// Server control
std::atomic<bool> server_running(true);
std::atomic<int> active_client_threads(0);

// Timeout settings (0 = disabled)
std::atomic<int> server_timeout_minutes(10);
std::atomic<int> server_idle_timeout_minutes(30);

// Server activity tracking
std::chrono::steady_clock::time_point server_last_activity;
std::mutex server_activity_mutex;

// Shutdown tracking
std::string shutdown_initiator = "";
std::mutex shutdown_mutex;

// ============================================================================
// SERVER SHUTDOWN
// ============================================================================

/**
 * @brief Perform a graceful server shutdown sequence.
 *
 * This routine performs an orderly shutdown by closing the listening
 * socket (which stops new accepts), notifying connected clients with a
 * KICK message, closing client sockets, joining the accept thread, and
 * waiting briefly for any remaining client handler threads to finish.
 * It also records who initiated the shutdown in the log if available.
 *
 * Steps performed (in order):
 *  - Close server socket (stop accepting new connections)
 *  - Notify all clients of shutdown
 *  - Close all client sockets
 *  - Wait for accept thread to finish
 *  - Wait for client handler threads to complete (bounded wait)
 *
 * @param server_fd The server's listening socket file descriptor
 * @param accept_thread Reference to the accept_clients thread (will be joined)
 *
 * @note This function calls logging helpers and should be invoked from
 *       a thread that owns the responsibility for final shutdown. It is
 *       idempotent-safe in the sense that closing already-closed sockets
 *       is tolerated.
 */
void shutdownServer(int server_fd, std::thread& accept_thread) {
    std::string initiator;
    {
        std::lock_guard<std::mutex> lock(shutdown_mutex);
        initiator = shutdown_initiator;
    }
    
    if(!initiator.empty()) {
        logMessage(getTimestamp() + "SHUTDOWN: Server shutting down (initiated by " + initiator + ")");
    } else {
        logMessage(getTimestamp() + "SHUTDOWN: Server shutting down");
    }
    
    // Stop accepting new connections
    close(server_fd);
    
    // Notify all clients
    std::string shutdown_msg = buildMessage(MessageHeader::KICK, SERVER_NAME);
    std::vector<std::string> all_clients;
    
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for(const auto& pair : client_sockets) {
            if(pair.first != SERVER_NAME) {
                all_clients.push_back(pair.first);
            }
        }
    }
    
    // Send shutdown notification to all clients
    for(const auto& username : all_clients) {
        int sock = getSocketForUser(username);
        if(sock > 0) {
            send(sock, shutdown_msg.c_str(), shutdown_msg.length(), 0);
        }
    }
    
    // Give clients time to receive notification
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Close all client sockets
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for(auto& pair : client_sockets) {
            if(pair.second > 0) {
                close(pair.second);
            }
        }
        client_sockets.clear();
    }
    
    // Wait for accept thread
    if(accept_thread.joinable()) {
        accept_thread.join();
    }
    
    // Wait for all client handler threads to finish (with timeout)
    auto start = std::chrono::steady_clock::now();
    while(active_client_threads > 0) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();
        
        if(elapsed > 5) {
            logMessage(getTimestamp() + "WARNING: " + std::to_string(active_client_threads.load()) 
                     + " client threads still active after 5 seconds");
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    logMessage(getTimestamp() + "SHUTDOWN: Server shutdown complete");
    closeLogging();
}

// ============================================================================
// MAIN
// ============================================================================

/**
 * @brief Server process entry point.
 *
 * Initializes logging, network listening socket, admin/whitelist
 * configurations, and starts background threads for accepting clients
 * and processing operator commands. The main thread supervises server
 * idle timeout and initiates shutdown when required.
 *
 * @param argc Argument count (optional port and server name may be provided)
 * @param argv Argument vector (argv[1] = port, argv[2] = server name)
 * @return exits the process via std::_Exit after shutdown sequence completes
 *
 * @note This program uses other modules (server_utils, message handlers,
 *       acceptor and command handler). This function is intentionally
 *       concise; most server behavior is implemented in helper modules.
 */
int main(int argc, char *argv[]) {
    // Parse command line arguments
    int port = PORT;
    if(argc >= 2) {
        port = atoi(argv[1]);
        if(port <= 0 || port > 65535) {
            logMessage(getTimestamp() + "WARNING: Invalid port number provided; using default port " + std::to_string(PORT));
            port = PORT;
        }
    }
    
    if(argc >= 3) {
        SERVER_NAME = argv[2];
    }
    
    // Initialize logging system
    if(!initializeLogging(SERVER_NAME)) {
        logMessage(getTimestamp() + "WARNING: Logging system failed to initialize. Continuing without logging.");
    }
    
    logMessage(getTimestamp() + "SERVER: Starting server '" + SERVER_NAME + "' on port " + std::to_string(port));
    
    // Create server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        logMessage(getTimestamp() + "ERROR: Socket creation failed");
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    logMessage(getTimestamp() + "SERVER: Socket created successfully");
    
    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        logMessage(getTimestamp() + "ERROR: setsockopt failed");
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    // Bind socket to address
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        logMessage(getTimestamp() + "ERROR: Bind failed on port " + std::to_string(port));
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    logMessage(getTimestamp() + "SERVER: Socket bound to port " + std::to_string(port));
    
    // Listen for connections
    if (listen(server_fd, 10) < 0) {
        logMessage(getTimestamp() + "ERROR: Listen failed");
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    logMessage(getTimestamp() + "SERVER: Listening for connections (queue size: 10)");
    std::cout << "Server '" << SERVER_NAME << "' listening on port " << port << "...\n";
    logMessage(getTimestamp() + "SERVER: '" + SERVER_NAME + "' listening on port " + std::to_string(port));
    
    // Initialize server tracking (use -1 to indicate server, not a real client socket)
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        client_sockets[SERVER_NAME] = -1;
    }
    
    logMessage(getTimestamp() + "SERVER: Initializing admin system");
    // Initialize admin list
    initializeAdmins();
    
    logMessage(getTimestamp() + "SERVER: Loading whitelist configuration");
    // Load whitelist configuration
    if(!WhitelistConfig::load()) {
        logMessage(getTimestamp() + "WARNING: Failed to load whitelist configuration");
    }
    
    // Initialize server activity timestamp
    updateServerActivity();
    
    logMessage(getTimestamp() + "SERVER: Starting client acceptor thread");
    // Start accept thread
    std::thread accept_thread(accept_clients, server_fd);
    
    logMessage(getTimestamp() + "SERVER: Starting console command thread");
    // Start console command processing thread (detached to avoid blocking on stdin)
    std::thread console_thread(processServerCommands);
    console_thread.detach();  // Detach so stdin errors don't crash the server
    
    // Suppress console logging while printing the operator-facing initialization
    // message so logMessage entries don't duplicate or interleave on stdout.
    console_logging_enabled.store(false);
    logMessage(getTimestamp() + "SERVER: Initialization complete, server is now running");
    std::cout << "Server initialized. Type /help for available commands.\n";
    logMessage(getTimestamp() + "SERVER: Initialization complete; operator may use /help for commands");
    console_logging_enabled.store(true);
    
    // Main monitoring loop - check for server inactivity timeout
    while(server_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Check server inactivity timeout
        int idle_timeout = server_idle_timeout_minutes.load();
        if(idle_timeout > 0) {
            auto now = std::chrono::steady_clock::now();
            auto last_activity = std::chrono::steady_clock::time_point::min();
            
            {
                std::lock_guard<std::mutex> lock(server_activity_mutex);
                last_activity = server_last_activity;
            }
            
            auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
                now - last_activity).count();
            
            if(elapsed >= idle_timeout) {
                logMessage(getTimestamp() + "TIMEOUT: Server timed out after " + 
                          std::to_string(elapsed) + " minutes of inactivity");
                // Record that timeout initiated shutdown
                {
                    std::lock_guard<std::mutex> lock(shutdown_mutex);
                    shutdown_initiator = "server timeout";
                }
                server_running = false;
                break;
            }
        }
    }
    
    // Shutdown sequence
    shutdownServer(server_fd, accept_thread);
    std::_Exit(0);
}
