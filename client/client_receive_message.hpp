/*
 * client_receive.hpp
 * 
 * Receive thread for chat client.
 * Continuously listens for messages from server and handles timeouts.
 */

#ifndef CLIENT_RECEIVE_HPP
#define CLIENT_RECEIVE_HPP

#include <iostream>
#include <string>
#include <string.h>
#include <cstdlib>
#include <atomic>
#include <chrono>
#include <chrono>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include "../common/common.hpp"
#include "client_message_handler.hpp"

// External references to global state (defined in client.cpp)
extern std::atomic<bool> running;
extern std::chrono::steady_clock::time_point lastActivityTime;

/**
 * @brief Continuously receive and process messages from the server.
 *
 * Runs in a dedicated receive thread. This function monitors the
 * client-side inactivity timeout (CLIENT_TIMEOUT_MINUTES), uses select()
 * with a short timeout for responsiveness, reads protocol messages, and
 * forwards them to `handleMessage`. On network errors or a detected
 * timeout it attempts to notify the server, cleanly close the socket,
 * and exit the process.
 *
 * @param socket_fd Socket descriptor connected to the server
 * @param username This client's username (used when notifying server of disconnect)
 *
 * @note If the client times out this function will call _Exit(0) to
 *       ensure immediate program termination. On other connection errors
 *       it will set `running = false` and return, allowing the send
 *       thread to observe the disconnect.
 */
void pullMessages(int socket_fd, const std::string& username) {
    const auto timeOutThreshold = std::chrono::minutes(CLIENT_TIMEOUT_MINUTES);
    char buffer[1024] = {0};
    
    while(running) {
        // Check if client has been inactive too long (if timeout enabled)
        if(CLIENT_TIMEOUT_MINUTES > 0) {
            auto currentTime = std::chrono::steady_clock::now();
            auto timeSinceActivity = std::chrono::duration_cast<std::chrono::minutes>(
                currentTime - lastActivityTime);

            if(timeSinceActivity >= timeOutThreshold) {
                running = false;
                std::cout << "Your session has timed out.\n";
                std::cout.flush();
                
                // Notify server of disconnect
                std::string msg = buildMessage(MessageHeader::LEAVE, username);
                send(socket_fd, msg.c_str(), msg.length(), 0);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                
                shutdown(socket_fd, SHUT_RDWR);
                close(socket_fd);
                _Exit(0);  // Force immediate exit
            }
        }

        // Use select() with 1-second timeout to avoid blocking
        // This allows periodic checking of timeout and running flag
        fd_set readfds;
        struct timeval timeout;
        
        FD_ZERO(&readfds);
        FD_SET(socket_fd, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(socket_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if(running) {
                std::cout << "Connection error.\n";
            }
            running = false;
            break;
        }
        
        if (activity == 0) {
            continue;  // Timeout, loop back to check inactivity
        }

        // Read message from server
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = read(socket_fd, buffer, 1024);
        
        if(bytes_read <= 0) {
            if(running) {
                std::cout << "Connection to server lost.\n";
            }
            running = false;
            break;
        }
        
        handleMessage(buffer, socket_fd);
    }
}

#endif // CLIENT_RECEIVE_HPP
