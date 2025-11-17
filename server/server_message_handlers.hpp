/*
 * server_message_handlers.hpp
 * 
 * Individual message type handlers for chat server.
 * Each function processes a specific message type from clients.
 */

#ifndef SERVER_MESSAGE_HANDLERS_HPP
#define SERVER_MESSAGE_HANDLERS_HPP

#include <iostream>
#include <string>
#include <string.h>
#include <sstream>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/common.hpp"
#include "server_utils.hpp"

// External references to global state (defined in server.cpp)
extern std::string SERVER_NAME;
extern std::unordered_map<std::string, int> client_sockets;
extern std::unordered_map<std::string, std::chrono::steady_clock::time_point> client_last_activity;
extern std::mutex clients_mutex;
extern std::unordered_set<std::string> session_admins;
extern std::mutex admin_mutex;
extern std::atomic<bool> server_running;
extern std::atomic<int> server_timeout_minutes;
extern std::atomic<int> server_idle_timeout_minutes;
extern std::string shutdown_initiator;
extern std::mutex shutdown_mutex;

// ============================================================================
// MESSAGE DISTRIBUTION FUNCTIONS
// ============================================================================

/**
 * @brief Send a message to all connected clients except the sender.
 *
 * Broadcasts the provided raw protocol message to every connected client
 * whose socket is valid and is not the sender's socket. This helper is
 * intended for use with already-formatted protocol messages (e.g. the
 * output of buildUserMessage or buildMessage).
 *
 * @param message Null-terminated C-string containing the protocol message to broadcast
 * @param sender_username Username of the sender (excluded from broadcast). If
 *                        `sender_username == SERVER_NAME` the server activity
 *                        timestamp will be updated.
 */
inline void broadcast(const char* message, const std::string& sender_username) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    int sender_socket = getSocketForUser(sender_username);
    
    for(const auto& pair : client_sockets) {
        if(pair.second != sender_socket && pair.second > 0) {
            send(pair.second, message, strlen(message), 0);
        }
    }
    
    // Track server activity when server is the sender
    if(sender_username == SERVER_NAME) {
        updateServerActivity();
    }
}

/**
 * @brief Send a message to a single specific user.
 *
 * Sends the raw protocol message to the socket associated with the
 * receiver username if the receiver is connected and is not the sender.
 * This function is a thin wrapper around send() that validates that the
 * recipient exists and is not the same as the sender.
 *
 * @param message Null-terminated C-string containing the protocol message to send
 * @param receiver_username Username of the intended recipient
 * @param sender_username Username of the sender (used to prevent echo and to
 *                        update server activity when appropriate)
 */
inline void unicast(const char* message, const std::string& receiver_username, const std::string& sender_username) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    int sender_socket = getSocketForUser(sender_username);
    int receiver_socket = getSocketForUser(receiver_username);
    
    if(receiver_socket > 0 && receiver_socket != sender_socket) {
        send(receiver_socket, message, strlen(message), 0);
        
        // Track server activity when server is the sender
        if(sender_username == SERVER_NAME) {
            updateServerActivity();
        }
    }
}

/**
 * @brief Send a message to multiple specific users.
 *
 * Iterates the provided recipient list and delivers the message to each
 * connected recipient that is not the sender. Missing or offline users
 * are silently skipped; callers should handle any required confirmation
 * back to the sender.
 *
 * @param message Null-terminated C-string containing the protocol message to send
 * @param receiver_usernames Vector of recipient usernames
 * @param sender_username Username of the sender (used to prevent echo and to
 *                        update server activity when appropriate)
 */
inline void multicast(const char* message, const std::vector<std::string>& receiver_usernames, 
                const std::string& sender_username) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    int sender_socket = getSocketForUser(sender_username);
    
    for(const std::string& username : receiver_usernames) {
        int receiver_socket = getSocketForUser(username);
        if(receiver_socket > 0 && receiver_socket != sender_socket) {
            send(receiver_socket, message, strlen(message), 0);
        }
    }
    
    // Track server activity when server is the sender
    if(sender_username == SERVER_NAME) {
        updateServerActivity();
    }
}

// ============================================================================
// MESSAGE HANDLERS
// ============================================================================

/**
 * @brief Authenticate a client for an admin-level command invoked with sudo.
 *
 * Admin users are automatically authorized. Non-admins must provide a
 * sudo wrapper or successfully authenticate with a password. When
 * authentication fails, an appropriate REJECT message is sent to the client.
 *
 * @param client_socket Socket descriptor to communicate with the client
 * @param username Username attempting the command
 * @param is_sudo_command True if the command included the [SUDO] wrapper
 * @param command_name The command name for use in error/usage messages (e.g., "/timeout")
 * @return true if the user is authorized to run the command, false otherwise
 */
inline bool authenticateSudoCommand(int client_socket, const std::string& username, 
                                    bool is_sudo_command, const std::string& command_name) {
    if(isAdmin(username)) {
        return true;
    }
    
    if(!is_sudo_command) {
        logMessage(getTimestamp() + "AUTH REJECT: Client '" + username + "' attempted admin command " + 
                  command_name + " without sudo. Rejected");
        std::string denial = buildMessage(MessageHeader::REJECT, 
            "Admin command. Use: /sudo " + command_name.substr(1) + " [args]");
        send(client_socket, denial.c_str(), denial.length(), 0);
        return false;
    }
    
    char temp_buffer[1024];
    bool password_valid = requestAndValidatePassword(client_socket, temp_buffer, sizeof(temp_buffer),
                                                    "password: ", AdminConfig::getRootPassword(), username);
    if(!password_valid) {
        return false;
    }
    
    logMessage(getTimestamp() + "AUTH SUCCESS: Password accepted. Processing " + command_name + " command");
    return true;
}

/**
 * @brief Authenticate a client (if necessary) and invoke provided actions.
 *
 * This helper centralizes the common sudo authentication flow used by
 * SUDO_SU and SUDO_HELP: if the user is already an admin, the
 * action_if_admin callable is invoked; otherwise the function requests a
 * password and on success invokes action_after_auth.
 *
 * @tparam AdminAction Callable type for the admin-branch action
 * @tparam AuthAction Callable type for the post-auth action
 * @param client_socket Socket descriptor to communicate with the client
 * @param buffer Buffer used to receive password responses
 * @param buffer_size Size of the buffer
 * @param username Username requesting the action
 * @param action_if_admin Callable invoked immediately if user is already admin
 * @param action_after_auth Callable invoked after successful password authentication
 * @return true always (returns into the caller's processing loop)
 */
template<typename AdminAction, typename AuthAction>
inline bool authenticateAndExecute(int client_socket, char* buffer, size_t buffer_size,
                                   const std::string& username,
                                   AdminAction action_if_admin,
                                   AuthAction action_after_auth) {
    if(isAdmin(username)) {
        action_if_admin();
        return true;
    }
    
    bool password_valid = requestAndValidatePassword(client_socket, buffer, buffer_size,
                                                    "password: ", AdminConfig::getRootPassword(), username);
    if(!password_valid) {
        return true;
    }
    
    action_after_auth();
    return true;
}

/**
 * @brief Handle a client's request to gain temporary admin privileges (/sudo su).
 *
 * Authenticates the requesting client (if not already an admin) and grants
 * session-level admin privileges on success.
 *
 * @param client_socket Socket descriptor for the client
 * @param buffer Buffer used for password exchange
 * @param buffer_size Size of the buffer
 * @param username Username requesting sudo
 * @return true to continue processing the client's message loop
 */
inline bool handleSudoSu(int client_socket, char* buffer, size_t buffer_size, const std::string& username) {
    logMessage(getTimestamp() + "SUDO REQUEST: '" + username + "' requesting admin privileges");
    
    return authenticateAndExecute(
        client_socket, buffer, buffer_size, username,
        [&]() {
            logMessage(getTimestamp() + "SUDO INFO: '" + username + "' already has admin privileges");
            std::string conf = buildMessage(MessageHeader::RESPONSE, "You already have admin privileges.");
            send(client_socket, conf.c_str(), conf.length(), 0);
        },
        [&]() {
            logMessage(getTimestamp() + "SUDO GRANT: Admin privileges granted to '" + username + "' for this session");
            addSessionAdmin(username);
            std::string conf = buildMessage(MessageHeader::RESPONSE, "Admin privileges granted for this session.");
            send(client_socket, conf.c_str(), conf.length(), 0);
        }
    );
}

/**
 * @brief Handle a client's request for the admin command list (/sudo help).
 *
 * Ensures authentication if necessary and sends the admin help text back to
 * the client.
 *
 * @param client_socket Socket descriptor for the client
 * @param buffer Buffer used for password exchange
 * @param buffer_size Size of the buffer
 * @param username Username requesting the admin help
 * @return true to continue processing the client's message loop
 */
inline bool handleSudoHelp(int client_socket, char* buffer, size_t buffer_size, const std::string& username) {
    return authenticateAndExecute(
        client_socket, buffer, buffer_size, username,
        [&]() {
            std::string help_msg = buildMessage(MessageHeader::RESPONSE, getAdminHelpText());
            send(client_socket, help_msg.c_str(), help_msg.length(), 0);
        },
        [&]() {
            std::string help_msg = buildMessage(MessageHeader::RESPONSE, getAdminHelpText());
            send(client_socket, help_msg.c_str(), help_msg.length(), 0);
        }
    );
}

/**
 * @brief Handle a timeout command (query or set) for client or server timeouts.
 *
 * When minutes_str is empty, the current timeout is returned. Otherwise the
 * supplied value is parsed and validated; on success the atomic timeout
 * variable is updated and an appropriate confirmation is sent to the client.
 *
 * @param client_socket Socket descriptor to send responses to
 * @param minutes_str The timeout value as a string (empty to query current)
 * @param username The user issuing the command
 * @param timeout_atomic Reference to the atomic<int> representing the timeout
 * @param command_pattern The full command pattern (for usage messages)
 * @param timeout_name Human-readable name for messages (e.g., "Client inactivity timeout")
 * @param log_prefix Prefix used for log entries (e.g., "TIMEOUT")
 * @param reset_activity_on_change If true, update server activity timestamp when changing value
 * @return true to continue processing the client's message loop
 */
inline bool handleTimeoutCommand(int client_socket, const std::string& minutes_str, const std::string& username,
                                std::atomic<int>& timeout_atomic, const std::string& command_pattern,
                                const std::string& timeout_name, const std::string& log_prefix,
                                bool reset_activity_on_change = false) {
    // Query current value if no argument provided
    if(minutes_str.empty()) {
        std::string resp_msg = buildTimeoutQueryResponse(command_pattern, timeout_atomic.load());
        send(client_socket, resp_msg.c_str(), resp_msg.length(), 0);
        logMessage(getTimestamp() + "QUERY: '" + username + "' queried " + timeout_name + " setting");
        return true;
    }
    
    // Parse and validate timeout value
    try {
        int minutes = std::stoi(minutes_str);
        if(minutes >= 0) {
            int old_timeout = timeout_atomic.load();
            timeout_atomic = minutes;
            
            if(reset_activity_on_change) {
                updateServerActivity();
            }
            
            std::string confirmation = minutes == 0 ? 
                timeout_name + " disabled." :
                timeout_name + " set to " + std::to_string(minutes) + " minute(s).";
            std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
            send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
            logMessage(getTimestamp() + log_prefix + " CHANGE: '" + username + "' changed " + timeout_name + 
                      " from " + std::to_string(old_timeout) + " to " + std::to_string(minutes) + " minute(s)");
        } else {
            std::string denial = buildMessage(MessageHeader::REJECT, 
                "Timeout must be 0 or a positive number. " + getCommandUsage(command_pattern + " <minutes>"));
            send(client_socket, denial.c_str(), denial.length(), 0);
        }
    } catch(...) {
        std::string denial = buildMessage(MessageHeader::REJECT, 
            "Invalid timeout value. " + getCommandUsage(command_pattern + " <minutes>"));
        send(client_socket, denial.c_str(), denial.length(), 0);
    }
    return true;
}

/**
 * @brief Handle the /timeout command from a client (query or set client timeout).
 *
 * Performs sudo authentication if required, then delegates to
 * handleTimeoutCommand to perform the query or update.
 *
 * @param client_socket Socket descriptor for the client
 * @param buffer Raw message buffer containing the command
 * @param username The username issuing the command
 * @param is_sudo_command True if command was wrapped with [SUDO]
 * @return true to continue processing the client's message loop
 */
inline bool handleTimeout(int client_socket, const char* buffer, const std::string& username, bool is_sudo_command = false) {
    if(!authenticateSudoCommand(client_socket, username, is_sudo_command, "/timeout")) {
        return true;
    }
    
    std::string minutes_str = std::string(buffer + HEADER_LENGTH);
    return handleTimeoutCommand(client_socket, minutes_str, username, server_timeout_minutes,
                               "/timeout", "Client inactivity timeout", "TIMEOUT", false);
}

/**
 * @brief Handle the /servertimeout command (query or set the server inactivity timeout).
 *
 * Performs sudo authentication if required and delegates to
 * handleTimeoutCommand. Optionally resets server activity when updated.
 *
 * @param client_socket Socket descriptor for the client
 * @param buffer Raw message buffer containing the command
 * @param username The username issuing the command
 * @param is_sudo_command True if command was wrapped with [SUDO]
 * @return true to continue processing the client's message loop
 */
inline bool handleServerTimeout(int client_socket, const char* buffer, const std::string& username, bool is_sudo_command = false) {
    if(!authenticateSudoCommand(client_socket, username, is_sudo_command, "/servertimeout")) {
        return true;
    }
    
    std::string minutes_str = std::string(buffer + HEADER_LENGTH);
    return handleTimeoutCommand(client_socket, minutes_str, username, server_idle_timeout_minutes,
                               "/servertimeout", "Server inactivity timeout", "SERVERTIMEOUT", true);
}

/**
 * @brief Handle /whitelist commands to query or modify whitelist configuration.
 *
 * Supports querying status, enabling/disabling, adding/removing users, and
 * clearing the whitelist. Admin or sudo authentication is required for
 * modifying operations.
 *
 * @param client_socket Socket descriptor for the client
 * @param buffer Raw message buffer containing the whitelist command
 * @param username The username issuing the command
 * @param is_sudo_command True if command was wrapped with [SUDO]
 * @return true to continue processing the client's message loop
 */
inline bool handleWhitelist(int client_socket, const char* buffer, const std::string& username, bool is_sudo_command = false) {
    std::string args_str = std::string(buffer + HEADER_LENGTH);
    
    // Authenticate user (admin or sudo with password)
    if(!authenticateSudoCommand(client_socket, username, is_sudo_command, "/whitelist")) {
        return true;  // Authentication failed, rejection already sent
    }
    
    // Trim leading/trailing whitespace
    size_t start = args_str.find_first_not_of(" \t\n\r");
    size_t end = args_str.find_last_not_of(" \t\n\r");
    if(start == std::string::npos) {
        args_str = "";
    } else {
        args_str = args_str.substr(start, end - start + 1);
    }
    
    // Case 1: No arguments - show current status
    if(args_str.empty()) {
        std::string status = WhitelistConfig::getStatus();
        std::string resp_msg = buildMessage(MessageHeader::RESPONSE, status);
        send(client_socket, resp_msg.c_str(), resp_msg.length(), 0);
        logMessage(getTimestamp() + "QUERY: Client '" + username + "' (admin) queried whitelist status");
        return true;
    }
    
    // Case 2: Enable/disable whitelist - /whitelist true|false
    if(args_str == "true" || args_str == "false" || args_str == "1" || args_str == "0") {
        bool enable = (args_str == "true" || args_str == "1");
        
        if(WhitelistConfig::setEnabled(enable)) {
            std::string confirmation = enable ? 
                "Whitelist mode enabled." :
                "Whitelist mode disabled.";
            std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
            send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
            logMessage(getTimestamp() + "ADMIN ACTION: '" + username + "' " + (enable ? "enabled" : "disabled") + " whitelist mode");
        } else {
            std::string error = buildMessage(MessageHeader::REJECT, "Failed to save whitelist configuration.");
            send(client_socket, error.c_str(), error.length(), 0);
            logMessage(getTimestamp() + "ERROR: '" + username + "' failed to " + (enable ? "enable" : "disable") + " whitelist mode");
        }
        return true;
    }
    
    // Case 3: Add users - /whitelist add <user> <pass> [<user> <pass> ...]
    if(args_str.substr(0, 4) == "add ") {
        std::string users_str = args_str.substr(4);
        std::vector<std::pair<std::string, std::string>> users_to_add;
        
        // Parse user/password pairs
        std::istringstream iss(users_str);
        std::string user, pass;
        while(iss >> user >> pass) {
            users_to_add.push_back({user, pass});
        }
        
        if(users_to_add.empty()) {
            std::string error = buildMessage(MessageHeader::REJECT, 
                "Invalid syntax. " + getCommandUsage("/whitelist add <user> <pass> [<user> <pass> ...]"));
            send(client_socket, error.c_str(), error.length(), 0);
            return true;
        }
        
        int added = WhitelistConfig::add(users_to_add);
        
        // Build list of added usernames for logging
        std::string added_users;
        for(size_t i = 0; i < users_to_add.size() && i < (size_t)added; ++i) {
            if(i > 0) added_users += ", ";
            added_users += users_to_add[i].first;
        }
        
        std::string confirmation = "Added " + std::to_string(added) + " user(s) to whitelist.";
        if(added < (int)users_to_add.size()) {
            confirmation += " (Skipped " + std::to_string(users_to_add.size() - added) + " duplicate(s))";
        }
        
        std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
        send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
        logMessage(getTimestamp() + "WHITELIST ADD: '" + username + "' added " + std::to_string(added) + " user(s): " + added_users);
        return true;
    }
    
    // Case 4: Remove users - /whitelist remove <user> [<user> ...]
    if(args_str.substr(0, 7) == "remove ") {
        std::string users_str = args_str.substr(7);
        std::vector<std::string> users_to_remove;
        
        // Parse usernames
        std::istringstream iss(users_str);
        std::string user;
        while(iss >> user) {
            users_to_remove.push_back(user);
        }
        
        if(users_to_remove.empty()) {
            std::string error = buildMessage(MessageHeader::REJECT, 
                "Invalid syntax. " + getCommandUsage("/whitelist remove <user> [<user> ...]"));
            send(client_socket, error.c_str(), error.length(), 0);
            return true;
        }
        
        // Build list of usernames for logging
        std::string removed_users;
        for(size_t i = 0; i < users_to_remove.size(); ++i) {
            if(i > 0) removed_users += ", ";
            removed_users += users_to_remove[i];
        }
        
        int removed = WhitelistConfig::remove(users_to_remove);
        std::string confirmation = "Removed " + std::to_string(removed) + " user(s) from whitelist.";
        if(removed == 0) {
            confirmation = "No matching users found in whitelist.";
        }
        
        std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
        send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
        logMessage(getTimestamp() + "WHITELIST REMOVE: '" + username + "' removed " + std::to_string(removed) + " user(s): " + removed_users);
        return true;
    }
    
    // Case 5: Clear all whitelist users - /whitelist clear
    if(args_str == "clear") {
        int cleared = WhitelistConfig::clear();
        
        std::string confirmation = "Cleared " + std::to_string(cleared) + " user(s) from whitelist.";
        if(cleared == 0) {
            confirmation = "No users to clear from whitelist.";
        }
        
        std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
        send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
        logMessage(getTimestamp() + "WHITELIST CLEAR: '" + username + "' cleared " + std::to_string(cleared) + " user(s) from whitelist");
        return true;
    }
    
    // Invalid subcommand
    std::string error = buildMessage(MessageHeader::REJECT, 
        "Invalid whitelist command. Usage:\n" +
        getCommandUsage("/whitelist") + "\n" +
        getCommandUsage("/whitelist <true|false>") + "\n" +
        getCommandUsage("/whitelist add <user> <pass> [<user> <pass> ...]") + "\n" +
        getCommandUsage("/whitelist remove <user> [<user> ...]") + "\n" +
        getCommandUsage("/whitelist clear"));
    send(client_socket, error.c_str(), error.length(), 0);
    return true;
}

/**
 * @brief Handle /admin commands for managing admin accounts and status.
 *
 * Allows querying admin status, adding/removing admins, and clearing the
 * admin list (root cannot be removed). Admin or sudo authentication is
 * required for modification operations.
 *
 * @param client_socket Socket descriptor for the client
 * @param buffer Raw message buffer containing the admin command
 * @param username The username issuing the command
 * @param is_sudo_command True if command was wrapped with [SUDO]
 * @return true to continue processing the client's message loop
 */
inline bool handleAdmin(int client_socket, const char* buffer, const std::string& username, bool is_sudo_command = false) {
    std::string args_str = std::string(buffer + HEADER_LENGTH);
    
    // Authenticate user (admin or sudo with password)
    if(!authenticateSudoCommand(client_socket, username, is_sudo_command, "/admin")) {
        return true;  // Authentication failed, rejection already sent
    }
    
    // Trim leading/trailing whitespace
    size_t start = args_str.find_first_not_of(" \t\n\r");
    size_t end = args_str.find_last_not_of(" \t\n\r");
    if(start == std::string::npos) {
        args_str = "";
    } else {
        args_str = args_str.substr(start, end - start + 1);
    }
    
    // Case 1: No arguments - show current status
    if(args_str.empty()) {
        std::string status = AdminConfig::getStatus();
        std::string resp_msg = buildMessage(MessageHeader::RESPONSE, status);
        send(client_socket, resp_msg.c_str(), resp_msg.length(), 0);
        logMessage(getTimestamp() + "QUERY: Client '" + username + "' (admin) queried admin status");
        return true;
    }
    
    // Case 2: Add admins - /admin add <user> <pass> [<user> <pass> ...]
    if(args_str.substr(0, 4) == "add ") {
        std::string users_str = args_str.substr(4);
        std::vector<std::pair<std::string, std::string>> admins_to_add;
        
        // Parse user/password pairs
        std::istringstream iss(users_str);
        std::string user, pass;
        while(iss >> user >> pass) {
            admins_to_add.push_back({user, pass});
        }
        
        if(admins_to_add.empty()) {
            std::string error = buildMessage(MessageHeader::REJECT, 
                "Invalid syntax. " + getCommandUsage("/admin add <user> <pass> [<user> <pass> ...]"));
            send(client_socket, error.c_str(), error.length(), 0);
            return true;
        }
        
        int added = AdminConfig::add(admins_to_add);
        
        // Build list of added admin usernames for logging
        std::string added_admins;
        for(size_t i = 0; i < admins_to_add.size() && i < (size_t)added; ++i) {
            if(i > 0) added_admins += ", ";
            added_admins += admins_to_add[i].first;
        }
        
        std::string confirmation = "Added " + std::to_string(added) + " admin(s).";
        if(added < (int)admins_to_add.size()) {
            confirmation += " (Skipped " + std::to_string(admins_to_add.size() - added) + " duplicate(s) or reserved username)";
        }
        
        std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
        send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
        logMessage(getTimestamp() + "ADMIN ADD: '" + username + "' added " + std::to_string(added) + " admin(s): " + added_admins);
        return true;
    }
    
    // Case 3: Remove admins - /admin remove <user> [<user> ...]
    if(args_str.substr(0, 7) == "remove ") {
        std::string users_str = args_str.substr(7);
        std::vector<std::string> admins_to_remove;
        
        // Parse usernames
        std::istringstream iss(users_str);
        std::string user;
        while(iss >> user) {
            admins_to_remove.push_back(user);
        }
        
        if(admins_to_remove.empty()) {
            std::string error = buildMessage(MessageHeader::REJECT, 
                "Invalid syntax. " + getCommandUsage("/admin remove <user> [<user> ...]"));
            send(client_socket, error.c_str(), error.length(), 0);
            return true;
        }
        
        // Build list of usernames for logging
        std::string removed_admins;
        for(size_t i = 0; i < admins_to_remove.size(); ++i) {
            if(i > 0) removed_admins += ", ";
            removed_admins += admins_to_remove[i];
        }
        
        int removed = AdminConfig::remove(admins_to_remove);
        
        std::string confirmation = "Removed " + std::to_string(removed) + " admin(s).";
        if(removed == 0) {
            confirmation = "No matching admins found (or attempted to remove root).";
        }
        
        std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
        send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
        logMessage(getTimestamp() + "ADMIN REMOVE: '" + username + "' removed " + std::to_string(removed) + " admin(s): " + removed_admins);
        return true;
    }
    
    // Case 4: Clear all admins - /admin clear
    if(args_str == "clear") {
        int cleared = AdminConfig::clear();
        
        std::string confirmation = "Cleared " + std::to_string(cleared) + " admin(s).";
        if(cleared == 0) {
            confirmation = "No admins to clear (root cannot be removed).";
        }
        
        std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
        send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
        logMessage(getTimestamp() + "ADMIN CLEAR: '" + username + "' cleared " + std::to_string(cleared) + " admin(s) from admin list");
        return true;
    }
    
    // Invalid subcommand
    std::string error = buildMessage(MessageHeader::REJECT, 
        "Invalid admin command. Usage:\n" +
        getCommandUsage("/admin") + "\n" +
        getCommandUsage("/admin add <user> <pass> [<user> <pass> ...]") + "\n" +
        getCommandUsage("/admin remove <user> [<user> ...]") + "\n" +
        getCommandUsage("/admin clear"));
    send(client_socket, error.c_str(), error.length(), 0);
    return true;
}

/**
 * @brief Handle a request to shutdown the server (/shutdown).
 *
 * Validates authentication and records the shutdown initiator; notifies
 * connected clients and initiates graceful server shutdown.
 *
 * @param client_socket Socket descriptor for the client
 * @param buffer Raw message buffer containing the shutdown request
 * @param username The username issuing the shutdown
 * @param is_sudo_command True if command was wrapped with [SUDO]
 * @return false to indicate the client loop should be terminated after handling
 */
inline bool handleShutdown(int client_socket, const char* buffer, const std::string& username, bool is_sudo_command = false) {
    std::string full_msg(buffer);
    std::string rest_of_msg = full_msg.substr(HEADER_LENGTH);
    
    // Check if there are extra arguments
    size_t first_bracket = rest_of_msg.find('[');
    std::string potential_args = (first_bracket != std::string::npos) ? 
                                rest_of_msg.substr(0, first_bracket) : rest_of_msg;
    
    // Format: [SHUT]username - check if there's anything beyond username
    if(!potential_args.empty() && potential_args != username) {
        std::string denial = buildMessage(MessageHeader::REJECT, 
            "Command /shutdown does not accept arguments. " + getCommandUsage("/shutdown"));
        send(client_socket, denial.c_str(), denial.length(), 0);
        return true;
    }
    
    logMessage(getTimestamp() + "SHUTDOWN REQUEST: '" + username + "' requested server shutdown");
    
    // Authenticate user (admin or sudo with password)
    if(!authenticateSudoCommand(client_socket, username, is_sudo_command, "/shutdown")) {
        return true;  // Authentication failed, rejection already sent
    }
    
    logMessage(getTimestamp() + "SHUTDOWN: Admin privileges confirmed");
    logMessage(getTimestamp() + "SHUTDOWN: Shutting down server");
    
    // Record who initiated shutdown
    {
        std::lock_guard<std::mutex> lock(shutdown_mutex);
        shutdown_initiator = username;
    }
    
    // Send confirmation to requester
    std::string conf = buildMessage(MessageHeader::RESPONSE, "Server shutdown initiated.");
    send(client_socket, conf.c_str(), conf.length(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Notify all clients
    std::string shutdown_notification = buildMessage(MessageHeader::SHUTDOWN, SERVER_NAME);
    broadcast(shutdown_notification.c_str(), username);
    
    server_running = false;
    return false;  // Break client loop
}

/**
 * @brief Handle a client's help request and return the appropriate help text.
 *
 * Sends admin or client help text depending on the user's registered
 * admin status.
 *
 * @param client_socket Socket descriptor for the client
 * @param username The username requesting help
 * @return true to continue processing the client's message loop
 */
inline bool handleHelpRequest(int client_socket, const std::string& username) {
    logMessage(getTimestamp() + "HELP REQUEST: Client '" + username + "' requested help");
    
    bool user_is_admin = isAdmin(username);
    
    std::string help_text = user_is_admin ? getAdminHelpText() : getClientHelpText();
    std::string help_msg = buildMessage(MessageHeader::RESPONSE, help_text);
    send(client_socket, help_msg.c_str(), help_msg.length(), 0);
    return true;
}

/**
 * @brief Handle a client's request for the list of connected users.
 *
 * Gathers the connected usernames and their roles (server/admin/client)
 * and returns the information to the requesting client.
 *
 * @param client_socket Socket descriptor for the client
 * @param username The username requesting the list
 * @return true to continue processing the client's message loop
 */
inline bool handleListRequest(int client_socket, const std::string& username) {
    logMessage(getTimestamp() + "LIST REQUEST: Client '" + username + "' requested user list");
    
    std::vector<std::string> all_usernames;
    std::unordered_set<std::string> all_admins;
    
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        all_usernames.push_back(SERVER_NAME);
        for(const auto& pair : client_sockets) {
            if(pair.first != SERVER_NAME) {
                all_usernames.push_back(pair.first);
            }
        }
    }
    
    // Build admin set: registered admins + session admins
    {
        std::lock_guard<std::mutex> admin_lock(admin_mutex);
        // Add registered admins from JSON
        auto admins = AdminConfig::getList();
        all_admins.insert(AdminConfig::ROOT_USERNAME);  // Always include root
        for(const auto& admin : admins) {
            all_admins.insert(admin.first);
        }
        // Add session admins
        all_admins.insert(session_admins.begin(), session_admins.end());
    }
    
    std::string list_msg = buildListResponse(all_usernames, all_admins, SERVER_NAME);
    send(client_socket, list_msg.c_str(), list_msg.length(), 0);
    return true;
}

/**
 * @brief Handle a request to disconnect specific client sessions (/close).
 *
 * Requires admin or sudo authentication and attempts to disconnect each
 * specified username. Returns a confirmation to the requester listing any
 * failures.
 *
 * @param client_socket Socket descriptor for the client issuing the request
 * @param buffer Raw message buffer containing the close request
 * @param username The username issuing the request
 * @param is_sudo_command True if command was wrapped with [SUDO]
 * @return true to continue processing the client's message loop
 */
inline bool handleCloseRequest(int client_socket, const char* buffer, const std::string& username, bool is_sudo_command = false) {
    std::string full_msg(buffer);
    size_t user_pos = full_msg.find(buildMessage(MessageHeader::USER, ""));
    
    // Authenticate user (admin or sudo with password)
    if(!authenticateSudoCommand(client_socket, username, is_sudo_command, "/close")) {
        return true;  // Authentication failed, rejection already sent
    }
    
    // Extract usernames and process close request
    if(user_pos != std::string::npos) {
        std::string usernames_str = full_msg.substr(user_pos + HEADER_LENGTH);
        
        // Parse comma-separated usernames
        std::vector<std::string> usernames;
        std::stringstream ss(usernames_str);
        std::string single_username;
        while(std::getline(ss, single_username, ',')) {
            // Trim whitespace
            single_username.erase(0, single_username.find_first_not_of(" \t"));
            single_username.erase(single_username.find_last_not_of(" \t") + 1);
            if(!single_username.empty()) {
                usernames.push_back(single_username);
            }
        }
        
        // Check if usernames list is empty
        if(usernames.empty()) {
            std::string denial = buildMessage(MessageHeader::REJECT, "No usernames provided. " + getCommandUsage("/close <username1,username2...>"));
            send(client_socket, denial.c_str(), denial.length(), 0);
            return true;
        }
        
        logMessage(getTimestamp() + "CLOSE REQUEST: '" + username + "' requested to close: " + usernames_str);
        
        // Close each specified client
        int closed_count = 0;
        std::vector<std::string> failed_users;
        
        for(const auto& user_to_close : usernames) {
            int target_socket = getSocketForUser(user_to_close);
            if(target_socket > 0 && user_to_close != SERVER_NAME) {
                logMessage(getTimestamp() + "CLOSE ACTION: '" + username + "' is closing '" + user_to_close + "'");
                
                // Send disconnect notification to target client
                std::string disconnect_msg = buildMessage(MessageHeader::KICK, username);
                send(target_socket, disconnect_msg.c_str(), disconnect_msg.length(), 0);
                
                // Remove from tracking maps FIRST (before broadcast)
                // This prevents the handle_client thread from broadcasting another LEAVE
                {
                    std::lock_guard<std::mutex> lock(clients_mutex);
                    client_sockets.erase(user_to_close);
                    client_last_activity.erase(user_to_close);
                }
                
                // Notify other users about this disconnection AFTER removing from map
                std::string leave_notification = buildMessage(MessageHeader::LEAVE, user_to_close);
                broadcast(leave_notification.c_str(), user_to_close);
                
                close(target_socket);
                closed_count++;
            } else {
                failed_users.push_back(user_to_close);
            }
        }
        
        // Send confirmation back to requester
        std::string confirmation = buildCloseConfirmationMessage(closed_count, failed_users);
        send(client_socket, confirmation.c_str(), confirmation.length(), 0);
    }
    return true;
}

/**
 * @brief Handle a request to disconnect all client sessions (/closeall).
 *
 * Requires admin or sudo authentication. Notifies and disconnects all
 * connected client sessions (except the server itself) and returns control
 * to the caller indicating whether the requester should be disconnected.
 *
 * @param client_socket Socket descriptor for the client issuing the request
 * @param buffer Raw message buffer containing the closeall request
 * @param username The username issuing the request
 * @param is_sudo_command True if command was wrapped with [SUDO]
 * @return false to indicate the client's handler should be terminated
 */
inline bool handleCloseAllRequest(int client_socket, const char* buffer, const std::string& username, bool is_sudo_command = false) {
    std::string full_msg(buffer);
    std::string rest_of_msg = full_msg.substr(HEADER_LENGTH);
    
    // Check if there are extra arguments
    size_t first_bracket = rest_of_msg.find('[');
    std::string potential_args = (first_bracket != std::string::npos) ? 
                                rest_of_msg.substr(0, first_bracket) : rest_of_msg;
    
    // Format: [CARQ]username - check if there's anything beyond username
    if(!potential_args.empty() && potential_args != username) {
        std::string denial = buildMessage(MessageHeader::REJECT, 
            "Command /closeall does not accept arguments. " + getCommandUsage("/closeall"));
        send(client_socket, denial.c_str(), denial.length(), 0);
        return true;
    }
    
    logMessage(getTimestamp() + "CLOSEALL REQUEST: '" + username + "' requested to close all client sessions");
    
    // Authenticate user (admin or sudo with password)
    if(!authenticateSudoCommand(client_socket, username, is_sudo_command, "/closeall")) {
        return true;  // Authentication failed, rejection already sent
    }
    
    logMessage("Admin privileges confirmed");
    
    std::vector<std::string> clients_to_close;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for(const auto& pair : client_sockets) {
            // Don't close the server, but DO include the requester
            if(pair.first != SERVER_NAME) {
                clients_to_close.push_back(pair.first);
            }
        }
    }
    
    // Send confirmation back to requester first (before closing them)
    std::string confirmation = "All client sessions closed (" + 
                        std::to_string(clients_to_close.size()) + " clients)";
    std::string conf_msg = buildMessage(MessageHeader::RESPONSE, confirmation);
    send(client_socket, conf_msg.c_str(), conf_msg.length(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Close each client
    for(const auto& user_to_close : clients_to_close) {
        int target_socket = getSocketForUser(user_to_close);
        if(target_socket > 0) {
            // Send disconnect notification to target client
            std::string disconnect_msg = buildMessage(MessageHeader::KICK, username);
            send(target_socket, disconnect_msg.c_str(), disconnect_msg.length(), 0);
            
            // Remove from tracking maps FIRST (before broadcast)
            // This prevents the handle_client thread from broadcasting another LEAVE
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                client_sockets.erase(user_to_close);
                client_last_activity.erase(user_to_close);
            }
            
            // Notify remaining users about this disconnection AFTER removing from map
            std::string leave_notification = buildMessage(MessageHeader::LEAVE, user_to_close);
            broadcast(leave_notification.c_str(), user_to_close);
            
            close(target_socket);
        }
    }
    
    return false;  // Break client loop (requester was closed)
}

/**
 * @brief Process a MSG message that delivers a direct message to recipients.
 *
 * Parses the msg payload, validates recipients and message content,
 * logs the send action (without exposing private content in server logs
 * beyond configured policy), and returns a confirmation to the sender.
 *
 * @param client_socket Socket descriptor for the sending client
 * @param buffer Raw protocol buffer containing the MSG message
 * @return true to continue processing the client's message loop
 */
inline bool handleMsg(int client_socket, const char* buffer) {
    std::string sender;
    std::vector<std::string> recipients;
    std::string message;
    
    if(parseMsgMessage(buffer, sender, recipients, message)) {
        // Check if recipients or message is empty
        if(recipients.empty() || message.empty()) {
            std::string denial = buildMessage(MessageHeader::REJECT, 
                "Invalid msg format. " + getCommandUsage("/msg <username1,username2,...> <message>"));
            send(client_socket, denial.c_str(), denial.length(), 0);
            return true;
        }
        
        // Build recipients list for logging
        std::string recipients_str;
        for(size_t i = 0; i < recipients.size(); i++) {
            if(i > 0) recipients_str += ", ";
            recipients_str += recipients[i];
        }
        logMessage(getTimestamp() + "MSG: '" + sender + "' sending to [" + recipients_str + "]: " + message);
        
        std::string msg_to_send = buildUserMessage(sender, message);
        
        int success_count = 0;
        std::vector<std::string> failed_users;
        
        // Attempt to send to each recipient
        for(const auto& recipient : recipients) {
            int recipient_socket = getSocketForUser(recipient);
            if(recipient_socket > 0) {
                send(recipient_socket, msg_to_send.c_str(), msg_to_send.length(), 0);
                success_count++;
            } else {
                failed_users.push_back(recipient);
            }
        }
        
        // Send confirmation back to sender
        std::string confirmation = buildConfirmationMessage(success_count, failed_users);
        send(client_socket, confirmation.c_str(), confirmation.length(), 0);
    } else {
        // Parse failed - malformed message
        std::string denial = buildMessage(MessageHeader::REJECT, 
            "Malformed msg message. " + getCommandUsage("/msg <username1,username2,...> <message>"));
        send(client_socket, denial.c_str(), denial.length(), 0);
    }
    return true;
}

/**
 * @brief Handle a regular user chat message (USER header).
 *
 * Detects attempted commands in user messages and rejects unknown
 * commands. Otherwise broadcasts the message to other clients and logs
 * the chat event according to logging policy.
 *
 * @param client_socket Socket descriptor for the sender
 * @param buffer Raw protocol buffer containing the user message
 * @param username Username of the sender
 * @return true to continue processing the client's message loop
 */
inline bool handleUserMessage(int client_socket, const char* buffer, const std::string& username) {
    // Regular message - check if it looks like a command attempt
    std::string full_msg(buffer + HEADER_LENGTH);
    size_t mesg_pos = full_msg.find(headerToString(MessageHeader::MESSAGE));
    
    if(mesg_pos != std::string::npos) {
        std::string msg_content = full_msg.substr(mesg_pos + HEADER_LENGTH);
        
        // Check if message starts with COMMAND_PREFIX (looks like a command)
        if(!msg_content.empty() && msg_content[0] == COMMAND_PREFIX) {
            // Extract potential command
            size_t space_pos = msg_content.find(' ');
            std::string potential_cmd = (space_pos != std::string::npos) ? 
                                       msg_content.substr(0, space_pos) : msg_content;
            
            // Check if it's actually an unknown command
            Command cmd = parseCommand(potential_cmd);
            if(cmd == Command::UNKNOWN) {
                // Log to server terminal
                logMessage(getTimestamp() + "UNKNOWN COMMAND: '" + username + "' attempted: " + msg_content);
                
                // Send error message back to sender
                std::string error_msg = buildMessage(MessageHeader::REJECT, 
                    "Unknown command: " + potential_cmd + ". Type " + 
                    commandToString(Command::HELP) + " for available commands.");
                send(client_socket, error_msg.c_str(), error_msg.length(), 0);
                return true;  // Don't broadcast unknown commands
            }
        }
    }
    
    // Regular message - broadcast to all other clients
    // Log the chat message (msg_content already extracted above)
    if(mesg_pos != std::string::npos) {
        std::string msg_content = full_msg.substr(mesg_pos + HEADER_LENGTH);
        logMessage(getTimestamp() + "CHAT: '" + username + "' sent message: " + msg_content);
    }
    
    broadcast(buffer, username);
    return true;
}

#endif // SERVER_MESSAGE_HANDLERS_HPP
