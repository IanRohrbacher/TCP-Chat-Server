/*
 * server_command_handler.hpp
 * 
 * Server console command processor.
 * Handles commands entered by the server operator for administration and control.
 */

#ifndef SERVER_COMMAND_HANDLER_HPP
#define SERVER_COMMAND_HANDLER_HPP

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <sys/socket.h>
#include <unistd.h>
#include "../common/common.hpp"
#include "server_utils.hpp"
#include "server_message_handlers.hpp"

// External references to global state (defined in server.cpp)
extern std::string SERVER_NAME;
extern std::unordered_map<std::string, int> client_sockets;
extern std::mutex clients_mutex;
extern std::unordered_set<std::string> session_admins;
extern std::mutex admin_mutex;
extern std::atomic<bool> server_running;
extern std::atomic<int> server_timeout_minutes;
extern std::atomic<int> server_idle_timeout_minutes;
extern std::string shutdown_initiator;
extern std::mutex shutdown_mutex;
extern std::atomic<bool> console_logging_enabled;
extern std::mutex console_output_mutex;

/**
 * @brief Handle the /msg command entered on the server console.
 *
 * Parses the console arguments to identify recipients (comma-separated)
 * and the message text, validates that recipients are currently
 * connected, and delivers the message by calling `unicast` or
 * `multicast` as appropriate.
 *
 * @param rest The command arguments following "/msg" (format: "user1,user2 message text")
 *
 * @note Invalid or offline recipients are skipped and an operator-facing
 *       message is printed to the console. This helper is intended for
 *       interactive operator use and logs actions via `logMessage`.
 */
inline void handleMsgCommand(const std::string& rest) {
    size_t space_pos = rest.find(' ');
    
    if(space_pos == std::string::npos) {
        std::string usage = getCommandUsage("/msg");
        std::cout << usage << "\n";
        logMessage(getTimestamp() + "CONSOLE: show usage for /msg");
        return;
    }
    
    std::string usernames_str = rest.substr(0, space_pos);
    std::string message = rest.substr(space_pos + 1);
    std::vector<std::string> usernames = parseUsernames(usernames_str);
    
    std::string server_msg = buildUserMessage(SERVER_NAME, message);
    
    // Validate each username and collect valid ones
    std::vector<std::string> valid_users;
    for(const std::string& username : usernames) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if(client_sockets.find(username) != client_sockets.end() && 
           username != SERVER_NAME) {
            valid_users.push_back(username);
        } else {
            logMessage(getTimestamp() + "CONSOLE MSG: User '" + username + "' not found");
        }
    }
    
    // Send message using appropriate method based on recipient count
    if(valid_users.size() == 1) {
        unicast(server_msg.c_str(), valid_users[0], SERVER_NAME);
        logMessage(getTimestamp() + "CONSOLE MSG: Message sent to '" + valid_users[0] + "'");
    } else if(valid_users.size() > 1) {
        multicast(server_msg.c_str(), valid_users, SERVER_NAME);
        logMessage(getTimestamp() + "CONSOLE MSG: Message sent to " + std::to_string(valid_users.size()) + " client(s)");
    }
}

/**
 * @brief Handle the /close command to disconnect specific clients.
 *
 * Attempts to find each named user and gracefully close their socket.
 * The function removes the user from server tracking maps before
 * notifying other clients to avoid double-broadcasting LEAVE events.
 *
 * @param usernames_str Comma-separated list of usernames to disconnect
 *
 * @note Root/server username is never closed by this operation.
 */
inline void handleCloseCommand(const std::string& usernames_str) {
    std::vector<std::string> usernames = parseUsernames(usernames_str);
    int closed_count = 0;
    
    for(const std::string& username : usernames) {
        int user_socket;
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            auto it = client_sockets.find(username);
            if(it != client_sockets.end() && username != SERVER_NAME) {
                user_socket = it->second;
            } else {
                logMessage(getTimestamp() + "CONSOLE: User '" + username + "' not found");
                continue;
            }
        }
        
        // Notify client of disconnect
        std::string disconnect_msg = buildMessage(MessageHeader::KICK, SERVER_NAME);
        send(user_socket, disconnect_msg.c_str(), disconnect_msg.length(), 0);
        
        // Give client time to receive the message
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        // Close the connection
        shutdown(user_socket, SHUT_RDWR);
        close(user_socket);
        
        logMessage(getTimestamp() + "CONSOLE CLOSE: Closed connection for user '" + username + "'");
        closed_count++;
    }
    
    if(closed_count > 0) {
        logMessage(getTimestamp() + "CONSOLE: Closed " + std::to_string(closed_count) + " client connection(s)");
    }
}

/**
 * @brief Handle the /closeall command to disconnect all client sessions.
 *
 * Notifies connected clients and closes their sockets. The server
 * process remains running. This operation requires admin privileges when
 * invoked from network clients; when invoked interactively from the
 * console it is performed immediately.
 *
 * @note The server username is not closed. The function removes clients
 *       from internal maps before broadcasting LEAVE notifications.
 */
inline void handleCloseAllCommand() {
    std::vector<std::string> usernames_to_close;

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for(const auto& pair : client_sockets) {
            if(pair.first != SERVER_NAME) {
                usernames_to_close.push_back(pair.first);
            }
        }
    }

    if(usernames_to_close.empty()) {
        logMessage(getTimestamp() + "CONSOLE: No clients connected to close");
        return;
    }

    // Notify all clients they're being disconnected
    std::string disconnect_msg = buildMessage(MessageHeader::KICK, SERVER_NAME);
    for(const auto& username : usernames_to_close) {
        int user_socket = getSocketForUser(username);
        if(user_socket > 0) {
            send(user_socket, disconnect_msg.c_str(), disconnect_msg.length(), 0);
        }
    }

    // Give clients time to receive notification
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Close all connections
    for(const auto& username : usernames_to_close) {
        int user_socket = getSocketForUser(username);
        if(user_socket > 0) {
            shutdown(user_socket, SHUT_RDWR);
            close(user_socket);
        }
    }

    logMessage(getTimestamp() + "CONSOLE CLOSEALL: Closed all " + std::to_string(usernames_to_close.size()) + " client connection(s)");
}

/**
 * @brief Prompt the local console operator for the admin/root password.
 *
 * Reads a password line from stdin (echo enabled) and compares it to the
 * persisted root password from AdminConfig. Logs attempts and does not
 * write the password itself to any logs. Returns true on successful
 * authentication, false after exhausting attempts.
 *
 * @param prompt Prompt text to display (e.g. "Password: ")
 * @param max_attempts Number of allowed attempts (default 3)
 * @return true if entered password matches root password, false otherwise
 */
inline bool consoleRequestAndValidatePassword(const std::string& prompt, int max_attempts = 3) {
    // Suppress console logging to avoid interleaving other log output while prompting
    console_logging_enabled.store(false);
    for(int attempt = 1; attempt <= max_attempts; ++attempt) {
        std::string pw;
        {
            std::lock_guard<std::mutex> cout_lock(console_output_mutex);
            std::cout << prompt;
            // Ensure prompt is flushed before reading
            std::cout.flush();
        }
        std::getline(std::cin, pw);

        // Trim whitespace
        size_t s = pw.find_first_not_of(" \t\n\r");
        size_t e = pw.find_last_not_of(" \t\n\r");
        if(s == std::string::npos) pw = ""; else pw = pw.substr(s, e - s + 1);

        if(pw == AdminConfig::getRootPassword()) {
            logMessage(getTimestamp() + "CONSOLE SUDO: Password accepted");
            console_logging_enabled.store(true);
            return true;
        }

        logMessage(getTimestamp() + "CONSOLE SUDO: Invalid password attempt " + std::to_string(attempt));
    }

    logMessage(getTimestamp() + "CONSOLE SUDO: Access denied after failed password attempts");
    console_logging_enabled.store(true);
    return false;
}

/**
 * @brief Parse and execute a single server-console command string.
 *
 * Recognizes administrative console commands (help, list, close, msg,
 * shutdown, whitelist, admin, timeout, etc.) and dispatches them to the
 * corresponding helper functions. Operator-visible output is written to
 * stdout and operator actions are logged via `logMessage`.
 *
 * @param input The full command string entered by the server operator
 *
 * @note This function runs in the console command thread and must not
 *       block for long periods; helpers that perform blocking I/O should
 *       delegate to other threads when appropriate.
 */
inline void handleServerCommand(const std::string& input) {
    if(input.empty()) return;

    // Only handle inputs that start with the command prefix.
    if(input[0] != COMMAND_PREFIX) {
        std::cout << "Command '" << input << "' not found. Try /help for available commands.\n";
        logMessage(getTimestamp() + std::string("CONSOLE: Unknown command entered by operator: '") + input + "'");
        return;
    }

    // Parse command enum and extract arguments (text after the command name)
    Command cmd = parseCommand(input);
    std::string cmd_input = input.substr(1); // remove prefix
    size_t space_pos = cmd_input.find(' ');
    std::string args = (space_pos == std::string::npos) ? "" : cmd_input.substr(space_pos + 1);

    switch(cmd) {
        case Command::BROADCAST:
            if(!args.empty()) {
                std::string server_msg = buildUserMessage(SERVER_NAME, args);
                broadcast(server_msg.c_str(), SERVER_NAME);
                logMessage(getTimestamp() + "CONSOLE BROADCAST: Broadcast sent to all clients");
            } else {
                std::cout << getCommandUsage("/broadcast") << "\n";
                logMessage(getTimestamp() + "CONSOLE: show usage for /broadcast");
            }
            break;

        case Command::MSG:
            if(!args.empty()) {
                handleMsgCommand(args);
            } else {
                std::cout << getCommandUsage("/msg") << "\n";
                logMessage(getTimestamp() + "CONSOLE: show usage for /msg");
            }
            break;

        case Command::CLOSEALL:
            handleCloseAllCommand();
            break;

        case Command::CLOSE:
            if(!args.empty()) {
                handleCloseCommand(args);
            } else {
                std::cout << getCommandUsage("/close") << "\n";
                logMessage(getTimestamp() + "CONSOLE: show usage for /close");
            }
            break;

        case Command::TIMEOUT:
            if(!args.empty()) {
                try {
                    int minutes = std::stoi(args);
                    if(minutes >= 0) {
                        int old_timeout = server_timeout_minutes.load();
                        server_timeout_minutes = minutes;
                        if(minutes == 0) {
                            logMessage(getTimestamp() + "CONSOLE TIMEOUT: Client inactivity timeout disabled (was " + std::to_string(old_timeout) + " minutes)");
                        } else {
                            logMessage(getTimestamp() + "CONSOLE TIMEOUT: Client inactivity timeout set to " + std::to_string(minutes) + " minute(s) (was " + std::to_string(old_timeout) + " minutes)");
                        }
                    } else {
                        std::cout << "Timeout must be 0 or a positive number. " << getCommandUsage("/timeout <minutes>") << "\n";
                        logMessage(getTimestamp() + "CONSOLE TIMEOUT: Operator provided invalid timeout value (must be >=0)");
                    }
                } catch(...) {
                    std::cout << "Invalid timeout value. " << getCommandUsage("/timeout <minutes>") << "\n";
                    logMessage(getTimestamp() + "CONSOLE TIMEOUT: Operator provided non-numeric timeout value");
                }
            } else {
                logMessage(getTimestamp() + "CONSOLE TIMEOUT: Queried client timeout setting (" + std::to_string(server_timeout_minutes.load()) + " minutes)");
                std::cout << getCommandUsage("/timeout") << "\n";
                std::string current = "Current client timeout: " + std::to_string(server_timeout_minutes.load()) + " minute(s) ";
                if(server_timeout_minutes == 0) current += "(disabled)";
                std::cout << current << "\n";
                logMessage(getTimestamp() + "CONSOLE TIMEOUT: " + current);
            }
            break;

        case Command::SUDO_HELP:
            // Prompt local operator for password before showing sudo/admin help
            if(consoleRequestAndValidatePassword("Password: ")) {
                {
                    std::lock_guard<std::mutex> cout_lock(console_output_mutex);
                    std::cout << getAdminHelpText();
                    std::cout.flush();
                }
                logMessage(getTimestamp() + "CONSOLE SUDO HELP: Displayed admin help to operator");
            } else {
                std::cout << "Access denied.\n";
            }
            break;

        case Command::SUDO_SU: {
            // Require password and then grant session admin to the named user
            // Usage: /sudo su <username>
            std::string target = args;
            // Trim whitespace
            size_t s = target.find_first_not_of(" \t\n\r");
            size_t e = target.find_last_not_of(" \t\n\r");
            if(s == std::string::npos) target = ""; else target = target.substr(s, e - s + 1);

            if(target.empty()) {
                std::cout << "Usage: /sudo su <username>\n";
                logMessage(getTimestamp() + "CONSOLE SUDO SU: Missing target username");
                break;
            }

            // Verify the target user exists (must be connected)
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                if(client_sockets.find(target) == client_sockets.end()) {
                    std::cout << "User '" << target << "' is not connected. Cannot grant session admin.\n";
                    logMessage(getTimestamp() + "CONSOLE SUDO SU: Attempted to grant admin to unknown user '" + target + "'");
                    break;
                }
            }

            if(consoleRequestAndValidatePassword("Password: ")) {
                addSessionAdmin(target);
                std::cout << "Granted session admin to '" << target << "'.\n";
                logMessage(getTimestamp() + "CONSOLE SUDO SU: Granted session admin to '" + target + "'");
            } else {
                std::cout << "Access denied.\n";
            }
        }
        break;

        case Command::SUDO: {
            // Generic sudo wrapper: run an admin command from args without password
            // args format: <inner_command> [inner_args...]
            std::string sudo_rest = args;
            // Trim leading whitespace
            size_t start = sudo_rest.find_first_not_of(" \t\n\r");
            if(start == std::string::npos) {
                // No inner command provided - show sudo help
                displaySudoCommands();
                break;
            }
            sudo_rest = sudo_rest.substr(start);

            // Prompt the local operator for password before executing sudo-wrapped commands
            if(!consoleRequestAndValidatePassword("Password: ")) {
                std::cout << "Access denied.\n";
                break;
            }

            size_t space_pos_inner = sudo_rest.find(' ');
            std::string inner_cmd_token = (space_pos_inner == std::string::npos) ? sudo_rest : sudo_rest.substr(0, space_pos_inner);
            std::string inner_args = (space_pos_inner == std::string::npos) ? "" : sudo_rest.substr(space_pos_inner + 1);

            Command inner_cmd = stringToCommand(inner_cmd_token);

            switch(inner_cmd) {
                case Command::CLOSE:
                    if(!inner_args.empty()) handleCloseCommand(inner_args);
                    else std::cout << getCommandUsage("/close") << "\n";
                    break;

                case Command::CLOSEALL:
                    handleCloseAllCommand();
                    break;

                case Command::SHUTDOWN:
                    // Console-level shutdown: same as normal shutdown
                    logMessage(getTimestamp() + "CONSOLE SUDO: executing shutdown via /sudo");
                    logMessage(getTimestamp() + "CONSOLE SHUTDOWN: Server shutdown initiated from console (sudo)");
                    {
                        std::lock_guard<std::mutex> lock(shutdown_mutex);
                        shutdown_initiator = "server console (sudo)";
                    }
                    server_running = false;
                    break;

                case Command::TIMEOUT:
                    if(!inner_args.empty()) {
                        try {
                            int minutes = std::stoi(inner_args);
                            server_timeout_minutes = minutes;
                            logMessage(getTimestamp() + "CONSOLE SUDO TIMEOUT: set to " + std::to_string(minutes));
                        } catch(...) {
                            std::cout << "Invalid timeout value. " << getCommandUsage("/timeout <minutes>") << "\n";
                        }
                    } else {
                        std::cout << getCommandUsage("/timeout") << "\n";
                    }
                    break;

                case Command::SERVERTIMEOUT:
                    if(!inner_args.empty()) {
                        try {
                            int minutes = std::stoi(inner_args);
                            server_idle_timeout_minutes = minutes;
                            updateServerActivity();
                            logMessage(getTimestamp() + "CONSOLE SUDO SERVERTIMEOUT: set to " + std::to_string(minutes));
                        } catch(...) {
                            std::cout << "Invalid timeout value. " << getCommandUsage("/servertimeout <minutes>") << "\n";
                        }
                    } else {
                        std::cout << getCommandUsage("/servertimeout") << "\n";
                    }
                    break;

                case Command::WHITELIST:
                    // Delegate to whitelist logic via existing handlers where possible
                    if(inner_args.empty()) {
                        logMessage(getTimestamp() + "CONSOLE SUDO: Queried whitelist status");
                        std::cout << WhitelistConfig::getStatus();
                    } else {
                        // Reuse the same parsing logic as normal /whitelist handling
                        // We'll call the same blocks used in the non-sudo path by setting args
                        // and reusing the existing case above: simply call handleServerCommand on a constructed string
                        handleServerCommand(std::string(1, COMMAND_PREFIX) + std::string("whitelist ") + inner_args);
                    }
                    break;

                case Command::ADMIN:
                    if(inner_args.empty()) {
                        std::cout << AdminConfig::getStatus();
                    } else {
                        handleServerCommand(std::string(1, COMMAND_PREFIX) + std::string("admin ") + inner_args);
                    }
                    break;

                default:
                    // Unknown inner command - show sudo help
                    displaySudoCommands();
                    break;
            }
        }
        break;

        case Command::SERVERTIMEOUT:
            if(!args.empty()) {
                try {
                    int minutes = std::stoi(args);
                    if(minutes >= 0) {
                        int old_timeout = server_idle_timeout_minutes.load();
                        server_idle_timeout_minutes = minutes;
                        if(minutes == 0) {
                            logMessage(getTimestamp() + "CONSOLE SERVERTIMEOUT: Server inactivity timeout disabled (was " + std::to_string(old_timeout) + " minutes)");
                        } else {
                            logMessage(getTimestamp() + "CONSOLE SERVERTIMEOUT: Server inactivity timeout set to " + std::to_string(minutes) + " minute(s) (was " + std::to_string(old_timeout) + " minutes)");
                        }
                        updateServerActivity();
                    } else {
                        std::cout << "Timeout must be 0 or a positive number. " << getCommandUsage("/servertimeout <minutes>") << "\n";
                        logMessage(getTimestamp() + "CONSOLE SERVERTIMEOUT: Operator provided invalid timeout value (must be >=0)");
                    }
                } catch(...) {
                    std::cout << "Invalid timeout value. " << getCommandUsage("/servertimeout <minutes>") << "\n";
                    logMessage(getTimestamp() + "CONSOLE SERVERTIMEOUT: Operator provided non-numeric timeout value");
                }
            } else {
                logMessage(getTimestamp() + "CONSOLE SERVERTIMEOUT: Queried server timeout setting (" + std::to_string(server_idle_timeout_minutes.load()) + " minutes)");
                std::cout << getCommandUsage("/servertimeout") << "\n";
                std::string current = "Current server timeout: " + std::to_string(server_idle_timeout_minutes.load()) + " minute(s) ";
                if(server_idle_timeout_minutes == 0) current += "(disabled)";
                std::cout << current << "\n";
                logMessage(getTimestamp() + "CONSOLE SERVERTIMEOUT: " + current);
            }
            break;

        case Command::WHITELIST: {
            // args may be empty or contain subcommands (add/remove/clear/true|false)
            std::string sub = args;
            // trim
            size_t s = sub.find_first_not_of(" \t\n\r");
            size_t e = sub.find_last_not_of(" \t\n\r");
            if(s == std::string::npos) sub = ""; else sub = sub.substr(s, e - s + 1);

            if(sub.empty()) {
                logMessage(getTimestamp() + "CONSOLE WHITELIST: Queried whitelist status");
                std::string status = WhitelistConfig::getStatus();
                std::cout << status;
                logMessage(getTimestamp() + "CONSOLE WHITELIST: " + status);
            } else if(sub == "true" || sub == "false" || sub == "1" || sub == "0") {
                bool enable = (sub == "true" || sub == "1");
                if(WhitelistConfig::setEnabled(enable)) {
                    logMessage(getTimestamp() + "CONSOLE WHITELIST: Whitelist mode " + (enable ? std::string("enabled") : std::string("disabled")));
                } else {
                    std::cout << "Failed to save whitelist configuration.\n";
                    logMessage(getTimestamp() + "ERROR: Failed to save whitelist configuration (console operator)");
                }
            } else if(sub.rfind("add ", 0) == 0) {
                std::string users_str = sub.substr(4);
                std::vector<std::pair<std::string, std::string>> users_to_add;
                std::istringstream iss(users_str);
                std::string user, pass;
                while(iss >> user >> pass) users_to_add.push_back({user, pass});
                if(users_to_add.empty()) {
                    std::cout << "Invalid syntax. " << getCommandUsage("/whitelist add <user> <pass> [<user> <pass> ...]") << "\n";
                    logMessage(getTimestamp() + "CONSOLE WHITELIST: Invalid syntax for add command");
                } else {
                    int added = WhitelistConfig::add(users_to_add);
                    logMessage(getTimestamp() + "CONSOLE WHITELIST ADD: Added " + std::to_string(added) + " user(s) to whitelist");
                    if(added < (int)users_to_add.size()) {
                        std::cout << "(Skipped " << (users_to_add.size() - added) << " duplicate(s))\n";
                        logMessage(getTimestamp() + "CONSOLE WHITELIST: Some users were skipped when adding (duplicates)");
                    }
                }
            } else if(sub.rfind("remove ", 0) == 0) {
                std::string users_str = sub.substr(7);
                std::vector<std::string> users_to_remove;
                std::istringstream iss(users_str);
                std::string user;
                while(iss >> user) users_to_remove.push_back(user);
                if(users_to_remove.empty()) {
                    std::cout << "Invalid syntax. " << getCommandUsage("/whitelist remove <user> [<user> ...]") << "\n";
                    logMessage(getTimestamp() + "CONSOLE WHITELIST: Invalid syntax for remove command");
                } else {
                    int removed = WhitelistConfig::remove(users_to_remove);
                    logMessage(getTimestamp() + "CONSOLE WHITELIST REMOVE: Removed " + std::to_string(removed) + " user(s) from whitelist");
                    if(removed == 0) {
                        std::cout << "No matching users found in whitelist.\n";
                        logMessage(getTimestamp() + "CONSOLE WHITELIST: Remove command found no matching users");
                    }
                }
            } else if(sub == "clear") {
                int cleared = WhitelistConfig::clear();
                logMessage(getTimestamp() + "CONSOLE WHITELIST CLEAR: Cleared " + std::to_string(cleared) + " user(s) from whitelist");
                if(cleared == 0) {
                    std::cout << "No users to clear from whitelist.\n";
                    logMessage(getTimestamp() + "CONSOLE WHITELIST: Clear command found no users to clear");
                }
            } else {
                std::cout << "Invalid whitelist command. Usage:\n";
                std::cout << getCommandUsage("/whitelist") << "\n";
                std::cout << getCommandUsage("/whitelist <true|false>") << "\n";
                std::cout << getCommandUsage("/whitelist add <user> <pass> [<user> <pass> ...]") << "\n";
                std::cout << getCommandUsage("/whitelist remove <user> [<user> ...]") << "\n";
                std::cout << getCommandUsage("/whitelist clear") << "\n";
                logMessage(getTimestamp() + "CONSOLE WHITELIST: Invalid subcommand used by operator");
            }
        }
        break;

        case Command::ADMIN: {
            std::string sub = args;
            size_t s = sub.find_first_not_of(" \t\n\r");
            size_t e = sub.find_last_not_of(" \t\n\r");
            if(s == std::string::npos) sub = ""; else sub = sub.substr(s, e - s + 1);

            if(sub.empty()) {
                logMessage(getTimestamp() + "CONSOLE ADMIN: Queried admin status");
                std::cout << AdminConfig::getStatus();
                logMessage(getTimestamp() + "CONSOLE ADMIN: " + AdminConfig::getStatus());
            }
            else if(sub.rfind("add ", 0) == 0) {
                std::string users_str = sub.substr(4);
                std::vector<std::pair<std::string, std::string>> admins_to_add;
                std::istringstream iss(users_str);
                std::string user, pass;
                while(iss >> user >> pass) admins_to_add.push_back({user, pass});
                if(admins_to_add.empty()) {
                    std::cout << "Invalid syntax. " << getCommandUsage("/admin add <user> <pass> [<user> <pass> ...]") << "\n";
                    logMessage(getTimestamp() + "CONSOLE ADMIN: Invalid syntax for add command");
                } else {
                    int added = AdminConfig::add(admins_to_add);
                    logMessage(getTimestamp() + "CONSOLE ADMIN ADD: Added " + std::to_string(added) + " admin(s)");
                    if(added < (int)admins_to_add.size()) {
                        std::cout << "(Skipped " << (admins_to_add.size() - added) << " duplicate(s) or reserved username)\n";
                        logMessage(getTimestamp() + "CONSOLE ADMIN: Some admins were skipped when adding (duplicates/reserved)");
                    }
                }
            }
            else if(sub.rfind("remove ", 0) == 0) {
                std::string users_str = sub.substr(7);
                std::vector<std::string> admins_to_remove;
                std::istringstream iss(users_str);
                std::string user;
                while(iss >> user) admins_to_remove.push_back(user);
                if(admins_to_remove.empty()) {
                    std::cout << "Invalid syntax. " << getCommandUsage("/admin remove <user> [<user> ...]") << "\n";
                    logMessage(getTimestamp() + "CONSOLE ADMIN: Invalid syntax for remove command");
                } else {
                    int removed = AdminConfig::remove(admins_to_remove);
                    logMessage(getTimestamp() + "CONSOLE ADMIN REMOVE: Removed " + std::to_string(removed) + " admin(s)");
                    if(removed == 0) {
                        std::cout << "No matching admins found (or attempted to remove root).\n";
                        logMessage(getTimestamp() + "CONSOLE ADMIN: Remove command found no matching admins");
                    }
                }
            }
            else if(sub == "clear") {
                int cleared = AdminConfig::clear();
                logMessage(getTimestamp() + "CONSOLE ADMIN CLEAR: Cleared " + std::to_string(cleared) + " admin(s)");
                if(cleared == 0) {
                    std::cout << "No admins to clear (root cannot be removed).\n";
                    logMessage(getTimestamp() + "CONSOLE ADMIN: Clear command found no admins to clear");
                }
            }
            else {
                std::cout << "Invalid admin command. Usage:\n";
                std::cout << getCommandUsage("/admin") << "\n";
                std::cout << getCommandUsage("/admin add <user> <pass> [<user> <pass> ...]") << "\n";
                std::cout << getCommandUsage("/admin remove <user> [<user> ...]") << "\n";
                std::cout << getCommandUsage("/admin clear") << "\n";
                logMessage(getTimestamp() + "CONSOLE ADMIN: Invalid subcommand used by operator");
            }
        }
        break;

        case Command::SHUTDOWN:
            logMessage(getTimestamp() + "CONSOLE SHUTDOWN: Server shutdown initiated from console");
            {
                std::lock_guard<std::mutex> lock(shutdown_mutex);
                shutdown_initiator = "server console";
            }
            server_running = false;
            break;

        case Command::LIST: {
            std::lock_guard<std::mutex> lock(clients_mutex);
            std::unordered_set<std::string> all_admins;
            {
                std::lock_guard<std::mutex> admin_lock(admin_mutex);
                auto admins = AdminConfig::getList();
                all_admins.insert(AdminConfig::ROOT_USERNAME);
                for(const auto& admin : admins) all_admins.insert(admin.first);
                all_admins.insert(session_admins.begin(), session_admins.end());
            }
            logMessage(getTimestamp() + "CONSOLE LIST: Listed " + std::to_string(client_sockets.size()) + " connected user(s)");
            std::cout << "Connected users (" << client_sockets.size() << "):\n";
            for(const auto& pair : client_sockets) {
                if(pair.first == SERVER_NAME) {
                    std::cout << "  - " << pair.first << " (server, socket: " << pair.second << ")\n";
                    break;
                }
            }
            for(const auto& pair : client_sockets) {
                if(pair.first != SERVER_NAME) {
                    bool is_admin = all_admins.find(pair.first) != all_admins.end();
                    std::cout << "  - " << pair.first << " (" << (is_admin ? "admin" : "client") << ", socket: " << pair.second << ")\n";
                }
            }
            logMessage(getTimestamp() + "CONSOLE LIST: Displayed connected users to operator");
        }
        break;

        case Command::HELP:
            displayServerCommands();
            break;

        default:
            std::cout << "Command '" << input << "' not found. Try /help for available commands.\n";
            logMessage(getTimestamp() + std::string("CONSOLE: Unknown command entered by operator: '") + input + "'");
            break;
    }
}

/**
 * @brief Read and process commands from server console input in a loop.
 *
 * Executes in a dedicated thread, reading lines from stdin and
 * dispatching them to handleServerCommand until the server shuts down or
 * stdin is closed.
 */
inline void processServerCommands() {
    std::string input;
    while(server_running) {
        if(!std::cin.good()) {
            // stdin is closed or in error state - stop trying to read
            break;
        }

        std::getline(std::cin, input);

        if(!std::cin) {
            // Error reading from stdin (broken pipe, EOF, etc.)
            break;
        }

        if(!server_running) break;

        updateServerActivity();
        handleServerCommand(input);
    }
}

#endif // SERVER_COMMAND_HANDLER_HPP
