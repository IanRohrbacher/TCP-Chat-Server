/*
 * server_utils.hpp
 * 
 * Utility functions for chat server.
 * Includes admin management, activity tracking, and password validation.
 */

#ifndef SERVER_UTILS_HPP
#define SERVER_UTILS_HPP

#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include "../common/common.hpp"

// External references to global state (defined in server.cpp)
extern std::unordered_map<std::string, int> client_sockets;
extern std::unordered_map<std::string, std::chrono::steady_clock::time_point> client_last_activity;
extern std::mutex clients_mutex;
extern std::unordered_set<std::string> session_admins;
extern std::mutex admin_mutex;
extern std::chrono::steady_clock::time_point server_last_activity;
extern std::mutex server_activity_mutex;

// Global log file
extern std::ofstream log_file;
extern std::mutex log_mutex;
extern std::atomic<bool> console_logging_enabled;
extern std::mutex console_output_mutex;

/**
 * @brief Get current timestamp in a readable format for logging.
 *
 * The returned string is formatted for human-readable logs and is intended
 * to be prefixed to log entries. It includes a trailing space to separate
 * the timestamp from the message text.
 *
 * @return Formatted timestamp string: "[YYYY-MM-DD HH:MM:SS] "
 */
/**
 * @brief Obtain the current local time as std::tm (thread-unsafe wrapper of localtime).
 *
 * This helper centralizes the time retrieval so all timestamp-formatting
 * functions use the same source of truth. The returned tm is a copy so
 * callers can safely pass it to std::put_time.
 */
inline std::tm getLocalTm() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    return *std::localtime(&time_t_now);
}

/**
 * @brief Format the local time using a strftime-style format string.
 *
 * This small wrapper calls std::put_time with the provided format and the
 * centralized local time source returned by getLocalTm(). It keeps the
 * formatting logic in one place so both human-readable and filename-safe
 * timestamps remain consistent.
 *
 * @param fmt The format string for std::put_time (for example "%Y-%m-%d %H:%M:%S")
 * @return Formatted timestamp string according to fmt
 */
inline std::string formatLocalTime(const char* fmt) {
    std::tm tm_now = getLocalTm();
    std::ostringstream oss;
    oss << std::put_time(&tm_now, fmt);
    return oss.str();
}

/**
 * @brief Get current timestamp in a readable format for logging.
 *
 * The returned string is formatted for human-readable logs and is intended
 * to be prefixed to log entries. It includes a trailing space to separate
 * the timestamp from the message text.
 *
 * @return Formatted timestamp string: "[YYYY-MM-DD HH:MM:SS] "
 */
inline std::string getTimestamp() {
    return std::string("[") + formatLocalTime("%Y-%m-%d %H:%M:%S") + "] ";
}

/**
 * @brief Get a compact timestamp safe for filenames.
 *
 * This variant avoids whitespace and characters that are inconvenient in
 * filenames and is suitable for including in log filenames.
 *
 * @return Formatted timestamp string: "YYYY-MM-DD_HH-MM-SS"
 */
inline std::string getFilenameTimestamp() {
    return formatLocalTime("%Y-%m-%d_%H-%M-%S");
}

/**
 * @brief Initialize the logging system and open the log file.
 *
 * Creates a `logs` directory if missing and opens a per-server log file
 * named using the provided server_name plus a timestamp. An initial
 * header line is written so external monitors can detect startup.
 *
 * Note: This function logs errors via logMessage() when it can; if the
 * log file cannot be opened logging to file will be disabled but the
 * process may continue.
 *
 * @param server_name The name of the server used to construct the log filename
 * @return true if the log file was successfully opened for append, false otherwise
 */
inline bool initializeLogging(const std::string& server_name) {
    // Create logs directory if it doesn't exist
    struct stat st;
    if(stat("logs", &st) != 0) {
        if(mkdir("logs", 0755) != 0) {
            logMessage(getTimestamp() + "ERROR: Failed to create logs directory");
            return false;
        }
    }
    
    // Create log filename
    std::string filename = "logs/" + server_name + "-" + getFilenameTimestamp() + "-log.txt";
    
    // Open log file
    log_file.open(filename, std::ios::out | std::ios::app);
    if(!log_file.is_open()) {
        logMessage(getTimestamp() + "ERROR: Failed to open log file: " + filename);
        return false;
    }
    
    std::cout << "Logging to: " << filename << "\n";
    logMessage(getTimestamp() + "SERVER: Logging to: " + filename);
    // Write an initial log entry so external observers immediately see when logging began
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        if(log_file.is_open()) {
            log_file << getTimestamp() << "SERVER: Logging started for '" << server_name << "'.\n";
            log_file.flush();
        }
    }
    return true;
}

/**
 * @brief Thread-safe logging helper that writes to console and to the log file.
 *
 * The function atomically writes the provided message to stdout and, if
 * available, to the shared log file. The message should normally include
 * a timestamp (there are convenience helpers such as getTimestamp()).
 *
 * Security: Callers MUST NOT pass secrets (passwords, raw private message
 * bodies, or other sensitive data) to this function. Log metadata (event
 * types, usernames, counts) is preferred.
 *
 * @param message Message text to append to the log; a newline is appended
 */
inline void logMessage(const std::string& message) {
    // Optionally write to console (can be suppressed during interactive prompts)
    if(console_logging_enabled.load()) {
        std::cout << message << "\n";
    }

    // Always write to the log file when available
    std::lock_guard<std::mutex> lock(log_mutex);
    if(log_file.is_open()) {
        log_file << message << "\n";
        log_file.flush();  // Ensure immediate write
    }
}

/**
 * @brief Close the global log file if open.
 *
 * Flushes and closes the shared log file. Safe to call multiple times.
 */
inline void closeLogging() {
    std::lock_guard<std::mutex> lock(log_mutex);
    if(log_file.is_open()) {
        log_file << getTimestamp() << "SERVER: Logging system shutdown.\n";
        log_file.close();
    }
}

/**
 * @brief Update the server's last activity timestamp.
 *
 * Protects the shared server_last_activity variable with a mutex and sets it
 * to the current steady_clock::now(). Call this when the server performs an
 * action that should reset the inactivity/shutdown timer.
 */
void updateServerActivity() {
    std::lock_guard<std::mutex> lock(server_activity_mutex);
    server_last_activity = std::chrono::steady_clock::now();
}

/**
 * @brief Retrieve the socket descriptor associated with a username.
 *
 * Returns the socket fd for the given username or -1 if the user is not
 * present in the client_sockets map. Callers should hold clients_mutex
 * when required by the calling context to prevent races.
 *
 * @param username The username to look up
 * @return Socket descriptor if found, or -1 if not found
 */
int getSocketForUser(const std::string& username) {
    auto it = client_sockets.find(username);
    return (it != client_sockets.end()) ? it->second : -1;
}

/**
 * @brief Determine whether a username currently has admin privileges.
 *
 * Checks the session_admins set (temporary sudo grants) and the persisted
 * AdminConfig JSON to determine whether the user is an admin. This ensures
 * real-time revocation of privileges when the JSON file changes.
 *
 * @param username The username to check
 * @return true if the user is an admin (session or registered), false otherwise
 */
bool isAdmin(const std::string& username) {
    // Check session admins (temporary sudo su)
    {
        std::lock_guard<std::mutex> lock(admin_mutex);
        if (session_admins.find(username) != session_admins.end()) {
            return true;
        }
    }
    
    // Check registered admins from JSON config (real-time check)
    return AdminConfig::isAdmin(username);
}

/**
 * @brief Grant session-level admin privileges to a user.
 *
 * Inserts the username into the session_admins set under a mutex. This is
 * a temporary grant (does not persist to JSON) and is revoked on disconnect.
 * Also emits a console message and a log entry noting the grant.
 *
 * @param username The username to grant admin privileges to for the session
 */
void addSessionAdmin(const std::string& username) {
    std::lock_guard<std::mutex> lock(admin_mutex);
    session_admins.insert(username);
    {
        std::lock_guard<std::mutex> cout_lock(console_output_mutex);
        std::cout << "User '" << username << "' granted admin privileges for this session.\n";
    }
    logMessage(getTimestamp() + std::string("CONSOLE ADMIN: User '") + username + "' granted admin privileges for this session");
}

/**
 * @brief Revoke session-level admin privileges for a user.
 *
 * Removes the username from the session_admins set under the admin mutex.
 * This does not affect persisted admin definitions in the AdminConfig.
 *
 * @param username The username whose session admin privileges should be removed
 */
void removeSessionAdmin(const std::string& username) {
    std::lock_guard<std::mutex> lock(admin_mutex);
    session_admins.erase(username);
}

/**
 * @brief Initialize the admin management system.
 *
 * Loads admin user definitions from the AdminConfig JSON and prompts the
 * local operator for the root password on first run or when changing it.
 * The operator-visible password prompt is logged as an event but the
 * password text is never written to logs.
 */
void initializeAdmins() {
    // Load admin configuration from JSON
    if(!AdminConfig::load()) {
        logMessage(getTimestamp() + "WARNING: Failed to load admin configuration");
    }
    
    // Prompt for root password on first run or update
    // Suppress console log output while prompting to avoid interleaving logs
    console_logging_enabled.store(false);
    {
        std::lock_guard<std::mutex> cout_lock(console_output_mutex);
        std::cout << "Enter password for root admin (press Enter to keep current, 30s timeout): ";
        std::cout.flush();
    }
    // Log the prompt to file only (console output suppressed)
    logMessage(getTimestamp() + "CONSOLE ADMIN: Prompted operator for root admin password (no password logged)");

    std::string new_password;
    // Wait up to 30 seconds for operator input on stdin. If no input, default to keeping existing password.
    int stdin_fd = fileno(stdin);
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(stdin_fd, &readfds);
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;

    int sel = select(stdin_fd + 1, &readfds, nullptr, nullptr, &tv);
    if(sel > 0 && FD_ISSET(stdin_fd, &readfds)) {
        // Input is available - read the line
        std::getline(std::cin, new_password);
    } else if(sel == 0) {
        // Timeout - keep existing password
        // Ensure prompt line is terminated so subsequent logs appear on a new line
        {
            std::lock_guard<std::mutex> cout_lock(console_output_mutex);
            std::cout << "\n";
            std::cout.flush();
        }
        logMessage(getTimestamp() + "ADMIN: No operator input for new password within 30s; keeping existing root password (timeout)");
        new_password = "";
    } else {
        // select error - log and keep existing password
        // Ensure prompt line is terminated so subsequent logs appear on a new line
        {
            std::lock_guard<std::mutex> cout_lock(console_output_mutex);
            std::cout << "\n";
            std::cout.flush();
        }
        logMessage(getTimestamp() + std::string("ADMIN: Error waiting for operator input for root password: select() returned ") + std::to_string(sel));
        new_password = "";
    }

    // Restore console log output
    console_logging_enabled.store(true);
    
    // Trim whitespace
    size_t start = new_password.find_first_not_of(" \t\n\r");
    size_t end = new_password.find_last_not_of(" \t\n\r");
    if(start != std::string::npos) {
        new_password = new_password.substr(start, end - start + 1);
    } else {
        new_password = "";
    }
    
    if(!new_password.empty()) {
        if(AdminConfig::setRootPassword(new_password)) {
            logMessage(getTimestamp() + "ADMIN: Root password updated successfully");
        } else {
            logMessage(getTimestamp() + "WARNING: Failed to save root password");
        }
    } else {
        logMessage(getTimestamp() + "ADMIN: Keeping existing root password");
    }

    logMessage(getTimestamp() + "ADMIN: Admin system initialized");
}

/**
 * Request and validate password from client with up to 3 attempts.
 * Sends PASSWORD_CHALLENGE and waits for PASSWORD_RESPONSE.
 * 
 * @param client_socket Socket to communicate with client
 * @param buffer Buffer to receive password response
 * @param buffer_size Size of the buffer
 * @param prompt Prompt message to display to client
 * @param expected_password The password to validate against
 * @param username Client username (for logging)
 * @return true if password is valid, false otherwise
 */
bool requestAndValidatePassword(int client_socket, char* buffer, size_t buffer_size, 
                                const std::string& prompt, const std::string& expected_password, 
                                const std::string& username) {
    const int MAX_ATTEMPTS = 3;
    
    for(int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        // Send password challenge
        std::string attempt_prompt = prompt;
        if(attempt > 1) {
            attempt_prompt = "password: ";
        }
        
        logMessage(getTimestamp() + "PASSWORD REQUEST: Requesting password from '" + username + "' (attempt " + std::to_string(attempt) + ")");
        std::string challenge = buildMessage(MessageHeader::PASSWORD_CHALLENGE, attempt_prompt);
        send(client_socket, challenge.c_str(), challenge.length(), 0);
        
        // Wait for password response
        memset(buffer, 0, buffer_size);
        int pwd_bytes = read(client_socket, buffer, buffer_size);
        
        if(pwd_bytes <= 0) {
            logMessage(getTimestamp() + "PASSWORD ERROR: Client '" + username + "' disconnected during password entry");
            return false;
        }
        
        MessageHeader pwd_header = extractHeader(buffer, pwd_bytes);
        if(pwd_header != MessageHeader::PASSWORD_RESPONSE) {
            logMessage(getTimestamp() + "PASSWORD ERROR: Invalid password response from '" + username + "'");
            std::string denial = buildMessage(MessageHeader::REJECT, "Access denied.");
            send(client_socket, denial.c_str(), denial.length(), 0);
            return false;
        }
        
        std::string password(buffer + HEADER_LENGTH);
        
        // Validate password
        if(password == expected_password) {
            logMessage(getTimestamp() + "PASSWORD SUCCESS: Password accepted for '" + username + "'");
            return true;
        }
        
        logMessage(getTimestamp() + "PASSWORD FAILED: Invalid password from '" + username + "' (attempt " + std::to_string(attempt) + ")");
    }
    
    // All attempts exhausted
    logMessage(getTimestamp() + "PASSWORD EXHAUSTED: Client '" + username + "' failed password authentication after " + std::to_string(MAX_ATTEMPTS) + " attempts");
    std::string denial = buildMessage(MessageHeader::REJECT, "Access denied.");
    send(client_socket, denial.c_str(), denial.length(), 0);
    return false;
}

#endif // SERVER_UTILS_HPP
