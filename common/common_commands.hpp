/*
 * common_commands.hpp
 * 
 * Command system definitions for chat server/client.
 * Contains command enums, parsing functions, command metadata,
 * and help text generation utilities.
 */

#ifndef COMMON_COMMANDS_HPP
#define COMMON_COMMANDS_HPP

#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

// ============================================================================
// COMMAND CONFIGURATION
// ============================================================================

// Command prefix - change this to use a different prefix for commands
const char COMMAND_PREFIX = '/';

// ============================================================================
// COMMAND ENUMERATION
// ============================================================================

// Command types for chat operations
enum class Command {
    QUIT,           // Leave the chat session
    HELP,           // Display available commands
    LIST,           // List connected clients
    MSG,            // Send to specific users
    CLOSE,          // Close specific users client sessions (admin)
    CLOSEALL,       // Close all client sessions (admin)
    SHUTDOWN,       // Shutdown the server (admin)
    TIMEOUT,        // Set/query client inactivity timeout (admin)
    SERVERTIMEOUT,  // Set/query server inactivity timeout (admin)
    WHITELIST,      // Manage whitelist configuration (admin)
    ADMIN,          // Manage admin configuration (admin)
    BROADCAST,      // Send message to all clients (server only)
    SUDO,           // Privilege escalation wrapper
    SUDO_SU,        // Become admin for this session
    SUDO_HELP,      // Show admin commands
    UNKNOWN         // Invalid/unrecognized command
};

// Command to string mapping (without prefix - prefix is added dynamically)
const std::pair<Command, const char*> COMMAND_MAPPINGS[] = {
    {Command::QUIT, "quit"},
    {Command::HELP, "help"},
    {Command::LIST, "list"},
    {Command::MSG, "msg"},
    {Command::CLOSE, "close"},
    {Command::CLOSEALL, "closeall"},
    {Command::SHUTDOWN, "shutdown"},
    {Command::TIMEOUT, "timeout"},
    {Command::SERVERTIMEOUT, "servertimeout"},
    {Command::WHITELIST, "whitelist"},
    {Command::ADMIN, "admin"},
    {Command::BROADCAST, "broadcast"},
    {Command::SUDO_SU, "sudo su"},      // Check longer sudo commands first
    {Command::SUDO_HELP, "sudo help"},  // Check longer sudo commands first
    {Command::SUDO, "sudo"}             // Check generic sudo last
};

/**
 * @brief Convert a command string into the Command enum.
 *
 * Handles inputs with or without the command prefix (e.g., "/help" or "help").
 * Comparison is done against the canonical command mappings. If no match is
 * found, Command::UNKNOWN is returned.
 *
 * @param str The input command string (may include leading prefix)
 * @return Corresponding Command enum value, or Command::UNKNOWN if not matched
 */
inline Command stringToCommand(const std::string& str) {
    std::string cmd = str;
    
    // Remove prefix if present
    if(!cmd.empty() && cmd[0] == COMMAND_PREFIX) {
        cmd = cmd.substr(1);
    }
    
    for(const auto& pair : COMMAND_MAPPINGS) {
        if(cmd == pair.second) {
            return pair.first;
        }
    }
    return Command::UNKNOWN;
}

/**
 * @brief Convert a Command enum value to its user-facing string form.
 *
 * The returned string includes the command prefix (COMMAND_PREFIX). If the
 * command enum is unknown, an empty string is returned.
 *
 * @param cmd The Command enum value
 * @return Command string with prefix (e.g., "/help") or empty string
 */
inline std::string commandToString(Command cmd) {
    for(const auto& pair : COMMAND_MAPPINGS) {
        if(pair.first == cmd) {
            return std::string(1, COMMAND_PREFIX) + pair.second;
        }
    }
    return "";
}

/**
 * @brief Parse a command from raw user input.
 *
 * Returns Command::UNKNOWN for non-commands or unrecognized commands. The
 * function expects input starting with COMMAND_PREFIX; it supports commands
 * with or without arguments (matches both exact and prefix-with-args).
 *
 * @param input Raw user input string
 * @return Parsed Command enum, or Command::UNKNOWN
 */
inline Command parseCommand(const std::string& input) {
    // Check if input starts with command prefix
    if(input.empty() || input[0] != COMMAND_PREFIX) {
        return Command::UNKNOWN;  // Not a command
    }
    
    // Remove prefix
    std::string cmd_input = input.substr(1);
    
    // Check for exact matches and commands with arguments
    for(const auto& pair : COMMAND_MAPPINGS) {
        std::string cmd_str = pair.second;
        
        // For exact commands (no arguments expected)
        if(cmd_input == cmd_str) {
            return pair.first;
        }
        
        // For commands with arguments (command followed by space)
        if(cmd_input.length() > cmd_str.length() && 
           cmd_input.substr(0, cmd_str.length() + 1) == cmd_str + " ") {
            return pair.first;
        }
    }
    return Command::UNKNOWN;
}

// ============================================================================
// COMMAND DEFINITIONS
// ============================================================================
// Static command metadata using Command enum
// Each entry: {Command enum, usage pattern, description, display_weight}
// - usage_pattern: The command syntax shown to users (may include args)
// - description: Brief explanation of what the command does
// - display_weight: Higher values appear first in help listings (100 = top)

struct CommandInfo {
    Command cmd;
    const char* usage_pattern;
    const char* description;
    int display_weight;
};

// Commands available to everyone (server console, admin clients, regular clients)
const CommandInfo SHARED_COMMANDS[] = {
    {Command::HELP, "/help", "Display available commands", 100},
    {Command::LIST, "/list", "List connected clients", 80},
    {Command::MSG, "/msg <username1,username2,...> <message>", "Send to specific users", 70}
};

// Commands available to server console and admin clients only
const CommandInfo ADMIN_COMMANDS[] = {
    {Command::CLOSE, "/close <username1,username2...>", "Close specific users client sessions", 50},
    {Command::CLOSEALL, "/closeall", "Close all client sessions", 40},
    {Command::SHUTDOWN, "/shutdown", "Shutdown the server", 30},
    {Command::WHITELIST, "/whitelist", "Show whitelist status", 27},
    {Command::WHITELIST, "/whitelist <true|false>", "Enable/disable whitelist mode", 26},
    {Command::WHITELIST, "/whitelist add <user> <pass> [<user> <pass> ...]", "Add users to whitelist", 25},
    {Command::WHITELIST, "/whitelist remove <user> [<user> ...]", "Remove users from whitelist", 24},
    {Command::WHITELIST, "/whitelist clear", "Clear all whitelist users", 23},
    {Command::ADMIN, "/admin", "Show admin list status", 22},
    {Command::ADMIN, "/admin add <user> <pass> [<user> <pass> ...]", "Add admin users", 21},
    {Command::ADMIN, "/admin remove <user> [<user> ...]", "Remove admin users", 20},
    {Command::ADMIN, "/admin clear", "Clear all admins (except root)", 19},
    {Command::TIMEOUT, "/timeout <minutes>", "Set client inactivity timeout (0=disabled)", 18},
    {Command::TIMEOUT, "/timeout", "Show current client inactivity timeout (0=disabled)", 17},
    {Command::SERVERTIMEOUT, "/servertimeout <minutes>", "Set server inactivity timeout (0=disabled)", 10},
    {Command::SERVERTIMEOUT, "/servertimeout", "Show current server inactivity timeout (0=disabled)", 9}
};

// Commands exclusive to server console (not available to any clients)
const CommandInfo SERVER_ONLY_COMMANDS[] = {
    {Command::BROADCAST, "/broadcast <message>", "Send message to all clients", 90}
};

// Commands exclusive to regular clients (not available to server or admins)
const CommandInfo CLIENT_ONLY_COMMANDS[] = {
    {Command::QUIT, "/quit", "Leave the chat session", 60}
};

// Commands for privilege escalation (allows non-admins to execute admin commands)
const CommandInfo SUDO_COMMANDS[] = {
    {Command::SUDO_HELP, "/sudo help", "Show admin commands (password prompt)", 50},
    {Command::SUDO_SU, "/sudo su", "Become admin for this session (password prompt)", 40},
    {Command::SUDO, "/sudo <admin_command> [args]", "Execute admin command (password prompt)", 30}
};

// ============================================================================
// COMMAND DISPLAY FUNCTIONS
// ============================================================================

/**
 * @brief Build and return the list of commands available to the server console.
 *
 * Combines shared, admin-specific, and server-only command definitions and
 * returns them sorted by their display_weight. Uses lazy initialization to
 * build the list only once.
 *
 * @return Reference to a vector containing CommandInfo entries sorted by weight
 */
inline const std::vector<CommandInfo>& getServerCommands() {
    static std::vector<CommandInfo> server_commands = []() {
        std::vector<CommandInfo> commands;
        commands.insert(commands.end(), std::begin(SHARED_COMMANDS), std::end(SHARED_COMMANDS));
        commands.insert(commands.end(), std::begin(ADMIN_COMMANDS), std::end(ADMIN_COMMANDS));
        commands.insert(commands.end(), std::begin(SERVER_ONLY_COMMANDS), std::end(SERVER_ONLY_COMMANDS));
        
        std::sort(commands.begin(), commands.end(), 
            [](const CommandInfo& a, const CommandInfo& b) {
                return a.display_weight > b.display_weight;
            });
        return commands;
    }();
    
    return server_commands;
}

/**
 * @brief Print the server console command list to stdout.
 *
 * This helper prints usage lines for the server operator and records a
 * single log entry indicating the operator viewed the help.
 */
inline void displayServerCommands() {
    const auto& commands = getServerCommands();
    std::cout << "Available commands:\n";
    for(const auto& cmd : commands) {
        std::cout << "  " << cmd.usage_pattern << " - " << cmd.description << "\n";
    }
    logMessage(getTimestamp() + "CONSOLE: Displayed server commands/help to operator");
}

/**
 * @brief Build and return the list of commands available to admin clients.
 *
 * Combines shared commands, admin commands and client-only commands and
 * returns them sorted by display_weight. Implemented with lazy
 * initialization for efficiency.
 *
 * @return Reference to a vector of CommandInfo sorted by weight
 */
inline const std::vector<CommandInfo>& getAdminClientCommands() {
    static std::vector<CommandInfo> admin_commands = []() {
        std::vector<CommandInfo> commands;
        commands.insert(commands.end(), std::begin(SHARED_COMMANDS), std::end(SHARED_COMMANDS));
        commands.insert(commands.end(), std::begin(ADMIN_COMMANDS), std::end(ADMIN_COMMANDS));
        commands.insert(commands.end(), std::begin(CLIENT_ONLY_COMMANDS), std::end(CLIENT_ONLY_COMMANDS));
        
        std::sort(commands.begin(), commands.end(), 
            [](const CommandInfo& a, const CommandInfo& b) {
                return a.display_weight > b.display_weight;
            });
        return commands;
    }();
    
    return admin_commands;
}

/**
 * @brief Print the admin-client command list to stdout.
 *
 * Shows commands available to admin clients and logs the operator action.
 */
inline void displayAdminClientCommands() {
    const auto& commands = getAdminClientCommands();
    std::cout << "Available commands (Admin):\n";
    for(const auto& cmd : commands) {
        std::cout << "  " << cmd.usage_pattern << " - " << cmd.description << "\n";
    }
    logMessage(getTimestamp() + "CONSOLE: Displayed admin client commands/help");
}

/**
 * @brief Build and return the list of commands available to regular clients.
 *
 * Combines shared, client-only and sudo commands and sorts them by
 * display_weight. Uses lazy initialization for efficiency.
 *
 * @return Reference to a vector of CommandInfo sorted by weight
 */
inline const std::vector<CommandInfo>& getClientCommands() {
    static std::vector<CommandInfo> client_commands = []() {
        std::vector<CommandInfo> commands;
        commands.insert(commands.end(), std::begin(SHARED_COMMANDS), std::end(SHARED_COMMANDS));
        commands.insert(commands.end(), std::begin(CLIENT_ONLY_COMMANDS), std::end(CLIENT_ONLY_COMMANDS));
        commands.insert(commands.end(), std::begin(SUDO_COMMANDS), std::end(SUDO_COMMANDS));
        
        std::sort(commands.begin(), commands.end(), 
            [](const CommandInfo& a, const CommandInfo& b) {
                return a.display_weight > b.display_weight;
            });
        return commands;
    }();
    
    return client_commands;
}

/**
 * @brief Produce a help text string for regular (non-admin) clients.
 *
 * Aggregates the client-visible commands and formats them into a
 * multi-line help string suitable for sending to a client.
 *
 * @return Help text string for non-admin clients
 */
inline std::string getClientHelpText() {
    const auto& commands = getClientCommands();
    std::string help_text = "Available commands:\n";
    for(const auto& cmd : commands) {
        help_text += "  " + std::string(cmd.usage_pattern) + " - " + std::string(cmd.description) + "\n";
    }
    return help_text;
}

/**
 * @brief Produce a help text string for admin clients.
 *
 * Aggregates admin-visible commands and formats them into a multi-line
 * help string suitable for sending to an admin client.
 *
 * @return Help text string for admin clients
 */
inline std::string getAdminHelpText() {
    const auto& commands = getAdminClientCommands();
    std::string help_text = "Available commands (Admin):\n";
    for(const auto& cmd : commands) {
        help_text += "  " + std::string(cmd.usage_pattern) + " - " + std::string(cmd.description) + "\n";
    }
    return help_text;
}

/**
 * @brief Build and return the list of sudo-related commands.
 *
 * Returns a vector of CommandInfo for the sudo helper commands, sorted by
 * display weight. Uses lazy initialization to construct the vector once.
 *
 * @return Reference to a vector of sudo CommandInfo entries
 */
inline const std::vector<CommandInfo>& getSudoCommands() {
    static std::vector<CommandInfo> sudo_commands = []() {
        std::vector<CommandInfo> commands;
        commands.insert(commands.end(), std::begin(SUDO_COMMANDS), std::end(SUDO_COMMANDS));
        
        std::sort(commands.begin(), commands.end(), 
            [](const CommandInfo& a, const CommandInfo& b) {
                return a.display_weight > b.display_weight;
            });
        return commands;
    }();
    
    return sudo_commands;
}

/**
 * @brief Print the sudo command list to stdout for users invoking /sudo.
 *
 * Outputs the available sudo variants and logs that the list was shown.
 */
inline void displaySudoCommands() {
    const auto& commands = getSudoCommands();
    std::cout << "Sudo commands:\n";
    for(const auto& cmd : commands) {
        std::cout << "  " << cmd.usage_pattern << " - " << cmd.description << "\n";
    }
    logMessage(getTimestamp() + "CONSOLE: Displayed sudo commands/help");
}

/**
 * @brief Aggregate every command definition into a single sorted list.
 *
 * Useful for searching, usage lookup, and validation. The returned list
 * is built once and cached for subsequent calls.
 *
 * @return Reference to a vector containing all CommandInfo entries sorted by weight
 */
inline const std::vector<CommandInfo>& getAllCommands() {
    static std::vector<CommandInfo> all_commands = []() {
        std::vector<CommandInfo> commands;
        commands.insert(commands.end(), std::begin(SHARED_COMMANDS), std::end(SHARED_COMMANDS));
        commands.insert(commands.end(), std::begin(ADMIN_COMMANDS), std::end(ADMIN_COMMANDS));
        commands.insert(commands.end(), std::begin(SERVER_ONLY_COMMANDS), std::end(SERVER_ONLY_COMMANDS));
        commands.insert(commands.end(), std::begin(CLIENT_ONLY_COMMANDS), std::end(CLIENT_ONLY_COMMANDS));
        commands.insert(commands.end(), std::begin(SUDO_COMMANDS), std::end(SUDO_COMMANDS));
        
        std::sort(commands.begin(), commands.end(), 
            [](const CommandInfo& a, const CommandInfo& b) {
                return a.display_weight > b.display_weight;
            });
        return commands;
    }();
    
    return all_commands;
}

/**
 * @brief Retrieve a user-facing usage string for a given command pattern.
 *
 * Attempts an exact pattern match against defined command usages. If not
 * found, falls back to matching by command name and returns the canonical
 * usage. Returns a helpful fallback string if the command is unknown.
 *
 * @param command_pattern The command pattern to search for (e.g., "/timeout <minutes>")
 * @return Formatted usage string (e.g., "Usage: /timeout <minutes>") or an error message
 */
inline std::string getCommandUsage(const std::string& command_pattern) {
    // Use cached list of all commands
    const auto& all_commands = getAllCommands();
    
    // First, try to find exact pattern match
    for(const auto& cmd : all_commands) {
        if(cmd.usage_pattern == command_pattern) {
            return "Usage: " + std::string(cmd.usage_pattern);
        }
    }
    
    // If no exact match, extract command name and find first matching command
    size_t space_pos = command_pattern.find(' ');
    std::string cmd_name = (space_pos == std::string::npos) ? command_pattern : command_pattern.substr(0, space_pos);
    
    for(const auto& cmd : all_commands) {
        std::string cmd_def(cmd.usage_pattern);
        size_t def_space_pos = cmd_def.find(' ');
        std::string def_cmd_name = (def_space_pos == std::string::npos) ? cmd_def : cmd_def.substr(0, def_space_pos);
        
        if(def_cmd_name == cmd_name) {
            return "Usage: " + cmd_def;
        }
    }
    
    return "Failed to find usage for command: " + command_pattern;
}

/**
 * @brief Validate that core command definitions exist and detect duplicates.
 *
 * Confirms that required command names are present in the aggregated
 * definitions and detects exact duplicate usage patterns. Logs any
 * validation errors found.
 *
 * @return true if validation passes (no missing or duplicate patterns), false otherwise
 */
inline bool validateCommandDefinitions() {
    // Required commands that must be defined (without prefix)
    std::vector<std::string> required_commands = {
        "help", "list", "msg", "broadcast", "quit",
        "close", "closeall", "shutdown", "timeout", "servertimeout",
        "whitelist", "sudo"
    };
    
    std::vector<std::string> missing_commands;
    std::vector<std::string> duplicate_commands;
    
    // Use cached list of all commands
    const auto& all_commands = getAllCommands();
    
    // Track command occurrences by FULL PATTERN to detect exact duplicates
    std::unordered_map<std::string, int> pattern_count;
    // Track command names (for checking required commands exist)
    std::unordered_set<std::string> defined_command_names;
    
    for(const auto& cmd : all_commands) {
        std::string cmd_pattern(cmd.usage_pattern);
        
        // Count full patterns for duplicate detection
        pattern_count[cmd_pattern]++;
        
        // Extract command name for required command checking
        size_t space_pos = cmd_pattern.find(' ');
        std::string cmd_name = (space_pos == std::string::npos) ? cmd_pattern : cmd_pattern.substr(0, space_pos);
        defined_command_names.insert(cmd_name);
    }
    
    // Check for missing required commands
    for(const auto& required : required_commands) {
        if(defined_command_names.find(required) == defined_command_names.end()) {
            missing_commands.push_back(required);
        }
    }
    
    // Check for duplicate command PATTERNS (exact matches)
    for(const auto& pair : pattern_count) {
        if(pair.second > 1) {
            duplicate_commands.push_back(pair.first + " (defined " + std::to_string(pair.second) + " times)");
        }
    }
    
    bool has_errors = false;
    
    if(!missing_commands.empty()) {
        logMessage(getTimestamp() + "ERROR: Command validation failed. Missing required command definitions in common.hpp:");
        for(const auto& cmd : missing_commands) {
            logMessage(getTimestamp() + "  - " + cmd);
        }
        has_errors = true;
    }
    
    if(!duplicate_commands.empty()) {
        logMessage(getTimestamp() + "ERROR: Command validation failed. Duplicate command definitions found in common.hpp:");
        for(const auto& cmd : duplicate_commands) {
            logMessage(getTimestamp() + "  - " + cmd);
        }
        has_errors = true;
    }
    
    return !has_errors;
}

#endif // COMMON_COMMANDS_HPP
