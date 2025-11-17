/*
 * common.hpp
 * 
 * Main header file for chat server/client shared components.
 * This file includes all modular common headers and serves as the
 * single point of import for both server and client code.
 * 
 * Module Structure:
 * - common_protocol.hpp:          Protocol headers, message types, network config
 * - common_commands.hpp:          Command system, parsing, help text generation
 * - common_json_management.hpp:   JSON-based configuration (admins & whitelist)
 * - common_messages.hpp:          Message parsing and building utilities
 * 
 * Usage:
 *   #include "common/common.hpp"  // Includes all common components
 */

#ifndef COMMON_HPP
#define COMMON_HPP
#include <string>

// Forward declarations for logging helpers implemented by server utilities.
// These allow common modules to call logging helpers when included from server
// translation units; the actual implementations are provided in server_utils.hpp.

/**
 * @brief Return a human-readable timestamp string for log entries.
 *
 * The returned string is expected to be safe to prefix to log lines and
 * should include a trailing space or separator as appropriate. Example:
 * "[2025-11-17 14:23:01] "
 *
 * @return Formatted timestamp string for use in logging
 */
std::string getTimestamp();

/**
 * @brief Append a message to the server log in a thread-safe manner.
 *
 * Implementations should ensure mutual exclusion when writing to the
 * shared log file and may also mirror the message to stdout if desired.
 * Callers must avoid placing secrets (passwords, raw message bodies) in
 * messages passed to this function — prefer logging metadata instead.
 *
 * @param message Message text to append to the log (should include timestamp)
 */
void logMessage(const std::string& message);

// Include all common modules in dependency order
#include "common_protocol.hpp"        // Must be first (defines MessageHeader, HEADER_LENGTH)
#include "common_json_management.hpp" // JSON config management (admins & whitelist)
#include "common_commands.hpp"        // Command system (no dependencies on other common modules)
#include "common_messages.hpp"        // Message utilities (depends on protocol and commands)

#endif // COMMON_HPP


