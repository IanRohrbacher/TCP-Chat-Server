/*
 * common_protocol.hpp
 * 
 * Protocol definitions for chat server/client communication.
 * Contains network configuration, timeout settings, message headers,
 * and header conversion utilities.
 */

#ifndef COMMON_PROTOCOL_HPP
#define COMMON_PROTOCOL_HPP

#include <string>
#include <utility>

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

const int PORT = 8080;  // TCP port for server-client communication

// ============================================================================
// TIMEOUT CONFIGURATION
// ============================================================================
// All timeout values are in minutes. Setting to 0 disables that timeout.

const int CLIENT_TIMEOUT_MINUTES = 5;           // Client disconnects itself after inactivity
const int SERVER_CLIENT_TIMEOUT_MINUTES = 10;  // Server disconnects inactive clients
const int SERVER_TIMEOUT_MINUTES = 30;          // Server shuts down after inactivity

// ============================================================================
// PROTOCOL MESSAGE HEADERS
// ============================================================================
// All protocol headers are exactly 6 characters in format [XXXX]
// This ensures fixed-length parsing and clear message type identification

const int HEADER_LENGTH = 6;  // All headers must be exactly this length

// ============================================================================
// MESSAGE HEADER ENUMERATION
// ============================================================================

// Message header enumeration for efficient switch-case handling
enum class MessageHeader {
    // Connection & User Lifecycle Headers
    ENTER,              // Sent when a user joins the chat
    LEAVE,              // Sent when a user voluntarily leaves
    KICK,               // Server forcing a client to disconnect
    ACCEPT,             // Server accepts username (connection approved)
    REJECT,             // Server rejects username (duplicate/invalid)
    
    // Password Challenge Headers
    PASSWORD_CHALLENGE, // Server requests password from client
    PASSWORD_RESPONSE,  // Client sends password to server
    
    // Standard Messaging Headers
    USER,               // Marks username in a message
    MESSAGE,            // Marks message content
    MSG,                // Direct message to specific user(s)
    RESPONSE,           // Server response to a command
    
    // Information & List Headers
    LIST_REQUEST,       // Client requesting connected users list
    LIST_RESPONSE,      // Server sending connected users list
    ROLE,               // Indicates user role (server/admin/client)
    HELP_REQUEST,       // Client requesting help/command list
    
    // Administrative & Control Headers
    SHUTDOWN,           // Request server shutdown
    CLOSE_REQUEST,      // Request to disconnect specific user(s)
    CLOSEALL_REQUEST,   // Request to disconnect all users
    TIMEOUT,            // Configure client inactivity timeout
    SERVERTIMEOUT,      // Configure server inactivity timeout
    WHITELIST,          // Manage whitelist configuration
    ADMIN,              // Manage admin configuration
    PASSWORD,           // Marks password in admin commands
    SUDO,               // Wrapper for sudo-invoked admin commands
    SUDO_SU,            // Request temporary admin privileges
    SUDO_HELP,          // Request admin command list
    
    UNKNOWN             // Unknown/invalid header
};

// Header string mappings - single source of truth
const std::pair<MessageHeader, const char*> HEADER_MAPPINGS[] = {
    {MessageHeader::ENTER, "[ENTR]"},
    {MessageHeader::LEAVE, "[LEAV]"},
    {MessageHeader::KICK, "[KICK]"},
    {MessageHeader::ACCEPT, "[ACPT]"},
    {MessageHeader::REJECT, "[RJCT]"},
    {MessageHeader::PASSWORD_CHALLENGE, "[PCHA]"},
    {MessageHeader::PASSWORD_RESPONSE, "[PRES]"},
    {MessageHeader::USER, "[USER]"},
    {MessageHeader::MESSAGE, "[MESG]"},
    {MessageHeader::MSG, "[SEND]"},
    {MessageHeader::RESPONSE, "[RESP]"},
    {MessageHeader::LIST_REQUEST, "[LREQ]"},
    {MessageHeader::LIST_RESPONSE, "[LRES]"},
    {MessageHeader::ROLE, "[ROLE]"},
    {MessageHeader::HELP_REQUEST, "[HREQ]"},
    {MessageHeader::SHUTDOWN, "[SHUT]"},
    {MessageHeader::CLOSE_REQUEST, "[CLRQ]"},
    {MessageHeader::CLOSEALL_REQUEST, "[CARQ]"},
    {MessageHeader::TIMEOUT, "[TOUT]"},
    {MessageHeader::SERVERTIMEOUT, "[STOU]"},
    {MessageHeader::WHITELIST, "[WLST]"},
    {MessageHeader::ADMIN, "[ADMN]"},
    {MessageHeader::PASSWORD, "[PASS]"},
    {MessageHeader::SUDO, "[SUDO]"},
    {MessageHeader::SUDO_SU, "[SUSU]"},
    {MessageHeader::SUDO_HELP, "[SHLP]"}
};

/**
 * @brief Convert a protocol header string to the corresponding MessageHeader enum.
 *
 * Expects a 6-character header of the form "[XXXX]". The mapping is
 * defined by HEADER_MAPPINGS. This helper centralizes conversion logic
 * for use by message parsers.
 *
 * @param str A 6-character protocol header string (for example "[ENTR]")
 * @return The matching MessageHeader enum value, or MessageHeader::UNKNOWN if not found
 */
inline MessageHeader stringToHeader(const std::string& str) {
    for(const auto& pair : HEADER_MAPPINGS) {
        if(str == pair.second) {
            return pair.first;
        }
    }
    return MessageHeader::UNKNOWN;
}

/**
 * @brief Convert a MessageHeader enum value to its string representation.
 *
 * Looks up the canonical 6-character string for the provided enum value.
 * Returns an empty string when the enum is not mapped.
 *
 * @param header The MessageHeader enum value to convert
 * @return The 6-character protocol header string (for example "[ENTR]") or an empty string if unknown
 */
inline const std::string headerToString(MessageHeader header) {
    for(const auto& pair : HEADER_MAPPINGS) {
        if(pair.first == header) {
            return pair.second;
        }
    }
    return "";
}

#endif // COMMON_PROTOCOL_HPP
