/*
 * common_messages.hpp
 * 
 * Message parsing and building utilities for chat protocol.
 * Contains functions to construct and parse protocol-compliant messages
 * using the headers defined in common_protocol.hpp.
 */

#ifndef COMMON_MESSAGES_HPP
#define COMMON_MESSAGES_HPP

#include "common_protocol.hpp"
#include "common_commands.hpp"
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>

// ============================================================================
// MESSAGE PARSING UTILITIES
// ============================================================================
/*
 * Protocol Message Format Overview:
 * 
 * All messages follow a structured format with headers and optional data sections.
 * Headers are always 6 characters in brackets: [XXXX]
 * 
 * Basic Message Formats:
 * 1. Simple: [HEADER]content
 *    Example: [RESP]Connection successful
 * 
 * 2. User Message: [USER]username[MESG]message_content
 *    Example: [USER]alice[MESG]Hello everyone!
 * 
 * 3. List Response: [LRES][USER]name1[ROLE]role1[USER]name2[ROLE]role2...
 *    Example: [LRES][USER]Server[ROLE]server[USER]alice[ROLE]client
 * 
 * 4. Msg (Direct Message): [SEND][USER]sender[USER]recipient1[USER]recipient2...[MESG]content
 *    Example: [SEND][USER]alice[USER]bob[USER]charlie[MESG]Secret message
 * 
 * 5. Admin Command with Password: [HEADER][PASS]password[USER]args
 *    Example: [CLRQ][PASS]admin123[USER]alice,bob
 * 
 * The fixed-length header design allows:
 * - Fast message type identification (read first 6 bytes)
 * - Simple parsing without delimiters
 * - Clear message boundaries in the protocol
 */

/**
 * @brief Extract the protocol header from a message buffer.
 *
 * Reads up to HEADER_LENGTH bytes from the provided buffer and converts
 * that substring into a MessageHeader enum using stringToHeader(). This
 * is the canonical way to identify the message type before parsing the
 * rest of the message payload.
 *
 * @param buffer Raw message buffer received from network
 * @param buffer_len Length of the buffer in bytes
 * @return The MessageHeader enum value corresponding to the header
 *
 * Example:
 *   extractHeader("[RESP]OK", 6) -> MessageHeader::RESPONSE
 */
inline MessageHeader extractHeader(const char* buffer, size_t buffer_len) {
    size_t len = std::min((size_t)HEADER_LENGTH, buffer_len);
    std::string header_str(buffer, len);
    return stringToHeader(header_str);
}

/**
 * @brief Extract a username field from a protocol buffer starting at offset.
 *
 * Reads characters from buffer+offset until the next '[' bracket or end
 * of string and returns the substring as the username. This helper is
 * useful when parsing multi-part messages that tag usernames with [USER].
 *
 * @param buffer The complete message buffer
 * @param offset Byte position to start reading from (typically after header)
 * @return The extracted username (stops at next '[' or end of string)
 *
 * Example:
 *   extractUsername("[USER]alice[MESG]hello", 6) -> "alice"
 */
inline std::string extractUsername(const char* buffer, size_t offset) {
    std::string user(buffer + offset);
    size_t end_pos = user.find('[');
    if(end_pos != std::string::npos) {
        user = user.substr(0, end_pos);
    }
    return user;
}

/**
 * @brief Parse a comma-separated list of usernames into individual strings.
 *
 * Duplicates in the input are collapsed: only the first occurrence is
 * kept. This preserves order while preventing duplicate processing when
 * commands target multiple users.
 *
 * @param usernames_str Comma-separated username string (no spaces expected)
 * @return Vector of individual usernames in the same order as input
 *
 * Examples:
 *   parseUsernames("alice,bob,charlie") -> ["alice","bob","charlie"]
 *   parseUsernames("singleuser") -> ["singleuser"]
 */
inline std::vector<std::string> parseUsernames(const std::string& usernames_str) {
    std::vector<std::string> usernames;
    std::unordered_set<std::string> seen;  // Track duplicates
    size_t start = 0;
    size_t comma_pos;
    
    while((comma_pos = usernames_str.find(',', start)) != std::string::npos) {
        std::string username = usernames_str.substr(start, comma_pos - start);
        // Only add if not already seen
        if(seen.find(username) == seen.end()) {
            usernames.push_back(username);
            seen.insert(username);
        }
        start = comma_pos + 1;
    }
    
    std::string last_username = usernames_str.substr(start);
    // Only add if not already seen
    if(seen.find(last_username) == seen.end()) {
        usernames.push_back(last_username);
        seen.insert(last_username);
    }
    
    return usernames;
}

// ============================================================================
// MESSAGE BUILDING UTILITIES
// ============================================================================
/*
 * These functions construct protocol-compliant messages for network transmission.
 * All messages must follow the protocol format defined in MESSAGE PARSING UTILITIES.
 * 
 * Usage Pattern:
 * 1. Build message using appropriate function
 * 2. Send via socket: send(socket_fd, msg.c_str(), msg.length(), 0)
 * 3. Receiver extracts header, then parses remaining data
 */

/**
 * @brief Construct a simple protocol message consisting of a header and content.
 *
 * This function concatenates the header text (e.g., "[RESP]") with the
 * provided content. It is the fundamental building block used by higher
 * level message constructors.
 *
 * @param header Protocol header enum (e.g., MessageHeader::ENTER)
 * @param content String content to follow the header
 * @return Formatted message string ready for send(), e.g. "[RESP]OK"
 *
 * Example:
 *   buildMessage(MessageHeader::RESPONSE, "OK") -> "[RESP]OK"
 */
inline std::string buildMessage(MessageHeader header, const std::string& content) {
    return headerToString(header) + content;
}

/**
 * @brief Build a standard user chat message including the sender and message.
 *
 * Produces a message of the form: [USER]username[MESG]message. Use this
 * when sending chat text to other clients or broadcasting.
 *
 * @param username Sender's username
 * @param message Message body (note: message bodies may be sensitive; if
 *                you don't want bodies in server logs, log metadata only)
 * @return Formatted message string following protocol
 *
 * Example:
 *   buildUserMessage("alice", "Hello!") -> "[USER]alice[MESG]Hello!"
 */
inline std::string buildUserMessage(const std::string& username, const std::string& message) {
    return buildMessage(MessageHeader::USER, username) + buildMessage(MessageHeader::MESSAGE, message);
}

/**
 * @brief Build a list response message enumerating users and their roles.
 *
 * Produces a [LRES] message that contains repeated [USER] and [ROLE]
 * pairs. The server name should be included first in `usernames` and
 * receives the role "server". Other users are marked as "admin" or
 * "client" according to admin_usernames.
 *
 * @param usernames Ordered vector of all usernames (server first)
 * @param admin_usernames Set of usernames with admin privileges
 * @param server_name Server username which receives the "server" role
 * @return Formatted list response string for transmission
 *
 * Example:
 *   buildListResponse({"Server","alice","bob"}, {"alice"}, "Server") ->
 *     "[LRES][USER]Server[ROLE]server[USER]alice[ROLE]admin[USER]bob[ROLE]client"
 */
inline std::string buildListResponse(const std::vector<std::string>& usernames, 
                                     const std::unordered_set<std::string>& admin_usernames,
                                     const std::string& server_name) {
    std::string msg = buildMessage(MessageHeader::LIST_RESPONSE, "");
    for(const auto& username : usernames) {
        msg += buildMessage(MessageHeader::USER, username);
        // Determine role
        if(username == server_name) {
            msg += buildMessage(MessageHeader::ROLE, "server");
        } else if(admin_usernames.find(username) != admin_usernames.end()) {
            msg += buildMessage(MessageHeader::ROLE, "admin");
        } else {
            msg += buildMessage(MessageHeader::ROLE, "client");
        }
    }
    return msg;
}

/**
 * @brief Parse a [LRES] list response and extract (username, role) pairs.
 *
 * Parses repeated [USER] and [ROLE] entries from the message buffer and
 * fills users_with_roles in order. Returns false on format mismatch or
 * if the buffer is not a LIST_RESPONSE.
 *
 * @param buffer The complete message buffer received from network
 * @param users_with_roles Output vector filled with (username, role) pairs
 * @return true if parsing succeeded and at least one user was extracted
 *
 * Example:
 *   parseListResponse("[LRES][USER]Server[ROLE]server[USER]alice[ROLE]client", out)
 *     -> out = {{"Server","server"},{"alice","client"}}
 */
inline bool parseListResponse(const char* buffer, std::vector<std::pair<std::string, std::string>>& users_with_roles) {
    std::string full_msg(buffer);
    
    // Verify this is a list response message
    MessageHeader header = extractHeader(buffer, full_msg.length());
    if(header != MessageHeader::LIST_RESPONSE) {
        return false;
    }
    
    size_t pos = HEADER_LENGTH;
    users_with_roles.clear();
    
    // Parse all [USER] and [ROLE] pairs
    while(pos < full_msg.length()) {
        MessageHeader current_header = extractHeader(full_msg.c_str() + pos, full_msg.length() - pos);
        if(current_header == MessageHeader::USER) {
            pos += HEADER_LENGTH;
            size_t end_pos = full_msg.find('[', pos);
            if(end_pos == std::string::npos) break;
            
            std::string username = full_msg.substr(pos, end_pos - pos);
            pos = end_pos;
            
            // Now expect [ROLE]
            current_header = extractHeader(full_msg.c_str() + pos, full_msg.length() - pos);
            if(current_header == MessageHeader::ROLE) {
                pos += HEADER_LENGTH;
                end_pos = full_msg.find('[', pos);
                
                std::string role;
                if(end_pos == std::string::npos) {
                    // Last entry
                    role = full_msg.substr(pos);
                } else {
                    role = full_msg.substr(pos, end_pos - pos);
                }
                
                users_with_roles.push_back({username, role});
                
                if(end_pos == std::string::npos) break;
                pos = end_pos;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    
    return !users_with_roles.empty();
}

/**
 * @brief Build a send-to (direct) message targeted at specific recipients.
 *
 * The message format contains the sender followed by one or more
 * recipient [USER] fields and ends with a [MESG] message body.
 *
 * @param sender Sender username
 * @param recipients Vector of recipient usernames in order
 * @param message Message body (may be sensitive; avoid logging bodies if not desired)
 * @return Formatted msg message string ready for transmission
 *
 * Example:
 *   buildMsgMessage("alice", {"bob","charlie"}, "Hi!") ->
 *     "[SEND][USER]alice[USER]bob[USER]charlie[MESG]Hi!"
 */
inline std::string buildMsgMessage(const std::string& sender, const std::vector<std::string>& recipients, const std::string& message) {
    std::string msg = buildMessage(MessageHeader::MSG, "");
    msg += buildMessage(MessageHeader::USER, sender);
    for(const auto& recipient : recipients) {
        msg += buildMessage(MessageHeader::USER, recipient);
    }
    msg += buildMessage(MessageHeader::MESSAGE, message);
    return msg;
}

/**
 * @brief Build a confirmation response summarizing msg delivery results.
 *
 * Constructs a [RESP] message that reports how many recipients
 * succeeded and lists usernames for which delivery failed.
 *
 * @param success_count Number of recipients where delivery succeeded
 * @param failed_users Vector of usernames that failed delivery
 * @return Formatted response message for clients/operators
 *
 * Example:
 *   buildConfirmationMessage(2, {"dave"}) ->
 *     "[RESP]Message sent to 2 client(s). Failed: 'dave'"
 */
inline std::string buildConfirmationMessage(int success_count, const std::vector<std::string>& failed_users) {
    std::string msg = buildMessage(MessageHeader::RESPONSE, "\n");
    if(success_count > 0) {
        msg += "Message sent to " + std::to_string(success_count) + " client(s).";
    } else {
        msg += "Message failed to send.";
    }
    
    if(!failed_users.empty()) {
        msg += " Failed: ";
        for(size_t i = 0; i < failed_users.size(); ++i) {
            msg += "'" + failed_users[i] + "'";
            if(i < failed_users.size() - 1) msg += ", ";
        }
    }
    
    return msg;
}

/**
 * @brief Build a confirmation response for the /close command.
 *
 * Reports the number of successfully closed client connections and
 * enumerates usernames that could not be found/closed.
 *
 * @param closed_count Number of successfully closed connections
 * @param failed_users Vector of usernames that were not found/closed
 * @return Formatted [RESP] message summarizing the result
 *
 * Example:
 *   buildCloseConfirmationMessage(1, {"alice","bob"}) ->
 *     "[RESP]Closed 1 client connection(s). User 'alice' not found. User 'bob' not found."
 */
inline std::string buildCloseConfirmationMessage(int closed_count, const std::vector<std::string>& failed_users) {
    std::string msg = buildMessage(MessageHeader::RESPONSE, "");
    
    if(closed_count > 0) {
        msg += "Closed " + std::to_string(closed_count) + " client connection(s).";
    }
    
    if(!failed_users.empty()) {
        if(closed_count > 0) msg += " ";
        for(size_t i = 0; i < failed_users.size(); ++i) {
            msg += "User '" + failed_users[i] + "' not found.";
            if(i < failed_users.size() - 1) msg += " ";
        }
    }
    
    return msg;
}

/**
 * @brief Parse a send-to message and extract sender, recipients, and body.
 *
 * Walks the message fields in order and fills the output parameters. The
 * first [USER] field is interpreted as the sender, subsequent [USER]
 * fields are recipients, and [MESG] contains the message body.
 *
 * @param buffer Complete message buffer received from network
 * @param sender Output parameter: populated with sender username
 * @param recipients Output vector: populated with recipient usernames in order
 * @param message Output parameter: populated with message content
 * @return true on successful parse, false on format error
 *
 * Example:
 *   parseMsgMessage("[SEND][USER]alice[USER]bob[MESG]Hi", s, r, m)
 *     -> s="alice", r={"bob"}, m="Hi"
 */
inline bool parseMsgMessage(const char* buffer, std::string& sender, std::vector<std::string>& recipients, std::string& message) {
    std::string full_msg(buffer);
    
    // Verify this is a msg message
    MessageHeader header = extractHeader(buffer, full_msg.length());
    if(header != MessageHeader::MSG) {
        return false;
    }
    
    size_t pos = HEADER_LENGTH;
    recipients.clear();
    
    // Parse all [USER] tagged usernames and the [MESG] content
    while(pos < full_msg.length()) {
        MessageHeader current_header = extractHeader(full_msg.c_str() + pos, full_msg.length() - pos);
        if(current_header == MessageHeader::USER) {
            pos += HEADER_LENGTH;
            size_t end_pos = full_msg.find('[', pos);
            if(end_pos == std::string::npos) break;
            
            std::string username = full_msg.substr(pos, end_pos - pos);
            
            // First [USER] tag is always the sender
            if(sender.empty()) {
                sender = username;
            } else {
                recipients.push_back(username);
            }
            pos = end_pos;
        }
        else if(current_header == MessageHeader::MESSAGE) {
            pos += HEADER_LENGTH;
            message = full_msg.substr(pos);
            return true;
        }
        else {
            break;
        }
    }
    
    return false;
}

/**
 * @brief Build a timeout query response message.
 *
 * Handles both /timeout and /servertimeout commands by showing usage and current value.
 * Used when the server receives an empty timeout request (query instead of set).
 *
 * @param command_pattern The full command pattern (e.g., "/timeout" or "/servertimeout")
 * @param current_value The current timeout value in minutes (0 = disabled)
 * @return Formatted response message with usage info and current value
 *
 * Example: buildTimeoutQueryResponse("/timeout", 10)
 *          Returns: "[RESP]Usage: /timeout\nCurrent client timeout: 10 minute(s)"
 *
 * Example: buildTimeoutQueryResponse("/servertimeout", 0)
 *          Returns: "[RESP]Usage: /servertimeout\nCurrent server timeout: 0 minute(s) (disabled)"
 */
inline std::string buildTimeoutQueryResponse(const std::string& command_pattern, int current_value) {
    std::string usage = getCommandUsage(command_pattern);
    std::string timeout_name = (command_pattern == "/timeout") ? "client timeout" : "server timeout";
    
    std::string response = usage + "\nCurrent " + timeout_name + ": " + 
                          std::to_string(current_value) + " minute(s)";
    
    if(current_value == 0) {
        response += " (disabled)";
    }
    
    return buildMessage(MessageHeader::RESPONSE, response);
}

#endif // COMMON_MESSAGES_HPP
