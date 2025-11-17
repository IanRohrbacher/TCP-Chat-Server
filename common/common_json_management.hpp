/*
 * common_json_management.hpp
 * 
 * Generic JSON-based configuration management system.
 * Provides reusable functions for loading, saving, and modifying JSON configurations.
 * Used by both admin and whitelist systems.
 */

#ifndef COMMON_JSON_MANAGEMENT_HPP
#define COMMON_JSON_MANAGEMENT_HPP

#include <string>
#include <vector>
#include <utility>
#include <fstream>
#include <iostream>
#include <mutex>
#include "../nlohmann/json.hpp"

using json = nlohmann::json;

// ============================================================================
// ADMIN CONFIGURATION
// ============================================================================

namespace AdminConfig {
    const std::string CONFIG_FILE = "admin_config.json";
    const std::string ROOT_USERNAME = "root";
    
    static std::string root_password = "root123";  // Default
    static std::vector<std::pair<std::string, std::string>> admin_list;
    static std::mutex config_mutex;
    
    /**
     * @brief Load admin configuration from JSON file.
     *
     * If the config file is missing a default file is created and a blank
     * in-memory configuration is left. The method returns false on parse
     * errors or file I/O failures.
     *
     * @return true when the configuration was loaded or default created,
     *         false on error.
     */
    inline bool load() {
        std::lock_guard<std::mutex> lock(config_mutex);
        
        std::ifstream file(CONFIG_FILE);
        if (!file.is_open()) {
            logMessage(getTimestamp() + "CONFIG: Admin config file not found. Creating default configuration.");

            json default_config;
            default_config["root_password"] = root_password;
            default_config["admins"] = json::array();

            std::ofstream out_file(CONFIG_FILE);
            if (!out_file.is_open()) {
                logMessage(getTimestamp() + "ERROR: Failed to create admin config file");
                return false;
            }
            out_file << default_config.dump(4);
            out_file.close();

            admin_list.clear();
            return true;
        }
        
        try {
            json config;
            file >> config;
            file.close();
            
            if (config.contains("root_password")) {
                root_password = config["root_password"].get<std::string>();
            }
            
            admin_list.clear();
            if (config.contains("admins") && config["admins"].is_array()) {
                for (const auto& admin : config["admins"]) {
                    if (admin.contains("username") && admin.contains("password")) {
                        std::string username = admin["username"].get<std::string>();
                        if (username != ROOT_USERNAME) {
                            admin_list.push_back({
                                username,
                                admin["password"].get<std::string>()
                            });
                        }
                    }
                }
            }
            
            logMessage(getTimestamp() + "CONFIG: Loaded admin config; additional admins=" + std::to_string(admin_list.size()));
            return true;
            
        } catch (const json::exception& e) {
            logMessage(getTimestamp() + std::string("ERROR: Failed to parse admin config: ") + e.what());
            return false;
        }
    }
    
    /**
     * @brief Save admin configuration to JSON file.
     *
     * Persists the in-memory admin list and root password to disk. Returns
     * false if the file cannot be written.
     *
     * @return true on successful write, false on error.
     */
    inline bool save() {
        std::lock_guard<std::mutex> lock(config_mutex);
        
        try {
            json config;
            config["root_password"] = root_password;
            config["admins"] = json::array();
            
            for (const auto& admin : admin_list) {
                json admin_obj;
                admin_obj["username"] = admin.first;
                admin_obj["password"] = admin.second;
                config["admins"].push_back(admin_obj);
            }
            
            std::ofstream file(CONFIG_FILE);
            if (!file.is_open()) {
                logMessage(getTimestamp() + "ERROR: Failed to open admin config file for writing");
                return false;
            }

            file << config.dump(4);
            file.close();

            logMessage(getTimestamp() + "CONFIG: Saved admin config; additional admins=" + std::to_string(admin_list.size()));
            return true;
            
        } catch (const json::exception& e) {
            logMessage(getTimestamp() + std::string("ERROR: Failed to save admin config: ") + e.what());
            return false;
        }
    }
    
    /**
     * @brief Get all registered admins (excluding root).
     *
     * @return Vector of (username,password) pairs currently configured.
     */
    inline std::vector<std::pair<std::string, std::string>> getList() {
        std::lock_guard<std::mutex> lock(config_mutex);
        return admin_list;
    }
    
    /**
     * @brief Check if username is an admin (including root).
     *
     * @param username Username to check
     * @return true if username is root or present in the admin list
     */
    inline bool isAdmin(const std::string& username) {
        if (username == ROOT_USERNAME) return true;
        
        std::lock_guard<std::mutex> lock(config_mutex);
        for (const auto& admin : admin_list) {
            if (admin.first == username) return true;
        }
        return false;
    }
    
    /**
     * @brief Get password for a specific admin.
     *
     * Note: callers should avoid logging returned passwords. An empty
     * string is returned when the username is not found.
     *
     * @param username Username to query
     * @return Password string or empty string if absent
     */
    inline std::string getPassword(const std::string& username) {
        if (username == ROOT_USERNAME) {
            std::lock_guard<std::mutex> lock(config_mutex);
            return root_password;
        }
        
        std::lock_guard<std::mutex> lock(config_mutex);
        for (const auto& admin : admin_list) {
            if (admin.first == username) return admin.second;
        }
        return "";
    }
    
    /**
     * @brief Get the configured root password.
     *
     * @return Root password string.
     */
    inline std::string getRootPassword() {
        std::lock_guard<std::mutex> lock(config_mutex);
        return root_password;
    }
    
    /**
     * @brief Set the root password and persist the change.
     *
     * This updates the in-memory root password and immediately saves the
     * configuration to disk using save().
     *
     * @param new_password New root password to set
     * @return true when the new password was saved successfully
     */
    inline bool setRootPassword(const std::string& new_password) {
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            root_password = new_password;
        }
        return save();
    }
    
    /**
     * @brief Add admins to the list.
     *
     * Skips attempts to add the reserved root username. New admins are
     * appended in order; duplicates are ignored. The configuration is
     * saved if any admins were actually added.
     *
     * @param admins Vector of (username,password) pairs to add
     * @return Number of accounts actually added
     */
    inline int add(const std::vector<std::pair<std::string, std::string>>& admins) {
        int added = 0;
        
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            
            for (const auto& new_admin : admins) {
                if (new_admin.first == ROOT_USERNAME) {
                    logMessage(getTimestamp() + "WARNING: Attempted to add reserved username 'root' to admin list");
                    continue;
                }
                
                bool exists = false;
                for (const auto& existing_admin : admin_list) {
                    if (existing_admin.first == new_admin.first) {
                        exists = true;
                        break;
                    }
                }
                
                if (!exists) {
                    admin_list.push_back(new_admin);
                    added++;
                }
            }
        }
        
        if (added > 0) save();
        return added;
    }
    
    /**
     * @brief Remove admins from the list.
     *
     * Attempts to remove each username; removal of the reserved root is
     * ignored. The configuration is saved if any entries were removed.
     *
     * @param usernames Vector of usernames to remove
     * @return Number of accounts removed
     */
    inline int remove(const std::vector<std::string>& usernames) {
        int removed = 0;
        
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            
            for (const auto& username : usernames) {
                if (username == ROOT_USERNAME) {
                    logMessage(getTimestamp() + "WARNING: Attempted to remove reserved username 'root' from admin list");
                    continue;
                }
                
                auto it = admin_list.begin();
                while (it != admin_list.end()) {
                    if (it->first == username) {
                        it = admin_list.erase(it);
                        removed++;
                    } else {
                        ++it;
                    }
                }
            }
        }
        
        if (removed > 0) save();
        return removed;
    }
    
    /**
     * @brief Clear all admins from the list (except root).
     *
     * Removes all additional admins and persists the updated config if any
     * entries were removed.
     *
     * @return Number of accounts cleared
     */
    inline int clear() {
        int cleared = 0;
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            cleared = admin_list.size();
            admin_list.clear();
        }
        
        if (cleared > 0) save();
        return cleared;
    }
    
    /**
     * @brief Get a human-readable status string summarizing the admin config.
     *
     * Intended for operator display; it lists the root user and any
     * additionally registered admins.
     *
     * @return Multi-line status string
     */
    inline std::string getStatus() {
        std::lock_guard<std::mutex> lock(config_mutex);
        
        std::string status = "Admin configuration:\n";
        status += "  Root user: " + ROOT_USERNAME + " (password set)\n";
        status += "  Additional admins: " + std::to_string(admin_list.size()) + "\n";
        
        if (!admin_list.empty()) {
            status += "  Registered admins:\n";
            for (const auto& admin : admin_list) {
                status += "    - " + admin.first + "\n";
            }
        }
        
        return status;
    }
}

// ============================================================================
// WHITELIST CONFIGURATION
// ============================================================================

namespace WhitelistConfig {
    const std::string CONFIG_FILE = "whitelist_config.json";
    
    static bool enabled = false;
    static std::vector<std::pair<std::string, std::string>> user_list;
    static std::mutex config_mutex;
    
    /**
     * @brief Load whitelist configuration from JSON file.
     *
     * If missing, a default file is created and an empty in-memory
     * whitelist is used. Returns false on parse or I/O errors.
     *
     * @return true when loaded or default created, false on error
     */
    inline bool load() {
        std::lock_guard<std::mutex> lock(config_mutex);
        
        std::ifstream file(CONFIG_FILE);
        if (!file.is_open()) {
            logMessage(getTimestamp() + "CONFIG: Whitelist config file not found. Creating default configuration.");

            json default_config;
            default_config["enabled"] = false;
            default_config["users"] = json::array();

            std::ofstream out_file(CONFIG_FILE);
            if (!out_file.is_open()) {
                logMessage(getTimestamp() + "ERROR: Failed to create whitelist config file");
                return false;
            }
            out_file << default_config.dump(4);
            out_file.close();

            enabled = false;
            user_list.clear();
            return true;
        }
        
        try {
            json config;
            file >> config;
            file.close();
            
            enabled = config.value("enabled", false);
            user_list.clear();
            
            if (config.contains("users") && config["users"].is_array()) {
                for (const auto& user : config["users"]) {
                    if (user.contains("username") && user.contains("password")) {
                        user_list.push_back({
                            user["username"].get<std::string>(),
                            user["password"].get<std::string>()
                        });
                    }
                }
            }
            
            logMessage(getTimestamp() + "CONFIG: Loaded whitelist config: enabled=" + std::string(enabled ? "true" : "false") + ", users=" + std::to_string(user_list.size()));
            return true;
            
        } catch (const json::exception& e) {
            logMessage(getTimestamp() + std::string("ERROR: Failed to parse whitelist config: ") + e.what());
            return false;
        }
    }
    
    /**
     * @brief Save whitelist configuration to JSON file.
     *
     * Persists the enabled flag and user list to disk. Returns false on
     * file write error.
     *
     * @return true on success, false on error
     */
    inline bool save() {
        std::lock_guard<std::mutex> lock(config_mutex);
        
        try {
            json config;
            config["enabled"] = enabled;
            config["users"] = json::array();
            
            for (const auto& user : user_list) {
                json user_obj;
                user_obj["username"] = user.first;
                user_obj["password"] = user.second;
                config["users"].push_back(user_obj);
            }
            
            std::ofstream file(CONFIG_FILE);
            if (!file.is_open()) {
                logMessage(getTimestamp() + "ERROR: Failed to open whitelist config file for writing");
                return false;
            }
            
            file << config.dump(4);
            file.close();
            
            logMessage(getTimestamp() + "CONFIG: Saved whitelist config: enabled=" + std::string(enabled ? "true" : "false") + ", users=" + std::to_string(user_list.size()));
            return true;
            
        } catch (const json::exception& e) {
            logMessage(getTimestamp() + std::string("ERROR: Failed to save whitelist config: ") + e.what());
            return false;
        }
    }
    
    /**
     * @brief Check if whitelist is enabled.
     *
     * @return true when whitelist enforcement is active
     */
    inline bool isEnabled() {
        std::lock_guard<std::mutex> lock(config_mutex);
        return enabled;
    }
    
    /**
     * @brief Enable or disable whitelist and persist the change.
     *
     * @param new_enabled New enabled state
     * @return true when save() succeeds
     */
    inline bool setEnabled(bool new_enabled) {
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            enabled = new_enabled;
        }
        return save();
    }
    
    /**
     * @brief Get all whitelisted users.
     *
     * @return Vector of (username,password) pairs currently whitelisted
     */
    inline std::vector<std::pair<std::string, std::string>> getList() {
        std::lock_guard<std::mutex> lock(config_mutex);
        return user_list;
    }
    
    /**
     * @brief Check if username is whitelisted.
     *
     * @param username Username to query
     * @return true if the username exists in the whitelist
     */
    inline bool isWhitelisted(const std::string& username) {
        std::lock_guard<std::mutex> lock(config_mutex);
        for (const auto& user : user_list) {
            if (user.first == username) return true;
        }
        return false;
    }
    
    /**
     * @brief Get password for a specific whitelisted user.
     *
     * @param username Username to query
     * @return Password string or empty string if not found
     */
    inline std::string getPassword(const std::string& username) {
        std::lock_guard<std::mutex> lock(config_mutex);
        for (const auto& user : user_list) {
            if (user.first == username) return user.second;
        }
        return "";
    }
    
    /**
     * @brief Add users to the whitelist.
     *
     * Skips duplicates and persists the config if new users were added.
     *
     * @param users Vector of (username,password) pairs to add
     * @return Number of users actually added
     */
    inline int add(const std::vector<std::pair<std::string, std::string>>& users) {
        int added = 0;
        
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            
            for (const auto& new_user : users) {
                bool exists = false;
                for (const auto& existing_user : user_list) {
                    if (existing_user.first == new_user.first) {
                        exists = true;
                        break;
                    }
                }
                
                if (!exists) {
                    user_list.push_back(new_user);
                    added++;
                }
            }
        }
        
        if (added > 0) save();
        return added;
    }
    
    /**
     * @brief Remove users from the whitelist.
     *
     * Persists changes when any users are removed.
     *
     * @param usernames Vector of usernames to remove
     * @return Number of users removed
     */
    inline int remove(const std::vector<std::string>& usernames) {
        int removed = 0;
        
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            
            for (const auto& username : usernames) {
                auto it = user_list.begin();
                while (it != user_list.end()) {
                    if (it->first == username) {
                        it = user_list.erase(it);
                        removed++;
                    } else {
                        ++it;
                    }
                }
            }
        }
        
        if (removed > 0) save();
        return removed;
    }
    
    /**
     * @brief Clear all users from whitelist.
     *
     * Removes all entries and persists the change if any were present.
     *
     * @return Number of users cleared
     */
    inline int clear() {
        int cleared = 0;
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            cleared = user_list.size();
            user_list.clear();
        }
        
        if (cleared > 0) save();
        return cleared;
    }
    
    /**
     * @brief Get a human-readable status string for the whitelist.
     *
     * @return Multi-line status suitable for operator display.
     */
    inline std::string getStatus() {
        std::lock_guard<std::mutex> lock(config_mutex);
        
        std::string status = "Whitelist status:\n";
        status += "  Enabled: " + std::string(enabled ? "true" : "false") + "\n";
        status += "  Users: " + std::to_string(user_list.size()) + "\n";
        
        if (!user_list.empty()) {
            status += "  Whitelisted users:\n";
            for (const auto& user : user_list) {
                status += "    - " + user.first + "\n";
            }
        }
        
        return status;
    }
}

#endif // COMMON_JSON_MANAGEMENT_HPP
