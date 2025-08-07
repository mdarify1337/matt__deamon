#pragma once

#include <string>
#include <unordered_map>
#include <mutex>

class AuthManager {
public:
    static AuthManager& getInstance();
    
    bool authenticate(const std::string& username, const std::string& password);
    bool registerUser(const std::string& username, const std::string& password);
    void loadUsers();
    void saveUsers();
    
private:
    AuthManager() = default;
    std::unordered_map<std::string, std::string> users; // username -> password hash
    std::mutex authMutex;
    static const std::string AUTH_FILE;
};