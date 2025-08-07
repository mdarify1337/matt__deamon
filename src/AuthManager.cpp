#include "AuthManager.hpp"
#include "Crypto.hpp"
#include <fstream>
#include <sstream>

const std::string AuthManager::AUTH_FILE = "/etc/matt_daemon/users.auth";

AuthManager& AuthManager::getInstance() {
    static AuthManager instance;
    return instance;
}

bool AuthManager::authenticate(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(authMutex);
    auto it = users.find(username);
    if (it != users.end()) {
        return Crypto::verifyPassword(password, it->second);
    }
    return false;
}

bool AuthManager::registerUser(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(authMutex);
    if (users.find(username) != users.end()) {
        return false; // User already exists
    }
    
    users[username] = Crypto::hashPassword(password);
    saveUsers();
    return true;
}

void AuthManager::loadUsers() {
    std::lock_guard<std::mutex> lock(authMutex);
    std::ifstream file(AUTH_FILE);
    if (!file.is_open()) {
        // Create default admin user
        users["admin"] = Crypto::hashPassword("admin123");
        saveUsers();
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string username, hash;
        if (std::getline(iss, username, ':') && std::getline(iss, hash)) {
            users[username] = hash;
        }
    }
}

void AuthManager::saveUsers() {
    // Create directory if it doesn't exist
    system("mkdir -p /etc/matt_daemon");
    
    std::ofstream file(AUTH_FILE);
    if (file.is_open()) {
        for (const auto& pair : users) {
            file << pair.first << ":" << pair.second << std::endl;
        }
    }
}
