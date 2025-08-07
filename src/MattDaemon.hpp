#pragma once

#include "TintinReporter.hpp"
#include "AuthManager.hpp"
#include "Crypto.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <atomic>
#include <unordered_map>
#include <memory>
#include <sstream>


struct ClientSession {
    int socket;
    bool authenticated;
    std::string username;
    std::string encryptionKey;
    std::chrono::steady_clock::time_point lastActivity;
};

class MattDaemon {
public:
    // Coplien form
    MattDaemon();
    ~MattDaemon();
    MattDaemon(const MattDaemon& other) = delete;
    MattDaemon& operator=(const MattDaemon& other) = delete;

    void run();
    static void signalHandler(int signal);

private:
    static const int PORT = 4245;
    static const int MAX_CLIENTS = 3;
    static const std::string LOCK_FILE;
    static MattDaemon* instance;
    static std::atomic<bool> running;

    int serverSocket;
    int lockFileDescriptor;
    std::unordered_map<int, std::unique_ptr<ClientSession>> clientSessions;
    TintinReporter& logger;
    AuthManager& authManager;

    bool checkRootPrivileges();
    bool createLockFile();
    void removeLockFile();
    void daemonize();
    bool createServer();
    void handleConnections();
    void acceptNewConnection(fd_set& readFds);
    void handleClientData(int clientSocket, fd_set& readFds);
    void processClientMessage(ClientSession* session, const std::string& message);
    void handleAuthenticationRequest(ClientSession* session, const std::string& message);
    void handleRemoteShellCommand(ClientSession* session, const std::string& command);
    void closeAllConnections();
    void cleanup();
    void setupSignalHandlers();
    void cleanupInactiveSessions();
    std::string encryptMessage(const std::string& message, const std::string& key);
    std::string decryptMessage(const std::string& message, const std::string& key);
};