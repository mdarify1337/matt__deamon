#include "MattDaemon.hpp"
#include <iostream>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <cstring>
#include <algorithm>
#include <errno.h>
#include <cstdlib>



// Use local paths instead of system paths
const std::string MattDaemon::LOCK_FILE = "./matt_daemon.log";
MattDaemon *MattDaemon::instance = nullptr;
std::atomic<bool> MattDaemon::running{true};

MattDaemon::MattDaemon() : serverSocket(-1), lockFileDescriptor(-1), clientSessions(), logger(TintinReporter::getInstance()),
                           authManager(AuthManager::getInstance()) {
    instance = this;
    authManager.loadUsers();
}

MattDaemon::~MattDaemon()
{
    cleanup();
}

bool MattDaemon::checkRootPrivileges()
{
    if (getuid() != 0)
    {
        std::cerr << "Matt_daemon must be run as root" << std::endl;
        return false;
    }
    return true;
}

void MattDaemon::removeLockFile() {
    if (lockFileDescriptor != -1) {
        flock(lockFileDescriptor, LOCK_UN);
        close(lockFileDescriptor);
        unlink(LOCK_FILE.c_str());
        lockFileDescriptor = -1;
    }
}

bool MattDaemon::createLockFile()
{
    lockFileDescriptor = open(LOCK_FILE.c_str(), O_CREAT | O_RDWR, 0777);
    if (lockFileDescriptor == -1)
    {
        std::cerr << "Can't open lock file " << LOCK_FILE << ": " << strerror(errno) << std::endl;
        logger.log(TintinReporter::ERROR, "Matt_daemon: Error opening lock file.");
        return false;
    }

    if (flock(lockFileDescriptor, LOCK_EX | LOCK_NB) == -1)
    {
        std::cerr << "Can't lock file " << LOCK_FILE << ": " << strerror(errno) << std::endl;
        logger.log(TintinReporter::ERROR, "Matt_daemon: Error - daemon already running or file locked.");
        close(lockFileDescriptor);
        lockFileDescriptor = -1;
        return false;
    }

    std::string pidStr = std::to_string(getpid()) + "\n";
    if (write(lockFileDescriptor, pidStr.c_str(), pidStr.length()) == -1)
    {
        std::cerr << "Failed to write PID to lock file: " << strerror(errno) << std::endl;
    }

    std::cout << "Lock file created successfully: " << LOCK_FILE << std::endl;
    return true;
}


void MattDaemon::daemonize()
{
    logger.log(TintinReporter::INFO, "Matt_daemon: Entering Daemon mode.");
    
    // First fork
    pid_t pid = fork();
    if (pid < 0)
    {
        logger.log(TintinReporter::ERROR, "Matt_daemon: First fork failed.");
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
    {
        exit(EXIT_SUCCESS); // Parent exits
    }

    
    if (setsid() < 0)
    {
        logger.log(TintinReporter::ERROR, "Matt_daemon: setsid failed.");
        exit(EXIT_FAILURE);
    }

    // Ignore SIGHUP
    signal(SIGHUP, SIG_IGN);

    // Second fork
    pid = fork();
    if (pid < 0)
    {
        logger.log(TintinReporter::ERROR, "Matt_daemon: Second fork failed.");
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
    {
        exit(EXIT_SUCCESS); // Parent exits
    }

    // Change working directory to home instead of root
    const char *home = getenv("HOME");
    if (home && chdir(home) < 0)
    {
        logger.log(TintinReporter::ERROR, "Matt_daemon: chdir to home failed.");
        if (chdir("/tmp") < 0)
        {
            logger.log(TintinReporter::ERROR, "Matt_daemon: chdir to /tmp failed.");
            exit(EXIT_FAILURE);
        }
    }

    // Set file permissions
    umask(0);

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect standard file descriptors to /dev/null
    int devNull = open("/dev/null", O_RDWR);
    if (devNull != -1)
    {
        dup2(devNull, STDIN_FILENO);
        dup2(devNull, STDOUT_FILENO);
        dup2(devNull, STDERR_FILENO);
        if (devNull > STDERR_FILENO)
        {
            close(devNull);
        }
    }

    logger.log(TintinReporter::INFO, "Matt_daemon: started. PID: " + std::to_string(getpid()) + ".");
}

bool MattDaemon::createServer()
{
    logger.log(TintinReporter::INFO, "Matt_daemon: Creating server.");
    logger.log(TintinReporter::INFO, "Matt_daemon: Server created.");
    logger.log(TintinReporter::INFO, "Matt_daemon: started. PID: " + std::to_string(getpid()) + ".");
    std::cout << "Creating server on port " << PORT << std::endl;
    
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        std::string error_msg = "Socket creation failed: " + std::string(strerror(errno));
        std::cerr << error_msg << std::endl;
        logger.log(TintinReporter::ERROR, "Matt_daemon: " + error_msg);
        return false;
    }
    std::cout << "Socket created successfully: " << serverSocket << std::endl;

    // Set socket options
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        std::string error_msg = "setsockopt failed: " + std::string(strerror(errno));
        std::cerr << error_msg << std::endl;
        logger.log(TintinReporter::ERROR, "Matt_daemon: " + error_msg);
        close(serverSocket);
        serverSocket = -1;
        return false;
    }
    std::cout << "Socket options set successfully" << std::endl;

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);
    
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        std::string error_msg = "Bind failed: " + std::string(strerror(errno));
        std::cerr << error_msg << std::endl;
        logger.log(TintinReporter::ERROR, "Matt_daemon: " + error_msg);
        close(serverSocket);
        serverSocket = -1;
        return false;
    }
    std::cout << "Socket bound successfully to port " << PORT << std::endl;

    if (listen(serverSocket, MAX_CLIENTS) < 0)
    {
        std::string error_msg = "Listen failed: " + std::string(strerror(errno));
        std::cerr << error_msg << std::endl;
        logger.log(TintinReporter::ERROR, "Matt_daemon: " + error_msg);
        close(serverSocket);
        serverSocket = -1;
        return false;
    }

    std::cout << "Server listening on port " << PORT << std::endl;
    logger.log(TintinReporter::INFO, "Matt_daemon: Server created on port " + std::to_string(PORT));
    return true;
}

void MattDaemon::setupSignalHandlers()
{
    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGQUIT, &sa, nullptr);
    
    std::cout << "Signal handlers setup complete" << std::endl;
}

void MattDaemon::signalHandler(int signal)
{
    if (instance)
    {
        instance->logger.log(TintinReporter::INFO, "Matt_daemon: Received signal " + std::to_string(signal));
        running = false;
    }
}

void MattDaemon::acceptNewConnection(fd_set& readFds) {
    if (!FD_ISSET(serverSocket, &readFds)) {
        return;
    }

    if (clientSessions.size() >= MAX_CLIENTS) {
        int newSocket = accept(serverSocket, nullptr, nullptr);
        if (newSocket != -1) {
            close(newSocket);
        }
        logger.log(TintinReporter::WARNING, "Matt_daemon: Max clients reached, connection rejected.");
        return;
    }

    struct sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);
    int newSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
    
    if (newSocket != -1) {
        auto session = std::make_unique<ClientSession>();
        session->socket = newSocket;
        session->authenticated = false;
        session->encryptionKey = Crypto::generateKey();
        session->lastActivity = std::chrono::steady_clock::now();
        
        clientSessions[newSocket] = std::move(session);
        
        // Send welcome message with encryption key
        std::string welcome = "MATT_DAEMON_V2\nKEY:" + clientSessions[newSocket]->encryptionKey + "\nAUTH_REQUIRED\n";
        send(newSocket, welcome.c_str(), welcome.length(), 0);
        
        logger.log(TintinReporter::INFO, "Matt_daemon: New client connected from " + 
                  std::string(inet_ntoa(clientAddr.sin_addr)));
    }
}

std::string MattDaemon::encryptMessage(const std::string& message, const std::string& key) {
    return Crypto::encrypt(message, key);
}

std::string MattDaemon::decryptMessage(const std::string& message, const std::string& key) {
    try {
        return Crypto::decrypt(message, key);
    } catch (...) {
        return message; // Return original if decryption fails
    }
}
void MattDaemon::handleClientData(int clientSocket, fd_set& readFds) {
    if (!FD_ISSET(clientSocket, &readFds)) {
        return;
    }

    auto it = clientSessions.find(clientSocket);
    if (it == clientSessions.end()) {
        return;
    }

    ClientSession* session = it->second.get();
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    
    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesReceived <= 0) {
        logger.log(TintinReporter::INFO, "Matt_daemon: Client " + session->username + " disconnected.");
        close(clientSocket);
        clientSessions.erase(it);
        return;
    }

    session->lastActivity = std::chrono::steady_clock::now();
    
    std::string message(buffer, bytesReceived);
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
        message.pop_back();
    }

    processClientMessage(session, message);
}

void MattDaemon::handleRemoteShellCommand(ClientSession* session, const std::string& command) {
    logger.log(TintinReporter::INFO, "Matt_daemon: Remote shell command from " + 
              session->username + ": " + command);
    
    // Execute command and capture output
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::string response = "SHELL_ERROR: Failed to execute command";
        if (!session->encryptionKey.empty()) {
            response = encryptMessage(response, session->encryptionKey);
        }
        send(session->socket, response.c_str(), response.length(), 0);
        return;
    }
    
    std::string output;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    
    std::string response = "SHELL_OUTPUT:\n" + output;
    if (!session->encryptionKey.empty()) {
        response = encryptMessage(response, session->encryptionKey);
    }
    send(session->socket, response.c_str(), response.length(), 0);
}


void MattDaemon::handleAuthenticationRequest(ClientSession* session, const std::string& message) {
    if (message.substr(0, 4) == "AUTH") {
        std::istringstream iss(message.substr(5));
        std::string username, password;
        if (std::getline(iss, username, ':') && std::getline(iss, password)) {
            if (authManager.authenticate(username, password)) {
                session->authenticated = true;
                session->username = username;
                
                std::string response = "AUTH_SUCCESS\nWelcome " + username + "!\nCommands: quit, SHELL <command>, REGISTER <user>:<pass>";
                if (!session->encryptionKey.empty()) {
                    response = encryptMessage(response, session->encryptionKey);
                }
                send(session->socket, response.c_str(), response.length(), 0);
                
                logger.log(TintinReporter::INFO, "Matt_daemon: User " + username + " authenticated successfully.");
            } else {
                std::string response = "AUTH_FAILED";
                if (!session->encryptionKey.empty()) {
                    response = encryptMessage(response, session->encryptionKey);
                }
                send(session->socket, response.c_str(), response.length(), 0);
                
                logger.log(TintinReporter::WARNING, "Matt_daemon: Authentication failed for user: " + username);
            }
        }
    }
}

void MattDaemon::cleanupInactiveSessions() {
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::minutes(30); // 30 minute timeout
    
    for (auto it = clientSessions.begin(); it != clientSessions.end();) {
        if (now - it->second->lastActivity > timeout) {
            logger.log(TintinReporter::INFO, "Matt_daemon: Session timeout for user: " + 
                      it->second->username);
            close(it->first);
            it = clientSessions.erase(it);
        } else {
            ++it;
        }
    }
}


void MattDaemon::processClientMessage(ClientSession* session, const std::string& message) {
    if (message.empty()) return;

    // Try to decrypt message if client is authenticated
    std::string decryptedMessage = message;
    if (session->authenticated && !session->encryptionKey.empty()) {
        decryptedMessage = decryptMessage(message, session->encryptionKey);
    }

    if (!session->authenticated) {
        handleAuthenticationRequest(session, decryptedMessage);
        return;
    }

    if (decryptedMessage == "quit") {
        logger.log(TintinReporter::INFO, "Matt_daemon: Request quit from " + session->username);
        running = false;
        return;
    }

    if (decryptedMessage.substr(0, 5) == "SHELL") {
        handleRemoteShellCommand(session, decryptedMessage.substr(6));
        return;
    }

    if (decryptedMessage.substr(0, 8) == "REGISTER") {
        std::istringstream iss(decryptedMessage.substr(9));
        std::string username, password;
        if (std::getline(iss, username, ':') && std::getline(iss, password)) {
            if (authManager.registerUser(username, password)) {
                std::string response = "USER_REGISTERED";
                if (!session->encryptionKey.empty()) {
                    response = encryptMessage(response, session->encryptionKey);
                }
                send(session->socket, response.c_str(), response.length(), 0);
                logger.log(TintinReporter::INFO, "Matt_daemon: New user registered: " + username);
            } else {
                std::string response = "REGISTRATION_FAILED";
                if (!session->encryptionKey.empty()) {
                    response = encryptMessage(response, session->encryptionKey);
                }
                send(session->socket, response.c_str(), response.length(), 0);
            }
        }
        return;
    }

    logger.log(TintinReporter::LOG, "Matt_daemon: User input from " + session->username + ": " + decryptedMessage);
}


void MattDaemon::handleConnections() {
    fd_set readFds;
    int maxFd;
    struct timeval timeout;

    while (running) {
        FD_ZERO(&readFds);
        FD_SET(serverSocket, &readFds);
        maxFd = serverSocket;

        for (const auto& pair : clientSessions) {
            FD_SET(pair.first, &readFds);
            if (pair.first > maxFd) {
                maxFd = pair.first;
            }
        }

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(maxFd + 1, &readFds, nullptr, nullptr, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            logger.log(TintinReporter::ERROR, "Matt_daemon: select error.");
            break;
        }

        if (activity > 0) {
            acceptNewConnection(readFds);

            // Handle existing clients
            std::vector<int> socketsToProcess;
            for (const auto& pair : clientSessions) {
                socketsToProcess.push_back(pair.first);
            }
            
            for (int socket : socketsToProcess) {
                handleClientData(socket, readFds);
            }
        }
        
        // Cleanup inactive sessions every minute
        static auto lastCleanup = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (now - lastCleanup > std::chrono::minutes(1)) {
            cleanupInactiveSessions();
            logger.archiveLogs();
            lastCleanup = now;
        }
    }
}


void MattDaemon::closeAllConnections() {
    for (const auto& pair : clientSessions) {
        close(pair.first);
    }
    clientSessions.clear();

    if (serverSocket != -1) {
        close(serverSocket);
        serverSocket = -1;
    }
}

void MattDaemon::cleanup()
{
    std::cout << "Cleaning up..." << std::endl;
    logger.log(TintinReporter::INFO, "Matt_daemon: Cleaning up and quitting");
    closeAllConnections();
    removeLockFile();
}

void MattDaemon::run()
{
    std::cout << "Matt_daemon starting up..." << std::endl;
    logger.log(TintinReporter::INFO, "Matt_daemon: Starting up");

    std::cout << "Skipping root privilege check for testing..." << std::endl;

    if (!createLockFile())
    {
        std::cerr << "Failed to create lock file, quitting" << std::endl;
        logger.log(TintinReporter::ERROR, "Matt_daemon: Failed to create lock file, quitting");
        return;
    }

    if (!createServer())
    {
        std::cerr << "Failed to create server, quitting" << std::endl;
        logger.log(TintinReporter::ERROR, "Matt_daemon: Failed to create server, quitting");
        cleanup();
        return;
    }
    setupSignalHandlers();
    std::cout << "Skipping daemonization for debugging..." << std::endl;
    daemonize();
    handleConnections();
    cleanup();
}