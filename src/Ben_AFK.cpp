#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <termios.h>
#include <fcntl.h>
#include "Crypto.hpp"
#include <cstring>
#include <sstream>
#include <termios.h>
#include <limits>
#include <vector>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <string>

// Email Handler Class
class EmailHandler {
private:
    std::string smtpServer;
    std::string smtpPort;
    std::string username;
    std::string password;
    bool useSSL;

public:
    struct User {
        std::string email;
        std::string name;
        std::string status;
        int daysSinceLastLogin;
    };

    EmailHandler(const std::string& server = "smtp.gmail.com", 
                const std::string& port = "587",
                const std::string& user = "", 
                const std::string& pass = "",
                bool ssl = true) 
        : smtpServer(server), smtpPort(port), username(user), password(pass), useSSL(ssl) {}

    // Method 1: Improved sendmail with proper headers
    bool sendEmailWithSendmail(const std::string& to, const std::string& subject, const std::string& body) {
        // Check if sendmail exists
        if (system("which sendmail > /dev/null 2>&1") != 0) {
            std::cout << "❌ sendmail not found on system" << std::endl;
            return false;
        }

        std::string command = "sendmail -t";
        FILE *mail = popen(command.c_str(), "w");
        if (!mail) {
            std::cout << "❌ Failed to open sendmail pipe" << std::endl;
            return false;
        }

        // Write proper email headers
        fprintf(mail, "From: Ben_AFK Client <client@localhost>\n");
        fprintf(mail, "To: %s\n", to.c_str());
        fprintf(mail, "Subject: %s\n", subject.c_str());
        fprintf(mail, "Content-Type: text/plain; charset=UTF-8\n");
        fprintf(mail, "\n"); // Empty line separates headers from body
        fprintf(mail, "%s\n", body.c_str());

        int result = pclose(mail);
        if (result == 0) {
            std::cout << "✅ Email sent successfully to " << to << std::endl;
            return true;
        } else {
            std::cout << "❌ Failed to send email via sendmail (exit code: " << result << ")" << std::endl;
            return false;
        }
    }

    // Method 2: Log emails to file (for development/testing)
    bool logEmailToFile(const std::string& to, const std::string& subject, const std::string& body) {
        std::string filename = "/tmp/ben_afk_emails.log";
        std::ofstream emailLog(filename, std::ios::app);
        
        if (!emailLog.is_open()) {
            std::cout << "❌ Failed to open email log file: " << filename << std::endl;
            return false;
        }

        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        
        emailLog << "========================================" << std::endl;
        emailLog << "Timestamp: " << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << std::endl;
        emailLog << "To: " << to << std::endl;
        emailLog << "Subject: " << subject << std::endl;
        emailLog << "Body:" << std::endl;
        emailLog << body << std::endl;
        emailLog << "========================================" << std::endl << std::endl;
        
        emailLog.close();
        
        std::cout << "📝 Email logged to file: " << filename << std::endl;
        std::cout << "   To: " << to << std::endl;
        std::cout << "   Subject: " << subject << std::endl;
        return true;
    }

    // Method 3: Using external mail command with better formatting
    bool sendEmailWithMailCommand(const std::string& to, const std::string& subject, const std::string& body) {
        // Check if mail command exists
        if (system("which mail > /dev/null 2>&1") != 0) {
            std::cout << "❌ mail command not found on system" << std::endl;
            return false;
        }

        // Escape quotes in subject and body
        std::string escaped_subject = subject;
        std::string escaped_body = body;
        
        // Replace quotes with escaped quotes
        size_t pos = 0;
        while ((pos = escaped_subject.find("'", pos)) != std::string::npos) {
            escaped_subject.replace(pos, 1, "\\'");
            pos += 2;
        }
        
        pos = 0;
        while ((pos = escaped_body.find("'", pos)) != std::string::npos) {
            escaped_body.replace(pos, 1, "\\'");
            pos += 2;
        }

        std::string command = "echo '" + escaped_body + "' | mail -s '" + escaped_subject + "' " + to;
        
        int result = system(command.c_str());
        if (result == 0) {
            std::cout << "✅ Email sent successfully to " << to << std::endl;
            return true;
        } else {
            std::cout << "❌ Failed to send email via mail command (exit code: " << result << ")" << std::endl;
            return false;
        }
    }

    // Main send function that tries multiple methods
    bool sendEmail(const std::string& to, const std::string& subject, const std::string& body) {
        std::cout << "🔄 Attempting to send email to: " << to << std::endl;
        
        // Method 1: Try mail command
        std::cout << "📧 Trying mail command..." << std::endl;
        if (sendEmailWithMailCommand(to, subject, body)) {
            return true;
        }
        
        // Method 2: Try sendmail
        std::cout << "📧 Trying sendmail..." << std::endl;
        if (sendEmailWithSendmail(to, subject, body)) {
            return true;
        }
        
        // Method 3: Fallback to logging
        std::cout << "📧 Falling back to file logging..." << std::endl;
        return logEmailToFile(to, subject, body);
    }

    bool shouldSendEmail(const User &user) {
        return user.status == "active" && user.daysSinceLastLogin >= 2;
    }

    std::string createEmailBody(const User &user) {
        return "Hi " + user.name + ",\n\n"
               "We noticed you haven't logged in for " + std::to_string(user.daysSinceLastLogin) + " days.\n"
               "We miss you! Please come back and check out what's new.\n\n"
               "Best regards,\n"
               "Ben_AFK Client System";
    }

    bool processUsers(const std::vector<User> &users) {
        if (users.empty()) {
            std::cout << "❌ No users to process" << std::endl;
            return false;
        }

        std::cout << "🔄 Starting email processing..." << std::endl;
        
        // Show eligible users
        int eligibleUsers = 0;
        std::cout << "\n📋 Users eligible for email notifications:" << std::endl;
        for (const auto &user : users) {
            if (shouldSendEmail(user)) {
                std::cout << "   ✓ " << user.name << " (" << user.email << ") - " 
                         << user.daysSinceLastLogin << " days inactive" << std::endl;
                eligibleUsers++;
            }
        }

        if (eligibleUsers == 0) {
            std::cout << "ℹ️  No users meet the criteria for email notifications" << std::endl;
            return true;
        }

        // Ask for confirmation
        std::cout << "\n📧 Send emails to " << eligibleUsers << " eligible users? (y/n): ";
        std::string confirmation;
        std::getline(std::cin, confirmation);
        
        if (confirmation != "y" && confirmation != "Y" && confirmation != "yes") {
            std::cout << "❌ Email sending cancelled" << std::endl;
            return false;
        }

        int emailsSent = 0;
        int emailsFailed = 0;

        for (const auto &user : users) {
            if (shouldSendEmail(user)) {
                std::cout << "\n🔍 Processing user: " << user.name << " (" << user.email << ")" << std::endl;
                
                std::string subject = "We Miss You!";
                std::string body = createEmailBody(user);
                
                std::cout << "📤 Sending email..." << std::endl;
                
                if (sendEmail(user.email, subject, body)) {
                    emailsSent++;
                } else {
                    emailsFailed++;
                }
            }
        }

        std::cout << "\n📊 Email Processing Summary:" << std::endl;
        std::cout << "✅ Emails sent: " << emailsSent << std::endl;
        std::cout << "❌ Emails failed: " << emailsFailed << std::endl;
        std::cout << "👥 Total users processed: " << users.size() << std::endl;
        std::cout << "🎯 Eligible users: " << eligibleUsers << std::endl;

        return emailsSent > 0;
    }
};

class BenAFK
{
private:
    int socket_fd;
    std::string encryptionKey;
    std::atomic<bool> connected{false};
    std::atomic<bool> authenticated{false};
    std::string username;
    
    // Use the EmailHandler's User struct
    using User = EmailHandler::User;
    std::vector<User> loginUsers;
    EmailHandler emailHandler;

    void displayWelcome()
    {
        std::cout << "\033[2J\033[1;1H"; // Clear screen
        std::cout << "╔══════════════════════════════════════╗\n";
        std::cout << "║        Ben_AFK Client v2.1           ║\n";
        std::cout << "║    Matt_daemon Graphic Interface     ║\n";
        std::cout << "║          Enhanced Email System       ║\n";
        std::cout << "╚══════════════════════════════════════╝\n\n";
    }

    void displayMenu()
    {
        std::cout << "\n╔══════════════════════════════════════╗\n";
        std::cout << "║              COMMANDS                ║\n";
        std::cout << "╠══════════════════════════════════════╣\n";
        std::cout << "║ 1. Send message                      ║\n";
        std::cout << "║ 2. Execute Mail sending              ║\n";
        std::cout << "║ 3. Register new user                 ║\n";
        std::cout << "║ 4. View user statistics              ║\n";
        std::cout << "║ 5. Execute shell command             ║\n";
        std::cout << "║ 6. Quit daemon                       ║\n";
        std::cout << "║ 7. Disconnect                        ║\n";
        std::cout << "╚══════════════════════════════════════╝\n";
        std::cout << "Choice: ";
    }

    void displayUsers()
    {
        std::cout << "╔══════════════════════════════════════╗\n";
        std::cout << "║     👥 Registered Users              ║\n";
        std::cout << "╠══════════════════════════════════════╣\n";
        if (loginUsers.empty()) {
            std::cout << "║         No users registered          ║\n";
        } else {
            for (const auto &user : loginUsers)
            {
                std::cout << "║ " << std::setw(36) << std::left 
                         << (user.name + " (" + user.email + ")") << " ║" << std::endl;
            }
        }
        std::cout << "╚══════════════════════════════════════╝\n";
    }

    void displayUserStatistics()
    {
        std::cout << "\n╔══════════════════════════════════════╗\n";
        std::cout << "║          📊 User Statistics          ║\n";
        std::cout << "╠══════════════════════════════════════╣\n";
        
        if (loginUsers.empty()) {
            std::cout << "║         No users registered          ║\n";
        } else {
            int activeUsers = 0;
            int inactiveUsers = 0;
            int eligibleForEmail = 0;
            
            for (const auto &user : loginUsers) {
                if (user.status == "active") activeUsers++;
                else inactiveUsers++;
                
                if (emailHandler.shouldSendEmail(user)) eligibleForEmail++;
            }
            
            std::cout << "║ Total users: " << std::setw(23) << std::right << loginUsers.size() << " ║\n";
            std::cout << "║ Active users: " << std::setw(22) << std::right << activeUsers << " ║\n";
            std::cout << "║ Inactive users: " << std::setw(20) << std::right << inactiveUsers << " ║\n";
            std::cout << "║ Eligible for email: " << std::setw(16) << std::right << eligibleForEmail << " ║\n";
        }
        
        std::cout << "╚══════════════════════════════════════╝\n";
        
        if (!loginUsers.empty()) {
            std::cout << "\n📋 Detailed User List:\n";
            std::cout << "┌─────────────────┬──────────────────────┬────────────┬───────────┐\n";
            std::cout << "│ Name            │ Email                │ Status     │ Days Out  │\n";
            std::cout << "├─────────────────┼──────────────────────┼────────────┼───────────┤\n";
            
            for (const auto &user : loginUsers) {
                std::cout << "│ " << std::setw(15) << std::left << user.name.substr(0, 15)
                         << " │ " << std::setw(20) << std::left << user.email.substr(0, 20)
                         << " │ " << std::setw(10) << std::left << user.status
                         << " │ " << std::setw(9) << std::right << user.daysSinceLastLogin << " │\n";
            }
            
            std::cout << "└─────────────────┴──────────────────────┴────────────┴───────────┘\n";
        }
    }

    bool connectToServer()
    {
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0)
        {
            std::cout << "❌ Socket creation failed\n";
            return false;
        }
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(4245);
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            std::cout << "❌ Connection to Matt_daemon failed\n";
            close(socket_fd);
            return false;
        }
        connected = true;
        std::cout << "✅ Connected to Matt_daemon\n";
        // Receive welcome message and encryption key
        char buffer[1024];
        recv(socket_fd, buffer, sizeof(buffer), 0);
        std::string response(buffer);
        size_t keyPos = response.find("KEY:");
        if (keyPos != std::string::npos)
        {
            size_t keyEnd = response.find("\n", keyPos);
            encryptionKey = response.substr(keyPos + 4, keyEnd - keyPos - 4);
            std::cout << "🔐 Encryption enabled\n";
        }
        return true;
    }

    bool authenticate()
    {
        std::cout << "\n🔐 Authentication Required\n";
        std::cout << "Username: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";
        std::string password;
        // Hide password input
        termios oldTermios, newTermios;
        tcgetattr(STDIN_FILENO, &oldTermios);
        newTermios = oldTermios;
        newTermios.c_lflag &= ~(ECHO | ICANON);
        tcsetattr(STDIN_FILENO, TCSANOW, &newTermios);
        char ch;
        while ((ch = getchar()) != '\n' && ch != '\r' && ch != EOF)
        {
            if (ch == 127 || ch == 8)
            { // Backspace
                if (!password.empty())
                {
                    password.pop_back();
                    std::cout << "\b \b";
                }
            }
            else
            {
                password += ch;
                std::cout << '*';
            }
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &oldTermios);
        std::cout << "\n";
        std::string authMessage = "AUTH " + username + ":" + password;
        std::cout << "🔄 Authenticating user: " << username << std::endl;
        // Send plain text first for debugging
        send(socket_fd, authMessage.c_str(), authMessage.length(), 0);
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        ssize_t received = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0)
        {
            std::cout << "❌ Connection lost during authentication\n";
            return false;
        }
        std::string response(buffer, received);
        std::cout << "📡 Server response: " << response << std::endl;
        // Try to decrypt if encrypted
        if (!encryptionKey.empty() && response.length() > 20)
        {
            try
            {
                std::string decrypted = Crypto::decrypt(response, encryptionKey);
                std::cout << "🔓 Decrypted response: " << decrypted << std::endl;
                response = decrypted;
            }
            catch (...)
            {
                std::cout << "⚠️  Using original response (decryption failed)\n";
            }
        }
        if (response.find("AUTH_SUCCESS") != std::string::npos)
        {
            authenticated = true;
            std::cout << "✅ Authentication successful!\n";
            size_t welcomePos = response.find("Welcome");
            if (welcomePos != std::string::npos)
            {
                std::cout << response.substr(welcomePos) << "\n";
            }
            return true;
        }
        else
        {
            std::cout << "❌ Authentication failed\n";
            std::cout << "Debug - Full response: '" << response << "'\n";
            return false;
        }
    }

    void sendMessage(const std::string &message)
    {
        if (!connected || !authenticated)
            return;
        std::string encryptedMessage = message;
        if (!encryptionKey.empty())
        {
            encryptedMessage = Crypto::encrypt(message, encryptionKey);
        }
        send(socket_fd, encryptedMessage.c_str(), encryptedMessage.length(), 0);
    }

    std::string receiveMessage()
    {
        if (!connected)
            return "";
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        ssize_t received = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0)
        {
            connected = false;
            return "";
        }
        std::string message(buffer, received);
        if (!encryptionKey.empty())
        {
            try
            {
                message = Crypto::decrypt(message, encryptionKey);
            }
            catch (...)
            {
                // If decryption fails, return original message
            }
        }
        return message;
    }

    void handleShellCommand()
    {
        std::cout << "Enter shell command: ";
        std::string command;
        std::getline(std::cin, command);
        if (!command.empty())
        {
            sendMessage("SHELL " + command);
            std::cout << "\n📡 Executing command...\n";
            std::string response = receiveMessage();
            std::cout << "📥 Response: ==> " << response << std::endl;
            if (response.find("SHELL_OUTPUT:") != std::string::npos)
            {
                std::cout << "📄 Output:\n";
                std::cout << "╔══════════════════════════════════════╗\n";
                std::cout << response.substr(response.find("SHELL_OUTPUT:") + 14) << "\n";
                std::cout << "╚══════════════════════════════════════╝\n";
            }
            else
            {
                std::cout << "❌ Command failed: " << response << "\n";
            }
        }
    }

    void registerUser()
    {
        std::string newUsername, newPassword, email, status;
        int daysSinceLastLogin;
        std::cout << "New username: ";
        std::getline(std::cin, newUsername);
        std::cout << "New password: ";
        // Hide password input
        termios oldTermios, newTermios;
        tcgetattr(STDIN_FILENO, &oldTermios);
        newTermios = oldTermios;
        newTermios.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newTermios);
        std::getline(std::cin, newPassword);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldTermios);
        std::cout << "\n";
        std::cout << "Email: ";
        std::getline(std::cin, email);
        std::cout << "Status (active/inactive): ";
        std::getline(std::cin, status);
        std::cout << "Days since last login: ";
        std::cin >> daysSinceLastLogin;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // flush newline
        
        // Construct full register message
        std::ostringstream oss;
        oss << "REGISTER " << newUsername << ":" << newPassword
            << ":" << email << ":" << status << ":" << daysSinceLastLogin;
        std::string registerMessage = oss.str();
        std::cout << "📤 Sending registration request..." << std::endl;
        sendMessage(registerMessage);
        std::string response = receiveMessage();
        std::cout << "📥 Response: " << response << std::endl;
        
        if (response.find("USER_REGISTERED") != std::string::npos)
        {
            loginUsers.push_back({email, newUsername, status, daysSinceLastLogin});
            std::cout << "✅ User registered successfully!\n";
            std::cout << "📊 User Details:\n";
            std::cout << "   Name: " << newUsername << "\n";
            std::cout << "   Email: " << email << "\n";
            std::cout << "   Status: " << status << "\n";
            std::cout << "   Days since last login: " << daysSinceLastLogin << "\n";
        }
        else
        {
            std::cout << "❌ Registration failed: " << response << "\n";
        }
    }

public:
    void run()
    {
        displayWelcome();
        if (!connectToServer())
        {
            return;
        }
        if (!authenticate())
        {
            close(socket_fd);
            return;
        }
        std::string choice;
        while (connected && authenticated)
        {
            displayMenu();
            std::getline(std::cin, choice);
            if (choice == "1")
            {
                std::cout << "Enter message: ";
                std::string message;
                std::getline(std::cin, message);
                if (!message.empty())
                {
                    sendMessage(message);
                    std::cout << "✅ Message sent\n";
                }
            }
            else if (choice == "2")
            {
                std::cout << "\n📧 Email Management System\n";
                if (loginUsers.empty()) {
                    std::cout << "❌ No users registered. Please register users first.\n";
                } else {
                    emailHandler.processUsers(loginUsers);
                }
            }
            else if (choice == "3")
            {
                registerUser();
            }
            else if (choice == "4")
            {
                displayUserStatistics();
            }
            else if (choice == "5")
            {
                handleShellCommand();
            }
            else if (choice == "6")
            {
                std::cout << "⚠️  Shutting down daemon...\n";
                sendMessage("quit");
                break;
            }
            else if (choice == "7")
            {
                std::cout << "👋 Disconnecting...\n";
                break;
            }
            else
            {
                std::cout << "❌ Invalid choice\n";
            }
            std::cout << "\nPress Enter to continue...";
            std::cin.get();
            std::cout << "\033[2J\033[1;1H"; // Clear screen
        }
        if (connected)
        {
            close(socket_fd);
        }
    }
};

int main()
{
    BenAFK client;
    client.run();
    return 0;
}