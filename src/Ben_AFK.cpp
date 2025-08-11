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

class BenAFK
{
private:
    int socket_fd;
    std::string encryptionKey;
    std::atomic<bool> connected{false};
    std::atomic<bool> authenticated{false};
    std::string username;

    struct User
    {
        std::string email;
        std::string name;
        std::string status;
        int daysSinceLastLogin;
    };

    std::vector<User> loginUsers;

    void displayWelcome()
    {
        std::cout << "\033[2J\033[1;1H"; // Clear screen
        std::cout << "╔══════════════════════════════════════╗\n";
        std::cout << "║        Ben_AFK Client v2.0           ║\n";
        std::cout << "║    Matt_daemon Graphic Interface     ║\n";
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
        std::cout << "║ 4. Quit daemon                       ║\n";
        std::cout << "║ 5. Disconnect                        ║\n";
        std::cout << "╚══════════════════════════════════════╝\n";
        std::cout << "Choice: ";
    }


    void displayUsers()
    {
        std::cout << "╔══════════════════════════════════════╗\n";
        std::cout << "║     👥 Registered Users              ║\n";
        std::cout << "╠══════════════════════════════════════╣\n";
        for (const auto &user : loginUsers)
        {
        std::cout << "║    "  << user.email <<           "   ║" <<std::endl;
        }
        std::cout << "╚══════════════════════════════════════╝\n";
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

    bool shouldSendEmail(const User &user)
    {
        return user.status == "active" && user.daysSinceLastLogin >= 2;
    }

    std::string createEmailBody(const User &user)
    {
        
        return "Hi " + user.name + ",\n\nWe noticed you haven't logged in recently. Come back!";
    }

    void sendEmail(const std::string &to, const std::string &subject, const std::string &body)
    {
        std::string command = "sendmail " + to;
        FILE *mail = popen(command.c_str(), "w");
        if (mail)
        {
            fprintf(mail, "Subject: %s\n\n%s\n", subject.c_str(), body.c_str());
            pclose(mail);
        }
    }

    void processUsers(const std::vector<User> &users)
    {
        std::cout << "Enter Mail sending : ==> ";
        std::string Mail;
        std::getline(std::cin, Mail);
        if (Mail.empty())
        {
            std::cout << "❌ No mail to send\n";
            return;
        }
        displayUsers();
        for (const auto &user : users)
        {
            
                std::cout << "Processing user: " << user.name << " (" << user.email << ")\n";
                std::string subject = "We Miss You!";
                std::string body = createEmailBody(user);
                std::cout << "Sending email to: " << body << "\n";
                sendEmail(user.email, subject, body);
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
        std::cout << "📤 Sending: " << registerMessage << std::endl;

        sendMessage(registerMessage);

        std::string response = receiveMessage();
        std::cout << "📥 Response: " << response << std::endl;

        if (response.find("USER_REGISTERED") != std::string::npos)
        {
            loginUsers.push_back({email, newUsername, status, daysSinceLastLogin});
            std::cout << "✅ User registered successfully!\n";
        }
        else
        {
            std::cout << "❌ Registration failed\n";
        }

        std::cout << "👥 Registered Users:\n";
        for (const auto &user : loginUsers)
        {
            std::cout << " - " << user.name << ", " << user.email
                      << ", " << user.status << ", Days: " << user.daysSinceLastLogin << "\n";
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
                processUsers(loginUsers);
            }
            else if (choice == "3")
            {
                registerUser();
            }
            else if (choice == "4")
            {
                std::cout << "⚠️  Shutting down daemon...\n";
                sendMessage("quit");
                break;
            }
            else if (choice == "5")
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