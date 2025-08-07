
#include "TintinReporter.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <sys/stat.h>
#include <sys/types.h>
#include <filesystem>
#include <cstdlib>

const std::string TintinReporter::LOG_DIR = "/var/log/matt_daemon/";  // <-- use /tmp or $HOME for dev
const std::string TintinReporter::LOG_FILE = LOG_DIR + "matt_daemon.log";

TintinReporter::TintinReporter() : logRotationSize(10 * 1024 * 1024), logFileIndex(0) { // 10MB rotation
    createLogDirectory();
    logFile.open(LOG_FILE, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file: " << LOG_FILE << std::endl;
    }
}

TintinReporter::~TintinReporter() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

TintinReporter::TintinReporter(const TintinReporter& other) : logRotationSize(other.logRotationSize), logFileIndex(0) {
    createLogDirectory();
    logFile.open(LOG_FILE, std::ios::app);
}

TintinReporter& TintinReporter::operator=(const TintinReporter& other) {
    if (this != &other) {
        if (logFile.is_open()) {
            logFile.close();
        }
        logRotationSize = other.logRotationSize;
        createLogDirectory();
        logFile.open(LOG_FILE, std::ios::app);
    }
    return *this;
}

void TintinReporter::createLogDirectory() {
    struct stat st;
    if (stat(LOG_DIR.c_str(), &st) != 0) {
        mkdir(LOG_DIR.c_str(), 0755);
    }
}

std::string TintinReporter::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::stringstream ss;
    ss << "[" << std::setfill('0') << std::setw(2) << tm.tm_mday << "/"
       << std::setw(2) << (tm.tm_mon + 1) << "/" << (tm.tm_year + 1900) << "-"
       << std::setw(2) << tm.tm_hour << ":" << std::setw(2) << tm.tm_min << ":"
       << std::setw(2) << tm.tm_sec << "]";
    return ss.str();
}

std::string TintinReporter::levelToString(LogLevel level) {
    switch (level) {
        case INFO: return "[ INFO ]";
        case ERROR: return "[ ERROR ]";
        case LOG: return "[ LOG ]";
        case WARNING: return "[ WARNING ]";
        case DEBUG: return "[ DEBUG ]";
        default: return "[ UNKNOWN ]";
    }
}

bool TintinReporter::shouldRotate() {
    if (!logFile.is_open()) return false;
    
    logFile.seekp(0, std::ios::end);
    return logFile.tellp() > static_cast<std::streampos>(logRotationSize);
}

void TintinReporter::rotateLogFile() {
    if (logFile.is_open()) {
        logFile.close();
    }
    
    std::string archivedFile = LOG_DIR + "matt_daemon_" + std::to_string(logFileIndex++) + ".log.archived";
    std::filesystem::rename(LOG_FILE, archivedFile);
    
    logFile.open(LOG_FILE, std::ios::app);
}

void TintinReporter::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    if (logFile.is_open()) {
        if (shouldRotate()) {
            rotateLogFile();
        }
        
        logFile << getCurrentTimestamp() << " " << levelToString(level) 
                << " - " << message << std::endl;
        logFile.flush();
        
        // Send mail alert for ERROR level
        if (level == ERROR) {
            sendMailAlert(message);
        }
    }
}

void TintinReporter::sendMailAlert(const std::string& message) {
    std::string command = "echo 'Matt_daemon Error: " + message + 
                         "' | mail -s 'Matt_daemon Alert' root@localhost 2>/dev/null";
    system(command.c_str());
}

void TintinReporter::archiveLogs() {
    std::lock_guard<std::mutex> lock(logMutex);
    // Archive old logs older than 30 days
    auto thirtyDaysAgo = std::chrono::system_clock::now() - std::chrono::hours(24 * 30);
    
    for (const auto& entry : std::filesystem::directory_iterator(LOG_DIR)) {
        if (entry.is_regular_file() && entry.path().extension() == ".archived") {
            auto fileTime = std::chrono::system_clock::from_time_t(
                std::chrono::duration_cast<std::chrono::seconds>(
                    entry.last_write_time().time_since_epoch()).count());
            
            if (fileTime < thirtyDaysAgo) {
                std::filesystem::remove(entry);
            }
        }
    }
}

TintinReporter& TintinReporter::getInstance() {
    static TintinReporter instance;
    return instance;
}
