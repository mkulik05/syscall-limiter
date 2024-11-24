#include "Logger.h"

#include <cstdarg>
#include <iomanip>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
#include <chrono>


std::string generateLogFilePath() {
    using namespace std::chrono;

    auto now = system_clock::now();
    auto now_time_t = system_clock::to_time_t(now);
    auto tm = *std::localtime(&now_time_t);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S") << ".log";
    return oss.str();
}

Logger::Logger() : verbosityLevel(Verbosity::DEBUG) {
    logFilePath = "/tmp/" + generateLogFilePath();
    logFile.open(logFilePath, std::ios::app);
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}


Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

std::string Logger::currentTime() {
    using namespace std::chrono;

    auto now = system_clock::now();
    auto now_time_t = system_clock::to_time_t(now);
    auto now_ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    auto tm = *std::localtime(&now_time_t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
    return oss.str();
}

void Logger::writeLog(const std::string& msg) {
    std::lock_guard<std::mutex> guard(logMutex);
    if (logFile.is_open()) {
        logFile << msg << std::endl;
    }
    // if (verbosityLevel == Verbosity::DEBUG) {
    //     std::cout << msg << std::endl;
    // }
}

void Logger::log(Verbosity level, const std::string& format, ...) {
    if (level > verbosityLevel) return;

    va_list args;
    va_start(args, format);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format.c_str(), args);
    va_end(args);
    
    pid_t pid = getpid();
    std::ostringstream pidStream;
    pidStream << std::setw(6) << std::setfill(' ') << pid;

    std::string msg = currentTime() + " [" + std::to_string(static_cast<int>(level)) + "] [" + pidStream.str() + "] " + buffer;
    writeLog(msg);
}