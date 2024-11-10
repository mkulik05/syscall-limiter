#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>

class Logger {
public:
    enum class Verbosity {
        ERROR,
        WARNING,
        INFO,
        DEBUG
    };

    static Logger& getInstance();

    void log(Verbosity level, const std::string& format, ...);

    void setVerbosity(Verbosity level) { verbosityLevel = level; }

private:
    Logger();
    ~Logger();

    std::ofstream logFile;
    Verbosity verbosityLevel;
    std::string logFilePath = "log.txt";
    std::mutex logMutex;

    std::string currentTime();
    void writeLog(const std::string& msg);
};

#endif 