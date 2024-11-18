#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <unistd.h> 
#include <fcntl.h>  
#include <cstring>  
#include <ctime>    

std::atomic<bool> running(true);
const char* filename = "/tmp/output.txt";

void writeToFile(const std::string& message) {
    int fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1) {
        std::cerr << "Error opening file: " << strerror(errno) << std::endl;
        return;
    }

    ssize_t bytesWritten = write(fd, message.c_str(), message.size());
    if (bytesWritten == -1) {
        std::cerr << "Error writing to file: " << strerror(errno) << std::endl;
    }

    if (close(fd) == -1) {
        std::cerr << "Error closing file: " << strerror(errno) << std::endl;
    }
}

std::string getCurrentTime() {
    std::time_t now = std::time(nullptr);
    std::tm local_tm = *std::localtime(&now);
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), "%M:%S", &local_tm);
    return std::string(buffer);
}

void threadFunction(int id) {
    while (running) {
        pid_t tgid = getpid();
        std::string message = "[" + getCurrentTime() + "] Thread " + std::to_string(id) +
                              " (ID: " + std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id())) +
                              ") is running. \nPID (Process ID): " + std::to_string(tgid) + "\n\n";
        writeToFile(message);
        std::cout << message;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    writeToFile("[" + getCurrentTime() + "] Thread " + std::to_string(id) + " is terminating.\n");
    
}

void signalHandler(int signum) {
    std::cout << "\nInterrupt signal (" << signum << ") received.\n";
    running = false;
}

int main() {

    std::signal(SIGINT, signalHandler);

    std::thread thread1(threadFunction, 1);
    std::thread thread2(threadFunction, 2);


    thread1.join();
    thread2.join();

    std::cout << "All threads have been terminated." << std::endl;
    return 0;
}