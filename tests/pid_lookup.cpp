#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

pid_t getParentPID(pid_t pid) {
    std::ifstream statFile("/proc/" + std::to_string(pid) + "/stat");
    if (!statFile.is_open()) {
        return -1; // Return -1 if the process does not exist or cannot be opened
    }

    std::string line;
    if (std::getline(statFile, line)) {
        std::istringstream iss(line);
        std::string token;
        for (int i = 0; i < 3; ++i) {
            iss >> token; // Skip the first three tokens
        }
        pid_t ppid;
        iss >> ppid; // The fourth token is the parent PID
        return ppid;
    }

    return -1; // In case of failure to read
}

int main() {
    while (true) {
        std::cout << "Enter PID (or -1 to exit): ";
        pid_t pid;
        std::cin >> pid;

        if (pid == -1) {
            break; // Exit the loop if the user enters -1
        }

        pid_t parentPid = getParentPID(pid);
        if (parentPid != -1) {
            std::cout << "Parent PID of " << pid << " is: " << parentPid << std::endl;
        } else {
            std::cout << "Could not find parent PID for " << pid << std::endl;
        }
    }

    std::cout << "Exiting." << std::endl;
    return 0;
}