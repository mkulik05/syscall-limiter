#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

void createChildProcess(int depth) {
    if (depth == 0) return;

    int pid = fork();
    if (pid < 0) {
        perror(("Fork failed at depth " + std::to_string(depth)).c_str());
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {

        int fd = open("child_file.txt", O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd < 0) {
            perror(("Child: open failed at depth " + std::to_string(depth)).c_str());
            createChildProcess(depth - 1);
            return;
        }
        std::cout << "Child process (PID: " << getpid() << ") created child.\n";
        close(fd);

        createChildProcess(depth - 1);
        return;
    }


    std::cout << "Parent process (PID: " << getpid() << ") created child (PID: " << pid << ").\n";
}

int main() {
    createChildProcess(5);
    return 0;
}