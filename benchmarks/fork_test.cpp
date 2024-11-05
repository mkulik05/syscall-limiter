#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

int main() {
    int pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        int fd = open("child_file.txt", O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            perror("Child: open failed");
            exit(EXIT_FAILURE);
        }
        close(fd);
        std::cout << "DONE\n";
        return 0;
    } 

    std::cout << pid;
    int fd = open("../parent_file.txt", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        perror("Parent: open failed");
        exit(EXIT_FAILURE);
    } 

    std::cout << "DONE2\n";

    close(fd);
    

    return 0;    
}