#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

int main() {
    const char* filename = "./../benchmarks/testfile.txt";
    const char* message = "Hello, World!";
    char buffer[50];

    int fd = open(filename, O_PATH | O_CREAT);
    if (fd == -1) {
        perror("Error opening file for writing");
        return 1;
    }

    close(fd);
    
    std::cout << "DONE";
    return 0;
}