#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>

int main() {
    const char* dirName = "tempdir";
    if (mkdir(dirName, 0755) != 0) {
        std::cerr << "Error creating directory: " << strerror(errno) << std::endl;
        return 1;
    }

    int dirfd = open(dirName, O_RDONLY);
    if (dirfd == -1) {
        std::cerr << "Error opening directory: " << strerror(errno) << std::endl;
        return 1;
    }

    const char* fileName = "example.txt";

    int filefd = openat(dirfd, fileName, O_CREAT | O_WRONLY, 0644);
    if (filefd == -1) {
        std::cerr << "Error opening file with openat: " << strerror(errno) << std::endl;
        close(dirfd);
        return 1;
    }

    const char* content = "Hello, world!";
    if (write(filefd, content, strlen(content)) == -1) {
        std::cerr << "Error writing to file: " << strerror(errno) << std::endl;
        close(filefd);
        close(dirfd);
        return 1;
    }

    
    close(filefd);
    close(dirfd);

    std::cout << "File created successfully in " << dirName << std::endl;
    return 0;
}