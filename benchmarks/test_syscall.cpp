#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

int main() {
    const char* filename = "./../build/testfile.txt";
    const char* message = "Hello, World!";
    char buffer[50];

    // Open the file for writing (create if it doesn't exist)
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("Error opening file for writing");
        return 1;
    }

    close(fd);
    // // Write to the file
    // ssize_t bytesWritten = write(fd, message, strlen(message));
    // if (bytesWritten == -1) {
    //     perror("Error writing to file");
    //     close(fd);
    //     return 1;
    // }

    // // Close the file after writing
    // close(fd);

    // // Open the file for reading
    // fd = open(filename, O_RDONLY);
    // if (fd == -1) {
    //     perror("Error opening file for reading");
    //     return 1;
    // }

    // // Read from the file
    // ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
    // if (bytesRead == -1) {
    //     perror("Error reading from file");
    //     close(fd);
    //     return 1;
    // }

    // // Null-terminate the string
    // buffer[bytesRead] = '\0';

    // // Output the read content
    // std::cout << "Read from file: " << buffer << std::endl;

    // // Close the file after reading
    // close(fd);
    std::cout << "DONE";
    return 0;
}