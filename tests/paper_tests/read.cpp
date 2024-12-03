#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

int main() {
    const char* filename = "/tmp/testfile.txt";
    char buffer[100];
    int fd = open(filename, O_RDONLY);

    if (fd == -1) {
        perror("open failed");
        return 1;
    }

    ssize_t bytesRead = read(fd, buffer, sizeof(buffer));
    if (bytesRead == -1) {
        perror("read failed");
        close(fd);
        return 1;
    }

    std::cout << "Read " << bytesRead << " bytes." << std::endl;
    close(fd);
}