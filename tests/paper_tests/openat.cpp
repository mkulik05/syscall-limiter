#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

int main() {
    const char* dir = "/tmp";
    const char* filename = "testfile.txt";
    int dirfd = open(dir, O_RDONLY);

    if (dirfd == -1) {
        perror("open directory failed");
        return 1;
    }

    int fd = openat(dirfd, filename, O_RDONLY);
    if (fd == -1) {
        perror("openat failed");
        close(dirfd);
        return 1;
    }

    std::cout << "File opened successfully with openat." << std::endl;
    close(fd);
    close(dirfd);
}