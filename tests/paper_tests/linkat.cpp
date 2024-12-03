#include <iostream>
#include <fcntl.h>
#include <unistd.h>

int main() {
    const char* target = "file1.txt";
    const char* linkname = "linkfile.txt";

    int dirfd = open("/tmp", O_RDONLY); 

    if (dirfd == -1) {
        perror("open directory failed");
        return 1; 
    }

    if (linkat(dirfd, target, dirfd, linkname, 0) == -1) {
        perror("linkat failed");
        close(dirfd);
        return 1; 
    }

    std::cout << "Link created successfully." << std::endl;
    close(dirfd);
    return 0; 
}