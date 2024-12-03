#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sendfile.h>

int main() {
    const char* sourceFile = "/tmp/src.txt";
    const char* destFile = "/tmp/dst.txt";
    int srcFd = open(sourceFile, O_RDONLY);
    int destFd = open(destFile, O_WRONLY | O_CREAT, 0644);

    if (srcFd == -1 || destFd == -1) {
        perror("open failed");
        return 1;
    }

    off_t bytesSent = sendfile(destFd, srcFd, nullptr, 5);
    if (bytesSent == -1) {
        perror("sendfile failed");
        close(srcFd);
        close(destFd);
        return 1; 
    }

    std::cout << "Sent " << bytesSent << " bytes successfully." << std::endl;
    close(srcFd);
    close(destFd);
}