#include <iostream>
#include <unistd.h>
#include <cstdio>

int main() {
    const char* filename = "/tmp/testfile.txt";
    if (unlink(filename) == -1) {
        perror("unlink failed");
        return 1;
    }
    std::cout << "File unlinked successfully." << std::endl;
}