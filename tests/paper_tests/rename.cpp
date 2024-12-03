#include <iostream>
#include <unistd.h>

int main() {
    const char* oldName = "/tmp/file1.txt";
    const char* newName = "/tmp/file2.txt";

    if (rename(oldName, newName) == -1) {
        perror("rename failed");
        return 1;
    }

    std::cout << "File renamed successfully." << std::endl;
}