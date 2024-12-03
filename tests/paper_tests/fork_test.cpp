#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

void createChildProcess(int depth) {
    if (depth == 0) return;

    int pid = fork();
    if (pid == 0) {

        int r = unlink("/tmp/test.txt");
        if (r < 0) {
            perror(("unlink failed, depth = " + std::to_string(depth)).c_str());
            createChildProcess(depth - 1);
            return;
        }

        createChildProcess(depth - 1);
        return;
    }

    std::cout << "Process " << getpid() << " created child " << pid << "\n";
}

int main() {
    createChildProcess(5);
    return 0;
}