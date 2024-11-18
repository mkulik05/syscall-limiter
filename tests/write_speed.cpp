#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <chrono>
#include <cstring>

int main() {
    const char *filename = "output.txt";
    const char *message = "Hello, World!\n";
    const size_t messageLength = strlen(message);
    const int iterations = 100000;


    int fileDescriptor = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fileDescriptor < 0) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return 1;
    }


    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        write(fileDescriptor, message, messageLength);
    }

    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> duration = end - start;

    std::cout << "Total time for " << iterations << " writes: " 
              << duration.count() << " milliseconds" << std::endl;


    close(fileDescriptor);

    return 0;
}