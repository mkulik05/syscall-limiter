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

    // Open the file for writing (create if it doesn't exist)
    int fileDescriptor = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fileDescriptor < 0) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return 1;
    }

    // Measure the start time
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        write(fileDescriptor, message, messageLength);
    }

    // Measure the end time
    auto end = std::chrono::high_resolution_clock::now();

    // Calculate the duration in milliseconds
    std::chrono::duration<double, std::milli> duration = end - start;

    // Print the total time taken in milliseconds
    std::cout << "Total time for " << iterations << " writes: " 
              << duration.count() << " milliseconds" << std::endl;

    // Close the file
    close(fileDescriptor);

    return 0;
}