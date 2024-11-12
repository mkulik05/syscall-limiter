#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>

std::mutex mtx; // Mutex for critical section
int sharedVariable = 0; // Shared variable

void increment() {
    for (int i = 0; i < 1000; ++i) {
        std::lock_guard<std::mutex> lock(mtx); // Lock the mutex
        ++sharedVariable; // Increment the shared variable
    }
}

void decrement() {
    for (int i = 0; i < 1000; ++i) {
        std::lock_guard<std::mutex> lock(mtx); // Lock the mutex
        --sharedVariable; // Decrement the shared variable
    }
}

int main() {
    std::thread t1(increment); // Create first thread
    std::thread t2(decrement); // Create second thread

    t1.join(); // Wait for the first thread to finish
    t2.join(); // Wait for the second thread to finish

    std::cout << "Final value of sharedVariable: " << sharedVariable << std::endl;

    return 0;
}