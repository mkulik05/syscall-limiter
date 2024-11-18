#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>

std::mutex mtx; 
int sharedVariable = 0; 

void increment() {
    for (int i = 0; i < 1000; ++i) {
        std::lock_guard<std::mutex> lock(mtx); 
        ++sharedVariable; 
    }
}

void decrement() {
    for (int i = 0; i < 1000; ++i) {
        std::lock_guard<std::mutex> lock(mtx); 
        --sharedVariable; 
    }
}

int main() {
    std::thread t1(increment); 
    std::thread t2(decrement); 

    t1.join(); 
    t2.join(); 

    std::cout << "Final value of sharedVariable: " << sharedVariable << std::endl;

    return 0;
}