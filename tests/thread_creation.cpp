#include <iostream>
#include <thread>
#include <chrono>

void threadFunction() {
    std::cout << "Thread is running..." << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::cout << "Thread has finished work." << std::endl;
}

int main() {
    std::cout << "Start" << std::endl;
    std::thread myThread(threadFunction);

    myThread.join();

    std::cout << "Main thread exiting." << std::endl;
    return 0;
}