#include <iostream>
#include <thread>
#include <unistd.h>
#include <sys/syscall.h>


void threadFunction() {
    std::cout << "Thread PID: " << getpid() << ", TID: " << gettid() << std::endl;
}

int main() {
    std::cout << "Main PID: " << getpid() << ", TID: " << gettid() << std::endl;

    std::thread t(threadFunction);
    t.join(); 

    return 0;
}