#include <iostream>
#include <chrono>
#include <vector>

class Base {
public:
    virtual void work() = 0;
};

class Base2 : public Base {
public:
    void work() override {
        volatile int sum = 0;
        for (int i = 0; i < 100; ++i) {
            sum += i;
        }
        volatile int la = sum; 
    }
};

class Usual {
public:
    void work() {
        volatile int sum = 0;
        for (int i = 0; i < 100; ++i) {
            sum += i;
        }
        volatile int la = sum; 
    }
};

void work() {
    volatile int sum = 0;
    for (int i = 0; i < 100; ++i) {
        sum += i;
    }
    volatile int la = sum; 
}

double benchVirtual(int iterations) {
    Base2 derived;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        derived.work();
    }
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(end - start).count();
}

double benchUsual(int iterations) {
    Usual nonAbstract;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        nonAbstract.work();
    }
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(end - start).count();
}

double benchPureFunc(int iterations) {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        work();
    }
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(end - start).count();
}

int main() {
    const int iterations = 100000000;
    const int runs = 5; 
    std::vector<double> virtualTimes, usualTimes, pureFuncTimes;

    for (int i = 0; i < runs; ++i) {
        virtualTimes.push_back(benchVirtual(iterations));
        usualTimes.push_back(benchUsual(iterations));
        pureFuncTimes.push_back(benchPureFunc(iterations));
    }

    auto average = [](const std::vector<double>& times) {
        double sum = 0;
        for (double time : times) {
            sum += time;
        }
        return sum / times.size();
    };

    std::cout << "Average Virtual method time: " << average(virtualTimes) << " seconds\n";
    std::cout << "Average Non-virtual method time: " << average(usualTimes) << " seconds\n";
    std::cout << "Average Pure function time: " << average(pureFuncTimes) << " seconds\n";

    return 0;
}