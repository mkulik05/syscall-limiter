#include <iostream>
#include <vector>
#include <cstdlib>

int main() {
    const size_t allocationSize = 10 * 1024 * 1024;
    for (int i = 0;; i++) {
        char* ptr = new char[allocationSize];
        if (ptr == nullptr) break;
        for (int i = 0; i < allocationSize; i++) {
            ptr[i] = i % 256;
        }
        std::cout << "Allocated " << allocationSize / (1024 * 1024) << " MB in iteration " << i + 1 << std::endl;
    }
    return 0;
}