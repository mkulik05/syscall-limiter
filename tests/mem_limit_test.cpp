#include <iostream>
#include <vector>
#include <cstdlib>
#include <unistd.h> 
#include <sys/mman.h>
#include <cstring> 

int main() {
    const size_t allocationSize = 1024 * 1024; 
    std::vector<char*> allocations;
    usleep(1000000);
    try {
        while (true) {

            char* block = new char[allocationSize];

            memset(block, 0, allocationSize);



            allocations.push_back(block);
            std::cout << "Allocated and locked 1 MB, total allocations: " << allocations.size() << " MB" << std::endl;

            usleep(500000); 
        }
    } catch (const std::bad_alloc& e) {
        std::cerr << "Memory allocation failed after " << allocations.size() << " MB." << std::endl;
    }

    for (char* block : allocations) {
        munlock(block, allocationSize); 
        delete[] block;
    }

    return 0;
}