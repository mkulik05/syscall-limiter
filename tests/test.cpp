#include <iostream>
#include <chrono>
#include <semaphore.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024
#define NUM_ITERATIONS 10000000
#define SHM_NAME "/my_shared_memory"  // Name for shared memory

// Function to benchmark sem_wait and sem_post
void benchmark_semaphore() {
    sem_t semaphore;
    sem_init(&semaphore, 0, 1);

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        sem_wait(&semaphore);
        sem_post(&semaphore);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> duration = end - start;
    std::cout << "Semaphore benchmark took: " << duration.count() << " microseconds" << std::endl;

    sem_destroy(&semaphore);
}

// Function to benchmark reading from socketpair
void benchmark_socketpair() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        return;
    }

    // Set the socket to non-blocking mode
    fcntl(sv[1], F_SETFL, O_NONBLOCK);

    // Write some initial data to the socketpair for the read operation to succeed
    const char* initial_data = "Hello";
    send(sv[0], initial_data, strlen(initial_data), 0);

    auto start = std::chrono::high_resolution_clock::now();

    char buffer[BUFFER_SIZE];
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        // Attempt to read from the socketpair without blocking
        recv(sv[1], buffer, BUFFER_SIZE, MSG_DONTWAIT);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> duration = end - start;
    std::cout << "Socketpair read benchmark took: " << duration.count() << " microseconds" << std::endl;

    close(sv[0]);
    close(sv[1]);
}

// Function to benchmark reading from shared memory
void benchmark_shared_memory() {
    // Create shared memory object
    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    ftruncate(shm_fd, BUFFER_SIZE);  // Set size of shared memory

    // Map shared memory
    char* shared_memory = (char*)mmap(0, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_memory == MAP_FAILED) {
        perror("mmap");
        return;
    }

    sem_t semaphore;
    sem_init(&semaphore, 1, 1);  // Shared semaphore

    // Write initial data to shared memory
    const char* initial_data = "Hello";
    memcpy(shared_memory, initial_data, strlen(initial_data) + 1);  // +1 for null terminator

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        sem_wait(&semaphore);
        // Read from shared memory
        char buffer[BUFFER_SIZE];
        memcpy(buffer, shared_memory, BUFFER_SIZE);
        sem_post(&semaphore);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> duration = end - start;
    std::cout << "Shared memory benchmark took: " << duration.count() << " microseconds" << std::endl;

    // Clean up
    munmap(shared_memory, BUFFER_SIZE);
    shm_unlink(SHM_NAME);
    sem_destroy(&semaphore);
}

int main() {
    std::cout << "Starting benchmarks..." << std::endl;

    benchmark_semaphore();
    benchmark_socketpair();
    benchmark_shared_memory();

    return 0;
}