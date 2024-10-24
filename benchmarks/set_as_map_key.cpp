#include <iostream>
#include <map>
#include <set>
#include <chrono>
#include <vector>
#include <random>

struct SetComparator {
    bool operator()(const std::set<int>& lhs, const std::set<int>& rhs) const {
        return std::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
    }
};

void benchmark_int_map(size_t num_elements) {
    std::map<int, std::string> int_map;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_elements; ++i) {
        int_map[i] = "Value " + std::to_string(i);
    }

    auto insert_end = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_elements; ++i) {
        auto value = int_map[i];
    }

    auto lookup_end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> insert_duration = insert_end - start;
    std::chrono::duration<double> lookup_duration = lookup_end - insert_end;

    std::cout << "Int Map Insert Time: " << insert_duration.count() << " seconds\n";
    std::cout << "Int Map Lookup Time: " << lookup_duration.count() << " seconds\n";
}

void benchmark_set_map(size_t num_elements) {
    std::map<std::set<int>, std::string, SetComparator> set_map;
    auto start = std::chrono::high_resolution_clock::now();


    for (int i = 0; i < num_elements; ++i) {
        std::set<int> key = {i};
        set_map[key] = "Value " + std::to_string(i);
    }

    auto insert_end = std::chrono::high_resolution_clock::now();


    for (int i = 0; i < num_elements; ++i) {
        std::set<int> key = {i};
        auto value = set_map[key]; 
    }

    auto lookup_end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> insert_duration = insert_end - start;
    std::chrono::duration<double> lookup_duration = lookup_end - insert_end;

    std::cout << "Set Map Insert Time: " << insert_duration.count() << " seconds\n";
    std::cout << "Set Map Lookup Time: " << lookup_duration.count() << " seconds\n";
}

int main() {
    const size_t num_elements = 1000000; 
    std::cout << "Benchmarking with " << num_elements << " elements:\n";

    benchmark_int_map(num_elements);
    benchmark_set_map(num_elements);

    return 0;
}