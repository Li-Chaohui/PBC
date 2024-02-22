#include <bits/stdc++.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
using namespace std;
class Timer {
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> start_time;

public:
    Timer() : start_time(std::chrono::high_resolution_clock::now()) {}

    void reset() {
        start_time = std::chrono::high_resolution_clock::now();
    }

    double elapsed() const {
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double,std::milli> elapsed_time = end_time - start_time;
        return elapsed_time.count();
    }
};

void eclear(element_t &e){
    element_clear(e);
}
