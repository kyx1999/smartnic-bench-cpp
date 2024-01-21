#include "lib.h"

bench_runner::bench_runner(size_t num_workers) {
    this->num_workers = num_workers;
}

void bench_runner::stop() {
    this->running.store(false);
    for (auto &t: this->handlers) {
        t.join();
    }
}
