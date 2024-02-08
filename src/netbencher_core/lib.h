#ifndef _NETBENCHER_CORE_LIB_H_
#define _NETBENCHER_CORE_LIB_H_

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "reporter/mods.h"

class bench_runner {
public:
    std::vector<std::thread> handlers;
    std::vector<bench_stat *> worker_stats;
    size_t num_workers;
    std::atomic<bool> running{true};

    explicit bench_runner(size_t num_workers);

    template<typename _Callable, typename... _Args>
    void run(_Callable &&f, _Args &&... args) {
        for (size_t i = 0; i < this->num_workers; i++) {
            auto *stat = new bench_stat();
            this->worker_stats.push_back(stat);
            this->handlers.emplace_back(f, i, this, stat, args...);
        }
    };

    void stop();

    std::string report(bench_reporter *reporter);
};

#endif
