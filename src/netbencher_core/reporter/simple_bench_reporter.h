#ifndef _SIMPLE_BENCH_REPORTER_H_
#define _SIMPLE_BENCH_REPORTER_H_

#include <cstdint>

#include "mods.h"

class simple_bench_reporter : public bench_reporter {
public:
    explicit simple_bench_reporter(uint64_t id);
    // TODO
};

#endif
