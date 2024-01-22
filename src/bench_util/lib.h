#ifndef _BENCH_UTIL_LIB_
#define _BENCH_UTIL_LIB_

#include <cstdint>

#define MIN_SERVER_LIFE 30

inline uint64_t round_up(uint64_t num, int64_t factor) {
    if (factor == 0) {
        return num;
    }

    return ((int64_t) (num + ((uint64_t) factor) - 1)) & (-factor);
}

#endif
