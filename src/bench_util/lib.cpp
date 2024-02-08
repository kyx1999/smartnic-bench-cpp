#include "lib.h"

uint64_t round_up(uint64_t num, int64_t factor) {
    if (factor == 0) {
        return num;
    }

    return ((int64_t) (num + ((uint64_t) factor) - 1)) & (-factor);
}
