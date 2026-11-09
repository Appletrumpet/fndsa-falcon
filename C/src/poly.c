#include "poly.h"

uint64_t falcon_norm_sq(const int32_t *a, size_t n)
{
    uint64_t s = 0;
    for (size_t i = 0; i < n; i++) {
        int64_t x = a[i];
        s += (uint64_t)(x * x);
    }
    return s;
}
