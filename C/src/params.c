#include "params.h"

const falcon_params FALCON_512 = {
    512, FALCON_Q, 165.736617183, 1.277833697, 1.8205, 34034726, 666,
};

const falcon_params FALCON_1024 = {
    1024, FALCON_Q, 168.388571447, 1.298280334, 1.8205, 70265242, 1280,
};

static int is_prime(int32_t x)
{
    if (x < 2) {
        return 0;
    }
    for (int32_t d = 2; d <= x / d; d++) {
        if (x % d == 0) {
            return 0;
        }
    }
    return 1;
}

int falcon_logn(size_t n)
{
    if (n == 0 || (n & (n - 1)) != 0) {
        return -1;
    }
    int logn = 0;
    while (((size_t)1 << logn) < n) {
        logn++;
    }
    return (logn >= 1 && logn <= 10) ? logn : -1;
}

int falcon_params_validate(const falcon_params *p)
{
    if (falcon_logn(p->n) < 0 || !is_prime(p->q)) {
        return FALCON_ERR_VALUE;
    }
    if (((size_t)p->q - 1) % (2 * p->n) != 0) {
        return FALCON_ERR_VALUE;
    }
    /* In dieser Form schlagen die Prüfungen auch bei NaN an. */
    if (!(p->sigma > 0.0) || !(1.0 <= p->sigma_min && p->sigma_min < p->sigma_max)) {
        return FALCON_ERR_VALUE;
    }
    if (p->sig_bound == 0 || p->sig_bytelen == 0) {
        return FALCON_ERR_VALUE;
    }
    return FALCON_OK;
}

size_t falcon_pk_bytes(const falcon_params *p)
{
    return 1 + (14 * p->n + 7) / 8;
}

uint8_t falcon_sk_header_byte(const falcon_params *p)
{
    return (uint8_t)(0x50 | falcon_logn(p->n));
}
