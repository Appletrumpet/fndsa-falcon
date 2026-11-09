#include "sampler.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

/* Toleranz für Rundungsunterschiede bei sigma_min und sigma_max, wie in Python. */
#define SIGMA_EPS 1e-10

static void system_random_bytes(void *ctx, uint8_t *out, size_t k)
{
    static FILE *urandom = NULL;

    (void)ctx;
    if (urandom == NULL) {
        urandom = fopen("/dev/urandom", "rb");
    }
    if (urandom == NULL || fread(out, 1, k, urandom) != k) {
        abort();
    }
}

const falcon_rng FALCON_SYSTEM_RNG = {system_random_bytes, NULL};

void falcon_random_bytes(const falcon_rng *rng, uint8_t *out, size_t k)
{
    rng->random_bytes(rng->ctx, out, k);
}

int falcon_uniform_bits(falcon_u72 *out, int k, const falcon_rng *rng)
{
    uint8_t buf[9];

    if (k < 0 || k % 8 != 0 || k > 72) {
        return FALCON_ERR_VALUE;
    }
    falcon_u72 value = {0, 0};
    size_t count = (size_t)k / 8;
    falcon_random_bytes(rng, buf, count);
    for (size_t i = 0; i < count; i++) {
        value.high = (value.high << 8) | value.low;
        value.low = buf[i];
    }
    *out = value;
    return FALCON_OK;
}

/* 1, falls a < b, sonst 0: Subtraktion mit Übertrag, ohne Verzweigung. */
static int ct_lt_72(falcon_u72 a, falcon_u72 b)
{
    uint32_t borrow = (((uint32_t)a.low - b.low) >> 8) & 1u;
    uint64_t diff = a.high - b.high - borrow;
    uint64_t carry = ((~a.high & b.high) | (~(a.high ^ b.high) & diff)) >> 63;
    return (int)carry;
}

int falcon_base_sampler(const falcon_rng *rng)
{
    falcon_u72 u;
    int z0 = 0;

    (void)falcon_uniform_bits(&u, 72, rng);
    for (int i = 0; i < 18; i++) {
        z0 += ct_lt_72(u, FALCON_RCDT[i]);
    }
    return z0;
}

uint64_t falcon_approx_exp(double x, double ccs)
{
    uint64_t y = FALCON_EXP_C[0];
    double scaled = floor(x * 0x1p63);
    uint64_t z = scaled < 0.0 ? 0 : (uint64_t)scaled;

    for (int i = 1; i < 13; i++) {
        y = FALCON_EXP_C[i] - (uint64_t)(((unsigned __int128)z * y) >> 63);
    }
    z = (uint64_t)floor(ccs * 0x1p63);
    return (uint64_t)(((unsigned __int128)z * y) >> 63);
}

uint64_t falcon_ber_exp_z(double x, double ccs)
{
    if (x < 0.0) {
        x = 0.0;
    }

    /* Alg. 14, Z. 1-3: x = s * ln 2 + r, dann s <- min(s, 63). s bleibt zunächst ein double, wie
     * in Python exakt: Dort wird die ganze Zahl s vor dem Produkt in float umgewandelt. */
    double floored = floor(x / FALCON_LOG2);
    double r = x - floored * FALCON_LOG2;
    int s = floored > 63.0 ? 63 : (int)floored;

    /* Z. 4: Für y = 0 wäre 2y - 1 in Python negativ und wird dort auf 0 begrenzt. */
    uint64_t y = falcon_approx_exp(r, ccs);
    return (y == 0) ? 0 : (2 * y - 1) >> s;
}

int falcon_ber_exp(double x, double ccs, const falcon_rng *rng)
{
    uint64_t z = falcon_ber_exp_z(x, ccs);

    /* Z. 5-9: Vergleich von bis zu 8 Zufallsbytes mit z, oberstes Byte zuerst. */
    int i = 64;
    for (;;) {
        uint8_t b;
        i -= 8;
        falcon_random_bytes(rng, &b, 1);
        int w = (int)b - (int)((z >> i) & 0xFFu);
        if (w != 0 || i <= 0) {
            return w < 0;
        }
    }
}

double falcon_samplerz_x(int z, int z0, double r, double sigma_p, const falcon_params *p)
{
    /* Reihenfolge der Operationen wie in Python. */
    double two_sigma_p_sq = 2.0 * sigma_p * sigma_p;
    double two_sigma_max_sq = 2.0 * p->sigma_max * p->sigma_max;
    double d = (double)z - r;
    double x = (d * d) / two_sigma_p_sq;
    x -= (double)(z0 * z0) / two_sigma_max_sq;
    return x;
}

int falcon_sample_integer_gaussian(int32_t *out, double mu, double sigma_p, const falcon_params *p,
                                   const falcon_rng *rng)
{
    if (!isfinite(sigma_p) || sigma_p < p->sigma_min - SIGMA_EPS
        || sigma_p > p->sigma_max + SIGMA_EPS) {
        return FALCON_ERR_VALUE;
    }

    /* Alg. 15, Z. 1-2 */
    double s = floor(mu);
    double r = mu - s;
    double ccs = p->sigma_min / sigma_p;
    if (ccs > 1.0) {
        ccs = 1.0;
    }

    for (;;) {
        /* Z. 4-6 */
        int z0 = falcon_base_sampler(rng);
        uint8_t byte;
        falcon_random_bytes(rng, &byte, 1);
        int b = byte & 1;
        int z = b + (2 * b - 1) * z0;

        double x = falcon_samplerz_x(z, z0, r, sigma_p, p);
        if (x < 0.0) {
            x = 0.0;
        }

        /* Z. 8-9 */
        if (falcon_ber_exp(x, ccs, rng)) {
            *out = (int32_t)s + z;
            return FALCON_OK;
        }
    }
}
