#include "sampler.h"

#include "ct.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    falcon_secure_zero(buf, sizeof buf); /* Z5 */
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
    /* z <- max(0, scaled) ohne Verzweigung (Python: z < 0 -> 0). */
    scaled = falcon_ct_select_double(falcon_ct_mask(falcon_ct_lt_double(scaled, 0.0)), 0.0, scaled);
    uint64_t z = (uint64_t)scaled;

    for (int i = 1; i < 13; i++) {
        y = FALCON_EXP_C[i] - (uint64_t)(((unsigned __int128)z * y) >> 63);
    }
    z = (uint64_t)floor(ccs * 0x1p63);
    return (uint64_t)(((unsigned __int128)z * y) >> 63);
}

uint64_t falcon_ber_exp_z(double x, double ccs)
{
    x = falcon_ct_select_double(falcon_ct_mask(falcon_ct_lt_double(x, 0.0)), 0.0, x);

    /* Alg. 14, Z. 1-3: x = s * ln 2 + r, dann s <- min(s, 63). s bleibt zunächst ein double, wie
     * in Python exakt: Dort wird die ganze Zahl s vor dem Produkt in float umgewandelt. */
    double floored = floor(x / FALCON_LOG2);
    double r = x - floored * FALCON_LOG2;
    floored = falcon_ct_select_double(falcon_ct_mask(falcon_ct_lt_double(63.0, floored)), 63.0, floored);
    int s = (int)floored;

    /* Z. 4: Für y = 0 wäre 2y - 1 in Python negativ und wird dort auf 0 begrenzt. */
    uint64_t y = falcon_approx_exp(r, ccs);
    return ((2 * y - 1) >> s) & falcon_ct_mask(falcon_ct_nonzero(y));
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
        /* Die Schleife muss nicht in konstanter Zeit laufen (Alg. 14, Z. 9); Z2-Ausnahme. */
        int done = (w != 0) | (i <= 0);
        FALCON_DECLASSIFY(&done, sizeof done);
        if (done) {
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
    /* Bereichsprüfung ohne Verzweigung; nur das Ergebnis wird freigegeben. Es ist für gültige
     * Schlüssel immer 1 und führt sonst nur zum Fehler (Z2-Ausnahme). */
    uint64_t bits;
    memcpy(&bits, &sigma_p, sizeof bits);
    uint64_t finite = falcon_ct_nonzero(((bits >> 52) & 0x7FFu) ^ 0x7FFu);
    int ok = (int)(finite & (1u ^ falcon_ct_lt_double(sigma_p, p->sigma_min - SIGMA_EPS))
                   & (1u ^ falcon_ct_lt_double(p->sigma_max + SIGMA_EPS, sigma_p)));
    FALCON_DECLASSIFY(&ok, sizeof ok);
    if (!ok) {
        return FALCON_ERR_VALUE;
    }

    /* Alg. 15, Z. 1-2 */
    double s = floor(mu);
    double r = mu - s;
    double ccs = p->sigma_min / sigma_p;
    ccs = falcon_ct_select_double(falcon_ct_mask(falcon_ct_lt_double(1.0, ccs)), 1.0, ccs);

    for (;;) {
        /* Z. 4-6 */
        int z0 = falcon_base_sampler(rng);
        uint8_t byte;
        falcon_random_bytes(rng, &byte, 1);
        int b = byte & 1;
        int z = b + (2 * b - 1) * z0;

        double x = falcon_samplerz_x(z, z0, r, sigma_p, p);
        x = falcon_ct_select_double(falcon_ct_mask(falcon_ct_lt_double(x, 0.0)), 0.0, x);

        /* Z. 8-9: Annahme oder Ablehnung je Runde ist nach Z2 erlaubt (Isochronie). */
        int accept = falcon_ber_exp(x, ccs, rng);
        FALCON_DECLASSIFY(&accept, sizeof accept);
        if (accept) {
            *out = (int32_t)s + z;
            return FALCON_OK;
        }
    }
}
