#include "modq.h"

#include <string.h>

#include "ntt_table.h"

#define PSI_ORDER (2 * FALCON_MAX_N)
#define INV2 ((FALCON_Q + 1) / 2)

int32_t falcon_mod_q(int64_t x)
{
    int64_t r = x % FALCON_Q;
    return (int32_t)(r < 0 ? r + FALCON_Q : r);
}

static int check_length(size_t n)
{
    /* Anders als in Python ist n = 2048 nicht vorgesehen: Falcon endet bei 1024. */
    return (n != 0 && (n & (n - 1)) == 0 && n <= FALCON_MAX_N) ? FALCON_OK : FALCON_ERR_VALUE;
}

static size_t zeta_exponent(size_t n, size_t k)
{
    return ((2 * k + 1) * (FALCON_MAX_N / n)) % PSI_ORDER;
}

static int32_t zeta(size_t n, size_t k)
{
    return FALCON_PSI_POWERS[zeta_exponent(n, k)];
}

static int32_t inv_zeta(size_t n, size_t k)
{
    return FALCON_PSI_POWERS[(PSI_ORDER - zeta_exponent(n, k)) % PSI_ORDER];
}

static int32_t mul_q(int32_t a, int32_t b)
{
    return (int32_t)(((int64_t)a * b) % FALCON_Q);
}

static int32_t add_q(int32_t a, int32_t b)
{
    return (a + b) % FALCON_Q;
}

static int32_t sub_q(int32_t a, int32_t b)
{
    return (a + FALCON_Q - b) % FALCON_Q;
}

/* Wie _ntt_rec: gerade und ungerade Koeffizienten transformieren, dann zusammenführen.
 * stride ersetzt die Teillisten a[0::2] und a[1::2]. */
static void ntt_rec(int32_t *out, const int32_t *a, size_t stride, size_t n)
{
    if (n == 1) {
        out[0] = falcon_mod_q(a[0]);
        return;
    }
    size_t h = n / 2;
    ntt_rec(out, a, 2 * stride, h);
    ntt_rec(out + h, a + stride, 2 * stride, h);
    for (size_t k = 0; k < h; k++) {
        int32_t t = mul_q(zeta(n, k), out[k + h]);
        int32_t s = out[k];
        out[k] = add_q(s, t);
        out[k + h] = sub_q(s, t);
    }
}

/* Wie _intt_rec. x enthält reduzierte Werte; tmp bietet Platz für n Werte. */
static void intt_rec(int32_t *x, int32_t *tmp, size_t n)
{
    if (n == 1) {
        return;
    }
    size_t h = n / 2;
    for (size_t k = 0; k < h; k++) {
        int32_t s = add_q(x[k], x[k + h]);
        int32_t d = sub_q(x[k], x[k + h]);
        x[k] = mul_q(s, INV2);
        x[k + h] = mul_q(mul_q(d, inv_zeta(n, k)), INV2);
    }
    intt_rec(x, tmp, h);
    intt_rec(x + h, tmp, h);
    memcpy(tmp, x, n * sizeof *x);
    for (size_t i = 0; i < h; i++) {
        x[2 * i] = tmp[i];
        x[2 * i + 1] = tmp[h + i];
    }
}

int falcon_ntt(int32_t *out, const int32_t *a, size_t n)
{
    if (check_length(n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    ntt_rec(out, a, 1, n);
    return FALCON_OK;
}

int falcon_intt(int32_t *out, const int32_t *a_hat, size_t n)
{
    int32_t tmp[FALCON_MAX_N];

    if (check_length(n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = falcon_mod_q(a_hat[i]);
    }
    intt_rec(out, tmp, n);
    return FALCON_OK;
}

int falcon_mul_mod_q(int32_t *out, const int32_t *a, const int32_t *b, size_t n)
{
    int32_t ah[FALCON_MAX_N];
    int32_t bh[FALCON_MAX_N];
    int32_t ch[FALCON_MAX_N];

    if (check_length(n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    ntt_rec(ah, a, 1, n);
    ntt_rec(bh, b, 1, n);
    for (size_t i = 0; i < n; i++) {
        ch[i] = mul_q(ah[i], bh[i]);
    }
    return falcon_intt(out, ch, n);
}

/* x^(q-2) mod q (Python: pow(x, q - 2, q)). */
static int32_t inverse_q(int32_t x)
{
    int32_t result = 1;
    int32_t base = x;
    for (int32_t e = FALCON_Q - 2; e > 0; e >>= 1) {
        if (e & 1) {
            result = mul_q(result, base);
        }
        base = mul_q(base, base);
    }
    return result;
}

int falcon_div_mod_q(int32_t *out, const int32_t *a, const int32_t *b, size_t n)
{
    int32_t ah[FALCON_MAX_N];
    int32_t bh[FALCON_MAX_N];
    int32_t ch[FALCON_MAX_N];

    if (check_length(n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    ntt_rec(ah, a, 1, n);
    ntt_rec(bh, b, 1, n);
    for (size_t i = 0; i < n; i++) {
        if (bh[i] == 0) {
            return FALCON_ERR_VALUE;
        }
        ch[i] = mul_q(ah[i], inverse_q(bh[i]));
    }
    return falcon_intt(out, ch, n);
}

int falcon_is_invertible_mod_q(const int32_t *a, size_t n)
{
    int32_t ah[FALCON_MAX_N];

    if (check_length(n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    ntt_rec(ah, a, 1, n);
    for (size_t i = 0; i < n; i++) {
        if (ah[i] == 0) {
            return 0;
        }
    }
    return 1;
}

void falcon_center_mod_q(int32_t *out, const int32_t *a, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        int32_t y = falcon_mod_q(a[i]);
        out[i] = (y > FALCON_Q / 2) ? y - FALCON_Q : y;
    }
}
