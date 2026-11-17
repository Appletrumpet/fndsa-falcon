#include "modq.h"

#include <string.h>

#include "ct.h"
#include "ntt_table.h"

#define PSI_ORDER (2 * FALCON_MAX_N)
#define INV2 ((FALCON_Q + 1) / 2)

/* u mod q für u < 2^63, ohne Division (Barrett): Der geschätzte Quotient ist dann höchstens um 1
 * zu klein, eine Korrektur über eine Maske genügt. Der Compiler setzt % sonst als sdiv/udiv um,
 * deren Laufzeit vom Prozessor abhängen kann (8.1.7). */
static uint32_t reduce_q(uint64_t u)
{
    const uint64_t m = UINT64_MAX / FALCON_Q;
    uint64_t quot = (uint64_t)(((unsigned __int128)u * m) >> 64);
    uint64_t r = u - quot * FALCON_Q;
    r -= falcon_ct_mask(1u ^ ((r - FALCON_Q) >> 63)) & FALCON_Q;
    return (uint32_t)r;
}

/* Gilt für -q * 2^40 <= x <= 2^62; alle Aufrufer liegen weit darin (|x| < 2^33). */
int32_t falcon_mod_q(int64_t x)
{
    return (int32_t)reduce_q((uint64_t)x + (uint64_t)FALCON_Q * ((uint64_t)1 << 40));
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
    return (int32_t)reduce_q((uint64_t)a * (uint64_t)b);
}

static int32_t add_q(int32_t a, int32_t b)
{
    /* a, b in 0 .. q-1: eine Korrektur genügt. */
    uint32_t r = (uint32_t)a + (uint32_t)b;
    r -= (uint32_t)falcon_ct_mask(1u ^ ((uint64_t)(r - FALCON_Q) >> 31 & 1u)) & FALCON_Q;
    return (int32_t)r;
}

static int32_t sub_q(int32_t a, int32_t b)
{
    /* a, b in 0 .. q-1: eine Korrektur genügt. */
    uint32_t r = (uint32_t)a - (uint32_t)b;
    r += (uint32_t)falcon_ct_mask((uint64_t)(r >> 31)) & FALCON_Q;
    return (int32_t)r;
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
    falcon_secure_zero(tmp, n * sizeof tmp[0]); /* Z5 */
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
    int rc = falcon_intt(out, ch, n);
    falcon_secure_zero(ah, n * sizeof ah[0]); /* Z5 */
    falcon_secure_zero(bh, n * sizeof bh[0]);
    falcon_secure_zero(ch, n * sizeof ch[0]);
    return rc;
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
    /* Nullprüfung ohne Verzweigung (recompute_G läuft auf geheimen Werten); nur „nicht
     * invertierbar“ wird am Ende freigegeben. inverse_q(0) ist 0, das Ergebnis wird dann verworfen. */
    uint64_t zero = 0;
    for (size_t i = 0; i < n; i++) {
        zero |= 1u ^ falcon_ct_nonzero((uint64_t)(uint32_t)bh[i]);
        ch[i] = mul_q(ah[i], inverse_q(bh[i]));
    }
    FALCON_DECLASSIFY(&zero, sizeof zero);
    int rc = zero ? FALCON_ERR_VALUE : falcon_intt(out, ch, n);
    falcon_secure_zero(ah, n * sizeof ah[0]); /* Z5 */
    falcon_secure_zero(bh, n * sizeof bh[0]);
    falcon_secure_zero(ch, n * sizeof ch[0]);
    return rc;
}

int falcon_is_invertible_mod_q(const int32_t *a, size_t n)
{
    int32_t ah[FALCON_MAX_N];

    if (check_length(n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    ntt_rec(ah, a, 1, n);
    int invertible = 1;
    for (size_t i = 0; i < n; i++) {
        invertible &= ah[i] != 0;
    }
    falcon_secure_zero(ah, n * sizeof ah[0]); /* Z5 */
    return invertible;
}

void falcon_center_mod_q(int32_t *out, const int32_t *a, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        int32_t y = falcon_mod_q(a[i]);
        /* y > q/2 -> y - q, ohne Verzweigung. */
        uint64_t above = (uint64_t)(uint32_t)(FALCON_Q / 2 - y) >> 31;
        out[i] = y - (int32_t)(falcon_ct_mask(above) & FALCON_Q);
    }
}
