#include "poly.h"

#include <stdlib.h>

#include "ct.h"
#include "params.h"

uint64_t falcon_norm_sq(const int32_t *a, size_t n)
{
    uint64_t s = 0;
    for (size_t i = 0; i < n; i++) {
        int64_t x = a[i];
        s += (uint64_t)(x * x);
    }
    return s;
}

falcon_big *falcon_poly_new(size_t n)
{
    falcon_big *a = malloc((n ? n : 1) * sizeof *a);
    if (a == NULL) {
        abort();
    }
    for (size_t i = 0; i < n; i++) {
        falcon_big_init(&a[i]);
    }
    return a;
}

void falcon_poly_free(falcon_big *a, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        falcon_big_free(&a[i]);
    }
    free(a);
}

void falcon_poly_from_ints(falcon_big *out, const int32_t *a, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        falcon_big_set_i64(&out[i], a[i]);
    }
}

void falcon_poly_add(falcon_big *out, const falcon_big *a, const falcon_big *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        falcon_big_add(&out[i], &a[i], &b[i]);
    }
}

void falcon_poly_sub(falcon_big *out, const falcon_big *a, const falcon_big *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        falcon_big_sub(&out[i], &a[i], &b[i]);
    }
}

void falcon_poly_neg(falcon_big *out, const falcon_big *a, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        falcon_big_neg(&out[i], &a[i]);
    }
}

/* Betrag < 2^63 vorausgesetzt (geprüft über die Bitlänge). */
static int64_t small_value(const falcon_big *a)
{
    uint64_t m = a->len > 0 ? a->limb[0] : 0;
    if (a->len > 1) {
        m |= (uint64_t)a->limb[1] << 32;
    }
    return a->neg ? -(int64_t)m : (int64_t)m;
}

static size_t max_bits(const falcon_big *a, size_t n)
{
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        size_t b = falcon_big_bit_length(&a[i]);
        m = b > m ? b : m;
    }
    return m;
}

/* Schneller Weg für kleine Koeffizienten (Stufe 2, Z6): Passt jede Summe von Produkten in 128 Bit,
 * wird mit nativen Ganzzahlen gerechnet und nur das Ergebnis in grosse Ganzzahlen umgewandelt.
 * Das Ergebnis ist exakt und damit gleich. In NTRUSolve trifft das auf die grossen Grade zu
 * (n = 128 bis 1024, Koeffizienten mit wenigen Bit), wo sonst n^2 Aufrufe auf grossen Zahlen anfallen. */
static int poly_mul_small(falcon_big *out, const falcon_big *a, const falcon_big *b, size_t n)
{
    size_t ba = max_bits(a, n), bb = max_bits(b, n);
    size_t bn = 0;
    while (((size_t)1 << bn) < n) {
        bn++;
    }
    /* |Summe| < n * 2^(ba + bb) <= 2^(bn + ba + bb) muss unter 2^127 bleiben. */
    if (n > FALCON_MAX_N || ba > 63 || bb > 63 || ba + bb + bn > 126) {
        return 0;
    }
    int64_t av[FALCON_MAX_N], bv[FALCON_MAX_N];
    __int128 acc[FALCON_MAX_N];
    for (size_t i = 0; i < n; i++) {
        av[i] = small_value(&a[i]);
        bv[i] = small_value(&b[i]);
        acc[i] = 0;
    }
    for (size_t i = 0; i < n; i++) {
        __int128 x = av[i];
        for (size_t j = 0; j < n - i; j++) {
            acc[i + j] += x * bv[j];
        }
        for (size_t j = n - i; j < n; j++) {
            acc[i + j - n] -= x * bv[j]; /* x^n = -1 */
        }
    }
    for (size_t k = 0; k < n; k++) {
        falcon_big_set_i128(&out[k], acc[k]);
    }
    falcon_secure_zero(av, n * sizeof av[0]); /* Z5: Werte aus keygen */
    falcon_secure_zero(bv, n * sizeof bv[0]);
    falcon_secure_zero(acc, n * sizeof acc[0]);
    return 1;
}

void falcon_poly_mul(falcon_big *out, const falcon_big *a, const falcon_big *b, size_t n)
{
    falcon_big product;

    if (poly_mul_small(out, a, b, n)) {
        return;
    }

    falcon_big_init(&product);
    for (size_t k = 0; k < n; k++) {
        falcon_big_set_i64(&out[k], 0);
    }
    for (size_t i = 0; i < n; i++) {
        if (falcon_big_is_zero(&a[i])) {
            continue;
        }
        for (size_t j = 0; j < n; j++) {
            if (falcon_big_is_zero(&b[j])) {
                continue;
            }
            falcon_big_mul(&product, &a[i], &b[j]);
            size_t k = i + j;
            if (k < n) {
                falcon_big_add(&out[k], &out[k], &product);
            } else {
                falcon_big_sub(&out[k - n], &out[k - n], &product);
            }
        }
    }
    falcon_big_free(&product);
}

int falcon_poly_split(falcon_big *a0, falcon_big *a1, const falcon_big *a, size_t n)
{
    if (n < 2 || (n & 1) != 0) {
        return FALCON_ERR_VALUE;
    }
    for (size_t i = 0; i < n / 2; i++) {
        falcon_big_copy(&a0[i], &a[2 * i]);
        falcon_big_copy(&a1[i], &a[2 * i + 1]);
    }
    return FALCON_OK;
}

void falcon_poly_lift(falcon_big *out, const falcon_big *a, size_t m)
{
    for (size_t i = 0; i < m; i++) {
        falcon_big_copy(&out[2 * i], &a[i]);
        falcon_big_set_i64(&out[2 * i + 1], 0);
    }
}

void falcon_poly_galois_conjugate(falcon_big *out, const falcon_big *a, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (i % 2 == 0) {
            falcon_big_copy(&out[i], &a[i]);
        } else {
            falcon_big_neg(&out[i], &a[i]);
        }
    }
}
