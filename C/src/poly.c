#include "poly.h"

#include <stdlib.h>

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

void falcon_poly_mul(falcon_big *out, const falcon_big *a, const falcon_big *b, size_t n)
{
    falcon_big product;

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
