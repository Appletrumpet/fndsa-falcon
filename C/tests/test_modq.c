/* Tests für modq.c gegen die Python-Vektoren, bitgenau. */
#include <string.h>

#include "modq.h"
#include "vectors.h"

static int32_t a[VEC_MAX_LIST], b[VEC_MAX_LIST], out[VEC_MAX_LIST], expected[VEC_MAX_LIST];

static int expected_rc(const vec_file *v)
{
    return vec_status(v) == VEC_STATUS_OK ? FALCON_OK : FALCON_ERR_VALUE;
}

typedef int (*unary_fn)(int32_t *, const int32_t *, size_t);
typedef int (*binary_fn)(int32_t *, const int32_t *, const int32_t *, size_t);

static void check_unary(const char *file, unary_fn fn)
{
    vec_file v;
    vec_open(&v, file);
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "a", a, VEC_MAX_LIST);
        int rc = fn(out, a, n);
        CHECK(rc == expected_rc(&v), "%s Fall %zu: rc = %d", file, v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_ints(&v, "out", expected, VEC_MAX_LIST);
            CHECK(m == n && memcmp(out, expected, n * sizeof *out) == 0, "%s Fall %zu", file, v.index);
        }
    }
    vec_close(&v);
}

static void check_binary(const char *file, binary_fn fn)
{
    vec_file v;
    vec_open(&v, file);
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "a", a, VEC_MAX_LIST);
        size_t m = vec_ints(&v, "b", b, VEC_MAX_LIST);
        if (n != m) {
            continue; /* In C gibt es nur eine Länge; ungleich lange Operanden sind nicht darstellbar. */
        }
        int rc = fn(out, a, b, n);
        CHECK(rc == expected_rc(&v), "%s Fall %zu: rc = %d", file, v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            vec_ints(&v, "out", expected, VEC_MAX_LIST);
            CHECK(memcmp(out, expected, n * sizeof *out) == 0, "%s Fall %zu", file, v.index);
        }
    }
    vec_close(&v);
}

int main(void)
{
    vec_file v;

    check_unary("modq.ntt", falcon_ntt);
    check_unary("modq.intt", falcon_intt);
    check_binary("modq.mul_mod_q", falcon_mul_mod_q);
    check_binary("modq.div_mod_q", falcon_div_mod_q);

    vec_open(&v, "modq.is_invertible_mod_q");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "a", a, VEC_MAX_LIST);
        CHECK(falcon_is_invertible_mod_q(a, n) == vec_int(&v, "out"), "invertierbar Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "modq.center_mod_q");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "a", a, VEC_MAX_LIST);
        vec_ints(&v, "out", expected, VEC_MAX_LIST);
        falcon_center_mod_q(out, a, n);
        CHECK(memcmp(out, expected, n * sizeof *out) == 0, "center Fall %zu", v.index);
    }
    vec_close(&v);

    CHECK(falcon_mod_q(-3) == 12286, "-3 mod q");
    CHECK(falcon_mod_q(-12289) == 0, "-q mod q");
    /* Barrett-Reduktion gegen % über den ganzen zugesicherten Bereich und an den Rändern. */
    {
        const int64_t lo = -(int64_t)FALCON_Q * ((int64_t)1 << 40), hi = (int64_t)1 << 62;
        int64_t edges[] = {0, 1, FALCON_Q - 1, FALCON_Q, FALCON_Q + 1, 2 * FALCON_Q - 1, 2 * FALCON_Q,
                           (int64_t)(FALCON_Q - 1) * (FALCON_Q - 1), INT32_MAX, INT32_MIN,
                           ((int64_t)1 << 33), -((int64_t)1 << 33), lo, lo + 1, hi, hi - 1};
        int bad = 0;
        for (size_t i = 0; i < sizeof edges / sizeof edges[0]; i++) {
            for (int64_t d = -2; d <= 2; d++) {
                int64_t x = edges[i] + d;
                if (x < lo || x > hi) {
                    continue;
                }
                int64_t r = x % FALCON_Q;
                bad |= falcon_mod_q(x) != (int32_t)(r < 0 ? r + FALCON_Q : r);
            }
        }
        uint64_t state = 0x9E3779B97F4A7C15u;
        for (int i = 0; i < 200000; i++) {
            state = state * 6364136223846793005u + 1442695040888963407u;
            int64_t x = (int64_t)(state >> 1) % (hi - lo) + lo;
            if (x < lo) {
                x += hi - lo;
            }
            int64_t r = x % FALCON_Q;
            bad |= falcon_mod_q(x) != (int32_t)(r < 0 ? r + FALCON_Q : r);
        }
        CHECK(!bad, "mod_q gegen %%");
    }
    return test_summary("modq");
}
