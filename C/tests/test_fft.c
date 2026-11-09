/* Tests für fft.c gegen die Python-Vektoren, bitgenau (auch das Vorzeichen von Nullen). */
#include "fft.h"
#include "vectors.h"

static double reals[VEC_MAX_LIST], reals2[VEC_MAX_LIST];
static falcon_cplx a[VEC_MAX_LIST], b[VEC_MAX_LIST], out[VEC_MAX_LIST], out2[VEC_MAX_LIST];
static falcon_cplx expected[VEC_MAX_LIST], expected2[VEC_MAX_LIST];

typedef void (*pointwise_fn)(falcon_cplx *, const falcon_cplx *, const falcon_cplx *, size_t);

static void check_pointwise(const char *file, pointwise_fn fn)
{
    vec_file v;
    vec_open(&v, file);
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "a", a, VEC_MAX_LIST);
        size_t m = vec_cplx(&v, "b", b, VEC_MAX_LIST);
        if (n != m) {
            continue;
        }
        vec_cplx(&v, "out", expected, VEC_MAX_LIST);
        fn(out, a, b, n);
        CHECK(SAME_BITS(out, expected, n), "%s Fall %zu", file, v.index);
    }
    vec_close(&v);
}

int main(void)
{
    vec_file v;

    vec_open(&v, "fft.fft");
    while (vec_next(&v)) {
        size_t n = vec_doubles(&v, "a", reals, VEC_MAX_LIST);
        int rc = falcon_fft(out, reals, n);
        if (vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_cplx(&v, "out", expected, VEC_MAX_LIST);
            CHECK(rc == FALCON_OK && m == n && SAME_BITS(out, expected, n), "fft Fall %zu", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "fft Fall %zu: rc = %d", v.index, rc);
        }
    }
    vec_close(&v);

    vec_open(&v, "fft.ifft");
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "a", a, VEC_MAX_LIST);
        int rc = falcon_ifft(reals, a, n);
        if (vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_doubles(&v, "out", reals2, VEC_MAX_LIST);
            CHECK(rc == FALCON_OK && m == n && SAME_BITS(reals, reals2, n), "ifft Fall %zu", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "ifft Fall %zu: rc = %d", v.index, rc);
        }
    }
    vec_close(&v);

    check_pointwise("fft.fft_add", falcon_fft_add);
    check_pointwise("fft.fft_sub", falcon_fft_sub);
    check_pointwise("fft.fft_mul", falcon_fft_mul);

    vec_open(&v, "fft.fft_div");
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "a", a, VEC_MAX_LIST);
        vec_cplx(&v, "b", b, VEC_MAX_LIST);
        int rc = falcon_fft_div(out, a, b, n);
        if (vec_status(&v) == VEC_STATUS_OK) {
            vec_cplx(&v, "out", expected, VEC_MAX_LIST);
            CHECK(rc == FALCON_OK && SAME_BITS(out, expected, n), "fft_div Fall %zu", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "fft_div Fall %zu: rc = %d", v.index, rc);
        }
    }
    vec_close(&v);

    vec_open(&v, "fft.fft_adj");
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "a", a, VEC_MAX_LIST);
        vec_cplx(&v, "out", expected, VEC_MAX_LIST);
        falcon_fft_adj(out, a, n);
        CHECK(SAME_BITS(out, expected, n), "fft_adj Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "fft.fft_norm_sq");
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "a", a, VEC_MAX_LIST);
        double result = 0.0;
        int rc = falcon_fft_norm_sq(&result, a, n);
        if (vec_status(&v) == VEC_STATUS_OK) {
            double want = vec_double(&v, "out");
            CHECK(rc == FALCON_OK && memcmp(&result, &want, sizeof want) == 0, "fft_norm_sq Fall %zu", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "fft_norm_sq Fall %zu", v.index);
        }
    }
    vec_close(&v);

    vec_open(&v, "fft.split_fft");
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "a", a, VEC_MAX_LIST);
        int rc = falcon_split_fft(out, out2, a, n);
        if (vec_status(&v) == VEC_STATUS_OK) {
            vec_cplx(&v, "out0", expected, VEC_MAX_LIST);
            vec_cplx(&v, "out1", expected2, VEC_MAX_LIST);
            CHECK(rc == FALCON_OK && SAME_BITS(out, expected, n / 2) && SAME_BITS(out2, expected2, n / 2),
                  "split_fft Fall %zu (n = %zu)", v.index, n);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "split_fft Fall %zu", v.index);
        }
    }
    vec_close(&v);

    vec_open(&v, "fft.merge_fft");
    while (vec_next(&v)) {
        size_t h = vec_cplx(&v, "a0", a, VEC_MAX_LIST);
        vec_cplx(&v, "a1", b, VEC_MAX_LIST);
        int rc = falcon_merge_fft(out, a, b, h);
        if (vec_status(&v) == VEC_STATUS_OK) {
            vec_cplx(&v, "out", expected, VEC_MAX_LIST);
            CHECK(rc == FALCON_OK && SAME_BITS(out, expected, 2 * h), "merge_fft Fall %zu", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "merge_fft Fall %zu", v.index);
        }
    }
    vec_close(&v);

    return test_summary("fft");
}
