/* Tests für poly.c gegen die Python-Vektoren, auch mit grossen Koeffizienten. */
#include "poly.h"
#include "vectors.h"

#define CAP 4096

static falcon_big *a, *b, *out, *out2, *want, *want2;

typedef void (*binary_fn)(falcon_big *, const falcon_big *, const falcon_big *, size_t);
typedef void (*unary_fn)(falcon_big *, const falcon_big *, size_t);

static void check_binary(const char *file, binary_fn fn)
{
    vec_file v;
    vec_open(&v, file);
    while (vec_next(&v)) {
        size_t n = vec_big_list(&v, "a", a, CAP);
        size_t m = vec_big_list(&v, "b", b, CAP);
        size_t r = vec_big_list(&v, "out", want, CAP);
        if (n != m) {
            continue;
        }
        fn(out, a, b, n);
        CHECK(r == n && big_list_equal(out, want, n), "%s Fall %zu", file, v.index);
    }
    vec_close(&v);
}

static void check_unary(const char *file, unary_fn fn, size_t factor)
{
    vec_file v;
    vec_open(&v, file);
    while (vec_next(&v)) {
        size_t n = vec_big_list(&v, "a", a, CAP);
        size_t r = vec_big_list(&v, "out", want, CAP);
        fn(out, a, n);
        CHECK(r == factor * n && big_list_equal(out, want, r), "%s Fall %zu", file, v.index);
    }
    vec_close(&v);
}

int main(void)
{
    static int32_t ints[VEC_MAX_LIST];
    vec_file v;

    a = falcon_poly_new(CAP);
    b = falcon_poly_new(CAP);
    out = falcon_poly_new(CAP);
    out2 = falcon_poly_new(CAP);
    want = falcon_poly_new(CAP);
    want2 = falcon_poly_new(CAP);

    vec_open(&v, "poly.norm_sq");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "a", ints, VEC_MAX_LIST);
        CHECK(falcon_norm_sq(ints, n) == (uint64_t)vec_int(&v, "out"), "norm_sq Fall %zu", v.index);
    }
    vec_close(&v);

    check_binary("poly.poly_add", falcon_poly_add);
    check_binary("poly.poly_sub", falcon_poly_sub);
    check_binary("poly.poly_mul", falcon_poly_mul);
    check_unary("poly.poly_neg", falcon_poly_neg, 1);
    check_unary("poly.lift", falcon_poly_lift, 2);
    check_unary("poly.galois_conjugate", falcon_poly_galois_conjugate, 1);

    vec_open(&v, "poly.split");
    while (vec_next(&v)) {
        size_t n = vec_big_list(&v, "a", a, CAP);
        int rc = falcon_poly_split(out, out2, a, n);
        if (vec_status(&v) == VEC_STATUS_OK) {
            vec_big_list(&v, "out0", want, CAP);
            vec_big_list(&v, "out1", want2, CAP);
            CHECK(rc == FALCON_OK && big_list_equal(out, want, n / 2) && big_list_equal(out2, want2, n / 2),
                  "split Fall %zu", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "split Fall %zu", v.index);
        }
    }
    vec_close(&v);

    falcon_poly_free(a, CAP);
    falcon_poly_free(b, CAP);
    falcon_poly_free(out, CAP);
    falcon_poly_free(out2, CAP);
    falcon_poly_free(want, CAP);
    falcon_poly_free(want2, CAP);
    return test_summary("poly");
}
