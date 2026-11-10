/* Tests für ntrugen.c gegen die Python-Vektoren, bitgenau. */
#include "ntrugen.h"
#include "poly.h"
#include "vectors.h"

#define CAP FALCON_MAX_N

static int32_t f[VEC_MAX_LIST], g[VEC_MAX_LIST], F[VEC_MAX_LIST], G[VEC_MAX_LIST], expected[VEC_MAX_LIST];
static uint8_t random_bytes[1 << 20];
static falcon_big *bf, *bg, *bF, *bG, *eF, *eG;

static void test_recompute_g(void)
{
    vec_file v;
    vec_open(&v, "ntrugen.recompute_G");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "f", f, VEC_MAX_LIST);
        vec_ints(&v, "g", g, VEC_MAX_LIST);
        vec_ints(&v, "F", F, VEC_MAX_LIST);
        vec_ints(&v, "out", expected, VEC_MAX_LIST);
        CHECK(falcon_recompute_G(G, f, g, F, n) == FALCON_OK, "recompute_G Fall %zu", v.index);
        CHECK(SAME_BITS(G, expected, n), "recompute_G Fall %zu", v.index);
    }
    vec_close(&v);
}

static void test_small(void)
{
    vec_file v;

    vec_open(&v, "ntrugen.sample_short_poly");
    while (vec_next(&v)) {
        falcon_params p = vec_params(&v);
        size_t len = vec_bytes(&v, "random", random_bytes, sizeof random_bytes);
        size_t n = vec_ints(&v, "out", expected, VEC_MAX_LIST);
        fixed_rng_state st;
        falcon_rng rng = fixed_rng(&st, random_bytes, len);
        CHECK(falcon_sample_short_poly(f, &p, &rng) == FALCON_OK, "sample_short_poly Fall %zu", v.index);
        CHECK(SAME_BITS(f, expected, n), "sample_short_poly Fall %zu", v.index);
        CHECK(st.pos == st.len, "sample_short_poly Fall %zu: Verbrauch", v.index);
    }
    vec_close(&v);

    vec_open(&v, "ntrugen.gram_schmidt_norm");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "f", f, VEC_MAX_LIST);
        vec_ints(&v, "g", g, VEC_MAX_LIST);
        falcon_params p = vec_params(&v);
        double x = falcon_gram_schmidt_norm(f, g, n, &p);
        double want = vec_double(&v, "out");
        CHECK(memcmp(&x, &want, sizeof x) == 0, "gram_schmidt_norm Fall %zu", v.index);
    }
    vec_close(&v);
}

static void test_big(void)
{
    falcon_big a, b, d, u, w, e0, e1, e2;
    falcon_big *all[] = {&a, &b, &d, &u, &w, &e0, &e1, &e2};
    vec_file v;

    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
        falcon_big_init(all[i]);
    }

    vec_open(&v, "ntrugen.xgcd");
    while (vec_next(&v)) {
        vec_big(&v, "a", &a);
        vec_big(&v, "b", &b);
        vec_big(&v, "out0", &e0);
        vec_big(&v, "out1", &e1);
        vec_big(&v, "out2", &e2);
        falcon_xgcd(&d, &u, &w, &a, &b);
        CHECK(falcon_big_cmp(&d, &e0) == 0 && falcon_big_cmp(&u, &e1) == 0 && falcon_big_cmp(&w, &e2) == 0,
              "xgcd Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "ntrugen.scaled_float");
    while (vec_next(&v)) {
        vec_big(&v, "c", &a);
        double x = falcon_scaled_float(&a, (size_t)vec_int(&v, "scale"));
        double want = vec_double(&v, "out");
        CHECK(memcmp(&x, &want, sizeof x) == 0, "scaled_float Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "ntrugen.round_scaled_float");
    while (vec_next(&v)) {
        vec_big(&v, "out", &e0);
        falcon_round_scaled_float(&a, vec_double(&v, "x"), (int)vec_int(&v, "exp"));
        CHECK(falcon_big_cmp(&a, &e0) == 0, "round_scaled_float Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "ntrugen.field_norm");
    while (vec_next(&v)) {
        size_t n = vec_big_list(&v, "a", bf, CAP);
        int rc = falcon_field_norm(bg, bf, n);
        if (vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_big_list(&v, "out", eF, CAP);
            CHECK(rc == FALCON_OK && m == n / 2 && big_list_equal(bg, eF, m), "field_norm Fall %zu", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "field_norm Fall %zu", v.index);
        }
    }
    vec_close(&v);

    vec_open(&v, "ntrugen.reduce");
    while (vec_next(&v)) {
        size_t n = vec_big_list(&v, "f", bf, CAP);
        vec_big_list(&v, "g", bg, CAP);
        vec_big_list(&v, "F", bF, CAP);
        vec_big_list(&v, "G", bG, CAP);
        vec_big_list(&v, "out0", eF, CAP);
        vec_big_list(&v, "out1", eG, CAP);
        falcon_reduce(bf, bg, bF, bG, n);
        CHECK(big_list_equal(bF, eF, n) && big_list_equal(bG, eG, n), "reduce Fall %zu (n = %zu)", v.index, n);
    }
    vec_close(&v);

    vec_open(&v, "ntrugen.solve_ntru");
    while (vec_next(&v)) {
        size_t n = vec_big_list(&v, "f", bf, CAP);
        vec_big_list(&v, "g", bg, CAP);
        falcon_params p = vec_params(&v);
        int rc = falcon_solve_ntru(bF, bG, bf, bg, n, &p);
        if (vec_status(&v) == VEC_STATUS_OK) {
            vec_big_list(&v, "out0", eF, CAP);
            vec_big_list(&v, "out1", eG, CAP);
            CHECK(rc == FALCON_OK && big_list_equal(bF, eF, n) && big_list_equal(bG, eG, n),
                  "solve_ntru Fall %zu (n = %zu)", v.index, n);
        } else {
            CHECK(rc == FALCON_ERR_NONE, "solve_ntru Fall %zu: rc = %d", v.index, rc);
        }
    }
    vec_close(&v);

    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
        falcon_big_free(all[i]);
    }
}

int main(void)
{
    bf = falcon_poly_new(CAP);
    bg = falcon_poly_new(CAP);
    bF = falcon_poly_new(CAP);
    bG = falcon_poly_new(CAP);
    eF = falcon_poly_new(CAP);
    eG = falcon_poly_new(CAP);

    test_recompute_g();
    test_small();
    test_big();

    falcon_poly_free(bf, CAP);
    falcon_poly_free(bg, CAP);
    falcon_poly_free(bF, CAP);
    falcon_poly_free(bG, CAP);
    falcon_poly_free(eF, CAP);
    falcon_poly_free(eG, CAP);
    return test_summary("ntrugen");
}
