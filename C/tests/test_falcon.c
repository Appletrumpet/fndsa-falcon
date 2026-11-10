/* Tests für falcon.c: Bausteine und ganze Abläufe aus Python, bitgenau. */
#include <string.h>

#include "encoding.h"
#include "falcon.h"
#include "vectors.h"

static int32_t c[VEC_MAX_LIST], s1[VEC_MAX_LIST], s2[VEC_MAX_LIST], h[VEC_MAX_LIST], expected[VEC_MAX_LIST];
static uint8_t msg[VEC_MAX_BYTES], sig_bytes[VEC_MAX_BYTES], sk_bytes[VEC_MAX_BYTES], out_bytes[VEC_MAX_BYTES];
static falcon_cplx ca[FALCON_MAX_N], cb[FALCON_MAX_N], cc[FALCON_MAX_N], cd[FALCON_MAX_N];
static falcon_cplx oa[FALCON_MAX_N], ob[FALCON_MAX_N], ea[FALCON_MAX_N], eb[FALCON_MAX_N];
static falcon_secret_key sk;

static void test_sign_building_blocks(void)
{
    vec_file v;

    vec_open(&v, "falcon.compute_target");
    while (vec_next(&v)) {
        sk.n = (size_t)vec_ints(&v, "c", c, VEC_MAX_LIST);
        vec_ints(&v, "f", sk.f, FALCON_MAX_N);
        vec_ints(&v, "F", sk.F, FALCON_MAX_N);
        vec_cplx(&v, "out0", ea, FALCON_MAX_N);
        vec_cplx(&v, "out1", eb, FALCON_MAX_N);
        falcon_compute_target(oa, ob, c, &sk);
        CHECK(SAME_BITS(oa, ea, sk.n) && SAME_BITS(ob, eb, sk.n), "compute_target Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "falcon.compute_signature_vector");
    while (vec_next(&v)) {
        sk.n = vec_cplx(&v, "t0", ca, FALCON_MAX_N);
        vec_cplx(&v, "t1", cb, FALCON_MAX_N);
        vec_cplx(&v, "z0", cc, FALCON_MAX_N);
        vec_cplx(&v, "z1", cd, FALCON_MAX_N);
        vec_cplx(&v, "basis00", sk.b00, FALCON_MAX_N);
        vec_cplx(&v, "basis01", sk.b01, FALCON_MAX_N);
        vec_cplx(&v, "basis10", sk.b10, FALCON_MAX_N);
        vec_cplx(&v, "basis11", sk.b11, FALCON_MAX_N);
        vec_cplx(&v, "out0", ea, FALCON_MAX_N);
        vec_cplx(&v, "out1", eb, FALCON_MAX_N);
        falcon_compute_signature_vector(oa, ob, ca, cb, cc, cd, &sk);
        CHECK(SAME_BITS(oa, ea, sk.n) && SAME_BITS(ob, eb, sk.n), "compute_signature_vector Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "falcon.is_short_fft");
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "s0", ca, FALCON_MAX_N);
        vec_cplx(&v, "s1", cb, FALCON_MAX_N);
        falcon_params p = vec_params(&v);
        CHECK(falcon_is_short_fft(ca, cb, n, &p) == vec_int(&v, "out"), "is_short_fft Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "falcon.to_coefficients");
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "s0", ca, FALCON_MAX_N);
        vec_cplx(&v, "s1", cb, FALCON_MAX_N);
        vec_ints(&v, "out0", expected, VEC_MAX_LIST);
        vec_ints(&v, "out1", c, VEC_MAX_LIST);
        CHECK(falcon_to_coefficients(s1, s2, ca, cb, n) == FALCON_OK, "to_coefficients Fall %zu", v.index);
        CHECK(SAME_BITS(s1, expected, n) && SAME_BITS(s2, c, n), "to_coefficients Fall %zu", v.index);
    }
    vec_close(&v);
}

static void test_keygen(void)
{
    static falcon_public_key out_pk;
    static uint8_t seed[256];
    static int32_t ef[FALCON_MAX_N], eg[FALCON_MAX_N], eF[FALCON_MAX_N], eG[FALCON_MAX_N], eh[FALCON_MAX_N];
    vec_file v;

    vec_open(&v, "flow.keygen");
    while (vec_next(&v)) {
        size_t n = (size_t)vec_int(&v, "n");
        falcon_params p = n == 1024 ? FALCON_1024 : FALCON_512;
        p.n = n;
        size_t seed_len = vec_bytes(&v, "seed", seed, sizeof seed);
        vec_ints(&v, "key0", ef, FALCON_MAX_N);
        vec_ints(&v, "key1", eg, FALCON_MAX_N);
        vec_ints(&v, "key2", eF, FALCON_MAX_N);
        vec_ints(&v, "key3", eG, FALCON_MAX_N);
        vec_ints(&v, "h", eh, FALCON_MAX_N);
        falcon_shake256_ctx ctx;
        falcon_rng rng = shake_rng(&ctx, seed, seed_len);

        CHECK(falcon_keygen(&sk, &out_pk, &p, &rng) == FALCON_OK, "keygen Fall %zu (n = %zu)", v.index, n);
        CHECK(SAME_BITS(sk.f, ef, n) && SAME_BITS(sk.g, eg, n), "keygen Fall %zu: f, g", v.index);
        CHECK(SAME_BITS(sk.F, eF, n) && SAME_BITS(sk.G, eG, n), "keygen Fall %zu: F, G", v.index);
        CHECK(out_pk.n == n && SAME_BITS(out_pk.h, eh, n), "keygen Fall %zu: h", v.index);
    }
    vec_close(&v);

    vec_open(&v, "falcon.compute_public_key");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "f", ef, FALCON_MAX_N);
        vec_ints(&v, "g", eg, FALCON_MAX_N);
        falcon_params p = vec_params(&v);
        p.n = n;
        int rc = falcon_compute_public_key(eh, ef, eg, &p);
        if (vec_status(&v) == VEC_STATUS_OK) {
            vec_ints(&v, "out", eF, FALCON_MAX_N);
            CHECK(rc == FALCON_OK && SAME_BITS(eh, eF, n), "compute_public_key Fall %zu", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "compute_public_key Fall %zu", v.index);
        }
    }
    vec_close(&v);
}

static void test_sign_flow(const char *file, int with_limits)
{
    static falcon_signature sig;
    static uint8_t seed[256];
    vec_file v;

    vec_open(&v, file);
    while (vec_next(&v)) {
        falcon_params p = vec_int(&v, "n") == 1024 ? FALCON_1024 : FALCON_512;
        if (with_limits) {
            p.sig_bound = (uint64_t)vec_int(&v, "sig_bound");
            p.sig_bytelen = (size_t)vec_int(&v, "sig_bytelen");
        }
        size_t seed_len = vec_bytes(&v, "seed", seed, sizeof seed);
        size_t sk_len = vec_bytes(&v, "sk", sk_bytes, sizeof sk_bytes);
        size_t mlen = vec_bytes(&v, "msg", msg, sizeof msg);
        size_t slen = vec_bytes(&v, "sig", sig_bytes, sizeof sig_bytes);
        falcon_shake256_ctx ctx;
        falcon_rng rng = shake_rng(&ctx, seed, seed_len);
        size_t produced = 0;

        CHECK(falcon_load_secret_key(&sk, sk_bytes, sk_len, &p) == FALCON_OK, "%s Fall %zu: sk", file, v.index);
        CHECK(falcon_sign(&sig, &sk, msg, mlen, &p, &rng) == FALCON_OK, "%s Fall %zu: sign", file, v.index);
        CHECK(falcon_encode_sig(out_bytes, &produced, &sig, &p) == FALCON_OK, "%s Fall %zu: encode", file, v.index);
        CHECK(produced == slen && memcmp(out_bytes, sig_bytes, slen) == 0, "%s Fall %zu: Signatur", file, v.index);
    }
    vec_close(&v);
}

static falcon_params read_params(const vec_file *v)
{
    int32_t pv[2];
    vec_ints(v, "params", pv, 2);
    falcon_params p = pv[0] == 1024 ? FALCON_1024 : FALCON_512;
    p.n = (size_t)pv[0];
    p.sig_bytelen = (size_t)pv[1];
    return p;
}

int main(void)
{
    static falcon_public_key pk;
    static falcon_signature sig;
    vec_file v;

    vec_open(&v, "falcon.compute_s1");
    while (vec_next(&v)) {
        vec_ints(&v, "c", c, VEC_MAX_LIST);
        vec_ints(&v, "s2", s2, VEC_MAX_LIST);
        vec_ints(&v, "h", h, VEC_MAX_LIST);
        falcon_params p = read_params(&v);
        p.n = vec_ints(&v, "out", expected, VEC_MAX_LIST);
        CHECK(falcon_compute_s1(s1, c, s2, h, &p) == FALCON_OK, "compute_s1 Fall %zu", v.index);
        CHECK(memcmp(s1, expected, p.n * sizeof *s1) == 0, "compute_s1 Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "falcon.is_short");
    while (vec_next(&v)) {
        vec_ints(&v, "s1", s1, VEC_MAX_LIST);
        vec_ints(&v, "s2", s2, VEC_MAX_LIST);
        falcon_params p = read_params(&v);
        CHECK(falcon_is_short(s1, s2, &p) == vec_int(&v, "out"), "is_short Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "flow.verify");
    while (vec_next(&v)) {
        const falcon_params *p = vec_int(&v, "n") == 1024 ? &FALCON_1024 : &FALCON_512;
        pk.n = vec_ints(&v, "h", pk.h, FALCON_MAX_N);
        size_t mlen = vec_bytes(&v, "msg", msg, sizeof msg);
        size_t slen = vec_bytes(&v, "sig", sig_bytes, sizeof sig_bytes);
        CHECK(falcon_decode_sig(&sig, sig_bytes, slen, p) == FALCON_OK, "verify Fall %zu", v.index);
        CHECK(falcon_verify(&pk, msg, mlen, &sig, p) == vec_int(&v, "out"), "verify Fall %zu", v.index);
    }
    vec_close(&v);

    test_keygen();
    test_sign_building_blocks();
    test_sign_flow("flow.sign", 0);
    test_sign_flow("flow.sign_restart", 1);

    /* load_secret_key: Schlüssel eines anderen Parametersatzes und ungültige Kodierung. */
    {
        vec_open(&v, "flow.sign");
        CHECK(vec_next(&v), "flow.sign leer");
        size_t sk_len = vec_bytes(&v, "sk", sk_bytes, sizeof sk_bytes);
        CHECK(falcon_load_secret_key(&sk, sk_bytes, sk_len, &FALCON_1024) == FALCON_ERR_VALUE, "sk 512 mit Parametern 1024");
        CHECK(falcon_load_secret_key(&sk, sk_bytes, 11, &FALCON_512) == FALCON_ERR_VALUE, "abgeschnittener sk");
        vec_close(&v);
    }

    /* Falscher Parametersatz: wie in Python Ablehnung, kein Fehler. */
    pk.n = 512;
    CHECK(falcon_verify(&pk, msg, 0, &sig, &FALCON_1024) == 0, "pk passt nicht zu params");
    return test_summary("falcon");
}
