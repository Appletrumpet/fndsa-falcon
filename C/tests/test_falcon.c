/* Tests für falcon.c: compute_s1, is_short und ganze Verify-Abläufe aus Python. */
#include <string.h>

#include "encoding.h"
#include "falcon.h"
#include "vectors.h"

static int32_t c[VEC_MAX_LIST], s1[VEC_MAX_LIST], s2[VEC_MAX_LIST], h[VEC_MAX_LIST], expected[VEC_MAX_LIST];
static uint8_t msg[VEC_MAX_BYTES], sig_bytes[VEC_MAX_BYTES];

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

    /* Falscher Parametersatz: wie in Python Ablehnung, kein Fehler. */
    pk.n = 512;
    CHECK(falcon_verify(&pk, msg, 0, &sig, &FALCON_1024) == 0, "pk passt nicht zu params");
    return test_summary("falcon");
}
