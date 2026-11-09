/* Tests für encoding.c gegen die Python-Vektoren, inklusive Ablehnungen. */
#include <string.h>

#include "encoding.h"
#include "vectors.h"

static int32_t s[VEC_MAX_LIST], f[VEC_MAX_LIST], g[VEC_MAX_LIST], F[VEC_MAX_LIST];
static int32_t exp0[VEC_MAX_LIST], exp1[VEC_MAX_LIST], exp2[VEC_MAX_LIST];
static uint8_t b[VEC_MAX_BYTES], out[VEC_MAX_BYTES], expected[VEC_MAX_BYTES];

static falcon_params read_params(const vec_file *v)
{
    int32_t pv[2];
    vec_ints(v, "params", pv, 2);
    falcon_params p = FALCON_512;
    p.n = (size_t)pv[0];
    p.sig_bytelen = (size_t)pv[1];
    return p;
}

static int expected_rc(const vec_file *v)
{
    int st = vec_status(v);
    return st == VEC_STATUS_OK ? FALCON_OK : st == VEC_STATUS_NONE ? FALCON_ERR_NONE : FALCON_ERR_VALUE;
}

static void test_compress(void)
{
    vec_file v;
    vec_open(&v, "encoding.compress");
    while (vec_next(&v)) {
        vec_ints(&v, "s", s, VEC_MAX_LIST);
        falcon_params p = read_params(&v);
        size_t len = 0;
        int rc = falcon_compress(out, &len, s, &p);
        CHECK(rc == expected_rc(&v), "compress Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_bytes(&v, "out", expected, sizeof expected);
            CHECK(m == len && memcmp(out, expected, m) == 0, "compress Fall %zu", v.index);
        }
    }
    vec_close(&v);
}

static void test_decompress(void)
{
    vec_file v;
    vec_open(&v, "encoding.decompress");
    while (vec_next(&v)) {
        size_t len = vec_bytes(&v, "b", b, sizeof b);
        falcon_params p = read_params(&v);
        int rc = falcon_decompress(s, b, len, &p);
        CHECK(rc == expected_rc(&v), "decompress Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t n = vec_ints(&v, "out", exp0, VEC_MAX_LIST);
            CHECK(n == p.n && memcmp(s, exp0, n * sizeof *s) == 0, "decompress Fall %zu", v.index);
        }
    }
    vec_close(&v);
}

static void test_pk(void)
{
    vec_file v;
    vec_open(&v, "encoding.encode_pk");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "h", s, VEC_MAX_LIST);
        size_t len = 0;
        int rc = falcon_encode_pk(out, &len, s, n);
        CHECK(rc == expected_rc(&v), "encode_pk Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_bytes(&v, "out", expected, sizeof expected);
            CHECK(m == len && memcmp(out, expected, m) == 0, "encode_pk Fall %zu", v.index);
        }
    }
    vec_close(&v);

    vec_open(&v, "encoding.decode_pk");
    while (vec_next(&v)) {
        size_t len = vec_bytes(&v, "b", b, sizeof b);
        size_t n = 0;
        int rc = falcon_decode_pk(s, &n, b, len);
        CHECK(rc == expected_rc(&v), "decode_pk Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_ints(&v, "out", exp0, VEC_MAX_LIST);
            CHECK(m == n && memcmp(s, exp0, n * sizeof *s) == 0, "decode_pk Fall %zu", v.index);
        }
    }
    vec_close(&v);
}

static void test_sk(void)
{
    vec_file v;
    vec_open(&v, "encoding.encode_sk");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "f", f, VEC_MAX_LIST);
        size_t n2 = vec_ints(&v, "g", g, VEC_MAX_LIST);
        size_t n3 = vec_ints(&v, "F", F, VEC_MAX_LIST);
        if (n != n2 || n != n3) {
            continue; /* ungleich lange Polynome sind in C nicht darstellbar */
        }
        size_t len = 0;
        int rc = falcon_encode_sk(out, &len, f, g, F, n);
        CHECK(rc == expected_rc(&v), "encode_sk Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_bytes(&v, "out", expected, sizeof expected);
            CHECK(m == len && memcmp(out, expected, m) == 0, "encode_sk Fall %zu", v.index);
        }
    }
    vec_close(&v);

    vec_open(&v, "encoding.decode_sk");
    while (vec_next(&v)) {
        size_t len = vec_bytes(&v, "b", b, sizeof b);
        size_t n = 0;
        int rc = falcon_decode_sk(f, g, F, &n, b, len);
        CHECK(rc == expected_rc(&v), "decode_sk Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_ints(&v, "out0", exp0, VEC_MAX_LIST);
            vec_ints(&v, "out1", exp1, VEC_MAX_LIST);
            vec_ints(&v, "out2", exp2, VEC_MAX_LIST);
            CHECK(m == n && memcmp(f, exp0, n * sizeof *f) == 0, "decode_sk f Fall %zu", v.index);
            CHECK(memcmp(g, exp1, n * sizeof *g) == 0, "decode_sk g Fall %zu", v.index);
            CHECK(memcmp(F, exp2, n * sizeof *F) == 0, "decode_sk F Fall %zu", v.index);
        }
    }
    vec_close(&v);
}

static void test_sig(void)
{
    static falcon_signature sig;
    vec_file v;

    vec_open(&v, "encoding.encode_sig");
    while (vec_next(&v)) {
        size_t salt_len = vec_bytes(&v, "sig_salt", b, sizeof b);
        if (salt_len != FALCON_SALT_BYTES) {
            continue; /* Salt hat in C eine feste Länge */
        }
        memcpy(sig.salt, b, FALCON_SALT_BYTES);
        sig.s2_len = vec_bytes(&v, "sig_s2", sig.s2_encoded, sizeof sig.s2_encoded);
        falcon_params p = read_params(&v);
        size_t len = 0;
        int rc = falcon_encode_sig(out, &len, &sig, &p);
        CHECK(rc == expected_rc(&v), "encode_sig Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_bytes(&v, "out", expected, sizeof expected);
            CHECK(m == len && memcmp(out, expected, m) == 0, "encode_sig Fall %zu", v.index);
        }
    }
    vec_close(&v);

    vec_open(&v, "encoding.decode_sig");
    while (vec_next(&v)) {
        size_t len = vec_bytes(&v, "b", b, sizeof b);
        falcon_params p = read_params(&v);
        int rc = falcon_decode_sig(&sig, b, len, &p);
        CHECK(rc == expected_rc(&v), "decode_sig Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            vec_bytes(&v, "out_salt", expected, sizeof expected);
            CHECK(memcmp(sig.salt, expected, FALCON_SALT_BYTES) == 0, "decode_sig Salt Fall %zu", v.index);
            size_t m = vec_bytes(&v, "out_s2", expected, sizeof expected);
            CHECK(m == sig.s2_len && memcmp(sig.s2_encoded, expected, m) == 0, "decode_sig s2 Fall %zu", v.index);
        }
    }
    vec_close(&v);

    vec_open(&v, "encoding.decode_kat_message");
    while (vec_next(&v)) {
        size_t len = vec_bytes(&v, "sm", b, sizeof b);
        const uint8_t *msg = NULL;
        size_t mlen = 0;
        int rc = falcon_decode_kat_message(&msg, &mlen, &sig, b, len);
        CHECK(rc == expected_rc(&v), "decode_kat Fall %zu: rc = %d", v.index, rc);
        if (rc == FALCON_OK && vec_status(&v) == VEC_STATUS_OK) {
            size_t m = vec_bytes(&v, "msg", expected, sizeof expected);
            CHECK(m == mlen && memcmp(msg, expected, m) == 0, "decode_kat msg Fall %zu", v.index);
            m = vec_bytes(&v, "out_s2", expected, sizeof expected);
            CHECK(m == sig.s2_len && memcmp(sig.s2_encoded, expected, m) == 0, "decode_kat s2 Fall %zu", v.index);
        }
    }
    vec_close(&v);
}

int main(void)
{
    test_compress();
    test_decompress();
    test_pk();
    test_sk();
    test_sig();
    return test_summary("encoding");
}
