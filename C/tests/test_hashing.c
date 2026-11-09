/* Tests für hashing.c: Python-Vektoren und die NIST-Sampler-Testvektoren. */
#include <string.h>
#include <stdlib.h>

#include "hashing.h"
#include "vectors.h"

/* Hex-Wert einer Zeile "<schluessel> = <hex>" aus den NIST-Dateien. */
static size_t find_hex(const char *text, const char *key, uint8_t *dst)
{
    const char *p = strstr(text, key);
    size_t count = 0;
    if (p == NULL) {
        return 0;
    }
    p += strlen(key);
    while ((p[0] >= '0' && p[0] <= '9') || (p[0] >= 'a' && p[0] <= 'f')) {
        unsigned value;
        sscanf(p, "%2x", &value);
        dst[count++] = (uint8_t)value;
        p += 2;
    }
    return count;
}

static void check_nist_vector(const char *name, const falcon_params *p)
{
    static uint8_t nonce[64], data[64];
    static int32_t c[FALCON_MAX_N];
    char path[512];
    size_t len;

    snprintf(path, sizeof path, "%s/sampler/%s", FALCON_DATA_DIR, name);
    char *text = read_file(path, &len);
    size_t nlen = find_hex(text, "\nnonce = ", nonce);
    size_t dlen = find_hex(text, "\ndata = ", data);
    CHECK(nlen == 40 && dlen == 5, "%s: Kopfdaten", name);
    CHECK(falcon_hash_to_point(c, nonce, nlen, data, dlen, p) == FALCON_OK, "%s", name);

    const char *q = strstr(text, "hashed message = ");
    CHECK(q != NULL, "%s: hashed message fehlt", name);
    q += strlen("hashed message = ");
    for (size_t i = 0; i < p->n; i++) {
        int expected, used;
        sscanf(q, "%d%n", &expected, &used);
        q += used;
        CHECK(c[i] == expected, "%s: Koeffizient %zu", name, i);
    }
    free(text);
}

int main(void)
{
    static uint8_t data[VEC_MAX_BYTES];
    static int32_t expected[VEC_MAX_LIST], c[VEC_MAX_LIST], c2[VEC_MAX_LIST];
    int32_t pv[2];
    vec_file v;

    vec_open(&v, "hashing.hash_to_point");
    while (vec_next(&v)) {
        size_t dlen = vec_bytes(&v, "data", data, sizeof data);
        vec_ints(&v, "params", pv, 2);
        falcon_params p = FALCON_512;
        p.n = (size_t)pv[0];
        p.sig_bytelen = (size_t)pv[1];
        size_t n = vec_ints(&v, "out", expected, VEC_MAX_LIST);

        CHECK(falcon_hash_to_point(c, data, dlen, NULL, 0, &p) == FALCON_OK, "Fall %zu", v.index);
        CHECK(n == p.n && memcmp(c, expected, n * sizeof *c) == 0, "Fall %zu", v.index);

        /* Salt und Nachricht werden fortlaufend eingelesen: Trennstelle ist egal. */
        size_t cut = dlen / 3;
        CHECK(falcon_hash_to_point(c2, data, cut, data + cut, dlen - cut, &p) == FALCON_OK, "Fall %zu", v.index);
        CHECK(memcmp(c2, expected, n * sizeof *c2) == 0, "Fall %zu, geteilt", v.index);
    }
    vec_close(&v);

    check_nist_vector("test-vector-sampler-falcon512.txt", &FALCON_512);
    check_nist_vector("test-vector-sampler-falcon1024.txt", &FALCON_1024);
    return test_summary("hashing");
}
