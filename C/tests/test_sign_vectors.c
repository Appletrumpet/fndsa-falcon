/*
 * Unveränderliche Testschicht: die Sampler-Testvektoren aus dem NIST-Paket, ohne Python.
 * Jeder SamplerZ-Aufruf einzeln (die ersten 16 der 512-Datei sind Tab. 3.2) und die ganze Signatur.
 */
#include <stdlib.h>

#include "encoding.h"
#include "falcon.h"
#include "ntrugen.h"
#include "tree.h"
#include "vectors.h"

#define MAX_RANDOM (1 << 20)

static uint8_t all_random[MAX_RANDOM];
static falcon_secret_key sk;
static falcon_signature sig;
static int32_t G_file[FALCON_MAX_N], sig_vector[FALCON_MAX_N], s2[FALCON_MAX_N], Grec[FALCON_MAX_N];

static int starts_with(const char *line, const char *prefix)
{
    return strncmp(line, prefix, strlen(prefix)) == 0;
}

static size_t parse_int_list(const char *p, int32_t *dst, size_t cap)
{
    size_t count = 0;
    for (;;) {
        char *end;
        long v = strtol(p, &end, 10);
        if (end == p || count >= cap) {
            return count;
        }
        dst[count++] = (int32_t)v;
        p = end;
    }
}

static size_t parse_hex_bytes(const char *p, uint8_t *dst)
{
    size_t count = 0;
    unsigned value;
    while (sscanf(p, "%2x", &value) == 1) {
        dst[count++] = (uint8_t)value;
        p += 2;
    }
    return count;
}

static void run(const char *name, const falcon_params *p)
{
    char path[512];
    size_t len;
    uint8_t nonce[64], data[64];
    size_t nonce_len = 0, data_len = 0;
    size_t total = 0;       /* alle Sampler-Bytes */
    size_t call_start = 0;  /* Beginn des aktuellen SamplerZ-Aufrufs */
    double mu = 0.0, inv_sigma = 1.0;
    size_t calls = 0;

    snprintf(path, sizeof path, "%s/sampler/%s", FALCON_DATA_DIR, name);
    char *text = read_file(path, &len);

    for (char *line = text; line != NULL && *line != '\0';) {
        char *end = strchr(line, '\n');
        if (end != NULL) {
            *end = '\0';
        }
        const char *hit;
        const char *t = line;
        while (*t == ' ') {
            t++;
        }

        if (starts_with(t, "nonce = ")) {
            nonce_len = parse_hex_bytes(t + 8, nonce);
        } else if (starts_with(t, "data = ")) {
            data_len = parse_hex_bytes(t + 7, data);
        } else if (starts_with(t, "f = ")) {
            parse_int_list(t + 4, sk.f, FALCON_MAX_N);
        } else if (starts_with(t, "g = ")) {
            parse_int_list(t + 4, sk.g, FALCON_MAX_N);
        } else if (starts_with(t, "F = ")) {
            parse_int_list(t + 4, sk.F, FALCON_MAX_N);
        } else if (starts_with(t, "G = ")) {
            parse_int_list(t + 4, G_file, FALCON_MAX_N);
        } else if (starts_with(t, "signature vector = ")) {
            parse_int_list(t + 19, sig_vector, FALCON_MAX_N);
        } else if (starts_with(t, "mu ")) {
            mu = strtod(strchr(t, '=') + 1, NULL);
        } else if (starts_with(t, "1/sigma ")) {
            inv_sigma = strtod(strchr(t, '=') + 1, NULL);
        } else if ((hit = strstr(t, "BaseSampler: u = 0x")) != NULL) {
            total += parse_hex_bytes(hit + 19, all_random + total);
        } else if ((hit = strstr(t, "from random byte: 0x")) != NULL) {
            total += parse_hex_bytes(hit + 20, all_random + total);
        } else if (starts_with(t, "Accepted, ret = ")) {
            fixed_rng_state st;
            falcon_rng rng = fixed_rng(&st, all_random + call_start, total - call_start);
            int32_t z = 0;
            int rc = falcon_sample_integer_gaussian(&z, mu, 1.0 / inv_sigma, p, &rng);
            CHECK(rc == FALCON_OK && z == atoi(t + 16), "%s: SamplerZ %zu", name, calls);
            CHECK(st.pos == st.len, "%s: SamplerZ %zu, Verbrauch", name, calls);
            call_start = total;
            calls++;
        }
        line = (end != NULL) ? end + 1 : NULL;
    }
    CHECK(calls == 2 * p->n, "%s: %zu SamplerZ-Aufrufe", name, calls);
    CHECK(nonce_len == 40 && data_len == 5, "%s: Kopfdaten", name);

    /* Ganze Signatur: Zufall = Nonce, dann alle Sampler-Bytes. */
    static uint8_t stream[MAX_RANDOM];
    memcpy(stream, nonce, nonce_len);
    memcpy(stream + nonce_len, all_random, total);

    sk.n = p->n;
    CHECK(falcon_recompute_G(Grec, sk.f, sk.g, sk.F, p->n) == FALCON_OK, "%s: G", name);
    CHECK(SAME_BITS(Grec, G_file, p->n), "%s: G wie in der Datei", name);
    memcpy(sk.G, G_file, p->n * sizeof *sk.G);
    falcon_build_basis_fft(sk.b00, sk.b01, sk.b10, sk.b11, sk.f, sk.g, sk.F, sk.G, p->n);
    falcon_mat22 basis = {sk.b00, sk.b01, sk.b10, sk.b11};
    CHECK(falcon_build_falcon_tree(&sk.tree, &basis, p->n, p) == FALCON_OK, "%s: Baum", name);

    fixed_rng_state st;
    falcon_rng rng = fixed_rng(&st, stream, nonce_len + total);
    CHECK(falcon_sign(&sig, &sk, data, data_len, p, &rng) == FALCON_OK, "%s: sign", name);
    CHECK(st.pos == st.len, "%s: sign, Verbrauch %zu von %zu", name, st.pos, st.len);
    CHECK(memcmp(sig.salt, nonce, 40) == 0, "%s: Salt", name);
    CHECK(falcon_decompress(s2, sig.s2_encoded, sig.s2_len, p) == FALCON_OK, "%s: decompress", name);
    CHECK(SAME_BITS(s2, sig_vector, p->n), "%s: s2 = signature vector", name);
    free(text);
}

int main(void)
{
    run("test-vector-sampler-falcon512.txt", &FALCON_512);
    run("test-vector-sampler-falcon1024.txt", &FALCON_1024);
    return test_summary("sign_vectors");
}
