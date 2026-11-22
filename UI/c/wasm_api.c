/*
 * Hülle der C-Implementierung für die Web-Oberfläche (UI/README.md).
 *
 * Gleiche Schnittstelle wie die Rust-Hülle (Rust/wasm): Keygen aus einem
 * Seed, Sign mit Zufall aus dem Aufrufer, Verify mit Prüfbericht. Zufall
 * kommt als SHAKE-256-Strom über dem übergebenen Seed, wie `ShakeRNG` in
 * Python/tests/support.py; gleicher Seed ergibt deshalb in C und Python
 * denselben Schlüssel.
 *
 * Verify rechnet dieselben Schritte wie falcon_verify, meldet aber, an
 * welchem Schritt es scheitert, und die Norm (wie VerifyingKey::verify_report
 * in Rust). Alles hier ist öffentlich bis auf den Schlüssel in fw_key.
 */
#include <emscripten/emscripten.h>
#include <stdlib.h>
#include <string.h>

#include "encoding.h"
#include "falcon.h"
#include "hashing.h"
#include "shake256.h"

typedef struct {
    falcon_secret_key sk;
    const falcon_params *p;
} fw_key;

static void shake_random_bytes(void *ctx, uint8_t *out, size_t k)
{
    falcon_shake256_extract((falcon_shake256_ctx *)ctx, out, k);
}

static falcon_rng shake_rng(falcon_shake256_ctx *ctx, const uint8_t *seed, size_t len)
{
    falcon_shake256_init(ctx);
    falcon_shake256_inject(ctx, seed, len);
    falcon_shake256_flip(ctx);
    falcon_rng rng = {shake_random_bytes, ctx};
    return rng;
}

static const falcon_params *params_for_logn(int logn)
{
    if (logn == 9) {
        return &FALCON_512;
    }
    if (logn == 10) {
        return &FALCON_1024;
    }
    return NULL;
}

/* Schlüsselpaar aus `seed`; schreibt den Public Key nach pk_out (Platz für
 * FALCON_MAX_PK_BYTES). NULL bei Fehler. */
EMSCRIPTEN_KEEPALIVE
fw_key *fw_keygen(int logn, const uint8_t *seed, size_t seed_len, uint8_t *pk_out,
                  size_t *pk_len)
{
    const falcon_params *p = params_for_logn(logn);
    if (p == NULL) {
        return NULL;
    }
    fw_key *k = malloc(sizeof *k);
    if (k == NULL) {
        return NULL;
    }
    falcon_public_key pk;
    falcon_shake256_ctx ctx;
    falcon_rng rng = shake_rng(&ctx, seed, seed_len);
    int rc = falcon_keygen(&k->sk, &pk, p, &rng);
    if (rc == FALCON_OK) {
        rc = falcon_encode_pk(pk_out, pk_len, pk.h, pk.n);
    }
    memset(&ctx, 0, sizeof ctx);
    if (rc != FALCON_OK) {
        falcon_secret_key_clear(&k->sk);
        free(k);
        return NULL;
    }
    k->p = p;
    return k;
}

/* Länge des Secret Keys im Byteformat (§3.11.5). */
EMSCRIPTEN_KEEPALIVE
int fw_sk_length(const fw_key *k)
{
    uint8_t buf[FALCON_MAX_SK_BYTES];
    size_t len = 0;
    if (falcon_encode_sk(buf, &len, k->sk.f, k->sk.g, k->sk.F, k->sk.n) != FALCON_OK) {
        len = 0;
    }
    memset(buf, 0, sizeof buf);
    return (int)len;
}

/* Signiert `msg`; Zufall ist der SHAKE-Strom über `rnd`. Schreibt die
 * Signatur nach sig_out (Platz für FALCON_MAX_SIG_BYTES). */
EMSCRIPTEN_KEEPALIVE
int fw_sign(const fw_key *k, const uint8_t *msg, size_t msg_len, const uint8_t *rnd,
            size_t rnd_len, uint8_t *sig_out, size_t *sig_len)
{
    falcon_signature sig;
    falcon_shake256_ctx ctx;
    falcon_rng rng = shake_rng(&ctx, rnd, rnd_len);
    int rc = falcon_sign(&sig, &k->sk, msg, msg_len, k->p, &rng);
    memset(&ctx, 0, sizeof ctx);
    if (rc == FALCON_OK) {
        rc = falcon_encode_sig(sig_out, sig_len, &sig, k->p);
    }
    return rc;
}

EMSCRIPTEN_KEEPALIVE
void fw_free(fw_key *k)
{
    if (k != NULL) {
        falcon_secret_key_clear(&k->sk);
        free(k);
    }
}

/* Verify mit Prüfbericht. Rückgabe 0 und out = {angenommen, Schritt des
 * Fehlers (−1 = keiner), Norm (−1 = nicht berechnet), Schranke}. Die
 * Schritte zählen wie in Rust: 0 Dekodieren, 1 HashToPoint, 2 s₂ entpacken,
 * 3 s₁, 4 Norm. Rückgabe −1: Public Key ungültig, −2: Signatur ungültig
 * (zu kurz, falscher Header); Rust wirft in diesen Fällen einen Fehler. */
EMSCRIPTEN_KEEPALIVE
int fw_verify(const uint8_t *pkb, size_t pk_len, const uint8_t *sigb, size_t sig_len,
              const uint8_t *msg, size_t msg_len, double *out)
{
    static int32_t h[FALCON_MAX_N], c[FALCON_MAX_N], s1[FALCON_MAX_N], s2[FALCON_MAX_N];
    size_t n = 0;

    if (falcon_decode_pk(h, &n, pkb, pk_len) != FALCON_OK) {
        return -1;
    }
    const falcon_params *p = params_for_logn(falcon_logn(n));
    if (p == NULL) {
        return -1;
    }
    int sig_logn = sig_len > 0 ? (sigb[0] & 0x0F) : 0;
    if (sig_len < 42 || (sigb[0] >> 4) != 3 || sig_logn < 1 || sig_logn > 10) {
        return -2;
    }
    out[0] = 0;
    out[2] = -1;
    out[3] = (double)p->sig_bound;
    if (sig_logn != falcon_logn(n)) {
        out[1] = 0;
        return 0;
    }
    falcon_signature sig;
    if (falcon_decode_sig(&sig, sigb, sig_len, p) != FALCON_OK) {
        out[1] = 2; /* s2 länger als jede gültige Kodierung */
        return 0;
    }
    if (falcon_hash_to_point(c, sig.salt, FALCON_SALT_BYTES, msg, msg_len, p) != FALCON_OK) {
        out[1] = 1;
        return 0;
    }
    if (falcon_decompress(s2, sig.s2_encoded, sig.s2_len, p) != FALCON_OK) {
        out[1] = 2;
        return 0;
    }
    if (falcon_compute_s1(s1, c, s2, h, p) != FALCON_OK) {
        out[1] = 3;
        return 0;
    }
    int64_t norm = 0;
    for (size_t i = 0; i < n; i++) {
        norm += (int64_t)s1[i] * s1[i] + (int64_t)s2[i] * s2[i];
    }
    int ok = (uint64_t)norm <= p->sig_bound;
    out[0] = ok;
    out[1] = ok ? -1 : 4;
    out[2] = (double)norm;
    return 0;
}
