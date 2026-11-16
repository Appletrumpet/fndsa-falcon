/*
 * Prüfung der konstanten Laufzeit mit Valgrind (Ebene 5, Z2; Prinzip ctgrind, §8.1.6).
 *
 * Geheime Daten werden für Memcheck als „nicht initialisiert“ markiert: die Bytes des Secret Key
 * und die Zufallsbytes, die sign nach dem Salt verbraucht (sie bestimmen z). Der Salt (die ersten
 * 40 Bytes) ist Teil der Signatur und bleibt öffentlich. Memcheck meldet dann jede Verzweigung und
 * jede Adressberechnung, die von geheimen Werten abhängt. Instruktionen mit variabler Laufzeit
 * (z. B. Division) sieht Valgrind nicht; dafür ist die Zeitmessung (dudect) da.
 *
 * Läuft nur unter Linux (ct/ctgrind.sh startet einen Container). Geprüft wird load_secret_key
 * und sign; keygen und verify fallen nicht unter Z2.
 */
#include <stdio.h>
#include <string.h>

#include <valgrind/memcheck.h>

#include "encoding.h"
#include "falcon.h"
#include "params.h"
#include "vectors.h"

static falcon_secret_key sk;
static falcon_public_key pk;
static falcon_signature sig;
static uint8_t sk_bytes[FALCON_MAX_SK_BYTES];

typedef struct {
    falcon_rng inner;
    size_t used; /* seit Beginn von sign verbrauchte Bytes */
} secret_rng_state;

static void secret_random_bytes(void *state, uint8_t *out, size_t k)
{
    secret_rng_state *s = state;
    falcon_random_bytes(&s->inner, out, k);
    for (size_t i = 0; i < k; i++, s->used++) {
        if (s->used >= FALCON_SALT_BYTES) {
            VALGRIND_MAKE_MEM_UNDEFINED(&out[i], 1);
        }
    }
}

static int run(const falcon_params *p, const char *seed_text, int signatures)
{
    falcon_shake256_ctx kctx, sctx;
    falcon_rng krng = shake_rng(&kctx, (const uint8_t *)seed_text, strlen(seed_text));
    size_t sk_len = 0;
    static const uint8_t msg[32] = {0x5A};

    /* keygen ist von Z2 ausgenommen und läuft mit öffentlichen Werten. */
    if (falcon_keygen(&sk, &pk, p, &krng) != FALCON_OK
        || falcon_encode_sk(sk_bytes, &sk_len, sk.f, sk.g, sk.F, p->n) != FALCON_OK) {
        return 1;
    }
    memset(&sk, 0, sizeof sk);

    VALGRIND_MAKE_MEM_UNDEFINED(sk_bytes + 1, sk_len - 1); /* Header (logn) ist öffentlich */
    if (falcon_load_secret_key(&sk, sk_bytes, sk_len, p) != FALCON_OK) {
        return 1;
    }
    for (int i = 0; i < signatures; i++) {
        secret_rng_state st = {shake_rng(&sctx, (const uint8_t *)"ctgrind", 7), 0};
        falcon_rng rng = {secret_random_bytes, &st};
        int rc = falcon_sign(&sig, &sk, msg, sizeof msg, p, &rng);
        VALGRIND_MAKE_MEM_DEFINED(&rc, sizeof rc);
        if (rc != FALCON_OK) {
            return 1;
        }
        /* Die Signatur ist öffentlich. */
        VALGRIND_MAKE_MEM_DEFINED(&sig, sizeof sig);
        if (falcon_verify(&pk, msg, sizeof msg, &sig, p) != 1) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    int bad = run(&FALCON_512, "ctgrind-512", 2) | run(&FALCON_1024, "ctgrind-1024", 1);
    printf("ctgrind: %s\n", bad ? "Fehler im Ablauf" : "Ablauf vollständig");
    return bad;
}
