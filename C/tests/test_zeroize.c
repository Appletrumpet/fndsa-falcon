/*
 * Löschtest (Ebene 5, Z5): Nach load_secret_key und sign dürfen keine geheimen Zwischenwerte im
 * verlassenen Stackbereich zurückbleiben.
 *
 * Vorgehen: Stack mit einem Muster füllen, die Funktion aufrufen, danach den Bereich unterhalb des
 * aktuellen Rahmens nach bekannten geheimen Werten durchsuchen (8-Byte-Muster von double, die der
 * Test selbst nachrechnet). sign: Ziel t0, t1 (aus c und der geheimen Basis). load_secret_key:
 * Gram-Matrix G der Basis (liegt nur in Zwischenpuffern, nicht im Secret Key).
 *
 * Das Lesen unterhalb des Stackzeigers ist in C nicht definiert und funktioniert nur ohne
 * AddressSanitizer (der verschiebt lokale Felder). Im Debug-Build wird der Test deshalb übersprungen.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encoding.h"
#include "fft.h"
#include "falcon.h"
#include "hashing.h"
#include "params.h"
#include "tree.h"
#include "vectors.h"

#if defined(__SANITIZE_ADDRESS__)
#define FALCON_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FALCON_ASAN 1
#endif
#endif

#define REGION ((size_t)1 << 20)

#ifndef FALCON_ASAN
static uint64_t needles[8 * FALCON_MAX_N];
static size_t nneedles;

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* ±0.0 nicht als Nadel: Gelöschter Speicher besteht aus Nullen (G00 und G11 haben Imaginärteil 0). */
static void add_needle(double x)
{
    uint64_t u;
    memcpy(&u, &x, sizeof u);
    if ((u << 1) != 0) {
        needles[nneedles++] = u;
    }
}

static void add_needles(const falcon_cplx *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        add_needle(v[i].re);
        add_needle(v[i].im);
    }
}

static void finish_needles(void)
{
    qsort(needles, nneedles, sizeof needles[0], cmp_u64);
}

__attribute__((noinline)) static void paint(void)
{
    volatile uint8_t area[REGION];
    for (size_t i = 0; i < REGION; i++) {
        area[i] = 0xA5;
    }
}

/* Treffer im Bereich unterhalb dieses Rahmens; die ersten 4 KiB (eigener Rahmen, qsort/bsearch)
 * werden übersprungen. */
__attribute__((noinline)) static size_t scan(void)
{
    volatile uint64_t marker = 0;
    uintptr_t top = ((uintptr_t)&marker) & ~(uintptr_t)7;
    size_t hits = 0;
    for (size_t off = 4096; off < REGION; off += 8) {
        uint64_t w = *(const volatile uint64_t *)(top - off);
        if (bsearch(&w, needles, nneedles, sizeof needles[0], cmp_u64) != NULL) {
            hits++;
        }
    }
    return hits;
}

static falcon_signature sig;
static falcon_cplx g00[FALCON_MAX_N], g01[FALCON_MAX_N], g10[FALCON_MAX_N], g11[FALCON_MAX_N];
static falcon_cplx t0[FALCON_MAX_N], t1[FALCON_MAX_N];
static falcon_cplx fh[FALCON_MAX_N];
static double fv[FALCON_MAX_N];
static falcon_secret_key sk3;
static falcon_public_key pk3;
#endif

static falcon_secret_key sk, sk2;
static falcon_public_key pk;
static uint8_t sk_bytes[FALCON_MAX_SK_BYTES];
static size_t sk_len;

int main(void)
{
    const falcon_params *p = &FALCON_512;
    falcon_shake256_ctx kctx;
    falcon_rng krng = shake_rng(&kctx, (const uint8_t *)"zeroize-key", 11);
    CHECK(falcon_keygen(&sk, &pk, p, &krng) == FALCON_OK, "keygen");
    CHECK(falcon_encode_sk(sk_bytes, &sk_len, sk.f, sk.g, sk.F, p->n) == FALCON_OK, "encode_sk");

    /* falcon_secret_key_clear löscht den ganzen Schlüssel. */
    {
        static const falcon_secret_key zero;
        sk2 = sk;
        falcon_secret_key_clear(&sk2);
        CHECK(memcmp(&sk2, &zero, sizeof sk2) == 0, "secret_key_clear");
    }

#ifdef FALCON_ASAN
    printf("zeroize: Stacksuche übersprungen (AddressSanitizer)\n");
#else
    const uint8_t msg[] = "zeroize";
    falcon_shake256_ctx sctx, sctx2;

    /* load_secret_key: Gram-Matrix als Nadeln. */
    {
        falcon_mat22 basis = {sk.b00, sk.b01, sk.b10, sk.b11};
        falcon_mat22 gram = {g00, g01, g10, g11};
        falcon_gram_matrix(&gram, &basis, p->n);
        nneedles = 0;
        add_needles(g00, p->n);
        add_needles(g01, p->n);
        add_needles(g11, p->n);
        finish_needles();
        paint();
        CHECK(falcon_load_secret_key(&sk2, sk_bytes, sk_len, p) == FALCON_OK, "load_secret_key");
        size_t hits = scan();
        CHECK(hits == 0, "load_secret_key: %zu Werte der Gram-Matrix im Stack zurückgeblieben", hits);
    }

    /* sign: Ziel t0, t1 als Nadeln; der Salt sind die ersten 40 Bytes derselben Zufallsquelle. */
    {
        uint8_t salt[FALCON_SALT_BYTES];
        int32_t c[FALCON_MAX_N];
        falcon_rng srng2 = shake_rng(&sctx2, (const uint8_t *)"zeroize-sign", 12);
        falcon_random_bytes(&srng2, salt, sizeof salt);
        CHECK(falcon_hash_to_point(c, salt, sizeof salt, msg, sizeof msg, p) == FALCON_OK, "hash_to_point");
        falcon_compute_target(t0, t1, c, &sk2);
        nneedles = 0;
        add_needles(t0, p->n);
        add_needles(t1, p->n);
        finish_needles();
        falcon_rng srng = shake_rng(&sctx, (const uint8_t *)"zeroize-sign", 12);
        paint();
        CHECK(falcon_sign(&sig, &sk2, msg, sizeof msg, p, &srng) == FALCON_OK, "sign");
        size_t hits = scan();
        CHECK(hits == 0, "sign: %zu Werte des Ziels t im Stack zurückgeblieben", hits);
    }
    /* keygen: FFT von f als Nadeln (gram_schmidt_norm, Basis). Gleicher Seed wie oben, also
     * derselbe Schlüssel; f vorab aus dem ersten Lauf. */
    {
        falcon_shake256_ctx kctx3;
        falcon_rng krng3 = shake_rng(&kctx3, (const uint8_t *)"zeroize-key", 11);
        for (size_t i = 0; i < p->n; i++) {
            fv[i] = (double)sk.f[i];
        }
        (void)falcon_fft(fh, fv, p->n);
        nneedles = 0;
        add_needles(fh, p->n);
        finish_needles();
        paint();
        CHECK(falcon_keygen(&sk3, &pk3, p, &krng3) == FALCON_OK, "keygen 2");
        size_t hits = scan();
        CHECK(memcmp(sk3.f, sk.f, sizeof sk.f) == 0, "keygen 2: gleicher Schlüssel");
        CHECK(hits == 0, "keygen: %zu Werte der FFT von f im Stack zurückgeblieben", hits);
    }
#endif
    return test_summary("zeroize");
}
