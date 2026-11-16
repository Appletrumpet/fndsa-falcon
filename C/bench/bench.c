/*
 * Laufzeitmessung nach dem gemeinsamen Messprotokoll (Rust/PLAN.md 5.2, Ziel Z6).
 *
 * Dieselben Operationen, Eingaben und Laufzahlen wie Rust/examples/bench.rs:
 * Keygen aus einem Seed (48 gleiche Bytes, ShakeRNG wie in Python), Secret Key laden,
 * Sign, Verify, je für Falcon-512 und Falcon-1024; Nachricht 32 Bytes 0x5A; ein Thread.
 * Gemeldet werden Median sowie 10- und 90-%-Perzentil in Mikrosekunden.
 *
 * Uhr: macOS CLOCK_UPTIME_RAW (24 MHz auf Apple M3, also rund 42 ns Auflösung), sonst
 * CLOCK_MONOTONIC. Zyklen werden nicht gemeldet: Unter macOS gibt es keinen Zyklenzähler
 * für normale Programme.
 */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>

#if defined(__APPLE__)
#include <pthread.h>
#include <sys/sysctl.h>
#endif

#include "encoding.h"
#include "falcon.h"
#include "params.h"
#include "vectors.h"

#define MAX_RUNS 2000

static falcon_secret_key sk, sk_tmp, sk_loaded;
static falcon_public_key pk, pk_tmp;
static falcon_signature sig, sig_tmp;
static uint8_t sk_bytes[FALCON_MAX_SK_BYTES];
static size_t sk_len;
static uint64_t times[MAX_RUNS];
static const uint8_t msg[32] = {
    0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
    0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
};
static const falcon_params *params;
static falcon_shake256_ctx sign_ctx;
static falcon_rng sign_rng;

static uint64_t now_ns(void)
{
#if defined(__APPLE__)
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
#endif
}

static void must(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "Fehler: %s\n", what);
        exit(1);
    }
}

static void run_keygen(size_t i)
{
    uint8_t seed[48];
    falcon_shake256_ctx ctx;
    memset(seed, (int)(i & 0xFF), sizeof seed);
    falcon_rng rng = shake_rng(&ctx, seed, sizeof seed);
    must(falcon_keygen(&sk_tmp, &pk_tmp, params, &rng) == FALCON_OK, "keygen");
}

static void run_load(size_t i)
{
    (void)i;
    must(falcon_load_secret_key(&sk_loaded, sk_bytes, sk_len, params) == FALCON_OK, "sk laden");
}

static void run_sign(size_t i)
{
    (void)i;
    must(falcon_sign(&sig_tmp, &sk, msg, sizeof msg, params, &sign_rng) == FALCON_OK, "sign");
}

static void run_verify(size_t i)
{
    (void)i;
    must(falcon_verify(&pk, msg, sizeof msg, &sig, params) == 1, "verify");
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Wie measure() in bench.rs: warm Aufwärmläufe, dann runs Messungen; run(i) erhält den Index. */
static void measure(const char *op, size_t runs, size_t warm, void (*run)(size_t))
{
    for (size_t i = 0; i < warm; i++) {
        run(i);
    }
    for (size_t i = 0; i < runs; i++) {
        uint64_t t0 = now_ns();
        run(i);
        times[i] = now_ns() - t0;
    }
    qsort(times, runs, sizeof times[0], cmp_u64);
    /* Perzentil wie in bench_python.py: Index round((runs - 1) * p). */
    double m = (double)times[(size_t)((double)(runs - 1) * 0.5 + 0.5)] / 1e3;
    double p10 = (double)times[(size_t)((double)(runs - 1) * 0.1 + 0.5)] / 1e3;
    double p90 = (double)times[(size_t)((double)(runs - 1) * 0.9 + 0.5)] / 1e3;
    printf("%-16s %5zu %6zu %12.1f %12.1f %12.1f\n", op, params->n, runs, m, p10, p90);
    fflush(stdout);
}

static void environment(void)
{
    struct utsname u;
    char cpu[128] = "unbekannt";
#if defined(__APPLE__)
    size_t len = sizeof cpu;
    if (sysctlbyname("machdep.cpu.brand_string", cpu, &len, NULL, 0) != 0) {
        strcpy(cpu, "unbekannt");
    }
    /* Kein Festlegen auf einen Leistungskern möglich; höchste Priorität bevorzugt sie. */
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
    uname(&u);
    printf("C (%s), %s, %s %s %s\n", __VERSION__, cpu, u.sysname, u.release, u.machine);
    printf("%-16s %5s %6s %12s %12s %12s\n", "Operation", "n", "Läufe", "µs Median", "10 %", "90 %");
}

int main(void)
{
    environment();
    const falcon_params *sets[2] = {&FALCON_512, &FALCON_1024};
    const size_t keygen_runs[2] = {50, 30};

    for (int s = 0; s < 2; s++) {
        params = sets[s];
        measure("Keygen", keygen_runs[s], 3, run_keygen);

        uint8_t seed[48];
        falcon_shake256_ctx ctx;
        memset(seed, 0xAB, sizeof seed);
        falcon_rng rng = shake_rng(&ctx, seed, sizeof seed);
        must(falcon_keygen(&sk, &pk, params, &rng) == FALCON_OK, "keygen");
        must(falcon_encode_sk(sk_bytes, &sk_len, sk.f, sk.g, sk.F, params->n) == FALCON_OK, "encode_sk");
        measure("sk laden", 200, 10, run_load);

        sign_rng = shake_rng(&sign_ctx, (const uint8_t *)"bench", 5);
        measure("Sign", 500, 20, run_sign);

        must(falcon_sign(&sig, &sk, msg, sizeof msg, params, &sign_rng) == FALCON_OK, "sign");
        measure("Verify", 2000, 100, run_verify);
    }
    return 0;
}
