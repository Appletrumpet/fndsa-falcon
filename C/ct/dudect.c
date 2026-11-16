/*
 * Zeitmessung nach dem Prinzip von dudect (Ebene 5, Z2; §8.1.6).
 *
 * Zwei Klassen von Eingaben: Klasse 0 fest, Klasse 1 zufällig, in zufälliger Reihenfolge gemischt.
 * Welch-t-Test über die Laufzeiten, zusätzlich nach Abschneiden langer Ausreisser bei mehreren
 * Perzentilen; gemeldet wird das grösste |t|. Konvention von dudect: |t| > 4.5 gilt als Hinweis auf
 * ein Leck, |t| > 10 als sicher.
 *
 * Valgrind (ct/ctgrind.sh) sieht nur Verzweigungen und Adressen; hier geht es um die Laufzeit
 * einzelner Instruktionen (Gleitkomma-Division und -Wurzel) und ganzer Abläufe.
 *
 *   make dudect          alle Messungen
 *   make dudect DIT=1    mit gesetztem DIT-Flag (aarch64, ARMv8.4)
 *
 * Uhr: macOS CLOCK_UPTIME_RAW (24 MHz auf Apple M3). Kurze Operationen werden deshalb in Blöcken
 * gemessen, damit eine Messung viele Takte der Uhr umfasst.
 */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__APPLE__)
#include <pthread.h>
#endif

#include "encoding.h"
#include "falcon.h"
#include "params.h"
#include "sampler.h"
#include "vectors.h"

#define BLOCK 512

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

/* xorshift für Klassen und Eingaben; nicht kryptographisch, nur für die Messung. */
static uint64_t prng_state = 0x243F6A8885A308D3u;
static uint64_t prng(void)
{
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 7;
    prng_state ^= prng_state << 17;
    return prng_state;
}

/* Gleichverteilt in [lo, hi). */
static double uniform(double lo, double hi)
{
    return lo + (hi - lo) * (double)(prng() >> 11) * 0x1p-53;
}

/* Vorbereitung für beide Klassen mit genau derselben Arbeit: Zufallswerte werden immer erzeugt
 * und dann über eine Maske durch den festen Wert ersetzt. Sonst misst man den Zustand, den die
 * Vorbereitung hinterlässt (Cache, Sprungvorhersage), statt der Operation. */
static uint64_t pick_u64(int cls, uint64_t random, uint64_t fixed)
{
    uint64_t m = (uint64_t)0 - (uint64_t)cls;
    __asm__("" : "+r"(m));
    return fixed ^ (m & (random ^ fixed));
}

static double pick_double(int cls, double random, double fixed)
{
    uint64_t r, f;
    memcpy(&r, &random, sizeof r);
    memcpy(&f, &fixed, sizeof f);
    uint64_t v = pick_u64(cls, r, f);
    double d;
    memcpy(&d, &v, sizeof d);
    return d;
}

/* Mantisse von x mit Exponent 0, also in [1, 2); nur Bitoperationen. */
static double to_unit(double x)
{
    uint64_t u;
    memcpy(&u, &x, sizeof u);
    u = (u & 0x000FFFFFFFFFFFFFu) | 0x3FF0000000000000u;
    memcpy(&x, &u, sizeof x);
    return x;
}

static volatile double sink_d;
static volatile uint64_t sink_u;

/* ------------------------------------------------------------------------- */
/* Welch-t-Test mit Abschneiden                                               */
/* ------------------------------------------------------------------------- */

#define CROPS 6
static const double CROP_P[CROPS] = {1.0, 0.99, 0.95, 0.9, 0.75, 0.5};

typedef struct {
    double n[2], mean[2], m2[2];
} welch;

static void welch_add(welch *w, int cls, double x)
{
    w->n[cls] += 1;
    double d = x - w->mean[cls];
    w->mean[cls] += d / w->n[cls];
    w->m2[cls] += d * (x - w->mean[cls]);
}

static double welch_t(const welch *w)
{
    if (w->n[0] < 2 || w->n[1] < 2) {
        return 0;
    }
    double v0 = w->m2[0] / (w->n[0] - 1), v1 = w->m2[1] / (w->n[1] - 1);
    return (w->mean[0] - w->mean[1]) / sqrt(v0 / w->n[0] + v1 / w->n[1]);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Eine Messung: prepare legt die Eingaben für die Klasse fest (nicht gemessen), run misst. */
typedef struct {
    const char *name;
    size_t count;
    void (*prepare)(int cls);
    void (*run)(void);
} test_case;

static void run_test(const test_case *t)
{
    uint64_t *times = malloc(t->count * sizeof *times);
    uint8_t *cls = malloc(t->count);
    if (times == NULL || cls == NULL) {
        abort();
    }
    for (size_t i = 0; i < t->count; i++) {
        cls[i] = (uint8_t)(prng() & 1);
        t->prepare(cls[i]);
        uint64_t t0 = now_ns();
        t->run();
        times[i] = now_ns() - t0;
    }
    /* Schwellen aus allen Messungen; die ersten 1 % gelten als Aufwärmen. */
    size_t skip = t->count / 100;
    uint64_t *sorted = malloc((t->count - skip) * sizeof *sorted);
    if (sorted == NULL) {
        abort();
    }
    memcpy(sorted, times + skip, (t->count - skip) * sizeof *sorted);
    qsort(sorted, t->count - skip, sizeof *sorted, cmp_u64);
    welch w[CROPS];
    memset(w, 0, sizeof w);
    for (int c = 0; c < CROPS; c++) {
        size_t idx = (size_t)((double)(t->count - skip - 1) * CROP_P[c]);
        uint64_t limit = sorted[idx];
        for (size_t i = skip; i < t->count; i++) {
            if (times[i] <= limit) {
                welch_add(&w[c], cls[i], (double)times[i]);
            }
        }
    }
    double tmax = 0;
    int cmax = 0;
    for (int c = 0; c < CROPS; c++) {
        double tv = fabs(welch_t(&w[c]));
        if (tv > tmax) {
            tmax = tv;
            cmax = c;
        }
    }
    printf("%-26s %9zu  Mittel %10.1f / %10.1f ns   max |t| = %7.2f (bis %3.0f %%)  %s\n", t->name,
           t->count - skip, w[0].mean[0], w[0].mean[1], tmax, CROP_P[cmax] * 100,
           tmax > 10 ? "LECK" : tmax > 4.5 ? "Verdacht" : "ok");
    fflush(stdout);
    free(sorted);
    free(times);
    free(cls);
}

/* ------------------------------------------------------------------------- */
/* Kontrollen: ein absichtliches Leck muss auffallen, XOR darf nicht           */
/* ------------------------------------------------------------------------- */

static uint8_t cmp_a[BLOCK], cmp_b[BLOCK];

static void prep_leak(int cls)
{
    memset(cmp_a, 0x55, sizeof cmp_a);
    memset(cmp_b, 0x55, sizeof cmp_b);
    cmp_b[0] ^= (uint8_t)cls; /* Klasse 1: Unterschied gleich am Anfang, früher Abbruch */
}

static void run_leak(void)
{
    size_t i = 0;
    while (i < BLOCK && cmp_a[i] == *(volatile uint8_t *)&cmp_b[i]) {
        i++;
    }
    sink_u = i;
}

static uint64_t xor_in[BLOCK];

static void prep_xor(int cls)
{
    for (int i = 0; i < BLOCK; i++) {
        xor_in[i] = pick_u64(cls, prng(), 0x0123456789ABCDEFu);
    }
}

static void run_xor(void)
{
    uint64_t acc = 0;
    for (int i = 0; i < BLOCK; i++) {
        acc = (acc ^ xor_in[i]) * 0x9E3779B97F4A7C15u;
    }
    sink_u = acc;
}

/* ------------------------------------------------------------------------- */
/* Gleitkomma: abhängige Ketten, damit die Latenz jeder Instruktion zählt      */
/* ------------------------------------------------------------------------- */

static double fp_in[BLOCK];

/* Klasse 0: ein fester Wert mit voller Mantisse; Klasse 1: zufällige Mantisse und Exponent im
 * Bereich, den Falcon auf geheimen Werten erreicht. */
static void prep_fp(int cls)
{
    for (int i = 0; i < BLOCK; i++) {
        double r = ldexp(uniform(1.0, 2.0), (int)(prng() % 41) - 20);
        fp_in[i] = pick_double(cls, r, 1.4142135623730951);
    }
}

/* Wie prep_fp, aber der feste Wert ist „einfach“ (Mantisse 0): fängt Abkürzungen der Hardware für
 * solche Operanden. */
static void prep_fp_simple(int cls)
{
    for (int i = 0; i < BLOCK; i++) {
        double r = ldexp(uniform(1.0, 2.0), (int)(prng() % 41) - 20);
        fp_in[i] = pick_double(cls, r, 4.0);
    }
}

static void run_fdiv(void)
{
    double x = 1.25;
    for (int i = 0; i < BLOCK; i++) {
        /* x bleibt in [1, 2): Division durch die Eingabe, dann Mantisse zurück in den Bereich. */
        x = to_unit(x / fp_in[i]);
    }
    sink_d = x;
}

static void run_fsqrt(void)
{
    double x = 1.25;
    for (int i = 0; i < BLOCK; i++) {
        x = to_unit(__builtin_sqrt(fp_in[i] * x));
    }
    sink_d = x;
}

static void run_fmul(void)
{
    double x = 1.25;
    for (int i = 0; i < BLOCK; i++) {
        x = to_unit(x * fp_in[i]);
    }
    sink_d = x;
}

/* Gleiche Kette ohne die geprüfte Instruktion: zeigt, ob frexp/ldexp selbst schwanken. */
static void run_frame(void)
{
    double x = 1.25;
    for (int i = 0; i < BLOCK; i++) {
        x = to_unit(x + fp_in[i] * 0.0);
    }
    sink_d = x;
}

/* ------------------------------------------------------------------------- */
/* SamplerZ und sign                                                          */
/* ------------------------------------------------------------------------- */

#define SAMPLES 32
static double sz_mu[SAMPLES], sz_sigma[SAMPLES];
static falcon_shake256_ctx sz_ctx;
static falcon_rng sz_rng;

static void prep_samplerz(int cls)
{
    const falcon_params *p = &FALCON_512;
    for (int i = 0; i < SAMPLES; i++) {
        sz_mu[i] = pick_double(cls, uniform(-200.0, 200.0), 7.25);
        sz_sigma[i] = pick_double(cls, uniform(p->sigma_min, p->sigma_max), 0.5 * (p->sigma_min + p->sigma_max));
    }
}

static void run_samplerz(void)
{
    int32_t z;
    uint64_t acc = 0;
    for (int i = 0; i < SAMPLES; i++) {
        if (falcon_sample_integer_gaussian(&z, sz_mu[i], sz_sigma[i], &FALCON_512, &sz_rng) != FALCON_OK) {
            abort();
        }
        acc += (uint64_t)(uint32_t)z;
    }
    sink_u = acc;
}

static falcon_secret_key sk;
static falcon_public_key pk;
static falcon_signature sig;
static uint8_t msg[32];
static falcon_shake256_ctx sign_ctx;
static falcon_rng sign_rng;

/* Klasse 0: feste Nachricht, also festes Ziel t; Klasse 1: zufällige Nachricht. */
static void prep_sign(int cls)
{
    for (size_t i = 0; i < sizeof msg; i++) {
        msg[i] = (uint8_t)pick_u64(cls, prng(), 0x5A);
    }
}

static void run_sign(void)
{
    if (falcon_sign(&sig, &sk, msg, sizeof msg, &FALCON_512, &sign_rng) != FALCON_OK) {
        abort();
    }
}

int main(int argc, char **argv)
{
    double scale = argc > 1 ? atof(argv[1]) : 1.0;
#if defined(__APPLE__)
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
#if defined(FALCON_DIT) && defined(__aarch64__)
    __asm__ volatile("msr dit, #1");
    printf("DIT gesetzt\n");
#else
    printf("DIT nicht gesetzt\n");
#endif

    uint8_t seed[48];
    memset(seed, 0xAB, sizeof seed);
    falcon_shake256_ctx kctx;
    falcon_rng krng = shake_rng(&kctx, seed, sizeof seed);
    if (falcon_keygen(&sk, &pk, &FALCON_512, &krng) != FALCON_OK) {
        return 1;
    }
    sz_rng = shake_rng(&sz_ctx, (const uint8_t *)"dudect-sz", 9);
    sign_rng = shake_rng(&sign_ctx, (const uint8_t *)"dudect-sign", 11);

    const test_case tests[] = {
        {"Kontrolle: Leck", 200000, prep_leak, run_leak},
        {"Kontrolle: XOR", 200000, prep_xor, run_xor},
        {"Gleitkomma: Rahmen", 200000, prep_fp, run_frame},
        {"Gleitkomma: Multiplikation", 200000, prep_fp, run_fmul},
        {"Gleitkomma: Division", 200000, prep_fp, run_fdiv},
        {"Gleitkomma: Wurzel", 200000, prep_fp, run_fsqrt},
        {"Division, fest = 4.0", 200000, prep_fp_simple, run_fdiv},
        {"Wurzel, fest = 4.0", 200000, prep_fp_simple, run_fsqrt},
        {"Multiplikation, fest = 4.0", 200000, prep_fp_simple, run_fmul},
        {"SamplerZ (32 Aufrufe)", 200000, prep_samplerz, run_samplerz},
        {"sign (Falcon-512)", 20000, prep_sign, run_sign},
    };
    printf("%-26s %9s  %-30s  %s\n", "Test", "Messungen", "Mittel Klasse 0 / 1", "Ergebnis");
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        test_case t = tests[i];
        t.count = (size_t)((double)t.count * scale);
        run_test(&t);
    }
    return 0;
}
