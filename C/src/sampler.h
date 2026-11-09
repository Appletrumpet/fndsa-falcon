/*
 * Zufallsquelle und Gauss-verteilte ganze Zahlen.
 *
 * Spec-Referenz: §3.9.3, Alg. 12-15, Tab. 3.1, Tab. 3.2.
 *
 * Stufe 1: wörtliche Portierung, noch nicht konstante Laufzeit (siehe Dokumentation 8.1.7).
 */
#ifndef FALCON_SAMPLER_H
#define FALCON_SAMPLER_H

#include "params.h"
#include "sampler_table.h"

/* Zufallsquelle: Python-Objekt mit random_bytes(k). */
typedef struct {
    void (*random_bytes)(void *ctx, uint8_t *out, size_t k);
    void *ctx;
} falcon_rng;

/* Systemzufall aus /dev/urandom; bricht das Programm ab, wenn keiner verfügbar ist. */
extern const falcon_rng FALCON_SYSTEM_RNG;

void falcon_random_bytes(const falcon_rng *rng, uint8_t *out, size_t k);

/* k Zufallsbits (Vielfaches von 8, höchstens 72) big-endian. Gl. 3.32, Tab. 3.2. */
int falcon_uniform_bits(falcon_u72 *out, int k, const falcon_rng *rng);

/* Halb-Gauss über die Tabelle RCDT; Werte 0 bis 18. Alg. 12. */
int falcon_base_sampler(const falcon_rng *rng);

/* Ganzzahlige Näherung von 2^63 * ccs * exp(-x); Annahme 0 <= x <= ln 2 (bis auf Rundung). Alg. 13. */
uint64_t falcon_approx_exp(double x, double ccs);

/* Vergleichswert z aus Alg. 14, Z. 1-4; eigene Funktion, damit Tests ihn bitgenau prüfen können. */
uint64_t falcon_ber_exp_z(double x, double ccs);

/* x aus Alg. 15, Z. 7; eigene Funktion aus demselben Grund. */
double falcon_samplerz_x(int z, int z0, double r, double sigma_p, const falcon_params *p);

/* 1 mit Wahrscheinlichkeit ccs * exp(-x). Alg. 14. */
int falcon_ber_exp(double x, double ccs, const falcon_rng *rng);

/* Gauss-verteilte ganze Zahl um mu (SamplerZ). FALCON_ERR_VALUE, wenn sigma_p ausserhalb
 * [sigma_min, sigma_max] liegt. Alg. 15. */
int falcon_sample_integer_gaussian(int32_t *out, double mu, double sigma_p, const falcon_params *p,
                                   const falcon_rng *rng);

#endif
