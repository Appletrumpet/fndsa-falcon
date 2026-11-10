/*
 * Polynome in Koeffizientenform über Z, in Z[x]/(x^n + 1).
 *
 * Spec-Referenz: §3.1, §3.3. Exakte ganze Zahlen beliebiger Grösse; nur der Schnitt KeyGen
 * braucht die grossen Zahlen, sonst genügen int32_t (norm_sq).
 *
 * Bei poly_mul, split und lift dürfen sich Ein- und Ausgabe nicht überlappen.
 */
#ifndef FALCON_POLY_H
#define FALCON_POLY_H

#include <stddef.h>
#include <stdint.h>

#include "bigint.h"

/* Summe der quadrierten Koeffizienten. Gl. 3.10.
 * Annahme: |a[i]| < 2^26; so bleibt die Summe für n <= 2048 unter 2^64. */
uint64_t falcon_norm_sq(const int32_t *a, size_t n);

/* n initialisierte grosse Zahlen (Wert 0). */
falcon_big *falcon_poly_new(size_t n);
void falcon_poly_free(falcon_big *a, size_t n);
void falcon_poly_from_ints(falcon_big *out, const int32_t *a, size_t n);

/* Koeffizientenweise. §3.1, Alg. 4 Z. 2. */
void falcon_poly_add(falcon_big *out, const falcon_big *a, const falcon_big *b, size_t n);
void falcon_poly_sub(falcon_big *out, const falcon_big *a, const falcon_big *b, size_t n);
void falcon_poly_neg(falcon_big *out, const falcon_big *a, size_t n);

/* Multiplizieren mit x^n = -1. §3.1. */
void falcon_poly_mul(falcon_big *out, const falcon_big *a, const falcon_big *b, size_t n);

/* Gerade und ungerade Koeffizienten trennen; FALCON_ERR_VALUE bei ungerader Länge oder n < 2. Gl. 3.20. */
int falcon_poly_split(falcon_big *a0, falcon_big *a1, const falcon_big *a, size_t n);

/* a(x) zu a(x^2): m Koeffizienten zu 2m. Alg. 6, Z. 11-12. */
void falcon_poly_lift(falcon_big *out, const falcon_big *a, size_t m);

/* a(x) zu a(-x). Alg. 6, Z. 11-12. */
void falcon_poly_galois_conjugate(falcon_big *out, const falcon_big *a, size_t n);

#endif
