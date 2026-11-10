/*
 * Erzeugung der NTRU-Schlüsselkomponenten f, g, F, G.
 *
 * Spec-Referenz: §3.8.2, §4.4.3, Alg. 5-7, Gl. 3.25, 3.28, 3.29, 3.35.
 *
 * Polynome mit grossen Koeffizienten (solve_ntru, reduce, field_norm) sind Felder von falcon_big.
 */
#ifndef FALCON_NTRUGEN_H
#define FALCON_NTRUGEN_H

#include "bigint.h"
#include "datatypes.h"
#include "sampler.h"

/* f, g, F, G ziehen, prüfen, lösen; bei Misserfolg Neustart. FALCON_ERR_KEYGEN nach 5000 Versuchen. Alg. 5. */
int falcon_generate_ntru_keys(int32_t *f, int32_t *g, int32_t *F, int32_t *G, const falcon_params *p,
                              const falcon_rng *rng);

/* Koeffizienten als Summe von 4096/n Ziehungen aus SamplerZ. Alg. 5, Z. 1-6; Gl. 3.29. */
int falcon_sample_short_poly(int32_t *a, const falcon_params *p, const falcon_rng *rng);

/* gamma nach Gl. 3.28 (nicht quadriert); unendlich, wenn der Nenner 0 ist. */
double falcon_gram_schmidt_norm(const int32_t *f, const int32_t *g, size_t n, const falcon_params *p);

/* fG - gF = q rekursiv lösen. FALCON_ERR_NONE, wenn es keine Lösung gibt oder die Prüfung am Ende
 * fehlschlägt. Alg. 6, §4.4.3. */
int falcon_solve_ntru(falcon_big *F, falcon_big *G, const falcon_big *f, const falcon_big *g,
                      size_t n, const falcon_params *p);

/* a0^2 - x*a1^2, n Koeffizienten zu n/2. FALCON_ERR_VALUE bei ungerader Länge oder n < 2. Gl. 3.25. */
int falcon_field_norm(falcon_big *out, const falcon_big *a, size_t n);

/* (d, u, v) mit u*a - v*b = d = gcd(a, b). Alg. 6, Z. 2. */
void falcon_xgcd(falcon_big *d, falcon_big *u, falcon_big *v, const falcon_big *a, const falcon_big *b);

/* c * 2^(-scale) als double, aus den obersten 53 Bit von c, aufgerundet bei gesetztem nächstem Bit. */
double falcon_scaled_float(const falcon_big *c, size_t scale);

/* round(x * 2^exp) als ganze Zahl; 0 für x = 0 und nicht endliche x. */
void falcon_round_scaled_float(falcon_big *out, double x, int exp);

/* F, G direkt gegen f, g verkleinern (Babai-Reduktion). Wie in Python ohne Obergrenze der
 * Durchläufe: Ist ein Koeffizient von mu exakt 1/2, endet die Schleife nicht. Alg. 7, §4.4.3. */
void falcon_reduce(const falcon_big *f, const falcon_big *g, falcon_big *F, falcon_big *G, size_t n);

/* G aus der NTRU-Gleichung, zentriert. FALCON_ERR_VALUE, wenn f nicht invertierbar ist. Gl. 3.35. */
int falcon_recompute_G(int32_t *G, const int32_t *f, const int32_t *g, const int32_t *F, size_t n);

#endif
