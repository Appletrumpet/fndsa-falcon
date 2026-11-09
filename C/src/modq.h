/*
 * Rechnen mod q über NTT (Number Theoretic Transform).
 *
 * Spec-Referenz: §3.5, §4.2.2.
 *
 * Alle Funktionen arbeiten mit q = 12289 und Graden n = 2^k <= 1024. Eingaben
 * dürfen negativ oder >= q sein und werden reduziert; Ausgaben liegen in
 * 0 .. q-1 (ausser center_mod_q). Reihenfolge der NTT-Werte wie in Python:
 * Index k enthält den Wert an psi_n^(2k+1).
 */
#ifndef FALCON_MODQ_H
#define FALCON_MODQ_H

#include "params.h"

/* x mod q in 0 .. q-1, auch für negative x (Python: x % q). */
int32_t falcon_mod_q(int64_t x);

/* Polynom mod q in Wertedarstellung. §3.5, §4.2.2. */
int falcon_ntt(int32_t *out, const int32_t *a, size_t n);

/* Zurück in Koeffizientenform. §3.5. */
int falcon_intt(int32_t *out, const int32_t *a_hat, size_t n);

/* Multiplizieren mod q über NTT. §4.2.2. */
int falcon_mul_mod_q(int32_t *out, const int32_t *a, const int32_t *b, size_t n);

/* a * b^-1 mod q, punktweise in NTT-Form. FALCON_ERR_VALUE, wenn b nicht invertierbar ist.
 * §3.4.3, §4.2.2. */
int falcon_div_mod_q(int32_t *out, const int32_t *a, const int32_t *b, size_t n);

/* 1, wenn NTT(a) keine Null enthält, sonst 0; FALCON_ERR_VALUE bei ungültigem n. Alg. 5, Z. 7. */
int falcon_is_invertible_mod_q(const int32_t *a, size_t n);

/* Koeffizienten auf -6144 .. 6144 abbilden. Alg. 16, Z. 5. */
void falcon_center_mod_q(int32_t *out, const int32_t *a, size_t n);

#endif
