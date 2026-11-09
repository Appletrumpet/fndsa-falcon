/*
 * HashToPoint: Nachricht auf Polynom in Z_q[x]/(x^n + 1) abbilden.
 *
 * Spec-Referenz: §3.7, Alg. 3.
 */
#ifndef FALCON_HASHING_H
#define FALCON_HASHING_H

#include "params.h"

/* SHAKE-256 über a || b, je 16 Bit lesen, Werte < k*q annehmen, Koeffizient = Wert mod q.
 * a und b werden fortlaufend eingelesen (Salt, dann Nachricht); für einen einzigen
 * Datenblock ist b_len = 0. FALCON_ERR_VALUE, wenn q zu gross ist. Alg. 3. */
int falcon_hash_to_point(int32_t *c, const uint8_t *a, size_t a_len, const uint8_t *b,
                         size_t b_len, const falcon_params *p);

#endif
