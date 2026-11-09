/*
 * Top-Level-Funktionen und interne Bausteine von Falcon.
 *
 * Spec-Referenz: §3.8 bis §3.10. Im Schnitt Verify: verify, compute_s1, is_short.
 */
#ifndef FALCON_FALCON_H
#define FALCON_FALCON_H

#include "datatypes.h"

/* 1, wenn die Signatur gültig ist, sonst 0. Jeder Fehlerpfad gilt als Ablehnung. Alg. 16. */
int falcon_verify(const falcon_public_key *pk, const uint8_t *message, size_t message_len,
                  const falcon_signature *sig, const falcon_params *p);

/* s1 = c - s2*h mod q, zentriert. Alg. 16, Z. 5. */
int falcon_compute_s1(int32_t *s1, const int32_t *c, const int32_t *s2, const int32_t *h,
                      const falcon_params *p);

/* norm_sq(s1) + norm_sq(s2) <= sig_bound. Alg. 16, Z. 6. */
int falcon_is_short(const int32_t *s1, const int32_t *s2, const falcon_params *p);

#endif
