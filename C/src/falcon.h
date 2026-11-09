/*
 * Top-Level-Funktionen und interne Bausteine von Falcon.
 *
 * Spec-Referenz: §3.8 bis §3.10. Bisher die Schnitte Verify und Sign; keygen folgt.
 */
#ifndef FALCON_FALCON_H
#define FALCON_FALCON_H

#include "datatypes.h"
#include "sampler.h"

/* Secret Key aus Bytes laden: decode_sk, recompute_G, Basis, Baum. Der Baum zeigt in *sk.
 * §3.11.5, Alg. 4, Z. 2-7. */
int falcon_load_secret_key(falcon_secret_key *sk, const uint8_t *b, size_t len,
                           const falcon_params *p);

/* Signaturerzeugung. Zieht zuerst 40 Bytes Salt, danach nur noch Zufall für das Sampling. Alg. 10. */
int falcon_sign(falcon_signature *sig, const falcon_secret_key *sk, const uint8_t *message,
                size_t message_len, const falcon_params *p, const falcon_rng *rng);

/* Wie falcon_sign mit Systemzufall (Python: Standardargument rng=SYSTEM_RNG). */
int falcon_sign_system(falcon_signature *sig, const falcon_secret_key *sk, const uint8_t *message,
                       size_t message_len, const falcon_params *p);

/* (c, 0) in Koordinaten der geheimen Basis. Alg. 10, Z. 3. */
void falcon_compute_target(falcon_cplx *t0, falcon_cplx *t1, const int32_t *c,
                           const falcon_secret_key *sk);

/* (t - z) * basis_fft, bleibt in FFT-Form. Alg. 10, Z. 7. */
void falcon_compute_signature_vector(falcon_cplx *s0, falcon_cplx *s1, const falcon_cplx *t0,
                                     const falcon_cplx *t1, const falcon_cplx *z0,
                                     const falcon_cplx *z1, const falcon_secret_key *sk);

/* fft_norm_sq beider Komponenten <= sig_bound. Alg. 10, Z. 8. */
int falcon_is_short_fft(const falcon_cplx *s0, const falcon_cplx *s1, size_t n,
                        const falcon_params *p);

/* ifft beider Komponenten, auf ganze Zahlen runden (Gleichstand zur geraden Zahl). Alg. 10, Z. 9. */
int falcon_to_coefficients(int32_t *a, int32_t *b, const falcon_cplx *s0, const falcon_cplx *s1,
                           size_t n);

/* 1, wenn die Signatur gültig ist, sonst 0. Jeder Fehlerpfad gilt als Ablehnung. Alg. 16. */
int falcon_verify(const falcon_public_key *pk, const uint8_t *message, size_t message_len,
                  const falcon_signature *sig, const falcon_params *p);

/* s1 = c - s2*h mod q, zentriert. Alg. 16, Z. 5. */
int falcon_compute_s1(int32_t *s1, const int32_t *c, const int32_t *s2, const int32_t *h,
                      const falcon_params *p);

/* norm_sq(s1) + norm_sq(s2) <= sig_bound. Alg. 16, Z. 6. */
int falcon_is_short(const int32_t *s1, const int32_t *s2, const falcon_params *p);

#endif
