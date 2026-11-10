#include "falcon.h"
#include <math.h>
#include <string.h>

#include "cplx.h"
#include "encoding.h"
#include "ffsampling.h"
#include "fft.h"
#include "hashing.h"
#include "modq.h"
#include "ntrugen.h"
#include "poly.h"
#include "tree.h"

int falcon_keygen(falcon_secret_key *sk, falcon_public_key *pk, const falcon_params *p,
                  const falcon_rng *rng)
{
    int rc = falcon_generate_ntru_keys(sk->f, sk->g, sk->F, sk->G, p, rng);
    if (rc != FALCON_OK) {
        return rc;
    }
    size_t n = p->n;
    sk->n = n;
    falcon_build_basis_fft(sk->b00, sk->b01, sk->b10, sk->b11, sk->f, sk->g, sk->F, sk->G, n);
    falcon_mat22 basis = {sk->b00, sk->b01, sk->b10, sk->b11};
    rc = falcon_build_falcon_tree(&sk->tree, &basis, n, p);
    if (rc != FALCON_OK) {
        return rc;
    }
    pk->n = n;
    return falcon_compute_public_key(pk->h, sk->f, sk->g, p);
}

int falcon_keygen_system(falcon_secret_key *sk, falcon_public_key *pk, const falcon_params *p)
{
    return falcon_keygen(sk, pk, p, &FALCON_SYSTEM_RNG);
}

int falcon_compute_public_key(int32_t *h, const int32_t *f, const int32_t *g, const falcon_params *p)
{
    return falcon_div_mod_q(h, g, f, p->n);
}

int falcon_load_secret_key(falcon_secret_key *sk, const uint8_t *b, size_t len,
                           const falcon_params *p)
{
    size_t n = 0;

    if (falcon_decode_sk(sk->f, sk->g, sk->F, &n, b, len) != FALCON_OK || n != p->n) {
        return FALCON_ERR_VALUE;
    }
    sk->n = n;
    if (falcon_recompute_G(sk->G, sk->f, sk->g, sk->F, n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    falcon_build_basis_fft(sk->b00, sk->b01, sk->b10, sk->b11, sk->f, sk->g, sk->F, sk->G, n);
    falcon_mat22 basis = {sk->b00, sk->b01, sk->b10, sk->b11};
    return falcon_build_falcon_tree(&sk->tree, &basis, n, p);
}

int falcon_sign(falcon_signature *sig, const falcon_secret_key *sk, const uint8_t *message,
                size_t message_len, const falcon_params *p, const falcon_rng *rng)
{
    int32_t c[FALCON_MAX_N];
    int32_t s1_coeff[FALCON_MAX_N];
    int32_t s2_coeff[FALCON_MAX_N];
    falcon_cplx t0[FALCON_MAX_N], t1[FALCON_MAX_N];
    falcon_cplx z0[FALCON_MAX_N], z1[FALCON_MAX_N];
    falcon_cplx s0[FALCON_MAX_N], s1[FALCON_MAX_N];

    if (sk->n != p->n || p->sig_bytelen < 41 || p->sig_bytelen - 41 > FALCON_MAX_S2_BYTES) {
        return FALCON_ERR_VALUE;
    }

    /* Der Salt wird genau einmal gezogen; beide Schleifen wiederholen nur das Sampling. */
    falcon_random_bytes(rng, sig->salt, FALCON_SALT_BYTES);
    if (falcon_hash_to_point(c, sig->salt, FALCON_SALT_BYTES, message, message_len, p)
        != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    falcon_compute_target(t0, t1, c, sk);

    for (;;) {
        for (;;) {
            int rc = falcon_ff_sampling(z0, z1, t0, t1, p->n, &sk->tree, p, rng);
            if (rc != FALCON_OK) {
                return rc;
            }
            falcon_compute_signature_vector(s0, s1, t0, t1, z0, z1, sk);
            if (falcon_is_short_fft(s0, s1, p->n, p)) {
                break;
            }
        }
        if (falcon_to_coefficients(s1_coeff, s2_coeff, s0, s1, p->n) != FALCON_OK) {
            return FALCON_ERR_VALUE;
        }
        if (falcon_compress(sig->s2_encoded, &sig->s2_len, s2_coeff, p) == FALCON_OK) {
            return FALCON_OK;
        }
    }
}

int falcon_sign_system(falcon_signature *sig, const falcon_secret_key *sk, const uint8_t *message,
                       size_t message_len, const falcon_params *p)
{
    return falcon_sign(sig, sk, message, message_len, p, &FALCON_SYSTEM_RNG);
}

void falcon_compute_target(falcon_cplx *t0, falcon_cplx *t1, const int32_t *c,
                           const falcon_secret_key *sk)
{
    double values[FALCON_MAX_N];
    falcon_cplx c_hat[FALCON_MAX_N], f_hat[FALCON_MAX_N], F_hat[FALCON_MAX_N];
    size_t n = sk->n;
    double q = (double)FALCON_Q;

    falcon_ints_to_doubles(values, c, n);
    (void)falcon_fft(c_hat, values, n);
    falcon_ints_to_doubles(values, sk->f, n);
    (void)falcon_fft(f_hat, values, n);
    falcon_ints_to_doubles(values, sk->F, n);
    (void)falcon_fft(F_hat, values, n);

    for (size_t k = 0; k < n; k++) {
        falcon_cplx v = falcon_c_mul(c_hat[k], F_hat[k]);
        t0[k].re = -v.re / q;
        t0[k].im = -v.im / q;
        v = falcon_c_mul(c_hat[k], f_hat[k]);
        t1[k].re = v.re / q;
        t1[k].im = v.im / q;
    }
}

void falcon_compute_signature_vector(falcon_cplx *s0, falcon_cplx *s1, const falcon_cplx *t0,
                                     const falcon_cplx *t1, const falcon_cplx *z0,
                                     const falcon_cplx *z1, const falcon_secret_key *sk)
{
    for (size_t k = 0; k < sk->n; k++) {
        falcon_cplx d0 = falcon_c_sub(t0[k], z0[k]);
        falcon_cplx d1 = falcon_c_sub(t1[k], z1[k]);
        s0[k] = falcon_c_add(falcon_c_mul(d0, sk->b00[k]), falcon_c_mul(d1, sk->b10[k]));
        s1[k] = falcon_c_add(falcon_c_mul(d0, sk->b01[k]), falcon_c_mul(d1, sk->b11[k]));
    }
}

int falcon_is_short_fft(const falcon_cplx *s0, const falcon_cplx *s1, size_t n,
                        const falcon_params *p)
{
    double a = 0.0, b = 0.0;
    if (falcon_fft_norm_sq(&a, s0, n) != FALCON_OK || falcon_fft_norm_sq(&b, s1, n) != FALCON_OK) {
        return 0;
    }
    return (a + b) <= (double)p->sig_bound;
}

int falcon_to_coefficients(int32_t *a, int32_t *b, const falcon_cplx *s0, const falcon_cplx *s1,
                           size_t n)
{
    double values[FALCON_MAX_N];

    /* llrint rundet im Standardmodus bei Gleichstand zur geraden Zahl, wie Python round. */
    if (falcon_ifft(values, s0, n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    for (size_t i = 0; i < n; i++) {
        a[i] = (int32_t)llrint(values[i]);
    }
    if (falcon_ifft(values, s1, n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    for (size_t i = 0; i < n; i++) {
        b[i] = (int32_t)llrint(values[i]);
    }
    return FALCON_OK;
}

int falcon_verify(const falcon_public_key *pk, const uint8_t *message, size_t message_len,
                  const falcon_signature *sig, const falcon_params *p)
{
    int32_t c[FALCON_MAX_N];
    int32_t s1[FALCON_MAX_N];
    int32_t s2[FALCON_MAX_N];

    if (pk->n != p->n || p->n > FALCON_MAX_N) {
        return 0;
    }
    if (falcon_hash_to_point(c, sig->salt, FALCON_SALT_BYTES, message, message_len, p)
        != FALCON_OK) {
        return 0;
    }
    if (falcon_decompress(s2, sig->s2_encoded, sig->s2_len, p) != FALCON_OK) {
        return 0;
    }
    if (falcon_compute_s1(s1, c, s2, pk->h, p) != FALCON_OK) {
        return 0;
    }
    return falcon_is_short(s1, s2, p);
}

int falcon_compute_s1(int32_t *s1, const int32_t *c, const int32_t *s2, const int32_t *h,
                      const falcon_params *p)
{
    int32_t s2h[FALCON_MAX_N];
    int32_t diff[FALCON_MAX_N];

    if (falcon_mul_mod_q(s2h, s2, h, p->n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    for (size_t i = 0; i < p->n; i++) {
        diff[i] = falcon_mod_q((int64_t)c[i] - s2h[i]);
    }
    falcon_center_mod_q(s1, diff, p->n);
    return FALCON_OK;
}

int falcon_is_short(const int32_t *s1, const int32_t *s2, const falcon_params *p)
{
    return falcon_norm_sq(s1, p->n) + falcon_norm_sq(s2, p->n) <= p->sig_bound;
}
