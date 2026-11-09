#include "falcon.h"

#include "encoding.h"
#include "hashing.h"
#include "modq.h"
#include "poly.h"

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
