#include "hashing.h"

#include "shake256.h"

int falcon_hash_to_point(int32_t *c, const uint8_t *a, size_t a_len, const uint8_t *b,
                         size_t b_len, const falcon_params *p)
{
    falcon_shake256_ctx ctx;

    if (p->q <= 0 || p->q > 65536) {
        return FALCON_ERR_VALUE;
    }
    uint32_t q = (uint32_t)p->q;
    uint32_t limit = (65536u / q) * q;

    falcon_shake256_init(&ctx);
    falcon_shake256_inject(&ctx, a, a_len);
    falcon_shake256_inject(&ctx, b, b_len);
    falcon_shake256_flip(&ctx);

    size_t i = 0;
    while (i < p->n) {
        uint8_t chunk[2];
        falcon_shake256_extract(&ctx, chunk, sizeof chunk);
        uint32_t t = ((uint32_t)chunk[0] << 8) | chunk[1];
        if (t < limit) {
            c[i] = (int32_t)(t % q);
            i++;
        }
    }
    return FALCON_OK;
}
