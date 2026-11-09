#include "shake256.h"

#include <string.h>

/* Rate von SHAKE-256: 1600 - 2 * 256 = 1088 Bit (FIPS 202, §6.2). */
#define RATE 136

/* Rundenkonstanten RC[i] (FIPS 202, §3.2.5). */
static const uint64_t ROUND_CONSTANTS[24] = {
    0x0000000000000001u, 0x0000000000008082u, 0x800000000000808Au, 0x8000000080008000u,
    0x000000000000808Bu, 0x0000000080000001u, 0x8000000080008081u, 0x8000000000008009u,
    0x000000000000008Au, 0x0000000000000088u, 0x0000000080008009u, 0x000000008000000Au,
    0x000000008000808Bu, 0x800000000000008Bu, 0x8000000000008089u, 0x8000000000008003u,
    0x8000000000008002u, 0x8000000000000080u, 0x000000000000800Au, 0x800000008000000Au,
    0x8000000080008081u, 0x8000000000008080u, 0x0000000080000001u, 0x8000000080008008u,
};

/* Rotationsweiten aus Schritt rho, indiziert mit x + 5 * y (FIPS 202, §3.2.2). */
static const unsigned RHO_OFFSETS[25] = {
    0,  1,  62, 28, 27,
    36, 44, 6,  55, 20,
    3,  10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2,  61, 56, 14,
};

static uint64_t rotl(uint64_t x, unsigned r)
{
    return r == 0 ? x : (x << r) | (x >> (64 - r));
}

static void keccak_f1600(uint64_t *a)
{
    for (int round = 0; round < 24; round++) {
        uint64_t c[5];
        uint64_t d[5];
        uint64_t b[25];

        /* theta */
        for (int x = 0; x < 5; x++) {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            a[i] ^= d[i % 5];
        }

        /* rho und pi: A'[y, 2x + 3y] = ROT(A[x, y]) */
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int nx = y;
                int ny = (2 * x + 3 * y) % 5;
                b[nx + 5 * ny] = rotl(a[x + 5 * y], RHO_OFFSETS[x + 5 * y]);
            }
        }

        /* chi */
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }

        /* iota */
        a[0] ^= ROUND_CONSTANTS[round];
    }
}

/* Byte i des Zustands; Lanes sind little-endian (FIPS 202, §B.1), unabhängig von der Plattform. */
static void xor_byte(uint64_t *state, size_t i, uint8_t v)
{
    state[i / 8] ^= (uint64_t)v << (8 * (i % 8));
}

static uint8_t get_byte(const uint64_t *state, size_t i)
{
    return (uint8_t)(state[i / 8] >> (8 * (i % 8)));
}

void falcon_shake256_init(falcon_shake256_ctx *ctx)
{
    memset(ctx->state, 0, sizeof ctx->state);
    ctx->pos = 0;
}

void falcon_shake256_inject(falcon_shake256_ctx *ctx, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        xor_byte(ctx->state, ctx->pos, data[i]);
        ctx->pos++;
        if (ctx->pos == RATE) {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
    }
}

void falcon_shake256_flip(falcon_shake256_ctx *ctx)
{
    /* Suffix 1111 von SHAKE und Polsterung pad10*1 (FIPS 202, §6.2, §5.1). */
    xor_byte(ctx->state, ctx->pos, 0x1F);
    xor_byte(ctx->state, RATE - 1, 0x80);
    keccak_f1600(ctx->state);
    ctx->pos = 0;
}

void falcon_shake256_extract(falcon_shake256_ctx *ctx, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (ctx->pos == RATE) {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
        out[i] = get_byte(ctx->state, ctx->pos);
        ctx->pos++;
    }
}
