/*
 * SHAKE-256 nach FIPS 202. Eigene Implementierung, da C keine mitbringt.
 *
 * Ablauf: init, beliebig oft inject, flip, beliebig oft extract.
 */
#ifndef FALCON_SHAKE256_H
#define FALCON_SHAKE256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t state[25];
    size_t pos;
} falcon_shake256_ctx;

void falcon_shake256_init(falcon_shake256_ctx *ctx);
void falcon_shake256_inject(falcon_shake256_ctx *ctx, const uint8_t *data, size_t len);
void falcon_shake256_flip(falcon_shake256_ctx *ctx);
void falcon_shake256_extract(falcon_shake256_ctx *ctx, uint8_t *out, size_t len);

#endif
