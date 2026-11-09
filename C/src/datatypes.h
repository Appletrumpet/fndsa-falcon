/*
 * Datenstrukturen für Schlüssel und Signaturen.
 *
 * Spec-Referenz: §3.4.3 (PublicKey), §3.11.3 (Signature).
 * Polynome sind in Stufe 1 einheitlich int32_t, wie die Listen ganzer Zahlen
 * in Python.
 */
#ifndef FALCON_DATATYPES_H
#define FALCON_DATATYPES_H

#include "params.h"

/* Längstes angenommenes s2: gepolsterte Länge von Falcon-1024 plus 1 (KAT count = 82). */
#define FALCON_MAX_S2_BYTES (1280 - 41 + 1)
#define FALCON_MAX_SIG_BYTES (1 + FALCON_SALT_BYTES + FALCON_MAX_S2_BYTES)
#define FALCON_MAX_PK_BYTES 1793
#define FALCON_MAX_SK_BYTES 2305

typedef struct {
    int32_t h[FALCON_MAX_N];
    size_t n;
} falcon_public_key;

typedef struct {
    uint8_t salt[FALCON_SALT_BYTES];
    uint8_t s2_encoded[FALCON_MAX_S2_BYTES];
    size_t s2_len;
} falcon_signature;

#endif
