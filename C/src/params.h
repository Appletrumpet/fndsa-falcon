/*
 * Parametersätze für Falcon-512 und Falcon-1024.
 *
 * Spec-Referenz: Tabelle 3.3, §3.13.
 */
#ifndef FALCON_PARAMS_H
#define FALCON_PARAMS_H

#include <stddef.h>
#include <stdint.h>

#define FALCON_Q 12289
#define FALCON_MAX_N 1024
#define FALCON_SALT_BYTES 40

/* Rückgabecodes; entsprechen den beiden Fehlerarten der Python-Implementierung. */
#define FALCON_OK 0
#define FALCON_ERR_VALUE (-1) /* Python: ValueError */
#define FALCON_ERR_NONE (-2)  /* Python: Rückgabe None */

typedef struct {
    size_t n;
    int32_t q;
    double sigma;
    double sigma_min;
    double sigma_max;
    uint64_t sig_bound;
    size_t sig_bytelen;
} falcon_params;

extern const falcon_params FALCON_512;
extern const falcon_params FALCON_1024;

/* Bedingungen aus §3.4.1, §3.9.3, §3.11 und Gl. 2.10; FALCON_ERR_VALUE, wenn verletzt. */
int falcon_params_validate(const falcon_params *p);

/* log2(n), wenn n eine Zweierpotenz mit 1 <= log2(n) <= 10 ist, sonst -1. */
int falcon_logn(size_t n);

/* Länge des Public Keys in Bytes (§3.11.4). */
size_t falcon_pk_bytes(const falcon_params *p);

/* Header-Byte der Secret-Key-Kodierung (§3.11.5). */
uint8_t falcon_sk_header_byte(const falcon_params *p);

#endif
