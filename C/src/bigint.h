/*
 * Grosse Ganzzahlen mit Vorzeichen, für NTRUSolve (Spec §4.4.3: Koeffizienten bis rund 9'400 Bit).
 *
 * Eigene, kleine Implementierung; nur der Schnitt KeyGen braucht sie. Der Speicher wächst nach
 * Bedarf; schlägt malloc fehl, bricht das Programm ab. Die Laufzeit hängt von den Werten ab
 * (keygen ist vom Ziel konstanter Laufzeit ausgenommen).
 */
#ifndef FALCON_BIGINT_H
#define FALCON_BIGINT_H

#include <stddef.h>
#include <stdint.h>

/* Betrag in 32-Bit-Ziffern, niederwertige zuerst, ohne führende Nullen. Null: len = 0, neg = 0. */
typedef struct {
    uint32_t *limb;
    size_t len;
    size_t cap;
    int neg;
} falcon_big;

void falcon_big_init(falcon_big *a);
void falcon_big_free(falcon_big *a);
void falcon_big_set_i64(falcon_big *a, int64_t x);
void falcon_big_copy(falcon_big *r, const falcon_big *a);
int falcon_big_is_zero(const falcon_big *a);
int falcon_big_cmp(const falcon_big *a, const falcon_big *b);

/* r darf jeweils mit a oder b übereinstimmen. */
void falcon_big_add(falcon_big *r, const falcon_big *a, const falcon_big *b);
void falcon_big_sub(falcon_big *r, const falcon_big *a, const falcon_big *b);
void falcon_big_mul(falcon_big *r, const falcon_big *a, const falcon_big *b);
void falcon_big_neg(falcon_big *r, const falcon_big *a);

/* Division der Beträge; q und r müssen von a und b verschieden sein, b darf nicht 0 sein. */
void falcon_big_divmod_abs(falcon_big *q, falcon_big *r, const falcon_big *a, const falcon_big *b);

/* r = a * 2^bits (Vorzeichen bleibt). */
void falcon_big_shl(falcon_big *r, const falcon_big *a, size_t bits);
/* r = |a| >> bits. */
void falcon_big_shr_abs(falcon_big *r, const falcon_big *a, size_t bits);

/* Anzahl Bits des Betrags; 0 für a = 0. */
size_t falcon_big_bit_length(const falcon_big *a);
/* Bit i des Betrags. */
int falcon_big_get_bit(const falcon_big *a, size_t i);
/* Untere 64 Bit von |a| >> bits. */
uint64_t falcon_big_low64_shr(const falcon_big *a, size_t bits);
/* 1, wenn a in int32_t passt; dann steht der Wert in *out. */
int falcon_big_to_i32(const falcon_big *a, int32_t *out);

#endif
