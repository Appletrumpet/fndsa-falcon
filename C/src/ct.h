/*
 * Hilfsfunktionen für konstante Laufzeit (Ebene 5, Stufe 2, Z2).
 *
 * Auswahl über Masken statt Verzweigungen. Die leere asm-Anweisung hindert den Compiler daran,
 * eine Maske wieder in einen bedingten Sprung zu verwandeln. Ob das gelingt, prüft ct/ctgrind.sh.
 */
#ifndef FALCON_CT_H
#define FALCON_CT_H

#include <stdint.h>
#include <string.h>

#ifdef FALCON_CTGRIND
#include <valgrind/memcheck.h>
/* Gibt ein Ergebnis frei, das nach Z2 verzweigen darf (z. B. Ablehnung in SamplerZ). */
#define FALCON_DECLASSIFY(ptr, len) VALGRIND_MAKE_MEM_DEFINED((ptr), (len))
#else
#define FALCON_DECLASSIFY(ptr, len) ((void)(ptr), (void)(len))
#endif

static inline uint64_t falcon_ct_barrier(uint64_t x)
{
    __asm__("" : "+r"(x));
    return x;
}

/* bit ∈ {0, 1} → Maske aus lauter Nullen bzw. lauter Einsen. */
static inline uint64_t falcon_ct_mask(uint64_t bit)
{
    return falcon_ct_barrier((uint64_t)0 - bit);
}

/* 1, falls x != 0, sonst 0. */
static inline uint64_t falcon_ct_nonzero(uint64_t x)
{
    return (x | ((uint64_t)0 - x)) >> 63;
}

static inline uint64_t falcon_ct_select_u64(uint64_t mask, uint64_t a, uint64_t b)
{
    return b ^ (mask & (a ^ b));
}

/* mask = lauter Einsen → a, sonst b; bitgenau, auch für -0.0. */
static inline double falcon_ct_select_double(uint64_t mask, double a, double b)
{
    uint64_t ua, ub;
    memcpy(&ua, &a, sizeof ua);
    memcpy(&ub, &b, sizeof ub);
    uint64_t ur = falcon_ct_select_u64(mask, ua, ub);
    double r;
    memcpy(&r, &ur, sizeof r);
    return r;
}

/* 1, falls a < b, sonst 0 (Gleitkommavergleich ohne Sprung). */
static inline uint64_t falcon_ct_lt_double(double a, double b)
{
    return falcon_ct_barrier((uint64_t)(a < b));
}

#endif
