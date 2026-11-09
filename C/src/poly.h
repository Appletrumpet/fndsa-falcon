/*
 * Polynome in Koeffizientenform.
 *
 * Spec-Referenz: §3.1, §3.3. Im Schnitt Verify wird nur norm_sq benötigt, die
 * übrigen Bausteine folgen im Schnitt KeyGen.
 */
#ifndef FALCON_POLY_H
#define FALCON_POLY_H

#include <stddef.h>
#include <stdint.h>

/* Summe der quadrierten Koeffizienten. Gl. 3.10.
 * Annahme: |a[i]| < 2^26; so bleibt die Summe für n <= 2048 unter 2^64. */
uint64_t falcon_norm_sq(const int32_t *a, size_t n);

#endif
