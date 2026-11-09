/*
 * Erzeugung und Rekonstruktion der NTRU-Komponenten.
 *
 * Spec-Referenz: Gl. 3.35. Bisher nur recompute_G (Schnitt Sign); die übrigen Bausteine folgen
 * im Schnitt KeyGen.
 */
#ifndef FALCON_NTRUGEN_H
#define FALCON_NTRUGEN_H

#include "datatypes.h"

/* G aus der NTRU-Gleichung, zentriert. FALCON_ERR_VALUE, wenn f nicht invertierbar ist. Gl. 3.35. */
int falcon_recompute_G(int32_t *G, const int32_t *f, const int32_t *g, const int32_t *F, size_t n);

#endif
