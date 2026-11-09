/*
 * FF-Sampling: rekursiv und zufällig einen Gitterpunkt nahe t wählen.
 *
 * Spec-Referenz: §3.9.2, Alg. 11.
 */
#ifndef FALCON_FFSAMPLING_H
#define FALCON_FFSAMPLING_H

#include "datatypes.h"
#include "sampler.h"

/* Alle Polynome in FFT-Form mit Länge n; tree ist die Wurzel in t->nodes[0]. Alg. 11. */
int falcon_ff_sampling(falcon_cplx *z0, falcon_cplx *z1, const falcon_cplx *t0, const falcon_cplx *t1,
                       size_t n, const falcon_tree *tree, const falcon_params *p,
                       const falcon_rng *rng);

/* Dieselbe Rechnung ab einem beliebigen Knoten (für Bausteinvektoren). */
int falcon_ff_sampling_node(falcon_cplx *z0, falcon_cplx *z1, const falcon_cplx *t0,
                            const falcon_cplx *t1, size_t n, const falcon_tree_node *node,
                            const falcon_params *p, const falcon_rng *rng);

#endif
