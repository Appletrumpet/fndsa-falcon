/*
 * Geheime Basis und Falcon-Baum.
 *
 * Spec-Referenz: §3.8.3, Alg. 4 (Z. 2-7), Alg. 8, Alg. 9.
 */
#ifndef FALCON_TREE_H
#define FALCON_TREE_H

#include "datatypes.h"

/* 2x2-Matrix aus Polynomen in FFT-Form. */
typedef struct {
    falcon_cplx *a00;
    falcon_cplx *a01;
    falcon_cplx *a10;
    falcon_cplx *a11;
} falcon_mat22;

/* [[g, -f], [G, -F]] in FFT-Form. Alg. 4, Z. 2-3. */
void falcon_build_basis_fft(falcon_cplx *b00, falcon_cplx *b01, falcon_cplx *b10, falcon_cplx *b11,
                            const int32_t *f, const int32_t *g, const int32_t *F, const int32_t *G,
                            size_t n);

/* Basis mal adjungierte Basis. Alg. 4, Z. 4. */
void falcon_gram_matrix(const falcon_mat22 *out, const falcon_mat22 *basis, size_t n);

/* LDL*-Zerlegung einer 2x2-Matrix. Alg. 8. */
int falcon_ldl(falcon_cplx *L10, falcon_cplx *D00, falcon_cplx *D11, const falcon_mat22 *G, size_t n);

/* Baum rekursiv aufbauen, Wurzel in t->nodes[0]; Blätter noch nicht normalisiert. Alg. 9. */
int falcon_ff_ldl(falcon_tree *t, const falcon_mat22 *G, size_t n);

/* Jedes Blatt zu sigma / sqrt(Blatt), direkt im Baum (Python liefert einen neuen). Alg. 4, Z. 6-7. */
void falcon_normalize_leaves(falcon_tree_node *root, size_t n, double sigma);

/* gram_matrix, ff_ldl, normalize_leaves. Alg. 4, Z. 4-7. */
int falcon_build_falcon_tree(falcon_tree *t, const falcon_mat22 *basis, size_t n,
                             const falcon_params *p);

#endif
