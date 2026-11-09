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

/* Komplexe Zahl aus zwei double. Eigene Struktur, da complex.h keine festen Formeln vorgibt. */
typedef struct {
    double re;
    double im;
} falcon_cplx;

/* Knoten des Falcon-Baums (§3.4.2). Stufe 1 bildet die Python-Tupel nach. Die Form hängt nur
 * von n ab: Bei n = 1 ist der Knoten ein Blatt und nur sigma gesetzt. */
typedef struct falcon_tree_node {
    falcon_cplx *ell;
    struct falcon_tree_node *left;
    struct falcon_tree_node *right;
    double sigma;
} falcon_tree_node;

/* Für n = 1024: 2n - 1 Knoten, n * log2(n) Werte in den inneren Knoten. */
#define FALCON_MAX_TREE_NODES (2 * FALCON_MAX_N - 1)
#define FALCON_MAX_TREE_ELL (10 * FALCON_MAX_N)

/* Speicher des Baums; die Verweise zeigen in dieselbe Struktur, sie darf nicht kopiert werden. */
typedef struct {
    falcon_tree_node nodes[FALCON_MAX_TREE_NODES];
    falcon_cplx ell[FALCON_MAX_TREE_ELL];
    size_t nnodes;
    size_t nell;
} falcon_tree;

typedef struct {
    int32_t h[FALCON_MAX_N];
    size_t n;
} falcon_public_key;

/* Kern f, g, F, G (§3.4.2); abgeleitet: Basis in FFT-Form und Falcon-Baum. */
typedef struct {
    size_t n;
    int32_t f[FALCON_MAX_N];
    int32_t g[FALCON_MAX_N];
    int32_t F[FALCON_MAX_N];
    int32_t G[FALCON_MAX_N];
    falcon_cplx b00[FALCON_MAX_N];
    falcon_cplx b01[FALCON_MAX_N];
    falcon_cplx b10[FALCON_MAX_N];
    falcon_cplx b11[FALCON_MAX_N];
    falcon_tree tree;
} falcon_secret_key;

typedef struct {
    uint8_t salt[FALCON_SALT_BYTES];
    uint8_t s2_encoded[FALCON_MAX_S2_BYTES];
    size_t s2_len;
} falcon_signature;

#endif
