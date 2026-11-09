/*
 * Hilfen für die C-Tests: Testvektoren aus Python/data/vectors lesen und prüfen.
 * Format siehe Python/scripts/gen_vectors.py.
 */
#ifndef FALCON_TEST_VECTORS_H
#define FALCON_TEST_VECTORS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "datatypes.h"
#include "sampler.h"
#include "shake256.h"

#define VEC_MAX_LIST 8192
#define VEC_MAX_BYTES 65536

#define VEC_STATUS_OK 0
#define VEC_STATUS_NONE 1
#define VEC_STATUS_ERROR 2

typedef struct {
    const char *name;
    char *buf;
    char **lines;
    size_t nlines;
    size_t next;    /* Zeile hinter dem aktuellen Fall */
    size_t first;   /* erste Zeile des aktuellen Falls */
    size_t last;    /* eine Zeile hinter dem aktuellen Fall */
    size_t index;   /* Nummer des aktuellen Falls */
} vec_file;

void vec_open(vec_file *v, const char *name);
int vec_next(vec_file *v);
int vec_status(const vec_file *v);
int vec_has(const vec_file *v, const char *field);
size_t vec_ints(const vec_file *v, const char *field, int32_t *dst, size_t cap);
size_t vec_bytes(const vec_file *v, const char *field, uint8_t *dst, size_t cap);
int64_t vec_int(const vec_file *v, const char *field);
void vec_close(vec_file *v);

/* Gleitkomma als 64-Bit-Muster: Felder der Arten float, floats, tree und cplx. */
double vec_double(const vec_file *v, const char *field);
size_t vec_doubles(const vec_file *v, const char *field, double *dst, size_t cap);
size_t vec_cplx(const vec_file *v, const char *field, falcon_cplx *dst, size_t cap);
/* Dezimale ganze Zahl bis 2^127, für Werte, die int64_t sprengen. */
unsigned __int128 vec_u128(const vec_file *v, const char *field);
/* (n, sig_bytelen) aus dem Feld params auf Basis des passenden Parametersatzes. */
falcon_params vec_params(const vec_file *v);

/* Falcon-Baum aus den Token einer Vektordatei aufbauen; liefert n. */
size_t vec_tree(const vec_file *v, const char *field, falcon_tree *t);
/* Baum in Vorordnung als Token wie in der Vektordatei; liefert die Anzahl. */
size_t tree_tokens(double *out, const falcon_tree_node *node, size_t n);
#define VEC_MAX_TREE_TOKENS (2 * FALCON_MAX_TREE_ELL + FALCON_MAX_N)

/* Zufallsquellen für Tests: feste Bytes (mit Prüfung des Verbrauchs) und ShakeRNG. */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} fixed_rng_state;
falcon_rng fixed_rng(fixed_rng_state *state, const uint8_t *data, size_t len);
falcon_rng shake_rng(falcon_shake256_ctx *ctx, const uint8_t *seed, size_t len);

/* Vergleich bitgenau, also auch das Vorzeichen von Nullen. */
#define SAME_BITS(a, b, count) (memcmp((a), (b), (count) * sizeof *(a)) == 0)

/* Datei vollständig einlesen; NUL-terminiert, Länge in *len. Bricht bei Fehlern ab. */
char *read_file(const char *path, size_t *len);

extern int test_checks;
extern int test_failures;
int test_summary(const char *name);

#define CHECK(cond, ...)                                              \
    do {                                                              \
        test_checks++;                                                \
        if (!(cond)) {                                                \
            test_failures++;                                          \
            if (test_failures <= 20) {                                \
                fprintf(stderr, "FEHLER %s:%d: ", __FILE__, __LINE__); \
                fprintf(stderr, __VA_ARGS__);                         \
                fprintf(stderr, "\n");                                \
            }                                                         \
        }                                                             \
    } while (0)

#endif
