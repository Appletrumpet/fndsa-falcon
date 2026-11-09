/*
 * Hilfen für die C-Tests: Testvektoren aus Python/data/vectors lesen und prüfen.
 * Format siehe Python/scripts/gen_vectors.py.
 */
#ifndef FALCON_TEST_VECTORS_H
#define FALCON_TEST_VECTORS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

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
