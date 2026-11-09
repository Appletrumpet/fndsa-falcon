#include "vectors.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int test_checks = 0;
int test_failures = 0;

static void die(const char *what, const char *detail)
{
    fprintf(stderr, "Abbruch: %s: %s\n", what, detail);
    exit(2);
}

char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        die("Datei nicht lesbar", path);
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        die("Dateigrösse unbekannt", path);
    }
    char *buf = malloc((size_t)size + 1);
    if (buf == NULL || fread(buf, 1, (size_t)size, f) != (size_t)size) {
        die("Datei nicht gelesen", path);
    }
    buf[size] = '\0';
    fclose(f);
    *len = (size_t)size;
    return buf;
}

void vec_open(vec_file *v, const char *name)
{
    char path[512];
    size_t len;

    snprintf(path, sizeof path, "%s/vectors/%s.txt", FALCON_DATA_DIR, name);
    v->name = name;
    v->buf = read_file(path, &len);

    size_t count = 1;
    for (size_t i = 0; i < len; i++) {
        count += (v->buf[i] == '\n');
    }
    v->lines = malloc(count * sizeof *v->lines);
    if (v->lines == NULL) {
        die("kein Speicher", name);
    }
    v->nlines = 0;
    char *p = v->buf;
    while (*p != '\0') {
        char *end = strchr(p, '\n');
        if (end != NULL) {
            *end = '\0';
        }
        if (*p != '#') {
            v->lines[v->nlines++] = p;
        }
        if (end == NULL) {
            break;
        }
        p = end + 1;
    }
    v->next = 0;
    v->first = v->last = 0;
    v->index = 0;
}

int vec_next(vec_file *v)
{
    if (v->next >= v->nlines) {
        return 0;
    }
    if (strcmp(v->lines[v->next], "case") != 0) {
        die("Fall erwartet in", v->name);
    }
    v->first = v->next + 1;
    size_t i = v->first;
    while (i < v->nlines && strcmp(v->lines[i], "case") != 0) {
        i++;
    }
    v->last = i;
    v->next = i;
    v->index++;
    return 1;
}

/* Zeile des Feldes; NULL, wenn es im aktuellen Fall fehlt. */
static const char *find(const vec_file *v, const char *field)
{
    size_t flen = strlen(field);
    for (size_t i = v->first; i < v->last; i++) {
        if (strncmp(v->lines[i], field, flen) == 0 && v->lines[i][flen] == ' ') {
            return v->lines[i] + flen + 1;
        }
    }
    return NULL;
}

static const char *require(const vec_file *v, const char *field)
{
    const char *p = find(v, field);
    if (p == NULL) {
        die("Feld fehlt", field);
    }
    return p;
}

int vec_has(const vec_file *v, const char *field)
{
    return find(v, field) != NULL;
}

int vec_status(const vec_file *v)
{
    const char *p = require(v, "status");
    if (strcmp(p, "ok") == 0) {
        return VEC_STATUS_OK;
    }
    if (strcmp(p, "none") == 0) {
        return VEC_STATUS_NONE;
    }
    if (strcmp(p, "error") == 0) {
        return VEC_STATUS_ERROR;
    }
    die("unbekannter Status", p);
    return -1;
}

/* Überspringt "<art> <anzahl> " und liefert die Anzahl. */
static size_t parse_header(const char **p)
{
    const char *s = strchr(*p, ' ');
    if (s == NULL) {
        die("Feld ohne Anzahl", *p);
    }
    char *end;
    unsigned long count = strtoul(s + 1, &end, 10);
    *p = end;
    return count;
}

size_t vec_ints(const vec_file *v, const char *field, int32_t *dst, size_t cap)
{
    const char *p = require(v, field);
    size_t count = parse_header(&p);
    if (count > cap) {
        die("Liste zu lang", field);
    }
    for (size_t i = 0; i < count; i++) {
        char *end;
        errno = 0;
        long long x = strtoll(p, &end, 10);
        if (end == p || errno != 0 || x < INT32_MIN || x > INT32_MAX) {
            die("Wert passt nicht in int32_t", field);
        }
        dst[i] = (int32_t)x;
        p = end;
    }
    return count;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    die("kein Hex-Zeichen", "");
    return 0;
}

size_t vec_bytes(const vec_file *v, const char *field, uint8_t *dst, size_t cap)
{
    const char *p = require(v, field);
    size_t count = parse_header(&p);
    if (count > cap) {
        die("Bytefolge zu lang", field);
    }
    p++;
    for (size_t i = 0; i < count; i++) {
        dst[i] = (uint8_t)(hex_value(p[2 * i]) * 16 + hex_value(p[2 * i + 1]));
    }
    return count;
}

int64_t vec_int(const vec_file *v, const char *field)
{
    const char *p = require(v, field);
    parse_header(&p);
    return strtoll(p, NULL, 10);
}

void vec_close(vec_file *v)
{
    free(v->lines);
    free(v->buf);
}

int test_summary(const char *name)
{
    printf("%-14s %8d Prüfungen, %d Fehler\n", name, test_checks, test_failures);
    return test_failures == 0 ? 0 : 1;
}
