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

static double double_from_bits(uint64_t bits)
{
    double d;
    memcpy(&d, &bits, sizeof d);
    return d;
}

size_t vec_doubles(const vec_file *v, const char *field, double *dst, size_t cap)
{
    const char *p = require(v, field);
    size_t count = parse_header(&p);
    if (count > cap) {
        die("Liste zu lang", field);
    }
    for (size_t i = 0; i < count; i++) {
        char *end;
        dst[i] = double_from_bits(strtoull(p, &end, 16));
        p = end;
    }
    return count;
}

double vec_double(const vec_file *v, const char *field)
{
    double d;
    vec_doubles(v, field, &d, 1);
    return d;
}

size_t vec_cplx(const vec_file *v, const char *field, falcon_cplx *dst, size_t cap)
{
    const char *p = require(v, field);
    size_t count = parse_header(&p);
    if (count > cap) {
        die("Liste zu lang", field);
    }
    for (size_t i = 0; i < count; i++) {
        char *end;
        dst[i].re = double_from_bits(strtoull(p, &end, 16));
        p = end;
        dst[i].im = double_from_bits(strtoull(p, &end, 16));
        p = end;
    }
    return count;
}

unsigned __int128 vec_u128(const vec_file *v, const char *field)
{
    const char *p = require(v, field);
    parse_header(&p);
    while (*p == ' ') {
        p++;
    }
    unsigned __int128 value = 0;
    for (; *p >= '0' && *p <= '9'; p++) {
        value = value * 10 + (unsigned)(*p - '0');
    }
    return value;
}

falcon_params vec_params(const vec_file *v)
{
    int32_t pv[2];
    vec_ints(v, "params", pv, 2);
    falcon_params p = pv[0] == 1024 ? FALCON_1024 : FALCON_512;
    p.n = (size_t)pv[0];
    p.sig_bytelen = (size_t)pv[1];
    return p;
}

/* Liest eine Dezimalzahl ab *p und rückt *p dahinter. */
static void parse_big(falcon_big *dst, const char **p)
{
    static const int64_t chunk_base[10] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};
    falcon_big base, digit;
    const char *s = *p;
    int neg = 0;

    while (*s == ' ') {
        s++;
    }
    if (*s == '-') {
        neg = 1;
        s++;
    }
    falcon_big_init(&base);
    falcon_big_init(&digit);
    falcon_big_set_i64(dst, 0);
    while (*s >= '0' && *s <= '9') {
        int64_t chunk = 0;
        int count = 0;
        while (count < 9 && s[count] >= '0' && s[count] <= '9') {
            chunk = chunk * 10 + (s[count] - '0');
            count++;
        }
        s += count;
        falcon_big_set_i64(&base, chunk_base[count]);
        falcon_big_set_i64(&digit, chunk);
        falcon_big_mul(dst, dst, &base);
        falcon_big_add(dst, dst, &digit);
    }
    if (neg && dst->len != 0) {
        dst->neg = 1;
    }
    falcon_big_free(&base);
    falcon_big_free(&digit);
    *p = s;
}

void vec_big(const vec_file *v, const char *field, falcon_big *dst)
{
    const char *p = require(v, field);
    parse_header(&p);
    parse_big(dst, &p);
}

size_t vec_big_list(const vec_file *v, const char *field, falcon_big *dst, size_t cap)
{
    const char *p = require(v, field);
    size_t count = parse_header(&p);
    if (count > cap) {
        die("Liste zu lang", field);
    }
    for (size_t i = 0; i < count; i++) {
        parse_big(&dst[i], &p);
    }
    return count;
}

int big_list_equal(const falcon_big *a, const falcon_big *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (falcon_big_cmp(&a[i], &b[i]) != 0) {
            return 0;
        }
    }
    return 1;
}

static size_t tokens_for(size_t n)
{
    return n == 1 ? 1 : 2 * n + 2 * tokens_for(n / 2);
}

static falcon_tree_node *load_tree_rec(falcon_tree *t, const double **p, size_t n)
{
    falcon_tree_node *node = &t->nodes[t->nnodes++];
    node->ell = NULL;
    node->left = NULL;
    node->right = NULL;
    node->sigma = 0.0;
    if (n == 1) {
        node->sigma = *(*p)++;
        return node;
    }
    node->ell = &t->ell[t->nell];
    t->nell += n;
    for (size_t i = 0; i < n; i++) {
        node->ell[i].re = *(*p)++;
        node->ell[i].im = *(*p)++;
    }
    node->left = load_tree_rec(t, p, n / 2);
    node->right = load_tree_rec(t, p, n / 2);
    return node;
}

size_t vec_tree(const vec_file *v, const char *field, falcon_tree *t)
{
    static double tokens[VEC_MAX_TREE_TOKENS];
    size_t count = vec_doubles(v, field, tokens, VEC_MAX_TREE_TOKENS);
    size_t n = 1;

    while (tokens_for(n) < count) {
        n *= 2;
    }
    if (tokens_for(n) != count) {
        die("Baum mit unpassender Grösse", field);
    }
    const double *p = tokens;
    t->nnodes = 0;
    t->nell = 0;
    load_tree_rec(t, &p, n);
    return n;
}

size_t tree_tokens(double *out, const falcon_tree_node *node, size_t n)
{
    if (n == 1) {
        out[0] = node->sigma;
        return 1;
    }
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        out[count++] = node->ell[i].re;
        out[count++] = node->ell[i].im;
    }
    count += tree_tokens(out + count, node->left, n / 2);
    count += tree_tokens(out + count, node->right, n / 2);
    return count;
}

static void fixed_random_bytes(void *ctx, uint8_t *out, size_t k)
{
    fixed_rng_state *s = ctx;
    if (s->pos + k > s->len) {
        /* Sofort abbrechen: Mit Ersatzwerten könnte ein Fehler im Sampler endlos laufen. */
        die("Zufallsbytes aufgebraucht", "FixedRNG");
    }
    memcpy(out, s->data + s->pos, k);
    s->pos += k;
}

falcon_rng fixed_rng(fixed_rng_state *state, const uint8_t *data, size_t len)
{
    state->data = data;
    state->len = len;
    state->pos = 0;
    falcon_rng rng = {fixed_random_bytes, state};
    return rng;
}

static void shake_random_bytes(void *ctx, uint8_t *out, size_t k)
{
    falcon_shake256_extract(ctx, out, k);
}

falcon_rng shake_rng(falcon_shake256_ctx *ctx, const uint8_t *seed, size_t len)
{
    falcon_shake256_init(ctx);
    falcon_shake256_inject(ctx, seed, len);
    falcon_shake256_flip(ctx);
    falcon_rng rng = {shake_random_bytes, ctx};
    return rng;
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
