#include "encoding.h"

#include <string.h>

/* Bitbreite von f und g, indiziert mit log2(n) (§3.11.5). */
static const int FG_BITS[11] = {0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5};

/* ------------------------------------------------------------------------- */
/* Bits lesen und schreiben, oberstes Bit zuerst (§3.11.1)                   */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint8_t *buf;
    size_t len;
    unsigned acc;
    int nbits;
    size_t total;
} bit_writer;

static void writer_init(bit_writer *w, uint8_t *buf)
{
    w->buf = buf;
    w->len = 0;
    w->acc = 0;
    w->nbits = 0;
    w->total = 0;
}

static void write_bit(bit_writer *w, unsigned bit)
{
    w->acc = ((w->acc << 1) | (bit & 1u)) & 0xFFu;
    w->nbits++;
    w->total++;
    if (w->nbits == 8) {
        w->buf[w->len++] = (uint8_t)w->acc;
        w->acc = 0;
        w->nbits = 0;
    }
}

static void write_bits(bit_writer *w, uint32_t value, int length)
{
    for (int i = length - 1; i >= 0; i--) {
        write_bit(w, (value >> i) & 1u);
    }
}

static size_t writer_finish(bit_writer *w)
{
    if (w->nbits != 0) {
        w->buf[w->len++] = (uint8_t)(w->acc << (8 - w->nbits));
        w->acc = 0;
        w->nbits = 0;
    }
    return w->len;
}

typedef struct {
    const uint8_t *data;
    size_t pos;
    size_t total;
} bit_reader;

static void reader_init(bit_reader *r, const uint8_t *data, size_t len)
{
    r->data = data;
    r->pos = 0;
    r->total = len * 8;
}

/* 0 oder 1; -1 am Ende der Daten (Python: EOFError). */
static int read_bit(bit_reader *r)
{
    if (r->pos >= r->total) {
        return -1;
    }
    int bit = (r->data[r->pos >> 3] >> (7 - (r->pos & 7))) & 1;
    r->pos++;
    return bit;
}

/* length <= 31 Bits; -1, wenn nicht mehr so viele Bits vorhanden sind. */
static int32_t read_bits(bit_reader *r, int length)
{
    if (r->pos + (size_t)length > r->total) {
        return -1;
    }
    int32_t v = 0;
    for (int i = 0; i < length; i++) {
        v = (v << 1) | read_bit(r);
    }
    return v;
}

/* 1, wenn alle restlichen Bits 0 sind. */
static int rest_is_zero(bit_reader *r)
{
    while (r->pos < r->total) {
        if (read_bit(r) != 0) {
            return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------------- */
/* Signatur-Kompression (Alg. 17 / Alg. 18)                                  */
/* ------------------------------------------------------------------------- */

int falcon_compress(uint8_t *out, size_t *out_len, const int32_t *s, const falcon_params *p)
{
    bit_writer w;
    size_t padded_len = p->sig_bytelen - 41;
    size_t slen = padded_len * 8;

    writer_init(&w, out);
    for (size_t i = 0; i < p->n; i++) {
        unsigned sign = s[i] < 0 ? 1u : 0u;
        uint32_t av = s[i] < 0 ? (uint32_t)0 - (uint32_t)s[i] : (uint32_t)s[i];
        uint32_t low7 = av & 0x7Fu;
        uint32_t k = av >> 7;

        if (w.total + 1 + 7 + (size_t)k + 1 > slen) {
            return FALCON_ERR_NONE;
        }
        write_bit(&w, sign);
        write_bits(&w, low7, 7);
        for (uint32_t j = 0; j < k; j++) {
            write_bit(&w, 0);
        }
        write_bit(&w, 1);
    }
    while (w.total < slen) {
        write_bit(&w, 0);
    }
    *out_len = writer_finish(&w);
    return FALCON_OK;
}

int falcon_decompress(int32_t *s, const uint8_t *b, size_t len, const falcon_params *p)
{
    bit_reader r;

    if (len == 0 || p->sig_bytelen < 41) {
        return FALCON_ERR_NONE;
    }
    size_t padded_len = p->sig_bytelen - 41;
    if (len > padded_len + 1) {
        return FALCON_ERR_NONE;
    }
    int padded = (len == padded_len);
    if (!padded && b[len - 1] == 0) {
        return FALCON_ERR_NONE;
    }

    reader_init(&r, b, len);
    for (size_t i = 0; i < p->n; i++) {
        int sign = read_bit(&r);
        int32_t low7 = read_bits(&r, 7);
        if (sign < 0 || low7 < 0) {
            return FALCON_ERR_NONE;
        }
        int32_t k = 0;
        for (;;) {
            int bit = read_bit(&r);
            if (bit < 0) {
                return FALCON_ERR_NONE;
            }
            if (bit != 0) {
                break;
            }
            k++;
            if (k > (INT32_MAX >> 7)) {
                return FALCON_ERR_NONE; /* in C nicht darstellbar */
            }
        }
        int32_t value = low7 | (k << 7);
        if (sign != 0) {
            if (value == 0) {
                return FALCON_ERR_NONE;
            }
            value = -value;
        }
        s[i] = value;
    }

    /* Ungepolstert: Das Ende muss im letzten Byte liegen, Restbits 0. */
    if (!padded && r.pos <= (len - 1) * 8) {
        return FALCON_ERR_NONE;
    }
    return rest_is_zero(&r) ? FALCON_OK : FALCON_ERR_NONE;
}

/* ------------------------------------------------------------------------- */
/* Public Key (§3.11.4)                                                      */
/* ------------------------------------------------------------------------- */

int falcon_encode_pk(uint8_t *out, size_t *out_len, const int32_t *h, size_t n)
{
    bit_writer w;
    int logn = falcon_logn(n);

    if (logn < 0) {
        return FALCON_ERR_VALUE;
    }
    for (size_t i = 0; i < n; i++) {
        if (h[i] < 0 || h[i] >= FALCON_Q) {
            return FALCON_ERR_VALUE;
        }
    }
    writer_init(&w, out);
    write_bits(&w, (uint32_t)logn, 8);
    for (size_t i = 0; i < n; i++) {
        write_bits(&w, (uint32_t)h[i], 14);
    }
    *out_len = writer_finish(&w);
    return FALCON_OK;
}

int falcon_decode_pk(int32_t *h, size_t *n, const uint8_t *b, size_t len)
{
    bit_reader r;

    if (len == 0 || (b[0] >> 4) != 0) {
        return FALCON_ERR_VALUE;
    }
    int logn = b[0] & 0x0F;
    if (logn < 1 || logn > 10) {
        return FALCON_ERR_VALUE;
    }
    size_t count = (size_t)1 << logn;
    if (len != 1 + (14 * count + 7) / 8) {
        return FALCON_ERR_VALUE;
    }
    reader_init(&r, b + 1, len - 1);
    for (size_t i = 0; i < count; i++) {
        int32_t v = read_bits(&r, 14);
        if (v < 0 || v >= FALCON_Q) {
            return FALCON_ERR_VALUE;
        }
        h[i] = v;
    }
    if (!rest_is_zero(&r)) {
        return FALCON_ERR_VALUE;
    }
    *n = count;
    return FALCON_OK;
}

/* ------------------------------------------------------------------------- */
/* Secret Key (§3.11.5)                                                      */
/* ------------------------------------------------------------------------- */

/* Der Minimalwert -2^(bits-1) ist verboten. */
static int check_range(const int32_t *a, size_t n, int bits)
{
    int32_t maxv = ((int32_t)1 << (bits - 1)) - 1;
    for (size_t i = 0; i < n; i++) {
        if (a[i] < -maxv || a[i] > maxv) {
            return FALCON_ERR_VALUE;
        }
    }
    return FALCON_OK;
}

static void write_signed(bit_writer *w, const int32_t *a, size_t n, int bits)
{
    /* Erst vorzeichenlos machen, dann maskieren (Zweierkomplement). */
    uint32_t mask = ((uint32_t)1 << bits) - 1u;
    for (size_t i = 0; i < n; i++) {
        write_bits(w, (uint32_t)a[i] & mask, bits);
    }
}

int falcon_encode_sk(uint8_t *out, size_t *out_len, const int32_t *f, const int32_t *g,
                     const int32_t *F, size_t n)
{
    bit_writer w;
    int logn = falcon_logn(n);

    if (logn < 0) {
        return FALCON_ERR_VALUE;
    }
    int bits = FG_BITS[logn];
    if (check_range(f, n, bits) != FALCON_OK || check_range(g, n, bits) != FALCON_OK
        || check_range(F, n, 8) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    writer_init(&w, out);
    write_bits(&w, 0x50u | (uint32_t)logn, 8);
    write_signed(&w, f, n, bits);
    write_signed(&w, g, n, bits);
    write_signed(&w, F, n, 8);
    *out_len = writer_finish(&w);
    return FALCON_OK;
}

static int read_signed(bit_reader *r, int32_t *a, size_t n, int bits)
{
    int32_t top = (int32_t)1 << (bits - 1);
    for (size_t i = 0; i < n; i++) {
        int32_t raw = read_bits(r, bits);
        if (raw < 0 || raw == top) {
            return FALCON_ERR_VALUE;
        }
        a[i] = (raw >= top) ? raw - 2 * top : raw;
    }
    return FALCON_OK;
}

int falcon_decode_sk(int32_t *f, int32_t *g, int32_t *F, size_t *n, const uint8_t *b, size_t len)
{
    bit_reader r;

    if (len == 0 || (b[0] >> 4) != 5) {
        return FALCON_ERR_VALUE;
    }
    int logn = b[0] & 0x0F;
    if (logn < 1 || logn > 10) {
        return FALCON_ERR_VALUE;
    }
    size_t count = (size_t)1 << logn;
    int bits = FG_BITS[logn];
    if (len != 1 + (2 * count * (size_t)bits) / 8 + count) {
        return FALCON_ERR_VALUE;
    }
    reader_init(&r, b + 1, len - 1);
    if (read_signed(&r, f, count, bits) != FALCON_OK
        || read_signed(&r, g, count, bits) != FALCON_OK
        || read_signed(&r, F, count, 8) != FALCON_OK || r.pos != r.total) {
        return FALCON_ERR_VALUE;
    }
    *n = count;
    return FALCON_OK;
}

/* ------------------------------------------------------------------------- */
/* Signatur (§3.11.3)                                                        */
/* ------------------------------------------------------------------------- */

int falcon_encode_sig(uint8_t *out, size_t *out_len, const falcon_signature *sig,
                      const falcon_params *p)
{
    int logn = falcon_logn(p->n);

    if (logn < 0) {
        return FALCON_ERR_VALUE;
    }
    out[0] = (uint8_t)(0x30 | logn);
    memcpy(out + 1, sig->salt, FALCON_SALT_BYTES);
    memcpy(out + 1 + FALCON_SALT_BYTES, sig->s2_encoded, sig->s2_len);
    *out_len = 1 + FALCON_SALT_BYTES + sig->s2_len;
    return FALCON_OK;
}

int falcon_decode_sig(falcon_signature *sig, const uint8_t *b, size_t len, const falcon_params *p)
{
    int logn = falcon_logn(p->n);
    size_t s2_len = len - 1 - FALCON_SALT_BYTES;

    /* len <= sig_bytelen + 1 wegen KAT Falcon-1024 count = 82. */
    if (len < 42 || len > p->sig_bytelen + 1 || logn < 0 || s2_len > FALCON_MAX_S2_BYTES) {
        return FALCON_ERR_VALUE;
    }
    if (b[0] != (0x30 | logn)) {
        return FALCON_ERR_VALUE;
    }
    memcpy(sig->salt, b + 1, FALCON_SALT_BYTES);
    memcpy(sig->s2_encoded, b + 1 + FALCON_SALT_BYTES, s2_len);
    sig->s2_len = s2_len;
    return FALCON_OK;
}

/* ------------------------------------------------------------------------- */
/* KAT-Format (§3.11.6)                                                      */
/* ------------------------------------------------------------------------- */

int falcon_decode_kat_message(const uint8_t **msg, size_t *msg_len, falcon_signature *sig,
                              const uint8_t *sm, size_t sm_len)
{
    if (sm_len < 2 + FALCON_SALT_BYTES + 1) {
        return FALCON_ERR_VALUE;
    }
    size_t siglen = ((size_t)sm[0] << 8) | sm[1];
    if (siglen < 1 || sm_len < 2 + FALCON_SALT_BYTES + siglen) {
        return FALCON_ERR_VALUE;
    }
    size_t mlen = sm_len - 2 - FALCON_SALT_BYTES - siglen;
    const uint8_t *encoded = sm + 2 + FALCON_SALT_BYTES + mlen;

    if ((encoded[0] & 0xF0) != 0x20) {
        return FALCON_ERR_VALUE;
    }
    int logn = encoded[0] & 0x0F;
    if (logn < 1 || logn > 10 || siglen - 1 > FALCON_MAX_S2_BYTES) {
        return FALCON_ERR_VALUE;
    }
    memcpy(sig->salt, sm + 2, FALCON_SALT_BYTES);
    memcpy(sig->s2_encoded, encoded + 1, siglen - 1);
    sig->s2_len = siglen - 1;
    *msg = sm + 2 + FALCON_SALT_BYTES;
    *msg_len = mlen;
    return FALCON_OK;
}
