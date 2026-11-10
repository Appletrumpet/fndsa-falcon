#include "bigint.h"

#include <stdlib.h>
#include <string.h>

static void reserve(falcon_big *a, size_t cap)
{
    if (cap <= a->cap) {
        return;
    }
    uint32_t *p = realloc(a->limb, cap * sizeof *p);
    if (p == NULL) {
        abort();
    }
    a->limb = p;
    a->cap = cap;
}

static void trim(falcon_big *a)
{
    while (a->len > 0 && a->limb[a->len - 1] == 0) {
        a->len--;
    }
    if (a->len == 0) {
        a->neg = 0;
    }
}

void falcon_big_init(falcon_big *a)
{
    a->limb = NULL;
    a->len = 0;
    a->cap = 0;
    a->neg = 0;
}

void falcon_big_free(falcon_big *a)
{
    free(a->limb);
    falcon_big_init(a);
}

void falcon_big_set_i64(falcon_big *a, int64_t x)
{
    uint64_t m = x < 0 ? (uint64_t)0 - (uint64_t)x : (uint64_t)x;
    reserve(a, 2);
    a->limb[0] = (uint32_t)m;
    a->limb[1] = (uint32_t)(m >> 32);
    a->len = 2;
    a->neg = x < 0;
    trim(a);
}

void falcon_big_copy(falcon_big *r, const falcon_big *a)
{
    if (r == a) {
        return;
    }
    reserve(r, a->len);
    if (a->len != 0) {
        memcpy(r->limb, a->limb, a->len * sizeof *r->limb);
    }
    r->len = a->len;
    r->neg = a->neg;
}

int falcon_big_is_zero(const falcon_big *a)
{
    return a->len == 0;
}

static int cmp_abs(const falcon_big *a, const falcon_big *b)
{
    if (a->len != b->len) {
        return a->len < b->len ? -1 : 1;
    }
    for (size_t i = a->len; i > 0; i--) {
        if (a->limb[i - 1] != b->limb[i - 1]) {
            return a->limb[i - 1] < b->limb[i - 1] ? -1 : 1;
        }
    }
    return 0;
}

int falcon_big_cmp(const falcon_big *a, const falcon_big *b)
{
    if (a->neg != b->neg) {
        return a->neg ? -1 : 1;
    }
    return a->neg ? -cmp_abs(a, b) : cmp_abs(a, b);
}

/* r = |a| + |b|; r darf a oder b sein. */
static void add_abs(falcon_big *r, const falcon_big *a, const falcon_big *b)
{
    size_t la = a->len, lb = b->len;
    size_t max = la > lb ? la : lb;

    reserve(r, max + 1);
    uint64_t carry = 0;
    for (size_t i = 0; i < max; i++) {
        uint64_t s = carry;
        if (i < la) {
            s += a->limb[i];
        }
        if (i < lb) {
            s += b->limb[i];
        }
        r->limb[i] = (uint32_t)s;
        carry = s >> 32;
    }
    r->limb[max] = (uint32_t)carry;
    r->len = max + 1;
}

/* r = |a| - |b| mit |a| >= |b|; r darf a oder b sein. */
static void sub_abs(falcon_big *r, const falcon_big *a, const falcon_big *b)
{
    size_t la = a->len, lb = b->len;

    reserve(r, la);
    uint64_t borrow = 0;
    for (size_t i = 0; i < la; i++) {
        uint64_t d = (uint64_t)a->limb[i] - (i < lb ? b->limb[i] : 0) - borrow;
        r->limb[i] = (uint32_t)d;
        borrow = (d >> 32) & 1u;
    }
    r->len = la;
}

/* r = a + (b_neg ? -|b| : |b|). */
static void add_signed(falcon_big *r, const falcon_big *a, const falcon_big *b, int b_neg)
{
    int a_neg = a->neg;
    if (a_neg == b_neg) {
        add_abs(r, a, b);
        r->neg = a_neg;
    } else if (cmp_abs(a, b) >= 0) {
        sub_abs(r, a, b);
        r->neg = a_neg;
    } else {
        sub_abs(r, b, a);
        r->neg = b_neg;
    }
    trim(r);
}

void falcon_big_add(falcon_big *r, const falcon_big *a, const falcon_big *b)
{
    add_signed(r, a, b, b->neg);
}

void falcon_big_sub(falcon_big *r, const falcon_big *a, const falcon_big *b)
{
    add_signed(r, a, b, !b->neg);
}

void falcon_big_neg(falcon_big *r, const falcon_big *a)
{
    falcon_big_copy(r, a);
    if (r->len != 0) {
        r->neg = !r->neg;
    }
}

void falcon_big_mul(falcon_big *r, const falcon_big *a, const falcon_big *b)
{
    size_t la = a->len, lb = b->len;
    int neg = a->neg != b->neg;

    if (la == 0 || lb == 0) {
        r->len = 0;
        r->neg = 0;
        return;
    }

    uint32_t *out = calloc(la + lb, sizeof *out);
    if (out == NULL) {
        abort();
    }
    for (size_t i = 0; i < la; i++) {
        uint64_t carry = 0;
        uint64_t x = a->limb[i];
        for (size_t j = 0; j < lb; j++) {
            uint64_t t = x * b->limb[j] + out[i + j] + carry;
            out[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        out[i + lb] = (uint32_t)carry;
    }
    free(r->limb);
    r->limb = out;
    r->cap = la + lb;
    r->len = la + lb;
    r->neg = neg;
    trim(r);
}

void falcon_big_shl(falcon_big *r, const falcon_big *a, size_t bits)
{
    size_t words = bits / 32;
    unsigned shift = (unsigned)(bits % 32);
    size_t la = a->len;
    int neg = a->neg;

    if (la == 0) {
        r->len = 0;
        r->neg = 0;
        return;
    }
    reserve(r, la + words + 1);
    uint32_t top = shift ? a->limb[la - 1] >> (32 - shift) : 0;
    r->limb[la + words] = top;
    for (size_t i = la; i > 0; i--) {
        uint32_t v = a->limb[i - 1] << shift;
        if (shift != 0 && i >= 2) {
            v |= a->limb[i - 2] >> (32 - shift);
        }
        r->limb[i - 1 + words] = v;
    }
    memset(r->limb, 0, words * sizeof *r->limb);
    r->len = la + words + 1;
    r->neg = neg;
    trim(r);
}

void falcon_big_shr_abs(falcon_big *r, const falcon_big *a, size_t bits)
{
    size_t words = bits / 32;
    unsigned shift = (unsigned)(bits % 32);
    size_t la = a->len;

    if (words >= la) {
        r->len = 0;
        r->neg = 0;
        return;
    }
    size_t count = la - words;
    reserve(r, count);
    for (size_t i = 0; i < count; i++) {
        uint32_t v = a->limb[i + words] >> shift;
        if (shift != 0 && i + words + 1 < la) {
            v |= a->limb[i + words + 1] << (32 - shift);
        }
        r->limb[i] = v;
    }
    r->len = count;
    r->neg = 0;
    trim(r);
}

size_t falcon_big_bit_length(const falcon_big *a)
{
    if (a->len == 0) {
        return 0;
    }
    uint32_t top = a->limb[a->len - 1];
    size_t bits = (a->len - 1) * 32;
    while (top != 0) {
        bits++;
        top >>= 1;
    }
    return bits;
}

int falcon_big_get_bit(const falcon_big *a, size_t i)
{
    size_t word = i / 32;
    if (word >= a->len) {
        return 0;
    }
    return (int)((a->limb[word] >> (i % 32)) & 1u);
}

uint64_t falcon_big_low64_shr(const falcon_big *a, size_t bits)
{
    uint64_t out = 0;
    for (unsigned k = 0; k < 64; k++) {
        out |= (uint64_t)(unsigned)falcon_big_get_bit(a, bits + k) << k;
    }
    return out;
}

int falcon_big_to_i32(const falcon_big *a, int32_t *out)
{
    if (a->len == 0) {
        *out = 0;
        return 1;
    }
    if (a->len > 1) {
        return 0;
    }
    uint32_t m = a->limb[0];
    if (a->neg) {
        if (m > 0x80000000u) {
            return 0;
        }
        *out = (int32_t)(0 - (int64_t)m);
        return 1;
    }
    if (m > 0x7FFFFFFFu) {
        return 0;
    }
    *out = (int32_t)m;
    return 1;
}

void falcon_big_divmod_abs(falcon_big *q, falcon_big *r, const falcon_big *a, const falcon_big *b)
{
    size_t n = b->len;

    if (cmp_abs(a, b) < 0) {
        falcon_big_copy(r, a);
        r->neg = 0;
        q->len = 0;
        q->neg = 0;
        return;
    }
    size_t m = a->len - n;
    reserve(q, a->len);

    if (n == 1) {
        uint64_t divisor = b->limb[0];
        uint64_t rem = 0;
        for (size_t i = a->len; i > 0; i--) {
            uint64_t cur = (rem << 32) | a->limb[i - 1];
            q->limb[i - 1] = (uint32_t)(cur / divisor);
            rem = cur % divisor;
        }
        q->len = a->len;
        q->neg = 0;
        trim(q);
        falcon_big_set_i64(r, (int64_t)rem);
        return;
    }

    /* Knuth, TAOCP 2, Algorithmus D. Normalisieren: oberstes Bit des Divisors setzen. */
    unsigned shift = 0;
    while (((b->limb[n - 1] << shift) & 0x80000000u) == 0) {
        shift++;
    }
    uint32_t *u = malloc((a->len + 1) * sizeof *u);
    uint32_t *v = malloc(n * sizeof *v);
    if (u == NULL || v == NULL) {
        abort();
    }
    u[a->len] = shift ? a->limb[a->len - 1] >> (32 - shift) : 0;
    for (size_t i = a->len; i > 0; i--) {
        u[i - 1] = a->limb[i - 1] << shift;
        if (shift != 0 && i >= 2) {
            u[i - 1] |= a->limb[i - 2] >> (32 - shift);
        }
    }
    for (size_t i = n; i > 0; i--) {
        v[i - 1] = b->limb[i - 1] << shift;
        if (shift != 0 && i >= 2) {
            v[i - 1] |= b->limb[i - 2] >> (32 - shift);
        }
    }

    const uint64_t base = (uint64_t)1 << 32;
    for (size_t j = m + 1; j > 0; j--) {
        size_t pos = j - 1;
        uint64_t num = ((uint64_t)u[pos + n] << 32) | u[pos + n - 1];
        uint64_t qhat = num / v[n - 1];
        uint64_t rhat = num % v[n - 1];

        while (qhat >= base || qhat * v[n - 2] > ((rhat << 32) | u[pos + n - 2])) {
            qhat--;
            rhat += v[n - 1];
            if (rhat >= base) {
                break;
            }
        }

        /* qhat * v von u abziehen. */
        uint64_t carry = 0, borrow = 0;
        for (size_t i = 0; i < n; i++) {
            uint64_t p = qhat * v[i] + carry;
            carry = p >> 32;
            uint64_t t = (uint64_t)u[pos + i] - (p & 0xFFFFFFFFu) - borrow;
            u[pos + i] = (uint32_t)t;
            borrow = (t >> 32) & 1u;
        }
        uint64_t t = (uint64_t)u[pos + n] - carry - borrow;
        u[pos + n] = (uint32_t)t;

        /* qhat war um eins zu gross: v wieder addieren. */
        if ((t >> 32) & 1u) {
            qhat--;
            uint64_t c = 0;
            for (size_t i = 0; i < n; i++) {
                uint64_t s = (uint64_t)u[pos + i] + v[i] + c;
                u[pos + i] = (uint32_t)s;
                c = s >> 32;
            }
            u[pos + n] = (uint32_t)((uint64_t)u[pos + n] + c);
        }
        q->limb[pos] = (uint32_t)qhat;
    }
    q->len = m + 1;
    q->neg = 0;
    trim(q);

    /* Rest: die unteren n Ziffern von u, zurückgeschoben. */
    reserve(r, n);
    for (size_t i = 0; i < n; i++) {
        r->limb[i] = u[i] >> shift;
        if (shift != 0) {
            r->limb[i] |= u[i + 1] << (32 - shift);
        }
    }
    r->len = n;
    r->neg = 0;
    trim(r);
    free(u);
    free(v);
}
