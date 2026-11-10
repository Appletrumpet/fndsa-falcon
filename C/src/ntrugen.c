#include "ntrugen.h"

#include <math.h>

#include "cplx.h"
#include "fft.h"
#include "modq.h"
#include "poly.h"

#define MAX_ATTEMPTS 5000

int falcon_generate_ntru_keys(int32_t *f, int32_t *g, int32_t *F, int32_t *G, const falcon_params *p,
                              const falcon_rng *rng)
{
    double gs_bound = 1.17 * sqrt((double)p->q);
    size_t n = p->n;
    falcon_big *bf = falcon_poly_new(n), *bg = falcon_poly_new(n);
    falcon_big *bF = falcon_poly_new(n), *bG = falcon_poly_new(n);
    int result = FALCON_ERR_KEYGEN;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        if (falcon_sample_short_poly(f, p, rng) != FALCON_OK
            || falcon_sample_short_poly(g, p, rng) != FALCON_OK) {
            result = FALCON_ERR_VALUE;
            break;
        }
        if (falcon_is_invertible_mod_q(f, n) != 1) {
            continue;
        }
        double gamma = falcon_gram_schmidt_norm(f, g, n, p);
        if (!isfinite(gamma) || gamma > gs_bound) {
            continue;
        }
        falcon_poly_from_ints(bf, f, n);
        falcon_poly_from_ints(bg, g, n);
        if (falcon_solve_ntru(bF, bG, bf, bg, n, p) != FALCON_OK) {
            continue;
        }
        int fits = 1;
        for (size_t i = 0; i < n; i++) {
            fits &= falcon_big_to_i32(&bF[i], &F[i]) & falcon_big_to_i32(&bG[i], &G[i]);
        }
        if (!fits) {
            continue; /* In Python unbeschränkt; reduzierte F, G sind klein. */
        }
        result = FALCON_OK;
        break;
    }
    falcon_poly_free(bf, n);
    falcon_poly_free(bg, n);
    falcon_poly_free(bF, n);
    falcon_poly_free(bG, n);
    return result;
}

int falcon_sample_short_poly(int32_t *a, const falcon_params *p, const falcon_rng *rng)
{
    size_t m = 4096 / p->n;
    double sigma_star = 1.17 * sqrt((double)p->q / 8192.0);

    for (size_t i = 0; i < p->n; i++) {
        int32_t s = 0;
        for (size_t j = 0; j < m; j++) {
            int32_t z;
            int rc = falcon_sample_integer_gaussian(&z, 0.0, sigma_star, p, rng);
            if (rc != FALCON_OK) {
                return rc;
            }
            s += z;
        }
        a[i] = s;
    }
    return FALCON_OK;
}

double falcon_gram_schmidt_norm(const int32_t *f, const int32_t *g, size_t n, const falcon_params *p)
{
    double values[FALCON_MAX_N];
    falcon_cplx fh[FALCON_MAX_N], gh[FALCON_MAX_N];
    double first = sqrt((double)(falcon_norm_sq(f, n) + falcon_norm_sq(g, n)));
    double q2 = (double)((int64_t)p->q * p->q);

    falcon_ints_to_doubles(values, f, n);
    (void)falcon_fft(fh, values, n);
    falcon_ints_to_doubles(values, g, n);
    (void)falcon_fft(gh, values, n);

    double total = 0.0;
    for (size_t k = 0; k < n; k++) {
        double den = (fh[k].re * fh[k].re + fh[k].im * fh[k].im)
                     + (gh[k].re * gh[k].re + gh[k].im * gh[k].im);
        if (den <= 0.0) {
            return HUGE_VAL;
        }
        total += q2 / den;
    }
    double second = sqrt(total / (double)n);
    return second > first ? second : first;
}

/* fG - gF == q? */
static int check_ntru(const falcon_big *f, const falcon_big *g, const falcon_big *F, const falcon_big *G,
                      size_t n, int32_t q)
{
    falcon_big *fG = falcon_poly_new(n), *gF = falcon_poly_new(n), *lhs = falcon_poly_new(n);
    falcon_big q_big;
    int ok = 1;

    falcon_big_init(&q_big);
    falcon_big_set_i64(&q_big, q);
    falcon_poly_mul(fG, f, G, n);
    falcon_poly_mul(gF, g, F, n);
    falcon_poly_sub(lhs, fG, gF, n);
    if (falcon_big_cmp(&lhs[0], &q_big) != 0) {
        ok = 0;
    }
    for (size_t i = 1; i < n; i++) {
        if (!falcon_big_is_zero(&lhs[i])) {
            ok = 0;
        }
    }
    falcon_big_free(&q_big);
    falcon_poly_free(fG, n);
    falcon_poly_free(gF, n);
    falcon_poly_free(lhs, n);
    return ok;
}

int falcon_solve_ntru(falcon_big *F, falcon_big *G, const falcon_big *f, const falcon_big *g,
                      size_t n, const falcon_params *p)
{
    if (n == 0 || (n & (n - 1)) != 0) {
        return FALCON_ERR_NONE;
    }

    if (n == 1) {
        falcon_big d, u, v, q, one;
        int rc = FALCON_OK;

        falcon_big_init(&d);
        falcon_big_init(&u);
        falcon_big_init(&v);
        falcon_big_init(&q);
        falcon_big_init(&one);
        falcon_big_set_i64(&one, 1);
        falcon_big_set_i64(&q, p->q);
        falcon_xgcd(&d, &u, &v, &f[0], &g[0]);
        if (falcon_big_cmp(&d, &one) != 0) {
            rc = FALCON_ERR_NONE;
        } else {
            falcon_big_mul(&F[0], &v, &q);
            falcon_big_mul(&G[0], &u, &q);
            if (!check_ntru(f, g, F, G, 1, p->q)) {
                rc = FALCON_ERR_NONE;
            }
        }
        falcon_big_free(&d);
        falcon_big_free(&u);
        falcon_big_free(&v);
        falcon_big_free(&q);
        falcon_big_free(&one);
        return rc;
    }

    size_t h = n / 2;
    falcon_big *fn = falcon_poly_new(h), *gn = falcon_poly_new(h);
    falcon_big *Fp = falcon_poly_new(h), *Gp = falcon_poly_new(h);
    falcon_big *lifted = falcon_poly_new(n), *conj = falcon_poly_new(n);
    int rc;

    (void)falcon_field_norm(fn, f, n);
    (void)falcon_field_norm(gn, g, n);
    rc = falcon_solve_ntru(Fp, Gp, fn, gn, h, p);
    if (rc == FALCON_OK) {
        falcon_poly_lift(lifted, Fp, h);
        falcon_poly_galois_conjugate(conj, g, n);
        falcon_poly_mul(F, lifted, conj, n);
        falcon_poly_lift(lifted, Gp, h);
        falcon_poly_galois_conjugate(conj, f, n);
        falcon_poly_mul(G, lifted, conj, n);
        falcon_reduce(f, g, F, G, n);
        if (!check_ntru(f, g, F, G, n, p->q)) {
            rc = FALCON_ERR_NONE;
        }
    }
    falcon_poly_free(fn, h);
    falcon_poly_free(gn, h);
    falcon_poly_free(Fp, h);
    falcon_poly_free(Gp, h);
    falcon_poly_free(lifted, n);
    falcon_poly_free(conj, n);
    return rc;
}

int falcon_field_norm(falcon_big *out, const falcon_big *a, size_t n)
{
    if (n < 2 || (n & 1) != 0) {
        return FALCON_ERR_VALUE;
    }
    size_t m = n / 2;
    falcon_big *a0 = falcon_poly_new(m), *a1 = falcon_poly_new(m);
    falcon_big *s0 = falcon_poly_new(m), *s1 = falcon_poly_new(m);

    (void)falcon_poly_split(a0, a1, a, n);
    falcon_poly_mul(s0, a0, a0, m);
    falcon_poly_mul(s1, a1, a1, m);

    /* x * s1 in Z[x]/(x^m + 1): -s1[m-1] + s1[0] x + ... */
    falcon_big_add(&out[0], &s0[0], &s1[m - 1]);
    for (size_t i = 1; i < m; i++) {
        falcon_big_sub(&out[i], &s0[i], &s1[i - 1]);
    }
    falcon_poly_free(a0, m);
    falcon_poly_free(a1, m);
    falcon_poly_free(s0, m);
    falcon_poly_free(s1, m);
    return FALCON_OK;
}

void falcon_xgcd(falcon_big *d, falcon_big *u, falcon_big *v, const falcon_big *a, const falcon_big *b)
{
    falcon_big old_r, r, old_s, s, old_t, t, q, rem, product, tmp;
    falcon_big *all[] = {&old_r, &r, &old_s, &s, &old_t, &t, &q, &rem, &product, &tmp};

    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
        falcon_big_init(all[i]);
    }
    if (falcon_big_is_zero(a) && falcon_big_is_zero(b)) {
        falcon_big_set_i64(d, 0);
        falcon_big_set_i64(u, 0);
        falcon_big_set_i64(v, 0);
    } else {
        falcon_big_copy(&old_r, a);
        old_r.neg = 0;
        falcon_big_copy(&r, b);
        r.neg = 0;
        falcon_big_set_i64(&old_s, 1);
        falcon_big_set_i64(&s, 0);
        falcon_big_set_i64(&old_t, 0);
        falcon_big_set_i64(&t, 1);

        while (!falcon_big_is_zero(&r)) {
            falcon_big_divmod_abs(&q, &rem, &old_r, &r);

            falcon_big_copy(&old_r, &r);
            falcon_big_copy(&r, &rem);

            falcon_big_mul(&product, &q, &s);
            falcon_big_sub(&tmp, &old_s, &product);
            falcon_big_copy(&old_s, &s);
            falcon_big_copy(&s, &tmp);

            falcon_big_mul(&product, &q, &t);
            falcon_big_sub(&tmp, &old_t, &product);
            falcon_big_copy(&old_t, &t);
            falcon_big_copy(&t, &tmp);
        }

        falcon_big_copy(d, &old_r);
        /* u = x * sa, v = -y * sb */
        if (a->neg) {
            falcon_big_neg(u, &old_s);
        } else {
            falcon_big_copy(u, &old_s);
        }
        if (b->neg) {
            falcon_big_copy(v, &old_t);
        } else {
            falcon_big_neg(v, &old_t);
        }
    }
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
        falcon_big_free(all[i]);
    }
}

double falcon_scaled_float(const falcon_big *c, size_t scale)
{
    if (falcon_big_is_zero(c)) {
        return 0.0;
    }
    size_t bl = falcon_big_bit_length(c);
    double sign = c->neg ? -1.0 : 1.0;

    if (bl <= 53) {
        double value = (double)falcon_big_low64_shr(c, 0);
        return ldexp(sign * value, -(int)scale);
    }

    /* Bewusst keine Umwandlung aus einer Bibliothek: eigene Rundung wie in Python. */
    size_t shift = bl - 53;
    uint64_t mant = falcon_big_low64_shr(c, shift);
    if (falcon_big_get_bit(c, shift - 1)) {
        mant += 1;
        if (mant == ((uint64_t)1 << 53)) {
            mant >>= 1;
            shift += 1;
        }
    }
    return ldexp(sign * (double)mant, (int)shift - (int)scale);
}

void falcon_round_scaled_float(falcon_big *out, double x, int exp)
{
    if (x == 0.0 || !isfinite(x)) {
        falcon_big_set_i64(out, 0);
        return;
    }

    int e;
    double m = frexp(x, &e);
    /* m * 2^53 ist exakt und ganzzahlig. */
    int64_t m_int = (int64_t)llrint(m * 0x1p53);
    if (m_int == 0) {
        falcon_big_set_i64(out, 0);
        return;
    }
    if (m_int == ((int64_t)1 << 53) || m_int == -((int64_t)1 << 53)) {
        m_int /= 2;
        e += 1;
    }

    int shift = e + exp - 53;
    if (shift >= 0) {
        falcon_big value;
        falcon_big_init(&value);
        falcon_big_set_i64(&value, m_int);
        falcon_big_shl(out, &value, (size_t)shift);
        falcon_big_free(&value);
        return;
    }

    /* Für -shift >= 54 ist das Ergebnis 0 (m_int < 2^53); so bleibt die Schiebeweite gültig. */
    if (-shift >= 54) {
        falcon_big_set_i64(out, 0);
        return;
    }
    uint64_t denom = (uint64_t)1 << (unsigned)(-shift);
    uint64_t a = m_int < 0 ? (uint64_t)(-m_int) : (uint64_t)m_int;
    uint64_t q = (a + denom / 2) / denom;
    falcon_big_set_i64(out, m_int < 0 ? -(int64_t)q : (int64_t)q);
}

static size_t max_bit(const falcon_big *a, const falcon_big *b, size_t n)
{
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        size_t la = falcon_big_bit_length(&a[i]);
        size_t lb = falcon_big_bit_length(&b[i]);
        if (la > m) {
            m = la;
        }
        if (lb > m) {
            m = lb;
        }
    }
    return m;
}

static void fft_scaled(falcon_cplx *out, const falcon_big *a, size_t scale, size_t n)
{
    double values[FALCON_MAX_N];
    for (size_t i = 0; i < n; i++) {
        values[i] = falcon_scaled_float(&a[i], scale);
    }
    (void)falcon_fft(out, values, n);
}

void falcon_reduce(const falcon_big *f, const falcon_big *g, falcon_big *F, falcon_big *G, size_t n)
{
    falcon_cplx f_hat[FALCON_MAX_N], g_hat[FALCON_MAX_N];
    falcon_cplx F_hat[FALCON_MAX_N], G_hat[FALCON_MAX_N], mu_hat[FALCON_MAX_N];
    double denom[FALCON_MAX_N], mu[FALCON_MAX_N];

    size_t bits_fg = max_bit(f, g, n);
    if (n == 0 || bits_fg == 0) {
        return; /* f = g = 0: unverändert */
    }

    /* f und g so skalieren, dass ihre FFT-Werte sicher im Double-Bereich bleiben. */
    size_t scale_f = bits_fg > 350 ? bits_fg - 350 : 0;
    fft_scaled(f_hat, f, scale_f, n);
    fft_scaled(g_hat, g, scale_f, n);

    for (size_t i = 0; i < n; i++) {
        double d = falcon_c_add(falcon_c_mul(f_hat[i], falcon_c_adj(f_hat[i])),
                                falcon_c_mul(g_hat[i], falcon_c_adj(g_hat[i]))).re;
        if (isinf(d)) {
            d = 1e308;
        } else if (!isfinite(d) || d <= 0.0) {
            d = 1e-300;
        }
        denom[i] = d;
    }

    falcon_big *k = falcon_poly_new(n), *product = falcon_poly_new(n);

    for (;;) {
        size_t max_fg = max_bit(F, G, n);
        if (max_fg == 0) {
            break;
        }
        size_t scale_F = max_fg > 500 ? max_fg - 500 : 0;
        fft_scaled(F_hat, F, scale_F, n);
        fft_scaled(G_hat, G, scale_F, n);

        for (size_t i = 0; i < n; i++) {
            falcon_cplx num = falcon_c_add(falcon_c_mul(F_hat[i], falcon_c_adj(f_hat[i])),
                                           falcon_c_mul(G_hat[i], falcon_c_adj(g_hat[i])));
            mu_hat[i].re = num.re / denom[i];
            mu_hat[i].im = num.im / denom[i];
        }
        (void)falcon_ifft(mu, mu_hat, n);

        int exp = (int)scale_F - (int)scale_f;
        int all_zero = 1;
        for (size_t i = 0; i < n; i++) {
            falcon_round_scaled_float(&k[i], mu[i], exp);
            all_zero &= falcon_big_is_zero(&k[i]);
        }
        if (all_zero) {
            break;
        }

        falcon_poly_mul(product, k, f, n);
        falcon_poly_sub(F, F, product, n);
        falcon_poly_mul(product, k, g, n);
        falcon_poly_sub(G, G, product, n);
    }
    falcon_poly_free(k, n);
    falcon_poly_free(product, n);
}

int falcon_recompute_G(int32_t *G, const int32_t *f, const int32_t *g, const int32_t *F, size_t n)
{
    int32_t gF[FALCON_MAX_N];
    int32_t G_mod[FALCON_MAX_N];

    if (falcon_mul_mod_q(gF, g, F, n) != FALCON_OK
        || falcon_div_mod_q(G_mod, gF, f, n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    falcon_center_mod_q(G, G_mod, n);
    return FALCON_OK;
}
