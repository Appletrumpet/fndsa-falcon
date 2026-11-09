#include "fft.h"

#include "cplx.h"
#include "fft_table.h"

static int valid_length(size_t n)
{
    return n != 0 && (n & (n - 1)) == 0 && n <= FALCON_MAX_N;
}

static falcon_cplx zeta(size_t h, size_t k)
{
    return FALCON_ZETAS[h + k];
}

/* Wie in Python: a[0::2] und a[1::2] transformieren, zusammenführen. stride ersetzt die Teillisten. */
static void fft_rec(falcon_cplx *out, const double *a, size_t stride, size_t n)
{
    if (n == 1) {
        out[0].re = a[0];
        out[0].im = 0.0;
        return;
    }
    size_t h = n / 2;
    fft_rec(out, a, 2 * stride, h);
    fft_rec(out + h, a + stride, 2 * stride, h);
    (void)falcon_merge_fft(out, out, out + h, h);
}

int falcon_fft(falcon_cplx *out, const double *a, size_t n)
{
    if (!valid_length(n)) {
        return FALCON_ERR_VALUE;
    }
    fft_rec(out, a, 1, n);
    return FALCON_OK;
}

/* tmp bietet Platz für 2n Werte. */
static void ifft_rec(double *out, size_t stride, const falcon_cplx *a, falcon_cplx *tmp, size_t n)
{
    if (n == 1) {
        out[0] = a[0].re;
        return;
    }
    size_t h = n / 2;
    (void)falcon_split_fft(tmp, tmp + h, a, n);
    ifft_rec(out, 2 * stride, tmp, tmp + n, h);
    ifft_rec(out + stride, 2 * stride, tmp + h, tmp + n, h);
}

int falcon_ifft(double *out, const falcon_cplx *a_hat, size_t n)
{
    falcon_cplx tmp[2 * FALCON_MAX_N];

    if (!valid_length(n)) {
        return FALCON_ERR_VALUE;
    }
    ifft_rec(out, 1, a_hat, tmp, n);
    return FALCON_OK;
}

void falcon_fft_add(falcon_cplx *out, const falcon_cplx *a, const falcon_cplx *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = falcon_c_add(a[i], b[i]);
    }
}

void falcon_fft_sub(falcon_cplx *out, const falcon_cplx *a, const falcon_cplx *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = falcon_c_sub(a[i], b[i]);
    }
}

void falcon_fft_mul(falcon_cplx *out, const falcon_cplx *a, const falcon_cplx *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = falcon_c_mul(a[i], b[i]);
    }
}

int falcon_fft_div(falcon_cplx *out, const falcon_cplx *a, const falcon_cplx *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (b[i].re == 0.0 && b[i].im == 0.0) {
            return FALCON_ERR_VALUE;
        }
        out[i] = falcon_c_div(a[i], b[i]);
    }
    return FALCON_OK;
}

void falcon_fft_adj(falcon_cplx *out, const falcon_cplx *a, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = falcon_c_adj(a[i]);
    }
}

int falcon_fft_norm_sq(double *out, const falcon_cplx *a, size_t n)
{
    if (n == 0) {
        return FALCON_ERR_VALUE;
    }
    double s = 0.0;
    for (size_t i = 0; i < n; i++) {
        s += (a[i].re * a[i].re) + (a[i].im * a[i].im);
    }
    *out = s / (double)n;
    return FALCON_OK;
}

int falcon_split_fft(falcon_cplx *f0, falcon_cplx *f1, const falcon_cplx *a_hat, size_t n)
{
    if (n < 2 || !valid_length(n)) {
        return FALCON_ERR_VALUE;
    }
    size_t h = n / 2;
    for (size_t k = 0; k < h; k++) {
        falcon_cplx x = a_hat[k];
        falcon_cplx y = a_hat[k + h];
        falcon_cplx sum = falcon_c_add(x, y);
        falcon_cplx z = zeta(h, k);
        falcon_cplx twice = {2.0 * z.re, 2.0 * z.im};
        f0[k].re = sum.re / 2.0;
        f0[k].im = sum.im / 2.0;
        f1[k] = falcon_c_div(falcon_c_sub(x, y), twice);
    }
    return FALCON_OK;
}

int falcon_merge_fft(falcon_cplx *out, const falcon_cplx *a0, const falcon_cplx *a1, size_t h)
{
    if (h == 0 || 2 * h > FALCON_MAX_N || !valid_length(h)) {
        return FALCON_ERR_VALUE;
    }
    for (size_t k = 0; k < h; k++) {
        falcon_cplx v0 = a0[k];
        falcon_cplx v1 = a1[k];
        falcon_cplx t = falcon_c_mul(zeta(h, k), v1);
        out[k] = falcon_c_add(v0, t);
        out[k + h] = falcon_c_sub(v0, t);
    }
    return FALCON_OK;
}

void falcon_ints_to_doubles(double *out, const int32_t *a, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = (double)a[i];
    }
}
