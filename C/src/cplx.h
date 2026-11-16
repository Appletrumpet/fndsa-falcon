/*
 * Komplexe Rechenoperationen mit festen Formeln.
 *
 * Jede Gleitkommaoperation wird einzeln gerundet (Übersetzung mit -ffp-contract=off), damit die
 * Ergebnisse bitgleich mit Python sind.
 */
#ifndef FALCON_CPLX_H
#define FALCON_CPLX_H

#include "ct.h"
#include <math.h>

#include "datatypes.h"

static inline falcon_cplx falcon_c_add(falcon_cplx a, falcon_cplx b)
{
    falcon_cplx r = {a.re + b.re, a.im + b.im};
    return r;
}

static inline falcon_cplx falcon_c_sub(falcon_cplx a, falcon_cplx b)
{
    falcon_cplx r = {a.re - b.re, a.im - b.im};
    return r;
}

/* (ac - bd, ad + bc) wie in CPython. */
static inline falcon_cplx falcon_c_mul(falcon_cplx a, falcon_cplx b)
{
    falcon_cplx r = {a.re * b.re - a.im * b.im, a.re * b.im + a.im * b.re};
    return r;
}

static inline falcon_cplx falcon_c_adj(falcon_cplx a)
{
    falcon_cplx r = {a.re, -a.im};
    return r;
}

/* a / b nach Smith, Fallunterscheidung wie in CPython; b darf nicht 0 sein. Verzweigt auf b:
 * nur für öffentliche Nenner (split_fft: 2 * zeta). Für geheime Nenner falcon_c_div_ct. */
static inline falcon_cplx falcon_c_div(falcon_cplx a, falcon_cplx b)
{
    falcon_cplx r;
    if (fabs(b.re) >= fabs(b.im)) {
        double ratio = b.im / b.re;
        double denom = b.re + b.im * ratio;
        r.re = (a.re + a.im * ratio) / denom;
        r.im = (a.im - a.re * ratio) / denom;
    } else {
        double ratio = b.re / b.im;
        double denom = b.re * ratio + b.im;
        r.re = (a.re * ratio + a.im) / denom;
        r.im = (a.im * ratio - a.re) / denom;
    }
    return r;
}

/* Wie falcon_c_div, bitgleich, aber ohne Verzweigung auf b: beide Fälle rechnen, einen über eine
 * Maske wählen (fft_div in ldl, Nenner aus dem Secret Key). */
static inline falcon_cplx falcon_c_div_ct(falcon_cplx a, falcon_cplx b)
{
    double ratio1 = b.im / b.re;
    double denom1 = b.re + b.im * ratio1;
    double re1 = (a.re + a.im * ratio1) / denom1;
    double im1 = (a.im - a.re * ratio1) / denom1;
    double ratio2 = b.re / b.im;
    double denom2 = b.re * ratio2 + b.im;
    double re2 = (a.re * ratio2 + a.im) / denom2;
    double im2 = (a.im * ratio2 - a.re) / denom2;
    uint64_t first = falcon_ct_mask(1u ^ falcon_ct_lt_double(fabs(b.re), fabs(b.im)));
    falcon_cplx r = {falcon_ct_select_double(first, re1, re2), falcon_ct_select_double(first, im1, im2)};
    return r;
}

#endif
