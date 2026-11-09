/*
 * Komplexe Rechenoperationen mit festen Formeln.
 *
 * Jede Gleitkommaoperation wird einzeln gerundet (Übersetzung mit -ffp-contract=off), damit die
 * Ergebnisse bitgleich mit Python sind.
 */
#ifndef FALCON_CPLX_H
#define FALCON_CPLX_H

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

/* a / b nach Smith, Fallunterscheidung wie in CPython; b darf nicht 0 sein. */
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

#endif
