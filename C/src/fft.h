/*
 * Rechnen mit komplexen Werten, Splitten und Mergen.
 *
 * Konvention wie in Python: Index k enthält den Wert an der Wurzel
 * zeta_k = exp(i(2k+1)pi/n) (Gl. 3.19); gespeichert werden alle n Werte.
 *
 * Spec-Referenz: §3.5, §3.6, §4.2.1. Grade n = 2^k <= 1024; sonst FALCON_ERR_VALUE.
 */
#ifndef FALCON_FFT_H
#define FALCON_FFT_H

#include "datatypes.h"

/* Rekursiv über merge_fft; Basisfall n = 1. §3.5, §3.6, Gl. 3.19. */
int falcon_fft(falcon_cplx *out, const double *a, size_t n);

/* Umkehrung von fft, rekursiv über split_fft. §3.5, §3.6. */
int falcon_ifft(double *out, const falcon_cplx *a_hat, size_t n);

/* Punktweise Operationen. out darf mit den Eingaben übereinstimmen. §3.5. */
void falcon_fft_add(falcon_cplx *out, const falcon_cplx *a, const falcon_cplx *b, size_t n);
void falcon_fft_sub(falcon_cplx *out, const falcon_cplx *a, const falcon_cplx *b, size_t n);
void falcon_fft_mul(falcon_cplx *out, const falcon_cplx *a, const falcon_cplx *b, size_t n);

/* FALCON_ERR_VALUE, wenn ein Wert von b exakt 0 ist. §3.5. */
int falcon_fft_div(falcon_cplx *out, const falcon_cplx *a, const falcon_cplx *b, size_t n);

/* Adjungierte: jeden Wert komplex konjugieren. Gl. 3.6, §4.2.1. */
void falcon_fft_adj(falcon_cplx *out, const falcon_cplx *a, size_t n);

/* Quadrierte Norm direkt in FFT-Form. FALCON_ERR_VALUE für n = 0. Gl. 3.8. */
int falcon_fft_norm_sq(double *out, const falcon_cplx *a, size_t n);

/* Ein Polynom in zwei halb so grosse aufteilen. Alg. 1. */
int falcon_split_fft(falcon_cplx *f0, falcon_cplx *f1, const falcon_cplx *a_hat, size_t n);

/* Umkehrung von split_fft; h ist die Länge der Hälften. out darf a0 sein, wenn a1 = out + h. Alg. 2. */
int falcon_merge_fft(falcon_cplx *out, const falcon_cplx *a0, const falcon_cplx *a1, size_t h);

/* Ganze Zahlen in double umwandeln (exakt für die verwendeten Grössen). */
void falcon_ints_to_doubles(double *out, const int32_t *a, size_t n);

#endif
