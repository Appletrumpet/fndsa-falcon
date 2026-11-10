//! FFT der Referenz, nur für Keygen (NTRUSolve, PLAN.md 3.5).
//!
//! **Portierung der Referenz** (`fft.c`, PQClean). Anders als `fft.rs`
//! speichert diese FFT nur n/2 komplexe Werte (Realteile in der ersten,
//! Imaginärteile in der zweiten Hälfte) und benutzt die Wurzeltabelle
//! `fpr_gm_tab`. NTRUSolve rundet Näherungswerte, die mit dieser FFT
//! berechnet werden; damit F byte-genau wie in den KAT-Schlüsseln
//! herauskommt, muss jede Operation der Referenz gleich sein (L10).
//!
//! Die Polynome liegen im Arbeitspuffer von NTRUSolve (`zint::fget`,
//! `zint::fset`); Argumente sind Indizes darin (in u32-Wörtern).

use crate::fpr::Fpr;
use crate::keygen_tables::GM_TAB;
use crate::zint::{fget, fset};

#[inline(always)]
fn gm(i: usize) -> Fpr {
    Fpr::from_bits(GM_TAB[i])
}

/// (a_re + i·a_im)·(b_re + i·b_im) wie FPC_MUL der Referenz.
#[inline(always)]
fn cmul(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (a_re * b_re - a_im * b_im, a_re * b_im + a_im * b_re)
}

/// Element u eines Polynoms an Index `p`.
#[inline(always)]
fn at(p: usize, u: usize) -> usize {
    p + 2 * u
}

/// Referenz: fft.c, FFT.
pub(crate) fn fft(m: &mut [u32], f: usize, logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = hn;
    let mut mm = 2usize;
    for _ in 1..logn {
        let ht = t >> 1;
        let hm = mm >> 1;
        let mut j1 = 0;
        for i1 in 0..hm {
            let j2 = j1 + ht;
            let s_re = gm((mm + i1) << 1);
            let s_im = gm(((mm + i1) << 1) + 1);
            for j in j1..j2 {
                let x_re = fget(m, at(f, j));
                let x_im = fget(m, at(f, j + hn));
                let y_re = fget(m, at(f, j + ht));
                let y_im = fget(m, at(f, j + ht + hn));
                let (y_re, y_im) = cmul(y_re, y_im, s_re, s_im);
                fset(m, at(f, j), x_re + y_re);
                fset(m, at(f, j + hn), x_im + y_im);
                fset(m, at(f, j + ht), x_re - y_re);
                fset(m, at(f, j + ht + hn), x_im - y_im);
            }
            j1 += t;
        }
        t = ht;
        mm <<= 1;
    }
}

/// Referenz: fft.c, iFFT.
pub(crate) fn ifft(m: &mut [u32], f: usize, logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut t = 1usize;
    let mut mm = n;
    for _ in (2..=logn).rev() {
        let hm = mm >> 1;
        let dt = t << 1;
        let mut i1 = 0;
        let mut j1 = 0;
        while j1 < hn {
            let j2 = j1 + t;
            let s_re = gm((hm + i1) << 1);
            let s_im = -gm(((hm + i1) << 1) + 1);
            for j in j1..j2 {
                let x_re = fget(m, at(f, j));
                let x_im = fget(m, at(f, j + hn));
                let y_re = fget(m, at(f, j + t));
                let y_im = fget(m, at(f, j + t + hn));
                fset(m, at(f, j), x_re + y_re);
                fset(m, at(f, j + hn), x_im + y_im);
                let (x_re, x_im) = (x_re - y_re, x_im - y_im);
                let (r, i) = cmul(x_re, x_im, s_re, s_im);
                fset(m, at(f, j + t), r);
                fset(m, at(f, j + t + hn), i);
            }
            i1 += 1;
            j1 += dt;
        }
        t = dt;
        mm = hm;
    }
    if logn > 0 {
        // fpr_p2_tab[logn] = 2^(1 − logn)
        let ni = Fpr::scaled(1, 1 - logn as i32);
        for u in 0..n {
            let v = fget(m, at(f, u)) * ni;
            fset(m, at(f, u), v);
        }
    }
}

/// a ← a + b. Referenz: fft.c, poly_add.
pub(crate) fn poly_add(m: &mut [u32], a: usize, b: usize, logn: u32) {
    for u in 0..1usize << logn {
        let v = fget(m, at(a, u)) + fget(m, at(b, u));
        fset(m, at(a, u), v);
    }
}

/// a ← a − b. Referenz: fft.c, poly_sub.
pub(crate) fn poly_sub(m: &mut [u32], a: usize, b: usize, logn: u32) {
    for u in 0..1usize << logn {
        let v = fget(m, at(a, u)) - fget(m, at(b, u));
        fset(m, at(a, u), v);
    }
}

/// a ← adj(a). Referenz: fft.c, poly_adj_fft.
pub(crate) fn poly_adj_fft(m: &mut [u32], a: usize, logn: u32) {
    let n = 1usize << logn;
    for u in n >> 1..n {
        let v = -fget(m, at(a, u));
        fset(m, at(a, u), v);
    }
}

/// a ← a·b. Referenz: fft.c, poly_mul_fft.
pub(crate) fn poly_mul_fft(m: &mut [u32], a: usize, b: usize, logn: u32) {
    let hn = 1usize << (logn - 1);
    for u in 0..hn {
        let (re, im) = cmul(
            fget(m, at(a, u)),
            fget(m, at(a, u + hn)),
            fget(m, at(b, u)),
            fget(m, at(b, u + hn)),
        );
        fset(m, at(a, u), re);
        fset(m, at(a, u + hn), im);
    }
}

/// d ← 1/(|a|² + |b|²) (n/2 reelle Werte). Referenz: fft.c,
/// poly_invnorm2_fft.
pub(crate) fn poly_invnorm2_fft(m: &mut [u32], d: usize, a: usize, b: usize, logn: u32) {
    let hn = 1usize << (logn - 1);
    for u in 0..hn {
        let (a_re, a_im) = (fget(m, at(a, u)), fget(m, at(a, u + hn)));
        let (b_re, b_im) = (fget(m, at(b, u)), fget(m, at(b, u + hn)));
        let v = ((a_re.sqr() + a_im.sqr()) + (b_re.sqr() + b_im.sqr())).inv();
        fset(m, at(d, u), v);
    }
}

/// d ← F·adj(f) + G·adj(g). Referenz: fft.c, poly_add_muladj_fft.
#[allow(clippy::too_many_arguments)]
pub(crate) fn poly_add_muladj_fft(
    m: &mut [u32],
    d: usize,
    big_f: usize,
    big_g: usize,
    f: usize,
    g: usize,
    logn: u32,
) {
    let hn = 1usize << (logn - 1);
    for u in 0..hn {
        let (fr, fi) = (fget(m, at(big_f, u)), fget(m, at(big_f, u + hn)));
        let (gr, gi) = (fget(m, at(big_g, u)), fget(m, at(big_g, u + hn)));
        let (sr, si) = (fget(m, at(f, u)), fget(m, at(f, u + hn)));
        let (tr, ti) = (fget(m, at(g, u)), fget(m, at(g, u + hn)));
        let (a_re, a_im) = cmul(fr, fi, sr, -si);
        let (b_re, b_im) = cmul(gr, gi, tr, -ti);
        fset(m, at(d, u), a_re + b_re);
        fset(m, at(d, u + hn), a_im + b_im);
    }
}

/// a ← a·b, b selbstadjungiert (n/2 reelle Werte). Referenz: fft.c,
/// poly_mul_autoadj_fft.
pub(crate) fn poly_mul_autoadj_fft(m: &mut [u32], a: usize, b: usize, logn: u32) {
    let hn = 1usize << (logn - 1);
    for u in 0..hn {
        let bu = fget(m, at(b, u));
        let v0 = fget(m, at(a, u)) * bu;
        let v1 = fget(m, at(a, u + hn)) * bu;
        fset(m, at(a, u), v0);
        fset(m, at(a, u + hn), v1);
    }
}

/// a ← a/b, b selbstadjungiert. Referenz: fft.c, poly_div_autoadj_fft.
pub(crate) fn poly_div_autoadj_fft(m: &mut [u32], a: usize, b: usize, logn: u32) {
    let hn = 1usize << (logn - 1);
    for u in 0..hn {
        let ib = fget(m, at(b, u)).inv();
        let v0 = fget(m, at(a, u)) * ib;
        let v1 = fget(m, at(a, u + hn)) * ib;
        fset(m, at(a, u), v0);
        fset(m, at(a, u + hn), v1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// iFFT(FFT(a)) ≈ a und Produkt in FFT-Form = Produkt in ℝ[x]/(xⁿ+1).
    #[test]
    fn roundtrip_and_product() {
        for logn in 1..=10u32 {
            let n = 1usize << logn;
            let mut m = vec![0u32; 6 * n];
            let a: Vec<i64> = (0..n as i64).map(|i| (i * 37 % 101) - 50).collect();
            let b: Vec<i64> = (0..n as i64).map(|i| (i * 11 % 23) - 11).collect();
            for i in 0..n {
                fset(&mut m, 2 * i, Fpr::of_i64(a[i]));
                fset(&mut m, 2 * n + 2 * i, Fpr::of_i64(b[i]));
            }
            fft(&mut m, 0, logn);
            fft(&mut m, 2 * n, logn);
            poly_mul_fft(&mut m, 0, 2 * n, logn);
            ifft(&mut m, 0, logn);
            let mut want = vec![0i64; n];
            for i in 0..n {
                for j in 0..n {
                    let p = a[i] * b[j];
                    if i + j < n {
                        want[i + j] += p;
                    } else {
                        want[i + j - n] -= p;
                    }
                }
            }
            let got: Vec<i64> = (0..n).map(|i| fget(&m, 2 * i).rint()).collect();
            assert_eq!(got, want, "logn {logn}");
        }
    }
}
