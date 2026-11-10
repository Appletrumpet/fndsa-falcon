//! FFT über ℂ für Polynome in ℝ[x]/(xⁿ+1), mit emulierten Gleitkommazahlen.
//!
//! Spec-Referenz: §3.5, §3.6, Alg. 1/2, Gl. 3.19. Entspricht
//! `Python/falcon/fft.py` und `C/src/fft.c`.
//!
//! Konvention wie in Python: Index k enthält den Wert an der Wurzel
//! ζ_k = exp(i(2k+1)π/n); gespeichert werden alle n Werte.
//!
//! **Bitgleich mit Python und C:** Jede Gleitkommaoperation ist korrekt
//! gerundet (`Fpr`), die Wurzeln stammen aus derselben Tabelle wie in C
//! (`fft_table.rs`, erzeugt aus `C/src/fft_table.h`), und die Reihenfolge der
//! Operationen ist dieselbe. Damit stimmen die Ergebnisse Bit für Bit mit den
//! Testvektoren aus `Python/data/vectors/fft.*.txt` überein. Das ersetzt den
//! Vergleich mit Toleranz, den PLAN.md 3.3 ursprünglich vorsah.
//!
//! Abweichung von PLAN.md L8: alle n Werte statt n/2, damit die Rechenwege
//! und damit die Bits mit Python übereinstimmen.
//!
//! Konstante Laufzeit: keine Verzweigung auf Werten. Die Division nach Smith
//! wählt ihren Zweig über Masken (`Cplx::div`).

// Wird erst von Sign und Keygen benutzt (Phase 4/5); bis dahin nur in Tests.
#![allow(dead_code)]

use crate::fft_table::ZETA_BITS;
use crate::fpr::Fpr;

/// Komplexe Zahl aus zwei emulierten Gleitkommazahlen. Kein `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cplx {
    pub re: Fpr,
    pub im: Fpr,
}

impl Cplx {
    pub const ZERO: Cplx = Cplx {
        re: Fpr::ZERO,
        im: Fpr::ZERO,
    };

    pub fn new(re: Fpr, im: Fpr) -> Cplx {
        Cplx { re, im }
    }

    pub fn add(self, b: Cplx) -> Cplx {
        Cplx::new(self.re + b.re, self.im + b.im)
    }

    pub fn sub(self, b: Cplx) -> Cplx {
        Cplx::new(self.re - b.re, self.im - b.im)
    }

    /// (ac − bd, ad + bc), wie CPython und C.
    pub fn mul(self, b: Cplx) -> Cplx {
        Cplx::new(
            self.re * b.re - self.im * b.im,
            self.re * b.im + self.im * b.re,
        )
    }

    /// Komplex konjugiert (Adjungierte, Gl. 3.6).
    pub fn adj(self) -> Cplx {
        Cplx::new(self.re, -self.im)
    }

    /// a / b nach Smith, b ≠ 0. Gleiches Ergebnis wie `_smith_div` in Python
    /// und `falcon_c_div` in C, aber ohne Verzweigung.
    ///
    /// Die beiden Zweige von Smith lassen sich mit vertauschten Operanden
    /// gleich schreiben, weil IEEE-754-Addition und -Multiplikation
    /// kommutativ sind und a − b = −(b − a) exakt gilt:
    ///
    /// - |b.re| ≥ |b.im|: (u, v) = (b.re, b.im), (p, q) = (a.re, a.im)
    /// - sonst:           (u, v) = (b.im, b.re), (p, q) = (a.im, a.re)
    ///
    /// ratio = v/u, denom = u + v·ratio, re = (p + q·ratio)/denom,
    /// im = ±(q − p·ratio)/denom (Minus im zweiten Fall).
    pub fn div(self, b: Cplx) -> Cplx {
        // Maske „zweiter Fall“: |b.re| < |b.im|
        let second = b.re.abs().lt_mask(b.im.abs());
        let u = Fpr::select(second, b.re, b.im);
        let v = Fpr::select(second, b.im, b.re);
        let p = Fpr::select(second, self.re, self.im);
        let q = Fpr::select(second, self.im, self.re);

        let ratio = v / u;
        let denom = u + v * ratio;
        let re = (p + q * ratio) / denom;
        let im = (q - p * ratio) / denom;
        Cplx::new(re, Fpr::select(second, im, -im))
    }
}

/// ζ(n, k) mit n = 2h, k < h.
fn zeta(h: usize, k: usize) -> Cplx {
    let (re, im) = ZETA_BITS[h + k];
    Cplx::new(Fpr::from_bits(re), Fpr::from_bits(im))
}

fn assert_len(n: usize) {
    debug_assert!(n.is_power_of_two() && n <= 1024, "Länge {n}");
}

/// FFT: rekursiv, Koeffizienten in gerade und ungerade trennen, beide
/// Hälften transformieren, mit `merge_fft` zusammenführen. n = 1..=1024.
pub fn fft(a: &[Fpr]) -> Vec<Cplx> {
    assert_len(a.len());
    let mut out = vec![Cplx::ZERO; a.len()];
    fft_rec(&mut out, a, 1);
    out
}

fn fft_rec(out: &mut [Cplx], a: &[Fpr], stride: usize) {
    let n = out.len();
    if n == 1 {
        out[0] = Cplx::new(a[0], Fpr::ZERO);
        return;
    }
    let h = n / 2;
    let (lo, hi) = out.split_at_mut(h);
    fft_rec(lo, a, 2 * stride);
    fft_rec(hi, &a[stride..], 2 * stride);
    let merged = merge_fft(lo, hi);
    out.copy_from_slice(&merged);
}

/// Umkehrung von `fft`, rekursiv über `split_fft`.
pub fn ifft(a: &[Cplx]) -> Vec<Fpr> {
    assert_len(a.len());
    let mut out = vec![Fpr::ZERO; a.len()];
    ifft_rec(&mut out, 0, 1, a);
    out
}

fn ifft_rec(out: &mut [Fpr], start: usize, stride: usize, a: &[Cplx]) {
    if a.len() == 1 {
        out[start] = a[0].re;
        return;
    }
    let (f0, f1) = split_fft(a);
    ifft_rec(out, start, 2 * stride, &f0);
    ifft_rec(out, start + stride, 2 * stride, &f1);
}

/// Punktweise addieren.
pub fn fft_add(a: &[Cplx], b: &[Cplx]) -> Vec<Cplx> {
    a.iter().zip(b).map(|(x, y)| x.add(*y)).collect()
}

/// Punktweise subtrahieren.
pub fn fft_sub(a: &[Cplx], b: &[Cplx]) -> Vec<Cplx> {
    a.iter().zip(b).map(|(x, y)| x.sub(*y)).collect()
}

/// Punktweise multiplizieren.
pub fn fft_mul(a: &[Cplx], b: &[Cplx]) -> Vec<Cplx> {
    a.iter().zip(b).map(|(x, y)| x.mul(*y)).collect()
}

/// Punktweise dividieren; kein Wert von b darf 0 sein.
pub fn fft_div(a: &[Cplx], b: &[Cplx]) -> Vec<Cplx> {
    a.iter().zip(b).map(|(x, y)| x.div(*y)).collect()
}

/// Adjungierte: jeden Wert konjugieren.
pub fn fft_adj(a: &[Cplx]) -> Vec<Cplx> {
    a.iter().map(|x| x.adj()).collect()
}

/// Quadrierte Norm in FFT-Form (Gl. 3.8): Σ (re² + im²) / n.
pub fn fft_norm_sq(a: &[Cplx]) -> Fpr {
    let mut s = Fpr::ZERO;
    for x in a {
        s = s + (x.re * x.re + x.im * x.im);
    }
    s / Fpr::of_i64(a.len() as i64)
}

/// Ein Polynom in zwei halb so grosse aufteilen (Alg. 1), n ≥ 2:
/// f₀[k] = (f[k] + f[k+h]) / 2, f₁[k] = (f[k] − f[k+h]) / (2ζ_k).
pub fn split_fft(a: &[Cplx]) -> (Vec<Cplx>, Vec<Cplx>) {
    assert_len(a.len());
    let h = a.len() / 2;
    let mut f0 = Vec::with_capacity(h);
    let mut f1 = Vec::with_capacity(h);
    for k in 0..h {
        let (x, y) = (a[k], a[k + h]);
        let sum = x.add(y);
        let z = zeta(h, k);
        let twice = Cplx::new(z.re.double(), z.im.double());
        // Division durch 2 ist exakt und gleich dem Halbieren.
        f0.push(Cplx::new(sum.re.half(), sum.im.half()));
        f1.push(x.sub(y).div(twice));
    }
    (f0, f1)
}

/// Umkehrung von `split_fft` (Alg. 2): f[k] = f₀[k] + ζ_k·f₁[k],
/// f[k+h] = f₀[k] − ζ_k·f₁[k].
pub fn merge_fft(a0: &[Cplx], a1: &[Cplx]) -> Vec<Cplx> {
    let h = a0.len();
    debug_assert_eq!(a1.len(), h);
    assert_len(2 * h);
    let mut out = vec![Cplx::ZERO; 2 * h];
    for k in 0..h {
        let t = zeta(h, k).mul(a1[k]);
        out[k] = a0[k].add(t);
        out[k + h] = a0[k].sub(t);
    }
    out
}

/// Ganzzahlige Koeffizienten → Fpr.
pub fn ints_to_fpr(a: &[i32]) -> Vec<Fpr> {
    a.iter().map(|&x| Fpr::of_i64(x as i64)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::vectors::{load, Case};

    fn fprs(c: &Case, key: &str) -> Vec<Fpr> {
        c.floats(key).into_iter().map(Fpr::from_bits).collect()
    }

    fn cplxs(c: &Case, key: &str) -> Vec<Cplx> {
        c.cplx(key)
            .into_iter()
            .map(|(re, im)| Cplx::new(Fpr::from_bits(re), Fpr::from_bits(im)))
            .collect()
    }

    fn bits(v: &[Cplx]) -> Vec<(u64, u64)> {
        v.iter().map(|c| (c.re.to_bits(), c.im.to_bits())).collect()
    }

    fn fbits(v: &[Fpr]) -> Vec<u64> {
        v.iter().map(|x| x.to_bits()).collect()
    }

    /// Fälle mit gültiger Eingabe; Fehlerfälle (Länge keine Zweierpotenz,
    /// Division durch 0) fängt in Rust schon der Aufrufer ab.
    fn ok_cases(name: &str) -> Vec<Case> {
        let all = load(name);
        assert!(!all.is_empty(), "{name}: keine Fälle");
        all.into_iter().filter(|c| c.ok()).collect()
    }

    #[test]
    fn fft_matches_python() {
        for c in ok_cases("fft.fft") {
            let got = fft(&fprs(&c, "a"));
            assert_eq!(bits(&got), c.cplx("out"), "Fall {}", c.index);
        }
    }

    #[test]
    fn ifft_matches_python() {
        for c in ok_cases("fft.ifft") {
            let got = ifft(&cplxs(&c, "a"));
            assert_eq!(fbits(&got), c.floats("out"), "Fall {}", c.index);
        }
    }

    #[test]
    fn pointwise_match_python() {
        type Op = fn(&[Cplx], &[Cplx]) -> Vec<Cplx>;
        let ops: [(&str, Op); 4] = [
            ("fft.fft_add", fft_add),
            ("fft.fft_sub", fft_sub),
            ("fft.fft_mul", fft_mul),
            ("fft.fft_div", fft_div),
        ];
        for (name, op) in ops {
            for c in ok_cases(name) {
                let (a, b) = (cplxs(&c, "a"), cplxs(&c, "b"));
                if a.len() != b.len() {
                    continue;
                }
                assert_eq!(bits(&op(&a, &b)), c.cplx("out"), "{name} Fall {}", c.index);
            }
        }
    }

    #[test]
    fn adj_and_norm_match_python() {
        for c in ok_cases("fft.fft_adj") {
            assert_eq!(bits(&fft_adj(&cplxs(&c, "a"))), c.cplx("out"));
        }
        for c in ok_cases("fft.fft_norm_sq") {
            let got = fft_norm_sq(&cplxs(&c, "a"));
            assert_eq!(got.to_bits(), c.float("out"), "Fall {}", c.index);
        }
    }

    #[test]
    fn split_merge_match_python() {
        for c in ok_cases("fft.split_fft") {
            let (f0, f1) = split_fft(&cplxs(&c, "a"));
            assert_eq!(bits(&f0), c.cplx("out0"), "split Fall {}", c.index);
            assert_eq!(bits(&f1), c.cplx("out1"), "split Fall {}", c.index);
        }
        for c in ok_cases("fft.merge_fft") {
            let got = merge_fft(&cplxs(&c, "a0"), &cplxs(&c, "a1"));
            assert_eq!(bits(&got), c.cplx("out"), "merge Fall {}", c.index);
        }
    }

    /// Eigenschaft unabhängig von Python: ifft(fft(a)) ≈ a und das Produkt
    /// in FFT-Form entspricht der Multiplikation in ℤ[x]/(xⁿ+1).
    #[test]
    fn roundtrip_and_product() {
        for logn in 1..=10 {
            let n = 1usize << logn;
            let a: Vec<i32> = (0..n as i32).map(|i| (i * 37 % 101) - 50).collect();
            let b: Vec<i32> = (0..n as i32).map(|i| (i * 11 % 23) - 11).collect();
            let back = ifft(&fft(&ints_to_fpr(&a)));
            for (x, y) in back.iter().zip(&a) {
                assert_eq!(x.rint(), *y as i64, "Roundtrip n = {n}");
            }
            let prod = ifft(&fft_mul(&fft(&ints_to_fpr(&a)), &fft(&ints_to_fpr(&b))));
            let mut want = vec![0i64; n];
            for i in 0..n {
                for j in 0..n {
                    let p = a[i] as i64 * b[j] as i64;
                    if i + j < n {
                        want[i + j] += p;
                    } else {
                        want[i + j - n] -= p;
                    }
                }
            }
            let got: Vec<i64> = prod.iter().map(|x| x.rint()).collect();
            assert_eq!(got, want, "Produkt n = {n}");
        }
    }

    /// Die Smith-Division ohne Verzweigung trifft beide Zweige.
    #[test]
    fn smith_division_both_branches() {
        let c = |re: f64, im: f64| Cplx::new(Fpr::from_f64(re), Fpr::from_f64(im));
        for (a, b) in [
            (c(3.0, 4.0), c(1.0, 2.0)),    // |b.re| < |b.im|
            (c(3.0, 4.0), c(2.0, 1.0)),    // |b.re| > |b.im|
            (c(-1.5, 0.25), c(-7.0, 7.0)), // gleich
        ] {
            let q = a.div(b);
            let back = q.mul(b);
            assert!((back.re.to_f64() - a.re.to_f64()).abs() < 1e-12);
            assert!((back.im.to_f64() - a.im.to_f64()).abs() < 1e-12);
        }
    }
}
