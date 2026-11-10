//! Bausteine der Top-Level-Funktionen (Ebene 2): Public Key aus f, g,
//! Verify, Laden des Secret Keys (G neu berechnen) und Sign. Keygen folgt in
//! Phase 5.
//!
//! Spec-Referenz: Alg. 4 Z. 9, Alg. 10, Alg. 16, Gl. 3.35. Entspricht
//! `Python/falcon/falcon.py` (Sign bitgleich mit `flow.sign`).

use zeroize::Zeroizing;

use crate::encoding::{compress, decompress};
use crate::ffsampling::ff_sampling;
use crate::fft::{fft, fft_add, fft_mul, fft_norm_sq, fft_sub, ifft, Cplx, Poly};
use crate::fpr::Fpr;
use crate::hashing::hash_to_point;
use crate::modq;
use crate::params::{Params, Q};
use crate::prng::RandomSource;
use crate::tree::{Basis, Tree};
use crate::Error;

/// h = g · f⁻¹ mod q. Alg. 4, Z. 9.
///
/// f und g sind geheim: NTT, Invertierbarkeitstest und Inverse laufen ohne
/// Verzweigung auf den Werten (PLAN.md, 3.7). Nur das Ergebnis
/// „f invertierbar ja/nein“ verzweigt; ein nicht invertierbares f wird beim
/// Keygen verworfen.
pub(crate) fn compute_public_key(f: &[i8], g: &[i8]) -> Result<Vec<u16>, Error> {
    // Die Längen sind öffentlich. Ohne Prüfung würde `zip` still abschneiden
    // und die NTT prüft die Länge nur im Debug-Build.
    let n = f.len();
    if g.len() != n || !n.is_power_of_two() || !(2..=1024).contains(&n) {
        return Err(Error::InvalidEncoding("Länge von f, g"));
    }
    let mut ft: Zeroizing<Vec<u32>> =
        Zeroizing::new(f.iter().map(|&x| modq::from_i32(x as i32)).collect());
    let mut gt: Zeroizing<Vec<u32>> =
        Zeroizing::new(g.iter().map(|&x| modq::from_i32(x as i32)).collect());
    modq::ntt(&mut ft);
    modq::ntt(&mut gt);
    if modq::any_zero_mask(&ft) != 0 {
        return Err(Error::NotInvertible);
    }
    let mut h: Vec<u32> = ft
        .iter()
        .zip(gt.iter())
        .map(|(&a, &b)| modq::mul(b, modq::inv(a)))
        .collect();
    modq::intt(&mut h);
    Ok(h.into_iter().map(|x| x as u16).collect())
}

/// Verify (Alg. 16). Alles hier ist öffentlich, normaler Code erlaubt.
///
/// `h_ntt` ist h in NTT-Form (im `VerifyingKey` vorberechnet).
pub(crate) fn verify(
    params: &Params,
    h_ntt: &[u32],
    salt: &[u8],
    s2_enc: &[u8],
    msg: &[u8],
) -> bool {
    let n = params.n();
    let c = hash_to_point(salt, msg, n);
    let s2 = match decompress(s2_enc, n, params.s2_padded_len()) {
        Some(s) => s,
        None => return false,
    };

    // s₁ = c − s₂·h mod q, zentriert (Alg. 16, Z. 5)
    let mut t: Vec<u32> = s2.iter().map(|&x| modq::from_i32(x as i32)).collect();
    modq::ntt(&mut t);
    for (ti, &hi) in t.iter_mut().zip(h_ntt) {
        *ti = modq::mul(*ti, hi);
    }
    modq::intt(&mut t);

    // ‖(s₁, s₂)‖² ≤ ⌊β²⌋ (Alg. 16, Z. 6). Kein Überlauf: höchstens
    // 1024 · (6144² + 2047²) < 2⁴⁶.
    let mut norm = 0u64;
    for i in 0..n {
        let s1 = modq::center(modq::sub(c[i] as u32, t[i])) as i64;
        let s2i = s2[i] as i64;
        norm += (s1 * s1 + s2i * s2i) as u64;
    }
    norm <= params.sig_bound
}

// ---------------------------------------------------------------------------
// Sign (Alg. 10) und Laden des Secret Keys
// ---------------------------------------------------------------------------

/// G aus der NTRU-Gleichung: G = g·F/f mod q, zentriert (Gl. 3.35).
/// Für das Laden des Secret Keys, der G nicht speichert.
///
/// Geheim; wie `compute_public_key` ohne Verzweigung auf den Werten. Fehler
/// nur, wenn f nicht invertierbar ist (dann ist der Key ungültig).
pub(crate) fn recompute_g(f: &[i8], g: &[i8], big_f: &[i8]) -> Result<Zeroizing<Vec<i16>>, Error> {
    let ntt_of = |a: &[i8]| {
        let mut v: Zeroizing<Vec<u32>> =
            Zeroizing::new(a.iter().map(|&x| modq::from_i32(x as i32)).collect());
        modq::ntt(&mut v);
        v
    };
    let (ft, gt, bigft) = (ntt_of(f), ntt_of(g), ntt_of(big_f));
    if modq::any_zero_mask(&ft) != 0 {
        return Err(Error::NotInvertible);
    }
    let mut t: Zeroizing<Vec<u32>> = Zeroizing::new(
        (0..f.len())
            .map(|i| modq::mul(modq::mul(gt[i], bigft[i]), modq::inv(ft[i])))
            .collect(),
    );
    modq::intt(&mut t);
    Ok(Zeroizing::new(
        t.iter().map(|&x| modq::center(x) as i16).collect(),
    ))
}

fn fft_of_i8(a: &[i8]) -> Poly {
    let v: Zeroizing<Vec<Fpr>> = Zeroizing::new(a.iter().map(|&x| Fpr::of_i64(x as i64)).collect());
    fft(&v)
}

/// Ziel t = (c, 0)·B⁻¹ = (−c·F/q, c·f/q) in FFT-Form (Alg. 10, Z. 3).
/// Wie Python: Produkt, dann jede Komponente durch q.
pub(crate) fn compute_target(c: &[u16], f: &[i8], big_f: &[i8]) -> (Poly, Poly) {
    let cf: Zeroizing<Vec<Fpr>> =
        Zeroizing::new(c.iter().map(|&x| Fpr::of_i64(x as i64)).collect());
    let c_hat = fft(&cf);
    let (f_hat, bigf_hat) = (fft_of_i8(f), fft_of_i8(big_f));
    let q = Fpr::of_i64(Q as i64);
    let div_q = |x: Cplx| Cplx::new(x.re / q, x.im / q);
    let t0 = c_hat
        .iter()
        .zip(bigf_hat.iter())
        .map(|(a, b)| {
            let p = a.mul(*b);
            div_q(Cplx::new(-p.re, -p.im))
        })
        .collect();
    let t1 = c_hat
        .iter()
        .zip(f_hat.iter())
        .map(|(a, b)| div_q(a.mul(*b)))
        .collect();
    (Poly::new(t0), Poly::new(t1))
}

/// s = (t − z)·B in FFT-Form (Alg. 10, Z. 7).
pub(crate) fn compute_signature_vector(
    t: (&[Cplx], &[Cplx]),
    z: (&[Cplx], &[Cplx]),
    b: &Basis,
) -> (Poly, Poly) {
    let d0 = fft_sub(t.0, z.0);
    let d1 = fft_sub(t.1, z.1);
    let s0 = fft_add(&fft_mul(&d0, &b.b00), &fft_mul(&d1, &b.b10));
    let s1 = fft_add(&fft_mul(&d0, &b.b01), &fft_mul(&d1, &b.b11));
    (s0, s1)
}

/// ‖s₀‖² + ‖s₁‖² ≤ ⌊β²⌋ in FFT-Form, als Maske (Alg. 10, Z. 8).
pub(crate) fn is_short_fft_mask(s0: &[Cplx], s1: &[Cplx], bound: u64) -> u64 {
    let norm = fft_norm_sq(s0) + fft_norm_sq(s1);
    !Fpr::of_i64(bound as i64).lt_mask(norm)
}

/// iFFT beider Komponenten, gerundet (Alg. 10, Z. 9).
pub(crate) fn to_coefficients(
    s0: &[Cplx],
    s1: &[Cplx],
) -> (Zeroizing<Vec<i64>>, Zeroizing<Vec<i64>>) {
    let r = |s: &[Cplx]| Zeroizing::new(ifft(s).iter().map(|x| x.rint()).collect::<Vec<i64>>());
    (r(s0), r(s1))
}

/// Ganzzahlige Normprüfung wie in Verify (Alg. 16, Z. 6).
fn is_short(s1: &[i64], s2: &[i64], bound: u64) -> bool {
    let norm: i64 = s1.iter().chain(s2).map(|&x| x * x).sum();
    norm as u64 <= bound
}

/// Teile des Secret Keys, die Sign braucht.
pub(crate) struct SignKey<'a> {
    pub f: &'a [i8],
    pub big_f: &'a [i8],
    pub basis: &'a Basis,
    pub tree: &'a Tree,
}

/// Sign (Alg. 10) mit festem Salt; liefert das komprimierte s₂.
///
/// Erlaubte Verzweigungen auf geheimen Daten (PLAN.md §6): Neustart, wenn
/// die Norm zu gross ist, und wenn s₂ nicht in die feste Länge passt (s₂
/// ist ab dann öffentlich). Wie Python und Alg. 10 bleibt das Salt bei
/// einem Neustart gleich, nur der Zufall läuft weiter.
pub(crate) fn sign_core(
    key: &SignKey,
    params: &Params,
    msg: &[u8],
    salt: &[u8; 40],
    rng: &mut impl RandomSource,
) -> Vec<u8> {
    let c = hash_to_point(salt, msg, params.n());
    let (t0, t1) = compute_target(&c, key.f, key.big_f);
    loop {
        let (s0, s1) = loop {
            let (z0, z1) = ff_sampling(&t0, &t1, key.tree, params, rng);
            let (s0, s1) = compute_signature_vector((&t0, &t1), (&z0, &z1), key.basis);
            if is_short_fft_mask(&s0, &s1, params.sig_bound) != 0 {
                break (s0, s1);
            }
        };
        let (c1, c2) = to_coefficients(&s0, &s1);
        if !is_short(&c1, &c2, params.sig_bound) {
            continue;
        }
        // Ab hier ist s₂ öffentlich. |s₂ᵢ| ≤ √β² < 2¹⁵ wegen der Normprüfung.
        let s2: Vec<i16> = c2.iter().map(|&x| x as i16).collect();
        if let Some(enc) = compress(&s2, params.s2_padded_len()) {
            return enc;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{decode_pk, decode_sk};
    use crate::kat;

    #[test]
    fn kat_public_key_from_secret_key() {
        for n in [512, 1024] {
            for rec in kat::load_kat(n).iter().take(20) {
                let sk = decode_sk(&rec.sk).unwrap();
                let (_, h) = decode_pk(&rec.pk).unwrap();
                assert_eq!(
                    compute_public_key(&sk.f, &sk.g).unwrap(),
                    h,
                    "count {}",
                    rec.count
                );
            }
        }
    }

    /// Zweite, von den KAT-Dateien unabhängige Quelle: Schlüssel und s₂ aus
    /// den Sampler-Testvektoren. h = g/f, dann Verify (wie Python
    /// `TestVerify.test_nist_vector`).
    #[test]
    fn nist_sampler_vector_verifies() {
        use crate::encoding::compress;
        use crate::params::{FALCON_1024, FALCON_512};
        for p in [&FALCON_512, &FALCON_1024] {
            let v = kat::load_sampler_vector(p.n());
            let f: Vec<i8> = v.f.iter().map(|&x| x as i8).collect();
            let g: Vec<i8> = v.g.iter().map(|&x| x as i8).collect();
            let h = compute_public_key(&f, &g).unwrap();
            let mut h_ntt: Vec<u32> = h.iter().map(|&x| x as u32).collect();
            modq::ntt(&mut h_ntt);
            let s2: Vec<i16> = v.s2.iter().map(|&x| x as i16).collect();
            let s2_enc = compress(&s2, p.s2_padded_len()).unwrap();

            assert!(
                verify(p, &h_ntt, &v.nonce, &s2_enc, &v.data),
                "n = {}",
                p.n()
            );
            let mut other = v.data.clone();
            other.push(b'!');
            assert!(!verify(p, &h_ntt, &v.nonce, &s2_enc, &other));
            let mut salt = v.nonce.clone();
            salt[0] ^= 1;
            assert!(!verify(p, &h_ntt, &salt, &s2_enc, &v.data));
        }
    }

    /// Die Schlüssel der Testvektoren erfüllen fG − gF = q (Gl. 3.15).
    /// Prüft die Testdaten selbst; NTRUSolve kommt in Phase 5.
    #[test]
    fn nist_sampler_vector_ntru_equation() {
        for n in [512, 1024] {
            let v = kat::load_sampler_vector(n);
            let mut lhs = vec![0i64; n];
            for i in 0..n {
                for j in 0..n {
                    let p = v.f[i] as i64 * v.big_g[j] as i64 - v.g[i] as i64 * v.big_f[j] as i64;
                    if i + j < n {
                        lhs[i + j] += p;
                    } else {
                        lhs[i + j - n] -= p;
                    }
                }
            }
            assert_eq!(lhs[0], crate::params::Q as i64);
            assert!(lhs[1..].iter().all(|&x| x == 0));
        }
    }

    #[test]
    fn mismatched_lengths_are_rejected() {
        let bad = Some(Error::InvalidEncoding("Länge von f, g"));
        assert_eq!(compute_public_key(&[1; 8], &[1; 4]).err(), bad);
        assert_eq!(compute_public_key(&[1; 6], &[1; 6]).err(), bad);
        assert_eq!(compute_public_key(&[1; 1], &[1; 1]).err(), bad);
        assert_eq!(compute_public_key(&[1; 2048], &[1; 2048]).err(), bad);
        assert_eq!(compute_public_key(&[], &[]).err(), bad);
    }

    #[test]
    fn non_invertible_f_is_rejected() {
        // f = 0 ist nicht invertierbar
        assert_eq!(
            compute_public_key(&[0; 8], &[1; 8]).err(),
            Some(Error::NotInvertible)
        );
    }

    // -----------------------------------------------------------------------
    // Sign
    // -----------------------------------------------------------------------

    use crate::kat::vectors::load;
    use crate::tree::tests::{bits, cplxs};

    fn i8s(c: &crate::kat::vectors::Case, key: &str) -> Vec<i8> {
        c.ints(key).into_iter().map(|x| x as i8).collect()
    }

    #[test]
    fn recompute_g_matches_python() {
        for c in load("ntrugen.recompute_G") {
            // Grad 1 gibt es in Rust nicht (LogN ab 1, also n ≥ 2).
            if c.ints("f").len() < 2 {
                continue;
            }
            let g = recompute_g(&i8s(&c, "f"), &i8s(&c, "g"), &i8s(&c, "F")).unwrap();
            let want: Vec<i16> = c.ints("out").into_iter().map(|x| x as i16).collect();
            assert_eq!(&g[..], &want[..], "Fall {}", c.index);
        }
    }

    #[test]
    fn compute_target_matches_python() {
        for c in load("falcon.compute_target") {
            let cc: Vec<u16> = c.ints("c").into_iter().map(|x| x as u16).collect();
            let (t0, t1) = compute_target(&cc, &i8s(&c, "f"), &i8s(&c, "F"));
            assert_eq!(bits(&t0), c.cplx("out0"), "Fall {}", c.index);
            assert_eq!(bits(&t1), c.cplx("out1"), "Fall {}", c.index);
        }
    }

    #[test]
    fn signature_vector_matches_python() {
        for c in load("falcon.compute_signature_vector") {
            let p = |k: &str| Poly::new(cplxs(&c, k));
            let b = Basis {
                b00: p("basis00"),
                b01: p("basis01"),
                b10: p("basis10"),
                b11: p("basis11"),
            };
            let (s0, s1) = compute_signature_vector(
                (&cplxs(&c, "t0"), &cplxs(&c, "t1")),
                (&cplxs(&c, "z0"), &cplxs(&c, "z1")),
                &b,
            );
            assert_eq!(bits(&s0), c.cplx("out0"), "Fall {}", c.index);
            assert_eq!(bits(&s1), c.cplx("out1"), "Fall {}", c.index);
        }
    }

    #[test]
    fn norm_checks_and_rounding_match_python() {
        use crate::params::{FALCON_1024, FALCON_512};
        for c in load("falcon.is_short_fft") {
            let p = if c.ints("params")[0] == 1024 {
                &FALCON_1024
            } else {
                &FALCON_512
            };
            let m = is_short_fft_mask(&cplxs(&c, "s0"), &cplxs(&c, "s1"), p.sig_bound);
            assert_eq!(m != 0, c.bool("out"), "Fall {}", c.index);
        }
        for c in load("falcon.to_coefficients") {
            let (a, b) = to_coefficients(&cplxs(&c, "s0"), &cplxs(&c, "s1"));
            let want = |k: &str| -> Vec<i64> { c.ints(k).into_iter().map(|x| x as i64).collect() };
            assert_eq!(&a[..], &want("out0")[..], "Fall {}", c.index);
            assert_eq!(&b[..], &want("out1")[..], "Fall {}", c.index);
        }
    }
}
