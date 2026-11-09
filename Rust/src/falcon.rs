//! Bausteine der Top-Level-Funktionen (Ebene 2). Bisher: Public Key aus
//! f, g berechnen und Verify. Keygen und Sign folgen in Phase 4/5.
//!
//! Spec-Referenz: Alg. 4 Z. 9, Alg. 16. Entspricht `Python/falcon/falcon.py`.

use zeroize::Zeroizing;

use crate::encoding::decompress;
use crate::hashing::hash_to_point;
use crate::modq;
use crate::params::Params;
use crate::Error;

/// h = g · f⁻¹ mod q. Alg. 4, Z. 9.
///
/// f und g sind geheim: NTT, Invertierbarkeitstest und Inverse laufen ohne
/// Verzweigung auf den Werten (PLAN.md, 3.7). Nur das Ergebnis
/// „f invertierbar ja/nein“ verzweigt; ein nicht invertierbares f wird beim
/// Keygen verworfen.
pub(crate) fn compute_public_key(f: &[i8], g: &[i8]) -> Result<Vec<u16>, Error> {
    let mut ft: Zeroizing<Vec<u32>> = Zeroizing::new(f.iter().map(|&x| modq::from_i32(x as i32)).collect());
    let mut gt: Zeroizing<Vec<u32>> = Zeroizing::new(g.iter().map(|&x| modq::from_i32(x as i32)).collect());
    modq::ntt(&mut ft);
    modq::ntt(&mut gt);
    if modq::any_zero_mask(&ft) != 0 {
        return Err(Error::NotInvertible);
    }
    let mut h: Vec<u32> = ft.iter().zip(gt.iter()).map(|(&a, &b)| modq::mul(b, modq::inv(a))).collect();
    modq::intt(&mut h);
    Ok(h.into_iter().map(|x| x as u16).collect())
}

/// Verify (Alg. 16). Alles hier ist öffentlich, normaler Code erlaubt.
///
/// `h_ntt` ist h in NTT-Form (im `VerifyingKey` vorberechnet).
pub(crate) fn verify(params: &Params, h_ntt: &[u32], salt: &[u8], s2_enc: &[u8], msg: &[u8]) -> bool {
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
                assert_eq!(compute_public_key(&sk.f, &sk.g).unwrap(), h, "count {}", rec.count);
            }
        }
    }

    #[test]
    fn non_invertible_f_is_rejected() {
        // f = 0 ist nicht invertierbar
        assert_eq!(compute_public_key(&[0; 8], &[1; 8]).err(), Some(Error::NotInvertible));
    }
}
