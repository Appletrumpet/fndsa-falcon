//! FN-DSA (Falcon) in Rust, mit konstanter Laufzeit auf geheimen Daten.
//!
//! Stand: Phase 0 bis 4 aus `PLAN.md` – Parameter, Arithmetik mod q,
//! HashToPoint, Byteformate, Verify, emulierte Gleitkommazahlen, FFT,
//! Sampler und Sign. Keygen folgt in Phase 5; bis dahin werden Secret Keys
//! geladen (z. B. aus den NIST-KAT-Dateien).
//!
//! ```no_run
//! use fndsa::{Signature, SigningKey, VerifyingKey};
//! # struct R; impl rand_core::RngCore for R { fn next_u32(&mut self) -> u32 { 0 }
//! # fn next_u64(&mut self) -> u64 { 0 } fn fill_bytes(&mut self, _: &mut [u8]) {}
//! # fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> { Ok(()) } }
//! # impl rand_core::CryptoRng for R {}
//! # let (sk_bytes, msg, mut rng) = (vec![0u8], b"msg", R);
//! let sk = SigningKey::from_bytes(&sk_bytes).unwrap();
//! let sig = sk.sign(msg, &mut rng); // rng: z. B. rand_core::OsRng
//! let pk: VerifyingKey = sk.verifying_key();
//! assert!(pk.verify(msg, &Signature::from_bytes(&sig.to_bytes()).unwrap()));
//! ```

#![warn(missing_docs)]

// Bausteine, die erst Keygen (Phase 5) braucht, tragen einzeln
// `#[allow(dead_code)]`. Mit dem Aufruf in Phase 5 wird es entfernt.
mod ct;
mod encoding;
mod falcon;
mod ffsampling;
mod fft;
mod fft_table;
mod fpr;
mod hashing;
mod modq;
mod params;
mod prng;
mod sampler;
mod tree;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod kat;

use std::fmt;

use zeroize::Zeroizing;

pub use params::{LogN, Params, FALCON_1024, FALCON_512, Q};

/// Fehler beim Dekodieren oder Erzeugen von Schlüsseln und Signaturen.
///
/// `non_exhaustive`: Sign und Keygen (Phase 4/5) bringen neue Fälle dazu.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// logn liegt nicht in 1..=10.
    InvalidLogN,
    /// Für dieses logn gibt es (noch) keinen vollständigen Parametersatz;
    /// bisher nur Falcon-512 und Falcon-1024.
    UnsupportedLogN,
    /// Byteformat ungültig (Grund als Text).
    InvalidEncoding(&'static str),
    /// Ein Koeffizient von f, g oder F passt nicht ins Secret-Key-Format (L6).
    KeyOutOfRange,
    /// f ist modulo q nicht invertierbar.
    NotInvertible,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLogN => write!(f, "logn muss im Bereich 1..=10 liegen"),
            Error::UnsupportedLogN => write!(f, "kein Parametersatz für dieses logn"),
            Error::InvalidEncoding(why) => write!(f, "ungültige Kodierung: {why}"),
            Error::KeyOutOfRange => write!(f, "Schlüssel passt nicht ins Secret-Key-Format"),
            Error::NotInvertible => write!(f, "f ist modulo q nicht invertierbar"),
        }
    }
}

impl std::error::Error for Error {}

/// Public Key h (§3.11.4). Hält h zusätzlich in NTT-Form für Verify.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    params: &'static Params,
    h: Vec<u16>,
    h_ntt: Vec<u32>,
}

impl VerifyingKey {
    /// Dekodiert einen Public Key (Header 0000nnnn, 14 Bit je Koeffizient).
    ///
    /// Fehler `UnsupportedLogN`, wenn das Format zwar gültig ist, es für den
    /// Grad aber keinen Parametersatz gibt (bisher alles ausser 512/1024).
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (logn, h) = encoding::decode_pk(b)?;
        let params = logn.params().ok_or(Error::UnsupportedLogN)?;
        let mut h_ntt: Vec<u32> = h.iter().map(|&x| x as u32).collect();
        modq::ntt(&mut h_ntt);
        Ok(VerifyingKey { params, h, h_ntt })
    }

    /// Kodiert den Public Key (§3.11.4); Umkehrung von `from_bytes`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encoding::encode_pk(self.params.logn, &self.h)
    }

    /// Grad des Schlüssels (log₂ n).
    pub fn logn(&self) -> LogN {
        self.params.logn
    }

    /// Verify (Alg. 16). `false` bei anderem Grad als der Schlüssel,
    /// ungültiger Kodierung von s₂ oder zu grosser Norm.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        sig.logn == self.params.logn
            && falcon::verify(self.params, &self.h_ntt, &sig.salt, &sig.s2_enc, msg)
    }
}

// Gleich, wenn Grad und h gleich sind (h_ntt folgt daraus).
impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.params.logn == other.params.logn && self.h == other.h
    }
}

impl Eq for VerifyingKey {}

/// Secret Key (§3.11.5) mit vorberechneter Basis und Falcon-Baum
/// (Alg. 4, Z. 2–7). Alles darin ist geheim: kein `Debug`, kein
/// Vergleich, und beim Verwerfen werden alle Puffer gelöscht.
pub struct SigningKey {
    params: &'static Params,
    f: Zeroizing<Vec<i8>>,
    g: Zeroizing<Vec<i8>>,
    big_f: Zeroizing<Vec<i8>>,
    /// enthält Ĝ (G selbst wird nach dem Aufbau nicht mehr gebraucht)
    basis: tree::Basis,
    tree: tree::Tree,
}

impl SigningKey {
    /// Lädt einen Secret Key (Header 0101nnnn, f, g, F). Berechnet G aus
    /// der NTRU-Gleichung neu und baut Basis und Falcon-Baum auf.
    ///
    /// Fehler: ungültige Kodierung, `UnsupportedLogN` (bisher nur 512 und
    /// 1024), `NotInvertible` (f nicht invertierbar mod q, also kein
    /// gültiger Falcon-Schlüssel).
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let sk = encoding::decode_sk(b)?;
        let params = sk.logn.params().ok_or(Error::UnsupportedLogN)?;
        let big_g = falcon::recompute_g(&sk.f, &sk.g, &sk.big_f)?;
        let basis = tree::build_basis_fft(&sk.f, &sk.g, &sk.big_f, &big_g);
        let tree = tree::build_falcon_tree(&basis, fpr::Fpr::from_bits(params.sigma.to_bits()));
        Ok(SigningKey {
            params,
            f: Zeroizing::new(sk.f.clone()),
            g: Zeroizing::new(sk.g.clone()),
            big_f: Zeroizing::new(sk.big_f.clone()),
            basis,
            tree,
        })
    }

    /// Kodiert den Secret Key (§3.11.5); Umkehrung von `from_bytes`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let sk = encoding::SecretPolys {
            logn: self.params.logn,
            f: self.f.to_vec(),
            g: self.g.to_vec(),
            big_f: self.big_f.to_vec(),
        };
        // f, g, F stammen aus decode_sk und passen deshalb immer ins Format.
        encoding::encode_sk(&sk).expect("f, g, F passen ins Secret-Key-Format")
    }

    /// Grad des Schlüssels (log₂ n).
    pub fn logn(&self) -> LogN {
        self.params.logn
    }

    /// Der passende Public Key h = g/f mod q.
    pub fn verifying_key(&self) -> VerifyingKey {
        // f ist invertierbar, das hat `from_bytes` geprüft.
        let h = falcon::compute_public_key(&self.f, &self.g).expect("f ist invertierbar");
        let mut h_ntt: Vec<u32> = h.iter().map(|&x| x as u32).collect();
        modq::ntt(&mut h_ntt);
        VerifyingKey {
            params: self.params,
            h,
            h_ntt,
        }
    }

    /// Signiert `msg` (Alg. 10). Aus `rng` kommen 40 Bytes Salt und 56
    /// Bytes Seed für den Zufall des Samplers (ChaCha20, PLAN.md L9).
    pub fn sign(&self, msg: &[u8], rng: &mut impl rand_core::CryptoRngCore) -> Signature {
        let mut salt = [0u8; 40];
        rng.fill_bytes(&mut salt);
        let mut seed = Zeroizing::new([0u8; 56]);
        rng.fill_bytes(&mut seed[..]);
        let mut prng = prng::Prng::new(&seed[..]);
        let s2_enc = falcon::sign_core(&self.sign_key(), self.params, msg, &salt, &mut prng);
        Signature {
            logn: self.params.logn,
            salt,
            s2_enc,
        }
    }

    fn sign_key(&self) -> falcon::SignKey<'_> {
        falcon::SignKey {
            f: &self.f,
            big_f: &self.big_f,
            basis: &self.basis,
            tree: &self.tree,
        }
    }
}

/// Signatur (§3.11.3): Header 0011nnnn, 40 Bytes Salt, komprimiertes s₂.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    logn: LogN,
    salt: [u8; 40],
    s2_enc: Vec<u8>,
}

impl Signature {
    /// Dekodiert eine Signatur. Ob s₂ gültig kodiert ist, prüft erst
    /// `verify`. Keine Obergrenze für die Länge: ungepolsterte Signaturen
    /// dürfen länger als die feste Länge sein (§3.11.3).
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 42 {
            return Err(Error::InvalidEncoding("Signatur zu kurz"));
        }
        if b[0] >> 4 != 0b0011 {
            return Err(Error::InvalidEncoding("Signatur-Header"));
        }
        let logn = LogN::new((b[0] & 0x0F) as u32)?;
        let mut salt = [0u8; 40];
        salt.copy_from_slice(&b[1..41]);
        Ok(Signature {
            logn,
            salt,
            s2_enc: b[41..].to_vec(),
        })
    }

    /// Kodiert die Signatur; gibt genau die Bytes zurück, aus denen sie
    /// dekodiert wurde (gepolstert oder ungepolstert).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41 + self.s2_enc.len());
        out.push(0x30 | self.logn.get() as u8);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.s2_enc);
        out
    }

    /// Grad aus dem Header der Signatur (log₂ n).
    pub fn logn(&self) -> LogN {
        self.logn
    }

    /// Die 40 Bytes Salt r.
    pub fn salt(&self) -> &[u8; 40] {
        &self.salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::vectors::load;
    use crate::prng::testing::Replay;
    use crate::prng::RandomSource;

    /// Sign mit dem SHAKE-Strom der Python-Vektoren: Salt aus den ersten
    /// 40 Bytes, danach Zufall für den Sampler mit dem Byteverbrauch von
    /// Python. Ergibt exakt die Signatur aus Python.
    fn sign_like_python(sk: &SigningKey, params: &Params, msg: &[u8], seed: &[u8]) -> Vec<u8> {
        let mut src = Replay::shake(seed);
        let mut salt = [0u8; 40];
        src.fill(&mut salt);
        let enc = falcon::sign_core(&sk.sign_key(), params, msg, &salt, &mut src);
        let mut out = vec![0x30 | params.logn.get() as u8];
        out.extend_from_slice(&salt);
        out.extend_from_slice(&enc);
        out
    }

    #[test]
    fn flow_sign_matches_python() {
        let cases = load("flow.sign");
        assert!(!cases.is_empty());
        for c in cases {
            let sk = SigningKey::from_bytes(&c.bytes("sk")).unwrap();
            assert_eq!(&sk.to_bytes()[..], &c.bytes("sk")[..]);
            let sig = sign_like_python(&sk, sk.params, &c.bytes("msg"), &c.bytes("seed"));
            assert_eq!(sig, c.bytes("sig"), "Fall {}", c.index);
        }
    }

    /// Knappe Schranken erzwingen beide Neustarts aus Alg. 10 (Norm zu
    /// gross, s₂ passt nicht in die Länge).
    #[test]
    fn flow_sign_restart_matches_python() {
        let cases = load("flow.sign_restart");
        assert!(!cases.is_empty());
        for c in cases {
            let sk = SigningKey::from_bytes(&c.bytes("sk")).unwrap();
            let base = sk.params;
            let params = Params {
                logn: base.logn,
                sigma: base.sigma,
                sigma_min: base.sigma_min,
                sigma_max: base.sigma_max,
                sig_bound: c.int("sig_bound") as u64,
                sig_bytelen: c.int("sig_bytelen") as usize,
            };
            let sig = sign_like_python(&sk, &params, &c.bytes("msg"), &c.bytes("seed"));
            assert_eq!(sig, c.bytes("sig"), "Fall {}", c.index);
        }
    }
}
