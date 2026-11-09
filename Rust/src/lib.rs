//! FN-DSA (Falcon) in Rust, mit konstanter Laufzeit auf geheimen Daten.
//!
//! Stand: Phase 0 und 1 aus `PLAN.md` – Parameter, Arithmetik mod q,
//! HashToPoint, Byteformate und Verify. Keygen und Sign folgen.
//!
//! ```no_run
//! use fndsa::{Signature, VerifyingKey};
//! # let (pk_bytes, sig_bytes, msg) = (vec![0u8], vec![0u8], b"msg");
//! let pk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
//! let sig = Signature::from_bytes(&sig_bytes).unwrap();
//! assert!(pk.verify(msg, &sig));
//! ```

// compress, das Secret-Key-Format und h = g/f sind schon umgesetzt und
// getestet, werden aber erst von Sign und Keygen (Phase 4/5) benutzt. Bis
// dahin keine Warnungen für ungenutzten Code; danach `allow` entfernen.
#[allow(dead_code)]
mod ct;
#[allow(dead_code)]
mod encoding;
#[allow(dead_code)]
mod falcon;
mod hashing;
#[allow(dead_code)]
mod modq;
mod params;

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod kat;

use std::fmt;

pub use params::{LogN, Params, FALCON_1024, FALCON_512, Q};

/// Fehler beim Dekodieren oder Erzeugen von Schlüsseln und Signaturen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// logn liegt nicht in 1..=10.
    InvalidLogN,
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
            Error::InvalidEncoding(why) => write!(f, "ungültige Kodierung: {why}"),
            Error::KeyOutOfRange => write!(f, "Schlüssel passt nicht ins Secret-Key-Format"),
            Error::NotInvertible => write!(f, "f ist modulo q nicht invertierbar"),
        }
    }
}

impl std::error::Error for Error {}

/// Public Key h (§3.11.4). Hält h zusätzlich in NTT-Form für Verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    logn: LogN,
    h: Vec<u16>,
    h_ntt: Vec<u32>,
}

impl VerifyingKey {
    /// Dekodiert einen Public Key (Header 0000nnnn, 14 Bit je Koeffizient).
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (logn, h) = encoding::decode_pk(b)?;
        Ok(Self::from_h(logn, h))
    }

    fn from_h(logn: LogN, h: Vec<u16>) -> Self {
        let mut h_ntt: Vec<u32> = h.iter().map(|&x| x as u32).collect();
        modq::ntt(&mut h_ntt);
        VerifyingKey { logn, h, h_ntt }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encoding::encode_pk(self.logn, &self.h)
    }

    pub fn logn(&self) -> LogN {
        self.logn
    }

    /// Verify (Alg. 16). `false` bei falschem Grad, ungültiger Kodierung von
    /// s₂ oder zu grosser Norm. Nur für Falcon-512 und Falcon-1024; für
    /// verkleinerte Grade fehlen bisher die Parameter (immer `false`).
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        if sig.logn != self.logn {
            return false;
        }
        match self.logn.params() {
            Some(p) => falcon::verify(p, &self.h_ntt, &sig.salt, &sig.s2_enc, msg),
            None => false,
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
        Ok(Signature { logn, salt, s2_enc: b[41..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41 + self.s2_enc.len());
        out.push(0x30 | self.logn.get() as u8);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.s2_enc);
        out
    }

    pub fn logn(&self) -> LogN {
        self.logn
    }

    pub fn salt(&self) -> &[u8; 40] {
        &self.salt
    }
}
