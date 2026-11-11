//! Parametersätze für Falcon-512 und Falcon-1024.
//!
//! Spec-Referenz: Tab. 3.3, §3.13. Entspricht `Python/falcon/params.py`.
//!
//! `LogN` erlaubt 1..=10, damit Kodierung und NTT auch für verkleinerte
//! Grade getestet werden können. Vollständige Parametersätze (σ, β², Länge
//! der Signatur) gibt es nur für 512 und 1024; die verkleinerten Varianten
//! kommen in Phase 5 dazu (PLAN.md, Abschnitt 5).

use crate::Error;

/// Der Modulus q = 12289.
pub const Q: u32 = 12289;

/// log₂ n, geprüft auf 1..=10.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LogN(u32);

impl LogN {
    /// Falcon-512.
    pub const FALCON_512: LogN = LogN(9);
    /// Falcon-1024.
    pub const FALCON_1024: LogN = LogN(10);

    /// Prüft, dass `logn` im Bereich 1..=10 liegt.
    pub fn new(logn: u32) -> Result<LogN, Error> {
        if (1..=10).contains(&logn) {
            Ok(LogN(logn))
        } else {
            Err(Error::InvalidLogN)
        }
    }

    /// log₂ n.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Polynomgrad n = 2^logn.
    pub fn n(self) -> usize {
        1usize << self.0
    }

    /// Bitbreite von f und g im Secret Key (§3.11.5).
    pub fn fg_bits(self) -> u32 {
        match self.0 {
            1..=5 => 8,
            6..=7 => 7,
            8..=9 => 6,
            _ => 5,
        }
    }

    /// Länge des Public Keys in Bytes (§3.11.4).
    pub fn pk_bytes(self) -> usize {
        1 + (14 * self.n()).div_ceil(8)
    }

    /// Länge des Secret Keys in Bytes (§3.11.5).
    pub fn sk_bytes(self) -> usize {
        1 + (2 * self.n() * self.fg_bits() as usize) / 8 + self.n()
    }

    /// Vollständiger Parametersatz, nur für Falcon-512 und Falcon-1024.
    pub fn params(self) -> Option<&'static Params> {
        match self.0 {
            9 => Some(&FALCON_512),
            10 => Some(&FALCON_1024),
            _ => None,
        }
    }
}

/// Parametersatz einer Falcon-Instanz (Tab. 3.3).
///
/// Die Felder sind nicht öffentlich, damit sich ihr Typ ändern darf: σ,
/// σmin und σmax stehen hier als `f64` zur Dokumentation und werden ab
/// Phase 3 als emulierte Gleitkommazahlen (`fpr`) verwendet (PLAN.md, 3.3).
#[derive(Debug)]
pub struct Params {
    pub(crate) logn: LogN,
    pub(crate) sigma: f64,
    pub(crate) sigma_min: f64,
    pub(crate) sigma_max: f64,
    /// ⌊β²⌋, maximale quadrierte Norm einer Signatur.
    pub(crate) sig_bound: u64,
    /// Feste Länge der Signatur in Bytes (Header + Salt + s₂).
    pub(crate) sig_bytelen: usize,
}

impl Params {
    /// log₂ n.
    pub fn logn(&self) -> LogN {
        self.logn
    }

    /// Polynomgrad n.
    pub fn n(&self) -> usize {
        self.logn.n()
    }

    /// ⌊β²⌋, maximale quadrierte Norm einer gültigen Signatur.
    pub fn sig_bound(&self) -> u64 {
        self.sig_bound
    }

    /// Feste Länge der Signatur in Bytes (Header + Salt + s₂, gepolstert).
    pub fn sig_bytelen(&self) -> usize {
        self.sig_bytelen
    }

    /// Länge des gepolsterten s₂ in Bytes: sig_bytelen − 1 − 40.
    pub fn s2_padded_len(&self) -> usize {
        self.sig_bytelen - 41
    }
}

/// Falcon-512, NIST-Sicherheitsstufe I.
pub static FALCON_512: Params = Params {
    logn: LogN::FALCON_512,
    sigma: 165.736617183,
    sigma_min: 1.277833697,
    sigma_max: 1.8205,
    sig_bound: 34034726,
    sig_bytelen: 666,
};

/// Falcon-1024, NIST-Sicherheitsstufe V.
pub static FALCON_1024: Params = Params {
    logn: LogN::FALCON_1024,
    sigma: 168.388571447,
    sigma_min: 1.298280334,
    sigma_max: 1.8205,
    sig_bound: 70265242,
    sig_bytelen: 1280,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logn_range() {
        assert!(LogN::new(0).is_err());
        assert!(LogN::new(11).is_err());
        for l in 1..=10 {
            assert_eq!(LogN::new(l).unwrap().n(), 1 << l);
        }
    }

    #[test]
    fn table_3_3() {
        assert_eq!(FALCON_512.n(), 512);
        assert_eq!(FALCON_1024.n(), 1024);
        assert_eq!(FALCON_512.sig_bound, 34034726);
        assert_eq!(FALCON_1024.sig_bound, 70265242);
        assert_eq!(FALCON_512.sig_bytelen, 666);
        assert_eq!(FALCON_1024.sig_bytelen, 1280);
        // q ist prim und q ≡ 1 mod 2n für alle n ≤ 1024
        assert_eq!((Q - 1) % 2048, 0);
        assert!((2..Q)
            .take_while(|d| d * d <= Q)
            .all(|d| !Q.is_multiple_of(d)));
    }

    #[test]
    fn key_lengths() {
        assert_eq!(LogN::FALCON_512.pk_bytes(), 897);
        assert_eq!(LogN::FALCON_1024.pk_bytes(), 1793);
        assert_eq!(LogN::FALCON_512.sk_bytes(), 1281);
        assert_eq!(LogN::FALCON_1024.sk_bytes(), 2305);
    }
}
