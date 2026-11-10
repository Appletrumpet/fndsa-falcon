//! Zufallsquelle für den Sampler (PLAN.md, L9).
//!
//! SamplerZ braucht pro Signatur viele Kilobyte Zufall. Statt jedes Byte
//! vom Betriebssystem zu holen, wird einmal ein Seed gezogen und daraus mit
//! einem schnellen, kryptographisch sicheren Generator gestreckt:
//!
//! Seed → SHAKE256 → 32 Bytes Schlüssel und 12 Bytes Nonce → ChaCha20.
//!
//! Wie die Referenz (prng_init, prng_refill), aber nicht byte-gleich mit
//! ihr: Wegen L7 (BerExp immer 8 Bytes) würden die Signaturen ohnehin von
//! der Referenz abweichen, ein gleicher Strom brächte also nichts.
//!
//! ChaCha20 arbeitet nur mit Additionen, Rotationen und XOR auf 32 Bit und
//! hat damit konstante Laufzeit. Schlüssel und Puffer werden beim Verwerfen
//! gelöscht.

// Wird erst von Sign benutzt (Phase 4); bis dahin nur in Tests.
#![allow(dead_code)]

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::{Zeroize, Zeroizing};

/// Quelle für Zufallsbytes, wie sie der Sampler braucht.
pub trait RandomSource {
    /// Füllt `out` mit Zufallsbytes.
    fn fill(&mut self, out: &mut [u8]);

    /// 8 Bytes für BerExp (Alg. 14), big-endian als Zahl gelesen.
    ///
    /// `_z` ist die Schwelle, mit der BerExp vergleicht. Der normale Weg
    /// braucht sie nicht. Nur der Test-Generator, der den Byteverbrauch von
    /// Python nachbildet (Alg. 14 bricht nach dem ersten entscheidenden Byte
    /// ab), wertet sie aus (PLAN.md §7, SamplerZ-Äquivalenz).
    fn ber_u64(&mut self, _z: u64) -> u64 {
        let mut b = Zeroizing::new([0u8; 8]);
        self.fill(&mut b[..]);
        u64::from_be_bytes(*b)
    }
}

/// ChaCha20-Generator, gestartet aus einem Seed über SHAKE256.
pub struct Prng {
    cipher: ChaCha20,
    buf: [u8; 64],
    /// Nächste unbenutzte Stelle in `buf`; 64 heisst leer.
    pos: usize,
}

impl Prng {
    /// Startet den Generator aus `seed` (beliebige Länge, in Sign 56 Bytes).
    pub fn new(seed: &[u8]) -> Prng {
        let mut h = Shake256::default();
        h.update(seed);
        let mut xof = h.finalize_xof();
        let mut key = Zeroizing::new([0u8; 32]);
        let mut nonce = Zeroizing::new([0u8; 12]);
        xof.read(&mut key[..]);
        xof.read(&mut nonce[..]);
        Prng {
            cipher: ChaCha20::new(&(*key).into(), &(*nonce).into()),
            buf: [0; 64],
            pos: 64,
        }
    }

    fn refill(&mut self) {
        // Schlüsselstrom = Verschlüsselung von Nullen
        self.buf = [0; 64];
        self.cipher.apply_keystream(&mut self.buf);
        self.pos = 0;
    }
}

impl RandomSource for Prng {
    fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.pos == 64 {
                self.refill();
            }
            let k = (64 - self.pos).min(out.len() - done);
            out[done..done + k].copy_from_slice(&self.buf[self.pos..self.pos + k]);
            // benutzte Bytes sofort löschen
            self.buf[self.pos..self.pos + k].zeroize();
            self.pos += k;
            done += k;
        }
    }
}

impl Drop for Prng {
    fn drop(&mut self) {
        // `cipher` löscht sich selbst (Feature `zeroize` von chacha20).
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(p: &mut Prng, n: usize) -> Vec<u8> {
        let mut v = vec![0; n];
        p.fill(&mut v);
        v
    }

    #[test]
    fn deterministic_and_seed_dependent() {
        let a = bytes(&mut Prng::new(b"seed"), 300);
        let b = bytes(&mut Prng::new(b"seed"), 300);
        let c = bytes(&mut Prng::new(b"seee"), 300);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Stückweise gelesen ergibt denselben Strom
        let mut p = Prng::new(b"seed");
        let mut pieces = Vec::new();
        for k in [1, 7, 64, 0, 63, 100, 65] {
            pieces.extend(bytes(&mut p, k));
        }
        assert_eq!(pieces, a);
    }

    /// Der Strom ist ChaCha20 mit Schlüssel und Nonce aus SHAKE256(seed).
    #[test]
    fn is_chacha20_keyed_by_shake() {
        let mut h = Shake256::default();
        h.update(b"abc");
        let mut kn = [0u8; 44];
        h.finalize_xof().read(&mut kn);
        let mut want = [0u8; 128];
        let key: [u8; 32] = kn[..32].try_into().unwrap();
        let nonce: [u8; 12] = kn[32..].try_into().unwrap();
        ChaCha20::new(&key.into(), &nonce.into()).apply_keystream(&mut want);
        assert_eq!(bytes(&mut Prng::new(b"abc"), 128), want);
    }

    #[test]
    fn roughly_uniform() {
        let v = bytes(&mut Prng::new(b"uniform"), 1 << 16);
        let ones: u32 = v.iter().map(|b| b.count_ones()).sum();
        let bits = (v.len() * 8) as f64;
        // 4 Standardabweichungen um bits/2
        assert!((ones as f64 - bits / 2.0).abs() < 4.0 * (bits / 4.0).sqrt());
    }
}
