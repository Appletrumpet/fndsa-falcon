//! Einstiegspunkte für Fuzzing (PLAN.md, §7): alles, was Daten von aussen
//! verarbeitet. Sichtbar nur mit dem Feature `fuzzing`.
//!
//! Jede Funktion darf bei keiner Eingabe abstürzen und prüft zusätzlich eine
//! Eigenschaft (z. B. Kodieren nach Dekodieren ergibt dieselben Bytes). Die
//! Fuzz-Ziele in `fuzz/` rufen nur diese Funktionen auf. Die Unit-Tests
//! unten rufen sie mit Zufallsdaten und beschädigten KAT-Daten auf, damit
//! sie auch ohne `cargo fuzz` (Linux/WSL, Nightly) geprüft sind.

use crate::encoding;
use crate::params::{FALCON_1024, FALCON_512};
use crate::prng::{Prng, RandomSource};
use crate::{Signature, SigningKey, VerifyingKey};

/// Feste Zufallsquelle für das Fuzz-Ziel `signing_key` (ChaCha20 aus einem
/// festen Seed), damit Läufe reproduzierbar sind.
struct FuzzRng(Prng);

impl rand_core::RngCore for FuzzRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for FuzzRng {}

/// Secret Key laden; wenn gültig: wieder kodieren, signieren, prüfen. Darf
/// bei keiner Eingabe abstürzen oder hängen (Sign mit erfundenem Schlüssel
/// lief früher endlos, siehe `SigningKey::from_bytes`).
pub fn signing_key(data: &[u8]) {
    if let Ok(sk) = SigningKey::from_bytes(data) {
        assert_eq!(&sk.to_bytes()[..], data);
        let mut rng = FuzzRng(Prng::new(b"fuzz"));
        let sig = sk.sign(b"fuzz", &mut rng);
        assert!(sk.verifying_key().verify(b"fuzz", &sig));
    }
}

/// Public Key: dekodieren, und wenn gültig, wieder kodieren.
pub fn decode_pk(data: &[u8]) {
    if let Ok(pk) = VerifyingKey::from_bytes(data) {
        assert_eq!(pk.to_bytes(), data);
    }
}

/// Secret Key: dekodieren, und wenn gültig, wieder kodieren.
pub fn decode_sk(data: &[u8]) {
    if let Ok(sk) = encoding::decode_sk(data) {
        let enc = encoding::encode_sk(&sk).expect("dekodierter Key muss kodierbar sein");
        assert_eq!(&enc[..], data);
    }
}

/// s₂: dekodieren für beide Parametersätze; gültige Werte sind ≤ 2047 und
/// überstehen Kodieren und Dekodieren.
pub fn decompress(data: &[u8]) {
    for p in [&FALCON_512, &FALCON_1024] {
        if let Some(s) = encoding::decompress(data, p.n(), p.s2_padded_len()) {
            assert_eq!(s.len(), p.n());
            assert!(s
                .iter()
                .all(|&x| x.unsigned_abs() as u32 <= encoding::S2_MAX));
            if let Some(enc) = encoding::compress(&s, p.s2_padded_len()) {
                assert_eq!(
                    encoding::decompress(&enc, p.n(), p.s2_padded_len()).unwrap(),
                    s
                );
            }
        }
    }
}

/// Verify mit beliebigem Public Key, beliebiger Signatur und Nachricht.
/// Aufbau: Public Key (897 oder 1793 Bytes, je nach erstem Byte), dann
/// 2 Bytes Signaturlänge (big-endian), Signatur, Rest = Nachricht.
pub fn verify(data: &[u8]) {
    let pk_len = match data.first() {
        Some(0x09) => 897,
        Some(0x0A) => 1793,
        _ => return,
    };
    if data.len() < pk_len + 2 {
        return;
    }
    let (pk_bytes, rest) = data.split_at(pk_len);
    let Ok(pk) = VerifyingKey::from_bytes(pk_bytes) else {
        return;
    };
    let siglen = (u16::from_be_bytes([rest[0], rest[1]]) as usize).min(rest.len() - 2);
    let (sig_bytes, msg) = rest[2..].split_at(siglen);
    if let Ok(sig) = Signature::from_bytes(sig_bytes) {
        assert_eq!(sig.to_bytes(), sig_bytes);
        let _ = pk.verify(msg, &sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn random_inputs_do_not_panic() {
        let mut r = Rng(0x5EED);
        for _ in 0..2000 {
            let len = (r.next() % 2000) as usize;
            let mut d = r.bytes(len);
            decode_pk(&d);
            decode_sk(&d);
            decompress(&d);
            // gültige Header erzwingen, damit die Prüfungen weiter laufen
            if !d.is_empty() {
                d[0] = 0x09;
            }
            decode_pk(&d);
            verify(&d);
            if !d.is_empty() {
                d[0] = 0x59;
            }
            decode_sk(&d);
        }
    }

    /// KAT-Daten an jeder Stelle kürzen und einzelne Bits umdrehen.
    #[test]
    fn damaged_kat_inputs() {
        let mut r = Rng(0xFA11);
        for n in [512, 1024] {
            for rec in kat::load_kat(n).iter().take(3) {
                let (msg, sig) = kat::split_kat_sm(&rec.sm, rec.msg.len());
                for cut in 0..rec.pk.len() {
                    decode_pk(&rec.pk[..cut]);
                }
                for cut in 0..rec.sk.len() {
                    decode_sk(&rec.sk[..cut]);
                }
                for cut in 0..sig.len() - 41 {
                    decompress(&sig[41..41 + cut]);
                }

                let pk = VerifyingKey::from_bytes(&rec.pk).unwrap();
                for _ in 0..200 {
                    let i = (r.next() as usize) % sig.len();
                    let bit = 1u8 << (r.next() % 8);
                    let mut bad = sig.clone();
                    bad[i] ^= bit;
                    // Jede Änderung an Header, Salt oder s₂ muss abgelehnt werden.
                    let ok = Signature::from_bytes(&bad)
                        .map(|s| pk.verify(&msg, &s))
                        .unwrap_or(false);
                    assert!(!ok, "count {} Byte {i} Bit {bit:#x}", rec.count);

                    let mut bad_sk = rec.sk.clone();
                    let j = (r.next() as usize) % bad_sk.len();
                    bad_sk[j] ^= bit;
                    decode_sk(&bad_sk);
                    let mut bad_pk = rec.pk.clone();
                    let j = (r.next() as usize) % bad_pk.len();
                    bad_pk[j] ^= bit;
                    decode_pk(&bad_pk);
                }

                // Laden und Signieren mit echtem und beschädigtem Secret Key
                signing_key(&rec.sk);
                for _ in 0..5 {
                    let mut bad_sk = rec.sk.clone();
                    let j = 1 + (r.next() as usize) % (bad_sk.len() - 1);
                    bad_sk[j] ^= 1u8 << (r.next() % 8);
                    signing_key(&bad_sk);
                }

                // gültige Eingabe für das Verify-Ziel
                let mut d = rec.pk.clone();
                d.extend((sig.len() as u16).to_be_bytes());
                d.extend(&sig);
                d.extend(&msg);
                verify(&d);
            }
        }
    }
}
