//! Einstiegspunkte für Fuzzing (PLAN.md, §7): alles, was Daten von aussen
//! verarbeitet. Sichtbar nur mit dem Feature `fuzzing`.
//!
//! Jede Funktion darf bei keiner Eingabe abstürzen und prüft zusätzlich eine
//! Eigenschaft (z. B. Kodieren nach Dekodieren ergibt dieselben Bytes). Die
//! Fuzz-Ziele in `fuzz/` rufen nur diese Funktionen auf. Die Unit-Tests
//! unten rufen sie mit Zufallsdaten und beschädigten KAT-Daten auf, damit
//! sie auch ohne `cargo fuzz` (Linux/WSL, Nightly) geprüft sind.

use std::sync::OnceLock;

use crate::encoding;
use crate::fpr::Fpr;
use crate::params::{LogN, FALCON_1024, FALCON_512};
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

/// Zufallsquelle aus den Fuzz-Daten: liefert deren Bytes der Reihe nach,
/// danach Nullen. So steuert der Fuzzer Salt und Zufall des Samplers.
struct DataRng<'a>(&'a [u8]);

impl rand_core::RngCore for DataRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let k = dest.len().min(self.0.len());
        dest[..k].copy_from_slice(&self.0[..k]);
        dest[k..].fill(0);
        self.0 = &self.0[k..];
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for DataRng<'_> {}

/// Zwei feste Schlüssel (Falcon-512 und -1024), einmal erzeugt.
fn fixed_keys() -> &'static [SigningKey; 2] {
    static KEYS: OnceLock<[SigningKey; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [LogN::FALCON_512, LogN::FALCON_1024]
            .map(|l| crate::keygen_from_seed(l, &[0xF0; 48]).unwrap().0)
    })
}

/// Sign mit beliebigem Zufall und beliebiger Nachricht. Aufbau: 1 Byte
/// Auswahl des Schlüssels, bis zu 96 Bytes Zufall (Salt und Seed, fehlende
/// Bytes sind 0), Rest = Nachricht. Die Signatur muss ohne Fehler entstehen,
/// die feste Länge haben und Verify bestehen.
pub fn sign(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let sk = &fixed_keys()[(sel & 1) as usize];
    let (rnd, msg) = rest.split_at(rest.len().min(96));
    let sig = sk
        .try_sign(msg, &mut DataRng(rnd))
        .expect("Sign ohne Fehler im Rechner");
    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), sk.params.sig_bytelen());
    assert!(sk
        .verifying_key()
        .verify(msg, &Signature::from_bytes(&bytes).unwrap()));
}

/// Keygen aus beliebigem Seed (die ersten 48 Bytes, fehlende sind 0; Bit 0
/// von Byte 48 wählt Falcon-1024). Der Schlüssel muss sich speichern und
/// wieder laden lassen und denselben Public Key ergeben.
pub fn keygen(data: &[u8]) {
    let mut seed = [0u8; 48];
    let k = data.len().min(48);
    seed[..k].copy_from_slice(&data[..k]);
    let logn = if data.get(48).is_some_and(|b| b & 1 == 1) {
        LogN::FALCON_1024
    } else {
        LogN::FALCON_512
    };
    let (sk, pk) = crate::keygen_from_seed(logn, &seed).unwrap();
    let loaded = SigningKey::from_bytes(&sk.to_bytes()).expect("Keygen-Schlüssel lädt");
    assert!(loaded.verifying_key() == pk);
    assert!(VerifyingKey::from_bytes(&pk.to_bytes()).unwrap() == pk);
}

/// Emulierte Gleitkommazahlen gegen die Hardware (`f64`) für zwei
/// beliebige Werte (je 8 Bytes little-endian). Geprüft wird nur im
/// Zahlenbereich von `Fpr` (PLAN.md 3.3): Eingaben normal oder ±0;
/// Ergebnisse normal oder ±0 müssen bitgleich sein, subnormale werden zu
/// ±0, Überlauf ist nicht Teil des Bereichs.
pub fn fpr(data: &[u8]) {
    if data.len() < 16 {
        return;
    }
    let a = u64::from_le_bytes(data[..8].try_into().unwrap());
    let b = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let in_range = |x: u64| {
        let e = (x >> 52) & 0x7FF;
        e != 0x7FF && (e != 0 || x << 1 == 0)
    };
    if !in_range(a) || !in_range(b) {
        return;
    }
    let (fa, fb) = (Fpr::from_bits(a), Fpr::from_bits(b));
    let (xa, xb) = (f64::from_bits(a), f64::from_bits(b));
    let check = |op: &str, got: Fpr, want: f64| {
        if !want.is_finite() {
            return;
        }
        let flushed = got.to_bits() << 1 == 0;
        if want.abs() == f64::MIN_POSITIVE && flushed && !cfg!(feature = "native-fpu") {
            // Genaues Ergebnis knapp unter 2⁻¹⁰²², IEEE rundet auf; Fpr wie
            // die Referenz: ±0 (siehe Zahlenbereich in fpr.rs).
        } else if want == 0.0 || want.is_normal() {
            assert_eq!(got.to_bits(), want.to_bits(), "{op}({xa:e}, {xb:e})");
        } else if !cfg!(feature = "native-fpu") {
            // subnormal: Fpr liefert ±0 (mit native-fpu bleibt es subnormal)
            assert!(flushed, "{op}({xa:e}, {xb:e})");
        }
    };
    check("add", fa + fb, xa + xb);
    check("sub", fa - fb, xa - xb);
    check("mul", fa * fb, xa * xb);
    if xb != 0.0 {
        check("div", fa / fb, xa / xb);
    }
    check("sqrt", fa.abs().sqrt(), xa.abs().sqrt());
    if xa.abs() < 9.0e18 {
        assert_eq!(fa.rint(), xa.round_ties_even() as i64, "rint({xa:e})");
        assert_eq!(fa.floor(), xa.floor() as i64, "floor({xa:e})");
        assert_eq!(fa.trunc(), xa.trunc() as i64, "trunc({xa:e})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat;

    /// Neue Ziele mit Zufallsdaten; `fpr` mit Exponenten nahe beieinander,
    /// damit Rundung, Auslöschung und Unterlauf vorkommen.
    #[test]
    fn new_targets_random() {
        let mut r = Rng(0xA11CE);
        for i in 0..40 {
            let len = (r.next() % 300) as usize;
            sign(&r.bytes(len));
            if i < 2 {
                keygen(&r.bytes(49));
            }
        }
        sign(&[]);
        sign(&[1]);
        for i in 0..200_000u64 {
            let mut d = r.bytes(16);
            if i % 2 == 0 {
                // Exponenten in einen kleinen Bereich legen (Bits 52..62)
                let lim = [1022u64, 30, 1][(i % 3) as usize];
                for half in [0usize, 8] {
                    let x = u64::from_le_bytes(d[half..half + 8].try_into().unwrap());
                    let e = 1023 - lim + (x >> 52 & 0x7FF) % (2 * lim + 1);
                    let x = (x & !(0x7FF << 52)) | (e << 52);
                    d[half..half + 8].copy_from_slice(&x.to_le_bytes());
                }
            }
            fpr(&d);
        }
        fpr(&[0; 16]);
        fpr(&[0; 3]);
    }

    /// Restliche Wege: gültiges s₂ dekodieren, FuzzRng direkt.
    #[test]
    fn remaining_paths() {
        let rec = &kat::load_kat(512)[0];
        let (_, sig) = kat::split_kat_sm(&rec.sm, rec.msg.len());
        decompress(&sig[41..]);
        let mut rng = FuzzRng(Prng::new(b"x"));
        use rand_core::RngCore;
        let (a, b) = (rng.next_u32(), rng.next_u64());
        assert!(a != 0 || b != 0);
        let mut d = DataRng(&[1, 2, 3]);
        assert_eq!(d.next_u32(), 0x0003_0201);
        assert_eq!(d.next_u64(), 0);
        assert!(d.try_fill_bytes(&mut [0; 4]).is_ok());
    }

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
