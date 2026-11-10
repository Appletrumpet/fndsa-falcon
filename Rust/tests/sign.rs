//! Phase 4: Sign mit den NIST-KAT-Schlüsseln, aus Sicht eines Nutzers.
//!
//! Die Signaturen selbst sind nicht byte-gleich mit den KAT-Dateien (L7,
//! anderer Zufall); bitgleich mit Python prüfen die Unit-Tests in `lib.rs`
//! (`flow.sign`). Hier: laden, Public Key ableiten, signieren, prüfen.

mod common;

use common::load_kat;
use fndsa::{Error, Signature, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Reproduzierbare Zufallsquelle für die Tests (SHAKE256 über einem Seed).
struct TestRng(<sha3::Shake256 as ExtendableOutput>::Reader);

impl TestRng {
    fn new(seed: &[u8]) -> TestRng {
        let mut h = sha3::Shake256::default();
        h.update(seed);
        TestRng(h.finalize_xof())
    }
}

impl RngCore for TestRng {
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
        self.0.read(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

fn check(n: usize, cases: usize) {
    let mut rng = TestRng::new(format!("sign-{n}").as_bytes());
    for rec in load_kat(n).iter().take(cases) {
        let sk = SigningKey::from_bytes(&rec.sk).unwrap();
        assert_eq!(&sk.to_bytes()[..], &rec.sk[..], "sk count {}", rec.count);
        let vk = sk.verifying_key();
        assert_eq!(vk.to_bytes(), rec.pk, "pk count {}", rec.count);

        let sig = sk.sign(&rec.msg, &mut rng);
        let bytes = sig.to_bytes();
        // feste Länge (gepolstert, Tab. 3.3)
        assert_eq!(bytes.len(), if n == 512 { 666 } else { 1280 });
        let pk = VerifyingKey::from_bytes(&rec.pk).unwrap();
        assert!(pk.verify(&rec.msg, &Signature::from_bytes(&bytes).unwrap()));

        let mut other = rec.msg.clone();
        other.push(0);
        assert!(!pk.verify(&other, &sig), "count {}", rec.count);
    }
}

#[test]
fn kat_keys_sign_and_verify_512() {
    check(512, 10);
}

#[test]
fn kat_keys_sign_and_verify_1024() {
    check(1024, 10);
}

#[test]
fn signatures_differ_and_all_verify() {
    let rec = &load_kat(512)[0];
    let sk = SigningKey::from_bytes(&rec.sk).unwrap();
    let vk = sk.verifying_key();
    let mut rng = TestRng::new(b"repeat");
    let a = sk.sign(b"gleiche Nachricht", &mut rng);
    let b = sk.sign(b"gleiche Nachricht", &mut rng);
    assert_ne!(a, b, "neues Salt, neuer Zufall");
    assert!(vk.verify(b"gleiche Nachricht", &a));
    assert!(vk.verify(b"gleiche Nachricht", &b));
}

/// Die Schlüsselprüfung lehnt keinen echten Schlüssel ab (alle 200 KAT).
#[test]
fn all_kat_keys_load() {
    for n in [512, 1024] {
        for rec in load_kat(n) {
            assert!(
                SigningKey::from_bytes(&rec.sk).is_ok(),
                "{n} count {}",
                rec.count
            );
        }
    }
}

/// Erfundene Schlüssel: gültiges Format, f invertierbar, aber kein
/// NTRU-Schlüssel. Früher geladen, danach lief Sign endlos.
#[test]
fn fabricated_keys_are_rejected() {
    // f = 1, g = 0, F = 0: G = 0 ist klein, aber fG − gF = 0 ≠ q
    let mut one = vec![0x59u8, 0x04];
    one.extend([0; 1279]);
    assert!(matches!(
        SigningKey::from_bytes(&one),
        Err(Error::InvalidKey)
    ));

    // zufällig verteilte kleine Koeffizienten: G mod q wird gross
    let mut x = 0x1234_5678u64;
    let mut invalid = 0;
    for _ in 0..10 {
        let mut sk = vec![0x59u8];
        for _ in 0..1280 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            sk.push(if x.is_multiple_of(5) { 0x04 } else { 0 });
        }
        match SigningKey::from_bytes(&sk) {
            Err(Error::InvalidKey) => invalid += 1,
            Err(Error::NotInvertible) => {}
            other => panic!("erfundener Schlüssel angenommen: {:?}", other.err()),
        }
    }
    assert!(invalid > 0);
}

#[test]
fn invalid_secret_keys() {
    // f = 0 ist nicht invertierbar
    let mut zero = vec![0x59u8];
    zero.extend([0; 1280]);
    assert!(matches!(
        SigningKey::from_bytes(&zero),
        Err(Error::NotInvertible)
    ));
    // gültiges Format, aber Grad ohne Parametersatz
    assert!(matches!(
        SigningKey::from_bytes(&[0x51, 0x01, 0xff, 0x00, 0x81, 0x7f, 0x81]),
        Err(Error::UnsupportedLogN)
    ));
    assert!(SigningKey::from_bytes(&[]).is_err());
}
