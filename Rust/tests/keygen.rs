//! Phase 5 und 7: Keygen aus Sicht eines Nutzers.
//!
//! Alle 200 KAT-Fälle prüft `tests/kat_keygen.rs` (Phase 7); hier die
//! übrige öffentliche API: zufällige Schlüssel, Speichern, Laden,
//! Signieren, Prüfen, gleicher Seed, nicht unterstützter Grad.

use fndsa::{keygen, keygen_from_seed, Error, LogN, Signature, SigningKey};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};

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
        self.next_u64() as u32
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

#[test]
fn random_keys_sign_and_verify() {
    let mut rng = TestRng::new(b"keygen");
    for logn in [LogN::FALCON_512, LogN::FALCON_1024] {
        for _ in 0..3 {
            let (sk, pk) = keygen(logn, &mut rng).unwrap();
            assert_eq!(pk, sk.verifying_key());
            // speichern und laden
            let sk2 = SigningKey::from_bytes(&sk.to_bytes()).unwrap();
            let sig = sk2.sign(b"Nachricht", &mut rng);
            let sig = Signature::from_bytes(&sig.to_bytes()).unwrap();
            assert!(pk.verify(b"Nachricht", &sig));
            assert!(!pk.verify(b"Nachrichd", &sig));
        }
    }
}

#[test]
fn same_seed_same_key_other_seed_other_key() {
    let a = keygen_from_seed(LogN::FALCON_512, &[1; 48]).unwrap();
    let b = keygen_from_seed(LogN::FALCON_512, &[1; 48]).unwrap();
    let c = keygen_from_seed(LogN::FALCON_512, &[2; 48]).unwrap();
    assert_eq!(&a.0.to_bytes()[..], &b.0.to_bytes()[..]);
    assert_eq!(a.1, b.1);
    assert_ne!(a.1, c.1);
}

#[test]
fn unsupported_degree() {
    let logn = LogN::new(8).unwrap();
    assert!(matches!(
        keygen_from_seed(logn, &[0; 48]),
        Err(Error::UnsupportedLogN)
    ));
}
