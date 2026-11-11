//! Dauertest: viele Schlüssel und Signaturen, damit auch seltene Pfade
//! vorkommen (Neuziehen und Verwerfen im Keygen, Neustarts in Sign,
//! s₂ passt nicht in die feste Länge).
//!
//! Standardmässig übersprungen, weil er lange läuft:
//!
//! ```text
//! cargo test --release --test soak -- --ignored --nocapture
//! FNDSA_SOAK_KEYS=20000 cargo test --release --test soak -- --ignored
//! ```

use fndsa::{keygen_from_seed, LogN, Signature, SigningKey, VerifyingKey};
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

fn keys_from_env(default: usize) -> usize {
    std::env::var("FNDSA_SOAK_KEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn soak(logn: LogN, keys: usize, sigs_per_key: usize) {
    let mut rng = TestRng::new(&[logn.get() as u8, 0x50]);
    let t = std::time::Instant::now();
    for k in 0..keys {
        let mut seed = [0u8; 48];
        rng.fill_bytes(&mut seed);
        let (sk, pk) = keygen_from_seed(logn, &seed).unwrap();
        let sk_bytes = sk.to_bytes();
        let loaded = SigningKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(&loaded.to_bytes()[..], &sk_bytes[..], "Schlüssel {k}");
        let pk = VerifyingKey::from_bytes(&pk.to_bytes()).unwrap();
        for i in 0..sigs_per_key {
            let mut msg = vec![0u8; (rng.next_u32() % 200) as usize];
            rng.fill_bytes(&mut msg);
            let sig = loaded.try_sign(&msg, &mut rng).unwrap();
            let bytes = sig.to_bytes();
            assert_eq!(
                bytes.len(),
                logn.params().unwrap().sig_bytelen(),
                "Schlüssel {k}"
            );
            let sig = Signature::from_bytes(&bytes).unwrap();
            assert!(pk.verify(&msg, &sig), "Schlüssel {k}, Signatur {i}");
            if let Some(b) = msg.first_mut() {
                *b ^= 1;
                assert!(!pk.verify(&msg, &sig));
            }
        }
    }
    eprintln!(
        "n = {}: {keys} Schlüssel, {} Signaturen in {:.0?}",
        logn.n(),
        keys * sigs_per_key,
        t.elapsed()
    );
}

#[test]
#[ignore = "Dauertest, mit --ignored starten"]
fn soak_512() {
    soak(LogN::FALCON_512, keys_from_env(2000), 20);
}

#[test]
#[ignore = "Dauertest, mit --ignored starten"]
fn soak_1024() {
    soak(LogN::FALCON_1024, keys_from_env(2000) / 4, 20);
}
