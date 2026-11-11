//! Phase 7: alle 200 KAT-Fälle wie im NIST-Programm `PQCgenKAT_sign`.
//!
//! Ablauf je Fall: AES-256-CTR-DRBG mit dem `seed` der KAT-Datei starten;
//! `crypto_sign_keypair` zieht daraus 48 Bytes für Keygen, danach zieht
//! `crypto_sign` aus demselben Strom das Salt (40 Bytes) und den Seed für
//! den Zufall des Samplers.
//!
//! Erwartet (PLAN.md L10): sk und pk byte-genau wie in der KAT-Datei, das
//! Salt der Signatur ebenfalls. Der Rest der Signatur weicht ab, weil BerExp
//! immer 8 Bytes liest (L7) und der Sampler ChaCha20 benutzt (L9); geprüft
//! wird, dass Verify sie mit dem KAT-pk annimmt.

mod common;

use common::drbg::Drbg;
use common::{load_kat, split_kat_sm};
use fndsa::{keygen_from_seed, LogN, VerifyingKey};
use rand_core::{CryptoRng, RngCore};

/// Der DRBG als Zufallsquelle für `sign` (jeder Aufruf von `fill_bytes`
/// entspricht einem Aufruf von `randombytes`).
struct DrbgRng(Drbg);

impl RngCore for DrbgRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DrbgRng {}

fn check(n: usize, logn: LogN) {
    for rec in load_kat(n) {
        let mut drbg = Drbg::new(&rec.seed);
        let mut seed = [0u8; 48];
        drbg.fill(&mut seed);
        let (sk, pk) = keygen_from_seed(logn, &seed).unwrap();
        assert_eq!(
            &sk.to_bytes()[..],
            &rec.sk[..],
            "sk, n = {n}, count {}",
            rec.count
        );
        assert_eq!(pk.to_bytes(), rec.pk, "pk, n = {n}, count {}", rec.count);

        let sig = sk.sign(&rec.msg, &mut DrbgRng(drbg));
        let (msg, kat_sig) = split_kat_sm(&rec.sm, rec.msg.len());
        assert_eq!(msg, rec.msg);
        assert_eq!(
            &sig.salt()[..],
            &kat_sig[1..41],
            "Salt, n = {n}, count {}",
            rec.count
        );
        let kat_pk = VerifyingKey::from_bytes(&rec.pk).unwrap();
        assert!(
            kat_pk.verify(&rec.msg, &sig),
            "Verify, n = {n}, count {}",
            rec.count
        );
    }
}

#[test]
fn all_kat_cases_512() {
    check(512, LogN::FALCON_512);
}

#[test]
fn all_kat_cases_1024() {
    check(1024, LogN::FALCON_1024);
}
