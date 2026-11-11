//! Prüfung der konstanten Laufzeit mit Valgrind (PLAN.md §6, „ctgrind“).
//!
//! Geheime Eingaben (Keygen-Seed, Seed für den Zufall des Samplers) werden
//! für Memcheck als „nicht initialisiert“ markiert. Memcheck meldet dann
//! jede Verzweigung und jeden Speicherzugriff, der von geheimen Daten
//! abhängt. Die erlaubten Stellen (PLAN.md §6) gibt `ct::declassify` frei;
//! jede andere Meldung ist ein Befund.
//!
//! Nur unter Linux mit Valgrind:
//!
//! ```text
//! cargo build --release --example ctgrind --features ctgrind
//! valgrind --error-exitcode=1 target/release/examples/ctgrind
//! ```

use fndsa::{ctgrind, keygen_from_seed, LogN, SigningKey};
use rand_core::{CryptoRng, RngCore};

/// Deterministische Quelle. Der zweite Aufruf von `fill_bytes` in `sign`
/// (56 Bytes Seed für ChaCha20) ist geheim; das Salt (40 Bytes) nicht.
struct Rng(u64);

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = self.next_u64() as u8;
        }
        if dest.len() == 56 {
            ctgrind::poison(dest);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Rng {}

fn main() {
    // Selbsttest: mit CTGRIND_SELFTEST=1 absichtlich auf einem geheimen
    // Byte verzweigen. Valgrind muss das melden; sonst greift die
    // Markierung nicht und die Prüfung wäre wertlos.
    if std::env::var_os("CTGRIND_SELFTEST").is_some() {
        let mut secret = [std::hint::black_box(7u8)];
        ctgrind::poison(&mut secret);
        if std::hint::black_box(secret[0]) > 3 {
            println!("Selbsttest: Verzweigung auf geheimem Byte ausgeführt");
        }
        return;
    }
    for logn in [LogN::FALCON_512, LogN::FALCON_1024] {
        // Keygen mit geheimem Seed
        let mut seed = [0x42u8; 48];
        ctgrind::poison(&mut seed);
        let (sk, pk) = keygen_from_seed(logn, &seed).unwrap();

        // Speichern und Laden (G neu berechnen, Prüfungen, Baum)
        let mut bytes = sk.to_bytes();
        ctgrind::poison(&mut bytes[1..]);
        let sk = SigningKey::from_bytes(&bytes).unwrap();

        // Signieren und prüfen
        let mut rng = Rng(0x1234_5678);
        for i in 0..3u8 {
            let msg = [b'm', i];
            let sig = sk.sign(&msg, &mut rng);
            assert!(pk.verify(&msg, &sig));
        }
        println!("n = {}: Keygen, Laden, Sign, Verify fertig", logn.n());
    }
}
