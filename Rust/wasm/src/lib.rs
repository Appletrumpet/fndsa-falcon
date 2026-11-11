//! WASM-Hülle von `fndsa` für die Web-Oberfläche (UI-PLAN.md §5).
//!
//! Nur Umwandlungen zwischen Bytes, Fehlertexten und den Typen des Crates,
//! keine eigene Kryptographie. Die eigentliche Logik steht in Funktionen
//! ohne `wasm-bindgen` (`*_bytes`, `Signer::generate`), damit sie mit
//! `cargo test` nativ geprüft werden kann.
//!
//! Zufall kommt aus dem Browser (`crypto.getRandomValues`) und wird als
//! Bytes übergeben: 48 Bytes Seed für Keygen, mindestens 32 Bytes für jedes
//! Sign (daraus ein SHAKE256-Strom).
//!
//! **Nur zur Vorführung:** Auf `wasm32` gibt es keine Optimierungsbarriere
//! in Assembler (Rückfall `black_box`, PLAN.md 3.2), die Prüfungen der
//! konstanten Laufzeit (PLAN.md §6) gelten für x86-64 und aarch64. Der
//! Secret Key liegt im Speicher der Seite und wird beim Verwerfen gelöscht.

use fndsa::{keygen_from_seed, LogN, Signature, SigningKey, VerifyStep, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use wasm_bindgen::prelude::*;

/// Ergebnis von Verify für JavaScript (Felder als Getter).
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    accepted: bool,
    failed_at: Option<u32>,
    norm: Option<f64>,
    bound: f64,
    logn: u32,
}

#[wasm_bindgen]
impl Report {
    /// Signatur gültig.
    #[wasm_bindgen(getter)]
    pub fn accepted(&self) -> bool {
        self.accepted
    }
    /// Schritt (0 bis 4, Reihenfolge wie `VerifyStep::ALL`), an dem Verify
    /// gescheitert ist; `undefined`, wenn gültig.
    #[wasm_bindgen(getter, js_name = failedAt)]
    pub fn failed_at(&self) -> Option<u32> {
        self.failed_at
    }
    /// ‖(s₁, s₂)‖², falls berechnet (< 2⁵³, also exakt als Zahl).
    #[wasm_bindgen(getter)]
    pub fn norm(&self) -> Option<f64> {
        self.norm
    }
    /// ⌊β²⌋ des Parametersatzes.
    #[wasm_bindgen(getter)]
    pub fn bound(&self) -> f64 {
        self.bound
    }
    /// log₂ n des Public Keys.
    #[wasm_bindgen(getter)]
    pub fn logn(&self) -> u32 {
        self.logn
    }
}

/// Verify auf Bytes. Fehler (als deutscher Text), wenn Public Key oder
/// Signatur schon als Format ungültig sind; sonst ein Bericht.
pub fn verify_bytes(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<Report, String> {
    let pk = VerifyingKey::from_bytes(pk).map_err(|e| format!("Public Key: {e}"))?;
    let sig = Signature::from_bytes(sig).map_err(|e| format!("Signatur: {e}"))?;
    let r = pk.verify_report(msg, &sig);
    Ok(Report {
        accepted: r.accepted,
        failed_at: r.failed_at.map(|s: VerifyStep| s.index() as u32),
        norm: r.norm.map(|x| x as f64),
        bound: r.bound as f64,
        logn: pk.logn().get(),
    })
}

/// Verify für JavaScript; siehe `verify_bytes`.
#[wasm_bindgen]
pub fn verify(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<Report, JsError> {
    verify_bytes(pk, sig, msg).map_err(|e| JsError::new(&e))
}

/// Version für die Fusszeile.
#[wasm_bindgen]
pub fn version() -> String {
    format!("fndsa-wasm {} · Phasen 0–8", env!("CARGO_PKG_VERSION"))
}

/// Zufallsquelle aus Bytes des Browsers: SHAKE256(Bytes) als Strom.
struct SeedRng(<sha3::Shake256 as ExtendableOutput>::Reader);

impl SeedRng {
    fn new(seed: &[u8]) -> SeedRng {
        let mut h = sha3::Shake256::default();
        h.update(b"fndsa-wasm sign");
        h.update(seed);
        SeedRng(h.finalize_xof())
    }
}

impl RngCore for SeedRng {
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

impl CryptoRng for SeedRng {}

/// Schlüsselpaar im Speicher der Seite (Signieren-Ansicht).
#[wasm_bindgen]
pub struct Signer {
    sk: SigningKey,
    pk: Vec<u8>,
}

impl Signer {
    /// Keygen aus genau 48 Bytes Seed; logn 9 (Falcon-512) oder 10.
    pub fn generate(logn: u32, seed: &[u8]) -> Result<Signer, String> {
        let seed: &[u8; 48] = seed
            .try_into()
            .map_err(|_| format!("Seed muss 48 Bytes lang sein, nicht {}", seed.len()))?;
        let logn = LogN::new(logn).map_err(|e| e.to_string())?;
        let (sk, pk) = keygen_from_seed(logn, seed).map_err(|e| e.to_string())?;
        Ok(Signer {
            sk,
            pk: pk.to_bytes(),
        })
    }

    /// Signiert mit Zufall aus mindestens 32 Bytes.
    pub fn sign_bytes(&self, msg: &[u8], random: &[u8]) -> Result<Vec<u8>, String> {
        if random.len() < 32 {
            return Err(format!(
                "mindestens 32 Bytes Zufall nötig, nicht {}",
                random.len()
            ));
        }
        let sig = self
            .sk
            .try_sign(msg, &mut SeedRng::new(random))
            .map_err(|e| e.to_string())?;
        Ok(sig.to_bytes())
    }
}

#[wasm_bindgen]
impl Signer {
    /// Neues Schlüsselpaar; `seed`: 48 Bytes aus `crypto.getRandomValues`.
    #[wasm_bindgen(constructor)]
    pub fn new(logn: u32, seed: &[u8]) -> Result<Signer, JsError> {
        Signer::generate(logn, seed).map_err(|e| JsError::new(&e))
    }

    /// Public Key (897 bzw. 1793 Bytes).
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }

    /// log₂ n.
    #[wasm_bindgen(getter)]
    pub fn logn(&self) -> u32 {
        self.sk.logn().get()
    }

    /// Länge des Secret Keys in Bytes (der Inhalt verlässt WASM nicht).
    #[wasm_bindgen(getter, js_name = secretKeyLength)]
    pub fn secret_key_length(&self) -> usize {
        self.sk.logn().sk_bytes()
    }

    /// Signatur (gepolstert, 666 bzw. 1280 Bytes); `random`: mindestens
    /// 32 Bytes aus `crypto.getRandomValues`.
    pub fn sign(&self, msg: &[u8], random: &[u8]) -> Result<Vec<u8>, JsError> {
        self.sign_bytes(msg, random).map_err(|e| JsError::new(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_sign_verify() {
        for logn in [9, 10] {
            let s = Signer::generate(logn, &[logn as u8; 48]).unwrap();
            assert_eq!(s.public_key().len(), if logn == 9 { 897 } else { 1793 });
            let sig = s.sign_bytes(b"Hallo Bern", &[7; 32]).unwrap();
            assert_eq!(sig.len(), if logn == 9 { 666 } else { 1280 });
            let r = verify_bytes(&s.public_key(), &sig, b"Hallo Bern").unwrap();
            assert!(r.accepted);
            assert_eq!(r.failed_at, None);
            assert!(r.norm.unwrap() <= r.bound);
            assert_eq!(r.logn, logn);
        }
    }

    #[test]
    fn flipped_bits_fail_at_expected_step() {
        let s = Signer::generate(9, &[1; 48]).unwrap();
        let sig = s.sign_bytes(b"m", &[2; 40]).unwrap();
        // Salt: Norm zu gross
        let mut bad = sig.clone();
        bad[3] ^= 1;
        let r = verify_bytes(&s.public_key(), &bad, b"m").unwrap();
        assert!(!r.accepted);
        assert_eq!(r.failed_at, Some(4));
        assert!(r.norm.unwrap() > r.bound);
        // Polsterung nicht 0: Kodierung ungültig
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() = 1;
        let r = verify_bytes(&s.public_key(), &bad, b"m").unwrap();
        assert_eq!(r.failed_at, Some(2));
        assert_eq!(r.norm, None);
        // andere Nachricht
        assert!(!verify_bytes(&s.public_key(), &sig, b"n").unwrap().accepted);
    }

    #[test]
    fn invalid_inputs_give_errors() {
        let s = Signer::generate(9, &[3; 48]).unwrap();
        let sig = s.sign_bytes(b"m", &[4; 32]).unwrap();
        let e = verify_bytes(&[0x09, 1, 2], &sig, b"m").unwrap_err();
        assert!(e.starts_with("Public Key:"), "{e}");
        let e = verify_bytes(&s.public_key(), &sig[..10], b"m").unwrap_err();
        assert!(e.starts_with("Signatur:"), "{e}");
        assert!(Signer::generate(9, &[0; 47]).is_err());
        assert!(Signer::generate(8, &[0; 48]).is_err());
        assert!(Signer::generate(11, &[0; 48]).is_err());
        assert!(s.sign_bytes(b"m", &[0; 31]).is_err());
        // Signatur von 1024 gegen Schlüssel von 512: Schritt Dekodieren
        let s10 = Signer::generate(10, &[5; 48]).unwrap();
        let sig10 = s10.sign_bytes(b"m", &[6; 32]).unwrap();
        let r = verify_bytes(&s.public_key(), &sig10, b"m").unwrap();
        assert_eq!(r.failed_at, Some(0));
    }

    #[test]
    fn same_random_same_signature() {
        let s = Signer::generate(9, &[8; 48]).unwrap();
        assert_eq!(
            s.sign_bytes(b"m", &[9; 32]).unwrap(),
            s.sign_bytes(b"m", &[9; 32]).unwrap()
        );
        assert_ne!(
            s.sign_bytes(b"m", &[9; 32]).unwrap(),
            s.sign_bytes(b"m", &[10; 32]).unwrap()
        );
        assert_eq!(s.secret_key_length(), 1281);
        assert_eq!(s.logn(), 9);
        assert!(version().contains("fndsa-wasm"));
    }
}
