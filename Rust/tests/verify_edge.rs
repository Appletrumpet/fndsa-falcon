//! Grenzfälle und ungültige Eingaben für Verify, über die öffentliche
//! Schnittstelle.
//!
//! - Normschranke genau auf ⌊β²⌋ (gültig) und eins darüber (ungültig), mit
//!   einem dafür gebauten Public Key;
//! - eine gültige Signatur hat genau zwei Kodierungen (gepolstert und
//!   ungepolstert); jedes gekippte Bit, jede andere Länge und jeder andere
//!   Header wird abgelehnt;
//! - leere und lange Nachrichten.
//!
//! HashToPoint und die Kodierung von Public Key und s₂ sind hier unabhängig
//! von der Bibliothek neu geschrieben, damit der Test nicht nur den eigenen
//! Code mit sich selbst vergleicht.

use fndsa::{keygen_from_seed, LogN, Params, Signature, VerifyingKey, FALCON_1024, FALCON_512, Q};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// SHAKE256 als reproduzierbare Zufallsquelle.
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

/// HashToPoint (Alg. 3): SHAKE256(salt ‖ msg), 16 Bit big-endian, Werte
/// < 5q annehmen, Koeffizient = Wert mod q.
fn hash_to_point(salt: &[u8], msg: &[u8], n: usize) -> Vec<u32> {
    let mut h = sha3::Shake256::default();
    h.update(salt);
    h.update(msg);
    let mut xof = h.finalize_xof();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let mut b = [0u8; 2];
        xof.read(&mut b);
        let w = u16::from_be_bytes(b) as u32;
        if w < 5 * Q {
            out.push(w % Q);
        }
    }
    out
}

/// Bits von links nach rechts in Bytes schreiben.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    n: usize,
}

impl Bits {
    fn put(&mut self, v: u32, width: u32) {
        for i in (0..width).rev() {
            if self.n.is_multiple_of(8) {
                self.out.push(0);
            }
            if (v >> i) & 1 == 1 {
                *self.out.last_mut().unwrap() |= 0x80 >> (self.n % 8);
            }
            self.n += 1;
        }
    }
}

/// Public Key: Header 0000nnnn, 14 Bit je Koeffizient.
fn encode_pk(p: &Params, h: &[u32]) -> Vec<u8> {
    let mut w = Bits::default();
    w.put(p.logn().get(), 8);
    for &x in h {
        w.put(x, 14);
    }
    w.out
}

/// Signatur mit s₂ = (1, 0, …, 0), gepolstert: je Koeffizient Vorzeichen,
/// 7 niedrige Bits, dann „1“ (unär k = 0).
fn sig_with_s2_unit(p: &Params, salt: &[u8; 40]) -> Vec<u8> {
    let mut w = Bits::default();
    w.put(0x30 | p.logn().get(), 8);
    for &b in salt {
        w.put(b as u32, 8);
    }
    for i in 0..p.n() {
        w.put(0, 1);
        w.put((i == 0) as u32, 7);
        w.put(1, 1);
    }
    let mut sig = w.out;
    sig.resize(p.sig_bytelen(), 0);
    sig
}

/// Kurzer Vektor t mit ‖t‖² = target (gierig: grösste Quadratzahl zuerst,
/// Beträge höchstens 6000 < q/2).
fn vector_with_norm(n: usize, mut target: u64) -> Vec<i64> {
    let mut t = vec![0i64; n];
    for x in t.iter_mut() {
        if target == 0 {
            break;
        }
        let mut a = (target as f64).sqrt() as u64;
        while a * a > target {
            a -= 1;
        }
        while (a + 1) * (a + 1) <= target {
            a += 1;
        }
        let a = a.min(6000);
        *x = if a.is_multiple_of(2) {
            a as i64
        } else {
            -(a as i64)
        };
        target -= a * a;
    }
    assert_eq!(target, 0, "Norm nicht erreichbar");
    t
}

/// Mit s₂ = (1, 0, …, 0) ist s₂·h = h, also s₁ = c − h. Mit h = c − t wird
/// s₁ = t und ‖(s₁, s₂)‖² = ‖t‖² + 1, genau einstellbar.
fn verify_with_norm(p: &'static Params, norm: u64) -> bool {
    let n = p.n();
    let salt = [0x5Au8; 40];
    let msg = b"Normschranke";
    let c = hash_to_point(&salt, msg, n);
    let t = vector_with_norm(n, norm - 1);
    let q = Q as i64;
    let h: Vec<u32> = c
        .iter()
        .zip(&t)
        .map(|(&ci, &ti)| (ci as i64 - ti).rem_euclid(q) as u32)
        .collect();
    let pk = VerifyingKey::from_bytes(&encode_pk(p, &h)).unwrap();
    let sig = Signature::from_bytes(&sig_with_s2_unit(p, &salt)).unwrap();
    pk.verify(msg, &sig)
}

#[test]
fn norm_bound_is_inclusive() {
    for p in [&FALCON_512, &FALCON_1024] {
        let b = p.sig_bound();
        assert!(verify_with_norm(p, b), "n = {}: Norm = β² abgelehnt", p.n());
        assert!(verify_with_norm(p, b - 1), "n = {}", p.n());
        assert!(
            !verify_with_norm(p, b + 1),
            "n = {}: Norm = β² + 1 angenommen",
            p.n()
        );
        assert!(!verify_with_norm(p, 2 * b), "n = {}", p.n());
    }
}

/// Eine echte Signatur und ihre ungepolsterte Form (Nullbytes am Ende weg).
fn real_signature(logn: LogN, seed: u8, msg: &[u8]) -> (VerifyingKey, Vec<u8>, usize) {
    let (sk, pk) = keygen_from_seed(logn, &[seed; 48]).unwrap();
    let mut rng = TestRng::new(&[seed, 1]);
    let sig = sk.sign(msg, &mut rng).to_bytes();
    let unpadded = sig.iter().rposition(|&b| b != 0).unwrap() + 1;
    (pk, sig, unpadded)
}

fn accepts(pk: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    Signature::from_bytes(sig).is_ok_and(|s| pk.verify(msg, &s))
}

/// Jedes einzelne gekippte Bit (Header, Salt, s₂, Polsterung) macht die
/// Signatur ungültig.
#[test]
fn every_bit_flip_is_rejected() {
    for (logn, seeds) in [(LogN::FALCON_512, 3u8), (LogN::FALCON_1024, 2)] {
        for seed in 0..seeds {
            let msg = b"bit flips";
            let (pk, sig, _) = real_signature(logn, seed, msg);
            assert!(accepts(&pk, msg, &sig));
            for i in 0..sig.len() {
                for bit in 0..8 {
                    let mut bad = sig.clone();
                    bad[i] ^= 1 << bit;
                    assert!(!accepts(&pk, msg, &bad), "Byte {i}, Bit {bit}");
                }
            }
        }
    }
}

/// Genau zwei Längen werden angenommen: gepolstert und ungepolstert.
/// Kürzer, teilweise gepolstert oder länger (mit Null- oder anderen Bytes)
/// ist ungültig. Das entspricht der Referenz (PQClean `do_verify`).
#[test]
fn only_padded_and_unpadded_lengths() {
    for logn in [LogN::FALCON_512, LogN::FALCON_1024] {
        let msg = b"Laengen";
        let (pk, sig, unpadded) = real_signature(logn, 7, msg);
        let accepted: Vec<usize> = (0..=sig.len())
            .filter(|&l| accepts(&pk, msg, &sig[..l]))
            .collect();
        let mut expected = vec![unpadded, sig.len()];
        expected.dedup();
        assert_eq!(accepted, expected, "n = {}", logn.n());
        for extra in [&[0u8][..], &[0, 0], &[1], &[0xFF, 0]] {
            let long = [&sig[..], extra].concat();
            assert!(!accepts(&pk, msg, &long), "angehängt {extra:?}");
            let long = [&sig[..unpadded], extra].concat();
            if long.len() != sig.len() {
                assert!(!accepts(&pk, msg, &long), "ungepolstert + {extra:?}");
            }
        }
    }
}

/// Von den 256 möglichen Header-Bytes passt nur 0x30 | logn des Schlüssels.
#[test]
fn only_matching_header_is_accepted() {
    for logn in [LogN::FALCON_512, LogN::FALCON_1024] {
        let msg = b"Header";
        let (pk, sig, _) = real_signature(logn, 9, msg);
        for hdr in 0..=255u8 {
            let mut bad = sig.clone();
            bad[0] = hdr;
            assert_eq!(
                accepts(&pk, msg, &bad),
                hdr == 0x30 | logn.get() as u8,
                "Header {hdr:#04x}"
            );
        }
    }
}

/// Public Keys mit einem Koeffizienten ≥ q oder falscher Länge sind
/// ungültig; ein gültiger Key eines anderen Grades lehnt die Signatur ab.
#[test]
fn malformed_public_keys() {
    let msg = b"pk";
    let (pk, sig, _) = real_signature(LogN::FALCON_512, 11, msg);
    let pk_bytes = pk.to_bytes();
    // erster Koeffizient = q (14 Bit direkt nach dem Header)
    let mut bad = pk_bytes.clone();
    bad[1] = (Q >> 6) as u8;
    bad[2] = (bad[2] & 0x03) | ((Q & 0x3F) << 2) as u8;
    assert!(VerifyingKey::from_bytes(&bad).is_err());
    // um ein Byte zu kurz oder zu lang
    assert!(VerifyingKey::from_bytes(&pk_bytes[..pk_bytes.len() - 1]).is_err());
    assert!(VerifyingKey::from_bytes(&[&pk_bytes[..], &[0]].concat()).is_err());
    // anderer Grad
    let (pk1024, _, _) = real_signature(LogN::FALCON_1024, 11, msg);
    assert!(!pk1024.verify(msg, &Signature::from_bytes(&sig).unwrap()));
}

/// Leere und lange Nachrichten (1 MiB) lassen sich signieren und prüfen;
/// ein Byte mehr oder weniger ergibt eine ungültige Signatur.
#[test]
fn empty_and_long_messages() {
    let (sk, pk) = keygen_from_seed(LogN::FALCON_512, &[13; 48]).unwrap();
    let mut rng = TestRng::new(b"msgs");
    let long: Vec<u8> = (0..1 << 20).map(|i| (i * 7) as u8).collect();
    for msg in [&[][..], &long[..]] {
        let sig = sk.sign(msg, &mut rng);
        assert!(pk.verify(msg, &sig));
        assert!(!pk.verify(&[msg, &[0]].concat(), &sig));
        if !msg.is_empty() {
            assert!(!pk.verify(&msg[..msg.len() - 1], &sig));
        }
    }
}
