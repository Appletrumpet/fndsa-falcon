//! Differenztests gegen die übrigen Python-Testvektoren
//! (`Python/data/vectors/`, dieselben Dateien wie für die C-Tests).
//!
//! Die Vektoren für FFT, Sampler, Baum, ffSampling und Sign prüfen die
//! jeweiligen Module selbst. Hier stehen die übrigen: Kodierung, mod q,
//! HashToPoint, Bausteine von Verify, `flow.verify` und `flow.keygen`.
//!
//! Wo Rust eine Eingabe schon durch seine Typen ausschliesst (z. B. ein
//! Salt, das nicht 40 Bytes lang ist), wird der Fall nur gezählt und muss
//! in Python ein Fehler sein. Jeder Test meldet, wie viele Fälle er
//! geprüft und übersprungen hat. Zwei bekannte Unterschiede zählen
//! getrennt: Python erlaubt für mod q auch n = 1 (Falcon beginnt bei
//! n = 2), und Python dekomprimiert auch |sᵢ| > 2047, Rust lehnt das wie
//! die Referenz ab (PLAN.md L5).
//!
//! Die NTT legt in Rust die Werte in bitumgekehrter Reihenfolge ab, in
//! Python in natürlicher; die Tests bilden die Reihenfolge um.
//!
//! Nicht übertragbar und deshalb nicht hier: `bigint`, `poly.*`, die
//! `ntrugen`-Bausteine ausser `recompute_G` (Rust hat den Keygen der
//! Referenz, nicht den aus Python), `shake256` (Crate `sha3`) und
//! `sampler.uniform_bits` (in Rust Teil von BaseSampler).

use crate::encoding::{
    compress, decode_pk, decode_sk, decompress, encode_pk, encode_sk, SecretPolys,
};
use crate::falcon::{compute_public_key, compute_s1, is_short, key_valid_mask, recompute_g};
use crate::hashing::hash_to_point;
use crate::kat::vectors::{load, Case};
use crate::params::{LogN, FALCON_1024, FALCON_512, Q};
use crate::{modq, Signature, SigningKey, VerifyingKey};

/// Zählt geprüfte und übersprungene Fälle und gibt sie am Ende aus.
struct Tally {
    name: &'static str,
    checked: usize,
    skipped: usize,
    /// in Python gültig, in Rust bewusst nicht (n = 1, L5)
    known: usize,
}

impl Tally {
    fn new(name: &'static str) -> Tally {
        Tally {
            name,
            checked: 0,
            skipped: 0,
            known: 0,
        }
    }
    /// Fall mit n = 1: in Python gültig, in Falcon und Rust nicht vorgesehen.
    fn skip_n1(&mut self, c: &Case) {
        if c.ok() {
            self.known += 1;
        } else {
            self.skipped += 1;
        }
    }
    fn skip(&mut self, c: &Case, why: &str) {
        assert!(
            !c.ok(),
            "{} Fall {}: übersprungen ({why}), in Python aber gültig",
            self.name,
            c.index
        );
        self.skipped += 1;
    }
    fn done(self) {
        eprintln!(
            "{}: {} geprüft, {} übersprungen, {} bekannte Unterschiede",
            self.name, self.checked, self.skipped, self.known
        );
        assert!(self.checked > 0, "{}: kein Fall geprüft", self.name);
    }
}

/// Bitumkehr von i auf log₂ n Bit (Reihenfolge der NTT in Rust).
fn bitrev(i: usize, n: usize) -> usize {
    i.reverse_bits() >> (usize::BITS - n.trailing_zeros())
}

/// Natürliche Reihenfolge (Python) ↔ bitumgekehrte (Rust); die Abbildung
/// ist ihre eigene Umkehrung.
fn permute(v: &[u32]) -> Vec<u32> {
    (0..v.len()).map(|i| v[bitrev(i, v.len())]).collect()
}

fn logn_of(n: usize) -> Option<LogN> {
    n.is_power_of_two()
        .then(|| LogN::new(n.trailing_zeros()).ok())
        .flatten()
}

/// (n, sig_bytelen) aus dem Feld `params`.
fn params(c: &Case) -> (usize, usize) {
    let p = c.ints("params");
    (p[0] as usize, p[1] as usize)
}

/// Schranke ⌊β²⌋ wie in den C-Tests: von Falcon-1024 für n = 1024, sonst
/// von Falcon-512.
fn bound(n: usize) -> u64 {
    if n == 1024 {
        FALCON_1024.sig_bound()
    } else {
        FALCON_512.sig_bound()
    }
}

fn to_i8(v: &[i128]) -> Option<Vec<i8>> {
    v.iter().map(|&x| i8::try_from(x).ok()).collect()
}

fn to_i16(v: &[i128]) -> Option<Vec<i16>> {
    v.iter().map(|&x| i16::try_from(x).ok()).collect()
}

/// Werte mod q nach [0, q).
fn modq_vec(v: &[i128]) -> Vec<u32> {
    v.iter().map(|&x| x.rem_euclid(Q as i128) as u32).collect()
}

/// NTT nur für 2 ≤ n ≤ 1024, Zweierpotenz (wie in Falcon).
fn ntt_len_ok(n: usize) -> bool {
    n.is_power_of_two() && (2..=1024).contains(&n)
}

// ------------------------------------------------------------- Kodierung

#[test]
fn compress_vectors() {
    let mut t = Tally::new("encoding.compress");
    for c in load("encoding.compress") {
        let (_, bytelen) = params(&c);
        let Some(s) = to_i16(&c.ints("s")) else {
            t.skip(&c, "Wert ausserhalb i16");
            continue;
        };
        let got = compress(&s, bytelen - 41);
        match c.status.as_str() {
            "ok" => assert_eq!(
                got.as_deref(),
                Some(&c.bytes("out")[..]),
                "Fall {}",
                c.index
            ),
            _ => assert_eq!(got, None, "Fall {}", c.index),
        }
        t.checked += 1;
    }
    t.done();
}

#[test]
fn decompress_vectors() {
    let mut t = Tally::new("encoding.decompress");
    for c in load("encoding.decompress") {
        let (n, bytelen) = params(&c);
        let got = decompress(&c.bytes("b"), n, bytelen - 41);
        match c.status.as_str() {
            "ok" if c.ints("out").iter().any(|&x| x.abs() > 2047) => {
                // L5: Rust lehnt |sᵢ| > 2047 ab, Python nimmt es an
                assert_eq!(got, None, "Fall {}", c.index);
                t.known += 1;
                continue;
            }
            "ok" => {
                let want: Vec<i16> = c.ints("out").iter().map(|&x| x as i16).collect();
                assert_eq!(got, Some(want), "Fall {}", c.index)
            }
            _ => assert_eq!(got, None, "Fall {}", c.index),
        }
        t.checked += 1;
    }
    t.done();
}

#[test]
fn pk_vectors() {
    let mut t = Tally::new("encoding.decode_pk");
    for c in load("encoding.decode_pk") {
        let got = decode_pk(&c.bytes("b"));
        if c.ok() {
            let (logn, h) = got.unwrap_or_else(|e| panic!("Fall {}: {e}", c.index));
            let want: Vec<u16> = c.ints("out").iter().map(|&x| x as u16).collect();
            assert_eq!(h, want, "Fall {}", c.index);
            assert_eq!(logn.n(), want.len());
        } else {
            assert!(got.is_err(), "Fall {}", c.index);
        }
        t.checked += 1;
    }
    t.done();

    let mut t = Tally::new("encoding.encode_pk");
    for c in load("encoding.encode_pk") {
        let h = c.ints("h");
        let Some(logn) = logn_of(h.len()) else {
            t.skip(&c, "kein gültiger Grad");
            continue;
        };
        if h.iter().any(|&x| !(0..Q as i128).contains(&x)) {
            // encode_pk bekommt in Rust nur gültige h (aus g/f mod q)
            t.skip(&c, "Koeffizient ausserhalb [0, q)");
            continue;
        }
        assert!(
            c.ok(),
            "Fall {}: gültige Eingabe, in Python ein Fehler",
            c.index
        );
        let h: Vec<u16> = h.iter().map(|&x| x as u16).collect();
        assert_eq!(encode_pk(logn, &h), c.bytes("out"), "Fall {}", c.index);
        t.checked += 1;
    }
    t.done();
}

#[test]
fn sk_vectors() {
    let mut t = Tally::new("encoding.decode_sk");
    for c in load("encoding.decode_sk") {
        let got = decode_sk(&c.bytes("b"));
        if c.ok() {
            let sk = got.unwrap_or_else(|e| panic!("Fall {}: {e}", c.index));
            for (k, part) in [&sk.f, &sk.g, &sk.big_f].iter().enumerate() {
                let want: Vec<i8> = c
                    .ints(&format!("out{k}"))
                    .iter()
                    .map(|&x| x as i8)
                    .collect();
                assert_eq!(**part, want, "Fall {}, Teil {k}", c.index);
            }
        } else {
            assert!(got.is_err(), "Fall {}", c.index);
        }
        t.checked += 1;
    }
    t.done();

    let mut t = Tally::new("encoding.encode_sk");
    for c in load("encoding.encode_sk") {
        let (f, g, big_f) = (c.ints("f"), c.ints("g"), c.ints("F"));
        let (Some(logn), Some(f), Some(g), Some(big_f)) =
            (logn_of(f.len()), to_i8(&f), to_i8(&g), to_i8(&big_f))
        else {
            t.skip(&c, "Grad ungültig oder Wert ausserhalb i8");
            continue;
        };
        let got = encode_sk(&SecretPolys { logn, f, g, big_f });
        if c.ok() {
            let out = got.unwrap_or_else(|e| panic!("Fall {}: {e}", c.index));
            assert_eq!(&out[..], &c.bytes("out")[..], "Fall {}", c.index);
        } else {
            assert!(got.is_err(), "Fall {}", c.index);
        }
        t.checked += 1;
    }
    t.done();
}

/// Signaturformat. Unterschied zu Python: `Signature::from_bytes` kennt
/// den Parametersatz nicht und nimmt jeden gültigen Grad im Header an;
/// ein anderer Grad als der des Schlüssels fällt erst in Verify auf
/// (Schritt `Decode`). Ein Salt mit anderer Länge als 40 Bytes ist in Rust
/// durch den Typ `[u8; 40]` ausgeschlossen.
#[test]
fn sig_vectors() {
    let mut t = Tally::new("encoding.decode_sig");
    for c in load("encoding.decode_sig") {
        let (n, _) = params(&c);
        let b = c.bytes("b");
        let got = Signature::from_bytes(&b);
        if c.ok() {
            let sig = got.unwrap_or_else(|e| panic!("Fall {}: {e}", c.index));
            assert_eq!(sig.logn().n(), n);
            assert_eq!(
                &sig.salt()[..],
                &c.bytes("out_salt")[..],
                "Fall {}",
                c.index
            );
            assert_eq!(
                &sig.to_bytes()[41..],
                &c.bytes("out_s2")[..],
                "Fall {}",
                c.index
            );
        } else {
            // abgelehnt, oder angenommen mit anderem Grad (Verify lehnt ab)
            match got {
                Err(_) => {}
                Ok(sig) => assert_ne!(sig.logn().n(), n, "Fall {}", c.index),
            }
        }
        t.checked += 1;
    }
    t.done();

    let mut t = Tally::new("encoding.encode_sig");
    for c in load("encoding.encode_sig") {
        let (n, _) = params(&c);
        let salt = c.bytes("sig_salt");
        let (Some(logn), true) = (logn_of(n), salt.len() == 40) else {
            t.skip(&c, "Salt nicht 40 Bytes oder Grad ungültig");
            continue;
        };
        let mut b = vec![0x30 | logn.get() as u8];
        b.extend(&salt);
        b.extend(c.bytes("sig_s2"));
        // Ohne s₂ ist die Signatur kürzer als 42 Bytes; Python erlaubt das
        // beim Kodieren, Rust erzeugt solche Signaturen nicht.
        if b.len() < 42 {
            assert!(c.ok());
            assert_eq!(b, c.bytes("out"));
        } else {
            let sig = Signature::from_bytes(&b).unwrap();
            assert_eq!(sig.to_bytes(), c.bytes("out"), "Fall {}", c.index);
        }
        t.checked += 1;
    }
    t.done();
}

/// KAT-Format: nur die gültigen Fälle, gegen die Testhilfe `split_kat_sm`
/// (die Bibliothek selbst liest das NIST-Format nicht).
#[test]
fn kat_message_vectors() {
    let mut t = Tally::new("encoding.decode_kat_message");
    for c in load("encoding.decode_kat_message") {
        if !c.ok() {
            t.skip(&c, "Testhilfe prüft das Format nicht");
            continue;
        }
        let msg = c.bytes("msg");
        let (m, sig) = crate::kat::split_kat_sm(&c.bytes("sm"), msg.len());
        assert_eq!(m, msg, "Fall {}", c.index);
        assert_eq!(&sig[1..41], &c.bytes("out_salt")[..], "Fall {}", c.index);
        assert_eq!(&sig[41..], &c.bytes("out_s2")[..], "Fall {}", c.index);
        t.checked += 1;
    }
    t.done();
}

// ------------------------------------------------------------- mod q

/// NTT und inverse NTT. Die Reihenfolge der Werte nach der NTT ist eine
/// Darstellungsfrage; geprüft wird, ob sie mit Python übereinstimmt.
#[test]
fn ntt_vectors() {
    for (name, inverse) in [("modq.ntt", false), ("modq.intt", true)] {
        let mut t = Tally::new(if inverse { "modq.intt" } else { "modq.ntt" });
        for c in load(name) {
            let a = c.ints("a");
            if a.len() == 1 {
                t.skip_n1(&c);
                continue;
            }
            if !ntt_len_ok(a.len()) {
                t.skip(&c, "Länge nicht 2..=1024 oder keine Zweierpotenz");
                continue;
            }
            assert!(c.ok(), "{name} Fall {}", c.index);
            let out = modq_vec(&c.ints("out"));
            if inverse {
                let mut v = permute(&modq_vec(&a));
                modq::intt(&mut v);
                assert_eq!(v, out, "{name} Fall {}", c.index);
            } else {
                let mut v = modq_vec(&a);
                modq::ntt(&mut v);
                assert_eq!(permute(&v), out, "{name} Fall {}", c.index);
            }
            t.checked += 1;
        }
        t.done();
    }
}

#[test]
fn mul_div_vectors() {
    let mut t = Tally::new("modq.mul_mod_q");
    for c in load("modq.mul_mod_q") {
        let (a, b) = (c.ints("a"), c.ints("b"));
        if !ntt_len_ok(a.len()) || a.len() != b.len() {
            if a.len() == 1 {
                t.skip_n1(&c);
            } else {
                t.skip(&c, "Länge");
            }
            continue;
        }
        let got = modq::poly_mul(&modq_vec(&a), &modq_vec(&b));
        assert!(c.ok(), "Fall {}", c.index);
        assert_eq!(got, modq_vec(&c.ints("out")), "Fall {}", c.index);
        t.checked += 1;
    }
    t.done();

    let mut t = Tally::new("modq.div_mod_q");
    for c in load("modq.div_mod_q") {
        let (a, b) = (c.ints("a"), c.ints("b"));
        if !ntt_len_ok(a.len()) || a.len() != b.len() {
            if a.len() == 1 {
                t.skip_n1(&c);
            } else {
                t.skip(&c, "Länge");
            }
            continue;
        }
        let (mut x, mut y) = (modq_vec(&a), modq_vec(&b));
        modq::ntt(&mut x);
        modq::ntt(&mut y);
        let invertible = modq::any_zero_mask(&y) == 0;
        assert_eq!(invertible, c.ok(), "Fall {}: b invertierbar?", c.index);
        if invertible {
            for (xi, &yi) in x.iter_mut().zip(&y) {
                *xi = modq::mul(*xi, modq::inv(yi));
            }
            modq::intt(&mut x);
            assert_eq!(x, modq_vec(&c.ints("out")), "Fall {}", c.index);
        }
        t.checked += 1;
    }
    t.done();

    let mut t = Tally::new("modq.is_invertible_mod_q");
    for c in load("modq.is_invertible_mod_q") {
        let a = c.ints("a");
        if !ntt_len_ok(a.len()) {
            if a.len() == 1 {
                t.skip_n1(&c);
            } else {
                t.skip(&c, "Länge");
            }
            continue;
        }
        let mut v = modq_vec(&a);
        modq::ntt(&mut v);
        assert_eq!(
            modq::any_zero_mask(&v) == 0,
            c.bool("out"),
            "Fall {}",
            c.index
        );
        t.checked += 1;
    }
    t.done();

    let mut t = Tally::new("modq.center_mod_q");
    for c in load("modq.center_mod_q") {
        let got: Vec<i128> = modq_vec(&c.ints("a"))
            .into_iter()
            .map(|x| modq::center(x) as i128)
            .collect();
        assert_eq!(got, c.ints("out"), "Fall {}", c.index);
        t.checked += 1;
    }
    t.done();
}

// ------------------------------------------------------------- Bausteine von Verify

#[test]
fn hash_to_point_vectors() {
    let mut t = Tally::new("hashing.hash_to_point");
    for c in load("hashing.hash_to_point") {
        let (n, _) = params(&c);
        let got: Vec<i128> = hash_to_point(&c.bytes("data"), &[], n)
            .into_iter()
            .map(i128::from)
            .collect();
        assert_eq!(got, c.ints("out"), "Fall {}", c.index);
        t.checked += 1;
    }
    t.done();
}

#[test]
fn public_key_vectors() {
    let mut t = Tally::new("falcon.compute_public_key");
    for c in load("falcon.compute_public_key") {
        let (Some(f), Some(g)) = (to_i8(&c.ints("f")), to_i8(&c.ints("g"))) else {
            t.skip(&c, "Wert ausserhalb i8");
            continue;
        };
        let got = compute_public_key(&f, &g);
        if c.ok() {
            let h: Vec<i128> = got.unwrap().into_iter().map(i128::from).collect();
            assert_eq!(h, c.ints("out"), "Fall {}", c.index);
        } else {
            assert!(got.is_err(), "Fall {}", c.index);
        }
        t.checked += 1;
    }
    t.done();
}

#[test]
fn s1_and_norm_vectors() {
    let mut t = Tally::new("falcon.compute_s1");
    for c in load("falcon.compute_s1") {
        let Some(s2) = to_i16(&c.ints("s2")) else {
            t.skip(&c, "s₂ ausserhalb i16");
            continue;
        };
        let cc: Vec<u16> = modq_vec(&c.ints("c"))
            .into_iter()
            .map(|x| x as u16)
            .collect();
        let mut h = modq_vec(&c.ints("h"));
        modq::ntt(&mut h);
        let got: Vec<i128> = compute_s1(&cc, &s2, &h)
            .into_iter()
            .map(i128::from)
            .collect();
        assert_eq!(got, c.ints("out"), "Fall {}", c.index);
        t.checked += 1;
    }
    t.done();

    let mut t = Tally::new("falcon.is_short");
    for c in load("falcon.is_short") {
        let (n, _) = params(&c);
        let s1: Vec<i64> = c.ints("s1").iter().map(|&x| x as i64).collect();
        let s2: Vec<i64> = c.ints("s2").iter().map(|&x| x as i64).collect();
        assert_eq!(
            is_short(&s1, &s2, bound(n)),
            c.bool("out"),
            "Fall {}",
            c.index
        );
        t.checked += 1;
    }
    t.done();
}

// ------------------------------------------------------------- Abläufe

/// Ganze Verify-Fälle aus Python (gültig und mit veränderter Nachricht).
#[test]
fn flow_verify_vectors() {
    let mut t = Tally::new("flow.verify");
    for c in load("flow.verify") {
        let n = c.int("n") as usize;
        let logn = logn_of(n).unwrap();
        let h: Vec<u16> = c.ints("h").iter().map(|&x| x as u16).collect();
        let pk = VerifyingKey::from_bytes(&encode_pk(logn, &h)).unwrap();
        let sig = Signature::from_bytes(&c.bytes("sig")).unwrap();
        assert_eq!(
            pk.verify(&c.bytes("msg"), &sig),
            c.bool("out"),
            "Fall {}",
            c.index
        );
        t.checked += 1;
    }
    t.done();
}

/// Schlüssel aus dem Python-Keygen (alle Grade 2 … 1024). Rust erzeugt mit
/// dem Keygen der Referenz andere Schlüssel (PLAN.md L10); geprüft wird,
/// dass Rust die Python-Schlüssel als gültig erkennt:
/// h = g/f, fG − gF = q exakt, G aus f, g, F, und für 512/1024 das Laden
/// über das Secret-Key-Format.
#[test]
fn flow_keygen_vectors() {
    let mut t = Tally::new("flow.keygen");
    for c in load("flow.keygen") {
        let n = c.int("n") as usize;
        let [f, g, big_f, big_g] = [0, 1, 2, 3].map(|k| c.ints(&format!("key{k}")));
        let h = c.ints("h");

        // fG − gF = q in ℤ[x]/(xⁿ+1), unabhängig gerechnet
        let mut acc = vec![0i128; n];
        for i in 0..n {
            for j in 0..n {
                let p = f[i] * big_g[j] - g[i] * big_f[j];
                if i + j < n {
                    acc[i + j] += p;
                } else {
                    acc[i + j - n] -= p;
                }
            }
        }
        assert_eq!(acc[0], Q as i128, "Fall {} (n = {n})", c.index);
        assert!(
            acc[1..].iter().all(|&x| x == 0),
            "Fall {} (n = {n})",
            c.index
        );

        let (f8, g8) = (to_i8(&f).unwrap(), to_i8(&g).unwrap());
        let pk: Vec<i128> = compute_public_key(&f8, &g8)
            .unwrap()
            .into_iter()
            .map(i128::from)
            .collect();
        assert_eq!(pk, h, "Fall {} (n = {n}): h", c.index);

        // F, G in 8 Bit (für kleine n nicht immer, dann gilt nur das oben)
        if let (Some(bf8), Some(bg16)) = (to_i8(&big_f), to_i16(&big_g)) {
            if bg16.iter().all(|&x| x.abs() <= 127) {
                let rg = recompute_g(&f8, &g8, &bf8).unwrap();
                assert_eq!(&rg[..], &bg16[..], "Fall {} (n = {n}): G", c.index);
                assert_eq!(key_valid_mask(&f8, &g8, &bf8, &bg16), u32::MAX);
            }
            if n >= 512 {
                let logn = logn_of(n).unwrap();
                let bytes = encode_sk(&SecretPolys {
                    logn,
                    f: f8.clone(),
                    g: g8.clone(),
                    big_f: bf8,
                })
                .unwrap();
                let sk = SigningKey::from_bytes(&bytes).unwrap();
                let want: Vec<u16> = h.iter().map(|&x| x as u16).collect();
                assert_eq!(sk.verifying_key().to_bytes(), encode_pk(logn, &want));
            }
        }
        t.checked += 1;
    }
    t.done();
}
