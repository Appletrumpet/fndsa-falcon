//! FN-DSA (Falcon) in Rust, mit konstanter Laufzeit auf geheimen Daten.
//!
//! Stand: alle Phasen 0 bis 8 aus `PLAN.md` – Keygen, Sign, Verify und
//! alle Byteformate für Falcon-512 und Falcon-1024. Keygen ist eine
//! Portierung der Referenz und erzeugt aus den NIST-KAT-Seeds byte-genau
//! die KAT-Schlüssel. Sign prüft sich gegen eingeschleuste Fehler
//! (`SigningKey::try_sign`); auf aarch64 wird das DIT-Flag gesetzt
//! (`dit_available`).
//!
//! ```no_run
//! use fndsa::{keygen, LogN, Signature, SigningKey, VerifyingKey};
//! # struct R; impl rand_core::RngCore for R { fn next_u32(&mut self) -> u32 { 0 }
//! # fn next_u64(&mut self) -> u64 { 0 } fn fill_bytes(&mut self, _: &mut [u8]) {}
//! # fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> { Ok(()) } }
//! # impl rand_core::CryptoRng for R {}
//! # let (msg, mut rng) = (b"msg", R);
//! let (sk, pk) = keygen(LogN::FALCON_512, &mut rng).unwrap(); // rng: z. B. OsRng
//! let sk_bytes = sk.to_bytes();                              // speichern
//! let sk = SigningKey::from_bytes(&sk_bytes).unwrap();        // laden
//! let sig = sk.sign(msg, &mut rng);
//! let _: &VerifyingKey = &pk;
//! assert!(pk.verify(msg, &Signature::from_bytes(&sig.to_bytes()).unwrap()));
//! ```

#![warn(missing_docs)]

mod ct;
mod encoding;
mod falcon;
mod ffsampling;
mod fft;
mod fft_ref;
mod fft_table;
mod fpr;
mod hashing;
mod keygen_tables;
mod modq;
mod ntrugen;
mod params;
mod prng;
mod sampler;
mod tree;
mod zint;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

/// Für `examples/ctgrind.rs`: geheime Bytes für Valgrind markieren.
#[cfg(feature = "ctgrind")]
#[doc(hidden)]
pub mod ctgrind {
    pub use crate::ct::{poison, unpoison};
}

/// Für `examples/dudect.rs`: Bausteine mit geheimen Eingaben einzeln
/// aufrufbar machen (Zeitmessung, PLAN.md §6).
#[cfg(feature = "dudect")]
#[doc(hidden)]
pub mod dudect {
    use crate::fpr::Fpr;

    /// a/b auf IEEE-754-Bits.
    pub fn fpr_div(a: u64, b: u64) -> u64 {
        (Fpr::from_bits(a) / Fpr::from_bits(b)).to_bits()
    }
    /// a·b auf IEEE-754-Bits.
    pub fn fpr_mul(a: u64, b: u64) -> u64 {
        (Fpr::from_bits(a) * Fpr::from_bits(b)).to_bits()
    }
    /// a + b auf IEEE-754-Bits.
    pub fn fpr_add(a: u64, b: u64) -> u64 {
        (Fpr::from_bits(a) + Fpr::from_bits(b)).to_bits()
    }
    /// √a auf IEEE-754-Bits.
    pub fn fpr_sqrt(a: u64) -> u64 {
        Fpr::from_bits(a).sqrt().to_bits()
    }
    /// Runden auf IEEE-754-Bits.
    pub fn fpr_rint(a: u64) -> i64 {
        Fpr::from_bits(a).rint()
    }
    /// SamplerZ mit μ, σ′ als Bits; Zufall aus ChaCha20 mit `seed`.
    pub fn sampler_z(mu: u64, sigma: u64, seed: &[u8]) -> i64 {
        let mut rng = crate::prng::Prng::new(seed);
        crate::sampler::sampler_z(
            Fpr::from_bits(mu),
            Fpr::from_bits(sigma),
            &crate::params::FALCON_512,
            &mut rng,
        )
    }
    /// Ein einzelner Sign-Versuch ohne Neustarts: Ziel t für eine feste
    /// Nachricht, dann ffSampling und Signaturvektor. Trennt in der
    /// Zeitmessung die Arbeit je Versuch von der (erlaubten) Zahl der
    /// Neustarts.
    pub fn sign_attempt(sk: &crate::SigningKey, seed: &[u8]) -> u64 {
        let c = crate::hashing::hash_to_point(&[0u8; 40], b"dudect", sk.params.n());
        let (t0, t1) = crate::falcon::compute_target_fft(&c, &sk.f_hat, &sk.bigf_hat);
        let mut rng = crate::prng::Prng::new(seed);
        let (z0, z1) = crate::ffsampling::ff_sampling(&t0, &t1, &sk.tree, sk.params, &mut rng);
        let (s0, _) = crate::falcon::compute_signature_vector((&t0, &t1), (&z0, &z1), &sk.basis);
        s0[0].re.to_bits()
    }

    /// Ob auf dieser CPU das DIT-Flag gesetzt wird (nur aarch64).
    pub fn dit_available() -> bool {
        crate::ct::dit_available()
    }

    /// Zahl der SamplerZ-Runden seit dem letzten Aufruf (setzt zurück).
    pub fn take_sampler_rounds() -> u64 {
        crate::sampler::ROUNDS.swap(0, core::sync::atomic::Ordering::Relaxed)
    }

    /// BaseSampler mit 9 festen Zufallsbytes.
    pub fn base_sampler(bytes: [u8; 9]) -> u32 {
        struct Fixed([u8; 9]);
        impl crate::prng::RandomSource for Fixed {
            fn fill(&mut self, out: &mut [u8]) {
                out.copy_from_slice(&self.0[..out.len()]);
            }
        }
        crate::sampler::base_sampler(&mut Fixed(bytes))
    }
}

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod kat;

#[cfg(test)]
mod python_vectors;

use std::fmt;

use sha3::digest::{ExtendableOutput, Update};
use zeroize::Zeroizing;

pub use ct::dit_available;
pub use params::{LogN, Params, FALCON_1024, FALCON_512, Q};

/// Fehler beim Dekodieren oder Erzeugen von Schlüsseln und Signaturen.
///
/// `non_exhaustive`: Sign und Keygen (Phase 4/5) bringen neue Fälle dazu.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// logn liegt nicht in 1..=10.
    InvalidLogN,
    /// Für dieses logn gibt es (noch) keinen vollständigen Parametersatz;
    /// bisher nur Falcon-512 und Falcon-1024.
    UnsupportedLogN,
    /// Byteformat ungültig (Grund als Text).
    InvalidEncoding(&'static str),
    /// Ein Koeffizient von f, g oder F passt nicht ins Secret-Key-Format (L6).
    KeyOutOfRange,
    /// f ist modulo q nicht invertierbar.
    NotInvertible,
    /// Kein gültiger Falcon-Schlüssel: G passt nicht in 8 Bit, fG − gF ≠ q
    /// oder die Basis ist zu schlecht (σ′ ausserhalb von [σmin, σmax]).
    InvalidKey,
    /// Sign hat einen Fehler im Rechner erkannt (Fault-Schutz): der
    /// Schlüssel im Speicher ist verändert, oder dreimal hintereinander
    /// bestand die Signatur Verify nicht bzw. war unplausibel kurz. Es
    /// wurde keine Signatur ausgegeben.
    FaultDetected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLogN => write!(f, "logn muss im Bereich 1..=10 liegen"),
            Error::UnsupportedLogN => write!(f, "kein Parametersatz für dieses logn"),
            Error::InvalidEncoding(why) => write!(f, "ungültige Kodierung: {why}"),
            Error::KeyOutOfRange => write!(f, "Schlüssel passt nicht ins Secret-Key-Format"),
            Error::NotInvertible => write!(f, "f ist modulo q nicht invertierbar"),
            Error::InvalidKey => write!(f, "kein gültiger Falcon-Schlüssel"),
            Error::FaultDetected => {
                write!(f, "Fehler im Rechner erkannt, keine Signatur ausgegeben")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Public Key h (§3.11.4). Hält h zusätzlich in NTT-Form für Verify.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    params: &'static Params,
    h: Vec<u16>,
    h_ntt: Vec<u32>,
}

impl VerifyingKey {
    /// Dekodiert einen Public Key (Header 0000nnnn, 14 Bit je Koeffizient).
    ///
    /// Fehler `UnsupportedLogN`, wenn das Format zwar gültig ist, es für den
    /// Grad aber keinen Parametersatz gibt (bisher alles ausser 512/1024).
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (logn, h) = encoding::decode_pk(b)?;
        let params = logn.params().ok_or(Error::UnsupportedLogN)?;
        let mut h_ntt: Vec<u32> = h.iter().map(|&x| x as u32).collect();
        modq::ntt(&mut h_ntt);
        Ok(VerifyingKey { params, h, h_ntt })
    }

    /// Kodiert den Public Key (§3.11.4); Umkehrung von `from_bytes`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encoding::encode_pk(self.params.logn, &self.h)
    }

    /// Grad des Schlüssels (log₂ n).
    pub fn logn(&self) -> LogN {
        self.params.logn
    }

    /// Verify (Alg. 16). `false` bei anderem Grad als der Schlüssel,
    /// ungültiger Kodierung von s₂ oder zu grosser Norm.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        self.verify_report(msg, sig).accepted
    }

    /// Verify mit Zwischenergebnissen (UI-PLAN.md §4): an welchem Schritt
    /// Verify scheitert, die Norm ‖(s₁, s₂)‖² und die Schranke ⌊β²⌋. Für
    /// Erklärungen (Web-Oberfläche) und Tests; `verify` ruft diese Funktion
    /// auf, es gibt also nur einen Rechenweg. Alles hier ist öffentlich.
    pub fn verify_report(&self, msg: &[u8], sig: &Signature) -> VerifyReport {
        let bound = self.params.sig_bound;
        if sig.logn != self.params.logn {
            return VerifyReport {
                accepted: false,
                failed_at: Some(VerifyStep::Decode),
                norm: None,
                bound,
            };
        }
        match falcon::signature_norm_sq(self.params, &self.h_ntt, &sig.salt, &sig.s2_enc, msg) {
            None => VerifyReport {
                accepted: false,
                failed_at: Some(VerifyStep::Decompress),
                norm: None,
                bound,
            },
            Some(norm) => VerifyReport {
                accepted: norm <= bound,
                failed_at: (norm > bound).then_some(VerifyStep::Norm),
                norm: Some(norm),
                bound,
            },
        }
    }
}

/// Die fünf Schritte von Verify (Alg. 16), wie die Web-Oberfläche sie
/// zeigt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyStep {
    /// Grad von Signatur und Schlüssel prüfen (scheitert, wenn er nicht passt).
    Decode,
    /// c = HashToPoint(Salt ‖ Nachricht); kann nicht scheitern.
    HashToPoint,
    /// s₂ dekomprimieren (scheitert bei ungültiger Kodierung).
    Decompress,
    /// s₁ = c − s₂·h mod q; kann nicht scheitern.
    ComputeS1,
    /// ‖(s₁, s₂)‖² ≤ ⌊β²⌋ (scheitert, wenn die Norm zu gross ist).
    Norm,
}

impl VerifyStep {
    /// Alle Schritte in der Reihenfolge von Alg. 16.
    pub const ALL: [VerifyStep; 5] = [
        VerifyStep::Decode,
        VerifyStep::HashToPoint,
        VerifyStep::Decompress,
        VerifyStep::ComputeS1,
        VerifyStep::Norm,
    ];

    /// Position in `ALL` (0 bis 4).
    pub fn index(self) -> usize {
        match self {
            VerifyStep::Decode => 0,
            VerifyStep::HashToPoint => 1,
            VerifyStep::Decompress => 2,
            VerifyStep::ComputeS1 => 3,
            VerifyStep::Norm => 4,
        }
    }
}

/// Ergebnis von `VerifyingKey::verify_report`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyReport {
    /// Signatur gültig.
    pub accepted: bool,
    /// Schritt, an dem Verify abgebrochen hat; `None`, wenn gültig.
    pub failed_at: Option<VerifyStep>,
    /// ‖(s₁, s₂)‖², falls bis zur Norm gerechnet wurde.
    pub norm: Option<u64>,
    /// ⌊β²⌋ des Parametersatzes.
    pub bound: u64,
}

// Gleich, wenn Grad und h gleich sind (h_ntt folgt daraus).
impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.params.logn == other.params.logn && self.h == other.h
    }
}

impl Eq for VerifyingKey {}

/// Secret Key (§3.11.5) mit vorberechneter Basis und Falcon-Baum
/// (Alg. 4, Z. 2–7). Alles darin ist geheim: kein `Debug`, kein
/// Vergleich, und beim Verwerfen werden alle Puffer gelöscht.
pub struct SigningKey {
    params: &'static Params,
    f: Zeroizing<Vec<i8>>,
    g: Zeroizing<Vec<i8>>,
    big_f: Zeroizing<Vec<i8>>,
    /// enthält Ĝ (G selbst wird nach dem Aufbau nicht mehr gebraucht)
    basis: tree::Basis,
    /// f̂ und F̂ für das Ziel t in Sign (beim Laden berechnet)
    f_hat: fft::Poly,
    bigf_hat: fft::Poly,
    tree: tree::Tree,
    /// passender Public Key, für Verify nach Sign
    vk: VerifyingKey,
    /// Prüfsumme über alles oben (Fault-Schutz, `key_digest`)
    digest: Zeroizing<[u8; 32]>,
}

impl SigningKey {
    /// Lädt einen Secret Key (Header 0101nnnn, f, g, F). Berechnet G aus
    /// der NTRU-Gleichung neu und baut Basis und Falcon-Baum auf.
    ///
    /// Prüft dabei, dass es ein gültiger Falcon-Schlüssel ist: |G| ≤ 127,
    /// fG − gF = q und alle Blätter des Baums in [σmin, σmax]. Ohne diese
    /// Prüfung würde Sign mit einem erfundenen Schlüssel nie fertig. Die
    /// Prüfungen laufen ohne Verzweigung auf den Werten; nur das Ergebnis
    /// gültig/ungültig verzweigt.
    ///
    /// Fehler: ungültige Kodierung, `UnsupportedLogN` (bisher nur 512 und
    /// 1024), `NotInvertible` (f nicht invertierbar mod q), `InvalidKey`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let _dit = ct::DitGuard::new();
        let sk = encoding::decode_sk(b)?;
        let params = sk.logn.params().ok_or(Error::UnsupportedLogN)?;
        Self::from_polys(params, &sk.f, &sk.g, &sk.big_f)
    }

    /// Gemeinsamer Weg von `from_bytes` und Keygen: G berechnen, Schlüssel
    /// prüfen, Basis und Baum aufbauen.
    fn from_polys(
        params: &'static Params,
        f: &[i8],
        g: &[i8],
        big_f: &[i8],
    ) -> Result<Self, Error> {
        let _dit = ct::DitGuard::new();
        let big_g = falcon::recompute_g(f, g, big_f)?;
        if ct::declassify(falcon::key_valid_mask(f, g, big_f, &big_g)) == 0 {
            return Err(Error::InvalidKey);
        }
        let basis = tree::build_basis_fft(f, g, big_f, &big_g);
        let tree = tree::build_falcon_tree(&basis, fpr::Fpr::from_bits(params.sigma.to_bits()));
        let (lo, hi) = leaf_bounds(params);
        if ct::declassify(tree::leaves_in_range_mask(&tree, lo, hi)) == 0 {
            return Err(Error::InvalidKey);
        }
        // f ist invertierbar, das hat recompute_g geprüft.
        let h = falcon::compute_public_key(f, g)?;
        let (f_hat, bigf_hat) = falcon::target_ffts(f, big_f);
        let mut h_ntt: Vec<u32> = h.iter().map(|&x| x as u32).collect();
        modq::ntt(&mut h_ntt);
        let mut sk = SigningKey {
            params,
            f: Zeroizing::new(f.to_vec()),
            g: Zeroizing::new(g.to_vec()),
            big_f: Zeroizing::new(big_f.to_vec()),
            basis,
            f_hat,
            bigf_hat,
            tree,
            vk: VerifyingKey { params, h, h_ntt },
            digest: Zeroizing::new([0u8; 32]),
        };
        sk.digest = sk.key_digest();
        Ok(sk)
    }

    /// SHAKE256 über alle Teile des Schlüssels, die Sign benutzt: f, g, F,
    /// Basis, f̂ und F̂, Falcon-Baum und h (für Verify nach Sign). Beim Laden einmal
    /// berechnet und vor und nach jedem Signieren verglichen. Erkennt so
    /// Fehler, die den Schlüssel im Speicher verändern (Rowhammer, gekippte
    /// Bits, Fault-Angriffe auf gespeicherte Werte): Ein veränderter Baum
    /// liefert sonst Signaturen, die Verify bestehen, aber falsch verteilt
    /// sind und den Schlüssel verraten können.
    ///
    /// Konstante Laufzeit: Keccak arbeitet ohne Verzweigung auf den Daten.
    fn key_digest(&self) -> Zeroizing<[u8; 32]> {
        let n = self.params.n();
        // Alles in einen Puffer, Platz vorher reservieren: Beim Wachsen
        // bliebe sonst ein alter, nicht gelöschter Puffer im Speicher.
        let mut values = 12 * n;
        self.tree.for_each_value(&mut |_| values += 1);
        let mut buf: Zeroizing<Vec<u8>> =
            Zeroizing::new(Vec::with_capacity(1 + 3 * n + 8 * values));
        buf.push(self.params.logn.get() as u8);
        for p in [&self.f, &self.g, &self.big_f] {
            buf.extend(p.iter().map(|&x| x as u8));
        }
        let mut put = |x: fpr::Fpr| buf.extend_from_slice(&x.to_bits().to_le_bytes());
        let b = &self.basis;
        for p in [&b.b00, &b.b01, &b.b10, &b.b11, &self.f_hat, &self.bigf_hat] {
            for c in p.iter() {
                put(c.re);
                put(c.im);
            }
        }
        self.tree.for_each_value(&mut put);
        // Sicherheitsprüfung, nicht nur im Debug-Build: Wäre der Puffer
        // gewachsen, läge eine ungelöschte Kopie im Speicher.
        assert_eq!(buf.len(), buf.capacity());
        let mut h = sha3::Shake256::default();
        h.update(&buf);
        for &x in &self.vk.h {
            h.update(&x.to_le_bytes());
        }
        let mut out = Zeroizing::new([0u8; 32]);
        h.finalize_xof_into(&mut out[..]);
        out
    }

    /// Vergleicht die Prüfsumme ohne Verzweigung; nur das Ergebnis
    /// gleich/ungleich verzweigt (Fehler erkannt).
    fn intact(&self) -> bool {
        let now = self.key_digest();
        let mut d = 0u8;
        for (a, b) in now.iter().zip(self.digest.iter()) {
            d |= a ^ b;
        }
        ct::declassify(ct::is_zero_mask(d as u32)) != 0
    }

    /// Kodiert den Secret Key (§3.11.5); Umkehrung von `from_bytes`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let sk = encoding::SecretPolys {
            logn: self.params.logn,
            f: self.f.to_vec(),
            g: self.g.to_vec(),
            big_f: self.big_f.to_vec(),
        };
        // f, g, F stammen aus decode_sk und passen deshalb immer ins Format.
        encoding::encode_sk(&sk).expect("f, g, F passen ins Secret-Key-Format")
    }

    /// Grad des Schlüssels (log₂ n).
    pub fn logn(&self) -> LogN {
        self.params.logn
    }

    /// Der passende Public Key h = g/f mod q.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.vk.clone()
    }

    /// Signiert `msg` (Alg. 10) wie `try_sign`, bricht aber bei einem
    /// erkannten Fehler im Rechner mit einer Panik ab, statt eine
    /// Signatur auszugeben. Ohne Fehler im Rechner kommt das nicht vor.
    pub fn sign(&self, msg: &[u8], rng: &mut impl rand_core::CryptoRngCore) -> Signature {
        self.try_sign(msg, rng)
            .unwrap_or_else(|e| panic!("Signieren abgebrochen: {e}"))
    }

    /// Signiert `msg` (Alg. 10). Aus `rng` kommen 40 Bytes Salt und 56
    /// Bytes Seed für den Zufall des Samplers (ChaCha20, PLAN.md L9).
    ///
    /// Schutz gegen Fehler im Rechner (Fault-Angriffe, PLAN.md 3.6):
    /// - Vor und nach dem Signieren wird die Prüfsumme des Schlüssels
    ///   verglichen (`key_digest`); ist er im Speicher verändert, gibt es
    ///   sofort `FaultDetected`.
    /// - Jede Signatur muss Verify bestehen **und** eine Norm² von
    ///   mindestens ⌊β²⌋/2 haben (`falcon::min_norm_sq`). Die untere
    ///   Schranke erkennt einen ausgefallenen Sampler, dessen Signaturen
    ///   Verify bestehen, aber den Schlüssel verraten.
    /// - Sonst wird mit neuem Zufall neu signiert; nach drei Fehlschlägen
    ///   `FaultDetected`.
    ///
    /// Auf aarch64 läuft das Signieren mit gesetztem DIT-Flag.
    pub fn try_sign(
        &self,
        msg: &[u8],
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Signature, Error> {
        let _dit = ct::DitGuard::new();
        if !self.intact() {
            return Err(Error::FaultDetected);
        }
        let plausible = falcon::min_norm_sq(self.params)..=self.params.sig_bound;
        for _ in 0..3 {
            let mut salt = [0u8; 40];
            rng.fill_bytes(&mut salt);
            let mut seed = Zeroizing::new([0u8; 56]);
            rng.fill_bytes(&mut seed[..]);
            let mut prng = prng::Prng::new(&seed[..]);
            let s2_enc = falcon::sign_core(&self.sign_key(), self.params, msg, &salt, &mut prng);
            // Die Signatur ist ab hier öffentlich; die Norm darf verzweigen.
            let norm = falcon::signature_norm_sq(self.params, &self.vk.h_ntt, &salt, &s2_enc, msg);
            if norm.is_some_and(|x| plausible.contains(&x)) {
                if !self.intact() {
                    return Err(Error::FaultDetected);
                }
                return Ok(Signature {
                    logn: self.params.logn,
                    salt,
                    s2_enc,
                });
            }
        }
        Err(Error::FaultDetected)
    }

    fn sign_key(&self) -> falcon::SignKey<'_> {
        falcon::SignKey {
            f_hat: &self.f_hat,
            bigf_hat: &self.bigf_hat,
            basis: &self.basis,
            tree: &self.tree,
        }
    }
}

/// Erlaubter Bereich für die Blätter des Falcon-Baums: [σmin − ε, σmax + ε]
/// mit ε = 10⁻¹⁰ wie in Python (`_SIGMA_EPS`). σmin ist in Tab. 3.3 auf
/// neun Stellen gerundet, echte Blätter liegen bis zu 10⁻¹⁰ darunter. Mit
/// Fpr gerechnet, damit kein Befehl der Gleitkommaeinheit entsteht.
fn leaf_bounds(params: &Params) -> (fpr::Fpr, fpr::Fpr) {
    let fp = |x: f64| fpr::Fpr::from_bits(x.to_bits());
    let eps = fp(1e-10);
    (fp(params.sigma_min) - eps, fp(params.sigma_max) + eps)
}

/// Schlüsselpaar erzeugen (Alg. 4). Aus `rng` kommen 48 Bytes Seed; der
/// Rest ist `keygen_from_seed`. Fehler nur `UnsupportedLogN` (bisher nur
/// Falcon-512 und Falcon-1024).
pub fn keygen(
    logn: LogN,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<(SigningKey, VerifyingKey), Error> {
    let mut seed = Zeroizing::new([0u8; 48]);
    rng.fill_bytes(&mut seed[..]);
    keygen_from_seed(logn, &seed)
}

/// Schlüsselpaar deterministisch aus einem Seed erzeugen: SHAKE256(seed)
/// liefert allen Zufall, wie in der Referenz. Gleicher Seed ergibt
/// denselben Schlüssel; mit den Seeds der NIST-KAT-Dateien (über deren
/// AES-CTR-DRBG) entstehen byte-genau die KAT-Schlüssel (PLAN.md L10).
///
/// Konstante Laufzeit wie in der Referenz; erlaubte Verzweigungen nur beim
/// Neuziehen und Verwerfen von Kandidaten (PLAN.md 3.1, §6).
pub fn keygen_from_seed(logn: LogN, seed: &[u8; 48]) -> Result<(SigningKey, VerifyingKey), Error> {
    let params = logn.params().ok_or(Error::UnsupportedLogN)?;
    let _dit = ct::DitGuard::new();
    let k = ntrugen::keygen_from_seed(logn, seed);
    // Keygen erfüllt alle Prüfungen von from_polys (|G| ≤ 127 wegen
    // NTRUSolve, Blätter wegen der γ-Schranke); ein Fehler wäre ein
    // Programmfehler.
    let sk = SigningKey::from_polys(params, &k.f, &k.g, &k.big_f)
        .expect("Keygen liefert einen gültigen Schlüssel");
    debug_assert_eq!(sk.vk.h, k.h);
    let vk = sk.verifying_key();
    Ok((sk, vk))
}

/// Signatur (§3.11.3): Header 0011nnnn, 40 Bytes Salt, komprimiertes s₂.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    logn: LogN,
    salt: [u8; 40],
    s2_enc: Vec<u8>,
}

impl Signature {
    /// Dekodiert eine Signatur. Ob s₂ gültig kodiert ist, prüft erst
    /// `verify`. Keine Obergrenze für die Länge: ungepolsterte Signaturen
    /// dürfen länger als die feste Länge sein (§3.11.3); wer Eingaben aus
    /// dem Netz liest, begrenzt die Länge vorher selbst.
    ///
    /// Achtung: Zu praktisch jeder gepolsterten Signatur gibt es eine ungepolsterte
    /// (Nullbytes am Ende abgeschnitten), die ebenfalls gilt. Signaturbytes
    /// taugen daher nicht als eindeutige Kennung (PLAN.md 5.4).
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 42 {
            return Err(Error::InvalidEncoding("Signatur zu kurz"));
        }
        if b[0] >> 4 != 0b0011 {
            return Err(Error::InvalidEncoding("Signatur-Header"));
        }
        let logn = LogN::new((b[0] & 0x0F) as u32)?;
        let mut salt = [0u8; 40];
        salt.copy_from_slice(&b[1..41]);
        Ok(Signature {
            logn,
            salt,
            s2_enc: b[41..].to_vec(),
        })
    }

    /// Kodiert die Signatur; gibt genau die Bytes zurück, aus denen sie
    /// dekodiert wurde (gepolstert oder ungepolstert).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41 + self.s2_enc.len());
        out.push(0x30 | self.logn.get() as u8);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.s2_enc);
        out
    }

    /// Grad aus dem Header der Signatur (log₂ n).
    pub fn logn(&self) -> LogN {
        self.logn
    }

    /// Die 40 Bytes Salt r.
    pub fn salt(&self) -> &[u8; 40] {
        &self.salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::vectors::load;
    use crate::prng::testing::Replay;
    use crate::prng::RandomSource;

    /// Sign mit dem SHAKE-Strom der Python-Vektoren: Salt aus den ersten
    /// 40 Bytes, danach Zufall für den Sampler mit dem Byteverbrauch von
    /// Python. Ergibt exakt die Signatur aus Python.
    fn sign_like_python(sk: &SigningKey, params: &Params, msg: &[u8], seed: &[u8]) -> Vec<u8> {
        let mut src = Replay::shake(seed);
        let mut salt = [0u8; 40];
        src.fill(&mut salt);
        let enc = falcon::sign_core(&sk.sign_key(), params, msg, &salt, &mut src);
        let mut out = vec![0x30 | params.logn.get() as u8];
        out.extend_from_slice(&salt);
        out.extend_from_slice(&enc);
        out
    }

    #[test]
    fn flow_sign_matches_python() {
        let cases = load("flow.sign");
        assert!(!cases.is_empty());
        for c in cases {
            let sk = SigningKey::from_bytes(&c.bytes("sk")).unwrap();
            assert_eq!(&sk.to_bytes()[..], &c.bytes("sk")[..]);
            let sig = sign_like_python(&sk, sk.params, &c.bytes("msg"), &c.bytes("seed"));
            assert_eq!(sig, c.bytes("sig"), "Fall {}", c.index);
        }
    }

    fn key(logn: LogN, i: u8) -> SigningKey {
        keygen_from_seed(logn, &[i; 48]).unwrap().0
    }

    struct Rng(u64);
    impl rand_core::RngCore for Rng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            d.iter_mut().for_each(|b| *b = self.next_u64() as u8);
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(d);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for Rng {}

    /// Ehrliche Signaturen liegen weit über der unteren Schranke β²/2.
    #[test]
    fn honest_signatures_are_plausible() {
        for (logn, count) in [(LogN::FALCON_512, 300), (LogN::FALCON_1024, 150)] {
            let sk = key(logn, 1);
            let mut rng = Rng(7);
            let (mut lo, mut hi) = (f64::MAX, 0f64);
            for i in 0..count {
                let msg = (i as u32).to_le_bytes();
                let sig = sk.try_sign(&msg, &mut rng).unwrap();
                let norm = falcon::signature_norm_sq(
                    sk.params,
                    &sk.vk.h_ntt,
                    &sig.salt,
                    &sig.s2_enc,
                    &msg,
                )
                .unwrap();
                let r = norm as f64 / sk.params.sig_bound as f64;
                lo = lo.min(r);
                hi = hi.max(r);
            }
            eprintln!("n = {}: Norm²/β² in [{lo:.3}, {hi:.3}]", logn.n());
            assert!(lo > 0.65 && hi <= 1.0, "{lo} {hi}");
        }
    }

    /// Fällt der Sampler aus (rundet nur noch auf μ), bestehen die
    /// Signaturen Verify trotzdem: Verify nach Sign allein reicht also
    /// nicht. Die untere Normschranke erkennt den Fehler.
    #[test]
    fn faulty_sampler_is_detected() {
        for logn in [LogN::FALCON_512, LogN::FALCON_1024] {
            let sk = key(logn, 2);
            sampler::testing::FAULT_ROUND.with(|f| f.set(true));
            let msg = b"fault";
            let salt = [3u8; 40];
            let mut prng = prng::Prng::new(&[0u8; 56]);
            let enc = falcon::sign_core(&sk.sign_key(), sk.params, msg, &salt, &mut prng);
            let norm =
                falcon::signature_norm_sq(sk.params, &sk.vk.h_ntt, &salt, &enc, msg).unwrap();
            eprintln!(
                "n = {}: Norm²/β² mit ausgefallenem Sampler {:.3}",
                logn.n(),
                norm as f64 / sk.params.sig_bound as f64
            );
            assert!(falcon::verify(sk.params, &sk.vk.h_ntt, &salt, &enc, msg));
            assert!(norm < falcon::min_norm_sq(sk.params));
            let r = sk.try_sign(msg, &mut Rng(9));
            sampler::testing::FAULT_ROUND.with(|f| f.set(false));
            assert_eq!(r.unwrap_err(), Error::FaultDetected);
            // danach wieder normal
            assert!(sk.try_sign(msg, &mut Rng(9)).is_ok());
        }
    }

    fn first_leaf(t: &mut tree::Tree) -> &mut fpr::Fpr {
        match t {
            tree::Tree::Leaf(x) => x,
            tree::Tree::Node(_, a, _) => first_leaf(a),
        }
    }

    /// Jede Änderung am geladenen Schlüssel fällt vor dem Signieren auf.
    #[test]
    fn modified_key_is_detected() {
        let mut rng = Rng(11);
        let tamper: [fn(&mut SigningKey); 6] = [
            |k| k.f[0] ^= 1,
            |k| k.big_f[7] ^= 2,
            |k| k.basis.b11[3].re = fpr::Fpr::from_bits(k.basis.b11[3].re.to_bits() ^ 1),
            |k| {
                let x = first_leaf(&mut k.tree);
                *x = fpr::Fpr::from_bits(x.to_bits() ^ 1);
            },
            |k| k.vk.h[5] ^= 1,
            |k| k.f_hat[9].im = fpr::Fpr::from_bits(k.f_hat[9].im.to_bits() ^ 4),
        ];
        for (i, t) in tamper.iter().enumerate() {
            let mut sk = key(LogN::FALCON_512, 3);
            assert!(sk.try_sign(b"x", &mut rng).is_ok());
            t(&mut sk);
            assert_eq!(
                sk.try_sign(b"x", &mut rng).unwrap_err(),
                Error::FaultDetected,
                "Fall {i}"
            );
        }
    }

    /// Wert Nummer k im Baum (Reihenfolge wie `for_each_value`).
    fn tree_value_mut<'a>(t: &'a mut tree::Tree, k: &mut usize) -> Option<&'a mut fpr::Fpr> {
        match t {
            tree::Tree::Leaf(x) => {
                if *k == 0 {
                    return Some(x);
                }
                *k -= 1;
                None
            }
            tree::Tree::Node(l, a, b) => {
                if *k < 2 * l.len() {
                    let c = &mut l[*k / 2];
                    return Some(if (*k).is_multiple_of(2) {
                        &mut c.re
                    } else {
                        &mut c.im
                    });
                }
                *k -= 2 * l.len();
                if let Some(v) = tree_value_mut(a, k) {
                    return Some(v);
                }
                tree_value_mut(b, k)
            }
        }
    }

    /// Fehlersimulation: 400 zufällige einzelne Bits in f, g, F, Basis,
    /// Baum und h kippen. Die Prüfsumme muss jede Änderung erkennen und
    /// nach dem Zurückkippen wieder passen.
    #[test]
    fn random_bit_flips_in_key_are_detected() {
        let mut sk = key(LogN::FALCON_512, 6);
        let n = sk.params.n();
        let mut tree_len = 0;
        sk.tree.for_each_value(&mut |_| tree_len += 1);
        let mut r = Rng(0xB17F11B);
        use rand_core::RngCore;
        let flip = |sk: &mut SigningKey, part: u64, i: usize, bit: u32| match part {
            0 => sk.f[i % n] ^= 1 << (bit % 8),
            1 => sk.g[i % n] ^= 1 << (bit % 8),
            2 => sk.big_f[i % n] ^= 1 << (bit % 8),
            3 => {
                let b = &mut sk.basis;
                let p = match i % 4 {
                    0 => &mut b.b00,
                    1 => &mut b.b01,
                    2 => &mut b.b10,
                    _ => &mut b.b11,
                };
                let c = &mut p[(i / 4) % n];
                c.im = fpr::Fpr::from_bits(c.im.to_bits() ^ (1 << (bit % 64)));
            }
            4 => {
                let x = tree_value_mut(&mut sk.tree, &mut (i % tree_len)).unwrap();
                *x = fpr::Fpr::from_bits(x.to_bits() ^ (1 << (bit % 64)));
            }
            _ => sk.vk.h[i % n] ^= 1 << (bit % 14),
        };
        for _ in 0..400 {
            let (part, i, bit) = (r.next_u64() % 6, r.next_u64() as usize, r.next_u32());
            flip(&mut sk, part, i, bit);
            assert!(!sk.intact(), "Teil {part}, Stelle {i}, Bit {bit}");
            flip(&mut sk, part, i, bit);
            assert!(sk.intact());
        }
    }

    #[test]
    #[should_panic(expected = "Signieren abgebrochen")]
    fn sign_panics_on_fault() {
        let mut sk = key(LogN::FALCON_512, 4);
        sk.g[0] ^= 1;
        sk.sign(b"x", &mut Rng(1));
    }

    /// Während Keygen, Laden und Sign ist DIT gesetzt (falls vorhanden),
    /// danach wieder im alten Zustand.
    #[test]
    fn dit_restored_after_api_calls() {
        let before = ct::dit_enabled();
        let sk = key(LogN::FALCON_512, 5);
        let _ = SigningKey::from_bytes(&sk.to_bytes()).unwrap();
        let _ = sk.sign(b"x", &mut Rng(2));
        assert_eq!(ct::dit_enabled(), before);
    }

    /// Jeder Fehler hat einen eigenen, nicht leeren Text.
    #[test]
    fn error_messages() {
        let all = [
            Error::InvalidLogN,
            Error::UnsupportedLogN,
            Error::InvalidEncoding("x"),
            Error::KeyOutOfRange,
            Error::NotInvertible,
            Error::InvalidKey,
            Error::FaultDetected,
        ];
        let texts: Vec<String> = all.iter().map(|e| e.to_string()).collect();
        for (i, t) in texts.iter().enumerate() {
            assert!(t.len() > 10, "{t}");
            assert!(!texts[..i].contains(t), "{t} doppelt");
        }
        assert!(Error::InvalidEncoding("Grund")
            .to_string()
            .contains("Grund"));
    }

    /// Kürzeste mögliche Signatur: Header, Salt und 1 Byte s₂ (42 Bytes).
    #[test]
    fn signature_length_limit() {
        let mut b = vec![0x39u8; 42];
        b[41] = 0x80;
        let sig = Signature::from_bytes(&b).unwrap();
        assert_eq!(sig.to_bytes(), b);
        assert_eq!(sig.logn(), LogN::FALCON_512);
        assert_eq!(sig.salt(), &[0x39; 40]);
        assert!(Signature::from_bytes(&b[..41]).is_err());
    }

    /// Blätter dürfen bis zu 10⁻¹⁰ unter σmin und über σmax liegen.
    #[test]
    fn leaf_bounds_have_tolerance() {
        for p in [&FALCON_512, &FALCON_1024] {
            let (lo, hi) = leaf_bounds(p);
            let (lo, hi) = (f64::from_bits(lo.to_bits()), f64::from_bits(hi.to_bits()));
            assert!((p.sigma_min - lo - 1e-10).abs() < 1e-15, "{lo}");
            assert!((hi - p.sigma_max - 1e-10).abs() < 1e-15, "{hi}");
        }
    }

    /// Knappe Schranken erzwingen beide Neustarts aus Alg. 10 (Norm zu
    /// gross, s₂ passt nicht in die Länge).
    #[test]
    fn flow_sign_restart_matches_python() {
        let cases = load("flow.sign_restart");
        assert!(!cases.is_empty());
        for c in cases {
            let sk = SigningKey::from_bytes(&c.bytes("sk")).unwrap();
            let base = sk.params;
            let params = Params {
                logn: base.logn,
                sigma: base.sigma,
                sigma_min: base.sigma_min,
                sigma_max: base.sigma_max,
                sig_bound: c.int("sig_bound") as u64,
                sig_bytelen: c.int("sig_bytelen") as usize,
            };
            let sig = sign_like_python(&sk, &params, &c.bytes("msg"), &c.bytes("seed"));
            assert_eq!(sig, c.bytes("sig"), "Fall {}", c.index);
        }
    }
}
