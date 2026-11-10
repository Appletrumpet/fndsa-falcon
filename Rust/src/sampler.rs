//! Gauss-verteilte ganze Zahlen: BaseSampler, ApproxExp, BerExp, SamplerZ.
//!
//! Spec-Referenz: §3.9.3, Alg. 12–15, Tab. 3.1. Entspricht
//! `Python/falcon/sampler.py` und `C/src/sampler.c`, aber mit konstanter
//! Laufzeit (PLAN.md, 3.4).
//!
//! Geheim sind μ, σ′, z₀, b, z, x und alle Zufallsbytes. Keine Verzweigung
//! und kein Speicherzugriff hängt davon ab, mit einer erlaubten Ausnahme:
//! SamplerZ wiederholt seine Runde, bis BerExp annimmt. Die Zahl der Runden
//! ist durch ccs = σmin/σ′ unabhängig von μ und σ′ („isochron“, PLAN.md 3.4
//! und §6, Liste der freigegebenen Verzweigungen).
//!
//! **BerExp streng konstant (L7):** immer 8 Zufallsbytes, Vergleich u < z
//! auf 64 Bit. Alg. 14 vergleicht Byte für Byte von oben und hört beim
//! ersten Unterschied auf; bei gleichen Bytes ist das dasselbe Ergebnis, nur
//! der Verbrauch an Zufall ist anders.
//!
//! Gleitkomma über `Fpr` in derselben Reihenfolge wie Python; damit sind
//! x und die Schwelle z bitgleich mit den Python-Testvektoren.

// Wird erst von Sign und Keygen benutzt (Phase 4/5); bis dahin nur in Tests.
#![allow(dead_code)]

use crate::ct::{mask64_from_msb, mask64_lt, mask64_nonzero, select64};
use crate::fpr::Fpr;
use crate::params::Params;
use crate::prng::RandomSource;
use zeroize::Zeroize;

/// Tab. 3.1: RCDT, 72-Bit-Werte (nur die 18 benutzten Einträge).
const RCDT: [u128; 18] = [
    3024686241123004913666,
    1564742784480091954050,
    636254429462080897535,
    199560484645026482916,
    47667343854657281903,
    8595902006365044063,
    1163297957344668388,
    117656387352093658,
    8867391802663976,
    496969357462633,
    20680885154299,
    638331848991,
    14602316184,
    247426747,
    3104126,
    28824,
    198,
    1,
];

/// Konstanten C[] aus Alg. 13.
const EXP_C: [u64; 13] = [
    0x0000_0004_7411_83A3,
    0x0000_0036_548C_FC06,
    0x0000_024F_DCBF_140A,
    0x0000_171D_939D_E045,
    0x0000_D00C_F58F_6F84,
    0x0006_8068_1CF7_96E3,
    0x002D_82D8_305B_0FEA,
    0x0111_1111_0E06_6FD0,
    0x0555_5555_5507_0F00,
    0x1555_5555_5581_FF00,
    0x4000_0000_0002_B400,
    0x7FFF_FFFF_FFFF_4800,
    0x8000_0000_0000_0000,
];

/// ln 2 wie `math.log(2.0)` in Python (korrekt gerundet).
const LOG2: Fpr = Fpr::from_bits(0x3FE6_2E42_FEFA_39EF);
/// 2⁶³
const TWO63: Fpr = Fpr::from_bits(0x43E0_0000_0000_0000);

/// BaseSampler (Alg. 12): Halb-Gauss 0..=18 aus 72 Zufallsbits, Vergleich
/// mit allen 18 Tabelleneinträgen ohne Abbruch.
pub fn base_sampler(rng: &mut impl RandomSource) -> u32 {
    let mut b = [0u8; 9];
    rng.fill(&mut b);
    let u = b.iter().fold(0u128, |acc, &x| (acc << 8) | x as u128);
    b.zeroize();
    let mut z0 = 0u32;
    for &t in RCDT.iter() {
        // u < t: Borrow der 128-Bit-Subtraktion (beide < 2⁷²)
        z0 += (u.wrapping_sub(t) >> 127) as u32;
    }
    z0
}

/// ⌊v · 2⁶³⌋ für 0 ≤ v ≤ 1 als u64; negative Werte (Rundungsreste) → 0.
#[inline(always)]
fn floor_scaled63(v: Fpr) -> u64 {
    // `floor` liefert i64; 2⁶³ (v = 1) erscheint dort als i64::MIN und ist
    // als u64 wieder genau 2⁶³. Negativ geht nur bei v < 0.
    let f = (v * TWO63).floor() as u64;
    f & !mask64_from_msb(v.to_bits())
}

/// ApproxExp (Alg. 13): ganzzahlige Näherung von 2⁶³ · ccs · exp(−x) für
/// x ∈ [0, ln 2], ccs ∈ [0, 1].
pub fn approx_exp(x: Fpr, ccs: Fpr) -> u64 {
    let z = floor_scaled63(x) as u128;
    let mut y = EXP_C[0];
    for &c in &EXP_C[1..] {
        y = c - ((z * y as u128) >> 63) as u64;
    }
    let z = floor_scaled63(ccs) as u128;
    ((z * y as u128) >> 63) as u64
}

/// Schwelle z aus Alg. 14, Z. 1–4: BerExp liefert 1 genau dann, wenn
/// 64 Zufallsbits (big-endian) kleiner als z sind.
pub fn ber_threshold(x: Fpr, ccs: Fpr) -> u64 {
    // x < 0 → 0 (−0 bleibt −0, wie in Python)
    let x = Fpr::select(x.lt_mask(Fpr::ZERO), x, Fpr::ZERO);
    // x = s·ln 2 + r, dann s ← min(s, 63)
    let s = (x / LOG2).floor();
    let r = x - Fpr::of_i64(s) * LOG2;
    let s = select64(mask64_lt(63, s as u64), s as u64, 63);
    let y = approx_exp(r, ccs);
    // (2y − 1) >> s, für y = 0 (−1 >> s < 0) gilt z = 0
    (y.wrapping_mul(2).wrapping_sub(1) >> s) & mask64_nonzero(y)
}

/// BerExp (Alg. 14, streng konstant): 1 mit Wahrscheinlichkeit
/// ccs · exp(−x), als Maske (alle Bits gesetzt = 1).
pub fn ber_exp(x: Fpr, ccs: Fpr, rng: &mut impl RandomSource) -> u64 {
    let z = ber_threshold(x, ccs);
    let u = rng.ber_u64(z);
    mask64_lt(u, z)
}

/// Konstanten für SamplerZ zu einem Parametersatz und σ′.
struct SamplerConsts {
    ccs: Fpr,
    two_sigma_p_sq: Fpr,
    two_sigma_max_sq: Fpr,
}

fn f(x: f64) -> Fpr {
    Fpr::from_bits(x.to_bits())
}

impl SamplerConsts {
    fn new(sigma_p: Fpr, params: &Params) -> SamplerConsts {
        let (smin, smax) = (f(params.sigma_min), f(params.sigma_max));
        // Alg. 15 Z. 2: ccs ← σmin/σ′, höchstens 1
        let ccs = smin / sigma_p;
        let ccs = Fpr::select(Fpr::ONE.lt_mask(ccs), ccs, Fpr::ONE);
        SamplerConsts {
            ccs,
            // wie Python: (2·σ′)·σ′
            two_sigma_p_sq: sigma_p.double() * sigma_p,
            two_sigma_max_sq: smax.double() * smax,
        }
    }

    /// Alg. 15 Z. 7: x ← (z − r)²/(2σ′²) − z₀²/(2σmax²), höchstens 0.
    fn x(&self, z: i64, z0: i64, r: Fpr) -> Fpr {
        let d = Fpr::of_i64(z) - r;
        let x = (d * d) / self.two_sigma_p_sq;
        let x = x - Fpr::of_i64(z0 * z0) / self.two_sigma_max_sq;
        Fpr::select(x.lt_mask(Fpr::ZERO), x, Fpr::ZERO)
    }
}

/// SamplerZ (Alg. 15): ganze Zahl, verteilt nach der diskreten Gaussschen
/// Verteilung mit Mittelwert μ und Standardabweichung σ′ ∈ [σmin, σmax].
pub fn sampler_z(mu: Fpr, sigma_p: Fpr, params: &Params, rng: &mut impl RandomSource) -> i64 {
    // Alg. 15 Z. 1: r ← μ − ⌊μ⌋
    let s = mu.floor();
    let r = mu - Fpr::of_i64(s);
    let k = SamplerConsts::new(sigma_p, params);
    loop {
        // Z. 4–6: z₀ aus BaseSampler, Vorzeichenbit b, z = b + (2b−1)·z₀
        let z0 = base_sampler(rng) as i64;
        let mut b = [0u8; 1];
        rng.fill(&mut b);
        let bm = 0u64.wrapping_sub((b[0] & 1) as u64);
        b.zeroize();
        // b = 0 → −z₀, b = 1 → z₀ + 1
        let z = select64(bm, (-z0) as u64, (z0 + 1) as u64) as i64;
        // Z. 7–9
        let x = k.x(z, z0, r);
        // Erlaubte Verzweigung: angenommen ja/nein (isochron, siehe oben).
        if ber_exp(x, k.ccs, rng) != 0 {
            return s + z;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::vectors::{load, Case};
    use crate::params::{FALCON_1024, FALCON_512};
    use crate::prng::Prng;

    fn fpr(c: &Case, key: &str) -> Fpr {
        Fpr::from_bits(c.float(key))
    }

    fn params(c: &Case) -> &'static Params {
        match c.ints("params")[0] {
            512 => &FALCON_512,
            1024 => &FALCON_1024,
            n => panic!("Parametersatz {n}"),
        }
    }

    /// Liefert die Bytes eines Testvektors der Reihe nach.
    struct Replay {
        data: Vec<u8>,
        pos: usize,
    }

    impl RandomSource for Replay {
        fn fill(&mut self, out: &mut [u8]) {
            let end = self.pos + out.len();
            assert!(end <= self.data.len(), "Testvektor hat zu wenig Bytes");
            out.copy_from_slice(&self.data[self.pos..end]);
            self.pos = end;
        }

        /// Bildet Alg. 14 nach: Bytes einzeln lesen, bis eines von z
        /// abweicht (höchstens 8), den Rest mit 0 auffüllen.
        fn ber_u64(&mut self, z: u64) -> u64 {
            let mut u = 0u64;
            for i in 0..8 {
                let b = self.data[self.pos];
                self.pos += 1;
                u |= (b as u64) << (56 - 8 * i);
                if b as u64 != (z >> (56 - 8 * i)) & 0xFF {
                    break;
                }
            }
            u
        }
    }

    fn replay(c: &Case) -> Replay {
        Replay {
            data: c.bytes("random"),
            pos: 0,
        }
    }

    #[test]
    fn base_sampler_matches_python() {
        let cases = load("sampler.base_sampler");
        assert!(cases.len() > 100);
        for c in cases {
            assert_eq!(
                base_sampler(&mut replay(&c)) as i128,
                c.int("out"),
                "Fall {}",
                c.index
            );
        }
    }

    #[test]
    fn approx_exp_matches_python() {
        let cases = load("sampler.approx_exp");
        assert!(cases.len() > 100);
        for c in cases {
            let y = approx_exp(fpr(&c, "x"), fpr(&c, "ccs"));
            assert_eq!(y as i128, c.int("out"), "Fall {}", c.index);
        }
    }

    #[test]
    fn ber_threshold_matches_python() {
        let cases = load("sampler.ber_exp_z");
        assert!(cases.len() > 100);
        for c in cases {
            let z = ber_threshold(fpr(&c, "x"), fpr(&c, "ccs"));
            assert_eq!(z as i128, c.int("out"), "Fall {}", c.index);
        }
    }

    /// BerExp-Äquivalenz (PLAN.md §7): die von Alg. 14 gelesenen Bytes,
    /// mit Nullen auf 8 aufgefüllt, ergeben im strengen BerExp dasselbe Bit.
    #[test]
    fn ber_exp_matches_python() {
        let cases = load("sampler.ber_exp");
        assert!(cases.len() > 100);
        let mut multi_byte = 0;
        for c in cases {
            let mut bytes = c.bytes("random");
            assert!(bytes.len() <= 8);
            multi_byte += (bytes.len() > 1) as usize;
            bytes.resize(8, 0);
            let mut src = Replay {
                data: bytes,
                pos: 0,
            };
            let got = ber_exp(fpr(&c, "x"), fpr(&c, "ccs"), &mut src) != 0;
            assert_eq!(got, c.bool("out"), "Fall {}", c.index);
            // Mit anderer Auffüllung gleich, wenn Alg. 14 vorher entschieden hat
        }
        // auch Fälle, in denen Alg. 14 mehr als ein Byte braucht
        assert!(multi_byte > 0);
    }

    #[test]
    fn samplerz_x_matches_python() {
        let cases = load("sampler.samplerz_x");
        assert!(cases.len() > 100);
        for c in cases {
            let k = SamplerConsts::new(fpr(&c, "sigma"), params(&c));
            let x = k.x(c.int("z") as i64, c.int("z0") as i64, fpr(&c, "r"));
            assert_eq!(x.to_bits(), c.float("out"), "Fall {}", c.index);
        }
    }

    /// SamplerZ-Äquivalenz (PLAN.md §7): mit dem Byteverbrauch von Python
    /// nachgebildet ergibt sich genau die Ausgabe der Testvektoren, und alle
    /// Bytes werden verbraucht.
    #[test]
    fn sampler_z_matches_python() {
        let cases: Vec<Case> = load("sampler.sample_integer_gaussian")
            .into_iter()
            .filter(|c| c.ok())
            .collect();
        assert!(cases.len() > 100);
        for c in cases {
            let mut src = replay(&c);
            let z = sampler_z(fpr(&c, "mu"), fpr(&c, "sigma"), params(&c), &mut src);
            assert_eq!(z as i128, c.int("out"), "Fall {}", c.index);
            assert_eq!(src.pos, src.data.len(), "Fall {}: Bytes übrig", c.index);
        }
    }

    /// Statistik (PLAN.md §7): Mittelwert, Varianz und χ²-Test gegen die
    /// diskrete Gausssche Verteilung, mit festem Seed.
    #[test]
    fn sampler_z_distribution() {
        let p = &FALCON_512;
        let mut rng = Prng::new(b"sampler_z_distribution");
        for &(mu, sigma) in &[(0.0, 1.5), (-91.3, 1.8205), (12.75, 1.2779), (0.5, 1.6)] {
            let n = 20_000;
            let mut counts = std::collections::BTreeMap::new();
            let (mut sum, mut sum2) = (0.0, 0.0);
            for _ in 0..n {
                let z = sampler_z(Fpr::from_f64(mu), Fpr::from_f64(sigma), p, &mut rng);
                *counts.entry(z).or_insert(0usize) += 1;
                let d = z as f64 - mu;
                sum += d;
                sum2 += d * d;
            }
            // erwartete Wahrscheinlichkeiten ∝ exp(−(z−μ)²/(2σ²))
            let lo = (mu - 12.0 * sigma).floor() as i64;
            let hi = (mu + 12.0 * sigma).ceil() as i64;
            let w: Vec<(i64, f64)> = (lo..=hi)
                .map(|z| (z, (-(z as f64 - mu).powi(2) / (2.0 * sigma * sigma)).exp()))
                .collect();
            let total: f64 = w.iter().map(|(_, x)| x).sum();
            let mean: f64 = w.iter().map(|(z, x)| (*z as f64 - mu) * x).sum::<f64>() / total;
            let var: f64 = w
                .iter()
                .map(|(z, x)| (*z as f64 - mu).powi(2) * x)
                .sum::<f64>()
                / total
                - mean * mean;
            let m = sum / n as f64;
            let v = sum2 / n as f64 - m * m;
            // 5 Standardfehler
            assert!(
                (m - mean).abs() < 5.0 * (var / n as f64).sqrt(),
                "Mittelwert μ={mu}"
            );
            assert!(
                (v - var).abs() < 5.0 * var * (2.0 / n as f64).sqrt(),
                "Varianz μ={mu}"
            );

            // χ²: Klassen mit erwartet ≥ 5, Rest an den Rändern zusammengefasst
            let mut chi2 = 0.0;
            let mut df = 0;
            let (mut rest_obs, mut rest_exp) = (0.0, 0.0);
            for (z, x) in &w {
                let e = x / total * n as f64;
                let o = *counts.get(z).unwrap_or(&0) as f64;
                if e >= 5.0 {
                    chi2 += (o - e).powi(2) / e;
                    df += 1;
                } else {
                    rest_obs += o;
                    rest_exp += e;
                }
            }
            if rest_exp > 0.0 {
                chi2 += (rest_obs - rest_exp).powi(2) / rest_exp.max(1.0);
                df += 1;
            }
            // grobe Schranke für p ≈ 0,001: df + 3,1·√(2·df) + 5
            let limit = df as f64 + 3.1 * (2.0 * df as f64).sqrt() + 5.0;
            assert!(
                chi2 < limit,
                "χ² = {chi2:.1} bei {df} Klassen, μ={mu}, σ={sigma}"
            );
        }
    }
}
