//! Statistische Zeitmessung nach dudect (PLAN.md §6, Prüfung 2).
//!
//! Je Baustein zwei Klassen von Eingaben, zufällig gemischt gemessen:
//! Klasse 0 mit festen, Klasse 1 mit zufälligen geheimen Werten. Ein
//! Welch-t-Test vergleicht die Laufzeiten; |t| > 4.5 gilt als Leck. Wie in
//! dudect werden die Messungen zusätzlich an mehreren Perzentilen
//! abgeschnitten (Ausreisser durch Unterbrechungen), gemeldet wird das
//! grösste |t|.
//!
//! Nur auf echter Hardware aussagekräftig (nicht unter QEMU), Release-Build:
//!
//! ```text
//! cargo run --release --example dudect --features dudect
//! ```

use fndsa::dudect as d;
use fndsa::{keygen_from_seed, LogN, SigningKey};
use rand_core::{CryptoRng, RngCore};
use std::hint::black_box;

/// xorshift64 für die Auswahl von Klassen und Eingaben (öffentlich).
struct X(u64);

impl X {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// zufällige normale Gleitkommazahl mit Exponent in [−lim, lim]
    fn normal(&mut self, lim: u64) -> u64 {
        let r = self.next();
        let e = (r % (2 * lim + 1)) + 1023 - lim;
        ((r >> 63) << 63) | (e << 52) | (self.next() & ((1 << 52) - 1))
    }
    fn uniform(&mut self, lo: f64, hi: f64) -> u64 {
        let u = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        (lo + u * (hi - lo)).to_bits()
    }
}

impl RngCore for X {
    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.next()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for X {}

/// Zeitstempel in Zyklen (x86-64) bzw. Nanosekunden (sonst).
#[inline(always)]
fn now() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: lfence und rdtsc sind auf jeder x86-64-CPU vorhanden.
    unsafe {
        use core::arch::x86_64::{_mm_lfence, _rdtsc};
        _mm_lfence();
        let t = _rdtsc();
        _mm_lfence();
        t
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use std::sync::OnceLock;
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_nanos() as u64
    }
}

/// Welch-t-Statistik zweier Stichproben.
fn welch(a: &[f64], b: &[f64]) -> f64 {
    let mv = |x: &[f64]| {
        let n = x.len() as f64;
        let m = x.iter().sum::<f64>() / n;
        let v = x.iter().map(|y| (y - m).powi(2)).sum::<f64>() / (n - 1.0);
        (m, v, n)
    };
    let (ma, va, na) = mv(a);
    let (mb, vb, nb) = mv(b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}

/// Misst `n` Aufrufe; `run(klasse, rng)` bereitet die Eingabe vor und gibt
/// die gemessene Dauer zurück. Liefert (grösstes |t|, Median Klasse 0, 1).
fn test(n: usize, mut run: impl FnMut(bool, &mut X) -> u64) -> (f64, u64, u64) {
    let mut rng = X(0x9E37_79B9_7F4A_7C15);
    // Aufwärmen
    for _ in 0..n / 20 {
        let c = rng.next() & 1 == 1;
        run(c, &mut rng);
    }
    let mut samples: Vec<(bool, u64)> = Vec::with_capacity(n);
    for _ in 0..n {
        let c = rng.next() & 1 == 1;
        samples.push((c, run(c, &mut rng)));
    }
    let mut all: Vec<u64> = samples.iter().map(|s| s.1).collect();
    all.sort_unstable();
    let pct = |p: f64| all[((all.len() - 1) as f64 * p) as usize];
    let mut tmax: f64 = 0.0;
    for cut in [1.0, 0.99, 0.95, 0.9, 0.75, 0.5] {
        let lim = pct(cut);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for &(c, t) in &samples {
            if t <= lim {
                if c {
                    b.push(t as f64)
                } else {
                    a.push(t as f64)
                }
            }
        }
        if a.len() > 10 && b.len() > 10 {
            tmax = tmax.max(welch(&a, &b).abs());
        }
    }
    let median = |cls: bool| {
        let mut v: Vec<u64> = samples.iter().filter(|s| s.0 == cls).map(|s| s.1).collect();
        v.sort_unstable();
        v[v.len() / 2]
    };
    (tmax, median(false), median(true))
}

fn report(name: &str, n: usize, (t, m0, m1): (f64, u64, u64)) {
    let verdict = if t > 4.5 { "AUFFÄLLIG" } else { "ok" };
    println!("{name:<34} {n:>9} {m0:>10} {m1:>10} {t:>8.2}  {verdict}");
}

fn main() {
    let unit = if cfg!(target_arch = "x86_64") {
        "Zyklen"
    } else {
        "ns"
    };
    println!(
        "{:<34} {:>9} {:>10} {:>10} {:>8}",
        "Baustein (fest gegen zufällig)", "Messungen", "Median 0", "Median 1", "|t|"
    );
    println!("(Median in {unit})");

    let n = 1_000_000;
    type Op2 = fn(u64, u64) -> u64;
    for (name, op) in [
        ("fpr: Division", d::fpr_div as Op2),
        ("fpr: Multiplikation", d::fpr_mul),
        ("fpr: Addition", d::fpr_add),
    ] {
        let one = 1.0f64.to_bits();
        let three = 3.0f64.to_bits();
        let r = test(n, |c, x| {
            let (a, b) = if c {
                (x.normal(60), x.normal(60))
            } else {
                (one, three)
            };
            let (a, b) = (black_box(a), black_box(b));
            let t0 = now();
            black_box(op(a, b));
            now() - t0
        });
        report(name, n, r);
    }
    let r = test(n, |c, x| {
        let a = if c {
            x.normal(300) & !(1 << 63)
        } else {
            2.0f64.to_bits()
        };
        let a = black_box(a);
        let t0 = now();
        black_box(d::fpr_sqrt(a));
        now() - t0
    });
    report("fpr: Wurzel", n, r);
    let r = test(n, |c, x| {
        let a = if c { x.normal(40) } else { 0.5f64.to_bits() };
        let a = black_box(a);
        let t0 = now();
        black_box(d::fpr_rint(a));
        now() - t0
    });
    report("fpr: Runden", n, r);

    let r = test(n, |c, x| {
        // gleiche Vorbereitung für beide Klassen, erst danach fest setzen
        let mut b = [0u8; 9];
        x.fill_bytes(&mut b);
        if !c {
            b = [0u8; 9];
        }
        let b = black_box(b);
        let t0 = now();
        black_box(d::base_sampler(b));
        now() - t0
    });
    report("Sampler: BaseSampler", n, r);

    let ns = 200_000;
    let r = test(ns, |c, x| {
        let (mu, sigma) = if c {
            (x.uniform(-100.0, 100.0), x.uniform(1.2778337, 1.8205))
        } else {
            (0.0f64.to_bits(), 1.5f64.to_bits())
        };
        // Zufall des Samplers in beiden Klassen gleich verteilt
        let seed = x.next().to_le_bytes();
        let (mu, sigma) = (black_box(mu), black_box(sigma));
        let t0 = now();
        black_box(d::sampler_z(mu, sigma, &seed));
        now() - t0
    });
    report("Sampler: SamplerZ (μ, σ′)", ns, r);

    // Signieren: fester Schlüssel gegen Schlüssel aus einem Vorrat
    let keys: Vec<SigningKey> = (0..16u8)
        .map(|i| keygen_from_seed(LogN::FALCON_512, &[i; 48]).unwrap().0)
        .collect();
    let fixed = keygen_from_seed(LogN::FALCON_512, &[0xAA; 48]).unwrap().0;
    let nsig = 3000;
    // Vor jeder Messung den Cache für beide Klassen gleich leeren; sonst
    // bliebe der feste Schlüssel im Cache, die Schlüssel aus dem Vorrat
    // nicht (das misst, welcher Speicher benutzt wird, nicht die Werte).
    let mut evict = vec![0u8; 16 << 20];
    let r = test(nsig, |c, x| {
        let k = if c {
            &keys[(x.next() % 16) as usize]
        } else {
            &fixed
        };
        for i in (0..evict.len()).step_by(64) {
            evict[i] = evict[i].wrapping_add(1);
        }
        black_box(&evict);
        let t0 = now();
        black_box(k.sign(b"dudect", x));
        now() - t0
    });
    report("Sign (Schlüssel)", nsig, r);
}
