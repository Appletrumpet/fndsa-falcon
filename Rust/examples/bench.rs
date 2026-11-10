//! Laufzeitmessung nach gemeinsamem Messprotokoll (PLAN.md Phase 8, Z6).
//!
//! Protokoll (für Rust, C und Python gleich):
//! - Operationen: Keygen aus einem Seed, Secret Key laden, Sign, Verify,
//!   je für Falcon-512 und Falcon-1024;
//! - feste Eingaben: Seeds 0, 1, 2, … (48 gleiche Bytes), Nachricht
//!   32 Bytes; ein Thread, Release-Build;
//! - Aufwärmen, dann N Läufe; gemeldet werden Median sowie 10- und
//!   90-%-Perzentil, in Zyklen (Zyklenzähler, nur x86-64) und Mikrosekunden.
//!
//! ```text
//! cargo run --release --example bench                        # emuliert
//! cargo run --release --example bench --features native-fpu  # Hardware-FPU
//! ```

use std::hint::black_box;
use std::time::Instant;

use fndsa::{keygen_from_seed, LogN, SigningKey};
use rand_core::{CryptoRng, RngCore};

/// xorshift64 als Zufallsquelle für Sign (nur für die Messung).
struct X(u64);

impl RngCore for X {
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
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for X {}

#[inline(always)]
fn cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: lfence und rdtsc gibt es auf jeder x86-64-CPU.
    unsafe {
        use core::arch::x86_64::{_mm_lfence, _rdtsc};
        _mm_lfence();
        let t = _rdtsc();
        _mm_lfence();
        t
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Ergebnis einer Messreihe: (Zyklen, Nanosekunden) je Lauf.
struct Series(Vec<(u64, u64)>);

impl Series {
    fn stat(&self, f: impl Fn(&(u64, u64)) -> u64) -> (u64, u64, u64) {
        let mut v: Vec<u64> = self.0.iter().map(f).collect();
        v.sort_unstable();
        let at = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
        (at(0.5), at(0.1), at(0.9))
    }
}

/// Misst `run` n-mal nach `warm` Aufwärmläufen; `run(i)` bekommt die
/// Nummer des Laufs.
fn measure(n: usize, warm: usize, mut run: impl FnMut(usize)) -> Series {
    for i in 0..warm {
        run(i);
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let t0 = Instant::now();
        let c0 = cycles();
        run(i);
        let c = cycles() - c0;
        out.push((c, t0.elapsed().as_nanos() as u64));
    }
    Series(out)
}

fn report(op: &str, n_param: usize, runs: usize, s: &Series) {
    let (cm, c10, c90) = s.stat(|x| x.0);
    let (tm, t10, t90) = s.stat(|x| x.1);
    println!(
        "{op:<16} {n_param:>5} {runs:>6} {:>14} {:>12} {:>12} {:>11.1} {:>10.1} {:>10.1}",
        cm,
        c10,
        c90,
        tm as f64 / 1e3,
        t10 as f64 / 1e3,
        t90 as f64 / 1e3
    );
}

fn main() {
    let mode = if cfg!(feature = "native-fpu") {
        "Gleitkommaeinheit der Hardware (native-fpu)"
    } else {
        "emulierte Gleitkommazahlen (Standard)"
    };
    println!("Modus: {mode}");
    println!(
        "Ziel: {}-{}, CPU: {}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "unbekannt".into())
    );
    println!(
        "{:<16} {:>5} {:>6} {:>14} {:>12} {:>12} {:>11} {:>10} {:>10}",
        "Operation", "n", "Läufe", "Zyklen Median", "10 %", "90 %", "µs Median", "10 %", "90 %"
    );

    let msg = [0x5Au8; 32];
    for (logn, nk) in [(LogN::FALCON_512, 50), (LogN::FALCON_1024, 30)] {
        let n = logn.n();

        let s = measure(nk, 3, |i| {
            black_box(keygen_from_seed(logn, &[i as u8; 48]).unwrap());
        });
        report("Keygen", n, nk, &s);

        let (sk, pk) = keygen_from_seed(logn, &[0xAB; 48]).unwrap();
        let sk_bytes = sk.to_bytes();
        let s = measure(200, 10, |_| {
            black_box(SigningKey::from_bytes(black_box(&sk_bytes)).unwrap());
        });
        report("sk laden", n, 200, &s);

        let mut rng = X(0x1234_5678_9ABC_DEF0);
        let s = measure(500, 20, |_| {
            black_box(sk.sign(black_box(&msg), &mut rng));
        });
        report("Sign", n, 500, &s);

        let sig = sk.sign(&msg, &mut rng);
        let s = measure(2000, 100, |_| {
            black_box(pk.verify(black_box(&msg), black_box(&sig)));
        });
        report("Verify", n, 2000, &s);
    }
}
