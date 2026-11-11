//! Statistik der Signaturen: Die Koeffizienten von s₂ müssen wie eine
//! diskrete Gaussverteilung mit Mittelwert 0 und Standardabweichung σ
//! (Tab. 3.3) verteilt sein, und zwar für jeden Schlüssel gleich. Ein
//! Fehler im Sampler oder im Falcon-Baum, den Verify nicht bemerkt (die
//! Signatur ist trotzdem kurz genug), fällt hier auf.
//!
//! s₂ wird hier unabhängig von der Bibliothek dekomprimiert.

use fndsa::{keygen_from_seed, LogN};
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

/// s₂ aus der Signatur: je Koeffizient Vorzeichen, 7 niedrige Bits, unär.
fn s2_of(sig: &[u8], n: usize) -> Vec<f64> {
    let b = &sig[41..];
    let mut pos = 0usize;
    let mut bit = || {
        let v = (b[pos / 8] >> (7 - pos % 8)) & 1;
        pos += 1;
        v as i32
    };
    (0..n)
        .map(|_| {
            let sign = bit();
            let mut v = 0;
            for _ in 0..7 {
                v = (v << 1) | bit();
            }
            while bit() == 0 {
                v += 128;
            }
            (if sign == 1 { -v } else { v }) as f64
        })
        .collect()
}

/// Koeffizienten von s₂ aus `count` Signaturen mit dem Schlüssel aus `seed`.
fn samples(logn: LogN, seed: u8, count: usize) -> Vec<f64> {
    let (sk, _) = keygen_from_seed(logn, &[seed; 48]).unwrap();
    let mut rng = TestRng::new(&[seed, 0x57]);
    (0..count)
        .flat_map(|i| {
            s2_of(
                &sk.sign(&(i as u32).to_le_bytes(), &mut rng).to_bytes(),
                logn.n(),
            )
        })
        .collect()
}

/// Häufigkeiten in Klassen der Breite σ/2 (|x| bis 4σ, Rest am Rand).
fn histogram(x: &[f64], sigma: f64) -> Vec<f64> {
    let mut h = vec![0f64; 18];
    for &v in x {
        let k = ((v / (sigma / 2.0)).floor() + 9.0).clamp(0.0, 17.0) as usize;
        h[k] += 1.0;
    }
    h
}

/// Φ(x), Verteilungsfunktion der Standardnormalverteilung (Abramowitz/
/// Stegun 7.1.26 für erf, Fehler < 1.5·10⁻⁷).
fn phi(x: f64) -> f64 {
    let z = x.abs() / std::f64::consts::SQRT_2;
    let t = 1.0 / (1.0 + 0.3275911 * z);
    let poly = t
        * (0.254829592
            + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    let erf = 1.0 - poly * (-z * z).exp();
    if x >= 0.0 {
        0.5 * (1.0 + erf)
    } else {
        0.5 * (1.0 - erf)
    }
}

#[test]
fn s2_is_gaussian_with_sigma() {
    // σ aus Tab. 3.3
    for (logn, sigma, sigs) in [
        (LogN::FALCON_512, 165.736617183, 200),
        (LogN::FALCON_1024, 168.388571447, 100),
    ] {
        let x = samples(logn, 1, sigs);
        let n = x.len() as f64;
        let mean = x.iter().sum::<f64>() / n;
        let var = x.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
        let kurt = x.iter().map(|v| (v - mean).powi(4)).sum::<f64>() / n / var.powi(2);
        let sd = var.sqrt();
        eprintln!(
            "n = {}: {} Werte, Mittel {mean:.2}, σ̂ {sd:.2} (σ = {sigma:.2}), Wölbung {kurt:.3}",
            logn.n(),
            x.len()
        );
        // Standardfehler des Mittels ≈ σ/√N ≈ 0.5; 5 Standardfehler erlaubt
        assert!(mean.abs() < 5.0 * sigma / n.sqrt(), "Mittelwert {mean}");
        assert!((sd / sigma - 1.0).abs() < 0.02, "σ̂ = {sd}");
        assert!((kurt - 3.0).abs() < 0.1, "Wölbung {kurt}");

        // χ²-Anpassungstest gegen N(0, σ²), 18 Klassen (17 Freiheitsgrade):
        // Schranke 40.8 entspricht p = 0.001.
        let h = histogram(&x, sigma);
        let mut chi2 = 0.0;
        for (k, &obs) in h.iter().enumerate() {
            let lo = if k == 0 {
                f64::NEG_INFINITY
            } else {
                (k as f64 - 9.0) * 0.5
            };
            let hi = if k == 17 {
                f64::INFINITY
            } else {
                (k as f64 - 8.0) * 0.5
            };
            // Ganzzahlen: Klasse [a, b) in Einheiten von σ, Korrektur um ½
            let (a, b) = (lo * sigma - 0.5, hi * sigma - 0.5);
            let exp = n * (phi(b / sigma) - phi(a / sigma));
            chi2 += (obs - exp).powi(2) / exp;
        }
        eprintln!("n = {}: χ² = {chi2:.1} (Schranke 40.8)", logn.n());
        assert!(chi2 < 40.8, "χ² = {chi2}");
    }
}

/// Zwei verschiedene Schlüssel ergeben dieselbe Verteilung (χ²-Test auf
/// Gleichheit zweier Stichproben, 18 Klassen, Schranke 40.8 für p = 0.001).
/// Hinge die Verteilung vom Schlüssel ab, verriete jede Signatur etwas
/// über ihn.
#[test]
fn distribution_does_not_depend_on_key() {
    let sigma = 165.736617183;
    let a = histogram(&samples(LogN::FALCON_512, 2, 150), sigma);
    let b = histogram(&samples(LogN::FALCON_512, 3, 150), sigma);
    let (na, nb): (f64, f64) = (a.iter().sum(), b.iter().sum());
    let chi2: f64 = a
        .iter()
        .zip(&b)
        .filter(|(x, y)| *x + *y > 0.0)
        .map(|(x, y)| {
            let d = x * (nb / na).sqrt() - y * (na / nb).sqrt();
            d * d / (x + y)
        })
        .sum();
    eprintln!("χ² zwischen zwei Schlüsseln: {chi2:.1}");
    assert!(chi2 < 40.8, "χ² = {chi2}");
}
