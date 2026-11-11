//! Arithmetik modulo q = 12289 und NTT in ℤ_q[x]/(xⁿ+1).
//!
//! Spec-Referenz: §3.5 (NTT), Alg. 4 Z. 9 (h = g/f), Alg. 16 Z. 5.
//! Entspricht `Python/falcon/modq.py`, aber iterativ statt rekursiv.
//!
//! Konstante Laufzeit (PLAN.md, 3.7): keine Hardware-Division, Reduktion nach
//! Barrett, bedingte Subtraktion über Masken, Inverse per Fermat mit fester
//! Exponentenkette. Die Funktionen werden auch für geheime Polynome (f) benutzt.
//!
//! Darstellung der NTT: Die Werte liegen in bit-umgekehrter Reihenfolge der
//! Wurzeln ψ^(2k+1). Die Tabelle für n = 1024 dient allen kleineren n: für
//! k < n gilt brv₁₀(k) = brv_logn(k)·(1024/n).
//! Referenz: vrfy.c, mq_NTT / mq_iNTT (Aufbau der Tabelle).

use crate::ct;
use crate::params::Q;

/// Barrett-Konstante: ⌊2⁴²/q⌋.
const BARRETT_SHIFT: u32 = 42;
const BARRETT_M: u64 = (1u64 << BARRETT_SHIFT) / Q as u64;

/// Reduziert x < 2³² auf [0, q).
#[inline(always)]
fn reduce(x: u32) -> u32 {
    let qt = ((x as u64 * BARRETT_M) >> BARRETT_SHIFT) as u32;
    // Rest liegt in [0, 2q): Fehler von ⌊·⌋ ist höchstens 1.
    csub(x - qt * Q)
}

/// x ∈ [0, 2q) → [0, q).
#[inline(always)]
fn csub(x: u32) -> u32 {
    let t = x.wrapping_sub(Q);
    t.wrapping_add(Q & ct::mask_from_msb(t))
}

#[inline(always)]
pub fn add(a: u32, b: u32) -> u32 {
    csub(a + b)
}

#[inline(always)]
pub fn sub(a: u32, b: u32) -> u32 {
    let d = a.wrapping_sub(b);
    d.wrapping_add(Q & ct::mask_from_msb(d))
}

#[inline(always)]
pub fn mul(a: u32, b: u32) -> u32 {
    reduce(a * b)
}

/// a^(q−2) mod q, also a⁻¹ für a ≠ 0 (und 0 für a = 0).
/// Der Exponent ist öffentlich und fest, die Kette hängt nicht von a ab.
pub fn inv(a: u32) -> u32 {
    let mut r = 1u32;
    let mut b = a;
    let mut e = Q - 2;
    while e != 0 {
        // Das Bit von e ist öffentlich; beide Multiplikationen laufen immer.
        let m = 0u32.wrapping_sub(e & 1);
        r = ct::select(m, r, mul(r, b));
        b = mul(b, b);
        e >>= 1;
    }
    r
}

/// Ganze Zahl (z. B. ein Koeffizient von f oder s₂) → [0, q).
/// Für |x| < 2³¹ − q, ohne Verzweigung.
#[inline(always)]
pub fn from_i32(x: i32) -> u32 {
    // Betrag reduzieren, bei negativem x danach negieren.
    let neg = ct::mask_from_msb(x as u32);
    let abs = ((x as u32) ^ neg).wrapping_sub(neg);
    let r = reduce(abs);
    ct::select(neg, r, sub(0, r))
}

/// Wert aus [0, q) zentriert nach (−q/2, q/2].
#[inline(always)]
pub fn center(x: u32) -> i32 {
    // x > q/2 → x − q
    let t = (Q / 2).wrapping_sub(x);
    let m = ct::mask_from_msb(t);
    (x as i32) - ((Q & m) as i32)
}

// ---------------------------------------------------------------------------
// Tabellen
// ---------------------------------------------------------------------------

const fn pow_mod(mut b: u32, mut e: u32) -> u32 {
    let mut r = 1u32;
    while e != 0 {
        if e & 1 == 1 {
            r = r * b % Q;
        }
        b = b * b % Q;
        e >>= 1;
    }
    r
}

/// Primitive 2048-te Einheitswurzel ψ: ψ^1024 = −1.
const fn find_psi() -> u32 {
    let mut g = 2;
    loop {
        let psi = pow_mod(g, (Q - 1) / 2048);
        if pow_mod(psi, 1024) == Q - 1 {
            return psi;
        }
        g += 1;
    }
}

const PSI: u32 = find_psi();

const fn bitrev10(x: usize) -> usize {
    let mut r = 0;
    let mut i = 0;
    while i < 10 {
        r |= ((x >> i) & 1) << (9 - i);
        i += 1;
    }
    r
}

/// ZETA[k] = ψ^brv₁₀(k), IZETA[k] = ψ^−brv₁₀(k).
const fn make_tables() -> ([u32; 1024], [u32; 1024]) {
    let mut z = [0u32; 1024];
    let mut iz = [0u32; 1024];
    let psi_inv = pow_mod(PSI, Q - 2);
    let mut k = 0;
    while k < 1024 {
        z[k] = pow_mod(PSI, bitrev10(k) as u32);
        iz[k] = pow_mod(psi_inv, bitrev10(k) as u32);
        k += 1;
    }
    (z, iz)
}

const TABLES: ([u32; 1024], [u32; 1024]) = make_tables();
static ZETA: [u32; 1024] = TABLES.0;
static IZETA: [u32; 1024] = TABLES.1;

// ---------------------------------------------------------------------------
// NTT
// ---------------------------------------------------------------------------

/// NTT an Ort und Stelle, Werte in [0, q). Länge muss 2..=1024 und eine
/// Zweierpotenz sein. Die Schleifen hängen nur von n ab.
pub fn ntt(a: &mut [u32]) {
    let n = a.len();
    debug_assert!(n.is_power_of_two() && (2..=1024).contains(&n));
    let mut t = n;
    let mut m = 1;
    while m < n {
        t >>= 1;
        for i in 0..m {
            let s = ZETA[m + i];
            let j1 = 2 * i * t;
            for j in j1..j1 + t {
                let u = a[j];
                let v = mul(a[j + t], s);
                a[j] = add(u, v);
                a[j + t] = sub(u, v);
            }
        }
        m <<= 1;
    }
}

/// Umkehrung von `ntt`.
pub fn intt(a: &mut [u32]) {
    let n = a.len();
    debug_assert!(n.is_power_of_two() && (2..=1024).contains(&n));
    let mut t = 1;
    let mut m = n;
    while m > 1 {
        let hm = m >> 1;
        let mut j1 = 0;
        for i in 0..hm {
            let s = IZETA[hm + i];
            for j in j1..j1 + t {
                let u = a[j];
                let v = a[j + t];
                a[j] = add(u, v);
                a[j + t] = mul(sub(u, v), s);
            }
            j1 += 2 * t;
        }
        t <<= 1;
        m = hm;
    }
    let ninv = inv(n as u32);
    for x in a.iter_mut() {
        *x = mul(*x, ninv);
    }
}

/// Maske „mindestens ein Wert ist 0“, ohne Abbruch über alle Werte.
pub fn any_zero_mask(a: &[u32]) -> u32 {
    a.iter().fold(0, |acc, &x| acc | ct::is_zero_mask(x))
}

/// a · b in ℤ_q[x]/(xⁿ+1), Eingaben in [0, q). Bisher nur für Tests.
#[cfg(test)]
pub fn poly_mul(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut x = a.to_vec();
    let mut y = b.to_vec();
    ntt(&mut x);
    ntt(&mut y);
    for (xi, yi) in x.iter_mut().zip(y.iter()) {
        *xi = mul(*xi, *yi);
    }
    intt(&mut x);
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Einfacher, reproduzierbarer Zufall für Tests (xorshift64).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn modq(&mut self) -> u32 {
            (self.next() % Q as u64) as u32
        }
    }

    fn schoolbook(a: &[u32], b: &[u32]) -> Vec<u32> {
        let n = a.len();
        let mut c = vec![0i64; n];
        for i in 0..n {
            for j in 0..n {
                let p = a[i] as i64 * b[j] as i64;
                if i + j < n {
                    c[i + j] += p;
                } else {
                    c[i + j - n] -= p;
                }
            }
        }
        c.iter().map(|&x| x.rem_euclid(Q as i64) as u32).collect()
    }

    #[test]
    fn psi_has_order_2048() {
        assert_eq!(pow_mod(PSI, 1024), Q - 1);
        assert_eq!(pow_mod(PSI, 2048), 1);
    }

    #[test]
    fn scalar_ops_match_naive() {
        let mut r = Rng(1);
        for _ in 0..100_000 {
            let a = r.modq();
            let b = r.modq();
            assert_eq!(add(a, b), (a + b) % Q);
            assert_eq!(sub(a, b), (a + Q - b) % Q);
            assert_eq!(mul(a, b), a * b % Q);
        }
        for a in 1..Q {
            assert_eq!(mul(a, inv(a)), 1, "a = {a}");
        }
        assert_eq!(inv(0), 0);
    }

    #[test]
    fn reduce_full_range() {
        for x in (0..=u32::MAX).step_by(9973).chain([u32::MAX, Q * Q - 1]) {
            assert_eq!(reduce(x), x % Q, "x = {x}");
        }
    }

    #[test]
    fn from_i32_and_center() {
        for x in -100_000i32..=100_000 {
            assert_eq!(from_i32(x), x.rem_euclid(Q as i32) as u32, "x = {x}");
        }
        for x in 0..Q {
            let c = center(x);
            assert!(c > -(Q as i32) / 2 - 1 && c <= Q as i32 / 2);
            assert_eq!(c.rem_euclid(Q as i32) as u32, x);
        }
    }

    #[test]
    fn ntt_roundtrip_and_mul_all_degrees() {
        let mut r = Rng(42);
        for logn in 1..=10 {
            let n = 1usize << logn;
            let a: Vec<u32> = (0..n).map(|_| r.modq()).collect();
            let b: Vec<u32> = (0..n).map(|_| r.modq()).collect();
            let mut t = a.clone();
            ntt(&mut t);
            intt(&mut t);
            assert_eq!(t, a, "Roundtrip logn = {logn}");
            assert_eq!(poly_mul(&a, &b), schoolbook(&a, &b), "Mul logn = {logn}");
        }
    }

    #[test]
    fn ntt_of_x_has_no_zero_and_zero_is_detected() {
        let mut x = vec![0u32; 8];
        x[1] = 1;
        ntt(&mut x);
        assert_eq!(any_zero_mask(&x), 0);
        // Polynom mit genau einer Nullstelle: im NTT-Bereich eine 0 setzen.
        let mut y: Vec<u32> = (1..=8).collect();
        y[5] = 0;
        intt(&mut y);
        ntt(&mut y);
        assert_eq!(any_zero_mask(&y), u32::MAX);
    }
}
