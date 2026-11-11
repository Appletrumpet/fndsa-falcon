//! Emulierte Gleitkommazahlen (PLAN.md, 3.3, L3).
//!
//! `Fpr` hält die Bits einer IEEE-754-Zahl doppelter Genauigkeit. Alle
//! Rechnungen laufen nur mit Ganzzahloperationen und ohne Verzweigung auf den
//! Werten; die Hardware-Gleitkommaeinheit wird nicht benutzt. Grund: Division
//! und Wurzel haben auf vielen CPUs eine Laufzeit, die vom Wert abhängt, und
//! subnormale Zahlen sind oft viel langsamer.
//!
//! Jede Operation rundet korrekt nach IEEE-754 (zur nächsten Zahl, bei
//! Gleichstand zur geraden). Für normale Zahlen ist das Ergebnis deshalb
//! bitgleich mit Hardware-`f64`, auch das Vorzeichen von Nullen. So rechnet
//! Rust bitgleich mit Python und C (Testvektoren in `Python/data/vectors`).
//!
//! **Zahlenbereich:** Wie die Referenz kennt `Fpr` keine subnormalen Zahlen,
//! kein ±∞ und kein NaN. Ein Ergebnis im subnormalen Bereich wird zu ±0, ein
//! subnormaler Eingabewert gilt als ±0. Massgeblich ist der Wert **vor** dem
//! Runden, wie in der Referenz (`FPR()` in `fpr.h`): Ein Ergebnis knapp unter
//! 2⁻¹⁰²², das IEEE auf 2⁻¹⁰²² aufrunden würde, wird ebenfalls ±0 (gefunden
//! mit dem Fuzz-Ziel `fpr`). Überlauf wird nicht behandelt. In Falcon kommen
//! diese Fälle nicht vor.
//!
//! **Feature `native-fpu`** (PLAN.md 3.3, Phase 8): Addition, Subtraktion,
//! Multiplikation und Wurzel laufen dann über die Gleitkommaeinheit der
//! Hardware (gleiche Ergebnisse für normale Zahlen), Division und Runden
//! bleiben emuliert. Nur für Messungen und für Ziele, auf denen diese
//! Befehle nachweislich konstante Laufzeit haben (x86-64 mit SSE2 für
//! normale Zahlen; aarch64 nur mit DIT). Standard bleibt die Emulation.
//!
//! Darstellung beim Rechnen: Mantisse `m` als Ganzzahl und Exponent `e`, Wert
//! = m · 2^e. Vor dem Runden liegt `m` in [2⁵⁴, 2⁵⁵): 53 Bits Mantisse, ein
//! Rundungsbit und ein „Sticky“-Bit (ODER aller weggefallenen Bits).
//!
//! Schiebungen mit geheimer Weite laufen über `ct::shr64`/`ct::shl64`
//! (sechs feste Schritte mit Masken), nicht über Schiebebefehle mit
//! variabler Weite (Befund der Valgrind-Prüfung, Phase 6).
//!
//! Referenz: fpr.h / fpr.c (Technik: Mantisse mit drei Zusatzbits,
//! Normalisierung in festen Schritten, Division und Wurzel Bit für Bit).

use core::ops::{Add, Div, Mul, Neg, Sub};

use crate::ct::{
    cond_neg64, mask64_from_bit, mask64_from_msb, mask64_lt, mask64_nonzero, select64, shl64, shr64,
};

const SIGN: u64 = 1 << 63;
const FRAC: u64 = (1 << 52) - 1;

/// IEEE-754-Zahl doppelter Genauigkeit, emuliert. Kein `Debug`: die Werte
/// sind beim Signieren geheim (PLAN.md, 3.2 Regel 8). `Default` ist +0;
/// damit lässt sich `Fpr` löschen (`zeroize`).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Fpr(u64);

impl zeroize::DefaultIsZeroes for Fpr {}

impl Fpr {
    pub const ZERO: Fpr = Fpr(0);
    pub const ONE: Fpr = Fpr(0x3FF0_0000_0000_0000);
    pub const TWO: Fpr = Fpr(0x4000_0000_0000_0000);

    /// Aus den IEEE-754-Bits.
    pub const fn from_bits(bits: u64) -> Fpr {
        Fpr(bits)
    }

    /// Die IEEE-754-Bits.
    pub const fn to_bits(self) -> u64 {
        self.0
    }

    /// Ganzzahl → Fpr, korrekt gerundet.
    pub fn of_i64(i: i64) -> Fpr {
        Fpr::scaled(i, 0)
    }

    /// i · 2^sc, korrekt gerundet.
    pub fn scaled(i: i64, sc: i32) -> Fpr {
        let s = (i as u64) >> 63;
        // Betrag ohne Verzweigung; i64::MIN ergibt 2⁶³ als u64.
        let m = cond_neg64(i as u64, s);
        let (m, e) = norm64(m, sc);
        let (m, e) = shrink(m, e);
        make(s, e, m)
    }

    /// Betrag (Vorzeichenbit löschen).
    pub fn abs(self) -> Fpr {
        Fpr(self.0 & !SIGN)
    }

    /// x/2, exakt (Exponent − 1). ±0 bleibt ±0.
    pub fn half(self) -> Fpr {
        // Exponent 0 heisst ±0; dann nur das Vorzeichen behalten.
        let e = (self.0 >> 52) & 0x7FF;
        let nz = mask64_nonzero(e);
        Fpr(select64(nz, self.0 & SIGN, self.0.wrapping_sub(1 << 52)))
    }

    /// 2x, exakt (Exponent + 1). ±0 bleibt ±0.
    pub fn double(self) -> Fpr {
        let e = (self.0 >> 52) & 0x7FF;
        let nz = mask64_nonzero(e);
        Fpr(select64(nz, self.0 & SIGN, self.0.wrapping_add(1 << 52)))
    }

    /// x², korrekt gerundet.
    pub fn sqr(self) -> Fpr {
        self * self
    }

    /// 1/x, korrekt gerundet; x ≠ 0.
    pub fn inv(self) -> Fpr {
        Fpr::ONE / self
    }

    /// √x, korrekt gerundet; x ≥ 0 (√−0 = −0 wie IEEE-754).
    #[inline]
    pub fn sqrt(self) -> Fpr {
        #[cfg(feature = "native-fpu")]
        {
            Fpr(f64::from_bits(self.0).sqrt().to_bits())
        }
        #[cfg(not(feature = "native-fpu"))]
        {
            self.sqrt_emu()
        }
    }

    /// √x, emuliert (Bit für Bit, 54 Runden).
    #[cfg_attr(feature = "native-fpu", allow(dead_code))] // mit native-fpu nur in Tests
    pub(crate) fn sqrt_emu(self) -> Fpr {
        let (s, ex, m) = unpack(self.0);
        // Wert = m · 2^e; e gerade machen, damit sich die Wurzel teilen lässt.
        let mut e = ex - 1075;
        let odd = (e & 1) as u64;
        let m = select64(mask64_from_bit(odd), m, m << 1);
        e -= odd as i32;

        // q = ⌊√(m · 2⁵⁴)⌋ Bit für Bit, 54 Runden; m · 2⁵⁴ < 2¹⁰⁸.
        let mut rem = (m as u128) << 54;
        let mut q: u128 = 0;
        for i in (0..54u32).rev() {
            // (q + 2^i)² − q² = q · 2^(i+1) + 2^(2i)
            let t = (q << (i + 1)) + (1u128 << (2 * i));
            let ge = !mask128_lt(rem, t);
            rem -= t & ge;
            q |= (1u128 << i) & ge;
        }
        let sticky = mask64_nonzero((rem as u64) | ((rem >> 64) as u64)) & 1;
        // q in [2⁵³, 2⁵⁴): 53 Bits + Rundungsbit, dazu Sticky.
        let m = ((q as u64) << 1) | sticky;
        make(s, (e >> 1) - 28, m)
    }

    /// Runden zur nächsten Ganzzahl, bei Gleichstand zur geraden; |x| < 2⁶³.
    pub fn rint(self) -> i64 {
        let p = int_parts(self.0);
        // aufrunden, wenn Rest > ½ oder Rest = ½ und Ganzzahl ungerade
        let gt = mask64_lt(p.half, p.frac);
        let eq = !mask64_nonzero(p.frac ^ p.half);
        let up = (gt | (eq & mask64_from_bit(p.int))) & 1;
        apply_sign(p.s, p.int + up)
    }

    /// Abrunden (⌊x⌋); |x| < 2⁶³.
    pub fn floor(self) -> i64 {
        let p = int_parts(self.0);
        // bei negativem x mit Rest eine Stufe weiter weg von 0
        let up = mask64_nonzero(p.frac) & mask64_from_bit(p.s) & 1;
        apply_sign(p.s, p.int + up)
    }

    /// Abschneiden (Richtung 0); |x| < 2⁶³.
    #[allow(dead_code)] // nur in Tests benutzt
    pub fn trunc(self) -> i64 {
        let p = int_parts(self.0);
        apply_sign(p.s, p.int)
    }

    /// x < y als Maske (alle Bits gesetzt, wenn wahr). −0 und +0 gelten als
    /// gleich.
    pub fn lt_mask(self, y: Fpr) -> u64 {
        // In eine Ganzzahl umsetzen, deren Ordnung der Zahlenordnung
        // entspricht: positive Zahlen bekommen das oberste Bit, negative
        // werden komplett invertiert.
        let key = |x: u64| x ^ (mask64_from_msb(x) | SIGN);
        let both_zero = !mask64_nonzero((self.0 | y.0) & !SIGN);
        mask64_lt(key(self.0), key(y.0)) & !both_zero
    }

    /// Auswahl ohne Verzweigung: `b`, wenn `mask` wahr ist, sonst `a`.
    pub fn select(mask: u64, a: Fpr, b: Fpr) -> Fpr {
        Fpr(select64(mask, a.0, b.0))
    }

    #[cfg(test)]
    pub fn from_f64(x: f64) -> Fpr {
        Fpr(x.to_bits())
    }

    #[cfg(test)]
    pub fn to_f64(self) -> f64 {
        f64::from_bits(self.0)
    }
}

impl Neg for Fpr {
    type Output = Fpr;
    fn neg(self) -> Fpr {
        Fpr(self.0 ^ SIGN)
    }
}

impl Add for Fpr {
    type Output = Fpr;

    #[inline]
    fn add(self, y: Fpr) -> Fpr {
        #[cfg(feature = "native-fpu")]
        {
            Fpr((f64::from_bits(self.0) + f64::from_bits(y.0)).to_bits())
        }
        #[cfg(not(feature = "native-fpu"))]
        {
            self.add_emu(y)
        }
    }
}

impl Fpr {
    /// x + y, emuliert.
    #[cfg_attr(feature = "native-fpu", allow(dead_code))] // mit native-fpu nur in Tests
    pub(crate) fn add_emu(self, y: Fpr) -> Fpr {
        // x soll den grösseren Betrag haben.
        let (x, y) = (self.0, y.0);
        let sw = mask64_lt(x & !SIGN, y & !SIGN);
        let (x, y) = (select64(sw, x, y), select64(sw, y, x));

        let (sx, ex, mx) = unpack(x);
        let (sy, ey, my) = unpack(y);
        // drei Zusatzbits für Runden und Sticky
        let mx = mx << 3;
        let mut my = my << 3;

        // y auf den Exponenten von x schieben. Bei 60 oder mehr Stellen ist y
        // so klein, dass es das gerundete Ergebnis nicht ändert.
        let d = (ex - ey) as u64;
        my &= mask64_from_msb(d.wrapping_sub(60));
        let d = d & 63;
        let lost = my & shl64(1, d).wrapping_sub(1);
        my = shr64(my, d) | (mask64_nonzero(lost) & 1);

        // bei verschiedenen Vorzeichen subtrahieren
        let sd = sx ^ sy;
        let m = mx.wrapping_add(cond_neg64(my, sd));

        let (m, e) = norm64(m, ex - 1078);
        let (m, e) = shrink(m, e);
        // exakt 0: +0, ausser (−0) + (−0) = −0
        let s = select64(mask64_nonzero(m), sx & sy, sx);
        make(s, e, m)
    }
}

impl Sub for Fpr {
    type Output = Fpr;
    fn sub(self, y: Fpr) -> Fpr {
        self + (-y)
    }
}

impl Mul for Fpr {
    type Output = Fpr;

    #[inline]
    fn mul(self, y: Fpr) -> Fpr {
        #[cfg(feature = "native-fpu")]
        {
            Fpr((f64::from_bits(self.0) * f64::from_bits(y.0)).to_bits())
        }
        #[cfg(not(feature = "native-fpu"))]
        {
            self.mul_emu(y)
        }
    }
}

impl Fpr {
    /// x · y, emuliert.
    #[cfg_attr(feature = "native-fpu", allow(dead_code))] // mit native-fpu nur in Tests
    pub(crate) fn mul_emu(self, y: Fpr) -> Fpr {
        let s = (self.0 ^ y.0) >> 63;
        let (_, ex, mx) = unpack(self.0);
        let (_, ey, my) = unpack(y.0);
        // Produkt in [2¹⁰⁴, 2¹⁰⁶) oder 0
        let p = (mx as u128) * (my as u128);
        let top = ((p >> 105) as u64) & 1;
        // um 50 oder 51 Stellen schieben (feste Schiebung, dann Auswahl)
        let q = (p >> 50) as u64;
        let lost50 = (p as u64) & ((1u64 << 50) - 1);
        let sticky = (mask64_nonzero(lost50) | (mask64_from_bit(top) & mask64_from_bit(q))) & 1;
        let m = select64(mask64_from_bit(top), q, q >> 1) | sticky;
        // (mx · 2^(ex−1075)) · (my · 2^(ey−1075)) = m · 2^(ex+ey−2150+sh)
        make(s, ex + ey - 2100 + top as i32, m)
    }
}

impl Div for Fpr {
    type Output = Fpr;

    /// Korrekt gerundet; der Divisor darf nicht 0 sein.
    fn div(self, y: Fpr) -> Fpr {
        let s = (self.0 ^ y.0) >> 63;
        let (_, ex, mx) = unpack(self.0);
        let (_, ey, my) = unpack(y.0);
        // 56 Quotientenbits, Bit für Bit; r bleibt < 2·my < 2⁵⁴.
        let mut r = mx;
        let mut q = 0u64;
        for i in 0..56u32 {
            let ge = !mask64_lt(r, my);
            r = r.wrapping_sub(my & ge);
            q |= (ge & 1) << (55 - i);
            r <<= 1;
        }
        let sticky = mask64_nonzero(r) & 1;
        // q in [2⁵⁴, 2⁵⁶); bei q ≥ 2⁵⁵ ein Bit nach rechts (ins Sticky).
        let top = (q >> 55) & 1;
        let m = select64(mask64_from_bit(top), q, (q >> 1) | (q & 1)) | sticky;
        make(s, ex - ey - 55 + top as i32, m)
    }
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

/// Vorzeichen, Exponentenfeld und Mantisse mit führender 1 (0 für ±0).
#[inline(always)]
fn unpack(x: u64) -> (u64, i32, u64) {
    let e = ((x >> 52) & 0x7FF) as i32;
    let m = ((x & FRAC) | (1 << 52)) & mask64_nonzero(e as u64);
    (x >> 63, e, m)
}

/// Schiebt m nach links, bis Bit 63 gesetzt ist, in sechs festen Schritten.
/// Gibt (m, e − Schiebeweite) zurück; m = 0 bleibt 0.
#[inline(always)]
fn norm64(mut m: u64, mut e: i32) -> (u64, i32) {
    for k in [32u32, 16, 8, 4, 2, 1] {
        // alle Bits gesetzt, wenn die oberen k Bits 0 sind
        let z = !mask64_nonzero(m >> (64 - k));
        m = select64(z, m, m << k);
        e -= (k as u64 & z) as i32;
    }
    (m, e)
}

/// Normalisierte 64-Bit-Mantisse (Bit 63 gesetzt) auf 55 Bits kürzen; die
/// weggefallenen 9 Bits gehen ins Sticky-Bit.
#[inline(always)]
fn shrink(m: u64, e: i32) -> (u64, i32) {
    (((m >> 9) | ((m & 0x1FF) + 0x1FF) >> 9), e + 9)
}

/// Baut das Ergebnis aus Vorzeichen s, Exponent e und Mantisse m (0 oder in
/// [2⁵⁴, 2⁵⁵), mit Rundungs- und Sticky-Bit) und rundet.
#[inline(always)]
fn make(s: u64, e: i32, m: u64) -> Fpr {
    // Aufrunden je nach den drei untersten Bits (letztes Mantissenbit,
    // Rundungsbit, Sticky): bei 011, 110 und 111, also 0xC8 als Bitmaske.
    // Bitweise statt mit einer Schiebe-Tabelle: aufrunden, wenn das
    // Rundungsbit gesetzt ist und Sticky oder letztes Mantissenbit auch.
    let cc = (m >> 1) & (m | (m >> 2)) & 1;
    // Wert = (m/4) · 2^(e+2); die führende 1 von m/4 erhöht das
    // Exponentenfeld um 1, deshalb e + 1076 statt e + 1077.
    let ee = (e + 1076) as i64 as u64;
    // 0, wenn m = 0 oder der Exponent zu klein ist (subnormal → 0).
    let keep = mask64_nonzero(m >> 54) & !mask64_from_msb(ee);
    let body = (ee << 52).wrapping_add(m >> 2).wrapping_add(cc);
    Fpr((s << 63) | (body & keep))
}

/// Maske „a < b“ für u128 (beide < 2¹²⁷).
#[cfg_attr(feature = "native-fpu", allow(dead_code))] // mit native-fpu nur in Tests
#[inline(always)]
fn mask128_lt(a: u128, b: u128) -> u128 {
    let borrow = (a.wrapping_sub(b) >> 127) as u64;
    let m = mask64_nonzero(borrow) as u128;
    m | (m << 64)
}

/// Ganzzahl- und Nachkommateil von |x|, für rint, floor und trunc.
struct IntParts {
    s: u64,
    int: u64,
    frac: u64,
    /// Wert von ½ in der Einheit von `frac`
    half: u64,
}

#[inline(always)]
fn int_parts(x: u64) -> IntParts {
    let (s, ex, m) = unpack(x);
    // |x| = m · 2^e
    let e = ex - 1075;
    // e ≥ 0: ganzzahlig, m · 2^e (|x| < 2⁶³ vorausgesetzt).
    let int_big = shl64(m, (e as u64) & 63);
    // e < 0: um sh = −e Stellen nach rechts; ab 63 Stellen ist alles Rest
    // (m < 2⁵³, also auch mit sh = 63 richtig).
    let t = (-e) as i64 as u64;
    let sh = select64(mask64_lt(63, t), t, 63) & 63;
    let low = shl64(1, sh).wrapping_sub(1);
    let small = mask64_from_msb(e as i64 as u64);
    IntParts {
        s,
        int: select64(small, int_big, shr64(m, sh)),
        frac: m & low & small,
        // bei ganzzahligem x ein Wert, den frac (= 0) nie erreicht
        half: select64(small, u64::MAX, shl64(1, sh.wrapping_sub(1) & 63)),
    }
}

/// s = 1: −v, sonst v.
#[inline(always)]
fn apply_sign(s: u64, v: u64) -> i64 {
    cond_neg64(v, s) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64, reproduzierbar
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        /// Zufällige normale Zahl mit Exponent in [−lim, lim].
        fn normal(&mut self, lim: i64) -> f64 {
            let r = self.next();
            let e = (r % (2 * lim as u64 + 1)) as i64 - lim + 1023;
            let frac = self.next() & FRAC;
            // manchmal Mantissen mit vielen Nullen oder Einsen (Rundungsfälle)
            let frac = match r >> 60 {
                0 => frac & !0xFFFF,
                1 => frac | 0xFFFF,
                2 => 0,
                _ => frac,
            };
            f64::from_bits(((r >> 63) << 63) | ((e as u64) << 52) | frac)
        }
    }

    fn is_normal_or_zero(x: f64) -> bool {
        x == 0.0 || x.is_normal()
    }

    /// Vergleicht bitgenau; Ergebnisse ausserhalb des normalen Bereichs
    /// werden übersprungen (kein Teil des Zahlenbereichs von Fpr).
    fn check(op: &str, a: f64, b: f64, got: Fpr, want: f64) {
        if is_normal_or_zero(want) {
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "{op}({a:e}, {b:e}): {:e} statt {want:e}",
                got.to_f64()
            );
        }
    }

    const N: usize = 300_000;

    #[test]
    fn add_sub_match_f64() {
        let mut r = Rng(1);
        for i in 0..N {
            let a = r.normal(60);
            // nahe Exponenten, damit Auslöschung und Rundung oft vorkommen
            let b = if i % 2 == 0 {
                r.normal(60)
            } else {
                a * (1.0 + r.normal(3) * 1e-3)
            };
            let (fa, fb) = (Fpr::from_f64(a), Fpr::from_f64(b));
            check("add", a, b, fa + fb, a + b);
            check("sub", a, b, fa - fb, a - b);
        }
    }

    #[test]
    fn mul_div_match_f64() {
        let mut r = Rng(2);
        for _ in 0..N {
            let (a, b) = (r.normal(200), r.normal(200));
            let (fa, fb) = (Fpr::from_f64(a), Fpr::from_f64(b));
            check("mul", a, b, fa * fb, a * b);
            check("div", a, b, fa / fb, a / b);
        }
    }

    #[test]
    fn sqrt_matches_f64() {
        let mut r = Rng(3);
        for _ in 0..N {
            let a = r.normal(300).abs();
            check("sqrt", a, 0.0, Fpr::from_f64(a).sqrt(), a.sqrt());
        }
        for a in [0.0, -0.0, 1.0, 2.0, 4.0, 0.25, 1e-300, 1e300] {
            check("sqrt", a, 0.0, Fpr::from_f64(a).sqrt(), a.sqrt());
        }
    }

    #[test]
    fn of_i64_matches_f64() {
        let mut r = Rng(4);
        for i in 0..N {
            // verschiedene Grössenordnungen bis 2⁶³
            let v = (r.next() >> (i % 64)) as i64;
            let v = if i % 3 == 0 { v.wrapping_neg() } else { v };
            check("of_i64", v as f64, 0.0, Fpr::of_i64(v), v as f64);
        }
        for v in [0, 1, -1, i64::MAX, i64::MIN, (1 << 53) + 1, -(1 << 53) - 1] {
            check("of_i64", v as f64, 0.0, Fpr::of_i64(v), v as f64);
        }
        assert_eq!(Fpr::scaled(3, -1).to_f64(), 1.5);
        assert_eq!(Fpr::scaled(-5, 10).to_f64(), -5120.0);
    }

    #[test]
    fn rounding_to_integers() {
        let mut r = Rng(5);
        for i in 0..N {
            // |x| bis etwa 2⁶⁰, mit vielen Werten um ganze und halbe Zahlen
            let x = match i % 3 {
                0 => r.normal(60),
                1 => (r.next() % 2000) as f64 / 2.0 - 500.0,
                _ => r.normal(4),
            };
            let f = Fpr::from_f64(x);
            assert_eq!(f.rint(), x.round_ties_even() as i64, "rint({x:e})");
            assert_eq!(f.floor(), x.floor() as i64, "floor({x:e})");
            assert_eq!(f.trunc(), x.trunc() as i64, "trunc({x:e})");
        }
        for x in [
            0.0,
            -0.0,
            0.5,
            -0.5,
            1.5,
            2.5,
            -2.5,
            0.49999999999999994,
            1e-300,
        ] {
            let f = Fpr::from_f64(x);
            assert_eq!(f.rint(), x.round_ties_even() as i64, "rint({x:e})");
            assert_eq!(f.floor(), x.floor() as i64, "floor({x:e})");
        }
    }

    #[test]
    fn signed_zeros() {
        let (p, n) = (Fpr::ZERO, -Fpr::ZERO);
        let one = Fpr::ONE;
        assert_eq!((p + n).to_bits(), (0.0f64 + -0.0).to_bits());
        assert_eq!((n + n).to_bits(), (-0.0f64 + -0.0).to_bits());
        assert_eq!((one - one).to_bits(), 0.0f64.to_bits());
        assert_eq!((n * one).to_bits(), (-0.0f64).to_bits());
        assert_eq!((p * -one).to_bits(), (-0.0f64).to_bits());
        assert_eq!((n / one).to_bits(), (-0.0f64).to_bits());
        assert_eq!(n.half().to_bits(), (-0.0f64).to_bits());
        assert_eq!(p.double().to_bits(), 0.0f64.to_bits());
        assert_eq!(Fpr::of_i64(0).to_bits(), 0);
    }

    #[test]
    fn half_double_inv_sqr() {
        let mut r = Rng(6);
        for _ in 0..10_000 {
            let a = r.normal(300);
            let f = Fpr::from_f64(a);
            assert_eq!(f.half().to_f64(), a / 2.0);
            assert_eq!(f.double().to_f64(), a * 2.0);
            check("inv", a, 0.0, f.inv(), 1.0 / a);
            check("sqr", a, 0.0, f.sqr(), a * a);
        }
    }

    #[test]
    fn comparison() {
        let mut r = Rng(7);
        for _ in 0..N {
            let (a, b) = (r.normal(10), r.normal(10));
            let m = Fpr::from_f64(a).lt_mask(Fpr::from_f64(b));
            assert_eq!(m, if a < b { u64::MAX } else { 0 }, "{a} < {b}");
        }
        let (p, n) = (Fpr::ZERO, -Fpr::ZERO);
        assert_eq!(p.lt_mask(n), 0);
        assert_eq!(n.lt_mask(p), 0);
        assert_eq!(n.lt_mask(Fpr::ONE), u64::MAX);
        assert_eq!((-Fpr::ONE).lt_mask(n), u64::MAX);
    }

    /// Die emulierten Fassungen auch dann prüfen, wenn die Operatoren über
    /// die Hardware laufen (Feature `native-fpu`).
    #[test]
    fn emulated_ops_match_f64() {
        let mut r = Rng(8);
        for _ in 0..100_000 {
            let (a, b) = (r.normal(200), r.normal(200));
            let (fa, fb) = (Fpr::from_f64(a), Fpr::from_f64(b));
            check("add_emu", a, b, fa.add_emu(fb), a + b);
            check("mul_emu", a, b, fa.mul_emu(fb), a * b);
            check("sqrt_emu", a, 0.0, fa.abs().sqrt_emu(), a.abs().sqrt());
        }
    }

    // Unterlauf ergibt in der Emulation ±0; die Hardware liefert subnormale
    // Zahlen (in Falcon kommen sie nicht vor).
    #[cfg(not(feature = "native-fpu"))]
    #[test]
    fn underflow_gives_zero() {
        let tiny = Fpr::from_f64(1e-200);
        assert_eq!((tiny * tiny).to_bits(), 0);
        assert_eq!((-tiny * tiny).to_bits(), SIGN);
        assert_eq!((tiny / Fpr::from_f64(1e200)).to_bits(), 0);
        // subnormale Eingabe gilt als 0
        assert_eq!((Fpr::from_bits(1) + Fpr::ONE).to_bits(), Fpr::ONE.to_bits());
        // Grenzfall aus dem Fuzzing: Das genaue Produkt liegt knapp unter
        // 2⁻¹⁰²²; IEEE rundet auf 2⁻¹⁰²² auf, Fpr (wie die Referenz) gibt −0.
        let (a, b) = (2.999393627791262e-241, -7.418412301374842e-68);
        assert_eq!(a * b, -f64::MIN_POSITIVE);
        assert_eq!((Fpr::from_f64(a) * Fpr::from_f64(b)).to_bits(), SIGN);
    }
}
