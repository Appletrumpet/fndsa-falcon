//! Ganzzahlen fester Länge und Rechnen modulo kleiner Primzahlen, für
//! NTRUSolve (PLAN.md 3.5, L4).
//!
//! **Portierung der Referenz** (`keygen.c`, Abschnitte „Modular
//! arithmetics“ und „Custom bignum implementation“, PQClean). Grosse Zahlen
//! sind Felder von 31-Bit-Wörtern (Zweierkomplement) oder liegen im RNS
//! (Reste modulo vieler Primzahlen knapp unter 2³¹, Tabelle `PRIMES`).
//!
//! Wie in der Referenz arbeiten alle Funktionen auf einem gemeinsamen
//! Arbeitspuffer `m: &mut [u32]`; wo die Referenz Zeiger übergibt, stehen
//! hier Indizes in diesen Puffer. Gleitkommazahlen liegen als zwei Wörter
//! darin (`fget`, `fset`), so dass die Speicherbelegung genau der Referenz
//! entspricht. Konstante Laufzeit wie in der Referenz: Schleifen hängen nur
//! von den (öffentlichen) Längen ab, Auswahl über Masken.

// Schleifen mit Index wie in der Referenz, damit der Code Zeile für Zeile
// vergleichbar bleibt.
#![allow(clippy::needless_range_loop)]

use crate::fpr::Fpr;
use crate::keygen_tables::PRIMES;

// ---------------------------------------------------------------------------
// Gleitkommazahlen im Arbeitspuffer
// ---------------------------------------------------------------------------

/// Gleitkommazahl an Stelle `off` (zwei Wörter, niedriges zuerst).
#[inline(always)]
pub(crate) fn fget(m: &[u32], off: usize) -> Fpr {
    Fpr::from_bits(m[off] as u64 | (m[off + 1] as u64) << 32)
}

#[inline(always)]
pub(crate) fn fset(m: &mut [u32], off: usize, v: Fpr) {
    let b = v.to_bits();
    m[off] = b as u32;
    m[off + 1] = (b >> 32) as u32;
}

/// Index aufrunden, so dass dort eine Gleitkommazahl beginnen kann.
/// Referenz: keygen.c, align_fpr (in Einheiten von u32).
#[inline(always)]
pub(crate) fn align_fpr(off: usize) -> usize {
    (off + 1) & !1
}

// ---------------------------------------------------------------------------
// Rechnen modulo p (2³⁰ < p < 2³¹), Montgomery mit R = 2³¹
// ---------------------------------------------------------------------------

/// Referenz: keygen.c, modp_set (−p < x < p).
#[inline(always)]
pub(crate) fn modp_set(x: i32, p: u32) -> u32 {
    let w = x as u32;
    w.wrapping_add(p & 0u32.wrapping_sub(w >> 31))
}

/// Referenz: keygen.c, modp_norm.
#[inline(always)]
pub(crate) fn modp_norm(x: u32, p: u32) -> i32 {
    let t = (x.wrapping_sub((p + 1) >> 1) >> 31).wrapping_sub(1);
    x.wrapping_sub(p & t) as i32
}

/// −1/p mod 2³¹. Referenz: keygen.c, modp_ninv31.
pub(crate) fn modp_ninv31(p: u32) -> u32 {
    let mut y = 2u32.wrapping_sub(p);
    for _ in 0..4 {
        y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    }
    0x7FFF_FFFF & 0u32.wrapping_sub(y)
}

/// 2³¹ mod p. Referenz: keygen.c, modp_R.
#[inline(always)]
pub(crate) fn modp_r(p: u32) -> u32 {
    (1u32 << 31) - p
}

/// Referenz: keygen.c, modp_add.
#[inline(always)]
pub(crate) fn modp_add(a: u32, b: u32, p: u32) -> u32 {
    let d = a.wrapping_add(b).wrapping_sub(p);
    d.wrapping_add(p & 0u32.wrapping_sub(d >> 31))
}

/// Referenz: keygen.c, modp_sub.
#[inline(always)]
pub(crate) fn modp_sub(a: u32, b: u32, p: u32) -> u32 {
    let d = a.wrapping_sub(b);
    d.wrapping_add(p & 0u32.wrapping_sub(d >> 31))
}

/// Montgomery-Multiplikation (a·b/2³¹ mod p). Referenz: keygen.c,
/// modp_montymul.
#[inline(always)]
pub(crate) fn modp_montymul(a: u32, b: u32, p: u32, p0i: u32) -> u32 {
    let z = a as u64 * b as u64;
    let w = ((z.wrapping_mul(p0i as u64)) & 0x7FFF_FFFF) * p as u64;
    let d = (((z + w) >> 31) as u32).wrapping_sub(p);
    d.wrapping_add(p & 0u32.wrapping_sub(d >> 31))
}

/// 2⁶² mod p. Referenz: keygen.c, modp_R2.
pub(crate) fn modp_r2(p: u32, p0i: u32) -> u32 {
    let mut z = modp_r(p);
    z = modp_add(z, z, p);
    for _ in 0..5 {
        z = modp_montymul(z, z, p, p0i);
    }
    (z + (p & 0u32.wrapping_sub(z & 1))) >> 1
}

/// 2^(31·x) mod p. Referenz: keygen.c, modp_Rx (x öffentlich).
pub(crate) fn modp_rx(x: u32, p: u32, p0i: u32, r2: u32) -> u32 {
    let x = x - 1;
    let mut r = r2;
    let mut z = modp_r(p);
    let mut i = 0;
    while (1u32 << i) <= x {
        if (x & (1u32 << i)) != 0 {
            z = modp_montymul(z, r, p, p0i);
        }
        r = modp_montymul(r, r, p, p0i);
        i += 1;
    }
    z
}

/// a/b mod p (0, wenn b = 0). Referenz: keygen.c, modp_div.
pub(crate) fn modp_div(a: u32, b: u32, p: u32, p0i: u32, r: u32) -> u32 {
    let e = p - 2;
    let mut z = r;
    for i in (0..=30).rev() {
        z = modp_montymul(z, z, p, p0i);
        let z2 = modp_montymul(z, b, p, p0i);
        z ^= (z ^ z2) & 0u32.wrapping_sub((e >> i) & 1);
    }
    z = modp_montymul(z, 1, p, p0i);
    modp_montymul(a, z, p, p0i)
}

/// Bit-Umkehr über 10 Bit. Referenz: keygen.c, REV10.
#[inline(always)]
fn rev10(x: usize) -> usize {
    (x as u32).reverse_bits() as usize >> 22
}

/// Wurzeln für NTT und inverse NTT (Montgomery), gm[rev(i)] = g^i,
/// igm[rev(i)] = g^−i. Referenz: keygen.c, modp_mkgm2.
pub(crate) fn modp_mkgm2(
    m: &mut [u32],
    gm: usize,
    igm: usize,
    logn: u32,
    g: u32,
    p: u32,
    p0i: u32,
) {
    let n = 1usize << logn;
    let r2 = modp_r2(p, p0i);
    let mut g = modp_montymul(g, r2, p, p0i);
    for _ in logn..10 {
        g = modp_montymul(g, g, p, p0i);
    }
    let ig = modp_div(r2, g, p, p0i, modp_r(p));
    let k = 10 - logn;
    let (mut x1, mut x2) = (modp_r(p), modp_r(p));
    for u in 0..n {
        let v = rev10(u << k);
        m[gm + v] = x1;
        m[igm + v] = x2;
        x1 = modp_montymul(x1, g, p, p0i);
        x2 = modp_montymul(x2, ig, p, p0i);
    }
}

/// NTT, Elemente a[0], a[stride], … Referenz: keygen.c, modp_NTT2_ext.
pub(crate) fn modp_ntt2_ext(
    m: &mut [u32],
    a: usize,
    stride: usize,
    gm: usize,
    logn: u32,
    p: u32,
    p0i: u32,
) {
    if logn == 0 {
        return;
    }
    let n = 1usize << logn;
    let mut t = n;
    let mut mm = 1;
    while mm < n {
        let ht = t >> 1;
        let mut v1 = 0;
        for u in 0..mm {
            let s = m[gm + mm + u];
            let mut r1 = a + v1 * stride;
            let mut r2 = r1 + ht * stride;
            for _ in 0..ht {
                let x = m[r1];
                let y = modp_montymul(m[r2], s, p, p0i);
                m[r1] = modp_add(x, y, p);
                m[r2] = modp_sub(x, y, p);
                r1 += stride;
                r2 += stride;
            }
            v1 += t;
        }
        t = ht;
        mm <<= 1;
    }
}

/// Inverse NTT. Referenz: keygen.c, modp_iNTT2_ext.
pub(crate) fn modp_intt2_ext(
    m: &mut [u32],
    a: usize,
    stride: usize,
    igm: usize,
    logn: u32,
    p: u32,
    p0i: u32,
) {
    if logn == 0 {
        return;
    }
    let n = 1usize << logn;
    let mut t = 1;
    let mut mm = n;
    while mm > 1 {
        let hm = mm >> 1;
        let dt = t << 1;
        let mut v1 = 0;
        for u in 0..hm {
            let s = m[igm + hm + u];
            let mut r1 = a + v1 * stride;
            let mut r2 = r1 + t * stride;
            for _ in 0..t {
                let x = m[r1];
                let y = m[r2];
                m[r1] = modp_add(x, y, p);
                m[r2] = modp_montymul(modp_sub(x, y, p), s, p, p0i);
                r1 += stride;
                r2 += stride;
            }
            v1 += dt;
        }
        t = dt;
        mm = hm;
    }
    let ni = 1u32 << (31 - logn);
    let mut r = a;
    for _ in 0..n {
        m[r] = modp_montymul(m[r], ni, p, p0i);
        r += stride;
    }
}

#[inline(always)]
pub(crate) fn modp_ntt2(m: &mut [u32], a: usize, gm: usize, logn: u32, p: u32, p0i: u32) {
    modp_ntt2_ext(m, a, 1, gm, logn, p, p0i);
}

#[inline(always)]
pub(crate) fn modp_intt2(m: &mut [u32], a: usize, igm: usize, logn: u32, p: u32, p0i: u32) {
    modp_intt2_ext(m, a, 1, igm, logn, p, p0i);
}

/// f′ = f₀² − X·f₁² in NTT-Form, in place über die ersten N/2 Werte.
/// Referenz: keygen.c, modp_poly_rec_res.
pub(crate) fn modp_poly_rec_res(m: &mut [u32], f: usize, logn: u32, p: u32, p0i: u32, r2: u32) {
    let hn = 1usize << (logn - 1);
    for u in 0..hn {
        let w0 = m[f + (u << 1)];
        let w1 = m[f + (u << 1) + 1];
        m[f + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
    }
}

// ---------------------------------------------------------------------------
// Grosse Zahlen aus 31-Bit-Wörtern
// ---------------------------------------------------------------------------

/// a ← a − b, wenn ctl = 1 (sonst unverändert); gibt den Übertrag zurück.
/// Referenz: keygen.c, zint_sub.
pub(crate) fn zint_sub(m: &mut [u32], a: usize, b: usize, len: usize, ctl: u32) -> u32 {
    let mut cc = 0u32;
    let mk = 0u32.wrapping_sub(ctl);
    for u in 0..len {
        let mut aw = m[a + u];
        let w = aw.wrapping_sub(m[b + u]).wrapping_sub(cc);
        cc = w >> 31;
        aw ^= ((w & 0x7FFF_FFFF) ^ aw) & mk;
        m[a + u] = aw;
    }
    cc
}

/// m ← m·x (x < 2³¹); gibt das Übertragswort zurück.
/// Referenz: keygen.c, zint_mul_small.
pub(crate) fn zint_mul_small(m: &mut [u32], a: usize, len: usize, x: u32) -> u32 {
    let mut cc = 0u32;
    for u in 0..len {
        let z = m[a + u] as u64 * x as u64 + cc as u64;
        m[a + u] = z as u32 & 0x7FFF_FFFF;
        cc = (z >> 31) as u32;
    }
    cc
}

/// d mod p, d ohne Vorzeichen. Referenz: keygen.c, zint_mod_small_unsigned.
pub(crate) fn zint_mod_small_unsigned(
    m: &[u32],
    d: usize,
    dlen: usize,
    p: u32,
    p0i: u32,
    r2: u32,
) -> u32 {
    let mut x = 0u32;
    for u in (0..dlen).rev() {
        x = modp_montymul(x, r2, p, p0i);
        let w = m[d + u].wrapping_sub(p);
        let w = w.wrapping_add(p & 0u32.wrapping_sub(w >> 31));
        x = modp_add(x, w, p);
    }
    x
}

/// d mod p, d mit Vorzeichen; rx = 2^(31·dlen) mod p.
/// Referenz: keygen.c, zint_mod_small_signed.
pub(crate) fn zint_mod_small_signed(
    m: &[u32],
    d: usize,
    dlen: usize,
    p: u32,
    p0i: u32,
    r2: u32,
    rx: u32,
) -> u32 {
    if dlen == 0 {
        return 0;
    }
    let z = zint_mod_small_unsigned(m, d, dlen, p, p0i, r2);
    modp_sub(z, rx & 0u32.wrapping_sub(m[d + dlen - 1] >> 30), p)
}

/// x ← x + y·s (x danach len+1 Wörter). Referenz: keygen.c,
/// zint_add_mul_small.
pub(crate) fn zint_add_mul_small(m: &mut [u32], x: usize, y: usize, len: usize, s: u32) {
    let mut cc = 0u32;
    for u in 0..len {
        let z = m[y + u] as u64 * s as u64 + m[x + u] as u64 + cc as u64;
        m[x + u] = z as u32 & 0x7FFF_FFFF;
        cc = (z >> 31) as u32;
    }
    m[x + len] = cc;
}

/// x ← x − p, wenn x > p/2. Referenz: keygen.c, zint_norm_zero.
pub(crate) fn zint_norm_zero(m: &mut [u32], x: usize, p: usize, len: usize) {
    let mut r = 0u32;
    let mut bb = 0u32;
    for u in (0..len).rev() {
        let wx = m[x + u];
        let wp = (m[p + u] >> 1) | (bb << 30);
        bb = m[p + u] & 1;
        let cc = wp.wrapping_sub(wx);
        let cc = (0u32.wrapping_sub(cc) >> 31) | 0u32.wrapping_sub(cc >> 31);
        r |= cc & (r & 1).wrapping_sub(1);
    }
    zint_sub(m, x, p, len, r >> 31);
}

/// Zahlen aus der RNS-Darstellung zurückgewinnen (CRT); bei
/// `normalize_signed` symmetrisch um 0. Referenz: keygen.c,
/// zint_rebuild_CRT.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zint_rebuild_crt(
    m: &mut [u32],
    xx: usize,
    xlen: usize,
    xstride: usize,
    num: usize,
    normalize_signed: bool,
    tmp: usize,
) {
    m[tmp] = PRIMES[0].0;
    for u in 1..xlen {
        let (p, _, s) = PRIMES[u];
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let mut x = xx;
        for _ in 0..num {
            let xp = m[x + u];
            let xq = zint_mod_small_unsigned(m, x, u, p, p0i, r2);
            let xr = modp_montymul(s, modp_sub(xp, xq, p), p, p0i);
            zint_add_mul_small(m, x, tmp, u, xr);
            x += xstride;
        }
        m[tmp + u] = zint_mul_small(m, tmp, u, p);
    }
    if normalize_signed {
        let mut x = xx;
        for _ in 0..num {
            zint_norm_zero(m, x, tmp, xlen);
            x += xstride;
        }
    }
}

/// a ← −a, wenn ctl = 1. Referenz: keygen.c, zint_negate.
pub(crate) fn zint_negate(m: &mut [u32], a: usize, len: usize, ctl: u32) {
    let mut cc = ctl;
    let mk = 0u32.wrapping_sub(ctl) >> 1;
    for u in 0..len {
        let aw = (m[a + u] ^ mk).wrapping_add(cc);
        m[a + u] = aw & 0x7FFF_FFFF;
        cc = aw >> 31;
    }
}

/// a ← (a·xa + b·xb)/2³¹, b ← (a·ya + b·yb)/2³¹, negativ → negiert.
/// Referenz: keygen.c, zint_co_reduce.
#[allow(clippy::too_many_arguments)]
fn zint_co_reduce(
    m: &mut [u32],
    a: usize,
    b: usize,
    len: usize,
    xa: i64,
    xb: i64,
    ya: i64,
    yb: i64,
) -> u32 {
    let (mut cca, mut ccb) = (0i64, 0i64);
    for u in 0..len {
        let wa = m[a + u] as u64;
        let wb = m[b + u] as u64;
        let za = wa
            .wrapping_mul(xa as u64)
            .wrapping_add(wb.wrapping_mul(xb as u64))
            .wrapping_add(cca as u64);
        let zb = wa
            .wrapping_mul(ya as u64)
            .wrapping_add(wb.wrapping_mul(yb as u64))
            .wrapping_add(ccb as u64);
        if u > 0 {
            m[a + u - 1] = za as u32 & 0x7FFF_FFFF;
            m[b + u - 1] = zb as u32 & 0x7FFF_FFFF;
        }
        cca = (za as i64) >> 31;
        ccb = (zb as i64) >> 31;
    }
    m[a + len - 1] = cca as u32;
    m[b + len - 1] = ccb as u32;
    let nega = ((cca as u64) >> 63) as u32;
    let negb = ((ccb as u64) >> 63) as u32;
    zint_negate(m, a, len, nega);
    zint_negate(m, b, len, negb);
    nega | (negb << 1)
}

/// Modulare Reduktion abschliessen. Referenz: keygen.c, zint_finish_mod.
fn zint_finish_mod(m: &mut [u32], a: usize, len: usize, md: usize, neg: u32) {
    let mut cc = 0u32;
    for u in 0..len {
        cc = m[a + u].wrapping_sub(m[md + u]).wrapping_sub(cc) >> 31;
    }
    let xm = 0u32.wrapping_sub(neg) >> 1;
    let ym = 0u32.wrapping_sub(neg | (1 - cc));
    cc = neg;
    for u in 0..len {
        let mw = (m[md + u] ^ xm) & ym;
        let aw = m[a + u].wrapping_sub(mw).wrapping_sub(cc);
        m[a + u] = aw & 0x7FFF_FFFF;
        cc = aw >> 31;
    }
}

/// a ← (a·xa + b·xb)/2³¹ mod m, b ← (a·ya + b·yb)/2³¹ mod m.
/// Referenz: keygen.c, zint_co_reduce_mod.
#[allow(clippy::too_many_arguments)]
fn zint_co_reduce_mod(
    m: &mut [u32],
    a: usize,
    b: usize,
    md: usize,
    len: usize,
    m0i: u32,
    xa: i64,
    xb: i64,
    ya: i64,
    yb: i64,
) {
    let (mut cca, mut ccb) = (0i64, 0i64);
    let fa = (m[a]
        .wrapping_mul(xa as u32)
        .wrapping_add(m[b].wrapping_mul(xb as u32)))
    .wrapping_mul(m0i)
        & 0x7FFF_FFFF;
    let fb = (m[a]
        .wrapping_mul(ya as u32)
        .wrapping_add(m[b].wrapping_mul(yb as u32)))
    .wrapping_mul(m0i)
        & 0x7FFF_FFFF;
    for u in 0..len {
        let wa = m[a + u] as u64;
        let wb = m[b + u] as u64;
        let mu = m[md + u] as u64;
        let za = wa
            .wrapping_mul(xa as u64)
            .wrapping_add(wb.wrapping_mul(xb as u64))
            .wrapping_add(mu * fa as u64)
            .wrapping_add(cca as u64);
        let zb = wa
            .wrapping_mul(ya as u64)
            .wrapping_add(wb.wrapping_mul(yb as u64))
            .wrapping_add(mu * fb as u64)
            .wrapping_add(ccb as u64);
        if u > 0 {
            m[a + u - 1] = za as u32 & 0x7FFF_FFFF;
            m[b + u - 1] = zb as u32 & 0x7FFF_FFFF;
        }
        cca = (za as i64) >> 31;
        ccb = (zb as i64) >> 31;
    }
    m[a + len - 1] = cca as u32;
    m[b + len - 1] = ccb as u32;
    zint_finish_mod(m, a, len, md, ((cca as u64) >> 63) as u32);
    zint_finish_mod(m, b, len, md, ((ccb as u64) >> 63) as u32);
}

/// Binärer erweiterter GCD mit fester Rundenzahl: bei GCD(x, y) = 1 gilt
/// danach x·u − y·v = 1. tmp braucht Platz für 4·len Wörter.
/// Referenz: keygen.c, zint_bezout.
pub(crate) fn zint_bezout(
    m: &mut [u32],
    u: usize,
    v: usize,
    x: usize,
    y: usize,
    len: usize,
    tmp: usize,
) -> bool {
    if len == 0 {
        return false;
    }
    let (u0, v0) = (u, v);
    let u1 = tmp;
    let v1 = u1 + len;
    let a = v1 + len;
    let b = a + len;

    let x0i = modp_ninv31(m[x]);
    let y0i = modp_ninv31(m[y]);

    m.copy_within(x..x + len, a);
    m.copy_within(y..y + len, b);
    m[u0] = 1;
    m[u0 + 1..u0 + len].fill(0);
    m[v0..v0 + len].fill(0);
    m.copy_within(y..y + len, u1);
    m.copy_within(x..x + len, v1);
    m[v1] = m[v1].wrapping_sub(1);

    let mut num = 62 * len as u32 + 30;
    while num >= 30 {
        // obere Wörter von a und b (zwei Wörter, ohne Verzweigung)
        let (mut c0, mut c1) = (u32::MAX, u32::MAX);
        let (mut a0, mut a1, mut b0, mut b1) = (0u32, 0u32, 0u32, 0u32);
        for j in (0..len).rev() {
            let aw = m[a + j];
            let bw = m[b + j];
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw).wrapping_add(0x7FFF_FFFF)) >> 31).wrapping_sub(1);
        }
        a1 |= a0 & c1;
        a0 &= !c1;
        b1 |= b0 & c1;
        b0 &= !c1;
        let mut a_hi = ((a0 as u64) << 31) + a1 as u64;
        let mut b_hi = ((b0 as u64) << 31) + b1 as u64;
        let mut a_lo = m[a];
        let mut b_lo = m[b];

        let (mut pa, mut pb, mut qa, mut qb) = (1i64, 0i64, 0i64, 1i64);
        for i in 0..31 {
            let rz = b_hi.wrapping_sub(a_hi);
            let rt = ((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63) as u32;
            let oa = (a_lo >> i) & 1;
            let ob = (b_lo >> i) & 1;
            let c_ab = oa & ob & rt;
            let c_ba = oa & ob & !rt;
            let c_a = c_ab | (oa ^ 1);

            a_lo = a_lo.wrapping_sub(b_lo & 0u32.wrapping_sub(c_ab));
            a_hi = a_hi.wrapping_sub(b_hi & 0u64.wrapping_sub(c_ab as u64));
            pa = pa.wrapping_sub(qa & (c_ab as i64).wrapping_neg());
            pb = pb.wrapping_sub(qb & (c_ab as i64).wrapping_neg());
            b_lo = b_lo.wrapping_sub(a_lo & 0u32.wrapping_sub(c_ba));
            b_hi = b_hi.wrapping_sub(a_hi & 0u64.wrapping_sub(c_ba as u64));
            qa = qa.wrapping_sub(pa & (c_ba as i64).wrapping_neg());
            qb = qb.wrapping_sub(pb & (c_ba as i64).wrapping_neg());

            a_lo = a_lo.wrapping_add(a_lo & c_a.wrapping_sub(1));
            pa = pa.wrapping_add(pa & (c_a as i64).wrapping_sub(1));
            pb = pb.wrapping_add(pb & (c_a as i64).wrapping_sub(1));
            a_hi ^= (a_hi ^ (a_hi >> 1)) & 0u64.wrapping_sub(c_a as u64);
            b_lo = b_lo.wrapping_add(b_lo & 0u32.wrapping_sub(c_a));
            qa = qa.wrapping_add(qa & (c_a as i64).wrapping_neg());
            qb = qb.wrapping_add(qb & (c_a as i64).wrapping_neg());
            b_hi ^= (b_hi ^ (b_hi >> 1)) & (c_a as u64).wrapping_sub(1);
        }

        let r = zint_co_reduce(m, a, b, len, pa, pb, qa, qb);
        pa = pa.wrapping_sub(pa.wrapping_add(pa) & ((r & 1) as i64).wrapping_neg());
        pb = pb.wrapping_sub(pb.wrapping_add(pb) & ((r & 1) as i64).wrapping_neg());
        qa = qa.wrapping_sub(qa.wrapping_add(qa) & ((r >> 1) as i64).wrapping_neg());
        qb = qb.wrapping_sub(qb.wrapping_add(qb) & ((r >> 1) as i64).wrapping_neg());
        zint_co_reduce_mod(m, u0, u1, y, len, y0i, pa, pb, qa, qb);
        zint_co_reduce_mod(m, v0, v1, x, len, x0i, pa, pb, qa, qb);
        num -= 30;
    }

    let mut rc = m[a] ^ 1;
    for j in 1..len {
        rc |= m[a + j];
    }
    ((1 - ((rc | rc.wrapping_neg()) >> 31)) & m[x] & m[y]) != 0
}

/// x ← x + k·y·2^sc (sc = 31·sch + scl), mit Vorzeichen, abgeschnitten
/// auf xlen. Referenz: keygen.c, zint_add_scaled_mul_small.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zint_add_scaled_mul_small(
    m: &mut [u32],
    x: usize,
    xlen: usize,
    y: usize,
    ylen: usize,
    k: i32,
    sch: u32,
    scl: u32,
) {
    if ylen == 0 {
        return;
    }
    let ysign = 0u32.wrapping_sub(m[y + ylen - 1] >> 30) >> 1;
    let mut tw = 0u32;
    let mut cc = 0i32;
    for u in sch as usize..xlen {
        let v = u - sch as usize;
        let wy = if v < ylen { m[y + v] } else { ysign };
        let wys = ((wy << scl) & 0x7FFF_FFFF) | tw;
        tw = wy.checked_shr(31 - scl).unwrap_or(0);
        let z = (wys as i64 * k as i64 + m[x + u] as i64 + cc as i64) as u64;
        m[x + u] = z as u32 & 0x7FFF_FFFF;
        cc = ((z >> 31) as u32) as i32;
    }
}

/// x ← x − y·2^sc. Referenz: keygen.c, zint_sub_scaled.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zint_sub_scaled(
    m: &mut [u32],
    x: usize,
    xlen: usize,
    y: usize,
    ylen: usize,
    sch: u32,
    scl: u32,
) {
    if ylen == 0 {
        return;
    }
    let ysign = 0u32.wrapping_sub(m[y + ylen - 1] >> 30) >> 1;
    let mut tw = 0u32;
    let mut cc = 0u32;
    for u in sch as usize..xlen {
        let v = u - sch as usize;
        let wy = if v < ylen { m[y + v] } else { ysign };
        let wys = ((wy << scl) & 0x7FFF_FFFF) | tw;
        tw = wy.checked_shr(31 - scl).unwrap_or(0);
        let w = m[x + u].wrapping_sub(wys).wrapping_sub(cc);
        m[x + u] = w & 0x7FFF_FFFF;
        cc = w >> 31;
    }
}

/// Einwortige Zahl mit Vorzeichen (31 Bit) → i32. Referenz: keygen.c,
/// zint_one_to_plain.
#[inline(always)]
pub(crate) fn zint_one_to_plain(w: u32) -> i32 {
    (w | (w & 0x4000_0000) << 1) as i32
}

// ---------------------------------------------------------------------------
// Polynome mit grossen Koeffizienten
// ---------------------------------------------------------------------------

/// Polynom (Koeffizienten flen Wörter, Abstand fstride) → Gleitkomma in
/// d (Gleitkomma-Index). Referenz: keygen.c, poly_big_to_fp.
pub(crate) fn poly_big_to_fp(
    m: &mut [u32],
    d: usize,
    f: usize,
    flen: usize,
    fstride: usize,
    logn: u32,
) {
    let n = 1usize << logn;
    if flen == 0 {
        for u in 0..n {
            fset(m, d + 2 * u, Fpr::ZERO);
        }
        return;
    }
    let ptwo31 = Fpr::scaled(1, 31);
    let mut fo = f;
    for u in 0..n {
        let neg = 0u32.wrapping_sub(m[fo + flen - 1] >> 30);
        let xm = neg >> 1;
        let mut cc = neg & 1;
        let mut x = Fpr::ZERO;
        let mut fsc = Fpr::ONE;
        for v in 0..flen {
            let mut w = (m[fo + v] ^ xm).wrapping_add(cc);
            cc = w >> 31;
            w &= 0x7FFF_FFFF;
            w = w.wrapping_sub((w << 1) & neg);
            x = x + Fpr::of_i64(w as i32 as i64) * fsc;
            fsc = fsc * ptwo31;
        }
        fset(m, d + 2 * u, x);
        fo += fstride;
    }
}

/// Einwortige Koeffizienten → i8; false, wenn einer über `lim` liegt
/// (dann wird der Kandidat verworfen). Referenz: keygen.c,
/// poly_big_to_small.
pub(crate) fn poly_big_to_small(d: &mut [i8], m: &[u32], s: usize, lim: i32, logn: u32) -> bool {
    let n = 1usize << logn;
    for u in 0..n {
        let z = zint_one_to_plain(m[s + u]);
        if z < -lim || z > lim {
            return false;
        }
        d[u] = z as i8;
    }
    true
}

/// F ← F − k·f, k mit kleinen Koeffizienten (im Puffer als i32 an `k`)
/// mal 2^sc, Schulbuch-Multiplikation. Referenz: keygen.c, poly_sub_scaled.
#[allow(clippy::too_many_arguments)]
pub(crate) fn poly_sub_scaled(
    m: &mut [u32],
    big_f: usize,
    flen_big: usize,
    fstride_big: usize,
    f: usize,
    flen: usize,
    fstride: usize,
    k: usize,
    sch: u32,
    scl: u32,
    logn: u32,
) {
    let n = 1usize << logn;
    for u in 0..n {
        let mut kf = (m[k + u] as i32).wrapping_neg();
        let mut x = big_f + u * fstride_big;
        let mut y = f;
        for v in 0..n {
            zint_add_scaled_mul_small(m, x, flen_big, y, flen, kf, sch, scl);
            if u + v == n - 1 {
                x = big_f;
                kf = kf.wrapping_neg();
            } else {
                x += fstride_big;
            }
            y += fstride;
        }
    }
}

/// F ← F − k·f über NTT/RNS (für grosse Grade). Referenz: keygen.c,
/// poly_sub_scaled_ntt.
#[allow(clippy::too_many_arguments)]
pub(crate) fn poly_sub_scaled_ntt(
    m: &mut [u32],
    big_f: usize,
    flen_big: usize,
    fstride_big: usize,
    f: usize,
    flen: usize,
    fstride: usize,
    k: usize,
    sch: u32,
    scl: u32,
    logn: u32,
    tmp: usize,
) {
    let n = 1usize << logn;
    let tlen = flen + 1;
    let gm = tmp;
    let igm = gm + n;
    let fk = igm + n;
    let t1 = fk + n * tlen;
    for u in 0..tlen {
        let (p, g, _) = PRIMES[u];
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(flen as u32, p, p0i, r2);
        modp_mkgm2(m, gm, igm, logn, g, p, p0i);
        for v in 0..n {
            m[t1 + v] = modp_set(m[k + v] as i32, p);
        }
        modp_ntt2(m, t1, gm, logn, p, p0i);
        let mut y = f;
        let mut x = fk + u;
        for _ in 0..n {
            m[x] = zint_mod_small_signed(m, y, flen, p, p0i, r2, rx);
            y += fstride;
            x += tlen;
        }
        modp_ntt2_ext(m, fk + u, tlen, gm, logn, p, p0i);
        let mut x = fk + u;
        for v in 0..n {
            m[x] = modp_montymul(modp_montymul(m[t1 + v], m[x], p, p0i), r2, p, p0i);
            x += tlen;
        }
        modp_intt2_ext(m, fk + u, tlen, igm, logn, p, p0i);
    }
    zint_rebuild_crt(m, fk, tlen, tlen, n, true, t1);
    let (mut x, mut y) = (big_f, fk);
    for _ in 0..n {
        zint_sub_scaled(m, x, flen_big, y, tlen, sch, scl);
        x += fstride_big;
        y += tlen;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primes_table_is_consistent() {
        for (i, &(p, g, s)) in PRIMES.iter().enumerate().take(40) {
            assert_eq!(p % 2048, 1);
            assert!(p > (1 << 30) && p < (1 << 31));
            let p0i = modp_ninv31(p);
            assert_eq!(p.wrapping_mul(p0i) & 0x7FFF_FFFF, 0x7FFF_FFFF, "p0i");
            let r2 = modp_r2(p, p0i);
            assert_eq!(r2 as u64, (1u128 << 62) as u64 % p as u64);
            // g hat Ordnung 2048: g^1024 = −1 mod p
            let mut x = 1u64;
            for _ in 0..1024 {
                x = x * g as u64 % p as u64;
            }
            assert_eq!(x, p as u64 - 1, "g von Prime {i}");
            // s = R / (Produkt der vorigen Primzahlen) mod p
            let mut prod = 1u64;
            for &(q, _, _) in &PRIMES[..i] {
                prod = prod * (q as u64 % p as u64) % p as u64;
            }
            let r = (1u64 << 31) % p as u64;
            assert_eq!((s as u64 * prod) % p as u64, r, "s von Prime {i}");
        }
    }

    #[test]
    fn modp_arithmetic() {
        let p = PRIMES[3].0;
        let p0i = modp_ninv31(p);
        let r = modp_r(p) as u64;
        for &(a, b) in &[(1u32, 2u32), (p - 1, p - 1), (12345, 678910)] {
            assert_eq!(modp_add(a, b, p) as u64, (a as u64 + b as u64) % p as u64);
            assert_eq!(
                modp_sub(a, b, p) as u64,
                (a as u64 + p as u64 - b as u64) % p as u64
            );
            // montymul(a, b) · R = a·b
            let mm = modp_montymul(a, b, p, p0i) as u64;
            assert_eq!(mm * r % p as u64, a as u64 * b as u64 % p as u64);
            let d = modp_div(a, b, p, p0i, modp_r(p)) as u64;
            assert_eq!(d * b as u64 % p as u64, a as u64 % p as u64);
        }
        assert_eq!(modp_norm(p - 1, p), -1);
        assert_eq!(modp_set(-1, p), p - 1);
    }

    #[test]
    fn ntt_roundtrip() {
        let (p, g, _) = PRIMES[0];
        let p0i = modp_ninv31(p);
        for logn in 1..=10u32 {
            let n = 1usize << logn;
            let mut m = vec![0u32; 3 * n];
            modp_mkgm2(&mut m, n, 2 * n, logn, g, p, p0i);
            for i in 0..n {
                m[i] = (i as u32 * 7919 + 13) % p;
            }
            let orig = m[..n].to_vec();
            modp_ntt2(&mut m, 0, n, logn, p, p0i);
            modp_intt2(&mut m, 0, 2 * n, logn, p, p0i);
            assert_eq!(&m[..n], &orig[..], "logn {logn}");
        }
    }

    #[test]
    fn bezout_small() {
        // x = 15, y = 7 (ungerade, teilerfremd): 15·u − 7·v = 1
        let mut m = vec![0u32; 2 + 2 + 4];
        m[2] = 15;
        m[3] = 7;
        assert!(zint_bezout(&mut m, 0, 1, 2, 3, 1, 4));
        assert_eq!(15 * m[0] as i64 - 7 * m[1] as i64, 1);
        // nicht teilerfremd
        m[2] = 21;
        assert!(!zint_bezout(&mut m, 0, 1, 2, 3, 1, 4));
    }
}
