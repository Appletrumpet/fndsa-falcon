//! Schlüsselerzeugung: f, g ziehen, prüfen, NTRU-Gleichung lösen.
//!
//! **Portierung der Referenz** (PLAN.md 2.2, Ausnahme Keygen, L10): Damit
//! aus einem Seed byte-genau die KAT-Schlüssel entstehen, folgt dieser Teil
//! Schritt für Schritt `keygen.c` der Referenz (hier aus PQClean,
//! `crypto_sign/falcon-*/clean/keygen.c`). Jede Funktion nennt ihr Vorbild
//! (`Referenz: keygen.c, <Name>`). Der Code ist in Rust neu geschrieben.
//!
//! Konstante Laufzeit wie in der Referenz. Erlaubte Verzweigungen auf
//! geheimen Daten (PLAN.md §6):
//! - einzelner Koeffizient ausserhalb ±127 oder falsche Parität beim
//!   letzten Koeffizienten: neu ziehen (PLAN.md 3.1, Ausnahme);
//! - Kandidat verwerfen: FG_BITS, Norm, γ, nicht invertierbar, NTRUSolve.

// Schleifen mit Index wie in der Referenz, damit der Code Zeile für Zeile
// vergleichbar bleibt.
#![allow(clippy::needless_range_loop)]

use sha3::digest::XofReader;
use zeroize::Zeroizing;

use crate::fft::{fft, fft_adj, ifft, Cplx};
use crate::fft_ref;
use crate::fpr::Fpr;
use crate::keygen_tables::PRIMES;
use crate::params::{LogN, Q};
use crate::zint::*;

/// Zufallsquelle für Keygen: SHAKE256-Strom über dem Seed.
pub(crate) struct KeygenRng<R: XofReader>(pub R);

impl<R: XofReader> KeygenRng<R> {
    /// 64 Bit, little-endian (Referenz: keygen.c, get_rng_u64).
    fn next_u64(&mut self) -> u64 {
        let mut b = Zeroizing::new([0u8; 8]);
        self.0.read(&mut b[..]);
        u64::from_le_bytes(*b)
    }
}

/// Diskrete Gaussverteilung mit σ = 1.17·√(q/2048), Wahrscheinlichkeiten
/// · 2⁶³. Element 0: P(x = 0); Element k > 0: P(x ≥ k+1 | x > 0).
/// Referenz: keygen.c, gauss_1024_12289.
const GAUSS_1024_12289: [u64; 27] = [
    1283868770400643928,
    6416574995475331444,
    4078260278032692663,
    2353523259288686585,
    1227179971273316331,
    575931623374121527,
    242543240509105209,
    91437049221049666,
    30799446349977173,
    9255276791179340,
    2478152334826140,
    590642893610164,
    125206034929641,
    23590435911403,
    3948334035941,
    586753615614,
    77391054539,
    9056793210,
    940121950,
    86539696,
    7062824,
    510971,
    32764,
    1862,
    94,
    4,
    0,
];

/// Gauss-verteilter Wert um 0 (Summe von 1024/n Ziehungen für n = 1024),
/// Tabelle ganz durchlaufen, ohne Verzweigung auf Werten.
/// Referenz: keygen.c, mkgauss.
fn mkgauss<R: XofReader>(rng: &mut KeygenRng<R>, logn: u32) -> i32 {
    let mut val: u32 = 0;
    for _ in 0..(1u32 << (10 - logn)) {
        // erster Wert: Vorzeichen und „ist 0“
        let r = rng.next_u64();
        let neg = (r >> 63) as u32;
        let r = r & !(1u64 << 63);
        let mut f = (r.wrapping_sub(GAUSS_1024_12289[0]) >> 63) as u32;
        // zweiter Wert: Index des ersten Eintrags ≤ r, falls noch nicht 0
        let mut v: u32 = 0;
        let r = rng.next_u64() & !(1u64 << 63);
        for (k, &t) in GAUSS_1024_12289.iter().enumerate().skip(1) {
            let t = ((r.wrapping_sub(t) >> 63) as u32) ^ 1;
            v |= (k as u32) & 0u32.wrapping_sub(t & (f ^ 1));
            f |= t;
        }
        // Vorzeichen anwenden
        v = (v ^ 0u32.wrapping_sub(neg)).wrapping_add(neg);
        val = val.wrapping_add(v);
    }
    val as i32
}

/// Zufälliges kleines Polynom; Koeffizienten in −127..=127, Summe ungerade
/// (sonst ist die Resultante gerade und NTRUSolve scheitert sicher).
/// Referenz: keygen.c, poly_small_mkgauss.
pub(crate) fn poly_small_mkgauss<R: XofReader>(
    rng: &mut KeygenRng<R>,
    logn: LogN,
) -> Zeroizing<Vec<i8>> {
    let n = logn.n();
    let mut f = Zeroizing::new(vec![0i8; n]);
    let mut mod2 = 0u32;
    for u in 0..n {
        // Erlaubte Verzweigungen (PLAN.md 3.1, Ausnahme): neu ziehen.
        let s = loop {
            let s = mkgauss(rng, logn.get());
            // Maske statt `contains` (das im Debug-Build in zwei Schritten
            // vergleicht und damit vor der Freigabe verzweigt).
            if crate::ct::declassify(crate::encoding::out_of_range_mask(s, 127)) != 0 {
                continue;
            }
            if u == n - 1 {
                if crate::ct::declassify((mod2 ^ (s as u32 & 1)) == 0) {
                    continue;
                }
            } else {
                mod2 ^= s as u32 & 1;
            }
            break s;
        };
        f[u] = s as i8;
    }
    f
}

/// Quadrierte Norm, ab 2³¹ gesättigt auf 2³²−1.
/// Referenz: keygen.c, poly_small_sqnorm.
fn poly_small_sqnorm(f: &[i8]) -> u32 {
    let (mut s, mut ng) = (0u32, 0u32);
    for &z in f {
        let z = z as i32;
        s = s.wrapping_add((z * z) as u32);
        ng |= s;
    }
    s | 0u32.wrapping_sub(ng >> 31)
}

/// (1.17)²·q = 16822.4121 als Gleitkommazahl. Referenz: fpr.h, fpr_bnorm_max.
const BNORM_MAX: Fpr = Fpr::from_bits(4670353323383631276);

/// Quadrierte Norm des orthogonalisierten Vektors
/// (q·adj(f)/(f·adj(f)+g·adj(g)), q·adj(g)/(…)), Referenz: keygen.c, keygen
/// (Schritt „orthogonalized vector norm“). Gerechnet mit der FFT dieses
/// Crates; das Ergebnis entscheidet nur „verwerfen ja/nein“ und weicht von
/// der Referenz höchstens in den letzten Bits ab.
fn gamma_sq(f: &[i8], g: &[i8]) -> Fpr {
    let to = |a: &[i8]| -> Zeroizing<Vec<Fpr>> {
        Zeroizing::new(a.iter().map(|&x| Fpr::of_i64(x as i64)).collect())
    };
    let (fh, gh) = (fft(&to(f)), fft(&to(g)));
    let q = Fpr::of_i64(Q as i64);
    // 1/(|f|² + |g|²) punktweise (reell)
    let inv: Zeroizing<Vec<Fpr>> = Zeroizing::new(
        fh.iter()
            .zip(gh.iter())
            .map(|(a, b)| (a.re * a.re + a.im * a.im + b.re * b.re + b.im * b.im).inv())
            .collect(),
    );
    let scale = |x: &[Cplx]| -> Zeroizing<Vec<Cplx>> {
        Zeroizing::new(
            fft_adj(x)
                .iter()
                .zip(inv.iter())
                .map(|(c, &s)| Cplx::new(c.re * q * s, c.im * q * s))
                .collect(),
        )
    };
    let (r1, r2) = (ifft(&scale(&fh)), ifft(&scale(&gh)));
    let mut b = Fpr::ZERO;
    for (x, y) in r1.iter().zip(r2.iter()) {
        b = b + x.sqr();
        b = b + y.sqr();
    }
    b
}

/// Prüfungen der Referenz vor NTRUSolve, in derselben Reihenfolge:
/// FG_BITS, ‖(g, −f)‖² < 16823, γ² < 16822.4121, f invertierbar mod q.
/// Gibt h zurück, wenn alle bestehen. Referenz: keygen.c, keygen.
pub(crate) fn check_fg(logn: LogN, f: &[i8], g: &[i8]) -> Option<Vec<u16>> {
    let lim = 1i32 << (logn.fg_bits() - 1);
    // Verwerfen darf verzweigen (Kandidat wird nie benutzt), aber erst nach
    // allen Koeffizienten: Maske statt Abbruch beim ersten.
    let mut bad = 0u32;
    for &x in f.iter().chain(g) {
        bad |= crate::encoding::out_of_range_mask(x as i32, lim - 1);
    }
    if crate::ct::declassify(bad) != 0 {
        return None;
    }
    let normf = poly_small_sqnorm(f);
    let normg = poly_small_sqnorm(g);
    let norm = normf.wrapping_add(normg) | 0u32.wrapping_sub((normf | normg) >> 31);
    if crate::ct::declassify(norm >= 16823) {
        return None;
    }
    if crate::ct::declassify(gamma_sq(f, g).lt_mask(BNORM_MAX)) == 0 {
        return None;
    }
    crate::falcon::compute_public_key(f, g).ok()
}

// ---------------------------------------------------------------------------
// NTRUSolve (Referenz: keygen.c, solve_NTRU und Hilfsfunktionen)
// ---------------------------------------------------------------------------

/// Längen (in 31-Bit-Wörtern) für f, g je Tiefe. Referenz: keygen.c,
/// MAX_BL_SMALL.
const MAX_BL_SMALL: [usize; 11] = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209];
/// Längen für das noch nicht reduzierte F, G je Tiefe. Referenz: keygen.c,
/// MAX_BL_LARGE.
const MAX_BL_LARGE: [usize; 10] = [2, 2, 5, 7, 12, 21, 40, 78, 157, 308];
/// Mittelwert und Standardabweichung der Bitlänge von (f, g) je Tiefe.
/// Referenz: keygen.c, BITLENGTH.
const BITLENGTH: [(i32, i32); 11] = [
    (4, 0),
    (11, 1),
    (24, 1),
    (50, 1),
    (102, 1),
    (202, 2),
    (401, 4),
    (794, 5),
    (1577, 8),
    (3138, 13),
    (6308, 25),
];
/// Ab dieser Tiefe (≤) wird k·f über die NTT berechnet. Referenz: keygen.c,
/// DEPTH_INT_FG.
const DEPTH_INT_FG: usize = 4;
/// Grösse des Arbeitspuffers in u32 je logn. Referenz: inner.h,
/// FALCON_KEYGEN_TEMP_* (in Bytes, hier /4).
const KEYGEN_TEMP: [usize; 11] = [0, 136, 272, 224, 448, 896, 1792, 3584, 7168, 14336, 28672];

const Q_U32: u32 = Q;

/// Ein Schritt von f, g (Grad N) zu f′, g′ (Grad N/2) im RNS, Ein- und
/// Ausgabe wahlweise in NTT-Form. Referenz: keygen.c, make_fg_step.
fn make_fg_step(m: &mut [u32], data: usize, logn: u32, depth: usize, in_ntt: bool, out_ntt: bool) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL[depth];
    let tlen = MAX_BL_SMALL[depth + 1];
    let fd = data;
    let gd = fd + hn * tlen;
    let fs = gd + hn * tlen;
    let gs = fs + n * slen;
    let gm = gs + n * slen;
    let igm = gm + n;
    let t1 = igm + n;
    m.copy_within(data..data + 2 * n * slen, fs);

    for u in 0..slen {
        let (p, g, _) = PRIMES[u];
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        modp_mkgm2(m, gm, igm, logn, g, p, p0i);
        for v in 0..n {
            m[t1 + v] = m[fs + u + v * slen];
        }
        if !in_ntt {
            modp_ntt2(m, t1, gm, logn, p, p0i);
        }
        for v in 0..hn {
            let (w0, w1) = (m[t1 + 2 * v], m[t1 + 2 * v + 1]);
            m[fd + u + v * tlen] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }
        if in_ntt {
            modp_intt2_ext(m, fs + u, slen, igm, logn, p, p0i);
        }
        for v in 0..n {
            m[t1 + v] = m[gs + u + v * slen];
        }
        if !in_ntt {
            modp_ntt2(m, t1, gm, logn, p, p0i);
        }
        for v in 0..hn {
            let (w0, w1) = (m[t1 + 2 * v], m[t1 + 2 * v + 1]);
            m[gd + u + v * tlen] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }
        if in_ntt {
            modp_intt2_ext(m, gs + u, slen, igm, logn, p, p0i);
        }
        if !out_ntt {
            modp_intt2_ext(m, fd + u, tlen, igm, logn - 1, p, p0i);
            modp_intt2_ext(m, gd + u, tlen, igm, logn - 1, p, p0i);
        }
    }

    zint_rebuild_crt(m, fs, slen, slen, n, true, gm);
    zint_rebuild_crt(m, gs, slen, slen, n, true, gm);

    for u in slen..tlen {
        let (p, g, _) = PRIMES[u];
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(slen as u32, p, p0i, r2);
        modp_mkgm2(m, gm, igm, logn, g, p, p0i);
        for v in 0..n {
            m[t1 + v] = zint_mod_small_signed(m, fs + v * slen, slen, p, p0i, r2, rx);
        }
        modp_ntt2(m, t1, gm, logn, p, p0i);
        for v in 0..hn {
            let (w0, w1) = (m[t1 + 2 * v], m[t1 + 2 * v + 1]);
            m[fd + u + v * tlen] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }
        for v in 0..n {
            m[t1 + v] = zint_mod_small_signed(m, gs + v * slen, slen, p, p0i, r2, rx);
        }
        modp_ntt2(m, t1, gm, logn, p, p0i);
        for v in 0..hn {
            let (w0, w1) = (m[t1 + 2 * v], m[t1 + 2 * v + 1]);
            m[gd + u + v * tlen] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }
        if !out_ntt {
            modp_intt2_ext(m, fd + u, tlen, igm, logn - 1, p, p0i);
            modp_intt2_ext(m, gd + u, tlen, igm, logn - 1, p, p0i);
        }
    }
}

/// f, g in Tiefe `depth`, im RNS. Referenz: keygen.c, make_fg.
fn make_fg(m: &mut [u32], data: usize, f: &[i8], g: &[i8], logn: u32, depth: usize, out_ntt: bool) {
    let n = 1usize << logn;
    let ft = data;
    let gt = ft + n;
    let (p0, g0, _) = PRIMES[0];
    for u in 0..n {
        m[ft + u] = modp_set(f[u] as i32, p0);
        m[gt + u] = modp_set(g[u] as i32, p0);
    }
    if depth == 0 && out_ntt {
        let p0i = modp_ninv31(p0);
        let gm = gt + n;
        let igm = gm + n;
        modp_mkgm2(m, gm, igm, logn, g0, p0, p0i);
        modp_ntt2(m, ft, gm, logn, p0, p0i);
        modp_ntt2(m, gt, gm, logn, p0, p0i);
        return;
    }
    if depth == 0 {
        return;
    }
    if depth == 1 {
        make_fg_step(m, data, logn, 0, false, out_ntt);
        return;
    }
    make_fg_step(m, data, logn, 0, false, true);
    for d in 1..depth - 1 {
        make_fg_step(m, data, logn - d as u32, d, true, true);
    }
    make_fg_step(m, data, logn - depth as u32 + 1, depth - 1, true, out_ntt);
}

/// Tiefste Stufe: Resultanten von f, g mit xⁿ+1, binärer GCD.
/// Referenz: keygen.c, solve_NTRU_deepest.
fn solve_ntru_deepest(m: &mut [u32], logn_top: u32, f: &[i8], g: &[i8]) -> bool {
    let len = MAX_BL_SMALL[logn_top as usize];
    let fp_big = 0;
    let gp_big = fp_big + len;
    let fp = gp_big + len;
    let gp = fp + len;
    let t1 = gp + len;
    make_fg(m, fp, f, g, logn_top, logn_top as usize, false);
    zint_rebuild_crt(m, fp, len, len, 2, false, t1);
    if !crate::ct::declassify(zint_bezout(m, gp_big, fp_big, fp, gp, len, t1)) {
        return false;
    }
    let c1 = zint_mul_small(m, fp_big, len, Q_U32);
    let c2 = zint_mul_small(m, gp_big, len, Q_U32);
    crate::ct::declassify((c1 | c2) == 0)
}

/// F′(xᵈ)·adj(g) und G′(xᵈ)·adj(f) in NTT-Form: gemeinsamer Schritt von
/// solve_NTRU_intermediate und solve_NTRU_binary_depth1.
#[allow(clippy::too_many_arguments)]
fn lift_fg(
    m: &mut [u32],
    ft_big: usize,
    gt_big: usize,
    u: usize,
    llen: usize,
    fx: usize,
    gx: usize,
    fp: usize,
    gp: usize,
    hn: usize,
    p: u32,
    p0i: u32,
    r2: u32,
) {
    for v in 0..hn {
        let x = ft_big + u + v * (llen << 1);
        let y = gt_big + u + v * (llen << 1);
        let (fta, ftb) = (m[fx + 2 * v], m[fx + 2 * v + 1]);
        let (gta, gtb) = (m[gx + 2 * v], m[gx + 2 * v + 1]);
        let mfp = modp_montymul(m[fp + v], r2, p, p0i);
        let mgp = modp_montymul(m[gp + v], r2, p, p0i);
        m[x] = modp_montymul(gtb, mfp, p, p0i);
        m[x + llen] = modp_montymul(gta, mfp, p, p0i);
        m[y] = modp_montymul(ftb, mgp, p, p0i);
        m[y + llen] = modp_montymul(fta, mgp, p, p0i);
    }
}

/// Mittlere Stufe: F, G aus der tieferen Stufe anheben und mit Babai
/// reduzieren. Referenz: keygen.c, solve_NTRU_intermediate.
fn solve_ntru_intermediate(m: &mut [u32], logn_top: u32, f: &[i8], g: &[i8], depth: usize) -> bool {
    let logn = logn_top - depth as u32;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL[depth];
    let dlen = MAX_BL_SMALL[depth + 1];
    let llen = MAX_BL_LARGE[depth];

    let mut fd_big = 0;
    let gd_big0 = fd_big + dlen * hn;
    let mut ft = gd_big0 + dlen * hn;
    make_fg(m, ft, f, g, logn_top, depth, true);

    let ft_big = 0;
    let gt_big = ft_big + n * llen;
    let mut t1 = gt_big + n * llen;
    m.copy_within(ft..ft + 2 * n * slen, t1);
    ft = t1;
    let gt = ft + slen * n;
    t1 = gt + slen * n;
    m.copy_within(fd_big..fd_big + 2 * hn * dlen, t1);
    fd_big = t1;
    let gd_big = fd_big + hn * dlen;

    for u in 0..llen {
        let (p, _, _) = PRIMES[u];
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(dlen as u32, p, p0i, r2);
        for v in 0..hn {
            m[ft_big + u + v * llen] =
                zint_mod_small_signed(m, fd_big + v * dlen, dlen, p, p0i, r2, rx);
            m[gt_big + u + v * llen] =
                zint_mod_small_signed(m, gd_big + v * dlen, dlen, p, p0i, r2, rx);
        }
    }

    for u in 0..llen {
        let (p, gg, _) = PRIMES[u];
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        if u == slen {
            zint_rebuild_crt(m, ft, slen, slen, n, true, t1);
            zint_rebuild_crt(m, gt, slen, slen, n, true, t1);
        }
        let gm = t1;
        let igm = gm + n;
        let fx = igm + n;
        let gx = fx + n;
        modp_mkgm2(m, gm, igm, logn, gg, p, p0i);
        if u < slen {
            for v in 0..n {
                m[fx + v] = m[ft + u + v * slen];
                m[gx + v] = m[gt + u + v * slen];
            }
            modp_intt2_ext(m, ft + u, slen, igm, logn, p, p0i);
            modp_intt2_ext(m, gt + u, slen, igm, logn, p, p0i);
        } else {
            let rx = modp_rx(slen as u32, p, p0i, r2);
            for v in 0..n {
                m[fx + v] = zint_mod_small_signed(m, ft + v * slen, slen, p, p0i, r2, rx);
                m[gx + v] = zint_mod_small_signed(m, gt + v * slen, slen, p, p0i, r2, rx);
            }
            modp_ntt2(m, fx, gm, logn, p, p0i);
            modp_ntt2(m, gx, gm, logn, p, p0i);
        }
        let fp = gx + n;
        let gp = fp + hn;
        for v in 0..hn {
            m[fp + v] = m[ft_big + u + v * llen];
            m[gp + v] = m[gt_big + u + v * llen];
        }
        modp_ntt2(m, fp, gm, logn - 1, p, p0i);
        modp_ntt2(m, gp, gm, logn - 1, p, p0i);
        lift_fg(m, ft_big, gt_big, u, llen, fx, gx, fp, gp, hn, p, p0i, r2);
        modp_intt2_ext(m, ft_big + u, llen, igm, logn, p, p0i);
        modp_intt2_ext(m, gt_big + u, llen, igm, logn, p, p0i);
    }

    zint_rebuild_crt(m, ft_big, llen, llen, n, true, t1);
    zint_rebuild_crt(m, gt_big, llen, llen, n, true, t1);

    // Babai-Reduktion; Gleitkomma-Polynome im selben Puffer (je n Werte
    // = 2n Wörter, rt5 nur n/2 Werte).
    let rt3 = align_fpr(t1);
    let rt4 = rt3 + 2 * n;
    let rt5 = rt4 + 2 * n;
    let rt1 = rt5 + n;
    let k = rt1;
    let mut rt2 = align_fpr(k + n);
    if rt2 < rt1 + 2 * n {
        rt2 = rt1 + 2 * n;
    }
    let t1 = k + n;

    let rlen = slen.min(10);
    poly_big_to_fp(m, rt3, ft + slen - rlen, rlen, slen, logn);
    poly_big_to_fp(m, rt4, gt + slen - rlen, rlen, slen, logn);
    let scale_fg = 31 * (slen - rlen) as i32;
    let (avg, std) = BITLENGTH[depth];
    let minbl_fg = avg - 6 * std;
    let maxbl_fg = avg + 6 * std;

    fft_ref::fft(m, rt3, logn);
    fft_ref::fft(m, rt4, logn);
    fft_ref::poly_invnorm2_fft(m, rt5, rt3, rt4, logn);
    fft_ref::poly_adj_fft(m, rt3, logn);
    fft_ref::poly_adj_fft(m, rt4, logn);

    let mut fglen = llen;
    let mut maxbl_fg_big = 31 * llen as i32;
    let mut scale_k = maxbl_fg_big - minbl_fg;
    let ptwo31m1 = Fpr::from_bits(4746794007244308480);
    let mtwo31m1 = Fpr::from_bits(13970166044099084288);
    loop {
        let rlen = fglen.min(10);
        let scale_fg_big = 31 * (fglen - rlen) as i32;
        poly_big_to_fp(m, rt1, ft_big + fglen - rlen, rlen, llen, logn);
        poly_big_to_fp(m, rt2, gt_big + fglen - rlen, rlen, llen, logn);

        fft_ref::fft(m, rt1, logn);
        fft_ref::fft(m, rt2, logn);
        fft_ref::poly_mul_fft(m, rt1, rt3, logn);
        fft_ref::poly_mul_fft(m, rt2, rt4, logn);
        fft_ref::poly_add(m, rt2, rt1, logn);
        fft_ref::poly_mul_autoadj_fft(m, rt2, rt5, logn);
        fft_ref::ifft(m, rt2, logn);

        // 2^(−dc); dc ist öffentlich
        let mut dc = scale_k - scale_fg_big + scale_fg;
        let mut pt = if dc < 0 {
            dc = -dc;
            Fpr::TWO
        } else {
            Fpr::from_bits(4602678819172646912) // 0.5
        };
        let mut pdc = Fpr::ONE;
        while dc != 0 {
            if (dc & 1) != 0 {
                pdc = pdc * pt;
            }
            dc >>= 1;
            pt = pt.sqr();
        }
        for u in 0..n {
            let xv = fget(m, rt2 + 2 * u) * pdc;
            // Verwerfen darf verzweigen (Kandidat wird aufgegeben).
            if crate::ct::declassify(mtwo31m1.lt_mask(xv) & xv.lt_mask(ptwo31m1)) == 0 {
                return false;
            }
            m[k + u] = xv.rint() as i32 as u32;
        }

        let sch = (scale_k / 31) as u32;
        let scl = (scale_k % 31) as u32;
        if depth <= DEPTH_INT_FG {
            poly_sub_scaled_ntt(
                m, ft_big, fglen, llen, ft, slen, slen, k, sch, scl, logn, t1,
            );
            poly_sub_scaled_ntt(
                m, gt_big, fglen, llen, gt, slen, slen, k, sch, scl, logn, t1,
            );
        } else {
            poly_sub_scaled(m, ft_big, fglen, llen, ft, slen, slen, k, sch, scl, logn);
            poly_sub_scaled(m, gt_big, fglen, llen, gt, slen, slen, k, sch, scl, logn);
        }

        let new_maxbl = scale_k + maxbl_fg + 10;
        if new_maxbl < maxbl_fg_big {
            maxbl_fg_big = new_maxbl;
            if fglen as i32 * 31 >= maxbl_fg_big + 31 {
                fglen -= 1;
            }
        }
        if scale_k <= 0 {
            break;
        }
        scale_k = (scale_k - 25).max(0);
    }

    if fglen < slen {
        for u in 0..n {
            let (fo, go) = (ft_big + u * llen, gt_big + u * llen);
            let sw = 0u32.wrapping_sub(m[fo + fglen - 1] >> 30) >> 1;
            m[fo + fglen..fo + slen].fill(sw);
            let sw = 0u32.wrapping_sub(m[go + fglen - 1] >> 30) >> 1;
            m[go + fglen..go + slen].fill(sw);
        }
    }
    for u in 0..2 * n {
        m.copy_within(u * llen..u * llen + slen, u * slen);
    }
    true
}

/// Stufe 1 (binärer Fall). Referenz: keygen.c, solve_NTRU_binary_depth1.
fn solve_ntru_binary_depth1(m: &mut [u32], logn_top: u32, f: &[i8], g: &[i8]) -> bool {
    let depth = 1;
    let n_top = 1usize << logn_top;
    let logn = logn_top - depth as u32;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL[depth];
    let dlen = MAX_BL_SMALL[depth + 1];
    let llen = MAX_BL_LARGE[depth];

    let fd_big = 0;
    let gd_big = fd_big + dlen * hn;
    let ft_big0 = gd_big + dlen * hn;
    let gt_big0 = ft_big0 + llen * n;
    for u in 0..llen {
        let (p, _, _) = PRIMES[u];
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(dlen as u32, p, p0i, r2);
        for v in 0..hn {
            m[ft_big0 + u + v * llen] =
                zint_mod_small_signed(m, fd_big + v * dlen, dlen, p, p0i, r2, rx);
            m[gt_big0 + u + v * llen] =
                zint_mod_small_signed(m, gd_big + v * dlen, dlen, p, p0i, r2, rx);
        }
    }
    m.copy_within(ft_big0..ft_big0 + llen * n, 0);
    let ft_big = 0;
    m.copy_within(gt_big0..gt_big0 + llen * n, ft_big + llen * n);
    let gt_big = ft_big + llen * n;
    let ft = gt_big + llen * n;
    let gt = ft + slen * n;
    let t1 = gt + slen * n;

    for u in 0..llen {
        let (p, gg, _) = PRIMES[u];
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let gm = t1;
        let mut igm = gm + n_top;
        let mut fx = igm + n;
        let mut gx = fx + n_top;
        modp_mkgm2(m, gm, igm, logn_top, gg, p, p0i);
        for v in 0..n_top {
            m[fx + v] = modp_set(f[v] as i32, p);
            m[gx + v] = modp_set(g[v] as i32, p);
        }
        modp_ntt2(m, fx, gm, logn_top, p, p0i);
        modp_ntt2(m, gx, gm, logn_top, p, p0i);
        for e in (logn + 1..=logn_top).rev() {
            modp_poly_rec_res(m, fx, e, p, p0i, r2);
            modp_poly_rec_res(m, gx, e, p, p0i, r2);
        }
        // depth > 0: Tabellen und Werte zusammenschieben
        m.copy_within(igm..igm + n, gm + n);
        igm = gm + n;
        m.copy_within(fx..fx + n, igm + n);
        fx = igm + n;
        m.copy_within(gx..gx + n, fx + n);
        gx = fx + n;

        let fp = gx + n;
        let gp = fp + hn;
        for v in 0..hn {
            m[fp + v] = m[ft_big + u + v * llen];
            m[gp + v] = m[gt_big + u + v * llen];
        }
        modp_ntt2(m, fp, gm, logn - 1, p, p0i);
        modp_ntt2(m, gp, gm, logn - 1, p, p0i);
        lift_fg(m, ft_big, gt_big, u, llen, fx, gx, fp, gp, hn, p, p0i, r2);
        modp_intt2_ext(m, ft_big + u, llen, igm, logn, p, p0i);
        modp_intt2_ext(m, gt_big + u, llen, igm, logn, p, p0i);
        if u < slen {
            modp_intt2(m, fx, igm, logn, p, p0i);
            modp_intt2(m, gx, igm, logn, p, p0i);
            for v in 0..n {
                m[ft + u + v * slen] = m[fx + v];
                m[gt + u + v * slen] = m[gx + v];
            }
        }
    }

    zint_rebuild_crt(m, ft_big, llen, llen, n << 1, true, t1);
    zint_rebuild_crt(m, ft, slen, slen, n << 1, true, t1);

    let mut rt1 = align_fpr(gt + slen * n);
    let rt2 = rt1 + 2 * n;
    poly_big_to_fp(m, rt1, ft_big, llen, llen, logn);
    poly_big_to_fp(m, rt2, gt_big, llen, llen, logn);

    m.copy_within(ft..ft + 2 * slen * n, 0);
    let ft = 0;
    let gt = ft + slen * n;
    let rt3 = align_fpr(gt + slen * n);
    m.copy_within(rt1..rt1 + 4 * n, rt3);
    rt1 = rt3;
    let rt2 = rt1 + 2 * n;
    let rt3 = rt2 + 2 * n;
    let rt4 = rt3 + 2 * n;
    poly_big_to_fp(m, rt3, ft, slen, slen, logn);
    poly_big_to_fp(m, rt4, gt, slen, slen, logn);

    m.copy_within(rt1..rt1 + 8 * n, 0);
    let rt1 = 0;
    let rt2 = rt1 + 2 * n;
    let rt3 = rt2 + 2 * n;
    let rt4 = rt3 + 2 * n;
    let _ = rt2;

    fft_ref::fft(m, rt1, logn);
    fft_ref::fft(m, rt2, logn);
    fft_ref::fft(m, rt3, logn);
    fft_ref::fft(m, rt4, logn);

    let rt5 = rt4 + 2 * n;
    let rt6 = rt5 + 2 * n;
    fft_ref::poly_add_muladj_fft(m, rt5, rt1, rt2, rt3, rt4, logn);
    fft_ref::poly_invnorm2_fft(m, rt6, rt3, rt4, logn);
    fft_ref::poly_mul_autoadj_fft(m, rt5, rt6, logn);
    fft_ref::ifft(m, rt5, logn);
    let ptwo63m1 = Fpr::from_bits(4890909195324358656);
    let mtwo63m1 = Fpr::from_bits(14114281232179134464);
    for u in 0..n {
        let z = fget(m, rt5 + 2 * u);
        if crate::ct::declassify(z.lt_mask(ptwo63m1) & mtwo63m1.lt_mask(z)) == 0 {
            return false;
        }
        fset(m, rt5 + 2 * u, Fpr::of_i64(z.rint()));
    }
    fft_ref::fft(m, rt5, logn);
    fft_ref::poly_mul_fft(m, rt3, rt5, logn);
    fft_ref::poly_mul_fft(m, rt4, rt5, logn);
    fft_ref::poly_sub(m, rt1, rt3, logn);
    fft_ref::poly_sub(m, rt2, rt4, logn);
    fft_ref::ifft(m, rt1, logn);
    fft_ref::ifft(m, rt2, logn);

    let ft_big = 0;
    let gt_big = ft_big + n;
    let rt3 = align_fpr(gt_big + n);
    m.copy_within(rt1..rt1 + 4 * n, rt3);
    let rt1 = rt3;
    let rt2 = rt1 + 2 * n;
    for u in 0..n {
        m[ft_big + u] = fget(m, rt1 + 2 * u).rint() as u32;
        m[gt_big + u] = fget(m, rt2 + 2 * u).rint() as u32;
    }
    true
}

/// Stufe 0 (binärer Fall). Referenz: keygen.c, solve_NTRU_binary_depth0.
fn solve_ntru_binary_depth0(m: &mut [u32], logn: u32, f: &[i8], g: &[i8]) -> bool {
    let n = 1usize << logn;
    let hn = n >> 1;
    let (p, gg, _) = PRIMES[0];
    let p0i = modp_ninv31(p);
    let r2 = modp_r2(p, p0i);

    let fp = 0;
    let gp = fp + hn;
    let ft = gp + hn;
    let gt = ft + n;
    let gm = gt + n;
    let igm = gm + n;
    modp_mkgm2(m, gm, igm, logn, gg, p, p0i);
    for u in 0..hn {
        m[fp + u] = modp_set(zint_one_to_plain(m[fp + u]), p);
        m[gp + u] = modp_set(zint_one_to_plain(m[gp + u]), p);
    }
    modp_ntt2(m, fp, gm, logn - 1, p, p0i);
    modp_ntt2(m, gp, gm, logn - 1, p, p0i);
    for u in 0..n {
        m[ft + u] = modp_set(f[u] as i32, p);
        m[gt + u] = modp_set(g[u] as i32, p);
    }
    modp_ntt2(m, ft, gm, logn, p, p0i);
    modp_ntt2(m, gt, gm, logn, p, p0i);
    for u in (0..n).step_by(2) {
        let (fta, ftb) = (m[ft + u], m[ft + u + 1]);
        let (gta, gtb) = (m[gt + u], m[gt + u + 1]);
        let mfp = modp_montymul(m[fp + (u >> 1)], r2, p, p0i);
        let mgp = modp_montymul(m[gp + (u >> 1)], r2, p, p0i);
        m[ft + u] = modp_montymul(gtb, mfp, p, p0i);
        m[ft + u + 1] = modp_montymul(gta, mfp, p, p0i);
        m[gt + u] = modp_montymul(ftb, mgp, p, p0i);
        m[gt + u + 1] = modp_montymul(fta, mgp, p, p0i);
    }
    modp_intt2(m, ft, igm, logn, p, p0i);
    modp_intt2(m, gt, igm, logn, p, p0i);

    let gp = fp + n;
    let t1 = gp + n;
    m.copy_within(ft..ft + 2 * n, fp);
    let t2 = t1 + n;
    let t3 = t2 + n;
    let t4 = t3 + n;
    let t5 = t4 + n;
    modp_mkgm2(m, t1, t2, logn, gg, p, p0i);
    modp_ntt2(m, fp, t1, logn, p, p0i);
    modp_ntt2(m, gp, t1, logn, p, p0i);

    let v = modp_set(f[0] as i32, p);
    m[t4] = v;
    m[t5] = v;
    for u in 1..n {
        m[t4 + u] = modp_set(f[u] as i32, p);
        m[t5 + n - u] = modp_set(-(f[u] as i32), p);
    }
    modp_ntt2(m, t4, t1, logn, p, p0i);
    modp_ntt2(m, t5, t1, logn, p, p0i);
    for u in 0..n {
        let w = modp_montymul(m[t5 + u], r2, p, p0i);
        m[t2 + u] = modp_montymul(w, m[fp + u], p, p0i);
        m[t3 + u] = modp_montymul(w, m[t4 + u], p, p0i);
    }
    let v = modp_set(g[0] as i32, p);
    m[t4] = v;
    m[t5] = v;
    for u in 1..n {
        m[t4 + u] = modp_set(g[u] as i32, p);
        m[t5 + n - u] = modp_set(-(g[u] as i32), p);
    }
    modp_ntt2(m, t4, t1, logn, p, p0i);
    modp_ntt2(m, t5, t1, logn, p, p0i);
    for u in 0..n {
        let w = modp_montymul(m[t5 + u], r2, p, p0i);
        m[t2 + u] = modp_add(m[t2 + u], modp_montymul(w, m[gp + u], p, p0i), p);
        m[t3 + u] = modp_add(m[t3 + u], modp_montymul(w, m[t4 + u], p, p0i), p);
    }
    modp_mkgm2(m, t1, t4, logn, gg, p, p0i);
    modp_intt2(m, t2, t4, logn, p, p0i);
    modp_intt2(m, t3, t4, logn, p, p0i);
    for u in 0..n {
        m[t1 + u] = modp_norm(m[t2 + u], p) as u32;
        m[t2 + u] = modp_norm(m[t3 + u], p) as u32;
    }

    let rt3 = align_fpr(t3);
    for u in 0..n {
        fset(m, rt3 + 2 * u, Fpr::of_i64(m[t2 + u] as i32 as i64));
    }
    fft_ref::fft(m, rt3, logn);
    let rt2 = align_fpr(t2);
    m.copy_within(rt3..rt3 + 2 * hn, rt2);
    let rt3 = rt2 + 2 * hn;
    for u in 0..n {
        fset(m, rt3 + 2 * u, Fpr::of_i64(m[t1 + u] as i32 as i64));
    }
    fft_ref::fft(m, rt3, logn);
    fft_ref::poly_div_autoadj_fft(m, rt3, rt2, logn);
    fft_ref::ifft(m, rt3, logn);
    for u in 0..n {
        m[t1 + u] = modp_set(fget(m, rt3 + 2 * u).rint() as i32, p);
    }

    let t2 = t1 + n;
    let t3 = t2 + n;
    let t4 = t3 + n;
    let t5 = t4 + n;
    modp_mkgm2(m, t2, t3, logn, gg, p, p0i);
    for u in 0..n {
        m[t4 + u] = modp_set(f[u] as i32, p);
        m[t5 + u] = modp_set(g[u] as i32, p);
    }
    modp_ntt2(m, t1, t2, logn, p, p0i);
    modp_ntt2(m, t4, t2, logn, p, p0i);
    modp_ntt2(m, t5, t2, logn, p, p0i);
    for u in 0..n {
        let kw = modp_montymul(m[t1 + u], r2, p, p0i);
        m[fp + u] = modp_sub(m[fp + u], modp_montymul(kw, m[t4 + u], p, p0i), p);
        m[gp + u] = modp_sub(m[gp + u], modp_montymul(kw, m[t5 + u], p, p0i), p);
    }
    modp_intt2(m, fp, t3, logn, p, p0i);
    modp_intt2(m, gp, t3, logn, p, p0i);
    for u in 0..n {
        m[fp + u] = modp_norm(m[fp + u], p) as u32;
        m[gp + u] = modp_norm(m[gp + u], p) as u32;
    }
    true
}

/// F und G aus NTRUSolve.
pub(crate) type FgPair = (Zeroizing<Vec<i8>>, Zeroizing<Vec<i8>>);

/// NTRUSolve: F, G mit fG − gF = q und |F|, |G| ≤ lim, oder None, wenn
/// es nicht gelingt (dann wird der Kandidat verworfen).
/// Referenz: keygen.c, solve_NTRU.
pub(crate) fn solve_ntru(logn: u32, f: &[i8], g: &[i8], lim: i32) -> Option<FgPair> {
    let n = 1usize << logn;
    let mut buf = Zeroizing::new(vec![0u32; KEYGEN_TEMP[logn as usize] / 4]);
    let m = &mut buf[..];
    if !solve_ntru_deepest(m, logn, f, g) {
        return None;
    }
    if logn <= 2 {
        for depth in (0..logn as usize).rev() {
            if !solve_ntru_intermediate(m, logn, f, g, depth) {
                return None;
            }
        }
    } else {
        for depth in (2..logn as usize).rev() {
            if !solve_ntru_intermediate(m, logn, f, g, depth) {
                return None;
            }
        }
        if !solve_ntru_binary_depth1(m, logn, f, g) || !solve_ntru_binary_depth0(m, logn, f, g) {
            return None;
        }
    }
    let mut big_f = Zeroizing::new(vec![0i8; n]);
    let mut big_g = Zeroizing::new(vec![0i8; n]);
    if !poly_big_to_small(&mut big_f, m, 0, lim, logn)
        || !poly_big_to_small(&mut big_g, m, n, lim, logn)
    {
        return None;
    }

    // Prüfung fG − gF = q mod p (wie die Referenz).
    let gt_big = 0;
    let ft = gt_big + n;
    let gt = ft + n;
    let ft_big = gt + n;
    let gm = ft_big + n;
    let (p, gg, _) = PRIMES[0];
    let p0i = modp_ninv31(p);
    modp_mkgm2(m, gm, 0, logn, gg, p, p0i);
    for u in 0..n {
        m[gt_big + u] = modp_set(big_g[u] as i32, p);
    }
    for u in 0..n {
        m[ft + u] = modp_set(f[u] as i32, p);
        m[gt + u] = modp_set(g[u] as i32, p);
        m[ft_big + u] = modp_set(big_f[u] as i32, p);
    }
    modp_ntt2(m, ft, gm, logn, p, p0i);
    modp_ntt2(m, gt, gm, logn, p, p0i);
    modp_ntt2(m, ft_big, gm, logn, p, p0i);
    modp_ntt2(m, gt_big, gm, logn, p, p0i);
    let r = modp_montymul(Q_U32, 1, p, p0i);
    for u in 0..n {
        let z = modp_sub(
            modp_montymul(m[ft + u], m[gt_big + u], p, p0i),
            modp_montymul(m[gt + u], m[ft_big + u], p, p0i),
            p,
        );
        if crate::ct::declassify(z != r) {
            return None;
        }
    }
    Some((big_f, big_g))
}

/// Ergebnis von Keygen: f, g, F, G und h. Wird beim Verwerfen gelöscht
/// (h ist öffentlich).
pub(crate) struct KeyParts {
    pub f: Zeroizing<Vec<i8>>,
    pub g: Zeroizing<Vec<i8>>,
    pub big_f: Zeroizing<Vec<i8>>,
    /// G aus NTRUSolve; `SigningKey` berechnet G beim Aufbau selbst neu,
    /// hier nur für die Tests der verkleinerten Grade.
    #[cfg_attr(not(test), allow(dead_code))]
    pub big_g: Zeroizing<Vec<i8>>,
    pub h: Vec<u16>,
}

/// Keygen (Alg. 4) aus einem Seed: SHAKE256(seed) liefert allen Zufall.
/// Gleicher Seed → gleicher Schlüssel; mit dem Seed aus dem NIST-DRBG
/// entstehen die KAT-Schlüssel (L10). Referenz: keygen.c, keygen, und
/// pqclean.c, crypto_sign_keypair.
pub(crate) fn keygen_from_seed(logn: LogN, seed: &[u8]) -> KeyParts {
    use sha3::digest::{ExtendableOutput, Update};
    let mut h = sha3::Shake256::default();
    h.update(seed);
    let mut rng = KeygenRng(h.finalize_xof());
    loop {
        let f = poly_small_mkgauss(&mut rng, logn);
        let g = poly_small_mkgauss(&mut rng, logn);
        // Verwerfen darf verzweigen (PLAN.md §6).
        let Some(h) = check_fg(logn, &f, &g) else {
            continue;
        };
        let Some((big_f, big_g)) = solve_ntru(logn.get(), &f, &g, 127) else {
            continue;
        };
        return KeyParts {
            f,
            g,
            big_f,
            big_g,
            h,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::decode_sk;
    use crate::kat::{drbg::Drbg, load_kat};
    use sha3::digest::{ExtendableOutput, Update};

    #[test]
    fn bnorm_constant() {
        assert_eq!(BNORM_MAX.to_bits(), 16822.4121f64.to_bits());
    }

    /// Der DRBG bildet die Seeds der KAT-Dateien nach (Start mit 0..47).
    #[test]
    fn drbg_reproduces_kat_seeds() {
        let entropy: Vec<u8> = (0..48).collect();
        for n in [512, 1024] {
            let mut d = Drbg::new(&entropy);
            for rec in load_kat(n) {
                let mut seed = [0u8; 48];
                d.fill(&mut seed);
                assert_eq!(seed.to_vec(), rec.seed, "count {}", rec.count);
                // Rest des Ablaufs im NIST-Programm: Nachricht ziehen
                let mut msg = vec![0u8; rec.msg.len()];
                d.fill(&mut msg);
                assert_eq!(msg, rec.msg, "msg count {}", rec.count);
            }
        }
    }

    /// Erster Kandidat, der alle Prüfungen vor NTRUSolve besteht, für den
    /// Seed eines KAT-Falls.
    fn first_candidate(logn: LogN, kat_seed: &[u8]) -> (Vec<i8>, Vec<i8>) {
        let mut seed = [0u8; 48];
        Drbg::new(kat_seed).fill(&mut seed);
        let mut h = sha3::Shake256::default();
        h.update(&seed);
        let mut rng = KeygenRng(h.finalize_xof());
        loop {
            let f = poly_small_mkgauss(&mut rng, logn);
            let g = poly_small_mkgauss(&mut rng, logn);
            if check_fg(logn, &f, &g).is_some() {
                return (f.to_vec(), g.to_vec());
            }
        }
    }

    /// Meilenstein: f und g der KAT-Schlüssel kommen byte-genau heraus
    /// (solange NTRUSolve beim ersten passenden Kandidaten gelingt, was fast
    /// immer der Fall ist).
    #[test]
    fn kat_f_g_from_seed() {
        for (n, logn) in [(512, LogN::FALCON_512), (1024, LogN::FALCON_1024)] {
            let mut same = 0;
            let recs = load_kat(n);
            for rec in recs.iter().take(20) {
                let sk = decode_sk(&rec.sk).unwrap();
                let (f, g) = first_candidate(logn, &rec.seed);
                if f == sk.f && g == sk.g {
                    same += 1;
                }
            }
            // Rest: NTRUSolve scheitert beim ersten Kandidaten (prüft das volle Keygen)
            assert!(same >= 15, "n = {n}: nur {same} von 20 gleich");
            let sk0 = decode_sk(&recs[0].sk).unwrap();
            let (f0, g0) = first_candidate(logn, &recs[0].seed);
            assert_eq!((f0, g0), (sk0.f.clone(), sk0.g.clone()), "n = {n}, count 0");
        }
    }

    /// KAT-Schlüssel byte-genau aus dem Seed (L10, Phase 5: count 0).
    #[test]
    fn kat_count0_from_seed() {
        for (n, logn) in [(512, LogN::FALCON_512), (1024, LogN::FALCON_1024)] {
            let rec = &load_kat(n)[0];
            let mut seed = [0u8; 48];
            Drbg::new(&rec.seed).fill(&mut seed);
            let k = keygen_from_seed(logn, &seed);
            let sk = decode_sk(&rec.sk).unwrap();
            assert_eq!(&k.f[..], &sk.f[..], "f, n = {n}");
            assert_eq!(&k.g[..], &sk.g[..], "g, n = {n}");
            assert_eq!(&k.big_f[..], &sk.big_f[..], "F, n = {n}");
            let (_, h) = crate::encoding::decode_pk(&rec.pk).unwrap();
            assert_eq!(k.h, h, "h, n = {n}");
        }
    }

    /// Verkleinerte Grade (n = 2 … 256): Keygen liefert Schlüssel mit
    /// fG − gF = q und kleinen Koeffizienten.
    #[test]
    fn reduced_degrees_satisfy_ntru_equation() {
        for l in 1..=8u32 {
            let logn = LogN::new(l).unwrap();
            for i in 0..3u8 {
                let k = keygen_from_seed(logn, &[l as u8, i]);
                let g16: Vec<i16> = k.big_g.iter().map(|&x| x as i16).collect();
                assert_ne!(
                    crate::falcon::key_valid_mask(&k.f, &k.g, &k.big_f, &g16),
                    0,
                    "logn {l}, Seed {i}"
                );
            }
        }
    }
}
