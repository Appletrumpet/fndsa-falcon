//! Kompression von s₂ und Byteformate für Public Key und Secret Key.
//!
//! Spec-Referenz: §3.11.3–§3.11.5, Alg. 17/18. Entspricht
//! `Python/falcon/encoding.py`, mit zwei bewussten Unterschieden (PLAN.md,
//! 2.2, L5/L6):
//! - `decompress` lehnt |sᵢ| > 2047 ab (Python akzeptiert jeden Wert);
//!   `compress` erzeugt solche Werte deshalb auch nicht.
//! - Die Secret-Key-Funktionen laufen ohne Verzweigung auf den
//!   Koeffizientenwerten; nur das Gesamtergebnis gültig/ungültig verzweigt.
//!
//! Kompression und Public Key sind öffentlich: normaler Code.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ct;
use crate::params::{LogN, Q};
use crate::Error;

/// Grösster Betrag eines Koeffizienten von s₂ (L5): 7 tiefe Bits plus
/// höchstens 15 Bits unär.
pub const S2_MAX: u32 = 2047;

// ---------------------------------------------------------------------------
// Bits schreiben und lesen (höchstwertiges Bit zuerst)
// ---------------------------------------------------------------------------

struct BitWriter {
    buf: Vec<u8>,
    acc: u32,
    nbits: u32,
    total: usize,
}

impl BitWriter {
    /// `cap` ist die endgültige Länge in Bytes. Der Puffer wird damit nie
    /// vergrössert: Beim Vergrössern gäbe Rust den alten Speicher frei, ohne
    /// ihn zu löschen, und beim Secret Key blieben Kopien von f, g, F im RAM
    /// (PLAN.md, 3.2 Regel 7).
    fn with_capacity(cap: usize) -> Self {
        BitWriter {
            buf: Vec::with_capacity(cap),
            acc: 0,
            nbits: 0,
            total: 0,
        }
    }

    /// Schreibt die unteren `len` Bits von `value` (len ≤ 24). Keine
    /// Verzweigung auf `value`, daher auch für geheime Werte geeignet.
    fn write(&mut self, value: u32, len: u32) {
        debug_assert!(len <= 24);
        self.acc = (self.acc << len) | (value & ((1u32 << len) - 1));
        self.nbits += len;
        self.total += len as usize;
        while self.nbits >= 8 {
            self.nbits -= 8;
            self.buf.push((self.acc >> self.nbits) as u8);
        }
        self.acc &= (1u32 << self.nbits) - 1;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.buf.push((self.acc << (8 - self.nbits)) as u8);
        }
        self.acc.zeroize();
        self.buf
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0 }
    }

    fn total(&self) -> usize {
        self.data.len() * 8
    }

    /// Liest `len` Bits (len ≤ 24). `None`, wenn die Daten nicht reichen.
    /// Die Position ist öffentlich; auf den gelesenen Bits wird nicht
    /// verzweigt.
    fn read(&mut self, len: u32) -> Option<u32> {
        if self.pos + len as usize > self.total() {
            return None;
        }
        let mut v = 0u32;
        for _ in 0..len {
            let byte = self.data[self.pos >> 3] as u32;
            v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1);
            self.pos += 1;
        }
        Some(v)
    }

    /// Sind alle restlichen Bits 0?
    fn rest_is_zero(&mut self) -> bool {
        while self.pos < self.total() {
            if self.read(1) != Some(0) {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Kompression von s₂ (Alg. 17 / Alg. 18)
// ---------------------------------------------------------------------------

/// Vorzeichen, 7 tiefe Bits, Rest unär; mit Nullen auf `padded_len` Bytes
/// auffüllen. `None`, wenn die Kodierung nicht passt oder ein |sᵢ| > 2047
/// ist. Alg. 17.
pub fn compress(s: &[i16], padded_len: usize) -> Option<Vec<u8>> {
    let slen = padded_len * 8;
    let mut w = BitWriter::with_capacity(padded_len);
    for &c in s {
        let av = c.unsigned_abs() as u32;
        if av > S2_MAX {
            return None;
        }
        let k = av >> 7;
        if w.total + 9 + k as usize > slen {
            return None;
        }
        w.write((c < 0) as u32, 1);
        w.write(av & 0x7F, 7);
        // k Nullen, dann eine 1
        w.write(1, k + 1);
    }
    while w.total < slen {
        let len = (slen - w.total).min(24) as u32;
        w.write(0, len);
    }
    Some(w.finish())
}

/// Umkehrung von `compress`, für Polynomgrad `n`.
///
/// Akzeptiert gepolsterte Kodierungen (genau `padded_len` Bytes, Rest 0) und
/// ungepolsterte (§3.11.3: das letzte Byte ist nicht 0, die Kodierung endet
/// darin, Restbits 0). Ungepolsterte Kodierungen dürfen länger als
/// `padded_len` sein (NIST-KAT Falcon-1024, count = 82). Lehnt −0 und
/// |sᵢ| > 2047 ab (L5).
pub fn decompress(b: &[u8], n: usize, padded_len: usize) -> Option<Vec<i16>> {
    let last = *b.last()?;
    let padded = b.len() == padded_len;
    if !padded && last == 0 {
        return None;
    }

    let mut r = BitReader::new(b);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let sign = r.read(1)?;
        let low7 = r.read(7)?;
        let mut k = 0u32;
        while r.read(1)? == 0 {
            k += 1;
            if (k << 7) > S2_MAX {
                return None;
            }
        }
        let v = (low7 | (k << 7)) as i16;
        if sign == 1 {
            if v == 0 {
                return None;
            }
            out.push(-v);
        } else {
            out.push(v);
        }
    }

    if !padded && r.pos <= (b.len() - 1) * 8 {
        return None;
    }
    if !r.rest_is_zero() {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Public Key (§3.11.4)
// ---------------------------------------------------------------------------

/// Header 0000nnnn, dann 14 Bit je Koeffizient. `h` hat Länge n mit
/// n = 2..=1024 und Werte < q.
pub fn encode_pk(logn: LogN, h: &[u16]) -> Vec<u8> {
    debug_assert_eq!(h.len(), logn.n());
    let mut w = BitWriter::with_capacity(logn.pk_bytes());
    w.write(logn.get(), 8);
    for &c in h {
        debug_assert!((c as u32) < Q);
        w.write(c as u32, 14);
    }
    w.finish()
}

/// Umkehrung von `encode_pk`.
pub fn decode_pk(b: &[u8]) -> Result<(LogN, Vec<u16>), Error> {
    let header = *b
        .first()
        .ok_or(Error::InvalidEncoding("leerer Public Key"))?;
    if header >> 4 != 0 {
        return Err(Error::InvalidEncoding("Public-Key-Header"));
    }
    let logn = LogN::new((header & 0x0F) as u32)?;
    if b.len() != logn.pk_bytes() {
        return Err(Error::InvalidEncoding("Public-Key-Länge"));
    }
    let mut r = BitReader::new(&b[1..]);
    let mut h = Vec::with_capacity(logn.n());
    for _ in 0..logn.n() {
        let v = r
            .read(14)
            .ok_or(Error::InvalidEncoding("Public Key abgeschnitten"))?;
        if v >= Q {
            return Err(Error::InvalidEncoding("Public-Key-Koeffizient nicht < q"));
        }
        h.push(v as u16);
    }
    if !r.rest_is_zero() {
        return Err(Error::InvalidEncoding("Füllbits im Public Key"));
    }
    Ok((logn, h))
}

// ---------------------------------------------------------------------------
// Secret Key (§3.11.5)
// ---------------------------------------------------------------------------

/// Die gespeicherten Teile des Secret Keys: f, g, F. Wird beim Verwerfen
/// gelöscht.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretPolys {
    #[zeroize(skip)]
    pub logn: LogN,
    pub f: Vec<i8>,
    pub g: Vec<i8>,
    pub big_f: Vec<i8>,
}

/// Maske „x liegt nicht in [−lim, lim]“, ohne Verzweigung.
#[inline(always)]
pub(crate) fn out_of_range_mask(x: i32, lim: i32) -> u32 {
    ct::mask_from_msb((lim - x) as u32) | ct::mask_from_msb((x + lim) as u32)
}

/// Header 0101nnnn, f und g mit `fg_bits` Bit, F mit 8 Bit, Zweierkomplement.
/// Der kleinste Wert −2^(bits−1) ist verboten. Fehler nur, wenn ein Wert
/// nicht passt (L6); welcher, bleibt verborgen.
pub fn encode_sk(sk: &SecretPolys) -> Result<Zeroizing<Vec<u8>>, Error> {
    let logn = sk.logn;
    let n = logn.n();
    if sk.f.len() != n || sk.g.len() != n || sk.big_f.len() != n {
        return Err(Error::InvalidEncoding("Länge von f, g, F"));
    }
    let bits = logn.fg_bits();
    let lim = (1i32 << (bits - 1)) - 1;

    let mut bad = 0u32;
    let mut w = BitWriter::with_capacity(logn.sk_bytes());
    w.write(0x50 | logn.get(), 8);
    for &x in sk.f.iter().chain(sk.g.iter()) {
        bad |= out_of_range_mask(x as i32, lim);
        w.write(x as u8 as u32, bits);
    }
    for &x in sk.big_f.iter() {
        bad |= out_of_range_mask(x as i32, 127);
        w.write(x as u8 as u32, 8);
    }
    let out = Zeroizing::new(w.finish());
    if ct::declassify(bad) != 0 {
        return Err(Error::KeyOutOfRange);
    }
    Ok(out)
}

/// Umkehrung von `encode_sk`.
pub fn decode_sk(b: &[u8]) -> Result<SecretPolys, Error> {
    let header = *b
        .first()
        .ok_or(Error::InvalidEncoding("leerer Secret Key"))?;
    if header >> 4 != 0b0101 {
        return Err(Error::InvalidEncoding("Secret-Key-Header"));
    }
    let logn = LogN::new((header & 0x0F) as u32)?;
    if b.len() != logn.sk_bytes() {
        return Err(Error::InvalidEncoding("Secret-Key-Länge"));
    }
    let n = logn.n();
    let bits = logn.fg_bits();
    let mut r = BitReader::new(&b[1..]);
    let mut bad = 0u32;

    // Vorzeichen erweitern ohne Verzweigung; der verbotene Minimalwert wird
    // in `bad` gesammelt.
    let mut read_signed = |r: &mut BitReader, width: u32| -> Option<i8> {
        let raw = r.read(width)?;
        bad |= ct::is_zero_mask(raw ^ (1 << (width - 1)));
        Some((((raw << (32 - width)) as i32) >> (32 - width)) as i8)
    };

    let mut sk = SecretPolys {
        logn,
        f: Vec::with_capacity(n),
        g: Vec::with_capacity(n),
        big_f: Vec::with_capacity(n),
    };
    // Die Länge ist oben geprüft; abgeschnitten kann der Key hier nicht mehr
    // sein. Die Prüfung bleibt als Absicherung.
    let truncated = || Error::InvalidEncoding("Secret Key abgeschnitten");
    for _ in 0..n {
        sk.f.push(read_signed(&mut r, bits).ok_or_else(truncated)?);
    }
    for _ in 0..n {
        sk.g.push(read_signed(&mut r, bits).ok_or_else(truncated)?);
    }
    for _ in 0..n {
        sk.big_f.push(read_signed(&mut r, 8).ok_or_else(truncated)?);
    }
    if r.pos != r.total() {
        return Err(Error::InvalidEncoding("Restbits im Secret Key"));
    }
    if ct::declassify(bad) != 0 {
        return Err(Error::InvalidEncoding("Minimalwert im Secret Key"));
    }
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat;

    // Beispiel aus Python/tests/test_encoding.py, von Hand nach Alg. 17:
    //   1 → 0 0000001 1, −1 → 1 0000001 1, 0 → 0 0000000 1,
    //   130 → 0 0000010 01; 37 Bit, mit Nullen auf 40 → 01 C0 C0 20 48
    const EX_S: [i16; 4] = [1, -1, 0, 130];
    const EX_BYTES: [u8; 5] = [0x01, 0xc0, 0xc0, 0x20, 0x48];

    #[test]
    fn compress_example() {
        assert_eq!(compress(&EX_S, 5).unwrap(), EX_BYTES);
        let mut padded = EX_BYTES.to_vec();
        padded.extend([0; 4]);
        assert_eq!(compress(&EX_S, 9).unwrap(), padded);
        assert_eq!(compress(&EX_S, 4), None);
    }

    #[test]
    fn compress_exact_fit_and_bound() {
        // 514 = 4·2⁷ + 2 → 13 Bit; 27 + 13 = 40 Bit
        assert!(compress(&[1, -1, 0, 514], 5).is_some());
        assert!(compress(&[1, -1, 0, 640], 5).is_none());
        assert!(compress(&[2047], 10).is_some());
        assert!(compress(&[-2047], 10).is_some());
        assert!(compress(&[2048], 10).is_none());
    }

    #[test]
    fn decompress_valid_forms() {
        assert_eq!(decompress(&EX_BYTES, 4, 5).unwrap(), EX_S);
        let mut padded = EX_BYTES.to_vec();
        padded.extend([0; 4]);
        assert_eq!(decompress(&padded, 4, 9).unwrap(), EX_S);
        // ungepolstert, kürzer und länger als die gepolsterte Länge
        assert_eq!(decompress(&EX_BYTES, 4, 9).unwrap(), EX_S);
        assert_eq!(decompress(&EX_BYTES, 4, 4).unwrap(), EX_S);
    }

    #[test]
    fn decompress_rejects() {
        assert_eq!(decompress(&[], 4, 5), None);
        // −0: 1 0000000 1
        assert_eq!(decompress(&[0x80, 0x80], 1, 2), None);
        // Füllbits nicht 0
        assert_eq!(decompress(&[0x01, 0xc0, 0xc0, 0x20, 0x49], 4, 5), None);
        // teilweise gepolstert: ungepolstert mit Nullbyte am Ende
        let mut partial = EX_BYTES.to_vec();
        partial.push(0);
        assert_eq!(decompress(&partial, 4, 9), None);
        // abgeschnitten
        assert_eq!(decompress(&EX_BYTES[..4], 4, 4), None);
        // gepolstert + ein Byte: endet nicht im letzten Byte
        let mut long = EX_BYTES.to_vec();
        long.push(0x01);
        assert_eq!(decompress(&long, 4, 5), None);
        // |s| = 2048: 16 Nullen unär (L5)
        assert_eq!(decompress(&[0x00, 0x00, 0x00, 0x80], 1, 4), None);
    }

    /// Bitfolge wie in den Python-Tests („0 0000001 1“), links ausgerichtet,
    /// mit Nullen auf volle Bytes aufgefüllt.
    fn bits(parts: &[&str]) -> Vec<u8> {
        let s: String = parts
            .concat()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut out = vec![0u8; s.len().div_ceil(8)];
        for (i, c) in s.chars().enumerate() {
            if c == '1' {
                out[i / 8] |= 0x80 >> (i % 8);
            }
        }
        out
    }

    #[test]
    fn bits_helper() {
        assert_eq!(
            bits(&["0 0000001 1", "1 0000001 1", "0 0000000 1", "0 0000010 01"]),
            EX_BYTES
        );
    }

    /// Weitere Ablehnungsfälle aus Python `TestDecompress`.
    #[test]
    fn decompress_rejects_python_cases() {
        let ex = EX_BYTES.to_vec();
        let cat = |a: &[u8], b: &[u8]| [a, b].concat();
        // −0 (Alg. 18 Z. 9–10), +0 ist gültig
        assert_eq!(
            decompress(&bits(&["0 0000000 1", "0 0000000 1"]), 2, 3).unwrap(),
            [0, 0]
        );
        assert_eq!(
            decompress(&bits(&["1 0000000 1", "0 0000000 1"]), 2, 3),
            None
        );
        // Füllbyte nicht 0 (gepolstert, 9 Bytes)
        assert_eq!(decompress(&cat(&ex, &[0, 0, 1, 0]), 4, 9), None);
        // Restbits im letzten Byte nicht 0 (ungepolstert): 0x4C = 01001|100
        assert_eq!(decompress(&cat(&ex[..4], &[0x4c]), 4, 9), None);
        // teilweise gepolstert (1..3 Nullbytes) und über die Länge hinaus (5)
        for extra in [1usize, 2, 3, 5] {
            assert_eq!(
                decompress(&cat(&ex, &vec![0; extra]), 4, 9),
                None,
                "extra {extra}"
            );
        }
        // vollständig gepolstert (4 Nullbytes) ist gültig
        assert!(decompress(&cat(&ex, &[0; 4]), 4, 9).is_some());
        // abgeschnitten, unär ohne Ende
        assert_eq!(decompress(&ex[..4], 4, 9), None);
        assert_eq!(decompress(&[0, 0, 0], 2, 3), None);
    }

    #[test]
    fn decompress_rejects_damaged_real_signatures() {
        let mut x = 0xC0DEu64;
        for &(n, plen) in &[(512usize, 625usize), (1024, 1239)] {
            let s: Vec<i16> = (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    // etwa so gross wie echte s₂ (σ ≈ 165)
                    ((x % 301) as i16) - 150
                })
                .collect();
            let enc = compress(&s, plen).unwrap();
            // ungepolstert und um ein Byte gekürzt
            let end = enc.iter().rposition(|&b| b != 0).unwrap() + 1;
            assert_eq!(decompress(&enc[..end - 1], n, plen), None);
            // ungepolstert ist gültig
            assert_eq!(decompress(&enc[..end], n, plen).unwrap(), s);
            // gepolstert plus ein Nullbyte
            let mut long = enc.clone();
            long.push(0);
            assert_eq!(decompress(&long, n, plen), None);
        }
    }

    /// KAT-Signaturen lassen sich gepolstert neu kodieren, ausser
    /// Falcon-1024 count = 82 (zu lang, Python `test_kat_1024_count_82_too_long`).
    #[test]
    fn kat_signatures_recompress() {
        use crate::params::{FALCON_1024, FALCON_512};
        for p in [&FALCON_512, &FALCON_1024] {
            for rec in kat::load_kat(p.n()) {
                let (_, sig) = kat::split_kat_sm(&rec.sm, rec.msg.len());
                let s2 = decompress(&sig[41..], p.n(), p.s2_padded_len()).unwrap();
                match compress(&s2, p.s2_padded_len()) {
                    Some(enc) => {
                        assert_eq!(decompress(&enc, p.n(), p.s2_padded_len()).unwrap(), s2)
                    }
                    None => assert!(p.n() == 1024 && rec.count == 82, "count {}", rec.count),
                }
            }
        }
    }

    #[test]
    fn decode_pk_rejects_python_cases() {
        for header in [0x19u8, 0x89, 0x59, 0x39, 0x00, 0x0B, 0x0F] {
            let mut b = vec![header];
            b.extend([0; 896]);
            assert!(decode_pk(&b).is_err(), "Header {header:#x}");
        }
        let good = kat::load_kat(512)[0].pk.clone();
        assert!(decode_pk(&good[..good.len() - 1]).is_err());
        assert!(decode_pk(&[good.as_slice(), &[0]].concat()).is_err());
        // Koeffizient q und 2¹⁴ − 1
        for v in ["11000000000001", "11111111111111"] {
            let mut b = vec![0x01];
            b.extend(bits(&[v, "00000000000000"]));
            assert!(decode_pk(&b).is_err(), "{v}");
        }
        assert_eq!(
            decode_pk(&[0x01, 0x00, 0x07, 0x00, 0x01]).err(),
            Some(Error::InvalidEncoding("Füllbits im Public Key"))
        );
    }

    #[test]
    fn decode_sk_rejects_python_cases() {
        for header in [0x09u8, 0x39, 0xD9, 0x19, 0x50, 0x5B, 0x5F] {
            let mut b = vec![header];
            b.extend([0; 1280]);
            assert!(decode_sk(&b).is_err(), "Header {header:#x}");
        }
        let good = kat::load_kat(512)[0].sk.clone();
        assert!(decode_sk(&good[..good.len() - 1]).is_err());
        assert!(decode_sk(&[good.as_slice(), &[0]].concat()).is_err());
        assert!(decode_sk(&[]).is_err());

        // Minimalwert −32 (100000) in f, in g (nach 384 Bytes), −128 in F
        let mut f_min = vec![0x59];
        f_min.extend(bits(&["100000"]));
        f_min.extend([0; 1279]);
        let mut g_min = vec![0x59];
        g_min.extend([0; 384]);
        g_min.extend(bits(&["100000"]));
        g_min.extend([0; 895]);
        let mut bigf_min = vec![0x59];
        bigf_min.extend([0; 768]);
        bigf_min.push(0x80);
        bigf_min.extend([0; 511]);
        for b in [f_min, g_min, bigf_min, vec![0x51, 0x80, 0, 0, 0, 0, 0]] {
            assert_eq!(b.len(), if b[0] == 0x59 { 1281 } else { 7 });
            assert_eq!(
                decode_sk(&b).err(),
                Some(Error::InvalidEncoding("Minimalwert im Secret Key"))
            );
        }
    }

    #[test]
    fn encode_sk_rejects_mismatched_lengths() {
        let sk = SecretPolys {
            logn: LogN::FALCON_512,
            f: vec![0; 512],
            g: vec![0; 512],
            big_f: vec![0; 256],
        };
        assert!(matches!(encode_sk(&sk), Err(Error::InvalidEncoding(_))));
        // jede der drei Längen einzeln falsch
        for wrong in 0..3 {
            let len = |k: usize| if k == wrong { 511 } else { 512 };
            let sk = SecretPolys {
                logn: LogN::FALCON_512,
                f: vec![0; len(0)],
                g: vec![0; len(1)],
                big_f: vec![0; len(2)],
            };
            assert!(
                matches!(encode_sk(&sk), Err(Error::InvalidEncoding(_))),
                "{wrong}"
            );
        }
    }

    #[test]
    fn compress_roundtrip_random() {
        let mut x = 0x1234_5678_9abc_def0u64;
        for &(n, plen) in &[(512usize, 625usize), (1024, 1239)] {
            for _ in 0..20 {
                let s: Vec<i16> = (0..n)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        ((x % 401) as i16) - 200
                    })
                    .collect();
                let enc = compress(&s, plen).unwrap();
                assert_eq!(enc.len(), plen);
                assert_eq!(decompress(&enc, n, plen).unwrap(), s);
            }
        }
    }

    #[test]
    fn pk_examples() {
        let n2 = LogN::new(1).unwrap();
        assert_eq!(encode_pk(n2, &[1, 12288]), [0x01, 0x00, 0x07, 0x00, 0x00]);
        assert_eq!(
            decode_pk(&[0x01, 0x00, 0x07, 0x00, 0x00]).unwrap(),
            (n2, vec![1, 12288])
        );
        // Füllbits nicht 0, Wert ≥ q, falscher Header, falsche Länge
        assert!(decode_pk(&[0x01, 0x00, 0x07, 0x00, 0x01]).is_err());
        assert!(decode_pk(&[0x01, 0xC0, 0x04, 0x00, 0x00]).is_err());
        assert!(decode_pk(&[0x11, 0x00, 0x07, 0x00, 0x00]).is_err());
        assert!(decode_pk(&[0x01, 0x00, 0x07, 0x00]).is_err());
        assert!(decode_pk(&[]).is_err());
    }

    #[test]
    fn sk_example_n2() {
        // f = [1, −1] → 01 FF, g = [0, −127] → 00 81, F = [127, −127] → 7F 81
        let sk = SecretPolys {
            logn: LogN::new(1).unwrap(),
            f: vec![1, -1],
            g: vec![0, -127],
            big_f: vec![127, -127],
        };
        let enc = encode_sk(&sk).unwrap();
        assert_eq!(&enc[..], [0x51, 0x01, 0xff, 0x00, 0x81, 0x7f, 0x81]);
        let back = decode_sk(&enc).unwrap();
        assert_eq!(
            (back.f.clone(), back.g.clone(), back.big_f.clone()),
            (sk.f.clone(), sk.g.clone(), sk.big_f.clone())
        );
        // Minimalwert −128 verboten
        assert!(decode_sk(&[0x51, 0x80, 0xff, 0x00, 0x81, 0x7f, 0x81]).is_err());
    }

    #[test]
    fn secret_polys_zeroize() {
        let mut sk = SecretPolys {
            logn: LogN::new(1).unwrap(),
            f: vec![5, -3],
            g: vec![1, 1],
            big_f: vec![7, 7],
        };
        sk.zeroize();
        assert!(sk.f.is_empty() && sk.g.is_empty() && sk.big_f.is_empty());
    }

    #[test]
    fn sk_rejects_out_of_range() {
        let logn = LogN::FALCON_512; // 6 Bit: erlaubt −31..=31
        let mut sk = SecretPolys {
            logn,
            f: vec![0; 512],
            g: vec![0; 512],
            big_f: vec![0; 512],
        };
        sk.f[0] = 31;
        sk.g[1] = -31;
        assert!(encode_sk(&sk).is_ok());
        sk.f[0] = 32;
        assert_eq!(encode_sk(&sk).err(), Some(Error::KeyOutOfRange));
        sk.f[0] = 0;
        sk.big_f[5] = -128;
        assert_eq!(encode_sk(&sk).err(), Some(Error::KeyOutOfRange));
    }

    #[test]
    fn kat_key_roundtrip() {
        for n in [512, 1024] {
            for rec in kat::load_kat(n) {
                let (logn, h) = decode_pk(&rec.pk).unwrap();
                assert_eq!(logn.n(), n);
                assert_eq!(encode_pk(logn, &h), rec.pk, "pk count {}", rec.count);
                let sk = decode_sk(&rec.sk).unwrap();
                let enc = encode_sk(&sk).unwrap();
                assert_eq!(&enc[..], &rec.sk[..], "sk count {}", rec.count);
                // Puffer wurde nie vergrössert, also keine ungelöschten Kopien
                assert_eq!(enc.capacity(), logn.sk_bytes());
            }
        }
    }
}
