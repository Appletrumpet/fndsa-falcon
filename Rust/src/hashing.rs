//! HashToPoint: Nachricht auf ein Polynom in ℤ_q[x]/(xⁿ+1) abbilden.
//!
//! Spec-Referenz: §3.7, Alg. 3. Entspricht `Python/falcon/hashing.py`.
//!
//! Variable Laufzeit ist hier erlaubt: Salt und Nachricht sind öffentlich
//! (PLAN.md, 3.1). Deshalb normale Verzweigung und `%`.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::params::Q;

/// k·q mit k = ⌊2¹⁶/q⌋ = 5: Werte ab hier werden verworfen.
const LIMIT: u32 = (65536 / Q) * Q;

/// SHAKE256(salt ‖ msg), je 16 Bit big-endian lesen, Werte < 5q annehmen,
/// Koeffizient = Wert mod q. Alg. 3.
pub fn hash_to_point(salt: &[u8], msg: &[u8], n: usize) -> Vec<u16> {
    let mut h = Shake256::default();
    h.update(salt);
    h.update(msg);
    let mut xof = h.finalize_xof();

    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 2];
    while out.len() < n {
        xof.read(&mut buf);
        let w = u16::from_be_bytes(buf) as u32;
        if w < LIMIT {
            out.push((w % Q) as u16);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Beispiele aus Python/tests/test_hashing.py (von Hand nachgerechnet).

    #[test]
    fn empty_input() {
        assert_eq!(
            hash_to_point(b"", b"", 8),
            [5816, 7463, 2984, 11537, 9019, 4074, 5180, 11040]
        );
    }

    #[test]
    fn rejected_chunks_are_skipped() {
        assert_eq!(hash_to_point(b"Falcon\r", b"", 2), [11884, 6864]);
        assert_eq!(hash_to_point(b"Falcon\x04", b"", 4), [1733, 2891, 860, 11018]);
    }

    #[test]
    fn boundary() {
        // 61444 = 5q − 1 wird angenommen, 61445 = 5q verworfen.
        assert_eq!(hash_to_point(&[0x00, 0x01, 0x1c, 0x0a], b"", 2), [12288, 7737]);
        assert_eq!(hash_to_point(&[0x00, 0x00, 0x35, 0xaf], b"", 2), [11137, 6189]);
    }

    #[test]
    fn salt_and_message_are_concatenated() {
        assert_eq!(hash_to_point(b"Fal", b"con\r", 2), hash_to_point(b"Falcon\r", b"", 2));
    }
}
