//! Hilfen für konstante Laufzeit (PLAN.md, 3.2).
//!
//! Masken sind `0` (falsch) oder alle Bits gesetzt (wahr), als `u32` für
//! mod q und als `u64` für die emulierten Gleitkommazahlen (`fpr`). Alle
//! Funktionen arbeiten ohne Verzweigung.
//!
//! **Optimierungsbarriere (Regel 6):** Jede Maske läuft durch `barrier`.
//! Damit sieht LLVM nicht, dass eine Maske nur 0 oder −1 sein kann, und baut
//! die Auswahl nicht in einen Sprung um.
//!
//! Auf x86-64 und aarch64 ist die Barriere eine leere Assembler-Anweisung,
//! die den Wert im Register „verändern darf“. Der Compiler muss danach mit
//! einem unbekannten Wert rechnen, der Wert bleibt aber im Register.
//! `core::hint::black_box` dagegen schreibt jeden Wert auf den Stack und
//! liest ihn zurück: das kostet Zeit und lässt Masken aus geheimen Daten im
//! Stack liegen. Auf anderen Plattformen bleibt `black_box` als Rückfall.
//! Beides ist kein Nachweis; den liefert Phase 6 (Assembler, Valgrind).

/// Verbirgt den Wert vor dem Optimierer.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(always)]
pub fn barrier(mut x: u32) -> u32 {
    // SAFETY: Die Anweisung enthält nur einen Kommentar mit dem Register.
    // Sie liest und schreibt keinen Speicher, benutzt keinen Stack und
    // ändert keine Flags. `e`/`w` wählt den 32-Bit-Namen des Registers.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "/* {0:e} */",
            inout(reg) x,
            options(pure, nomem, nostack, preserves_flags)
        );
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "/* {0:w} */",
            inout(reg) x,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    x
}

/// Verbirgt den Wert vor dem Optimierer (Rückfall, siehe oben).
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
pub fn barrier(x: u32) -> u32 {
    core::hint::black_box(x)
}

/// Maske aus dem obersten Bit: `0xFFFF_FFFF`, wenn Bit 31 gesetzt ist.
#[inline(always)]
pub fn mask_from_msb(x: u32) -> u32 {
    barrier(0u32.wrapping_sub(x >> 31))
}

/// Maske „x == 0“.
#[inline(always)]
pub fn is_zero_mask(x: u32) -> u32 {
    // Das oberste Bit von x | −x ist genau dann 1, wenn x ≠ 0.
    !mask_from_msb(x | x.wrapping_neg())
}

/// Auswahl ohne Verzweigung: `b`, wenn `mask` wahr ist, sonst `a`.
#[inline(always)]
pub fn select(mask: u32, a: u32, b: u32) -> u32 {
    a ^ (mask & (a ^ b))
}

// ---------------------------------------------------------------------------
// 64 Bit (für fpr)
// ---------------------------------------------------------------------------

/// Verbirgt den Wert vor dem Optimierer (64 Bit).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(always)]
pub fn barrier64(mut x: u64) -> u64 {
    // SAFETY: wie `barrier`; ohne Zusatz ist das Register 64 Bit breit.
    unsafe {
        core::arch::asm!(
            "/* {0} */",
            inout(reg) x,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    x
}

/// Verbirgt den Wert vor dem Optimierer (64 Bit, Rückfall).
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
pub fn barrier64(x: u64) -> u64 {
    core::hint::black_box(x)
}

/// Maske aus dem obersten Bit (Bit 63).
#[inline(always)]
pub fn mask64_from_msb(x: u64) -> u64 {
    barrier64(0u64.wrapping_sub(x >> 63))
}

/// Maske aus dem untersten Bit von b (b ist 0 oder 1).
#[inline(always)]
pub fn mask64_from_bit(b: u64) -> u64 {
    barrier64(0u64.wrapping_sub(b & 1))
}

/// −v, wenn das unterste Bit von s gesetzt ist, sonst v (Zweierkomplement).
#[inline(always)]
pub fn cond_neg64(v: u64, s: u64) -> u64 {
    let m = mask64_from_bit(s);
    (v ^ m).wrapping_sub(m)
}

/// x >> n für 0 ≤ n < 64, n geheim: sechs feste Schiebungen, je über eine
/// Maske ausgewählt. Kein Schiebebefehl mit variabler Weite, damit die
/// Laufzeit auch auf CPUs ohne konstante Schiebebefehle nicht von n abhängt
/// (und Valgrind keine geheime Schiebeweite meldet).
#[inline(always)]
pub fn shr64(mut x: u64, n: u64) -> u64 {
    for j in 0..6 {
        x = select64(mask64_from_bit(n >> j), x, x >> (1u32 << j));
    }
    x
}

/// x << n für 0 ≤ n < 64, n geheim (wie `shr64`).
#[inline(always)]
pub fn shl64(mut x: u64, n: u64) -> u64 {
    for j in 0..6 {
        x = select64(mask64_from_bit(n >> j), x, x << (1u32 << j));
    }
    x
}

/// Maske „x ≠ 0“.
#[inline(always)]
pub fn mask64_nonzero(x: u64) -> u64 {
    mask64_from_msb(x | x.wrapping_neg())
}

/// Maske „a < b“ (ohne Vorzeichen). Das Borrow der Subtraktion steht im
/// obersten Bit von `(¬a ∧ b) ∨ (¬(a ⊕ b) ∧ (a − b))`.
#[inline(always)]
pub fn mask64_lt(a: u64, b: u64) -> u64 {
    mask64_from_msb((!a & b) | (!(a ^ b) & a.wrapping_sub(b)))
}

/// Auswahl ohne Verzweigung (64 Bit): `b`, wenn `mask` wahr ist, sonst `a`.
#[inline(always)]
pub fn select64(mask: u64, a: u64, b: u64) -> u64 {
    a ^ (mask & (a ^ b))
}

// ---------------------------------------------------------------------------
// Prüfung mit Valgrind (PLAN.md §6, „ctgrind“)
// ---------------------------------------------------------------------------
//
// Mit dem Feature `ctgrind` markiert `poison` geheime Bytes für Memcheck als
// „nicht initialisiert“. Memcheck meldet dann jede Verzweigung und jeden
// Speicherzugriff, dessen Adresse davon abhängt. An den erlaubten Stellen
// (PLAN.md §6, Tabelle der freigegebenen Verzweigungen) gibt `declassify`
// das Ergebnis frei. Ohne das Feature sind alle Funktionen leer.
//
// Die Aufrufe an Valgrind sind die dokumentierten „client requests“: eine
// Folge von Rotationen, die ohne Valgrind nichts bewirkt (zusammen 128 Bit
// = keine Änderung), und die Valgrind erkennt.

#[cfg(feature = "ctgrind")]
mod vg {
    const MC: u64 = ((b'M' as u64) << 24) | ((b'C' as u64) << 16);
    pub const MAKE_MEM_UNDEFINED: u64 = MC + 1;
    pub const MAKE_MEM_DEFINED: u64 = MC + 2;

    /// Client Request an Valgrind; ohne Valgrind wirkungslos.
    #[inline(never)]
    pub fn request(req: u64, addr: u64, len: u64) {
        let args: [u64; 6] = [req, addr, len, 0, 0, 0];
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Die Folge ändert keine Register ausser rdx (Ergebnis) und
        // den Flags; rdi wird um 128 Bit rotiert, also nicht verändert.
        unsafe {
            core::arch::asm!(
                "rol rdi, 3",
                "rol rdi, 13",
                "rol rdi, 61",
                "rol rdi, 51",
                "xchg rbx, rbx",
                inout("rdx") 0u64 => _,
                in("rax") args.as_ptr(),
                inout("rdi") 0u64 => _,
            );
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: wie oben; x12 wird um 128 Bit rotiert, x3 ist das Ergebnis.
        unsafe {
            core::arch::asm!(
                "ror x12, x12, #3",
                "ror x12, x12, #13",
                "ror x12, x12, #51",
                "ror x12, x12, #61",
                "orr x10, x10, x10",
                inout("x3") 0u64 => _,
                in("x4") args.as_ptr(),
                inout("x12") 0u64 => _,
            );
        }
        let _ = &args;
    }
}

/// Markiert Speicher als geheim (für Valgrind „nicht initialisiert“).
///
/// Nimmt `&mut`: Bei `&[T]` darf der Compiler annehmen, dass sich die Daten
/// nicht ändern, und mit einer früheren (unmarkierten) Kopie weiterrechnen;
/// dann sähe Valgrind die Markierung nicht (Befund des Selbsttests).
#[allow(unused_variables)]
#[cfg_attr(not(feature = "ctgrind"), allow(dead_code))]
#[inline(always)]
pub fn poison<T>(data: &mut [T]) {
    #[cfg(feature = "ctgrind")]
    vg::request(
        vg::MAKE_MEM_UNDEFINED,
        data.as_ptr() as u64,
        core::mem::size_of_val(data) as u64,
    );
}

/// Markiert Speicher als öffentlich (z. B. s₂ nach der Annahme, h).
#[allow(unused_variables)]
#[inline(always)]
pub fn unpoison<T>(data: &[T]) {
    #[cfg(feature = "ctgrind")]
    vg::request(
        vg::MAKE_MEM_DEFINED,
        data.as_ptr() as u64,
        core::mem::size_of_val(data) as u64,
    );
}

/// Gibt einen aus geheimen Daten berechneten Wert frei, an einer erlaubten
/// Verzweigung (PLAN.md §6). Ohne `ctgrind` die Identität.
#[inline(always)]
pub fn declassify<T: Copy>(x: T) -> T {
    #[cfg(feature = "ctgrind")]
    {
        let v = [x];
        unpoison(&v);
        // SAFETY: v ist ein gültiger, initialisierter Wert auf dem Stack.
        unsafe { core::ptr::read_volatile(&v[0]) }
    }
    #[cfg(not(feature = "ctgrind"))]
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(mask_from_msb(0), 0);
        assert_eq!(mask_from_msb(0x8000_0000), u32::MAX);
        for x in [0u32, 1, 2, 12288, 0x7FFF_FFFF, 0x8000_0000, u32::MAX] {
            assert_eq!(is_zero_mask(x), if x == 0 { u32::MAX } else { 0 });
        }
        assert_eq!(select(0, 3, 7), 3);
        assert_eq!(select(u32::MAX, 3, 7), 7);
    }

    #[test]
    fn masks64() {
        let vals = [
            0u64,
            1,
            2,
            0x7FFF_FFFF_FFFF_FFFF,
            1 << 63,
            u64::MAX - 1,
            u64::MAX,
        ];
        for &a in &vals {
            assert_eq!(mask64_nonzero(a), if a != 0 { u64::MAX } else { 0 });
            for &b in &vals {
                assert_eq!(
                    mask64_lt(a, b),
                    if a < b { u64::MAX } else { 0 },
                    "{a} < {b}"
                );
            }
        }
        assert_eq!(select64(0, 3, 7), 3);
        assert_eq!(select64(u64::MAX, 3, 7), 7);
        assert_eq!(mask64_from_bit(0), 0);
        assert_eq!(mask64_from_bit(1), u64::MAX);
        assert_eq!(cond_neg64(5, 0), 5);
        assert_eq!(cond_neg64(5, 1), 5u64.wrapping_neg());
        assert_eq!(cond_neg64(1 << 63, 1), 1 << 63);
        for n in 0..64u64 {
            for x in [1u64, 0xDEAD_BEEF_0123_4567, u64::MAX] {
                assert_eq!(shr64(x, n), x >> n);
                assert_eq!(shl64(x, n), x << n);
            }
        }
    }
}
