//! Hilfen für konstante Laufzeit (PLAN.md, 3.2).
//!
//! Masken sind `0` (falsch) oder `0xFFFF_FFFF` (wahr). Alle Funktionen
//! arbeiten ohne Verzweigung.
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
//! In Phase 2 kommen die Varianten für `u64` dazu.

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
#[allow(dead_code)] // nur vom Secret-Key-Format und Keygen benutzt (Phase 4/5)
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
}
