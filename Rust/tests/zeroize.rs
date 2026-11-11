//! Löschtest: Bleiben Teile des geheimen Schlüssels in freigegebenem
//! Speicher zurück?
//!
//! Ein eigener Speicherverwalter durchsucht jeden freigegebenen Block nach
//! Stücken von f, g und F (je 32 aufeinanderfolgende Koeffizienten als
//! `i8` und f zusätzlich als Werte mod q in `u32`, wie in der NTT). Findet
//! er eines, wurde ein Puffer mit geheimen Daten nicht gelöscht
//! (`zeroize`). Geprüft werden Keygen, Speichern, Laden, Sign und das
//! Verwerfen des Schlüssels.
//!
//! Grenze: Nur Heap-Speicher wird geprüft, nicht Stack und Register (siehe
//! README, „Bekannte Grenze“), und nur die Darstellungen oben.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fndsa::{keygen_from_seed, LogN, SigningKey};
use rand_core::{CryptoRng, RngCore};

const NEEDLES: usize = 4;
const LEN: usize = 32;

/// Gesuchte Muster; werden vor dem Scharfschalten gesetzt und danach nur
/// gelesen (im Speicherverwalter darf nichts angelegt werden).
static mut NEEDLE: [[u8; LEN]; NEEDLES] = [[0; LEN]; NEEDLES];
static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: [AtomicUsize; NEEDLES] = [const { AtomicUsize::new(0) }; NEEDLES];

struct Scan;

unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) && layout.size() >= LEN {
            // SAFETY: Der Block gehört bis zum Aufruf von System.dealloc noch
            // dem Programm und ist layout.size() Bytes lang.
            let block = std::slice::from_raw_parts(ptr, layout.size());
            // SAFETY: NEEDLE wird nur geschrieben, solange ARMED falsch ist.
            let needles = &*std::ptr::addr_of!(NEEDLE);
            for (k, n) in needles.iter().enumerate() {
                if block.windows(LEN).any(|w| w == n) {
                    HITS[k].fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Scan = Scan;

/// Liest `count` vorzeichenbehaftete Werte zu `width` Bit (MSB zuerst).
fn read_signed(b: &[u8], bitpos: &mut usize, width: usize, count: usize) -> Vec<i8> {
    (0..count)
        .map(|_| {
            let mut v = 0u32;
            for _ in 0..width {
                v = (v << 1) | ((b[*bitpos / 8] >> (7 - *bitpos % 8)) & 1) as u32;
                *bitpos += 1;
            }
            // Zweierkomplement auf width Bit
            ((v << (32 - width)) as i32 >> (32 - width)) as i8
        })
        .collect()
}

struct Rng(u64);
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, d: &mut [u8]) {
        d.iter_mut().for_each(|b| *b = self.next_u64() as u8);
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(d);
        Ok(())
    }
}
impl CryptoRng for Rng {}

#[test]
fn no_secret_left_in_freed_memory() {
    let seed = [0x77u8; 48];
    // Einmal ohne Prüfung erzeugen, um f, g, F zu kennen (Keygen ist
    // deterministisch, der zweite Lauf ergibt denselben Schlüssel).
    let sk_bytes = keygen_from_seed(LogN::FALCON_512, &seed)
        .unwrap()
        .0
        .to_bytes();
    let mut pos = 8;
    let f = read_signed(&sk_bytes, &mut pos, 6, 512);
    let g = read_signed(&sk_bytes, &mut pos, 6, 512);
    let big_f = read_signed(&sk_bytes, &mut pos, 8, 512);
    // Stücke aus der Mitte (der Anfang könnte zufällig oft vorkommen)
    let mut needles = [[0u8; LEN]; NEEDLES];
    for (n, src) in needles.iter_mut().zip([&f, &g, &big_f]) {
        for (d, &x) in n.iter_mut().zip(&src[100..100 + LEN]) {
            *d = x as u8;
        }
    }
    // f mod q als u32 little-endian (8 Koeffizienten)
    for (i, &x) in f[200..208].iter().enumerate() {
        let v = (x as i32).rem_euclid(12289) as u32;
        needles[3][4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    // SAFETY: ARMED ist falsch, niemand liest NEEDLE gleichzeitig.
    unsafe { NEEDLE = needles };
    drop((f, g, big_f));

    ARMED.store(true, Ordering::SeqCst);
    {
        let (sk, pk) = keygen_from_seed(LogN::FALCON_512, &seed).unwrap();
        let bytes = sk.to_bytes();
        let loaded = SigningKey::from_bytes(&bytes).unwrap();
        drop(bytes);
        let mut rng = Rng(5);
        for i in 0..3u8 {
            let sig = loaded.sign(&[i], &mut rng);
            assert!(pk.verify(&[i], &sig));
            let _ = loaded.try_sign(&[i, i], &mut rng).unwrap();
        }
        drop(loaded);
        drop(sk);
    }
    ARMED.store(false, Ordering::SeqCst);
    drop(sk_bytes);

    let hits: Vec<usize> = HITS.iter().map(|h| h.load(Ordering::SeqCst)).collect();
    assert_eq!(
        hits, [0; NEEDLES],
        "ungelöschte Kopien von [f, g, F, f mod q] in freigegebenem Speicher"
    );

    // Gegenprobe: ein absichtlich nicht gelöschter Puffer mit f muss
    // gemeldet werden, sonst greift die Suche nicht.
    ARMED.store(true, Ordering::SeqCst);
    let leak = std::hint::black_box(needles[0].to_vec());
    drop(leak);
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(
        HITS[0].load(Ordering::SeqCst),
        1,
        "Gegenprobe nicht erkannt"
    );
}
