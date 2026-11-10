//! AES-256-CTR-DRBG der NIST-API (`rng.c` aus dem NIST-Paket), nur für
//! Tests: Damit lässt sich aus dem `seed` einer KAT-Datei der Zufall
//! nachbilden, den die Referenz beim Erzeugen der KAT-Schlüssel bekam
//! (PLAN.md L10). Nicht für den Produktcode.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

pub struct Drbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl Drbg {
    /// `randombytes_init(seed, NULL, 256)`
    pub fn new(seed: &[u8]) -> Drbg {
        assert_eq!(seed.len(), 48);
        let mut d = Drbg {
            key: [0; 32],
            v: [0; 16],
        };
        d.update(Some(seed));
        d
    }

    fn increment_v(&mut self) {
        for b in self.v.iter_mut().rev() {
            if *b == 0xFF {
                *b = 0;
            } else {
                *b += 1;
                break;
            }
        }
    }

    fn block(&self) -> [u8; 16] {
        let cipher = Aes256::new(&self.key.into());
        let mut b = self.v.into();
        cipher.encrypt_block(&mut b);
        b.into()
    }

    /// `AES256_CTR_DRBG_Update`
    fn update(&mut self, provided: Option<&[u8]>) {
        let mut temp = [0u8; 48];
        for i in 0..3 {
            self.increment_v();
            temp[16 * i..16 * i + 16].copy_from_slice(&self.block());
        }
        if let Some(p) = provided {
            for (t, x) in temp.iter_mut().zip(p) {
                *t ^= x;
            }
        }
        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..]);
    }

    /// `randombytes(out, len)`
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(16) {
            self.increment_v();
            let b = self.block();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        self.update(None);
    }
}
