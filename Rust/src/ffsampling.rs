//! ffSampling: rekursiv und zufällig einen Gitterpunkt nahe t wählen.
//!
//! Spec-Referenz: §3.9.2, Alg. 11. Entspricht `Python/falcon/ffsampling.py`;
//! gleiche Reihenfolge, daher bitgleich mit
//! `Python/data/vectors/ffsampling.ff_sampling.txt`.
//!
//! t, z und der Baum sind geheim. Die Rekursion folgt der Form des Baums,
//! die nur von n abhängt.

use crate::fft::{fft_add, fft_mul, fft_sub, merge_fft, split_fft, Cplx, Poly};
use crate::fpr::Fpr;
use crate::params::Params;
use crate::prng::RandomSource;
use crate::sampler::sampler_z;
use crate::tree::Tree;

/// Alg. 11: (z₀, z₁) nahe (t₀, t₁) für den Falcon-Baum `tree`.
pub fn ff_sampling(
    t0: &[Cplx],
    t1: &[Cplx],
    tree: &Tree,
    params: &Params,
    rng: &mut impl RandomSource,
) -> (Poly, Poly) {
    match tree {
        Tree::Leaf(sigma) => {
            let z0 = sampler_z(t0[0].re, *sigma, params, rng);
            let z1 = sampler_z(t1[0].re, *sigma, params, rng);
            let c = |z: i64| Poly::new(vec![Cplx::new(Fpr::of_i64(z), Fpr::ZERO)]);
            (c(z0), c(z1))
        }
        Tree::Node(ell, left, right) => {
            // Rechter Teilbaum zuerst.
            let (a, b) = split_fft(t1);
            let (za, zb) = ff_sampling(&a, &b, right, params, rng);
            let z1 = merge_fft(&za, &zb);

            // t₀′ = t₀ + (t₁ − z₁)·ℓ
            let diff = fft_sub(t1, &z1);
            let t0p = fft_add(t0, &fft_mul(&diff, ell));

            let (a, b) = split_fft(&t0p);
            let (za, zb) = ff_sampling(&a, &b, left, params, rng);
            let z0 = merge_fft(&za, &zb);
            (z0, z1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::vectors::load;
    use crate::params::{FALCON_1024, FALCON_512};
    use crate::prng::testing::Replay;
    use crate::tree::tests::{bits, cplxs, unflatten};

    #[test]
    fn ff_sampling_matches_python() {
        let cases = load("ffsampling.ff_sampling");
        assert!(!cases.is_empty());
        for c in cases {
            let t0 = cplxs(&c, "t0");
            let tree = unflatten(&c.tree("tree"), t0.len());
            let p = if c.ints("params")[0] == 1024 {
                &FALCON_1024
            } else {
                &FALCON_512
            };
            let mut src = Replay::new(c.bytes("random"));
            let (z0, z1) = ff_sampling(&t0, &cplxs(&c, "t1"), &tree, p, &mut src);
            assert_eq!(bits(&z0), c.cplx("out0"), "Fall {}", c.index);
            assert_eq!(bits(&z1), c.cplx("out1"), "Fall {}", c.index);
            assert_eq!(src.remaining(), 0, "Fall {}: Bytes übrig", c.index);
        }
    }
}
