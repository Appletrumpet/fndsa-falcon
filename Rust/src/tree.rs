//! Geheime Basis und Falcon-Baum.
//!
//! Spec-Referenz: §3.8.3, Alg. 4 (Z. 2–7), Alg. 8, Alg. 9. Entspricht
//! `Python/falcon/tree.py`; dieselbe Reihenfolge der Operationen, daher
//! bitgleich mit `Python/data/vectors/tree.*`.
//!
//! Alles hier ist geheim. Die Form des Baums hängt nur von n ab, die
//! Rekursion verzweigt also nicht auf Werten.

use zeroize::Zeroize;

use crate::fft::{fft, fft_add, fft_adj, fft_div, fft_mul, fft_sub, split_fft, Cplx, Poly};
use crate::fpr::Fpr;

/// Basis [[ĝ, −f̂], [Ĝ, −F̂]] in FFT-Form (Alg. 4, Z. 2–3).
pub struct Basis {
    pub b00: Poly,
    pub b01: Poly,
    pub b10: Poly,
    pub b11: Poly,
}

/// Falcon-Baum: Knoten (ℓ, links, rechts) oder Blatt σ. Kein `Debug`.
pub enum Tree {
    Leaf(Fpr),
    Node(Poly, Box<Tree>, Box<Tree>),
}

impl Tree {
    /// Ruft `f` für jede Zahl im Baum auf (ℓ-Werte und Blätter, feste
    /// Reihenfolge). Für die Prüfsumme des Schlüssels (Fault-Schutz).
    pub fn for_each_value(&self, f: &mut impl FnMut(Fpr)) {
        match self {
            Tree::Leaf(x) => f(*x),
            Tree::Node(l, a, b) => {
                for c in l.iter() {
                    f(c.re);
                    f(c.im);
                }
                a.for_each_value(f);
                b.for_each_value(f);
            }
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        // ℓ löscht sich selbst (Poly), das Blatt hier.
        if let Tree::Leaf(x) = self {
            x.zeroize();
        }
    }
}

/// Ganzzahliges Polynom → FFT-Form.
fn fft_ints(a: impl Iterator<Item = i64>) -> Poly {
    let v: zeroize::Zeroizing<Vec<Fpr>> = zeroize::Zeroizing::new(a.map(Fpr::of_i64).collect());
    fft(&v)
}

/// [[ĝ, −f̂], [Ĝ, −F̂]] (Alg. 4, Z. 2–3).
pub fn build_basis_fft(f: &[i8], g: &[i8], big_f: &[i8], big_g: &[i16]) -> Basis {
    Basis {
        b00: fft_ints(g.iter().map(|&x| x as i64)),
        b01: fft_ints(f.iter().map(|&x| -(x as i64))),
        b10: fft_ints(big_g.iter().map(|&x| x as i64)),
        b11: fft_ints(big_f.iter().map(|&x| -(x as i64))),
    }
}

/// Gram-Matrix B·B* (Alg. 4, Z. 4), als (G00, G01, G10, G11).
pub fn gram_matrix(b: &Basis) -> [Poly; 4] {
    let gram = |x0: &Poly, x1: &Poly, y0: &Poly, y1: &Poly| {
        fft_add(&fft_mul(x0, &fft_adj(y0)), &fft_mul(x1, &fft_adj(y1)))
    };
    [
        gram(&b.b00, &b.b01, &b.b00, &b.b01),
        gram(&b.b00, &b.b01, &b.b10, &b.b11),
        gram(&b.b10, &b.b11, &b.b00, &b.b01),
        gram(&b.b10, &b.b11, &b.b10, &b.b11),
    ]
}

/// LDL*-Zerlegung einer 2×2-Matrix (Alg. 8): (L10, D00, D11).
pub fn ldl(g00: &[Cplx], g10: &[Cplx], g11: &[Cplx]) -> (Poly, Poly, Poly) {
    let l10 = fft_div(g10, g00);
    let d00 = Poly::new(g00.to_vec());
    let d11 = fft_sub(g11, &fft_mul(&fft_mul(&l10, &fft_adj(&l10)), g00));
    (l10, d00, d11)
}

/// ffLDL* (Alg. 9): Baum rekursiv aufbauen. Wie Python: bei n = 2 sind die
/// Blätter direkt die Realteile von D00[0] und D11[0].
pub fn ff_ldl(g00: &[Cplx], g10: &[Cplx], g11: &[Cplx]) -> Tree {
    let n = g00.len();
    let (l10, d00, d11) = ldl(g00, g10, g11);
    if n == 1 {
        return Tree::Leaf(d00[0].re);
    }
    if n == 2 {
        return Tree::Node(
            l10,
            Box::new(Tree::Leaf(d00[0].re)),
            Box::new(Tree::Leaf(d11[0].re)),
        );
    }
    // Teilmatrizen [[d0, d1], [d1*, d0]]; ldl braucht davon G00, G10, G11.
    let (d0, d1) = split_fft(&d00);
    let left = ff_ldl(&d0, &fft_adj(&d1), &d0);
    let (e0, e1) = split_fft(&d11);
    let right = ff_ldl(&e0, &fft_adj(&e1), &e0);
    Tree::Node(l10, Box::new(left), Box::new(right))
}

/// Jedes Blatt zu σ/√Blatt (Alg. 4, Z. 6–7).
pub fn normalize_leaves(tree: &mut Tree, sigma: Fpr) {
    match tree {
        Tree::Leaf(x) => *x = sigma / x.sqrt(),
        Tree::Node(_, l, r) => {
            normalize_leaves(l, sigma);
            normalize_leaves(r, sigma);
        }
    }
}

/// Maske „alle Blätter liegen in [lo, hi]“ (alle Bits gesetzt = ja), ohne
/// Verzweigung auf den Werten. Prüft σ′ ∈ [σmin, σmax] (L11) einmal beim
/// Laden statt bei jedem Aufruf von SamplerZ.
pub fn leaves_in_range_mask(tree: &Tree, lo: Fpr, hi: Fpr) -> u64 {
    match tree {
        Tree::Leaf(x) => !(x.lt_mask(lo) | hi.lt_mask(*x)),
        Tree::Node(_, l, r) => leaves_in_range_mask(l, lo, hi) & leaves_in_range_mask(r, lo, hi),
    }
}

/// Falcon-Baum aus der Basis (Alg. 4, Z. 4–7).
pub fn build_falcon_tree(b: &Basis, sigma: Fpr) -> Tree {
    let [g00, _g01, g10, g11] = gram_matrix(b);
    let mut t = ff_ldl(&g00, &g10, &g11);
    normalize_leaves(&mut t, sigma);
    t
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::kat::vectors::{load, Case};

    pub fn cplxs(c: &Case, key: &str) -> Vec<Cplx> {
        c.cplx(key)
            .into_iter()
            .map(|(re, im)| Cplx::new(Fpr::from_bits(re), Fpr::from_bits(im)))
            .collect()
    }

    pub fn bits(v: &[Cplx]) -> Vec<(u64, u64)> {
        v.iter().map(|c| (c.re.to_bits(), c.im.to_bits())).collect()
    }

    /// Baum flach wie in den Vektoren: ℓ als (re, im), dann links, rechts.
    pub fn flatten(t: &Tree) -> Vec<u64> {
        match t {
            Tree::Leaf(x) => vec![x.to_bits()],
            Tree::Node(ell, l, r) => {
                let mut out: Vec<u64> = bits(ell).into_iter().flat_map(|(a, b)| [a, b]).collect();
                out.extend(flatten(l));
                out.extend(flatten(r));
                out
            }
        }
    }

    /// Umkehrung von `flatten` für einen Baum zu Grad n.
    pub fn unflatten(tok: &[u64], n: usize) -> Tree {
        fn rec(tok: &[u64], pos: &mut usize, n: usize) -> Tree {
            if n == 1 {
                *pos += 1;
                return Tree::Leaf(Fpr::from_bits(tok[*pos - 1]));
            }
            let ell: Vec<Cplx> = (0..n)
                .map(|k| {
                    Cplx::new(
                        Fpr::from_bits(tok[*pos + 2 * k]),
                        Fpr::from_bits(tok[*pos + 2 * k + 1]),
                    )
                })
                .collect();
            *pos += 2 * n;
            let l = rec(tok, pos, n / 2);
            let r = rec(tok, pos, n / 2);
            Tree::Node(Poly::new(ell), Box::new(l), Box::new(r))
        }
        let mut pos = 0;
        let t = rec(tok, &mut pos, n);
        assert_eq!(
            pos,
            tok.len(),
            "Baum hat {} Werte, erwartet {pos}",
            tok.len()
        );
        t
    }

    /// Grad aus der Zahl der Werte: T(n) = 2n·log₂ n + n.
    pub fn degree_of(tokens: usize) -> usize {
        (0..=10)
            .map(|l| 1usize << l)
            .find(|&n| 2 * n * n.trailing_zeros() as usize + n == tokens)
            .unwrap_or_else(|| panic!("keine Baumgrösse: {tokens}"))
    }

    fn basis(c: &Case, prefix: &str) -> Basis {
        let p = |k: &str| Poly::new(cplxs(c, &format!("{prefix}{k}")));
        Basis {
            b00: p("00"),
            b01: p("01"),
            b10: p("10"),
            b11: p("11"),
        }
    }

    fn i8s(c: &Case, key: &str) -> Vec<i8> {
        c.ints(key).into_iter().map(|x| x as i8).collect()
    }

    #[test]
    fn basis_matches_python() {
        for c in load("tree.build_basis_fft") {
            let g16: Vec<i16> = c.ints("G").into_iter().map(|x| x as i16).collect();
            let b = build_basis_fft(&i8s(&c, "f"), &i8s(&c, "g"), &i8s(&c, "F"), &g16);
            assert_eq!(bits(&b.b00), c.cplx("out00"), "Fall {}", c.index);
            assert_eq!(bits(&b.b01), c.cplx("out01"), "Fall {}", c.index);
            assert_eq!(bits(&b.b10), c.cplx("out10"), "Fall {}", c.index);
            assert_eq!(bits(&b.b11), c.cplx("out11"), "Fall {}", c.index);
        }
    }

    #[test]
    fn gram_matches_python() {
        for c in load("tree.gram_matrix") {
            let g = gram_matrix(&basis(&c, "B"));
            for (i, k) in ["00", "01", "10", "11"].iter().enumerate() {
                assert_eq!(bits(&g[i]), c.cplx(&format!("out{k}")), "Fall {}", c.index);
            }
        }
    }

    #[test]
    fn ldl_matches_python() {
        let cases = load("tree.ldl");
        assert!(cases.len() > 100);
        for c in cases {
            let (l, d0, d1) = ldl(&cplxs(&c, "G00"), &cplxs(&c, "G10"), &cplxs(&c, "G11"));
            assert_eq!(bits(&l), c.cplx("L10"), "Fall {}", c.index);
            assert_eq!(bits(&d0), c.cplx("D00"), "Fall {}", c.index);
            assert_eq!(bits(&d1), c.cplx("D11"), "Fall {}", c.index);
        }
    }

    #[test]
    fn ff_ldl_matches_python() {
        for c in load("tree.ff_ldl") {
            let t = ff_ldl(&cplxs(&c, "G00"), &cplxs(&c, "G10"), &cplxs(&c, "G11"));
            assert_eq!(flatten(&t), c.tree("out"), "Fall {}", c.index);
        }
    }

    #[test]
    fn normalize_matches_python() {
        for c in load("tree.normalize_leaves") {
            let tok = c.tree("t");
            let mut t = unflatten(&tok, degree_of(tok.len()));
            normalize_leaves(&mut t, Fpr::from_bits(c.float("sigma")));
            assert_eq!(flatten(&t), c.tree("out"), "Fall {}", c.index);
        }
    }

    #[test]
    fn falcon_tree_matches_python() {
        use crate::params::{FALCON_1024, FALCON_512};
        for c in load("tree.build_falcon_tree") {
            // verkleinerte Grade benutzen die Werte von Falcon-512
            let p = if c.ints("params")[0] == 1024 {
                &FALCON_1024
            } else {
                &FALCON_512
            };
            let t = build_falcon_tree(&basis(&c, "B"), Fpr::from_bits(p.sigma.to_bits()));
            assert_eq!(flatten(&t), c.tree("out"), "Fall {}", c.index);
        }
    }
}
