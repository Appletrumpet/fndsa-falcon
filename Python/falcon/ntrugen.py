"""
Erzeugung der NTRU-Schlüsselkomponenten f, g, F, G.

Spec-Referenz: §3.8.2, §4.4.3, Alg. 5–7, Gl. 3.25, 3.28, 3.29, 3.35.

Ablauf (Alg. 5):
  1. f, g kurz samplen
  2. f invertierbar mod q und Gram-Schmidt-Norm ≤ 1.17·√q ?
  3. fG - gF = q rekursiv lösen (Alg. 6)
  4. F, G gegen f, g verkleinern (Alg. 7)
  5. Bei Misserfolg: Neustart
"""

from typing import List, Optional, Tuple
from .params import Params
from .sampler import RNG


def generate_ntru_keys(
    params: Params, rng: RNG
) -> Tuple[List[int], List[int], List[int], List[int]]:
    """f, g, F, G ziehen, prüfen, lösen; bei Misserfolg Neustart. Alg. 5."""
    raise NotImplementedError


def sample_short_poly(params: Params, rng: RNG) -> List[int]:
    """Koeffizienten als Summe von 4096/n Ziehungen aus
    sample_integer_gaussian. Alg. 5, Z. 1–6; Gl. 3.29."""
    raise NotImplementedError


def gram_schmidt_norm(f: List[int], g: List[int], params: Params) -> float:
    """Qualität der Basis, Grenze 1.17·√q. Gl. 3.28."""
    raise NotImplementedError


def solve_ntru(
    f: List[int], g: List[int], params: Params
) -> Optional[Tuple[List[int], List[int]]]:
    """fG - gF = q rekursiv lösen; am Ende Prüfung der NTRU-Gleichung,
    bei Verletzung None. Alg. 6, §4.4.3."""
    raise NotImplementedError


def field_norm(a: List[int]) -> List[int]:
    """a²₀ - x·a²₁, Grad n zu Grad n/2. Gl. 3.25."""
    raise NotImplementedError


def xgcd(a: List[int], b: List[int]) -> Tuple[List[int], List[int], List[int]]:
    """Erweiterter euklidischer Algorithmus. Alg. 6, Z. 2."""
    raise NotImplementedError


def reduce(
    f: List[int], g: List[int], F: List[int], G: List[int]
) -> Tuple[List[int], List[int]]:
    """F, G gegen f, g verkleinern.

    Hinweis: Koeffizienten erreichen in der Rekursion rund 9'400 Bit und
    übersteigen den Wertebereich von Gleitkommazahlen; daher skalieren,
    k in Gleitkomma berechnen und runden, k·f und k·g exakt ganzzahlig
    abziehen, wiederholen solange die Koeffizienten kleiner werden.
    Alg. 7, §4.4.3.
    """
    raise NotImplementedError


def recompute_G(
    f: List[int], g: List[int], F: List[int]
) -> List[int]:
    """G aus der NTRU-Gleichung, für decode_sk. Gl. 3.35."""
    raise NotImplementedError