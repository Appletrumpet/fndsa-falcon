"""
FF-Sampling: rekursives und zufälliges Wählen eines Gitterpunktes nahe t.

Spec-Referenz: §3.9.2, Alg. 11.
"""

from typing import List
from .params import Params
from .sampler import RNG


def ff_sampling(
    t: object,
    tree: object,
    params: Params,
    rng: RNG,
) -> object:
    """Rekursiv und zufällig einen Gitterpunkt nahe t wählen. Alg. 11."""
    raise NotImplementedError