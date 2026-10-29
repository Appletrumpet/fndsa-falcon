"""
FF-Sampling: rekursives und zufälliges Wählen eines Gitterpunktes nahe t.

Spec-Referenz: §3.9.2, Alg. 11.
"""

from typing import List
from .params import Params
from .sampler import RNG, sample_integer_gaussian
from .fft import split_fft, merge_fft, fft_add, fft_sub, fft_mul


def _is_leaf(t: object) -> bool:
    return isinstance(t, (int, float)) and not isinstance(t, bool)


def ff_sampling(
    t: object,
    tree: object,
    params: Params,
    rng: RNG,
) -> object:
    """Rekursiv und zufällig einen Gitterpunkt nahe t wählen. Alg. 11."""
    t0, t1 = t

    if _is_leaf(tree):
        sigma = float(tree)
        z0 = sample_integer_gaussian(t0[0].real, sigma, params, rng)
        z1 = sample_integer_gaussian(t1[0].real, sigma, params, rng)
        return ([complex(z0)], [complex(z1)])

    ell, left, right = tree

    # Rechter Teilbaum zuerst (Alg. 11).
    z1_split = ff_sampling(split_fft(t1), right, params, rng)
    z1 = merge_fft(z1_split[0], z1_split[1])

    # t0' = t0 + (t1 - z1) * ell
    diff = fft_sub(t1, z1)
    t0_prime = fft_add(t0, fft_mul(diff, ell))

    z0_split = ff_sampling(split_fft(t0_prime), left, params, rng)
    z0 = merge_fft(z0_split[0], z0_split[1])

    return (z0, z1)
