"""
Top-Level-Funktionen: keygen, sign, verify, Laden von Schlüsseln.

Diese Datei orchestriert die Bausteine aus Ebene 3 und bildet die
öffentliche API.

Spec-Referenz: §3.8 bis §3.10.
"""

from typing import Tuple

from .params import Params
from .datatypes import SecretKey, PublicKey, Signature
from .sampler import RNG, SYSTEM_RNG

from .ntrugen import generate_ntru_keys, recompute_G
from .tree import build_basis_fft, build_falcon_tree
from .modq import div_mod_q, mul_mod_q, center_mod_q, Q
from .hashing import hash_to_point
from .ffsampling import ff_sampling
from .fft import fft, ifft, fft_add, fft_sub, fft_mul, fft_norm_sq
from .poly import norm_sq
from .encoding import compress, decompress, decode_sk


# ---------------------------------------------------------------------------
# Top-Level API (Ebene 2)
# ---------------------------------------------------------------------------

def keygen(
    params: Params, rng: RNG = SYSTEM_RNG
) -> Tuple[SecretKey, PublicKey]:
    """Schlüsselerzeugung. Alg. 4.

    Ablauf:
      1. f, g, F, G = generate_ntru_keys(params, rng)
      2. basis_fft = build_basis_fft(f, g, F, G)
      3. tree = build_falcon_tree(basis_fft, params)
      4. h = compute_public_key(f, g, params)
      5. sk = SecretKey(f, g, F, G, basis_fft, tree)
      6. pk = PublicKey(h)
    """
    f, g, F, G = generate_ntru_keys(params, rng)
    basis_fft = build_basis_fft(f, g, F, G)
    tree = build_falcon_tree(basis_fft, params)
    h = compute_public_key(f, g, params)

    sk = SecretKey(f=f, g=g, F=F, G=G, basis_fft=basis_fft, tree=tree)
    pk = PublicKey(h=h)
    return sk, pk


def sign(
    sk: SecretKey,
    message: bytes,
    params: Params,
    rng: RNG = SYSTEM_RNG,
) -> Signature:
    """Signaturerzeugung. Alg. 10.

    Ablauf:
      1. salt = rng.random_bytes(40)
      2. c = hash_to_point(salt + message, params)
      3. t = compute_target(c, sk, params.q)
      4. while True:
           z = ff_sampling(t, sk.tree, params, rng)
           s = compute_signature_vector(t, z, sk)
           if is_short_fft(s, params): break
      5. s1, s2 = to_coefficients(s)
      6. s2_encoded = compress(s2, params)
         if s2_encoded is not None: return Signature(salt, s2_encoded)
    """
    salt = rng.random_bytes(40)
    c = hash_to_point(salt + message, params)
    t = compute_target(c, sk, params.q)

    while True:
        while True:
            z = ff_sampling(t, sk.tree, params, rng)
            s = compute_signature_vector(t, z, sk)
            if is_short_fft(s, params):
                break

        s1, s2 = to_coefficients(s)
        s2_encoded = compress(s2, params)

        if s2_encoded is not None:
            return Signature(salt=salt, s2_encoded=s2_encoded)


def verify(
    pk: PublicKey,
    message: bytes,
    sig: Signature,
    params: Params,
) -> bool:
    """Signaturverifikation. Alg. 16.

    Ablauf:
      1. c = hash_to_point(sig.salt + message, params)
      2. s2 = decompress(sig.s2_encoded, params); None → False
      3. s1 = compute_s1(c, s2, pk.h, params)
      4. return is_short(s1, s2, params)
    """
    try:
        if len(sig.salt) != 40:
            return False

        c = hash_to_point(sig.salt + message, params)
        s2 = decompress(sig.s2_encoded, params)
        if s2 is None:
            return False

        s1 = compute_s1(c, s2, pk.h, params)
        return is_short(s1, s2, params)
    except Exception:
        return False


def load_secret_key(b: bytes, params: Params) -> SecretKey:
    """Secret Key aus Bytes laden.

    decode_sk → recompute_G → build_basis_fft → build_falcon_tree.
    §3.11.5, Alg. 4, Z. 2–7.
    """
    f, g, F = decode_sk(b)

    if len(f) != params.n or len(g) != params.n or len(F) != params.n:
        raise ValueError("Secret Key passt nicht zum Parametersatz")

    G = recompute_G(f, g, F, params.q)
    basis_fft = build_basis_fft(f, g, F, G)
    tree = build_falcon_tree(basis_fft, params)

    return SecretKey(f=f, g=g, F=F, G=G, basis_fft=basis_fft, tree=tree)


# ---------------------------------------------------------------------------
# Interne Bausteine (aus Ebene 2, §5.3 / §5.4)
# ---------------------------------------------------------------------------

def compute_public_key(f: list, g: list, params: Params) -> list:
    """h = g · f⁻¹ mod q. Alg. 4, Z. 9."""
    return div_mod_q(g, f, params.q)


def compute_target(c: list, sk: SecretKey, q: int = Q) -> object:
    """(c, 0) in Koordinaten der geheimen Basis. Alg. 10, Z. 3."""
    c_hat = fft(c)
    f_hat = fft(sk.f)
    F_hat = fft(sk.F)

    t0 = [-(ch * fh) / q for ch, fh in zip(c_hat, F_hat)]
    t1 = [(ch * fh) / q for ch, fh in zip(c_hat, f_hat)]

    return (t0, t1)


def compute_signature_vector(t: object, z: object, sk: SecretKey) -> object:
    """(t - z) · basis_fft, bleibt in FFT-Form. Alg. 10, Z. 7."""
    t0, t1 = t
    z0, z1 = z
    B = sk.basis_fft

    d0 = fft_sub(t0, z0)
    d1 = fft_sub(t1, z1)

    s0 = fft_add(
        fft_mul(d0, B[0][0]),
        fft_mul(d1, B[1][0]),
    )
    s1 = fft_add(
        fft_mul(d0, B[0][1]),
        fft_mul(d1, B[1][1]),
    )

    return (s0, s1)


def is_short_fft(s: object, params: Params) -> bool:
    """fft_norm_sq beider Komponenten ≤ sig_bound. Alg. 10, Z. 8."""
    s0, s1 = s
    return (fft_norm_sq(s0) + fft_norm_sq(s1)) <= params.sig_bound


def to_coefficients(s: object) -> Tuple[list, list]:
    """ifft beider Komponenten, auf ganze Zahlen runden. Alg. 10, Z. 9."""
    s0, s1 = s
    a = [int(round(x)) for x in ifft(s0)]
    b = [int(round(x)) for x in ifft(s1)]
    return a, b


def compute_s1(c: list, s2: list, h: list, params: Params) -> list:
    """c - s2·h mod q, zentriert. Alg. 16, Z. 5."""
    s2h = mul_mod_q(s2, h, params.q)
    diff = [(ci - si) % params.q for ci, si in zip(c, s2h)]
    return center_mod_q(diff, params.q)


def is_short(s1: list, s2: list, params: Params) -> bool:
    """norm_sq(s1) + norm_sq(s2) ≤ sig_bound. Alg. 16, Z. 6."""
    return (norm_sq(s1) + norm_sq(s2)) <= params.sig_bound
