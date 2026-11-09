#!/usr/bin/env python3
"""Erzeugt die Testvektoren für die Portierungen nach C und Rust (Ebene 5).

Ein Aufzeichner umhüllt die Bausteine aus Ebene 3 und schreibt beim Durchlauf
von keygen, sign und verify Ein- und Ausgaben mit. Dazu kommen gezielte
Rand- und Ablehnungsfälle, die im normalen Ablauf nicht vorkommen.

Ablage: data/vectors/<modul>.<funktion>.txt, zeilenbasierter Text:

    # Kommentar
    case
    <feld> <art> <anzahl> <werte ...>
    status ok|none|error

Arten: int (Dezimal, beliebig gross), ints, bytes (Hex, leer: -), float und
floats (64-Bit-Muster hex), cplx (Paare von 64-Bit-Mustern), bool, tree (Baum in
Vorordnung: je Knoten ℓ als Paare, je Blatt ein Muster; Form folgt aus n).
Vergleich in den Portierungen: bitgenau, ohne Toleranz.

Aufruf aus Python/:  python scripts/gen_vectors.py
"""

import hashlib
import math
import platform
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from falcon import encoding, falcon as top, ffsampling, fft, hashing  # noqa: E402
from falcon import modq, ntrugen, poly, sampler, tree  # noqa: E402
from falcon.datatypes import Signature  # noqa: E402
from falcon.params import FALCON_512, FALCON_1024  # noqa: E402
from support import ShakeRNG, load_kat  # noqa: E402
import dataclasses  # noqa: E402

OUT = ROOT / "data" / "vectors"
REQUIRED_PYTHON = (3, 14)
MODULES = [modq, poly, fft, hashing, sampler, encoding, tree, ffsampling, ntrugen, top]


# ---------------------------------------------------------------------------
# Vorabprüfung: Ist dieser Python-Build reproduzierbar?
# ---------------------------------------------------------------------------

def preflight() -> None:
    if sys.version_info[:2] != REQUIRED_PYTHON:
        sys.exit(f"Abbruch: Python {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]} erforderlich "
                 f"(Vorzeichen von Nullen in gemischter Arithmetik)")
    if math.copysign(1.0, (complex(-0.0, 1.0) / 2).real) != -1.0:
        sys.exit("Abbruch: unerwartete Division complex/real")
    r = random.Random(1)
    for _ in range(20000):
        a = complex(r.uniform(-1e4, 1e4), r.uniform(-1e4, 1e4))
        b = complex(r.uniform(-1e4, 1e4), r.uniform(-1e4, 1e4))
        p = a * b
        if (p.real, p.imag) != (a.real * b.real - a.imag * b.imag,
                                a.real * b.imag + a.imag * b.real):
            sys.exit("Abbruch: komplexe Multiplikation dieses Builds nutzt FMA")


# ---------------------------------------------------------------------------
# Schreiben der Felder
# ---------------------------------------------------------------------------

def bits(x: float) -> str:
    return f"{struct.unpack('>Q', struct.pack('>d', float(x)))[0]:016x}"


def line(name, kind, values):
    values = list(values)
    return f"{name} {kind} {len(values)}" + "".join(" " + v for v in values)


def tree_tokens(t):
    if isinstance(t, (int, float)):
        return [bits(t)]
    ell, left, right = t
    out = []
    for c in ell:
        out += [bits(c.real), bits(c.imag)]
    return out + tree_tokens(left) + tree_tokens(right)


def cplx_tokens(v):
    return [tok for c in v for tok in (bits(c.real), bits(c.imag))]


def emit(name, kind, v):
    """Liefert die Zeilen eines Feldes."""
    if kind == "int":
        return [f"{name} int 1 {v}"]
    if kind == "bool":
        return [f"{name} bool 1 {int(bool(v))}"]
    if kind == "float":
        return [f"{name} float 1 {bits(v)}"]
    if kind == "ints":
        return [line(name, "ints", (str(x) for x in v))]
    if kind == "real":                      # ganze Zahlen oder Gleitkomma
        return [line(name, "floats", (bits(x) for x in v))]
    if kind == "floats":
        return [line(name, "floats", (bits(x) for x in v))]
    if kind == "bytes":
        return [f"{name} bytes {len(v)} {bytes(v).hex() or '-'}"]
    if kind == "cplx":
        return [f"{name} cplx {len(v)}" + "".join(" " + t for t in cplx_tokens(v))]
    if kind == "cplx2":
        return emit(name + "0", "cplx", v[0]) + emit(name + "1", "cplx", v[1])
    if kind == "cplx22":
        return [ln for i in (0, 1) for j in (0, 1)
                for ln in emit(f"{name}{i}{j}", "cplx", v[i][j])]
    if kind == "ints2":
        return emit(name + "0", "ints", v[0]) + emit(name + "1", "ints", v[1])
    if kind == "ints3":
        return [ln for i in (0, 1, 2) for ln in emit(f"{name}{i}", "ints", v[i])]
    if kind == "ints4":
        return [ln for i in (0, 1, 2, 3) for ln in emit(f"{name}{i}", "ints", v[i])]
    if kind == "int3":
        return [ln for i in (0, 1, 2) for ln in emit(f"{name}{i}", "int", v[i])]
    if kind == "tree":
        return [line(name, "tree", tree_tokens(v))]
    if kind == "params":
        return [f"{name} ints 2 {v.n} {v.sig_bytelen}"]
    if kind == "sig":
        return emit(name + "_salt", "bytes", v.salt) + emit(name + "_s2", "bytes", v.s2_encoded)
    if kind == "pk":
        return emit(name, "ints", v.h)
    if kind == "sk":
        return (emit("f", "ints", v.f) + emit("g", "ints", v.g) + emit("F", "ints", v.F)
                + emit("G", "ints", v.G) + emit("basis", "cplx22", v.basis_fft))
    if kind == "msg_sig":
        return emit("msg", "bytes", v[0]) + emit(name, "sig", v[1])
    raise ValueError(kind)


# ---------------------------------------------------------------------------
# Aufzeichner
# ---------------------------------------------------------------------------

class RecordingRNG:
    """Protokolliert alle gelesenen Bytes (rng-Felder der Vektoren)."""

    def __init__(self, inner):
        self.inner = inner
        self.log = bytearray()

    def random_bytes(self, k):
        out = self.inner.random_bytes(k)
        self.log += out
        return out


records = {}        # Dateiname → Liste von Fällen (je Fall: Liste von Zeilen)
counts = {}
recording = {"on": True}


def add_case(file, lines):
    records.setdefault(file, []).append(lines)


def record(file, argspec, outspec, args, status, result, rng_bytes):
    lines = ["case"]
    for (name, kind), value in zip(argspec, args):
        if kind != "skip" and kind != "rng":
            lines += emit(name, kind, value)
    if rng_bytes is not None:
        lines += emit("random", "bytes", rng_bytes)
    lines.append(f"status {status}")
    if status == "ok":
        lines += emit("out", outspec, result)
    add_case(file, lines)


def size_of(args):
    for a in args:
        if isinstance(a, (list, tuple, bytes, bytearray)):
            return len(a)
    return 0


def wrap(module, name, argspec, outspec, cap, by_size=True):
    file = f"{module.__name__.split('.')[-1]}.{name.lstrip('_')}"
    original = getattr(module, name)

    def wrapper(*args):
        key = (file, size_of(args) if by_size else 0)
        take = recording["on"] and counts.get(key, 0) < cap
        rng = next((a for a in args if isinstance(a, RecordingRNG)), None)
        start = len(rng.log) if rng is not None else 0
        try:
            result = original(*args)
        except Exception:
            if take:
                counts[key] = counts.get(key, 0) + 1
                record(file, argspec, outspec, args, "error", None,
                       None if rng is None else bytes(rng.log[start:]))
            raise
        if take:
            counts[key] = counts.get(key, 0) + 1
            status = "none" if result is None else "ok"
            record(file, argspec, outspec, args, status, result,
                   None if rng is None else bytes(rng.log[start:]))
        return result

    for m in MODULES:
        if getattr(m, name, None) is original:
            setattr(m, name, wrapper)
    return wrapper


def A(*spec):
    return [tuple(s.split(":")) for s in spec]


CAP, MANY, FEW = 4, 300, 2

WRAPS = [
    (modq, "ntt", A("a:ints", "q:skip"), "ints", CAP),
    (modq, "intt", A("a:ints", "q:skip"), "ints", CAP),
    (modq, "mul_mod_q", A("a:ints", "b:ints", "q:skip"), "ints", CAP),
    (modq, "div_mod_q", A("a:ints", "b:ints", "q:skip"), "ints", CAP),
    (modq, "is_invertible_mod_q", A("a:ints", "q:skip"), "bool", CAP),
    (modq, "center_mod_q", A("a:ints", "q:skip"), "ints", CAP),
    (poly, "poly_add", A("a:ints", "b:ints"), "ints", CAP),
    (poly, "poly_sub", A("a:ints", "b:ints"), "ints", FEW),
    (poly, "poly_neg", A("a:ints"), "ints", CAP),
    (poly, "poly_mul", A("a:ints", "b:ints"), "ints", FEW),
    (poly, "split", A("a:ints"), "ints2", CAP),
    (poly, "lift", A("a:ints"), "ints", FEW),
    (poly, "galois_conjugate", A("a:ints"), "ints", FEW),
    (poly, "norm_sq", A("a:ints"), "int", CAP),
    (fft, "fft", A("a:real"), "cplx", CAP),
    (fft, "ifft", A("a:cplx"), "floats", CAP),
    (fft, "fft_add", A("a:cplx", "b:cplx"), "cplx", CAP),
    (fft, "fft_sub", A("a:cplx", "b:cplx"), "cplx", CAP),
    (fft, "fft_mul", A("a:cplx", "b:cplx"), "cplx", CAP),
    (fft, "fft_div", A("a:cplx", "b:cplx"), "cplx", CAP),
    (fft, "fft_adj", A("a:cplx"), "cplx", CAP),
    (fft, "fft_norm_sq", A("a:cplx"), "float", CAP),
    (fft, "split_fft", A("a:cplx"), "cplx2", CAP),
    (fft, "merge_fft", A("a0:cplx", "a1:cplx"), "cplx", CAP),
    (hashing, "hash_to_point", A("data:bytes", "params:params"), "ints", CAP),
    (sampler, "uniform_bits", A("k:int", "rng:rng"), "int", MANY),
    (sampler, "base_sampler", A("rng:rng"), "int", MANY),
    (sampler, "approx_exp", A("x:float", "ccs:float"), "int", MANY),
    (sampler, "ber_exp", A("x:float", "ccs:float", "rng:rng"), "bool", MANY),
    (sampler, "sample_integer_gaussian",
     A("mu:float", "sigma:float", "params:params", "rng:rng"), "int", MANY),
    (encoding, "compress", A("s:ints", "params:params"), "bytes", CAP),
    (encoding, "decompress", A("b:bytes", "params:params"), "ints", CAP),
    (encoding, "encode_pk", A("h:ints", "q:skip"), "bytes", CAP),
    (encoding, "decode_pk", A("b:bytes", "q:skip"), "ints", CAP),
    (encoding, "encode_sk", A("f:ints", "g:ints", "F:ints"), "bytes", CAP),
    (encoding, "decode_sk", A("b:bytes"), "ints3", CAP),
    (encoding, "encode_sig", A("sig:sig", "params:params"), "bytes", CAP),
    (encoding, "decode_sig", A("b:bytes", "params:params"), "sig", CAP),
    (encoding, "decode_kat_message", A("sm:bytes"), "msg_sig", CAP),
    (tree, "build_basis_fft", A("f:ints", "g:ints", "F:ints", "G:ints"), "cplx22", CAP),
    (tree, "gram_matrix", A("B:cplx22"), "cplx22", CAP),
    (tree, "ff_ldl", A("G:cplx22"), "tree", FEW),
    (tree, "normalize_leaves", A("t:tree", "sigma:float"), "tree", FEW),
    (tree, "build_falcon_tree", A("B:cplx22", "params:params"), "tree", FEW),
    (ffsampling, "ff_sampling",
     A("t:cplx2", "tree:tree", "params:params", "rng:rng"), "cplx2", FEW),
    (ntrugen, "sample_short_poly", A("params:params", "rng:rng"), "ints", FEW),
    (ntrugen, "gram_schmidt_norm", A("f:ints", "g:ints", "params:params"), "float", CAP),
    (ntrugen, "solve_ntru", A("f:ints", "g:ints", "params:params"), "ints2", FEW),
    (ntrugen, "field_norm", A("a:ints"), "ints", FEW),
    (ntrugen, "reduce", A("f:ints", "g:ints", "F:ints", "G:ints"), "ints2", FEW),
    (ntrugen, "recompute_G", A("f:ints", "g:ints", "F:ints", "q:skip"), "ints", CAP),
    (top, "compute_public_key", A("f:ints", "g:ints", "params:params"), "ints", CAP),
    (top, "compute_target", A("c:ints", "sk:sk", "q:skip"), "cplx2", CAP),
    (top, "compute_signature_vector", A("t:cplx2", "z:cplx2", "sk:sk"), "cplx2", CAP),
    (top, "is_short_fft", A("s:cplx2", "params:params"), "bool", CAP),
    (top, "to_coefficients", A("s:cplx2"), "ints2", CAP),
    (top, "compute_s1", A("c:ints", "s2:ints", "h:ints", "params:params"), "ints", CAP),
    (top, "is_short", A("s1:ints", "s2:ints", "params:params"), "bool", CAP),
]

# Skalare Hilfsfunktionen: Anzahl unabhängig von einer Länge begrenzen.
SCALAR_WRAPS = [
    (ntrugen, "xgcd", A("a:int", "b:int"), "int3", MANY),
    (ntrugen, "_scaled_float", A("c:int", "scale:int"), "float", MANY),
    (ntrugen, "_round_scaled_float", A("x:float", "exp:int"), "int", MANY),
]

# ldl liefert drei Felder unterschiedlicher Art; eigene Behandlung.
def wrap_ldl():
    original = tree.ldl

    def wrapper(G):
        result = original(G)
        key = ("tree.ldl", len(G[0][0]))
        if recording["on"] and counts.get(key, 0) < CAP:
            counts[key] = counts.get(key, 0) + 1
            add_case("tree.ldl", ["case"] + emit("G", "cplx22", G) + ["status ok"]
                     + emit("L10", "cplx", result[0]) + emit("D00", "cplx", result[1])
                     + emit("D11", "cplx", result[2]))
        return result

    tree.ldl = wrapper


# ---------------------------------------------------------------------------
# Abläufe und Randfälle
# ---------------------------------------------------------------------------

def flows() -> None:
    """Ganze Abläufe; der Zufall steht als Startwert in der Datei."""
    for params, seed_text in ((FALCON_512, b"flow-512"), (FALCON_1024, b"flow-1024")):
        n = params.n
        rng = RecordingRNG(ShakeRNG(seed_text))
        sk, pk = top.keygen(params, rng)
        add_case("flow.keygen", ["case"] + emit("seed", "bytes", seed_text)
                 + emit("n", "int", n) + emit("key", "ints4", (sk.f, sk.g, sk.F, sk.G))
                 + emit("h", "ints", pk.h) + ["status ok"])
        sk_bytes = encoding.encode_sk(sk.f, sk.g, sk.F)
        for i in range(3):
            msg = f"message {i} for falcon-{n}".encode()
            seed = seed_text + b"-sign-%d" % i
            sig = top.sign(top.load_secret_key(sk_bytes, params), msg, params,
                           RecordingRNG(ShakeRNG(seed)))
            sig_bytes = encoding.encode_sig(sig, params)
            add_case("flow.sign", ["case"] + emit("seed", "bytes", seed)
                     + emit("n", "int", n) + emit("sk", "bytes", sk_bytes)
                     + emit("msg", "bytes", msg) + emit("sig", "bytes", sig_bytes)
                     + ["status ok"])
            verdict = top.verify(pk, msg, sig, params)
            bad = bytearray(msg)
            bad[0] ^= 1
            rejected = top.verify(pk, bytes(bad), sig, params)
            add_case("flow.verify", ["case"] + emit("n", "int", n) + emit("h", "ints", pk.h)
                     + emit("msg", "bytes", msg) + emit("sig", "bytes", sig_bytes)
                     + ["status ok"] + emit("out", "bool", verdict))
            add_case("flow.verify", ["case"] + emit("n", "int", n) + emit("h", "ints", pk.h)
                     + emit("msg", "bytes", bytes(bad)) + emit("sig", "bytes", sig_bytes)
                     + ["status ok"] + emit("out", "bool", rejected))


def attempt(function, *args):
    """Ruft eine umhüllte Funktion auf; Fehler sind hier gewollt."""
    try:
        function(*args)
    except Exception:
        pass


def with_n(n, sig_bytelen=None):
    return dataclasses.replace(FALCON_512, n=n,
                               sig_bytelen=sig_bytelen or FALCON_512.sig_bytelen)


def edge_cases() -> None:
    r = random.Random(0xFA1C0)
    q = modq.Q

    # --- modq: alle Grade, negative und grosse Eingaben, Ablehnungen ---------
    for logn in range(0, 11):
        n = 1 << logn
        for lo, hi in ((0, q - 1), (-30, 30), (-5 * q, 5 * q)):
            a = [r.randint(lo, hi) for _ in range(n)]
            b = [r.randint(lo, hi) for _ in range(n)]
            modq.ntt(a)
            modq.intt(a)
            modq.mul_mod_q(a, b)
            modq.is_invertible_mod_q(a)
            attempt(modq.div_mod_q, a, b)
            modq.center_mod_q(a)
        attempt(modq.div_mod_q, [1] + [0] * (n - 1), [0] * n)
    modq.center_mod_q([0, 1, 6144, 6145, 12288, q, -1, -6144, -6145, 3 * q + 5, -3 * q - 5])
    for n in (3, 6, 12, 4096):
        attempt(modq.ntt, [1] * n)
        attempt(modq.intt, [1] * n)
    attempt(modq.mul_mod_q, [1, 2], [1, 2, 3, 4])
    attempt(modq.div_mod_q, [1, 2], [1, 2, 3, 4])

    # --- poly -----------------------------------------------------------------
    poly.norm_sq([1, -2, 3, 0])
    poly.norm_sq([0] * 4)
    poly.norm_sq([-90000] + [6144] * 511)

    # --- hashing: Längen rund um die SHAKE-Blockgrösse, Grenzwerte ------------
    for length in (0, 1, 2, 40, 73, 135, 136, 137, 271, 272, 273, 1000, 5000):
        hashing.hash_to_point(bytes(r.randrange(256) for _ in range(length)), FALCON_512)
    for n in (2, 4, 8, 16, 256, 1024):
        hashing.hash_to_point(b"reduced degree", with_n(n) if n != 1024 else FALCON_1024)
    for data in (bytes.fromhex("00011c0a"), bytes.fromhex("000035af"), b"Falcon\r", b"Falcon\x04"):
        hashing.hash_to_point(data, with_n(4))

    # --- compress / decompress --------------------------------------------------
    ex = [1, -1, 0, 130]
    ex_bytes = bytes.fromhex("01c0c02048")
    encoding.compress(ex, with_n(4, 46))
    encoding.compress(ex, with_n(4, 50))
    encoding.compress(ex, with_n(4, 45))
    encoding.compress([1, -1, 0, 514], with_n(4, 46))
    encoding.compress([1, -1, 0, 642], with_n(4, 46))
    for v in (0, 127, 128, -128, 255, 2047, -2047):
        encoding.compress([v, 0], with_n(2, 46))
    p46, p50, p45, p44 = with_n(4, 46), with_n(4, 50), with_n(4, 45), with_n(2, 44)
    decompress_cases = [
        (ex_bytes, p46), (ex_bytes + bytes(4), p50), (ex_bytes, p50), (ex_bytes, p45),
        (ex_bytes[:-1] + b"\x49", p46), (ex_bytes + b"\x00\x00\x01\x00", p50),
        (ex_bytes[:-1] + b"\x4c", p50), (ex_bytes + bytes(1), p50), (ex_bytes + bytes(2), p50),
        (ex_bytes + bytes(3), p50), (ex_bytes + bytes(5), p50), (ex_bytes[:-1], p50),
        (bytes(3), p44), (bytes.fromhex("808040"), p44), (bytes.fromhex("008040"), p44),
        (b"", FALCON_512),
    ]
    for data, params in decompress_cases:
        encoding.decompress(data, params)
    for params in (FALCON_512, FALCON_1024):
        n = params.n
        s = [round(r.gauss(0, 165.7)) for _ in range(n)]
        enc = encoding.compress(s, params)
        unpadded = enc.rstrip(b"\x00")
        encoding.decompress(enc, params)
        encoding.decompress(unpadded, params)
        encoding.decompress(unpadded[:-1], params)
        encoding.decompress(enc + b"\x00", params)
        encoding.decompress(enc + bytes(2), params)
        # grösster darstellbarer Wert: ein Koeffizient mit langem unären Teil
        big = (params.sig_bytelen - 41 + 1) * 8 - 9 * n
        bitstr = "0" + "1" * 7 + "0" * (big - 1) + "1" + "000000001" * (n - 1)
        bitstr += "0" * (-len(bitstr) % 8)
        encoding.decompress(bytes(int(bitstr[i:i + 8], 2) for i in range(0, len(bitstr), 8)), params)
    for rec_n in (512, 1024):
        for i in (0, 7, 82):
            rec = load_kat(rec_n)[i]
            msg, sig = encoding.decode_kat_message(rec.sm)
            encoding.decompress(sig.s2_encoded, FALCON_512 if rec_n == 512 else FALCON_1024)

    # --- Public Key ---------------------------------------------------------------
    encoding.decode_pk(bytes.fromhex("0100070000"))
    encoding.encode_pk([1, 12288])
    encoding.encode_pk([12288, 0, 1, 4096])
    for logn in range(1, 11):
        encoding.encode_pk([r.randrange(q) for _ in range(1 << logn)])
    good_pk = load_kat(512)[0].pk
    for bad in (b"", bytes([0x19]) + bytes(896), bytes([0x89]) + bytes(896), bytes([0x59]) + bytes(896),
                bytes([0x00]) + bytes(896), bytes([0x0B]) + bytes(896), good_pk[:-1], good_pk + b"\x00",
                bytes.fromhex("0130004000"), bytes.fromhex("01ffff0000"), bytes.fromhex("0100070001")):
        attempt(encoding.decode_pk, bad)
    for bad in ([0, q, 0, 0], [0, -1, 0, 0], [0] * 3, [0], [0] * 2048):
        attempt(encoding.encode_pk, bad)

    # --- Secret Key ------------------------------------------------------------------
    encoding.encode_sk([1, -1], [0, -127], [127, -127])
    encoding.decode_sk(bytes.fromhex("5101ff00817f81"))
    for logn in range(1, 11):
        n = 1 << logn
        m = (1 << (encoding.FG_BITS[n] - 1)) - 1
        encoding.encode_sk([m, -m] * (n // 2), [-m, m] * (n // 2), [127, -127] * (n // 2))
    good_sk = load_kat(512)[0].sk
    bad_list = [b"", bytes([0x09]) + bytes(1280), bytes([0x39]) + bytes(1280), bytes([0xD9]) + bytes(1280),
                bytes([0x50]) + bytes(1280), bytes([0x5B]) + bytes(1280), good_sk[:-1], good_sk + b"\x00",
                b"\x59" + bytes([0x80]) + bytes(1279), b"\x59" + bytes(384) + bytes([0x80]) + bytes(895),
                b"\x59" + bytes(768) + b"\x80" + bytes(511), bytes.fromhex("51800000000000")]
    for bad in bad_list:
        attempt(encoding.decode_sk, bad)
    z512, z1024 = [0] * 512, [0] * 1024
    for args in (([-32] + z512[1:], z512, z512), ([32] + z512[1:], z512, z512), (z512, [-32] + z512[1:], z512),
                 (z512, z512, [-128] + z512[1:]), (z512, z512, [128] + z512[1:]),
                 ([16] + z1024[1:], z1024, z1024), ([-16] + z1024[1:], z1024, z1024),
                 (z512, z512, [0] * 256), ([0] * 3, [0] * 3, [0] * 3)):
        attempt(encoding.encode_sk, *args)

    # --- Signatur- und KAT-Format ---------------------------------------------------
    salt = bytes(range(40))
    encoding.encode_sig(Signature(salt, b"\x12\x34"), FALCON_512)
    for logn in range(1, 11):
        encoding.encode_sig(Signature(salt, b"\x80"), with_n(1 << logn))
    for length in (0, 39, 41):
        attempt(encoding.encode_sig, Signature(bytes(length), b"\x80"), FALCON_512)
    encoding.decode_sig(b"\x39" + salt + b"\x12\x34", FALCON_512)
    attempt(encoding.decode_sig, b"\x3a" + salt + b"\x80", FALCON_512)
    for header in (0x59, 0x19, 0x79, 0x29, 0xB9, 0x30, 0x3B):
        attempt(encoding.decode_sig, bytes([header]) + salt + b"\x80", FALCON_512)
    for length in (0, 1, 40, 41):
        attempt(encoding.decode_sig, (b"\x39" + salt)[:length], FALCON_512)
    attempt(encoding.decode_sig, b"\x39" + salt + bytes(FALCON_512.sig_bytelen - 40), FALCON_512)
    encoding.decode_sig(b"\x39" + salt + bytes(FALCON_512.sig_bytelen - 41), FALCON_512)
    encoding.decode_kat_message(b"\x00\x04" + salt + b"hello" + b"\x29\xaa\xbb\xcc")
    encoding.decode_kat_message(b"\x00\x02" + salt + b"\x29\x80")
    encoding.decode_kat_message(b"\x01\x02" + salt + b"m" + b"\x29" + bytes(257))
    for header in (0x39, 0x59, 0x09, 0x20, 0x2B):
        attempt(encoding.decode_kat_message, b"\x00\x02" + salt + bytes([header, 0x80]))
    attempt(encoding.decode_kat_message, b"\x00\x50" + salt + b"\x29\x80")
    for length in (0, 1, 2, 41, 42):
        attempt(encoding.decode_kat_message, (b"\x00\x02" + salt + b"\x29\x80")[:length])

    # --- compute_s1 / is_short -----------------------------------------------------
    top.compute_s1([5, 12288], [0, 0], [7, 9], FALCON_512)
    top.compute_s1([0, 0], [1, 0], [3, 0], FALCON_512)
    top.compute_s1([10, 20], [0, 1], [0, 1], FALCON_512)
    top.compute_s1([6144, 6145], [0, 0], [0, 0], FALCON_512)
    top.compute_s1([0, 0], [-1, 0], [3, 0], FALCON_512)
    for params in (FALCON_512, FALCON_1024):
        def squares(target):
            out = []
            while target:
                root = math.isqrt(target)
                out.append(root)
                target -= root * root
            return out + [0] * (params.n - len(out))
        top.is_short(squares(params.sig_bound), [0] * params.n, params)
        top.is_short(squares(params.sig_bound + 1), [0] * params.n, params)
        top.is_short([-x for x in squares(params.sig_bound)], [0] * params.n, params)


def shake_vectors() -> None:
    """SHAKE-256 aus hashlib, Längen rund um die Blockgrösse von 136 Bytes."""
    r = random.Random(202)
    for in_len in (0, 1, 32, 135, 136, 137, 271, 272, 273, 1000):
        data = bytes(r.randrange(256) for _ in range(in_len))
        for out_len in (0, 1, 32, 135, 136, 137, 272, 500, 2048):
            add_case("shake256", ["case"] + emit("data", "bytes", data)
                     + ["status ok"] + emit("out", "bytes", hashlib.shake_256(data).digest(out_len)))


def header() -> list:
    src = hashlib.sha256()
    for p in sorted((ROOT / "falcon").glob("*.py")):
        src.update(p.read_bytes())
    return [
        "# Erzeugt mit Python/scripts/gen_vectors.py",
        f"# python {platform.python_version()} {platform.machine()}",
        f"# falcon-quellen sha256 {src.hexdigest()}",
    ]


def main() -> None:
    preflight()
    for module, name, argspec, outspec, cap in WRAPS:
        wrap(module, name, argspec, outspec, cap)
    for module, name, argspec, outspec, cap in SCALAR_WRAPS:
        wrap(module, name, argspec, outspec, cap, by_size=False)
    wrap_ldl()

    flows()

    edge_cases_unlimited()
    shake_vectors()

    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.txt"):
        old.unlink()
    head = header()
    total = 0
    for file, cases in sorted(records.items()):
        text = "\n".join(head + [ln for case in cases for ln in case]) + "\n"
        (OUT / f"{file}.txt").write_text(text)
        total += len(text)
    print(f"{len(records)} Dateien, {sum(map(len, records.values()))} Fälle, "
          f"{total / 1e6:.1f} MB in {OUT}")


class _Unlimited(dict):
    """counts-Ersatz: nichts erreicht je die Obergrenze."""

    def get(self, key, default=0):
        return 0

    def __setitem__(self, key, value):
        pass


def edge_cases_unlimited() -> None:
    """Randfälle zählen nicht gegen die Obergrenzen."""
    global counts
    saved = counts
    counts = _Unlimited()
    edge_cases()
    counts = saved


if __name__ == "__main__":
    main()
