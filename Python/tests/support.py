"""Gemeinsame Test-Hilfen: feste Zufallsquelle und Parser für NIST-Testdaten.

Doku §6.9: „für Tests liest eine Quelle Bytes aus einer festen Zeichenkette
(Tab. 3.2)“.
"""

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

DATA_DIR = Path(__file__).parent.parent / "data"
SAMPLER_DIR = DATA_DIR / "sampler"


class FixedRNG:
    """Zufallsquelle, die eine feste Bytefolge der Reihe nach ausgibt.

    Liest ein Test mehr Bytes als vorhanden, schlägt er mit AssertionError
    fehl. `remaining` erlaubt zu prüfen, dass genau alle Bytes verbraucht
    wurden (zu wenig gelesen ist ebenso ein Fehler wie zu viel).
    """

    def __init__(self, data: bytes):
        self._data = bytes(data)
        self._pos = 0
        self.calls: List[int] = []   # angeforderte Längen, in Reihenfolge

    @classmethod
    def from_hex(cls, hexstr: str) -> "FixedRNG":
        return cls(bytes.fromhex(hexstr))

    def random_bytes(self, k: int) -> bytes:
        self.calls.append(k)
        end = self._pos + k
        assert end <= len(self._data), (
            f"FixedRNG erschöpft: {k} Bytes angefordert, "
            f"{len(self._data) - self._pos} übrig"
        )
        out = self._data[self._pos:end]
        self._pos = end
        return out

    @property
    def consumed(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos


class SeededRNG:
    """Reproduzierbare Zufallsquelle (random.Random mit fester Saat) für
    statistische Tests und Schlüsselerzeugung in Tests."""

    def __init__(self, seed: int):
        import random
        self._r = random.Random(seed)

    def random_bytes(self, k: int) -> bytes:
        return self._r.randbytes(k)


def nmul(a: List[int], b: List[int]) -> List[int]:
    """Schulbuch-Multiplikation in ℤ[x]/(xⁿ+1), exakt.

    Unabhängig von falcon.poly, damit Testdaten und Erwartungen auch dann
    geprüft werden können, wenn poly (noch) nicht implementiert ist."""
    n = len(a)
    c = [0] * n
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if i + j < n:
                    c[i + j] += ai * bj
                else:
                    c[i + j - n] -= ai * bj
    return c


# ---------------------------------------------------------------------------
# Parser für test-vector-sampler-falcon{512,1024}.txt
# ---------------------------------------------------------------------------

@dataclass
class BerExpTrace:
    x: float
    ccs: float
    s: int
    r: float
    z: int                 # (2·ApproxExp(r, ccs) − 1) >> s, ohne Vorzeichen
    random_bytes: bytes    # pro Schleifendurchlauf ein Byte
    ret: int


@dataclass
class IterationTrace:
    u: int                 # UniformBits(72) für BaseSampler
    u_bytes: bytes
    z0: int
    b_byte: int
    b: int
    berexp: BerExpTrace

    @property
    def random_bytes(self) -> bytes:
        return self.u_bytes + bytes([self.b_byte]) + self.berexp.random_bytes


@dataclass
class SamplerZTrace:
    mu: float
    inv_sigma: float
    iterations: List[IterationTrace] = field(default_factory=list)
    result: Optional[int] = None

    @property
    def sigma(self) -> float:
        return 1.0 / self.inv_sigma

    @property
    def random_bytes(self) -> bytes:
        return b"".join(it.random_bytes for it in self.iterations)


@dataclass
class SignatureTestVector:
    n: int
    nonce: bytes
    data: bytes
    f: List[int]
    g: List[int]
    F: List[int]
    G: List[int]
    hashed_message: List[int]
    samplerz: List[SamplerZTrace]
    signature_vector: List[int]


def _hexfloat(line: str) -> float:
    return float.fromhex(line.split("=", 1)[1].split()[0])


def _ints(line: str) -> List[int]:
    return [int(v) for v in line.split("=", 1)[1].split()]


_RANDOM_BYTE = re.compile(r"from random byte: 0x([0-9A-Fa-f]{2})")


@lru_cache(maxsize=None)
def load_sampler_vectors(n: int) -> SignatureTestVector:
    """Liest test-vector-sampler-falcon{n}.txt aus data/sampler/."""
    path = SAMPLER_DIR / f"test-vector-sampler-falcon{n}.txt"
    lines = [ln.strip() for ln in path.read_text().splitlines()]

    header = {}
    traces: List[SamplerZTrace] = []
    cur: Optional[SamplerZTrace] = None
    it: Optional[dict] = None
    be: Optional[dict] = None
    in_berexp = False

    def close_iteration():
        nonlocal it, be
        if it is not None:
            it["berexp"] = BerExpTrace(**be)
            cur.iterations.append(IterationTrace(**it))
        it, be = None, None

    for ln in lines:
        if ln.startswith(("nonce =", "data =")):
            header[ln.split()[0]] = bytes.fromhex(ln.split("=", 1)[1].strip())
        elif ln.startswith(("f =", "g =", "F =", "G =")):
            header[ln.split()[0]] = _ints(ln)
        elif ln.startswith("hashed message ="):
            header["hashed"] = _ints(ln)
        elif ln.startswith("signature vector ="):
            header["sig"] = _ints(ln)
        elif ln == "SamplerZ:":
            cur = SamplerZTrace(mu=0.0, inv_sigma=0.0)
            in_berexp = False
        elif cur is None:
            continue
        elif ln.startswith("mu "):
            cur.mu = _hexfloat(ln)
        elif ln.startswith("1/sigma "):
            cur.inv_sigma = _hexfloat(ln)
        elif ln.startswith("BaseSampler:"):
            close_iteration()
            m = re.search(r"u = 0x([0-9A-Fa-f]+) -> z0 = (\d+)", ln)
            u_hex = m.group(1).rjust(18, "0")
            it = dict(u=int(u_hex, 16), u_bytes=bytes.fromhex(u_hex), z0=int(m.group(2)))
            in_berexp = False
        elif ln.startswith("b ") and it is not None and not in_berexp:
            it["b"] = int(ln.split("=")[1].split()[0])
            it["b_byte"] = int(_RANDOM_BYTE.search(ln).group(1), 16)
        elif ln == "BerExp:":
            in_berexp = True
            be = dict(random_bytes=b"")
        elif in_berexp and ln.startswith("x "):
            be["x"] = _hexfloat(ln)
        elif in_berexp and ln.startswith("ccs "):
            be["ccs"] = _hexfloat(ln)
        elif in_berexp and ln.startswith("s "):
            be["s"] = int(ln.split("=")[1])
        elif in_berexp and ln.startswith("r "):
            be["r"] = _hexfloat(ln)
        elif in_berexp and ln.startswith("z "):
            be["z"] = int(re.search(r"0x([0-9A-Fa-f]+)", ln).group(1), 16)
        elif in_berexp and ln.startswith("i ="):
            be["random_bytes"] += bytes([int(_RANDOM_BYTE.search(ln).group(1), 16)])
        elif in_berexp and ln.startswith("ret:"):
            be["ret"] = int(ln.split(":")[1])
        elif ln.startswith("Accepted, ret ="):
            close_iteration()
            cur.result = int(ln.split("=")[1])
            traces.append(cur)
            cur = None

    return SignatureTestVector(
        n=n, nonce=header["nonce"], data=header["data"],
        f=header["f"], g=header["g"], F=header["F"], G=header["G"],
        hashed_message=header["hashed"], samplerz=traces,
        signature_vector=header["sig"],
    )


# ---------------------------------------------------------------------------
# Parser für NIST-KAT-Dateien falcon{512,1024}-KAT.rsp (§3.11.6)
# ---------------------------------------------------------------------------

KAT_DIR = DATA_DIR / "kat"


@dataclass
class KatRecord:
    count: int
    seed: bytes
    msg: bytes
    pk: bytes
    sk: bytes
    sm: bytes


@lru_cache(maxsize=None)
def load_kat(n: int) -> List[KatRecord]:
    """Liest data/kat/falcon{n}-KAT.rsp (100 Einträge)."""
    records, cur = [], {}
    for line in (KAT_DIR / f"falcon{n}-KAT.rsp").read_text().splitlines():
        line = line.strip()
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        cur[key] = value
        if key == "sm":
            mlen = int(cur["mlen"])
            msg = bytes.fromhex(cur["msg"]) if mlen else b""
            sm = bytes.fromhex(cur["sm"])
            assert len(msg) == mlen and len(sm) == int(cur["smlen"])
            records.append(KatRecord(
                count=int(cur["count"]), seed=bytes.fromhex(cur["seed"]),
                msg=msg, pk=bytes.fromhex(cur["pk"]), sk=bytes.fromhex(cur["sk"]),
                sm=sm,
            ))
            cur = {}
    return records
