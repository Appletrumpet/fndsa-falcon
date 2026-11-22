"""Brücke zwischen der Web-Oberfläche und dem Python-Paket (UI/README.md).

Läuft in Pyodide (UI/python-worker.js). Gleiche Schnittstelle wie die
Hüllen von Rust (Rust/wasm) und C (UI/c/wasm_api.c): Keygen aus einem Seed,
Sign mit Zufall aus dem Aufrufer, Verify mit Prüfbericht. Zufall ist der
SHAKE-256-Strom über dem Seed wie ShakeRNG in Python/tests/support.py;
gleicher Seed ergibt deshalb in Python und C denselben Schlüssel.
"""

import hashlib
import time

from falcon import falcon as F
from falcon.encoding import decode_pk, decode_sig, decompress, encode_pk, encode_sig, encode_sk
from falcon.hashing import hash_to_point
from falcon.params import FALCON_512, FALCON_1024
from falcon.poly import norm_sq

PARAMS = {9: FALCON_512, 10: FALCON_1024}
_keys = {}
_next_handle = 1


class ShakeRNG:
    """Fortlaufend ausgelesene Ausgabe von SHAKE-256 über einem Startwert."""

    def __init__(self, seed: bytes):
        self._shake = hashlib.shake_256(seed)
        self._buf = b""
        self._pos = 0

    def random_bytes(self, k: int) -> bytes:
        end = self._pos + k
        if end > len(self._buf):
            self._buf = self._shake.digest(max(end, 2 * len(self._buf), 4096))
        out = self._buf[self._pos:end]
        self._pos = end
        return out


def _bytes(x) -> bytes:
    """JS-Uint8Array (JsProxy) oder Bytes nach bytes."""
    return bytes(x.to_py()) if hasattr(x, "to_py") else bytes(x)


def keygen(logn: int, seed) -> tuple:
    """Schlüsselpaar; gibt (Handle, Public Key, Länge des Secret Keys)."""
    global _next_handle
    p = PARAMS[logn]
    sk, pk = F.keygen(p, ShakeRNG(_bytes(seed)))
    try:
        sk_len = len(encode_sk(sk.f, sk.g, sk.F))
    except ValueError:
        sk_len = 0  # selten: nicht speicherbar (PLAN.md L6), signieren geht trotzdem
    handle = _next_handle
    _next_handle += 1
    _keys[handle] = (sk, p)
    return handle, encode_pk(pk.h), sk_len


def sign(handle: int, msg, rnd) -> bytes:
    sk, p = _keys[handle]
    sig = F.sign(sk, _bytes(msg), p, ShakeRNG(_bytes(rnd)))
    return encode_sig(sig, p)


def free(handle: int) -> None:
    _keys.pop(handle, None)


def _report(pk: bytes, sig: bytes, msg: bytes) -> dict:
    """Schritte wie falcon.verify, mit Fehlerschritt und Norm (wie Rust:
    0 Dekodieren, 1 HashToPoint, 2 s₂ entpacken, 3 s₁, 4 Norm)."""
    try:
        h = decode_pk(pk)
    except ValueError as e:
        return {"error": f"Public Key: {e}"}
    p = next((q for q in PARAMS.values() if q.n == len(h)), None)
    if p is None:
        return {"error": "kein Parametersatz für diesen Grad"}
    logn = sig[0] & 0x0F if sig else 0
    if len(sig) < 42 or sig[0] >> 4 != 3 or not 1 <= logn <= 10:
        return {"error": "Signatur zu kurz oder Header ungültig"}
    out = {"accepted": False, "failedAt": None, "norm": None, "bound": p.sig_bound}
    if 1 << logn != p.n:
        out["failedAt"] = 0
        return out
    s = decode_sig(sig, p)
    c = hash_to_point(s.salt + msg, p)
    s2 = decompress(s.s2_encoded, p)
    if s2 is None:
        out["failedAt"] = 2
        return out
    s1 = F.compute_s1(c, s2, h, p)
    norm = norm_sq(s1) + norm_sq(s2)
    out["norm"] = norm
    out["accepted"] = norm <= p.sig_bound
    out["failedAt"] = None if out["accepted"] else 4
    return out


def verify_timed(pk, sig, msg, runs: int) -> dict:
    """Prüfbericht und mittlere Laufzeit in µs über `runs` Aufrufe."""
    pk, sig, msg = _bytes(pk), _bytes(sig), _bytes(msg)
    t0 = time.perf_counter()
    for _ in range(max(1, runs)):
        r = _report(pk, sig, msg)
    r["micros"] = (time.perf_counter() - t0) / max(1, runs) * 1e6
    return r
