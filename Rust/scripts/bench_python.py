#!/usr/bin/env python3
"""Laufzeit der Python-Implementierung nach dem Messprotokoll aus
Rust/examples/bench.rs (PLAN.md Phase 8, Z6).

Dieselben Operationen und Eingaben wie in Rust: Keygen aus einem Seed
(hier ShakeRNG aus Python/tests/support.py), Secret Key laden, Sign,
Verify; Nachricht 32 Bytes. Gemessen wird mit time.perf_counter_ns;
gemeldet werden Median sowie 10- und 90-%-Perzentil in Mikrosekunden.
Python wird nicht verändert.

Aufruf aus Rust/:  python scripts/bench_python.py
"""

import platform
import statistics
import sys
import time
from pathlib import Path

PY = Path(__file__).resolve().parent.parent.parent / "Python"
sys.path.insert(0, str(PY))
sys.path.insert(0, str(PY / "tests"))

from falcon import falcon as F  # noqa: E402
from falcon import encoding  # noqa: E402
from falcon.params import FALCON_512, FALCON_1024  # noqa: E402
from support import ShakeRNG  # noqa: E402


def measure(n, warm, run):
    for i in range(warm):
        run(i)
    out = []
    for i in range(n):
        t0 = time.perf_counter_ns()
        run(i)
        out.append(time.perf_counter_ns() - t0)
    out.sort()
    at = lambda p: out[round((len(out) - 1) * p)]  # noqa: E731
    return at(0.5), at(0.1), at(0.9)


def report(op, n, runs, s):
    m, p10, p90 = (x / 1e3 for x in s)
    print(f"{op:<16} {n:>5} {runs:>6} {m:>12.1f} {p10:>12.1f} {p90:>12.1f}")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print(f"Python {platform.python_version()} ({platform.machine()}, {platform.system()})")
    print(f"{'Operation':<16} {'n':>5} {'Läufe':>6} {'µs Median':>12} {'10 %':>12} {'90 %':>12}")
    msg = bytes([0x5A]) * 32
    for params, nk in ((FALCON_512, 8), (FALCON_1024, 4)):
        n = params.n
        s = measure(nk, 1, lambda i: F.keygen(params, ShakeRNG(bytes([i]) * 48)))
        report("Keygen", n, nk, s)

        sk, pk = F.keygen(params, ShakeRNG(bytes([0xAB]) * 48))
        sk_bytes = encoding.encode_sk(sk.f, sk.g, sk.F)
        s = measure(20, 2, lambda i: F.load_secret_key(sk_bytes, params))
        report("sk laden", n, 20, s)

        rng = ShakeRNG(b"bench")
        s = measure(50, 3, lambda i: F.sign(sk, msg, params, rng))
        report("Sign", n, 50, s)

        sig = F.sign(sk, msg, params, rng)
        s = measure(200, 10, lambda i: F.verify(pk, msg, sig, params))
        report("Verify", n, 200, s)


if __name__ == "__main__":
    main()
