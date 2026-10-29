"""
Kompression und Byteformate für Schlüssel und Signaturen.

Spec-Referenz: §3.11 (insbesondere §3.11.3–§3.11.6).

Kodierung von s₂: Vorzeichen, 7 tiefe Bits, Rest unär, auf feste Länge
auffüllen (Alg. 17). Dekompression lehnt mehrdeutige Kodierungen ab,
akzeptiert aber sowohl gepolsterte (feste Länge) als auch ungepolsterte
Kodierungen (§3.11.3); teilweises Padding ist ungültig.
"""

from typing import List, Optional, Tuple
from .params import Params
from .datatypes import Signature

Q = 12289

FG_BITS = {
    2: 8,
    4: 8,
    8: 8,
    16: 8,
    32: 8,
    64: 7,
    128: 7,
    256: 6,
    512: 6,
    1024: 5,
}


def _logn(n: int) -> int:
    return n.bit_length() - 1


def _valid_degree(n: int) -> bool:
    if n <= 0 or (n & (n - 1)) != 0:
        return False
    return 1 <= _logn(n) <= 10


class _BitWriter:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.acc = 0
        self.nbits = 0
        self.total = 0

    def write_bit(self, bit: int) -> None:
        self.acc = ((self.acc << 1) | (bit & 1)) & 0xFF
        self.nbits += 1
        self.total += 1
        if self.nbits == 8:
            self.buf.append(self.acc)
            self.acc = 0
            self.nbits = 0

    def write_bits(self, value: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            self.write_bit((value >> i) & 1)

    def finish(self) -> bytes:
        if self.nbits:
            self.acc <<= (8 - self.nbits)
            self.buf.append(self.acc)
            self.acc = 0
            self.nbits = 0
        return bytes(self.buf)


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.total = len(data) * 8

    def read_bit(self) -> int:
        if self.pos >= self.total:
            raise EOFError
        byte = self.data[self.pos >> 3]
        bit = (byte >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return bit

    def read_bits(self, n: int) -> int:
        if n < 0 or self.pos + n > self.total:
            raise EOFError
        v = 0
        for _ in range(n):
            v = (v << 1) | self.read_bit()
        return v


# ---------------------------------------------------------------------------
# Signatur-Kompression (Alg. 17 / Alg. 18)
# ---------------------------------------------------------------------------

def compress(s: List[int], params: Params) -> Optional[bytes]:
    """Vorzeichen, 7 tiefe Bits, Rest unär, auf feste Länge auffüllen.
    Alg. 17. Gibt None zurück, wenn die Kodierung die feste Signaturlänge
    überschreitet."""
    padded_len = params.sig_bytelen - 41
    slen = padded_len * 8

    w = _BitWriter()

    for coeff in s:
        sign = 1 if coeff < 0 else 0
        av = abs(coeff)
        low7 = av & 0x7F
        k = av >> 7

        needed = 1 + 7 + k + 1
        if w.total + needed > slen:
            return None

        w.write_bit(sign)
        w.write_bits(low7, 7)
        for _ in range(k):
            w.write_bit(0)
        w.write_bit(1)

    while w.total < slen:
        w.write_bit(0)

    return w.finish()


def decompress(b: bytes, params: Params) -> Optional[List[int]]:
    """Umkehrung von compress.

    Lehnt mehrdeutige Kodierungen ab. Akzeptiert:
      - gepolsterte Kodierungen fester Länge (Alg. 18)
      - ungepolsterte Kodierungen (§3.11.3)
    Teilweises Padding ist ungültig.
    """
    if not isinstance(b, (bytes, bytearray)) or len(b) == 0:
        return None

    b = bytes(b)
    padded_len = params.sig_bytelen - 41
    padded = (len(b) == padded_len)

    if not padded and b[-1] == 0:
        return None

    r = _BitReader(b)
    out: List[int] = []

    try:
        for _ in range(params.n):
            sign = r.read_bit()
            low7 = r.read_bits(7)

            k = 0
            while True:
                bit = r.read_bit()
                if bit:
                    break
                k += 1

            value = low7 | (k << 7)
            if sign:
                if value == 0:
                    return None
                value = -value

            out.append(value)

    except EOFError:
        return None

    consumed = r.pos

    if padded:
        try:
            while r.pos < r.total:
                if r.read_bit() != 0:
                    return None
        except EOFError:
            return None
        return out

    # Ungepolstert: das Ende muss im letzten Byte liegen, Restbits 0.
    if consumed <= (len(b) - 1) * 8:
        return None

    try:
        while r.pos < r.total:
            if r.read_bit() != 0:
                return None
    except EOFError:
        return None

    return out


# ---------------------------------------------------------------------------
# Public-Key-Kodierung (§3.11.4)
# ---------------------------------------------------------------------------

def encode_pk(h: List[int]) -> bytes:
    """Header + 14 Bit pro Koeffizient. §3.11.4."""
    n = len(h)
    if not _valid_degree(n):
        raise ValueError("ungültiger Polynomgrad")

    logn = _logn(n)
    w = _BitWriter()
    w.write_bits(logn, 8)

    for c in h:
        if not isinstance(c, int) or c < 0 or c >= Q:
            raise ValueError("Public-Key-Koeffizienten müssen 0 <= c < q sein")
        w.write_bits(c, 14)

    return w.finish()


def decode_pk(b: bytes) -> List[int]:
    """Umkehrung von encode_pk. §3.11.4."""
    if not isinstance(b, (bytes, bytearray)) or len(b) == 0:
        raise ValueError("leerer Public Key")

    b = bytes(b)
    header = b[0]
    if (header >> 4) != 0:
        raise ValueError("ungültiger Public-Key-Header")

    logn = header & 0x0F
    if not (1 <= logn <= 10):
        raise ValueError("ungültiger logn im Public-Key-Header")

    n = 1 << logn
    expected = 1 + (14 * n + 7) // 8
    if len(b) != expected:
        raise ValueError("ungültige Public-Key-Länge")

    r = _BitReader(b[1:])
    out: List[int] = []

    try:
        for _ in range(n):
            v = r.read_bits(14)
            if v >= Q:
                raise ValueError("Public-Key-Koeffizient ist nicht < q")
            out.append(v)

        while r.pos < r.total:
            if r.read_bit() != 0:
                raise ValueError("ungültige Padding-Bits im Public Key")

    except EOFError:
        raise ValueError("Public Key ist abgeschnitten")

    return out


# ---------------------------------------------------------------------------
# Secret-Key-Kodierung (§3.11.5)
# ---------------------------------------------------------------------------

def encode_sk(f: List[int], g: List[int], F: List[int]) -> bytes:
    """Header + f, g, F mit fester Bitbreite. §3.11.5."""
    n = len(f)
    if len(g) != n or len(F) != n:
        raise ValueError("f, g, F müssen dieselbe Länge haben")
    if not _valid_degree(n):
        raise ValueError("ungültiger Polynomgrad")

    bits = FG_BITS[n]
    maxv = (1 << (bits - 1)) - 1
    minv = -(1 << (bits - 1))

    for x in f:
        if not isinstance(x, int) or x <= minv or x > maxv:
            raise ValueError("f-Koeffizient außerhalb des erlaubten Bereichs")
    for x in g:
        if not isinstance(x, int) or x <= minv or x > maxv:
            raise ValueError("g-Koeffizient außerhalb des erlaubten Bereichs")
    for x in F:
        if not isinstance(x, int) or x <= -128 or x > 127:
            raise ValueError("F-Koeffizient außerhalb des erlaubten Bereichs")

    logn = _logn(n)
    w = _BitWriter()
    w.write_bits(0x50 | logn, 8)

    mask = (1 << bits) - 1
    for arr in (f, g):
        for x in arr:
            w.write_bits(x & mask, bits)

    for x in F:
        w.write_bits(x & 0xFF, 8)

    return w.finish()


def decode_sk(b: bytes) -> Tuple[List[int], List[int], List[int]]:
    """Umkehrung von encode_sk. §3.11.5."""
    if not isinstance(b, (bytes, bytearray)) or len(b) == 0:
        raise ValueError("leerer Secret Key")

    b = bytes(b)
    header = b[0]
    if (header >> 4) != 0b0101:
        raise ValueError("ungültiger Secret-Key-Header")

    logn = header & 0x0F
    if not (1 <= logn <= 10):
        raise ValueError("ungültiger logn im Secret-Key-Header")

    n = 1 << logn
    bits = FG_BITS[n]
    expected = 1 + (2 * n * bits) // 8 + n
    if len(b) != expected:
        raise ValueError("ungültige Secret-Key-Länge")

    r = _BitReader(b[1:])

    def read_signed(width: int) -> int:
        raw = r.read_bits(width)
        if raw == (1 << (width - 1)):
            raise ValueError("Minimalwert ist in der Secret-Key-Kodierung verboten")
        if raw >= (1 << (width - 1)):
            raw -= (1 << width)
        return raw

    try:
        f = [read_signed(bits) for _ in range(n)]
        g = [read_signed(bits) for _ in range(n)]

        F: List[int] = []
        for _ in range(n):
            raw = r.read_bits(8)
            if raw == 0x80:
                raise ValueError("Minimalwert ist in der Secret-Key-Kodierung verboten")
            if raw >= 0x80:
                raw -= 0x100
            F.append(raw)

        if r.pos != r.total:
            raise ValueError("ungültige Restbits im Secret Key")

    except EOFError:
        raise ValueError("Secret Key ist abgeschnitten")

    return f, g, F


# ---------------------------------------------------------------------------
# Signatur-Kodierung (§3.11.3)
# ---------------------------------------------------------------------------

def encode_sig(sig: Signature, params: Params) -> bytes:
    """Header + Salt + komprimiertes s₂. §3.11.3.

    params wird für den Header 0011nnnn (ℓ = log₂ n) benötigt; Signature
    selbst enthält n nicht."""
    if len(sig.salt) != 40:
        raise ValueError("Salt muss 40 Bytes lang sein")

    logn = _logn(params.n)
    if not (1 <= logn <= 10):
        raise ValueError("ungültiger Polynomgrad")

    return bytes([0x30 | logn]) + sig.salt + sig.s2_encoded


def decode_sig(b: bytes, params: Params) -> Signature:
    """Umkehrung von encode_sig. §3.11.3.

    Prüft den Header gegen params (n muss übereinstimmen)."""
    if not isinstance(b, (bytes, bytearray)) or len(b) < 42:
        raise ValueError("Signatur ist zu kurz")

    b = bytes(b)
    logn = _logn(params.n)
    expected_header = 0x30 | logn

    if b[0] != expected_header:
        raise ValueError("ungültiger Signatur-Header für diese Parameter")

    salt = b[1:41]
    s2_encoded = b[41:]
    return Signature(salt=salt, s2_encoded=s2_encoded)


# ---------------------------------------------------------------------------
# KAT-Format (§3.11.6)
# ---------------------------------------------------------------------------

def decode_kat_message(sm: bytes) -> Tuple[bytes, Signature]:
    """KAT-Format der NIST-API: Länge, Salt, Nachricht, Signatur mit
    Header 0x29 bzw. 0x2A, ohne Padding. Nur für Tests. §3.11.6."""
    if not isinstance(sm, (bytes, bytearray)) or len(sm) < 2 + 40 + 1:
        raise ValueError("KAT-Nachricht ist zu kurz")

    sm = bytes(sm)
    siglen = int.from_bytes(sm[:2], "big")

    if siglen < 1:
        raise ValueError("KAT-Signaturlänge muss mindestens 1 sein")
    if len(sm) < 2 + 40 + siglen:
        raise ValueError("KAT-Nachricht ist kürzer als die angegebene Signaturlänge")

    msg_len = len(sm) - 2 - 40 - siglen
    if msg_len < 0:
        raise ValueError("ungültige KAT-Länge")

    salt = sm[2:42]
    msg = sm[42:42 + msg_len]
    sig = sm[42 + msg_len:]

    if len(sig) != siglen:
        raise ValueError("KAT-Signatur hat die falsche Länge")

    header = sig[0]
    if (header & 0xF0) != 0x20:
        raise ValueError("ungültiger KAT-Signatur-Header")

    logn = header & 0x0F
    if not (1 <= logn <= 10):
        raise ValueError("ungültiger logn im KAT-Signatur-Header")

    return msg, Signature(salt=salt, s2_encoded=sig[1:])
