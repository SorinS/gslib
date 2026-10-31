#!/usr/bin/env python3
"""Generate test vectors for bignum, with Python as the oracle.

Writes test/vectors/bigint.txt: one case per line, `op operands... results...`,
every number in signed lowercase hex (`-1f`, `0`); test/vectors/x25519.txt:
`scalar u result` as 32-byte little-endian hex, from an RFC 7748 transcription;
and sha256.txt, aes.txt, gcm.txt and rsa.txt from hashlib and transcriptions
of FIPS 197, SP 800-38D and RFC 8017 (see crypto_vectors.py), and the rest
from extra_vectors.py and parity_vectors.py, all cross-checked against the openssl command when
it is installed.
Deterministic (fixed seed).

    python3 scripts/gen_vectors.py [count_per_op]
"""

import math
import os
import random
import sys

rng = random.Random(20261025)


def h(x):
    return "-" + format(-x, "x") if x < 0 else format(x, "x")


def special():
    k = rng.choice([1, 2, 3, 4, 5, 8, 40, 41, 80, 81, 100])
    return rng.choice([
        (1 << (32 * k)) - 1,
        1 << (32 * k),
        (1 << (32 * k)) + 1,
        1 << (32 * k - 1),
        (1 << (32 * k - 1)) - 1,
        ((1 << (32 * k)) - 1) << (32 * rng.randint(0, 3)),
    ])


def num(max_limbs=12, signed=True):
    r = rng.random()
    if r < 0.05:
        x = 0
    elif r < 0.12:
        x = rng.randint(1, 1 << 64)
    elif r < 0.25:
        x = special()
    else:
        limbs = rng.randint(1, max_limbs)
        x = rng.getrandbits(32 * limbs)
        if rng.random() < 0.2:
            x |= 1 << (32 * limbs - 1)      # top limb full
    if signed and rng.random() < 0.5:
        x = -x
    return x


def nonzero(max_limbs=12, signed=True):
    while True:
        x = num(max_limbs, signed)
        if x != 0:
            return x


P25519 = 2**255 - 19


def x25519(k, u):
    """RFC 7748 §5, straight from the text, on Python integers."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(u, "little") & ((1 << 255) - 1)
    p = P25519
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def x25519_vectors(n):
    out = []
    edge_us = [0, 1, P25519 - 1, P25519, P25519 + 1, 2**255 - 1, 2**256 - 1, 9]
    for i in range(n):
        k = rng.getrandbits(256).to_bytes(32, "little")
        if i < len(edge_us):
            u = edge_us[i].to_bytes(32, "little")
        else:
            u = rng.getrandbits(256).to_bytes(32, "little")     # top bit set half the time
        out.append(f"{k.hex()} {u.hex()} {x25519(k, u).hex()}")
    return out


def trunc_divmod(a, b):
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q, a - b * q


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    out = []
    for _ in range(n):
        a, b = num(), num()
        out.append(f"add {h(a)} {h(b)} {h(a + b)}")
        out.append(f"sub {h(a)} {h(b)} {h(a - b)}")
        out.append(f"cmp {h(a)} {h(b)} {h((a > b) - (a < b))}")
        out.append(f"mul {h(a)} {h(b)} {h(a * b)}")
    # Products across the Karatsuba threshold, balanced and not.
    for _ in range(n // 3):
        a, b = num(160), num(160)
        out.append(f"mul {h(a)} {h(b)} {h(a * b)}")
        a, b = num(400), num(50)
        out.append(f"mul {h(a)} {h(b)} {h(a * b)}")
    for _ in range(n):
        a, b = num(24), nonzero(12)
        q, r = trunc_divmod(a, b)
        out.append(f"divmod {h(a)} {h(b)} {h(q)} {h(r)}")
        out.append(f"divmod_floor {h(a)} {h(b)} {h(a // b)} {h(a % b)}")
    # Divisions built to stress qhat correction: top divisor limbs near
    # the normalization boundary, remainders close to the divisor.
    for _ in range(n // 2):
        bl = rng.randint(2, 10)
        b = (rng.choice([0x80000000, 0xffffffff, 1, 0x7fffffff]) << (32 * (bl - 1))) \
            + rng.getrandbits(32 * (bl - 1))
        q = rng.getrandbits(32 * rng.randint(1, 8)) or 1
        r = b - 1 - rng.randint(0, 3)
        a = b * q + max(r, 0)
        out.append(f"divmod {h(a)} {h(b)} {h(a // b)} {h(a % b)}")
    for _ in range(n):
        a, b = num(8), num(8)
        g = math.gcd(a, b)
        out.append(f"gcd {h(a)} {h(b)} {h(g)}")
        m = nonzero(6, signed=False)
        a = num(10)
        try:
            inv = pow(a, -1, m)
            out.append(f"modinv {h(a)} {h(m)} {h(inv)} 1")
        except ValueError:
            out.append(f"modinv {h(a)} {h(m)} 0 0")
        b, e, m = num(6), num(4, signed=False), nonzero(6, signed=False)
        out.append(f"modpow {h(b)} {h(e)} {h(m)} {h(pow(b, e, m))}")
        a, k = num(10), rng.randint(0, 200)
        out.append(f"shl {h(a)} {h(k)} {h(a << k)}")
        out.append(f"shr {h(a)} {h(k)} {h(a >> k)}")
        a, b = num(6), num(6)
        out.append(f"and {h(a)} {h(b)} {h(a & b)}")
        out.append(f"or {h(a)} {h(b)} {h(a | b)}")
        out.append(f"xor {h(a)} {h(b)} {h(a ^ b)}")
        out.append(f"not {h(a)} {h(~a)}")
        i = rng.randint(0, 250)
        out.append(f"bit {h(a)} {h(i)} {h((a >> i) & 1)}")
        a = num(20, signed=False)
        out.append(f"isqrt {h(a)} {h(math.isqrt(a))}")
        a, e = num(3), rng.randint(0, 40)
        out.append(f"pow {h(a)} {h(e)} {h(a ** e)}")
        a = num(30)
        out.append(f"dec {h(a)} {a}")
    write("bigint.txt", out)
    write("x25519.txt", x25519_vectors(max(n // 3, 10)))
    import crypto_vectors
    for name, lines in crypto_vectors.generate().items():
        write(name, lines)
    import extra_vectors
    for name, lines in extra_vectors.generate().items():
        write(name, lines)
    import parity_vectors
    for name, lines in parity_vectors.generate().items():
        write(name, lines)


def write(name, lines):
    path = os.path.join(os.path.dirname(__file__), "..", "test", "vectors", name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} cases to {os.path.normpath(path)}")


if __name__ == "__main__":
    main()
