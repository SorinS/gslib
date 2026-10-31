#!/usr/bin/env python3
"""Vectors for bignum.ffdh: test/vectors/ffdh.txt, from Python's own pow.

Each MODP group's prime, made from RFC 3526's formula (2^n - 2^(n-64) - 1
+ 2^64 * (floor(2^(n-130) pi) + offset), pi to 1400 digits by Machin), then:

    prime <group> <p hex>
    pub <group> <x hex> <2^x mod p hex>
    shared <group> <x_a hex> <x_b hex> <(2^x_b)^x_a mod p hex>
    pow <group> <base hex> <x hex> <base^x mod p hex>

    python3 scripts/ffdh_vectors.py
"""

import os
import random
from decimal import Decimal, getcontext

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
GROUPS = {14: (2048, 124476), 15: (3072, 1690314), 16: (4096, 240904)}


def pi():
    getcontext().prec = 1400

    def arctan_inv(x):
        x = Decimal(x)
        s, t, n, sign = Decimal(0), 1 / x, 1, 1
        while t / n >= Decimal(10) ** -1350:
            s += t / n if sign > 0 else -t / n
            t /= x * x
            n += 2
            sign = -sign
        return s
    return 4 * (4 * arctan_inv(5) - arctan_inv(239))


def main():
    rng = random.Random(3526)
    PI = pi()
    lines = []
    for g, (n, off) in GROUPS.items():
        p = 2 ** n - 2 ** (n - 64) - 1 + 2 ** 64 * (int(Decimal(2) ** (n - 130) * PI) + off)
        w = n // 8
        h = lambda v, k=w: v.to_bytes(k, "big").hex()
        lines.append(f"prime {g} {h(p)}")
        for xlen in (32, 64, 128, w):
            x = rng.getrandbits(8 * xlen) | 1 << (8 * xlen - 1)
            lines.append(f"pub {g} {h(x, xlen)} {h(pow(2, x, p))}")
        xa = rng.getrandbits(512) | 1 << 511
        xb = rng.getrandbits(512) | 1 << 511
        lines.append(f"shared {g} {h(xa, 64)} {h(xb, 64)} {h(pow(pow(2, xb, p), xa, p))}")
        for _ in range(3):
            b = rng.randrange(2, p - 1)
            x = rng.getrandbits(8 * w - 1)
            lines.append(f"pow {g} {h(b)} {h(x)} {h(pow(b, x, p))}")
    with open(os.path.join(ROOT, "test", "vectors", "ffdh.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{len(lines)} lines")


if __name__ == "__main__":
    main()
