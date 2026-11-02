"""Vectors for Camellia (RFC 3713) and CMAC (SP 800-38B): camellia.txt.

A transcription of RFC 3713 (table S-boxes) and of CMAC, checked against
RFC 3713's Appendix A and RFC 4493's examples, and every vector against
the openssl command (Camellia ECB, CBC, CFB, OFB and CTR; CMAC over AES,
Camellia and 3DES), which must be installed.

It also redoes the derivation camellia.goose rests on: Camellia's s1 is
A2(S_aes(A1(x))) for affine A1, A2, found here by a linear-equivalence
search (guess-and-determine on t = L2 . inv . L1), and checked on all 256
inputs. The test checks the same composition, with the Goose planes code,
against SBOX1.

Used by gen_vectors.py, or run alone: python3 scripts/camellia_vectors.py
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))
import crypto_vectors as cv
from crypto_vectors import openssl, hx

rng = random.Random(20261102)


def rbytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


# RFC 3713 §2.4.1's SBOX1.
SBOX1 = [
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
    35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
    134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
    166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
    139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
    223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
    20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
    254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
    170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
    16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
    135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
    82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
    233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
    120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
    114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
    64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158,
]
assert SBOX1[0x3d] == 86  # RFC 3713's own example


def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 255


SBOX2 = [rotl8(SBOX1[x], 1) for x in range(256)]
SBOX3 = [rotl8(SBOX1[x], 7) for x in range(256)]
SBOX4 = [SBOX1[rotl8(x, 1)] for x in range(256)]


# --- the affine equivalence with AES's S-box --------------------------------

def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return r


INV = [0] * 256
for _a in range(1, 256):
    for _b in range(1, 256):
        if gmul(_a, _b) == 1:
            INV[_a] = _b


def aes_lin(v):
    return v ^ rotl8(v, 1) ^ rotl8(v, 2) ^ rotl8(v, 3) ^ rotl8(v, 4)


SAES = [aes_lin(INV[x]) ^ 0x63 for x in range(256)]
assert SAES[0] == 0x63 and SAES[0x53] == 0xed


def extend(m, a, b):
    """Extends the linear map m (a dict closed under XOR) by a -> b."""
    if a in m:
        return m[a] == b
    for k, v in list(m.items()):
        m[k ^ a] = v ^ b
    return True


def equivalence():
    """A1, A2 (as functions on bytes) with SBOX1 = A2 . SAES . A1."""
    for x0 in range(256):
        c2 = SBOX1[x0]
        t = [SBOX1[u ^ x0] ^ c2 for u in range(256)]
        tinv = [0] * 256
        for u, v in enumerate(t):
            tinv[v] = u
        # inv(a y) = a^-1 inv(y): L1(1) = 1 loses nothing; guess L1(2).
        for v2 in range(2, 256):
            la, lb = {0: 0}, {0: 0}
            ok = extend(la, 1, 1) and extend(la, 2, v2)
            while ok and len(la) < 256:
                before = (len(la), len(lb))
                for u, y in list(la.items()):
                    ok = ok and extend(lb, INV[y], t[u])
                for z, w in list(lb.items()):
                    ok = ok and extend(la, tinv[w], INV[z])
                if ok and (len(la), len(lb)) == before:
                    ok = False
            if not ok or len(set(la.values())) != 256:
                continue
            for u, y in la.items():
                ok = ok and extend(lb, INV[y], t[u])
            if ok and len(lb) == 256 and all(lb[INV[la[u]]] == t[u] for u in range(256)):
                ainv = [0] * 256
                for v in range(256):
                    ainv[aes_lin(v)] = v
                a1 = [la[x ^ x0] for x in range(256)]
                a2 = [lb[ainv[w ^ 0x63]] ^ c2 for w in range(256)]
                assert all(a2[SAES[a1[x]]] == SBOX1[x] for x in range(256))
                return a1, a2
    raise AssertionError("no affine equivalence found")


# The matrices camellia.goose's camellia_a1 and camellia_a2 hard-code: the
# images of the unit vectors and the constant.
A1_COLS, A1_CONST = [0x01, 0x19, 0xb1, 0xab, 0xa7, 0x93, 0x61, 0xd9], 0x08
A2_COLS, A2_CONST = [0x93, 0x95, 0x2f, 0x60, 0xb8, 0xd9, 0xa0, 0xa8], 0x11


def affine(cols, const, x):
    v = const
    for j in range(8):
        if x >> j & 1:
            v ^= cols[j]
    return v


def check_equivalence():
    a1, a2 = equivalence()
    assert all(affine(A1_COLS, A1_CONST, x) == a1[x] for x in range(256))
    assert all(affine(A2_COLS, A2_CONST, x) == a2[x] for x in range(256))
    assert all(affine(A2_COLS, A2_CONST, SAES[affine(A1_COLS, A1_CONST, x)]) == SBOX1[x] for x in range(256))


# --- Camellia ---------------------------------------------------------------

M64 = (1 << 64) - 1
M128 = (1 << 128) - 1
SIGMA = [0xA09E667F3BCC908B, 0xB67AE8584CAA73B2, 0xC6EF372FE94F82BE,
         0x54FF53A5F1D36F1C, 0x10E527FADE682D1D, 0xB05688C2B3E6C1FD]


def F(fin, ke):
    x = fin ^ ke
    t = [(x >> (56 - 8 * i)) & 255 for i in range(8)]
    boxes = [SBOX1, SBOX2, SBOX3, SBOX4, SBOX2, SBOX3, SBOX4, SBOX1]
    t1, t2, t3, t4, t5, t6, t7, t8 = [boxes[i][t[i]] for i in range(8)]
    y = [t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8, t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8, t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8,
         t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7, t1 ^ t2 ^ t6 ^ t7 ^ t8, t2 ^ t3 ^ t5 ^ t7 ^ t8,
         t3 ^ t4 ^ t5 ^ t6 ^ t8, t1 ^ t4 ^ t5 ^ t6 ^ t7]
    r = 0
    for v in y:
        r = r << 8 | v
    return r


def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def FL(x, k):
    x1, x2, k1, k2 = x >> 32, x & 0xffffffff, k >> 32, k & 0xffffffff
    x2 ^= rotl32(x1 & k1, 1)
    x1 ^= x2 | k2
    return x1 << 32 | x2


def FLINV(y, k):
    y1, y2, k1, k2 = y >> 32, y & 0xffffffff, k >> 32, k & 0xffffffff
    y1 ^= y2 | k2
    y2 ^= rotl32(y1 & k1, 1)
    return y1 << 32 | y2


def rol128(v, n):
    return ((v << n) | (v >> (128 - n))) & M128 if n % 128 else v


def schedule(key):
    K = int.from_bytes(key, "big")
    if len(key) == 16:
        KL, KR = K, 0
    elif len(key) == 24:
        KL, KR = K >> 64, ((K & M64) << 64) | (~K & M64)
    else:
        KL, KR = K >> 128, K & M128
    D1, D2 = (KL ^ KR) >> 64, (KL ^ KR) & M64
    D2 ^= F(D1, SIGMA[0])
    D1 ^= F(D2, SIGMA[1])
    D1 ^= KL >> 64
    D2 ^= KL & M64
    D2 ^= F(D1, SIGMA[2])
    D1 ^= F(D2, SIGMA[3])
    KA = D1 << 64 | D2
    D1, D2 = (KA ^ KR) >> 64, (KA ^ KR) & M64
    D2 ^= F(D1, SIGMA[4])
    D1 ^= F(D2, SIGMA[5])
    KB = D1 << 64 | D2

    def L(v, n):
        return rol128(v, n) >> 64

    def R(v, n):
        return rol128(v, n) & M64

    if len(key) == 16:
        kw = [L(KL, 0), R(KL, 0), L(KA, 111), R(KA, 111)]
        k = [L(KA, 0), R(KA, 0), L(KL, 15), R(KL, 15), L(KA, 15), R(KA, 15), L(KL, 45), R(KL, 45),
             L(KA, 45), R(KL, 60), L(KA, 60), R(KA, 60), L(KL, 94), R(KL, 94), L(KA, 94), R(KA, 94),
             L(KL, 111), R(KL, 111)]
        ke = [L(KA, 30), R(KA, 30), L(KL, 77), R(KL, 77)]
    else:
        kw = [L(KL, 0), R(KL, 0), L(KB, 111), R(KB, 111)]
        k = [L(KB, 0), R(KB, 0), L(KR, 15), R(KR, 15), L(KA, 15), R(KA, 15), L(KB, 30), R(KB, 30),
             L(KL, 45), R(KL, 45), L(KA, 45), R(KA, 45), L(KR, 60), R(KR, 60), L(KB, 60), R(KB, 60),
             L(KL, 77), R(KL, 77), L(KR, 94), R(KR, 94), L(KA, 94), R(KA, 94), L(KL, 111), R(KL, 111)]
        ke = [L(KR, 30), R(KR, 30), L(KL, 60), R(KL, 60), L(KA, 77), R(KA, 77)]
    return kw, k, ke


def camellia(key, blk, decrypt=False):
    kw, k, ke = schedule(key)
    if decrypt:
        kw, k, ke = [kw[2], kw[3], kw[0], kw[1]], k[::-1], ke[::-1]
    M = int.from_bytes(blk, "big")
    D1, D2 = (M >> 64) ^ kw[0], (M & M64) ^ kw[1]
    rounds = len(k) // 2
    for r in range(rounds):
        D2 ^= F(D1, k[2 * r])
        D1 ^= F(D2, k[2 * r + 1])
        if r % 3 == 2 and r != rounds - 1:
            D1 = FL(D1, ke[2 * (r // 3)])
            D2 = FLINV(D2, ke[2 * (r // 3) + 1])
    D2 ^= kw[2]
    D1 ^= kw[3]
    return ((D2 << 64) | D1).to_bytes(16, "big")


def ecb(key, data):
    return b"".join(camellia(key, data[i:i + 16]) for i in range(0, len(data), 16))


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def modes(mode, key, iv, data):
    out, x = b"", iv
    if mode == "cbc":
        for i in range(0, len(data), 16):
            x = camellia(key, xor(x, data[i:i + 16]))
            out += x
        return out
    if mode == "ctr":
        ctr = int.from_bytes(iv, "big")
        for i in range(0, len(data), 16):
            ks = camellia(key, (ctr % (1 << 128)).to_bytes(16, "big"))
            out += xor(ks, data[i:i + 16])
            ctr += 1
        return out
    for i in range(0, len(data), 16):
        ks = camellia(key, x)
        c = xor(ks, data[i:i + 16])
        out += c
        x = c if mode == "cfb" else ks
    return out


# --- CMAC -------------------------------------------------------------------

def des3(key, blk):
    return openssl(["enc", "-des-ede3-ecb", "-K", key.hex(), "-nopad"], blk)


def aes(key, blk):
    return openssl(["enc", f"-aes-{8 * len(key)}-ecb", "-K", key.hex(), "-nopad"], blk)


def dbl(v, bs):
    n = int.from_bytes(v, "big") << 1
    if n >> (8 * bs):
        n ^= (1 << (8 * bs)) | (0x87 if bs == 16 else 0x1b)
    return n.to_bytes(bs, "big")


def cmac(enc, bs, key, msg):
    L = enc(key, bytes(bs))
    k1 = dbl(L, bs)
    k2 = dbl(k1, bs)
    n = max(1, (len(msg) + bs - 1) // bs)
    whole = len(msg) > 0 and len(msg) % bs == 0
    last = msg[(n - 1) * bs:]
    last = xor(last, k1) if whole else xor(last + b"\x80" + bytes(bs - len(last) - 1), k2)
    x = bytes(bs)
    for i in range(n - 1):
        x = enc(key, xor(x, msg[i * bs:(i + 1) * bs]))
    return enc(key, xor(x, last))


OSSL_CMAC = {"aes": lambda k: f"AES-{8 * len(k)}-CBC", "camellia": lambda k: f"CAMELLIA-{8 * len(k)}-CBC",
             "des3": lambda k: "DES-EDE3-CBC"}


def ossl_cmac(cipher, key, msg):
    out = openssl(["mac", "-cipher", OSSL_CMAC[cipher](key), "-macopt", "hexkey:" + key.hex(), "CMAC"], msg)
    return bytes.fromhex(out.decode().strip())


# --- vectors ----------------------------------------------------------------

def generate():
    if not cv.OPENSSL:
        print("openssl not found: camellia.txt left as it is")
        return {}
    check_equivalence()
    out = ["sbox1 " + hx(bytes(SBOX1))]
    count = 0

    # RFC 3713 Appendix A.
    k = bytes.fromhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
    p = bytes.fromhex("0123456789abcdeffedcba9876543210")
    for n, want in [(16, "67673138549669730857065648eabe43"), (24, "b4993401b3e996f84ee5cee7d79b09b9"),
                    (32, "9acc237dff16d76c20ef7c919e3a7509")]:
        assert camellia(k[:n], p).hex() == want and camellia(k[:n], bytes.fromhex(want), True) == p
        out.append(f"block {hx(k[:n])} {hx(p)} {want}")

    # F on random inputs, and on the edges.
    for i in range(200):
        x, kk = rng.getrandbits(64), rng.getrandbits(64)
        if i < 4:
            x, kk = [(0, 0), (M64, 0), (0, M64), (0x0123456789abcdef, 0)][i]
        out.append(f"f {x:016x} {kk:016x} {F(x, kk):016x}")

    # Blocks: random, and all-zero / all-one keys and blocks.
    for n in (16, 24, 32):
        keys = [bytes(n), b"\xff" * n] + [rbytes(n) for _ in range(30)]
        for key in keys:
            pt = rbytes(16 * 4)
            ct = ecb(key, pt)
            assert openssl(["enc", f"-camellia-{8 * n}-ecb", "-K", key.hex(), "-nopad"], pt) == ct
            assert b"".join(camellia(key, ct[i:i + 16], True) for i in range(0, 64, 16)) == pt
            count += 1
            for i in range(0, 64, 16):
                out.append(f"block {hx(key)} {hx(pt[i:i + 16])} {hx(ct[i:i + 16])}")

    # The NESSIE-style known-answer sets: every one-bit plaintext under the
    # zero key (MIT's camellia-expect-vt.txt for 128 and 256 bits are this
    # set) and every one-bit key on the zero block, at each key size.
    for n in (16, 24, 32):
        pts = b"".join((1 << (127 - i)).to_bytes(16, "big") for i in range(128))
        cts = ecb(bytes(n), pts)
        assert openssl(["enc", f"-camellia-{8 * n}-ecb", "-K", bytes(n).hex(), "-nopad"], pts) == cts
        count += 1
        for i in range(128):
            out.append(f"block {hx(bytes(n))} {hx(pts[16 * i:16 * i + 16])} {hx(cts[16 * i:16 * i + 16])}")
        for i in range(8 * n):
            key = (1 << (8 * n - 1 - i)).to_bytes(n, "big")
            ct = camellia(key, bytes(16))
            assert openssl(["enc", f"-camellia-{8 * n}-ecb", "-K", key.hex(), "-nopad"], bytes(16)) == ct
            count += 1
            out.append(f"block {hx(key)} {hx(bytes(16))} {hx(ct)}")

    # Modes, through bignum.modes.
    for mode in ("cbc", "cfb", "ofb", "ctr"):
        for n in (16, 24, 32):
            for _ in range(6):
                key, iv = rbytes(n), rbytes(16)
                if mode == "ctr" and rng.random() < 0.5:
                    iv = b"\xff" * 15 + bytes([rng.randrange(250, 256)])  # the counter wraps
                ln = 16 * rng.randrange(1, 9) if mode == "cbc" else rng.randrange(1, 130)
                pt = rbytes(ln)
                ct = modes(mode, key, iv, pt)
                args = ["enc", f"-camellia-{8 * n}-{mode}", "-K", key.hex(), "-iv", iv.hex()]
                if mode == "cbc":
                    args.append("-nopad")
                assert openssl(args, pt) == ct, mode
                count += 1
                out.append(f"mode {mode} {hx(key)} {hx(iv)} {hx(pt)} {hx(ct)}")

    # CMAC: RFC 4493's examples, then every length around the block edges.
    rk = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    rm = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                       "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    for n, tag in [(0, "bb1d6929e95937287fa37d129b756746"), (16, "070a16b46b4d4144f79bdd9dd04a287c"),
                   (40, "dfa66747de9ae63030ca32611497c827"), (64, "51f0bebf7e3b9d92fc49741779363cfe")]:
        assert cmac(aes, 16, rk, rm[:n]).hex() == tag
        out.append(f"cmac aes {hx(rk)} {hx(rm[:n])} {tag}")
    enc = {"aes": aes, "camellia": lambda kk, b: camellia(kk, b), "des3": des3}
    for cipher, sizes, bs in (("aes", (16, 24, 32), 16), ("camellia", (16, 24, 32), 16), ("des3", (24,), 8)):
        for n in sizes:
            key = rbytes(n)
            lens = sorted(set([0, 1, bs - 1, bs, bs + 1, 2 * bs - 1, 2 * bs, 2 * bs + 1, 3 * bs, 64, 100]
                              + [rng.randrange(0, 200) for _ in range(6)]))
            for ln in lens:
                msg = rbytes(ln)
                tag = cmac(enc[cipher], bs, key, msg)
                assert ossl_cmac(cipher, key, msg) == tag, (cipher, n, ln)
                count += 1
                out.append(f"cmac {cipher} {hx(key)} {hx(msg)} {hx(tag)}")
    # Keys whose L has its top bit set and clear, so both arms of the
    # doubling run: searched for, with a message of each kind.
    for cipher, n, bs in (("aes", 16, 16), ("camellia", 16, 16), ("camellia", 32, 16), ("des3", 24, 8)):
        seen = set()
        while len(seen) < 4:
            key = rbytes(n)
            L = enc[cipher](key, bytes(bs))
            kind = (L[0] >> 7, dbl(L, bs)[0] >> 7)
            if kind in seen:
                continue
            seen.add(kind)
            for ln in (bs, bs + 3):
                msg = rbytes(ln)
                tag = cmac(enc[cipher], bs, key, msg)
                assert ossl_cmac(cipher, key, msg) == tag
                count += 1
                out.append(f"cmac {cipher} {hx(key)} {hx(msg)} {hx(tag)}")
    print(f"camellia: the affine equivalence holds; openssl agreed on {count} vectors")
    return {"camellia.txt": out}


if __name__ == "__main__":
    import gen_vectors
    for name, lines in generate().items():
        gen_vectors.write(name, lines)
