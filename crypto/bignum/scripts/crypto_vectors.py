"""Reference implementations and vectors for bignum's hashes, aes, gcm, rsa,
ec and ed25519.

Straight transcriptions of the standards on Python integers and bytes, kept
simple rather than fast: FIPS 197 (AES), SP 800-38A (CTR), SP 800-38D (GCM),
RFC 8017 (PKCS #1 v1.5 signatures, PSS, OAEP, all with SHA-256), SEC 1 and
RFC 6979 (ECDH and deterministic ECDSA on P-256 and P-384), RFC 8032
(Ed25519). Each is checked against published vectors here, and, when the
openssl command is installed, every AES, CTR, RSA, ECDH, ECDSA and Ed25519
vector is also checked against it, so a mistake in a transcription cannot
pass into the vectors unnoticed. Hashes, HMAC and HKDF come from hashlib
and hmac.

Used by gen_vectors.py; generate() returns {file name: lines}.
"""

import hashlib
import hmac
import os
import random
import shutil
import subprocess
import tempfile

rng = random.Random(20261026)


def hx(b):
    return b.hex() if b else "-"


# --- AES (FIPS 197) ---------------------------------------------------------

def gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = (a << 1) ^ (0x11B if a & 0x80 else 0)
        b >>= 1
    return r


def make_sbox():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if gf_mul(a, b) == 1:
                inv[a] = b
                break
    rotl = lambda x, k: ((x << k) | (x >> (8 - k))) & 0xFF
    return [inv[x] ^ rotl(inv[x], 1) ^ rotl(inv[x], 2) ^ rotl(inv[x], 3) ^ rotl(inv[x], 4) ^ 0x63
            for x in range(256)]


SBOX = make_sbox()
INV_SBOX = [SBOX.index(i) for i in range(256)]
assert SBOX[0] == 0x63 and SBOX[0x53] == 0xED


def key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = gf_mul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def mix(col, m):
    return [gf_mul(m[r][0], col[0]) ^ gf_mul(m[r][1], col[1]) ^ gf_mul(m[r][2], col[2])
            ^ gf_mul(m[r][3], col[3]) for r in range(4)]


MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def aes_encrypt(key, block):
    rk = key_expansion(key)
    s = [b ^ k for b, k in zip(block, rk[0])]          # s[4c + r]: column c, row r
    for rnd in range(1, len(rk)):
        s = [SBOX[b] for b in s]
        s = [s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]
        if rnd != len(rk) - 1:
            s = sum((mix(s[4 * c:4 * c + 4], MIX) for c in range(4)), [])
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    return bytes(s)


def aes_decrypt(key, block):
    rk = key_expansion(key)
    s = [b ^ k for b, k in zip(block, rk[-1])]
    for rnd in range(len(rk) - 2, -1, -1):
        s = [s[4 * ((c - r) % 4) + r] for c in range(4) for r in range(4)]
        s = [INV_SBOX[b] for b in s]
        s = [b ^ k for b, k in zip(s, rk[rnd])]
        if rnd != 0:
            s = sum((mix(s[4 * c:4 * c + 4], INV_MIX) for c in range(4)), [])
    return bytes(s)


FIPS197 = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "8ea2b7ca516745bfeafc49904b496089"),
]
for k, c in FIPS197:
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes_encrypt(bytes.fromhex(k), pt).hex() == c
    assert aes_decrypt(bytes.fromhex(k), bytes.fromhex(c)) == pt


def aes_ctr(key, iv, data):
    out = bytearray()
    ctr = int.from_bytes(iv, "big")
    for off in range(0, len(data), 16):
        ks = aes_encrypt(key, ctr.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(data[off:off + 16], ks))
        ctr = (ctr + 1) % (1 << 128)
    return bytes(out)


# --- GCM (SP 800-38D) -------------------------------------------------------

def gf128_mul(x, y):
    r = 0xE1 << 120
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def ghash(h, data):
    y = 0
    for off in range(0, len(data), 16):
        blk = data[off:off + 16].ljust(16, b"\0")
        y = gf128_mul(y ^ int.from_bytes(blk, "big"), h)
    return y


def pad16(b):
    return b + b"\0" * (-len(b) % 16)


def gcm_encrypt(key, iv, aad, pt):
    h = int.from_bytes(aes_encrypt(key, bytes(16)), "big")
    if len(iv) == 12:
        j0 = iv + b"\0\0\0\1"
    else:
        j0 = ghash(h, pad16(iv) + (8 * len(iv)).to_bytes(16, "big")).to_bytes(16, "big")

    def inc32(b):
        return b[:12] + ((int.from_bytes(b[12:], "big") + 1) % (1 << 32)).to_bytes(4, "big")

    ct = bytearray()
    cb = inc32(j0)
    for off in range(0, len(pt), 16):
        ks = aes_encrypt(key, cb)
        ct += bytes(a ^ b for a, b in zip(pt[off:off + 16], ks))
        cb = inc32(cb)
    ct = bytes(ct)
    s = ghash(h, pad16(aad) + pad16(ct) + (8 * len(aad)).to_bytes(8, "big")
              + (8 * len(ct)).to_bytes(8, "big"))
    tag = bytes(a ^ b for a, b in zip(aes_encrypt(key, j0), s.to_bytes(16, "big")))
    return ct, tag


# The test cases of the GCM specification (McGrew and Viega), 1 to 5.
_K = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
_P = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                   "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
_A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
GCM_SPEC = [
    (bytes(16), bytes(12), b"", b"", "", "58e2fccefa7e3061367f1d57a4e7455a"),
    (bytes(16), bytes(12), b"", bytes(16), "0388dace60b6a392f328c2b971b2fe78",
     "ab6e47d42cec13bdf53a67b21257bddf"),
    (_K, bytes.fromhex("cafebabefacedbaddecaf888"), b"", _P,
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
     "4d5c2af327cd64a62cf35abd2ba6fab4"),
    (_K, bytes.fromhex("cafebabefacedbaddecaf888"), _A, _P[:60],
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47"),
    (_K, bytes.fromhex("cafebabefacedbad"), _A, _P[:60],
     "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423"
     "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
     "3612d2e79e3b0785561be14aaca2fccb"),
]
for k, iv, a, p, c, t in GCM_SPEC:
    got = gcm_encrypt(k, iv, a, p)
    assert (got[0].hex(), got[1].hex()) == (c, t)


# --- RSA (RFC 8017, SHA-256) ------------------------------------------------

DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
DIGEST_INFOS = {"sha256": DIGEST_INFO,
                "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
                "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
                "sha512_256": bytes.fromhex("3031300d060960864801650304020605000420"),
                "sha3_256": bytes.fromhex("3031300d060960864801650304020805000420"),
                "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
                "sha512": bytes.fromhex("3051300d060960864801650304020305000440")}


def is_probable_prime(n, rounds=40):
    if n < 4:
        return n in (2, 3)
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits, e):
    while True:
        p = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if math_gcd(p - 1, e) == 1 and is_probable_prime(p):
            return p


def math_gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def rsa_key(pbits, qbits, e):
    while True:
        p, q = random_prime(pbits, e), random_prime(qbits, e)
        if p == q:
            continue
        lam = (p - 1) * (q - 1) // math_gcd(p - 1, q - 1)
        return {"n": p * q, "e": e, "d": pow(e, -1, lam), "p": p, "q": q}


def i2osp(x, k):
    return x.to_bytes(k, "big")


def mgf1(seed, n, hn="sha256"):
    out = b""
    c = 0
    while len(out) < n:
        out += hashlib.new(hn, seed + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:n]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def k_of(key):
    return (key["n"].bit_length() + 7) // 8


def pkcs1_sign(key, msg, hn="sha256"):
    k = k_of(key)
    t = DIGEST_INFOS[hn] + hashlib.new(hn, msg).digest()
    em = b"\0\1" + b"\xff" * (k - len(t) - 3) + b"\0" + t
    return i2osp(pow(int.from_bytes(em, "big"), key["d"], key["n"]), k)


def pss_sign(key, msg, salt, hn="sha256"):
    embits = key["n"].bit_length() - 1
    emlen = (embits + 7) // 8
    hl = hashlib.new(hn).digest_size
    mhash = hashlib.new(hn, msg).digest()
    h = hashlib.new(hn, b"\0" * 8 + mhash + salt).digest()
    db = b"\0" * (emlen - len(salt) - hl - 2) + b"\1" + salt
    masked = bytearray(xor(db, mgf1(h, emlen - hl - 1, hn)))
    masked[0] &= 0xFF >> (8 * emlen - embits)
    em = bytes(masked) + h + b"\xbc"
    return i2osp(pow(int.from_bytes(em, "big"), key["d"], key["n"]), k_of(key))


def oaep_encrypt(key, msg, label, seed):
    k = k_of(key)
    lhash = hashlib.sha256(label).digest()
    db = lhash + b"\0" * (k - len(msg) - 66) + b"\1" + msg
    masked_db = xor(db, mgf1(seed, k - 33))
    masked_seed = xor(seed, mgf1(masked_db, 32))
    em = b"\0" + masked_seed + masked_db
    return i2osp(pow(int.from_bytes(em, "big"), key["e"], key["n"]), k)


# --- P-256 and P-384 (SEC 1, RFC 6979) ---------------------------------------

CURVES = {
    "p256": dict(
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        size=32, hash="sha256", oid="2a8648ce3d030107"),
    "p384": dict(
        p=int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
              "ffffffff0000000000000000ffffffff", 16),
        n=int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
              "581a0db248b0a77aecec196accc52973", 16),
        b=int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
              "c656398d8a2ed19d2a85c8edd3ec2aef", 16),
        gx=int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
               "5502f25dbf55296c3a545e3872760ab7", 16),
        gy=int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
               "0a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
        size=48, hash="sha384", oid="2b81040022"),
    "p521": dict(
        p=2 ** 521 - 1,
        n=int("1ff" + "ffffffff" * 7 + "fffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16),
        b=int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd"
              "3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
        gx=int("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127"
               "a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
        gy=int("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013f"
               "ad0761353c7086a272c24088be94769fd16650", 16),
        size=66, hash="sha512", oid="2b81040023"),
}


def bits2int(c, b):
    """The leftmost bits of b, as many as the order has (RFC 6979 §2.3.2)."""
    x = int.from_bytes(b, "big")
    qbits = c["n"].bit_length()
    if 8 * len(b) > qbits:
        x >>= 8 * len(b) - qbits
    return x


def ec_add(c, P, Q):
    p = c["p"]
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        l = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p) % p
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (l * l - x1 - x2) % p
    return x3, (l * (x1 - x3) - y1) % p


def ec_mul(c, k, P):
    R = None
    for bit in bin(k)[2:] if k else "":
        R = ec_add(c, R, R)
        if bit == "1":
            R = ec_add(c, R, P)
    return R


def ec_check(c):
    p, G = c["p"], (c["gx"], c["gy"])
    assert (G[1] ** 2 - G[0] ** 3 + 3 * G[0] - c["b"]) % p == 0
    assert is_probable_prime(p) and is_probable_prime(c["n"])
    assert ec_mul(c, c["n"], G) is None


def ec_encode(c, P):
    return b"\4" + P[0].to_bytes(c["size"], "big") + P[1].to_bytes(c["size"], "big")


def rfc6979_k(c, d, h):
    size, hn, n = c["size"], c["hash"], c["n"]
    x = d.to_bytes(size, "big")
    h1 = (bits2int(c, h) % n).to_bytes(size, "big")
    v, k = b"\1" * len(h), b"\0" * len(h)
    for sep in (b"\0", b"\1"):
        k = hmac.new(k, v + sep + x + h1, hn).digest()
        v = hmac.new(k, v, hn).digest()
    while True:
        t = b""
        while len(t) < size:
            v = hmac.new(k, v, hn).digest()
            t += v
        cand = bits2int(c, t)
        if 1 <= cand < n:
            yield cand
        k = hmac.new(k, v + b"\0", hn).digest()
        v = hmac.new(k, v, hn).digest()


def ecdsa_sign(c, d, msg):
    n = c["n"]
    h = hashlib.new(c["hash"], msg).digest()
    e = bits2int(c, h)
    for k in rfc6979_k(c, d, h):
        r = ec_mul(c, k, (c["gx"], c["gy"]))[0] % n
        s = pow(k, -1, n) * (e + r * d) % n
        if r and s:
            return r.to_bytes(c["size"], "big") + s.to_bytes(c["size"], "big")


# RFC 6979 A.2.5 and A.2.6, message "sample".
RFC6979 = [
    ("p256", 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721,
     "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
     "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"),
    ("p384", int("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8"
                 "96d5724e4c70a825f872c9ea60d2edf5", 16),
     "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c"
     "81a648152e44acf96e36dd1e80fabe46"
     "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f"
     "a329c145786e679e7b82c71a38628ac8"),
    ("p521", int("0fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1"
                 "466f6d8fbec67db89ec0c08b0e996b83538", 16),
     "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b5349"
     "31d7d4e8455cc91f9b15bf05ec36e377fa"
     "00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b"
     "1a20f8ccb1dccc43997f1ee0e44da4a67a"),
]


def der_sig(raw):
    def i(b):
        b = b.lstrip(b"\0") or b"\0"
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\2" + bytes([len(b)]) + b
    half = len(raw) // 2
    body = i(raw[:half]) + i(raw[half:])
    return b"\x30" + der_len(len(body)) + body


# --- Ed25519 (RFC 8032 §5.1, after its Python reference) ---------------------

EP = 2 ** 255 - 19
ED_L = 2 ** 252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, -1, EP) % EP
ED_I = pow(2, (EP - 1) // 4, EP)


def ed_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % EP
    b = (y1 + x1) * (y2 + x2) % EP
    c = t1 * 2 * ED_D * t2 % EP
    d = z1 * 2 * z2 % EP
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % EP, g * h % EP, f * g % EP, e * h % EP


def ed_mul(s, P):
    Q = (0, 1, 1, 0)
    while s:
        if s & 1:
            Q = ed_add(Q, P)
        P = ed_add(P, P)
        s >>= 1
    return Q


def ed_recover_x(y, sign):
    if y >= EP:
        return None
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, -1, EP)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (EP + 3) // 8, EP)
    if (x * x - x2) % EP:
        x = x * ED_I % EP
    if (x * x - x2) % EP:
        return None
    if (x & 1) != sign:
        x = EP - x
    return x


ED_GY = 4 * pow(5, -1, EP) % EP
ED_GX = ed_recover_x(ED_GY, 0)
ED_G = (ED_GX, ED_GY, 1, ED_GX * ED_GY % EP)


def ed_encode(P):
    zi = pow(P[2], -1, EP)
    x, y = P[0] * zi % EP, P[1] * zi % EP
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed_secret(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed_sha512_modl(b):
    return int.from_bytes(hashlib.sha512(b).digest(), "little") % ED_L


def ed_sign(seed, msg):
    a, prefix = ed_secret(seed)
    A = ed_encode(ed_mul(a, ED_G))
    r = ed_sha512_modl(prefix + msg)
    R = ed_encode(ed_mul(r, ED_G))
    k = ed_sha512_modl(R + A + msg)
    return A, R + ((r + k * a) % ED_L).to_bytes(32, "little")


# RFC 8032 §7.1, tests 1 to 3.
ED_RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
for seed, m, pk, sig in ED_RFC:
    A, S = ed_sign(bytes.fromhex(seed), bytes.fromhex(m))
    assert (A.hex(), S.hex()) == (pk, sig)


# --- ChaCha20 and Poly1305 (RFC 8439) ----------------------------------------

def chacha_block(key, counter, nonce):
    def qr(x, a, b, c, d):
        for (p, q, r, n) in ((a, b, d, 16), (c, d, b, 12), (a, b, d, 8), (c, d, b, 7)):
            x[p] = (x[p] + x[q]) & 0xffffffff
            x[r] ^= x[p]
            x[r] = ((x[r] << n) | (x[r] >> (32 - n))) & 0xffffffff
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    s += [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]
    s += [counter] + [int.from_bytes(nonce[4 * i:4 * i + 4], "little") for i in range(3)]
    x = list(s)
    for _ in range(10):
        qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
        qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
    return b"".join(((a + b) & 0xffffffff).to_bytes(4, "little") for a, b in zip(x, s))


def chacha_xor(key, counter, nonce, data):
    out = bytearray()
    for off in range(0, len(data), 64):
        ks = chacha_block(key, counter + off // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[off:off + 64], ks))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for off in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[off:off + 16] + b"\1", "little")) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def chacha_aead(key, nonce, aad, pt):
    otk = chacha_block(key, 0, nonce)[:32]
    ct = chacha_xor(key, 1, nonce, pt)
    mac = (aad + bytes(-len(aad) % 16) + ct + bytes(-len(ct) % 16)
           + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little"))
    return ct, poly1305(otk, mac)


_SUNSCREEN = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
              b"for the future, sunscreen would be it.")
assert poly1305(bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                b"Cryptographic Forum Research Group").hex() == "a8061dc1305136c6c22b8baf0c0127a9"
assert chacha_aead(bytes(range(0x80, 0xa0)), bytes.fromhex("070000004041424344454647"),
                   bytes.fromhex("50515253c0c1c2c3c4c5c6c7"), _SUNSCREEN)[1].hex() \
    == "1ae10b594f09e26a7e902ecbd0600691"
# §2.3.2: the block function's test vector, the first bytes of the output.
assert chacha_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000")).hex() \
    .startswith("10f1e7e4d13b5915500fdd1fa32071c4")


# --- openssl cross-checks ---------------------------------------------------

OPENSSL = shutil.which("openssl")


def der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_int(x):
    b = x.to_bytes((x.bit_length() + 8) // 8, "big")
    return b"\x02" + der_len(len(b)) + b


def rsa_der(key):
    p, q, d = key["p"], key["q"], key["d"]
    body = b"".join(der_int(v) for v in (0, key["n"], key["e"], d, p, q, d % (p - 1),
                                          d % (q - 1), pow(q, -1, p)))
    return b"\x30" + der_len(len(body)) + body


def openssl(args, data=None):
    p = subprocess.run([OPENSSL, *args], input=data, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
    return p.stdout


class OpenSSLCheck:
    def __init__(self):
        self.tmp = tempfile.mkdtemp()
        self.count = 0

    def path(self, name, data=None):
        p = os.path.join(self.tmp, name)
        if data is not None:
            with open(p, "wb") as f:
                f.write(data)
        return p

    def aes_ecb(self, key, pt, ct):
        out = openssl(["enc", f"-aes-{8 * len(key)}-ecb", "-K", key.hex(), "-nopad"], pt)
        assert out == ct, "openssl disagrees on AES"
        self.count += 1

    def aes_ctr(self, key, iv, pt, ct):
        out = openssl(["enc", f"-aes-{8 * len(key)}-ctr", "-K", key.hex(), "-iv", iv.hex()], pt)
        assert out == ct, "openssl disagrees on CTR"
        self.count += 1

    def key(self, key):
        der = self.path("k.der", rsa_der(key))
        pem = self.path("k.pem")
        openssl(["pkey", "-inform", "DER", "-in", der, "-out", pem])
        return pem

    def verify(self, pem, msg, sig, pss_salt=None, hn="sha256", digest=None):
        opts = ["-pkeyopt", f"digest:{hn}"]
        if pss_salt is not None:
            opts += ["-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", f"rsa_pss_saltlen:{pss_salt}"]
        dg = self.path("dg", digest if digest is not None else hashlib.new(hn, msg).digest())
        sf = self.path("sig", sig)
        out = openssl(["pkeyutl", "-verify", "-inkey", pem, "-in", dg, "-sigfile", sf, *opts])
        assert b"Verified Successfully" in out, "openssl rejects a signature"
        self.count += 1

    def oaep(self, pem, ct, label, msg):
        opts = ["-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256"]
        if label:
            opts += ["-pkeyopt", f"rsa_oaep_label:{label.hex()}"]
        out = openssl(["pkeyutl", "-decrypt", "-inkey", pem, "-in", self.path("ct", ct), *opts])
        assert out == msg, "openssl decrypts OAEP differently"
        self.count += 1

    def ec_keys(self, name, d):
        c = CURVES[name]
        oid = bytes.fromhex("06" + format(len(c["oid"]) // 2, "02x") + c["oid"])
        pub = ec_encode(c, ec_mul(c, d, (c["gx"], c["gy"])))
        bits = b"\3" + der_len(len(pub) + 1) + b"\0" + pub
        body = (b"\2\1\1" + b"\4" + bytes([c["size"]]) + d.to_bytes(c["size"], "big")
                + b"\xa0" + der_len(len(oid)) + oid + b"\xa1" + der_len(len(bits)) + bits)
        der = self.path(f"{name}.der", b"\x30" + der_len(len(body)) + body)
        pem = self.path(f"{name}-{d % 1000}.pem")
        openssl(["pkey", "-inform", "DER", "-in", der, "-out", pem])
        pubpem = pem + ".pub"
        openssl(["pkey", "-in", pem, "-pubout", "-out", pubpem])
        return pem, pubpem

    def ecdh(self, name, d1, d2, shared):
        pem, _ = self.ec_keys(name, d1)
        _, pub2 = self.ec_keys(name, d2)
        out = openssl(["pkeyutl", "-derive", "-inkey", pem, "-peerkey", pub2])
        assert out == shared, "openssl disagrees on ECDH"
        self.count += 1

    def ecdsa(self, name, d, msg, raw):
        _, pub = self.ec_keys(name, d)
        out = openssl(["dgst", "-" + CURVES[name]["hash"], "-verify", pub, "-signature",
                       self.path("sig.der", der_sig(raw)), self.path("msg", msg)])
        assert b"Verified OK" in out, "openssl rejects an ECDSA signature"
        self.count += 1

    def ed25519(self, seed, msg, sig):
        der = self.path("ed.der", bytes.fromhex("302e020100300506032b657004220420") + seed)
        pem = self.path("ed.pem")
        openssl(["pkey", "-inform", "DER", "-in", der, "-out", pem])
        out = openssl(["pkeyutl", "-sign", "-rawin", "-inkey", pem, "-in", self.path("msg", msg)])
        assert out == sig, "openssl signs Ed25519 differently"
        self.count += 1

    def chacha(self, key, counter, nonce, pt, ct):
        iv = counter.to_bytes(4, "little") + nonce
        out = openssl(["enc", "-chacha20", "-K", key.hex(), "-iv", iv.hex()], pt)
        assert out == ct, "openssl disagrees on ChaCha20"
        self.count += 1

    def poly1305(self, key, msg, tag):
        out = openssl(["mac", "-macopt", f"hexkey:{key.hex()}", "-in", self.path("m", msg),
                       "POLY1305"])
        assert out.strip().lower() == tag.hex().encode(), "openssl disagrees on Poly1305"
        self.count += 1

    def done(self):
        shutil.rmtree(self.tmp)


# --- the vectors ------------------------------------------------------------

def rbytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def generate():
    chk = OpenSSLCheck() if OPENSSL else None
    out = {}

    sha = []
    for n in list(range(0, 130)) + [rng.randint(130, 2000) for _ in range(20)]:
        m = rbytes(n)
        sha.append(f"sha256 {hx(m)} {hashlib.sha256(m).hexdigest()}")
    out["sha256.txt"] = sha

    aes = [f"sbox {bytes(SBOX).hex()}"]
    for i in range(60):
        key = rbytes((16, 24, 32)[i % 3])
        pt = rbytes(16)
        ct = aes_encrypt(key, pt)
        assert aes_decrypt(key, ct) == pt
        if chk:
            chk.aes_ecb(key, pt, ct)
        aes.append(f"block {hx(key)} {hx(pt)} {hx(ct)}")
    for i in range(36):
        key = rbytes((16, 24, 32)[i % 3])
        iv = rbytes(16)
        if i % 4 == 1:
            iv = iv[:13] + b"\xff\xff\xff"                  # carries past the low word
        if i % 4 == 2:
            iv = b"\xff" * 15 + bytes([rng.randint(250, 255)])  # wraps the whole block
        pt = rbytes(rng.choice([0, 1, 15, 16, 17, 31, 32, 33, rng.randint(34, 200)]))
        ct = aes_ctr(key, iv, pt)
        if chk and pt:
            chk.aes_ctr(key, iv, pt, ct)
        aes.append(f"ctr {hx(key)} {hx(iv)} {hx(pt)} {hx(ct)}")
    out["aes.txt"] = aes

    gcm = []
    for k, iv, a, p, c, t in GCM_SPEC:
        gcm.append(f"gcm {hx(k)} {hx(iv)} {hx(a)} {hx(p)} {c or '-'} {t}")
    for i in range(60):
        key = rbytes((16, 24, 32)[i % 3])
        iv = rbytes(12 if i % 3 else rng.choice([1, 8, 16, 17, 60]))
        aad = rbytes(rng.choice([0, 0, 1, 13, 16, 20, 33]))
        pt = rbytes(rng.choice([0, 1, 15, 16, 17, 32, 33, 64, rng.randint(65, 300)]))
        c, t = gcm_encrypt(key, iv, aad, pt)
        gcm.append(f"gcm {hx(key)} {hx(iv)} {hx(aad)} {hx(pt)} {hx(c)} {hx(t)}")
    out["gcm.txt"] = gcm

    rsa = []
    # Balanced and unbalanced primes, a modulus one bit past a byte (so PSS's
    # encoding is a byte shorter than the modulus), and e = 3.
    for name, pb, qb, e in [("k1024", 512, 512, 65537), ("k1025", 513, 512, 65537),
                            ("k1536", 768, 768, 3), ("k2048", 1024, 1024, 65537)]:
        key = rsa_key(pb, qb, e)
        assert key["n"].bit_length() == pb + qb
        pem = chk.key(key) if chk else None
        rsa.append(f"key {name} " + " ".join(format(key[x], "x") for x in "nedpq"))
        k = k_of(key)
        for i in range(3):
            m = rbytes(rng.choice([0, 3, 64, 200]))
            s = pkcs1_sign(key, m)
            if chk:
                chk.verify(pem, m, s)
            rsa.append(f"pkcs1 {name} {hx(m)} {hx(s)}")
        for slen in (32, 32, 0, 20):
            m = rbytes(rng.choice([0, 5, 100]))
            salt = rbytes(slen)
            s = pss_sign(key, m, salt)
            if chk:
                chk.verify(pem, m, s, slen)
            rsa.append(f"pss {name} {hx(m)} {hx(salt)} {hx(s)}")
        for mlen in (0, k - 66, rng.randint(1, k - 67)):
            m = rbytes(mlen)
            label = rbytes(rng.choice([0, 0, 7]))
            seed = rbytes(32)
            c = oaep_encrypt(key, m, label, seed)
            if chk:
                chk.oaep(pem, c, label, m)
            rsa.append(f"oaep {name} {hx(m)} {hx(label)} {hx(seed)} {hx(c)}")
    out["rsa.txt"] = rsa

    hashes = []
    for n in list(range(0, 260, 7)) + [111, 112, 127, 128, 129, 239, 240, rng.randint(300, 3000)]:
        m = rbytes(n)
        hashes.append(f"sha384 {hx(m)} {hashlib.sha384(m).hexdigest()}")
        hashes.append(f"sha512 {hx(m)} {hashlib.sha512(m).hexdigest()}")
    for bits in (256, 384, 512):
        for klen in (0, 3, 32, 64, 65, 128, 129, 200):
            key, msg = rbytes(klen), rbytes(rng.randint(0, 300))
            mac = hmac.new(key, msg, f"sha{bits}").hexdigest()
            hashes.append(f"hmac {bits} {hx(key)} {hx(msg)} {mac}")
    # HKDF: RFC 5869 test case 1, then random ones.
    hkdf_cases = [(256, bytes.fromhex("000102030405060708090a0b0c"), bytes([0x0b] * 22),
                   bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)]
    for bits in (256, 384, 256, 384, 512):
        hkdf_cases.append((bits, rbytes(rng.choice([0, 16, 32])), rbytes(rng.randint(1, 80)),
                           rbytes(rng.randint(0, 30)), rng.choice([1, 32, 48, 100, 255])))
    for bits, salt, ikm, info, n in hkdf_cases:
        hn = f"sha{bits}"
        prk = hmac.new(salt or bytes(bits // 8), ikm, hn).digest()
        okm, t, i = b"", b"", 1
        while len(okm) < n:
            t = hmac.new(prk, t + info + bytes([i]), hn).digest()
            okm, i = okm + t, i + 1
        hashes.append(f"hkdf {bits} {hx(salt)} {hx(ikm)} {hx(info)} {n} {okm[:n].hex()}")
    assert hashes[-6].endswith("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                               "34007208d5b887185865")
    out["hash.txt"] = hashes

    ec = []
    for name, d, sig in RFC6979[:2]:
        c = CURVES[name]
        ec_check(c)
        assert ecdsa_sign(c, d, b"sample").hex() == sig
    for name in ("p256", "p384"):
        c = CURVES[name]
        n, size = c["n"], c["size"]
        G = (c["gx"], c["gy"])
        for k in [1, 2, 3, n - 1, n - 2] + [rng.randrange(1, n) for _ in range(6)]:
            ec.append(f"mul {name} {format(k, 'x')} {ec_encode(c, ec_mul(c, k, G)).hex()}")
        for i in range(6):
            d1, d2 = rng.randrange(1, n), rng.randrange(1, n)
            if i == 0:
                d1 = n - 1
            p2 = ec_encode(c, ec_mul(c, d2, G))
            shared = ec_mul(c, d1, ec_mul(c, d2, G))[0].to_bytes(size, "big")
            if chk:
                chk.ecdh(name, d1, d2, shared)
            ec.append(f"ecdh {name} {d1.to_bytes(size, 'big').hex()} {p2.hex()} {shared.hex()}")
        for i in range(8):
            d = rng.randrange(1, n)
            msg = rbytes(rng.choice([0, 6, 100]))
            raw = ecdsa_sign(c, d, msg)
            if chk:
                chk.ecdsa(name, d, msg, raw)
            pub = ec_encode(c, ec_mul(c, d, G))
            ec.append(f"ecdsa {name} {d.to_bytes(size, 'big').hex()} {pub.hex()} {hx(msg)} "
                      f"{raw.hex()} {der_sig(raw).hex()}")
    out["ec.txt"] = ec

    ed = []
    for seed, m, pk, sig in ED_RFC:
        ed.append(f"ed25519 {seed} {m or '-'} {pk} {sig}")
    for i in range(30):
        seed, msg = rbytes(32), rbytes(rng.choice([0, 1, 32, 64, 200]))
        A, sig = ed_sign(seed, msg)
        if chk and msg:                                  # openssl cannot sign b""
            chk.ed25519(seed, msg, sig)
        ed.append(f"ed25519 {seed.hex()} {hx(msg)} {A.hex()} {sig.hex()}")
    out["ed25519.txt"] = ed

    cc = [f"aead {hx(bytes(range(0x80, 0xa0)))} 070000004041424344454647 "
          f"50515253c0c1c2c3c4c5c6c7 {hx(_SUNSCREEN)} "
          + "".join(x.hex() for x in chacha_aead(bytes(range(0x80, 0xa0)),
                                                 bytes.fromhex("070000004041424344454647"),
                                                 bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
                                                 _SUNSCREEN))]
    cc[0] = cc[0][:-32] + " " + cc[0][-32:]
    for i in range(30):
        key, nonce = rbytes(32), rbytes(12)
        counter = rng.choice([0, 1, 7, 0xfffffff0])          # no wrap: 400 bytes at most
        pt = rbytes(rng.choice([0, 1, 63, 64, 65, 128, rng.randint(129, 400)]))
        ct = chacha_xor(key, counter, nonce, pt)
        if chk and pt:
            chk.chacha(key, counter, nonce, pt, ct)
        cc.append(f"chacha {hx(key)} {counter} {hx(nonce)} {hx(pt)} {hx(ct)}")
    for i in range(30):
        key = rbytes(32)
        if i == 0:
            key = b"\xff" * 32                              # r and s at their largest
        msg = rbytes(rng.choice([0, 1, 15, 16, 17, 32, 64, rng.randint(65, 300)]))
        if i == 1:
            msg = b"\xff" * 64
        tag = poly1305(key, msg)
        if chk:
            chk.poly1305(key, msg, tag)
        cc.append(f"poly1305 {hx(key)} {hx(msg)} {hx(tag)}")
    for i in range(30):
        key, nonce = rbytes(32), rbytes(12)
        aad = rbytes(rng.choice([0, 5, 12, 16, 33]))
        pt = rbytes(rng.choice([0, 1, 16, 63, 64, 65, rng.randint(66, 300)]))
        ct, tag = chacha_aead(key, nonce, aad, pt)
        cc.append(f"aead {hx(key)} {hx(nonce)} {hx(aad)} {hx(pt)} {hx(ct)} {hx(tag)}")
    out["chacha20.txt"] = cc


    # SHA-384 and SHA-512 signatures, under a key of their own so that the
    # vectors above stay as they were.
    key = rsa_key(1024, 1024, 65537)
    pem = chk.key(key) if chk else None
    key2048b, pem2048b = key, pem
    rsa.append("key k2048b " + " ".join(format(key[x], "x") for x in "nedpq"))
    for bits in (384, 512, 256):
        hn = f"sha{bits}"
        for i in range(2):
            m = rbytes(rng.choice([0, 40, 300]))
            sig = pkcs1_sign(key, m, hn)
            if chk:
                chk.verify(pem, m, sig, None, hn)
            rsa.append(f"pkcs1h {bits} {hx(m)} {hx(sig)}")
            salt = rbytes(bits // 8 if i == 0 else 20)
            sig = pss_sign(key, m, salt, hn)
            if chk:
                chk.verify(pem, m, sig, len(salt), hn)
            rsa.append(f"pssh {bits} {hx(m)} {hx(salt)} {hx(sig)}")

    # SHA-1, SHA-224 and the SHA-512/t and SHA-3 hashes, with HMAC over them
    # and PKCS #1 v1.5 signatures under the key above.
    ids = {"sha1": 160, "sha224": 224, "sha512_224": 5224, "sha512_256": 5256,
           "sha3_224": 3224, "sha3_256": 3256, "sha3_384": 3384, "sha3_512": 3512}
    more = []
    lens = sorted(set([0, 1, 55, 56, 63, 64, 65, 71, 72, 73, 103, 104, 111, 112, 127, 128, 135, 136, 137,
                       143, 144, 167, 168, 169, 300, rng.randint(400, 2000)]))
    for n in lens:
        m = rbytes(n)
        for name, hid in ids.items():
            more.append(f"hash {hid} {hx(m)} {hashlib.new(name, m).hexdigest()}")
        for bits in (128, 256):
            for outn in (1, 32, 200):
                more.append(f"shake {bits} {hx(m)} {outn} {hashlib.new(f'shake_{bits}', m).hexdigest(outn)}")
    for name, hid in ids.items():
        for klen in (0, 20, 64, 72, 136, 145, 200):
            key, msg = rbytes(klen), rbytes(rng.randint(0, 300))
            more.append(f"hmac {hid} {hx(key)} {hx(msg)} {hmac.new(key, msg, name).hexdigest()}")
    out["hash2.txt"] = more
    opensslname = {"sha1": "sha1", "sha224": "sha224", "sha512_256": "sha512-256", "sha3_256": "sha3-256"}
    for name in ("sha1", "sha224", "sha512_256", "sha3_256"):
        m = rbytes(rng.choice([0, 40, 300]))
        di = DIGEST_INFOS[name] + hashlib.new(name, m).digest()
        kk = k_of(key2048b)
        em = b"\0\1" + b"\xff" * (kk - len(di) - 3) + b"\0" + di
        sig = i2osp(pow(int.from_bytes(em, "big"), key2048b["d"], key2048b["n"]), kk)
        if chk:
            chk.verify(pem2048b, m, sig, None, opensslname[name], hashlib.new(name, m).digest())
        rsa.append(f"pkcs1h {ids[name]} {hx(m)} {hx(sig)}")

    # P-521, after everything else so the vectors above stay as they were.
    ec521 = []
    c = CURVES["p521"]
    ec_check(c)
    assert ecdsa_sign(c, RFC6979[2][1], b"sample").hex() == RFC6979[2][2]
    n, size = c["n"], c["size"]
    G = (c["gx"], c["gy"])
    for k in [1, 2, n - 1, n - 2] + [rng.randrange(1, n) for _ in range(4)]:
        ec521.append(f"mul p521 {format(k, 'x')} {ec_encode(c, ec_mul(c, k, G)).hex()}")
    for i in range(5):
        d1, d2 = rng.randrange(1, n), rng.randrange(1, n)
        p2 = ec_encode(c, ec_mul(c, d2, G))
        shared = ec_mul(c, d1, ec_mul(c, d2, G))[0].to_bytes(size, "big")
        if chk:
            chk.ecdh("p521", d1, d2, shared)
        ec521.append(f"ecdh p521 {d1.to_bytes(size, 'big').hex()} {p2.hex()} {shared.hex()}")
    for i in range(6):
        d = rng.randrange(1, n)
        msg = rbytes(rng.choice([0, 6, 100]))
        raw = ecdsa_sign(c, d, msg)
        if chk:
            chk.ecdsa("p521", d, msg, raw)
        pub = ec_encode(c, ec_mul(c, d, G))
        ec521.append(f"ecdsa p521 {d.to_bytes(size, 'big').hex()} {pub.hex()} {hx(msg)} {raw.hex()} {der_sig(raw).hex()}")
    out["ec521.txt"] = ec521

    # ML-KEM, with openssl as the oracle: keys from seeds, its
    # encapsulations, and its implicit rejection of a changed ciphertext.
    # openssl's encapsulation is randomized, so this file changes when it
    # is regenerated; without openssl it is left as it is.
    if chk:
        mk = []
        for k, name in ((2, "ML-KEM-512"), (3, "ML-KEM-768"), (4, "ML-KEM-1024")):
            for t in range(3):
                seed = bytes(64) if t == 0 else (b"\xff" * 64 if t == 1 else rbytes(64))
                pem = chk.path("mk.pem")
                openssl(["genpkey", "-algorithm", name, "-pkeyopt", f"hexseed:{seed.hex()}", "-out", pem])
                text = openssl(["pkey", "-in", pem, "-text", "-noout"]).decode()
                parts = {}
                cur = None
                for line in text.splitlines():
                    if line.endswith(":") and not line.startswith(" "):
                        cur = line[:-1]
                        parts[cur] = ""
                    elif cur and line.startswith(" "):
                        parts[cur] += line.strip().replace(":", "")
                assert parts["seed"] == seed.hex()
                mk.append(f"mlkem {k} {seed.hex()} {parts['ek']} {parts['dk']}")
                pub = chk.path("mkpub.pem")
                openssl(["pkey", "-in", pem, "-pubout", "-out", pub])
                for e in range(3):
                    ctf, ssf = chk.path("ct"), chk.path("ss")
                    openssl(["pkeyutl", "-encap", "-inkey", pub, "-pubin", "-out", ctf, "-secret", ssf])
                    ct, ss = open(ctf, "rb").read(), open(ssf, "rb").read()
                    mk.append(f"encap {k} {seed.hex()} {ct.hex()} {ss.hex()}")
                    bad = bytearray(ct)
                    bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
                    with open(ctf, "wb") as f:
                        f.write(bad)
                    openssl(["pkeyutl", "-decap", "-inkey", pem, "-in", ctf, "-secret", ssf])
                    mk.append(f"reject {k} {seed.hex()} {bytes(bad).hex()} {open(ssf, 'rb').read().hex()}")
                    chk.count += 2
        out["mlkem.txt"] = mk

    if chk:
        print(f"openssl agreed on {chk.count} vectors")
        chk.done()
    else:
        print("openssl not found: vectors checked against the published ones only")
    return out
