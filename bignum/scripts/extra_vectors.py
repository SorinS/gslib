"""Vectors for the primitives added after crypto_vectors.py: P-224, the
AES and DES block modes, MD5, DES and 3DES, RC4, BLAKE2, PBKDF2, scrypt,
Argon2, XChaCha20-Poly1305, Ed25519ctx and Ed25519ph, RSA PKCS #1 v1.5
encryption and OAEP over other hashes, cSHAKE, and BLAKE2X and BLAKE2 as
a hash for HMAC, HKDF and PBKDF2 (blake2.txt, from a third random stream).

hashlib supplies MD5, BLAKE2, PBKDF2 and scrypt. The rest are
transcriptions of their standards, each checked here against the vectors
the standard publishes and, when the openssl command is installed, every
vector against openssl too (cSHAKE and XChaCha20, which openssl lacks,
are checked through KMAC and the draft's vectors). A separate random
stream from crypto_vectors.py, so neither changes the other's files.

Used by gen_vectors.py, or run alone: python3 scripts/extra_vectors.py
"""

import hashlib
import hmac
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import crypto_vectors as cv
from crypto_vectors import openssl, hx, i2osp, k_of, xor

rng = random.Random(20261026_2)


def rbytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


# --- P-224 ------------------------------------------------------------------

cv.CURVES["p224"] = dict(
    p=2 ** 224 - 2 ** 96 + 1,
    n=0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
    b=0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
    gx=0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
    gy=0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
    size=28, hash="sha224", oid="2b81040021")

# RFC 6979 A.2.4, SHA-224, message "sample".
P224_RFC6979 = (0xf220266e1105bfe3083e03ec7a3a654651f45e37167e88600bf257c1,
                "1cdfe6662dde1e4a1ec4cdedf6a1f5a2fb7fbd9145c12113e6abfd3e"
                "a6694fd7718a21053f225d3f46197ca699d45006c06f871808f43ebc")


def p224_vectors(chk):
    c = cv.CURVES["p224"]
    cv.ec_check(c)
    assert c["p"] == int("ffffffffffffffffffffffffffffffff000000000000000000000001", 16)
    assert cv.ecdsa_sign(c, P224_RFC6979[0], b"sample").hex() == P224_RFC6979[1]
    out = []
    n, size = c["n"], c["size"]
    G = (c["gx"], c["gy"])
    for k in [1, 2, 3, n - 1, n - 2] + [rng.randrange(1, n) for _ in range(5)]:
        out.append(f"mul p224 {format(k, 'x')} {cv.ec_encode(c, cv.ec_mul(c, k, G)).hex()}")
    for i in range(6):
        d1, d2 = rng.randrange(1, n), rng.randrange(1, n)
        p2 = cv.ec_encode(c, cv.ec_mul(c, d2, G))
        shared = cv.ec_mul(c, d1, cv.ec_mul(c, d2, G))[0].to_bytes(size, "big")
        if chk:
            chk.ecdh("p224", d1, d2, shared)
        out.append(f"ecdh p224 {d1.to_bytes(size, 'big').hex()} {p2.hex()} {shared.hex()}")
    for d, msg in [(P224_RFC6979[0], b"sample")] + [(rng.randrange(1, n), rbytes(rng.choice([0, 6, 100])))
                                                    for _ in range(8)]:
        raw = cv.ecdsa_sign(c, d, msg)
        if chk:
            chk.ecdsa("p224", d, msg, raw)
        pub = cv.ec_encode(c, cv.ec_mul(c, d, G))
        out.append(f"ecdsa p224 {d.to_bytes(size, 'big').hex()} {pub.hex()} {hx(msg)} {raw.hex()} "
                   f"{cv.der_sig(raw).hex()}")
    return out


# --- block modes, DES, MD5, RC4 ---------------------------------------------

import des_ref


def block_fn(cipher, key, decrypt=False):
    if cipher == "aes":
        return (lambda b: cv.aes_decrypt(key, b)) if decrypt else (lambda b: cv.aes_encrypt(key, b))
    if cipher == "des":
        return lambda b: des_ref.crypt(key, b, decrypt)
    return lambda b: des_ref.des3(key, b, decrypt)


def mode_crypt(mode, cipher, key, iv, data, decrypt=False):
    """SP 800-38A over 16- or 8-byte blocks; CFB with full-block segments."""
    bs = len(iv)
    enc = block_fn(cipher, key)
    out = b""
    x = iv
    for off in range(0, len(data), bs):
        blk = data[off:off + bs]
        if mode == "cbc":
            if decrypt:
                c = xor(block_fn(cipher, key, True)(blk), x)
                x = blk
            else:
                c = enc(xor(blk, x))
                x = c
        elif mode == "cfb":
            ks = enc(x)
            c = xor(blk, ks[:len(blk)])
            x = blk if decrypt else c
        elif mode == "ofb":
            x = enc(x)
            c = xor(blk, x[:len(blk)])
        else:
            c = xor(blk, enc(x)[:len(blk)])
            x = ((int.from_bytes(x, "big") + 1) % (1 << (8 * bs))).to_bytes(bs, "big")
        out += c
    return out


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


# SP 800-38A F.2.1, F.3.13, F.4.1 (AES-128), the first two blocks.
_K38A = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_IV38A = bytes(range(16))
_P38A = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
assert mode_crypt("cbc", "aes", _K38A, _IV38A, _P38A).hex() == \
    "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
assert mode_crypt("cfb", "aes", _K38A, _IV38A, _P38A).hex() == \
    "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
assert mode_crypt("ofb", "aes", _K38A, _IV38A, _P38A).hex() == \
    "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
# RFC 6229: the first 16 bytes of keystream for the key 0102030405.
assert rc4(bytes([1, 2, 3, 4, 5]), bytes(16)).hex() == "b2396305f03dc027ccc3524a0a1118a8"

LEGACY = ["-provider", "legacy", "-provider", "default"]


def openssl_mode(mode, cipher, key, iv, pt, ct, chk):
    if cipher == "aes":
        name = f"aes-{8 * len(key)}-{mode}"
    elif mode == "ctr":
        return                                    # openssl has no DES or 3DES CTR
    elif cipher == "des":
        name = f"des-{mode}"
    else:
        name = f"des-ede3-{mode}"
    extra = LEGACY if cipher == "des" else []
    out = openssl(["enc", f"-{name}", *extra, "-K", key.hex(), "-iv", iv.hex(), "-nopad"], pt)
    assert out == ct, f"openssl disagrees on {name}"
    chk.count += 1


def legacy_vectors(chk):
    out = []
    keylen = {"aes": None, "des": 8, "des3": 24}
    for cipher in ("aes", "des", "des3"):
        bs = 16 if cipher == "aes" else 8
        for mode in ("cbc", "cfb", "ofb", "ctr"):
            for t in range(9):
                key = rbytes(keylen[cipher] or (16, 24, 32)[t % 3])
                iv = b"\xff" * bs if t == 8 else rbytes(bs)
                if mode == "cbc":
                    n = bs * rng.choice([1, 2, 3, 7])
                else:
                    n = rng.choice([0, 1, bs - 1, bs, bs + 1, 3 * bs + 5, 100])
                pt = rbytes(n)
                ct = mode_crypt(mode, cipher, key, iv, pt)
                assert mode_crypt(mode, cipher, key, iv, ct, True) == pt
                if chk and pt:
                    openssl_mode(mode, cipher, key, iv, pt, ct, chk)
                out.append(f"{mode} {cipher} {key.hex()} {iv.hex()} {hx(pt)} {hx(ct)}")
    for t in range(6):
        for cipher, kl in (("des", 8), ("des3", 24)):
            key, pt = rbytes(kl), rbytes(8)
            ct = des_ref.crypt(key, pt) if cipher == "des" else des_ref.des3(key, pt)
            if chk:
                name = "des-ecb" if cipher == "des" else "des-ede3-ecb"
                extra = LEGACY if cipher == "des" else []
                assert openssl(["enc", f"-{name}", *extra, "-K", key.hex(), "-nopad"], pt) == ct
                chk.count += 1
            out.append(f"block {cipher} {key.hex()} {pt.hex()} {ct.hex()}")
    out.append("block des 133457799bbcdff1 0123456789abcdef 85e813540f0ab405")
    for n in list(range(0, 70)) + [119, 120, 200, 1000]:
        m = rbytes(n)
        out.append(f"md5 {hx(m)} {hashlib.md5(m).hexdigest()}")
    for klen in (0, 16, 64, 65, 100):
        key, msg = rbytes(klen), rbytes(rng.randint(0, 200))
        out.append(f"hmac 128 {hx(key)} {hx(msg)} {hmac.new(key, msg, 'md5').hexdigest()}")
    for t in range(8):
        key, pt = rbytes((16, 1, 5, 32, 256)[t % 5]), rbytes(rng.choice([0, 1, 50, 300]))
        ct = rc4(key, pt)
        if chk and pt and len(key) == 16:       # openssl's rc4 takes 16-byte keys only
            assert openssl(["enc", "-rc4", *LEGACY, "-K", key.hex(), "-nopad"], pt) == ct
            chk.count += 1
        out.append(f"rc4 {key.hex()} {hx(pt)} {hx(ct)}")
    out.append("rc4 0102030405 " + "00" * 16 + " b2396305f03dc027ccc3524a0a1118a8")
    return out


# --- BLAKE2, PBKDF2, scrypt, Argon2 -----------------------------------------

HASH_IDS = {"md5": 128, "sha1": 160, "sha224": 224, "sha256": 256, "sha384": 384, "sha512": 512,
            "sha512_256": 5256, "sha3_256": 3256, "sha3_512": 3512}

# RFC 9106 §5: P = 32 x 01, S = 16 x 02, K = 8 x 03, X = 12 x 04, t = 3,
# m = 32, p = 4, a 32-byte tag.
RFC9106 = {
    0: "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
    1: "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
    2: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
}


def argon2_openssl(kind, pw, salt, secret, ad, t, m, p, n):
    args = ["kdf", "-keylen", str(n), "-kdfopt", f"hexpass:{pw.hex()}", "-kdfopt", f"hexsalt:{salt.hex()}",
            "-kdfopt", f"iter:{t}", "-kdfopt", f"memcost:{m}", "-kdfopt", f"lanes:{p}", "-kdfopt", "threads:1"]
    if secret:
        args += ["-kdfopt", f"hexsecret:{secret.hex()}"]
    if ad:
        args += ["-kdfopt", f"hexad:{ad.hex()}"]
    out = openssl(args + [("ARGON2D", "ARGON2I", "ARGON2ID")[kind]])
    return bytes.fromhex(out.decode().strip().replace(":", ""))


def kdf_vectors(chk):
    out = []
    for n in list(range(0, 20)) + [63, 64, 65, 127, 128, 129, 255, 256, 257, 1000]:
        m = rbytes(n)
        out.append(f"blake2b 64 - {hx(m)} {hashlib.blake2b(m).hexdigest()}")
        out.append(f"blake2s 32 - {hx(m)} {hashlib.blake2s(m).hexdigest()}")
    for t in range(16):
        n = rng.choice([0, 1, 64, 127, 128, 129, 300])
        m = rbytes(n)
        ob, os_ = rng.randint(1, 64), rng.randint(1, 32)
        kb, ks = rbytes(rng.choice([0, 1, 32, 64])), rbytes(rng.choice([0, 1, 16, 32]))
        out.append(f"blake2b {ob} {hx(kb)} {hx(m)} {hashlib.blake2b(m, digest_size=ob, key=kb).hexdigest()}")
        out.append(f"blake2s {os_} {hx(ks)} {hx(m)} {hashlib.blake2s(m, digest_size=os_, key=ks).hexdigest()}")
    # RFC 6070 (PBKDF2-HMAC-SHA1) and RFC 7914 §11 (PBKDF2-HMAC-SHA256).
    assert hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 4096, 20).hex() == \
        "4b007901b765489abead49d926f721d065a429c1"
    assert hashlib.pbkdf2_hmac("sha256", b"passwd", b"salt", 1, 64).hex().startswith("55ac046e56e3089fec1691c22544b605")
    out.append("pbkdf2 160 " + b"password".hex() + " " + b"salt".hex() + " 4096 20 4b007901b765489abead49d926f721d065a429c1")
    for name, hid in HASH_IDS.items():
        for t in range(3):
            pw, salt = rbytes(rng.choice([0, 8, 100, 200])), rbytes(rng.choice([0, 16, 70]))
            it, n = rng.choice([1, 2, 7, 100]), rng.choice([1, 16, 33, 64, 100])
            out.append(f"pbkdf2 {hid} {hx(pw)} {hx(salt)} {it} {n} {hashlib.pbkdf2_hmac(name, pw, salt, it, n).hex()}")
    rfc7914 = [(b"", b"", 16, 1, 1), (b"password", b"NaCl", 1024, 8, 16)]
    assert hashlib.scrypt(b"", salt=b"", n=16, r=1, p=1, dklen=64).hex().startswith("77d6576238657b203b19ca42c18a0497")
    for pw, salt, n, r, p in rfc7914 + [(rbytes(rng.randint(0, 40)), rbytes(16), rng.choice([2, 4, 32, 256]),
                                         rng.randint(1, 4), rng.randint(1, 3)) for _ in range(6)]:
        dk = hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=64, maxmem=1 << 30)
        out.append(f"scrypt {hx(pw)} {hx(salt)} {n} {r} {p} {dk.hex()}")
    P, S, K, X = b"\1" * 32, b"\2" * 16, b"\3" * 8, b"\4" * 12
    for kind, tag in RFC9106.items():
        if chk:
            assert argon2_openssl(kind, P, S, K, X, 3, 32, 4, 32).hex() == tag
            chk.count += 1
        out.append(f"argon2 {kind} {P.hex()} {S.hex()} {K.hex()} {X.hex()} 3 32 4 32 {tag}")
    # Random ones, from openssl; they cross segment and address-block
    # boundaries (more than 128 blocks a segment) and use other lane
    # counts. Without openssl the file keeps what it had.
    if chk:
        for t in range(12):
            kind = t % 3
            p = rng.choice([1, 1, 2, 3, 4])
            m = rng.choice([8 * p, 8 * p + 5, 64, 600, 1024 + 3])
            m = max(m, 8 * p)
            tt = rng.choice([1, 2, 3])
            pw, salt = rbytes(rng.choice([0, 5, 32, 100])), rbytes(rng.choice([8, 16, 33]))
            sec = rbytes(rng.choice([0, 0, 8])) if t % 4 else b""
            ad = rbytes(rng.choice([0, 0, 12])) if t % 5 else b""
            n = rng.choice([4, 16, 32, 64, 65, 100])
            tag = argon2_openssl(kind, pw, salt, sec, ad, tt, m, p, n)
            chk.count += 1
            out.append(f"argon2 {kind} {hx(pw)} {hx(salt)} {hx(sec)} {hx(ad)} {tt} {m} {p} {n} {tag.hex()}")
    else:
        path = os.path.join(os.path.dirname(__file__), "..", "test", "vectors", "kdf.txt")
        if os.path.exists(path):
            out += [l for l in open(path).read().splitlines() if l.startswith("argon2 ") and l not in out
                    and not any(l.endswith(tg) for tg in RFC9106.values())]
    return out


# --- XChaCha20-Poly1305 -----------------------------------------------------

def hchacha20(key, nonce):
    def qr(x, a, b, c, d):
        for (p, q, r, n) in ((a, b, d, 16), (c, d, b, 12), (a, b, d, 8), (c, d, b, 7)):
            x[p] = (x[p] + x[q]) & 0xffffffff
            x[r] ^= x[p]
            x[r] = ((x[r] << n) | (x[r] >> (32 - n))) & 0xffffffff
    x = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    x += [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]
    x += [int.from_bytes(nonce[4 * i:4 * i + 4], "little") for i in range(4)]
    for _ in range(10):
        qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
        qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
    return b"".join(v.to_bytes(4, "little") for v in x[:4] + x[12:])


def xchacha_aead(key, nonce, aad, pt):
    return cv.chacha_aead(hchacha20(key, nonce[:16]), b"\0" * 4 + nonce[16:], aad, pt)


# draft-irtf-cfrg-xchacha-03 §2.2.1 and A.3.1.
assert hchacha20(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")).hex() == \
    "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
XCHACHA_A31 = (bytes(range(0x80, 0xa0)), bytes(range(0x40, 0x58)), bytes.fromhex("50515253c0c1c2c3c4c5c6c7"))
assert xchacha_aead(*XCHACHA_A31, cv._SUNSCREEN)[1].hex() == "c0875924c1c7987947deafd8780acf49"


# --- cSHAKE (SP 800-185), on a Keccak sponge checked against hashlib --------

def keccak_f(a):
    rc = [1, 0x8082, 0x800000000000808a, 0x8000000080008000, 0x808b, 0x80000001, 0x8000000080008081,
          0x8000000000008009, 0x8a, 0x88, 0x80008009, 0x8000000a, 0x8000808b, 0x800000000000008b,
          0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x800a,
          0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008]
    rot = lambda v, n: ((v << n) | (v >> (64 - n))) & (2 ** 64 - 1) if n else v
    r = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    for k in rc:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rot(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = rot(a[x][y], r[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= k
    return a


def sponge(rate, ds, data, n):
    a = [[0] * 5 for _ in range(5)]
    data = bytearray(data) + bytes([ds]) + bytes(-(len(data) + 1) % rate)
    data[-1] |= 0x80
    for off in range(0, len(data), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(data[off + 8 * i:off + 8 * i + 8], "little")
        a = keccak_f(a)
    out = b""
    while len(out) < n:
        out += b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(rate // 8))
        a = keccak_f(a)
    return out[:n]


assert sponge(136, 6, b"abc", 32) == hashlib.sha3_256(b"abc").digest()
assert sponge(168, 0x1f, bytes(200), 300) == hashlib.shake_128(bytes(200)).digest(300)


def left_encode(x):
    b = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
    return bytes([len(b)]) + b


def right_encode(x):
    b = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
    return b + bytes([len(b)])


def bytepad(x, w):
    x = left_encode(w) + x
    return x + bytes(-len(x) % w)


def cshake(bits, name, custom, data, n):
    rate = 200 - bits // 4
    if not name and not custom:
        return hashlib.new(f"shake_{bits}", data).digest(n)
    pre = bytepad(left_encode(8 * len(name)) + name + left_encode(8 * len(custom)) + custom, rate)
    return sponge(rate, 4, pre + data, n)


def kmac(bits, key, data, n, custom):
    rate = 200 - bits // 4
    x = bytepad(left_encode(8 * len(key)) + key, rate) + data + right_encode(8 * n)
    return cshake(bits, b"KMAC", custom, x, n)


# SP 800-185's cSHAKE samples 1 and 3.
assert cshake(128, b"", b"Email Signature", bytes(range(4)), 32).hex() == \
    "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5"
assert cshake(256, b"", b"Email Signature", bytes(range(4)), 64).hex().startswith("d008828e2b80ac9d2218ffee1d070c48")


# --- Ed25519ctx and Ed25519ph (RFC 8032 §5.1) -------------------------------

def ed_sign_dom(seed, dom, msg):
    a, prefix = cv.ed_secret(seed)
    A = cv.ed_encode(cv.ed_mul(a, cv.ED_G))
    r = cv.ed_sha512_modl(dom + prefix + msg)
    R = cv.ed_encode(cv.ed_mul(r, cv.ED_G))
    k = cv.ed_sha512_modl(dom + R + A + msg)
    return A, R + ((r + k * a) % cv.ED_L).to_bytes(32, "little")


def dom2(ph, ctx):
    return b"SigEd25519 no Ed25519 collisions" + bytes([ph, len(ctx)]) + ctx


# RFC 8032 §7.2 (Ed25519ctx, context "foo") and §7.3 (Ed25519ph, "abc").
ED_CTX = ("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6", "f726936d19c800494e3fdaff20b276a8",
          "666f6f", "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a"
          "8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d")
ED_PH = ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42", "616263", "",
         "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
         "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")
assert ed_sign_dom(bytes.fromhex(ED_CTX[0]), dom2(0, b"foo"), bytes.fromhex(ED_CTX[1]))[1].hex() == ED_CTX[3]
assert ed_sign_dom(bytes.fromhex(ED_PH[0]), dom2(1, b""), hashlib.sha512(b"abc").digest())[1].hex() == ED_PH[3]


def ed_openssl(chk, seed, msg, ctx, ph):
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    pem = chk.path("ed.pem")
    openssl(["pkey", "-inform", "DER", "-in", chk.path("ed.der", der), "-out", pem])
    opts = ["-pkeyopt", "instance:" + ("Ed25519ph" if ph else "Ed25519ctx")]
    if ctx:
        opts += ["-pkeyopt", f"hexcontext-string:{ctx.hex()}"]
    return openssl(["pkeyutl", "-sign", "-rawin", "-inkey", pem, "-in", chk.path("m", msg), *opts])


# --- RSA: OAEP over other hashes, PKCS #1 v1.5 encryption -------------------

def oaep_encrypt_h(key, msg, label, seed, hn):
    k, hl = k_of(key), hashlib.new(hn).digest_size
    db = hashlib.new(hn, label).digest() + bytes(k - len(msg) - 2 * hl - 2) + b"\1" + msg
    masked_db = xor(db, cv.mgf1(seed, k - hl - 1, hn))
    masked_seed = xor(seed, cv.mgf1(masked_db, hl, hn))
    return i2osp(pow(int.from_bytes(b"\0" + masked_seed + masked_db, "big"), key["e"], key["n"]), k)


def raw_encrypt(key, em):
    return i2osp(pow(int.from_bytes(em, "big"), key["e"], key["n"]), k_of(key))


def pkcs1_em(k, msg):
    ps = bytes(rng.randrange(1, 256) for _ in range(k - len(msg) - 3))
    return b"\0\2" + ps + b"\0" + msg


def extra_vectors(chk):
    out = []
    # XChaCha20-Poly1305.
    key, nonce, aad = XCHACHA_A31
    ct, tag = xchacha_aead(key, nonce, aad, cv._SUNSCREEN)
    out.append(f"xchacha {key.hex()} {nonce.hex()} {aad.hex()} {cv._SUNSCREEN.hex()} {ct.hex()}{tag.hex()}")
    for t in range(12):
        key, nonce = rbytes(32), rbytes(24)
        aad, pt = rbytes(rng.choice([0, 1, 12, 33])), rbytes(rng.choice([0, 1, 15, 16, 64, 65, 200]))
        ct, tag = xchacha_aead(key, nonce, aad, pt)
        out.append(f"xchacha {key.hex()} {nonce.hex()} {hx(aad)} {hx(pt)} {ct.hex()}{tag.hex()}")
    out.append(f"hchacha {bytes(range(32)).hex()} 000000090000004a0000000031415927 "
               "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    # cSHAKE, checked through openssl's KMAC, which is cSHAKE underneath.
    if chk:
        for bits in (128, 256):
            for t in range(4):
                key, data, custom = rbytes(rng.choice([4, 32, 200])), rbytes(rng.choice([0, 5, 300])), \
                    rbytes(rng.choice([0, 3, 30]))
                n = rng.choice([16, 32, 64, 100])
                opts = ["-macopt", f"hexkey:{key.hex()}", "-macopt", f"size:{n}"]
                if custom:
                    opts += ["-macopt", f"hexcustom:{custom.hex()}"]
                got = openssl(["mac", *opts, "-in", chk.path("km", data), f"KMAC{bits}"]).decode().strip().lower()
                assert got == kmac(bits, key, data, n, custom).hex(), "openssl disagrees on KMAC"
                chk.count += 1
    out.append("cshake 128 - 456d61696c205369676e6174757265 00010203 32 "
               "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5")
    for t in range(14):
        bits = (128, 256)[t % 2]
        name = rbytes(rng.choice([0, 0, 4, 9])) if t > 1 else b""
        custom = rbytes(rng.choice([0, 1, 15, 200])) if t > 1 else b""
        data, n = rbytes(rng.choice([0, 1, 100, 168, 300])), rng.choice([1, 32, 64, 200])
        out.append(f"cshake {bits} {hx(name)} {hx(custom)} {hx(data)} {n} {cshake(bits, name, custom, data, n).hex()}")
    # Ed25519ctx and Ed25519ph.
    out.append(f"edctx {ED_CTX[0]} {ED_CTX[1]} {ED_CTX[2]} {ED_CTX[3]}")
    out.append(f"edph {ED_PH[0]} {ED_PH[1]} - {ED_PH[3]}")
    for t in range(10):
        seed, msg = rbytes(32), rbytes(rng.choice([0, 1, 64, 200]))
        ph = t % 2 == 1
        ctx = rbytes(rng.choice([0, 1, 30, 255]) if ph else rng.choice([1, 30, 255]))
        m = hashlib.sha512(msg).digest() if ph else msg
        sig = ed_sign_dom(seed, dom2(int(ph), ctx), m)[1]
        if chk and msg:                            # openssl cannot sign an empty message here
            assert ed_openssl(chk, seed, msg, ctx, ph) == sig, "openssl disagrees on Ed25519ctx/ph"
            chk.count += 1
        out.append(f"{'edph' if ph else 'edctx'} {seed.hex()} {hx(msg)} {hx(ctx)} {sig.hex()}")
    # RSA: a 2048-bit key of this file's own.
    saved = cv.rng
    cv.rng = rng
    key = cv.rsa_key(1024, 1024, 65537)
    cv.rng = saved
    out.append("key k2048c " + " ".join(format(key[x], "x") for x in ("n", "e", "d", "p", "q")))
    k = k_of(key)
    pem = chk.key(key) if chk else None
    for hn in ("sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256"):
        for t in range(2):
            hl = hashlib.new(hn).digest_size
            msg, label = rbytes(rng.choice([0, 1, k - 2 * hl - 2])), rbytes(rng.choice([0, 0, 10]))
            seed = rbytes(hl)
            ct = oaep_encrypt_h(key, msg, label, seed, hn)
            if chk:
                md = hn.replace("_", "-")
                opts = ["-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", f"rsa_oaep_md:{md}",
                        "-pkeyopt", f"rsa_mgf1_md:{md}"]
                if label:
                    opts += ["-pkeyopt", f"rsa_oaep_label:{label.hex()}"]
                got = openssl(["pkeyutl", "-decrypt", "-inkey", pem, "-in", chk.path("ct", ct), *opts])
                assert got == msg, "openssl decrypts OAEP differently"
                chk.count += 1
            out.append(f"oaeph {HASH_IDS[hn]} {hx(msg)} {hx(label)} {seed.hex()} {ct.hex()}")
    for t in range(8):
        msg = rbytes(rng.choice([0, 1, 16, 48, k - 11]))
        ct = raw_encrypt(key, pkcs1_em(k, msg))
        if chk:
            got = openssl(["pkeyutl", "-decrypt", "-inkey", pem, "-in", chk.path("ct", ct),
                           "-pkeyopt", "rsa_padding_mode:pkcs1"])
            assert got == msg, "openssl decrypts PKCS #1 v1.5 differently"
            chk.count += 1
            if t < 3:
                # And openssl's own encryptions, which are randomized.
                pub = pem + ".pub"
                openssl(["pkey", "-in", pem, "-pubout", "-out", pub])
                ct2 = openssl(["pkeyutl", "-encrypt", "-pubin", "-inkey", pub, "-in", chk.path("m", msg),
                               "-pkeyopt", "rsa_padding_mode:pkcs1"])
                out.append(f"pkcs1enc {hx(msg)} {ct2.hex()}")
        out.append(f"pkcs1enc {hx(msg)} {ct.hex()}")
    # Malformed: a wrong first or second byte, padding shorter than 8, no
    # zero separator.
    good = pkcs1_em(k, rbytes(16))
    bads = [b"\1" + good[1:], good[:1] + b"\1" + good[2:],
            b"\0\2" + bytes(rng.randrange(1, 256) for _ in range(7)) + b"\0" + rbytes(k - 10),
            b"\0\2" + bytes(rng.randrange(1, 256) for _ in range(k - 2))]
    for em in bads:
        out.append(f"pkcs1bad {raw_encrypt(key, em).hex()}")
    return out


# --- BLAKE2X, and BLAKE2 under HMAC, HKDF and PBKDF2 ------------------------

def blake2_raw(wide, cfg, data, key=b""):
    """BLAKE2b (wide) or BLAKE2s from a whole parameter block, which
    hashlib can't take (it refuses BLAKE2X's depth of 0)."""
    ws, bb, rounds, rot = (8, 128, 12, (32, 24, 16, 63)) if wide else (4, 64, 10, (16, 12, 8, 7))
    bits = 8 * ws
    mask = (1 << bits) - 1
    iv = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
          0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    if not wide:
        iv = [v >> 32 for v in iv]
    sigma = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
             [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
             [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
             [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
             [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
             [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
             [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
             [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
             [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
             [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]]
    h = [iv[i] ^ int.from_bytes(cfg[ws * i:ws * i + ws], "little") for i in range(8)]

    def rotr(x, n):
        return ((x >> n) | (x << (bits - n))) & mask

    def compress(blk, t, last):
        m = [int.from_bytes(blk[ws * i:ws * i + ws], "little") for i in range(16)]
        v = h + iv
        v[12] ^= t & mask
        v[13] ^= t >> bits
        if last:
            v[14] ^= mask
        for r in range(rounds):
            sg = sigma[r % 10]
            for i, (a, b, c, d) in enumerate(((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                                              (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))):
                x, y = m[sg[2 * i]], m[sg[2 * i + 1]]
                v[a] = (v[a] + v[b] + x) & mask; v[d] = rotr(v[d] ^ v[a], rot[0])
                v[c] = (v[c] + v[d]) & mask;     v[b] = rotr(v[b] ^ v[c], rot[1])
                v[a] = (v[a] + v[b] + y) & mask; v[d] = rotr(v[d] ^ v[a], rot[2])
                v[c] = (v[c] + v[d]) & mask;     v[b] = rotr(v[b] ^ v[c], rot[3])
        for i in range(8):
            h[i] ^= v[i] ^ v[8 + i]

    if key:
        data = key.ljust(bb, b"\0") + data
    t = 0
    while len(data) > bb:
        t += bb
        compress(data[:bb], t, False)
        data = data[bb:]
    compress(data.ljust(bb, b"\0"), t + len(data), True)
    return b"".join(x.to_bytes(ws, "little") for x in h)[:cfg[0]]


def blake2x(wide, data, n, key=b"", read=None):
    """BLAKE2Xb or BLAKE2Xs: n bytes, or `read` bytes of the unknown-length
    form when n is 0."""
    size = 64 if wide else 32
    length = n or ((1 << 32) - 1 if wide else (1 << 16) - 1)
    cfg = bytearray(size)
    cfg[0], cfg[1], cfg[2], cfg[3] = size, len(key), 1, 1
    if wide:
        cfg[12:16] = length.to_bytes(4, "little")
    else:
        cfg[12:14] = length.to_bytes(2, "little")
    root = blake2_raw(wide, cfg, data, key)
    total = n or read
    out = b""
    node = 0
    while len(out) < total:
        c = bytearray(size)
        c[0] = min(size, total - len(out)) if n else size
        c[4] = size                                       # leaf length
        c[8:12] = node.to_bytes(4, "little")
        if wide:
            c[12:16] = length.to_bytes(4, "little")
            c[17] = size                                  # inner length
        else:
            c[12:14] = length.to_bytes(2, "little")
            c[15] = size
        out += blake2_raw(wide, c, root)
        node += 1
    return out[:total]


# The transcription against hashlib, then against the reference KATs (as
# Go's blake2b and blake2s tests carry them: the key 00..3f or 00..1f,
# the input 00..ff, and output lengths 1 to 256).
for _m in (b"", b"abc", bytes(range(200))):
    for _k in (b"", b"key"):
        assert blake2_raw(True, bytes([64, len(_k), 1, 1]) + bytes(60), _m, _k) == hashlib.blake2b(_m, key=_k).digest()
        assert blake2_raw(False, bytes([20, len(_k), 1, 1]) + bytes(28), _m, _k) == \
            hashlib.blake2s(_m, digest_size=20, key=_k).digest()
_KB, _KS, _IN = bytes(range(64)), bytes(range(32)), bytes(range(256))
assert blake2x(True, _IN, 1, _KB).hex() == "64"
assert blake2x(True, _IN, 32, _KB).hex() == "29f6bb55de7f8868e053176c878c9fe6c2055c4c5413b51ab0386c277fdbac75"
assert blake2x(True, _IN, 64, _KB).hex() == \
    "4324561d76c370ef35ac36a4adf8f3773a50d86504bd284f71f7ce9e2bc4c1f1d34a7fb2d67561d101955d448b67577eb30dfee96a95c7f921ef53e20be8bc44"
assert blake2x(True, _IN, 0, _KB, 64).hex() == \
    "3dbba8516da76bf7330055c66ea36cf1005e92714262b24d9710f51d9e126406e1bcd6497059f9331f1091c3634b695428d475ed432f987040575520a1c29f5e"
assert blake2x(False, _IN, 2, _KS).hex() == "5196"
assert blake2x(False, _IN, 33, _KS).hex() == "7dce710a20f42ab687ec6ea83b53faaa418229ce0d5a2ff2a5e66defb0b65c03c9"
assert blake2x(False, _IN, 0, _KS, 64).hex() == \
    "2a9a6977d915a2c4dd07dbcafe1918bf1682e56d9c8e567ecd19bfd7cd93528833c764d12b34a5e2a219c9fd463dab45e972c5574d73f45de5b2e23af72530d8"

BLAKE2_HASHES = {2256: lambda d=b"": hashlib.blake2b(d, digest_size=32), 2384: lambda d=b"": hashlib.blake2b(d, digest_size=48),
                 2512: hashlib.blake2b, 1256: hashlib.blake2s}


def hkdf_h(new, salt, ikm, info, n):
    prk = hmac.new(salt or bytes(new().digest_size), ikm, new).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), new).digest()
        out += t
        i += 1
    return out[:n]


def blake2_vectors(chk):
    rng2 = random.Random(20261026_3)

    def rb(n):
        return bytes(rng2.getrandbits(8) for _ in range(n))

    out = []
    # The KATs whole, the unknown-length outputs, then random ones.
    for wide, name, key in ((True, "blake2xb", _KB), (False, "blake2xs", _KS)):
        for n in range(1, 257):
            out.append(f"{name} {n} {key.hex()} {_IN.hex()} {blake2x(wide, _IN, n, key).hex()}")
        out.append(f"{name} 0 {key.hex()} {_IN.hex()} {blake2x(wide, _IN, 0, key, 64).hex()}")
        for t in range(12):
            m = rb(rng2.choice([0, 1, 31, 64, 65, 128, 129, 500]))
            k = rb(rng2.choice([0, 0, 1, 16, len(key)]))
            n = rng2.choice([0, 0, 1, 63, 64, 65, 300, 1000, 4097])
            got = blake2x(wide, m, n, k, rng2.choice([1, 64, 200, 3000]))
            out.append(f"{name} {n} {hx(k)} {hx(m)} {got.hex()}")
    for hid, new in BLAKE2_HASHES.items():
        for t in range(4):
            k, m = rb(rng2.choice([0, 16, 64, 65, 129, 200])), rb(rng2.choice([0, 3, 100, 300]))
            out.append(f"hmac {hid} {hx(k)} {hx(m)} {hmac.new(k, m, new).hexdigest()}")
        for t in range(3):
            salt, ikm, info = rb(rng2.choice([0, 13, 32])), rb(rng2.choice([1, 22, 80])), rb(rng2.choice([0, 10]))
            n = rng2.choice([1, 32, 42, 100, 255])
            out.append(f"hkdf {hid} {hx(salt)} {hx(ikm)} {hx(info)} {n} {hkdf_h(new, salt, ikm, info, n).hex()}")
        for t in range(3):
            pw, salt = rb(rng2.choice([0, 8, 100, 200])), rb(rng2.choice([0, 16, 70]))
            it, n = rng2.choice([1, 2, 7, 100]), rng2.choice([1, 16, 33, 64, 100])
            dk = cv_pbkdf2(new, pw, salt, it, n)
            out.append(f"pbkdf2 {hid} {hx(pw)} {hx(salt)} {it} {n} {dk.hex()}")
    # RSA-PSS over BLAKE2b-512 and BLAKE2s-256, and PKCS #1 v1.5 over MD5
    # (BLAKE2 has no DigestInfo), on a 1024-bit key of this stream's own.
    saved = cv.rng
    cv.rng = rng2
    key = cv.rsa_key(512, 512, 65537)
    cv.rng = saved
    out.append("key " + " ".join(format(key[x], "x") for x in ("n", "e", "d", "p", "q")))
    pem = chk.key(key) if chk else None
    for hid, hn in ((2512, "blake2b"), (1256, "blake2s")):
        for t in range(3):
            msg, salt = rb(rng2.choice([0, 5, 200])), rb(rng2.choice([0, 20, 32]))
            sig = cv.pss_sign(key, msg, salt, hn)        # openssl refuses RSA over BLAKE2
            out.append(f"pss {hid} {hx(salt)} {hx(msg)} {sig.hex()}")
    md5_di = bytes.fromhex("3020300c06082a864886f70d020505000410")
    for t in range(3):
        msg = rb(rng2.choice([0, 7, 100]))
        k = k_of(key)
        tt = md5_di + hashlib.md5(msg).digest()
        em = b"\0\1" + b"\xff" * (k - len(tt) - 3) + b"\0" + tt
        sig = i2osp(pow(int.from_bytes(em, "big"), key["d"], key["n"]), k)
        if chk:
            chk.verify(pem, msg, sig, None, "md5", hashlib.md5(msg).digest())
        out.append(f"pkcs1 128 {hx(msg)} {sig.hex()}")
    return out


def cv_pbkdf2(new, pw, salt, it, n):
    out, i = b"", 1
    while len(out) < n:
        u = hmac.new(pw, salt + i.to_bytes(4, "big"), new).digest()
        t = u
        for _ in range(it - 1):
            u = hmac.new(pw, u, new).digest()
            t = xor(t, u)
        out += t
        i += 1
    return out[:n]


assert cv_pbkdf2(hashlib.sha256, b"passwd", b"salt", 3, 50) == hashlib.pbkdf2_hmac("sha256", b"passwd", b"salt", 3, 50)


# --- driver -----------------------------------------------------------------

def generate():
    chk = cv.OpenSSLCheck() if cv.OPENSSL else None
    out = {}
    out["ec224.txt"] = p224_vectors(chk)
    out["legacy.txt"] = legacy_vectors(chk)
    out["kdf.txt"] = kdf_vectors(chk)
    out["extra.txt"] = extra_vectors(chk)
    out["blake2.txt"] = blake2_vectors(chk)
    if chk:
        print(f"openssl agreed on {chk.count} more vectors")
        chk.done()
    else:
        print("openssl not found: vectors checked against the published ones only")
    return out


if __name__ == "__main__":
    import gen_vectors
    for name, lines in generate().items():
        gen_vectors.write(name, lines)
