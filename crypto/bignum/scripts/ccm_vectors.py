"""Reference AES-CCM (NIST SP 800-38C) and vectors/ccm.txt.

A straight transcription on crypto_vectors.py's AES, checked against SP
800-38C's examples 1 to 3, RFC 3610's packet vector 1 and Microsoft's SMB
3.0 encryption vector (its WRITE request); then random keys of each AES
size, every nonce length (7 to 13) and tag length (4 to 16), AAD and
plaintext lengths around the block size and past the AAD's two-byte length
form.

Used by gen_vectors.py; generate() returns {file name: lines}. Its own
random stream, so the other vector files do not move.
"""

import random

from crypto_vectors import aes_ctr, aes_encrypt, hx, pad16

rng = random.Random(20261118)


def ccm_encrypt(key, nonce, aad, pt, tlen):
    q = 15 - len(nonce)
    b0 = bytes([(0x40 if aad else 0) | ((tlen - 2) // 2) << 3 | (q - 1)]) + nonce + len(pt).to_bytes(q, "big")
    blocks = b0
    if aad:
        head = len(aad).to_bytes(2, "big") if len(aad) < 0xff00 else b"\xff\xfe" + len(aad).to_bytes(4, "big")
        blocks += pad16(head + aad)
    blocks += pad16(pt)
    x = bytes(16)
    for off in range(0, len(blocks), 16):
        x = aes_encrypt(key, bytes(a ^ b for a, b in zip(x, blocks[off:off + 16])))
    ctr0 = bytes([q - 1]) + nonce + bytes(q)
    s0 = aes_encrypt(key, ctr0)
    ct = aes_ctr(key, (int.from_bytes(ctr0, "big") + 1).to_bytes(16, "big"), pt)
    return ct, bytes(a ^ b for a, b in zip(x[:tlen], s0))


_C = "404142434445464748494a4b4c4d4e4f"
CCM_SPEC = [
    (_C, "10111213141516", "0001020304050607", "20212223", "7162015b", "4dac255d"),
    (_C, "1011121314151617", "000102030405060708090a0b0c0d0e0f", "202122232425262728292a2b2c2d2e2f",
     "d2a1f0e051ea5f62081a7792073d593d", "1fc64fbfaccd"),
    (_C, "101112131415161718191a1b", "000102030405060708090a0b0c0d0e0f10111213",
     "202122232425262728292a2b2c2d2e2f3031323334353637",
     "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5", "484392fbc1b09951"),
    ("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", "00000003020100a0a1a2a3a4a5", "0001020304050607",
     "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
     "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384", "17e8d12cfdf926e0"),
    ("261b72350558f2e9dcf613070383edbf", "66e69a111892584fb5ed52",
     "66e69a111892584fb5ed524a744da3ee87000000000001001100001400e40800",
     "fe534d4240000100000000000900400008000000000000000400000000000000"
     "fffe0000010000001100001400e4080000000000000000000000000000000000"
     "3100700017000000000000000000000015010000390000020100000039020000"
     "00000000000000007000000000000000536d623320656e6372797074696f6e20"
     "74657374696e67",
     "25c8fee16605a437832d1cd52da9f4645333482a175fe5384563f45fcdafaef3"
     "8bc62ba4d5c62897996625a44c29be5658de2e6117585779e7b59ffd971278d0"
     "8580d7fa899e410e910eabf5aa1db43050b33b49182637759ac15d84bfcdf5b6"
     "b238993c0f4cf4d6012023f6c627297075d84b7803912d0a9639634453595ef3"
     "e33ffe4e7ac2ab", "81a286535415445dae393921e44fa42e"),
]
for _k, _n, _a, _p, _c, _t in CCM_SPEC:
    _got = ccm_encrypt(bytes.fromhex(_k), bytes.fromhex(_n), bytes.fromhex(_a), bytes.fromhex(_p), len(_t) // 2)
    assert (_got[0].hex(), _got[1].hex()) == (_c, _t)


def rbytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def generate():
    ccm = [f"ccm {' '.join(x or '-' for x in v)}" for v in CCM_SPEC]
    for i in range(42):
        key = rbytes((16, 24, 32)[i % 3])
        nonce = rbytes(7 + i % 7)
        tlen = 4 + 2 * (i % 7)
        aad = rbytes(rng.choice([0, 0, 1, 14, 15, 16, 17, 32, 40]))
        if i == 20:
            aad = rbytes(0xff00 + 5)              # the six-byte length form
        pt = rbytes(rng.choice([0, 1, 15, 16, 17, 32, 33, 64, rng.randint(65, 300)]))
        c, t = ccm_encrypt(key, nonce, aad, pt, tlen)
        ccm.append(f"ccm {hx(key)} {hx(nonce)} {hx(aad)} {hx(pt)} {hx(c)} {hx(t)}")
    return {"ccm.txt": ccm}


if __name__ == "__main__":
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test", "vectors", "ccm.txt")
    lines = generate()["ccm.txt"]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} cases to {os.path.normpath(path)}")
