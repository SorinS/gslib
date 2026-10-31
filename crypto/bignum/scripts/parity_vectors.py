"""Vectors for the primitives added for parity with Go's crypto: ML-DSA
(mldsa.txt), HPKE (hpke.txt), DSA (dsa.txt) and RC2 (rc2.txt, from
openssl's legacy provider; tools/govectors makes xcrypto.txt from Go's
x/crypto for the rest of the x/crypto ciphers and hashes). Each file has a random stream of its
own, so adding one changes no other.

ML-DSA's vectors come from the openssl command (3.5 or later), the oracle
here: key pairs from seeds, with the expanded private key's SHA3-256;
deterministic signatures under several contexts; hedged ones, which can
only be verified; and changed signatures that openssl refuses.

HPKE's come from two published sets, converted: RFC 9180's (all four
modes; the CFRG repository's test-vectors.json, named by $HPKE_RFC9180_JSON)
and Go's crypto/hpke/testdata/hpke-pq.json for the post-quantum KEMs and
SHAKE KDFs. Without the RFC file hpke.txt is left as it is.

Used by gen_vectors.py, or run alone: python3 scripts/parity_vectors.py
"""

import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from crypto_vectors import OPENSSL

TMP = tempfile.mkdtemp()


def path(name, data=None):
    p = os.path.join(TMP, name)
    if data is not None:
        with open(p, "wb") as f:
            f.write(data)
    return p


def run(args, data=None, ok=True):
    p = subprocess.run([OPENSSL, *args], input=data, capture_output=True)
    if ok and p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
    return p


# --- ML-DSA -----------------------------------------------------------------

MLDSA = {44: dict(k=4, l=4, omega=80, lam=128, zbits=18, pk=1312, sig=2420),
         65: dict(k=6, l=5, omega=55, lam=192, zbits=20, pk=1952, sig=3309),
         87: dict(k=8, l=7, omega=75, lam=256, zbits=20, pk=2592, sig=4627)}


def mldsa_key(s, seed):
    pem = path(f"mldsa{s}.pem")
    run(["genpkey", "-algorithm", f"ML-DSA-{s}", "-pkeyopt", f"hexseed:{seed.hex()}", "-out", pem])
    pk = run(["pkey", "-in", pem, "-pubout", "-outform", "DER"]).stdout[-MLDSA[s]["pk"]:]
    text = run(["pkey", "-in", pem, "-text", "-noout"]).stdout.decode()
    priv = text.split("priv:")[1].split("pub:")[0]
    sk = bytes.fromhex("".join(c for c in priv if c in "0123456789abcdef"))
    return pem, pk, sk


def mldsa_ctx_opts(ctx):
    return ["-pkeyopt", f"hexcontext-string:{ctx.hex()}"] if ctx else []


def mldsa_sign(pem, msg, ctx, deterministic):
    m = path("msg", msg)
    opts = ["-pkeyopt", "deterministic:1"] if deterministic else []
    return run(["pkeyutl", "-sign", "-rawin", "-inkey", pem, "-in", m, *opts, *mldsa_ctx_opts(ctx)]).stdout


def mldsa_verifies(pem, msg, sig, ctx):
    m = path("msg", msg)
    sf = path("sig", sig)
    p = run(["pkeyutl", "-verify", "-rawin", "-inkey", pem, "-in", m, "-sigfile", sf, *mldsa_ctx_opts(ctx)], ok=False)
    return p.returncode == 0


def mldsa_changes(rng, s, sig):
    """Signatures that must fail: a bit flipped in the challenge, in z and
    in a hint position, and hint encodings that are not the one encoding."""
    p = MLDSA[s]
    c = p["lam"] // 4
    hints = c + p["l"] * 32 * p["zbits"]
    out = []
    for at in (rng.randrange(c), c + rng.randrange(hints - c), hints + rng.randrange(p["omega"])):
        b = bytearray(sig)
        b[at] ^= 1 << rng.randrange(8)
        out.append(bytes(b))
    counts = sig[hints + p["omega"]:]
    # A count past omega; a count that goes down; a nonzero byte after the
    # last hint (when there is room); two equal positions in a row.
    b = bytearray(sig)
    b[hints + p["omega"] + p["k"] - 1] = p["omega"] + 1
    out.append(bytes(b))
    if counts[0] > 0:
        b = bytearray(sig)
        b[hints + p["omega"] + 1] = 0
        b[hints + p["omega"]] = counts[1] + 1 if counts[1] + 1 <= p["omega"] else counts[1]
        if b[hints + p["omega"]] > b[hints + p["omega"] + 1]:
            out.append(bytes(b))
    total = counts[-1]
    if total < p["omega"]:
        b = bytearray(sig)
        b[hints + p["omega"] - 1] = 1
        out.append(bytes(b))
    if counts[0] >= 2:
        b = bytearray(sig)
        b[hints + 1] = b[hints]
        out.append(bytes(b))
    return out


def mldsa_vectors():
    rng = random.Random(20261026_4)
    rb = lambda n: bytes(rng.getrandbits(8) for _ in range(n))
    lines = []
    count = 0
    for s in (44, 65, 87):
        for ki in range(3):
            seed = rb(32)
            pem, pk, sk = mldsa_key(s, seed)
            lines.append(f"key {s} {seed.hex()} {pk.hex()} {hashlib.sha3_256(sk).hexdigest()}")
            ctxs = [b"", rb(1), rb(rng.randrange(2, 64)), rb(255)]
            for ctx in ctxs:
                msg = rb(rng.choice([1, 32, rng.randrange(1, 300)]))  # openssl pkeyutl reads no empty file
                sig = mldsa_sign(pem, msg, ctx, True)
                assert len(sig) == MLDSA[s]["sig"] and mldsa_verifies(pem, msg, sig, ctx)
                lines.append(f"sig {ctx.hex() or '-'} {msg.hex() or '-'} {sig.hex()}")
                count += 1
            for _ in range(2):
                ctx, msg = rb(rng.randrange(8)), rb(rng.randrange(1, 100))
                sig = mldsa_sign(pem, msg, ctx, False)
                assert mldsa_verifies(pem, msg, sig, ctx)
                lines.append(f"hedged {ctx.hex() or '-'} {msg.hex() or '-'} {sig.hex()}")
                count += 1
            ctx, msg = rb(4), rb(50)
            sig = mldsa_sign(pem, msg, ctx, True)
            for bad in mldsa_changes(rng, s, sig):
                assert not mldsa_verifies(pem, msg, bad, ctx), "openssl accepted a changed signature"
                lines.append(f"bad {ctx.hex()} {msg.hex()} {bad.hex()}")
                count += 1
    print(f"ML-DSA: {count} signatures from openssl")
    return lines


# --- DSA --------------------------------------------------------------------

def dsa_field(text, name):
    part = text.split(name + ":")[1]
    hexes = []
    for line in part.splitlines()[1:]:
        if not line.startswith("    "):
            break
        hexes.append(line.strip().replace(":", ""))
    return bytes.fromhex("".join(hexes)).lstrip(b"\0")


def der_ints(der):
    """r and s of a DER DSA signature."""
    assert der[0] == 0x30
    at = 3 if der[1] == 0x81 else 2
    out = []
    for _ in range(2):
        assert der[at] == 2
        n = der[at + 1]
        out.append(int.from_bytes(der[at + 2:at + 2 + n], "big"))
        at += 2 + n
    return out


def dsa_vectors():
    rng = random.Random(20261026_5)
    rb = lambda n: bytes(rng.getrandbits(8) for _ in range(n))
    hashes = {"sha1": (hashlib.sha1, 160), "sha224": (hashlib.sha224, 224), "sha256": (hashlib.sha256, 256),
              "sha384": (hashlib.sha384, 384), "sha512": (hashlib.sha512, 512)}
    lines = []
    count = 0
    for l, n in ((1024, 160), (2048, 224), (2048, 256), (3072, 256)):
        params = path(f"dsa{l}.pem")
        run(["genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", f"dsa_paramgen_bits:{l}",
             "-pkeyopt", f"dsa_paramgen_q_bits:{n}", "-out", params])
        for ki in range(2):
            pem = path(f"dsakey{l}_{n}.pem")
            run(["genpkey", "-paramfile", params, "-out", pem])
            text = run(["pkey", "-in", pem, "-text", "-noout"]).stdout.decode()
            p, q, g = (dsa_field(text, x) for x in ("P", "Q", "G"))
            y, x = dsa_field(text, "pub"), dsa_field(text, "priv")
            pw, qw = l // 8, n // 8
            lines.append(f"key {p.rjust(pw, b'\0').hex()} {q.hex()} {g.rjust(pw, b'\0').hex()} "
                         f"{y.rjust(pw, b'\0').hex()} {x.rjust(qw, b'\0').hex()}")
            for name, (fn, hid) in hashes.items():
                d = fn(rb(rng.randrange(1, 100))).digest()
                df = path("digest", d)
                der = run(["pkeyutl", "-sign", "-inkey", pem, "-in", df, "-pkeyopt", f"digest:{name}",
                           "-pkeyopt", "nonce-type:1"]).stdout
                r, s_ = der_ints(der)
                raw = r.to_bytes(qw, "big") + s_.to_bytes(qw, "big")
                lines.append(f"det {hid} {d.hex()} {raw.hex()} {der.hex()}")
                count += 1
                rnd = run(["pkeyutl", "-sign", "-inkey", pem, "-in", df, "-pkeyopt", f"digest:{name}"]).stdout
                lines.append(f"rnd {d.hex()} {rnd.hex()}")
                count += 1
                # A changed signature openssl refuses: a flipped bit in r or s.
                r2, s2 = der_ints(rnd)
                bad = bytearray(r2.to_bytes(qw, "big") + s2.to_bytes(qw, "big"))
                bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
                rr, ss = int.from_bytes(bad[:qw], "big"), int.from_bytes(bad[qw:], "big")
                body = b"".join(b"\x02" + bytes([len(v)]) + v for v in
                                (i.to_bytes((i.bit_length() + 8) // 8, "big") for i in (rr, ss)))
                bder = (b"\x30" + bytes([len(body)]) + body) if len(body) < 128 else (b"\x30\x81" + bytes([len(body)]) + body)
                sf = path("sig", bder)
                ok = run(["pkeyutl", "-verify", "-inkey", pem, "-in", df, "-sigfile", sf, "-pkeyopt", f"digest:{name}"],
                         ok=False).returncode == 0
                assert not ok, "openssl accepted a changed DSA signature"
                lines.append(f"bad {d.hex()} {bytes(bad).hex()}")
                count += 1
    print(f"DSA: {count} signatures from openssl")
    return lines


# --- RC2 --------------------------------------------------------------------

def rc2_vectors():
    """CBC under RC2 at the effective key lengths PKCS #12 uses."""
    rng = random.Random(20261026_6)
    rb = lambda n: bytes(rng.getrandbits(8) for _ in range(n))
    lines = []
    for name, keylen, bits in (("rc2-40-cbc", 5, 40), ("rc2-64-cbc", 8, 64), ("rc2-cbc", 16, 128)):
        for _ in range(4):
            key, iv, pt = rb(keylen), rb(8), rb(8 * rng.randrange(1, 5))
            ct = run(["enc", f"-{name}", "-K", key.hex(), "-iv", iv.hex(), "-nopad", "-provider", "legacy",
                      "-provider", "default"], pt).stdout
            assert len(ct) == len(pt)
            lines.append(f"rc2 {key.hex()} {bits} {iv.hex()} {pt.hex()} {ct.hex()}")
    return lines


# --- HPKE -------------------------------------------------------------------

HPKE_SEALS = (0, 1, 2, 3, 4, 255, 256)     # the sequence numbers kept of 257


def hpke_lines(v):
    h = lambda k: v.get(k) or "-"
    lines = [" ".join(["suite", str(v["mode"]), str(v["kem_id"]), str(v["kdf_id"]), str(v["aead_id"]),
                       *(h(k) for k in ("info", "ikmE", "ikmR", "ikmS", "skRm", "pkRm", "skSm", "pkSm", "psk",
                                        "psk_id", "enc", "shared_secret", "key", "base_nonce", "exporter_secret"))])]
    encs = v.get("encryptions") or []
    for i, e in enumerate(encs):
        assert e["aad"] == f"Count-{i}".encode().hex() and e["pt"] == encs[0]["pt"]
        if i in HPKE_SEALS or i < 10:
            lines.append(f"seal {i} {e['aad']} {e['pt']} {e['ct']}")
    for x in v["exports"]:
        lines.append(f"export {x['exporter_context'] or '-'} {x['L']} {x['exported_value']}")
    return lines


def hpke_vectors():
    rfc = os.environ.get("HPKE_RFC9180_JSON")
    if not rfc or not os.path.exists(rfc):
        print("HPKE: $HPKE_RFC9180_JSON not set, hpke.txt left as it is")
        return None
    goroot = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True).stdout.strip()
    pq = os.path.join(goroot, "src", "crypto", "hpke", "testdata", "hpke-pq.json")
    lines = []
    n = 0
    for v in json.load(open(rfc)) + json.load(open(pq)):
        if v["kem_id"] == 0x0021 or v["kdf_id"] in (0x0012, 0x0013):
            continue                      # X448 and TurboSHAKE, which Go lacks too
        lines += hpke_lines(v)
        n += 1
    print(f"HPKE: {n} suites")
    return lines


def generate():
    out = {"mldsa.txt": mldsa_vectors(), "dsa.txt": dsa_vectors(), "rc2.txt": rc2_vectors()}
    h = hpke_vectors()
    if h is not None:
        out["hpke.txt"] = h
    return out


if __name__ == "__main__":
    import gen_vectors
    for name, lines in generate().items():
        gen_vectors.write(name, lines)
