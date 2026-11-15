#!/usr/bin/env python3
"""Known answers for tpm2's unit tests, computed here with Python's hashlib
and hmac alone (no TPM code shared with the library): KDFa and KDFe
(TPM Library Part 1 §11.4.10), well-known policy digests, a command's
cpHash and HMAC and a response's rpHash HMAC, and a crypto-agile TCG event
log with the PCR values its replay must give. Prints the Goose lets of
test/known.goose.

    python3 scripts/make_vectors.py > test/known.goose
"""

import hashlib
import hmac
import struct

H = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha384": hashlib.sha384}


def kdfa(h, key, label, u, v, bits):
    out = b""
    i = 1
    while len(out) * 8 < bits:
        out += hmac.new(key, struct.pack(">I", i) + label + b"\0" + u + v + struct.pack(">I", bits), H[h]).digest()
        i += 1
    out = out[:(bits + 7) // 8]
    if bits % 8:
        out = bytes([out[0] & ((1 << (bits % 8)) - 1)]) + out[1:]
    return out


def kdfe(h, z, label, u, v, bits):
    out = b""
    i = 1
    while len(out) * 8 < bits:
        out += H[h](struct.pack(">I", i) + z + label + b"\0" + u + v).digest()
        i += 1
    return out[:(bits + 7) // 8]


def let(name, b):
    print(f'let {name} = "{b.hex()}";')


def policy_update(digest, cc, arg):
    return hashlib.sha256(digest + struct.pack(">I", cc) + arg).digest()


def main():
    print("// Made by scripts/make_vectors.py with Python's hashlib and hmac: KDFa,")
    print("// KDFe, policy digests, a command and response HMAC, an event log.")
    print("")
    print("namespace known;")
    print("")
    let("KDFA_SHA256_256", kdfa("sha256", b"a key", b"LABEL", b"context u", b"context v", 256))
    let("KDFA_SHA256_600", kdfa("sha256", b"a key", b"LABEL", b"context u", b"context v", 600))
    let("KDFA_SHA256_100", kdfa("sha256", b"a key", b"LABEL", b"context u", b"context v", 100))
    let("KDFA_SHA1_160", kdfa("sha1", b"a key", b"STORAGE", b"\x00\x0bname", b"", 160))
    let("KDFA_SHA384_128", kdfa("sha384", b"", b"CFB", b"newer", b"older", 128))
    let("KDFE_SHA256_256", kdfe("sha256", b"\x11" * 32, b"IDENTITY", b"\x22" * 32, b"\x33" * 32, 256))
    let("KDFE_SHA384_512", kdfe("sha384", b"\x11" * 48, b"SECRET", b"\x22" * 48, b"\x33" * 48, 512))

    zero = b"\0" * 32
    let("POLICY_AUTH_VALUE", policy_update(zero, 0x16B, b""))
    ek = hashlib.sha256(policy_update(zero, 0x151, struct.pack(">I", 0x4000000B))).digest()
    let("POLICY_EK", ek)
    let("POLICY_CC_UNSEAL", policy_update(zero, 0x16C, struct.pack(">I", 0x15E)))
    # PolicyPCR of sha256 PCR 23, all zeros.
    sel = struct.pack(">IHB", 1, 0x000B, 3) + bytes([0, 0, 0x80])
    let("POLICY_PCR23_ZERO", policy_update(zero, 0x17F, sel + hashlib.sha256(zero).digest()))
    # PolicyOR of PolicyAuthValue and PolicyCommandCode(Unseal).
    a = policy_update(zero, 0x16B, b"")
    b = policy_update(zero, 0x16C, struct.pack(">I", 0x15E))
    let("POLICY_OR", policy_update(zero, 0x171, a + b))
    # PolicyAuthorize by a key Name, with a policyRef.
    name = bytes.fromhex("000b") + hashlib.sha256(b"authorizing key").digest()
    let("AUTHORIZE_NAME", name)
    let("POLICY_AUTHORIZE", hashlib.sha256(policy_update(zero, 0x16A, name) + b"ref").digest())

    # A command's HMAC: TPM2_Unseal(0x80000001) in an HMAC session.
    skey = bytes(range(32))
    nc = bytes([0xC0] * 32)
    nt = bytes([0x7E] * 32)
    item_name = bytes.fromhex("000b") + hashlib.sha256(b"sealed item").digest()
    auth = b"pin"
    cp = hashlib.sha256(struct.pack(">I", 0x15E) + item_name).digest()
    let("SESSION_KEY", skey)
    let("NONCE_CALLER", nc)
    let("NONCE_TPM", nt)
    let("ITEM_NAME", item_name)
    let("CMD_HMAC", hmac.new(skey + auth, cp + nc + nt + b"\x01", hashlib.sha256).digest())
    # The response: outData "unsealed!" and a new nonceTPM.
    params = struct.pack(">H", 9) + b"unsealed!"
    nt2 = bytes([0x5A] * 32)
    rp = hashlib.sha256(struct.pack(">II", 0, 0x15E) + params).digest()
    mac = hmac.new(skey + auth, rp + nt2 + nc + b"\x01", hashlib.sha256).digest()
    body = params
    auth_area = struct.pack(">H", 32) + nt2 + b"\x01" + struct.pack(">H", 32) + mac
    rsp = struct.pack(">HII", 0x8002, 10 + 4 + len(body) + len(auth_area), 0) + struct.pack(">I", len(body)) + body + auth_area
    let("UNSEAL_RESPONSE", rsp)

    # A crypto-agile event log: the Spec ID header (SHA-1 and SHA-256), a
    # StartupLocality of 3, events on PCRs 0, 1, 7 and separators.
    spec = b"Spec ID Event03\0" + struct.pack("<IBBBBI", 0, 0, 2, 0, 2, 2) + struct.pack("<HHHH", 0x4, 20, 0xB, 32) + b"\0"
    log = struct.pack("<II", 0, 3) + b"\0" * 20 + struct.pack("<I", len(spec)) + spec
    pcr1 = {i: b"\0" * 20 for i in range(24)}
    pcr256 = {i: b"\0" * 32 for i in range(24)}

    def event(pcr, etype, data, extend=True):
        nonlocal log
        d1 = hashlib.sha1(data).digest()
        d256 = hashlib.sha256(data).digest()
        log += struct.pack("<III", pcr, etype, 2) + struct.pack("<H", 0x4) + d1 + struct.pack("<H", 0xB) + d256
        log += struct.pack("<I", len(data)) + data
        if extend:
            pcr1[pcr] = hashlib.sha1(pcr1[pcr] + d1).digest()
            pcr256[pcr] = hashlib.sha256(pcr256[pcr] + d256).digest()

    # StartupLocality: EV_NO_ACTION on PCR 0, digests zero, not extended.
    loc = b"StartupLocality\0" + b"\x03"
    log += struct.pack("<III", 0, 3, 2) + struct.pack("<H", 0x4) + b"\0" * 20 + struct.pack("<H", 0xB) + b"\0" * 32
    log += struct.pack("<I", len(loc)) + loc
    pcr1[0] = b"\0" * 19 + b"\x03"
    pcr256[0] = b"\0" * 31 + b"\x03"
    event(0, 0x8, b"S-CRTM version 1.0")
    event(0, 0x80000008, b"firmware blob")
    event(1, 0x80000006, b"handoff tables")
    event(7, 0x800000E0, b"SecureBoot=1")
    for i in (0, 1, 7):
        event(i, 0x4, b"\0\0\0\0")
    event(4, 0x80000003, b"bootloader")
    let("EVENT_LOG", log)
    let("EVENT_LOG_PCRS_SHA256", b"".join(pcr256[i] for i in range(24)))
    let("EVENT_LOG_PCRS_SHA1", b"".join(pcr1[i] for i in range(24)))


if __name__ == "__main__":
    main()
