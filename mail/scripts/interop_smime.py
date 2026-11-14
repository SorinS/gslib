#!/usr/bin/env python3
"""mail.smime against OpenSSL's `cms`, both ways: `goose-mail smime`
(mail/tools/mail.goose) and openssl 3 or later sign, verify, encrypt
and decrypt each other's messages.

  - signing: multipart/signed and opaque (pkcs7-mime signed-data), by RSA
    (PKCS #1 v1.5 and PSS), P-256, P-384 with SHA-384 and Ed25519, the
    intermediate CA sent with the signature; openssl's checked by
    goose-mail against the test root (path, email protection, From), ours
    by `openssl cms -verify -CAfile`; openssl's BER (-stream) too; a
    changed byte refused both ways;
  - encryption: RSA-OAEP (SHA-256) and RSA PKCS #1 v1.5, EC P-256 and
    P-384 (ECDH, X9.63 KDF, AES key wrap; openssl's SHA-1 KDF and its
    SHA-256 one), AES-128/256-CBC (EnvelopedData) and AES-128/256-GCM
    (AuthEnvelopedData), several recipients, recipients by key identifier;
  - sign-then-encrypt both ways.

Skips, and exits 0, when there is no openssl 3+.

    python3 scripts/interop_smime.py [--goose PATH] [--openssl PATH] [-k NAME]
    python3 scripts/interop_smime.py --write-vectors

--write-vectors makes a new test PKI (test only: example.com and
example.org addresses, keys made here for the tests and nothing else)
and the fixed vectors the unit tests read: test/smime/ (certificates,
keys, messages openssl made) and ../crypto/x509/test/cms_smime/vectors.txt.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
X509_VECTORS = os.path.join(ROOT, "..", "crypto", "x509", "test", "cms_smime")
only = None
results = {"passed": 0, "failed": 0}
skipped = []
OPENSSL = None
TOOL = None
NOW = "1893456000"         # 2030-01-01: inside the test certificates' validity

KEY_NOTE = "Test key for gslib's S/MIME tests only, made for them. Never use it for anything else.\n"
PEOPLE = [  # name, address, key options, key usage
    ("alice", "alice@example.com", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
     "digitalSignature,keyEncipherment"),
    ("bob", "bob@example.org", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
     "digitalSignature,keyAgreement"),
    ("carol", "carol@example.com", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
     "digitalSignature,keyAgreement"),
    ("dave", "dave@example.org", ["-algorithm", "ED25519"], "digitalSignature"),
    ("eve", "eve@example.com", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
     "digitalSignature,keyAgreement"),   # serverAuth only: not for email
]
ENTITY = (b"Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n"
          b"Hello from OpenSSL.\r\nA second line, and a third:\r\n\r\n-- \r\nAlice\r\n")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def find_openssl(arg):
    """An openssl of version 3 or later, or None."""
    for cand in [arg, os.environ.get("OPENSSL"), "/opt/homebrew/bin/openssl", "/usr/local/opt/openssl/bin/openssl",
                 shutil.which("openssl")]:
        if not cand or not os.path.isfile(cand):
            continue
        p = subprocess.run([cand, "version"], capture_output=True, text=True)
        m = re.match(r"OpenSSL (\d+)\.", p.stdout)
        if p.returncode == 0 and m and int(m.group(1)) >= 3:
            return cand
    return None


def report(name, ok, detail=""):
    if ok:
        results["passed"] += 1
        print("ok    " + name)
    else:
        results["failed"] += 1
        print("FAIL  " + name + (": " + detail.strip().replace("\n", "\n      ") if detail else ""))


def wanted(name):
    return only is None or only in name


def ossl(*args, input=None, check=True):
    p = subprocess.run([OPENSSL, *args], input=input, capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
    return p


def tool(*args):
    p = subprocess.run([TOOL, "smime", *args], capture_output=True, timeout=300)
    return p.returncode, p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")


def crlf(b):
    return re.sub(rb"(?<!\r)\n", b"\r\n", b)


# --- The test PKI ---------------------------------------------------------------------

def make_pki(d):
    """A root and an intermediate (P-256) and PEOPLE's certificates under it, in d."""
    f = lambda n: os.path.join(d, n)

    def ext(name, text):
        with open(f(name + ".ext"), "w") as fh:
            fh.write(text)
        return f(name + ".ext")

    ossl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f("root.key"))
    ossl("req", "-x509", "-new", "-key", f("root.key"), "-subj", "/O=Example Test/CN=S-MIME Test Root CA",
         "-days", "36500", "-set_serial", "1", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
         "-out", f("root.pem"))
    ossl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f("inter.key"))
    ossl("req", "-new", "-key", f("inter.key"), "-subj", "/O=Example Test/CN=S-MIME Test Intermediate CA",
         "-out", f("inter.csr"))
    ossl("x509", "-req", "-in", f("inter.csr"), "-CA", f("root.pem"), "-CAkey", f("root.key"), "-set_serial", "2",
         "-days", "36500", "-out", f("inter.pem"),
         "-extfile", ext("inter", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                                  "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"))
    for i, (name, addr, kopts, ku) in enumerate(PEOPLE):
        ossl("genpkey", *kopts, "-out", f(name + ".raw"))
        with open(f(name + ".raw")) as src, open(f(name + ".key"), "w") as dst:
            dst.write(KEY_NOTE + src.read())
        os.remove(f(name + ".raw"))
        ossl("req", "-new", "-key", f(name + ".key"), "-subj", f"/O=Example Test/CN={name.capitalize()} (test)",
             "-out", f(name + ".csr"))
        eku = "serverAuth" if name == "eve" else "emailProtection"
        ossl("x509", "-req", "-in", f(name + ".csr"), "-CA", f("inter.pem"), "-CAkey", f("inter.key"),
             "-set_serial", str(0x1000 + i), "-days", "36500", "-out", f(name + ".pem"),
             "-extfile", ext(name, f"basicConstraints=CA:FALSE\nkeyUsage=critical,{ku}\nextendedKeyUsage={eku}\n"
                                   f"subjectAltName=email:{addr}\nsubjectKeyIdentifier=hash\n"
                                   "authorityKeyIdentifier=keyid\n"))
        with open(f(name + "-chain.pem"), "w") as fh:
            fh.write(open(f(name + ".pem")).read() + open(f("inter.pem")).read())


def der(d, name):
    return ossl("x509", "-in", os.path.join(d, name + ".pem"), "-outform", "DER").stdout


def pkcs8(d, name):
    return ossl("pkey", "-in", os.path.join(d, name + ".key"), "-outform", "DER").stdout


# --- Fixed vectors ----------------------------------------------------------------------

def write_vectors():
    d = os.path.join(ROOT, "test", "smime")
    if os.path.isdir(d):
        shutil.rmtree(d)
    os.makedirs(d)
    make_pki(d)
    f = lambda n: os.path.join(d, n)
    for n in os.listdir(d):
        if n.endswith((".csr", ".ext", ".srl")) or n in ("root.key", "inter.key"):
            os.remove(f(n))
    with open(f("entity.txt"), "wb") as fh:
        fh.write(ENTITY)
    hdr = ["-from", "Alice <alice@example.com>", "-to", "bob@example.org", "-subject", "From OpenSSL"]

    def sign(out, who, *extra):
        ossl("cms", "-sign", "-in", f("entity.txt"), "-signer", f(who + ".pem"), "-inkey", f(who + ".key"),
             "-certfile", f("inter.pem"), *hdr, "-out", f(out), *extra)

    def enc(out, *extra, src="entity.txt"):
        ossl("cms", "-encrypt", "-in", f(src), *hdr, "-out", f(out), *extra)

    sign("ossl-signed-rsa.eml", "alice")
    sign("ossl-signed-pss.eml", "alice", "-keyopt", "rsa_padding_mode:pss")
    sign("ossl-signed-p256-opaque.eml", "bob", "-nodetach")
    sign("ossl-signed-p384.eml", "carol", "-md", "sha384")
    sign("ossl-signed-ed25519.eml", "dave")
    sign("ossl-signed-stream.eml", "alice", "-stream")
    sign("ossl-signed-eve.eml", "eve")
    enc("ossl-enc-rsa-pkcs1.eml", f("alice.pem"))
    enc("ossl-enc-rsa-oaep.eml", "-aes-128-cbc", "-recip", f("alice.pem"), "-keyopt", "rsa_padding_mode:oaep",
        "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256")
    enc("ossl-enc-p256.eml", f("bob.pem"))
    enc("ossl-enc-gcm.eml", "-aes-256-gcm", f("alice.pem"), f("bob.pem"))
    enc("ossl-enc-multi.eml", "-aes-128-cbc", "-keyid", f("alice.pem"), f("bob.pem"), f("carol.pem"))
    ossl("cms", "-sign", "-in", f("entity.txt"), "-signer", f("alice.pem"), "-inkey", f("alice.key"),
         "-out", f("signed.tmp"))
    enc("ossl-sign-encrypt.eml", f("bob.pem"), src="signed.tmp")
    os.remove(f("signed.tmp"))
    print(f"wrote {d}")

    # crypto/x509's: DER, hex, one per line, with the same keys.
    lines = []
    for name in ("alice", "bob", "carol", "dave"):
        lines.append(f"key {name} {der(d, name).hex()} {pkcs8(d, name).hex()}")
    lines.append(f"content {ENTITY.hex()}")
    t = tempfile.mkdtemp()

    def sv(label, who, detached, *extra):
        out = ossl("cms", "-sign", "-binary", "-outform", "DER", "-in", f("entity.txt"), "-signer", f(who + ".pem"),
                   "-inkey", f(who + ".key"), *([] if detached else ["-nodetach"]), *extra).stdout
        lines.append(f"signed {label} {who} {1 if detached else 0} {out.hex()}")

    def ev(label, who, *extra):
        out = ossl("cms", "-encrypt", "-binary", "-outform", "DER", "-in", f("entity.txt"), *extra).stdout
        lines.append(f"enveloped {label} {who} {out.hex()}")

    sv("rsa", "alice", True)
    sv("rsa-opaque", "alice", False)
    sv("rsa-pss", "alice", True, "-keyopt", "rsa_padding_mode:pss")
    sv("rsa-noattr", "alice", True, "-noattr")
    sv("p256-keyid", "bob", True, "-keyid")
    sv("p384-sha384", "carol", False, "-md", "sha384")
    sv("ed25519", "dave", True)
    sv("ed25519-noattr", "dave", False, "-noattr")
    sv("rsa-ber", "alice", False, "-stream")
    ev("rsa-pkcs1", "alice", f("alice.pem"))
    ev("rsa-oaep-sha1", "alice", "-recip", f("alice.pem"), "-keyopt", "rsa_padding_mode:oaep")
    ev("rsa-oaep-sha256", "alice", "-aes-128-cbc", "-recip", f("alice.pem"), "-keyopt", "rsa_padding_mode:oaep",
       "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256")
    ev("rsa-keyid", "alice", "-keyid", f("alice.pem"))
    ev("rsa-aes192", "alice", "-aes-192-cbc", f("alice.pem"))
    ev("p256-sha1kdf", "bob", f("bob.pem"))
    ev("p256-sha256kdf-keyid", "bob", "-keyid", "-recip", f("bob.pem"), "-keyopt", "ecdh_kdf_md:sha256")
    ev("p384", "carol", "-aes-128-cbc", f("carol.pem"))
    ev("gcm-rsa", "alice", "-aes-256-gcm", f("alice.pem"))
    ev("gcm-p256", "bob", "-aes-128-gcm", f("bob.pem"))
    ev("multi", "alice,bob,carol", f("alice.pem"), f("bob.pem"), f("carol.pem"))
    ev("rsa-ber", "alice", "-stream", "-aes-128-cbc", f("alice.pem"))
    shutil.rmtree(t)
    os.makedirs(X509_VECTORS, exist_ok=True)
    with open(os.path.join(X509_VECTORS, "vectors.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {os.path.normpath(X509_VECTORS)}/vectors.txt: {len(lines)} lines")


# --- Interop ------------------------------------------------------------------------------

def run_interop(d):
    f = lambda n: os.path.join(d, n)
    make_pki(d)
    with open(f("msg.eml"), "wb") as fh:
        fh.write(b"Date: Mon, 01 Jan 2030 00:00:00 +0000\r\nFrom: Alice <alice@example.com>\r\n"
                 b"To: Bob <bob@example.org>\r\nSubject: Interop\r\nMessage-ID: <interop@example.com>\r\n"
                 b"MIME-Version: 1.0\r\n" + ENTITY)
    with open(f("entity.txt"), "wb") as fh:
        fh.write(ENTITY)
    body = b"Hello from OpenSSL."
    hdr = ["-from", "Alice <alice@example.com>", "-to", "bob@example.org", "-subject", "Interop"]
    signers = [  # label, who, goose-mail options, openssl options
        ("rsa", "alice", [], []),
        ("rsa-pss", "alice", ["--pss"], ["-keyopt", "rsa_padding_mode:pss"]),
        ("p256", "bob", [], []),
        ("p384-sha384", "carol", ["--hash", "384"], ["-md", "sha384"]),
        ("ed25519", "dave", [], []),
    ]

    # Ours, checked by openssl: the signer's chain to the root, the content.
    for label, who, opts, _ in signers:
        for opaque in (False, True):
            name = f"sign {label}{' opaque' if opaque else ''}: ours -> openssl"
            if not wanted(name):
                continue
            out = f("ours.eml")
            rc, text = tool("sign", *opts, *(["--opaque"] if opaque else []), f(who + "-chain.pem"), f(who + ".key"),
                            f("msg.eml"), out)
            if rc != 0:
                report(name, False, text)
                continue
            p = ossl("cms", "-verify", "-in", out, "-CAfile", f("root.pem"), "-purpose", "smimesign", check=False)
            report(name, p.returncode == 0 and crlf(p.stdout) == ENTITY, p.stderr.decode())
            if not opaque:
                # A changed byte in the signed part: refused.
                data = open(out, "rb").read()
                i = data.find(b"Hello from")
                with open(f("bad.eml"), "wb") as fh:
                    fh.write(data[:i] + b"J" + data[i + 1:])
                p = ossl("cms", "-verify", "-in", f("bad.eml"), "-CAfile", f("root.pem"), check=False)
                report(name + ", changed: refused", p.returncode != 0)

    # Theirs, checked by ours: the path to the root, email protection, From.
    for label, who, _, oopts in signers:
        for mode, extra in (("", []), (" opaque", ["-nodetach"]), (" BER", ["-stream"])):
            name = f"sign {label}{mode}: openssl -> ours"
            if not wanted(name):
                continue
            addr = dict((p[0], p[1]) for p in PEOPLE)[who]
            ossl("cms", "-sign", "-in", f("entity.txt"), "-signer", f(who + ".pem"), "-inkey", f(who + ".key"),
                 "-certfile", f("inter.pem"), "-from", addr, "-subject", "Interop", *oopts, *extra,
                 "-out", f("theirs.eml"))
            rc, text = tool("verify", "--roots", f("root.pem"), "--now", NOW, f("theirs.eml"), f("out.eml"))
            got = open(f("out.eml"), "rb").read() if os.path.exists(f("out.eml")) else b""
            report(name, rc == 0 and "signer ok" in text and body in got and b"From: " in got, text)
            if os.path.exists(f("out.eml")):
                os.remove(f("out.eml"))
    name = "sign: openssl -> ours, changed: refused"
    if wanted(name):
        ossl("cms", "-sign", "-in", f("entity.txt"), "-signer", f("alice.pem"), "-inkey", f("alice.key"),
             *hdr, "-out", f("theirs.eml"))
        data = open(f("theirs.eml"), "rb").read()
        i = data.find(b"Hello from")
        open(f("theirs.eml"), "wb").write(data[:i] + b"J" + data[i + 1:])
        rc, text = tool("verify", f("theirs.eml"))
        report(name, rc != 0 and "signature does not verify" in text, text)
    name = "sign eve: openssl -> ours, not for email: refused"
    if wanted(name):
        ossl("cms", "-sign", "-in", f("entity.txt"), "-signer", f("eve.pem"), "-inkey", f("eve.key"),
             "-certfile", f("inter.pem"), "-from", "eve@example.com", "-out", f("theirs.eml"))
        rc, text = tool("verify", "--roots", f("root.pem"), "--now", NOW, f("theirs.eml"))
        report(name, rc != 0 and "extended key usage" in text, text)
    name = "sign bob: openssl -> ours, From not the signer's: refused"
    if wanted(name):
        ossl("cms", "-sign", "-in", f("entity.txt"), "-signer", f("bob.pem"), "-inkey", f("bob.key"),
             "-certfile", f("inter.pem"), *hdr, "-out", f("theirs.eml"))
        rc, text = tool("verify", "--roots", f("root.pem"), "--now", NOW, f("theirs.eml"))
        report(name, rc != 0 and "not alice@example.com" in text, text)

    # Encryption, ours -> openssl.
    encs = [  # label, goose-mail options, recipients
        ("rsa-oaep", [], ["alice"]),
        ("rsa-pkcs1", ["--pkcs1"], ["alice"]),
        ("p256", [], ["bob"]),
        ("p384 aes128-cbc", ["--cipher", "aes128-cbc"], ["carol"]),
        ("rsa aes256-gcm", ["--cipher", "aes256-gcm"], ["alice"]),
        ("p256 aes128-gcm", ["--cipher", "aes128-gcm"], ["bob"]),
        ("keyid", ["--keyid"], ["alice", "bob"]),
        ("multi", [], ["alice", "bob", "carol"]),
    ]
    for label, opts, rcpts in encs:
        name = f"encrypt {label}: ours -> openssl"
        if not wanted(name):
            continue
        rc, text = tool("encrypt", *opts, f("msg.eml"), f("ours.eml"), *[f(r + ".pem") for r in rcpts])
        if rc != 0:
            report(name, False, text)
            continue
        for r in rcpts:
            p = ossl("cms", "-decrypt", "-in", f("ours.eml"), "-recip", f(r + ".pem"), "-inkey", f(r + ".key"),
                     check=False)
            report(f"{name} ({r})", p.returncode == 0 and crlf(p.stdout) == ENTITY, p.stderr.decode())

    # Encryption, openssl -> ours.
    theirs = [  # label, openssl options, recipients, who decrypts
        ("rsa-pkcs1", [], ["alice"], "alice"),
        ("rsa-oaep-sha256", ["-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256",
                             "-keyopt", "rsa_mgf1_md:sha256"], ["alice"], "alice"),
        ("p256 sha1kdf", [], ["bob"], "bob"),
        ("p256 sha256kdf", ["-keyopt", "ecdh_kdf_md:sha256"], ["bob"], "bob"),
        ("p384 aes128-cbc", ["-aes-128-cbc"], ["carol"], "carol"),
        ("aes256-gcm", ["-aes-256-gcm"], ["alice", "bob"], "bob"),
        ("aes128-gcm", ["-aes-128-gcm"], ["alice"], "alice"),
        ("keyid", ["-keyid"], ["alice", "bob"], "alice"),
        ("multi", [], ["alice", "bob", "carol"], "carol"),
        ("BER", ["-stream"], ["alice"], "alice"),
    ]
    for label, oopts, rcpts, who in theirs:
        name = f"encrypt {label}: openssl -> ours"
        if not wanted(name):
            continue
        if oopts and oopts[0] == "-keyopt":        # -keyopt applies to the -recip before it
            args = [x for r in rcpts for x in ["-recip", f(r + ".pem"), *oopts]]
        else:
            args = oopts + [f(r + ".pem") for r in rcpts]
        ossl("cms", "-encrypt", "-in", f("entity.txt"), *hdr, "-out", f("theirs.eml"), *args)
        rc, text = tool("decrypt", f(who + ".pem"), f(who + ".key"), f("theirs.eml"), f("out.eml"))
        got = open(f("out.eml"), "rb").read() if os.path.exists(f("out.eml")) else b""
        report(name, rc == 0 and "encrypted" in text and got.endswith(ENTITY), text)
        if os.path.exists(f("out.eml")):
            os.remove(f("out.eml"))
    name = "encrypt: openssl -> ours, not a recipient: refused"
    if wanted(name):
        ossl("cms", "-encrypt", "-in", f("entity.txt"), "-out", f("theirs.eml"), f("alice.pem"))
        rc, text = tool("decrypt", f("bob.pem"), f("bob.key"), f("theirs.eml"))
        report(name, rc != 0 and "does not decrypt" in text, text)

    # Sign, then encrypt.
    name = "sign-encrypt: ours -> openssl"
    if wanted(name):
        rc, text = tool("sign-encrypt", f("alice-chain.pem"), f("alice.key"), f("msg.eml"), f("ours.eml"),
                        f("bob.pem"), f("alice.pem"))
        ok = rc == 0
        if ok:
            p = ossl("cms", "-decrypt", "-in", f("ours.eml"), "-recip", f("bob.pem"), "-inkey", f("bob.key"),
                     check=False)
            q = ossl("cms", "-verify", "-CAfile", f("root.pem"), input=p.stdout, check=False)
            ok = p.returncode == 0 and q.returncode == 0 and crlf(q.stdout) == ENTITY
            text = p.stderr.decode() + q.stderr.decode()
        report(name, ok, text)
    name = "sign-encrypt: openssl -> ours"
    if wanted(name):
        ossl("cms", "-sign", "-in", f("entity.txt"), "-signer", f("alice.pem"), "-inkey", f("alice.key"),
             "-certfile", f("inter.pem"), "-out", f("signed.tmp"))
        ossl("cms", "-encrypt", "-in", f("signed.tmp"), *hdr, "-aes-256-gcm", "-out", f("theirs.eml"), f("bob.pem"))
        rc, text = tool("decrypt", "--roots", f("root.pem"), "--now", NOW, f("bob.pem"), f("bob.key"),
                        f("theirs.eml"), f("out.eml"))
        got = open(f("out.eml"), "rb").read() if os.path.exists(f("out.eml")) else b""
        report(name, rc == 0 and "encrypted" in text and "signer ok" in text and got.endswith(ENTITY), text)


def main():
    global only, OPENSSL, TOOL
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--openssl")
    ap.add_argument("-k", help="only cases whose name contains this")
    ap.add_argument("--write-vectors", action="store_true", help="remake the test PKI and the fixed vectors")
    args = ap.parse_args()
    only = args.k
    OPENSSL = find_openssl(args.openssl)
    if OPENSSL is None:
        print("skip  S/MIME interop: no openssl 3 or later (pass --openssl or set OPENSSL)")
        return 0
    if args.write_vectors:
        write_vectors()
        return 0
    goose = find_goose(args.goose)
    with tempfile.TemporaryDirectory() as tmp:
        TOOL = os.path.join(tmp, "goose-mail")
        p = subprocess.run([goose, "build", "-o", TOOL, os.path.join(ROOT, "tools", "mail.goose")],
                           capture_output=True, text=True)
        if p.returncode != 0:
            report("goose-mail builds", False, (p.stdout + p.stderr)[-2000:])
            return 1
        run_interop(tmp)
    for s in skipped:
        print("skip  " + s)
    print(f"\n{results['passed']} passed, {results['failed']} failed")
    return 1 if results["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
