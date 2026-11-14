#!/usr/bin/env python3
"""PGP/MIME (mail.pgp) against gpg, both ways.

gpg makes two test keys (Ed25519 + Curve25519, and RSA-3072) in a
throwaway GNUPGHOME, and for the interop a post-quantum one (Carol:
Ed25519 with gpg's ky768_cv25519 subkey, LibrePGP's ML-KEM-768+X25519).
Then:

  ours -> gpg   mail.pgp signs a message (multipart/signed): gpg verifies
                its signature over the first body part exactly as sent;
                mail.pgp encrypts one (multipart/encrypted), signed and
                not: gpg decrypts the second body part to the entity,
                and checks the signature inside; the same to Carol's
                post-quantum key
  gpg -> ours   gpg signs an entity and encrypts one (signed in the same
                message, RFC 3156 §6.2, and a multipart/signed inside the
                encryption, §6.1); the messages are put together here as a
                mail client would, and mail.pgp opens them to the entity;
                gpg encrypts one to Carol's post-quantum key

The goose side is test/pgp/pgpmime.goose, built into the temp directory.

    python3 scripts/interop_pgp.py [--goose PATH] [-k NAME]
    python3 scripts/interop_pgp.py --write-vectors

--write-vectors writes test/pgp/: the keys (test keys only, unprotected)
and messages gpg made, for test/pgp.goose. It skips (exit 0) when gpg is
not installed; the agent is stopped with gpgconf --kill gpg-agent under
its own GNUPGHOME.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "..", "crypto", "openpgp", "scripts"))
from gpghome import GpgHome, GPG  # noqa: E402

ENTITY = (b"Content-Type: text/plain; charset=UTF-8\r\n"
          b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
          b"Hello Bob,\r\n\r\nthis is signed. Caf=C3=A9 at noon?\r\n-- \r\nAlice\r\n")
OUTER = (b"Date: Sat, 14 Nov 2026 10:00:00 +0000\r\nFrom: Alice <alice@example.com>\r\n"
         b"To: Bob <bob@example.com>\r\nSubject: PGP/MIME test\r\n"
         b"Message-ID: <pgp-test@example.com>\r\nMIME-Version: 1.0\r\n")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def make_keys(g):
    g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
          "Alice <alice@example.com>", "default", "default", "never")
    spec = ("%no-protection\nKey-Type: RSA\nKey-Length: 3072\nSubkey-Type: RSA\nSubkey-Length: 3072\n"
            "Name-Real: Bob\nName-Email: bob@example.com\nExpire-Date: 0\n%commit\n")
    g.gpg("--gen-key", input=spec.encode())


def make_pqc_key(g):
    """Carol: Ed25519 with a ky768_cv25519 subkey (gpg's own "pqc" default
    is Brainpool, which mail.pgp's openpgp does not do)."""
    g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
          "Carol <carol@example.com>", "ed25519", "cert,sign", "never")
    fpr = [l.split(":")[9] for l in g.gpg("--with-colons", "--fingerprint", "--list-keys", "carol@example.com")
           .stdout.decode().splitlines() if l.startswith("fpr:")][0]
    g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-add-key", fpr, "ky768_cv25519", "encr", "never")


def gpg_signed(g, d):
    """A multipart/signed message put together around gpg's signature."""
    ent = os.path.join(d, "entity")
    with open(ent, "wb") as f:
        f.write(ENTITY)
    sig = g.gpg("--trust-model", "always", "-u", "alice@example.com", "--digest-algo", "SHA256",
                "-a", "-b", "-o", "-", ent).stdout.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    b = b"gpg-signed-boundary"
    return (OUTER + b'Content-Type: multipart/signed; boundary="' + b + b'"; micalg=pgp-sha256;\r\n'
            b' protocol="application/pgp-signature"\r\n\r\n--' + b + b"\r\n" + ENTITY + b"\r\n--" + b +
            b"\r\nContent-Type: application/pgp-signature; name=\"signature.asc\"\r\n\r\n" + sig +
            b"\r\n--" + b + b"--\r\n")


def gpg_encrypted(g, d, entity, sign, rcpts=("bob", "alice")):
    """A multipart/encrypted message around gpg's encryption of entity."""
    ent = os.path.join(d, "entity2")
    with open(ent, "wb") as f:
        f.write(entity)
    extra = ["-u", "alice@example.com", "-s"] if sign else []
    to = [a for r in rcpts for a in ("-r", r + "@example.com")]
    enc = g.gpg("--trust-model", "always", *to, *extra,
                "-a", "-e", "-o", "-", ent).stdout.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    b = b"gpg-encrypted-boundary"
    return (OUTER + b'Content-Type: multipart/encrypted; boundary="' + b + b'";\r\n'
            b' protocol="application/pgp-encrypted"\r\n\r\n--' + b +
            b"\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--" + b +
            b"\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\r\n" + enc +
            b"\r\n--" + b + b"--\r\n")


def nested_entity(signed_msg):
    """The multipart/signed entity of a signed message (its Content-* fields and body)."""
    head, body = signed_msg.split(b"\r\n\r\n", 1)
    fields = re.findall(rb"(?m)^Content-[^\r\n]*\r\n(?:[ \t][^\r\n]*\r\n)*", head + b"\r\n")
    return b"".join(fields) + b"\r\n" + body


def parts(msg):
    """The body parts of a multipart message, as sent."""
    head, body = msg.split(b"\r\n\r\n", 1)
    m = re.search(rb'boundary="([^"]+)"', head)
    delim = b"--" + m.group(1)
    pieces = body.split(b"\r\n" + delim)
    out = []
    for p in pieces[1:]:
        if p.startswith(b"--"):
            break
        out.append(p[p.index(b"\r\n") + 2:])
    return out


def write_vectors():
    out = os.path.join(ROOT, "test", "pgp")
    os.makedirs(out, exist_ok=True)
    with GpgHome() as g:
        make_keys(g)
        keys = g.gpg("--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys").stdout
        with open(os.path.join(out, "keys.sec"), "wb") as f:
            f.write(keys)
        with open(os.path.join(out, "keys.pub"), "wb") as f:
            f.write(g.gpg("--export").stdout)
        signed = gpg_signed(g, g.dir)
        for name, data in (("gpg-signed.eml", signed),
                           ("gpg-encrypted.eml", gpg_encrypted(g, g.dir, ENTITY, False)),
                           ("gpg-signed-encrypted.eml", gpg_encrypted(g, g.dir, ENTITY, True)),
                           ("gpg-nested.eml", gpg_encrypted(g, g.dir, nested_entity(signed), False))):
            with open(os.path.join(out, name), "wb") as f:
                f.write(data)
        with open(os.path.join(out, "entity.txt"), "wb") as f:
            f.write(ENTITY)
    print("wrote", out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--write-vectors", action="store_true")
    ap.add_argument("-k", help="only cases whose name contains this")
    args = ap.parse_args()
    if not GPG:
        print("gpg not found: interop skipped")
        return 0
    if args.write_vectors:
        write_vectors()
        return 0
    passed, failed = 0, []

    def case(name, ok, detail=b""):
        nonlocal passed
        if args.k and args.k not in name:
            return
        print(("ok    " if ok else "FAIL  ") + name)
        if ok:
            passed += 1
        else:
            failed.append(name)
            if detail:
                print("      " + detail.decode(errors="replace").strip().replace("\n", "\n      ")[:2000])

    with GpgHome() as g:
        d = g.dir
        tool = os.path.join(d, "pgpmime")
        p = subprocess.run([find_goose(args.goose), "build", "-o", tool, "pgpmime.goose"],
                           cwd=os.path.join(ROOT, "test", "pgp"), capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("building pgpmime failed:\n" + p.stdout + p.stderr)
        make_keys(g)
        make_pqc_key(g)
        keys = os.path.join(d, "keys.sec")
        with open(keys, "wb") as f:
            f.write(g.gpg("--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys").stdout)

        def path(n):
            return os.path.join(d, n)

        def write(n, data):
            with open(path(n), "wb") as f:
                f.write(data)

        def read(n):
            with open(path(n), "rb") as f:
                return f.read()

        # Ours -> gpg.
        write("plain.eml", OUTER + ENTITY)
        for signer in ("alice", "bob"):
            name = f"gpg verifies our multipart/signed by {signer}"
            q = subprocess.run([tool, "sign", keys, signer + "@example.com", path("plain.eml"), path("s.eml")], capture_output=True)
            ok = q.returncode == 0
            detail = q.stderr
            if ok:
                msg = read("s.eml")
                ps = parts(msg)
                write("s.part", ps[0])
                write("s.asc", ps[1].split(b"\r\n\r\n", 1)[1])
                v = g.gpg("--trust-model", "always", "--verify", path("s.asc"), path("s.part"), check=False)
                ok = (v.returncode == 0 and b"Good signature" in v.stderr and ps[0] == ENTITY
                      and msg.startswith(OUTER[:-len(b"MIME-Version: 1.0\r\n")]) and b"micalg=pgp-sha256" in msg)
                detail = v.stderr
            case(name, ok, detail)
        for rcpt, signer in (("bob", "-"), ("alice", "-"), ("bob", "alice"), ("alice", "bob"), ("carol", "-"),
                             ("carol", "alice")):
            name = (f"gpg decrypts our multipart/encrypted to {rcpt}" + (" (Kyber)" if rcpt == "carol" else "")
                    + ("" if signer == "-" else f", signed by {signer}"))
            signer_arg = signer if signer == "-" else signer + "@example.com"
            q = subprocess.run([tool, "encrypt", keys, rcpt + "@example.com", signer_arg, path("plain.eml"), path("e.eml")],
                               capture_output=True)
            ok = q.returncode == 0
            detail = q.stderr
            if ok:
                ps = parts(read("e.eml"))
                write("e.asc", ps[1].split(b"\r\n\r\n", 1)[1])
                v = g.gpg("--trust-model", "always", "-o", path("e.out"), "--decrypt", path("e.asc"), check=False)
                ok = (v.returncode == 0 and read("e.out") == ENTITY and ps[0].endswith(b"Version: 1\r\n")
                      and (signer == "-" or b"Good signature" in v.stderr)
                      and (rcpt != "carol" or b"ky768_cv25519" in v.stderr))
                detail = v.stderr
            case(name, ok, detail)

        # gpg -> ours.
        signed = gpg_signed(g, d)
        for name, data, enc, sig in (("we open gpg's multipart/signed", signed, False, True),
                                     ("we open gpg's multipart/encrypted", gpg_encrypted(g, d, ENTITY, False), True, False),
                                     ("we open gpg's signed and encrypted (combined)", gpg_encrypted(g, d, ENTITY, True), True, True),
                                     ("we open gpg's multipart/signed inside multipart/encrypted",
                                      gpg_encrypted(g, d, nested_entity(signed), False), True, True),
                                     ("we open gpg's multipart/encrypted to carol (Kyber)",
                                      gpg_encrypted(g, d, ENTITY, False, ("carol",)), True, False),
                                     ("we open gpg's signed and encrypted to carol (Kyber)",
                                      gpg_encrypted(g, d, ENTITY, True, ("carol",)), True, True)):
            write("g.eml", data)
            q = subprocess.run([tool, "open", keys, path("g.eml"), path("g.out")], capture_output=True)
            ok = (q.returncode == 0 and read("g.out") == ENTITY and (b"encrypted" in q.stdout) == enc
                  and (b"signed by" in q.stdout) == sig)
            case(name, ok, q.stdout + q.stderr)
        bad = bytearray(signed)
        bad[bad.index(b"this is signed")] = ord("T")
        write("bad.eml", bytes(bad))
        q = subprocess.run([tool, "open", keys, path("bad.eml"), path("g.out")], capture_output=True)
        case("we refuse gpg's multipart/signed with a changed body", q.returncode != 0 and b"signature" in q.stderr, q.stderr)
    print(f"\n{passed} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
