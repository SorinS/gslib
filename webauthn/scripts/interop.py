#!/usr/bin/env python3
"""goose-webauthn against python-fido2's Fido2Server, py_webauthn (Duo's)
and go-webauthn, both ways, with a software authenticator.

The authenticator here builds its responses with python-fido2's own
classes (CollectedClientData, AuthenticatorData, AttestedCredentialData,
AttestationObject, CoseKey) and signs with cryptography: ES256, ES384,
EdDSA, RS256 and PS256 credentials, attested none, packed (self, and
with a certificate under a throwaway CA) and fido-u2f.

- Its registrations and assertions are verified by goose-webauthn
  (verify-registration with the CA as root and trust required,
  verify-authentication with the record that wrote), by py_webauthn
  (verify_registration_response, verify_authentication_response), by
  python-fido2's Fido2Server (register_complete, authenticate_complete)
  and by go-webauthn (CreateCredential, ValidateLogin).
- Their options (Fido2Server.register_begin and authenticate_begin,
  py_webauthn's generate_*_options, go-webauthn's BeginRegistration and
  BeginLogin) are answered by the authenticator, and the answers checked
  by them and by goose-webauthn with their challenge.
- goose-webauthn's options are read by them: py_webauthn's
  parse_*_options_json, python-fido2's PublicKeyCredential*Options.from_dict
  and go-webauthn's protocol types, which must find what was asked.
- Changed responses (another challenge, origin or RP ID, a signature
  changed, UV required and not given, the credential ID swapped) are
  refused by every one of them.

    WEBAUTHN_PYTHON=venv/bin/python make interop-webauthn
    python3 webauthn/scripts/interop.py [--work DIR] [--goose PATH]

Needs fido2 (2.x), webauthn, cbor2 and cryptography in the Python that
runs it, and Go for go-webauthn (built from scripts/gowebauthn, whose
go.mod pins it; WEBAUTHN_GOPATH keeps the module cache between runs).
A part whose tool is missing is skipped. Nothing is installed.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
RP_ID = "example.org"
ORIGIN = "https://example.org"

passed = failed = skipped = 0


def check(what, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("ok    " + what)
    else:
        failed += 1
        print("FAIL  " + what + ("\n      " + detail.strip().replace("\n", "\n      ") if detail else ""))


def skip(what, why):
    global skipped
    skipped += 1
    print(f"skip  {what}: {why}")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


# --- The software authenticator ------------------------------------------------------

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import (AttestationObject, AttestedCredentialData, AuthenticatorData, CollectedClientData)

AAGUID = bytes.fromhex("6e6f742d612d7265616c2d6b65792121")
FLAGS_UP, FLAGS_UV, FLAGS_BE, FLAGS_BS, FLAGS_AT = 0x01, 0x04, 0x08, 0x10, 0x40


def new_key(alg):
    if alg == -7:
        return ec.generate_private_key(ec.SECP256R1())
    if alg == -35:
        return ec.generate_private_key(ec.SECP384R1())
    if alg == -8:
        return ed25519.Ed25519PrivateKey.generate()
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign(key, alg, data):
    if alg == -7:
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    if alg == -35:
        return key.sign(data, ec.ECDSA(hashes.SHA384()))
    if alg == -8:
        return key.sign(data)
    if alg == -257:
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if alg == -37:
        return key.sign(data, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256())
    raise ValueError(alg)


def cose_key(key, alg):
    k = dict(CoseKey.for_alg(alg).from_cryptography_key(key.public_key()))
    k[3] = alg
    return CoseKey.parse(k)


class CA:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Interop Attestation CA")])
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
                     .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                     .not_valid_after(now + datetime.timedelta(days=30))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                     .sign(self.key, hashes.SHA256()))
        self.att_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "AA"),
                             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Interop"),
                             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
                             x509.NameAttribute(NameOID.COMMON_NAME, "Interop Authenticator")])
        self.att_cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(name)
                         .public_key(self.att_key.public_key()).serial_number(x509.random_serial_number())
                         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                         .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
                                                                   b"\x04\x10" + AAGUID), critical=False)
                         .sign(self.key, hashes.SHA256()))

    def pem(self):
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def att_der(self):
        return self.att_cert.public_bytes(serialization.Encoding.DER)


class Credential:
    def __init__(self, alg, fmt, ca, rk=True):
        self.alg, self.fmt, self.ca = alg, fmt, ca
        self.key = new_key(-7 if fmt == "fido-u2f" else alg)
        if fmt == "fido-u2f":
            self.alg = -7
        self.id = os.urandom(32)
        self.counter = 0
        self.user = os.urandom(16)
        self.rk = rk

    def register(self, challenge, origin=ORIGIN, rp_id=RP_ID, uv=True, flags_extra=0):
        cd = CollectedClientData.create(CollectedClientData.TYPE.CREATE, challenge, origin)
        aaguid = bytes(16) if self.fmt == "fido-u2f" else AAGUID
        ck = cose_key(self.key, self.alg)
        acd = AttestedCredentialData.create(aaguid, self.id, ck)
        flags = FLAGS_UP | FLAGS_AT | (FLAGS_UV if uv and self.fmt != "fido-u2f" else 0) | flags_extra
        ad = AuthenticatorData.create(hashlib.sha256(rp_id.encode()).digest(), flags, 0, acd)
        cdh = hashlib.sha256(bytes(cd)).digest()
        if self.fmt == "none":
            stmt = {}
        elif self.fmt == "packed-self":
            stmt = {"alg": self.alg, "sig": sign(self.key, self.alg, bytes(ad) + cdh)}
        elif self.fmt == "packed":
            stmt = {"alg": -7, "sig": sign(self.ca.att_key, -7, bytes(ad) + cdh), "x5c": [self.ca.att_der()]}
        else:
            pub = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            data = b"\x00" + hashlib.sha256(rp_id.encode()).digest() + cdh + self.id + pub
            stmt = {"sig": sign(self.ca.att_key, -7, data), "x5c": [self.ca.att_der()]}
        fmt = "packed" if self.fmt.startswith("packed") else self.fmt
        ao = AttestationObject.create(fmt, ad, stmt)
        self.cose = cbor.encode(dict(ck))
        return {"id": b64u(self.id), "rawId": b64u(self.id), "type": "public-key",
                "response": {"clientDataJSON": b64u(bytes(cd)), "attestationObject": b64u(bytes(ao)), "transports": ["usb"]},
                "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {"credProps": {"rk": self.rk}}}

    def assert_(self, challenge, origin=ORIGIN, rp_id=RP_ID, uv=True, user_handle=True):
        self.counter += 1
        cd = CollectedClientData.create(CollectedClientData.TYPE.GET, challenge, origin)
        flags = FLAGS_UP | (FLAGS_UV if uv else 0)
        ad = AuthenticatorData.create(hashlib.sha256(rp_id.encode()).digest(), flags, self.counter)
        sig = sign(self.key, self.alg, bytes(ad) + hashlib.sha256(bytes(cd)).digest())
        r = {"clientDataJSON": b64u(bytes(cd)), "authenticatorData": b64u(bytes(ad)), "signature": b64u(sig)}
        if user_handle:
            r["userHandle"] = b64u(self.user)
        return {"id": b64u(self.id), "rawId": b64u(self.id), "type": "public-key", "response": r,
                "authenticatorAttachment": "cross-platform", "clientExtensionResults": {}}


# --- The verifiers ------------------------------------------------------------------------

class Goose:
    def __init__(self, exe, work, ca):
        self.exe, self.work = exe, work
        self.roots = os.path.join(work, "ca.pem")
        with open(self.roots, "wb") as f:
            f.write(ca.pem())
        self.n = 0

    def run(self, args, body):
        self.n += 1
        path = os.path.join(self.work, f"response-{self.n}.json")
        with open(path, "w") as f:
            json.dump(body, f)
        p = subprocess.run([self.exe, *args, path], capture_output=True, text=True)
        return p.returncode == 0, p.stdout + p.stderr

    def register(self, cred, challenge, body, trusted, uv=False):
        rec = os.path.join(self.work, f"record-{cred.id.hex()[:16]}.bin")
        args = ["verify-registration", "--rp-id", RP_ID, "--origin", ORIGIN, "--challenge", b64u(challenge),
                "--record-out", rec]
        if trusted:
            args += ["--roots", self.roots, "--require-trusted"]
        if uv:
            args += ["--uv", "required"]
        cred.record = rec
        return self.run(args, body)

    def authenticate(self, cred, challenge, body, uv=False):
        args = ["verify-authentication", "--rp-id", RP_ID, "--origin", ORIGIN, "--challenge", b64u(challenge),
                "--record", cred.record, "--record-out", cred.record, "--user-handle", b64u(cred.user)]
        if uv:
            args += ["--uv", "required"]
        return self.run(args, body)


def py_register(cred, challenge, body, ca, uv=False):
    import webauthn as pw
    from webauthn.helpers.structs import AttestationFormat
    roots = {AttestationFormat.PACKED: [ca.pem()], AttestationFormat.FIDO_U2F: [ca.pem()]}
    try:
        from webauthn.helpers.cose import COSEAlgorithmIdentifier as A
        r = pw.verify_registration_response(credential=json.dumps(body), expected_challenge=challenge,
                                            expected_origin=ORIGIN, expected_rp_id=RP_ID,
                                            require_user_verification=uv, pem_root_certs_bytes_by_fmt=roots,
                                            supported_pub_key_algs=[A(-7), A(-8), A(-257), A(-37), A(-36)])
        return True, str(r.fmt)
    except Exception as ex:
        return False, f"{type(ex).__name__}: {ex}"


def py_authenticate(cred, challenge, body, uv=False):
    import webauthn as pw
    try:
        r = pw.verify_authentication_response(credential=json.dumps(body), expected_challenge=challenge,
                                              expected_origin=ORIGIN, expected_rp_id=RP_ID,
                                              credential_public_key=cred.cose, credential_current_sign_count=cred.counter - 1,
                                              require_user_verification=uv)
        return True, str(r.new_sign_count)
    except Exception as ex:
        return False, f"{type(ex).__name__}: {ex}"


def fido_server():
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity
    return Fido2Server(PublicKeyCredentialRpEntity(name="Interop", id=RP_ID))


def fido_register(cred, challenge, body, uv=False):
    try:
        state = {"challenge": b64u(challenge), "user_verification": "required" if uv else "preferred"}
        ad = fido_server().register_complete(state, body)
        cred.fido_acd = ad.credential_data
        return True, ""
    except Exception as ex:
        return False, f"{type(ex).__name__}: {ex}"


def fido_authenticate(cred, challenge, body, uv=False):
    try:
        state = {"challenge": b64u(challenge), "user_verification": "required" if uv else "preferred"}
        fido_server().authenticate_complete(state, [cred.fido_acd], body)
        return True, ""
    except Exception as ex:
        return False, f"{type(ex).__name__}: {ex}"


class Go:
    def __init__(self, exe, work):
        self.exe, self.work, self.n = exe, work, 0

    def file(self, obj):
        self.n += 1
        path = os.path.join(self.work, f"go-{self.n}.json")
        with open(path, "w") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))
        return path

    def run(self, *args):
        p = subprocess.run([self.exe, *args], capture_output=True, text=True)
        return p.returncode == 0, p.stdout.strip() if p.returncode == 0 else p.stderr.strip()

    def session(self, challenge, user, uv):
        # credParams: the algorithms the options asked for, which
        # CreateCredential holds the key to.
        return self.file({"challenge": b64u(challenge), "rpId": RP_ID, "user_id": base64.b64encode(user).decode(),
                          "expires": "0001-01-01T00:00:00Z", "userVerification": "required" if uv else "preferred",
                          "credParams": [{"type": "public-key", "alg": a} for a in (-7, -35, -36, -8, -257, -37)]})

    def register(self, cred, challenge, body, uv=False):
        ok, out = self.run("finish-registration", RP_ID, ORIGIN, self.session(challenge, cred.user, uv), self.file(body))
        if ok:
            cred.go_cred = out
        return ok, out

    def authenticate(self, cred, challenge, body, uv=False):
        s = self.session(challenge, cred.user, uv)
        ok, out = self.run("finish-login", RP_ID, ORIGIN, s, self.file(cred.go_cred), b64u(cred.user), self.file(body))
        if ok:
            cred.go_cred = out
        return ok, out


# --- The checks ---------------------------------------------------------------------------

def tamper(body, what):
    b = json.loads(json.dumps(body))
    r = b["response"]
    if what == "signature":
        sig = bytearray(unb64u(r["signature"]))
        sig[-3] ^= 1
        r["signature"] = b64u(bytes(sig))
    elif what == "id":
        other = b64u(os.urandom(32))
        b["id"] = b["rawId"] = other
    return b


def serve_check(exe, work, ca):
    import socket
    import time
    import urllib.request
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    log = open(os.path.join(work, "serve.log"), "w")
    proc = subprocess.Popen([exe, "serve", "--port", str(port)], stdout=log, stderr=log)
    origin = f"http://localhost:{port}"

    def post(path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read())

    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1).read()
                break
            except OSError:
                time.sleep(0.1)
        users = {}
        for name, alg in (("alice", -7), ("bob", -8)):
            cred = Credential(alg, "packed-self", ca)
            o = post("/register/begin", {"username": name})
            cred.user = unb64u(o["user"]["id"])
            r = post("/register/finish", cred.register(unb64u(o["challenge"]), origin=origin, rp_id="localhost"))
            check(f"serve: {name} registers", r.get("ok") is True, json.dumps(r))
            users[name] = cred
        o = post("/login/begin", {"username": "alice"})
        check("serve: alice's sign-in options allow her credential",
              [c["id"] for c in o["allowCredentials"]] == [b64u(users["alice"].id)], json.dumps(o))
        r = post("/login/finish", users["alice"].assert_(unb64u(o["challenge"]), origin=origin, rp_id="localhost"))
        check("serve: alice signs in by name", r.get("ok") is True and "signed in as alice" in r["message"], json.dumps(r))
        o = post("/login/begin", {"username": ""})
        r = post("/login/finish", users["bob"].assert_(unb64u(o["challenge"]), origin=origin, rp_id="localhost"))
        check("serve: bob signs in with a passkey", r.get("ok") is True and "signed in as bob" in r["message"], json.dumps(r))
        o = post("/login/begin", {"username": ""})
        r = post("/login/finish", users["bob"].assert_(unb64u(o["challenge"]), origin=origin, rp_id="localhost",
                                                       user_handle=False))
        check("serve: a passkey sign-in without a user handle is refused", r.get("ok") is False, json.dumps(r))
        o = post("/login/begin", {"username": "alice"})
        r = post("/login/finish", users["bob"].assert_(unb64u(o["challenge"]), origin=origin, rp_id="localhost"))
        check("serve: bob's credential for alice's sign-in is refused", r.get("ok") is False, json.dumps(r))
        o = post("/login/begin", {"username": "alice"})
        r = post("/login/finish", users["alice"].assert_(unb64u(o["challenge"]), origin="https://evil.example", rp_id="localhost"))
        check("serve: another origin is refused", r.get("ok") is False, json.dumps(r))
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work")
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    work = args.work or tempfile.mkdtemp(prefix="webauthn-interop-")
    os.makedirs(work, exist_ok=True)
    print(f"work directory {work}")

    exe = os.path.join(work, "goose-webauthn")
    p = subprocess.run([goose, "build", "-o", exe, os.path.join(ROOT, "tools", "webauthn.goose")], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("cannot build goose-webauthn:\n" + p.stderr[-3000:])

    have_py = have_fido = True
    try:
        import webauthn  # noqa: F401
    except ImportError:
        have_py = False
        skip("py_webauthn", "not installed in this Python")
    try:
        import fido2.server  # noqa: F401
    except ImportError:
        have_fido = False
        skip("python-fido2's Fido2Server", "not installed in this Python")
    go = None
    if shutil.which("go"):
        gopath = os.environ.get("WEBAUTHN_GOPATH") or os.path.join(work, "gopath")
        env = dict(os.environ, GOPATH=gopath, GOFLAGS="-modcacherw")
        gexe = os.path.join(work, "gowebauthn")
        p = subprocess.run(["go", "build", "-o", gexe, "."], cwd=os.path.join(ROOT, "scripts", "gowebauthn"),
                           env=env, capture_output=True, text=True)
        if p.returncode == 0:
            go = Go(gexe, work)
        else:
            skip("go-webauthn", "the build failed: " + p.stderr[-500:])
    else:
        skip("go-webauthn", "no Go")

    ca = CA()
    g = Goose(exe, work, ca)

    # 1. The software authenticator's registrations and assertions, by everyone.
    combos = [(-7, "none"), (-7, "packed-self"), (-7, "packed"), (-7, "fido-u2f"), (-35, "packed-self"),
              (-8, "packed-self"), (-8, "packed"), (-257, "packed-self"), (-257, "none"), (-37, "packed-self")]
    for alg, fmt in combos:
        name = f"alg {alg} {fmt}"
        cred = Credential(alg, fmt, ca)
        ch = os.urandom(32)
        body = cred.register(ch)
        trusted = fmt in ("packed", "fido-u2f")
        ok, out = g.register(cred, ch, body, trusted)
        check(f"{name}: goose-webauthn registers it" + (" (trusted)" if trusted else ""), ok, out)
        py = have_py and alg != -35       # py_webauthn does not do ES384
        if have_py and not py:
            skip(f"{name}: py_webauthn", "it has no ES384")
        if py:
            ok, out = py_register(cred, ch, body, ca)
            check(f"{name}: py_webauthn registers it", ok, out)
        if have_fido:
            ok, out = fido_register(cred, ch, body)
            check(f"{name}: Fido2Server registers it", ok, out)
        if go:
            ok, out = go.register(cred, ch, body)
            check(f"{name}: go-webauthn registers it", ok, out)
        for round in range(2):
            ch = os.urandom(32)
            body = cred.assert_(ch)
            ok, out = g.authenticate(cred, ch, body)
            check(f"{name}: goose-webauthn signs in #{round + 1}", ok and "counter_regressed false" in out, out)
            if py:
                ok, out = py_authenticate(cred, ch, body)
                check(f"{name}: py_webauthn signs in #{round + 1}", ok, out)
            if have_fido and hasattr(cred, "fido_acd"):
                ok, out = fido_authenticate(cred, ch, body)
                check(f"{name}: Fido2Server signs in #{round + 1}", ok, out)
            if go and hasattr(cred, "go_cred"):
                ok, out = go.authenticate(cred, ch, body)
                check(f"{name}: go-webauthn signs in #{round + 1}", ok, out)

        # Changed responses: refused by every one of them.
        ch = os.urandom(32)
        good = cred.assert_(ch)
        cases = [("another challenge", os.urandom(32), good), ("signature changed", ch, tamper(good, "signature")),
                 ("another origin", ch, cred.assert_(ch, origin="https://evil.example")),
                 ("another RP ID", ch, cred.assert_(ch, rp_id="evil.example")),
                 ("another credential ID", ch, tamper(good, "id"))]
        for what, chal, b in cases:
            ok, out = g.authenticate(cred, chal, b)
            check(f"{name}: goose-webauthn refuses {what}", not ok, out)
            if py:
                ok, out = py_authenticate(cred, chal, b)
                check(f"{name}: py_webauthn refuses {what}", not ok, out)
            if have_fido and hasattr(cred, "fido_acd") and what != "another credential ID":
                ok, out = fido_authenticate(cred, chal, b)
                check(f"{name}: Fido2Server refuses {what}", not ok, out)
            if go and hasattr(cred, "go_cred"):
                ok, out = go.authenticate(cred, chal, b)
                check(f"{name}: go-webauthn refuses {what}", not ok, out)
        # UV required, the assertion without it.
        ch = os.urandom(32)
        b = cred.assert_(ch, uv=False)
        ok, out = g.authenticate(cred, ch, b, uv=True)
        check(f"{name}: goose-webauthn refuses no UV when required", not ok, out)
        if py:
            ok, out = py_authenticate(cred, ch, b, uv=True)
            check(f"{name}: py_webauthn refuses no UV when required", not ok, out)

    # A registration for another RP ID, and one whose challenge is not ours.
    cred = Credential(-7, "packed-self", ca)
    ch = os.urandom(32)
    body = cred.register(ch, rp_id="evil.example")
    ok, out = g.register(cred, ch, body, False)
    check("goose-webauthn refuses a registration for another RP ID", not ok, out)
    if have_py:
        ok, out = py_register(cred, ch, body, ca)
        check("py_webauthn refuses a registration for another RP ID", not ok, out)
    if go:
        ok, out = go.register(cred, ch, body)
        check("go-webauthn refuses a registration for another RP ID", not ok, out)
    body = cred.register(ch)
    ok, out = g.register(cred, os.urandom(32), body, False)
    check("goose-webauthn refuses a registration for another challenge", not ok, out)

    # 2. Their options, answered by the authenticator, checked by them and by us.
    if have_fido:
        from fido2.webauthn import PublicKeyCredentialUserEntity
        server = fido_server()
        cred = Credential(-7, "packed-self", ca)
        opts, state = server.register_begin(PublicKeyCredentialUserEntity(id=cred.user, name="alice", display_name="Alice"))
        ch = bytes(opts.public_key.challenge)
        body = cred.register(ch)
        try:
            ad = server.register_complete(state, body)
            ok, out = True, ""
        except Exception as ex:
            ok, out = False, str(ex)
        check("Fido2Server's registration options answered: it registers", ok, out)
        ok, out = g.register(cred, ch, body, False)
        check("Fido2Server's registration options answered: goose-webauthn registers", ok, out)
        if ok:
            aopts, astate = server.authenticate_begin([ad.credential_data])
            ch = bytes(aopts.public_key.challenge)
            b = cred.assert_(ch)
            try:
                server.authenticate_complete(astate, [ad.credential_data], b)
                ok, out = True, ""
            except Exception as ex:
                ok, out = False, str(ex)
            check("Fido2Server's authentication options answered: it signs in", ok, out)
            ok, out = g.authenticate(cred, ch, b)
            check("Fido2Server's authentication options answered: goose-webauthn signs in", ok, out)
    if have_py:
        import webauthn as pw
        cred = Credential(-8, "none", ca)
        o = pw.generate_registration_options(rp_id=RP_ID, rp_name="Interop", user_name="alice", user_id=cred.user)
        j = json.loads(pw.options_to_json(o))
        ch = unb64u(j["challenge"])
        body = cred.register(ch)
        ok, out = py_register(cred, ch, body, ca)
        check("py_webauthn's registration options answered: it registers", ok, out)
        ok, out = g.register(cred, ch, body, False)
        check("py_webauthn's registration options answered: goose-webauthn registers", ok, out)
    if go:
        cred = Credential(-7, "packed-self", ca)
        ok, out = go.run("begin-registration", RP_ID, ORIGIN, b64u(cred.user))
        check("go-webauthn begins a registration", ok, out)
        if ok:
            r = json.loads(out)
            ch = unb64u(r["options"]["challenge"])
            body = cred.register(ch)
            ok2, out2 = go.run("finish-registration", RP_ID, ORIGIN, go.file(r["session"]), go.file(body))
            check("go-webauthn's registration options answered: it registers", ok2, out2)
            ok3, out3 = g.register(cred, ch, body, False)
            check("go-webauthn's registration options answered: goose-webauthn registers", ok3, out3)
            if ok2:
                cred.go_cred = out2
                ok, out = go.run("begin-login", RP_ID, ORIGIN, go.file(cred.go_cred), b64u(cred.user))
                check("go-webauthn begins a login", ok, out)
                if ok:
                    r = json.loads(out)
                    ch = unb64u(r["options"]["challenge"])
                    b = cred.assert_(ch)
                    ok4, out4 = go.run("finish-login", RP_ID, ORIGIN, go.file(r["session"]), go.file(cred.go_cred),
                                       b64u(cred.user), go.file(b))
                    check("go-webauthn's login options answered: it signs in", ok4, out4)
                    ok5, out5 = g.authenticate(cred, ch, b)
                    check("go-webauthn's login options answered: goose-webauthn signs in", ok5, out5)

    # 3. goose-webauthn's options, read by them.
    user = os.urandom(16)
    ch = os.urandom(32)
    excl = os.urandom(20)
    p = subprocess.run([exe, "registration-options", "--rp-id", RP_ID, "--rp-name", "Interop", "--user-name", "alice",
                        "--user-id", b64u(user), "--challenge", b64u(ch), "--alg", "-7", "--alg", "-8", "--alg", "-257",
                        "--resident-key", "required", "--uv", "required", "--attestation", "direct",
                        "--exclude", b64u(excl)], capture_output=True, text=True)
    check("goose-webauthn makes registration options", p.returncode == 0, p.stderr)
    reg_json = p.stdout.strip()
    p = subprocess.run([exe, "authentication-options", "--rp-id", RP_ID, "--challenge", b64u(ch), "--allow", b64u(excl),
                        "--uv", "required"], capture_output=True, text=True)
    check("goose-webauthn makes authentication options", p.returncode == 0, p.stderr)
    auth_json = p.stdout.strip()
    if have_py:
        import webauthn as pw
        try:
            o = pw.helpers.parse_registration_options_json(reg_json)
            ok = (o.rp.id == RP_ID and o.user.id == user and o.challenge == ch
                  and [int(x.alg) for x in o.pub_key_cred_params] == [-7, -8, -257]
                  and o.exclude_credentials[0].id == excl and o.authenticator_selection.resident_key.value == "required"
                  and o.authenticator_selection.user_verification.value == "required" and o.attestation.value == "direct")
            check("py_webauthn reads goose-webauthn's registration options", ok, repr(o))
        except Exception as ex:
            check("py_webauthn reads goose-webauthn's registration options", False, str(ex))
        try:
            o = pw.helpers.parse_authentication_options_json(auth_json)
            ok = o.rp_id == RP_ID and o.challenge == ch and o.allow_credentials[0].id == excl
            check("py_webauthn reads goose-webauthn's authentication options", ok, repr(o))
        except Exception as ex:
            check("py_webauthn reads goose-webauthn's authentication options", False, str(ex))
    if have_fido:
        from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions
        try:
            o = PublicKeyCredentialCreationOptions.from_dict(json.loads(reg_json))
            ok = (o.rp.id == RP_ID and bytes(o.user.id) == user and bytes(o.challenge) == ch
                  and [p.alg for p in o.pub_key_cred_params] == [-7, -8, -257]
                  and bytes(o.exclude_credentials[0].id) == excl and o.attestation == "direct")
            check("python-fido2 reads goose-webauthn's registration options", ok, repr(o))
        except Exception as ex:
            check("python-fido2 reads goose-webauthn's registration options", False, str(ex))
        try:
            o = PublicKeyCredentialRequestOptions.from_dict(json.loads(auth_json))
            ok = o.rp_id == RP_ID and bytes(o.challenge) == ch and bytes(o.allow_credentials[0].id) == excl
            check("python-fido2 reads goose-webauthn's authentication options", ok, repr(o))
        except Exception as ex:
            check("python-fido2 reads goose-webauthn's authentication options", False, str(ex))
    if go:
        ok, out = go.run("parse-creation-options", go.file(reg_json))
        if ok:
            r = json.loads(out)
            ok = (r["rp"] == RP_ID and r["user"] == b64u(user) and r["challenge"] == b64u(ch) and r["algs"] == [-7, -8, -257]
                  and r["exclude"] == 1 and r["residentKey"] == "required" and r["uv"] == "required" and r["attestation"] == "direct")
        check("go-webauthn reads goose-webauthn's registration options", ok, out)
        ok, out = go.run("parse-request-options", go.file(auth_json))
        if ok:
            r = json.loads(out)
            ok = r["rp"] == RP_ID and r["challenge"] == b64u(ch) and r["allow"] == 1 and r["uv"] == "required"
        check("go-webauthn reads goose-webauthn's authentication options", ok, out)

    # 4. goose-webauthn serve, the demo RP, driven over HTTP by the
    # authenticator as a browser would: register two users, sign in by
    # name and as passkeys, and a sign-in by the wrong user refused.
    serve_check(exe, work, ca)

    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
