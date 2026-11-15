#!/usr/bin/env python3
"""Make webauthn/test/data's vectors from published ones:

- the WebAuthn Level 3 specification's test vectors (§16, "Test Vectors"):
  every registration and authentication of §16.2 to §16.16 (none, self,
  crossOrigin, topOrigin, a long credential ID, packed ES256/ES384/ES512/
  RS256/Ed25519/Ed448, TPM, Android Key, Apple, FIDO U2F) and the
  attestation root certificate of §16.1 (spec_ca.pem);
- py_webauthn's (Duo's) test vectors: registrations by real authenticators
  (packed, fido-u2f, tpm, android-key, apple, none) and authentications
  (EC2, RSA, OKP), with the outcome py_webauthn's tests expect, and the
  Apple and Google roots it ships (apple_root.pem, google_roots.pem).

Only public values are kept: the spec's credential and attestation
private keys are not copied. Each vector is a block of "key value" lines
(see webauthn/test/tv.goose).

    python3 -I webauthn/scripts/make_vectors.py --spec webauthn-3.html --py-webauthn DIR

The spec is https://www.w3.org/TR/webauthn-3/ saved as HTML; DIR is a
checkout of https://github.com/duo-labs/py_webauthn (its tests import
webauthn, cbor2, cryptography and pyOpenSSL: run with a Python that has
them, as the interop's venv does).
"""

import argparse
import base64
import calendar
import datetime
import hashlib
import html
import importlib
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "test", "data")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def cred_id_of(att_obj):
    import cbor2
    a = cbor2.loads(att_obj)
    ad = a["authData"]
    n = int.from_bytes(ad[53:55], "big")
    return ad[55:55 + n], a


def cose_key_of(att_obj):
    import cbor2
    a = cbor2.loads(att_obj)
    ad = a["authData"]
    n = int.from_bytes(ad[53:55], "big")
    rest = ad[55 + n:]
    dec = cbor2.CBORDecoder(__import__("io").BytesIO(rest))
    dec.decode()
    return rest[:dec.fp.tell()]


def spec_vectors(path):
    text = html.unescape(re.sub(r"<[^>]+>", "", open(path, encoding="utf-8").read()))
    start = text.index("16.1. Attestation trust root certificate")
    end = text.index("16.17. Test Vectors for WebAuthn Extensions")
    text = text[start:end]
    ca = re.search(r"attestation_ca_cert = h'([0-9a-f]+)'", text).group(1)
    sections = re.split(r"\n\s*(16\.\d+)\. ", text)
    out = []
    for i in range(1, len(sections), 2):
        num, body = sections[i], sections[i + 1]
        if num == "16.1":
            continue
        title = body.splitlines()[0].strip()
        reg, _, auth = body.partition("Authentication:")

        def field(part, name):
            m = re.search(r"^" + name + r" = h'([0-9a-f]*)'", part, re.M)
            return bytes.fromhex(m.group(1)) if m else None

        name = "spec " + num + " " + title
        cdj = field(reg, "clientDataJSON")
        ao = field(reg, "attestationObject")
        cid, a = cred_id_of(ao)
        top = "https://example.com" if b'"topOrigin"' in cdj else None
        cross = b'"crossOrigin":true' in cdj
        resp = {"id": b64u(cid), "rawId": b64u(cid), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(ao)},
                "clientExtensionResults": {}}
        v = {"name": name, "kind": "registration", "expect": "ok", "rp_id": "example.org",
             "origin": ["https://example.org"], "challenge": field(reg, "challenge").hex(),
             "response": json.dumps(resp, separators=(",", ":")), "fmt": a["fmt"],
             "cred_id": cid.hex(), "roots": "spec_ca.pem", "now": 1767225600,
             "cross_origin": int(cross)}
        if top:
            v["top_origin"] = top
        out.append(v)
        adata = field(auth, "authenticatorData")
        resp = {"id": b64u(cid), "rawId": b64u(cid), "type": "public-key",
                "response": {"clientDataJSON": b64u(field(auth, "clientDataJSON")),
                             "authenticatorData": b64u(adata), "signature": b64u(field(auth, "signature"))},
                "clientExtensionResults": {}}
        cdj2 = field(auth, "clientDataJSON")
        w = {"name": name + " (authentication)", "kind": "authentication", "expect": "ok", "rp_id": "example.org",
             "origin": ["https://example.org"], "challenge": field(auth, "challenge").hex(),
             "response": json.dumps(resp, separators=(",", ":")), "public_key": cose_key_of(ao).hex(),
             "cred_id": cid.hex(), "sign_count": 0, "backup_eligible": int(a["authData"][32] & 0x08 != 0),
             "cross_origin": int(b'"crossOrigin":true' in cdj2)}
        if b'"topOrigin"' in cdj2:
            w["top_origin"] = "https://example.com"
        out.append(w)
    return out, bytes.fromhex(ca)


# The dates py_webauthn's tests set their certificate stores to.
PY_TIMES = {"test_verify_attestation_apple_passkey": (2021, 9, 1),
            "test_verify_attestation_android_key_hardware_authority": (2025, 1, 8),
            "test_verify_attestation_android_key_root_5": (2026, 4, 26)}
# Registrations whose roots are py_webauthn's own.
PY_ROOTS = {"apple": "apple_root.pem", "android-key": "google_roots.pem"}
# The tests whose calls are real (no mocks of the response or its parsing).
PY_SKIP = {"test_verifies_response_optional_user_presence", "test_raises_exception_on_invalid_attestation_type",
           "test_raises_when_root_cert_invalid_for_response", "test_supports_already_parsed_credential",
           "test_supports_dict_credential", "test_raises_useful_error_on_bad_attestation_object",
           "test_raises_useful_error_on_bad_client_data_json", "test_raises_on_bad_attestationObject",
           "test_raises_on_bad_client_data_json", "test_verify_attestation_android_safetynet",
           "test_verify_attestation_android_safetynet_basic_integrity_true_cts_profile_match_false",
           "test_raise_attestation_android_safetynet_basic_integrity_false_cts_profile_match_false"}


def py_vectors(src):
    sys.path.insert(0, src)
    import webauthn
    import webauthn.helpers.known_root_certs as roots
    calls = []
    real_reg = webauthn.verify_registration_response
    real_auth = webauthn.verify_authentication_response

    def recorder(kind, real):
        def f(**kw):
            rec = {"kind": kind, "kw": kw}
            calls.append(rec)
            try:
                r = real(**kw)
                rec["result"] = r
                return r
            except Exception as ex:
                rec["error"] = ex
                raise
        return f

    out = []
    names = ["test_verify_registration_response", "test_verify_registration_response_packed",
             "test_verify_registration_response_fido_u2f", "test_verify_registration_response_tpm",
             "test_verify_registration_response_android_key", "test_verify_registration_response_apple",
             "test_verify_authentication_response"]
    for mod_name in names:
        mod = importlib.import_module("tests." + mod_name)
        if hasattr(mod, "verify_registration_response"):
            mod.verify_registration_response = recorder("registration", real_reg)
        if hasattr(mod, "verify_authentication_response"):
            mod.verify_authentication_response = recorder("authentication", real_auth)
        for cls in [c for c in vars(mod).values() if isinstance(c, type) and issubclass(c, unittest.TestCase)]:
            for t in sorted(n for n in dir(cls) if n.startswith("test")):
                if t in PY_SKIP:
                    continue
                calls.clear()
                res = unittest.TestResult()
                cls(t).run(res)
                if res.errors or res.failures:
                    print(f"skip {mod_name}.{t}: the test itself fails here", file=sys.stderr)
                    continue
                for k, c in enumerate(calls):
                    short = mod_name.replace("test_verify_", "").replace("_response", "")
                    out.append(py_vector(f"py_webauthn {short} {t}" + (f" #{k + 1}" if len(calls) > 1 else ""), t, c))
    def text(v):
        return (v.decode() if isinstance(v, bytes) else v).strip() + "\n"

    pem = {"apple_root.pem": text(roots.apple_webauthn_root_ca),
           "google_roots.pem": "".join(text(getattr(roots, n)) for n in sorted(dir(roots))
                                       if n.startswith("google_hardware_attestation_root"))}
    return [v for v in out if v], pem


def py_vector(name, test, c):
    kw = c["kw"]
    cred = kw["credential"]
    if not isinstance(cred, str):
        return None
    cred = json.dumps(json.loads(cred), separators=(",", ":"))
    origins = kw["expected_origin"]
    v = {"name": name, "kind": c["kind"], "expect": "ok" if "result" in c else "fail",
         "rp_id": kw["expected_rp_id"], "origin": origins if isinstance(origins, list) else [origins],
         "challenge": kw["expected_challenge"].hex(), "response": cred,
         "require_uv": int(bool(kw.get("require_user_verification", False)))}
    if "error" in c:
        v["why"] = str(c["error"]).replace("\n", " ")[:200]
    if c["kind"] == "registration":
        r = c.get("result")
        if r is not None:
            v["fmt"] = getattr(r.fmt, "value", r.fmt)
            v["cred_id"] = r.credential_id.hex()
            v["aaguid"] = r.aaguid.replace("-", "")
            v["sign_count"] = r.sign_count
            if v["fmt"] in PY_ROOTS:
                v["roots"] = PY_ROOTS[v["fmt"]]
        y, m, d = PY_TIMES.get(test, (2021, 1, 1))
        v["now"] = calendar.timegm(datetime.datetime(y, m, d).timetuple())
    else:
        v["public_key"] = bytes(kw["credential_public_key"]).hex()
        v["sign_count"] = kw["credential_current_sign_count"]
        r = c.get("result")
        if r is not None:
            v["new_sign_count"] = r.new_sign_count
    return v


def write(vectors, path):
    with open(path, "w") as f:
        f.write("# Made by webauthn/scripts/make_vectors.py: the WebAuthn L3 spec's test vectors (§16) and\n"
                "# py_webauthn's. Each block: [name], then \"key value\" lines.\n")
        for v in vectors:
            f.write(f"\n[{v['name']}]\n")
            for k, val in v.items():
                if k == "name":
                    continue
                for x in (val if isinstance(val, list) else [val]):
                    f.write(f"{k} {x}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True, help="the WebAuthn L3 spec, as HTML")
    ap.add_argument("--py-webauthn", required=True, help="a checkout of duo-labs/py_webauthn")
    args = ap.parse_args()
    os.makedirs(DATA, exist_ok=True)
    spec, ca = spec_vectors(args.spec)
    with open(os.path.join(DATA, "spec_ca.pem"), "w") as f:
        f.write("-----BEGIN CERTIFICATE-----\n")
        b = base64.b64encode(ca).decode()
        f.write("\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n")
    write(spec, os.path.join(DATA, "spec_vectors.txt"))
    py, pem = py_vectors(os.path.abspath(args.py_webauthn))
    for n, text in pem.items():
        with open(os.path.join(DATA, n), "w") as f:
            f.write(text.strip() + "\n")
    write(py, os.path.join(DATA, "py_webauthn_vectors.txt"))
    print(f"{len(spec)} spec vectors, {len(py)} py_webauthn vectors")


if __name__ == "__main__":
    main()
