#!/usr/bin/env python3
"""goose-saml against other SAML implementations, all on 127.0.0.1.

    SAML_PYTHON=/path/to/venv/bin/python make interop-saml
    /path/to/venv/bin/python saml/scripts/interop.py [--goose PATH] [--work DIR] [-k NAME]

The Python that runs it needs requests, and for the python3-saml checks
python3-saml (OneLogin's toolkit, on python-xmlsec, whose wheel carries
libxmlsec1) and lxml; the crewjam/saml checks need Go, and build
saml/scripts/crewjam (go.mod pins crewjam/saml) into the work directory.
What is missing is skipped and said so. Nothing is installed system-wide.

- goose-saml's SP and IdP against each other over HTTP: every binding for
  AuthnRequests, signed and not, the assertion signed, the Response
  signed, both, encrypted; IdP-initiated logins; Single Logout started by
  either side over either binding.
- python3-saml as an SP against goose-saml's IdP: its AuthnRequests
  (signed and not) answered and its Response checks passed, encrypted
  assertions decrypted, logout both ways; and building and signing
  Responses (xmlsec: assertion, Response, both, encrypted) that
  goose-saml's SP takes or refuses (tampered, SHA-1); its signed
  LogoutRequests read by goose-saml's SP.
- crewjam/saml's SP (samlsp) against goose-saml's IdP and crewjam/saml's
  IdP (samlidp) against goose-saml's SP, logins by both bindings, signed
  requests, encrypted assertions, and logout both ways.
"""

import argparse
import base64
import html.parser
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SAML_DIR = os.path.normpath(os.path.join(HERE, ".."))
GSLIB = os.path.normpath(os.path.join(SAML_DIR, ".."))
DATA = os.path.join(SAML_DIR, "test", "data")

try:
    import requests
except ImportError:
    sys.exit("interop.py needs requests (run it with a venv's python: SAML_PYTHON)")

passed = 0
failed = []
skipped = []


def check(what, ok, detail=""):
    global passed
    if ok:
        passed += 1
        print("ok    " + what)
    else:
        failed.append(what)
        print("FAIL  " + what + (("\n      " + str(detail)[:2000].replace("\n", "\n      ")) if detail else ""))
    return ok


def skip(what, why):
    skipped.append(what)
    print(f"skip  {what}: {why}")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(GSLIB, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, proc, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def pem_body(name):
    return "".join(l for l in open(os.path.join(DATA, name)).read().splitlines() if not l.startswith("-----"))


# --- Servers ---------------------------------------------------------------------------

class Server:
    """A process serving on a port; its stdout lines (goose-saml's JSON) in a queue."""

    def __init__(self, name, cmd, port, work):
        self.name = name
        self.port = port
        self.lines = queue.Queue()
        self.log = open(os.path.join(work, f"{name}.log"), "w")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=self.log, text=True)
        threading.Thread(target=self._read, daemon=True).start()
        if not wait_port(port, self.proc):
            self.stop()
            raise RuntimeError(f"{name} did not start: see {self.log.name}")

    def _read(self):
        for line in self.proc.stdout:
            self.lines.put(line)

    def events(self, wait=2.0):
        """The JSON lines printed so far (waiting up to `wait` for the first)."""
        out = []
        try:
            out.append(json.loads(self.lines.get(timeout=wait)))
            while True:
                out.append(json.loads(self.lines.get_nowait()))
        except queue.Empty:
            pass
        return out

    def drain(self):
        while not self.lines.empty():
            self.lines.get_nowait()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()


class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get").lower(), "fields": {}})
        elif tag == "input" and self.forms and a.get("name"):
            self.forms[-1]["fields"][a["name"]] = a.get("value") or ""


def forms_of(text):
    p = Forms()
    p.feed(text)
    return p.forms


class Browser:
    """Follows redirects and submits the forms that carry SAML messages, as
    a browser with script does. `trace` lists the URLs visited."""

    def __init__(self):
        self.s = requests.Session()
        self.trace = []

    def go(self, method, url, data=None, hops=20):
        r = self.s.request(method, url, data=data, allow_redirects=False, timeout=30)
        self.trace.append(f"{method} {url.split('?')[0]} -> {r.status_code}")
        for _ in range(hops):
            if r.status_code in (301, 302, 303, 307):
                loc = urllib.parse.urljoin(r.url, r.headers["Location"])
                r = self.s.get(loc, allow_redirects=False, timeout=30)
                self.trace.append(f"GET {loc.split('?')[0]} -> {r.status_code}")
                continue
            fs = [f for f in forms_of(r.text) if "SAMLResponse" in f["fields"] or "SAMLRequest" in f["fields"]]
            if r.status_code == 200 and fs and "password" not in fs[0]["fields"]:
                f = fs[0]
                action = urllib.parse.urljoin(r.url, f["action"])
                r = self.s.post(action, data=f["fields"], allow_redirects=False, timeout=30)
                self.trace.append(f"POST {action.split('?')[0]} -> {r.status_code}")
                continue
            break
        return r


# --- goose-saml ------------------------------------------------------------------------

class Goose:
    def __init__(self, tool, work):
        self.tool = tool
        self.work = work

    def metadata(self, role, base, extra=()):
        key = "sp" if role == "sp" else "idp"
        out = subprocess.run([self.tool, "metadata", role, "--base", base, "--key", os.path.join(DATA, key + ".key"),
                              "--cert", os.path.join(DATA, key + ".crt"), *extra], capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(out.stderr)
        path = os.path.join(self.work, f"{role}-{base.rsplit(':', 1)[1]}.xml")
        open(path, "w").write(out.stdout)
        return path

    def sp(self, port, idp_metadata, extra=()):
        base = f"http://127.0.0.1:{port}"
        return Server(f"goose-sp-{port}", [self.tool, "sp", "--base", base, "--port", str(port), "--idp-metadata", idp_metadata,
                                            "--key", os.path.join(DATA, "sp.key"), "--cert", os.path.join(DATA, "sp.crt"), *extra],
                      port, self.work)

    def idp(self, port, sp_metadata, extra=()):
        base = f"http://127.0.0.1:{port}"
        cmd = [self.tool, "idp", "--base", base, "--port", str(port), "--key", os.path.join(DATA, "idp.key"),
               "--cert", os.path.join(DATA, "idp.crt"), "--user", "alice@example.test",
               "--attr", "mail=alice@example.test", "--attr", "groups=staff", "--attr", "groups=admins", *extra]
        for m in sp_metadata:
            cmd += ["--sp-metadata", m]
        return Server(f"goose-idp-{port}", cmd, port, self.work)


def login_event(server):
    evs = [e for e in server.events() if e.get("event") in ("login", "refused")]
    return evs[-1] if evs else {}


# --- goose-saml against itself --------------------------------------------------------------

def goose_pair(g):
    sp_port, idp_port = free_port(), free_port()
    sp_base, idp_base = f"http://127.0.0.1:{sp_port}", f"http://127.0.0.1:{idp_port}"
    idp_md = g.metadata("idp", idp_base)
    variants = [
        ("redirect, assertion signed", [], []),
        ("POST, signed requests, Response signed", ["--binding", "post", "--sign-requests"], ["--sign", "response", "--want-signed-requests"]),
        ("redirect, signed requests, both signed, encrypted", ["--sign-requests", "--require-encrypted", "--want-assertions-signed"],
         ["--sign", "both", "--encrypt", "--want-signed-requests"]),
    ]
    for name, sp_extra, idp_extra in variants:
        sp_md = g.metadata("sp", sp_base, [x for x in sp_extra if x == "--sign-requests"])
        sp = g.sp(sp_port, idp_md, sp_extra + ["--allow-idp-initiated"])
        idp = g.idp(idp_port, [sp_md], idp_extra)
        try:
            b = Browser()
            r = b.go("GET", f"{sp_base}/login?RelayState=/after")
            ev = login_event(sp)
            check(f"goose SP <-> goose IdP, {name}: login", r.status_code == 200 and ev.get("event") == "login", (r.status_code, r.text, b.trace))
            check(f"  the assertion", ev.get("name_id") == "alice@example.test" and ev.get("attributes", {}).get("groups") == ["staff", "admins"]
                  and ev.get("relay_state") == "/after", ev)
            enc = "--encrypt" in idp_extra
            check(f"  signed as asked, encrypted {enc}", ev.get("encrypted") == enc and ev.get("assertion_signed") == ("response" not in idp_extra)
                  and ev.get("response_signed") == ("response" in idp_extra or "both" in idp_extra), ev)
            idp.drain()
            r = b.go("GET", f"{sp_base}/logout")
            check(f"  SP-initiated logout", r.status_code == 200 and "logged out" in r.text, (r.status_code, r.text, b.trace))
            check(f"  the IdP read the LogoutRequest", any(e.get("event") == "logout-request" and e.get("result") == "ok" for e in idp.events()))
            sp.drain()
            for binding in ("redirect", "post"):
                r = b.go("GET", f"{idp_base}/logout?sp={urllib.parse.quote(sp_base + '/metadata')}&binding={binding}")
                check(f"  IdP-initiated logout by {binding}", r.status_code == 200 and "logged out" in r.text, (r.status_code, r.text, b.trace))
            r = b.go("GET", f"{idp_base}/init?sp={urllib.parse.quote(sp_base + '/metadata')}&RelayState=unsolicited")
            ev = login_event(sp)
            check(f"  IdP-initiated login", r.status_code == 200 and ev.get("event") == "login" and ev.get("in_response_to") == "", (r.text, ev))
        finally:
            sp.stop()
            idp.stop()


def goose_replay(g):
    """A Response posted twice to goose-saml's SP: the second is refused."""
    sp_port, idp_port = free_port(), free_port()
    sp_base, idp_base = f"http://127.0.0.1:{sp_port}", f"http://127.0.0.1:{idp_port}"
    idp_md = g.metadata("idp", idp_base)
    sp_md = g.metadata("sp", sp_base)
    sp = g.sp(sp_port, idp_md)
    idp = g.idp(idp_port, [sp_md])
    try:
        s = requests.Session()
        r = s.get(f"{sp_base}/login", allow_redirects=False)
        r = s.get(r.headers["Location"], allow_redirects=False)
        f = forms_of(r.text)[0]
        r1 = s.post(f["action"], data=f["fields"])
        r2 = s.post(f["action"], data=f["fields"])
        check("goose SP: a Response posted twice, the second refused", r1.status_code == 200 and r2.status_code == 403 and "seen before" in r2.text,
              (r1.status_code, r2.status_code, r2.text))
        f["fields"]["SAMLResponse"] = base64.b64encode(base64.b64decode(f["fields"]["SAMLResponse"]).replace(b"alice@", b"admin@")).decode()
        r3 = s.post(f["action"], data=f["fields"])
        check("goose SP: a Response with its NameID changed refused", r3.status_code == 403, (r3.status_code, r3.text))
    finally:
        sp.stop()
        idp.stop()


# --- python3-saml ----------------------------------------------------------------------------

def py_settings(sp_base, idp_base, idp_cert="idp.crt", sp_key="sp", security=None, sp_entity=None, idp_entity=None,
                idp_sso=None, idp_slo=None):
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    return OneLogin_Saml2_Settings({
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity or f"{sp_base}/metadata",
            "assertionConsumerService": {"url": f"{sp_base}/acs", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
            "singleLogoutService": {"url": f"{sp_base}/sls", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": pem_body(sp_key + ".crt"),
            "privateKey": open(os.path.join(DATA, sp_key + ".key")).read(),
        },
        "idp": {
            "entityId": idp_entity or f"{idp_base}/metadata",
            "singleSignOnService": {"url": idp_sso or f"{idp_base}/sso", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
            "singleLogoutService": {"url": idp_slo or f"{idp_base}/slo", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
            "x509cert": pem_body(idp_cert),
        },
        "security": dict({"signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                          "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                          "rejectDeprecatedAlgorithm": True}, **(security or {})),
    }, sp_validation_only=False)


def req_data(url, post=None):
    u = urllib.parse.urlparse(url)
    return {"https": "off", "http_host": u.hostname, "server_port": str(u.port), "script_name": u.path,
            "get_data": dict(urllib.parse.parse_qsl(u.query)) if not post else {},
            "post_data": post or {},
            # Keep the query as it came, for the Redirect binding's signature.
            "query_string": u.query}


def python3_saml_sp(g):
    """python3-saml's SP (no server: the script is its HTTP layer) against goose-saml's IdP."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    idp_port = free_port()
    idp_base = f"http://127.0.0.1:{idp_port}"
    sp_base = f"http://127.0.0.1:{free_port()}"
    variants = [
        ("unsigned requests, assertion signed", {}, []),
        ("signed requests, both signed", {"authnRequestsSigned": True, "logoutRequestSigned": True, "logoutResponseSigned": True,
                                           "wantMessagesSigned": True, "wantAssertionsSigned": True},
         ["--sign", "both", "--want-signed-requests"]),
        ("encrypted assertion, Response signed", {"wantAssertionsEncrypted": True, "wantMessagesSigned": True, "logoutRequestSigned": True,
                                                  "logoutResponseSigned": True},
         ["--sign", "response", "--encrypt"]),
    ]
    for name, security, idp_extra in variants:
        settings = py_settings(sp_base, idp_base, security=security)
        md_path = os.path.join(g.work, f"py-sp-{idp_port}.xml")
        open(md_path, "w").write(settings.get_sp_metadata().decode() if isinstance(settings.get_sp_metadata(), bytes) else settings.get_sp_metadata())
        idp = g.idp(idp_port, [md_path], idp_extra)
        try:
            auth = OneLogin_Saml2_Auth(req_data(f"{sp_base}/login"), old_settings=settings)
            url = auth.login(return_to="/after")
            request_id = auth.get_last_request_id()
            s = requests.Session()
            r = s.get(url, allow_redirects=False)
            fs = forms_of(r.text)
            ok = r.status_code == 200 and fs and "SAMLResponse" in fs[0]["fields"]
            if not check(f"python3-saml SP -> goose IdP, {name}: the IdP answers", ok, (r.status_code, r.text, idp.events(0.2))):
                continue
            f = fs[0]
            check("  to the SP's ACS", f["action"] == f"{sp_base}/acs", f["action"])
            auth2 = OneLogin_Saml2_Auth(req_data(f["action"], f["fields"]), old_settings=settings)
            auth2.process_response(request_id=request_id)
            errs = auth2.get_errors()
            check("  python3-saml takes the Response", not errs and auth2.is_authenticated(), (errs, auth2.get_last_error_reason()))
            check("  NameID and attributes", auth2.get_nameid() == "alice@example.test" and auth2.get_attribute("groups") == ["staff", "admins"],
                  (auth2.get_nameid(), auth2.get_attributes()))
            check("  RelayState", f["fields"].get("RelayState") == "/after", f["fields"].get("RelayState"))
            session_index = auth2.get_session_index()
            # SP-initiated logout (python3-saml speaks only the Redirect binding for SLO).
            auth3 = OneLogin_Saml2_Auth(req_data(f"{sp_base}/logout"), old_settings=settings)
            url = auth3.logout(name_id="alice@example.test", session_index=session_index,
                               name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
            logout_id = auth3.get_last_request_id()
            r = s.get(url, allow_redirects=False)
            ev = [e for e in idp.events() if e.get("event") == "logout-request"]
            if not security.get("logoutRequestSigned"):
                # saml-profiles §4.4.4.1: a front-channel LogoutRequest must be signed.
                check("  goose IdP refuses python3-saml's unsigned LogoutRequest", r.status_code == 403 and ev and ev[-1].get("result") == "not signed", (ev, r.text))
            else:
                check("  goose IdP reads python3-saml's signed LogoutRequest", ev and ev[-1].get("result") == "ok", (ev, r.text))
                loc = r.headers.get("Location", "")
                auth4 = OneLogin_Saml2_Auth(req_data(loc), old_settings=settings)
                auth4.process_slo(request_id=logout_id, keep_local_session=True)
                check("  python3-saml takes the LogoutResponse", r.status_code == 302 and not auth4.get_errors(),
                      (r.status_code, auth4.get_errors(), auth4.get_last_error_reason()))
            # IdP-initiated logout.
            r = s.get(f"{idp_base}/logout?sp={urllib.parse.quote(sp_base + '/metadata')}", allow_redirects=False)
            loc = r.headers.get("Location", "")
            auth5 = OneLogin_Saml2_Auth(req_data(loc), old_settings=settings)
            back = auth5.process_slo(keep_local_session=True)
            check("  python3-saml takes goose IdP's LogoutRequest", r.status_code == 302 and not auth5.get_errors() and back,
                  (r.status_code, auth5.get_errors(), auth5.get_last_error_reason()))
            if back:
                r = s.get(back, allow_redirects=False)
                if security.get("logoutResponseSigned"):
                    check("  goose IdP takes python3-saml's signed LogoutResponse", r.status_code == 200 and "logged out" in r.text, (r.status_code, r.text))
                else:
                    # saml-profiles §4.4.4.2: so must a LogoutResponse.
                    check("  goose IdP refuses python3-saml's unsigned LogoutResponse", r.status_code == 403 and "not signed" in r.text, (r.status_code, r.text))
        finally:
            idp.stop()


RESPONSE = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r{n}" Version="2.0" IssueInstant="{now}" Destination="{acs}" InResponseTo="{irt}"><saml:Issuer>{idp}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a{n}" Version="2.0" IssueInstant="{now}"><saml:Issuer>{idp}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{later}" Recipient="{acs}" InResponseTo="{irt}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{before}" NotOnOrAfter="{later}"><saml:AudienceRestriction><saml:Audience>{sp}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_s{n}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"""


def xmlsec_sign(el, alg="rsa-sha256"):
    import xmlsec
    C = xmlsec.constants
    xmlsec.tree.add_ids(el, ["ID"])
    algs = {"rsa-sha256": (C.TransformRsaSha256, C.TransformSha256), "rsa-sha1": (C.TransformRsaSha1, C.TransformSha1)}
    sig = xmlsec.template.create(el, C.TransformExclC14N, algs[alg][0], ns="ds")
    el.insert(1, sig)
    ref = xmlsec.template.add_reference(sig, algs[alg][1], uri="#" + el.get("ID"))
    xmlsec.template.add_transform(ref, C.TransformEnveloped)
    xmlsec.template.add_transform(ref, C.TransformExclC14N)
    xmlsec.template.add_x509_data(xmlsec.template.ensure_key_info(sig))
    ctx = xmlsec.SignatureContext()
    k = xmlsec.Key.from_file(os.path.join(DATA, "idp.key"), C.KeyDataFormatPem)
    k.load_cert_from_file(os.path.join(DATA, "idp.crt"), C.KeyDataFormatPem)
    ctx.key = k
    ctx.sign(sig)


def xmlsec_encrypt_assertion(root, cbc=False):
    import xmlsec
    from lxml import etree
    C = xmlsec.constants
    A = "urn:oasis:names:tc:SAML:2.0:assertion"
    asrt = root.find(f"{{{A}}}Assertion")
    ea = etree.Element(f"{{{A}}}EncryptedAssertion")
    asrt.addprevious(ea)
    ea.append(asrt)
    ed = xmlsec.template.encrypted_data_create(ea, C.TransformAes128Cbc if cbc else C.TransformAes256Gcm, type=C.TypeEncElement, ns="xenc")
    xmlsec.template.encrypted_data_ensure_cipher_value(ed)
    ki = xmlsec.template.encrypted_data_ensure_key_info(ed, ns="dsig")
    ek = xmlsec.template.add_encrypted_key(ki, C.TransformRsaOaep)
    xmlsec.template.encrypted_data_ensure_cipher_value(ek)
    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file(os.path.join(DATA, "sp.crt"), C.KeyDataFormatCertPem, None))
    ctx = xmlsec.EncryptionContext(manager)
    ctx.key = xmlsec.Key.generate(C.KeyDataAes, 128 if cbc else 256, C.KeyDataTypeSession)
    enc = ctx.encrypt_xml(ed, asrt)
    return root


def python_idp_to_goose_sp(g):
    """Responses built and signed by python3-saml's xmlsec (and its add_sign), posted to goose-saml's SP."""
    from lxml import etree
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    sp_port = free_port()
    sp_base = f"http://127.0.0.1:{sp_port}"
    idp_base = f"http://127.0.0.1:{free_port()}"
    idp_md = g.metadata("idp", idp_base)
    sp = g.sp(sp_port, idp_md)
    sp_cbc = None
    try:
        cases = [
            ("assertion signed by xmlsec", "asrt", False, 200, None),
            ("Response signed by python3-saml's add_sign", "resp", False, 200, None),
            ("both signed", "both", False, 200, None),
            ("assertion signed and encrypted (AES-256-GCM, RSA-OAEP) by xmlsec", "asrt", True, 200, None),
            ("signed with RSA-SHA1: refused", "asrt-sha1", False, 403, "algorithm"),
            ("NameID changed after signing: refused", "tamper", False, 403, "digest"),
            ("unsigned: refused", "none", False, 403, "signed"),
        ]
        for n, (name, how, encrypt, want, why) in enumerate(cases):
            s = requests.Session()
            r = s.get(f"{sp_base}/login", allow_redirects=False)
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["Location"]).query))
            req = OneLogin_Saml2_Utils.decode_base64_and_inflate(q["SAMLRequest"])
            irt = re.search(rb'ID="([^"]+)"', req if isinstance(req, bytes) else req.encode()).group(1).decode()
            now = time.time()
            fmt = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
            xml = RESPONSE.format(n=n, now=fmt(now), later=fmt(now + 300), before=fmt(now - 60), acs=f"{sp_base}/acs", irt=irt,
                                  idp=f"{idp_base}/metadata", sp=f"{sp_base}/metadata", user="alice@example.test")
            root = etree.fromstring(xml.encode())
            asrt = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
            if how in ("asrt", "both", "tamper"):
                xmlsec_sign(asrt)
            if how == "asrt-sha1":
                xmlsec_sign(asrt, "rsa-sha1")
            if how == "tamper":
                asrt.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text = "admin@example.test"
            if encrypt:
                root = xmlsec_encrypt_assertion(root)
            out = etree.tostring(root)
            if how in ("resp", "both"):
                out = OneLogin_Saml2_Utils.add_sign(out, open(os.path.join(DATA, "idp.key")).read(), open(os.path.join(DATA, "idp.crt")).read(),
                                                    sign_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                                                    digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
            r = s.post(f"{sp_base}/acs", data={"SAMLResponse": base64.b64encode(out).decode()})
            ev = login_event(sp)
            ok = r.status_code == want and (want != 200 or (ev.get("name_id") == "alice@example.test" and ev.get("encrypted") == encrypt
                                                           and ev.get("attributes", {}).get("groups") == ["staff", "admins"]))
            if why:
                ok = ok and why in r.text
            check(f"python3-saml/xmlsec Response -> goose SP: {name}", ok, (r.status_code, r.text, ev))
        # AES-CBC (as older IdPs send): refused unless --allow-cbc.
        sp.stop()
        for allow in (False, True):
            sp = g.sp(sp_port, idp_md, ["--allow-cbc"] if allow else [])
            s = requests.Session()
            r = s.get(f"{sp_base}/login", allow_redirects=False)
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["Location"]).query))
            req = OneLogin_Saml2_Utils.decode_base64_and_inflate(q["SAMLRequest"])
            irt = re.search(rb'ID="([^"]+)"', req if isinstance(req, bytes) else req.encode()).group(1).decode()
            now = time.time()
            fmt = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
            xml = RESPONSE.format(n=100 + allow, now=fmt(now), later=fmt(now + 300), before=fmt(now - 60), acs=f"{sp_base}/acs", irt=irt,
                                  idp=f"{idp_base}/metadata", sp=f"{sp_base}/metadata", user="alice@example.test")
            root = etree.fromstring(xml.encode())
            xmlsec_sign(root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"))
            root = xmlsec_encrypt_assertion(root, cbc=True)
            r = s.post(f"{sp_base}/acs", data={"SAMLResponse": base64.b64encode(etree.tostring(root)).decode()})
            check(f"xmlsec AES-128-CBC assertion -> goose SP, --allow-cbc {allow}", r.status_code == (200 if allow else 403), (r.status_code, r.text))
            if not allow:
                sp.stop()
        # A LogoutRequest signed (Redirect query) by python3-saml, playing the IdP's part.
        settings = py_settings(idp_base, sp_base, idp_cert="sp.crt", sp_key="idp",
                               security={"logoutRequestSigned": True, "logoutResponseSigned": True},
                               sp_entity=f"{idp_base}/metadata", idp_entity=f"{sp_base}/metadata", idp_slo=f"{sp_base}/slo")
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        auth = OneLogin_Saml2_Auth(req_data(f"{idp_base}/logout"), old_settings=settings)
        url = auth.logout(name_id="alice@example.test", name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        logout_id = auth.get_last_request_id()
        sp.drain()
        r = requests.get(url, allow_redirects=False)
        ev = [e for e in sp.events() if e.get("event") == "logout-request"]
        check("python3-saml's signed LogoutRequest -> goose SP", r.status_code == 302 and ev and ev[-1].get("result") == "ok", (r.status_code, r.text, ev))
        auth2 = OneLogin_Saml2_Auth(req_data(r.headers.get("Location", "")), old_settings=settings)
        auth2.process_slo(request_id=logout_id, keep_local_session=True)
        check("  python3-saml takes goose SP's signed LogoutResponse", not auth2.get_errors(), (auth2.get_errors(), auth2.get_last_error_reason()))
        # The same query with RelayState changed: the signature fails.
        bad = re.sub(r"RelayState=[^&]*", "RelayState=evil", url)
        r = requests.get(bad, allow_redirects=False)
        check("  the query with its RelayState changed: refused", bad != url and r.status_code == 403 and "signature" in r.text, (r.status_code, r.text))
    finally:
        sp.stop()


# --- crewjam/saml ---------------------------------------------------------------------------

def build_crewjam(work):
    if not shutil.which("go"):
        return None
    env = dict(os.environ)
    gopath = os.environ.get("SAML_GOPATH") or os.path.join(work, "gopath")
    env.update(GOPATH=gopath, GOMODCACHE=os.path.join(gopath, "pkg", "mod"), GOFLAGS="-modcacherw", GOBIN=os.path.join(work, "bin"))
    exe = os.path.join(work, "bin", "crewjam")
    p = subprocess.run(["go", "build", "-o", exe, "."], cwd=os.path.join(HERE, "crewjam"), env=env, capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stderr)
        return None
    return exe


def crewjam_sp_goose_idp(g, crew):
    idp_port, sp_port = free_port(), free_port()
    idp_base, sp_base = f"http://127.0.0.1:{idp_port}", f"http://127.0.0.1:{sp_port}"
    idp_md = g.metadata("idp", idp_base)
    variants = [
        ("redirect, unsigned requests, assertion signed", [], []),
        ("redirect, signed requests, Response signed, encrypted", ["-sign-request"], ["--want-signed-requests", "--sign", "both", "--encrypt"]),
        ("POST, signed requests, both signed", ["-sign-request", "-post"], ["--want-signed-requests", "--sign", "both"]),
    ]
    for name, sp_extra, idp_extra in variants:
        sp = Server(f"crewjam-sp-{sp_port}", [crew, "sp", "-url", sp_base, "-key", os.path.join(DATA, "sp.key"), "-cert", os.path.join(DATA, "sp.crt"),
                                              "-idp-metadata", idp_md, *sp_extra], sp_port, g.work)
        idp = None
        try:
            md = requests.get(f"{sp_base}/saml/metadata").text
            md_path = os.path.join(g.work, f"crewjam-sp-{sp_port}.xml")
            open(md_path, "w").write(md)
            idp = g.idp(idp_port, [md_path], idp_extra)
            b = Browser()
            r = b.go("GET", f"{sp_base}/hello")
            evs = idp.events()
            ok = r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/json")
            check(f"crewjam SP -> goose IdP, {name}: login", ok, (r.status_code, r.text[:500], b.trace, evs))
            if not ok:
                continue
            j = r.json()
            check("  the attributes crewjam read", "staff" in j.get("attributes", {}).get("groups", []) and j.get("subject") == "alice@example.test", j)
            check("  the AuthnRequest was signed as asked", any(e.get("event") == "authn-request" and e.get("signed") == ("-sign-request" in sp_extra) for e in evs), evs)
            signs = "-sign-request" in sp_extra
            r = b.go("GET", f"{sp_base}/logout")
            evs = idp.events()
            if not signs:
                # crewjam signs logout messages only with SignRequest; saml-profiles §4.4.4 wants them signed.
                check("  crewjam's unsigned LogoutRequest refused by goose IdP",
                      any(e.get("event") == "logout-request" and e.get("result") == "not signed" for e in evs), (evs, b.trace))
            else:
                check("  crewjam's LogoutRequest read by goose IdP", any(e.get("event") == "logout-request" and e.get("result") == "ok" for e in evs), (evs, b.trace))
                check("  and its LogoutResponse taken by crewjam (it sends the browser home)", r.status_code == 200 and r.text == "home\n" and
                      b.trace[-2].startswith(f"GET {sp_base}/saml/slo -> 302"), (r.status_code, r.text[:300], b.trace))
                r = b.s.get(f"{sp_base}/hello", allow_redirects=False)
                check("  the crewjam session is over", (r.status_code == 302 and r.headers.get("Location", "").startswith(f"{idp_base}/sso")) or
                      (r.status_code == 200 and "SAMLRequest" in r.text), (r.status_code, r.text[:200]))
            r = b.go("GET", f"{sp_base}/hello")
            r = b.go("GET", f"{idp_base}/logout?sp={urllib.parse.quote(sp_base + '/saml/metadata')}")
            if signs:
                check("  goose IdP's LogoutRequest taken by crewjam, its LogoutResponse by goose IdP", r.status_code == 200 and "logged out" in r.text,
                      (r.status_code, r.text[:300], b.trace))
            else:
                check("  goose IdP's LogoutRequest taken by crewjam, its unsigned LogoutResponse refused", r.status_code == 403 and "not signed" in r.text
                      and b.trace[-2].startswith(f"GET {sp_base}/saml/slo -> 302"), (r.status_code, r.text[:300], b.trace))
        finally:
            sp.stop()
            if idp:
                idp.stop()


def crewjam_idp_goose_sp(g, crew):
    idp_port, sp_port = free_port(), free_port()
    idp_base, sp_base = f"http://127.0.0.1:{idp_port}", f"http://127.0.0.1:{sp_port}"
    idp = Server(f"crewjam-idp-{idp_port}", [crew, "idp", "-url", idp_base, "-key", os.path.join(DATA, "idp.key"),
                                              "-cert", os.path.join(DATA, "idp.crt")], idp_port, g.work)
    try:
        md = requests.get(f"{idp_base}/metadata").text
        idp_md = os.path.join(g.work, f"crewjam-idp-{idp_port}.xml")
        open(idp_md, "w").write(md)
        variants = [
            ("redirect, encrypted (crewjam reads our EncryptionMethods)", [], True),
            ("POST, signed requests, encrypted", ["--binding", "post", "--sign-requests"], True),
            # crewjam's login form posts the SAMLRequest back to /sso without the
            # Redirect binding's query signature, so a signed Redirect request is
            # only answered with a session already open (POST /login).
            ("redirect, signed requests, plain (no encryption key in our metadata), logged in first", ["--sign-requests"], False),
        ]
        for name, sp_extra, encrypted in variants:
            sp_md = g.metadata("sp", sp_base, [x for x in sp_extra if x == "--sign-requests"])
            text = open(sp_md).read()
            if not encrypted:
                text = re.sub(r'<md:KeyDescriptor use="encryption">.*?</md:KeyDescriptor>', "", text, flags=re.S)
            r = requests.put(f"{idp_base}/services/goose", data=text)
            if not check(f"crewjam IdP: our SP's metadata registered ({name})", r.status_code in (200, 204), (r.status_code, r.text)):
                continue
            sp = g.sp(sp_port, idp_md, sp_extra)
            try:
                b = Browser()
                first = "logged in first" in name
                if first:
                    r = b.s.post(f"{idp_base}/login", data={"user": "alice", "password": "hunter2"})
                    check("crewjam IdP: a session opened by POST /login", r.status_code == 200, (r.status_code, r.text[:300]))
                r = b.go("GET", f"{sp_base}/login?RelayState=/after")
                fs = forms_of(r.text)
                if not first:
                    if not check(f"crewjam IdP: its login form", r.status_code == 200 and fs and "password" in fs[0]["fields"], (r.status_code, r.text[:500], b.trace)):
                        continue
                    f = fs[0]
                    f["fields"].update(user="alice", password="hunter2")
                    r = b.go("POST", urllib.parse.urljoin(r.url, f["action"]), data=f["fields"])
                ev = login_event(sp)
                check(f"crewjam IdP -> goose SP, {name}: login", r.status_code == 200 and ev.get("event") == "login", (r.status_code, r.text[:500], ev, b.trace))
                if os.environ.get("SAML_VERBOSE"):
                    print(json.dumps(ev))
                attrs = ev.get("attributes", {})
                check("  the assertion: NameID, mail, a multi-valued attribute", ev.get("name_id") == "alice@example.test" and
                      attrs.get("urn:oid:0.9.2342.19200300.100.1.3") == ["alice@example.test"] and
                      attrs.get("urn:oid:1.3.6.1.4.1.5923.1.1.1.1") == ["Administrators", "Users"], ev)
                check(f"  encrypted {encrypted}, signed", ev.get("encrypted") == encrypted and (ev.get("assertion_signed") or ev.get("response_signed")), ev)
                check("  RelayState", ev.get("relay_state") == "/after", ev)
                # SP-initiated logout.
                r = b.go("GET", f"{sp_base}/logout")
                evs = sp.events()
                check("  goose SP's LogoutRequest taken by crewjam, its LogoutResponse by goose SP",
                      r.status_code == 200 and "logged out" in r.text and any(e.get("event") == "logout-response" and e.get("result") == "ok" for e in evs),
                      (r.status_code, r.text[:300], evs, b.trace))
                # Log in again, then IdP-initiated logout from crewjam.
                if first:
                    b.s.post(f"{idp_base}/login", data={"user": "alice", "password": "hunter2"})
                r = b.go("GET", f"{sp_base}/login")
                fs = forms_of(r.text)
                if fs and "password" in fs[0]["fields"]:
                    f = fs[0]
                    f["fields"].update(user="alice", password="hunter2")
                    r = b.go("POST", urllib.parse.urljoin(r.url, f["action"]), data=f["fields"])
                login_event(sp)
                r = b.go("GET", f"{idp_base}/logout")
                evs = sp.events()
                check("  crewjam's LogoutRequest read by goose SP", any(e.get("event") == "logout-request" and e.get("result") == "ok" for e in evs),
                      (r.status_code, r.text[:300], evs, b.trace))
            finally:
                sp.stop()
    finally:
        idp.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--tool", help="a goose-saml already built")
    ap.add_argument("--work", help="a directory for the builds and logs (a temporary one by default)")
    ap.add_argument("-k", help="only the groups whose name contains this")
    args = ap.parse_args()
    work = args.work or tempfile.mkdtemp(prefix="saml-interop-")
    os.makedirs(work, exist_ok=True)
    tool = args.tool
    if not tool:
        tool = os.path.join(work, "goose-saml")
        goose = find_goose(args.goose)
        p = subprocess.run([goose, "build", "-O2", "-o", tool, "saml.goose"], cwd=os.path.join(SAML_DIR, "tools"), capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("cannot build goose-saml:\n" + p.stderr)
    g = Goose(tool, work)
    try:
        import onelogin.saml2  # noqa: F401
        import xmlsec  # noqa: F401
        have_py = True
    except ImportError:
        have_py = False
    groups = [("goose", lambda: (goose_pair(g), goose_replay(g)), True, ""),
              ("python3-saml-sp", lambda: python3_saml_sp(g), have_py, "python3-saml and xmlsec not importable"),
              ("python3-saml-idp", lambda: python_idp_to_goose_sp(g), have_py, "python3-saml and xmlsec not importable")]
    crew = None
    if not args.k or "crewjam" in args.k:
        crew = build_crewjam(work)
    groups += [("crewjam-sp", lambda: crewjam_sp_goose_idp(g, crew), crew is not None, "no Go, or crewjam did not build"),
               ("crewjam-idp", lambda: crewjam_idp_goose_sp(g, crew), crew is not None, "no Go, or crewjam did not build")]
    for name, run, can, why in groups:
        if args.k and args.k not in name:
            continue
        if not can:
            skip(name, why)
            continue
        try:
            run()
        except Exception as e:  # a server that did not start, a peer that broke: one failure, go on
            check(f"{name}: ran to the end", False, repr(e))
    print(f"\n{passed} passed, {len(failed)} failed, {len(skipped)} skipped (logs in {work})")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
