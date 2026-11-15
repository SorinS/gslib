#!/usr/bin/env python3
"""goose-oauth against OAuth 2.0 / OpenID Connect servers, on 127.0.0.1:

1. node-oidc-provider (OpenID Certified), from scripts/op (package.json
   and its lock; `npm ci` is run there when node_modules is missing), on
   https with a test CA, asking for client certificates: discovery;
   client credentials by client_secret_basic, client_secret_post,
   private_key_jwt and tls_client_auth (RFC 8705); JWT access tokens (RFC
   9068) for a resource indicator, validated, one bound to the client's
   certificate (cnf x5t#S256); DPoP-bound tokens with the server asking
   for nonces (RFC 9449); introspection and revocation; the
   authorization code flow with PKCE through goose-oauth's loopback
   redirect, plain and by PAR (RFC 9126) with DPoP, the logins driven by
   this script; ID token validation; refresh; UserInfo, JSON and signed;
   the device grant (RFC 8628), its pages driven by this script; token
   exchange (RFC 8693, a grant scripted into the provider); refusals.
2. Keycloak in Docker or Podman, when a daemon is running (never started
   here): see keycloak() below.

Needs node and npm (or skips), openssl.

    python3 scripts/interop.py [--goose PATH]
"""

import argparse
import base64
import hashlib
import html.parser
import http.cookiejar
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOP = os.path.normpath(os.path.join(ROOT, ".."))
OP_DIR = os.path.join(ROOT, "scripts", "op")
API = "urn:example:api"

failures = 0
passed = 0


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(TOP, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def check(what, ok, detail=""):
    global failures, passed
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if ok:
        passed += 1
    else:
        failures += 1
        if detail:
            print("     " + detail.strip()[-1500:].replace("\n", "\n     "))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_parts(token):
    h, p, _ = token.split(".")
    return json.loads(b64u_dec(h)), json.loads(b64u_dec(p))


def jwk_thumbprint(k):
    if k["kty"] == "EC":
        m = {"crv": k["crv"], "kty": "EC", "x": k["x"], "y": k["y"]}
    elif k["kty"] == "RSA":
        m = {"e": k["e"], "kty": "RSA", "n": k["n"]}
    else:
        m = {"crv": k["crv"], "kty": k["kty"], "x": k["x"]}
    return b64u(hashlib.sha256(json.dumps(m, separators=(",", ":"), sort_keys=True).encode()).digest())


def openssl(*args, cwd=None):
    p = subprocess.run(["openssl", *args], capture_output=True, text=True, cwd=cwd)
    if p.returncode != 0:
        sys.exit(f"openssl {' '.join(args)} failed:\n{p.stderr}")
    return p.stdout


def make_pki(tmp):
    """A CA, the server's certificate (localhost, 127.0.0.1), and a client's (CN=mtls-client)."""
    f = lambda n: os.path.join(tmp, n)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f("ca.key"),
            "-out", f("ca.pem"), "-subj", "/CN=goose-oauth test CA", "-days", "2",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, subj, ext in [("server", "/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth"),
                            ("client", "/CN=mtls-client", "extendedKeyUsage=clientAuth")]:
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f(name + ".key"),
                "-out", f(name + ".csr"), "-subj", subj)
        open(f(name + ".ext"), "w").write(ext + "\nauthorityKeyIdentifier=keyid\nkeyUsage=critical,digitalSignature\n")
        openssl("x509", "-req", "-in", f(name + ".csr"), "-CA", f("ca.pem"), "-CAkey", f("ca.key"), "-CAcreateserial",
                "-out", f(name + ".pem"), "-days", "2", "-extfile", f(name + ".ext"))
    der = subprocess.run(["openssl", "x509", "-in", f("client.pem"), "-outform", "DER"], capture_output=True).stdout
    return b64u(hashlib.sha256(der).digest())


class Tool:
    def __init__(self, exe, issuer, ca, tmp):
        self.exe, self.issuer, self.ca, self.tmp = exe, issuer, ca, tmp

    def cmd(self, client, *args):
        return [self.exe, "--issuer", self.issuer, "--ca-file", self.ca, "--client-id", client, *args]

    def __call__(self, client, *args, timeout=120, stdin=None):
        p = subprocess.run(self.cmd(client, *args), capture_output=True, text=True, timeout=timeout, input=stdin)
        return p.returncode, p.stdout, p.stderr

    def spawn(self, client, *args):
        return subprocess.Popen(self.cmd(client, *args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


class Forms(html.parser.HTMLParser):
    """The forms of a page: each one's action and its inputs' names and values."""

    def __init__(self):
        super().__init__()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append({"action": a.get("action", ""), "id": a.get("id", ""), "fields": {}})
        elif tag == "input" and self.forms and a.get("name"):
            self.forms[-1]["fields"][a["name"]] = a.get("value") or ""


def browser(ctx):
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                       urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def read_url_from(proc, marker, timeout=60):
    """The first URL on a stderr line after `marker`, as the tool prints it; and what it printed so far."""
    seen = []
    end = time.time() + timeout
    want = False
    while time.time() < end:
        line = proc.stderr.readline()
        if not line:
            break
        seen.append(line)
        if marker in line:
            want = True
            m = re.search(r"https?://\S+", line)
            if m:
                return m.group(0), "".join(seen)
            continue
        if want:
            m = re.search(r"https?://\S+", line)
            if m:
                return m.group(0), "".join(seen)
    return None, "".join(seen)


def finish(proc, timeout=120):
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    return proc.returncode, out, err


def login(tool, ctx, client, *args):
    """goose-oauth login, the sign-in driven as a browser would follow the redirects."""
    proc = tool.spawn(client, *args, "--timeout", "60", "login")
    url, early = read_url_from(proc, "open this URL")
    if not url:
        rc, out, err = finish(proc)
        return rc, out, early + err, None
    try:
        r = browser(ctx).open(url, timeout=30)
        final = r.geturl()
        r.read()
    except Exception as e:  # the provider's refusal: the tool waits in vain
        final = str(e)
        proc.kill()
    rc, out, err = finish(proc)
    return rc, out, early + err, final


def device(tool, ctx, client, *args):
    """goose-oauth device: its verification page's forms filled in and sent until the provider says it is done."""
    proc = tool.spawn(client, *args, "device")
    url, early = read_url_from(proc, "or open")
    if not url:
        rc, out, err = finish(proc)
        return rc, out, early + err, False
    b = browser(ctx)
    done = False
    try:
        page = b.open(url, timeout=30)
        for _ in range(6):
            text = page.read().decode()
            if "Sign-in Success" in text:
                done = True
                break
            fp = Forms()
            fp.feed(text)
            if not fp.forms:
                break
            form = fp.forms[0]
            fields = {k: v for k, v in form["fields"].items() if k != "abort"}
            action = urllib.parse.urljoin(page.geturl(), form["action"] or page.geturl())
            page = b.open(action, data=urllib.parse.urlencode(fields).encode(), timeout=30)
    except Exception as e:
        early += f"[driver: {e}]\n"
    if not done:
        proc.kill()
    rc, out, err = finish(proc)
    return rc, out, early + err, done


def write_secret(tmp, name, value):
    path = os.path.join(tmp, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    return path


def node_provider(exe, tmp):
    node, npm = shutil.which("node") or "/opt/homebrew/bin/node", shutil.which("npm")
    if not os.path.isfile(node) or not npm:
        print("skip oidc-provider: node or npm not found")
        return
    if not os.path.isdir(os.path.join(OP_DIR, "node_modules", "oidc-provider")):
        p = subprocess.run([npm, "ci", "--no-audit", "--no-fund"], cwd=OP_DIR, capture_output=True, text=True)
        if p.returncode != 0:
            print(f"skip oidc-provider: npm ci failed\n{p.stderr[-800:]}")
            return
    cert_x5t = make_pki(tmp)
    f = lambda n: os.path.join(tmp, n)
    port = free_port()
    secrets_ = {k: secrets.token_urlsafe(24) for k in ("basic", "post", "dpop")}
    cfg = {"port": port, "key": f("server.key"), "cert": f("server.pem"), "ca": f("ca.pem"),
           "secrets": secrets_, "client_key_out": f("jwt-client.jwk")}
    json.dump(cfg, open(f("op.json"), "w"))
    os.chmod(f("op.json"), 0o600)
    srv = subprocess.Popen([node, os.path.join(OP_DIR, "provider.mjs"), f("op.json")], cwd=OP_DIR,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = srv.stdout.readline()
    if not line.startswith("listening on "):
        srv.kill()
        check("oidc-provider starts", False, line + srv.stderr.read())
        return
    issuer = line.split()[-1]
    log = []
    threading.Thread(target=lambda: log.extend(srv.stderr), daemon=True).start()
    try:
        run_node_tests(exe, issuer, tmp, secrets_, cert_x5t)
    finally:
        srv.terminate()
        try:
            srv.wait(10)
        except subprocess.TimeoutExpired:
            srv.kill()


def run_node_tests(exe, issuer, tmp, secrets_, cert_x5t):
    f = lambda n: os.path.join(tmp, n)
    tool = Tool(exe, issuer, f("ca.pem"), tmp)
    ctx = ssl.create_default_context(cafile=f("ca.pem"))
    sec = {k: write_secret(tmp, k + ".secret", v) for k, v in secrets_.items()}
    no_secret = lambda text: all(v not in text for v in secrets_.values())
    one_token = lambda out: len(out.strip().splitlines()) == 1 and len(out.strip()) > 20

    rc, out, err = tool("basic-client", "discover")
    meta = json.loads(out) if rc == 0 else {}
    check("op: discovery", rc == 0 and meta.get("issuer") == issuer and "private_key_jwt" in meta.get(
        "token_endpoint_auth_methods_supported", ""), err)

    # Client credentials, every way of authenticating.
    rc, out, err = tool("basic-client", "--client-secret-file", sec["basic"], "--scope", "api:read", "token")
    check("op: client credentials, client_secret_basic", rc == 0 and one_token(out) and "got a Bearer token" in err, err)
    check("op: the secret is printed nowhere", no_secret(out + err))
    basic_at = out.strip()
    rc, out, err = tool("post-client", "--auth", "post", "--client-secret-file", sec["post"], "token")
    check("op: client credentials, client_secret_post", rc == 0 and one_token(out), err)
    rc, out, err = tool("jwt-client", "--auth", "private-key-jwt", "--key", f("jwt-client.jwk"), "token")
    check("op: client credentials, private_key_jwt", rc == 0 and one_token(out), err)
    check("op: the private key is printed nowhere", json.load(open(f("jwt-client.jwk")))["d"] not in out + err)
    env_rc = subprocess.run(tool.cmd("basic-client", "token"), capture_output=True, text=True,
                            env=dict(os.environ, OAUTH_CLIENT_SECRET=secrets_["basic"]))
    check("op: the secret from $OAUTH_CLIENT_SECRET", env_rc.returncode == 0, env_rc.stderr)
    rc, out, err = tool("basic-client", "--client-secret-file", sec["post"], "token")
    check("op: a wrong secret is refused (invalid_client)", rc == 1 and "invalid_client" in err and no_secret(out + err), err)
    rc, out, err = tool("basic-client", "--client-secret-file", sec["basic"], "--scope", "nonsense", "token")
    check("op: an unknown scope is not granted", rc == 0 and "nonsense" not in err, err)

    # JWT access tokens (RFC 9068) for a resource, validated as a resource server would.
    rc, out, err = tool("basic-client", "--client-secret-file", sec["basic"], "--resource", API, "--scope", "api:read", "token")
    jat = out.strip()
    hdr, claims = jwt_parts(jat) if rc == 0 and jat.count(".") == 2 else ({}, {})
    check("op: a JWT access token for a resource", rc == 0 and hdr.get("typ") == "at+jwt" and claims.get("aud") == API, err)
    tf = write_secret(tmp, "jat", jat)
    rc, out, err = tool("basic-client", "--token-file", tf, "--audience", API, "--scope", "api:read", "validate-access-token")
    check("op: RFC 9068 validation", rc == 0 and json.loads(out).get("client_id") == "basic-client", err)
    rc, out, err = tool("basic-client", "--token-file", tf, "--audience", "urn:example:other", "validate-access-token")
    check("op: RFC 9068, another audience refused", rc == 1 and "audience" in err, err)
    rc, out, err = tool("basic-client", "--token-file", tf, "--audience", API, "--scope", "api:write", "validate-access-token")
    check("op: RFC 9068, a scope it lacks refused", rc == 1 and "scope" in err, err)

    # Mutual TLS: tls_client_auth, and a token bound to the certificate.
    rc, out, err = tool("mtls-client", "--auth", "tls", "--cert", f("client.pem"), "--cert-key", f("client.key"),
                        "--resource", API, "--scope", "api:read", "token")
    mat = out.strip()
    check("op: client credentials, tls_client_auth", rc == 0 and one_token(out), err)
    if rc == 0:
        hdr, claims = jwt_parts(mat)
        check("op: bound to the certificate (cnf x5t#S256)", claims.get("cnf", {}).get("x5t#S256") == cert_x5t, str(claims))
        tf = write_secret(tmp, "mat", mat)
        rc, out, err = tool("mtls-client", "--token-file", tf, "--audience", API, "validate-access-token")
        check("op: the bound token validates, its cnf there",
              rc == 0 and json.loads(out).get("cnf", {}).get("x5t#S256") == cert_x5t, err)
    rc, out, err = tool("mtls-client", "--auth", "tls", "--cert", f("server.pem"), "--cert-key", f("server.key"), "token")
    check("op: tls_client_auth with another certificate refused", rc == 1 and "invalid_client" in err, err)

    # Introspection and revocation.
    tf = write_secret(tmp, "basic_at", basic_at)
    rc, out, err = tool("basic-client", "--client-secret-file", sec["basic"], "--token-file", tf, "introspect")
    it = json.loads(out) if rc == 0 else {}
    check("op: introspection, active", rc == 0 and it.get("active") is True and it.get("client_id") == "basic-client", err)
    rc, out, err = tool("basic-client", "--client-secret-file", sec["basic"], "--token-file", tf, "revoke")
    check("op: revocation", rc == 0, err)
    rc, out, err = tool("basic-client", "--client-secret-file", sec["basic"], "--token-file", tf, "introspect")
    check("op: introspection after revocation, inactive", rc == 0 and json.loads(out).get("active") is False, out + err)
    rc, out, err = tool("basic-client", "--client-secret-file", sec["basic"], "--token-file", "-", "introspect",
                        stdin="not-a-token\n")
    check("op: introspection of nonsense (from stdin), inactive", rc == 0 and json.loads(out).get("active") is False, out + err)

    # DPoP: the provider asks for a nonce on every proof.
    rc, out, err = tool("dpop-client", "--client-secret-file", sec["dpop"], "--dpop-key", f("dpop.jwk"), "--scope", "api:read", "token")
    check("op: a DPoP token, after the server's use_dpop_nonce", rc == 0 and "got a DPoP token" in err, err)
    check("op: the DPoP key file is 0600", os.path.exists(f("dpop.jwk")) and os.stat(f("dpop.jwk")).st_mode & 0o777 == 0o600)
    if rc == 0:
        jkt = jwk_thumbprint(json.load(open(f("dpop.jwk"))))
        tf = write_secret(tmp, "dpop_at", out.strip())
        rc, out, err = tool("dpop-client", "--client-secret-file", sec["dpop"], "--token-file", tf, "introspect")
        it = json.loads(out) if rc == 0 else {}
        check("op: introspection shows the DPoP binding (cnf jkt)", it.get("cnf", {}).get("jkt") == jkt and it.get("token_type") == "DPoP", out + err)
    rc, out, err = tool("dpop-client", "--client-secret-file", sec["dpop"], "token")
    check("op: a client bound to DPoP is refused without it", rc == 1 and "invalid" in err, err)

    # The authorization code flow, PKCE, the loopback redirect.
    rc, out, err, final = login(tool, ctx, "public-client", "--scope", "openid profile email offline_access",
                                "--save", f("public.json"))
    check("op: login, a public client with PKCE", rc == 0 and one_token(out) and "an ID token" in err
          and "the ID token is valid: sub alice" in err, err)
    check("op: the redirect reached goose-oauth", bool(final) and final.startswith("http://127.0.0.1:"), str(final))
    saved = json.load(open(f("public.json"))) if os.path.exists(f("public.json")) else {}
    check("op: the saved response, 0600, with refresh and ID tokens",
          os.path.exists(f("public.json")) and os.stat(f("public.json")).st_mode & 0o777 == 0o600
          and saved.get("refresh_token") and saved.get("id_token") and saved.get("nonce"))
    check("op: neither printed", saved.get("refresh_token", "x") not in out + err and saved.get("id_token", "x") not in out + err)
    rc, out, err = tool("public-client", "--saved", f("public.json"), "validate-id-token")
    claims = json.loads(out) if rc == 0 else {}
    check("op: the ID token validates (iss, aud, nonce, signature by the JWKS)", rc == 0 and claims.get("sub") == "alice"
          and claims.get("nonce") == saved.get("nonce"), err)
    rc, out, err = tool("public-client", "--saved", f("public.json"), "--nonce", "another", "validate-id-token")
    check("op: another nonce refused", rc == 1 and "nonce" in err, err)
    rc, out, err = tool("public-client", "--saved", f("public.json"), "userinfo")
    check("op: UserInfo (JSON), sub matching the ID token", rc == 0 and json.loads(out).get("email") == "alice@example.test", err)
    rc, out, err = tool("public-client", "--saved", f("public.json"), "--save", f("public2.json"), "refresh")
    check("op: refresh", rc == 0 and one_token(out) and out.strip() != saved.get("access_token"), err)
    rc, out, err = tool("public-client", "--saved", f("public.json"), "--refresh", "revoke")
    check("op: revoke the refresh token (rotated: the old one)", rc == 0, err)
    rc, out, err = tool("public-client", "--saved", f("public2.json"), "--refresh", "revoke")
    rc, out, err = tool("public-client", "--saved", f("public2.json"), "refresh")
    check("op: a revoked refresh token is refused (invalid_grant)", rc == 1 and "invalid_grant" in err, err)

    # By PAR, with DPoP: the code bound to the key (dpop_jkt), the token too.
    rc, out, err, final = login(tool, ctx, "dpop-client", "--client-secret-file", sec["dpop"], "--dpop-key", f("dpop.jwk"),
                                "--par", "--scope", "openid email", "--save", f("dpop.json"))
    check("op: login by PAR, with DPoP", rc == 0 and "got a DPoP token" in err, err)
    rc, out, err = tool("dpop-client", "--client-secret-file", sec["dpop"], "--dpop-key", f("dpop.jwk"), "--saved", f("dpop.json"), "userinfo")
    check("op: UserInfo with a DPoP token, after its nonce", rc == 0 and json.loads(out).get("sub") == "alice", err)
    rc, out, err = tool("dpop-client", "--client-secret-file", sec["dpop"], "--dpop-key", f("other.jwk"), "--saved", f("dpop.json"), "userinfo")
    check("op: UserInfo with another DPoP key refused", rc == 1 and "invalid_token" in err, err)

    # private_key_jwt and a resource: a JWT access token with the code flow; UserInfo signed.
    rc, out, err, final = login(tool, ctx, "post-client", "--auth", "post", "--client-secret-file", sec["post"],
                                "--scope", "openid email", "--save", f("post.json"))
    check("op: login, client_secret_post", rc == 0, err)
    rc, out, err = tool("post-client", "--auth", "post", "--client-secret-file", sec["post"], "--saved", f("post.json"), "userinfo")
    check("op: UserInfo signed (application/jwt), verified", rc == 0 and json.loads(out).get("sub") == "alice", err)
    rc, out, err, final = login(tool, ctx, "jwt-client", "--auth", "private-key-jwt", "--key", f("jwt-client.jwk"),
                                "--resource", API, "--scope", "openid api:read", "--save", f("jwt.json"))
    check("op: login, private_key_jwt, for a resource", rc == 0, err)
    if rc == 0:
        tf = write_secret(tmp, "jwt_at", out.strip())
        rc, out, err = tool("jwt-client", "--token-file", tf, "--audience", API, "--scope", "api:read", "validate-access-token")
        check("op: its access token validates (RFC 9068), sub alice", rc == 0 and json.loads(out).get("sub") == "alice", err)

    # The device grant.
    rc, out, err, done = device(tool, ctx, "basic-client", "--client-secret-file", sec["basic"], "--scope", "openid api:read")
    check("op: the device grant", rc == 0 and done and one_token(out) and "enter the code" in err, err)

    # Token exchange (the provider's scripted grant).
    rc, out, err = tool("basic-client", "--client-secret-file", sec["basic"], "--scope", "api:read", "token")
    tf = write_secret(tmp, "subject", out.strip())
    rc, out, err = tool("post-client", "--auth", "post", "--client-secret-file", sec["post"], "--token-file", tf, "exchange")
    check("op: token exchange", rc == 0 and one_token(out) and "issued as urn:ietf:params:oauth:token-type:access_token" in err, err)
    tf = write_secret(tmp, "bogus", "not-a-token")
    rc, out, err = tool("post-client", "--auth", "post", "--client-secret-file", sec["post"], "--token-file", tf, "exchange")
    check("op: token exchange of nonsense refused (invalid_grant)", rc == 1 and "invalid_grant" in err, err)


def keycloak(exe, tmp):
    """Keycloak needs a container runtime; a daemon that is not running is not started here."""
    for rt in ("docker", "podman"):
        path = shutil.which(rt)
        if not path:
            continue
        p = subprocess.run([path, "info"], capture_output=True, text=True, timeout=30)
        if p.returncode == 0:
            print(f"skip Keycloak: {rt} is running, but the Keycloak run is not written yet")
            return
    print("skip Keycloak: neither docker's daemon nor a podman machine is running")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--exe", help="a goose-oauth already built, rather than building one")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    if not shutil.which("openssl"):
        sys.exit("openssl not found")
    with tempfile.TemporaryDirectory() as tmp:
        exe = args.exe or os.path.join(tmp, "goose-oauth")
        p = subprocess.CompletedProcess([], 0, "", "") if args.exe else subprocess.run([goose, "build", "-o", exe, "oauth.goose"], cwd=os.path.join(ROOT, "tools"),
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(f"cannot build goose-oauth:\n{p.stdout}{p.stderr}")
        node_provider(exe, tmp)
        keycloak(exe, tmp)
    print(f"\n{passed} passed, {failures} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
