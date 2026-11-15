#!/usr/bin/env python3
"""goose-acme against ACME servers, on 127.0.0.1:

1. Pebble (Let's Encrypt's test server) in -strict mode, turning down a
   fifth of the nonces (badNonce), with goose-dnsd as its DNS (*.example.test
   at 127.0.0.1): http-01 served by goose-acme, http-01 from a web root
   (served by Python), dns-01 by TSIG-signed dynamic updates to goose-dnsd
   (a wildcard and its apex, an RSA key), an update with the wrong TSIG
   key refused, revoking (twice), rolling the account key over,
   deactivating; each chain verified by openssl against Pebble's root.
2. Pebble requiring external account binding: refused without one and
   with the wrong MAC key, registered with the right one.
3. OpenBao's (or Vault's) PKI engine as an ACME server, dev mode: dns-01
   through goose-dnsd, the chain verified against the engine's root,
   revoking, and external account binding with a key from new-eab.

Pebble: `go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest`
or $PEBBLE (its test certificates are taken from Go's module cache, or
$PEBBLE_DIR).
OpenBao (`bao`) or Vault (`vault`) on PATH or in ~/go/bin; skipped if
neither is there. Needs openssl.

    python3 scripts/interop.py [--goose PATH]
"""

import argparse
import base64
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import ssl

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOP = os.path.normpath(os.path.join(ROOT, ".."))
TSIG_NAME = "acme-key."
TSIG_SECRET = base64.b64encode(b"a TSIG key for goose-acme's tests").decode()
ZONE = """$ORIGIN example.test.
$TTL 60
@   IN SOA ns.example.test. admin.example.test. 1 3600 600 86400 60
@   IN NS  ns.example.test.
ns  IN A   127.0.0.1
*   IN A   127.0.0.1
"""
# Pebble's own test keys (test/config/pebble-config-external-account-bindings.json).
EAB_KID = "kid-1"
EAB_KEY = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
EAB_OTHER_KEY = "b10lLJs8l1GPIzsLP0s6pMt8O0XVGnfTaCeROxQM0BIt2XrJMDHJZBM5NuQmQJQH"

failures = 0


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(TOP, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def find_tool(name):
    for cand in [os.environ.get(name.upper()), shutil.which(name), os.path.expanduser(f"~/go/bin/{name}")]:
        if cand and os.path.isfile(cand):
            return cand
    return None


def pebble_dir():
    d = os.environ.get("PEBBLE_DIR")
    if d:
        return d
    found = sorted(glob.glob(os.path.expanduser("~/go/pkg/mod/github.com/letsencrypt/pebble/v2@*")))
    return found[-1] if found else None


def check(what, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures += 1
        if detail:
            print("     " + detail.strip()[-1500:].replace("\n", "\n     "))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def build(goose, src, out):
    p = subprocess.run([goose, "build", "-o", out, os.path.basename(src)], cwd=os.path.dirname(src),
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"cannot build {src}:\n{p.stdout}{p.stderr}")


def start_dnsd(dnsd, zone_file):
    p = subprocess.Popen([dnsd, "-a", "127.0.0.1", "-p", "0", "-y", f"{TSIG_NAME}:{TSIG_SECRET}",
                          f"example.test.={zone_file}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    if not line.startswith("listening on "):
        p.kill()
        sys.exit(f"goose-dnsd did not start: {line}{p.stderr.read()}")
    return p, line.split()[-1]


def stop(p):
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()


class Acme:
    def __init__(self, exe, server, ca_file, tmp):
        self.exe, self.server, self.ca_file, self.tmp = exe, server, ca_file, tmp

    def __call__(self, key, *args, timeout=300):
        cmd = [self.exe, "--server", self.server, "--account-key", os.path.join(self.tmp, key)]
        if self.ca_file:
            cmd += ["--ca-file", self.ca_file]
        p = subprocess.run(cmd + list(args), capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr


def openssl(*args):
    p = subprocess.run(["openssl", *args], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def sans(cert):
    rc, out = openssl("x509", "-in", cert, "-noout", "-ext", "subjectAltName")
    return sorted(re.findall(r"DNS:([^,\s]+)", out))


def verify_chain(cert, root, tmp):
    # The chain file holds the leaf first, then the intermediates.
    text = open(cert).read()
    blocks = ["-----BEGIN" + b for b in text.split("-----BEGIN")[1:]]
    leaf = os.path.join(tmp, "leaf.pem")
    inter = os.path.join(tmp, "inter.pem")
    open(leaf, "w").write(blocks[0])
    open(inter, "w").write("".join(blocks[1:]) or blocks[0])
    rc, out = openssl("verify", "-CAfile", root, "-untrusted", inter, leaf)
    return rc == 0, out


def fetch_insecure(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx, timeout=10).read().decode()


def pebble_config(pdir, tmp, name, eab):
    ports = {"acme": free_port(), "mgmt": free_port(), "http": free_port(), "tls": free_port()}
    cfg = {"pebble": {
        "listenAddress": f"127.0.0.1:{ports['acme']}",
        "managementListenAddress": f"127.0.0.1:{ports['mgmt']}",
        "certificate": os.path.join(pdir, "test/certs/localhost/cert.pem"),
        "privateKey": os.path.join(pdir, "test/certs/localhost/key.pem"),
        "httpPort": ports["http"], "tlsPort": ports["tls"], "ocspResponderURL": "",
        "externalAccountBindingRequired": eab,
        "retryAfter": {"authz": 1, "order": 1},
    }}
    if eab:
        cfg["pebble"]["externalAccountMACKeys"] = {EAB_KID: EAB_KEY, "kid-2": EAB_OTHER_KEY}
    path = os.path.join(tmp, name)
    json.dump(cfg, open(path, "w"))
    return path, ports


def start_pebble(pebble, pdir, cfg, ports, dns_port, env_extra):
    env = dict(os.environ, PEBBLE_VA_NOSLEEP="1", **env_extra)
    p = subprocess.Popen([pebble, "-config", cfg, "-strict", "-dnsserver", f"127.0.0.1:{dns_port}"],
                         cwd=pdir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port(ports["acme"]):
        p.kill()
        sys.exit("pebble did not start")
    return p


def with_pebble(acme_exe, pebble, pdir, dns_port, tmp):
    cfg, ports = pebble_config(pdir, tmp, "pebble.json", False)
    srv = start_pebble(pebble, pdir, cfg, ports, dns_port, {"PEBBLE_WFE_NONCEREJECT": "20"})
    try:
        acme = Acme(acme_exe, f"https://localhost:{ports['acme']}/dir",
                    os.path.join(pdir, "test/certs/pebble.minica.pem"), tmp)
        root = os.path.join(tmp, "pebble-root.pem")
        open(root, "w").write(fetch_insecure(f"https://localhost:{ports['mgmt']}/roots/0"))
        out_dir = lambda n: os.path.join(tmp, n)

        rc, out = acme("a.jwk", "--email", "admin@example.test", "--agree-tos", "run",
                       "-d", "web.example.test", "-d", "www.example.test", "--http", str(ports["http"]),
                       "--cert-out", out_dir("web.pem"), "--key-out", out_dir("web.key"))
        check("pebble: http-01 served by goose-acme", rc == 0, out)
        if rc == 0:
            ok, vout = verify_chain(out_dir("web.pem"), root, tmp)
            check("pebble: http-01 chain verifies", ok, vout)
            check("pebble: http-01 names", sans(out_dir("web.pem")) == ["web.example.test", "www.example.test"])
            check("pebble: key file 0600", os.stat(out_dir("web.key")).st_mode & 0o777 == 0o600)
            check("pebble: account key file 0600", os.stat(out_dir("a.jwk")).st_mode & 0o777 == 0o600)

        # A web root, served by Python's http.server on Pebble's http-01 port.
        www = out_dir("www")
        os.makedirs(www, exist_ok=True)
        web = subprocess.Popen([sys.executable, "-m", "http.server", str(ports["http"]), "--bind", "127.0.0.1",
                                "--directory", www], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_port(ports["http"])
            rc, out = acme("a.jwk", "run", "-d", "static.example.test", "--webroot", www,
                           "--cert-out", out_dir("static.pem"), "--key-out", out_dir("static.key"))
            check("pebble: http-01 from a web root", rc == 0, out)
            left = os.listdir(os.path.join(www, ".well-known", "acme-challenge")) if rc == 0 else []
            check("pebble: web root cleaned up", left == [], str(left))
        finally:
            stop(web)

        rc, out = acme("a.jwk", "run", "-d", "*.example.test", "-d", "example.test",
                       "--dns", f"127.0.0.1:{dns_port}", "--tsig", f"{TSIG_NAME}:{TSIG_SECRET}",
                       "--key-type", "rsa2048", "--cert-out", out_dir("wild.pem"), "--key-out", out_dir("wild.key"))
        check("pebble: dns-01 by RFC 2136, wildcard and apex", rc == 0, out)
        if rc == 0:
            ok, vout = verify_chain(out_dir("wild.pem"), root, tmp)
            check("pebble: dns-01 chain verifies", ok, vout)
            check("pebble: dns-01 names", sans(out_dir("wild.pem")) == ["*.example.test", "example.test"])
            rc2, kout = openssl("pkey", "-in", out_dir("wild.key"), "-noout", "-text_pub")
            check("pebble: an RSA key", "2048 bit" in kout, kout)
            if shutil.which("dig"):
                dout = subprocess.run(["dig", "@127.0.0.1", "-p", str(dns_port), "+short",
                                       "_acme-challenge.example.test", "TXT"], capture_output=True, text=True).stdout
                check("pebble: TXT records removed afterwards", dout.strip() == "", dout)
        rc, out = acme("a.jwk", "run", "-d", "bad.example.test", "--dns", f"127.0.0.1:{dns_port}",
                       "--tsig", f"{TSIG_NAME}:d3Jvbmcgc2VjcmV0", "--cert-out", out_dir("bad.pem"))
        check("pebble: an update with the wrong TSIG key", rc == 1 and "could not be published" in out, out)

        if os.path.exists(out_dir("web.pem")):
            rc, out = acme("a.jwk", "revoke", "--cert", out_dir("web.pem"), "--reason", "4")
            check("pebble: revoke, superseded", rc == 0, out)
            rc, out = acme("a.jwk", "revoke", "--cert", out_dir("web.pem"))
            check("pebble: revoked already", rc == 1 and "alreadyRevoked" in out, out)

        rc, before = acme("a.jwk", "register")
        rc, out = acme("a.jwk", "rollover", "--new-account-key", out_dir("b.jwk"))
        check("pebble: key rollover", rc == 0, out)
        rc, after = acme("b.jwk", "register")
        url = before.strip().splitlines()[-1] if before.strip() else "?"
        check("pebble: the new key has the account", rc == 0 and after.strip().splitlines()[-1] == url, after)
        rc, out = acme("b.jwk", "deactivate")
        check("pebble: deactivate", rc == 0, out)
        rc, out = acme("b.jwk", "register")
        check("pebble: a deactivated account is refused", rc == 1 and "deactivated" in out, out)
    finally:
        stop(srv)

    cfg, ports = pebble_config(pdir, tmp, "pebble-eab.json", True)
    srv = start_pebble(pebble, pdir, cfg, ports, dns_port, {"PEBBLE_VA_ALWAYS_VALID": "1"})
    try:
        acme = Acme(acme_exe, f"https://localhost:{ports['acme']}/dir",
                    os.path.join(pdir, "test/certs/pebble.minica.pem"), tmp)
        rc, out = acme("e.jwk", "--agree-tos", "register")
        check("pebble eab: refused without a binding", rc == 1 and "externalAccountRequired" in out, out)
        rc, out = acme("e.jwk", "--agree-tos", "--eab-kid", "kid-2", "--eab-hmac", EAB_KEY, "register")
        check("pebble eab: refused with the wrong MAC key", rc == 1 and "unauthorized" in out, out)
        rc, out = acme("e.jwk", "--agree-tos", "--eab-kid", EAB_KID, "--eab-hmac", EAB_KEY, "register")
        check("pebble eab: registered", rc == 0, out)
    finally:
        stop(srv)


def with_bao(acme_exe, bao, dns_port, tmp):
    port = free_port()
    addr = f"http://127.0.0.1:{port}"
    srv = subprocess.Popen([bao, "server", "-dev", "-dev-root-token-id=root", f"-dev-listen-address=127.0.0.1:{port}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    name = os.path.basename(bao)
    env = dict(os.environ, BAO_ADDR=addr, BAO_TOKEN="root", VAULT_ADDR=addr, VAULT_TOKEN="root")

    def cli(*args):
        p = subprocess.run([bao, *args], env=env, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout + p.stderr

    try:
        if not wait_port(port):
            check(f"{name}: dev server starts", False)
            return
        time.sleep(1)
        steps = [
            ["secrets", "enable", "pki"],
            ["secrets", "tune", "-max-lease-ttl=87600h", "-passthrough-request-headers=If-Modified-Since",
             "-allowed-response-headers=Last-Modified", "-allowed-response-headers=Location",
             "-allowed-response-headers=Replay-Nonce", "-allowed-response-headers=Link", "pki"],
            ["write", "pki/config/cluster", f"path={addr}/v1/pki", f"aia_path={addr}/v1/pki"],
            ["write", "pki/config/acme", "enabled=true", f"dns_resolver=127.0.0.1:{dns_port}", "eab_policy=not-required"],
        ]
        ok, out = True, ""
        for s in steps[:2]:
            if ok:
                rc, out = cli(*s)
                ok = rc == 0
        rc, root_pem = cli("write", "-field=certificate", "pki/root/generate/internal", "common_name=Test Root", "ttl=8760h")
        ok = ok and rc == 0
        for s in steps[2:]:
            if ok:
                rc, out = cli(*s)
                ok = rc == 0
        check(f"{name}: PKI with ACME set up", ok, out if not ok else "")
        if not ok:
            return
        root = os.path.join(tmp, "bao-root.pem")
        open(root, "w").write(root_pem)
        acme = Acme(acme_exe, f"{addr}/v1/pki/acme/directory", None, tmp)
        cert = os.path.join(tmp, "bao.pem")
        rc, out = acme("v.jwk", "--email", "admin@example.test", "--agree-tos", "run",
                       "-d", "app.example.test", "-d", "api.example.test", "--dns", f"127.0.0.1:{dns_port}",
                       "--tsig", f"{TSIG_NAME}:{TSIG_SECRET}", "--cert-out", cert,
                       "--key-out", os.path.join(tmp, "bao.key"))
        check(f"{name}: dns-01 by RFC 2136", rc == 0, out)
        if rc == 0:
            ok, vout = verify_chain(cert, root, tmp)
            check(f"{name}: chain verifies against the engine's root", ok, vout)
            check(f"{name}: names", sans(cert) == ["api.example.test", "app.example.test"])
            rc, out = acme("v.jwk", "revoke", "--cert", cert)
            check(f"{name}: revoke", rc == 0, out)
        rc, out = cli("write", "pki/config/acme", "enabled=true", f"dns_resolver=127.0.0.1:{dns_port}",
                      "eab_policy=always-required")
        rc, out = cli("write", "-format=json", "-f", "pki/acme/new-eab")
        data = json.loads(out)["data"] if rc == 0 else {}
        rc, out = acme("w.jwk", "--agree-tos", "register")
        check(f"{name}: refused without a binding", rc == 1 and "externalAccountRequired" in out, out)
        rc, out = acme("w.jwk", "--agree-tos", "--eab-kid", data.get("id", ""), "--eab-hmac", data.get("key", ""), "register")
        check(f"{name}: registered with a binding from new-eab", rc == 0, out)
    finally:
        stop(srv)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    if not shutil.which("openssl"):
        sys.exit("openssl not found")
    pebble = find_tool("pebble")
    pdir = pebble_dir()
    bao = find_tool("bao") or find_tool("vault")
    with tempfile.TemporaryDirectory() as tmp:
        acme_exe = os.path.join(tmp, "goose-acme")
        dnsd = os.path.join(tmp, "goose-dnsd")
        build(goose, os.path.join(ROOT, "tools", "acme.goose"), acme_exe)
        build(goose, os.path.join(TOP, "dns", "tools", "dnsd.goose"), dnsd)
        zone = os.path.join(tmp, "example.test.zone")
        open(zone, "w").write(ZONE)
        dns, dns_port = start_dnsd(dnsd, zone)
        try:
            if pebble and pdir:
                with_pebble(acme_exe, pebble, pdir, dns_port, tmp)
            else:
                print("skip pebble: not found (go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest)")
            if bao:
                with_bao(acme_exe, bao, dns_port, tmp)
            else:
                print("skip OpenBao/Vault: neither bao nor vault found")
        finally:
            stop(dns)
    print(f"\n{'all passed' if failures == 0 else f'{failures} failed'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
