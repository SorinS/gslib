#!/usr/bin/env python3
"""krb5 against an Active Directory domain controller: what AD does that
MIT's KDC does not (the PAC from a real DC, claims, compound identity,
LDAP with SASL GSSAPI, RC4 accounts). The DC is the one scripts/windows
sets up (goose.test: users alice and bob, the service svc-web and its
keytab, the computer goosepc$), reached through an ssh tunnel to its
loopback, since its ports are closed from outside:

    ssh -N -L 127.0.0.1:8888:127.0.0.1:88 -L 127.0.0.1:3890:127.0.0.1:389 Administrator@<dc>
    scp Administrator@<dc>:C:/Goose/dc/web.keytab web.keytab

    python3 scripts/ad.py --password-file FILE --keytab web.keytab --dc-host NAME
        [--trust-password-file FILE] [--mit PREFIX]
        [--kdc 127.0.0.1:8888] [--ldap 127.0.0.1:3890] [--domain goose.test] [--goose PATH] [-k NAME] [-v]

The password file holds the test accounts' password (the one setup.ps1
was given); NAME is the DC's host name in the domain (its LDAP service is
ldap/NAME). With --trust-password-file (the password windows/trust.ps1
was given), the realm trust between the domain and MIT's A.TEST too: the
MIT KDCs of scripts/kdc.py are started on 127.0.0.1 with the trust's
keys. Our servers listen on 127.0.0.1 only. Each check prints ok or
FAIL; the exit status is 1 if any failed.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
import interop  # noqa: E402
from interop import ROOT, check, find_goose, out, start_server, stop_server  # noqa: E402
from kdc import REALM_A, Kdc  # noqa: E402


class Env:
    """What interop.run needs: the environment the tools run in."""

    def __init__(self, tmp, conf):
        self.tmp = tmp
        self.env = dict(os.environ, KRB5_CONFIG=conf, KRB5CCNAME="FILE:" + os.path.join(tmp, "cc"))

    def cache(self, name):
        return "FILE:" + os.path.join(self.tmp, "cc_" + name)

    def with_cache(self, name, conf=None):
        e = dict(self.env, KRB5CCNAME=self.cache(name))
        if conf:
            e["KRB5_CONFIG"] = conf
        return e


def run(e, args, stdin=None, env=None):
    return interop.run(e, args, stdin, env)


def write_conf(path, realm, domain, kdc, extra="", realms="", domain_realm=""):
    with open(path, "w") as f:
        f.write(f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_kdc = false
    rdns = false
    udp_preference_limit = 1
    forwardable = true
    renew_lifetime = 7d
{extra}
[realms]
    {realm} = {{
        kdc = tcp/{kdc}
    }}
{realms}
[domain_realm]
    .{domain} = {realm}
    {domain} = {realm}
{domain_realm}""")


def pac_lines(log, prefix):
    return [l.split(": ", 1)[1].strip() for l in log.splitlines() if l.startswith(prefix + ": ")]


def pac_buffers(log):
    m = re.search(r"^pac: verified .* buffers ([\d ]+)$", log, re.M)
    return sorted(int(x) for x in m.group(1).split()) if m else None


def serve_once(e, gss, keytab, client_args, env):
    """Our GSS server for one client: the client's run and the server's log."""
    srv, port = start_server([gss, "server", "0", "-once", "-keytab", keytab], e.env)
    try:
        p = run(e, [gss, "client", "127.0.0.1", str(port)] + client_args, env=env)
    finally:
        log = stop_server(srv)
    return p, log


def kinit_tests(e, tool, pw, keytab, realm, rc4_conf):
    p = run(e, [tool, "kinit", f"alice@{realm}"], pw + "\n", e.with_cache("alice"))
    check("kinit alice (AES, password)", p.returncode == 0, out(p))
    p = run(e, [tool, "klist"], env=e.with_cache("alice"))
    check("klist: alice's TGT, aes256", p.returncode == 0
          and re.search(rf"krbtgt/{realm}@{realm}\s+aes256-cts-hmac-sha1-96", p.stdout) is not None, out(p))
    p = run(e, [tool, "kinit", f"alice@{realm}"], "not-the-password\n", e.with_cache("x"))
    check("kinit alice, wrong password: KDC_ERR_PREAUTH_FAILED", p.returncode == 1 and "KDC_ERR_PREAUTH_FAILED" in out(p), out(p))
    p = run(e, [tool, "kinit", f"nobody-here@{realm}"], pw + "\n", e.with_cache("x"))
    check("kinit unknown user: KDC_ERR_C_PRINCIPAL_UNKNOWN", p.returncode == 1 and "C_PRINCIPAL_UNKNOWN" in out(p), out(p))
    p = run(e, [tool, "kinit", f"goosepc$@{realm}"], pw + "\n", e.with_cache("pc"))
    check("kinit goosepc$ (a computer: its salt from ETYPE-INFO2)", p.returncode == 0, out(p))
    p = run(e, [tool, "kinit", "-k", keytab, f"HTTP/web.{e.domain}@{realm}"], env=e.with_cache("svc"))
    check("kinit -k the service's keytab (ktpass, UPN = SPN)", p.returncode == 0, out(p))

    # FAST: bob armored by alice's TGT, and an armored error.
    p = run(e, [tool, "kinit", "-T", e.cache("alice"), f"bob@{realm}"], pw + "\n", e.with_cache("bob"))
    check("FAST: kinit -T bob, armored by alice's TGT", p.returncode == 0, out(p))
    p = run(e, [tool, "kinit", "-T", e.cache("pc"), f"alice@{realm}"], "not-the-password\n", e.with_cache("x"))
    check("FAST: wrong password, the error read inside the armor", p.returncode == 1 and "KDC_ERR_PREAUTH_FAILED" in out(p), out(p))
    p = run(e, [tool, "kinit", "-T", e.cache("pc"), f"alice@{realm}"], pw + "\n", e.with_cache("alice_fast"))
    check("FAST: kinit -T alice, armored by the computer's TGT", p.returncode == 0, out(p))

    # RC4. Every AD account keeps an RC4 key (the NT hash), so even alice
    # gets an RC4 TGT; msDS-SupportedEncryptionTypes governs only tickets
    # issued to the account as a service: svc-web's, AES only.
    p = run(e, [tool, "kinit", f"bob@{realm}"], pw + "\n", e.with_cache("bob_rc4", rc4_conf))
    p2 = run(e, [tool, "klist"], env=e.with_cache("bob_rc4", rc4_conf))
    check("RC4: kinit bob, arcfour-hmac only", p.returncode == 0 and "arcfour-hmac" in p2.stdout, out(p) + out(p2))
    p = run(e, [tool, "kvno", f"HTTP/web.{e.domain}"], env=e.with_cache("bob_rc4", rc4_conf))
    check("RC4: a ticket for svc-web (AES only) refused: KDC_ERR_ETYPE_NOSUPP", p.returncode == 1
          and "ETYPE_NOSUPP" in out(p), out(p))

    p = run(e, [tool, "renew"], env=e.with_cache("alice"))
    check("renew alice's TGT", p.returncode == 0, out(p))


def kvno_tests(e, tool, keytab, realm):
    p = run(e, [tool, "klist", "-k", keytab])
    m = re.search(rf"^(\d+) HTTP/web\.{re.escape(e.domain)}@{realm}", p.stdout, re.M)
    kvno = m.group(1) if m else "?"
    for spn in (f"HTTP/web.{e.domain}", f"host/web.{e.domain}"):
        p = run(e, [tool, "kvno", spn], env=e.with_cache("alice"))
        check(f"kvno {spn}: the keytab's kvno, aes256", p.returncode == 0
              and f"kvno = {kvno}, aes256-cts-hmac-sha1-96" in p.stdout, out(p))
    p = run(e, [tool, "kvno", f"HTTP/nowhere.{e.domain}"], env=e.with_cache("alice"))
    check("kvno unknown service: KDC_ERR_S_PRINCIPAL_UNKNOWN", p.returncode == 1 and "S_PRINCIPAL_UNKNOWN" in out(p), out(p))


def pac_tests(e, gss, keytab, realm):
    """The PAC from AD, verified by our acceptor; returns alice's SIDs."""
    svc = f"HTTP@web.{e.domain}"
    p, log = serve_once(e, gss, keytab, [svc, "hello"], e.with_cache("alice"))
    want = [1, 6, 7, 10, 12, 13, 16, 19]
    check("PAC: verified, buffers logon, sigs, client, UPN, claims, ticket+full checksums",
          p.returncode == 0 and pac_buffers(log) == want, log + out(p))
    sids = pac_lines(log, "pac sid")
    upn = re.search(r"^pac upn: sam=(\S+) sid=(\S+)$", log, re.M)
    user_sid = upn.group(2) if upn else ""
    domain_sid = user_sid.rsplit("-", 1)[0]
    check("PAC: UPN_DNS_INFO's SAM name and SID agree with the logon info",
          upn is not None and upn.group(1) == "alice" and sids[:1] == [user_sid], log)
    check("PAC: Domain Users (513) among alice's SIDs", domain_sid + "-513" in sids, log)
    check("PAC: claim department = Engineering", "ad://ext/department:goose Engineering" in pac_lines(log, "pac claim"), log)
    check("PAC: no device info, no Compounded Authentication without explicit armor",
          14 not in (pac_buffers(log) or []) and "S-1-5-21-0-0-0-496" not in sids, log)
    check("PAC: Claims Valid (-497) with the claims", "S-1-5-21-0-0-0-497" in sids, log)

    p, log = serve_once(e, gss, keytab, [svc, "hello"], e.with_cache("bob"))
    check("PAC: bob, no department, no claim", p.returncode == 0 and pac_lines(log, "pac claim") == []
          and pac_buffers(log) is not None, log + out(p))

    p, log = serve_once(e, gss, keytab, [svc, "hello", "-spnego"], e.with_cache("alice"))
    check("SPNEGO: alice -> our acceptor, PAC verified", p.returncode == 0 and "spnego=true" in log
          and pac_buffers(log) == want, log + out(p))

    p, log = serve_once(e, gss, keytab, [svc, "hello", "-deleg"], e.with_cache("alice"))
    check("delegation: alice's forwarded TGT reaches the acceptor", p.returncode == 0 and "delegated=1" in log
          and f"delegated: krbtgt/{realm}@{realm}" in log, log + out(p))
    return sids, domain_sid


def compound_tests(e, tool, gss, keytab, realm, domain_sid):
    """Compound identity: alice's TGS request armored by goosepc$'s TGT."""
    p = run(e, [tool, "kinit", f"alice@{realm}"], e.pw + "\n", e.with_cache("alice_dev"))
    p = run(e, [tool, "kvno", "-T", e.cache("pc"), f"HTTP/web.{e.domain}"], env=e.with_cache("alice_dev"))
    check("compound: kvno -T (explicit TGS armor by goosepc$'s TGT)", p.returncode == 0, out(p))
    p, log = serve_once(e, gss, keytab, [f"HTTP@web.{e.domain}", "hello"], e.with_cache("alice_dev"))
    bufs = pac_buffers(log) or []
    check("compound: PAC gains device info (14) and device claims (15)", p.returncode == 0 and 14 in bufs and 15 in bufs,
          log + out(p))
    dev = pac_lines(log, "pac device sid")
    check("compound: the device is in Domain Computers (515)", domain_sid + "-515" in dev, log)
    # MS-DTYP §2.4.2.4: S-1-5-21-0-0-0-496 Compounded Authentication,
    # -497 Claims Valid (in any ticket with claims).
    check("compound: alice's SIDs gain Compounded Authentication (-496)",
          "S-1-5-21-0-0-0-496" in pac_lines(log, "pac sid"), log)
    p = run(e, [tool, "kvno", "-T", e.cache("bob"), f"HTTP/web.{e.domain}"], env=e.with_cache("x_none"))
    check("compound: no client cache, refused", p.returncode == 1, out(p))
    return dev[0] if dev else ""


def http_tests(e, gss, keytab):
    srv, port = start_server([gss, "http-server", "0", "-once", "-keytab", keytab], e.env)
    try:
        p = run(e, [gss, "http-client", "127.0.0.1", str(port), "/", f"HTTP@web.{e.domain}"], env=e.with_cache("alice"))
    finally:
        log = stop_server(srv)
    check("HTTP Negotiate: alice -> our server, mutual, PAC verified", p.returncode == 0 and "200 OK" in p.stdout
          and "mutual authentication: ok" in p.stdout and pac_buffers(log) is not None, out(p) + log)


def ldap_tests(e, gss, ldap, dc_host, user_sid, pac_sids, domain_sid, device_sid):
    host, port = ldap.rsplit(":", 1)
    base = [gss, "ldap", host, port, "-service", f"ldap@{dc_host}"]
    for layer, name in (("conf", "confidentiality"), ("integ", "integrity"), ("none", "none")):
        p = run(e, base + ["-layer", layer], env=e.with_cache("alice"))
        check(f"LDAP SASL GSSAPI, layer {layer}: Who am I? GOOSE\\alice", p.returncode == 0
              and f"bound: layer {name}" in p.stdout and re.search(r"^whoami: u:\w+\\alice$", p.stdout, re.M) is not None,
              out(p))
    args = ["-sid", user_sid, "-groups", "alice"] + (["-sid", device_sid] if device_sid else [])
    p = run(e, base + args, env=e.with_cache("alice"))
    check("LDAP: alice's SID is her entry", re.search(rf"^sid {re.escape(user_sid)}: CN=alice,.* \(alice\)$", p.stdout, re.M)
          is not None, out(p))
    if device_sid:
        check("LDAP: the PAC's device SID is goosepc$",
              re.search(rf"^sid {re.escape(device_sid)}: CN=goosepc,.* \(goosepc\$\)$", p.stdout, re.M) is not None, out(p))
    # tokenGroups and the PAC agree on the domain's groups (tokenGroups also
    # has builtin ones, the PAC the user's own SID and well-known ones).
    groups = re.findall(r"^sid (S-1-5-21-[\d-]+): ", p.stdout.split("account: ", 1)[-1], re.M)
    in_domain = lambda s: s.startswith(domain_sid + "-")
    want = sorted(s for s in pac_sids if in_domain(s) and s != user_sid)
    check("LDAP tokenGroups = the PAC's domain groups", p.returncode == 0 and sorted(filter(in_domain, groups)) == want,
          f"tokenGroups {sorted(groups)}\nPAC {want}\n" + out(p))


def trust_tests(e, tool, gss, realm, trust_pw, mit, alice_sids, domain_sid):
    """The realm trust with MIT's A.TEST (windows/trust.ps1), both ways."""
    with Kdc(mit=mit) as k:
        to_ad, to_mit = f"krbtgt/{realm}@{REALM_A}", f"krbtgt/{REALM_A}@{realm}"
        for p in (to_ad, to_mit):
            try:
                k.kadmin(REALM_A, f'addprinc -e "aes256-cts:normal aes128-cts:normal" -pw {trust_pw} {p}')
            except RuntimeError:
                raise RuntimeError(f"kadmin addprinc {p} failed") from None  # its message has the password
        # Both realms; without the [domain_realm] entry for A.TEST's hosts too.
        a = f"    {REALM_A} = {{\n        kdc = tcp/127.0.0.1:{k.port_a}\n    }}\n"
        conf = os.path.join(e.tmp, "trust.conf")
        noref = os.path.join(e.tmp, "trust-noref.conf")
        write_conf(conf, realm, e.domain, e.kdc, realms=a, domain_realm=f"    .a.test = {REALM_A}\n")
        write_conf(noref, realm, e.domain, e.kdc, realms=a)

        # AD's user to MIT's service: AD's referral TGT, MIT's ticket.
        p = run(e, [tool, "kinit", f"alice@{realm}"], e.pw + "\n", e.with_cache("t_alice", conf))
        p = run(e, [tool, "kvno", "host/svc.a.test"], env=e.with_cache("t_alice", conf))
        p2 = run(e, [tool, "klist"], env=e.with_cache("t_alice", conf))
        check(f"trust: alice@{realm} -> host/svc.a.test@{REALM_A} (AD's cross-realm TGT, MIT's ticket)",
              p.returncode == 0 and to_mit in p2.stdout, out(p) + out(p2))
        srv, port = start_server([gss, "server", "0", "-once", "-keytab", k.path("svc.keytab")], e.env)
        try:
            p = run(e, [gss, "client", "127.0.0.1", str(port), "host@svc.a.test", "hello"], env=e.with_cache("t_alice", conf))
        finally:
            log = stop_server(srv)
        bufs = pac_buffers(log) or []
        check("trust: our acceptor in A.TEST takes AD's alice; MIT's own PAC, AD's logon info dropped",
              p.returncode == 0 and f"accepted: alice@{realm}" in log and 10 in bufs and 1 not in bufs, log + out(p))
        run(e, [tool, "kinit", f"alice@{realm}"], e.pw + "\n", e.with_cache("t_alice2", noref))
        p = run(e, [tool, "kvno", "host/svc.a.test"], env=e.with_cache("t_alice2", noref))
        check("trust: no [domain_realm] for the MIT realm, no referral from AD", p.returncode == 1
              and "S_PRINCIPAL_UNKNOWN" in out(p), out(p))

        # MIT's users to AD's service. MIT (1.20 on) puts a PAC in every
        # ticket, and AD refuses a cross-realm TGT from an MIT realm with
        # one; the trust's principal says to leave it out.
        p = run(e, [tool, "kinit", f"alice@{REALM_A}"], "alice-pw\n", e.with_cache("t_m0", conf))
        p = run(e, [tool, "kvno", f"HTTP/web.{e.domain}"], env=e.with_cache("t_m0", conf))
        check("trust: AD refuses MIT's cross-realm TGT that carries MIT's PAC", p.returncode == 1
              and "KRB_ERR_GENERIC" in out(p), out(p))
        k.kadmin(REALM_A, f"modprinc +no_auth_data_required {to_ad}")
        p = run(e, [tool, "kinit", f"alice@{REALM_A}"], "alice-pw\n", e.with_cache("t_m1", conf))
        p = run(e, [tool, "kvno", f"HTTP/web.{e.domain}"], env=e.with_cache("t_m1", conf))
        p2 = run(e, [tool, "klist"], env=e.with_cache("t_m1", conf))
        check(f"trust: alice@{REALM_A} -> HTTP/web.{e.domain} (no PAC in MIT's cross-realm TGT)",
              p.returncode == 0 and to_ad in p2.stdout, out(p) + out(p2))
        p, log = serve_once(e, gss, e.keytab, [f"HTTP@web.{e.domain}", "hello"], e.with_cache("t_m1", conf))
        upn = re.search(r"^pac upn: sam=(\S+) sid=(\S+)$", log, re.M)
        groups = [s for s in alice_sids if s.startswith(domain_sid + "-") and s != (alice_sids[:1] or [""])[0]]
        sids = pac_lines(log, "pac sid")
        check("trust: AD's PAC for the mapped alice@A.TEST is mit-alice's (altSecurityIdentities), her groups",
              p.returncode == 0 and f"accepted: alice@{REALM_A}" in log and upn is not None and upn.group(1) == "mit-alice"
              and all(g in sids for g in groups), log + out(p))
        p = run(e, [tool, "kinit", f"bob@{REALM_A}"], "bob-pw\n", e.with_cache("t_m2", conf))
        p = run(e, [tool, "kvno", f"HTTP/web.{e.domain}"], env=e.with_cache("t_m2", conf))
        p, log = serve_once(e, gss, e.keytab, [f"HTTP@web.{e.domain}", "hello"], e.with_cache("t_m2", conf))
        check(f"trust: an unmapped bob@{REALM_A} gets a ticket with no PAC", p.returncode == 0
              and f"accepted: bob@{REALM_A}" in log and "pac: none" in log, log + out(p))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--keytab", required=True)
    ap.add_argument("--dc-host", required=True)
    ap.add_argument("--kdc", default="127.0.0.1:8888")
    ap.add_argument("--ldap", default="127.0.0.1:3890")
    ap.add_argument("--domain", default="goose.test")
    ap.add_argument("--trust-password-file")
    ap.add_argument("--mit")
    ap.add_argument("--goose")
    ap.add_argument("-k", help="only checks whose name contains this")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    interop.verbose = args.v
    interop.only = args.k
    goose = find_goose(args.goose)
    with open(args.password_file) as f:
        pw = f.readline().strip()
    realm = args.domain.upper()
    keytab = os.path.abspath(args.keytab)
    with tempfile.TemporaryDirectory() as tmp:
        tool = os.path.join(tmp, "krb5")
        gss = os.path.join(tmp, "gss")
        for src, exe in (("tools/krb5.goose", tool), ("tools/gss.goose", gss)):
            p = subprocess.run([goose, "build", "-o", exe, src], cwd=ROOT, capture_output=True, text=True)
            if p.returncode != 0:
                sys.exit(f"building {src} failed:\n{p.stdout}{p.stderr}")
        conf = os.path.join(tmp, "krb5.conf")
        rc4_conf = os.path.join(tmp, "krb5-rc4.conf")
        write_conf(conf, realm, args.domain, args.kdc)
        write_conf(rc4_conf, realm, args.domain, args.kdc,
                   "    default_tkt_enctypes = arcfour-hmac\n    default_tgs_enctypes = arcfour-hmac\n"
                   "    permitted_enctypes = arcfour-hmac\n    allow_weak_crypto = true\n")
        e = Env(tmp, conf)
        e.domain = args.domain
        e.pw = pw
        e.kdc = args.kdc
        e.keytab = keytab
        kinit_tests(e, tool, pw, keytab, realm, rc4_conf)
        kvno_tests(e, tool, keytab, realm)
        pac_sids, domain_sid = pac_tests(e, gss, keytab, realm)
        device_sid = compound_tests(e, tool, gss, keytab, realm, domain_sid)
        http_tests(e, gss, keytab)
        user_sid = pac_sids[0] if pac_sids else ""
        ldap_tests(e, gss, args.ldap, args.dc_host, user_sid, pac_sids, domain_sid, device_sid)
        if args.trust_password_file:
            with open(args.trust_password_file) as f:
                trust_pw = f.readline().strip()
            trust_tests(e, tool, gss, realm, trust_pw, args.mit, pac_sids, domain_sid)
    print(f"\n{interop.passed} passed, {len(interop.failed)} failed")
    sys.exit(1 if interop.failed else 0)


if __name__ == "__main__":
    main()
