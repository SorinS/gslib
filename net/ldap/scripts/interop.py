#!/usr/bin/env python3
"""The goose-ldap* tools against OpenLDAP, live.

Starts slapd (OpenLDAP 2.5 or later, run as you on free ports of
127.0.0.1, its socket and files in a temporary directory) with an mdb
database of test entries, TLS from a CA made here with openssl, and SASL
(EXTERNAL over ldapi and TLS client certificates, PLAIN, DIGEST-MD5).
Then runs each case with a goose tool and with OpenLDAP's tool of the same
name, and requires the same standard output, standard error and exit
status: searches of every kind over ldap://, ldaps://, StartTLS and
ldapi://, binds of every kind, whoami, compare and passwd. The tools that
write (ldapadd, ldapmodify, ldapdelete, ldapmodrdn) each change a subtree
of their own from the same input, and the two subtrees must end up the
same. go-ldap (tools/goldap) reads entries as goose-ldapsearch does. slapd
is stopped at the end, whatever happens.

    python3 scripts/interop.py [--goose PATH] [--openldap PREFIX] [-k NAME] [-v]

The compiler is --goose, else $GOOSE, else `goose` on PATH, else
../goose.git/build/goose. OpenLDAP is --openldap, else $OPENLDAP, else
Homebrew's (/opt/homebrew/opt/openldap), else what is on PATH.
"""

import argparse
import base64
import difflib
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS = os.path.join(ROOT, "tools")
PROGRAMS = ["ldapsearch", "ldapmodify", "ldapdelete", "ldapmodrdn", "ldapcompare", "ldapwhoami", "ldappasswd"]
SUFFIX = "dc=example,dc=com"
ADMIN = "cn=admin," + SUFFIX
ADMIN_PW = "secret"


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def find_openldap(arg):
    for prefix in [arg, os.environ.get("OPENLDAP"), "/opt/homebrew/opt/openldap", "/usr/local/opt/openldap", "/usr"]:
        if not prefix:
            continue
        slapd = None
        for d in ["libexec", "sbin", "lib/openldap"]:
            if os.path.isfile(os.path.join(prefix, d, "slapd")):
                slapd = os.path.join(prefix, d, "slapd")
        if slapd and os.path.isfile(os.path.join(prefix, "bin", "ldapsearch")):
            slapadd = os.path.join(prefix, "sbin", "slapadd")
            if not os.path.isfile(slapadd):
                slapadd = shutil.which("slapadd") or slapadd
            schema = None
            for s in [os.path.join(prefix, "etc", "openldap", "schema"), "/opt/homebrew/etc/openldap/schema",
                      "/usr/local/etc/openldap/schema", "/etc/openldap/schema", "/etc/ldap/schema"]:
                if os.path.isfile(os.path.join(s, "core.schema")):
                    schema = s
                    break
            if schema:
                return os.path.join(prefix, "bin"), slapd, slapadd, schema
    sys.exit("no OpenLDAP found: pass --openldap PREFIX or set OPENLDAP")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def b64(v):
    return base64.b64encode(v.encode() if isinstance(v, str) else v).decode()


def make_certs(d):
    def run(*a):
        subprocess.run(["openssl", *a], cwd=d, check=True, capture_output=True)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key",
        "-out", "ca.pem", "-days", "2", "-subj", "/O=Goose Test/CN=Goose Test CA")
    run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "server.key",
        "-out", "server.csr", "-subj", "/O=Goose Test/CN=localhost")
    with open(os.path.join(d, "server.ext"), "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth\n")
    run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem",
        "-days", "2", "-extfile", "server.ext")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "client.key", "-out", "client.csr", "-subj", "/O=Goose Test/CN=alice")
    with open(os.path.join(d, "client.ext"), "w") as f:
        f.write("extendedKeyUsage=clientAuth\n")
    run("x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "client.pem",
        "-days", "2", "-extfile", "client.ext")
    # A CA that signed nothing here, for the failures.
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "other.key",
        "-out", "other.pem", "-days", "2", "-subj", "/CN=Some Other CA")


def entries():
    """The test directory, as LDIF for slapadd."""
    out = []

    def entry(dn, *attrs):
        lines = ["dn: " + dn]
        for name, value in attrs:
            raw = value.encode() if isinstance(value, str) else value
            safe = raw and all(0x20 <= c < 0x7f for c in raw) and raw[:1] not in (b" ", b":", b"<") and raw[-1:] != b" "
            lines.append(f"{name}: {raw.decode()}" if safe else f"{name}:: {b64(raw)}")
        out.append("\n".join(lines) + "\n")

    entry(SUFFIX, ("objectClass", "dcObject"), ("objectClass", "organization"), ("o", "Example"), ("dc", "example"))
    entry("cn=admin," + SUFFIX, ("objectClass", "organizationalRole"), ("cn", "admin"))
    for ou in ["people", "groups", "goose", "openldap"]:
        entry(f"ou={ou},{SUFFIX}", ("objectClass", "organizationalUnit"), ("ou", ou))
    entry(f"uid=alice,ou=people,{SUFFIX}", ("objectClass", "inetOrgPerson"), ("uid", "alice"), ("cn", "Alice Liddell"),
          ("cn", "alice"), ("sn", "Liddell"), ("givenName", "Alice"), ("mail", "alice@example.com"),
          ("userPassword", "alicepw"), ("description", " leading space"), ("title", "trailing space "),
          ("displayName", "Zoë Ågren 日本"), ("telephoneNumber", "+1 555 0100"),
          ("jpegPhoto", bytes(range(256)) * 2), ("street", "line one\nline two"),
          ("postalAddress", ":colon first"), ("l", "<angle first"),
          ("labeledURI", "http://example.com/" + "x" * 150))
    entry(f"uid=bob,ou=people,{SUFFIX}", ("objectClass", "inetOrgPerson"), ("uid", "bob"), ("cn", "Bob Smith"),
          ("sn", "Smith"), ("mail", "bob@example.com"), ("userPassword", "bobpw"), ("employeeNumber", "42"),
          ("cn;lang-fr", "Robert"))
    entry(f"uid=carol,ou=people,{SUFFIX}", ("objectClass", "inetOrgPerson"), ("uid", "carol"), ("cn", "Carol (admin)"),
          ("sn", "Smyth"), ("mail", "carol@example.org"), ("userPassword", "carolpw"), ("employeeNumber", "7"),
          ("description", "a*b\\c"))
    for i in range(40):
        entry(f"uid=user{i:02d},ou=people,{SUFFIX}", ("objectClass", "inetOrgPerson"), ("uid", f"user{i:02d}"),
              ("cn", f"User {i:02d}"), ("sn", f"Number{i % 7}"), ("employeeNumber", str(100 + i)))
    entry(f"cn=staff,ou=groups,{SUFFIX}", ("objectClass", "groupOfNames"), ("cn", "staff"),
          ("member", f"uid=alice,ou=people,{SUFFIX}"), ("member", f"uid=bob,ou=people,{SUFFIX}"))
    entry(f"cn=to alice,ou=groups,{SUFFIX}", ("objectClass", "alias"), ("objectClass", "extensibleObject"),
          ("cn", "to alice"), ("aliasedObjectName", f"uid=alice,ou=people,{SUFFIX}"))
    entry(f"ou=elsewhere,{SUFFIX}", ("objectClass", "referral"), ("objectClass", "extensibleObject"), ("ou", "elsewhere"),
          ("ref", f"ldap://other.example.com/ou=elsewhere,{SUFFIX}"))
    entry(f"cn=a\\,b+sn=c\\+d,ou=people,{SUFFIX}", ("objectClass", "person"), ("cn", "a,b"), ("sn", "c+d"))
    return "\n".join(out)


def slapd_conf(d, schema, uid):
    return f"""include {schema}/core.schema
include {schema}/cosine.schema
include {schema}/inetorgperson.schema
pidfile {d}/slapd.pid
argsfile {d}/slapd.args
TLSCACertificateFile {d}/ca.pem
TLSCertificateFile {d}/server.pem
TLSCertificateKeyFile {d}/server.key
TLSVerifyClient try
sasl-secprops none
authz-regexp "^gidnumber=[0-9]+[+]uidnumber={uid},cn=peercred,cn=external,cn=auth$" "{ADMIN}"
authz-regexp "^cn=alice,o=goose test$" "uid=alice,ou=people,{SUFFIX}"
authz-regexp "^uid=([^,]+),(cn=[^,]+,)?cn=(plain|digest-md5),cn=auth$" "uid=$1,ou=people,{SUFFIX}"
database mdb
maxsize 33554432
suffix "{SUFFIX}"
rootdn "{ADMIN}"
rootpw {ADMIN_PW}
directory {d}/db
access to attrs=userPassword
    by self write
    by anonymous auth
    by * none
access to *
    by self write
    by users read
    by anonymous read
"""


class Run:
    def __init__(self, args):
        self.args = args
        self.passed = 0
        self.failed = []

    def check(self, name, ok, detail=""):
        if self.args.k and self.args.k not in name:
            return
        print(("ok    " if ok else "FAIL  ") + name)
        if ok:
            self.passed += 1
        else:
            self.failed.append(name)
            if detail:
                print("      " + detail.strip().replace("\n", "\n      "))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--openldap")
    ap.add_argument("-k", help="only cases whose name contains this")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    bindir, slapd, slapadd, schema = find_openldap(args.openldap)
    for p in PROGRAMS:
        r = subprocess.run([goose, "build", p + ".goose"], cwd=TOOLS, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"building {p}: {r.stdout}{r.stderr}")
    shutil.copy(os.path.join(TOOLS, "goose-ldapmodify"), os.path.join(TOOLS, "goose-ldapadd"))

    # Short: the ldapi socket's path must fit in sun_path.
    d = tempfile.mkdtemp(prefix="lg", dir="/tmp" if os.path.isdir("/tmp") else None)
    proc = None
    try:
        make_certs(d)
        os.makedirs(os.path.join(d, "db"))
        with open(os.path.join(d, "slapd.conf"), "w") as f:
            f.write(slapd_conf(d, schema, os.getuid()))
        with open(os.path.join(d, "data.ldif"), "w") as f:
            f.write(entries())
        r = subprocess.run([slapadd, "-f", os.path.join(d, "slapd.conf"), "-l", os.path.join(d, "data.ldif")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("slapadd: " + r.stdout + r.stderr)
        p_ldap, p_ldaps = free_port(), free_port()
        sock = os.path.join(d, "ldapi")
        ldapi = "ldapi://" + sock.replace("/", "%2F")
        urls = f"ldap://127.0.0.1:{p_ldap}/ ldaps://127.0.0.1:{p_ldaps}/ {ldapi}"
        log = open(os.path.join(d, "slapd.log"), "w")
        proc = subprocess.Popen([slapd, "-f", os.path.join(d, "slapd.conf"), "-h", urls, "-d", "0"],
                                stdout=log, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", p_ldap), 0.2).close()
                socket.create_connection(("127.0.0.1", p_ldaps), 0.2).close()
                if os.path.exists(sock):
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            sys.exit("slapd did not start: " + open(os.path.join(d, "slapd.log")).read())

        env = dict(os.environ)
        for k in list(env):
            if k.startswith("LDAP"):
                del env[k]
        open(os.path.join(d, "ldap.conf"), "w").close()
        env.update({"LDAPCONF": os.path.join(d, "ldap.conf"), "LDAPRC": "nonexistent-ldaprc", "HOME": d,
                    "LDAPTLS_CACERT": os.path.join(d, "ca.pem"), "LDAPTLS_REQCERT": "demand"})
        run = Run(args)
        cases(run, d, bindir, env, p_ldap, p_ldaps, ldapi)
        print(f"\n{run.passed} passed, {len(run.failed)} failed")
        return 1 if run.failed else 0
    finally:
        if proc:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(d, ignore_errors=True)


def cases(run, d, bindir, env, p_ldap, p_ldaps, ldapi):
    H = f"ldap://127.0.0.1:{p_ldap}"
    # OpenLDAP's own client checks a server certificate against a name
    # from the address it reached, and so fails on localhost now and then;
    # the certificate names 127.0.0.1 too.
    HS = f"ldaps://127.0.0.1:{p_ldaps}"
    HL = f"ldap://127.0.0.1:{p_ldap}"
    client = dict(env, LDAPTLS_CERT=os.path.join(d, "client.pem"), LDAPTLS_KEY=os.path.join(d, "client.key"))
    pwfile = os.path.join(d, "pw")
    with open(pwfile, "w") as f:
        f.write(ADMIN_PW)
    os.chmod(pwfile, 0o600)

    def tool(which, prog, argv, e=None, stdin=None):
        exe = os.path.join(TOOLS, "goose-" + prog) if which == "goose" else os.path.join(bindir, prog)
        r = subprocess.run([exe, *argv], env=e or env, input=stdin, capture_output=True, timeout=60)
        # OpenLDAP 2.7 puts its log's time and thread before some messages.
        err = re.sub(rb"(?m)^[0-9a-f]+\.[0-9a-f]+ 0x[0-9a-f]+ ", b"", r.stderr)
        return r.returncode, r.stdout, err

    def same(name, prog, argv, e=None, stdin=None, normalize=None):
        if run.args.k and run.args.k not in name:
            return (0, b"", b"")
        g = tool("goose", prog, argv, e, stdin)
        o = tool("openldap", prog, argv, e, stdin)
        if normalize:
            g = (g[0], normalize(g[1]), normalize(g[2]))
            o = (o[0], normalize(o[1]), normalize(o[2]))
        ok = g == o
        detail = ""
        if not ok:
            detail = f"exit {g[0]} / OpenLDAP {o[0]}\n"
            for label, a, b in [("stdout", g[1], o[1]), ("stderr", g[2], o[2])]:
                if a != b:
                    diff = difflib.unified_diff(b.decode(errors="replace").splitlines(), a.decode(errors="replace").splitlines(),
                                                "OpenLDAP " + label, "goose " + label, lineterm="", n=1)
                    detail += "\n".join(list(diff)[:40]) + "\n"
        run.check(name, ok, detail)
        return g

    admin = ["-x", "-D", ADMIN, "-w", ADMIN_PW]
    base = ["-b", SUFFIX]

    # --- Searches, over each transport -------------------------------------------------
    filters = [
        "(objectClass=*)", "(uid=alice)", "(cn=Alice*)", "(cn=*Smith)", "(cn=*o*)", "(sn=Sm*th)", "(!(uid=user*))",
        "(&(objectClass=inetOrgPerson)(|(sn=Smith)(sn=Smyth)))", "(employeeNumber>=42)", "(employeeNumber<=7)",
        "(sn~=Smith)", "(cn:caseExactMatch:=Bob Smith)", "(ou:dn:=people)", "(description=a\\2ab\\5cc)",
        "(displayName=Zo\\c3\\ab*)", "(cn;lang-fr=Robert)", "(|)", "(&)", "(uid=nobody)", "(mail=*@example.org)",
        "(cn=Carol \\28admin\\29)", "uid=bob",
    ]
    transports = [("ldap", ["-H", H]), ("ldaps", ["-H", HS]), ("starttls", ["-H", HL, "-ZZ"]),
                  ("ldapi", ["-H", ldapi, "-Y", "EXTERNAL", "-Q"])]
    for tname, targs in transports:
        auth = admin if tname != "ldapi" else []
        for i, f in enumerate(filters):
            same(f"search {tname} filter {i} {f}", "ldapsearch", [*targs, *auth, *base, "-LLL", f])
        same(f"search {tname} default output", "ldapsearch", [*targs, *auth, *base, "(uid=alice)"])
    for lvl in ["", "-L", "-LL", "-LLL"]:
        same(f"search output {lvl or 'extended'}", "ldapsearch", ["-H", H, *admin, *base, *([lvl] if lvl else []), "(uid=bob)", "cn", "mail"])
        same(f"search output {lvl or 'extended'} values that need base64", "ldapsearch", ["-H", H, *admin, *base, *([lvl] if lvl else []), "(uid=alice)"])
    for scope in ["base", "one", "sub", "children"]:
        same(f"search scope {scope}", "ldapsearch", ["-H", H, "-x", "-b", "ou=people," + SUFFIX, "-s", scope, "-LLL", "(objectClass=*)", "1.1"])
    for attrs in [["*"], ["+"], ["1.1"], ["cn", "mail", "nonexistent"], ["*", "+"], ["CN", "Mail"]]:
        same(f"search attributes {' '.join(attrs)}", "ldapsearch", ["-H", H, *admin, *base, "-LLL", "(uid=bob)", *attrs])
    same("search types only", "ldapsearch", ["-H", H, *admin, *base, "-A", "(uid=alice)"])
    same("search no wrapping", "ldapsearch", ["-H", H, *admin, *base, "-LLL", "-o", "ldif_wrap=no", "(uid=alice)"])
    same("search wrap at 40", "ldapsearch", ["-H", H, *admin, *base, "-LLL", "-o", "ldif_wrap=40", "(uid=alice)"])
    same("search size limit", "ldapsearch", ["-H", H, "-x", *base, "-z", "3", "(uid=user*)", "uid"])
    same("search size limit LLL", "ldapsearch", ["-H", H, "-x", *base, "-z", "3", "-LLL", "(uid=user*)", "uid"])
    same("search time limit", "ldapsearch", ["-H", H, "-x", *base, "-l", "10", "-LLL", "(uid=bob)", "uid"])
    for p in ["7", "1", "100"]:
        same(f"search paged {p}", "ldapsearch", ["-H", H, "-x", "-b", "ou=people," + SUFFIX, "-E", f"pr={p}/noprompt", "(uid=user*)", "uid"])
        same(f"search paged {p} LLL", "ldapsearch", ["-H", H, "-x", "-b", "ou=people," + SUFFIX, "-LLL", "-E", f"pr={p}/noprompt", "(uid=user*)", "uid"])
    same("search sort (not critical)", "ldapsearch", ["-H", H, "-x", *base, "-LLL", "-E", "sss=sn/-uid", "(uid=user0*)", "uid"])
    same("search sort (critical)", "ldapsearch", ["-H", H, "-x", *base, "-LLL", "-E", "!sss=sn", "(uid=user0*)", "uid"])
    for deref in ["never", "search", "find", "always"]:
        same(f"search deref {deref}", "ldapsearch", ["-H", H, "-x", "-b", "ou=groups," + SUFFIX, "-a", deref, "-LLL", "(objectClass=*)", "uid", "cn"])
        same(f"search deref {deref} base on the alias", "ldapsearch", ["-H", H, "-x", "-b", "cn=to alice,ou=groups," + SUFFIX, "-s", "base", "-a", deref, "-LLL", "(objectClass=*)", "uid"])
    same("search referral", "ldapsearch", ["-H", H, "-x", "-b", "ou=elsewhere," + SUFFIX, "(objectClass=*)"])
    same("search referral LLL", "ldapsearch", ["-H", H, "-x", "-b", "ou=elsewhere," + SUFFIX, "-LLL", "(objectClass=*)"])
    same("search references", "ldapsearch", ["-H", H, "-x", *base, "-s", "one", "(ou=*)", "ou"])
    same("search ManageDsaIT", "ldapsearch", ["-H", H, "-x", "-M", "-b", "ou=elsewhere," + SUFFIX, "-LLL", "(objectClass=*)"])
    same("search no such object", "ldapsearch", ["-H", H, "-x", "-b", "ou=nowhere," + SUFFIX, "(objectClass=*)"])
    same("search no such object LLL", "ldapsearch", ["-H", H, "-x", "-b", "ou=nowhere," + SUFFIX, "-LLL", "(objectClass=*)"])
    same("search invalid DN", "ldapsearch", ["-H", H, "-x", "-b", "not a dn", "-LLL", "(objectClass=*)"])
    same("search bad filter", "ldapsearch", ["-H", H, "-x", *base, "(cn=a"])
    same("search undefined attribute in filter", "ldapsearch", ["-H", H, "-x", *base, "-LLL", "(frobnicate=1)"])
    same("search root DSE", "ldapsearch", ["-H", H, "-x", "-b", "", "-s", "base", "-LLL", "namingContexts", "supportedLDAPVersion"])
    same("search DN with escapes", "ldapsearch", ["-H", H, "-x", "-b", "cn=a\\,b+sn=c\\+d,ou=people," + SUFFIX, "-s", "base", "(objectClass=*)"])
    same("search assertion control true", "ldapsearch", ["-H", H, *admin, "-b", "uid=bob,ou=people," + SUFFIX, "-s", "base", "-e", "assert=(sn=Smith)", "-LLL", "(objectClass=*)", "uid"])
    same("search assertion control false", "ldapsearch", ["-H", H, *admin, "-b", "uid=bob,ou=people," + SUFFIX, "-s", "base", "-e", "assert=(sn=Jones)", "-LLL", "(objectClass=*)", "uid"])
    same("search proxied authorization", "ldapsearch", ["-H", H, *admin, "-e", "!authzid=dn:uid=bob,ou=people," + SUFFIX, "-b", "uid=alice,ou=people," + SUFFIX, "-s", "base", "-LLL", "(objectClass=*)", "userPassword", "uid"])

    # --- Binds and who am I ----------------------------------------------------------------
    binds = [
        ("anonymous", ["-H", H, "-x"], env),
        ("simple", ["-H", H, *admin], env),
        ("simple from a file", ["-H", H, "-x", "-D", ADMIN, "-y", pwfile], env),
        ("user", ["-H", H, "-x", "-D", "uid=bob,ou=people," + SUFFIX, "-w", "bobpw"], env),
        ("wrong password", ["-H", H, "-x", "-D", ADMIN, "-w", "wrong"], env),
        ("no such user", ["-H", H, "-x", "-D", "uid=nobody,ou=people," + SUFFIX, "-w", "x"], env),
        ("unauthenticated", ["-H", H, "-x", "-D", ADMIN], env),
        ("ldaps simple", ["-H", HS, *admin], env),
        ("starttls simple", ["-H", HL, "-ZZ", *admin], env),
        ("starttls over ldapi", ["-H", ldapi, "-ZZ", "-x"], dict(env, LDAPTLS_REQCERT="never")),
        ("EXTERNAL over ldapi", ["-H", ldapi, "-Y", "EXTERNAL", "-Q"], env),
        ("EXTERNAL with a client certificate", ["-H", HS, "-Y", "EXTERNAL", "-Q"], client),
        ("EXTERNAL with a certificate and StartTLS", ["-H", HL, "-ZZ", "-Y", "EXTERNAL", "-Q"], client),
        ("EXTERNAL with an authzid", ["-H", ldapi, "-Y", "EXTERNAL", "-Q", "-X", "dn:uid=carol,ou=people," + SUFFIX], env),
        ("PLAIN", ["-H", HS, "-Y", "PLAIN", "-Q", "-U", "alice", "-w", "alicepw"], env),
        ("PLAIN wrong password", ["-H", HS, "-Y", "PLAIN", "-Q", "-U", "alice", "-w", "nope"], env),
        ("DIGEST-MD5", ["-H", H, "-Y", "DIGEST-MD5", "-Q", "-U", "bob", "-w", "bobpw"], env),
        ("DIGEST-MD5 wrong password", ["-H", H, "-Y", "DIGEST-MD5", "-Q", "-U", "bob", "-w", "nope"], env),
        ("unknown mechanism", ["-H", H, "-Y", "FROBNICATE", "-Q"], env),
    ]
    for name, argv, e in binds:
        g = same(f"whoami {name}", "ldapwhoami", argv, e)
    same("whoami ldapi EXTERNAL search", "ldapsearch", ["-H", ldapi, "-Y", "EXTERNAL", "-Q", *base, "-LLL", "(uid=alice)", "userPassword"])

    # TLS failures: both refuse; the messages are each library's own.
    def refuses(name, prog, argv, e):
        g = tool("goose", prog, argv, e)
        o = tool("openldap", prog, argv, e)
        run.check(name, g[0] != 0 and o[0] != 0, f"exit {g[0]} / OpenLDAP {o[0]}: {g[2].decode(errors='replace')}")
    other = dict(env, LDAPTLS_CACERT=os.path.join(d, "other.pem"))
    refuses("ldaps refused: unknown CA", "ldapwhoami", ["-H", HS, "-x"], other)
    refuses("starttls refused: unknown CA", "ldapwhoami", ["-H", HL, "-ZZ", "-x"], other)
    g = tool("goose", "ldapwhoami", ["-H", HS, "-x"], dict(other, LDAPTLS_REQCERT="never"))
    run.check("ldaps with checking off", g[0] == 0 and g[1] == b"anonymous\n", g[2].decode(errors="replace"))
    refuses("connect refused", "ldapwhoami", ["-H", "ldap://127.0.0.1:1", "-x"], env)
    same("connect refused message", "ldapsearch", ["-H", "ldap://127.0.0.1:1", "-x", *base])

    # --- Compare -------------------------------------------------------------------------
    for name, argv in [("true", ["uid=bob,ou=people," + SUFFIX, "sn:Smith"]), ("false", ["uid=bob,ou=people," + SUFFIX, "sn:Jones"]),
                       ("base64", ["uid=alice,ou=people," + SUFFIX, "displayName::" + b64("Zoë Ågren 日本")]),
                       ("no such object", ["uid=nobody,ou=people," + SUFFIX, "sn:x"]),
                       ("undefined attribute", ["uid=bob,ou=people," + SUFFIX, "frobnicate:x"]),
                       ("no such attribute", ["uid=bob,ou=people," + SUFFIX, "title:x"]),
                       ("quiet", ["-z", "uid=bob,ou=people," + SUFFIX, "sn:Smith"])]:
        same(f"compare {name}", "ldapcompare", ["-H", H, *admin, *argv])

    # --- Writes: the same input to each tool, each in its own subtree ---------------------------
    def sub(text, who):
        return text.replace("ou=TREE", f"ou={who}")

    def dump(who):
        r = subprocess.run([os.path.join(bindir, "ldapsearch"), "-H", H, *admin, "-b", f"ou={who},{SUFFIX}", "-LLL",
                            "-o", "ldif_wrap=no", "(objectClass=*)", "*"], env=env, capture_output=True)
        # The entries in order, with the subtree's name made the same.
        blocks = [b for b in r.stdout.decode(errors="replace").replace(f"ou={who},", "ou=TREE,").split("\n\n") if b.strip()]
        blocks = [b.replace(f"ou: {who}", "ou: TREE") for b in blocks]
        return r.returncode, sorted(blocks)

    def write_case(name, prog, argv, stdin=None, files=None):
        outs = {}
        for which, who in [("goose", "goose"), ("openldap", "openldap")]:
            a = [sub(x, who) for x in argv]
            if files:
                for fname, text in files.items():
                    with open(os.path.join(d, f"{who}-{fname}"), "w" if isinstance(text, str) else "wb") as f:
                        f.write(sub(text, who) if isinstance(text, str) else text)
                a = [x.replace("FILE:", os.path.join(d, f"{who}-")) for x in a]
            s = sub(stdin, who).encode() if stdin else None
            r = tool(which, prog, a, None, s)
            outs[which] = (r[0], r[1].decode(errors="replace").replace(f"ou={who},", "ou=TREE,"),
                           r[2].decode(errors="replace").replace(f"ou={who},", "ou=TREE,"))
        ok = outs["goose"] == outs["openldap"]
        run.check(f"{prog} {name}", ok, f"goose: {outs['goose']}\nOpenLDAP: {outs['openldap']}")
        g, o = dump("goose"), dump("openldap")
        run.check(f"{prog} {name}: the same directory after", g == o,
                  "\n".join(x for x in set(g[1]) ^ set(o[1]))[:3000])

    photo = os.path.join(d, "photo.bin")
    with open(photo, "wb") as f:
        f.write(bytes(range(256)))
    adds = """dn: cn=one,ou=TREE,dc=example,dc=com
objectClass: person
cn: one
sn: First
description:: w6lsw6huZQ==
description: second value

dn: cn=two,ou=TREE,dc=example,dc=com
objectclass: inetOrgPerson
cn: two
sn: Second
jpegPhoto:< file://PHOTO
mail: two@example.com
mail: deux@example.com
telephoneNumber: +1 555
 0199

dn: ou=sub,ou=TREE,dc=example,dc=com
objectClass: organizationalUnit
ou: sub

dn: cn=three,ou=sub,ou=TREE,dc=example,dc=com
objectClass: person
cn: three
sn: Third
""".replace("PHOTO", photo)
    write_case("add entries", "ldapadd", ["-H", H, *admin], adds)
    write_case("add existing", "ldapadd", ["-H", H, *admin], adds)
    write_case("add existing, continue", "ldapadd", ["-H", H, *admin, "-c"], adds)
    write_case("modify", "ldapmodify", ["-H", H, *admin, "-f", "FILE:mods.ldif"], files={"mods.ldif": """dn: cn=one,ou=TREE,dc=example,dc=com
changetype: modify
replace: sn
sn: Uno
-
add: telephoneNumber
telephoneNumber: +1 555 0001
telephoneNumber: +1 555 0002
-
delete: description
description: second value
-

dn: cn=two,ou=TREE,dc=example,dc=com
changetype: modify
delete: jpegPhoto
-
replace: mail
mail: two@example.net

"""})
    write_case("a plain record without -a", "ldapmodify", ["-H", H, *admin], """dn: cn=three,ou=sub,ou=TREE,dc=example,dc=com
sn: Tres
description: replaced
""")
    write_case("modify errors", "ldapmodify", ["-H", H, *admin, "-c"], """dn: cn=missing,ou=TREE,dc=example,dc=com
changetype: modify
replace: sn
sn: x

dn: cn=one,ou=TREE,dc=example,dc=com
changetype: modify
add: frobnicate
frobnicate: x

dn: cn=one,ou=TREE,dc=example,dc=com
changetype: modify
delete: mail
-

dn: cn=one,ou=TREE,dc=example,dc=com
changetype: modify
add: sn
sn: Uno
""")
    write_case("modify stops at the first error", "ldapmodify", ["-H", H, *admin], """dn: cn=missing,ou=TREE,dc=example,dc=com
changetype: delete

dn: cn=one,ou=TREE,dc=example,dc=com
changetype: modify
replace: description
description: never
""")
    write_case("modify as a user who may not", "ldapmodify", ["-H", H, "-x", "-D", "uid=bob,ou=people," + SUFFIX, "-w", "bobpw"], """dn: cn=one,ou=TREE,dc=example,dc=com
changetype: modify
replace: sn
sn: Bob was here
""")
    write_case("modrdn records", "ldapmodify", ["-H", H, *admin], """dn: cn=two,ou=TREE,dc=example,dc=com
changetype: modrdn
newrdn: cn=deux
deleteoldrdn: 1

dn: cn=one,ou=TREE,dc=example,dc=com
changetype: moddn
newrdn: cn=un
deleteoldrdn: 0
newsuperior: ou=sub,ou=TREE,dc=example,dc=com
""")
    write_case("change records with controls", "ldapmodify", ["-H", H, *admin], """dn: ou=sub,ou=TREE,dc=example,dc=com
control: 2.16.840.1.113730.3.4.2 false
changetype: modify
replace: description
description: managed
""")
    write_case("ldapmodrdn", "ldapmodrdn", ["-H", H, *admin, "-r", "cn=deux,ou=TREE,dc=example,dc=com", "cn=two"])
    write_case("ldapmodrdn to a new superior", "ldapmodrdn", ["-H", H, *admin, "-s", "ou=TREE,dc=example,dc=com", "cn=un,ou=sub,ou=TREE,dc=example,dc=com", "cn=one"])
    write_case("ldapmodrdn no such object", "ldapmodrdn", ["-H", H, *admin, "cn=missing,ou=TREE,dc=example,dc=com", "cn=x"])
    write_case("ldapmodrdn from input", "ldapmodrdn", ["-H", H, *admin], "cn=two,ou=TREE,dc=example,dc=com\ncn=zwei\n")
    write_case("ldapdelete", "ldapdelete", ["-H", H, *admin, "cn=zwei,ou=TREE,dc=example,dc=com"])
    write_case("ldapdelete no such object", "ldapdelete", ["-H", H, *admin, "cn=zwei,ou=TREE,dc=example,dc=com"])
    write_case("ldapdelete a non-leaf", "ldapdelete", ["-H", H, *admin, "ou=sub,ou=TREE,dc=example,dc=com"])
    write_case("ldapdelete recursively", "ldapdelete", ["-H", H, *admin, "-r", "ou=sub,ou=TREE,dc=example,dc=com"])
    write_case("ldapdelete from input, continue", "ldapdelete", ["-H", H, *admin, "-c"], "cn=missing,ou=TREE,dc=example,dc=com\ncn=one,ou=TREE,dc=example,dc=com\n")
    write_case("add again over ldaps", "ldapadd", ["-H", HS, *admin], adds)
    write_case("delete over ldapi", "ldapdelete", ["-H", ldapi, "-Y", "EXTERNAL", "-Q", "-r", "cn=one,ou=TREE,dc=example,dc=com"])
    write_case("bad LDIF", "ldapmodify", ["-H", H, *admin], "dn: cn=x,ou=TREE,dc=example,dc=com\nchangetype: frobnicate\n")

    # --- Passwords -------------------------------------------------------------------------
    same("passwd as admin", "ldappasswd", ["-H", H, *admin, "-s", "newbob", "uid=bob,ou=people," + SUFFIX])
    same("whoami with the new password", "ldapwhoami", ["-H", H, "-x", "-D", "uid=bob,ou=people," + SUFFIX, "-w", "newbob"])
    same("passwd own, old one wrong", "ldappasswd", ["-H", H, "-x", "-D", "uid=carol,ou=people," + SUFFIX, "-w", "carolpw", "-a", "wrong", "-s", "x"])
    same("passwd own", "ldappasswd", ["-H", H, "-x", "-D", "uid=carol,ou=people," + SUFFIX, "-w", "carolpw", "-a", "carolpw", "-s", "carolpw"])
    same("passwd not allowed", "ldappasswd", ["-H", H, "-x", "-D", "uid=bob,ou=people," + SUFFIX, "-w", "newbob", "-s", "x", "uid=carol,ou=people," + SUFFIX])
    same("passwd no such user", "ldappasswd", ["-H", H, *admin, "-s", "x", "uid=nobody,ou=people," + SUFFIX])
    for which in ["goose", "openldap"]:
        r = tool(which, "ldappasswd", ["-H", H, *admin, "uid=user00,ou=people," + SUFFIX])
        m = re.fullmatch(rb"New password: (\S+)\n", r[1])
        run.check(f"passwd generated ({which})", r[0] == 0 and m is not None, repr(r))
        if m:
            w = tool(which, "ldapwhoami", ["-H", H, "-x", "-D", "uid=user00,ou=people," + SUFFIX, "-w", m.group(1).decode()])
            run.check(f"bind with the generated password ({which})", w[0] == 0 and w[1].startswith(b"dn:uid=user00"), repr(w))

    # --- go-ldap reads what goose-ldapsearch reads ---------------------------------------------------
    goldap = os.path.join(TOOLS, "goldap.sh")
    for f in ["(uid=alice)", "(objectClass=inetOrgPerson)", "(cn=a\\2cb)"]:
        # Go's own environment: its module cache is under the real $HOME.
        go = subprocess.run([goldap, "search", H, SUFFIX, f, ADMIN, ADMIN_PW], capture_output=True, timeout=300)
        mine = tool("goose", "ldapsearch", ["-H", H, *admin, *base, "-LLL", "-o", "ldif_wrap=no", f])
        lines = []
        for block in mine[1].decode().split("\n\n"):
            if not block.strip():
                continue
            attrs = []
            dn = ""
            for ln in block.split("\n"):
                if not ln:
                    continue
                name, _, rest = ln.partition(":")
                if rest.startswith(":"):
                    v = base64.b64decode(rest[1:].strip())
                else:
                    v = rest[1:].encode() if rest.startswith(" ") else rest.encode()
                if name == "dn":
                    dn = v.decode()
                else:
                    attrs.append((name, v.hex()))
            lines.append("dn: " + dn)
            # go-ldap's order: names sorted, values as they came.
            for name in sorted(dict.fromkeys(a for a, _ in attrs)):
                for a, v in attrs:
                    if a == name:
                        lines.append(f"{a}: {v}")
        want = go.stdout.decode().splitlines()
        run.check(f"go-ldap reads the same {f}", go.returncode == 0 and lines == want and len(want) > 0,
                  f"exit {go.returncode}\ngo-ldap: {want[:6]}\ngoose: {lines[:6]}\n{go.stderr.decode()[-500:]}")


if __name__ == "__main__":
    sys.exit(main())
