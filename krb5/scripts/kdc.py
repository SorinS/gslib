#!/usr/bin/env python3
"""MIT KDCs for krb5's tests, on 127.0.0.1 only.

Two realms, A.TEST and B.TEST, served by one krb5kdc, each on its own
loopback port (UDP and TCP), trusting each other both ways (the
cross-realm krbtgt keys are in both databases). In A.TEST:

    alice     password "alice-pw", aes and sha2 and rc4 keys
    bob       password "bob-pw", pre-authentication required
    carol     password "carol-pw", rc4-hmac keys only
    dave      password "dave-pw", des3 keys only
    frank     password "frank-pw", camellia keys only, pre-authentication required
    host/svc.a.test, HTTP/svc.a.test   random keys, in svc.keytab
    host/cam.a.test   random camellia keys only, in svc.keytab
    alice's alias "alice-alias"
In B.TEST:
    HTTP/web.b.test   random key, in web.keytab
    erin       password "erin-pw"
In F.TEST, served by a second krb5kdc whose encrypted-timestamp module is
disabled ([plugins] kdcpreauth), so that a password works only through
FAST's encrypted challenge:
    grace      password "grace-pw", pre-authentication required
    heidi      password "heidi-pw", camellia keys only, pre-authentication required
    host/fast.f.test   random aes keys, in fast.keytab (its TGT is the armor;
                       no pre-authentication, so a keytab gets it unarmored)
    HTTP/svc.f.test    random key

Used by scripts/interop.py (`with Kdc() as k: ... k.env`), or run alone
to keep the KDCs up until Ctrl-C:

    python3 scripts/kdc.py [--dir DIR]

MIT's binaries are Homebrew's keg-only krb5 (brew --prefix krb5) unless
--mit names another prefix; the PATH's kinit on macOS is Heimdal's.
"""

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

REALM_A = "A.TEST"
REALM_B = "B.TEST"
REALM_F = "F.TEST"
ENCTYPES = ("aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal "
            "aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal "
            "arcfour-hmac:normal camellia256-cts-cmac:normal camellia128-cts-cmac:normal")


def mit_prefix(arg=None):
    if arg:
        return arg
    try:
        p = subprocess.run(["brew", "--prefix", "krb5"], capture_output=True, text=True, check=True).stdout.strip()
        if p and os.path.isdir(p):
            return p
    except (OSError, subprocess.CalledProcessError):
        pass
    for p in ("/opt/homebrew/opt/krb5", "/usr/local/opt/krb5", "/usr"):
        if os.path.exists(os.path.join(p, "sbin", "krb5kdc")):
            return p
    sys.exit("no MIT krb5 found: pass --mit PREFIX")


def free_port():
    # A port free for both UDP and TCP on 127.0.0.1.
    for _ in range(100):
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.bind(("127.0.0.1", 0))
        port = t.getsockname()[1]
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            u.close()
            t.close()
    raise RuntimeError("no free port")


class Kdc:
    def __init__(self, directory=None, mit=None, quiet=True, time_offset=0):
        self.mit = mit_prefix(mit)
        self.own_dir = directory is None
        self.dir = directory or tempfile.mkdtemp(prefix="krb5kdc-")
        self.quiet = quiet
        self.proc = None
        self.proc_f = None
        self.port_a = free_port()
        self.port_b = free_port()
        self.port_f = free_port()
        self.env = None
        self.time_offset = time_offset

    def bin(self, name):
        for sub in ("sbin", "bin"):
            p = os.path.join(self.mit, sub, name)
            if os.path.exists(p):
                return p
        raise FileNotFoundError(name)

    def path(self, name):
        return os.path.join(self.dir, name)

    def run(self, args, stdin=None, env=None):
        p = subprocess.run(args, env=env or self.env, input=stdin, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"{' '.join(args)}: {p.stdout}{p.stderr}")
        return p.stdout

    def kadmin(self, realm, query):
        return self.run([self.bin("kadmin.local"), "-r", realm, "-q", query],
                        env=self.env_f if realm == REALM_F else None)

    def write_conf(self):
        d = self.dir
        with open(self.path("krb5.conf"), "w") as f:
            f.write(f"""[libdefaults]
    default_realm = {REALM_A}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    allow_weak_crypto = true
    allow_rc4 = true
    allow_des3 = true
    permitted_enctypes = aes256-cts aes128-cts aes256-sha2 aes128-sha2 rc4-hmac des3-cbc-sha1 camellia256-cts-cmac camellia128-cts-cmac

[realms]
    {REALM_A} = {{
        kdc = 127.0.0.1:{self.port_a}
    }}
    {REALM_B} = {{
        kdc = 127.0.0.1:{self.port_b}
    }}
    {REALM_F} = {{
        kdc = 127.0.0.1:{self.port_f}
    }}

[domain_realm]
    .a.test = {REALM_A}
    a.test = {REALM_A}
    .b.test = {REALM_B}
    b.test = {REALM_B}
    .f.test = {REALM_F}
    f.test = {REALM_F}
""")
        with open(self.path("kdc.conf"), "w") as f:
            f.write(f"""[kdcdefaults]
    kdc_listen = 127.0.0.1:{self.port_a}
    kdc_tcp_listen = 127.0.0.1:{self.port_a}

[realms]
    {REALM_A} = {{
        database_name = {d}/a/principal
        key_stash_file = {d}/a/stash
        acl_file = {d}/a/kadm5.acl
        kdc_listen = 127.0.0.1:{self.port_a}
        kdc_tcp_listen = 127.0.0.1:{self.port_a}
        kadmind_listen = 127.0.0.1:{free_port()}
        kpasswd_listen = 127.0.0.1:{free_port()}
        master_key_type = aes256-cts
        supported_enctypes = {ENCTYPES} des3-cbc-sha1:normal
        max_life = 10h
        max_renewable_life = 7d
    }}
    {REALM_B} = {{
        database_name = {d}/b/principal
        key_stash_file = {d}/b/stash
        acl_file = {d}/b/kadm5.acl
        kdc_listen = 127.0.0.1:{self.port_b}
        kdc_tcp_listen = 127.0.0.1:{self.port_b}
        kadmind_listen = 127.0.0.1:{free_port()}
        kpasswd_listen = 127.0.0.1:{free_port()}
        master_key_type = aes256-cts
        supported_enctypes = {ENCTYPES}
        max_life = 10h
        max_renewable_life = 7d
    }}

[logging]
    kdc = FILE:{d}/kdc.log
""")
        with open(self.path("kdc-f.conf"), "w") as f:
            f.write(f"""[kdcdefaults]
    kdc_listen = 127.0.0.1:{self.port_f}
    kdc_tcp_listen = 127.0.0.1:{self.port_f}

[realms]
    {REALM_F} = {{
        database_name = {d}/f/principal
        key_stash_file = {d}/f/stash
        acl_file = {d}/f/kadm5.acl
        kdc_listen = 127.0.0.1:{self.port_f}
        kdc_tcp_listen = 127.0.0.1:{self.port_f}
        kadmind_listen = 127.0.0.1:{free_port()}
        kpasswd_listen = 127.0.0.1:{free_port()}
        master_key_type = aes256-cts
        supported_enctypes = {ENCTYPES}
        max_life = 10h
        max_renewable_life = 7d
    }}

[plugins]
    kdcpreauth = {{
        disable = encrypted_timestamp
    }}

[logging]
    kdc = FILE:{d}/kdc-f.log
""")
        self.env_f = dict(os.environ, KRB5_CONFIG=self.path("krb5.conf"), KRB5_KDC_PROFILE=self.path("kdc-f.conf"))
        self.env = dict(os.environ, KRB5_CONFIG=self.path("krb5.conf"), KRB5_KDC_PROFILE=self.path("kdc.conf"),
                        KRB5CCNAME="FILE:" + self.path("ccache"), KRB5_TRACE=self.path("trace.log"))

    def create(self):
        for sub in ("a", "b", "f"):
            os.makedirs(self.path(sub), exist_ok=True)
            open(self.path(f"{sub}/kadm5.acl"), "w").close()
        self.run([self.bin("kdb5_util"), "-r", REALM_A, "create", "-s", "-P", "master-a"])
        self.run([self.bin("kdb5_util"), "-r", REALM_B, "create", "-s", "-P", "master-b"])
        self.run([self.bin("kdb5_util"), "-r", REALM_F, "create", "-s", "-P", "master-f"], env=self.env_f)
        a, b = REALM_A, REALM_B
        self.kadmin(a, "addprinc -pw alice-pw alice")
        self.kadmin(a, "addprinc -pw bob-pw +requires_preauth bob")
        self.kadmin(a, "addprinc -pw carol-pw -e arcfour-hmac:normal carol")
        self.kadmin(a, "addprinc -pw dave-pw -e des3-cbc-sha1:normal dave")
        self.kadmin(a, "addprinc -pw frank-pw +requires_preauth "
                       "-e camellia256-cts-cmac:normal,camellia128-cts-cmac:normal frank")
        self.kadmin(a, "addprinc -randkey host/svc.a.test")
        self.kadmin(a, "addprinc -randkey HTTP/svc.a.test")
        self.kadmin(a, "addprinc -randkey -e camellia256-cts-cmac:normal,camellia128-cts-cmac:normal host/cam.a.test")
        self.kadmin(a, f"ktadd -k {self.path('svc.keytab')} host/svc.a.test HTTP/svc.a.test")
        self.kadmin(a, f"ktadd -k {self.path('svc.keytab')} -e camellia256-cts-cmac:normal,camellia128-cts-cmac:normal "
                       "host/cam.a.test")
        try:
            self.kadmin(a, "add_alias alice-alias alice")
            self.alias = True
        except RuntimeError:
            self.alias = False
        self.kadmin(b, "addprinc -pw erin-pw erin")
        self.kadmin(b, "addprinc -randkey HTTP/web.b.test")
        self.kadmin(b, f"ktadd -k {self.path('web.keytab')} HTTP/web.b.test")
        f = REALM_F
        self.kadmin(f, "addprinc -pw grace-pw +requires_preauth grace")
        self.kadmin(f, "addprinc -pw heidi-pw +requires_preauth "
                       "-e camellia256-cts-cmac:normal,camellia128-cts-cmac:normal heidi")
        self.kadmin(f, "addprinc -randkey -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal host/fast.f.test")
        self.kadmin(f, f"ktadd -k {self.path('fast.keytab')} host/fast.f.test")
        self.kadmin(f, "addprinc -randkey HTTP/svc.f.test")
        # The trust: the same keys in both databases.
        for p in (f"krbtgt/{b}@{a}", f"krbtgt/{a}@{b}"):
            self.kadmin(a, f"addprinc -pw trust-{p.replace('/', '-')} -e \"{ENCTYPES}\" {p}")
            self.kadmin(b, f"addprinc -pw trust-{p.replace('/', '-')} -e \"{ENCTYPES}\" {p}")

    def start(self):
        args = [self.bin("krb5kdc"), "-n", "-r", REALM_A, "-r", REALM_B]
        args_f = [self.bin("krb5kdc"), "-n", "-r", REALM_F]
        if self.time_offset:
            # The KDC's clock, ahead of ours by this many seconds.
            args += ["-T", str(self.time_offset)]
            args_f += ["-T", str(self.time_offset)]
        out = subprocess.DEVNULL if self.quiet else None
        self.proc = subprocess.Popen(args, env=self.env, stdout=out, stderr=out)
        self.proc_f = subprocess.Popen(args_f, env=self.env_f, stdout=out, stderr=out)
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None or self.proc_f.poll() is not None:
                raise RuntimeError("krb5kdc exited: see " + self.path("kdc.log") + " and " + self.path("kdc-f.log"))
            try:
                for port in (self.port_a, self.port_b, self.port_f):
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("krb5kdc did not start")

    def stop(self):
        for p in (self.proc, self.proc_f):
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()

    def __enter__(self):
        self.write_conf()
        self.create()
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        if self.own_dir:
            shutil.rmtree(self.dir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir")
    ap.add_argument("--mit")
    args = ap.parse_args()
    if args.dir:
        os.makedirs(args.dir, exist_ok=True)
    with Kdc(args.dir, args.mit, quiet=False) as k:
        print(f"KRB5_CONFIG={k.path('krb5.conf')}")
        print(f"A.TEST on 127.0.0.1:{k.port_a}, B.TEST on 127.0.0.1:{k.port_b}, F.TEST on 127.0.0.1:{k.port_f}; "
              "Ctrl-C to stop")
        sys.stdout.flush()
        try:
            signal.pause()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
