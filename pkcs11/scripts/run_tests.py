#!/usr/bin/env python3
"""Run pkcs11's tests against SoftHSM2.

Every test/*.goose runs under the JIT at -O0, -O2 and with --debug (and
natively with --native), and each of gslib's examples/pkcs11 once, each
run with a token of its own: a fresh SoftHSM token directory, one token
initialized by softhsm2-util, labelled "gslib", with the SO PIN 12345678 and the user PIN 1234. The tests find it through

    P11_MODULE, SOFTHSM2_CONF, P11_LABEL, P11_PIN, P11_SO_PIN

The module is $P11_MODULE, else the first SoftHSM2 found in the usual
places (Homebrew, Debian, Fedora). Without SoftHSM2 the tests are skipped,
not failed, and the examples only type-checked.

    python3 scripts/run_tests.py [--goose PATH] [--native] [-k NAME]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
MODULES = ["/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so",
           "/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
           "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so", "/usr/lib64/pkcs11/libsofthsm2.so"]
LABEL, PIN, SO_PIN = "gslib", "1234", "12345678"


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def find_module():
    m = os.environ.get("P11_MODULE")
    if m:
        return m if os.path.isfile(m) else None
    return next((m for m in MODULES if os.path.isfile(m)), None)


def softhsm_util():
    return shutil.which("softhsm2-util") or next(
        (p for p in ["/opt/homebrew/bin/softhsm2-util", "/usr/local/bin/softhsm2-util", "/usr/bin/softhsm2-util"]
         if os.path.isfile(p)), None)


def token_env(tmp, module, util):
    """A fresh token directory and its configuration, one token in it."""
    tokens = os.path.join(tmp, "tokens")
    os.makedirs(tokens)
    conf = os.path.join(tmp, "softhsm2.conf")
    with open(conf, "w") as f:
        f.write(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
    env = dict(os.environ, SOFTHSM2_CONF=conf, P11_MODULE=module, P11_LABEL=LABEL, P11_PIN=PIN, P11_SO_PIN=SO_PIN)
    subprocess.run([util, "--init-token", "--free", "--label", LABEL, "--so-pin", SO_PIN, "--pin", PIN],
                   env=env, check=True, capture_output=True)
    return env


def strip_notes(text):
    return "".join(l for l in text.splitlines(True)
                   if not l.startswith(("parsed ok", "typechecked ok", "bce:")))


def report(label, p, failed):
    """Prints the result; True if it passed."""
    if p.returncode == 0:
        print("ok    " + label)
        return True
    failed.append(label)
    print("FAIL  " + label)
    out = strip_notes(p.stdout) + "\n".join(l for l in p.stderr.splitlines()
                                            if "warning" not in l and not l.strip().startswith("^"))
    print("      " + out.strip()[-3000:].replace("\n", "\n      "))
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--native", action="store_true")
    ap.add_argument("-k", help="only files whose name contains this")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    module, util = find_module(), softhsm_util()
    # The examples are gslib's examples/pkcs11.
    ex_dir = os.path.join(ROOT, "..", "examples", "pkcs11")
    examples = sorted(f for f in os.listdir(ex_dir) if f.endswith(".goose")) if os.path.isdir(ex_dir) else []
    if args.k:
        examples = [e for e in examples if args.k in e]
    failed, passed = [], 0
    if not module or not util:
        print("SoftHSM2 not found (set P11_MODULE, install softhsm2): pkcs11's tests skipped")
        for e in examples:
            p = subprocess.run([goose, "check", e], cwd=ex_dir, capture_output=True, text=True)
            passed += report(f"examples/pkcs11/{e} check", p, failed)
        print(f"\n{passed} passed, {len(failed)} failed")
        sys.exit(1 if failed else 0)

    test_dir = os.path.join(ROOT, "test")
    tests = sorted(f for f in os.listdir(test_dir)
                   if f.endswith(".goose") and "fn main()" in open(os.path.join(test_dir, f)).read())
    if args.k:
        tests = [t for t in tests if args.k in t]
    runs = [["-O0"], ["-O2"], ["--debug"]] + ([["native"]] if args.native else [])
    for t in tests:
        for flags in runs:
            with tempfile.TemporaryDirectory() as tmp:
                env = token_env(tmp, module, util)
                if flags == ["native"]:
                    exe = os.path.join(tmp, t[:-6])
                    p = subprocess.run([goose, "build", "-o", exe, t], cwd=test_dir, env=env,
                                       capture_output=True, text=True)
                    if p.returncode == 0:
                        p = subprocess.run([exe], cwd=test_dir, env=env, capture_output=True, text=True)
                else:
                    p = subprocess.run([goose, *flags, t], cwd=test_dir, env=env, capture_output=True, text=True)
            passed += report(f"{t} {' '.join(flags)}", p, failed)
    for e in examples:
        with tempfile.TemporaryDirectory() as tmp:
            env = token_env(tmp, module, util)
            p = subprocess.run([goose, e], cwd=ex_dir, env=env, capture_output=True, text=True)
        passed += report(f"examples/pkcs11/{e}", p, failed)
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
