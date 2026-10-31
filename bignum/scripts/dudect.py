#!/usr/bin/env python3
"""Run dudect (github.com/oreparaz/dudect), its own harness and statistics,
on bignum's constant-time code: tools/dudect/targets.goose, built natively
at -O2, one executable per target. x86 only (dudect times with rdtsc).

    python3 scripts/dudect.py [--dudect DIR] [--goose PATH] [--cc CC] [--seconds S] [target ...]

Each target runs for S seconds (60). A leak is dudect's "definitely not
constant time" (t above 500), or t above 10 with an effect size (tau) ten
times that of a negative control which is constant time by construction
(a noisy machine takes even that past t 10, given millions of
measurements). The two controls (an early-exit comparison with a secret,
BigInt's modpow) must leak; no other target may. dudect.git is --dudect, else $DUDECT, else
../dudect.git beside this repository. On Linux the run is pinned to one core.
Exit status 1 if a target leaked or a control was not caught.
"""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

# (function, input bytes, must leak)
TARGETS = [
    ("dut_memcmp", 512, True),
    ("dut_control_modpow", 64, True),
    ("dut_mont_modexp", 64, False),
    ("dut_ct_mod_inv", 128, False),
    ("dut_plain_mix", 128, False),
    ("dut_ct_mod_small", 128, False),
    ("dut_rsa_private_op", 128, False),
    ("dut_rsa_public_op_ct", 128, False),
    ("dut_x25519_base", 32, False),
    ("dut_ecdsa_p256_sign", 32, False),
    ("dut_ed25519_sign", 32, False),
]


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dudect", default=os.environ.get("DUDECT") or os.path.join(ROOT, "..", "dudect.git"))
    ap.add_argument("--goose")
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("targets", nargs="*")
    args = ap.parse_args()
    if platform.machine() not in ("x86_64", "AMD64", "i686"):
        sys.exit(f"dudect times with rdtsc, which this machine ({platform.machine()}) does not have")
    header = os.path.join(args.dudect, "src", "dudect.h")
    if not os.path.isfile(header):
        sys.exit(f"no dudect at {args.dudect}: pass --dudect or set DUDECT")
    goose = find_goose(args.goose)
    targets = [t for t in TARGETS if not args.targets or t[0] in args.targets]
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {max(os.sched_getaffinity(0))})
    failures = 0
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        c = os.path.join(tmp, "targets.c")
        p = subprocess.run([goose, "-o", c, "--header", os.path.join(tmp, "targets.h"),
                            os.path.join(ROOT, "tools", "dudect", "targets.goose")], capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(p.stdout + p.stderr)
        # The program's C, and the runtime's (goose --emit-runtime), each
        # compiled once.
        rt = os.path.join(tmp, "goose_runtime.c")
        p = subprocess.run([goose, "--emit-runtime", rt], capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(p.stdout + p.stderr)
        objs = []
        for src in (c, rt):
            obj = src[:-2] + ".o"
            p = subprocess.run([args.cc, "-O2", "-w", "-c", "-o", obj, src], capture_output=True, text=True)
            if p.returncode != 0:
                sys.exit(p.stdout + p.stderr)
            objs.append(obj)
        for name, chunk, leaky in targets:
            exe = os.path.join(tmp, name)
            flags = [f"-DTARGET={name}", f"-DCHUNK={chunk}"]
            p = subprocess.run([args.cc, "-O2", "-std=gnu11", "-w", "-I", os.path.dirname(header), *flags, "-o", exe,
                                os.path.join(ROOT, "tools", "dudect", "harness.c"), *objs, "-lm", "-pthread", "-ldl"],
                               capture_output=True, text=True)
            if p.returncode != 0:
                sys.exit(p.stdout + p.stderr)
            r = subprocess.run([exe, str(args.seconds)], capture_output=True, text=True)
            meas = [l for l in r.stdout.splitlines() if l.startswith("meas:") and "max t:" in l]
            if r.returncode != 0 or not meas:
                print(f"FAIL {name}: no result (exit {r.returncode})")
                failures += 1
                continue
            m = re.search(r"meas:\s*([\d.]+) M, max t:\s*([-+\d.]+), max tau:\s*([\d.e+-]+)", meas[-1])
            n, t, tau = float(m.group(1)), abs(float(m.group(2))), float(m.group(3))
            results[name] = (n, t, tau, leaky)
    # A leak: dudect's "definitely not constant time" (t above 500), or t
    # above its moderate threshold (10) with an effect size (tau = t /
    # sqrt(N)) ten times the negative control's, which is constant time by
    # construction: on a noisy machine that control itself passes t 10
    # given millions of measurements, and a slow target cannot reach 500
    # in a minute.
    floor = results.get("dut_plain_mix", (0, 0, 0, False))[2]
    print(f"| Target | Measurements | max t | max tau | tau / control's | Verdict |")
    print(f"|---|---:|---:|---:|---:|---|")
    for name, (n, t, tau, leaky) in results.items():
        leak = t >= 500 or (t >= 10 and floor > 0 and tau >= 10 * floor)
        ok = leak == leaky
        if not ok:
            failures += 1
        ratio = f"{tau / floor:.1f}" if floor > 0 else "-"
        verdict = ("leak (expected: a control)" if leaky else "LEAK") if leak else \
                  ("NOT CAUGHT (a control)" if leaky else "no leak")
        print(f"| {name} | {n:.2f} M | {t:.1f} | {tau:.2e} | {ratio} | {verdict} |")
    print("dudect: " + ("as expected" if failures == 0 else f"{failures} unexpected"))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
