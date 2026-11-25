#!/usr/bin/env python3
"""gslib's regex against Rust's regex crate, Go's regexp, PCRE2 (JIT and
interpreter) and POSIX regex.h, on the same corpora and patterns.

    python3 bench.py run --goose PATH [--goose-cc CC[=LABEL]]... --work DIR \\
        --machine NAME --out results.json [--cc CC] [--pcre2 PREFIX] [--go GO] [--lock DIR]
    python3 bench.py report results.json... > results.md

`run` writes the corpora into the work directory (a generated ~10 MB
English-like text, deterministic; Project Gutenberg's "The Adventures of
Sherlock Holmes", fetched once; and the pathological texts), builds each
engine there (bench.goose with goose build, once per --goose-cc; the Rust
crate in release with LTO; the Go program; c/bench.c at -O2 against PCRE2
and the C library's regex.h), runs each on each corpus, checks that they
agree on every match count and capture sum, and writes the results. Every
engine prints "pattern corpus metric value" lines: compile_us, count,
count_mbps and, for capture patterns, caps_sum and caps_mbps. With --lock,
each timed run holds that directory (mkdir, rmdir), waiting while another
run has it.
"""

import argparse
import hashlib
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# Project Gutenberg's "The Adventures of Sherlock Holmes" (ebook 1661), from
# its PGLAF mirror (www.gutenberg.org was down for maintenance).
GUTENBERG = "https://gutenberg.pglaf.org/1/6/6/1661/1661-0.txt"
PATHO = [20, 25, 30]          # (a|aa)+$ on a^n b
# Patterns whose search ends near the start: timed per search, not per MB.
PER_SEARCH = {"text_start"}
ENGINES = ["rust", "go", "pcre2-jit", "pcre2", "posix"]

# --- corpora ---------------------------------------------------------------------

WORDS = """the of and to a in that is was he for it with as his on be at by i this had not are but
from or have an they which one you were her all she there would their we him been has when who will
more no if out so said what up its about into than them can only other new some could time these two
may then do first any my now such like our over man me even most made after also did many before must
through back years where much your way well down should because each just those people how too little
state good very make world still own see men work long get here between both life being under never day
same another know while last might us great old year off come since against go came right used take
three states himself few house use during without again place around however home small found mrs
thought went say part once general high upon school every does got united left number course war until
always away something fact though water less public put think almost hand enough far took head yet
government system better set told nothing night end why called didn find going look asked later point
knew city next program business give group toward young days let room president side social given
present several order national possible rather second face per among form important often things
looked early white case john become large big need four within felt along children saw best church ever
least power development light thing seemed family interest want members mind country area others done
turned although open god service certain kind problem began different door thus help sense means whole
matter perhaps itself york times law human line above name example action company hands local show
whether five history gave today either act feet across taken past quite anything seen having death
experience body word half really week free car field morning reading writing walking evening nothing
something nothing thinking looking speaking during building watching standing sitting""".split()
NAMES = ["Sherlock", "Holmes", "Watson", "Lestrade", "Hudson", "Baker", "London", "Mary", "Irene"]


def generated_corpus(size=10_000_000, seed=20261125):
    """English-like ASCII text: sentences of common words, capitalized,
    with punctuation, a few names, numbers, dates and email addresses,
    lines wrapped near 72 columns and blank lines between paragraphs; one
    rare name about every 500 KB."""
    r = random.Random(seed)
    out, line, n, sentences = [], [], 0, 0
    def emit(tok):
        nonlocal n, line
        if sum(len(t) + 1 for t in line) + len(tok) > 72:
            s = " ".join(line) + "\n"
            out.append(s)
            n += len(s)
            line = []
        line.append(tok)
    while n < size:
        words = []
        for k in range(r.randint(5, 20)):
            x = r.random()
            if x < 0.03: w = r.choice(NAMES)
            elif x < 0.04: w = str(r.randint(1, 9999))
            elif x < 0.05: w = "%04d-%02d-%02d" % (r.randint(1850, 2030), r.randint(1, 12), r.randint(1, 28))
            elif x < 0.055: w = "%s.%s@%s.%s" % (r.choice(WORDS), r.choice(WORDS), r.choice(WORDS), r.choice(["com", "org", "net", "co.uk"]))
            elif x < 0.05505: w = "Moriarty"
            else: w = r.choice(WORDS)
            if k == 0: w = w[:1].upper() + w[1:]
            if k > 0 and r.random() < 0.08: words[-1] += ","
            words.append(w)
        words[-1] += r.choice([".", ".", ".", "?", "!", ";"])
        for w in words: emit(w)
        sentences += 1
        if r.random() < 0.15:
            s = " ".join(line) + "\n\n"
            out.append(s)
            n += len(s)
            line = []
    if line: out.append(" ".join(line) + "\n")
    return "".join(out).encode()


def corpora(work):
    """The corpora: name -> (path, patterns file, note)."""
    gen = os.path.join(work, "generated.txt")
    if not os.path.exists(gen):
        with open(gen, "wb") as f: f.write(generated_corpus())
    gut = os.path.join(work, "sherlock-1661-0.txt")
    if not os.path.exists(gut):
        req = urllib.request.Request(GUTENBERG, headers={"User-Agent": "Mozilla/5.0 (gslib regex benchmark)"})
        with urllib.request.urlopen(req) as u, open(gut, "wb") as f: f.write(u.read())
    out = {"generated": (gen, "patterns.tsv"), "sherlock": (gut, "patterns.tsv")}
    for n in PATHO:
        p = os.path.join(work, "patho%d.txt" % n)
        with open(p, "wb") as f: f.write(b"a" * n + b"b")
        out["patho%d" % n] = (p, "patho.tsv")
    return out


def describe(path):
    data = open(path, "rb").read()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()[:16]}

# --- building ----------------------------------------------------------------------

def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()[0]
    except (OSError, IndexError):
        return "?"


def build(args, work):
    """name -> (argv prefix, description) for each engine."""
    eng, vers = {}, {}
    for spec in args.goose_cc or [""]:
        cc, _, label = spec.partition("=")
        name = "goose" + ("-" + (label or os.path.basename(cc)) if cc else "")
        exe = os.path.join(work, "bench-" + name)
        env = dict(os.environ, **({"GOOSE_CC": cc} if cc else {}))
        sh([args.goose, "build", "-O2", "-o", exe, os.path.join(HERE, "bench.goose")], env=env)
        eng[name] = [exe]
        vers[name] = "%s, C by %s" % (version([args.goose, "--version"]), version([cc or "cc", "--version"]))
    target = os.path.join(work, "rust-target")
    sh(["cargo", "build", "--release", "--quiet", "--target-dir", target], cwd=os.path.join(HERE, "rust"))
    eng["rust"] = [os.path.join(target, "release", "regex-bench")]
    vers["rust"] = "regex 1.13.2, %s, release, LTO" % version(["rustc", "--version"])
    exe = os.path.join(work, "bench-go")
    sh([args.go, "build", "-o", exe, "."], cwd=os.path.join(HERE, "go"),
       env=dict(os.environ, GOCACHE=os.path.join(work, "gocache")))
    eng["go"] = [exe]
    vers["go"] = version([args.go, "version"])
    if args.pcre2:
        cflags = ["-I" + os.path.join(args.pcre2, "include")]
        libs = ["-L" + os.path.join(args.pcre2, "lib"), "-Wl,-rpath," + os.path.join(args.pcre2, "lib"), "-lpcre2-8"]
        pv = version([os.path.join(args.pcre2, "bin", "pcre2-config"), "--version"])
    else:
        cflags = sh(["pcre2-config", "--cflags"]).split()
        libs = sh(["pcre2-config", "--libs8"]).split()
        pv = version(["pcre2-config", "--version"])
    exe = os.path.join(work, "bench-c")
    sh([args.cc, "-O2", "-o", exe, os.path.join(HERE, "c", "bench.c"), *cflags, *libs])
    for e in ("pcre2-jit", "pcre2", "posix"):
        eng[e] = [exe, e]
    cv = version([args.cc, "--version"])
    vers["pcre2-jit"] = "PCRE2 %s, pcre2_jit_match, %s -O2" % (pv, cv)
    vers["pcre2"] = "PCRE2 %s, pcre2_match (interpreter), %s -O2" % (pv, cv)
    libc = platform.mac_ver()[0] and "macOS %s libc" % platform.mac_ver()[0] or version(["ldd", "--version"])
    vers["posix"] = "regcomp/regexec of %s, %s -O2" % (libc, cv)
    return eng, vers

# --- running -----------------------------------------------------------------------

class Lock:
    def __init__(self, path): self.path = path
    def __enter__(self):
        while self.path:
            try:
                os.mkdir(self.path)
                return
            except FileExistsError:
                time.sleep(5)
    def __exit__(self, *a):
        if self.path: os.rmdir(self.path)


def run_engine(argv, patterns, corpus, name, timeout, lock):
    with Lock(lock):
        try:
            p = subprocess.run([*argv, os.path.join(HERE, patterns), corpus, name],
                               capture_output=True, text=True, timeout=timeout)
            text = p.stdout
        except subprocess.TimeoutExpired as e:
            text = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            text += "\n- %s timeout %d\n" % (name, timeout)
    res = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) == 4:
            res.setdefault(f[0], {})[f[2]] = f[3]
    return res


def cmd_run(args):
    os.makedirs(args.work, exist_ok=True)
    cs = corpora(args.work)
    eng, vers = build(args, args.work)
    results = {"machine": args.machine, "engines": vers, "corpora": {}, "results": {}}
    for c, (path, patterns) in cs.items():
        results["corpora"][c] = describe(path)
        if c == "sherlock": results["corpora"][c]["url"] = GUTENBERG
        for e, argv in eng.items():
            if args.engines and not any(e == x or (x == "goose" and e.startswith("goose")) for x in args.engines.split(",")):
                continue
            print("running %s on %s" % (e, c), file=sys.stderr)
            r = run_engine(argv, patterns, path, c, 60 if c.startswith("patho") else 1800, args.lock)
            results["results"].setdefault(c, {})[e] = r
    with open(args.out, "w") as f: json.dump(results, f, indent=1)
    problems = check(results)
    for p in problems: print("DISAGREE " + p, file=sys.stderr)
    print("wrote %s; %d disagreements" % (args.out, len(problems)), file=sys.stderr)


def check(results):
    """The counts and capture sums that differ from Rust's: POSIX's are
    reported apart (leftmost-longest), and timeouts and errors are no
    disagreement."""
    out = []
    for c, by in results["results"].items():
        ref = by.get("rust", {})
        for e, pats in by.items():
            for p, m in pats.items():
                for k in ("count", "caps_sum"):
                    if k in m and k in ref.get(p, {}) and m[k] != ref[p][k]:
                        out.append("%s %s %s %s: %s, rust %s" % (c, p, e, k, m[k], ref[p][k]))
    return out

# --- the report --------------------------------------------------------------------

LABELS = {"rust": "Rust regex", "go": "Go regexp", "pcre2-jit": "PCRE2 JIT", "pcre2": "PCRE2", "posix": "POSIX"}


def label(e):
    if e.startswith("goose"): return "Goose" + (" (" + e[6:] + ")" if len(e) > 5 else "")
    return LABELS.get(e, e)


def fnum(x, digits=0):
    return "{:,.{}f}".format(x, digits)


def cell(m, key):
    if not m: return "-"
    if "skip" in m: return "n/a"
    if "error" in m: return "error"
    if "timeout" in m and key not in m: return "timeout"
    return m.get(key)


def report(res):
    out = []
    by = res["results"]
    gooses = sorted(e for e in by["generated"] if e.startswith("goose"))
    others = [e for e in ENGINES if e in by["generated"]]
    engines = gooses + others
    pats = [l.split("\t")[0] for l in open(os.path.join(HERE, "patterns.tsv")) if l.strip() and not l.startswith("#")]
    caps = [l.split("\t")[0] for l in open(os.path.join(HERE, "patterns.tsv")) if "\tcaps\t" in l]

    def mbps(c, e, p, key):
        v = cell(by[c].get(e, {}).get(p), key)
        try: return float(v)
        except (TypeError, ValueError): return None

    def rows(c, key, plist):
        g = gooses[0]
        out.append("| Pattern | " + " | ".join(label(e) for e in others) + " |")
        out.append("|---|" + "---:|" * len(others))
        for p in plist:
            mine = mbps(c, g, p, key)
            cells = []
            for e in others:
                o = mbps(c, e, p, key)
                cells.append("%.2f" % (mine / o) if mine and o else (cell(by[c].get(e, {}).get(p), key) if o is None else "-"))
            out.append("| %s | %s |" % (p, " | ".join(cells)))
        out.append("")

    for c in ("generated", "sherlock"):
        out.append("#### Summary, %s corpus: %s's MB/s over the other's (above 1: Goose is faster)\n" % (c, label(gooses[0])))
        rows(c, "count_mbps", pats)
        out.append("Captures (each match's groups):\n")
        rows(c, "caps_mbps", caps)
    for c in ("generated", "sherlock"):
        out.append("#### Matches counted, %s corpus, MB/s\n" % c)
        out.append("| Pattern | Matches | " + " | ".join(label(e) for e in engines) + " |")
        out.append("|---|---:|" + "---:|" * len(engines))
        for p in pats:
            n = cell(by[c]["rust"].get(p), "count")
            cells = []
            for e in engines:
                v = mbps(c, e, p, "count_mbps")
                if v and p in PER_SEARCH:     # a search that stops at the start: ns per search
                    cells.append(fnum(res["corpora"][c]["bytes"] / (v * 1e6) * 1e9, 0) + " ns")
                else:
                    cells.append(fnum(v, 1) if v else cell(by[c].get(e, {}).get(p), "count_mbps") or "-")
            out.append("| %s | %s | %s |" % (p, fnum(int(n)) if n else "-", " | ".join(cells)))
        out.append("")
        out.append("#### Captures, %s corpus, MB/s\n" % c)
        out.append("| Pattern | " + " | ".join(label(e) for e in engines) + " |")
        out.append("|---|" + "---:|" * len(engines))
        for p in caps:
            cells = [fnum(v, 1) if (v := mbps(c, e, p, "caps_mbps")) else cell(by[c].get(e, {}).get(p), "caps_mbps") or "-" for e in engines]
            out.append("| %s | %s |" % (p, " | ".join(cells)))
        out.append("")
    out.append("#### Compile time, µs per pattern\n")
    out.append("| Pattern | " + " | ".join(label(e) for e in engines) + " |")
    out.append("|---|" + "---:|" * len(engines))
    for p in pats:
        cells = [fnum(v, 1) if (v := mbps("generated", e, p, "compile_us")) else cell(by["generated"].get(e, {}).get(p), "compile_us") or "-" for e in engines]
        out.append("| %s | %s |" % (p, " | ".join(cells)))
    out.append("")
    out.append("#### Pathological: `(a|aa)+$` on a^n b, µs per search\n")
    out.append("| n | " + " | ".join(label(e) for e in engines) + " |")
    out.append("|---|" + "---:|" * len(engines))
    for n in PATHO:
        c = "patho%d" % n
        size = res["corpora"][c]["bytes"]
        cells = []
        for e in engines:
            m = by.get(c, {}).get(e, {}).get("patho")
            v = mbps(c, e, "patho", "count_mbps")
            cells.append(fnum(size / (v * 1e6) * 1e6, 2) if v else (cell(m, "count_mbps") or "-"))
        out.append("| %d | %s |" % (n, " | ".join(cells)))
    out.append("")
    return "\n".join(out)


def cmd_report(args):
    for path in args.results:
        res = json.load(open(path))
        print("### %s\n" % res["machine"])
        print("| Engine | Version |\n|---|---|")
        for e, v in res["engines"].items(): print("| %s | %s |" % (label(e), v))
        print()
        for c, d in res["corpora"].items():
            print("- %s: %s bytes, sha256 %s…%s" % (c, fnum(d["bytes"]), d["sha256"], " (" + d["url"] + ")" if "url" in d else ""))
        print()
        problems = check(res)
        if problems:
            print("Counts that differ from Rust's:\n")
            for p in problems: print("- " + p)
            print()
        print(report(res))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--goose", required=True)
    r.add_argument("--goose-cc", action="append", help="a C compiler for goose build (GOOSE_CC), as CC or CC=LABEL; repeatable")
    r.add_argument("--work", required=True)
    r.add_argument("--machine", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--cc", default="cc")
    r.add_argument("--go", default="go")
    r.add_argument("--pcre2", help="PCRE2's install prefix (else pcre2-config on PATH)")
    r.add_argument("--lock")
    r.add_argument("--engines", help="only these engines, comma-separated (goose matches every Goose build)")
    p = sub.add_parser("report")
    p.add_argument("results", nargs="+")
    args = ap.parse_args()
    cmd_run(args) if args.cmd == "run" else cmd_report(args)


if __name__ == "__main__":
    main()
