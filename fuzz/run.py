#!/usr/bin/env python3
"""gslib's fuzz targets: build them, replay their corpora and regression
inputs, run them under libFuzzer, and triage what they find.

    python3 fuzz/run.py list
    python3 fuzz/run.py build [--libfuzzer] [TARGET...]
    python3 fuzz/run.py replay [TARGET...]
    python3 fuzz/run.py fuzz TARGET [--seconds N] [--jobs J] [--work DIR]
    python3 fuzz/run.py triage TARGET [--work DIR] [CRASH...]
    python3 fuzz/run.py merge TARGET [--work DIR] [--dict]

Each target is fuzz/targets/<name>.goose, a Goose program whose
`export fn fuzz_one(data: const u8[:]) -> i32` takes one input. The
compiler writes its C (goose -o x.c --standalone --header), which is
compiled with GS_DEBUG=1 (Goose's overflow, `as` range and tag checks on)
and fuzz/driver/shim.h forced in, so a runtime error ends in abort().
Two drivers link with it:

  replay   fuzz/driver/replay.c, the system C compiler, ASan and UBSan
           when it has them (FUZZ_SAN=0 for none). Runs each file in a
           child with a time limit. No libFuzzer needed.
  fuzz     fuzz/driver/libfuzzer.c, a clang with libFuzzer (FUZZ_CC, else
           Homebrew's LLVM, else clang on PATH), -fsanitize=fuzzer,
           address,undefined.

`fuzz` keeps its working corpus and raw crashes in --work (default
$FUZZ_WORK, else build/work/<target> under fuzz/), starting from
fuzz/corpus/<target> and fuzz/dict/<target>.dict. Afterwards (and with
`triage`) each crash is replayed, keyed by its abort site (the "goose
runtime error ... (file:line)" line, else the sanitizer's top frames),
deduplicated, minimized with -minimize_crash, and written to
fuzz/crashes/<target>/<key>.bin with the report beside it as .txt.
fuzz/crashes is not committed; a crash kept as a regression input is
copied to fuzz/regressions/<target>/ by hand.

The compiler is $GOOSE, else goose on PATH, else ../goose.git/build/goose.
"""

import argparse
import concurrent.futures
import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import time

FUZZ = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(FUZZ)
TARGETS = os.path.join(FUZZ, "targets")
DRIVER = os.path.join(FUZZ, "driver")
BUILD = os.environ.get("FUZZ_BUILD") or os.path.join(FUZZ, "build")
# gslib's own C, from gslib.build (pkcs11's p11.c needs the runtime's
# header, and no target loads modules). Linked into every target; only the
# symbols a target calls are pulled in.
NATIVE = ["net/src/net.c", "mime/src/path.c", "tpm2/src/tpmdev.c"]

GOOSE_RE = re.compile(r"goose runtime error: (.*?)(?: \(([^()]*:\d+)\))?$", re.M)
FRAME_RE = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+)")
SAN_RE = re.compile(r"(ERROR: AddressSanitizer: [\w-]+|runtime error: .*|ERROR: libFuzzer: [\w-]+)")


def log(*a):
    print(*a, flush=True)


def goose():
    g = os.environ.get("GOOSE") or shutil.which("goose")
    if g:
        return g
    g = os.path.normpath(os.path.join(ROOT, "..", "goose.git", "build", "goose"))
    if os.path.exists(g):
        return g
    sys.exit("run.py: no goose compiler (set GOOSE)")


def all_targets():
    return sorted(os.path.basename(p)[:-6] for p in glob.glob(os.path.join(TARGETS, "*.goose")))


def system_cc():
    return os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or "gcc"


def fuzzer_cc():
    c = os.environ.get("FUZZ_CC")
    if c:
        return c
    for c in ["/opt/homebrew/opt/llvm/bin/clang", "/usr/local/opt/llvm/bin/clang"]:
        if os.path.exists(c):
            return c
    for n in ["clang"] + [f"clang-{v}" for v in range(23, 9, -1)]:
        c = shutil.which(n)
        if c and supports_libfuzzer(c):
            return c
    sys.exit("run.py: no clang with libFuzzer (set FUZZ_CC); `run.py replay` needs none")


_san_ok = {}


def try_link(cc, flags):
    key = (cc, tuple(flags))
    if key not in _san_ok:
        d = os.path.join(BUILD, ".probe", str(os.getpid()))
        os.makedirs(d, exist_ok=True)
        src = os.path.join(d, "probe.c")
        with open(src, "w") as f:
            f.write("#include <stddef.h>\n#include <stdint.h>\n"
                    "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\n"
                    "#ifndef FUZZ\nint main(void) { return 0; }\n#endif\n")
        p = subprocess.run([cc, *flags, src, "-o", os.path.join(d, "probe")], capture_output=True)
        _san_ok[key] = p.returncode == 0
    return _san_ok[key]


def supports_libfuzzer(cc):
    return try_link(cc, ["-DFUZZ", "-fsanitize=fuzzer,address,undefined"])


SAN = ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined", "-fno-omit-frame-pointer"]


def flags_for(kind, cc):
    """Compile flags for the target's C, and the driver's and link's."""
    common = ["-g", "-O1", "-DGS_DEBUG=1"]
    if kind == "libfuzzer":
        san = SAN + ["-fsanitize=fuzzer-no-link"]
        return common + san, ["-g", "-O1", *SAN, "-fsanitize=fuzzer"]
    san = SAN if os.environ.get("FUZZ_SAN", "1") != "0" and try_link(cc, SAN) else []
    return common + san, ["-g", "-O1", *san]


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        raise RuntimeError("$ " + " ".join(cmd) + "\n" + (p.stdout + p.stderr)[-6000:])
    return p


def sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p if isinstance(p, bytes) else p.encode())
        h.update(b"\0")
    return h.hexdigest()


def native_objects(cc, cflags, outdir):
    objs = []
    os.makedirs(outdir, exist_ok=True)
    for src in NATIVE:
        path = os.path.join(ROOT, src)
        obj = os.path.join(outdir, os.path.basename(src)[:-2] + ".o")
        stamp = obj + ".key"
        key = sha(open(path, "rb").read(), cc, *cflags)
        if not (os.path.exists(obj) and os.path.exists(stamp) and open(stamp).read() == key):
            # A temporary name, so builds running at once never link half an object.
            tmp = f"{obj}.{os.getpid()}.{threading.get_ident()}"
            run([cc, *[f for f in cflags if f != "-DGS_DEBUG=1"], "-c", path, "-o", tmp])
            os.replace(tmp, obj)
            with open(stamp + ".tmp" + str(os.getpid()), "w") as f:
                f.write(key)
            os.replace(stamp + ".tmp" + str(os.getpid()), stamp)
        objs.append(obj)
    return objs


def build(target, kind):
    """Builds fuzz/build/<kind>/<target>; returns the executable's path."""
    cc = fuzzer_cc() if kind == "libfuzzer" else system_cc()
    out = os.path.join(BUILD, kind, target)
    os.makedirs(out, exist_ok=True)
    src = os.path.join(TARGETS, target + ".goose")
    c_new = os.path.join(out, "target.c.new")
    h = os.path.join(out, "fuzz_target.h")
    # --no-bce: every bounds check kept, so an unsound elision shows up too.
    run([goose(), "-o", c_new, "--no-bce", "--standalone", "--header", h, src])
    cflags, lflags = flags_for(kind, cc)
    shim = os.path.join(DRIVER, "shim.h")
    drv = os.path.join(DRIVER, "libfuzzer.c" if kind == "libfuzzer" else "replay.c")
    exe = os.path.join(out, ("fuzz-" if kind == "libfuzzer" else "replay-") + target)
    key = sha(open(c_new, "rb").read(), open(shim, "rb").read(), open(drv, "rb").read(),
              open(os.path.join(DRIVER, "common.c"), "rb").read(), cc, *cflags, *lflags)
    stamp = exe + ".key"
    if os.path.exists(exe) and os.path.exists(stamp) and open(stamp).read() == key:
        os.remove(c_new)
        return exe
    c = os.path.join(out, "target.c")
    os.replace(c_new, c)
    obj = os.path.join(out, "target.o")
    run([cc, *cflags, "-include", shim, "-c", c, "-o", obj])
    natives = native_objects(cc, cflags, os.path.join(BUILD, kind, ".native"))
    libs = ["-lm", "-pthread"] + (["-ldl"] if sys.platform.startswith("linux") else [])
    run([cc, *lflags, "-I", out, drv, obj, *natives, "-o", exe, *libs])
    with open(stamp, "w") as f:
        f.write(key)
    return exe


def build_many(targets, kind, jobs=None):
    exes, failed = {}, []
    # The native objects once, before the targets that link them.
    cc = fuzzer_cc() if kind == "libfuzzer" else system_cc()
    native_objects(cc, flags_for(kind, cc)[0], os.path.join(BUILD, kind, ".native"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs or os.cpu_count()) as ex:
        futs = {ex.submit(build, t, kind): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            t = futs[fut]
            try:
                exes[t] = fut.result()
                log(f"built   {kind:9} {t}")
            except Exception as e:  # noqa: BLE001 (the build's own message)
                failed.append(t)
                log(f"FAILED  {kind:9} {t}\n{e}")
    return exes, failed


def pick(names):
    known = all_targets()
    bad = [n for n in names if n not in known]
    if bad:
        sys.exit(f"run.py: no such target: {', '.join(bad)} (they are {', '.join(known)})")
    return names or known


def cmd_list(_):
    for t in all_targets():
        corpus = glob.glob(os.path.join(FUZZ, "corpus", t, "*"))
        regs = glob.glob(os.path.join(FUZZ, "regressions", t, "*"))
        d = " dict" if os.path.exists(os.path.join(FUZZ, "dict", t + ".dict")) else ""
        log(f"{t:20} {len(corpus):4} seeds {len(regs):3} regressions{d}")


def cmd_build(a):
    _, failed = build_many(pick(a.targets), "libfuzzer" if a.libfuzzer else "replay")
    sys.exit(1 if failed else 0)


def cmd_replay(a):
    targets = pick(a.targets)
    exes, failed = build_many(targets, "replay")
    bad = list(failed)
    for t in targets:
        if t not in exes:
            continue
        paths = [p for p in (os.path.join(FUZZ, "corpus", t), os.path.join(FUZZ, "regressions", t))
                 if os.path.isdir(p) and os.listdir(p)]
        if not paths:
            log(f"skip    {t} (no inputs)")
            continue
        t0 = time.time()
        p = subprocess.run([exes[t], "-q", "-t", str(a.timeout), *paths], capture_output=True, text=True)
        lines = [l for l in p.stderr.splitlines() if l.startswith(("CRASH", "TIMEOUT", "goose runtime error"))
                 or "runtime error:" in l or "ERROR: AddressSanitizer" in l]
        summary = (p.stderr.strip().splitlines() or ["?"])[-1]
        if p.returncode == 0:
            log(f"ok      {t:20} {summary.replace('replay: ', '')} ({time.time() - t0:.1f} s)")
        else:
            bad.append(t)
            log(f"FAIL    {t:20} {summary.replace('replay: ', '')}")
            for l in lines[:40]:
                log("        " + l)
    log(f"\n{len(targets) - len(bad)} targets ok, {len(bad)} failed" + (f": {', '.join(bad)}" if bad else ""))
    sys.exit(1 if bad else 0)


def work_dir(a, target):
    return a.work or os.path.join(os.environ.get("FUZZ_WORK") or os.path.join(BUILD, "work"), target)


def cmd_fuzz(a):
    t = pick([a.target])[0]
    exe = build(t, "libfuzzer")
    work = work_dir(a, t)
    corpus = os.path.join(work, "corpus")
    crashes = os.path.join(work, "crashes") + os.sep
    os.makedirs(corpus, exist_ok=True)
    os.makedirs(crashes, exist_ok=True)
    seeds = os.path.join(FUZZ, "corpus", t)
    args = [exe, corpus] + ([seeds] if os.path.isdir(seeds) else [])
    args += [f"-max_total_time={a.seconds}", f"-artifact_prefix={crashes}", f"-timeout={a.timeout}",
             f"-rss_limit_mb={a.rss}", f"-max_len={a.max_len}", "-print_final_stats=1"]
    d = os.path.join(FUZZ, "dict", t + ".dict")
    if os.path.exists(d):
        args.append(f"-dict={d}")
    if a.jobs > 1 or a.keep_going:
        args += [f"-fork={a.jobs}", "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1"]
    args += a.extra
    log("$ " + " ".join(args))
    t0 = time.time()
    with open(os.path.join(work, "fuzz.log"), "a") as logf:
        p = subprocess.run(args, stdout=logf, stderr=subprocess.STDOUT)
    tail = open(os.path.join(work, "fuzz.log"), errors="replace").read().splitlines()[-12:]
    log("\n".join(tail))
    log(f"fuzz: {t} ran {time.time() - t0:.0f} s, exit {p.returncode}; corpus {len(os.listdir(corpus))} files")
    triage(t, exe, sorted(glob.glob(crashes + "*")), work)


def reproduce(exe, path, timeout):
    """The crash report of one input under the libFuzzer build."""
    try:
        p = subprocess.run([exe, f"-timeout={timeout}", "-rss_limit_mb=4096", path], capture_output=True,
                           text=True, errors="replace", timeout=timeout * 6 + 30)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, "ERROR: libFuzzer: timeout (killed by run.py)"


def crash_key(report):
    """The abort site: the Goose runtime error's file:line, else the
    sanitizer's kind and first frames inside the program."""
    report = report.replace(ROOT + os.sep, "")
    m = GOOSE_RE.search(report)
    if m:
        msg = re.sub(r"-?\d+", "N", m.group(1))
        return f"{m.group(2) or 'runtime'}: {msg}" if m.group(2) else f"runtime: {msg}"
    kind = SAN_RE.search(report)
    frames = []
    for fn, loc in FRAME_RE.findall(report):
        if any(s in fn for s in ("__sanitizer", "fuzzer::", "__asan", "__ubsan", "_sigtramp", "abort", "pthread_kill",
                                 "gs_fuzz_end", "gs_end", "gs_fail", "gs_panic", "malloc", "realloc", "calloc")):
            continue
        frames.append(fn)
        if len(frames) == 3:
            break
    k = kind.group(1) if kind else ("timeout" if "timeout" in report else "crash")
    return k + " in " + " < ".join(frames)


def slug(key):
    s = re.sub(r"[^A-Za-z0-9]+", "-", key).strip("-")[:60]
    return f"{s}-{sha(key)[:8]}"


def triage(t, exe, files, work):
    if not files:
        log(f"triage: {t}: no crashes")
        return
    outdir = os.path.join(FUZZ, "crashes", t)
    os.makedirs(outdir, exist_ok=True)
    seen = {}
    for f in files:
        rc, rep = reproduce(exe, f, 10)
        if rc == 0:
            log(f"triage: {os.path.basename(f)} did not reproduce")
            continue
        key = crash_key(rep)
        if key in seen:
            continue
        seen[key] = f
    for key, f in seen.items():
        name = slug(key)
        dst = os.path.join(outdir, name + ".bin")
        if os.path.exists(dst):
            log(f"triage: {t}: {key} (already in crashes/{t}/{name}.bin)")
            continue
        mini = os.path.join(work, "min-" + name)
        subprocess.run([exe, f, "-minimize_crash=1", "-runs=20000", "-max_total_time=60", "-timeout=10",
                        f"-exact_artifact_path={mini}"], capture_output=True)
        src = mini if os.path.exists(mini) and crash_key(reproduce(exe, mini, 10)[1]) == key else f
        shutil.copyfile(src, dst)
        _, rep = reproduce(exe, dst, 10)
        with open(os.path.join(outdir, name + ".txt"), "w") as fo:
            fo.write(f"key: {key}\nsize: {os.path.getsize(dst)}\nfrom: {os.path.basename(f)}\n\n")
            fo.write("\n".join(l for l in rep.splitlines() if not l.startswith("INFO:"))[-8000:])
        log(f"triage: {t}: NEW {key}\n        -> crashes/{t}/{name}.bin ({os.path.getsize(dst)} bytes)")


def cmd_triage(a):
    t = pick([a.target])[0]
    exe = build(t, "libfuzzer")
    work = work_dir(a, t)
    files = a.files or sorted(glob.glob(os.path.join(work, "crashes", "*")))
    triage(t, exe, files, work)


def cmd_merge(a):
    """Minimizes fuzz/corpus/<target> plus the work corpus into a new
    fuzz/corpus/<target>: libFuzzer's -merge keeps the inputs that add
    coverage, of those no larger than --max-file, at most --max-files."""
    t = pick([a.target])[0]
    exe = build(t, "libfuzzer")
    work = work_dir(a, t)
    seeds = os.path.join(FUZZ, "corpus", t)
    stage = os.path.join(work, "merge-in")
    out = os.path.join(work, "merge-out")
    for d in (stage, out):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    n = 0
    for d in (seeds, os.path.join(work, "corpus")):
        for f in glob.glob(os.path.join(d, "*")):
            if 0 < os.path.getsize(f) <= a.max_file:
                shutil.copyfile(f, os.path.join(stage, os.path.basename(f)))
                n += 1
    p = subprocess.run([exe, "-merge=1", f"-max_len={a.max_file}", "-timeout=10", out, stage],
                       capture_output=True, text=True, errors="replace")
    if p.returncode != 0:
        sys.exit(p.stderr[-3000:])
    kept = sorted(glob.glob(os.path.join(out, "*")), key=os.path.getsize)[:a.max_files]
    os.makedirs(seeds, exist_ok=True)
    for f in glob.glob(os.path.join(seeds, "*")):
        os.remove(f)
    for f in kept:
        shutil.copyfile(f, os.path.join(seeds, os.path.basename(f)))
    size = sum(os.path.getsize(f) for f in kept)
    log(f"merge: {t}: {n} inputs -> {len(kept)} in corpus/{t} ({size // 1024} KiB)")
    # libFuzzer's recommended dictionary from the last run, if it printed one.
    logf = os.path.join(work, "fuzz.log")
    if a.dict and os.path.exists(logf):
        text = open(logf, errors="replace").read()
        m = text.rfind("###### Recommended dictionary. ######")
        if m >= 0:
            entries = re.findall(r'^(".*") # Uses: \d+$', text[m:], re.M)
            d = os.path.join(FUZZ, "dict", t + ".dict")
            old = open(d).read() if os.path.exists(d) else ""
            new = [e for e in entries if e not in old]
            if new:
                with open(d, "a") as f:
                    f.write(("" if old.endswith("\n") or not old else "\n") + "# libFuzzer's recommended entries\n")
                    f.write("".join(e + "\n" for e in new))
                log(f"merge: {t}: {len(new)} dictionary entries added")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    b = sub.add_parser("build")
    b.add_argument("--libfuzzer", action="store_true")
    b.add_argument("targets", nargs="*")
    b.set_defaults(fn=cmd_build)
    r = sub.add_parser("replay")
    r.add_argument("-t", "--timeout", type=int, default=10)
    r.add_argument("targets", nargs="*")
    r.set_defaults(fn=cmd_replay)
    f = sub.add_parser("fuzz")
    f.add_argument("target")
    f.add_argument("--seconds", type=int, default=60)
    f.add_argument("--jobs", type=int, default=1)
    f.add_argument("--keep-going", action="store_true",
                   help="go on past crashes, time-outs and OOMs (libFuzzer -fork, also with one job)")
    f.add_argument("--work")
    f.add_argument("--timeout", type=int, default=10)
    f.add_argument("--rss", type=int, default=2048)
    f.add_argument("--max-len", type=int, default=65536)
    f.add_argument("extra", nargs="*", help="more libFuzzer flags, after --")
    f.set_defaults(fn=cmd_fuzz)
    tr = sub.add_parser("triage")
    tr.add_argument("target")
    tr.add_argument("--work")
    tr.add_argument("files", nargs="*")
    tr.set_defaults(fn=cmd_triage)
    m = sub.add_parser("merge")
    m.add_argument("target")
    m.add_argument("--work")
    m.add_argument("--max-file", type=int, default=8192)
    m.add_argument("--max-files", type=int, default=300)
    m.add_argument("--dict", action="store_true", help="also append libFuzzer's recommended dictionary")
    m.set_defaults(fn=cmd_merge)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
