#!/usr/bin/env python3
"""zip archives: compress.zip against Go's archive/zip, both ways.

Reading. Every archive below is read by tools/zipverdict.goose and by Go
(gooracle zip), each printing every File field Go exposes, Mode(), the
data offset, and the data's size, CRC-32 and Adler-32 or the error from
opening or reading it; the two outputs must be equal line for line. The
archives:

  * Go's own testdata (archive/zip/testdata, the .base64 one decoded, the
    sparse ZIP64 goldens of testdata/zip64 read from their tail);
  * archives Python's zipfile writes: stored, deflated at several levels,
    bzip2 and LZMA (methods we and Go do not read), ZIP64 forced, data
    descriptors (written to an unseekable stream), comments, UTF-8 and
    non-UTF-8 names, directories, times from 1980 to 2107, a prefix (as a
    self-extracting archive has) and trailing bytes;
  * archives the zip CLI writes (-0, -9, -X, -fz, streamed to stdout);
  * archives Go's writer makes from a spec, and ours from the same spec;
  * corrupted copies of all of these: a flipped bit, a changed byte, a cut
    end, bytes inserted, the central directory's fields changed.

Each runs with Go's default (zipinsecurepath off) and with
GODEBUG=zipinsecurepath=0 (-check), and our reader goes through output
rooms of 65536 bytes and of 1 to 7 bytes.

Writing. Our archives (tools/zipmake.goose) are read back by Go, Python's
zipfile (testzip and every file's bytes) and unzip -t; archives of stored
files are byte-identical to Go's writer's from the same spec, including
one of 70,000 files (ZIP64's end records).

    python3 scripts/zip_differential.py [--goose PATH] [--seed N] [--count N] [--debug] [-v]
"""

import argparse
import base64
import glob
import io
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def build(goose, tmp, debug=False):
    tools = {}
    for name in ("zipverdict", "zipmake"):
        exe = os.path.join(tmp, name)
        p = subprocess.run([goose, "build", *(["--debug"] if debug else []), "-o", exe, f"tools/{name}.goose"], cwd=ROOT, capture_output=True, text=True)
        tools[name] = [exe] if p.returncode == 0 else [goose, "-O2", f"tools/{name}.goose", "--"]
    oracle = os.path.join(tmp, "gooracle")
    p = subprocess.run(["go", "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "gooracle"),
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("cannot build gooracle:\n" + p.stderr)
    tools["oracle"] = oracle
    return tools


def run(cmd, env=None):
    p = subprocess.run(cmd, capture_output=True, env=env)
    if p.returncode != 0:
        sys.exit(f"{cmd} failed:\n" + p.stdout.decode(errors="replace")[-2000:] + p.stderr.decode(errors="replace"))
    return p.stdout.decode()


def payload(rng):
    n = rng.choice([0, 0, 1, 10, 100, 511, 512, 1000, 5000, 70000, 300000] + ([2_000_000] if rng.random() < 0.05 else []))
    k = rng.randrange(4)
    if k == 0:
        return rng.randbytes(n)
    if k == 1:
        return bytes([rng.randrange(256)]) * n
    if k == 2:
        words = [b"zip", b"archive", b"the", b"file", b"\n", b"data", b"go", b"goose"]
        return b" ".join(rng.choice(words) for _ in range(n // 4 + 1))[:n]
    unit = rng.randbytes(rng.randrange(1, 200))
    return (unit * (n // len(unit) + 1))[:n]


NAME_PARTS = ["a", "b", "dir", "file.txt", "Ünïcødé", "日本語", "x y", "back\\slash", "..", ".", "",
              "long" * 20, "é", "tab\tname"]


def rand_name(rng, is_dir=False):
    parts = [rng.choice(NAME_PARTS) for _ in range(rng.randrange(1, 4))]
    name = "/".join(parts)
    if rng.random() < 0.05:
        name = "/" + name
    if rng.random() < 0.05:
        name = "../" + name
    if is_dir and not name.endswith("/"):
        name += "/"
    if not is_dir and name.endswith("/"):
        name += "f"
    return name or "empty"


def python_zip(rng):
    """An archive written by Python's zipfile, in one of its forms."""
    buf = io.BytesIO()
    stream = rng.random() < 0.3
    target = buf
    if stream:
        class Unseekable(io.RawIOBase):
            def writable(self):
                return True

            def write(self, b):
                return buf.write(b)
        target = Unseekable()
    method = rng.choice([zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2,
                         zipfile.ZIP_LZMA])
    with zipfile.ZipFile(target, "w", compression=method, compresslevel=rng.choice([None, 1, 6, 9])
                         if method == zipfile.ZIP_DEFLATED else None) as z:
        for i in range(rng.randrange(0, 8)):
            is_dir = rng.random() < 0.15
            year = rng.choice([1980, 1999, 2024, 2107])
            info = zipfile.ZipInfo(rand_name(rng, is_dir),
                                   date_time=(year, rng.randrange(1, 13), rng.randrange(1, 29), rng.randrange(24),
                                              rng.randrange(60), rng.randrange(0, 60, 2)))
            info.compress_type = method if not is_dir else zipfile.ZIP_STORED
            if rng.random() < 0.3:
                info.comment = rng.choice([b"c", "cömment".encode(), b"\xff\xfe"])
            if rng.random() < 0.3:
                info.external_attr = rng.choice([0o100644 << 16, 0o40755 << 16 | 0x10, 0o120777 << 16, 0x01, 0x10])
            if rng.random() < 0.2:
                info.extra = struct.pack("<HHBI", 0x5455, 5, 1, rng.randrange(1 << 32))
            if is_dir:
                z.writestr(info, b"")
            elif rng.random() < 0.2:
                with z.open(info, "w", force_zip64=True) as f:
                    f.write(payload(rng))
            else:
                z.writestr(info, payload(rng))
        if rng.random() < 0.3:
            z.comment = rng.choice([b"archive comment", b"x" * 1000, "ünï".encode()])
    data = buf.getvalue()
    if rng.random() < 0.1:
        data = rng.randbytes(rng.randrange(1, 2000)) + data       # a prefix: Go's base offset
    if rng.random() < 0.05:
        data = data + b"trailing junk"
    return data


def cli_zip(rng, tmp, k):
    """An archive by the zip CLI over a small random tree."""
    tree = os.path.join(tmp, f"tree{k}")
    os.makedirs(tree)
    for i in range(rng.randrange(1, 6)):
        d = os.path.join(tree, *[rng.choice(["a", "b", "ü", "dir"]) for _ in range(rng.randrange(0, 3))])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, rng.choice(["f.txt", "g.bin", "日本", "x"]) + str(i)), "wb") as f:
            f.write(payload(rng))
    out = os.path.join(tmp, f"cli{k}.zip")
    opts = rng.choice([[], ["-0"], ["-9"], ["-X"], ["-fz"], ["-1", "-X"]])
    if rng.random() < 0.3:
        with open(out, "wb") as f:
            subprocess.run(["zip", "-q", "-r", *opts, "-", "."], cwd=tree, stdout=f, check=True)
    else:
        subprocess.run(["zip", "-q", "-r", *opts, out, "."], cwd=tree, check=True)
    with open(out, "rb") as f:
        return f.read()


def spec(rng, tmp, k, store_only=False):
    """A writer spec (tools/zipmake.goose's format) and its files' expected bytes."""
    lines = []
    files = []
    if rng.random() < 0.3:
        lines.append(f"comment {rng.randbytes(rng.randrange(1, 50)).hex()}")
    if rng.random() < 0.2:
        lines.append(f"offset {rng.randrange(0, 100000)}")
    for i in range(rng.randrange(0, 8)):
        is_dir = rng.random() < 0.15
        name = rand_name(rng, is_dir).encode()
        data = b"" if is_dir else payload(rng)
        path = os.path.join(tmp, f"spec{k}_{i}")
        with open(path, "wb") as f:
            f.write(data)
        chunk = rng.choice([1, 7, 4096, 1 << 30])
        if len(data) > 100000 and chunk < 4096:
            chunk = 4096
        if not store_only and rng.random() < 0.3:
            lines.append(f"create {name.hex()} {path} {chunk}")
            files.append((name, data))
            continue
        method = 0 if store_only else rng.choice([0, 8])
        if rng.random() < 0.5:
            mt = f"{rng.randrange(315532800, 4102444800)} {rng.choice([0, 3600, -18000, 19800, 50400])}"
        else:
            mt = "- 0"
        mode = rng.choice(["-", "1a4", "1ed", "800001ed", "80000000", "8000016d", "21a4", "c00001a4"])
        cmt = rng.choice(["-", b"comment".hex(), "c3bc"])
        extra = rng.choice(["-", "cafe0400deadbeef"])
        nonutf8 = rng.choice(["0", "0", "1"])
        lines.append(f"file {name.hex()} {method} {mt} {mode} {cmt} {extra} {nonutf8} {path if not is_dir else '-'} {chunk}")
        files.append((name, data))
    return "\n".join(lines) + "\n", files


def raw_spec(rng, tmp, k, sources):
    """A spec of raw files (sizes as given, 64-bit ones too) and copies of
    other archives' files: our bytes must be Go's."""
    lines = []
    for i in range(rng.randrange(1, 6)):
        if sources and rng.random() < 0.3:
            lines.append(f"copy {rng.choice(sources)}")
            continue
        is_dir = rng.random() < 0.1
        name = rand_name(rng, is_dir).encode()
        data = b"" if is_dir else rng.randbytes(rng.choice([0, 1, 100, 3000]))
        path = os.path.join(tmp, f"raw{k}_{i}")
        with open(path, "wb") as f:
            f.write(data)
        size = rng.choice([len(data), len(data), 0xfffffffe, 0xffffffff, 0x100000000, 5 << 30])
        csize = rng.choice([len(data), size])
        lines.append(f"raw {name.hex()} {rng.choice([0, 8, 99])} {rng.choice([0, 8, 0x808])} "
                     f"{rng.randrange(1 << 32):08x} {csize} {size} {rng.choice([20, 0x314, 45])} "
                     f"{rng.choice([10, 20, 45])} {path}")
    return "\n".join(lines) + "\n"


def corrupt(rng, data):
    if not data:
        return data
    k = rng.randrange(6)
    if k == 0:
        i = rng.randrange(len(data))
        return data[:i] + bytes([data[i] ^ (1 << rng.randrange(8))]) + data[i + 1:]
    if k == 1:
        i = rng.randrange(len(data))
        return data[:i] + bytes([rng.randrange(256)]) + data[i + 1:]
    if k == 2:
        return data[:rng.randrange(len(data))]
    if k == 3:
        i = rng.randrange(len(data))
        return data[:i] + rng.randbytes(rng.randrange(1, 40)) + data[i:]
    # A central directory record's field.
    p = data.rfind(b"PK\x01\x02")
    if p < 0:
        return data[:-1]
    off = p + rng.choice([4, 6, 8, 10, 16, 20, 24, 28, 30, 42])
    if off + 4 > len(data):
        return data
    v = rng.choice([0, 1, 0xffffffff, 0x7fffffff, rng.randrange(1 << 32)])
    return data[:off] + struct.pack("<I", v) + data[off + 4:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("-v", action="store_true")
    ap.add_argument("--keep", help="work in this directory and keep it")
    ap.add_argument("--debug", action="store_true", help="build the Goose tools with --debug (checked arithmetic)")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)
    goroot = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True).stdout.strip()
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        if args.keep:
            tmp = args.keep
            os.makedirs(tmp, exist_ok=True)
        tools = build(goose, tmp, args.debug)
        archives = []      # (kind, path)

        def add(kind, data):
            path = os.path.join(tmp, f"a{len(archives)}.zip")
            with open(path, "wb") as f:
                f.write(data)
            archives.append((kind, path))

        for path in sorted(glob.glob(os.path.join(goroot, "src/archive/zip/testdata/*"))):
            if os.path.isdir(path) or path.endswith(".png"):
                continue
            data = open(path, "rb").read()
            if path.endswith(".base64"):
                data = base64.b64decode(data)
            add("go-testdata", data)
        for path in sorted(glob.glob(os.path.join(goroot, "src/archive/zip/testdata/zip64/*.zsparse"))):
            archives.append(("go-zsparse", path))
        n_testdata = len(archives)

        written = []       # (spec path, ours, go's, files, store_only)
        for k in range(args.count):
            kind = rng.choice(["python", "python", "cli", "spec"])
            if kind == "python":
                add("python", python_zip(rng))
            elif kind == "cli":
                add("zip-cli", cli_zip(rng, tmp, k))
            else:
                store_only = rng.random() < 0.3
                text, files = spec(rng, tmp, k, store_only)
                sp = os.path.join(tmp, f"spec{k}.txt")
                with open(sp, "w") as f:
                    f.write(text)
                ours = os.path.join(tmp, f"ours{k}.zip")
                gos = os.path.join(tmp, f"go{k}.zip")
                run(tools["zipmake"] + [sp, ours])
                run([tools["oracle"], "zipmake", sp, gos])
                written.append((sp, ours, gos, files, store_only))
                archives.append(("ours", ours))
                archives.append(("go-writer", gos))
        # Raw files and copies: Go's bytes exactly.
        sources = []
        for kind, path in archives:
            if kind in ("python", "zip-cli", "go-writer"):
                with open(path, "rb") as f:
                    zf = None
                    try:
                        zf = zipfile.ZipFile(f)
                        zf.testzip()
                        sources.append(path)
                    except Exception:  # noqa: BLE001
                        pass
        n_raw = 0
        for k in range(max(10, args.count // 5)):
            text = raw_spec(rng, tmp, k, sources[:50])
            sp = os.path.join(tmp, f"rawspec{k}.txt")
            with open(sp, "w") as f:
                f.write(text)
            ours = os.path.join(tmp, f"oursraw{k}.zip")
            gos = os.path.join(tmp, f"goraw{k}.zip")
            p1 = subprocess.run(tools["zipmake"] + [sp, ours], capture_output=True)
            p2 = subprocess.run([tools["oracle"], "zipmake", sp, gos], capture_output=True)
            if (p1.returncode == 0) != (p2.returncode == 0):
                failures += 1
                print(f"FAIL {sp}: ours {p1.returncode} {p1.stdout[-200:]!r}, Go {p2.returncode} {p2.stderr[-200:]!r}")
                continue
            if p1.returncode != 0:
                continue
            n_raw += 1
            written.append((sp, ours, gos, None, True))
            archives.append(("ours-raw", ours))
        # 70,000 stored files: ZIP64's end of central directory, byte for byte.
        big = os.path.join(tmp, "many.txt")
        with open(big, "w") as f:
            for i in range(70000):
                f.write(f"file {('f%d' % i).encode().hex()} 0 - 0 - - - 0 - 1\n")
        many_ours, many_go = os.path.join(tmp, "many_ours.zip"), os.path.join(tmp, "many_go.zip")
        run(tools["zipmake"] + [big, many_ours])
        run([tools["oracle"], "zipmake", big, many_go])
        written.append((big, many_ours, many_go, [((b"f%d" % i), b"") for i in range(70000)], True))
        archives.append(("ours-70000", many_ours))
        # Corrupted copies.
        for kind, path in list(archives):
            if path.endswith(".zsparse") or kind == "ours-70000":
                continue
            data = open(path, "rb").read()
            for j in range(2 if kind == "go-testdata" else 1):
                add("corrupt-" + kind, corrupt(rng, data))

        # Reading: ours against Go, line for line.
        lst = os.path.join(tmp, "list.txt")
        with open(lst, "w") as f:
            f.write("\n".join(p for _, p in archives) + "\n")
        go_default = run([tools["oracle"], "zip", "-list", lst])
        env = dict(os.environ, GODEBUG="zipinsecurepath=0")
        go_check = run([tools["oracle"], "zip", "-list", lst], env=env)
        runs = [("default, room 65536", go_default, tools["zipverdict"] + [lst]),
                ("zipinsecurepath=0, room 65536", go_check, tools["zipverdict"] + ["-check", lst]),
                (f"default, room {1 + args.seed % 7}", go_default,
                 tools["zipverdict"] + ["-room", str(1 + args.seed % 7), lst])]
        for label, want, cmd in runs:
            got = run(cmd)
            w_parts = want.split("end\n")
            g_parts = got.split("end\n")
            if len(w_parts) != len(g_parts):
                print(f"FAIL {label}: {len(g_parts)} archives against Go's {len(w_parts)}")
                failures += 1
                continue
            diffs = 0
            for (kind, path), w, g in zip(archives + [("", "")], w_parts, g_parts):
                if w != g:
                    diffs += 1
                    if args.v or diffs <= 5:
                        wl, gl = w.splitlines(), g.splitlines()
                        for a, b in zip(wl + [""] * len(gl), gl + [""] * len(wl)):
                            if a != b:
                                print(f"DIFF {label} {kind} {path}:\n  go:   {a[:300]}\n  ours: {b[:300]}")
                                break
            refused = sum(1 for p in w_parts if not p.startswith("archive ok") and p)
            print(f"{label}: {len(archives)} archives ({refused} refused by Go), {diffs} differ")
            failures += diffs

        # Writing: our archives read back by Python, unzip and (above) Go.
        bad_write = 0
        identical = 0
        for sp, ours, gos, files, store_only in written:
            if files is None:
                if open(ours, "rb").read() != open(gos, "rb").read():
                    bad_write += 1
                    print(f"FAIL {sp}: raw/copy archive differs from Go's")
                else:
                    identical += 1
                continue
            try:
                with zipfile.ZipFile(ours) as z:
                    if z.testzip() is not None:
                        raise ValueError("testzip")
                    infos = z.infolist()
                    if len(infos) != len(files):
                        raise ValueError(f"{len(infos)} files, want {len(files)}")
                    for info, (name, data) in zip(infos, files):
                        if not info.is_dir() and z.read(info) != data:
                            raise ValueError(f"{name!r}: data differs")
            except Exception as e:  # noqa: BLE001
                bad_write += 1
                print(f"FAIL python reading {ours}: {e}")
            # (An archive written with zip_set_offset is meant to follow that
            # many bytes, and unzip says the bytes are missing; Go's too.)
            if files and len(files) < 1000 and "offset " not in open(sp).read():
                p = subprocess.run(["unzip", "-tqq", ours], capture_output=True)
                if p.returncode != 0:
                    bad_write += 1
                    print(f"FAIL unzip -t {ours}: {p.stdout.decode(errors='replace')[:300]}")
            if store_only:
                if open(ours, "rb").read() != open(gos, "rb").read():
                    bad_write += 1
                    print(f"FAIL {sp}: stored archive differs from Go's")
                else:
                    identical += 1
        print(f"writing: {len(written) - n_raw} archives read back by Python zipfile and unzip -t; "
              f"{identical} (stored, raw with 64-bit sizes, copies: {n_raw}) byte-identical to Go's; "
              f"{bad_write} failures")
        failures += bad_write
        print(f"{len(archives)} archives read ({n_testdata} Go testdata), {failures} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
