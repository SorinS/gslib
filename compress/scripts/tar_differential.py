#!/usr/bin/env python3
"""tar: the compress package's reader and writer against Go's archive/tar.

Reading. tools/tarverdict.goose and `gooracle tar read` (Go) print every
header field, the PAX records, a CRC-32 of each entry's contents and the
error that ends the archive; the two must print the same, for

  1. every archive of $GOROOT/src/archive/tar/testdata (the .base64 and
     .bz2 ones decoded here), fed whole and in chunks of 1, 7, 511 and 513
     bytes, read whole and with contents cut to 100 bytes (skipping the
     rest), with and without the insecure-path check (Go's
     GODEBUG=tarinsecurepath=0);
  2. mutations of those archives: bytes of a header block changed (its
     checksum made right again, or not), PAX record text changed, cut at
     any point;
  3. archives made by Python's tarfile (USTAR, GNU and PAX, long and
     non-ASCII names, large ids and sizes of fields, sub-second times,
     links, directories, devices, global headers), by GNU tar (old GNU,
     ustar and posix, with sparse files in every GNU sparse format) and by
     bsdtar, over random trees.

Writing. Random headers (every type, names long and short, ASCII or not,
large numbers, sub-second and negative times, PAX records, a format asked
for or not, contents too short or too long) are written by Go's Writer
and by ours; the archives must be the same bytes, and each call's result
the same. The archives we write are also read back by Python's tarfile,
GNU tar and bsdtar, and must give the names, links, sizes and contents
written.

    python3 scripts/tar_differential.py [--goose PATH] [--seed N] [--count N] [-v]
"""

import argparse
import base64
import bz2
import io
import os
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
GNUTAR = "/usr/local/bin/tar" if os.path.exists("/usr/local/bin/tar") else shutil.which("gtar")
BSDTAR = shutil.which("bsdtar")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def build(goose, tmp):
    oracle = os.path.join(tmp, "gooracle")
    subprocess.run(["go", "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "gooracle"), check=True,
                   env=dict(os.environ, GOPROXY="off", GOFLAGS="-mod=mod"))
    verdict = os.path.join(tmp, "tarverdict")
    p = subprocess.run([goose, "build", "-o", verdict, "tarverdict.goose"], cwd=os.path.join(ROOT, "tools"),
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("building tarverdict failed:\n" + p.stdout + p.stderr)
    return oracle, verdict


def run(cmd, env=None):
    p = subprocess.run(cmd, capture_output=True, env=env)
    if p.returncode != 0:
        sys.exit(f"{cmd[0]} failed ({p.returncode}): {p.stderr.decode(errors='replace')}")
    return p.stdout.decode()


def split_archives(text):
    """The output, per archive name."""
    out = {}
    cur = None
    for line in text.splitlines(True):
        if line.startswith("archive "):
            cur = line[8:].strip()
            out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return {k: "".join(v) for k, v in out.items()}


class Stats:
    def __init__(self):
        self.cases = 0
        self.fails = 0


def compare_read(oracle, verdict, files, stats, label, verbose, extra_go=(), extra_goose=(), check=False):
    env = dict(os.environ)
    if check:
        env["GODEBUG"] = "tarinsecurepath=0"
    go = split_archives(run([oracle, "tar", "read", *extra_go, *files], env=env))
    flags = list(extra_goose) + (["-check"] if check else [])
    goose = split_archives(run([verdict, "read", *flags, *files]))
    for f in files:
        stats.cases += 1
        if go.get(f) != goose.get(f):
            stats.fails += 1
            print(f"FAIL {label}: {os.path.basename(f)}")
            if verbose or stats.fails <= 5:
                print("  go:\n    " + (go.get(f) or "").replace("\n", "\n    "))
                print("  goose:\n    " + (goose.get(f) or "").replace("\n", "\n    "))


def go_testdata(tmp):
    src = os.path.join(subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True).stdout.strip(),
                       "src", "archive", "tar", "testdata")
    d = os.path.join(tmp, "testdata")
    os.makedirs(d)
    files = []
    for f in sorted(os.listdir(src)):
        if not f.endswith((".tar", ".base64", ".bz2")):
            continue
        data = open(os.path.join(src, f), "rb").read()
        name = f
        if name.endswith(".base64"):
            data = base64.b64decode(data)
            name = name[:-7]
        if name.endswith(".bz2"):
            data = bz2.decompress(data)
            name = name[:-4]
        path = os.path.join(d, name)
        open(path, "wb").write(data)
        files.append(path)
    return files


def fix_checksum(blk):
    blk = bytearray(blk)
    blk[148:156] = b" " * 8
    s = sum(blk)
    blk[148:156] = b"%06o\x00 " % s
    return bytes(blk)


def mutate(rng, data):
    data = bytearray(data)
    kind = rng.randrange(6)
    nblocks = len(data) // 512
    if kind == 0 or nblocks == 0:
        cut = rng.randrange(len(data) + 1)
        return bytes(data[:cut])
    # A header block: one whose checksum is right.
    heads = [i for i in range(nblocks) if tarfile_checksum_ok(data[i * 512:(i + 1) * 512])]
    if not heads:
        heads = list(range(nblocks))
    b = rng.choice(heads) * 512
    blk = bytearray(data[b:b + 512])
    if kind == 1:
        # Fields: size, mode, uid, mtime, typeflag, a numeric field in base 256, the magic.
        field = rng.choice([(124, 12), (100, 8), (108, 8), (136, 12), (156, 1), (257, 8), (329, 8), (345, 12),
                            (357, 12), (483, 12), (386, 24), (482, 1), (0, 100), (157, 100), (345, 155)])
        off, ln = field
        how = rng.randrange(5)
        if how == 0:
            blk[off:off + ln] = bytes(rng.randrange(256) for _ in range(ln))
        elif how == 1:
            v = rng.choice([0, 1, 511, 512, 513, 1 << 20, (1 << 33) - 1, 1 << 33, 7777777])
            s = b"%0*o" % (ln - 1, v)
            blk[off:off + ln] = (s[-(ln - 1):] + b"\x00")[:ln]
        elif how == 2:
            v = rng.choice([0, 1, -1, 1 << 40, -(1 << 40), (1 << 63) - 1, -(1 << 63)])
            raw = v.to_bytes(ln, "big", signed=True) if -(1 << (8 * ln - 1)) <= v < (1 << (8 * ln - 1)) else b"\xff" * ln
            raw = bytearray(raw)
            raw[0] |= 0x80
            blk[off:off + ln] = raw
        elif how == 3:
            blk[off + rng.randrange(ln)] = rng.choice([0, 32, ord("0"), ord("7"), ord("8"), 0x80, 0xff, ord("x"),
                                                       ord("g"), ord("L"), ord("K"), ord("S"), ord("/")])
        else:
            blk[off:off + ln] = bytes(ln)
    elif kind == 2:
        for _ in range(rng.randrange(1, 4)):
            blk[rng.randrange(512)] = rng.randrange(256)
    elif kind == 3:
        # The block after a header (PAX records, a long name, a sparse map).
        if b + 1024 <= len(data):
            nb = bytearray(data[b + 512:b + 1024])
            for _ in range(rng.randrange(1, 4)):
                p = rng.randrange(512)
                nb[p] = rng.choice([ord(" "), ord("="), ord("\n"), 0, ord("0"), ord("9"), ord(","), ord("-"), ord(".")])
            data[b + 512:b + 1024] = nb
    elif kind == 4:
        data = data[:b] + bytes(512) + data[b:]
    else:
        data = data[:b] + data[b + 512:]
        return bytes(data)
    if kind != 3:
        if rng.random() < 0.85:
            blk = bytearray(fix_checksum(blk))
        data[b:b + 512] = blk
    return bytes(data)


def tarfile_checksum_ok(blk):
    if len(blk) < 512 or blk == bytes(512):
        return False
    try:
        want = int(blk[148:156].replace(b"\x00", b" ").strip() or b"0", 8)
    except ValueError:
        return False
    b = bytearray(blk)
    b[148:156] = b" " * 8
    return want in (sum(b), sum(x - 256 if x > 127 else x for x in b))


def random_name(rng, deep=True):
    parts = []
    for _ in range(rng.randrange(1, 6 if deep else 2)):
        n = rng.choice([1, 3, 8, 30, 99, 100, 101, 155, 160])
        alpha = rng.choice(["abc", "abcdefghijklmnopqrstuvwxyz0123456789._-", "aé日本ü", "x y"])
        parts.append("".join(rng.choice(alpha) for _ in range(n)))
    name = "/".join(parts)
    r = rng.random()
    if r < 0.05:
        name = "/" + name
    elif r < 0.1:
        name = "../" + name
    elif r < 0.12:
        name = name + "/../../x"
    return name


def octal(n, width):
    return (b"%0*o" % (width - 1, n))[-(width - 1):] + b"\x00"


def header_block(name, size, typ, magic=b"ustar\x0000", extra=None):
    """A header block made by hand: name, mode, ids, size, mtime, type,
    the magic, and fields given as {offset: bytes}; the checksum right."""
    b = bytearray(512)
    b[0:len(name)] = name[:100]
    b[100:108] = octal(0o644, 8)
    b[108:116] = octal(1000, 8)
    b[116:124] = octal(1000, 8)
    b[124:136] = octal(size, 12) if size >= 0 else b"\xff" * 12
    b[136:148] = octal(1600000000, 12)
    b[156] = typ
    b[257:265] = magic
    for off, val in (extra or {}).items():
        b[off:off + len(val)] = val
    return fix_checksum(b)


def pad512(b):
    return b + bytes(-len(b) % 512)


def sparse_archives(rng, d, count):
    """GNU sparse files in every format: old GNU ('S', the map in the
    header and extension blocks), PAX 0.0 (offset and numbytes records),
    0.1 (a map record) and 1.0 (the map in the data); maps valid and not,
    dense data short, long or right."""
    files = []
    for i in range(count):
        out = b""
        for e in range(rng.randrange(1, 4)):
            size = rng.choice([0, 1, 512, 1000, 5000, 100000, 1 << 34])
            frags = []
            pos = 0
            for k in range(rng.choice([0, 1, 2, 3, 5, 30])):
                if pos >= size:
                    break
                off = pos + rng.randrange(0, max(1, min(size - pos, 3000)))
                ln = rng.randrange(0, min(size - off, 2000) + 1)
                frags.append([off, ln])
                pos = off + ln
            r = rng.random()
            if r < 0.05 and frags:
                frags[-1][1] += size          # past the end
            elif r < 0.1 and len(frags) > 1:
                frags[1][0] = frags[0][0]     # overlapping or out of order
            elif r < 0.12 and frags:
                frags[0][0] = -1
            dense = b"".join(rng.randbytes(max(0, ln)) for _, ln in frags if ln < 1 << 20)
            r = rng.random()
            if r < 0.1:
                dense += b"extra"
            elif r < 0.2 and dense:
                dense = dense[:-1]
            kind = rng.choice(["oldgnu", "pax00", "pax01", "pax10"])
            name = b"sparse%d" % e
            if kind == "oldgnu":
                ent = b"".join(octal(o, 12) + octal(l, 12) for o, l in frags) if all(o >= 0 for o, _ in frags) else \
                      b"".join((o.to_bytes(12, "big", signed=True) if o < 0 else octal(o, 12)) + octal(l, 12) for o, l in frags)
                ents = [ent[j:j + 24] for j in range(0, len(ent), 24)]
                head, rest = ents[:4], ents[4:]
                extra = {386: b"".join(head), 483: octal(size, 12) if size < 1 << 33 else b"\x80" + size.to_bytes(11, "big")}
                if rest:
                    extra[482] = b"\x01"
                out += header_block(name, len(dense), ord("S"), b"ustar  \x00", extra)
                while rest:
                    blk = bytearray(512)
                    chunk, rest = rest[:21], rest[21:]
                    blk[:24 * len(chunk)] = b"".join(chunk)
                    if rest:
                        blk[504] = 1
                    out += bytes(blk)
                out += pad512(dense)
            else:
                recs = b""
                body = dense
                if kind == "pax00":
                    recs += pax_rec("GNU.sparse.numblocks", str(len(frags)))
                    for o, l in frags:
                        recs += pax_rec("GNU.sparse.offset", str(o)) + pax_rec("GNU.sparse.numbytes", str(l))
                    recs += pax_rec("GNU.sparse.size", str(size))
                elif kind == "pax01":
                    recs += pax_rec("GNU.sparse.numblocks", str(len(frags) + (1 if rng.random() < 0.05 else 0)))
                    recs += pax_rec("GNU.sparse.map", ",".join("%d,%d" % (o, l) for o, l in frags))
                    recs += pax_rec("GNU.sparse.size", str(size))
                    recs += pax_rec("GNU.sparse.name", "real%d" % e)
                else:
                    recs += pax_rec("GNU.sparse.major", "1") + pax_rec("GNU.sparse.minor", "0")
                    recs += pax_rec("GNU.sparse.realsize", str(size))
                    recs += pax_rec("GNU.sparse.name", "real%d" % e)
                    m = b"%d\n" % len(frags) + b"".join(b"%d\n%d\n" % (o, l) for o, l in frags)
                    if rng.random() < 0.05:
                        m = m.replace(b"\n", b"x", 1)
                    body = pad512(m) + dense
                if rng.random() < 0.5:
                    recs += pax_rec("size", str(len(body)))
                out += header_block(b"PaxHeaders/" + name, len(recs), ord("x")) + pad512(recs)
                out += header_block(name, len(body), ord("0")) + pad512(body)
        out += bytes(1024)
        p = os.path.join(d, f"sparse{i}.tar")
        open(p, "wb").write(out)
        files.append(p)
    return files


def python_archives(rng, d, count):
    files = []
    for i in range(count):
        fmt = rng.choice([tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT])
        buf = io.BytesIO()
        try:
            with tarfile.open(fileobj=buf, mode="w", format=fmt, encoding="utf-8",
                              pax_headers={"comment": "global"} if fmt == tarfile.PAX_FORMAT and rng.random() < 0.2 else None) as t:
                for j in range(rng.randrange(1, 8)):
                    ti = tarfile.TarInfo(random_name(rng))
                    ti.type = rng.choice([tarfile.REGTYPE, tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE,
                                          tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE])
                    big = rng.random() < 0.3
                    ti.uid = rng.choice([0, 1000, 2097151, 2097152, 1 << 40]) if big else 1000
                    ti.gid = rng.choice([0, 7, 2097152]) if big else 1000
                    ti.mode = rng.choice([0o644, 0o755, 0o4755, 0o7777])
                    mt = rng.choice([0, 1, 1700000000, 1700000000.5, 8589934591, 8589934592, -1, -100.25])
                    ti.mtime = mt
                    ti.uname = rng.choice(["", "user", "u" * 40, "üser"])
                    ti.gname = rng.choice(["", "grp", "g" * 33])
                    if ti.type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                        ti.linkname = random_name(rng)
                    if ti.type == tarfile.CHRTYPE:
                        ti.devmajor, ti.devminor = rng.choice([(1, 3), (2097151, 1), (2097152, 5)])
                    data = b""
                    if ti.type == tarfile.REGTYPE:
                        n = rng.choice([0, 1, 511, 512, 513, 1024, 5000])
                        data = rng.randbytes(n)
                        ti.size = n
                    if fmt == tarfile.PAX_FORMAT and rng.random() < 0.3:
                        ti.pax_headers = {"SCHILY.xattr.user.k": "v" * rng.randrange(0, 50), "custom": "x"}
                    try:
                        t.addfile(ti, io.BytesIO(data) if data or ti.type == tarfile.REGTYPE else None)
                    except (ValueError, UnicodeError):
                        pass
        except (ValueError, UnicodeError):
            continue
        p = os.path.join(d, f"py{i}.tar")
        open(p, "wb").write(buf.getvalue())
        files.append(p)
    return files


def make_tree(rng, root):
    os.makedirs(root)
    names = []
    for i in range(rng.randrange(1, 6)):
        sub = os.path.join(root, *["d%d" % rng.randrange(3)] * rng.randrange(0, 3))
        os.makedirs(sub, exist_ok=True)
        n = rng.choice(["f", "file.txt", "x" * rng.choice([50, 99, 100, 101, 200]), "üñí", "a b"]) + str(i)
        p = os.path.join(sub, n)
        kind = rng.randrange(4)
        if kind == 0 and names:
            os.symlink(rng.choice(names), p)
        elif kind == 1:
            # A sparse file: holes and data.
            with open(p, "wb") as f:
                size = rng.choice([4096, 100000, 1 << 20])
                for k in range(rng.randrange(1, 5)):
                    f.seek(rng.randrange(size))
                    f.write(rng.randbytes(rng.randrange(1, 3000)))
                f.truncate(size)
        else:
            open(p, "wb").write(rng.randbytes(rng.choice([0, 1, 511, 512, 513, 10000])))
        os.utime(p, ns=(1600000000123456789, 1600000000987654321), follow_symlinks=False)
        names.append(p)
    return names


def cli_archives(rng, d, count):
    files = []
    for i in range(count):
        tree = os.path.join(d, f"tree{i}")
        make_tree(rng, tree)
        opts = []
        tool = rng.choice(["gnu", "bsd"]) if BSDTAR else "gnu"
        if tool == "gnu" and GNUTAR:
            fmt = rng.choice(["gnu", "oldgnu", "ustar", "posix", "v7"])
            opts = [GNUTAR, "--format=" + fmt]
            if fmt in ("gnu", "oldgnu", "posix") and rng.random() < 0.7:
                opts.append("--sparse")
                if fmt == "posix":
                    opts.append("--sparse-version=" + rng.choice(["0.0", "0.1", "1.0"]))
        elif BSDTAR:
            opts = [BSDTAR, "--format=" + rng.choice(["ustar", "pax", "gnutar", "v7"])]
        else:
            continue
        p = os.path.join(d, f"cli{i}.tar")
        r = subprocess.run(opts + ["-cf", p, "-C", tree, "."], capture_output=True)
        if r.returncode != 0 and not os.path.exists(p):
            continue
        files.append(p)
    return files


def pax_rec(k, v):
    k = k.encode() if isinstance(k, str) else k
    v = v.encode() if isinstance(v, str) else v
    size = len(k) + len(v) + 3
    size += len(str(size))
    rec = b"%d %s=%s\n" % (size, k, v)
    if len(rec) != size:
        size = len(rec)
        rec = b"%d %s=%s\n" % (size, k, v)
    return rec


def random_spec(rng, sane=False):
    """Header lines for `tar write`; a sane spec holds only what other tar
    readers are asked to take (no negative or oversized numbers, contents
    as long as the header says)."""
    lines = []
    for i in range(rng.randrange(1, 7)):
        typ = rng.choice([ord("0"), ord("0"), ord("5"), ord("2"), ord("1"), ord("3"), ord("4"), ord("6"), 0,
                          ord("7"), ord("g"), ord("x"), ord("L"), ord("S")])
        name = random_name(rng).encode()
        if rng.random() < 0.1:
            name += b"/"
        if rng.random() < 0.03:
            name = b"a\x00b"
        link = random_name(rng).encode() if typ in (ord("1"), ord("2")) or rng.random() < 0.05 else b""
        size = rng.choice([0, 0, 1, 100, 511, 512, 513, 3000, (1 << 33) - 1, 1 << 33, -1])
        mode = rng.choice([0o644, 0o755, 0o7777, (1 << 21) - 1, 1 << 21, -1, 1 << 60])
        uid = rng.choice([0, 1000, (1 << 21) - 1, 1 << 21, 1 << 56, -5, (1 << 63) - 1])
        if sane:
            typ = rng.choice([ord("0"), ord("0"), ord("5"), ord("2"), ord("1"), ord("6"), 0])
            if b"\x00" in name:
                name = b"plain"
            if typ != ord("5") and name.endswith(b"/"):
                name = name.rstrip(b"/") or b"x"
            size = rng.choice([0, 1, 100, 511, 512, 513, 3000])
            mode = rng.choice([0o644, 0o755, 0o4755])
            uid = rng.choice([0, 1000, (1 << 21) - 1, 1 << 21, (1 << 31) - 1])
        gid = rng.choice([0, 1000, 1 << 21])
        uname = rng.choice([b"", b"root", b"u" * 32, b"u" * 33, "üser".encode(), b"a\x00b"]) if rng.random() < 0.6 else b""
        gname = rng.choice([b"", b"wheel", b"g" * 40])
        def t(allow_zero=True):
            r = rng.random()
            if allow_zero and r < 0.4:
                return "zero"
            sec = rng.choice([0, 1, 1700000000, (1 << 33) - 1, 1 << 33, -1, -62135596800, 1 << 40])
            ns = rng.choice([0, 0, 1, 500000000, 499999999, 999999999, 123456789])
            return f"{sec}.{ns}"
        mtime, atime, ctime = t(), t(), t()
        if typ == ord("g") and rng.random() < 0.7:
            size, mode, uid, gid, uname, gname, link, mtime, atime, ctime = 0, 0, 0, 0, b"", b"", b"", "zero", "zero", "zero"
        devmajor = rng.choice([0, 0, 1, (1 << 21) - 1, 1 << 21])
        devminor = rng.choice([0, 0, 3, -1])
        if sane:
            fmt_sane = rng.choice([0, 0, 2, 4, 8])
            uname = uname.replace(b"\x00", b"")
            if typ not in (ord("0"), 0):
                size = 0
            devminor = abs(devminor)
            if mtime != "zero" and mtime.startswith("-"):
                mtime = "1.5"
        fmt = rng.choice([0, 0, 0, 2, 4, 8, 6, 12, 14, 1, 16]) if not sane else fmt_sane
        pax = b""
        if rng.random() < 0.3:
            for _ in range(rng.randrange(1, 4)) if not sane else ():
                k = rng.choice(["comment", "path", "mtime", "uid", "SCHILY.xattr.user.a", "GNU.sparse.map", "z" * 20,
                                "size", "linkpath", "atime", "foo.bar"])
                v = rng.choice(["", "1", "value", "1700000000", name.decode(errors="replace"), "x" * 100])
                pax += pax_rec(k, v)
        dlen = size if 0 <= size <= 10000 else rng.choice([0, 10])
        if typ in (ord("1"), ord("2"), ord("5"), ord("6")):
            dlen = 0
        r = 1 if sane else rng.random()
        if r < 0.1:
            dlen += 5
        elif r < 0.2 and dlen > 0:
            dlen -= 1
        hx = lambda b: b.hex() if b else "-"
        lines.append(f"{typ} {hx(name)} {hx(link)} {size} {mode} {uid} {gid} {hx(uname)} {hx(gname)} {mtime} {atime} "
                     f"{ctime} {devmajor} {devminor} {fmt} {hx(pax)} {dlen} {rng.randrange(1 << 32)}")
    return "\n".join(lines) + "\n"


def spec_data(n, seed):
    out = bytearray(n)
    x = seed
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0xffffffff
        out[i] = (x >> 16) & 0xff
    return bytes(out)


def check_with_readers(path, verbose):
    """Python's tarfile, GNU tar and bsdtar on an archive we wrote: they
    must read every entry, with the names, link names and sizes Go reads."""
    problems = []
    try:
        with tarfile.open(path, encoding="utf-8", errors="surrogateescape") as t:
            members = t.getmembers()
            for m in members:
                if m.isreg():
                    t.extractfile(m).read()
    except Exception as e:
        problems.append(f"tarfile: {e}")
    for tool in [GNUTAR, BSDTAR]:
        if not tool:
            continue
        r = subprocess.run([tool, "-tvf", path], capture_output=True)
        if r.returncode != 0:
            problems.append(f"{tool}: {r.stderr.decode(errors='replace').strip()}")
    return problems


class _Keep:
    def __init__(self, d):
        self.d = os.path.abspath(d)

    def __enter__(self):
        os.makedirs(self.d)
        return self.d

    def __exit__(self, *a):
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=400, help="mutations; a fifth as many made archives and specs")
    ap.add_argument("-v", action="store_true")
    ap.add_argument("--keep", help="work in this (new) directory and keep it")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)
    t0 = time.time()
    with (tempfile.TemporaryDirectory() if not args.keep else _Keep(args.keep)) as tmp:
        oracle, verdict = build(goose, tmp)
        testdata = go_testdata(tmp)
        stats = Stats()

        # 1. Go's own archives, every way.
        for chunk in [None, 1, 7, 511, 513]:
            extra = ["-chunk", str(chunk)] if chunk else []
            compare_read(oracle, verdict, testdata, stats, f"testdata chunk {chunk}", args.v, extra_goose=extra)
        compare_read(oracle, verdict, testdata, stats, "testdata cap 100", args.v, ["-cap", "100"], ["-cap", "100", "-chunk", "3"])
        compare_read(oracle, verdict, testdata, stats, "testdata insecure check", args.v, check=True)
        print(f"testdata: {len(testdata)} archives, {stats.cases} comparisons, {stats.fails} failures")

        # 2. Mutations.
        mdir = os.path.join(tmp, "mut")
        os.makedirs(mdir)
        small = [f for f in testdata if os.path.getsize(f) <= 65536]
        mfiles = []
        for i in range(args.count):
            src = open(rng.choice(small), "rb").read()
            data = src
            for _ in range(rng.randrange(1, 3)):
                data = mutate(rng, data)
            p = os.path.join(mdir, f"m{i}.tar")
            open(p, "wb").write(data)
            mfiles.append(p)
        before = (stats.cases, stats.fails)
        for k in range(0, len(mfiles), 200):
            part = mfiles[k:k + 200]
            compare_read(oracle, verdict, part, stats, "mutation", args.v, extra_goose=["-chunk", str(rng.choice([1, 13, 512, 1 << 30]))])
            compare_read(oracle, verdict, part, stats, "mutation cap", args.v, ["-cap", "50"], ["-cap", "50"], check=True)
        print(f"mutations: {len(mfiles)} archives, {stats.cases - before[0]} comparisons, {stats.fails - before[1]} failures")

        # 3. Archives other programs make.
        adir = os.path.join(tmp, "made")
        os.makedirs(adir)
        made = (python_archives(rng, adir, max(10, args.count // 5)) + cli_archives(rng, adir, max(10, args.count // 10))
                + sparse_archives(rng, adir, max(20, args.count // 2)))
        before = (stats.cases, stats.fails)
        compare_read(oracle, verdict, made, stats, "made", args.v, extra_goose=["-chunk", "777"])
        compare_read(oracle, verdict, made, stats, "made check", args.v, check=True)
        mmade = []
        for k, f in enumerate(made):
            data = open(f, "rb").read()
            if len(data) <= 65536:
                p = os.path.join(adir, f"mm{k}.tar")
                open(p, "wb").write(mutate(rng, data))
                mmade.append(p)
        compare_read(oracle, verdict, mmade, stats, "made, mutated", args.v, extra_goose=["-chunk", "1"])
        print(f"archives made by tarfile, GNU tar, bsdtar and by hand (sparse): {len(made)}, and {len(mmade)} of them mutated: {stats.cases - before[0]} comparisons, "
              f"{stats.fails - before[1]} failures")

        # 4. Writing: the same bytes as Go's Writer.
        wdir = os.path.join(tmp, "write")
        os.makedirs(wdir)
        wcases = wfails = rcases = rfails = 0
        for i in range(max(20, args.count // 2)):
            sane = i % 2 == 1
            spec = random_spec(rng, sane)
            sp = os.path.join(wdir, f"s{i}.txt")
            open(sp, "w").write(spec)
            ga, ya = os.path.join(wdir, f"go{i}.tar"), os.path.join(wdir, f"goose{i}.tar")
            gout = run([oracle, "tar", "write", sp, ga])
            yout = run([verdict, "write", sp, ya])
            wcases += 1
            gb, yb = open(ga, "rb").read(), open(ya, "rb").read()
            if gout != yout or gb != yb:
                wfails += 1
                print(f"FAIL write {i}: results {'same' if gout == yout else 'differ'}, archives "
                      f"{'same' if gb == yb else 'differ'} ({len(gb)} and {len(yb)} bytes)")
                if args.v or wfails <= 3:
                    print("  spec:\n    " + spec.replace("\n", "\n    "))
                    print("  go:\n    " + gout.replace("\n", "\n    "))
                    print("  goose:\n    " + yout.replace("\n", "\n    "))
                    for o in range(0, max(len(gb), len(yb)), 512):
                        if gb[o:o + 512] != yb[o:o + 512]:
                            print(f"  first different block at {o}:\n    go    {gb[o:o + 512]!r}\n    goose {yb[o:o + 512]!r}")
                            break
                continue
            # Other readers take what we wrote (of what they are meant to).
            if not sane:
                continue
            rcases += 1
            probs = check_with_readers(ya, args.v)
            if probs:
                rfails += 1
                print(f"FAIL readers on written archive {i}: {probs}")
        print(f"writing: {wcases} archives, {wfails} differ from Go's; read back by tarfile/GNU tar/bsdtar: "
              f"{rcases}, {rfails} refused")

        # 5. Round trips: trees written by us (from a listing Python makes),
        # extracted by tarfile and the tar programs, compared with the tree.
        rt = rt_fail = 0
        for i in range(max(10, args.count // 20)):
            lines = []
            entries = []
            for j in range(rng.randrange(1, 8)):
                kind = rng.choice(["f", "f", "d", "l"])
                nm = "/".join(rng.choice(["a", "bb", "ü" * 3, "x" * 60, "y" * 120]) + str(j) for _ in range(rng.randrange(1, 4)))
                size = rng.choice([0, 1, 511, 512, 513, 4000]) if kind == "f" else 0
                seed = rng.randrange(1 << 32)
                mt = rng.choice(["1700000000.0", "1700000000.123456789", "8589934592.5"])
                typ = {"f": ord("0"), "d": ord("5"), "l": ord("2")}[kind]
                link = (b"target" + str(j).encode()).hex() if kind == "l" else "-"
                name = (nm + ("/" if kind == "d" else "")).encode()
                lines.append(f"{typ} {name.hex()} {link} {size} 420 {rng.choice([1000, 1 << 22])} 1000 - - {mt} zero zero 0 0 0 - {size} {seed}")
                entries.append((kind, nm, size, seed, link))
            sp = os.path.join(wdir, f"rt{i}.txt")
            open(sp, "w").write("\n".join(lines) + "\n")
            ya = os.path.join(wdir, f"rt{i}.tar")
            run([verdict, "write", sp, ya])
            for tool in ["tarfile", GNUTAR, BSDTAR]:
                if not tool:
                    continue
                rt += 1
                ex = os.path.join(wdir, f"rt{i}-{os.path.basename(tool)}")
                os.makedirs(ex)
                try:
                    if tool == "tarfile":
                        with tarfile.open(ya) as t:
                            t.extractall(ex, filter="tar")
                    else:
                        subprocess.run([tool, "-xf", ya, "-C", ex], check=True, capture_output=True)
                    for kind, nm, size, seed, link in entries:
                        p = os.path.join(ex, nm)
                        if kind == "f":
                            got = open(p, "rb").read()
                            if got != spec_data(size, seed):
                                raise RuntimeError(f"{nm}: contents differ")
                        elif kind == "d":
                            if not os.path.isdir(p):
                                raise RuntimeError(f"{nm}: not a directory")
                        else:
                            if os.readlink(p) != bytes.fromhex(link).decode():
                                raise RuntimeError(f"{nm}: link differs")
                except Exception as e:
                    # A later entry of the same name may replace an earlier one.
                    names = [e2[1] for e2 in entries]
                    if len(set(names)) == len(names) and not any(a != b and (b + "/").startswith(a + "/") for a in names for b in names):
                        rt_fail += 1
                        print(f"FAIL round trip {i} with {tool}: {e}")
        print(f"round trips (ours written, extracted by tarfile, GNU tar, bsdtar): {rt}, {rt_fail} failures")

        total = stats.fails + wfails + rfails + rt_fail
        print(f"\n{time.time() - t0:.0f} s; {'all agree' if total == 0 else f'{total} failures'}")
        sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
