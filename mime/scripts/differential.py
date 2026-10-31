#!/usr/bin/env python3
"""Differential test of mimegoose against Go's mime packages.

Generates random cases (media types and their parameters, encoded-words
and headers holding them, quoted-printable data both ways, MIME header
sections, multipart bodies with random boundaries, preambles, epilogues,
CRLF/LF mixes, traps near the boundary, quoted-printable parts, nested
parts and truncations, forms with their limits, file extensions), has Go
(tools/mimeoracle.sh serve) and Goose (tools/mimecheck.goose, which feeds
multipart bodies in pseudo-random pieces) answer each, and compares the
answers byte for byte. Differences are reported by kind, with examples.

    python3 scripts/differential.py [-n CASES] [--seed S] [--kinds k,k] [--goose PATH]

The kind "alltypes" asks for every extension and type of the system's
tables (and Go's built-in one) rather than a random sample.
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
ORACLE = os.path.join(ROOT, "tools", "mimeoracle.sh")
CHECK = os.path.join(ROOT, "tools", "mimecheck.goose")

R = random.Random()


def esc(b):
    if isinstance(b, str):
        b = b.encode("utf-8", "surrogateescape")
    out = []
    for c in b:
        if c < 0x20 or c > 0x7E or c in (0x5C, 0x7C):
            out.append("\\x%02x" % c)
        else:
            out.append(chr(c))
    return "".join(out)


def pick(*xs):
    return R.choice(xs)


def chance(p):
    return R.random() < p


def rand_bytes(n, alphabet=None):
    if alphabet is None:
        return bytes(R.randrange(256) for _ in range(n))
    return bytes(R.choice(alphabet) for _ in range(n))


TOKEN = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`{|}~"
TSPECIALS = b'()<>@,;:\\"/[]?='
UNICODE_SPACES = ["\u00a0", "\u0085", "\u3000", "\u2003", "\u1680", "\u2028"]


def token(n=None):
    return rand_bytes(n or R.randint(1, 8), TOKEN)


def ws():
    return pick(b"", b"", b" ", b"  ", b"\t", b" \t ", b"\r\n ", b"\n",
                UNICODE_SPACES[R.randrange(len(UNICODE_SPACES))].encode())


# --- media types -------------------------------------------------------------

def quoted(v=None):
    v = v if v is not None else rand_bytes(R.randint(0, 10), TOKEN + b' ;=,"\\\t\xc3\xa9')
    out = b'"'
    for c in v:
        ch = bytes([c])
        if ch in (b'"', b"\\") and chance(0.8):
            out += b"\\" + ch
        elif chance(0.05):
            out += b"\\" + ch
        else:
            out += ch
    if chance(0.95):
        out += b'"'
    return out


def pct(v):
    return b"".join(b"%%%02X" % c if (c < 0x21 or c > 0x7E or c in b"%'*" or chance(0.2)) else bytes([c]) for c in v)


def param_value():
    k = R.randrange(9)
    if k < 3:
        return token()
    if k < 5:
        return quoted()
    if k == 5:
        cs = pick(b"utf-8", b"UTF-8", b"us-ascii", b"iso-8859-1", b"", b"US-ASC\xc4\xb0\xc4\xb0")
        v = cs + b"'" + pick(b"", b"en", b"en-us") + b"'" + pct(rand_bytes(R.randint(0, 8)))
        if chance(0.2):
            v += pick(b"%", b"%4", b"%zz")
        return quoted(v) if chance(0.3) else v
    if k == 6:
        return b""
    if k == 7:
        return pct(rand_bytes(R.randint(0, 6)))
    return rand_bytes(R.randint(0, 5))


def param_name():
    base = pick(b"name", b"filename", b"charset", b"title", b"boundary", b"x", b"URL", token(3))
    k = R.randrange(6)
    if k == 0:
        return base + b"*"
    if k == 1:
        return base + b"*" + str(R.randrange(3)).encode()
    if k == 2:
        return base + b"*" + str(R.randrange(3)).encode() + b"*"
    if k == 3 and chance(0.2):
        return pick(b"*", b"**", b"*0", base + b"*01")
    return base


def media_type():
    if chance(0.1):
        return rand_bytes(R.randint(0, 30), TOKEN + TSPECIALS + b" \t\r\n\xc3\xa9")
    t = pick(token(), token() + b"/" + token(), b"Text/HTML", b"multipart/form-data", b"form-data",
             b"", b"/x", b"x/", b"x/y/z", "\u212aey/x".encode(), b"text/plain\xff")
    v = ws() + t + ws()
    for _ in range(R.randint(0, 5)):
        sep = pick(b";", b"; ", b" ; ", b";;", b"", b",")
        v += sep + ws() + param_name() + ws() + pick(b"=", b"=", b"= ", b" =", b"") + ws() + param_value()
    v += pick(b"", b"", b";", b" ;", b"; ", b";\r\n", b" junk", b'"')
    if chance(0.1) and len(v) > 2:
        i = R.randrange(len(v))
        v = v[:i] + rand_bytes(1) + v[i + 1:]
    return v


def gen_mt():
    return ["mt", media_type()]


def gen_fmt():
    t = pick(token(), token() + b"/" + token(), b"foo bar/baz", b"Foo/BAR", b"", b"a/b/c", b"x/\xc3\xa9")
    n = R.randint(0, 4)
    keys = set()
    f = ["fmt", t, str(n)]
    while len(keys) < n:
        keys.add(pick(token(), token().upper(), b"", b"bad key", b"k\xc3\xa9", b"X", b"x"))
    for k in sorted(keys):
        f += [k, rand_bytes(R.randint(0, 12), pick(None, TOKEN, TOKEN + b' "\\\t'))]
    f[2] = str(len(keys))
    return f


# --- encoded words -----------------------------------------------------------

def gen_ew():
    enc = pick(b"b", b"q", b"B", b"Q", b"x")
    cs = pick(b"utf-8", b"UTF-8", b"uTf-8", b"iso-8859-1", b"us-ascii", b"", b"x-unknown")
    k = R.randrange(5)
    if k == 0:
        s = rand_bytes(R.randint(0, 120), TOKEN + b" \t")
    elif k == 1:
        s = "".join(R.choice("aé€😀 _=?\t") for _ in range(R.randint(0, 80))).encode()
    elif k == 2:
        s = rand_bytes(R.randint(0, 100))
    else:
        s = "".join(R.choice(["é", "ß", "😀", "a", " ", "=", "?", "_", "\x80", "日本"]) for _ in range(R.randint(0, 60))).encode("utf-8", "surrogatepass")
    return ["ew", enc, cs, s]


def b64(b):
    import base64
    return base64.b64encode(b)


def word():
    cs = pick(b"UTF-8", b"utf-8", b"ISO-8859-1", b"iso-8859-1", b"US-ASCII", b"us-ascii", b"", b"x-unknown",
              b"u\xc5\xbf-a\xc5\xbfcii", b"?")
    enc = pick(b"Q", b"q", b"B", b"b", b"x", b"", b"QQ")
    if enc in (b"B", b"b"):
        text = b64(rand_bytes(R.randint(0, 20)))
        if chance(0.3):
            i = R.randrange(len(text) + 1)
            text = text[:i] + pick(b"=", b"\r\n", b"!", b"A", b"==", b"") + text[i:]
        if chance(0.2):
            text = text.rstrip(b"=")
    else:
        text = b"".join(pick(b"a", b"_", b" ", b"=41", b"=4", b"=", b"=e9", b"=G1", b"?", b"\t", b"\x01",
                             b"\xc3\xa9", b"=C3=A9", b"~") for _ in range(R.randint(0, 10)))
    w = b"=?" + cs + b"?" + enc + b"?" + text + b"?="
    if chance(0.1) and w:
        w = w[:R.randrange(len(w))]
    return w


def gen_dw():
    return ["dw", word()]


def gen_dh():
    h = b""
    for _ in range(R.randint(0, 5)):
        h += pick(word(), word(), b"plain", b" ", b"\r\n\t", b"  ", b"=?", b"?=", b"\xc3\xa9", b"a=?b")
    return ["dh", h]


# --- quoted-printable ----------------------------------------------------------

def gen_qpr():
    if chance(0.03):
        n = R.choice([4094, 4095, 4096, 4097, 5000])
        return ["qpr", b"a" * n + pick(b"", b"\r\n", b"\n", b"=", b"=\r\nb")]
    alpha = pick(b"0A \r\n=", b"0A \r\n=\t\x00\xffbz=", bytes(range(256)))
    s = rand_bytes(R.randint(0, 60), alpha)
    if chance(0.3):
        s += pick(b"=", b"= ", b"=\r", b"=\n", b"=\r\n", b" ", b"\r")
    return ["qpr", s]


def gen_qpw():
    alpha = pick(None, b"a \t\r\n=", b"a\r\n")
    n = R.choice([R.randint(0, 20), R.randint(60, 200)])
    return ["qpw", pick(b"0", b"1"), rand_bytes(n, alpha)]


# --- headers -------------------------------------------------------------------

def header_section():
    nl = pick(b"\r\n", b"\n")
    h = b""
    if chance(0.05):
        h += pick(b" ", b"\t") + b"X: y" + nl
    for _ in range(R.randint(0, 5)):
        key = pick(token(), b"Content-Type", b"content-disposition", b"X Y", b"", b"K\x01", b"K\xc3\xa9", b"A b",
                   b"foo-BAR")
        val = pick(b"v", b" v ", b"\tv\t", b"", rand_bytes(R.randint(0, 10)), b"a\x7fb", b"a\x00", b"\xc3\xa9")
        line = key + pick(b":", b":", b": ", b" :", b"") + val
        h += line + pick(nl, nl, b"\r\n", b"\n")
        if chance(0.2):
            h += pick(b" ", b"\t", b"  \t") + rand_bytes(R.randint(0, 6), TOKEN + b" ") + pick(nl, b"\n")
    if chance(0.85):
        h += nl
    return h


def gen_hdr():
    return ["hdr", header_section()]


def gen_hdrl():
    return ["hdrl", str(R.choice([0, 400, 600, 612, 650, 800, 1000, 10000])), str(R.randint(0, 5)), header_section()]


# --- multipart -------------------------------------------------------------------

BCHARS = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+_,-./:=?"


def boundary():
    k = R.randrange(10)
    if k == 0:
        return pick(b"foo", b"b", b"MyBoundary", b"--", b"a b")
    if k == 1:
        return rand_bytes(R.randint(1, 70), BCHARS + b" ")
    return rand_bytes(R.randint(1, 20), BCHARS)


def qp_encode(b):
    out = b""
    col = 0
    for c in b:
        if (33 <= c <= 126 and c != 61) or (c == 32 and chance(0.8)):
            piece = bytes([c])
        elif c in (10, 13) and chance(0.5):
            piece = bytes([c])
        else:
            piece = b"=%02X" % c
        if col + len(piece) > 75:
            out += b"=\r\n"
            col = 0
        out += piece
        col += len(piece)
    return out


def body_text(b, nl):
    traps = [nl + b"--" + b, b"--" + b, nl + b"--" + b + b"X", nl + b"--" + b + b"-", b"\r", b"\n",
             b"\r\n", nl + b"--" + b[:max(0, len(b) - 1)], b"=", b"=\r\n"]
    s = b""
    for _ in range(R.randint(0, 6)):
        if chance(0.3):
            s += R.choice(traps)
        else:
            s += rand_bytes(R.randint(0, 20), pick(None, TOKEN + b" \r\n"))
    return s


def multipart_body(b, depth=0):
    nl = pick(b"\r\n", b"\r\n", b"\n")
    out = b""
    for _ in range(R.randint(0, 2)):
        out += pick(b"preamble", b"", b"--" + b + b"x", b"-" + b, b"--notit", rand_bytes(R.randint(0, 30)),
                    b"p" * R.choice([4094, 4095, 4096, 5000]) if chance(0.05) else b"") + pick(nl, b"\r\n", b"\n")
    nparts = R.randint(0, 4)
    for i in range(nparts):
        out += b"--" + b + pick(b"", b"", b" ", b"\t ", b"x") + pick(nl, nl, b"\r\n", b"\n")
        qp = chance(0.2)
        fields = []
        if chance(0.7):
            cd = b"form-data; name=" + pick(b'"f%d"' % i, b"f", b'""', token())
            if chance(0.4):
                cd += b'; filename="' + pick(b"a.txt", b"dir/b.txt", b"C:\\x\\y.txt", b"", b"/", b"../z") + b'"'
            fields.append(b"Content-Disposition: " + pick(cd, b"attachment", b"bogus;;"))
        if qp:
            fields.append(b"Content-Transfer-Encoding: " + pick(b"quoted-printable", b"Quoted-Printable", b"7bit"))
        if chance(0.3):
            fields.append(b"Content-Type: text/plain")
        if chance(0.04):
            fields.append(pick(b"Bad Line", b" folded", b"X:\x01"))
        for fl in fields:
            out += fl + pick(nl, nl, b"\r\n", b"\n")
            if chance(0.05):
                out += b"\t continued" + nl
        out += nl if chance(0.9) else b""
        if depth == 0 and chance(0.1):
            inner = b + pick(b"-bar", b"x", b"")
            data = multipart_body(inner, 1)
        else:
            data = body_text(b, nl)
            if chance(0.05):
                # a body around Go's 4096-byte buffer, a trap at its edge
                k = R.randint(4000, 4200)
                data = rand_bytes(k, TOKEN) + R.choice([nl + b"--" + b, b"\r", nl + b"--" + b + b"x", b""]) + data
            if qp and chance(0.6):
                data = qp_encode(data)
        out += data
        out += pick(nl, nl, b"\r\n", b"\n", b"")
    out += b"--" + b + pick(b"--", b"--", b"-", b"", b"--x") + pick(b"", b" ", b"\t") + pick(nl, b"", b"\r\n")
    out += pick(b"", b"epilogue" + nl, b"--" + b + nl)
    if chance(0.25) and out:
        out = out[:R.randrange(len(out) + 1)]
    return out


def gen_mp():
    b = boundary()
    raw = "".join(pick("0", "1") for _ in range(4)) if chance(0.2) else ""
    return ["mp", b, raw, multipart_body(b)]


def gen_form():
    b = boundary()
    nl = b"\r\n"
    out = b""
    for i in range(R.randint(0, 5)):
        out += b"--" + b + nl
        name = pick(b"a", b"b", b"file", b"", b"x%d" % i)
        cd = b'form-data; name="' + name + b'"'
        if chance(0.5):
            cd += b'; filename="' + pick(b"f.txt", b"", b"d/g.bin") + b'"'
        if chance(0.9):
            out += b"Content-Disposition: " + cd + nl
        if chance(0.3):
            out += b"Content-Type: application/octet-stream" + nl
        if chance(0.1):
            out += b"Content-Transfer-Encoding: quoted-printable" + nl
        out += nl
        out += rand_bytes(R.choice([0, 1, 5, 20, 30, 100, 300]), TOKEN)
        out += nl
    out += b"--" + b + b"--" + nl
    if chance(0.1):
        out = out[:R.randrange(len(out) + 1)]
    if chance(0.01):
        many = b"".join(b"--" + b + nl + b'Content-Disposition: form-data; name="m"' + nl + nl + b"v" + nl
                        for _ in range(R.choice([999, 1000, 1001])))
        out = many + out
    ten = 10 << 20
    mm = R.choice([-1, 0, 1, 10, 25, 30, 100, 1000, 1 << 20, 9223372036854775807, -ten, -ten - 5, -ten + 300,
                   9223372036854775807 - ten + 1, -9223372036854775807 - 1])
    return ["form", b, str(mm), out]


# --- types, writer -------------------------------------------------------------------

def system_extensions():
    exts, types = set(), set()
    for path in ["/etc/mime.types", "/etc/apache2/mime.types", "/etc/apache/mime.types", "/etc/httpd/conf/mime.types"]:
        if os.path.exists(path):
            for line in open(path, encoding="latin-1"):
                f = line.split()
                if len(f) > 1 and not f[0].startswith("#"):
                    types.add(f[0])
                    for e in f[1:]:
                        if e.startswith("#"):
                            break
                        exts.add("." + e)
    for path in ["/usr/local/share/mime/globs2", "/usr/share/mime/globs2"]:
        if os.path.exists(path):
            for line in open(path, encoding="latin-1"):
                f = line.rstrip("\n").split(":")
                if len(f) >= 3 and not f[0].startswith("#"):
                    types.add(f[1])
                    if f[2].startswith("*."):
                        exts.add(f[2][1:])
    for line in open(os.path.join(ROOT, "types_builtin.goose")):
        if "KV { key:" in line:
            k = line.split('"')[1]
            v = line.split('"')[3]
            exts.add(k)
            types.add(v)
    return sorted(exts), sorted(types)


EXTS, TYPES = [], []


def gen_type():
    e = R.choice(EXTS) if EXTS and chance(0.8) else pick(".x", "", "html", ".HTML", ".TxT", ".\u00e9", ".Jpg")
    if chance(0.3):
        e = "".join(c.upper() if chance(0.5) else c for c in e)
    return ["type", e.encode()]


def gen_exts():
    t = R.choice(TYPES) if TYPES and chance(0.8) else pick("text/html", "TEXT/HTML; charset=x", "x/", "", "image/png")
    return ["exts", t.encode()]


def gen_cd():
    return ["cd", rand_bytes(R.randint(0, 10), TOKEN + b'"\\\r\n '), rand_bytes(R.randint(0, 10), TOKEN + b'"\\\r\n ')]


def gen_sb():
    return ["sb", pick(rand_bytes(R.randint(0, 72), BCHARS + b" !\xc3"), b"a" * 70, b"a" * 71, b"x ", b" x")]


KINDS = {
    "mt": gen_mt, "fmt": gen_fmt, "ew": gen_ew, "dw": gen_dw, "dh": gen_dh, "qpr": gen_qpr, "qpw": gen_qpw,
    "hdr": gen_hdr, "hdrl": gen_hdrl, "mp": gen_mp, "form": gen_form, "type": gen_type, "exts": gen_exts,
    "cd": gen_cd, "sb": gen_sb,
}
WEIGHT = {"mp": 4, "form": 2, "mt": 2, "dh": 2}


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def main():
    global EXTS, TYPES
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000, help="cases per kind (times its weight)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--kinds", default=",".join(KINDS))
    ap.add_argument("--goose")
    ap.add_argument("--keep", help="write the cases and both answers into this directory")
    args = ap.parse_args()
    R.seed(args.seed)
    EXTS, TYPES = system_extensions()
    goose = find_goose(args.goose)
    cases = []
    for k in args.kinds.split(","):
        if k == "alltypes":  # every extension (and its upper case) and every type the system has
            for e in EXTS:
                cases += [["type", e.encode()], ["type", e.upper().encode()]]
            for t in TYPES:
                cases.append(["exts", t.encode()])
            continue
        for _ in range(args.n * WEIGHT.get(k, 1)):
            cases.append(KINDS[k]())
    lines = "".join("|".join([c[0]] + [esc(x) for x in c[1:]]) + "\n" for c in cases)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cases.txt")
        open(path, "w").write(lines)
        env = dict(os.environ, GODEBUG="multipartfiles=distinct", TMPDIR=tmp)
        go = subprocess.run([ORACLE, "serve"], input=lines, capture_output=True, text=True, env=env)
        if go.returncode != 0:
            sys.exit("oracle: " + go.stderr)
        exe = os.path.join(tmp, "mimecheck")
        b = subprocess.run([goose, "build", "-o", exe, CHECK], capture_output=True, text=True, cwd=ROOT)
        if b.returncode != 0:
            sys.exit("goose build: " + b.stderr + b.stdout)
        gs = subprocess.run([exe, path], capture_output=True, text=True, env=env)
        if gs.returncode != 0:
            sys.exit("mimecheck: " + gs.stderr[-2000:])
        if args.keep:
            os.makedirs(args.keep, exist_ok=True)
            open(os.path.join(args.keep, "cases.txt"), "w").write(lines)
            open(os.path.join(args.keep, "go.txt"), "w").write(go.stdout)
            open(os.path.join(args.keep, "goose.txt"), "w").write(gs.stdout)
        left = os.listdir(tmp)
    go_lines = go.stdout.split("\n")
    gs_lines = gs.stdout.split("\n")
    diffs = {}
    counts = {}
    for i, c in enumerate(cases):
        counts[c[0]] = counts.get(c[0], 0) + 1
        a = go_lines[i] if i < len(go_lines) else "<none>"
        g = gs_lines[i] if i < len(gs_lines) else "<none>"
        if a != g:
            diffs.setdefault(c[0], []).append((lines.split("\n")[i], a, g))
    total = sum(len(v) for v in diffs.values())
    for k in sorted(counts):
        n = len(diffs.get(k, []))
        print(f"{k:5} {counts[k]:6} cases  {n} differences")
        for case, a, g in diffs.get(k, [])[:3]:
            print(f"      case  {case[:300]}")
            print(f"      go    {a[:300]}")
            print(f"      goose {g[:300]}")
    stray = [f for f in left if f.startswith("multipart-")]
    if stray:
        print(f"temporary files left behind: {len(stray)}")
    print(f"\n{len(cases)} cases, {total} differences (seed {args.seed})")
    sys.exit(1 if total or stray else 0)


if __name__ == "__main__":
    main()
