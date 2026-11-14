#!/usr/bin/env python3
"""Check mail.message's output against Python's email package.

test/gen_messages.goose writes a set of varied messages, each with a
manifest of what went in. Every message is read with
email.parser.BytesParser(policy=email.policy.default) and must come back as
it was made:

  - the bytes: CRLF line ends only, no line over 998 bytes, a CRLF at the
    end, the header ASCII unless an address is not;
  - no defect anywhere in the parse;
  - From, To, Cc and Reply-To as the same (name, address) pairs; Subject
    and the other fields decoded to the text given; no Bcc; the Date and
    Message-ID given;
  - the nesting of content types, each body's charset and encoding, the
    bodies decoded to the text given (line ends made LF), each file's
    name (RFC 2231 decoded), disposition, Content-ID and bytes.

Then addresses both ways: what write_address wrote, read by
email.headerregistry and email.utils.parseaddr; and what Python's
email.utils.formataddr writes, read by parse_address.

    python3 scripts/check_message.py [--goose PATH] [--keep DIR]

The compiler is --goose, else $GOOSE, else `goose` on PATH, else
~/.local/bin/goose, else ../goose.git/build/goose beside gslib.git.
"""

import argparse
import base64
import email.headerregistry
import email.policy
import email.utils
import json
import os
import shutil
import subprocess
import sys
import tempfile
from email.parser import BytesParser

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

failures = []


def fail(case, what):
    failures.append(f"{case}: {what}")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.expanduser("~/.local/bin/goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


# Pairs for formataddr, which parse_address must read back.
PY_PAIRS = [
    ("", "alice@example.com"),
    ("Alice", "alice@example.com"),
    ("Bob Smith", "bob.smith@example.com"),
    ("Joe Q. Public", "john.q.public@example.com"),
    ("O'Brien, Seán", "sean@example.ie"),
    ("Zoë Ångström", "zoe@example.com"),
    ('"Quoted" Name', "q@example.com"),
    ("a\\b", "ab@example.com"),
    ("日本語の名前", "nihongo@example.jp"),
    ("Müller; Jörg (Büro)", "joerg@example.de"),
    ("x@y", "xy@example.com"),
    ("Dr. Who", "who@example.co.uk"),
]


def check_bytes(case, raw, wide_ok):
    if not raw.endswith(b"\r\n"):
        fail(case, "does not end with CRLF")
    for i, b in enumerate(raw):
        if b == 0x0A and (i == 0 or raw[i - 1] != 0x0D):
            fail(case, f"bare LF at byte {i}")
            break
        if b == 0x0D and (i + 1 >= len(raw) or raw[i + 1] != 0x0A):
            fail(case, f"bare CR at byte {i}")
            break
    for n, line in enumerate(raw.split(b"\r\n")):
        if len(line) > 998:
            fail(case, f"line {n + 1} is {len(line)} bytes")
    head = raw.split(b"\r\n\r\n", 1)[0]
    if not wide_ok and any(b >= 0x80 for b in head):
        fail(case, "header is not ASCII")
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and not line.strip():
            fail(case, "a folded header line of white space only")


def structure(part):
    ct = part.get_content_type()
    if part.is_multipart():
        return ct + "(" + ",".join(structure(p) for p in part.iter_parts()) + ")"
    return ct


def defects(msg):
    out = []
    for p in msg.walk():
        out += [type(d).__name__ for d in p.defects]
        for k in p.keys():
            h = p[k]
            out += [f"{k}: {type(d).__name__}" for d in getattr(h, "defects", ())]
    return out


def pairs(header):
    if header is None:
        return []
    return [[a.display_name, unquote_local(a.addr_spec)] for a in header.addresses]


def unquote_local(spec):
    """An addr-spec with its local part's quotes undone: Python keeps them,
    Go's net/mail (and parse_address) does not."""
    if not spec.startswith('"'):
        return spec
    local, i = "", 1
    while i < len(spec) and spec[i] != '"':
        if spec[i] == "\\":
            i += 1
        local += spec[i]
        i += 1
    return local + spec[i + 1:]


def lf(s):
    return s.replace("\r\n", "\n").replace("\r", "\n")


def check_message(case, raw, man):
    # RFC 6532: an address that is not ASCII is written as it is.
    specs = [p[1] for p in [man["from"]] + man["to"] + man["cc"] + man["reply_to"] if p]
    check_bytes(case, raw, wide_ok=any(ord(c) >= 0x80 for s in specs for c in s))
    msg = BytesParser(policy=email.policy.default).parsebytes(raw)
    d = defects(msg)
    if d:
        fail(case, f"defects: {d}")

    if man["from"] is not None and pairs(msg["From"]) != [man["from"]]:
        fail(case, f"From {pairs(msg['From'])} != {[man['from']]}")
    for key, field in (("to", "To"), ("cc", "Cc"), ("reply_to", "Reply-To")):
        if pairs(msg[field]) != man[key]:
            fail(case, f"{field} {pairs(msg[field])} != {man[key]}")
    if "Bcc" in msg:
        fail(case, "Bcc is written")
    for b in man["bcc"]:
        if b.encode() in raw:
            fail(case, f"Bcc address {b} is in the message")
    if man["subject"] is not None and msg["Subject"] != man["subject"]:
        fail(case, f"Subject {msg['Subject']!r} != {man['subject']!r}")
    for name, value in man["headers"]:
        if msg[name] != value:
            fail(case, f"{name} {msg[name]!r} != {value!r}")
    if msg["Date"].datetime.timestamp() != man["date"]:
        fail(case, f"Date {msg['Date']} is not {man['date']}")
    if msg["Message-ID"] != "<" + man["message_id"] + ">":
        fail(case, f"Message-ID {msg['Message-ID']} != <{man['message_id']}>")
    if msg["MIME-Version"] != "1.0":
        fail(case, "MIME-Version")

    if structure(msg) != man["structure"]:
        fail(case, f"structure {structure(msg)} != {man['structure']}")

    leaves = [p for p in msg.walk() if not p.is_multipart()]
    bodies = [p for p in leaves if p.get_content_disposition() is None]
    files = [p for p in leaves if p.get_content_disposition() is not None]
    # A message of nothing has an empty text/plain body; files alone, none.
    want_bodies = man["bodies"] or ([] if man["files"] else [["text/plain", ""]])
    if len(bodies) != len(want_bodies):
        fail(case, f"{len(bodies)} bodies, not {len(want_bodies)}")
    single = not msg.is_multipart()
    for p, (ctype, text) in zip(bodies, want_bodies):
        if p.get_content_type() != ctype:
            fail(case, f"body type {p.get_content_type()} != {ctype}")
        if (p.get_param("charset") or "").lower() != "utf-8":
            fail(case, f"charset {p.get_param('charset')}")
        if p["Content-Transfer-Encoding"] != man["encoding"]:
            fail(case, f"encoding {p['Content-Transfer-Encoding']} != {man['encoding']}")
        got = lf(p.get_content())
        want = lf(text)
        # A message of one part ends with the CRLF write adds.
        if got != want and not (single and got == want + "\n"):
            fail(case, f"body {ctype} differs:\n  got  {got[:200]!r}\n  want {want[:200]!r}")
    if len(files) != len(man["files"]):
        fail(case, f"{len(files)} files, not {len(man['files'])}")
    for p, f in zip(files, man["files"]):
        inline = f["cid"] != ""
        if p.get_content_disposition() != ("inline" if inline else "attachment"):
            fail(case, f"disposition {p.get_content_disposition()} of {f['name']}")
        if p.get_filename() != f["name"]:
            fail(case, f"filename {p.get_filename()!r} != {f['name']!r}")
        if p.get_param("name") != f["name"]:
            fail(case, f"name {p.get_param('name')!r} != {f['name']!r}")
        if p.get_content_type() != f["type"]:
            fail(case, f"type {p.get_content_type()} != {f['type']} of {f['name']}")
        if p["Content-Transfer-Encoding"] != "base64":
            fail(case, f"{f['name']} is not base64")
        if inline and p["Content-ID"] != "<" + f["cid"] + ">":
            fail(case, f"Content-ID {p['Content-ID']} != <{f['cid']}>")
        if p.get_payload(decode=True) != base64.b64decode(f["data"]):
            fail(case, f"bytes of {f['name']} differ")


def check_addresses(tmp):
    # Ours, read by Python.
    with open(os.path.join(tmp, "addr_out.json"), encoding="utf-8") as f:
        written = json.load(f)
    for name, spec, text in written:
        case = f"write_address {text!r}"
        if "=?" in name:
            # A quoted display name that looks like an encoded-word is
            # text (RFC 2047 §5), as Go writes and reads it; Python decodes
            # it anyway and notes a defect.
            continue
        h = email.headerregistry.HeaderRegistry()("To", text)
        got = [(a.display_name, unquote_local(a.addr_spec)) for a in h.addresses]
        if got != [(name, spec)]:
            fail(case, f"headerregistry {got} != {[(name, spec)]}")
        if h.defects:
            fail(case, f"defects {[type(d).__name__ for d in h.defects]}")
        if all(ord(c) < 0x80 for c in name) and "=?" not in text and "[" not in spec:
            # parseaddr decodes no encoded-words and reads no domain-literals.
            pn, pa = email.utils.parseaddr(text)
            if (pn, unquote_local(pa)) != (name, spec):
                fail(case, f"parseaddr {(pn, pa)} != {(name, spec)}")
    # Python's, read by us.
    with open(os.path.join(tmp, "addr_parsed.json"), encoding="utf-8") as f:
        parsed = json.load(f)
    if len(parsed) != len(PY_PAIRS):
        fail("parse_address", f"{len(parsed)} results for {len(PY_PAIRS)} lines")
    for (line, ok, name, spec), want in zip(parsed, PY_PAIRS):
        if not ok or (name, spec) != want:
            fail(f"parse_address {line!r}", f"{(ok, name, spec)} != {want}")
    return len(written), len(parsed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--keep", help="write the messages here and keep them")
    args = ap.parse_args()
    goose = find_goose(args.goose)

    tmp = args.keep or tempfile.mkdtemp(prefix="mail-check-")
    os.makedirs(tmp, exist_ok=True)
    try:
        with open(os.path.join(tmp, "addr_in.txt"), "w", encoding="utf-8", newline="\n") as f:
            for name, spec in PY_PAIRS:
                f.write(email.utils.formataddr((name, spec)) + "\n")
        p = subprocess.run([goose, "gen_messages.goose", "--", tmp], cwd=os.path.join(ROOT, "test"),
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("gen_messages failed:\n" + p.stdout + p.stderr)
        cases = sorted(f[:-4] for f in os.listdir(tmp) if f.endswith(".eml"))
        for case in cases:
            with open(os.path.join(tmp, case + ".eml"), "rb") as f:
                raw = f.read()
            with open(os.path.join(tmp, case + ".json"), encoding="utf-8") as f:
                man = json.load(f)
            check_message(case, raw, man)
        nw, np = check_addresses(tmp)
    finally:
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)

    for f in failures:
        print("FAIL " + f)
    print(f"{len(cases)} messages, {nw} written and {np} parsed addresses: "
          f"{'ok' if not failures else str(len(failures)) + ' failures'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
