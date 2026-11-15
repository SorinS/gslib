#!/usr/bin/env python3
"""A hostile SFTP server on stdin and stdout, for scripts/interop.py's
goose-scp cases (run by goose-sshd as its sftp subsystem):

    python3 scripts/evil_sftp.py file|dir

It answers expand-path@openssh.com with a path of its own choosing,
"/evil/.bashrc" (file) or "/evil/.." (dir), as a server that would have
the client write where the user never asked (CVE-2019-6111); every file
it serves has the setuid, setgid and sticky bits set; a directory it lists
holds "payload" and names no client should write: "..", "../escape", "",
"a/b" and ".".
"""

import struct
import sys

MODE = sys.argv[1]
inp = sys.stdin.buffer
outp = sys.stdout.buffer
DATA = b"from the evil server\n"
FILE_PERM = 0o107755                       # a regular file, setuid, setgid, sticky, 0755
DIR_PERM = 0o040755


def u32(b, o): return struct.unpack(">I", b[o:o + 4])[0]
def s(x): return struct.pack(">I", len(x)) + x


def pkt(t, body):
    d = bytes([t]) + body
    outp.write(struct.pack(">I", len(d)) + d)
    outp.flush()


def status(i, code): pkt(101, struct.pack(">II", i, code) + s(b"x") + s(b""))
def attrs(perm, size): return struct.pack(">IQIII", 0x1 | 0x4 | 0x8, size, perm, 1500000000, 1500000000)


def read_exact(n):
    b = b""
    while len(b) < n:
        c = inp.read(n - len(b))
        if not c:
            sys.exit(0)
        b += c
    return b


def is_file(path):
    return MODE == "file" or path.rsplit(b"/", 1)[-1] in (b"payload", b"escape", b"b")


listed = False
while True:
    p = read_exact(u32(read_exact(4), 0))
    t = p[0]
    if t == 1:                                              # INIT
        pkt(2, struct.pack(">I", 3) + s(b"expand-path@openssh.com") + s(b"1"))
        continue
    i = u32(p, 1)
    if t == 200:                                            # EXTENDED
        name = p[9:9 + u32(p, 5)]
        if name == b"expand-path@openssh.com":
            n = b"/evil/.bashrc" if MODE == "file" else b"/evil/.."
            pkt(104, struct.pack(">II", i, 1) + s(n) + s(n) + struct.pack(">I", 0))
        else:
            status(i, 8)
    elif t in (17, 7):                                      # STAT, LSTAT
        path = p[9:9 + u32(p, 5)]
        pkt(105, struct.pack(">I", i) + (attrs(FILE_PERM, len(DATA)) if is_file(path) else attrs(DIR_PERM, 0)))
    elif t == 11:                                           # OPENDIR
        pkt(102, struct.pack(">I", i) + s(b"D"))
        listed = False
    elif t == 12:                                           # READDIR
        if listed:
            status(i, 1)
        else:
            listed = True
            names = [b"payload", b"..", b"../escape", b"", b"a/b", b"."]
            body = struct.pack(">II", i, len(names))
            for n in names:
                body += s(n) + s(n) + attrs(FILE_PERM, len(DATA))
            pkt(104, body)
    elif t == 3:                                            # OPEN
        pkt(102, struct.pack(">I", i) + s(b"F"))
    elif t == 5:                                            # READ
        ln = u32(p, 5)
        off = struct.unpack(">Q", p[9 + ln:17 + ln])[0]
        if off >= len(DATA):
            status(i, 1)
        else:
            pkt(103, struct.pack(">I", i) + s(DATA[off:]))
    elif t == 4:                                            # CLOSE
        status(i, 0)
    else:
        status(i, 8)
