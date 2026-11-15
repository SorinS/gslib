#!/usr/bin/env python3
"""src/net.c without Goose: test/native/net_drive.c compiled with
it and run against two servers on 127.0.0.1 (an HTTP one, and one that
accepts and never answers): connecting by address and by name, writing,
reading to the end, a read timing out, a write to a peer that never
reads timing out, refused, unresolvable and empty hosts, and whether a
connection the server closed reads as such.

    python3 scripts/net_check.py [--cc CC]       # POSIX: cc, -Wall -Wextra
    python3 scripts/net_check.py --msvc          # Windows: cl /W4, from a vcvars64 shell
"""

import argparse
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    ap.add_argument("--msvc", action="store_true")
    args = ap.parse_args()
    src = [os.path.join(ROOT, "test", "native", "net_drive.c"), os.path.join(ROOT, "src", "net.c")]
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "drive.exe" if args.msvc else "drive")
        if args.msvc:
            cmd = ["cl", "/nologo", "/W4", "/WX", "/O2", *src, "ws2_32.lib", "/Fe:" + exe, "/Fo:" + tmp + "\\"]
        else:
            cmd = [args.cc, "-O2", "-Wall", "-Wextra", "-Werror", "-o", exe, *src]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("compile failed:\n" + p.stdout + p.stderr)
        h = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(8)
        held = []

        def accept():
            try:
                while True:
                    held.append(s.accept()[0])
            except OSError:
                pass
        threading.Thread(target=accept, daemon=True).start()
        threading.Thread(target=h.serve_forever, daemon=True).start()
        # The watchdog: a call that blocks past its timeout fails the run
        # instead of hanging it.
        try:
            p = subprocess.run([exe, str(h.server_address[1]), str(s.getsockname()[1])], capture_output=True,
                               text=True, timeout=30)
            out, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired as e:
            out = (e.stdout.decode() if isinstance(e.stdout, bytes) else e.stdout or "")
            out += "FAIL the driver was still running after 30 s, and was killed\n"
            rc = 1
        print(out, end="")
        h.shutdown()
        s.close()
        sys.exit(rc)


if __name__ == "__main__":
    main()
