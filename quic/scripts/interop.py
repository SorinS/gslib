#!/usr/bin/env python3
"""quic against aioquic (Python) and quic-go (Go), in Docker on this
machine (Linux), on loopback; each side's HTTP/3 client and server:

  * goose-h3 (tools/h3.goose) against an aioquic server, with and without
    its Retry, and against a quic-go server: a GET, a POST echoed, and a
    body of 300 KB;
  * aioquic's and quic-go's clients against goose-h3d (tools/h3d.goose):
    the same three.

The peers are small programs written here (AIOQUIC_*, QUICGO_*) on
aioquic 1.2.0 and quic-go v0.48.2; their servers' UDP ports are published
on 127.0.0.1 only, their clients use the host's network to reach
goose-h3d on 127.0.0.1.

    python3 scripts/interop.py [--goose PATH] [--work DIR] [--only aioquic|quicgo]
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
AIO_IMAGE = "gs-aioquic"
GO_IMAGE = "gs-quicgo"
BIG = 300000

AIO_DOCKERFILE = """FROM python:3.12-slim
RUN pip install --no-cache-dir aioquic==1.2.0
COPY peer.py /peer.py
"""

AIOQUIC_PEER = r'''
import asyncio, ssl, sys
from aioquic.asyncio import serve, connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration

class Server(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = H3Connection(self._quic)
        self.reqs = {}
    def quic_event_received(self, event):
        for e in self.h3.handle_event(event):
            if isinstance(e, HeadersReceived):
                self.reqs[e.stream_id] = [dict(e.headers), b""]
            elif isinstance(e, DataReceived):
                self.reqs[e.stream_id][1] += e.data
            else:
                continue
            if e.stream_ended:
                h, body = self.reqs.pop(e.stream_id)
                path = h[b":path"].decode()
                if h[b":method"] == b"POST":
                    out = body
                elif path.startswith("/size/"):
                    out = bytes(i * 7 % 251 for i in range(int(path[6:])))
                else:
                    out = ("hello from aioquic: " + path).encode()
                self.h3.send_headers(e.stream_id, [(b":status", b"200"), (b"content-length", str(len(out)).encode())])
                self.h3.send_data(e.stream_id, out, end_stream=True)
                self.transmit()

class Client(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = H3Connection(self._quic)
        self.done = {}
    def quic_event_received(self, event):
        for e in self.h3.handle_event(event):
            if isinstance(e, (HeadersReceived, DataReceived)):
                d = self.done.setdefault(e.stream_id, [None, b"", asyncio.get_event_loop().create_future()])
                if isinstance(e, HeadersReceived):
                    d[0] = dict(e.headers)[b":status"]
                else:
                    d[1] += e.data
                if e.stream_ended and not d[2].done():
                    d[2].set_result(True)
    async def request(self, method, path, body=b""):
        sid = self._quic.get_next_available_stream_id()
        fut = asyncio.get_event_loop().create_future()
        self.done[sid] = [None, b"", fut]
        self.h3.send_headers(sid, [(b":method", method), (b":scheme", b"https"), (b":authority", b"localhost"),
                                   (b":path", path.encode())], end_stream=not body)
        if body:
            self.h3.send_data(sid, body, end_stream=True)
        self.transmit()
        await asyncio.wait_for(fut, 20)
        return self.done[sid][0], self.done[sid][1]

async def main():
    if sys.argv[1] == "server":
        c = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        c.load_cert_chain("/w/cert.pem", "/w/key.pem")
        await serve("0.0.0.0", int(sys.argv[2]), configuration=c, create_protocol=Server, retry=sys.argv[3] == "retry")
        await asyncio.Future()
    c = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE)
    async with connect("127.0.0.1", int(sys.argv[2]), configuration=c, create_protocol=Client) as p:
        st, b = await p.request(b"GET", "/hello")
        print("GET", st.decode(), b.decode())
        st, b = await p.request(b"POST", "/echo", b"posted by aioquic")
        print("POST", st.decode(), b.decode())
        st, b = await p.request(b"GET", "/big")
        print("BIG", st.decode(), len(b), b == bytes(i * 7 % 251 for i in range(len(b))))
        p.close()

asyncio.run(main())
'''

GO_DOCKERFILE = """FROM golang:1.23
WORKDIR /p
COPY go.mod main.go /p/
RUN go mod tidy && go build -o /usr/local/bin/peer .
"""

GO_MOD = """module peer

go 1.23

require github.com/quic-go/quic-go v0.48.2
"""

QUICGO_PEER = r'''
package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/http3"
)

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7 % 251)
	}
	return b
}

func main() {
	if os.Args[1] == "server" {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				b, _ := io.ReadAll(r.Body)
				w.Write(b)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/size/") {
				n, _ := strconv.Atoi(r.URL.Path[6:])
				w.Write(pattern(n))
				return
			}
			fmt.Fprintf(w, "hello from quic-go: %s", r.URL.Path)
		})
		s := http3.Server{Addr: "0.0.0.0:" + os.Args[2], Handler: h}
		panic(s.ListenAndServeTLS("/w/cert.pem", "/w/key.pem"))
	}
	rt := &http3.RoundTripper{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	c := &http.Client{Transport: rt}
	base := "https://127.0.0.1:" + os.Args[2]
	r, err := c.Get(base + "/hello")
	if err != nil {
		panic(err)
	}
	b, _ := io.ReadAll(r.Body)
	fmt.Println("GET", r.StatusCode, string(b))
	r, err = c.Post(base+"/echo", "text/plain", strings.NewReader("posted by quic-go"))
	if err != nil {
		panic(err)
	}
	b, _ = io.ReadAll(r.Body)
	fmt.Println("POST", r.StatusCode, string(b))
	r, err = c.Get(base + "/big")
	if err != nil {
		panic(err)
	}
	b, _ = io.ReadAll(r.Body)
	fmt.Println("BIG", r.StatusCode, len(b), bytes.Equal(b, pattern(len(b))))
	rt.Close()
}
'''

passed = 0
failed = []


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def run(cmd, timeout=600, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        return -1, "timed out: " + str(e)


def check(label, ok, out=""):
    global passed
    print(("ok    " if ok else "FAIL  ") + label, flush=True)
    if ok:
        passed += 1
    else:
        failed.append(label)
        lines = out.strip().splitlines()[-12:]
        if lines:
            print("      " + "\n      ".join(lines))


def build(goose, src, out):
    rc, text = run([goose, "build", src, "-o", out], timeout=1200, cwd=os.path.dirname(src))
    if rc != 0:
        sys.exit("cannot build " + src + ":\n" + text)


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def certificate(work):
    if os.path.exists(os.path.join(work, "cert.pem")):
        return
    rc, out = run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                   "-keyout", os.path.join(work, "key.pem"), "-out", os.path.join(work, "cert.pem"), "-days", "30",
                   "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
    if rc != 0:
        sys.exit("openssl: " + out)
    os.chmod(os.path.join(work, "key.pem"), 0o644)      # the containers read it


def goose_h3_against(work, h3, port, label):
    """goose-h3's GET, POST and big GET against a server on 127.0.0.1:port."""
    out = ""
    for attempt in range(20):                           # the server in its container may not be up yet
        rc, out = run([h3, "-k", f"https://127.0.0.1:{port}/hello"], timeout=60)
        if rc == 0:
            break
        time.sleep(1)
    check(f"goose-h3 GET against {label}", rc == 0 and "hello from" in out and "/hello" in out, out)
    rc, out = run([h3, "-k", "--data", "posted by goose", f"https://127.0.0.1:{port}/echo"], timeout=60)
    check(f"goose-h3 POST against {label}", rc == 0 and out.startswith("posted by goose"), out)
    p = subprocess.run([h3, "-k", f"https://127.0.0.1:{port}/size/{BIG}"], capture_output=True, timeout=120)
    body = p.stdout
    ok = p.returncode == 0 and len(body) == BIG and body == bytes(i * 7 % 251 for i in range(BIG))
    check(f"goose-h3 {BIG} bytes from {label}", ok, p.stderr.decode(errors="replace") + f" got {len(body)}")


def start_h3d(work, h3d, port):
    root = os.path.join(work, "www")
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "big"), "wb") as f:
        f.write(bytes(i * 7 % 251 for i in range(BIG)))
    with open(os.path.join(root, "hello"), "w") as f:
        f.write("hello from goose-h3d")
    log = open(os.path.join(work, f"h3d-{port}.log"), "w")
    p = subprocess.Popen([h3d, "--cert", os.path.join(work, "cert.pem"), "--key", os.path.join(work, "key.pem"),
                          "--port", str(port), "--root", root], stdout=log, stderr=log)
    time.sleep(1)
    return p


def client_against_h3d(out, label):
    check(f"{label} GET from goose-h3d", "GET 200 hello from goose-h3d" in out, out)
    check(f"{label} POST to goose-h3d", "POST 200 posted by" in out, out)
    check(f"{label} {BIG} bytes from goose-h3d", f"big 200 {BIG} true" in out.lower(), out)


def aioquic(goose, work, h3, h3d):
    d = os.path.join(work, "aioquic")
    os.makedirs(d, exist_ok=True)
    write(os.path.join(d, "Dockerfile"), AIO_DOCKERFILE)
    write(os.path.join(d, "peer.py"), AIOQUIC_PEER)
    rc, out = run(["docker", "build", "-q", "-t", AIO_IMAGE, d], timeout=1200)
    if rc != 0:
        check("aioquic image", False, out)
        return
    for retry, port in (("noretry", 4434), ("retry", 4436)):
        name = "gs-aioquic-" + retry
        run(["docker", "rm", "-f", name])
        rc, out = run(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:{port}/udp",
                       "-v", work + ":/w:ro", AIO_IMAGE, "python", "/peer.py", "server", str(port), retry])
        if rc != 0:
            check(f"aioquic server ({retry})", False, out)
            continue
        try:
            goose_h3_against(work, h3, port, "aioquic" + (" with Retry" if retry == "retry" else ""))
        finally:
            run(["docker", "rm", "-f", name])
    p = start_h3d(work, h3d, 4433)
    try:
        rc, out = run(["docker", "run", "--rm", "--network", "host", AIO_IMAGE, "python", "/peer.py", "client", "4433"],
                      timeout=120)
        client_against_h3d(out, "aioquic")
    finally:
        p.kill()


def quicgo(goose, work, h3, h3d):
    d = os.path.join(work, "quicgo")
    os.makedirs(d, exist_ok=True)
    write(os.path.join(d, "Dockerfile"), GO_DOCKERFILE)
    write(os.path.join(d, "go.mod"), GO_MOD)
    write(os.path.join(d, "main.go"), QUICGO_PEER)
    rc, out = run(["docker", "build", "-q", "-t", GO_IMAGE, d], timeout=1800)
    if rc != 0:
        check("quic-go image", False, out)
        return
    name = "gs-quicgo-server"
    run(["docker", "rm", "-f", name])
    rc, out = run(["docker", "run", "-d", "--name", name, "-p", "127.0.0.1:4435:4435/udp",
                   "-v", work + ":/w:ro", GO_IMAGE, "peer", "server", "4435"])
    if rc != 0:
        check("quic-go server", False, out)
    else:
        try:
            goose_h3_against(work, h3, 4435, "quic-go")
        finally:
            run(["docker", "rm", "-f", name])
    p = start_h3d(work, h3d, 4437)
    try:
        rc, out = run(["docker", "run", "--rm", "--network", "host", GO_IMAGE, "peer", "client", "4437"], timeout=120)
        client_against_h3d(out, "quic-go")
    finally:
        p.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--work", default=os.path.join(os.getcwd(), "quic-interop"))
    ap.add_argument("--only", choices=["aioquic", "quicgo"])
    args = ap.parse_args()
    goose = os.path.abspath(find_goose(args.goose))
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    certificate(work)
    h3 = os.path.join(work, "goose-h3")
    h3d = os.path.join(work, "goose-h3d")
    build(goose, os.path.join(ROOT, "tools", "h3.goose"), h3)
    build(goose, os.path.join(ROOT, "tools", "h3d.goose"), h3d)
    if args.only in (None, "aioquic"):
        aioquic(goose, work, h3, h3d)
    if args.only in (None, "quicgo"):
        quicgo(goose, work, h3, h3d)
    print(f"{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
