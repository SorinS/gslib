#!/usr/bin/env python3
"""websocket against Autobahn|Testsuite and Python's websockets, in Docker
on this machine (Linux), on loopback:

  * Autobahn's fuzzingclient against goose-wsecho (tools/wsecho.goose):
    every case (1.* to 13.*: framing, pings, reserved bits, opcodes,
    fragmentation, UTF-8, limits and performance, the closing handshake,
    permessage-deflate with every parameter), messages echoed whole, and
    again echoed a frame at a time (--stream).
  * Autobahn's fuzzingserver against gslib's client
    (test/interop_autobahn.goose), whole and a frame at a time.
  * Python's websockets library: its client against goose-wsecho (text,
    binary, sizes up to 1 MiB, permessage-deflate and not, subprotocols,
    ping and the close code), and goose-wscat against its server.

    python3 scripts/interop.py [--goose PATH] [--work DIR] [--only autobahn|python]

A case passes when Autobahn calls its behaviour OK, NON-STRICT or
INFORMATIONAL and the closing behaviour OK or INFORMATIONAL. The reports
are left in WORK/reports/<time> (index.html in each directory).
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
AUTOBAHN = "crossbario/autobahn-testsuite:25.10.1"
PY_IMAGE = "gs-websockets"
PY_DOCKERFILE = """FROM python:3.12-slim
RUN pip install --no-cache-dir websockets==13.1
"""

passed = 0
failed = []


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def run(cmd, timeout=3600, cwd=None, input=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, input=input)
    return p.returncode, p.stdout + p.stderr


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


def wait_port(port, seconds=60):
    """Until a WebSocket handshake on 127.0.0.1:port gets 101: a published
    container port accepts connections (Docker's proxy) before the server
    in the container listens, so an open port alone proves nothing."""
    req = ("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" % port).encode()
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                s.sendall(req)
                if s.recv(64).startswith(b"HTTP/1.1 101"):
                    return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def build(goose, src, out):
    rc, text = run([goose, "build", src, "-o", out], cwd=os.path.dirname(src))
    if rc != 0:
        sys.exit("cannot build " + src + ":\n" + text)


def start_echo(binary, port, extra, log):
    f = open(log, "w")
    p = subprocess.Popen([binary, "--port", str(port)] + extra, stdout=f, stderr=f)
    if not wait_port(port, 10):
        p.kill()
        sys.exit("goose-wsecho did not start")
    return p


OK_BEHAVIOR = {"OK", "NON-STRICT", "INFORMATIONAL"}
OK_CLOSE = {"OK", "INFORMATIONAL"}


def judge(index_path, agent, label):
    with open(index_path) as f:
        index = json.load(f)
    cases = index.get(agent, {})
    bad = []
    tally = {}
    for case, r in sorted(cases.items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        b, c = r.get("behavior"), r.get("behaviorClose")
        tally[b] = tally.get(b, 0) + 1
        if b not in OK_BEHAVIOR or c not in OK_CLOSE:
            bad.append(f"{case}: {b} / {c}")
    summary = ", ".join(f"{n} {k}" for k, n in sorted(tally.items()))
    check(f"{label}: {len(cases)} cases ({summary})", len(cases) > 0 and not bad, "\n".join(bad))


def autobahn(goose, work):
    tools = os.path.join(ROOT, "tools")
    echo = os.path.join(work, "goose-wsecho")
    build(goose, os.path.join(tools, "wsecho.goose"), echo)
    cfg = os.path.join(work, "config")
    # Autobahn writes its reports as root: each run gets a directory of its own.
    reports = os.path.join(work, "reports", time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(cfg, exist_ok=True)
    os.makedirs(reports)
    # fuzzingclient: Autobahn connects to our servers.
    servers = [{"agent": "goose-wsecho", "url": "ws://127.0.0.1:9101"},
               {"agent": "goose-wsecho-stream", "url": "ws://127.0.0.1:9102"}]
    with open(os.path.join(cfg, "fuzzingclient.json"), "w") as f:
        json.dump({"outdir": "/reports/servers", "servers": servers, "cases": ["*"],
                   "exclude-cases": [], "exclude-agent-cases": {}}, f)
    if os.environ.get("WS_CLIENT_ONLY"):
        return autobahn_clients(goose, cfg, reports)
    p1 = start_echo(echo, 9101, [], os.path.join(work, "wsecho.log"))
    p2 = start_echo(echo, 9102, ["--stream"], os.path.join(work, "wsecho-stream.log"))
    try:
        rc, out = run(["docker", "run", "--rm", "--network", "host", "-v", cfg + ":/config",
                       "-v", reports + ":/reports", AUTOBAHN,
                       "wstest", "-m", "fuzzingclient", "-s", "/config/fuzzingclient.json"], timeout=7200)
        check("fuzzingclient ran", rc == 0, out)
    finally:
        p1.kill()
        p2.kill()
    index = os.path.join(reports, "servers", "index.json")
    if os.path.exists(index):
        judge(index, "goose-wsecho", "server, messages whole")
        judge(index, "goose-wsecho-stream", "server, a frame at a time")
    autobahn_clients(goose, cfg, reports)


def autobahn_clients(goose, cfg, reports):
    # fuzzingserver: our client connects to Autobahn.
    with open(os.path.join(cfg, "fuzzingserver.json"), "w") as f:
        json.dump({"url": "ws://127.0.0.1:9103", "outdir": "/reports/clients", "cases": ["*"],
                   "exclude-cases": [], "exclude-agent-cases": {}}, f)
    run(["docker", "rm", "-f", "gs-autobahn-server"])
    # Servers in containers publish their port on loopback only: never the
    # host's network, which on a test box faces the internet.
    rc, out = run(["docker", "run", "-d", "--name", "gs-autobahn-server", "-p", "127.0.0.1:9103:9103",
                   "-v", cfg + ":/config", "-v", reports + ":/reports", AUTOBAHN,
                   "wstest", "-m", "fuzzingserver", "-s", "/config/fuzzingserver.json"])
    if rc != 0 or not wait_port(9103, 60):
        check("fuzzingserver started", False, out)
        return
    try:
        client = os.path.join(ROOT, "test", "interop_autobahn.goose")
        for agent, extra in (("goose-client", []), ("goose-client-stream", ["--stream"])):
            rc, out = run([goose, "run", client, "--", "ws://127.0.0.1:9103", agent] + extra, timeout=7200)
            check(f"client {agent} ran", rc == 0 and "ran " in out, out)
    finally:
        run(["docker", "rm", "-f", "gs-autobahn-server"])
    index = os.path.join(reports, "clients", "index.json")
    if os.path.exists(index):
        judge(index, "goose-client", "client, messages whole")
        judge(index, "goose-client-stream", "client, a frame at a time")


PY_CLIENT = r'''
import asyncio, sys, websockets
async def main():
    url = sys.argv[1]
    n = 0
    for comp in (None, "deflate"):
        async with websockets.connect(url, compression=comp, max_size=2**24,
                                      subprotocols=["v2.chat", "v1.chat"]) as ws:
            assert ws.subprotocol == "v1.chat", ws.subprotocol
            for size in (0, 1, 125, 126, 65535, 65536, 1 << 20):
                text = ("é" * size)[:size]
                await ws.send(text)
                assert await ws.recv() == text
                data = bytes((i * 7) & 255 for i in range(size))
                await ws.send(data)
                assert await ws.recv() == data
                n += 2
            await ws.send(["frag", "mented ", "message"])
            assert await ws.recv() == "fragmented message"
            pong = await ws.ping(b"hb")
            await asyncio.wait_for(pong, 5)
            n += 2
            await ws.close(4000, "done")
            assert ws.close_code == 4000, ws.close_code
            n += 1
    print("python client:", n, "checks")
asyncio.run(main())
'''

PY_SERVER = r'''
import asyncio, websockets
async def echo(ws):
    async for m in ws:
        await ws.send(m)
async def main():
    async with websockets.serve(echo, "0.0.0.0", 9105, max_size=2**24,
                                subprotocols=["v1.chat"]):
        await asyncio.Future()
asyncio.run(main())
'''


def python_websockets(goose, work):
    pydir = os.path.join(work, "python")
    os.makedirs(pydir, exist_ok=True)
    with open(os.path.join(pydir, "Dockerfile"), "w") as f:
        f.write(PY_DOCKERFILE)
    for name, text in (("client.py", PY_CLIENT), ("server.py", PY_SERVER)):
        with open(os.path.join(pydir, name), "w") as f:
            f.write(text)
    rc, out = run(["docker", "build", "-q", "-t", PY_IMAGE, pydir], timeout=1200)
    if rc != 0:
        check("websockets image", False, out)
        return
    echo = os.path.join(work, "goose-wsecho")
    if not os.path.exists(echo):
        build(goose, os.path.join(ROOT, "tools", "wsecho.goose"), echo)
    wscat = os.path.join(work, "goose-wscat")
    build(goose, os.path.join(ROOT, "tools", "wscat.goose"), wscat)
    for extra, label in (([], "whole"), (["--stream"], "a frame at a time")):
        p = start_echo(echo, 9104, ["--protocol", "v1.chat"] + extra, os.path.join(work, "wsecho-py.log"))
        try:
            rc, out = run(["docker", "run", "--rm", "--network", "host", "-v", pydir + ":/w", PY_IMAGE,
                           "python", "/w/client.py", "ws://127.0.0.1:9104/"], timeout=600)
            check(f"websockets client against goose-wsecho ({label})", rc == 0 and "python client" in out, out)
        finally:
            p.kill()
    run(["docker", "rm", "-f", "gs-websockets-server"])
    rc, out = run(["docker", "run", "-d", "--name", "gs-websockets-server", "-p", "127.0.0.1:9105:9105",
                   "-v", pydir + ":/w", PY_IMAGE, "python", "/w/server.py"])
    if rc != 0 or not wait_port(9105, 60):
        check("websockets server started", False, out)
        return
    try:
        for extra, label in (([], "plain"), (["--compression"], "permessage-deflate")):
            rc, out = run([wscat, "--protocol", "v1.chat", "--wait", "2000", "-x", "hello", "-x", "été",
                           "--close", "4001"] + extra + ["ws://127.0.0.1:9105/"])
            want = "< hello\n< été\n"
            ok = rc == 0 and want in out and ("permessage-deflate" in out) == bool(extra) and "closed: 4001" in out
            check(f"goose-wscat against websockets ({label})", ok, out)
        rc, out = run([wscat, "--binary", "--wait", "2000", "-x", "abc", "ws://127.0.0.1:9105/"])
        check("goose-wscat binary against websockets", rc == 0 and "[binary 3 bytes] 616263" in out, out)
    finally:
        run(["docker", "rm", "-f", "gs-websockets-server"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--work", default=os.path.join(os.getcwd(), "websocket-interop"))
    ap.add_argument("--only", choices=["autobahn", "python"])
    args = ap.parse_args()
    goose = os.path.abspath(find_goose(args.goose))
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    if args.only in (None, "python"):
        python_websockets(goose, work)
    if args.only in (None, "autobahn"):
        autobahn(goose, work)
    print(f"{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
