#!/usr/bin/env python3
"""A live check of service: examples/service/heartbeat built, installed,
started, killed (and restarted by the service manager), stopped and
uninstalled, through its own verbs, on the platform this runs on:

  - Windows: a service of the service control manager (run as an
    administrator);
  - Linux: a user's systemd unit (systemctl --user), or the system's with
    --system (as root);
  - macOS: a launchd agent in ~/Library/LaunchAgents, or a daemon with
    --system (as root).

    python3 scripts/service_check.py [--goose PATH] [--dir DIR] [--system] [--cc NAME]

DIR (default: a new temporary directory) holds the program and the file it
writes; on Windows give one the LocalSystem account can read. Whatever it
installed is removed at the end, whether the check passed or not. Exit
status 0 when every step passed.
"""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
NAME = "goose-heartbeat"
WINDOWS = platform.system() == "Windows"
MACOS = platform.system() == "Darwin"


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


class Check:
    def __init__(self, exe, beats, user):
        self.exe, self.beats, self.user = exe, beats, user
        self.failed = 0

    def verb(self, *words):
        cmd = [self.exe] + (["--user"] if self.user else []) + list(words)
        p = subprocess.run(cmd, capture_output=True, text=True)
        return p.returncode, (p.stdout + p.stderr).strip()

    def step(self, what, ok, detail=""):
        print(("ok    " if ok else "FAIL  ") + what + ("" if ok or not detail else "\n      " + detail.replace("\n", "\n      ")))
        if not ok:
            self.failed += 1
        return ok

    def status(self):
        rc, out = self.verb("status")
        m = re.search(r": (.*)$", out)
        return m.group(1) if m else out

    def wait_status(self, want, seconds=20):
        end = time.time() + seconds
        s = self.status()
        while s != want and time.time() < end:
            time.sleep(0.5)
            s = self.status()
        return s

    def lines(self):
        try:
            with open(self.beats) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def wait_lines(self, pred, seconds=20):
        end = time.time() + seconds
        while time.time() < end:
            if pred(self.lines()):
                return True
            time.sleep(0.5)
        return False

    def pid(self):
        """The running service's process id, from its service manager."""
        if WINDOWS:
            out = subprocess.run(["sc", "queryex", NAME], capture_output=True, text=True).stdout
            m = re.search(r"PID\s*:\s*(\d+)", out)
        elif MACOS:
            dom = f"gui/{os.getuid()}" if self.user else "system"
            out = subprocess.run(["launchctl", "print", f"{dom}/{NAME}"], capture_output=True, text=True).stdout
            m = re.search(r"\bpid = (\d+)", out)
        else:
            out = subprocess.run(["systemctl"] + (["--user"] if self.user else []) +
                                 ["show", "-p", "MainPID", "--value", NAME + ".service"],
                                 capture_output=True, text=True).stdout
            m = re.search(r"(\d+)", out)
        n = int(m.group(1)) if m else 0
        return n if n > 0 else 0

    def kill(self, pid):
        if WINDOWS:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        else:
            os.kill(pid, 9)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--dir")
    ap.add_argument("--system", action="store_true", help="the system's unit or daemon, not a user's")
    ap.add_argument("--cc", help="the C compiler for goose build")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    work = args.dir or tempfile.mkdtemp(prefix="goose-service-")
    os.makedirs(work, exist_ok=True)
    exe = os.path.join(work, NAME + (".exe" if WINDOWS else ""))
    beats = os.path.join(work, "beats.txt")
    user = not WINDOWS and not args.system

    ex_dir = os.path.join(ROOT, "..", "examples", "service")
    cmd = [goose, "build"] + (["--cc", args.cc] if args.cc else []) + ["-o", exe, "heartbeat.goose"]
    p = subprocess.run(cmd, cwd=ex_dir, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("build failed:\n" + p.stdout + p.stderr)
    print(f"built {exe}")

    c = Check(exe, beats, user)
    # Whatever an earlier run left.
    if c.status() != "not installed":
        c.verb("stop")
        c.verb("uninstall")
        time.sleep(2)
    if os.path.exists(beats):
        os.remove(beats)
    try:
        rc, out = c.verb("install", beats)
        c.step("install", rc == 0, out)
        rc, out = c.verb("install", beats)
        c.step("install again is refused", rc != 0 and "already installed" in out, out)
        s = c.status()
        c.step("installed, not running", s == "stopped", s)

        rc, out = c.verb("start")
        c.step("start", rc == 0, out)
        s = c.wait_status("running")
        c.step("running", s == "running", s)
        c.step("beats", c.wait_lines(lambda l: "beat 2" in l),
               "\n".join(c.lines()[-5:]))
        c.step("started as a service", "started service" in c.lines(), "\n".join(c.lines()[:3]))

        # Killed: the service manager starts it again (restart_ms 5 s).
        pid = c.pid()
        if c.step("its process id", pid > 0):
            c.kill(pid)
            starts = lambda l: sum(1 for x in l if x.startswith("started"))
            c.step("restarted after it was killed", c.wait_lines(lambda l: starts(l) >= 2, 40),
                   "\n".join(c.lines()[-5:]))
            s = c.wait_status("running")
            c.step("running again", s == "running", s)
            c.step("a new process", c.pid() not in (0, pid))

        rc, out = c.verb("stop")
        c.step("stop", rc == 0, out)
        c.step("stopped cleanly", c.wait_lines(lambda l: l and l[-1] == "stopped"),
               "\n".join(c.lines()[-5:]))
        s = c.wait_status("stopped")
        c.step("stopped", s == "stopped", s)
        n = len(c.lines())
        time.sleep(7)
        c.step("stays stopped", len(c.lines()) == n and c.status() == "stopped")

        rc, out = c.verb("restart")
        c.step("restart from stopped", rc == 0, out)
        c.step("running after restart", c.wait_status("running") == "running")
        rc, out = c.verb("restart")
        c.step("restart while running", rc == 0 and c.wait_status("running") == "running", out)
        c.step("stopped by the restart", sum(1 for x in c.lines() if x == "stopped") >= 2)
        rc, out = c.verb("stop")
        c.step("stop", rc == 0, out)
    finally:
        c.wait_status("stopped", 10)
        rc, out = c.verb("uninstall")
        c.step("uninstall", rc == 0, out)
        s = c.wait_status("not installed", 30)
        c.step("not installed", s == "not installed", s)
        rc, out = c.verb("start")
        c.step("start when not installed is refused", rc != 0 and "not installed" in out, out)
    print(f"\n{'all passed' if c.failed == 0 else str(c.failed) + ' failed'}")
    sys.exit(1 if c.failed else 0)


if __name__ == "__main__":
    main()
