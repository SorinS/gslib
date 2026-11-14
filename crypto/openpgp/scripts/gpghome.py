"""A throwaway GNUPGHOME for the scripts: made in a temp directory, with its
agent stopped (gpgconf --kill gpg-agent, under that home only) and the
directory removed at the end.

gpg-agent's socket lives in GNUPGHOME, and a Unix socket's path has room
for about 100 bytes, so when the temp directory's path is long, a short
symlink to it is made in $PGP_SHORT_DIR (default /tmp) and used instead.
"""

import os
import shutil
import subprocess
import tempfile

GPG = shutil.which("gpg") or ("/opt/homebrew/bin/gpg" if os.path.exists("/opt/homebrew/bin/gpg") else None)
GPGCONF = shutil.which("gpgconf") or ("/opt/homebrew/bin/gpgconf" if os.path.exists("/opt/homebrew/bin/gpgconf") else None)


class GpgHome:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="pgp")
        self.home = os.path.join(self.dir, "g")
        os.mkdir(self.home, 0o700)
        self.link = None
        if len(self.home) > 60:
            short = os.environ.get("PGP_SHORT_DIR", "/tmp")
            self.link = tempfile.mktemp(prefix="g", dir=short)
            os.symlink(self.home, self.link)
        self.path = self.link or self.home
        with open(os.path.join(self.home, "gpg-agent.conf"), "w") as f:
            # Keys exported for the tests are protected with a small count.
            f.write("s2k-count 65536\n")
        self.env = dict(os.environ, GNUPGHOME=self.path)

    def gpg(self, *args, input=None, check=True):
        p = subprocess.run([GPG, "--batch", "--yes", "--no-tty", *args], env=self.env,
                           input=input, capture_output=True)
        if check and p.returncode != 0:
            raise RuntimeError("gpg %s failed: %s" % (" ".join(args), p.stderr.decode(errors="replace")))
        return p

    def close(self):
        if GPGCONF:
            subprocess.run([GPGCONF, "--kill", "gpg-agent"], env=self.env, capture_output=True)
        if self.link:
            os.unlink(self.link)
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
