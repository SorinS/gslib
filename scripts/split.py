#!/usr/bin/env python3
"""Sync gslib's libraries into their standalone repositories.

Each library in SPLITS below also lives in a repository of its own beside
gslib.git (bigmongoose.git for bignum, tlsgoose.git for tls, ...), as a
package named after the library. This copies a library's modules, its C
and sidecars, tests with their vectors and expected outputs, tools,
scripts, README and gslib's examples/<lib>/ into its repository, and
rewrites what differs there:

- imports: inside the library, gslib's package-root names become the
  package's own (`import crypto.tls.record;` -> `import record;`), and
  other libraries become the dependency's package (`import
  crypto.bignum.hmac;` -> `import bignum.hmac;`), with a requirement line
  in the entry file (`import bignum from "...";`), except for the
  packages in SWAPPABLE, which are imported by name only;
- root files (tests, tools, examples): `import gslib from "...";` becomes
  the declarations of the package itself and of every package it needs,
  directly or not, and `import gslib.crypto.tls.handshake;` becomes
  `import tls.handshake;`;
- README and comments: gslib's import snippets and paths, the same way;
- scripts: the paths that assumed gslib's layout.

The dependencies come from the imports, not from the table: a library
that needs one with no repository here, or a cycle between repositories,
stops the sync with the reason.

Dependencies are declared in one of two forms:

  --mode pinned   (the default) GitHub pins, `"SorinS/bigmongoose@<tag>"`,
                  what the repositories publish;
  --mode local    sibling paths, `"../bigmongoose.git"` (as deep as the
                  file is), to build and test the whole set before the
                  tags exist.

A root file always declares its own package by path (`".."`), so its
tests test the working copy. Both modes write the same files but for
those import lines, so running with the same mode twice changes nothing.

Each repository keeps its own LICENSE (a template copyright line is set
to SPLIT_COPYRIGHT), .gitignore (gslib's lines for the library are merged
in) and any file the sync does not produce. A tracked file under what
the sync manages (the package's .goose and .build files at the top,
src/, test/, tools/, scripts/, examples/, data/) that it no longer
produces came from an older copy of the library and is deleted, unless
--keep-stale; other tracked files only in the repository are listed and
kept, unless --delete-other. Nothing is committed: review with git
status and git diff in each repository.

    python3 scripts/split.py [--mode local|pinned] [--tag v0.7.0] [--dest DIR]
                             [--only net,bignum] [--dry-run] [--keep-stale]
                             [--delete-other] [--graph]

--dest is the directory holding the repositories (gslib.git's parent by
default); a repository marked new in the table is created there with
`git init` when it is missing. --tag defaults to gslib's tag at HEAD, or,
when HEAD has none, the latest tag before it (said so on stderr).
--graph prints the dependency graph and the order to tag and push in.
"""

import argparse
import os
import re
import stat
import subprocess
import sys

GSLIB = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OWNER = "SorinS"
SPLIT_COPYRIGHT = "Copyright 2026 SorinS"
TEMPLATE_COPYRIGHT = "Copyright [yyyy] [name of copyright owner]"

# Every gslib library: its name (the package's and namespace's) and where
# it is in gslib, the entry being <path>.goose. A library a split needs
# must have a row in SPLITS too.
LIBRARIES = {
    "entropy": "entropy",
    "bignum": "crypto/bignum", "x509": "crypto/x509", "tls": "crypto/tls",
    "ssh": "crypto/ssh", "openpgp": "crypto/openpgp",
    "asn1": "encoding/asn1", "yaml": "encoding/yaml", "xml": "encoding/xml",
    "cbor": "encoding/cbor",
    "net": "net", "http": "net/http", "ldap": "net/ldap",
    "compress": "compress", "mime": "mime", "krb5": "krb5", "jwx": "jwx",
    "pkcs11": "pkcs11", "dns": "dns", "mail": "mail", "acme": "acme",
    "oauth": "oauth", "tsp": "tsp", "est": "est", "scep": "scep",
    "saml": "saml", "webauthn": "webauthn", "ntlm": "ntlm", "tpm2": "tpm2",
    "radius": "radius",
    "service": "service", "sys": "sys", "sspi": "sspi",
}

# Packages the libraries import by name only, with no requirement line:
# whichever package the program's root declares under that name is the
# one used. A requirement line would make any other source an error
# ("declared from a different source"), and entropy is meant to be
# replaced (a fixed generator for tests, a TPM, an HSM). Root files still
# declare it, as they declare every package they need.
SWAPPABLE = {"entropy"}

# The repositories, one row each:
#   repo      the directory beside gslib.git, without .git, and the GitHub name
#   new       created (git init) when missing
#   subdirs   only these of <path>/ (net: its other subdirectories are http's and ldap's)
#   exclude   gslib paths left out, with why in the comment
#   sidecar   <name>.build at the top, when the package has native parts
#   gitignore lines the repository's .gitignore must have beyond gslib's
#   fixups    (repo file, old, new): text replacements a generic rewrite cannot make
#   readme    the README, when gslib has none for the library ({tag}: the tag)
#   note      a paragraph added to the README's end
SPLITS = {
    "entropy": dict(
        repo="entropygoose", new=True, subdirs=["src", "scripts", "test", "README.md"],
        sidecar=(
            "// entropy's sidecar: the OS's random bytes (src/entropy.c), compiled\n"
            "// only into programs that call them. Windows: BCryptGenRandom.\n"
            "c_sources = [\"src/entropy.c\"];\n"
            "c_libs_windows = [\"bcrypt\"];\n"
            "\n"
            "// Programs, not the package's modules.\n"
            "exclude = [\"examples\", \"test\", \"scripts\"];\n"),
        gitignore=["__pycache__/"],
        fixups=[
            ("entropy.goose", "The C is\n// entropy/src/entropy.c,", "The C is\n// src/entropy.c,"),
            ("entropy.goose", "//   import entropy;        // from a program; `import entropy;` inside gslib",
             "//   import entropy;        // in a program whose root declares entropy"),
        ],
    ),
    "net": dict(
        repo="netgoose", new=True, subdirs=["src", "scripts", "test", "ip.goose", "idna.goose", "README.md"],
        sidecar=(
            "// net's sidecar: the sockets of net.goose (src/net.c), compiled only\n"
            "// into programs that call them.\n"
            "c_sources = [\"src/net.c\"];\n"
            "c_libs_windows = [\"ws2_32\"];\n"
            "\n"
            "// Programs, not the package's modules.\n"
            "exclude = [\"examples\", \"test\", \"scripts\"];\n"),
        gitignore=["__pycache__/", "*.o"],
        fixups=[
            ("net.goose", "The C is net/src/net.c,", "The C is src/net.c,"),
            ("net.goose", "//   import net;        // from a program; `import net;` inside gslib",
             "//   import net;        // in a program whose root declares net"),
            ("net.goose", "// The libraries in net/ (http, ldap) are modules of their own, with their\n"
             "// own namespaces; this one, ip and idna are `net::`.",
             "// http and ldap (httpgoose, ldapgoose) are packages of their own; this\n"
             "// one, ip and idna are `net::`."),
            ("ip.goose", "//   import net.ip;      // `import net.ip;` inside gslib",
             "//   import net.ip;"),
            ("idna.goose", "//   import net.idna;    // `import net.idna;` inside gslib",
             "//   import net.idna;"),
            ("README.md", 'import gslib from "SorinS/gslib@v0.7.0";\nimport gslib.net;\nimport gslib.net.ip;',
             'import net from "SorinS/netgoose@v0.7.0";\nimport net.ip;'),
            ("README.md", "| `gslib.net` |", "| `net` |"),
            ("README.md", "| `gslib.net.ip` |", "| `net.ip` |"),
            ("README.md", "| `gslib.net.idna` |", "| `net.idna` |"),
            ("README.md", "It is what gslib's http, ldap,\ndns and krb5 talk through, and what their tools serve on.",
             "It is what gslib's http, ldap,\ndns and krb5 talk through (httpgoose and ldapgoose among them)."),
            ("README.md", "The C is `net/src/net.c`, named in `gslib.build`", "The C is `src/net.c`, named in `net.build`"),
            ("README.md", "python3 net/scripts/", "python3 scripts/"),
            ("README.md", " DNS itself, record by record, is gslib's dns |", " |"),
        ],
    ),
    "bignum": dict(
        repo="bigmongoose",
        fixups=[
            ("README.md", "gslib's `examples/factorial.goose`", "`examples/factorial.goose`"),
            ("scripts/ct_audit.py", 'os.path.join(ROOT, "..", "bignum.goose")', 'os.path.join(ROOT, "bignum.goose")'),
        ],
    ),
    "asn1": dict(repo="asn1goose"),
    "compress": dict(
        repo="compressgoose",
        fixups=[
            ("scripts/run_tests.py", '"../../compress/README.md"', '"../README.md"'),
        ],
    ),
    "yaml": dict(repo="yamlgoose"),
    "mime": dict(repo="mimegoose"),
    "x509": dict(
        repo="x509goose",
        gitignore=["!examples/*.pem", "!examples/*.p12"],
        fixups=[
            ("scripts/gen_vectors.py", 'os.path.join(ROOT, "..", "tls", "test", "vectors", "rfc8448.txt")',
             'os.path.join(ROOT, "..", "tlsgoose.git", "test", "vectors", "rfc8448.txt")'),
        ],
    ),
    "tls": dict(repo="tlsgoose"),
    "ssh": dict(repo="sshgoose"),
    "ntlm": dict(
        repo="ntlmgoose", new=True,
        exclude=[
            # goose-ntlm needs krb5, dns and http: krb5 and dns have no
            # repository, and http needs ntlm. interop.py drives
            # goose-ntlm, with scripts/gontlm as one of its peers.
            "ntlm/tools/ntlm.goose", "ntlm/tools/ntlm.build",
            "ntlm/scripts/interop.py", "ntlm/scripts/gontlm/",
            # SPNEGO is krb5's (krb5.spnego); no repository.
            "ntlm/test/spnego.goose", "examples/ntlm/spnego.goose",
            # http needs ntlm: this one is httpgoose's to show.
            "examples/ntlm/http_client.goose",
        ],
        gitignore=["__pycache__/"],
        note=(
            "This repository is gslib's ntlm on its own. gslib's goose-ntlm tool and\n"
            "its interop run (scripts/interop.py), the SPNEGO test and example, and\n"
            "the HTTP client example are not here: they need krb5, dns and http,\n"
            "and http needs ntlm. They are in gslib (`ntlm/tools`, `ntlm/scripts`,\n"
            "`examples/ntlm`).\n"),
    ),
    "radius": dict(
        repo="radiusgoose", new=True,
        gitignore=["__pycache__/"],
        fixups=[
            ("README.md", "make test-radius                                  # or: cd radius && python3 scripts/run_tests.py",
             "python3 scripts/run_tests.py"),
            ("README.md", "make interop-radius                               # Linux with Docker",
             "python3 scripts/interop.py                        # Linux with Docker"),
        ],
    ),
    "service": dict(
        repo="servicegoose", new=True,
        sidecar=(
            "// service's sidecar: src/service.c, the service managers' side (the\n"
            "// Windows service control manager, POSIX signals, systemctl and\n"
            "// launchctl), compiled only into programs that call it.\n"
            "c_sources = [\"src/service.c\"];\n"
            "c_libs_windows = [\"advapi32\"];\n"
            "\n"
            "// Programs, not the package's modules.\n"
            "exclude = [\"examples\", \"test\", \"scripts\"];\n"),
        gitignore=["__pycache__/"],
        fixups=[
            ("README.md", "python3 service/scripts/", "python3 scripts/"),
            ("README.md", "# live (make live-service)", "# live"),
        ],
    ),
    "sys": dict(
        repo="osgoose", new=True,
        sidecar=(
            "// sys's sidecar: src/, the system calls (posix.c, unix.c and spawn.c on POSIX,\n"
            "// win.c, winreg.c, winmgmt.c and winspawn.c on Windows, and the stubs for what a\n"
            "// platform lacks), compiled only into programs that call them.\n"
            "c_sources = [\"src/posix.c\", \"src/unix.c\", \"src/spawn.c\", \"src/win.c\", \"src/winreg.c\", \"src/winmgmt.c\", \"src/winspawn.c\", \"src/gssys_stubs.c\"];\n"
            "// Accounts, groups and shares (netapi32), sessions (wtsapi32).\n"
            "c_libs_windows = [\"advapi32\", \"netapi32\", \"wtsapi32\"];\n"
            "\n"
            "// Programs, not the package's modules.\n"
            "exclude = [\"examples\", \"test\", \"scripts\"];\n"),
        gitignore=["__pycache__/"],
        fixups=[
            ("README.md", "python3 sys/scripts/", "python3 scripts/"),
            ("README.md", "`sys/src/api.def`", "`src/api.def`"),
            ("README.md", "`sys/scripts/gen_ffi.py`", "`scripts/gen_ffi.py`"),
            ("README.md", "(`sys/ffi.goose`)", "(`ffi.goose`)"),
            ("README.md", "(`sys/src/gssys_api.h`", "(`src/gssys_api.h`"),
            ("README.md", "(`sys/src/gssys_stubs.c`)", "(`src/gssys_stubs.c`)"),
            ("README.md", "The C is in `sys/src`", "The C is in `src`"),
            ("scripts/gen_ffi.py", "sys/src/", "src/"),
            ("scripts/gen_ffi.py", "sys/ffi.goose", "ffi.goose"),
            ("scripts/gen_ffi.py", "python3 sys/scripts/", "python3 scripts/"),
            ("src/api.def", "sys/scripts/gen_ffi.py makes sys/ffi.goose", "scripts/gen_ffi.py makes ffi.goose"),
            ("scripts/run_tests.py", "run sys/scripts/gen_ffi.py", "run scripts/gen_ffi.py"),
        ],
    ),
    "sspi": dict(
        repo="sspigoose", new=True,
        sidecar=(
            "// sspi's sidecar: src/sspi.c, SSPI's handles and buffers (secur32 and\n"
            "// crypt32 are loaded at run time: nothing to link), compiled only into\n"
            "// programs that call it.\n"
            "c_sources = [\"src/sspi.c\"];\n"
            "\n"
            "// Programs, not the package's modules.\n"
            "exclude = [\"examples\", \"test\", \"scripts\"];\n"),
        exclude=[
            # The live check builds gslib's TLS server (crypto/tls/tools) and goose-ntlm.
            "sspi/scripts/sspi_check.py",
        ],
        gitignore=["__pycache__/"],
        fixups=[("README.md", "python3 sspi/scripts/", "python3 scripts/")],
        note=(
            "This repository is gslib's sspi on its own. Its live check\n"
            "(sspi/scripts/sspi_check.py), which drives gslib's TLS server and\n"
            "goose-ntlm, is in gslib.\n"),
    ),
    "ldap": dict(repo="ldapgoose"),
    "http": dict(
        repo="httpgoose",
        fixups=[
            # net's tests are netgoose's.
            ("scripts/run_tests.py",
             "run once (net's own tests, net/src/net.c's among them, are net's\n"
             "scripts/run_tests.py). --native also builds",
             "run once (net's own tests, net/src/net.c's among them, are\n"
             "netgoose's). --native also builds"),
            # The README names gslib's modules where they are separate packages here.
            ("README.md",
             "Sockets from gslib's `net` module (`net.goose`, C in `net/src/net.c`)",
             "Sockets from [netgoose](https://github.com/SorinS/netgoose)"),
            ("README.md",
             "(gslib's ntlm: `NTLM`",
             "([ntlmgoose](https://github.com/SorinS/ntlmgoose): `NTLM`"),
        ],
    ),
}

# What the sync manages in a repository: a tracked file there that it
# does not produce is stale.
MANAGED_DIRS = ("src/", "test/", "tools/", "scripts/", "examples/", "data/")
# Kept whatever the sync produces.
KEPT = (".gitignore", "LICENSE")

# Modules that are not gslib's: never rewritten.
IMPORT_RE = re.compile(r'^(\s*)import\s+(\.?[A-Za-z_][\w.]*)\s*(?:from\s+"([^"]*)")?\s*;(.*)$')


def die(msg):
    sys.exit("split.py: " + msg)


def git(args, cwd, check=True):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and p.returncode != 0:
        die(f"git {' '.join(args)} in {cwd}: {p.stderr.strip()}")
    return p.stdout


def dotted(path):
    return path.replace("/", ".")


def lib_of(module):
    """The library a gslib package-root module name belongs to, or None."""
    best = None
    for name, path in LIBRARIES.items():
        d = dotted(path)
        if module == d or module.startswith(d + "."):
            if best is None or len(d) > len(dotted(LIBRARIES[best])):
                best = name
    return best


def rename(module, lib):
    """gslib's package-root module name -> the standalone package's name."""
    return lib + module[len(dotted(LIBRARIES[lib])):]


# --------------------------------------------------------------------------
# What a library is made of
# --------------------------------------------------------------------------

class Lib:
    def __init__(self, name, tracked):
        spec = SPLITS[name]
        self.name, self.spec = name, spec
        self.path = LIBRARIES[name]
        self.repo = spec["repo"]
        excl = spec.get("exclude", [])

        def excluded(p):
            return any(p == e or (e.endswith("/") and p.startswith(e)) for e in excl)

        # gslib path -> repository path
        self.files = {}
        entry = self.path + ".goose"
        self.files[entry] = name + ".goose"
        prefix = self.path + "/"
        subdirs = spec.get("subdirs")
        for p in tracked:
            if excluded(p):
                continue
            if p.startswith(prefix):
                rel = p[len(prefix):]
                if subdirs is not None and rel.split("/")[0] not in subdirs:
                    continue
                if rel == ".gitignore":
                    continue
                self.files[p] = rel
            elif p.startswith(f"examples/{name}/"):
                self.files[p] = "examples/" + p[len(f"examples/{name}/"):]
        # Library modules: the entry and the .goose files beside it.
        self.lib_files = {p for p, r in self.files.items()
                          if r.endswith(".goose") and "/" not in r}

    def gslib_text(self, p):
        return open(os.path.join(GSLIB, p), encoding="utf-8").read()


def module_imports(text):
    for line in text.splitlines():
        m = IMPORT_RE.match(line)
        if m:
            yield m.group(2), m.group(3)


def library_deps(lib):
    """Libraries the library's own modules import (directly), with an example of each."""
    deps = {}
    for p in sorted(lib.lib_files):
        for mod, src in module_imports(lib.gslib_text(p)):
            if mod.startswith(".") or src is not None:
                continue
            other = lib_of(mod)
            if other and other != lib.name:
                deps.setdefault(other, f"{p}: import {mod};")
    return deps


def root_gslib_libs(lib, p, seen=None):
    """Libraries a root or helper file imports as gslib.*, with the helpers it imports beside it."""
    seen = seen if seen is not None else set()
    if p in seen:
        return set()
    seen.add(p)
    out = set()
    for mod, src in module_imports(lib.gslib_text(p)):
        if src is not None:
            continue
        if mod.startswith("gslib."):
            other = lib_of(mod[len("gslib."):])
            if other is None:
                die(f"{p}: import {mod}: not a gslib library")
            out.add(other)
        elif mod != "gslib":
            # A helper beside the file (import tv; or import .sysnet;).
            helper = os.path.normpath(os.path.join(os.path.dirname(p), mod.lstrip(".").replace(".", "/") + ".goose"))
            if helper in lib.files:
                out |= root_gslib_libs(lib, helper, seen)
    return out


def is_root(text):
    return any(mod == "gslib" and src is not None for mod, src in module_imports(text))


# --------------------------------------------------------------------------
# The graph
# --------------------------------------------------------------------------

def closure(names, deps):
    out, todo = set(), list(names)
    while todo:
        n = todo.pop()
        if n not in out:
            out.add(n)
            todo.extend(deps.get(n, ()))
    return out


def topo(nodes, edges):
    """Nodes in an order where each comes after what it needs; table order breaks ties."""
    order, state = [], {}

    def visit(n, stack):
        if state.get(n) == 2:
            return
        if state.get(n) == 1:
            die("dependency cycle: " + " -> ".join(stack[stack.index(n):] + [n]))
        state[n] = 1
        for d in [x for x in SPLITS if x in edges.get(n, ())]:
            visit(d, stack + [n])
        state[n] = 2
        order.append(n)

    for n in [x for x in SPLITS if x in nodes]:
        visit(n, [])
    return order


# --------------------------------------------------------------------------
# Rewriting
# --------------------------------------------------------------------------

class Ctx:
    def __init__(self, args, libs, lib_deps, order):
        self.mode, self.tag, self.dest = args.mode, args.tag, args.dest
        self.libs, self.lib_deps, self.order = libs, lib_deps, order

    def pin(self, name):
        return f"{OWNER}/{SPLITS[name]['repo']}@{self.tag}"

    def source(self, name, lib, repo_file):
        """The source of package `name` as written in repo_file of lib's repository."""
        here = os.path.dirname(os.path.join(self.dest, lib.repo + ".git", repo_file))
        if name == lib.name:
            return os.path.relpath(os.path.join(self.dest, lib.repo + ".git"), here)
        if self.mode == "pinned":
            return self.pin(name)
        return os.path.relpath(os.path.join(self.dest, SPLITS[name]["repo"] + ".git"), here)

    def ordered(self, names):
        return [n for n in self.order if n in names]


GSLIB_REF_RE = re.compile(r'\bgslib\.([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*)')
GSLIB_DECL_RE = re.compile(r'import gslib from "[^"]*";')


def rewrite_refs(text, ctx, lib):
    """gslib.<path> in prose and comments -> the standalone module name."""
    def sub(m):
        other = lib_of(m.group(1))
        return rename(m.group(1), other) if other in SPLITS else m.group(0)
    text = GSLIB_REF_RE.sub(sub, text)
    return GSLIB_DECL_RE.sub(f'import {lib.name} from "{ctx.pin(lib.name)}";', text)


def generic_text(text, lib):
    n = lib.name
    for old, new in [
        (f"In gslib's `examples/{n}/`, run from gslib's top as", "In `examples/`, run from the repository's top as"),
        (f"The examples are gslib's examples/{n}.", "The examples are in examples/."),
        (f"gslib's `examples/{n}/`", "`examples/`"),
        (f"gslib's examples/{n}", "examples/"),
        (f"examples/{n}/", "examples/"),
        ("from gslib's top", "from the repository's top"),
        ("beside gslib.git", "beside this repository"),
    ]:
        text = text.replace(old, new)
    return text


def rewrite_script(text, lib):
    text = generic_text(text, lib)
    # The compiler beside the repository, not beside gslib.git.
    text = re.sub(r'os\.path\.join\((\w+), (?:"\.\.", )+"goose\.git"', r'os.path.join(\1, "..", "goose.git"', text)
    # gslib's examples/<lib> -> the repository's examples.
    text = re.sub(r'os\.path\.join\((\w+), (?:"\.\.", )+"examples", "' + lib.name + '"', r'os.path.join(\1, "examples"', text)
    return text


def rewrite_library_module(text, ctx, lib, gpath):
    """A module of the library: package-relative imports, requirements in the entry."""
    is_entry = gpath == lib.path + ".goose"
    deps = ctx.ordered(ctx.lib_deps[lib.name] - SWAPPABLE)
    out, req_at, seen_req = [], None, set()
    for line in text.splitlines(True):
        m = IMPORT_RE.match(line.rstrip("\n"))
        if not m or m.group(2).startswith(".") or m.group(3) is not None:
            out.append(line)
            continue
        ind, mod, tail = m.group(1), m.group(2), m.group(4)
        other = lib_of(mod)
        if other is None:
            out.append(line)
            continue
        if other == lib.name:
            new = lib.name if mod == dotted(lib.path) else mod[len(dotted(lib.path)) + 1:]
            out.append(f"{ind}import {new};{tail}\n")
            continue
        if other not in SPLITS:
            die(f"{gpath}: import {mod}: {other} has no repository")
        if other in SWAPPABLE:
            out.append(f"{ind}import {rename(mod, other)};{tail}\n")
            continue
        if is_entry and mod == dotted(LIBRARIES[other]):
            # The requirement imports the entry: this line becomes it.
            if req_at is None:
                req_at = len(out)
            seen_req.add(other)
            continue
        if is_entry and req_at is None:
            req_at = len(out)
        out.append(f"{ind}import {rename(mod, other)};{tail}\n")
    if is_entry and deps:
        if req_at is None:
            # After the last import at the top, else after the namespace line.
            req_at = 0
            for i, line in enumerate(out):
                if line.startswith("import ") or line.startswith("namespace "):
                    req_at = i + 1
                elif line.strip() and not line.startswith("//") and req_at:
                    break
        reqs = [f'import {d} from "{ctx.source(d, lib, lib.files[gpath])}";\n' for d in deps]
        out[req_at:req_at] = reqs
    return rewrite_refs("".join(out), ctx, lib)


def rewrite_program(text, ctx, lib, gpath):
    """A root file or a helper of one: declarations and gslib.* imports."""
    rfile = lib.files[gpath]
    root = is_root(text)
    declared = set()
    if root:
        need = root_gslib_libs(lib, gpath) | {lib.name}
        for n in need:
            if n not in SPLITS:
                die(f"{gpath} needs {n}, which has no repository (exclude the file, or add {n})")
        declared = closure(need, ctx.lib_deps)
    out = []
    for line in text.splitlines(True):
        m = IMPORT_RE.match(line.rstrip("\n"))
        if not m:
            out.append(line)
            continue
        ind, mod, src, tail = m.groups()
        if mod == "gslib" and src is not None:
            names = [lib.name] + [n for n in ctx.ordered(declared) if n != lib.name]
            for n in names:
                out.append(f'{ind}import {n} from "{ctx.source(n, lib, rfile)}";\n')
            continue
        if mod == "gslib":
            continue
        if mod.startswith("gslib."):
            other = lib_of(mod[len("gslib."):])
            if other not in SPLITS:
                die(f"{gpath}: import {mod}: {other} has no repository")
            if root and mod[len("gslib."):] == dotted(LIBRARIES[other]) and other in declared:
                continue                    # its declaration imports it
            out.append(f"{ind}import {rename(mod[len('gslib.'):], other)};{tail}\n")
            continue
        out.append(line)
    return rewrite_refs("".join(out), ctx, lib)


MD_LINK_RE = re.compile(r'\]\(((?:\.\./)+[^)\s]*|\.\.)\)')


def rewrite_readme(text, ctx, lib):
    deps = ctx.ordered(closure(ctx.lib_deps[lib.name], ctx.lib_deps) - {lib.name})
    lines, out, i = text.splitlines(True), [], 0
    # Code blocks with gslib's declaration: the package's and its needs'.
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("```"):
            j = i + 1
            while j < len(lines) and not lines[j].lstrip().startswith("```"):
                j += 1
            block = lines[i + 1:j]
            if any(GSLIB_DECL_RE.search(b) for b in block):
                nb = []
                for b in block:
                    if GSLIB_DECL_RE.search(b):
                        ind = b[:len(b) - len(b.lstrip())]
                        nb.append(f'{ind}import {lib.name} from "{ctx.pin(lib.name)}";\n')
                        for k, d in enumerate(deps):
                            c = f"   // {lib.name} needs it; the root declares it" if k == 0 else ""
                            nb.append(f'{ind}import {d} from "{ctx.pin(d)}";{c}\n')
                        continue
                    m = IMPORT_RE.match(b.rstrip("\n"))
                    if m and m.group(2).startswith("gslib."):
                        mod = m.group(2)[len("gslib."):]
                        other = lib_of(mod)
                        if other in SPLITS and mod == dotted(LIBRARIES[other]) and (other == lib.name or other in deps):
                            continue
                    nb.append(b)
                block = nb
            out.append(line)
            out.extend(block)
            if j < len(lines):
                out.append(lines[j])
            i = j + 1
            continue
        out.append(line)
        i += 1
    text = rewrite_refs("".join(out), ctx, lib)
    text = generic_text(text, lib)

    # Relative links out of the library's directory.
    def link(m):
        target = os.path.normpath(os.path.join(lib.path, m.group(1)))
        for name, path in LIBRARIES.items():
            if name in SPLITS and (target == path or target.startswith(path + "/")):
                if name == lib.name:
                    return "](" + (os.path.relpath(target, path) if target != path else ".") + ")"
                rest = target[len(path):]
                return f"](https://github.com/{OWNER}/{SPLITS[name]['repo']}" + (f"/tree/main{rest}" if rest else "") + ")"
        if target.startswith(f"examples/{lib.name}"):
            return "](examples" + target[len(f"examples/{lib.name}"):] + ")"
        return f"](https://github.com/{OWNER}/gslib/tree/{ctx.tag}/{target})"
    text = MD_LINK_RE.sub(link, text)
    if lib.spec.get("note"):
        text = text.rstrip("\n") + "\n\n" + lib.spec["note"]
    return text


def merge_gitignore(existing, lib):
    lines = existing.splitlines() if existing else []
    gi = os.path.join(GSLIB, lib.path, ".gitignore")
    want = (open(gi).read().splitlines() if os.path.exists(gi) else []) + lib.spec.get("gitignore", [])
    for w in want:
        if w and w not in lines:
            lines.append(w)
    return "\n".join(lines) + "\n" if lines else None


# --------------------------------------------------------------------------
# One repository
# --------------------------------------------------------------------------

def produce(ctx, lib):
    """repo path -> (bytes, executable) for everything the sync writes."""
    out = {}
    for gpath, rpath in sorted(lib.files.items()):
        full = os.path.join(GSLIB, gpath)
        exe = bool(os.stat(full).st_mode & stat.S_IXUSR)
        if gpath in lib.lib_files:
            data = generic_text(rewrite_library_module(lib.gslib_text(gpath), ctx, lib, gpath), lib)
        elif rpath.endswith(".goose"):
            data = rewrite_program(lib.gslib_text(gpath), ctx, lib, gpath)
            data = generic_text(data, lib)
        elif rpath == "README.md":
            data = rewrite_readme(lib.gslib_text(gpath), ctx, lib)
        elif rpath.endswith((".py", ".sh")):
            data = rewrite_script(lib.gslib_text(gpath), lib)
        else:
            out[rpath] = (open(full, "rb").read(), exe)
            continue
        out[rpath] = (data.encode("utf-8"), exe)
    if lib.spec.get("readme"):
        out["README.md"] = (lib.spec["readme"].replace("{tag}", ctx.tag).encode("utf-8"), False)
    if lib.spec.get("sidecar"):
        out[lib.name + ".build"] = (lib.spec["sidecar"].encode("utf-8"), False)
    for rfile, old, new in lib.spec.get("fixups", []):
        if rfile not in out:
            die(f"{lib.repo}: fixup for {rfile}, which is not produced")
        data = out[rfile][0].decode("utf-8")
        if old not in data:
            if new and new in data:
                continue
            die(f"{lib.repo}/{rfile}: fixup text not found (gslib changed?): {old[:60]!r}")
        out[rfile] = (data.replace(old, new).encode("utf-8"), out[rfile][1])
    return out


def managed(path, name):
    if "/" not in path:
        return path.endswith((".goose", ".build"))
    return path.startswith(MANAGED_DIRS)


def sync(ctx, lib, args):
    repo_dir = os.path.join(ctx.dest, lib.repo + ".git")
    report = {"added": [], "changed": [], "deleted": [], "kept": [], "created": False}
    if not os.path.isdir(repo_dir):
        if not lib.spec.get("new"):
            die(f"{repo_dir} is missing")
        report["created"] = True
        if not args.dry_run:
            os.makedirs(repo_dir)
            git(["init", "-q", "-b", "main"], repo_dir)
    tracked = set(git(["ls-files"], repo_dir).splitlines()) if os.path.isdir(os.path.join(repo_dir, ".git")) else set()
    want = produce(ctx, lib)

    # LICENSE: the repository's own; gslib's where it has none.
    lic = os.path.join(repo_dir, "LICENSE")
    if os.path.exists(lic):
        t = open(lic).read()
        if TEMPLATE_COPYRIGHT in t:
            want["LICENSE"] = (t.replace(TEMPLATE_COPYRIGHT, SPLIT_COPYRIGHT).encode(), False)
    else:
        want["LICENSE"] = (open(os.path.join(GSLIB, "LICENSE"), "rb").read(), False)
    gi = os.path.join(repo_dir, ".gitignore")
    merged = merge_gitignore(open(gi).read() if os.path.exists(gi) else "", lib)
    if merged:
        want[".gitignore"] = (merged.encode(), False)

    for rpath, (data, exe) in sorted(want.items()):
        dst = os.path.join(repo_dir, rpath)
        if os.path.exists(dst):
            same = open(dst, "rb").read() == data
            same_mode = bool(os.stat(dst).st_mode & stat.S_IXUSR) == exe
            if same and same_mode:
                continue
            report["changed"].append(rpath)
        else:
            report["added"].append(rpath)
        if not args.dry_run:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(data)
            mode = os.stat(dst).st_mode
            os.chmod(dst, mode | 0o111 if exe else mode & ~0o111)

    for rpath in sorted(tracked - set(want)):
        if rpath in KEPT or not os.path.exists(os.path.join(repo_dir, rpath)):
            continue
        stale = managed(rpath, lib.name)
        if (stale and not args.keep_stale) or (not stale and args.delete_other):
            report["deleted"].append(rpath)
            if not args.dry_run:
                os.remove(os.path.join(repo_dir, rpath))
                d = os.path.dirname(os.path.join(repo_dir, rpath))
                while d != repo_dir and os.path.isdir(d) and not os.listdir(d):
                    os.rmdir(d)
                    d = os.path.dirname(d)
        else:
            report["kept"].append(rpath + ("" if not stale else " (stale, --keep-stale)"))

    # A file the sync writes that the repository's .gitignore hides would
    # never be committed.
    if not args.dry_run and want:
        p = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"], cwd=repo_dir,
                           input="\n".join(sorted(want)), capture_output=True, text=True)
        report["ignored"] = p.stdout.split()
    return report


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", choices=["pinned", "local"], default="pinned")
    ap.add_argument("--tag")
    ap.add_argument("--dest", default=os.path.dirname(GSLIB))
    ap.add_argument("--only", help="comma-separated library names")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--keep-stale", action="store_true", help="keep files an older copy of the library left")
    ap.add_argument("--delete-other", action="store_true", help="also delete tracked files only the repository has")
    ap.add_argument("--graph", action="store_true", help="print the dependency graph and the tag order, and stop")
    args = ap.parse_args()
    args.dest = os.path.abspath(args.dest)
    if not args.tag:
        args.tag = git(["describe", "--tags", "--exact-match"], GSLIB, check=False).strip()
        if not args.tag:
            args.tag = git(["describe", "--tags", "--abbrev=0"], GSLIB, check=False).strip()
            if not args.tag:
                die("gslib has no tag: pass --tag")
            print(f"split.py: gslib's HEAD has no tag; pinning {args.tag}, the latest before it",
                  file=sys.stderr)

    tracked = git(["ls-files"], GSLIB).splitlines()
    libs = {n: Lib(n, tracked) for n in SPLITS}
    lib_deps, root_deps = {}, {}
    for n, lib in libs.items():
        deps = library_deps(lib)
        for d, why in deps.items():
            if d not in SPLITS:
                die(f"{n} needs {d}, which has no repository ({why})")
        lib_deps[n] = set(deps)
    for n, lib in libs.items():
        rd = set()
        for p in lib.files:
            if p.endswith(".goose") and p not in lib.lib_files and is_root(lib.gslib_text(p)):
                rd |= root_gslib_libs(lib, p)
        missing = rd - set(SPLITS)
        if missing:
            die(f"{n}'s tests, tools or examples need {', '.join(sorted(missing))}, which have no repository")
        root_deps[n] = closure(rd, lib_deps) - closure({n}, lib_deps)
    # Libraries first: a cycle there cannot be published at all.
    topo(set(SPLITS), lib_deps)
    edges = {n: lib_deps[n] | root_deps[n] for n in SPLITS}
    order = topo(set(SPLITS), edges)

    if args.graph:
        for n in order:
            print(f"{n:9} {SPLITS[n]['repo'] + '.git':18} needs {', '.join(ctx_order(order, lib_deps[n])) or '-'}"
                  + (f"; its tests, tools and examples also {', '.join(ctx_order(order, root_deps[n]))}" if root_deps[n] else ""))
        print("tag and push in this order: " + ", ".join(SPLITS[n]["repo"] for n in order))
        return

    ctx = Ctx(args, libs, lib_deps, order)
    only = args.only.split(",") if args.only else order
    for n in only:
        if n not in SPLITS:
            die(f"--only: no library {n}")
    for n in [x for x in order if x in only]:
        r = sync(ctx, libs[n], args)
        print(f"== {SPLITS[n]['repo']}.git ({n})" + ("  [new repository]" if r["created"] else ""))
        for k in ("added", "changed", "deleted"):
            if r[k]:
                print(f"   {k} {len(r[k])}: " + ", ".join(r[k]))
        if r["kept"]:
            print("   kept, only in the repository: " + ", ".join(r["kept"]))
        if r.get("ignored"):
            print("   WARNING: hidden by .gitignore: " + ", ".join(r["ignored"]))
        if not any(r[k] for k in ("added", "changed", "deleted")):
            print("   up to date")
    if args.dry_run:
        print("(dry run: nothing written)")


def ctx_order(order, names):
    return [n for n in order if n in names]


if __name__ == "__main__":
    main()
