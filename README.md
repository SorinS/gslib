# gslib

Goose Library: libraries for [Goose](https://github.com/aardappel/goose),
the batteries that a standard library leaves out, in one package, tested
together and versioned together. gslib is not the compiler's standard
library. Some of it may be proposed for that, or as a blessed package,
later.

| Library | What | |
|---|---|---|
| `crypto/bignum` | Integers of any size, constant-time arithmetic, and cryptography: AES, ChaCha20, the SHA-1/2/3 and BLAKE2 hashes, HMAC, HKDF, PBKDF2, scrypt, Argon2, bcrypt, RSA, DSA, ECDH and ECDSA (P-224 to P-521), X25519, Ed25519, ML-KEM, ML-DSA, HPKE, NaCl, the legacy ciphers | [README](crypto/bignum/README.md) |
| `encoding/asn1` | DER and BER reading and writing, PEM | [README](encoding/asn1/README.md) |
| `crypto/x509` | Certificates: parsing, path building and verification, name constraints, policies, system roots, creating certificates, CSRs and CRLs, OCSP, PKCS #12 | [README](crypto/x509/README.md) |
| `crypto/tls` | TLS 1.3 and 1.2, client and server, without I/O: resumption, client certificates, ECH, post-quantum key exchange | [README](crypto/tls/README.md) |
| `crypto/ssh` | SSH (RFC 4251-4254) without I/O, client and server, SFTP; goose-ssh, goose-sshd, goose-scp, goose-sftp-server, goose-ssh-keygen | [README](crypto/ssh/README.md) |
| `net/ldap` | LDAP (RFC 4511): messages, filters, DNs, LDIF, URLs, connections; ldapsearch-style tools | [README](net/ldap/README.md) |
| `encoding/yaml` | YAML 1.2 | [README](encoding/yaml/README.md) |
| `compress` | Compression and archives, as Go's compress/* and archive/*, plus xz: DEFLATE, gzip, zlib, LZW, bzip2, xz and LZMA, zip, tar; reading and writing | [README](compress/README.md) |
| `mime` | MIME, as Go's mime, mime/quotedprintable and mime/multipart, and net/textproto's header sections: media types, RFC 2047 encoded-words, file extensions' types, quoted-printable, multipart bodies and forms | [README](mime/README.md) |
| `net/http` | HTTP/1.1 and HTTP/2, server and client: a client with Go's policy (redirects, cookies, credentials, proxies, gzip, TLS session resumption, streaming uploads, several responses at once), URLs, cookies, HPACK; goose-http and goose-httpd | [README](net/http/README.md) |

## Using it

A program declares the package once, in its root file, and imports the
modules it uses:

```goose
import gslib from "SorinS/gslib@v0.1";     // or a path: import gslib from "../gslib.git";
import gslib.net.http.fetch;
import gslib.crypto.tls.handshake;

fn main() {
    var c = http::Client { .. };
    var r = http::get(c, "https://example.com/");
    print(r.status, " ", http::response_body(r).len);
}
```

The libraries are grouped as Go groups its packages: `crypto/` (bignum,
tls, x509, ssh), `encoding/` (asn1, yaml), `net/` (http, ldap), and
`compress/` and `mime/` at the top, as Go's are (zip and tar are in
compress too: they share its namespace, results and checksums). As in Go,
the group is part of the import path but not of the name in code:
`import gslib.net.http.fetch;`, then `http::get(...)`. Goose namespaces
are one identifier, so each library keeps its own (`http::`, `tls::`,
`bignum::`, …). A library's module `gslib/<group>/<lib>/<m>.goose` is
`import gslib.<group>.<lib>.<m>;`, and its main module
`gslib/<group>/<lib>.goose` is `import gslib.<group>.<lib>;`. Inside
gslib the same modules are `import <group>.<lib>.<m>;`, which the
compiler resolves within the package (packages.md §4.4). compress, with
no group, is `import gslib.compress;` and `import gslib.compress.gzip;`,
and `compress::` in code; mime likewise (`import gslib.mime.multipart;`,
then `multipart::` and `mime::`). Only the
modules a program imports are compiled. The libraries need one another (http needs
tls, x509, asn1 and bignum), and since they are one package, a program
declares only gslib.

The C is http's sockets (`net/http/src/httpnet.c`) and mime's platform
constant (`mime/src/path.c`), named in `gslib.build` and compiled only
into programs that call them. bignum reaches the OS's random bytes through
libc, by an `extern "c"` block; mime's multipart takes them from there.

## Layout

```
gslib.goose, gslib.build              the package's entry and its sidecar
<group>/<lib>.goose                   each library's main module (crypto/tls.goose)
<group>/<lib>/*.goose                 its other modules (crypto/tls/handshake.goose)
<group>/<lib>/test, tools, examples   its programs (excluded from the package in gslib.build)
<group>/<lib>/scripts                 its test runners, differentials, interop
<group>/<lib>/README.md               its documentation
compress.goose, compress/             compress, laid out the same way at the top
mime.goose, mime/                     mime, the same
scripts/run_all.py            every library's unit tests
Makefile                      the programs, checks and tests
```

Each library came from a repository of its own (bigmongoose, asn1goose,
x509goose, tlsgoose, sshgoose, ldapgoose, yamlgoose, httpgoose,
compressgoose, mimegoose), and `git log --follow -- <group>/<lib>` shows that history.

## Requirements

goose.git's master from 683ebc94 (v2026.3-154) on: http's client keeps
its state in a `root struct`. The tests ran with master as it is,
v2026.3-252-g2ed1a63d, on Linux, and on macOS with v2026.3-254-gd402d2c7,
master and one fix of TinyCC's arm64 code (dfe35659, for `goose run`).

On Windows, programs that need random bytes (keys, TLS, SSH) fail to
start until the compiler offers them: bignum reaches `getentropy` through
libc, which Windows does not have. Executables `goose build` writes there
also get a 1 MB stack, which some tests overflow.

`net/http/data/public_suffix_list.dat` is publicsuffix.org's list (MPL 2.0),
built into programs that call `http::psl_builtin`.

## Building

```bash
make            # the targets, with what each does
make build      # the programs into ../bin (BIN=dir for another): goose-http, goose-httpd,
                # goose-ssh, goose-sshd, goose-scp, goose-sftp-server, goose-ssh-keygen,
                # goose-ldapsearch, goose-ldapadd, goose-ldapmodify and the other ldap tools
make check      # type-check every tool and example
```

The compiler is `GOOSE`, else `goose` on the PATH, else
`../goose.git/build/goose`.

## Tests

```bash
make test                 # every library's unit tests (make test-http: one library's)
make test-native          # also built with the C compiler
make interop              # live: OpenSSL, Go, OpenSSH, OpenLDAP, curl, nghttp2, h2spec
make differential         # against Go (net/http, net/url, hpack, compress, mime), zlib, openssl
make test-all             # check, test, interop and differential
python3 scripts/run_all.py [--native] [--only http,tls]   # what make test runs
```

Each library's README lists its differentials (against Go, Python's zlib
and hashlib, OpenSSL), its interop runs (curl, Go's net/http and
crypto/tls, OpenSSL, OpenSSH, OpenLDAP, nghttp2, h2spec), and what is
not done yet. Every server they start listens on 127.0.0.1.
