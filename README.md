# gslib

Goose Library: libraries for [Goose](https://github.com/aardappel/goose),
the batteries that a standard library leaves out, in one package, tested
together and versioned together. gslib is not the compiler's standard
library. Some of it may be proposed for that, or as a blessed package,
later.

| Library | What | |
|---|---|---|
| `crypto/bignum` | Integers of any size, constant-time arithmetic, and cryptography: AES, Camellia, ChaCha20, the SHA-1/2/3 and BLAKE2 hashes, HMAC, CMAC, AES Key Wrap (RFC 3394 and 5649, used by jwx), HKDF, PBKDF2, scrypt, Argon2, bcrypt, RSA, DSA, ECDH and ECDSA (P-224 to P-521), X25519, Ed25519, ML-KEM, ML-DSA, SLH-DSA, HPKE, NaCl, the legacy ciphers | [README](crypto/bignum/README.md) |
| `encoding/asn1` | DER and BER reading and writing, PEM | [README](encoding/asn1/README.md) |
| `crypto/x509` | Certificates: parsing, path building and verification, name constraints, policies, system roots, creating certificates, CSRs and CRLs, OCSP, PKCS #12; post-quantum ML-DSA and SLH-DSA keys and signatures, ML-KEM keys, CMS with ML-DSA signers and ML-KEM recipients | [README](crypto/x509/README.md) |
| `crypto/tls` | TLS 1.3 and 1.2, client and server, without I/O: resumption, client certificates, ECH, post-quantum key exchange | [README](crypto/tls/README.md) |
| `crypto/ssh` | SSH (RFC 4251-4254) without I/O, client and server, SFTP; goose-ssh, goose-sshd, goose-scp, goose-sftp-server, goose-ssh-keygen | [README](crypto/ssh/README.md) |
| `net/ldap` | LDAP (RFC 4511): messages, filters, DNs, LDIF, URLs, connections; ldapsearch-style tools | [README](net/ldap/README.md) |
| `encoding/yaml` | YAML 1.2 | [README](encoding/yaml/README.md) |
| `compress` | Compression and archives, as Go's compress/* and archive/*, plus xz: DEFLATE, gzip, zlib, LZW, bzip2, xz and LZMA, zip, tar; reading and writing | [README](compress/README.md) |
| `mime` | MIME, as Go's mime, mime/quotedprintable and mime/multipart, and net/textproto's header sections: media types, RFC 2047 encoded-words, file extensions' types, quoted-printable, multipart bodies and forms | [README](mime/README.md) |
| `krb5` | Kerberos V5 (RFC 4120) as go-krb5 has it: TGTs and service tickets (password, keytab, cross-realm, referrals, FAST armoring), the acceptor, GSS-API (RFC 4121), SPNEGO and HTTP Negotiate, Microsoft's PAC, keytabs and credential caches; goose-krb5 (kinit, kvno, klist) and goose-gss | [README](krb5/README.md) |
| `jwx` | JOSE, as Go's lestrrat-go/jwx: JSON Web Keys (and key sets, thumbprints, PEM), Signatures (compact and JSON, every RFC 7518 algorithm, EdDSA and post-quantum ML-DSA (RFC 9964)), Encryption (every key management and content algorithm, zip, several recipients) and Tokens (claims, validation, nested) | [README](jwx/README.md) |
| `pkcs11` | PKCS#11 (Cryptoki), as Go's miekg/pkcs11: modules (HSMs, tokens, SoftHSM) loaded at run time, every C_* function, templates, mechanisms and their parameters, all the OASIS constants; and miekg's p11 layer (Module, Slot, Session, Object, keys) | [README](pkcs11/README.md) |
| `dns` | The DNS, as Go's miekg/dns: messages and the 79 record types it implements, in wire form (with compression) and text, zone files (`$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`), EDNS0, DNSSEC (signing, verifying, DS, NSEC3, keys), TSIG and SIG(0), dynamic updates, zone transfers, a client and a server; goose-dig and goose-dnsd | [README](dns/README.md) |
| `crypto/openpgp` | OpenPGP (RFC 9580, RFC 4880 as gpg writes it): keys (Ed25519/Curve25519, RSA, ECDSA/ECDH on NIST curves, v6 read), protected secret keys, signatures (inline, detached, cleartext), encryption to keys and passphrases (SEIPD v1, gpg's OCB packet and SEIPD v2 read), compression, key generation; post-quantum ML-KEM-768+X25519 (gpg 2.5's and RFC 9980's) and ML-DSA-65+Ed25519 (RFC 9980); goose-pgp | [README](crypto/openpgp/README.md) |
| `mail` | Email, as Go's go-mail for sending: messages built and written as MIME (addresses, text and HTML, attachments, inline parts), an SMTP client (STARTTLS or TLS, AUTH with PLAIN, LOGIN, CRAM-MD5, SCRAM-SHA-1/256, XOAUTH2, SMTPUTF8, DSN), a POP3 client (STLS, APOP, SASL, UIDL, TOP) and an IMAP client (IMAP4rev2 and rev1: mailboxes, FETCH with ENVELOPE and BODYSTRUCTURE, SEARCH, STORE, MOVE, APPEND, IDLE); DKIM signing and verifying (RSA, Ed25519); S/MIME (ML-DSA and ML-KEM too) and PGP/MIME signing and encryption; goose-mail | [README](mail/README.md) |
| `net/http` | HTTP/1.1 and HTTP/2, server and client: a client with Go's policy (redirects, cookies, credentials, proxies, gzip, TLS session resumption, streaming uploads, several responses at once), URLs, cookies, HPACK; goose-http and goose-httpd | [README](net/http/README.md) |
| `net` | TCP client sockets, as the client half of Go's net: `net::dial` with a deadline, `net::read` and `net::write` with timeouts, `net::readable`, `net::close`; what http, dns, krb5 and the examples connect with (POSIX and Winsock) | [net.goose](net.goose) |

## dns, pkcs11, jwx, mail and openpgp

These five have the most to say beyond their table rows: what each
module does, how it was built and how it was tested. Each README has the
full API.

### dns: the DNS

`dns` is modelled on Go's
[miekg/dns](https://github.com/miekg/dns) (v1.1.73); its
[README](dns/README.md) has the API, the design and the departures.

- **`dns`**: domain names in wire and text form (RFC 1035 escapes, as
  miekg writes them), label functions, canonical order (RFC 4034 §6.1),
  reverse names; the numbers and names of types, classes, rcodes, opcodes.
- **`dns.rdata`**: the 79 record types miekg implements, each described by a
  layout of its fields, which one codec uses to check rdata, decompress and
  compress its names, lower-case them for DNSSEC and write its text.
  Unknown types are kept opaque (RFC 3597).
- **`dns.msg`**: messages, packed with name compression and unpacked;
  miekg's `Msg.String()`; `set_question`, `set_reply`, `truncate`, `dedup`.
- **`dns.zone`**: zone files and single records from text, with `$ORIGIN`,
  `$TTL`, `$INCLUDE`, `$GENERATE`, parentheses, TTL units.
- **`dns.edns`**: the OPT record and its options (client subnet,
  cookies, keepalive, padding, extended errors, ...).
- **`dns.dnssec`**: RRSIG signing and verification with RSA (SHA-1,
  SHA-256, SHA-512), ECDSA (P-256, P-384) and Ed25519; key tags, DS,
  validity periods, NSEC3 hashing; key generation and BIND's private-key
  files.
- **`dns.tsig`**, **`dns.sig0`**: TSIG (HMAC-MD5 to HMAC-SHA512) over
  queries, replies and the messages of a zone transfer; SIG(0).
- **`dns.update`**, **`dns.client`**, **`dns.server`**: dynamic updates
  (RFC 2136); queries over UDP and TCP with TSIG, zone transfers in,
  resolv.conf; a server over UDP and TCP whose handler is a block.
- **goose-dig** (miekg's `q`) and **goose-dnsd**, an authoritative server
  for zone files (referrals, wildcards, CNAMEs, AXFR/IXFR, NOTIFY,
  updates, TSIG).

A record is held as its uncompressed wire form, and a section or zone as
records back to back, read through offsets: Goose has no interfaces or
garbage collector for miekg's struct per type. The C (`dns/src/dnsnet.c`,
in the package sidecar) is UDP and listening sockets; TCP is http's.

Tested against miekg/dns itself, which `dns/scripts/oracle` (a Go module
pinned to v1.1.73) uses to write the vectors: 160 records and 23 refusals,
52 messages packed into miekg's bytes, a zone file, miekg's DNSSEC keys
and signatures for every algorithm (RSA and Ed25519 signatures remade
byte for byte), TSIG messages for every SHA HMAC remade byte for byte,
SIG(0), updates, EDNS0 options and truncation; RFC 8080's Ed25519 RRSIG
remade exactly. Over the network: dig against goose-dnsd, miekg's client
against goose-dnsd, goose-dig against a miekg server, including TSIG-signed
zone transfers of several messages that dig and miekg verify (`make
interop-dns`), and fresh vectors from miekg (`make differential-dns`).
Tested on macOS, Linux (where dig 9.18's DNS cookies found a bug in reading
OPT records with options) and Windows; there, all but DNSSEC and SIG(0)
(which need bignum's random bytes) work, goose-dig and goose-dnsd included.
Departures from miekg (AMTRELAY's gateway, NSEC type order, RFC 3597
rdata, a server that answers bad TSIG itself) are in its README.

### pkcs11: PKCS#11 modules, HSMs and tokens

`pkcs11` is modelled on Go's
[miekg/pkcs11](https://github.com/miekg/pkcs11); its
[README](pkcs11/README.md) has the API, the C↔Goose encodings and the
limits.

- **`pkcs11`**: a module loaded at run time, and every function of its
  function list (the 68 of PKCS#11 2.40): slots, tokens, sessions, login and
  PINs, objects and their attributes, searches, encryption, decryption,
  digests, signatures (with recovery), the dual-function updates, key
  generation, wrapping, unwrapping and derivation, random numbers, slot
  events. Templates and mechanisms are built in Goose, with the
  parameters of GCM, CCM, OAEP, PSS, ECDH1, RSA-AES key wrap and EdDSA;
  error names as miekg gives them.
- **`pkcs11.constants`**: the 939 constants of the OASIS PKCS#11 3.1
  header, generated by `scripts/gen_const.py`, with name tables.
- **`pkcs11.p11`**: miekg's p11 layer: Module, Slot, Session, Object, and
  private, public and secret keys that sign, verify, encrypt, decrypt and
  derive.

The C (`pkcs11/src/p11.c`, in the package sidecar) loads the module with
`dlopen` or `LoadLibrary` and calls through its `CK_FUNCTION_LIST`. It
declares the PKCS#11 types itself, with Windows' 4-byte `CK_ULONG` and
1-byte packing, its function order and structure layouts checked against
the OASIS headers.

Tested against SoftHSM2 on fresh tokens, each cryptographic result checked
with crypto/bignum (AES-CBC, ECB, GCM, AES Key Wrap, SHA-2, HMAC, RSA PKCS
#1 v1.5, PSS and OAEP, ECDSA on P-256 and P-384 both ways, Ed25519, ECDH),
and against OpenSC's pkcs11-tool and OpenSSL both ways (`make
interop-pkcs11`). Tested on macOS; the Linux and Windows paths are written
but not yet run. Mechanism parameters live only for the call that takes
them, so modules that write a GCM IV back later are not supported.

### jwx: JOSE (JWA, JWK, JWS, JWE, JWT)

`jwx` is modelled on Go's
[lestrrat-go/jwx](https://github.com/lestrrat-go/jwx); its
[README](jwx/README.md) has the API and the design.

- **`jwx`**: error codes and strict base64url (no padding, no stray bits).
- **`jwx.jwa`**: every algorithm, key type and curve of RFC 7518, RFC 8037,
  RFC 9864 and RFC 9964, with what each needs.
- **`jwx.jwk`**: keys and key sets (RSA, EC P-256/384/521, OKP Ed25519 and
  X25519, oct, AKP ML-DSA-44/65/87), checked for consistency; RFC 7638 thumbprints; generation.
- **`jwx.pem`**: keys from and to PEM and DER: PKCS #8, SEC 1, PKCS #1,
  SubjectPublicKeyInfo, and certificates (with `x5t` and `x5t#S256`);
  ML-DSA keys as RFC 9881 has them.
- **`jwx.jws`**: signatures, compact and JSON (general and flattened),
  detached and unencoded (RFC 7797) payloads; HS, RS, PS, ES, EdDSA and
  ML-DSA.
- **`jwx.jwe`**: encryption, compact and JSON, several recipients,
  additional authenticated data, `zip`; RSA1_5, RSA-OAEP(-256/384/512),
  A*KW, dir, ECDH-ES(+A*KW) on the NIST curves and X25519, A*GCMKW, PBES2;
  A*CBC-HS* and A*GCM.
- **`jwx.jwt`**: claims, signed, encrypted and nested tokens, validation
  of exp, nbf, iat, iss, sub, aud, jti, max age and required claims.

Verifying and decrypting take the algorithm the caller expects, so a token
cannot choose its own (no alg confusion, no `none` unless asked for by
name). Key unwrap and decryption failures are uniform, RSA1_5 continues
with a random key on bad padding, and ECDH-ES ephemeral keys are checked
to be on their curve. As jwx v4, PBES2 encrypts with OWASP 2023's counts
(600000, 210000) and decrypting accepts 1000 to 1000000, and `zip`
payloads may inflate to 10 MB, both adjustable.

Departures from jwx: keys keep only the members RFC 7517 and RFC 7518
define (no private members, no `x5c`), as Goose's fixed-size structs
cannot hold them; and a JWE header parameter may appear in two headers
only with the same value (Go's jwx v3 repeats `alg`, which RFC 7516 §7.2.1
forbids). Not supported: Ed448, X448, ES256K, multi-prime RSA keys,
HashML-DSA, ML-DSA contexts, expanded ML-DSA private keys in JWKs.

Tested against RFC 7520's examples (the JOSE cookbook), with 10
ciphertexts and 8 encrypted keys remade byte for byte; RFC 7515, 7517,
7518 Appendix C, 7519, 7638, 7797, 8037 and 9964 (its ML-DSA signatures
remade byte for byte); keys made by OpenSSL, ML-DSA too; 174 messages made
by Go's jwx v4; and a differential both ways with Go's jwx v4.6.0
(`make differential-jwx`).

**Post-quantum JOSE.** jwx signs and verifies with ML-DSA-44, ML-DSA-65 and
ML-DSA-87 as RFC 9964 defines them for JOSE. Keys are the new `AKP` type
(`{"kty":"AKP","alg":"ML-DSA-65","pub":…,"priv":…}`, the private part
being FIPS 204's 32-byte seed), thumbprints cover `alg`, `kty` and `pub`,
and signatures are pure ML-DSA with the empty context, from crypto/bignum's
ML-DSA. `jwk::generate_akp(jwa::ML_DSA_65)` makes a key; `jws` and `jwt`
take the new algorithms as they take any other; `jwx.pem` reads and writes
ML-DSA keys (OpenSSL's PEM files included). An AKP key only ever fits the
one algorithm it names, and is never a JWE key. Go's lestrrat-go/jwx v4 and
gslib verify each other's ML-DSA tokens.

### mail: messages, SMTP, POP3, IMAP, DKIM, S/MIME and PGP/MIME

`mail` sends email as Go's
[go-mail](https://github.com/wneessen/go-mail) does, and fetches it as
Python's `poplib` and an IMAP4rev2 client do; its [README](mail/README.md)
has the API.

- **`mail.address`** and **`mail.message`**: addresses as Go's net/mail
  parses and writes them, and a message builder: From, To, Cc, Bcc (kept
  out of the headers), Reply-To, an encoded-word subject, headers, Date
  and Message-ID, text and HTML bodies, attachments and inline parts,
  written as multipart/mixed, related and alternative with
  quoted-printable, base64 or 8bit, plus the SMTP envelope.
- **`mail.smtp`**: EHLO (HELO as a fallback), STARTTLS or TLS on 465,
  AUTH, MAIL with 8BITMIME, SMTPUTF8 and DSN, RCPT, DATA with
  dot-stuffing, `send` and `send_message`.
- **`mail.pop3`**: CAPA, STLS or TLS on 995, USER/PASS, APOP and AUTH,
  STAT, LIST, UIDL, RETR, TOP, DELE.
- **`mail.imap`**: CAPABILITY, STARTTLS or TLS on 993, LOGIN and
  AUTHENTICATE (SASL-IR), ENABLE, mailboxes (LIST in modified UTF-7 or
  UTF-8, SELECT, STATUS, CREATE, RENAME, DELETE), FETCH with ENVELOPE and
  BODYSTRUCTURE parsed, SEARCH and ESEARCH, STORE, COPY, MOVE, EXPUNGE,
  APPEND with LITERAL+, IDLE; a response parser with literals and nested
  lists, bounded in memory.
- **`mail.sasl`**: PLAIN, LOGIN, CRAM-MD5, SCRAM-SHA-1 and SCRAM-SHA-256
  (the server's signature checked) and XOAUTH2, for all three clients.
- **`mail.dkim`**: DKIM (RFC 6376) signing and verifying with
  RSA-SHA256 and Ed25519-SHA256 (RFC 8463), simple and relaxed
  canonicalization, From over-signed, keys from DNS through dns.client or
  handed in; rsa-sha1 and small RSA keys refused (RFC 8301).
- **`mail.smime`**: S/MIME 4.0 signing (multipart/signed and opaque; RSA,
  ECDSA, Ed25519 and post-quantum ML-DSA signers) and encryption (RSA-OAEP,
  RSA PKCS #1 v1.5, ECDH and post-quantum ML-KEM recipients, AES-CBC and
  AES-GCM), and reading both back with the signer checked against From;
  over x509's CMS, which grew detached signatures, EnvelopedData and
  AuthEnvelopedData for it, ML-DSA SignedData (RFC 9882) and ML-KEM
  recipients (KEMRecipientInfo, RFC 9629, as openssl 4.1 writes them).
- **`mail.pgp`**: PGP/MIME (RFC 3156) signing and encryption over
  crypto/openpgp.
- **goose-mail** sends a file or a built message, reads a POP3 or IMAP
  mailbox, and signs, verifies, encrypts and decrypts with DKIM and
  S/MIME.

The clients do their own I/O over `net` and gslib's TLS. They refuse CR
and LF in commands, refuse to read bytes a server sent before STARTTLS or
STLS took effect (CVE-2011-0411), and send passwords readable only over
TLS or to localhost.

Tested against the RFCs' SASL examples (RFC 5802, 7677, 2195, and RFC
1939's APOP digest); 80 addresses checked against Go's net/mail; messages
compared byte for byte and parsed back by Python's `email`. Over the
network: scripted SMTP, POP3 and IMAP servers that check every mechanism
the server's way and misbehave on purpose, mailpit (SMTP, then POP3
reading what was sent) and dovecot 2.4 (POP3 and IMAP with STARTTLS,
APOP and SASL, and IMAP's mailbox commands) (`make interop-mail`). DKIM
is checked against RFC 8463's examples and dkimpy both ways, S/MIME
against `openssl cms` both ways (ML-DSA and ML-KEM included, all three
parameter sets each), PGP/MIME against gpg. `examples/mail/smime_pq.goose`
and `examples/x509/cms_pq.goose` show the post-quantum side.

### openpgp: OpenPGP

`crypto/openpgp` reads and writes what gpg does: v4 keys with their user IDs,
subkeys, bindings and back-signatures checked; secret keys protected by gpg's
S2K; signatures inline, detached and in cleartext by RSA, Ed25519 and ECDSA;
encryption to RSA, Curve25519, X25519 and NIST ECDH keys and to passphrases.
It reads gpg 2.3+'s default encryption, LibrePGP's OCB packet (AES-OCB is
in crypto/openpgp/ocb.goose, checked against RFC 7253), and writes SEIPD v1
with the MDC, which every implementation reads. mail.pgp builds PGP/MIME
(RFC 3156) on it. Tested against RFC 9580's samples, fixtures gpg made,
tampering and fuzzed input, and gpg both ways (`make interop-openpgp`).

The OpenPGP library now does post-quantum encryption and signatures. gpg
2.5's ky768_cv25519 keys (LibrePGP's ML-KEM-768+X25519 on v5 subkeys) work
both ways with gpg: keys generated here are imported by gpg, secret parts
included, and messages go in both directions. RFC 9980's ML-KEM-768+X25519
and ML-DSA-65+Ed25519 (v6 keys) match the RFC's Appendix A vectors. PGP/MIME
in mail.pgp encrypts to either kind with no API change. The two cannot meet:
gpg 2.5 gives RFC 9980's algorithm numbers to its own Dilithium and does not
read v6 keys.

## Post-quantum cryptography

The NIST post-quantum standards are in crypto/bignum, and the protocols
use them:

- **ML-KEM** (FIPS 203) and **ML-DSA** (FIPS 204), all three parameter sets
  each, constant time.
- **SLH-DSA** (FIPS 205), described below.
- **TLS 1.3**: the X25519MLKEM768 hybrid by default, SecP256r1MLKEM768,
  SecP384r1MLKEM1024 and MLKEM1024 alone, and ML-DSA certificates.
- **SSH**: mlkem768x25519-sha256, first in the default list.
- **HPKE**: ML-KEM and its hybrids, X-Wing among them.
- **x509**: ML-DSA (RFC 9881), SLH-DSA (RFC 9909) and ML-KEM keys, and
  certificates, CSRs and CRLs signed with ML-DSA or SLH-DSA.
- **CMS and S/MIME**: ML-DSA signers (RFC 9882) and ML-KEM recipients
  (KEMRecipientInfo, RFC 9629), checked against `openssl cms` both ways.
- **JOSE**: ML-DSA in JWS, JWK and JWT (RFC 9964), checked against Go's jwx
  v4 both ways.
- **OpenPGP and PGP/MIME**: gpg 2.5's ML-KEM-768+X25519 keys, both ways
  with gpg, and RFC 9980's ML-KEM-768+X25519 and ML-DSA-65+Ed25519, against
  the RFC's vectors; KMAC (SP 800-185) in crypto/bignum for them.

**Stateless hash-based signatures.** crypto/bignum has SLH-DSA (FIPS 205)
in all twelve parameter sets (SHA2 and SHAKE at 128, 192 and 256 bits,
small or fast), with hedged and deterministic signing, context strings,
HashSLH-DSA over every pre-hash the standard names, and the internal
interface. Its security rests on the hash function alone. Keys and
signatures match openssl's byte for byte and NIST's ACVP vectors. The fast
sets sign in about 0.1–0.6 s and the small ones in 2–5 s; verifying takes
milliseconds. crypto/x509 carries SLH-DSA keys in PKCS #8 and
SubjectPublicKeyInfo and signs certificates, CSRs and CRLs with them (RFC
9909), and openssl verifies what it writes.

Examples: `examples/bignum/mlkem_demo.goose`, `mldsa_demo.goose` and
`slhdsa_demo.goose`; `examples/x509/slhdsa_cert.goose` and `cms_pq.goose`;
`examples/mail/smime_pq.goose` and `pgp_pq.goose`;
`examples/openpgp/pqc.goose`; `examples/jwx/mldsa_tokens.goose`;
`examples/tls/post_quantum.goose`.

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
tls, x509, ssh, openpgp), `encoding/` (asn1, yaml), `net/` (http, ldap), and
`compress/` and `mime/` at the top, as Go's are (zip and tar are in
compress too: they share its namespace, results and checksums), and
`krb5/`, `jwx/`, `pkcs11/` and `dns/` at the top as well, none having a place in Go's tree. As in Go,
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
then `multipart::` and `mime::`), and krb5 (`import gslib.krb5.client;`,
then `krb5::`: all its modules share one namespace). Only the
modules a program imports are compiled. The libraries need one another (http needs
tls, x509, asn1 and bignum), and since they are one package, a program
declares only gslib.

The C is net's TCP sockets (`net/src/net.c`, behind `net.goose`:
`import gslib.net;`, then `net::dial`), mime's platform
constant (`mime/src/path.c`), krb5's UDP, owner-only files and host
names (`krb5/src/krb5sys.c`), pkcs11's module loading
(`pkcs11/src/p11.c`) and dns's UDP and listening sockets
(`dns/src/dnsnet.c`), named in `gslib.build` and compiled only into
programs that call them. bignum reaches the OS's random bytes through
libc, by an `extern "c"` block; mime's multipart takes them from there.

## Layout

```
gslib.goose, gslib.build              the package's entry and its sidecar
<group>/<lib>.goose                   each library's main module (crypto/tls.goose)
<group>/<lib>/*.goose                 its other modules (crypto/tls/handshake.goose)
<group>/<lib>/test, tools            its programs (excluded from the package in gslib.build)
<group>/<lib>/scripts                 its test runners, differentials, interop
<group>/<lib>/README.md               its documentation
compress.goose, compress/             compress, laid out the same way at the top
net.goose, net/src/                   net's sockets and their C (net/ is also http's and ldap's group)
mime.goose, mime/                     mime, the same
mail.goose, mail/                     mail, the same
examples/<lib>/                       each library's examples (excluded too)
scripts/run_all.py            every library's unit tests
Makefile                      the programs, checks and tests
```

Each library came from a repository of its own (bigmongoose, asn1goose,
x509goose, tlsgoose, sshgoose, ldapgoose, yamlgoose, httpgoose,
compressgoose, mimegoose), and `git log --follow -- <group>/<lib>` shows that history.

## Examples

`examples/` has a folder for each library (`examples/dns`, `examples/ldap`,
...), with programs for what a user does first with each of its modules:
parse a zone, sign a JWT, make a CA, run a TLS or SSH client and server
against each other in one process. Each is short, runs from gslib's top as

```bash
goose examples/jwx/jwt_tokens.goose
```

and checks its own results, so `make test` runs them too, with each
library's tests. The few that need a live peer (an HTTP, LDAP, DNS or mail
server, a KDC) take it as arguments and are only type-checked there; the
pkcs11 ones run against a fresh SoftHSM token. Each library's README lists
its examples.

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
                # goose-ldapsearch, goose-ldapadd, goose-ldapmodify and the other ldap tools,
                # goose-krb5, goose-gss, goose-dig, goose-dnsd, goose-mail, goose-pgp
make check      # type-check every tool and example
```

The compiler is `GOOSE`, else `goose` on the PATH, else
`../goose.git/build/goose`.

## Tests

```bash
make test                 # every library's unit tests (make test-http: one library's)
make test-native          # also built with the C compiler
make interop              # live: OpenSSL, Go, OpenSSH, OpenLDAP, curl, nghttp2, h2spec, pkcs11-tool, dig, miekg/dns,
                          # mailpit, dovecot, dkimpy, gpg
make differential         # against Go (net/http, net/url, hpack, compress, mime, jwx, miekg/dns), zlib, openssl
make test-all             # check, test, interop and differential
python3 scripts/run_all.py [--native] [--only http,tls]   # what make test runs
```

Each library's README lists its differentials (against Go, Python's zlib
and hashlib, OpenSSL, Go's lestrrat-go/jwx and miekg/dns), its interop
runs (curl, Go's net/http and crypto/tls, OpenSSL, OpenSSH, OpenLDAP,
nghttp2, h2spec, OpenSC's pkcs11-tool, dig, miekg/dns, mailpit, dovecot,
dkimpy, gpg), and what is not
done yet. Every server they start
listens on 127.0.0.1.

pkcs11's tests run against SoftHSM2 (`brew install softhsm`, `apt install
softhsm2`), each on a fresh token of its own; without it they are skipped,
not failed. Its interop also needs OpenSC (`pkcs11-tool`) and OpenSSL.

dns's client test starts goose-dnsd on 127.0.0.1 itself and needs nothing
else; its interop and differential need Go (miekg/dns is fetched by
`scripts/oracle`'s go.mod), and dig if it is installed.

mail's interop runs scripted SMTP, POP3 and IMAP servers of its own
(Python's `ssl`, and `openssl` for their certificate), and mailpit and
dovecot when they are installed (`brew install mailpit dovecot`); DKIM's
needs dkimpy (`pip install dkimpy pynacl`, or `DKIMPY_PYTHON` naming a
python with them), S/MIME's openssl 3 or later, PGP/MIME's and
openpgp's gpg (`brew install gnupg`). Each is skipped when its tool is
missing.
