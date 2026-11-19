# gslib

Goose Library: libraries for [Goose](https://github.com/aardappel/goose),
the batteries that a standard library leaves out, in one package, tested
together and versioned together. gslib is not the compiler's standard
library. Some of it may be proposed for that, or as a blessed package,
later.

| Library | What | |
|---|---|---|
| `entropy` | Random bytes for keys from the operating system, as Go's crypto/rand: getentropy, or ProcessPrng on Windows, through goose's os::random_bytes; what every library that makes keys, nonces or salts uses, and a program can swap for its own (a fixed generator for tests, a TPM, an HSM) | [README](entropy/README.md) |
| `crypto/bignum` | Integers of any size, constant-time arithmetic, and cryptography: AES, Camellia, ChaCha20, the SHA-1/2/3 and BLAKE2 hashes, HMAC, CMAC, AES Key Wrap (RFC 3394 and 5649, used by jwx), HKDF, PBKDF2, scrypt, Argon2, bcrypt, RSA, DSA, ECDH and ECDSA (P-224 to P-521, brainpoolP256r1/384r1/512r1), X25519, Ed25519, X448, Ed448, ML-KEM, ML-DSA, SLH-DSA, HPKE, NaCl, the legacy ciphers | [README](crypto/bignum/README.md) |
| `encoding/asn1` | DER and BER reading and writing, PEM | [README](encoding/asn1/README.md) |
| `crypto/x509` | Certificates: parsing, path building and verification, name constraints, policies, system roots, creating certificates, CSRs and CRLs, OCSP, PKCS #12; brainpool, Ed448 and X448 keys and signatures; post-quantum ML-DSA and SLH-DSA keys and signatures, ML-KEM keys, CMS with ML-DSA, Ed448 and brainpool signers and ML-KEM, X448 and brainpool recipients | [README](crypto/x509/README.md) |
| `crypto/tls` | TLS 1.3 and 1.2, client and server, without I/O: resumption, client certificates, ECH, post-quantum key exchange, X448, Brainpool and Ed448 | [README](crypto/tls/README.md) |
| `crypto/ssh` | SSH (RFC 4251-4254) without I/O, client and server, SFTP; goose-ssh, goose-sshd, goose-scp, goose-sftp-server, goose-ssh-keygen | [README](crypto/ssh/README.md) |
| `net/ldap` | LDAP (RFC 4511): messages, filters, DNs, LDIF, URLs, connections; ldapsearch-style tools | [README](net/ldap/README.md) |
| `encoding/yaml` | YAML 1.2 | [README](encoding/yaml/README.md) |
| `encoding/xml` | XML 1.0 and Namespaces, parsed for documents from strangers (no DTDs or entities, limits, strict well-formedness, unique IDs), built and written; Canonical XML 1.0 and 1.1 and Exclusive XML Canonicalization; XML Signature (enveloped, RSA, RSA-PSS, ECDSA, Ed25519), verified against signature wrapping; XML Encryption (AES-GCM, RSA-OAEP, ECDH-ES; AES-CBC and RSA 1.5 to decrypt, opted into): what SAML is built on | [README](encoding/xml/README.md) |
| `encoding/cbor` | CBOR (RFC 8949) decoded strictly for data from strangers (definite lengths unless opted into, no duplicate map keys, UTF-8 checked, depth, item and size limits, the shortest or the deterministic form when asked; tags passed through) and written in the core deterministic encoding; diagnostic notation; COSE_Key (RFC 9052/9053, RFC 8230) for EC2, OKP and RSA keys and signatures by ES256/384/512, EdDSA, Ed25519, Ed448, PS256/384/512, RS256/384/512, converted to and from JWKs and SubjectPublicKeyInfo: what WebAuthn is built on | [README](encoding/cbor/README.md) |
| `compress` | Compression and archives, as Go's compress/* and archive/*, plus xz: DEFLATE, gzip, zlib, LZW, bzip2, xz and LZMA, zip, tar; reading and writing | [README](compress/README.md) |
| `mime` | MIME, as Go's mime, mime/quotedprintable and mime/multipart, and net/textproto's header sections: media types, RFC 2047 encoded-words, file extensions' types, quoted-printable, multipart bodies and forms | [README](mime/README.md) |
| `krb5` | Kerberos V5 (RFC 4120) as go-krb5 has it: TGTs and service tickets (password, keytab, cross-realm, referrals, FAST armoring), the acceptor, GSS-API (RFC 4121), SPNEGO and HTTP Negotiate, Microsoft's PAC, keytabs and credential caches; goose-krb5 (kinit, kvno, klist) and goose-gss | [README](krb5/README.md) |
| `jwx` | JOSE, as Go's lestrrat-go/jwx: JSON Web Keys (and key sets, thumbprints, PEM), Signatures (compact and JSON, every RFC 7518 algorithm, EdDSA on Ed25519 and Ed448 and post-quantum ML-DSA (RFC 9964)), Encryption (every key management and content algorithm, ECDH-ES on X25519 and X448 too, zip, several recipients) and Tokens (claims, validation, nested) | [README](jwx/README.md) |
| `pkcs11` | PKCS#11 (Cryptoki), as Go's miekg/pkcs11: modules (HSMs, tokens, SoftHSM) loaded at run time, every C_* function, templates, mechanisms and their parameters, all the OASIS constants; and miekg's p11 layer (Module, Slot, Session, Object, keys) | [README](pkcs11/README.md) |
| `dns` | The DNS, as Go's miekg/dns: messages and the 79 record types it implements, in wire form (with compression) and text, zone files (`$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`), EDNS0, DNSSEC primitives (signing, verifying, DS, NSEC3, keys; no validating resolver), TSIG and SIG(0), dynamic updates, zone transfers, a client and a server; goose-dig and goose-dnsd | [README](dns/README.md) |
| `crypto/openpgp` | OpenPGP (RFC 9580, RFC 4880 as gpg writes it): keys (Ed25519/Curve25519, Ed448/X448, RSA, ECDSA/ECDH on NIST and Brainpool curves, v6 read), protected secret keys, signatures (inline, detached, cleartext; gpg's v5 ones), encryption to keys and passphrases (SEIPD v1, gpg's OCB packet and SEIPD v2 read), compression, key generation; post-quantum ML-KEM+ECDH (gpg 2.5's Kyber keys, its default ky768_bp256 among them, and RFC 9980's) and ML-DSA-65+Ed25519 (RFC 9980); goose-pgp | [README](crypto/openpgp/README.md) |
| `mail` | Email, as Go's go-mail for sending: messages built and written as MIME (addresses, text and HTML, attachments, inline parts), an SMTP client (STARTTLS or TLS, AUTH with PLAIN, LOGIN, CRAM-MD5, SCRAM-SHA-1/256, XOAUTH2, SMTPUTF8, DSN), a POP3 client (STLS, APOP, SASL, UIDL, TOP) and an IMAP client (IMAP4rev2 and rev1: mailboxes, FETCH with ENVELOPE and BODYSTRUCTURE, SEARCH, STORE, MOVE, APPEND, IDLE); DKIM signing and verifying (RSA, Ed25519); S/MIME (ML-DSA and ML-KEM too) and PGP/MIME signing and encryption; goose-mail | [README](mail/README.md) |
| `acme` | ACME (RFC 8555) certificates from Let's Encrypt, an enterprise's own CA (Vault and OpenBao's PKI, step-ca, EJBCA) or a commercial CA with external account binding: accounts, orders, http-01 and dns-01, finalizing, the chain, revoking, key rollover; goose-acme, with http-01 served or from a web root, and dns-01 by RFC 2136 updates | [README](acme/README.md) |
| `oauth` | OAuth 2.0 and OpenID Connect clients: discovery (RFC 8414), the authorization code flow with PKCE and PAR, client credentials, refresh, the device grant, token exchange, introspection, revocation; client authentication by secret, private_key_jwt and mutual TLS; DPoP and certificate-bound tokens; ID tokens, JWT access tokens (RFC 9068) and DPoP proofs validated against the issuer's JWKS; UserInfo; goose-oauth, with a loopback redirect for logins | [README](oauth/README.md) |
| `tsp` | Time-stamps (RFC 3161, RFC 5816): requests, replies and TSTInfo, tokens checked (signature, signingCertificate and V2, the TSA's critical timeStamping usage, its path at genTime, imprint, nonce, policy), a TSA that signs them, CMS signatures time-stamped (Appendix A); goose-ts, as openssl ts with a TSA over HTTP | [README](tsp/README.md) |
| `est` | EST (RFC 7030, RFC 8951) certificates over HTTPS: /cacerts, /simpleenroll and /simplereenroll (waiting out 202 and Retry-After), /csrattrs, /serverkeygen, labels; HTTP Basic or a TLS client certificate; a test CA; goose-est, with the test CA over TLS | [README](est/README.md) |
| `scep` | SCEP (RFC 8894) certificates: GetCACaps, GetCACert, PKCSReq and RenewalReq with CertPoll, GetCert, GetCRL, by POST or GET; replies checked against the CA's certificate, transactionID and nonces; AES and SHA-256, DES and SHA-1 only when allowed; a test CA; goose-scep | [README](scep/README.md) |
| `saml` | SAML 2.0 Web Browser SSO and Single Logout, service provider and identity provider: the HTTP-Redirect binding (DEFLATE, the query signed and checked over the bytes as received) and HTTP-POST; Responses checked as the profile asks, reading only what xml's signature verification says is signed (all eight XSW attacks, the comment-in-NameID bug, replay refused), encrypted assertions; signed and encrypted Responses made; metadata read, verified and written; goose-saml (metadata, an SP, a test IdP, verify) | [README](saml/README.md) |
| `ntlm` | NTLM authentication ([MS-NLMP]), NTLMv2 only (no LM or NTLMv1 response is ever made, and the acceptor refuses them): NEGOTIATE, CHALLENGE and AUTHENTICATE with their AV_PAIRs, an initiator and an acceptor (the NT hash looked up through a block) checking NTProofStr, the MIC, the time, channel bindings (tls-server-end-point) and the target name; signing and sealing; NTLM inside SPNEGO (krb5), over HTTP (net/http's fetch, `AUTH_NTLM`) and in SMTP/POP3/IMAP AUTH (mail); goose-ntlm (compute, decode, a test HTTP server, a client) | [README](ntlm/README.md) |
| `tpm2` | TPM 2.0, as go-tpm with go-tpm-tools' checks: raw TCP (swtpm), the Microsoft simulator's protocol and Linux's /dev/tpmrm0; password, HMAC (bound, salted by RSA-OAEP or ECDH) and policy sessions with AES-CFB parameter encryption; the TCG EK and SRK templates, keys, signing, RSA-OAEP, ECDH, NV and EK certificates, PCRs, sealing to PCR policies; a policy calculator; Quote, Certify, CertifyCreation and ActivateCredential, with their verification, MakeCredential and TCG event log replay in software; goose-tpm | [README](tpm2/README.md) |
| `radius` | RADIUS, both sides, as FreeRADIUS speaks it: packets and their authenticators with the Message-Authenticator always first (BlastRADIUS), hidden attributes (User-Password, CHAP, Tunnel-Password, MS-MPPE keys), a client over UDP and RadSec (RADIUS over TLS) with PAP, CHAP, MS-CHAPv2, EAP, accounting, Status-Server, CoA and Disconnect, a server's handling of each request; EAP peer and server for MD5, MS-CHAPv2, EAP-TLS, PEAP and TTLS over TLS 1.2 and 1.3 with their keys; goose-radtest and goose-radiusd | [README](radius/README.md) |
| `smb` | An SMB2 and SMB3 client, as Windows and Samba speak it: dialects 2.0.2 to 3.1.1, NEGOTIATE with 3.1.1's contexts and 3.0's validate-negotiate, SPNEGO logins with NTLMv2 or Kerberos, signing (HMAC-SHA256, AES-CMAC, AES-GMAC) and encryption (AES-128/256 CCM and GCM) required where the server or the client asks and checked on every response; shares, files and directories: read and write with multi-credit requests, list, stat, rename, delete, truncate, times, the share's space; goose-smbclient | [README](smb/README.md) |
| `kmip` | KMIP 1.0 to 2.1, both sides, in TTLV, XML and JSON, over TLS or HTTPS: one list of attributes sent in 1.x's or 2.x's form; keys in every format, wrapped keys, certificates, split keys, secrets; a client for every operation (the life cycle, Get and Export wrapped, Import, Re-key, Derive Key, Certify, cryptography in parts, asynchronous items, tickets); an in-memory server answering them, checked against OASIS's test cases; goose-kmip and goose-kmipd | [README](kmip/README.md) |
| `webauthn` | WebAuthn Level 3 and passkeys for a relying party: registration and authentication options as the L3 JSON has them; registrations checked whole (clientDataJSON, the attestation object, authenticator data and its flags, the algorithm) with every attestation format but SafetyNet: none, packed, fido-u2f, tpm, android-key, apple, chained to the RP's roots by x509; authentications against the stored credential record (signature, user handle, counter, backup flags); FIDO MDS3 BLOBs verified and searched; goose-webauthn (options, verify, MDS, a demo RP for a real browser) | [README](webauthn/README.md) |
| `net/http` | HTTP/1.1 and HTTP/2, server and client: a client with Go's policy (redirects, cookies, credentials, proxies, gzip, TLS session resumption, streaming uploads, several responses at once), URLs, cookies, HPACK; goose-http and goose-httpd | [README](net/http/README.md) |
| `websocket` | WebSocket, both sides, as Go's gorilla/websocket: RFC 6455 framing and handshake, RFC 7692 permessage-deflate with every parameter (windows of 8 to 15 bits), ws:// and wss://, an HTTP proxy, an Upgrader for a server that reads the request or an HTTP server that did; messages whole or a frame at a time, pings and closes answered, UTF-8 checked as it arrives; goose-wscat and goose-wsecho; Autobahn's testsuite both ways | [README](websocket/README.md) |
| `net` | Sockets and IP addresses, as Go's net and net/netip: TCP connections and listeners with timeouts, UDP connected or answering many, Unix-domain sockets, waiting on several sockets, the system resolver; addresses parsed, printed (RFC 5952), classified and checked against prefixes; host:port; Punycode host names; what http, ldap, dns, krb5 and the tools' servers talk through (POSIX and Winsock) | [README](net/README.md) |
| `service` | Programs as system services, as Go's kardianos/service: one API for Windows services (the service control manager: dispatcher, control handler, stop, shutdown, pause, parameter changes; installing with a description, delayed start and restart on failure; the Application event log), systemd units (a user's or the system's) and launchd agents and daemons; begin, wait for the system's requests, end; install, uninstall, start, stop, restart, status, and those as a program's verbs | [README](service/README.md) |
| `sys` | The operating system's own calls, as Go's golang.org/x/sys, os/user and x/term with go-win64api's Windows management, on Windows, Linux and macOS: the host, processes (list, arguments, executable, kill), users and groups, files by path and by descriptor (stat, links, locks, pipes, memory maps), errors sorted portably; the Windows registry; local accounts and groups, sessions, services, shares and installed software; signals as values, limits, usage and sysctl; terminals and consoles; its FFI generated from one table, as mksyscall | [README](sys/README.md) |
| `sspi` | Windows' SSPI, as Go's alexbrainman/sspi: security packages, credentials (the login's or a password's), contexts a token at a time, sign/verify/seal/unseal; a TLS client on Windows' own Schannel (the system's roots, policy and TLS 1.3, peer certificate for x509, manual validation for test servers); HTTP Negotiate (RFC 4559) from the Windows login, Kerberos in a domain and NTLM otherwise, or as a user by password | [README](sspi/README.md) |

## entropy, net, websocket, dns, pkcs11, jwx, mail, openpgp, acme, oauth, tsp, xml, est, scep, saml, ntlm, tpm2, webauthn, radius, smb, kmip, service, sys and sspi

These twenty-four have the most to say beyond their table rows: what each
module does, how it was built and how it was tested. Each README has the
full API.

### entropy: random bytes for secrets

Every key, nonce, salt and token gslib makes comes from
`entropy::random_bytes`, which reads the operating system's
cryptographically secure generator: getentropy on macOS, Linux and the
BSDs (with /dev/urandom for kernels that lack it) and ProcessPrng on
Windows. It is a thin layer over goose's own `os::random_bytes`, with no
C of its own. It
stops the program if the OS gives nothing, since carrying on with a key
that is not random is worse; `try_random_bytes` reports instead. It used
to be bignum's, which reached getentropy through the C library and so had
no Windows at all; as a package of its own it works on all three
platforms, and dns takes its message IDs from it too, where they used to
come from the seed of std's generator.

It is also the one place a program can change where randomness comes
from. Goose has no interfaces, but a program's root file chooses its
packages, and in the standalone repositories bignum, tls, x509 and the
rest import `entropy` by name alone. A root that declares its own package
named entropy, with a `random_bytes` of the same shape, gets that one
everywhere: a fixed generator for tests that compare against recorded
output, or a TPM's or an HSM's generator. Tested under the JIT and built
natively on macOS, Linux and Windows Server 2022; a trial of the split
repositories ran tls's tests with a replacement declared in their root.

### net: sockets and addresses

net is the transport the rest of gslib stands on, after Go's net and
net/netip. It dials TCP connections, each address of a name in turn,
with a deadline, and reads and writes with timeouts that hold even when a
peer stops reading. It listens and accepts, gives both ends' addresses,
waits on up to 256 sockets at once, writes what fits without waiting, and
half-closes. UDP is either connected to one peer or bound to answer many,
with each sender's address. There are Unix-domain stream sockets for
ldapi://, and the system resolver for a name's addresses and an
address's name. Sockets stay plain i64 descriptors, so a library can hand
one to TLS or to poll; addresses have types: an Addr parsed by Go's
rules and printed the RFC 5952 way, classified (loopback, private,
link-local, multicast, global), with a port, and prefixes such as
10.0.0.0/8 that say whether they hold an address. net.idna turns host
names outside ASCII into Punycode.

It used to be a TCP client and nothing more, so each server brought its
own sockets: dns had UDP and listening ones, krb5 its own UDP exchange,
and the http, ldap and gss tools each a POSIX-only C file. All of that is
net now, in one C file that works on Windows too. IP parsing and Punycode
moved out of http's URL code, and ldap's URLs now check a bracketed host
as an IPv6 address. Tested on macOS, Linux and Windows (MSVC, natively
too): parsing against Go's cases, printing round trips, every address
class, prefixes and Go's Punycode vectors, and sockets on 127.0.0.1 and
::1 covering accept timeouts, both ends' addresses, poll, a socket filled
by write_some, half-closing, UDP both ways and each error.

### websocket: WebSocket

`websocket` is RFC 6455 for both ends, after gorilla/websocket. A client
dials a ws:// or wss:// URL, through an HTTP proxy's CONNECT if asked,
and a server either accepts a connection and reads the upgrade request
itself or upgrades one its HTTP server already read (net.http's conn1
hands over the head and the bytes after it), with gorilla's Upgrader
checks: the Origin against Host or a list, subprotocols by the server's
preference, version 13 (426 otherwise). A Conn then reads messages
whole or a frame at a time and writes them whole, fragmented, or as
they are made, while it answers pings and echoes the peer's close; text
is checked as UTF-8 byte by byte, so a bad message fails at the byte
that shows it, and every protocol violation closes with the code the
RFC names (1002, 1007, 1009). permessage-deflate (RFC 7692) is complete
on both sides: no-context-takeover either way, and window sizes of 8 to
15 bits honoured by the compressor, for which `compress.deflate` gained
`deflate_set_window_bits`; a message that ends its DEFLATE stream with a
final block is followed by a new stream that still reaches into the
old one, for which `compress.flate` gained `inflate_continue`. A Conn
without a socket takes bytes from `feed` and leaves its output for
`take_output`, which is how the tests run both sides in one thread.
goose-wsecho is an echo server, goose-wscat a client after npm's wscat.

Tested against RFC 6455's and RFC 7692's frames byte for byte, every
violation and its close code, permessage-deflate with every combination
of parameters and windows in memory (4502 checks); live (`make
interop-websocket`, Docker) against Autobahn|Testsuite, its
fuzzingclient against goose-wsecho and its fuzzingserver against the
client, every case, messages whole and a frame at a time (517 cases in
each run, all OK but 3 that are only informational), and against
Python's websockets both ways. A libFuzzer target covers the Conn on
both sides, the handshake and the extension header.

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
garbage collector for miekg's struct per type. Its sockets, UDP, TCP
and listening, are net's.

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
- **`jwx.jwk`**: keys and key sets (RSA, EC P-256/384/521, OKP Ed25519,
  Ed448, X25519 and X448, oct, AKP ML-DSA-44/65/87), checked for consistency; RFC 7638 thumbprints; generation.
- **`jwx.pem`**: keys from and to PEM and DER: PKCS #8, SEC 1, PKCS #1,
  SubjectPublicKeyInfo, and certificates (with `x5t` and `x5t#S256`);
  ML-DSA keys as RFC 9881 has them.
- **`jwx.jws`**: signatures, compact and JSON (general and flattened),
  detached and unencoded (RFC 7797) payloads; HS, RS, PS, ES, EdDSA
  (Ed25519 and Ed448, and RFC 9864's `Ed25519` and `Ed448`) and ML-DSA.
- **`jwx.jwe`**: encryption, compact and JSON, several recipients,
  additional authenticated data, `zip`; RSA1_5, RSA-OAEP(-256/384/512),
  A*KW, dir, ECDH-ES(+A*KW) on the NIST curves, X25519 and X448, A*GCMKW, PBES2;
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
forbids). Not supported: Brainpool (no JOSE identifiers), ES256K,
multi-prime RSA keys, HashML-DSA, ML-DSA contexts, expanded ML-DSA private
keys in JWKs.

Tested against RFC 7520's examples (the JOSE cookbook), with 10
ciphertexts and 8 encrypted keys remade byte for byte; RFC 7515, 7517,
7518 Appendix C, 7519, 7638, 7797, 8037 (A.7's X448 example among them)
and 9964 (its ML-DSA signatures remade byte for byte); keys made by
OpenSSL, ML-DSA too; 176 messages made by Go's jwx v4, Ed448 and X448
among them; and a differential both ways with Go's jwx v4.6.0 and its
Ed448 and X448 modules (`make differential-jwx`).

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

OpenPGP also has the newer curves now, both ways with gpg: Brainpool ECDSA
and ECDH keys on brainpoolP256r1, P384r1 and P512r1; Ed448 and cv448, which
gpg makes as v5 keys signing LibrePGP's v5 signatures, so those are read
and written too; and gpg's default post-quantum key, brainpoolP384r1 with a
ky768_bp256 subkey (ML-KEM-768 with brainpoolP256r1), along with its
ky1024_bp384 and ky1024_cv448 kinds. goose-pgp's `genkey --type pqc` now
makes gpg's default. RFC 9580's own Ed448 and X448 algorithms (on v6 keys)
are read and written as well; gpg 2.5 does not know them.

### acme: certificates

`acme` gets certificates by ACME (RFC 8555), from Let's Encrypt or from a
CA run in-house: the PKI engine of Vault or OpenBao, step-ca, EJBCA. It
registers accounts (with external account binding, which commercial CAs
and Vault ask for), orders certificates for DNS names, wildcards and IP
addresses, proves them by http-01 or dns-01, finalizes with a CSR from
x509, downloads the chain, revokes, and rolls the account key over. Every
request is a JWS made by jwx and goes over gslib's HTTP client; a nonce
the server turns down is replaced and the request sent again. `obtain`
does it all in one call, with a block that publishes each challenge.

goose-acme is the tool: one command for a certificate, the names proved by
http-01 served on a thread of its own or written into a web root, or by
dns-01 through RFC 2136 updates signed with TSIG (gslib's dns), which
BIND, Knot, PowerDNS and Windows DNS take. Keys are written 0600 and
nothing secret is printed.

Tested without a server against RFC 7638's thumbprint and RFC 8555's
examples, and live (`make interop-acme`) against Pebble, Let's Encrypt's
test server, in strict mode with a fifth of the nonces refused (http-01
both ways, dns-01 for a wildcard and its apex, revoking, rollover,
deactivating, external account binding), and against OpenBao's PKI engine
(dns-01, revoking, external account binding from its new-eab endpoint),
with goose-dnsd as both servers' DNS; every chain verified by openssl.

### oauth: OAuth 2.0 and OpenID Connect

`oauth` is a client of OAuth 2.0 authorization servers and OpenID
Providers (Keycloak, Entra ID, Okta, Auth0, node-oidc-provider and the
rest). It reads the server's metadata by OpenID Connect discovery or RFC
8414, and gets tokens by every grant a client uses now: the authorization
code with PKCE (S256), sent directly or as a pushed authorization request
(RFC 9126); client credentials; refresh; the device grant (RFC 8628),
polling with slow_down honoured; token exchange (RFC 8693) and JWT bearer
assertions. It introspects (RFC 7662) and revokes (RFC 7009). The client
authenticates by client_secret_basic or _post, by a JWT signed with its
key (private_key_jwt) or the secret (client_secret_jwt), or by its TLS
certificate (RFC 8705, through the mtls_endpoint_aliases). A DPoP key
(RFC 9449) makes every token request and resource request carry a proof,
and a server's demand for a nonce is answered; the callback of a login
is checked for state and for the issuer (RFC 9207). Refusals keep the
server's error and error_description, as acme keeps problem documents.

`oauth.oidc` checks tokens against the issuer's keys, fetched from its
jwks_uri and fetched again, at most once a minute, for a kid it does not
know: ID tokens as OpenID Connect Core §3.1.3.7 says (iss, aud and azp,
exp and iat with a leeway, the nonce, auth_time against max_age, at_hash
and c_hash, an algorithm the client allows and never "none"), JWT access
tokens as a resource server does (RFC 9068: typ at+jwt, audience, scope),
DPoP proofs, and the binding of a token to a DPoP key or a client
certificate (cnf). It reads UserInfo, JSON or signed.

goose-oauth is the tool: a token by client credentials, by the device
grant, or by a login in the browser that comes back to a loopback
listener of its own (RFC 8252); refresh, exchange, introspect, revoke,
UserInfo, and validating an ID token or access token. It prints the
access token alone on stdout, everything else on stderr, and never a
secret, key or refresh token; secrets come from a file or the
environment, not the command line.

Tested without a server against RFC 7636's PKCE example, RFC 9449's DPoP
proofs, OpenID Connect's at_hash and c_hash examples and ID tokens signed
in the test with each fault the validation looks for, and live (`make
interop-oauth`) against node-oidc-provider, an OpenID Certified server:
every grant and every client authentication above, PAR, DPoP with the
server asking for nonces, certificate-bound and JWT access tokens,
introspection, revocation, UserInfo signed and not, with the logins and
the device's pages driven by the test.

### tsp: time-stamps

`tsp` is RFC 3161's Time-Stamp Protocol, both sides of it. A client
hashes its data (SHA-256, -384 or -512; SHA-1 only when asked), sends the
request with a nonce over gslib's HTTP client, and checks the reply: the
status and its failInfo, then the token, a CMS SignedData read by x509,
whose signature and signed attributes must verify, whose
signingCertificateV2 (or the older signingCertificate) must name the
signer's certificate, which must carry the critical extended key usage
of timeStamping alone and chain to the roots given at the time stamped,
and whose TSTInfo must hold the request's imprint, nonce and policy. A
TSA (`Tsa`, `respond`) answers requests with tokens signed by its key,
signingCertificateV2 in them, its accuracy, ordering and name if set,
random or counted serial numbers, and refuses what it does not take with
the failInfo that says why. A token can also go into a CMS signature's
unsigned attributes (Appendix A), so that the signature can be trusted
after its certificate has expired; x509's CMS signing gained the two
options this needed (extra signed attributes, no certificates) and a
verify that takes the signer's certificate from the caller.

goose-ts is the tool, `openssl ts` in its commands: query, reply, verify
(against a query, the data or a digest), show, and request and serve over
HTTP, plus stamp and verify-stamp for CMS signatures.

Tested without a network against a TSA made in the test and every check
above failing in turn, and against replies openssl made (test/vectors);
live (`make interop-tsp`) against `openssl ts` both ways (openssl's
queries answered by goose-ts and verified by openssl, goose-ts's answered
by openssl and verified by goose-ts, ESSCertID and ESSCertIDv2, EC and RSA
TSAs), over HTTP with curl, with openssl's CMS signatures time-stamped and
still verified by openssl, and against a Go TSA built on
digitorus/timestamp, both ways.

### xml: XML, signatures and encryption

`encoding/xml` is the XML that SAML needs, written for documents that
come from strangers and carry signatures. The parser builds a document
of numbered nodes (an arena, links by index) and refuses rather than
interprets: no DTD is ever processed, so no entity is expanded or
fetched (XXE and billion laughs cannot happen; a DOCTYPE is an error
unless allowed, and then only one without an internal subset); input
size, nesting, attributes, names and nodes have limits that are errors,
never cuts; well-formedness is checked in full, down to UTF-8 and the
characters XML allows, with Namespaces 1.0's rules and an attribute
refused twice also under two prefixes of one namespace; and an ID value
(ID, Id, id, xml:id) seen twice in a document is an error, so the
signature code never has two elements to choose from. A builder makes
documents, a writer writes them so they parse back the same.

On it, in the same namespace: **c14n**, Canonical XML 1.0 and 1.1 and
Exclusive XML Canonicalization 1.0, with and without comments, with
InclusiveNamespaces, of a document or of an element's subtree with
another subtree left out, the namespaces, xml: attributes and 1.1's
xml:base fix-up as the specs give a subset; **dsig**, XML Signature 1.1's
enveloped signatures (RSA PKCS #1 and PSS, ECDSA P-256 to P-521, Ed25519;
SHA-256 to -512, SHA-1 only to verify and only when allowed), whose
verification is built against signature wrapping: it checks the
Signature it is given with a certificate the caller trusts, reads it
strictly, verifies SignedInfo before any Reference, allows only "" and
"#id" references, each resolved once to the one element with that ID,
and enveloped-signature plus one canonicalization as transforms, and
returns the nodes that were signed, not a yes; `verify_enveloped` adds
SAML's rule that the element's own single Signature references the
element itself. And **enc**, XML Encryption 1.1 for SAML's
EncryptedAssertion: AES-GCM, RSA-OAEP (both forms, any hashes) and
ECDH-ES with ConcatKDF and AES key wrap, AES-CBC and RSA 1.5 only to
decrypt and only when opted into (padding oracles, Bleichenbacher), one
error for every decryption failure, and the plaintext parsed into the
document where the EncryptedData was, under the same rules.

Tested at every optimization level with the W3C's canonicalization
examples, RFC 3986's resolution examples, a matrix of every algorithm,
signatures and ciphertexts signxml, xmlsec and cryptography made, and a
catalogue of wrapping, tampering and hostile input; live (`make
interop-xml`, a venv with lxml, signxml and xmlsec) against signxml and
xmlsec both ways, for signatures and encryption, and (`make
differential-xml`) canonicalization of a corpus and random documents
against libxml2, through lxml for whole documents and exclusive subsets
and through xmlsec's digests for 1.0 and 1.1 subsets.

### est and scep: certificates for devices

`est` and `scep` are the two other ways certificates are handed out
besides ACME, the ones network gear, MDM servers and enterprise CAs
speak. EST (RFC 7030, with RFC 8951's fixes) is HTTPS: the CA's
certificates as certs-only CMS, a PKCS #10 request in base64 posted to
/simpleenroll (or /simplereenroll, authenticated by the certificate
being renewed), what the CA wants in a CSR from /csrattrs, and a key the
CA makes from /serverkeygen, in a multipart reply; the client
authenticates by HTTP Basic or a TLS client certificate, and a request
the CA holds (202 and Retry-After) is asked again until it is done or a
deadline passes. SCEP (RFC 8894) is older and carries its own security:
each message is a CMS SignedData over an EnvelopedData, the request
encrypted to the CA and signed by the device's key under a self-signed
certificate, the reply signed by the CA and encrypted to that
certificate, with a transactionID and nonces tying them together. The
client checks a reply before using anything in it: signed by the very
certificate GetCACert gave, its transaction and nonce its own, the
issued certificate for its key. Both libraries have a test CA in the
same module, which goose-est and goose-scep serve, and x509's CMS gained
what SCEP needed (signed-attribute reading, certs-only, DES-EDE3 and
SHA-1 for servers that know nothing newer, only when asked).

Tested without a network through their test CAs and against hostile
replies of every kind (a reply signed by another key under the CA's
name, another transaction's, unsigned, oversized, a certificate for
another key); live (`make interop-est`, `make interop-scep`) against
GlobalSign's EST server and client and micromdm's SCEP server and client,
both ways, each certificate checked by openssl. micromdm signs its
replies with SHA-1 and encrypts them with single DES whatever its caps
say, so goose-scep talks to it with `--legacy`.

### saml: SAML 2.0 single sign-on

`saml` is both sides of SAML 2.0's Web Browser SSO and Single Logout, on
`xml`. A service provider sends AuthnRequests by the HTTP-Redirect
binding (DEFLATE, base64, the query signed by SigAlg and Signature) or
HTTP-POST (an auto-submitting form, the XML signed), and checks the
Response that comes back as the profile asks: the Response's signature
and then the assertion's, with the IdP's certificates from its metadata;
Destination, Issuer, InResponseTo against the request ID the caller kept
(an IdP-initiated Response only when allowed), the status, exactly one
assertion as a direct child of the verified Response, decrypted when it
came encrypted, a bearer SubjectConfirmation with our ACS as Recipient
and a NotOnOrAfter ahead, Conditions with a clock skew, an
AudienceRestriction naming us, OneTimeUse, SessionNotOnOrAfter; the
NameID and every attribute value. What it reads, it reads from the nodes
xml's verification returned as signed, never by searching the document
again, which is what defeats signature wrapping; the NameID is its whole
text, so a comment cannot cut it short (the bug Duo found in 2018 in
several libraries). The assertion's ID and how long to remember it come
back for the caller's replay cache, through a block. An identity
provider reads AuthnRequests (signatures by either binding, the ACS URL
against the SP's metadata) and answers with the assertion signed, the
Response signed, or both, the assertion encrypted to the SP's key when
asked. Logout requests and responses go both ways over both bindings,
and must be signed. Metadata is read (an entity, or one out of an
aggregate; verified against a pinned certificate when signed, validUntil
checked) and written, signed or not. goose-saml prints metadata, runs a
small SP that prints each verified assertion as JSON and a test IdP, and
checks a Response from a file.

Tested without a network against all eight wrapping attacks of "On
Breaking SAML" and their variants, the NameID comment, unsigned and
foreign-signed assertions, every time window, audience, recipient,
destination and InResponseTo fault, replay, SHA-1 (a libxmlsec1-signed
Response, refused by default), RSA 1024, DOCTYPEs, a DEFLATE bomb and
oversized messages; live (`make interop-saml`) against python3-saml
(OneLogin's toolkit, on libxmlsec1) as an SP and as the signer of
Responses, and against crewjam/saml's SP and IdP, both ways, by both
bindings, encrypted and not, logins and logouts.

### ntlm: NTLMv2

`ntlm` is NTLM authentication ([MS-NLMP]) for the peers that offer
nothing better: IIS and http.sys sites, Exchange's SMTP, POP3 and IMAP,
workgroup machines. It is legacy (keys from an unsalted MD4 of the
password, RC4 and HMAC-MD5), and NTLMv2 is all of it that is here: no LM
or NTLMv1 response is ever computed, and the acceptor refuses them
(24-byte responses, LM alone, LM_KEY), since an NTLMv1 response turns
back into the NT hash. The initiator offers 128-bit keys, KEY_EXCH and
extended session security, refuses a CHALLENGE that drops them, sends
the server's target info back with MsvAvFlags, the channel bindings
(MD5 of gss_channel_bindings_struct around RFC 5929's
tls-server-end-point) and the SPN, a random session key RC4'd under the
session base key, and the MIC over the three messages. The acceptor
writes a CHALLENGE with its names and the time, and checks the
AUTHENTICATE strictly: every field inside the message and none
overlapping, the AV_PAIRs ending in MsvAvEOL with nothing twice,
NTProofStr against the NT hash its caller's block gives (one error for
an unknown user and a wrong password), the time within a skew and the
timestamp it sent, channel bindings and the target name as its policy
asks, flags not downgraded, and the MIC. Signing and sealing (HMAC-MD5,
RC4, sequence numbers) follow as GSS wrap and MIC. NTLM also goes where
gslib already spoke Negotiate: krb5.spnego takes it as SPNEGO's
mechanism with mechListMIC on the NTLM keys, net/http's fetch answers
`WWW-Authenticate: NTLM` (or `Negotiate` alone, with raw NTLMSSP) on the
same HTTP/1.1 connection with the channel binding of the server's
certificate, and mail's SASL has `AUTH_NTLM`. goose-ntlm computes
responses from given inputs, decodes messages, runs both sides over
stdin and stdout, serves HTTP behind NTLM and fetches through it.

Tested against [MS-NLMP] §4.2.4 byte for byte (NTOWFv2, LMv2,
NTProofStr, the session and encrypted keys, the CHALLENGE and
AUTHENTICATE messages, §4.2.4.4's sealing), and without a network
against truncated, oversized, out-of-range and overlapping messages,
AV_PAIR lists without an end or with a pair twice, every single byte of
an AUTHENTICATE changed, wrong and stripped MICs, old and replayed
timestamps, channel binding and SPN mismatches, NTLMv1 and LM, and
downgraded flags both ways; live (`make interop-ntlm`) against pyspnego
as initiator and acceptor (raw and SPNEGO, channel bindings, sealing),
impacket, curl `--ntlm` and Azure/go-ntlmssp, both ways over HTTP.

### tpm2: TPM 2.0

`tpm2` talks to a TPM 2.0 and checks what it says, after go-tpm with
go-tpm-tools' attestation verification. Commands go over raw TCP (swtpm's
data channel), the Microsoft simulator's protocol (with its platform
channel's power-on) or Linux's /dev/tpmrm0, each response read with its
sizes checked against what is left and the structure's maximum, and
refused whole when any of it lies. Sessions are password, HMAC (cpHash
and rpHash, fresh nonces, bound to an entity, salted to a TPM key by
RSA-OAEP or by ECDH and KDFe) and policy, and any of them encrypts a
command's first parameter or a response's with AES-CFB. The TCG
templates make EKs and SRKs whose Names are checked against the ones
computed here; keys sign (RSASSA, RSAPSS, ECDSA, each signature checked
by x509 through the key as a SubjectPublicKeyInfo), decrypt and do ECDH;
NV indices are defined, written, read, counted and extended, and EK
certificates read from their standard indices. A policy calculator
gives an object's authPolicy before the object exists (PolicyPCR,
PolicySecret, PolicySigned, PolicyOR, PolicyAuthValue, PolicyPassword,
PolicyCommandCode, PolicyAuthorize), the same digests a trial session
gives, and the same assertions satisfy a policy session for Unseal.
For attestation it quotes, certifies and activates credentials on the
TPM, and verifies with none: a TPMS_ATTEST's signature by the AK, its
nonce, PCR selection and digest against PCR values, a certified Name or
creation hash; a TCG crypto-agile event log replayed to the PCRs it
should give; and MakeCredential, which binds a verifier's secret to an
AK's Name under the EK, so that only that TPM gets it back. goose-tpm
does the same from a shell: random bytes, PCRs, primaries, EK keys and
certificates, quotes and their verification, sealing, keys and
signatures, NV.

Tested without a TPM against the Names, quotes, certifications and
policy digests swtpm made, KDFa, KDFe, command and response HMACs,
policies and an event log computed with Python's hashlib, MakeCredential
recovered with software EKs' private keys, and responses that lie in
every field; against go-tpm on 3000 random cases (KDFs, Names of every
kind of public area, policy digests); live (`make interop-tpm2`) against
swtpm, with EK certificates provisioned by swtpm_setup, and the Sail TPM
emulator over TCP and mssim, whose departures from the specification
(policies not enforced at use, a bound session's parameter-encryption
key, OAEP labels ignored, ECC ActivateCredential, random primaries) are
in tpm2's README.

### webauthn: passkeys and FIDO metadata

`webauthn` is the relying party's half of WebAuthn Level 3: the server
that makes the options a browser's navigator.credentials.create() and
.get() take, in the L3 JSON serialization (base64url for bytes:
challenges made from the OS's entropy, the user handle, the algorithms
asked for, credentials to exclude or allow with their transports,
residentKey and userVerification, attestation and its formats, hints,
credProps), and checks what comes back. A registration is checked
whole, as §7.1 orders it: clientDataJSON with no member twice, its type,
the challenge exactly, an origin from the RP's list (its related origins
included), crossOrigin and topOrigin only when the RP allows them; the
attestation object decoded strictly; the authenticator data's RP ID
hash, its flags (UP, UV when required, BS never without BE, AT and ED
saying what follows) and nothing after it, a credential ID of at most
1023 bytes, the COSE key on its curve with an alg the RP asked for and
that fits it; and the attestation statement by format: packed (self or
with a certificate, its subject and FIDO AAGUID extension checked),
fido-u2f, tpm (TPMS_ATTEST and TPMT_PUBAREA parsed, the certified name
and extraData recomputed, the AIK certificate's empty subject, TCG SAN
with a registered manufacturer and AIK key usage), android-key (the key
description: the challenge, no allApplications, a generated signing
key), apple (the nonce extension) and none. The statement's
certificates are checked against the roots the RP trusts with x509;
untrusted attestation is an error only when the RP says so. What comes
out is the credential record the RP stores, as deterministic CBOR if it
likes. An authentication is checked against that record: the same
client data rules, the signature over authData and the client data's
hash by the stored key and algorithm, a passkey's user handle, the
backup flags, and a counter that did not go forward, reported (and
refused only when asked). MDS3 BLOBs are verified (the JWT's x5c to the
FIDO root, by jwx) and searched by AAGUID for an authenticator's
attestation roots and status, refusing revoked and compromised ones.
goose-webauthn makes options, verifies responses and BLOBs from files,
and serves a small RP on localhost whose page registers a passkey and
signs in with it, for trying a real browser and authenticator by hand.

It stands on `encoding/cbor`, new with it: RFC 8949 decoded into nodes
that point into the input, strictly (definite lengths unless opted into,
no duplicate map keys by value, UTF-8 checked, limits on depth, items
and size, the shortest or the deterministic form when asked), written in
the core deterministic encoding, and shown in diagnostic notation; and
its COSE_Key module, whose keys verify ES256 to ES512, EdDSA, Ed25519,
Ed448, PS256 to PS512 and RS256 to RS512 signatures and convert to and
from JWKs and SubjectPublicKeyInfo.

Tested against every registration and authentication of the L3
specification's test vectors (§16: none, self, crossOrigin, topOrigin, a
long credential ID, packed with six key types, TPM, Android Key, Apple,
FIDO U2F, chained to its root), py_webauthn's vectors from real
authenticators (YubiKeys, four TPMs, Android phones under
Google's roots, an iPhone under Apple's), and a software authenticator
changing one thing at a time (wrong challenge, origin, RP ID and type,
missing UP and UV, contradicting flags, trailing bytes, duplicate CBOR
keys, oversized credential IDs, a wrong AAGUID extension, an ES256 key
that says RS256, unknown and forbidden algorithms, counters going
back); cbor against RFC 8949's Appendix A and against Python's cbor2 on
random items written every way and mutated (`make differential-cbor`);
live (`make interop-webauthn`) against python-fido2's Fido2Server,
py_webauthn and go-webauthn, both ways: a software authenticator built
with python-fido2's classes registers and signs in with all four, each
refuses the same tampered responses, each one's options are answered
and checked by the others, and goose-webauthn's options are read by all
three. The real FIDO MDS3 BLOB verifies too.

### radius: RADIUS, RadSec and EAP

`radius` is RADIUS for both ends of a network's logins: the NAS (a
switch, an access point, a VPN concentrator) asking, and the server
answering, with EAP inside for 802.1X. Packets are numbers and bytes in
wire order, with helpers for the standard attributes and Microsoft's;
every Access-Request and every answer to one carries a
Message-Authenticator as its first attribute, and the client and server
require one, which is what BlastRADIUS (CVE-2024-3596) asks of both
ends. The client retransmits over UDP the same bytes each time and
drops answers that do not check, or runs over RadSec (RFC 6614) with
TLS certificates both ways; it does PAP, CHAP, MS-CHAPv2 (checking the
server's proof), accounting, Status-Server, CoA and Disconnect, and a
whole EAP conversation with the State carried, checking at the end that
the MS-MPPE keys in the Access-Accept are the supplicant's own MSK. The
server's `handle` takes a request's bytes and gives the answer's, the
passwords from a block, EAP conversations kept by their State between
requests. EAP's peer and server are step functions that know nothing of
RADIUS: MD5-Challenge, MS-CHAPv2, EAP-TLS (RFC 5216, and RFC 9190 over
TLS 1.3 with its commitment message), PEAPv0 with EAP-MS-CHAPv2 inside
and the Result TLV, and TTLS with PAP or MS-CHAPv2 inside; TLS messages
in fragments both ways; the keys from TLS 1.2's PRF or TLS 1.3's
exporter (RFC 9427), for which `crypto/tls` gained `tls::export_keys`.
goose-radtest makes one exchange of any method as radtest and eapol_test
do, and goose-radiusd is a small server with RadSec and a NAS's CoA
port.

Tested against RFC 2865 §7.1's packets, RFC 2759's MS-CHAPv2 and RFC
3079's key vectors byte for byte, every method peer against server in
memory over TLS 1.2 and 1.3 with small fragments, wrong passwords,
missing certificates and untrusted servers; and live (`make
interop-radius`, Docker) against FreeRADIUS 3.2.10, wpa_supplicant's
eapol_test and radclient, both ways, every method on both TLS
versions, RadSec both ways (FreeRADIUS proxying over it too), with the
MS-MPPE keys matching the MSK on every side: 57 checks. A libFuzzer
target covers the parser, EAP's reassembly and the server's handling.

### smb: an SMB2 and SMB3 client

`smb` reads and writes files on Windows and Samba file servers. It
speaks every SMB2 and SMB3 dialect, 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1,
over TCP port 445, and logs in through SPNEGO with NTLMv2 (gslib's
`ntlm`) or Kerberos with a service ticket from gslib's `krb5`, the
server's AP-REP checked. Then come shares and files: trees, CREATE and
CLOSE, READ and WRITE cut to the server's maximums and charged several
credits each when the server allows large ones, directory listings,
file and file system information, times and sizes set, renames and
deletes, and whole files read or written in one call.

Its first concern is that nothing the session should protect gets
through unprotected. Signing is required by default; encryption is used
when the server asks for it, for the session or a share, or when the
client requires it. Every response is then checked: one that should
have been signed or encrypted and was not, or whose signature or tag is
wrong, fails the request. The negotiation is protected too: under 3.1.1
the session's keys come from a SHA-512 hash of every NEGOTIATE and
SESSION_SETUP message, and the server's signature on its last
SESSION_SETUP response is checked with them; under 3.0 and 3.0.2 a
signed FSCTL_VALIDATE_NEGOTIATE_INFO follows the first TREE_CONNECT.
Signing is HMAC-SHA256 on 2.x, AES-128-CMAC on 3.x and AES-128-GMAC
when 3.1.1 negotiates it; encryption is AES-128-CCM on 3.0 and 3.0.2,
and AES-128-GCM, AES-128-CCM, AES-256-GCM or AES-256-CCM on 3.1.1, the
256-bit keys from the whole Kerberos session key. Keys come from SP
800-108's KDF with each dialect's labels. AES-CCM was new to gslib:
`crypto/bignum` gained `bignum.ccm`. goose-smbclient is a small
smbclient: ls, get, put, cat, mkdir, rmdir, rm, mv, stat, truncate,
touch, df and info, several in one connection.

Tested against Microsoft's published SMB 3 vectors (the 3.1.1 preauth
hash over real Windows messages, the keys of seven sessions, signatures,
and WRITE and READ messages encrypted and decrypted with CCM and GCM,
byte for byte both ways), Windows's own requests rebuilt byte for byte,
and every truncation of a response refused; and live (`make
interop-smb`, Docker) against Samba 4.17: every dialect with every file
operation and Samba's smbclient reading what it wrote and the other way,
both 3.1.1 signing algorithms, AES-128-CCM on 3.0 and 3.0.2 and all
four ciphers on 3.1.1, shares and
servers that require encryption, Kerberos against Samba's AD DC
(including AES-256-GCM), anonymous sessions, refusals, and a man in the
middle changing one response at a time (a signature, the SIGNED flag,
an encrypted message, the final SESSION_SETUP, a NEGOTIATE under 3.1.1
and under 3.0), which every time fails the client: 57 checks. A
libFuzzer target covers the response parsers, decryption and signature
checks.

### kmip: KMIP, a key manager's protocol

`kmip` speaks KMIP, the OASIS protocol between programs and key
managers (HSMs, CipherTrust, Fortanix, Vault's KMIP engine, the storage
arrays and databases that encrypt with keys kept elsewhere), versions
1.0 to 1.4, 2.0 and 2.1, in its three encodings: TTLV, decoded into
nodes that point into the buffer and refused at the first thing that is
not exactly right, and the XML and JSON of KMIP's Profiles, as strict;
over TLS, or over HTTPS in any of the three. The tags and enumerations
are generated from KMIP 2.1's specification. The one real difference
between 1.x and 2.x for a client is attributes: 1.x names them by text
inside Template-Attributes, 2.x writes each under its own tag; `Attrs`
holds 2.x's items, vendors' attributes included, and each operation
writes the form of the version negotiated.

Both sides cover KMIP 2.1 nearly whole. The client has every operation:
the key life cycle, Locate and the attribute operations; Get and Export
in any key format (PKCS #1, PKCS #8, SEC 1, X.509 and the transparent
structures, converted both ways) and wrapped as a Key Wrapping
Specification asks (NIST Key Wrap, AES Key Wrap with Padding, GCM,
RSA-OAEP, HMAC or signatures, either encoding), which a client can
unwrap with its own copy of the key; Import; Re-key and Re-key Key
Pair; Derive Key (PBKDF2, HKDF, SP 800-108's three modes, HMAC, HASH,
ENCRYPT, ECDH); Certify, Re-certify and Validate; split keys; Encrypt,
Decrypt, Sign, Signature Verify, MAC, MAC Verify and Hash, each also in
parts; asynchronous items, tickets (Login, Delegated Login), and 2.1's
defaults, constraints and Rotate attributes. The same operations run
against a server in the same program (`kmip.local`), and `handle` is
that server: an in-memory store whose objects belong to the client that
made them, KMIP's life cycle and its dates enforced (Protect Stop and
Process Start Dates, Usage Limits, Sensitive and Extractable, archived
and destroyed objects), batches stopped, continued or undone, the
attributes a server keeps (Digest, Short Unique Identifier, Fresh,
Lease Time...) kept; its cryptography gslib's own (AES, Triple DES,
ChaCha20-Poly1305, HMAC, CMAC, RSA, ECDSA and ECDH on the NIST curves,
secp256k1 and brainpool). goose-kmip is a command-line client and
goose-kmipd serves the in-memory store over TLS with client certificates,
and over HTTPS.

Tested against KMIP 1.2's encoding examples byte for byte, the 245 TTLV
encodings in PyKMIP's unit tests decoded and written again unchanged
and through XML and JSON; against published answers for what the server
computes (RFC 3394, 5869, 6070 and 8439, SP 800-38B and 800-108); against
OASIS's own test cases for KMIP 1.4, 2.0 and 2.1 (fetched, not kept
here), 541 recorded conversations replayed against the in-memory server,
of which 467 pass and the rest are listed in kmip's README by what they
need; and live (`make interop-kmip`, Docker) against PyKMIP's server in
KMIP 1.0 to 2.0, goose-kmipd against gslib's client and PyKMIP's, and
the HTTPS binding against curl. Two libFuzzer targets cover the TTLV
decoder, the XML and JSON readers, the readers of messages and the
server's `handle`.

### service: system services

`service` makes a Goose program a system service on the three platforms
gslib runs on, with one API, after Go's kardianos/service: a Windows
service of the service control manager, a systemd unit on Linux (a
user's, with `systemctl --user`, or the system's), or a launchd agent or
daemon on macOS. A program calls `service::begin` first thing, then takes
the system's requests from `service::wait` while it works (stop, system
shutdown, reload, pause and continue), and calls `service::end` when it is
done. From a console the same program runs as it is, with Ctrl+C,
SIGTERM and the console closing as a stop, so a service is tried out by
running it. `service::install`, `uninstall`, `start`, `stop`, `restart` and
`status` manage one from a `Config` (its name, description, arguments,
working directory, start type, restart delay and stop timeout), and
`service::command` gives a program those as its first argument's verbs.
On Windows install registers the service with its description, delayed
automatic start if asked, restart on failure (a non-zero exit counting as
one), and an Application event log source, so `service::log` writes
readable entries there; elsewhere the log is stderr, with systemd's
priority prefixes under the journal. The systemd unit and the launchd
property list are made in Goose (quoted for systemd's and Windows'
command lines, escaped for XML) and checked byte for byte by the tests.

Goose has no function pointers and its code must not be entered from
threads it did not start, while the service control manager runs a
service's ServiceMain and control handler on threads of its own. So the
C half, service/src/service.c, keeps all of that to itself: it starts the
dispatcher on a thread, reports the service running, and turns every
control (and on POSIX every SIGTERM, SIGINT and SIGHUP, through a
self-pipe) into an event in one queue, which Goose waits on from its own
thread. ServiceMain does not return, and the service is not reported
stopped, until the program calls `end`. It also runs systemctl and
launchctl, since os has no way to start a process.

Tested with unit tests of the generated texts, the event queue and the
signals; and live (`make live-service`): examples/service/heartbeat is
built, installed, started, killed (and restarted by the service manager),
stopped (writing its last line on the way out), restarted and
uninstalled through its own verbs on Windows Server 2022 (the program
built by MSVC, clang-cl and clang, and by MinGW's gcc with
libwinpthread beside it), on Linux with systemd 245 (a user's unit) and
on macOS (a launchd agent).

### sys: the operating system's calls

`sys` is what Go keeps in golang.org/x/sys and os/user, for the three
platforms gslib runs on, with one API where they agree and a module each
where they do not. The `sys` module has the host (name, `uname`, CPUs,
memory, uptime, load), this process and others (the process list, another
process's executable and arguments, `kill`), the environment, users and
groups looked up by name or id (SIDs on Windows, as Go's os/user has them),
files by path (`stat` with birth times, modes, links and symbolic links,
`readlink` of junctions too, `utimes`, `realpath`, `read_dir` with kinds)
and by descriptor (a HANDLE on Windows: `pread`, `pwrite`, `seek`, whole-file
locks, pipes), and memory maps. `sys.registry` is x/sys/windows/registry:
keys, every value type, enumeration, deletion. `sys.windows` manages a
Windows machine as iamacarpet/go-win64api does: local accounts (added,
deleted, passwords, enabled, disabled, unlocked), local groups and their
members, Remote Desktop sessions, services with their configuration,
shares, installed software and a process's owner and memory. `sys.unix` has
signals as values a loop waits for, resource limits and usage, sessions and
process groups, sysctl (on Linux read from /proc/sys) and every user and
group; `sys.term` is x/term: terminal size, raw mode, passwords without
echo, on POSIX terminals and Windows consoles alike.

`sys.process` is Go's os/exec, with a pseudo-terminal as well: a child
started from its words (found on PATH as `exec.LookPath` finds it, with
PATHEXT on Windows), its environment inherited or not and its directory,
each of stdin, stdout and stderr inherited, piped, sent to the null device,
given a descriptor or (stderr) sent where stdout goes; a new session or
process group, so that a signal reaches all of it; waiting with a timeout,
killing, and `output` and `run` for the simple cases. A program that cannot
be run is `start`'s error, not a child that exits 127: on POSIX the child
reports exec's errno through a pipe that the exec closes, as Go does. With
`pty` the child gets a terminal of its own, a POSIX pty or, on Windows 10 and
later, a ConPTY pseudo-console, which `resize` changes; `collect` reads its
output while waiting for it, the order Windows' pseudo-console needs. Only
the child's own three handles are inherited on Windows
(`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), and on POSIX every other descriptor is
closed in the child. `poll` waits on several descriptors (POSIX) and
`available` says what a pipe holds (both).

The `sys` module also makes files that are only their owner's: a mode that
gives the group and others nothing (0600, 0700) is honoured on Windows too,
as an owner-only DACL (SYSTEM, Administrators and the owner, as Python's
`os.mkdir(path, 0o700)`). On top of that are `create_file` (new only, never
through a symbolic link: `O_EXCL` and `O_NOFOLLOW`, which sys now has
everywhere), `replace_file` (a new file beside the old, renamed over it),
`read_private` (opened without following a link, then checked on the
descriptor: a regular file that only this user can reach, as ssh checks its
keys; `is_private` asks the same of any descriptor), and Go's
`os.CreateTemp` and `os.MkdirTemp`. `os_info` says what the system is:
os-release's name, id and version on Linux, macOS's version and build, and
Windows' product name (Windows 11 told from Windows 10 by its build, which
the registry's ProductName does not), display version, build and edition;
`boot_time` when it started. mime's spilled form files and tpm2's device go
through these, so neither has C of its own any more.

Errors are the system's, negated (errno, or the Win32 code), with
`sys::ENOTSUP` for a call a platform does not have, so a program calls
anything anywhere and asks `is_not_exist`, `is_permission` and the like what
it got. Every function the Goose side declares has to exist on every
platform, since gslib's JIT library resolves all of a package's externs; so,
as Go generates its syscall stubs with mksyscall, sys/scripts/gen_ffi.py
makes the declarations, the C prototypes and a not-supported stub for each
platform a function is not for, all from one table (sys/src/api.def), and
the prototypes keep the C honest. Strings and lists come back through a
builder the C appends to, as length-prefixed fields; text is UTF-8 in Goose
and UTF-16 in the Windows C.

Tested by five programs whose output is the same on every platform: the
host and process calls, users and groups found three ways, files and
descriptors in a directory of their own (locks between two descriptors,
pipes, hard and symbolic links, file and anonymous maps), the registry
under a key of its own, signals sent to the test itself, and, as an
administrator on Windows, an account, a group and a share made, changed and
deleted; then child processes on pipes and on a pseudo-terminal (the
environment, the directory, a timeout, kill, a program that cannot be run),
and private and temporary files with the system's name. They pass on macOS,
Linux and Windows Server 2022, under the JIT and built with MSVC. Seven
examples go with it: sysinfo, an `ls -l`, a `reg query`, a Windows admin
view, a password prompt, a signal-driven daemon loop and a command run on a
pipe and on a terminal. Not yet there from go-win64api: firewall rules and Windows Update
history (COM) and the WMI hardware inventory.

### sspi: Windows' security packages

On Windows, sspi reaches the system's own authentication and TLS through
SSPI, as Go's alexbrainman/sspi does. sspi.schannel is a TLS client that
uses Windows' TLS stack over gslib's sockets. It uses the system's roots,
revocation checks and protocol policy, TLS 1.3 included, and hands over
the server's certificate for x509 to check. sspi.negotiate makes HTTP's
Authorization: Negotiate header from the Windows login (Kerberos in a
domain, NTLM otherwise) or from a user's name and password, so the server
never sees a password. Underneath, the core layer gets credentials,
builds client and server contexts a token at a time, and signs and seals
messages. It has no C: secur32 is bound by Goose extern blocks, its
structures laid out in memory from kernel32. Off Windows every call says
SEC_E_UNSUPPORTED_FUNCTION, so programs build everywhere (and run there
with a goose whose runtime leaves the libraries gslib.build spells `-`
unopened). The live check (`make live-sspi`,
sspi/scripts/sspi_check.py) runs Schannel against gslib's own TLS server
and public sites, and Negotiate against gslib's NTLM acceptor. Kerberos
was tried against an Active Directory domain: SSPI's tickets went to a
Goose server (examples/krb5/negotiate_server.goose) holding only the
service's keytab, which verified them and their PACs, and SSPI verified
the server's reply in turn.

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
- **OpenPGP and PGP/MIME**: gpg 2.5's Kyber keys (ML-KEM-768+X25519, and
  its default ML-KEM-768+brainpoolP256r1), both ways with gpg, and RFC
  9980's ML-KEM-768+X25519 and ML-DSA-65+Ed25519, against the RFC's
  vectors; KMAC (SP 800-185) in crypto/bignum for them.

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

## Elliptic curves

crypto/bignum's ECDH and ECDSA run on the NIST curves P-224 to P-521 and
on the Brainpool curves brainpoolP256r1, P384r1 and P512r1 (RFC 5639; RFC
7027 and RFC 8734 name them for TLS), signing the Brainpool ones with
SHA-256, SHA-384 and SHA-512. All seven share one constant-time
implementation, adding points with Renes, Costello and Batina's complete
formulas (the a = −3 form for NIST's, the general one for Brainpool's).
The Brainpool curves pass RFC 7027's and RFC 6932's ECDH examples,
Wycheproof's ECDH and ECDSA tests for those three curves, and signatures
from openssl and Python's `cryptography` and `ecdsa`. Example:
`examples/bignum/brainpool.goose`.

Besides Curve25519 (X25519, Ed25519), crypto/bignum has Curve448: X448
key exchange (RFC 7748) and Ed448 signatures (RFC 8032), with contexts and
Ed448ph, in constant time on sixteen 28-bit limbs. They pass all of the
RFCs' vectors (X448's million-step chain among them), Wycheproof's X448
and Ed448 tests, and keys, secrets and signatures from openssl. The API
mirrors Ed25519's (`ed448_sign(seed, msg, ctx)`, `x448_shared(sk,
peer)`), so x509, TLS, OpenPGP and JOSE can take them up the same way.
Example: `examples/bignum/x448_ed448.goose`. jwx has: Ed448 JWS and JWT
(`EdDSA` and RFC 9864's `Ed448`) and X448 ECDH-ES on RFC 8037's OKP keys,
agreeing both ways with Go's jwx v4 (Brainpool has no JOSE identifiers, so
jwx leaves it out). crypto/x509 takes all five: brainpool keys under
id-ecPublicKey and Ed448 and X448 under RFC 8410's OIDs, in certificates,
CSRs, CRLs, OCSP, PKCS #8 and PKCS #12, and in CMS (brainpool ECDSA and
ECDH, Ed448 signers by RFC 8419, X448 recipients by RFC 8418; mail.smime
signs with brainpool keys and encrypts to brainpool and X448
certificates), checked against openssl both ways; its example is
`examples/x509/new_curves.goose`. OpenPGP uses them as gpg does: Brainpool
ECDSA and ECDH keys, gpg's v5 Ed448 and cv448 keys, and gpg's default
post-quantum key (brainpoolP384r1 with ML-KEM-768+brainpoolP256r1), all
checked against gpg 2.5 both ways; and RFC 9580's native Ed448 and X448 on
v6 keys, which gpg 2.5 does not know. Example:
`examples/openpgp/new_curves.goose`. crypto/tls has the X448 and RFC
8734's Brainpool groups (named last by default, with no share) and Ed448
and Brainpool certificates in TLS 1.3, and X448, RFC 7027's Brainpool
groups and Ed448 in TLS 1.2, checked against OpenSSL 4.1; example:
`examples/tls/new_curves.goose`, and jwx's PEM reads and writes Ed448
and X448 keys as OKP JWKs.

## Keys held elsewhere: TPMs, tokens and signers

A private key that lives in a TPM, on a PKCS#11 token or HSM, or in a
remote signing service can be used wherever gslib signs: a TLS server's
or client's certificate (TLS 1.3 and 1.2), an SSH host key or user key,
certificates, CSRs, CRLs and OCSP responses made by x509, CMS SignedData,
JWS and JWT, and an HTTPS client's certificate. It works as Go's
crypto.Signer does. A configuration holds the key's public half, an
`x509::external_key` made from its SubjectPublicKeyInfo or from its
certificate, and the call that signs takes a signer as its last argument:
a function or block given x509's algorithm, the hash and the digest (the
message itself for Ed25519, Ed448 and ML-DSA), which returns the
signature. Goose has no interfaces and keeps no function in a struct, so
the signer is passed to the call rather than stored in the configuration,
and a block may name the caller's own TPM or PKCS#11 session:

    tls::server_feed(c, cfg, input, out, app) { k, alg, h, data => tpm2::sign_data(t, key, s, alg, h, data) }

The calls without a signer sign with keys in memory as before, and
tls, ssh, x509 and jwx gain no dependency: the signers come from tpm2
(`tpm2::sign_data`, `tpm2::x509_key` for a TPM key's public half) and
pkcs11 (`p11::sign_data`, `p11::x509_key`). TLS never chooses the RSA key
exchange, which would need to decrypt, for such a key. x509 checks the
signature a signer returns on the certificates and CSRs it makes, as Go
checks a crypto.Signer's, so a signer answering with another key's
signature is caught.

Tested in memory with a signer holding the key apart, for every key type
TLS 1.3 and 1.2 sign with, SSH's Ed25519, ECDSA and RSA host and user
keys, x509's certificates, CSRs, CRLs, OCSP and CMS, and JWS and JWT; live
against swtpm, a P-256 and an RSA key made in the TPM signing a
certificate, a CSR, TLS 1.3 and 1.2 handshakes, an SSH login and a JWT,
and an HTTPS server answering curl and openssl; against SoftHSM2, P-256,
RSA and Ed25519 keys on the token doing the same; and goose-http with a
client certificate (`--cert`, `--key`, the key signing through a signer)
against a Python server that requires one. Examples:
`examples/tls/key_elsewhere.goose`, `examples/tpm2/tls_server.goose` and
`examples/pkcs11/signer.goose`.

## Using it

A program declares the package once, in its root file, and imports the
modules it uses:

```goose
import gslib from "SorinS/gslib@v0.7.0";     // or a path: import gslib from "../gslib.git";
import gslib.net.http.fetch;
import gslib.crypto.tls.handshake;

fn main() {
    var c = http::Client { .. };
    var r = http::get(c, "https://example.com/");
    print(r.status, " ", http::response_body(r).len);
}
```

The tag pins a release; use v0.7.0 or a later one (`git tag` in gslib.git
lists them), or a commit by its full hash.

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

The C is net's sockets
(`net/src/net.c`, behind `net.goose`: `import gslib.net;`, then
`net::dial`), sys's system calls (`sys/src`, which mime and tpm2 use
too), pkcs11's module loading (`pkcs11/src/p11.c`), service's service
managers, named in `gslib.build` and compiled only into programs that
call them. Libraries and tools reach the system through net and sys
rather than C of their own, and Windows' DLLs through Goose extern blocks
(sspi's secur32).

## Layout

```
gslib.goose, gslib.build              the package's entry and its sidecar
<group>/<lib>.goose                   each library's main module (crypto/tls.goose)
<group>/<lib>/*.goose                 its other modules (crypto/tls/handshake.goose)
<group>/<lib>/test, tools            its programs (excluded from the package in gslib.build)
<group>/<lib>/scripts                 its test runners, differentials, interop
<group>/<lib>/README.md               its documentation
compress.goose, compress/             compress, laid out the same way at the top
entropy.goose, entropy/src/           entropy and its C, the same
net.goose, net/                       net's sockets (net/src), addresses (net/ip.goose) and IDNA; net/ is also http's and ldap's group
websocket.goose, websocket/           websocket, the same
mime.goose, mime/                     mime, the same
mail.goose, mail/                     mail, the same
acme.goose, acme/                     acme, the same
oauth.goose, oauth/                   oauth, the same
tsp.goose, tsp/                       tsp, the same
est.goose, est/                       est, the same
scep.goose, scep/                     scep, the same
saml.goose, saml/                     saml, the same
ntlm.goose, ntlm/                     ntlm, the same
tpm2.goose, tpm2/                     tpm2, the same
radius.goose, radius/                 radius, the same
smb.goose, smb/                       smb, the same
kmip.goose, kmip/                     kmip, the same
webauthn.goose, webauthn/             webauthn, the same
service.goose, service/, service/src/ service, the same, and its C
sys.goose, sys/, sys/src/             sys and its modules (registry, windows, unix, term, process), the same, and its C
sspi.goose, sspi/                     sspi, the same
examples/<lib>/                       each library's examples (excluded too)
scripts/run_all.py            every library's unit tests
scripts/split.py              the standalone repositories, synced from here
Makefile                      the programs, checks and tests
```

Each library came from a repository of its own (bigmongoose, asn1goose,
x509goose, tlsgoose, sshgoose, ldapgoose, yamlgoose, httpgoose,
compressgoose, mimegoose), and `git log --follow -- <group>/<lib>` shows that history.

Those repositories still publish each library as a package of its own,
and `scripts/split.py` keeps them in step with gslib: run from gslib's
top, it copies a library's modules, C, tests, tools, scripts, README and
examples into its repository beside gslib.git and rewrites the imports
for a package of its own (`import gslib.crypto.tls.handshake;` becomes
`import tls.handshake;`, and a library that needs another declares it, as
`import bignum from "SorinS/bigmongoose@v0.7.0";`). net and ntlm, which
http needs, have repositories of their own too (netgoose, ntlmgoose), and
so does entropy (entropygoose), which the libraries import by name alone,
with no requirement line, so that a program's root can declare another
package in its place. The
table at the top of the script maps each library to its repository and
lists what is left out and why; the dependencies come from the imports,
and a library needing one with no repository, or a cycle, stops it.

```bash
python3 scripts/split.py --graph               # who needs whom, and the order to tag and push in
python3 scripts/split.py --mode local          # sibling paths (../bigmongoose.git), to test the set
python3 scripts/split.py --dry-run             # what would change in each repository
python3 scripts/split.py                       # GitHub pins at gslib's tag, as published
```

It commits nothing: each repository is then tested, reviewed, committed
and tagged on its own, in the order `--graph` prints. Files an older
copy of a library left there are deleted (`--keep-stale` keeps them);
anything else only a repository has, its LICENSE and .gitignore among
them, is kept.

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

goose.git's master from ee261a4c (#346) on: entropy takes its bytes from
`os::random_bytes`, which has ProcessPrng on Windows since then; http's
client keeps its state in a `root struct` (683ebc94 on). The tests ran with master as it is,
v2026.3-252-g2ed1a63d, on Linux, and on macOS with v2026.3-254-gd402d2c7,
master and one fix of TinyCC's arm64 code (dfe35659, for `goose run`).

On Windows, executables `goose build` writes get a 1 MB stack, which
some tests overflow.

`net/http/data/public_suffix_list.dat` is publicsuffix.org's list (MPL 2.0),
built into programs that call `http::psl_builtin`.

## Building

```bash
make            # the targets, with what each does
make build      # the programs into ../bin (BIN=dir for another): goose-http, goose-httpd,
                # goose-ssh, goose-sshd, goose-scp, goose-sftp-server, goose-ssh-keygen,
                # goose-ldapsearch, goose-ldapadd, goose-ldapmodify and the other ldap tools,
                # goose-krb5, goose-gss, goose-dig, goose-dnsd, goose-mail, goose-pgp, goose-acme,
                # goose-oauth, goose-ts, goose-est, goose-scep, goose-saml, goose-ntlm, goose-tpm,
                # goose-webauthn, goose-wscat, goose-wsecho
make check      # type-check every tool and example
```

The compiler is `GOOSE`, else `goose` on the PATH, else
`../goose.git/build/goose`.

## Tests

```bash
make test                 # every library's unit tests (make test-http: one library's)
make test-native          # also built with the C compiler
make interop              # live: OpenSSL, Go, OpenSSH, OpenLDAP, curl, nghttp2, h2spec, pkcs11-tool, dig, miekg/dns,
                          # mailpit, dovecot, dkimpy, gpg, Pebble, OpenBao, node-oidc-provider,
                          # digitorus/timestamp, signxml, xmlsec, GlobalSign's EST, micromdm's SCEP,
                          # pyspnego, impacket, go-ntlmssp, swtpm, tpmemu, python-fido2, py_webauthn, go-webauthn,
                          # Autobahn|Testsuite, Python's websockets
make differential         # against Go (net/http, net/url, hpack, compress, mime, jwx, miekg/dns), zlib, openssl,
                          # libxml2 (lxml, xmlsec), go-tpm, cbor2
make live-service         # installs, starts, kills, stops and uninstalls a real service (a user's
                          # systemd unit or launchd agent; on Windows, as an administrator)
make live-sspi            # Windows: Schannel against gslib's TLS server and public sites, Negotiate
                          # against gslib's NTLM acceptor
make test-all             # check, test, interop and differential
python3 scripts/run_all.py [--native] [--only http,tls]   # what make test runs
```

Each library's README lists its differentials (against Go, Python's zlib
and hashlib, OpenSSL, Go's lestrrat-go/jwx and miekg/dns), its interop
runs (curl, Go's net/http and crypto/tls, OpenSSL, OpenSSH, OpenLDAP,
nghttp2, h2spec, OpenSC's pkcs11-tool, dig, miekg/dns, mailpit, dovecot,
dkimpy, gpg, Pebble, OpenBao, node-oidc-provider, digitorus/timestamp, signxml,
xmlsec, GlobalSign's estserver and estclient, micromdm's scepserver and
scepclient), and what is not
done yet. Every server they start
listens on 127.0.0.1.

xml's interop and differential need a Python with lxml, signxml, xmlsec
and cryptography: `python3 -m venv VENV && VENV/bin/pip install lxml
signxml xmlsec cryptography`, then `XML_PYTHON=VENV/bin/python make
interop-xml differential-xml` (xmlsec's wheel carries libxmlsec1; nothing
is installed system-wide). Without the modules they are skipped.

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

oauth's interop runs node-oidc-provider (node and npm; `npm ci` installs
it into `oauth/scripts/op` from the committed lock file on the first run)
and needs openssl for its test CA; it is skipped without node. Keycloak,
in Docker or Podman, is skipped unless a daemon is already running.

tsp's interop needs openssl 3 or later (`openssl ts`, `openssl cms`), and
uses curl and Go (digitorus/timestamp, fetched by `tsp/scripts/gotsa`'s
go.mod) when they are installed.

saml's interop needs a Python with requests, python3-saml and lxml in a
venv (`SAML_PYTHON`; python-xmlsec's wheel carries libxmlsec1), and Go
for crewjam/saml (fetched by `saml/scripts/crewjam`'s go.mod); each part
is skipped without what it needs.

ntlm's interop needs a Python with pyspnego (impacket optional) in a
venv (`NTLM_PYTHON`), and uses curl and Go (Azure/go-ntlmssp, pinned by
`ntlm/scripts/gontlm`'s go.mod) when they are there. It talks to no
Windows host; ntlm/README.md says how to try one of your own.

tpm2's interop needs swtpm (`brew install swtpm`, `apt install swtpm
swtpm-tools`; swtpm_setup for the EK certificates) and runs the Sail TPM's
tpmemu when `TPMEMU` names it (or it is on the PATH); each is skipped when
missing, and tpmemu's known departures from the specification are
reported, not failed. Its differential needs Go (go-tpm, pinned by
`tpm2/scripts/gotpm`'s go.mod).

webauthn's interop needs a Python with fido2 (python-fido2 2.x),
webauthn (py_webauthn), cbor2 and cryptography in a venv
(`WEBAUTHN_PYTHON`), and Go for go-webauthn (pinned by
`webauthn/scripts/gowebauthn`'s go.mod); each part is skipped without
what it needs. No browser or hardware key can be driven from here:
webauthn/README.md says how to try `goose-webauthn serve` with your own.
cbor's differential needs cbor2 (`CBOR_PYTHON`).

The parsers of untrusted input are also fuzzed, coverage-guided: fuzz/
holds a target for each (ASN.1, the X.509 family and CMS, DNS messages and
zone files, CBOR and COSE keys, XML, YAML, every compressor and archive,
MIME, HTTP/1.1, HPACK, HTTP/2, URLs and cookies, LDAP, JOSE, OpenPGP, SSH,
Kerberos and the PAC, NTLM, TPM 2.0, WebAuthn, SAML, the TLS handshake and
mail), with seed corpora from the test vectors. `make fuzz-replay` runs
the corpora and the regression inputs through a plain driver with ASan
and UBSan, which Apple's clang builds; `make fuzz TARGET=dns_msg
SECONDS=600` runs one target under libFuzzer, which needs a clang that
has it (Homebrew's LLVM, or clang on Linux). fuzz/README.md says how the
targets are built and how crashes are triaged.
