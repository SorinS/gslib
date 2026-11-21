# openpgp

OpenPGP (RFC 9580, and RFC 4880 as GnuPG still writes it) for the Goose
language. It reads and writes keys, signatures and encrypted messages, and
it interoperates with gpg 2.5 in both directions. Everything is in
namespace `openpgp`.

| Module | Holds |
|---|---|
| `openpgp` | error codes, algorithm ids, MPIs, hashes by OpenPGP id, CFB over every cipher, S2K (simple, salted, iterated, Argon2) |
| `openpgp.armor` | `armor`, `dearmor`, `decode_input`, CRC24; the cleartext framework's text rules (`parse_cleartext`, `dash_escape`, `canonical_text`) |
| `openpgp.packet` | `Packet`, `next_packet`, `packet_body` (partial lengths joined), `put_packet`, `put_old_packet` |
| `openpgp.ocb` | AES-OCB (RFC 7253), which bignum does not have |
| `openpgp.key` | `Key`: one key packet (v4, LibrePGP's v5, v6), its fingerprint and key ID, `unlock_key`, signing and verifying a digest, wrapping and unwrapping session keys |
| `openpgp.sig` | `Signature`: signature packets (v4, LibrePGP's v5 as gpg's Ed448 keys make them, v6) and subpackets, `verify_signature`, `make_signature` |
| `openpgp.keyring` | `Keyring`: transferable keys with their user IDs and subkeys checked, `add_keys`, `find_key`, `unlock`, `signing_key`, `encryption_key`, `export_public`, `export_secret` |
| `openpgp.message` | `sign`, `sign_detached`, `sign_cleartext`, `encrypt`; `read_message`, `decrypt`, `verify`, `verify_detached`, `verify_cleartext` |
| `openpgp.keygen` | `generate_key` (Ed25519 + Curve25519), `generate_rsa_key`, `generate_brainpool_key`, `generate_ed448_key` (gpg's v5 Ed448 + cv448), `generate_ed448_v6_key` (RFC 9580's Ed448 + X448); post-quantum: `generate_pqc_bp_key` (gpg 2.5's default, brainpoolP384r1 + ky768_bp256), `generate_pqc_key` (Ed25519 + ky768_cv25519), `generate_rfc9980_key` |
| `openpgp.pqc` | the composite KEMs of RFC 9980 and LibrePGP, gpg-agent's S-expressions and their OCB protection (gpg's "mode 1003" secret keys) |
| `openpgp.dump` | `list_packets`, in the manner of `gpg --list-packets` |

It builds on [bignum](../bignum) for the cryptography (ML-KEM, ML-DSA
and KMAC256 for the post-quantum keys) and on
[compress](../../compress) for ZIP, ZLIB and BZip2.
[mail.pgp](../../mail) uses it for PGP/MIME (RFC 3156).

```goose
import gslib from "SorinS/gslib@v0.7.0";   // or a path to gslib.git
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;

var kr = openpgp::Keyring { .. };
var err = openpgp::add_keys(kr, my_secret_key);        // armored or binary, gpg's export
err = openpgp::add_keys(kr, bobs_public_key);
let me = openpgp::find_key(kr, "alice@example.com");
let bob = openpgp::find_key(kr, "bob@example.com");
err = openpgp::unlock(kr, me, passphrase);             // when the secret key is protected

var out: u8[>..] = [];
err = openpgp::encrypt(kr, [bob], "", data, out, openpgp::WriteOptions { .. }, me);  // signed, then encrypted

var m = openpgp::Message { .. };
err = openpgp::read_message(kr, received, m, openpgp::ReadOptions { .. });
if err == openpgp::OK && openpgp::signature_status(m) == openpgp::OK { use(m.data); }
```

## What gpg writes, and what is read

gpg 2.5.22's defaults, with keys made by `gpg --quick-gen-key`:

| | gpg writes | here |
|---|---|---|
| keys | v4: Ed25519 (EdDSALegacy, algo 22) primary with a Curve25519 ECDH subkey (algo 18, KDF SHA-256 / AES-128); RSA-3072 on request | read and written (`generate_key` makes the same) |
| protected secret keys | S2K usage 254: iterated and salted SHA-1, count byte 251, AES-128 CFB, the SHA-1 check | read (usage 254 and 255, any cipher here, and RFC 9580's AEAD usage 253 with OCB); written with SHA-256 S2K and AES-256 |
| signatures | v4, SHA-512, issuer fingerprint, a notation | read; written with SHA-256 by default (any SHA-2) |
| encryption to its own keys | LibrePGP's OCB Encrypted Data packet (tag 20, AES-256, chunk byte 16), because its keys advertise AEAD (features 0x07) | read |
| encryption to a passphrase, or to keys without the AEAD feature | SKESK v4 and SEIPD v1 (CFB with the MDC) | read and written |
| compression | ZIP for signed messages, ZLIB to its keys (old-format packets of indeterminate length) | ZIP, ZLIB and BZip2 read and written |
| post-quantum keys | `pqc` (its default): a v4 brainpoolP384r1 ECDSA primary with a v5 Kyber subkey, ky768_bp256 (algo 8, LibrePGP's ML-KEM-768+brainpoolP256r1); `ed25519 cert` then `--quick-add-key FPR ky768_cv25519 encr`; also ky1024_bp384 and ky1024_cv448. The Kyber secret is exported in gpg-agent's format (mode 1003) | read and written (`generate_pqc_bp_key`, `generate_pqc_key`); encrypted to and decrypted both ways (ky1024 read, encrypted to and decrypted; not generated) |
| Brainpool keys | `brainpoolP256r1` (P384r1, P512r1): v4 ECDSA, and ECDH with the KDF by size (SHA-256/AES-128, SHA-384/AES-256, SHA-512/AES-256); signatures with a hash as long as the curve | read and written (`generate_brainpool_key`) |
| Ed448 keys | `ed448` and `cv448`: v5 keys only (EdDSALegacy under OID 1.3.101.113, ECDH under 1.3.101.111 with SHA-512/AES-256), the native octets as SOS (no 0x40 prefix, X448's secret little-endian); v5 signatures, SHA-512 | read and written (`generate_ed448_key`), v5 signatures too |

Also read: RFC 9580's v6 keys (Ed25519, X25519, Ed448, X448), v6
signatures (salted), X25519 and X448 PKESK v3, PKESK v6, SEIPD v2 (OCB),
Argon2 S2K, old-format headers and partial body lengths, the cleartext
framework with or without a `Hash:` header. Written: v4 keys (v5 for gpg's
Ed448 and Kyber kinds, v6 for RFC 9580's and RFC 9980's), PKESK v3, SKESK
v4, SEIPD v1 with the MDC (which every implementation reads, gpg included
whatever the key advertises), one-pass signed messages, v4 signatures (v5
for v5 keys, v6 for v6 keys).

A v5 signature (LibrePGP; what gpg's v5 keys make) is laid out as a v4 one,
with the issuer's v5 fingerprint and no key ID, but hashes more: over a
document (types 0x00 and 0x01) the literal packet's format, name length,
name and date follow the hashed area, six zero octets for a detached
signature and `'t'`, 0 and a zero date for a cleartext one (the literal
packet gpg's armor fakes for it); then 05 FF and an 8-octet length. So an
inline v5 signature also covers the literal packet's name and date.

| Public-key algorithm | |
|---|---|
| RSA (1, 2, 3), 1024 to 8192 bits | sign, verify, encrypt, decrypt (PKCS #1 v1.5) |
| EdDSALegacy (22): Ed25519, and Ed448 (gpg's, OID 1.3.101.113) | sign, verify |
| Ed25519 (27), Ed448 (28; a hash of 512 bits at least) | sign, verify |
| ECDSA (19) on P-256, P-384, P-521, brainpoolP256r1, P384r1, P512r1 | sign, verify |
| ECDH (18) on Curve25519, X448 (gpg's cv448), P-256, P-384, P-521 and the three Brainpool curves | encrypt, decrypt (RFC 6637 KDF, AES key wrap) |
| X25519 (25) | encrypt, decrypt (HKDF-SHA256, AES-128 key wrap) |
| X448 (26) | encrypt, decrypt (HKDF-SHA512, AES-256 key wrap) |
| ML-KEM-768+X25519 (35, RFC 9980), v4 and v6 keys | encrypt, decrypt; v3 and v6 PKESK read, v3 written |
| ML-DSA-65+Ed25519 (30, RFC 9980), v6 keys | sign, verify |
| Kyber (8, LibrePGP), v5 subkeys: ML-KEM-768 or -1024 with X25519, X448 or a Weierstrass curve (gpg's ky768_cv25519, ky768_bp256, ky1024_bp384, ky1024_cv448) | encrypt, decrypt (v3 PKESK) |
| DSA, ElGamal, ML-KEM-1024+X448 (36), ML-DSA-87+Ed448 (31), SLH-DSA (32-34) | listed, fingerprinted; `ERR_UNSUPPORTED` when used |

Symmetric ciphers: AES-128/192/256, CAST5, Twofish, Camellia, Blowfish
and triple DES read; AES, CAST5, Twofish and Camellia written. Hashes:
SHA-2 and SHA-3 for signing; SHA-1 and RIPEMD-160 verified for old
signatures; MD5 refused.

## Keys

`add_keys(kr, data)` reads any number of transferable keys, armored (any
number of blocks) or binary, public or secret. It checks, as it reads:
- each user ID's self-certification (0x10-0x13) by the primary;
- each subkey's binding (0x18) by the primary, and for a subkey that may
  sign, its embedded back-signature (0x19) by the subkey;
- direct-key signatures (v6 keys put their flags there) and revocations
  (0x20, 0x28, 0x30) by the key itself.

The newest valid self-signature (the primary user ID's, for the primary)
gives a key's flags (`FLAG_*`) and expiry, as in gpg. Third-party
certifications are kept for export but not checked: there is no web of
trust here, so who a key belongs to is the caller's to decide.

A key the keyring already holds (the same fingerprint) is merged into
that copy, as gpg imports: new user IDs, subkeys, a secret the copy lacks,
and the key's own signatures (a revocation, a newer self-signature) are
added; third-party certifications in the second copy are not. So a key
fetched again with its revocation is revoked, not shadowed by the first
copy. A key revocation certificate on its own (gpg's `--gen-revoke`)
revokes the key it is for; `add_keys` gives `ERR_NO_KEY` when there is
none.

A `Key` is fixed-size (its numbers are in bounded arrays sized for
RSA-8192), and a keyring refers to its keys by index. A subkey's `primary`
is its primary's index. `find_key` takes a fingerprint or key ID in hex,
an email address (matched whole against a user ID's `<address>`, without
case) or other text from a user ID, and prefers a key whose secret is
there. Only user IDs with a valid self-certification and no revocation
are searched.
`signing_key` and `encryption_key` choose the newest usable subkey, else
the primary.

A protected secret stays locked until `unlock(kr, primary, passphrase)`
(or `unlock_all`); a wrong passphrase is `ERR_PASSPHRASE`, found by the
SHA-1 check. gpg's default count (65 million octets hashed) takes about a
second per key. gpg's stubs (gnu-dummy S2K) read as keys without a secret.

`export_public` writes a key back as it was read, secret packets made
public; given gpg's secret export, it gives gpg's public export byte for
byte. `export_secret` writes the secrets unprotected, protected anew
(iterated SHA-256 S2K, AES-256, the SHA-1 check), or as they were read
while still locked.

## Signing and verifying

`sign` (one-pass signature, literal, signature; compressed if asked),
`sign_detached` and `sign_cleartext` take the signer as a primary key
(whose signing key signs) or a key. `WriteOptions` give the hash (SHA-256
by default), the time, text mode (signature type 0x01 over CRLF line
ends, and a 'u' literal holding the text with CRLF line ends, as RFC 9580
§5.9 asks and gpg writes), armor, and the literal's name and date. Reading
gives a text literal's data as it is in the packet, CRLF and all;
goose-pgp writes it out with LF line ends, as gpg does.

Reading, `read_message` checks every signature it finds and puts the
results in `m.sigs`; `signature_status(m)` is OK when one verifies.
`verify` and `verify_detached` fail unless one does. A signature counts
when:
- it verifies, with a hash that is not MD5;
- its hashed area has no critical subpacket that is not known here;
- its key is in the keyring, bound by a valid self-signature, not
  revoked, not expired at the signature's time, and allowed to sign;
- it has not expired itself (its expiration subpacket) by `now`, or by
  the clock when `now` is 0;
- a v6 signature is not by SHA-1 (or MD5, RIPEMD-160): `ERR_UNSUPPORTED`.

Each of `read_message`, `verify`, `decrypt`, `verify_detached` and
`verify_cleartext` starts by emptying the `Message` it is given, so one
can be used again. (They shrink `m.data`: a label made with `str(...)` in
the same call's arguments has to go into a local first.)

`verify_cleartext` reads the cleartext framework: dash escapes undone,
trailing white space dropped, a signature over a hash its `Hash:` header
leaves out refused. Lines end at LF; a CR elsewhere in a line is part of
the text, for `sign_cleartext` as for the reader (and gpg).

## Encrypting and decrypting

`encrypt(kr, recipients, passphrase, data, out, opts, signer)` makes a
random session key (AES-256 by default), a PKESK v3 for each recipient's
encryption key and an SKESK v4 for the passphrase if one is given, and the
data in SEIPD v1: CFB with the MDC. With a signer, the data is signed
first, in the same message.

`read_message` tries the session key packets in order, PKESKs with the
keyring's unlocked secret keys (wildcard key IDs too) and SKESKs with
`ReadOptions.passphrase`, and stops at the first whose session key opens
the data. Whoever sends a message chooses how many there are, so it takes
at most 8 private-key operations (`MAX_KEY_TRIES`) and 4 passphrase S2K
runs (`MAX_PASS_TRIES`) for one, then `ERR_LIMIT`; an Argon2 S2K may ask
for at most 2 GiB, 16 lanes and the work of one pass over 2 GiB (RFC
9580's first choice; its second, 3 passes over 64 MiB, is well within).
As RFC 9580 §5.1 has it, v3 PKESKs and v4 SKESKs open SEIPD v1 (and
LibrePGP's OCB packet), v6 PKESKs SEIPD v2; others are not tried. It
then decrypts:
- SEIPD v1: the MDC is checked over all of it before anything is
  returned, so changed data is `ERR_INTEGRITY` with nothing out;
- LibrePGP's OCB packet and SEIPD v2: each chunk and the final tag
  checked;
- packet 9, which has no integrity protection: refused
  (`ERR_UNPROTECTED`) unless `allow_unprotected`, as gpg refuses it.

A wrong passphrase is told from changed data by the two repeated octets
of the prefix, as gpg does; with a public-key session key, whose own
checksum held, a mismatch there is changed data. What is decompressed,
all compression layers together, is limited to `ReadOptions.max_size`
(32 MiB unless set; < 0 for none), checked as it comes out, so a bomb
stops there with `ERR_LIMIT` before anything else is checked; a literal
that is not compressed is no larger than the input and is not held to
it. Each layer is read from one buffer into another in turn, not copied.
Eight layers of encryption and compression at most.

RSA decryption uses bignum's PKCS #1 v1.5 decoding, which is constant
time, but a failure is still reported: a server that decrypts messages
for anyone and says whether it worked is a padding oracle.

## Post-quantum

Two composite schemes of ML-KEM-768 (FIPS 203) and X25519 are here, and
they do not mix: gpg 2.5 implements LibrePGP's (draft-koch-librepgp), and
gives algorithm ids 35 and 36 to Dilithium in its headers, so it does not
read RFC 9980's keys (or any v6 key); RFC 9980's test vectors are the
oracle for those.

| | LibrePGP (gpg 2.5) | RFC 9980 |
|---|---|---|
| algorithm | 8 ("Kyber") | 35 |
| key | v5 subkey | v4 subkey or v6 |
| public key | OID 1.3.101.110, `40` X25519 point (as an MPI), 4-octet length, ML-KEM key | X25519 key (32), ML-KEM key (1184) |
| secret key | gpg-agent's S-expression (S2K mode 1003): `(composite-key (private-key (ecc ... (q ...)(d ...))) (private-key (kyber768 (p ...)(s ...)(seed ...))))` | X25519 secret (32), the seed d \|\| z (64) |
| ECDH share | SHA3-256(X25519(eph, R) \|\| eph \|\| R); on brainpoolP256r1 the whole point eph·R (04 \|\| x \|\| y) in its place, with eph and R 65 octets; SHA3-512 past 256-bit curves (X448, bp384, bp512) | X25519(eph, R) |
| KEK | KMAC256(key "OpenPGPCompositeKeyDerivationFunction", 00000001 \|\| eccSS \|\| eph \|\| mlkemSS \|\| mlkemCT \|\| cipher \|\| v5 fingerprint, 256, "KDF") | SHA3-256(mlkemSS \|\| ecdhSS \|\| eph \|\| R \|\| 35 \|\| "OpenPGPCompositeKDFv1" \|\| 21) |
| PKESK fields (v3) | eph as an SOS, 4-octet length and ML-KEM ciphertext, cipher, length, AES-256 key wrap of the session key | eph, ML-KEM ciphertext, length, cipher, AES-256 key wrap |

gpg's Kyber keys on other curves work the same way: the ECC half's OID
(RFC 8410's X448, or a Brainpool or NIST curve), its point (X448's 56
native octets, or 04 || x || y), ML-KEM-1024's 1568-octet key for ky1024;
the agent's S-expression names the curve (`(curve brainpoolP256r1)`,
`(curve X448)`) with no djb-tweak flag, the secret big-endian on a
Weierstrass curve and native for X448, and `kyber1024` for ML-KEM-1024.
gpg's default `pqc` key is brainpoolP384r1 with ky768_bp256.

Both were checked against their oracles: gpg 2.5.22 decrypts what is
written here to its keys and to keys made here, and the other way round
(gpg's OCB packet, SEIPD v1 to keys made here); RFC 9980's Appendix A.1
to A.3 give their fingerprints, session keys, combiner outputs, messages
and signatures. The LibrePGP side follows gpg's source (common/kem.c,
g10/pkglue.c, g10/build-packet.c, agent/pkdecrypt.c, agent/protect.c).

A v5 key's fingerprint is SHA-256 over 0x9A, a 4-octet length and the
key packet's body; its key ID the first eight octets; a signature over it
(gpg's v4 binding of its v5 subkey) hashes it the same way.

gpg keeps a Kyber subkey's secret in its agent and exports it as the
agent's S-expression, and imports it only so: `export_secret` writes it
that way too. With a passphrase, gpg protects the X25519 half with the
agent's openpgp-s2k3-ocb-aes (iterated SHA-1 S2K, AES-128-OCB, the rest of
the S-expression as associated data) and leaves the ML-KEM half as it is;
here both halves are protected, which gpg imports. `unlock` opens either.

ML-DSA-65+Ed25519 signs the digest twice, Ed25519 and ML-DSA (hedged, the
context empty), and a signature verifies only when both do; its hash is at
least 256 bits (SHA-256 is used when a shorter one is asked for). The
seeds are kept (32 octets for ML-DSA, 64 for ML-KEM; gpg's expanded ML-KEM
key when its export has no seed) and expanded when used.

A post-quantum subkey bound by SHA-1 or RIPEMD-160 is not valid (RFC
9980 §7.2). The agent's S2K count is limited to 2^28 octets (ERR_LIMIT).

Messages to post-quantum keys are written as to any other: v3 PKESKs,
SEIPD v1 with the MDC, AES-256 by default (an RFC 9980 key takes AES
only). v6 PKESKs (with SEIPD v2) are read, not written.

## Errors

| Code | Meaning |
|---|---|
| `ERR_MALFORMED` | not OpenPGP: framing, armor, MPIs or lengths broken, input truncated |
| `ERR_UNSUPPORTED` | a version, algorithm, curve or packet this package does not do; an unknown critical subpacket |
| `ERR_BAD_SIGNATURE` | the signature does not verify |
| `ERR_NO_KEY` | no key in the keyring for the signature or the message |
| `ERR_KEY` | a key that cannot do it: no secret, not bound, not allowed to sign or encrypt |
| `ERR_PASSPHRASE` | the passphrase does not open the key or the message; or the key is still locked |
| `ERR_DECRYPT` | a session key that does not decrypt |
| `ERR_INTEGRITY` | the MDC or an AEAD tag does not match: changed data |
| `ERR_CHECKSUM` | the armor's CRC24 does not match |
| `ERR_LIMIT` | too large, too deep, or Argon2 parameters past 2 GiB |
| `ERR_EXPIRED`, `ERR_REVOKED` | the key, at the signature's time |
| `ERR_NO_SIGNATURE`, `ERR_UNPROTECTED`, `ERR_NOT_ENCRYPTED` | as named |

`error_text` gives each one's message.

## Not here

- v6 SKESK, and v6 PKESK written, so nothing is written in SEIPD v2;
  LibrePGP's v5 one-pass signatures and v5 PKESK (gpg writes v3 for both);
- RFC 9980's ML-KEM-1024+X448 (36) and ML-DSA-87+Ed448 (31), and SLH-DSA
  (32-34) in OpenPGP; generating gpg's ky1024 subkeys (they are read and
  used);
- EAX and GCM (read or written): gpg uses OCB;
- DSA and ElGamal operations;
- revoking keys, certifying other keys, adding user IDs or subkeys to a
  key; key expiry when generating;
- the web of trust and trust signatures; keyserver and WKD lookups.

## Tests and tools

`python3 scripts/run_tests.py [-k NAME]` runs test/*.goose at -O0, -O2
and with --debug:
- `ocb`: RFC 7253's sixteen samples and its iterative test for AES-128,
  -192 and -256;
- `pqc`: KMAC256 (SP 800-185's samples); gpg's Kyber key and messages
  (test/vectors/pqc*, from `scripts/gen_pqc_vectors.py`): fingerprints,
  mode 1003 secrets protected and not, decryption, the public export
  identical to gpg's; RFC 9980's Appendix A (rfc9980_a*): fingerprints,
  combiner outputs, session keys, v3 and v6 PKESK with SEIPD v1 and v2,
  ML-DSA-65+Ed25519 signatures with either half changed refused; keys of
  both kinds made, exported, read back and used;
- `framing`: armor, CRC24, packet headers of every kind, partial lengths,
  MPIs, the cleartext text rules;
- `curves`: gpg's Brainpool, Ed448/cv448 (v5) and Kyber keys on
  brainpoolP256r1, P384r1 and X448 (test/vectors, from
  `scripts/gen_curve_vectors.py`): fingerprints and names as gpg lists
  them, every kind of signature verified and refused over changed data,
  messages decrypted (protected keys unlocked), public exports identical
  to gpg's, secrets exported and read back; a v5 signature's trailer octet
  by octet; keys of every new kind made here (RFC 9580's Ed448 and X448
  among them: its Appendix A has no 448 samples), used both ways;
- `gpg_vectors`: what gpg wrote (test/vectors, from
  `scripts/gen_vectors.py`: test keys only, their passphrase in
  passphrase.txt), and RFC 9580 Appendix A's v4 and v6 samples;
- `roundtrip`: everything written here read back, and tampering refused;
- `malformed`: every vector truncated, changed and replaced by random
  bytes, through every reader, without a crash (the post-quantum ones
  among them).

The examples are in [examples/openpgp](../../examples/openpgp):
`sign_verify` (Ed25519, gpg's test key), `pqc` (a key of gpg 2.5's
ky768_cv25519 kind exported armored, encrypted to and decrypted; an RFC
9980 key signing and encrypting) and `new_curves` (brainpoolP384r1, gpg's
Ed448, RFC 9580's Ed448 and X448, and gpg's default post-quantum key:
each made, signing and verifying, encrypting and decrypting through a
protected export). All run offline and check their results.

`python3 scripts/interop.py` runs goose-pgp against gpg both ways (it
skips when gpg is missing): signatures of every kind, encryption to each
kind of key, compression, armor, passphrases, and keys made by each side,
gpg's post-quantum Kyber keys and goose-pgp's (its secret key imported
into gpg, gpg's protected Kyber export read here), and the newer curves:
gpg's Brainpool keys, its Ed448 + cv448, its default `pqc` key and its
ky1024_bp384 and ky1024_cv448 kinds, and goose-pgp's Brainpool, Ed448 and
`pqc` keys (imported into gpg, secrets and all): signatures of every kind
and encryption both ways, gpg's secret exports read here (protected ones
for goose-pgp's keys).
It uses its own GNUPGHOME in a temp directory and stops its agent with
`gpgconf --kill gpg-agent` there.

`tools/pgp.goose` is goose-pgp: `sign`, `verify`, `encrypt`, `decrypt`,
`list-packets`, `list-keys`, `export`, `armor`, `dearmor` and `genkey`.
Passphrases come from a file (`--pass-file`). `genkey --type` makes
`ed25519` (the default), `rsa`, `brainpoolP256r1`, `brainpoolP384r1`,
`brainpoolP512r1`, `ed448` (gpg's v5 Ed448 + cv448), `ed448-v6` (RFC
9580's Ed448 + X448, which gpg does not read), `pqc` (gpg 2.5's default
post-quantum key: brainpoolP384r1 with ky768_bp256), `ky768_cv25519`
(Ed25519 with ky768_cv25519; what `pqc` made before gpg's default could be
made here) or `rfc9980` (ML-DSA-65+Ed25519 with ML-KEM-768+X25519, v6).
gpg imports all but `ed448-v6` and `rfc9980`, secrets and all.
