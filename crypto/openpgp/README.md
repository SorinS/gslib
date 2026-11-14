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
| `openpgp.key` | `Key`: one key packet (v4 and v6), its fingerprint and key ID, `unlock_key`, signing and verifying a digest, wrapping and unwrapping session keys |
| `openpgp.sig` | `Signature`: signature packets and subpackets, `verify_signature`, `make_signature` |
| `openpgp.keyring` | `Keyring`: transferable keys with their user IDs and subkeys checked, `add_keys`, `find_key`, `unlock`, `signing_key`, `encryption_key`, `export_public`, `export_secret` |
| `openpgp.message` | `sign`, `sign_detached`, `sign_cleartext`, `encrypt`; `read_message`, `decrypt`, `verify`, `verify_detached`, `verify_cleartext` |
| `openpgp.keygen` | `generate_key` (Ed25519 + Curve25519), `generate_rsa_key` |
| `openpgp.dump` | `list_packets`, in the manner of `gpg --list-packets` |

It builds on [bignum](../bignum) for the cryptography and on
[compress](../../compress) for ZIP, ZLIB and BZip2.
[mail.pgp](../../mail) uses it for PGP/MIME (RFC 3156).

```goose
import gslib from "SorinS/gslib@v0.1";   // or a path to gslib.git
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

Also read: RFC 9580's v6 keys (Ed25519, X25519), v6 signatures (salted),
X25519 PKESK v3, SEIPD v2 (OCB), Argon2 S2K, old-format headers and
partial body lengths, the cleartext framework with or without a `Hash:`
header. Written: v4 keys, PKESK v3, SKESK v4, SEIPD v1 with the MDC (which
every implementation reads, gpg included whatever the key advertises),
one-pass signed messages, v4 signatures (v6 for v6 keys).

| Public-key algorithm | |
|---|---|
| RSA (1, 2, 3), 1024 to 8192 bits | sign, verify, encrypt, decrypt (PKCS #1 v1.5) |
| EdDSALegacy (22) and Ed25519 (27) | sign, verify |
| ECDSA (19) on P-256, P-384, P-521 | sign, verify |
| ECDH (18) on Curve25519 and P-256, P-384, P-521 | encrypt, decrypt (RFC 6637 KDF, AES key wrap) |
| X25519 (25) | encrypt, decrypt (HKDF-SHA256, AES-128 key wrap) |
| DSA, ElGamal, X448, Ed448 | listed, fingerprinted; `ERR_UNSUPPORTED` when used |

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

A `Key` is fixed-size (its numbers are in bounded arrays sized for
RSA-8192), and a keyring refers to its keys by index. A subkey's `primary`
is its primary's index. `find_key` takes a fingerprint or key ID in hex,
or text from a user ID, and prefers a key whose secret is there.
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
ends), armor, and the literal's name and date.

Reading, `read_message` checks every signature it finds and puts the
results in `m.sigs`; `signature_status(m)` is OK when one verifies.
`verify` and `verify_detached` fail unless one does. A signature counts
when:
- it verifies, with a hash that is not MD5;
- its hashed area has no critical subpacket that is not known here;
- its key is in the keyring, bound by a valid self-signature, not
  revoked, not expired at the signature's time, and allowed to sign.

`verify_cleartext` reads the cleartext framework: dash escapes undone,
trailing white space dropped, a signature over a hash its `Hash:` header
leaves out refused.

## Encrypting and decrypting

`encrypt(kr, recipients, passphrase, data, out, opts, signer)` makes a
random session key (AES-256 by default), a PKESK v3 for each recipient's
encryption key and an SKESK v4 for the passphrase if one is given, and the
data in SEIPD v1: CFB with the MDC. With a signer, the data is signed
first, in the same message.

`read_message` tries each session key it can open: PKESKs with the
keyring's unlocked secret keys (wildcard key IDs too), SKESKs with
`ReadOptions.passphrase`. It then decrypts:
- SEIPD v1: the MDC is checked over all of it before anything is
  returned, so changed data is `ERR_INTEGRITY` with nothing out;
- LibrePGP's OCB packet and SEIPD v2: each chunk and the final tag
  checked;
- packet 9, which has no integrity protection: refused
  (`ERR_UNPROTECTED`) unless `allow_unprotected`, as gpg refuses it.

A wrong passphrase is told from changed data by the two repeated octets
of the prefix, as gpg does; with a public-key session key, whose own
checksum held, a mismatch there is changed data. Decompressed data and
literals are limited to `ReadOptions.max_size` (1 GiB); eight layers of
encryption and compression at most.

RSA decryption uses bignum's PKCS #1 v1.5 decoding, which is constant
time, but a failure is still reported: a server that decrypts messages
for anyone and says whether it worked is a padding oracle.

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

- v5 keys and LibrePGP's v5 signatures; v6 PKESK and SKESK, so nothing
  is written in SEIPD v2;
- EAX and GCM (read or written): gpg uses OCB;
- DSA and ElGamal operations, X448 and Ed448;
- revoking keys, certifying other keys, adding user IDs or subkeys to a
  key; key expiry when generating;
- the web of trust and trust signatures; keyserver and WKD lookups.

## Tests and tools

`python3 scripts/run_tests.py [-k NAME]` runs test/*.goose at -O0, -O2
and with --debug:
- `ocb`: RFC 7253's sixteen samples and its iterative test for AES-128,
  -192 and -256;
- `framing`: armor, CRC24, packet headers of every kind, partial lengths,
  MPIs, the cleartext text rules;
- `gpg_vectors`: what gpg wrote (test/vectors, from
  `scripts/gen_vectors.py`: test keys only, their passphrase in
  passphrase.txt), and RFC 9580 Appendix A's v4 and v6 samples;
- `roundtrip`: everything written here read back, and tampering refused;
- `malformed`: every vector truncated, changed and replaced by random
  bytes, through every reader, without a crash.

`python3 scripts/interop.py` runs goose-pgp against gpg both ways (it
skips when gpg is missing): signatures of every kind, encryption to each
kind of key, compression, armor, passphrases, and keys made by each side.
It uses its own GNUPGHOME in a temp directory and stops its agent with
`gpgconf --kill gpg-agent` there.

`tools/pgp.goose` is goose-pgp: `sign`, `verify`, `encrypt`, `decrypt`,
`list-packets`, `list-keys`, `export`, `armor`, `dearmor` and `genkey`.
Passphrases come from a file (`--pass-file`).
