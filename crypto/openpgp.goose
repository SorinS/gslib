// openpgp: OpenPGP (RFC 9580, and RFC 4880 as GnuPG still writes it) for
// the Goose language: keys, signatures and encryption, read and written as
// gpg reads and writes them.
//
//   openpgp             this module: errors, algorithm ids, MPIs, hashes,
//                       CFB and S2K (string-to-key)
//   openpgp.armor       ASCII armor with its CRC24, and the cleartext
//                       signature framework's text rules
//   openpgp.packet      packet framing: old and new headers, partial
//                       lengths; a packet lister (gpg --list-packets)
//   openpgp.ocb         AES-OCB (RFC 7253), for AEAD-encrypted data
//   openpgp.key         one key: its public and secret material,
//                       fingerprint and key ID, the raw operations
//   openpgp.sig         signature packets and their subpackets
//   openpgp.keyring     transferable keys: user IDs, subkeys, their
//                       self-signatures checked; unlocking; export
//   openpgp.message     signing, verifying, encrypting and decrypting
//                       messages: detached, inline and cleartext
//   openpgp.keygen      Ed25519 + Curve25519 (and RSA, Brainpool, Ed448)
//                       key generation, and post-quantum keys: gpg 2.5's
//                       Kyber, RFC 9980's
//   openpgp.pqc         the composite KEMs (RFC 9980's and LibrePGP's),
//                       gpg-agent's S-expressions and their protection
//   openpgp.dump        a packet listing, as gpg --list-packets
//
// All of it is in namespace openpgp. Every fallible function returns one of
// the ERR_* codes below (OK, 0, for success).

namespace openpgp;

import std;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.aes;
import crypto.bignum.cast5;
import crypto.bignum.des;
import crypto.bignum.twofish;
import crypto.bignum.camellia;
import crypto.bignum.blowfish;
import crypto.bignum.modes;
import crypto.bignum.sha1;
import crypto.bignum.sha256;
import crypto.bignum.sha512;
import crypto.bignum.sha3;
import crypto.bignum.ripemd160;
import crypto.bignum.hmac;
import crypto.bignum.kdf;
import crypto.bignum.argon2;
import crypto.bignum.ec;
import entropy;

// --- Errors -------------------------------------------------------------------

let OK:                i64 = 0;
let ERR_MALFORMED:     i64 = 1;      // not OpenPGP: bad framing, armor, MPIs or lengths, truncated input
let ERR_UNSUPPORTED:   i64 = 2;      // a version, algorithm, curve or packet this package does not do
let ERR_BAD_SIGNATURE: i64 = 3;      // a signature that does not verify
let ERR_NO_KEY:        i64 = 4;      // no key of the keyring fits the signature or the encrypted message
let ERR_KEY:           i64 = 5;      // a key unfit for the job: no secret, locked, the wrong usage
let ERR_PASSPHRASE:    i64 = 6;      // the passphrase does not unlock the key or the message
let ERR_DECRYPT:       i64 = 7;      // the session key does not decrypt (bad padding or checksum)
let ERR_INTEGRITY:     i64 = 8;      // the MDC or an AEAD tag does not match: the data was changed
let ERR_CHECKSUM:      i64 = 9;      // the armor's CRC24 does not match
let ERR_LIMIT:         i64 = 10;     // nesting, packet count or decompressed size over its limit
let ERR_EXPIRED:       i64 = 11;     // the key or signature expired before the signature was made
let ERR_REVOKED:       i64 = 12;     // the key is revoked
let ERR_NO_SIGNATURE:  i64 = 13;     // the message carries no signature
let ERR_UNPROTECTED:   i64 = 14;     // encrypted data without integrity protection (no MDC), refused
let ERR_NOT_ENCRYPTED: i64 = 15;     // decryption of a message that is not encrypted, when asked to require it

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_MALFORMED { return "openpgp: malformed input"; }
    if e == ERR_UNSUPPORTED { return "openpgp: unsupported version, algorithm or packet"; }
    if e == ERR_BAD_SIGNATURE { return "openpgp: signature verification failed"; }
    if e == ERR_NO_KEY { return "openpgp: no key matches"; }
    if e == ERR_KEY { return "openpgp: the key cannot be used for this"; }
    if e == ERR_PASSPHRASE { return "openpgp: wrong passphrase"; }
    if e == ERR_DECRYPT { return "openpgp: decryption failed"; }
    if e == ERR_INTEGRITY { return "openpgp: integrity check failed: the data was modified"; }
    if e == ERR_CHECKSUM { return "openpgp: armor checksum mismatch"; }
    if e == ERR_LIMIT { return "openpgp: a limit was exceeded"; }
    if e == ERR_EXPIRED { return "openpgp: key or signature expired"; }
    if e == ERR_REVOKED { return "openpgp: key revoked"; }
    if e == ERR_NO_SIGNATURE { return "openpgp: the message is not signed"; }
    if e == ERR_UNPROTECTED { return "openpgp: encrypted data without integrity protection"; }
    if e == ERR_NOT_ENCRYPTED { return "openpgp: the message is not encrypted"; }
    return "openpgp: unknown error";
}

// --- Algorithm ids (RFC 9580 §9) -------------------------------------------------

// Public-key algorithms.
let PK_RSA:     i64 = 1;
let PK_RSA_E:   i64 = 2;             // encrypt-only, read as RSA
let PK_RSA_S:   i64 = 3;             // sign-only, read as RSA
let PK_ELGAMAL: i64 = 16;
let PK_DSA:     i64 = 17;
let PK_ECDH:    i64 = 18;
let PK_ECDSA:   i64 = 19;
let PK_EDDSA:   i64 = 22;            // EdDSALegacy: Ed25519 under its legacy OID
let PK_X25519:  i64 = 25;
let PK_X448:    i64 = 26;
let PK_ED25519: i64 = 27;
let PK_ED448:   i64 = 28;

// Post-quantum (RFC 9980): composite ML-DSA + EdDSA signatures and
// ML-KEM + ECDH encryption, on v6 keys (35 on v4 subkeys too).
let PK_MLDSA65_ED25519: i64 = 30;
let PK_MLDSA87_ED448:   i64 = 31;
let PK_SLHDSA_128S:     i64 = 32;
let PK_SLHDSA_128F:     i64 = 33;
let PK_SLHDSA_256S:     i64 = 34;
let PK_MLKEM768_X25519: i64 = 35;
let PK_MLKEM1024_X448:  i64 = 36;
// LibrePGP's composite Kyber (ML-KEM) + ECDH, on v5 subkeys: what gpg 2.5
// makes ("ky768_cv25519"). gpg's own headers give 35 and 36 to Dilithium,
// so its keys and RFC 9980's do not mix.
let PK_KYBER: i64 = 8;

// Symmetric ciphers.
let CIPHER_PLAIN:       i64 = 0;
let CIPHER_IDEA:        i64 = 1;
let CIPHER_3DES:        i64 = 2;
let CIPHER_CAST5:       i64 = 3;
let CIPHER_BLOWFISH:    i64 = 4;
let CIPHER_AES128:      i64 = 7;
let CIPHER_AES192:      i64 = 8;
let CIPHER_AES256:      i64 = 9;
let CIPHER_TWOFISH:     i64 = 10;
let CIPHER_CAMELLIA128: i64 = 11;
let CIPHER_CAMELLIA192: i64 = 12;
let CIPHER_CAMELLIA256: i64 = 13;

// Hashes.
let HASH_MD5:       i64 = 1;
let HASH_SHA1:      i64 = 2;
let HASH_RIPEMD160: i64 = 3;
let HASH_SHA256:    i64 = 8;
let HASH_SHA384:    i64 = 9;
let HASH_SHA512:    i64 = 10;
let HASH_SHA224:    i64 = 11;
let HASH_SHA3_256:  i64 = 12;
let HASH_SHA3_512:  i64 = 14;

// Compression.
let COMP_NONE:  i64 = 0;
let COMP_ZIP:   i64 = 1;             // raw DEFLATE
let COMP_ZLIB:  i64 = 2;
let COMP_BZIP2: i64 = 3;

// AEAD modes.
let AEAD_EAX: i64 = 1;
let AEAD_OCB: i64 = 2;
let AEAD_GCM: i64 = 3;

// Curves of ECDH, ECDSA and EdDSALegacy keys, by OID.
let CURVE_NONE:    i64 = 0;
let CURVE_ED25519: i64 = 1;          // 1.3.6.1.4.1.11591.15.1, EdDSALegacy
let CURVE_X25519:  i64 = 2;          // 1.3.6.1.4.1.3029.1.5.1, legacy Curve25519 ECDH
let CURVE_P256:    i64 = 3;
let CURVE_P384:    i64 = 4;
let CURVE_P521:    i64 = 5;
let CURVE_BP256:   i64 = 6;          // brainpoolP256r1 (RFC 5639), 1.3.36.3.3.2.8.1.1.7
let CURVE_BP384:   i64 = 7;          // brainpoolP384r1, 1.3.36.3.3.2.8.1.1.11
let CURVE_BP512:   i64 = 8;          // brainpoolP512r1, 1.3.36.3.3.2.8.1.1.13
let CURVE_ED448:   i64 = 9;          // 1.3.101.113: gpg's Ed448 under EdDSALegacy
let CURVE_X448:    i64 = 10;         // 1.3.101.111: gpg's cv448 ECDH

let OID_ED25519: const u8[:] = "\x2b\x06\x01\x04\x01\xda\x47\x0f\x01";
let OID_X25519:  const u8[:] = "\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01";
let OID_P256:    const u8[:] = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
let OID_P384:    const u8[:] = "\x2b\x81\x04\x00\x22";
let OID_P521:    const u8[:] = "\x2b\x81\x04\x00\x23";
let OID_ED448:   const u8[:] = "\x2b\x65\x71";
// RFC 8410's X25519 and X448 (1.3.101.110, .111): gpg puts both in its
// Kyber keys, and X448 in its cv448 ECDH keys.
let OID_X25519_RFC8410: const u8[:] = "\x2b\x65\x6e";
let OID_X448_RFC8410:   const u8[:] = "\x2b\x65\x6f";
let OID_BP256:          const u8[:] = "\x2b\x24\x03\x03\x02\x08\x01\x01\x07";
let OID_BP384:          const u8[:] = "\x2b\x24\x03\x03\x02\x08\x01\x01\x0b";
let OID_BP512:          const u8[:] = "\x2b\x24\x03\x03\x02\x08\x01\x01\x0d";

fn curve_of_oid(oid: const u8[:]) -> i64 {
    if oid == OID_ED25519 { return CURVE_ED25519; }
    if oid == OID_X25519 { return CURVE_X25519; }
    if oid == OID_P256 { return CURVE_P256; }
    if oid == OID_P384 { return CURVE_P384; }
    if oid == OID_P521 { return CURVE_P521; }
    if oid == OID_BP256 { return CURVE_BP256; }
    if oid == OID_BP384 { return CURVE_BP384; }
    if oid == OID_BP512 { return CURVE_BP512; }
    if oid == OID_ED448 { return CURVE_ED448; }
    if oid == OID_X448_RFC8410 { return CURVE_X448; }
    return CURVE_NONE;
}

fn oid_of_curve(c: i64) -> const u8[:] {
    if c == CURVE_ED25519 { return OID_ED25519; }
    if c == CURVE_X25519 { return OID_X25519; }
    if c == CURVE_P256 { return OID_P256; }
    if c == CURVE_P384 { return OID_P384; }
    if c == CURVE_P521 { return OID_P521; }
    if c == CURVE_BP256 { return OID_BP256; }
    if c == CURVE_BP384 { return OID_BP384; }
    if c == CURVE_BP512 { return OID_BP512; }
    if c == CURVE_ED448 { return OID_ED448; }
    if c == CURVE_X448 { return OID_X448_RFC8410; }
    return "";
}

// The bytes of a curve's scalars and field elements (the 448 curves': their
// native secrets, 57 octets for Ed448's seed and 56 for X448's).
fn curve_size(c: i64) -> i64 {
    if c == CURVE_P256 || c == CURVE_BP256 { return 32; }
    if c == CURVE_P384 || c == CURVE_BP384 { return 48; }
    if c == CURVE_P521 { return 66; }
    if c == CURVE_BP512 { return 64; }
    if c == CURVE_ED448 { return 57; }
    if c == CURVE_X448 { return 56; }
    return 32;
}

// The short Weierstrass curves (NIST and Brainpool): points 04 || x || y,
// scalars big-endian, ECDSA and RFC 6637 ECDH over bignum.ec.
fn is_weierstrass(c: i64) -> bool {
    c == CURVE_P256 || c == CURVE_P384 || c == CURVE_P521 || c == CURVE_BP256 || c == CURVE_BP384 || c == CURVE_BP512
}

fn weierstrass_curve(c: i64) -> bignum::Curve {
    if c == CURVE_P256 { return bignum::p256(); }
    if c == CURVE_P384 { return bignum::p384(); }
    if c == CURVE_BP256 { return bignum::bp256(); }
    if c == CURVE_BP384 { return bignum::bp384(); }
    if c == CURVE_BP512 { return bignum::bp512(); }
    return bignum::p521();
}

// --- Bytes ---------------------------------------------------------------------

fn be16(p: const u8[:], at: i64) -> i64 { (p[at] as i64) << 8 | p[at + 1] }
fn be32(p: const u8[:], at: i64) -> i64 {
    (p[at] as i64) << 24 | (p[at + 1] as i64) << 16 | (p[at + 2] as i64) << 8 | p[at + 3]
}

fn put16(out: u8[>..]&, v: i64) { out.push((v >> 8 & 255) as! u8); out.push((v & 255) as! u8); }
fn put32(out: u8[>..]&, v: i64) {
    out.push((v >> 24 & 255) as! u8);
    out.push((v >> 16 & 255) as! u8);
    out.push((v >> 8 & 255) as! u8);
    out.push((v & 255) as! u8);
}
fn put64(out: u8[>..]&, v: i64) { put32(out, v >> 32 & 0xffffffff); put32(out, v & 0xffffffff); }

let HEX_UPPER: const u8[:] = "0123456789ABCDEF";
let HEX_LOWER: const u8[:] = "0123456789abcdef";

fn hex_append(out: u8[>..]&, b: const u8[:], upper: bool = true) {
    let d = if upper { HEX_UPPER } else { HEX_LOWER };
    for x in b { out.push(d[(x >> 4) as i64]); out.push(d[(x & 15) as i64]); }
}

fn hex(b: const u8[:], upper: bool = true) -> u8[>..] {
    var out: u8[>..] = [];
    hex_append(out, b, upper);
    return out;
}

fn hex_value(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

// Hex text (spaces ignored) as bytes; false on anything else or an odd count.
fn unhex(s: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var hi:  i64     = -1;
    for c in s {
        if c == ' ' { continue; }
        let v = hex_value(c);
        if v < 0 { out.clear(); return out, false; }
        if hi < 0 { hi = v; } else { out.push((hi << 4 | v) as! u8); hi = -1; }
    }
    if hi >= 0 { out.clear(); return out, false; }
    return out, true;
}

// The bytes of s without leading zero bytes.
fn strip_zeros(s: const u8[:]) -> const u8[:] {
    var i = 0;
    while i < s.len && s[i] == 0 { i++; }
    return s[i..];
}

// s left-padded with zeros to n bytes (s no longer than n) into out.
fn pad_left(out: u8[>..]&, s: const u8[:], n: i64) {
    for i in n - s.len { out.push(0); }
    out.append(s);
}

fn reversed(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = s.len;
    while i > 0 { i--; out.push(s[i]); }
    return out;
}

fn random(n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.resize(n, 0);
    entropy::random_bytes(out);
    return out;
}

// --- MPIs (RFC 9580 §3.2) -----------------------------------------------------------

// The MPI at data[at..]: where its value starts and ends, and the position
// after it. A bit count that overstates the leading byte is accepted (gpg
// writes 263 bits for 0x40-prefixed points), one past the data is not.
fn read_mpi(data: const u8[:], at: i64) -> i64, i64, i64, bool {
    if at < 0 || at + 2 > data.len { return 0, 0, 0, false; }
    let bits = be16(data, at);
    let n = (bits + 7) / 8;
    if at + 2 + n > data.len { return 0, 0, 0, false; }
    return at + 2, at + 2 + n, at + 2 + n, true;
}

// An MPI of the big-endian number v (leading zeros dropped).
fn put_mpi(out: u8[>..]&, v: const u8[:]) {
    let s = strip_zeros(v);
    var bits: i64 = 0;
    if s.len > 0 { bits = 8 * (s.len - 1) + 64 - ::clz(s[0]); }
    put16(out, bits);
    out.append(s);
}

// gpg's SOS (string of octets in MPI framing): every byte written, the bit
// count from the first one when it is not zero (8 per byte when it is), as
// gpg's sos_write does. A fixed-size value keeps its size.
fn put_sos(out: u8[>..]&, v: const u8[:]) {
    var bits: i64 = 8 * v.len;
    if v.len > 0 && v[0] != 0 { bits = 8 * (v.len - 1) + 64 - ::clz(v[0]); }
    put16(out, bits);
    out.append(v);
}

// --- Hashes ----------------------------------------------------------------------

// bignum.hmac's id for an OpenPGP hash, or 0 (RIPEMD-160 has none: -1).
fn hash_bits(algo: i64) -> i64 {
    if algo == HASH_MD5 { return 128; }
    if algo == HASH_SHA1 { return 160; }
    if algo == HASH_SHA256 { return 256; }
    if algo == HASH_SHA384 { return 384; }
    if algo == HASH_SHA512 { return 512; }
    if algo == HASH_SHA224 { return 224; }
    if algo == HASH_SHA3_256 { return bignum::HASH_SHA3_256; }
    if algo == HASH_SHA3_512 { return bignum::HASH_SHA3_512; }
    if algo == HASH_RIPEMD160 { return -1; }
    return 0;
}

fn hash_size(algo: i64) -> i64 {
    if algo == HASH_MD5 { return 16; }
    if algo == HASH_SHA1 || algo == HASH_RIPEMD160 { return 20; }
    if algo == HASH_SHA224 { return 28; }
    if algo == HASH_SHA256 || algo == HASH_SHA3_256 { return 32; }
    if algo == HASH_SHA384 { return 48; }
    if algo == HASH_SHA512 || algo == HASH_SHA3_512 { return 64; }
    return 0;
}

fn hash_known(algo: i64) -> bool { hash_bits(algo) != 0 }

// Hashes signatures may use: not MD5 (RFC 9580 §9.5); SHA-1 and RIPEMD-160
// only to verify old signatures.
fn hash_ok_for_signing(algo: i64) -> bool {
    algo == HASH_SHA256 || algo == HASH_SHA384 || algo == HASH_SHA512 || algo == HASH_SHA224
        || algo == HASH_SHA3_256 || algo == HASH_SHA3_512
}

fn hash_name(algo: i64) -> const u8[:] {
    if algo == HASH_MD5 { return "MD5"; }
    if algo == HASH_SHA1 { return "SHA1"; }
    if algo == HASH_RIPEMD160 { return "RIPEMD160"; }
    if algo == HASH_SHA256 { return "SHA256"; }
    if algo == HASH_SHA384 { return "SHA384"; }
    if algo == HASH_SHA512 { return "SHA512"; }
    if algo == HASH_SHA224 { return "SHA224"; }
    if algo == HASH_SHA3_256 { return "SHA3-256"; }
    if algo == HASH_SHA3_512 { return "SHA3-512"; }
    return "";
}

// The hash of a "Hash:" armor header's name, or 0.
fn hash_of_name(name: const u8[:]) -> i64 {
    for a in [HASH_MD5, HASH_SHA1, HASH_RIPEMD160, HASH_SHA256, HASH_SHA384, HASH_SHA512,
              HASH_SHA224, HASH_SHA3_256, HASH_SHA3_512] {
        if name == hash_name(a) { return a; }
    }
    return 0;
}

// The hash of a || b || c by an OpenPGP hash id (hash_known).
fn digest3(algo: i64, a: const u8[:], b: const u8[:], c: const u8[:]) -> u8[>..] {
    let bits = hash_bits(algo);
    assert(bits != 0);
    var out: u8[>..] = [];
    if bits == -1 {
        var s = bignum::ripemd160_init();
        bignum::ripemd160_update(s, a);
        bignum::ripemd160_update(s, b);
        bignum::ripemd160_update(s, c);
        out.append(bignum::ripemd160_final(s));
    } else if bits == 160 {
        var s = bignum::sha1_init();
        bignum::sha1_update(s, a);
        bignum::sha1_update(s, b);
        bignum::sha1_update(s, c);
        out.append(bignum::sha1_final(s));
    } else if bits == 256 || bits == 224 {
        var s = if bits == 256 { bignum::sha256_init() } else { bignum::sha224_init() };
        bignum::sha256_update(s, a);
        bignum::sha256_update(s, b);
        bignum::sha256_update(s, c);
        if bits == 256 { out.append(bignum::sha256_final(s)); } else { out.append(bignum::sha224_final(s)); }
    } else if bits == 384 || bits == 512 {
        var s = if bits == 384 { bignum::sha384_init() } else { bignum::sha512_init() };
        bignum::sha512_update(s, a);
        bignum::sha512_update(s, b);
        bignum::sha512_update(s, c);
        out = bignum::sha512_final(s);
    } else if bits == 128 {
        var buf: u8[>..] = [];
        buf.append(a);
        buf.append(b);
        buf.append(c);
        out = bignum::hash_bits(128, buf);
    } else {
        var s = bignum::sha3_init(bits - 3000);
        bignum::sha3_update(s, a);
        bignum::sha3_update(s, b);
        bignum::sha3_update(s, c);
        out = bignum::sha3_final(s);
    }
    return out;
}

fn digest(algo: i64, a: const u8[:]) -> u8[>..] { digest3(algo, a, "", "") }

// --- Symmetric ciphers ------------------------------------------------------------

fn cipher_key_size(algo: i64) -> i64 {
    if algo == CIPHER_3DES { return 24; }
    if algo == CIPHER_CAST5 || algo == CIPHER_BLOWFISH { return 16; }
    if algo == CIPHER_AES128 || algo == CIPHER_CAMELLIA128 { return 16; }
    if algo == CIPHER_AES192 || algo == CIPHER_CAMELLIA192 { return 24; }
    if algo == CIPHER_AES256 || algo == CIPHER_TWOFISH || algo == CIPHER_CAMELLIA256 { return 32; }
    return 0;
}

fn cipher_block_size(algo: i64) -> i64 {
    if algo == CIPHER_3DES || algo == CIPHER_CAST5 || algo == CIPHER_BLOWFISH { return 8; }
    if cipher_key_size(algo) != 0 { return 16; }
    return 0;
}

fn cipher_known(algo: i64) -> bool { cipher_key_size(algo) != 0 }

fn is_aes(algo: i64) -> bool { algo == CIPHER_AES128 || algo == CIPHER_AES192 || algo == CIPHER_AES256 }

fn cipher_name(algo: i64) -> const u8[:] {
    if algo == CIPHER_3DES { return "3DES"; }
    if algo == CIPHER_CAST5 { return "CAST5"; }
    if algo == CIPHER_BLOWFISH { return "BLOWFISH"; }
    if algo == CIPHER_AES128 { return "AES128"; }
    if algo == CIPHER_AES192 { return "AES192"; }
    if algo == CIPHER_AES256 { return "AES256"; }
    if algo == CIPHER_TWOFISH { return "TWOFISH"; }
    if algo == CIPHER_CAMELLIA128 { return "CAMELLIA128"; }
    if algo == CIPHER_CAMELLIA192 { return "CAMELLIA192"; }
    if algo == CIPHER_CAMELLIA256 { return "CAMELLIA256"; }
    return "";
}

// CFB with whole-block segments, in place, from iv (one block): what the
// secret-key protection and SEIPD v1 use. False for an unknown cipher or
// a key or IV of the wrong size.
fn cfb(algo: i64, key: const u8[:], iv: const u8[:], data: u8[:], decrypt: bool) -> bool {
    if !cipher_known(algo) || key.len != cipher_key_size(algo) || iv.len != cipher_block_size(algo) { return false; }
    if is_aes(algo) {
        let k = bignum::aes_init(key);
        bignum::cfb_crypt(k, iv, data, decrypt);
    } else if algo == CIPHER_CAST5 {
        let k = bignum::cast5_init(key);
        bignum::cfb_crypt(k, iv, data, decrypt);
    } else if algo == CIPHER_3DES {
        let k = bignum::des3_init(key);
        bignum::cfb_crypt(k, iv, data, decrypt);
    } else if algo == CIPHER_BLOWFISH {
        let k = bignum::blowfish_init(key);
        bignum::cfb_crypt(k, iv, data, decrypt);
    } else if algo == CIPHER_TWOFISH {
        let k = bignum::twofish_init(key);
        bignum::cfb_crypt(k, iv, data, decrypt);
    } else {
        let k = bignum::camellia_init(key);
        bignum::cfb_crypt(k, iv, data, decrypt);
    }
    return true;
}

// --- S2K (RFC 9580 §3.7) -------------------------------------------------------------

let S2K_SIMPLE:    i64 = 0;
let S2K_SALTED:    i64 = 1;
let S2K_ITERATED:  i64 = 3;
let S2K_ARGON2:    i64 = 4;
let S2K_GNU_DUMMY: i64 = 101;        // GnuPG's "gnu-dummy": no secret here (a stub)

struct S2k {
    kind:  i64      = S2K_ITERATED,
    hash:  i64      = HASH_SHA256,
    salt:  u8[..16] = [],
    count: i64      = 65011712,      // octets hashed: the coded count 255
    coded: i64      = 255,
    t:     i64      = 0, p: i64 = 0, m: i64 = 0, // Argon2: passes, parallelism, log2 of memory KiB
}

// The octet count of an iterated S2K's coded count.
fn s2k_count(c: i64) -> i64 { (16 + (c & 15)) << ((c >> 4) + 6) }

// The S2K specifier at data[at..], and the position after it.
fn read_s2k(data: const u8[:], at: i64) -> S2k, i64, i64 {
    var s = S2k { .. };
    if at >= data.len { return s, at, ERR_MALFORMED; }
    s.kind = data[at];
    var p = at + 1;
    if s.kind == S2K_SIMPLE || s.kind == S2K_SALTED || s.kind == S2K_ITERATED {
        if p >= data.len { return s, p, ERR_MALFORMED; }
        s.hash = data[p];
        p++;
        if s.kind != S2K_SIMPLE {
            if p + 8 > data.len { return s, p, ERR_MALFORMED; }
            s.salt.append(data[p..p + 8]);
            p += 8;
        }
        if s.kind == S2K_ITERATED {
            if p >= data.len { return s, p, ERR_MALFORMED; }
            s.coded = data[p];
            s.count = s2k_count(s.coded);
            p++;
        }
        if !hash_known(s.hash) { return s, p, ERR_UNSUPPORTED; }
        return s, p, OK;
    }
    if s.kind == S2K_ARGON2 {
        if p + 19 > data.len { return s, p, ERR_MALFORMED; }
        s.salt.append(data[p..p + 16]);
        s.t = data[p + 16];
        s.p = data[p + 17];
        s.m = data[p + 18];
        p += 19;
        // RFC 9580 §3.7.1.4: m at least 8p KiB. Past 2^21 KiB (2 GiB, the
        // RFC's first choice), 16 lanes, or more work than that choice (t
        // passes over 2^m KiB: 2^21 KiB-passes, the RFC's second choice of
        // 3 passes over 64 MiB well within it), ERR_LIMIT: whoever sends a
        // message chooses these.
        if s.t < 1 || s.p < 1 || s.m > 31 || (1 << s.m) < 8 * s.p { return s, p, ERR_MALFORMED; }
        if s.m > 21 || s.p > 16 || s.t > 64 || s.t * (1 << s.m) > 1 << 21 { return s, p, ERR_LIMIT; }
        return s, p, OK;
    }
    if s.kind == S2K_GNU_DUMMY {
        // hash, then "GNU" and the mode (1: no secret; 2: on a card).
        if p + 5 > data.len || data[p + 1..p + 4] != "GNU" { return s, p, ERR_MALFORMED; }
        s.hash = data[p];
        s.coded = data[p + 4];
        p += 5;
        if s.coded == 2 && p < data.len { p += 1 + data[p]; }
        return s, ::min(p, data.len), OK;
    }
    return s, p, ERR_UNSUPPORTED;
}

fn put_s2k(out: u8[>..]&, s: const S2k&) {
    out.push(s.kind as! u8);
    if s.kind == S2K_ARGON2 {
        out.append(s.salt);
        out.push(s.t as! u8);
        out.push(s.p as! u8);
        out.push(s.m as! u8);
        return;
    }
    out.push(s.hash as! u8);
    if s.kind != S2K_SIMPLE { out.append(s.salt); }
    if s.kind == S2K_ITERATED { out.push(s.coded as! u8); }
}

// A fresh iterated and salted S2K over SHA-256 with gpg's default count
// (coded 255 unless coded says otherwise).
fn new_s2k(coded: i64 = 255) -> S2k {
    var s = S2k { .. };
    s.salt.append(random(8));
    s.coded = coded;
    s.count = s2k_count(coded);
    return s;
}

// One iterated S2K hash context, preloaded with `zeros` zero octets: count
// octets of salt || pass repeated (at least one whole copy).
fn s2k_run(s0, bits: i64, zeros: i64, unit: const u8[:], count: i64, out: u8[:]) {
    var s = s0;
    var z: u8[64] = [0; 64];
    if zeros > 0 { bignum::kdf_update(s, z[..zeros]); }
    var total = ::max(count, unit.len);
    if unit.len == 0 { total = 0; }
    // A block of whole copies, hashed as many times as it fits, then the
    // prefix of it that is left: the copies start on the block's edges.
    var run: u8[>..] = [];
    while run.len < 8192 && unit.len > 0 { run.append(unit); }
    while total >= run.len && run.len > 0 {
        bignum::kdf_update(s, run);
        total -= run.len;
    }
    if total > 0 { bignum::kdf_update(s, run[..total]); }
    bignum::kdf_final(s, bits, out);
}

// The key of `size` octets an S2K makes of a passphrase.
fn s2k_key(s: const S2k&, pass: const u8[:], size: i64) -> u8[>..], i64 {
    var key: u8[>..] = [];
    if s.kind == S2K_ARGON2 {
        key = bignum::argon2id_key(pass, s.salt, s.t, 1 << s.m, s.p, size);
        return key, OK;
    }
    if s.kind != S2K_SIMPLE && s.kind != S2K_SALTED && s.kind != S2K_ITERATED { return key, ERR_UNSUPPORTED; }
    let hl = hash_size(s.hash);
    let bits = hash_bits(s.hash);
    if hl == 0 || bits <= 0 || bits == 128 { return key, ERR_UNSUPPORTED; }
    var unit: u8[>..] = [];
    unit.append(s.salt);
    unit.append(pass);
    let count = if s.kind == S2K_ITERATED { s.count } else { unit.len };
    var h: u8[64] = [0; 64];
    var zeros = 0;
    while key.len < size {
        if bits == 160 { s2k_run(bignum::sha1_init(), bits, zeros, unit, count, h); }
        else if bits == 256 { s2k_run(bignum::sha256_init(), bits, zeros, unit, count, h); }
        else if bits == 224 { s2k_run(bignum::sha224_init(), bits, zeros, unit, count, h); }
        else if bits == 384 { s2k_run(bignum::sha384_init(), bits, zeros, unit, count, h); }
        else if bits == 512 { s2k_run(bignum::sha512_init(), bits, zeros, unit, count, h); }
        else { s2k_run(bignum::sha3_init(bits - 3000), bits, zeros, unit, count, h); }
        key.append(h[.. ::min(hl, size - key.len)]);
        zeros++;
    }
    return key, OK;
}
