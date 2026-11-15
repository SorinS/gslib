// openpgp.key: one key (RFC 9580 §5.5): a public or secret key or subkey
// packet, version 4, 5 (LibrePGP) or 6; its fingerprint and key ID;
// unlocking a secret key that a passphrase protects; and the operations of
// its algorithm: signing and verifying a digest, wrapping and unwrapping a
// session key.
//
//   RSA (1, 2, 3)          PKCS #1 v1.5 signatures and encryption
//   EdDSALegacy (22)       Ed25519 under its legacy OID, as gpg writes it,
//                          and Ed448 (OID 1.3.101.113, gpg's v5 keys)
//   Ed25519 (27), Ed448 (28)  RFC 9580's own
//   ECDH (18)              Curve25519 (legacy OID), X448 (1.3.101.111, gpg's
//                          cv448), P-256/384/521 and brainpoolP256r1/
//                          P384r1/P512r1: the RFC 6637 KDF and AES key wrap
//   X25519 (25)            RFC 9580's: HKDF-SHA256 and AES-128 key wrap
//   X448 (26)              RFC 9580's: HKDF-SHA512 and AES-256 key wrap
//   ECDSA (19)             P-256, P-384, P-521, brainpoolP256r1/P384r1/P512r1
//   ML-KEM-768+X25519 (35) RFC 9980's composite KEM (v4 and v6 keys)
//   ML-DSA-65+Ed25519 (30) RFC 9980's composite signature (v6 keys)
//   Kyber (8)              LibrePGP's ML-KEM-768 or -1024 with X25519, X448
//                          or a Weierstrass curve, on gpg's v5 subkeys
//                          ("ky768_cv25519", "ky768_bp256", ...); see
//                          openpgp.pqc
//
// The 448 curves' keys are native octets (no 0x40 prefix, X448's secret
// little-endian), as gpg writes them. DSA, ElGamal, ML-KEM-1024+X448,
// ML-DSA-87+Ed448 and SLH-DSA parse (their keys list and fingerprint) but
// fail with ERR_UNSUPPORTED when used.
//
// A Key is fixed-size, so a keyring can hold an array of them: its numbers
// are in bounded arrays sized for RSA-8192, its public key packet for
// ML-DSA-87+Ed448. A post-quantum public key stays in the body (pq_at,
// pq_len); its secret, a seed (or gpg's expanded ML-KEM key), in pq_sec.

namespace openpgp;

import std;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.ed25519;
import crypto.bignum.x25519;
import crypto.bignum.x448;
import crypto.bignum.ed448;
import crypto.bignum.keywrap;
import crypto.bignum.hmac;
import crypto.bignum.sha1;
import crypto.bignum.mlkem;
import crypto.bignum.mldsa;
import crypto.openpgp;
import crypto.openpgp.packet;
import crypto.openpgp.ocb;
import crypto.openpgp.pqc;

// Key flags (§5.2.3.29), as bits of Key.flags.
let FLAG_CERTIFY:         u32 = 0x01;
let FLAG_SIGN:            u32 = 0x02;
let FLAG_ENCRYPT_COMMS:   u32 = 0x04;
let FLAG_ENCRYPT_STORAGE: u32 = 0x08;
let FLAG_AUTH:            u32 = 0x20;
let FLAG_ENCRYPT:         u32 = 0x0C;

struct Key {
    version: i64        = 0,         // 4, 5 or 6
    algo:    i64        = 0,
    created: i64        = 0,         // seconds since 1970
    subkey:  bool       = false,
    body:    u8[..2700] = [],        // the public key packet's body, as hashed and exported
    fpr:     u8[..32]   = [],        // 20 bytes (v4) or 32 (v5, v6)
    keyid:   u8[8]      = [0; 8],
    // Public material.
    curve:    i64        = CURVE_NONE,
    n:        u8[..1024] = [], e: u8[..8] = [],  // RSA
    point:    u8[..133]  = [],       // EC: 32 bytes for the 25519 keys (no 0x40), 56/57 for 448, else 04 || x || y
    kdf_hash: i64        = 0, kdf_cipher: i64 = 0, // ECDH
    pq_at:    i64        = 0, pq_len: i64 = 0,     // the ML-KEM or ML-DSA public key, in body
    // Secret material.
    has_secret: bool       = false,  // a secret key packet, its material maybe still locked
    locked:     bool       = false,  // protected by a passphrase and not yet unlocked
    stub:       bool       = false,  // gpg's gnu-dummy: no secret here at all
    sexp:       bool       = false,  // gpg's mode 1003: the secret is the agent's S-expression
    sec_raw:    u8[..6144] = [],     // what followed the public part in the secret packet (gpg's ky1024: 4.9K)
    d:          u8[..1024] = [], p: u8[..512] = [], q: u8[..512] = [], u: u8[..512] = [], // RSA
    scalar:     u8[..66]   = [],     // EC: the seed (EdDSA), little-endian scalar (X25519, X448), or big-endian scalar
    pq_sec:     u8[..3168] = [],     // the ML-KEM seed d || z (or gpg's expanded key), the ML-DSA seed
    // Set by the keyring.
    primary:   i64  = -1,            // the index of this key's primary in the keyring
    flags:     u32  = 0,
    has_flags: bool = false,
    expires:   i64  = 0,             // seconds after creation; 0 never
    revoked:   bool = false,
    valid:     bool = false,         // a primary with a valid self-signature, a subkey with a valid binding
    bound_at:  i64  = 0,             // the creation time of the binding that counts
    bound_primary: bool = false,     // that binding is a primary user ID's self-signature
}

fn is_rsa(algo: i64) -> bool { algo == PK_RSA || algo == PK_RSA_E || algo == PK_RSA_S }

fn algo_name(algo: i64) -> const u8[:] {
    if is_rsa(algo) { return "RSA"; }
    if algo == PK_ELGAMAL { return "ElGamal"; }
    if algo == PK_DSA { return "DSA"; }
    if algo == PK_ECDH { return "ECDH"; }
    if algo == PK_ECDSA { return "ECDSA"; }
    if algo == PK_EDDSA { return "EdDSA"; }
    if algo == PK_X25519 { return "X25519"; }
    if algo == PK_X448 { return "X448"; }
    if algo == PK_ED25519 { return "Ed25519"; }
    if algo == PK_ED448 { return "Ed448"; }
    if algo == PK_KYBER { return "Kyber"; }
    if algo == PK_MLDSA65_ED25519 { return "ML-DSA-65+Ed25519"; }
    if algo == PK_MLDSA87_ED448 { return "ML-DSA-87+Ed448"; }
    if algo == PK_SLHDSA_128S { return "SLH-DSA-SHAKE-128s"; }
    if algo == PK_SLHDSA_128F { return "SLH-DSA-SHAKE-128f"; }
    if algo == PK_SLHDSA_256S { return "SLH-DSA-SHAKE-256s"; }
    if algo == PK_MLKEM768_X25519 { return "ML-KEM-768+X25519"; }
    if algo == PK_MLKEM1024_X448 { return "ML-KEM-1024+X448"; }
    return "unknown";
}

// The post-quantum public key of k (ML-KEM's encapsulation key, ML-DSA's
// public key), empty for other algorithms.
fn pq_pub(k: const Key&) -> const u8[:] { k.body[k.pq_at..k.pq_at + k.pq_len] }

// gpg's name of a Kyber key: ky768_cv25519, ky768_bp256, ky1024_bp384...
fn kyber_name(k: const Key&) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(if k.pq_len == MLKEM1024_EK_LEN { "ky1024_" } else { "ky768_" });
    let at = if k.version == 4 { 6 } else { 10 };
    if at >= k.body.len { return out; }
    let ol: i64 = k.body[at];
    if at + 1 + ol > k.body.len { return out; }
    let oid = k.body[at + 1..at + 1 + ol];
    if oid == OID_X25519_RFC8410 || oid == OID_X25519 { out.append("cv25519"); }
    else if oid == OID_X448_RFC8410 { out.append("cv448"); }
    else if oid == OID_BP256 { out.append("bp256"); }
    else if oid == OID_BP384 { out.append("bp384"); }
    else if oid == OID_BP512 { out.append("bp512"); }
    else if oid == OID_P256 { out.append("nistp256"); }
    else if oid == OID_P384 { out.append("nistp384"); }
    else { out.append("unknown"); }
    return out;
}

fn curve_name(c: i64) -> const u8[:] {
    if c == CURVE_ED25519 { return "ed25519"; }
    if c == CURVE_X25519 { return "cv25519"; }
    if c == CURVE_P256 { return "nistp256"; }
    if c == CURVE_P384 { return "nistp384"; }
    if c == CURVE_P521 { return "nistp521"; }
    if c == CURVE_BP256 { return "brainpoolP256r1"; }
    if c == CURVE_BP384 { return "brainpoolP384r1"; }
    if c == CURVE_BP512 { return "brainpoolP512r1"; }
    if c == CURVE_ED448 { return "ed448"; }
    if c == CURVE_X448 { return "cv448"; }
    return "";
}

// "rsa3072", "ed25519", "cv25519", "nistp256", as gpg lists keys.
fn key_type_name(k: const Key&) -> u8[>..] {
    if is_rsa(k.algo) { return str("rsa", rsa_key_bits(k)); }
    if k.algo == PK_ED25519 { return str("ed25519"); }
    if k.algo == PK_X25519 { return str("cv25519"); }
    if k.algo == PK_ED448 { return str("ed448"); }
    if k.algo == PK_X448 { return str("cv448"); }
    if k.algo == PK_KYBER { return kyber_name(k); }
    if k.algo == PK_MLKEM768_X25519 { return str("mlkem768_x25519"); }
    if k.algo == PK_MLKEM1024_X448 { return str("mlkem1024_x448"); }
    if k.algo == PK_MLDSA65_ED25519 { return str("mldsa65_ed25519"); }
    if k.algo == PK_MLDSA87_ED448 { return str("mldsa87_ed448"); }
    if k.curve != CURVE_NONE { return str(curve_name(k.curve)); }
    return str(algo_name(k.algo));
}

fn rsa_key_bits(k: const Key&) -> i64 {
    let n = strip_zeros(k.n);
    if n.len == 0 { return 0; }
    return 8 * (n.len - 1) + 64 - ::clz(n[0]);
}

fn can_sign_algo(algo: i64) -> bool {
    algo == PK_RSA || algo == PK_RSA_S || algo == PK_EDDSA || algo == PK_ED25519 || algo == PK_ECDSA
        || algo == PK_ED448 || algo == PK_MLDSA65_ED25519
}

fn can_encrypt_algo(algo: i64) -> bool {
    algo == PK_RSA || algo == PK_RSA_E || algo == PK_ECDH || algo == PK_X25519 || algo == PK_X448
        || algo == PK_KYBER || algo == PK_MLKEM768_X25519
}

// Whether a session key wrapped for this algorithm goes without the
// 2-octet checksum (and, in a v3 PKESK, with its cipher in the clear).
fn session_no_checksum(algo: i64) -> bool {
    algo == PK_X25519 || algo == PK_X448 || algo == PK_KYBER || algo == PK_MLKEM768_X25519
}

// --- Parsing --------------------------------------------------------------------

// An MPI of the body into dst (bounded), and the position after it.
fn take_mpi<A>(body: const u8[:], at: i64, dst: A&) -> i64, bool {
    let s, e, next, ok = read_mpi(body, at);
    if !ok || e - s > dst.cap { return at, false; }
    dst.clear();
    dst.append(body[s..e]);
    return next, true;
}

// The octets of a 448 key's point or secret, or of an ECC value of a Kyber
// key (curve: X25519, X448 or a Weierstrass curve), as an MPI or SOS
// holds them: a 0x40 prefix dropped for the Montgomery curves, leading
// zeros an MPI dropped put back; false when it is not that long.
fn ecc_octets(curve: i64, v: const u8[:], secret: bool = false) -> u8[>..], bool {
    var out: u8[>..] = [];
    var n = if curve == CURVE_X25519 || curve == CURVE_ED25519 { 32 } else { curve_size(curve) };
    if is_weierstrass(curve) && !secret {
        // A point: 04 || x || y, whole.
        n = 1 + 2 * n;
        if v.len != n || v[0] != 4 { return out, false; }
        out.append(v);
        return out, true;
    }
    var w = v;
    if !secret && w.len == n + 1 && w[0] == 0x40 { w = v[1..]; }
    if is_weierstrass(curve) || secret { w = strip_zeros(w); }
    if w.len > n { return out, false; }
    pad_left(out, w, n);
    return out, true;
}

// The algorithm-specific public fields at body[at..end]; the position after them.
fn parse_public_material(k: Key&, body: const u8[:], at: i64) -> i64, i64 {
    var p = at;
    if is_rsa(k.algo) {
        let p1, ok1 = take_mpi(body, p, k.n);
        let p2, ok2 = take_mpi(body, p1, k.e);
        if !ok1 || !ok2 { return p, ERR_MALFORMED; }
        return p2, OK;
    }
    if k.algo == PK_DSA || k.algo == PK_ELGAMAL {
        let count = if k.algo == PK_DSA { 4 } else { 3 };
        for i in count {
            let s, e, next, ok = read_mpi(body, p);
            if !ok { return p, ERR_MALFORMED; }
            p = next;
        }
        return p, OK;
    }
    if k.algo == PK_ECDSA || k.algo == PK_EDDSA || k.algo == PK_ECDH {
        if p >= body.len { return p, ERR_MALFORMED; }
        let ol: i64 = body[p];
        if ol == 0 || ol == 255 || p + 1 + ol > body.len { return p, ERR_MALFORMED; }
        k.curve = curve_of_oid(body[p + 1..p + 1 + ol]);
        p += 1 + ol;
        let s, e, next, ok = read_mpi(body, p);
        if !ok { return p, ERR_MALFORMED; }
        let pt = body[s..e];
        p = next;
        if k.curve == CURVE_ED25519 || k.curve == CURVE_X25519 {
            if pt.len != 33 || pt[0] != 0x40 { return p, ERR_MALFORMED; }
            k.point.append(pt[1..]);
        } else if k.curve == CURVE_ED448 || k.curve == CURVE_X448 {
            // gpg's: the native 57 (Ed448) or 56 (X448) octets, no prefix.
            let v, okv = ecc_octets(k.curve, pt);
            if !okv { return p, ERR_MALFORMED; }
            k.point.append(v);
        } else if k.curve != CURVE_NONE {
            if pt.len > k.point.cap { return p, ERR_MALFORMED; }
            k.point.append(pt);
        }
        if k.algo == PK_ECDH {
            if p + 4 > body.len || body[p] != 3 || body[p + 1] != 1 { return p, ERR_MALFORMED; }
            k.kdf_hash = body[p + 2];
            k.kdf_cipher = body[p + 3];
            p += 4;
        }
        // An EdDSALegacy key on another curve, or ECDH on an Edwards curve, is not one.
        let edwards = k.curve == CURVE_ED25519 || k.curve == CURVE_ED448;
        if k.algo == PK_EDDSA && !edwards { k.curve = CURVE_NONE; }
        if k.algo == PK_ECDH && edwards { k.curve = CURVE_NONE; }
        if k.algo == PK_ECDSA && !is_weierstrass(k.curve) { k.curve = CURVE_NONE; }
        return p, OK;
    }
    if k.algo == PK_X25519 || k.algo == PK_ED25519 {
        if p + 32 > body.len { return p, ERR_MALFORMED; }
        k.point.append(body[p..p + 32]);
        return p + 32, OK;
    }
    if k.algo == PK_X448 || k.algo == PK_ED448 {
        let n = if k.algo == PK_X448 { 56 } else { 57 };
        if p + n > body.len { return p, ERR_MALFORMED; }
        k.point.append(body[p..p + n]);
        return p + n, OK;
    }
    if k.algo == PK_KYBER { return parse_kyber_public(k, body, p); }
    // RFC 9980: fixed-size fields, the ECC key first.
    if is_pq_kem(k.algo) || is_pq_sig(k.algo) {
        var ecc = 0;
        var pq = 0;
        if k.algo == PK_MLKEM768_X25519 { ecc = 32; pq = MLKEM768_EK_LEN; }
        else if k.algo == PK_MLKEM1024_X448 { ecc = 56; pq = 1568; }
        else if k.algo == PK_MLDSA65_ED25519 { ecc = 32; pq = MLDSA65_PK_LEN; }
        else if k.algo == PK_MLDSA87_ED448 { ecc = 57; pq = 2592; }
        else if k.algo == PK_SLHDSA_256S { pq = 64; }
        else { pq = 32; }
        if ecc + pq > body.len - p { return p, ERR_MALFORMED; }
        if ecc == 32 { k.point.append(body[p..p + 32]); }
        k.pq_at = p + ecc;
        k.pq_len = pq;
        return p + ecc + pq, OK;
    }
    return p, ERR_UNSUPPORTED;
}

// gpg's Kyber key: the ECC part's OID and point (as ECDH has them), then
// the ML-KEM key with a 4-octet length. ML-KEM-768 or -1024 with X25519,
// X448 or a Weierstrass curve is usable here (gpg makes ky768_cv25519,
// ky768_bp256, ky1024_bp384 and ky1024_cv448); others keep CURVE_NONE.
fn parse_kyber_public(k: Key&, body: const u8[:], at: i64) -> i64, i64 {
    var p = at;
    if p >= body.len { return p, ERR_MALFORMED; }
    let ol: i64 = body[p];
    if ol == 0 || ol == 255 || p + 1 + ol > body.len { return p, ERR_MALFORMED; }
    let oid = body[p + 1..p + 1 + ol];
    var curve = curve_of_oid(oid);
    if oid == OID_X25519_RFC8410 { curve = CURVE_X25519; }
    p += 1 + ol;
    let s, e, next, ok = read_mpi(body, p);
    if !ok { return p, ERR_MALFORMED; }
    let pt = body[s..e];
    p = next;
    if p + 4 > body.len { return p, ERR_MALFORMED; }
    let n = be32(body, p);
    if n > body.len - p - 4 { return p, ERR_MALFORMED; }
    k.pq_at = p + 4;
    k.pq_len = n;
    p += 4 + n;
    let usable = curve == CURVE_X25519 || curve == CURVE_X448 || is_weierstrass(curve);
    if usable && (n == MLKEM768_EK_LEN || n == MLKEM1024_EK_LEN) {
        // gpg takes X25519's point with its 0x40 or without.
        let v, okv = ecc_octets(curve, pt);
        if !okv { return p, ERR_MALFORMED; }
        k.point.append(v);
        k.curve = curve;
    }
    return p, OK;
}

// ML-KEM's k (3 or 4) for a key's ML-KEM part.
fn mlkem_level(k: const Key&) -> i64 { if k.pq_len == MLKEM1024_EK_LEN { 4 } else { 3 } }

// The fingerprint and key ID of k.body.
fn set_fingerprint(k: Key&) {
    k.fpr.clear();
    if k.version == 6 || k.version == 5 {
        // v5 (LibrePGP) as v6, but for the first octet.
        var pre: u8[>..] = [];
        pre.push(if k.version == 6 { 0x9B } else { 0x9A });
        put32(pre, k.body.len);
        let h = digest3(HASH_SHA256, pre, k.body, "");
        k.fpr.append(h);
        for i in 8 { k.keyid[i] = h[i]; }
    } else {
        var pre: u8[>..] = [];
        pre.push(0x99);
        put16(pre, k.body.len);
        let h = digest3(HASH_SHA1, pre, k.body, "");
        k.fpr.append(h);
        for i in 8 { k.keyid[i] = h[12 + i]; }
    }
}

// A key packet's body: a public key or subkey (tag 6 or 14) or a secret
// one (5 or 7), version 4 or 6. A protected secret stays locked until
// unlock; an unprotected one is read now.
fn parse_key(tag: i64, body: const u8[:]) -> Key, i64 {
    var k = Key { .. };
    k.subkey = tag == TAG_PUBLIC_SUBKEY || tag == TAG_SECRET_SUBKEY;
    if body.len < 6 { return k, ERR_MALFORMED; }
    k.version = body[0];
    if k.version != 4 && k.version != 5 && k.version != 6 { return k, ERR_UNSUPPORTED; }
    k.created = be32(body, 1);
    k.algo = body[5];
    var p = 6;
    var mat_end = body.len;
    if k.version >= 5 {
        if body.len < 10 { return k, ERR_MALFORMED; }
        let ml = be32(body, 6);
        p = 10;
        if ml > body.len - 10 { return k, ERR_MALFORMED; }
        mat_end = 10 + ml;
    }
    let end, err = parse_public_material(k, body[..mat_end], p);
    if err != OK { return k, err; }
    if k.version >= 5 && end != mat_end { return k, ERR_MALFORMED; }
    let secret = tag == TAG_SECRET_KEY || tag == TAG_SECRET_SUBKEY;
    if !secret && end != body.len { return k, ERR_MALFORMED; }
    if end > k.body.cap { return k, ERR_UNSUPPORTED; }
    k.body.append(body[..end]);
    set_fingerprint(k);
    if !secret { return k, OK; }
    if body.len - end > k.sec_raw.cap { return k, ERR_UNSUPPORTED; }
    k.sec_raw.append(body[end..]);
    k.has_secret = true;
    if k.sec_raw.len == 0 { return k, ERR_MALFORMED; }
    let usage: i64 = k.sec_raw[0];
    if usage == 0 {
        if k.version == 5 {
            // v5: no protection fields (a zero count), then the material's
            // 4-octet length; the checksum stays, as gpg writes it.
            let raw = k.sec_raw[..];
            if raw.len < 6 + 2 || raw[1] != 0 || be32(raw, 2) != raw.len - 6 - 2 { return k, ERR_MALFORMED; }
            let e5 = read_secret_material(k, raw[6..], true);
            return k, e5;
        }
        let e2 = read_secret_material(k, k.sec_raw[1..], k.version == 4);
        return k, e2;
    }
    // Protected: check that the S2K parses, so a stub is known now.
    let s2k, iv_at, e3 = protection_of(k);
    if e3 != OK && e3 != ERR_UNSUPPORTED { return k, e3; }
    if e3 == OK && s2k.kind == S2K_GNU_DUMMY {
        // gpg's mode 1003: its agent's S-expression, protected or not.
        if s2k.coded == 3 && k.algo == PK_KYBER {
            k.sexp = true;
            let e4 = read_gnu1003(k, "");
            if e4 == ERR_PASSPHRASE { k.locked = true; return k, OK; }
            return k, e4;
        }
        k.stub = true;
        return k, OK;
    }
    k.locked = true;
    return k, OK;
}

// The protection of a locked secret: its S2K and where its IV starts in
// sec_raw. usage 254 and 255 (v4, v5 and v6) and 253 (AEAD, v6).
fn protection_of(k: const Key&) -> S2k, i64, i64 {
    let raw = k.sec_raw[..];
    var none = S2k { .. };
    if raw.len < 2 { return none, 0, ERR_MALFORMED; }
    let usage: i64 = raw[0];
    if usage != 254 && usage != 255 && usage != 253 { return none, 0, ERR_UNSUPPORTED; }
    var p = 1;
    if k.version >= 5 { p++; }       // the count of the fields that follow
    p++;                              // the cipher
    if usage == 253 { p++; }          // the AEAD mode
    if k.version == 6 { p++; }       // the S2K's length
    let s, next, err = read_s2k(raw, p);
    return s, next, err;
}

// The S-expression of a mode 1003 secret: after the protection fields,
// its 4-octet length.
fn gnu1003_blob(k: const Key&) -> const u8[:], bool {
    let s2k, at, err = protection_of(k);
    let raw = k.sec_raw[..];
    if err != OK || at + 4 > raw.len || be32(raw, at) != raw.len - at - 4 { return raw[..0], false; }
    return raw[at + 4..], true;
}

// The secrets of a Kyber key in gpg's mode 1003, with the passphrase for
// the parts that are protected (ERR_PASSPHRASE when "" will not do).
fn read_gnu1003(k: Key&, pass: const u8[:]) -> i64 {
    let blob, ok = gnu1003_blob(k);
    if !ok { return ERR_MALFORMED; }
    var st: i64[..8] = [];
    var en: i64[..8] = [];
    if !sexp_items(blob, st, en) || st.len != 3 { return ERR_MALFORMED; }
    let a, e, oka = sexp_atom(blob, st[0]);
    if !oka || blob[a..e] != "composite-key" { return ERR_MALFORMED; }
    var scalar: u8[>..] = [];
    var seed:   u8[>..] = [];
    for i in 1..3 {
        let part = blob[st[i]..en[i]];
        var clear: u8[>..] = [];
        if sexp_is(part, 0, "protected-private-key") {
            if pass.len == 0 { return ERR_PASSPHRASE; }
            let eu = agent_unprotect(part, pass, clear);
            if eu != OK { return eu; }
        } else if sexp_is(part, 0, "private-key") {
            clear.append(part);
        } else {
            return ERR_MALFORMED;
        }
        // clear: the secret parameters (the list, or its decrypted part).
        let ecc_at, ecc_end = sexp_find(part, "ecc");
        if ecc_at >= 0 {
            let q, okq = sexp_value(part, "q");
            if !okq { return ERR_MALFORMED; }
            let qv, okv = ecc_octets(k.curve, q);
            if !okv || qv[..] != k.point[..] { return ERR_KEY; }
            let d, okd = sexp_value(clear, "d");
            if !okd { return ERR_MALFORMED; }
            let dv, okdv = ecc_octets(k.curve, d, true);
            if !okdv { return ERR_MALFORMED; }
            // As in an OpenPGP packet: Curve25519's big-endian, X25519 takes
            // it reversed; X448's native; a Weierstrass curve's big-endian.
            scalar.clear();
            if k.curve == CURVE_X25519 { scalar.append(reversed(dv)); } else { scalar.append(dv); }
            continue;
        }
        let ky_at, ky_end = sexp_find(part, if mlkem_level(k) == 4 { "kyber1024" } else { "kyber768" });
        if ky_at < 0 { return ERR_UNSUPPORTED; }
        let sd, oks = sexp_value(clear, "seed");
        if oks && sd.len == MLKEM_SEED_LEN { seed.append(sd); continue; }
        let dk, okk = sexp_value(clear, "s");
        if !okk || dk.len != bignum::mlkem_dk_len(mlkem_level(k)) { return ERR_MALFORMED; }
        seed.append(dk);
    }
    if k.curve == CURVE_NONE || scalar.len == 0 || seed.len == 0 { return ERR_MALFORMED; }
    k.scalar.clear();
    k.scalar.append(scalar);
    k.pq_sec.clear();
    k.pq_sec.append(seed);
    k.locked = false;
    return check_secret(k);
}

// gpg-agent's name of a curve, as its S-expressions give it.
fn agent_curve_name(c: i64) -> const u8[:] {
    if c == CURVE_X448 { return "X448"; }
    if c == CURVE_P256 { return "NIST P-256"; }
    if c == CURVE_P384 { return "NIST P-384"; }
    if c == CURVE_P521 { return "NIST P-521"; }
    return curve_name(c);
}

// gpg's mode 1003 S-expression of an unlocked Kyber key: both parts
// unprotected, or protected by pass with the agent's OCB (count octets
// hashed by its S2K).
fn put_gnu1003(out: u8[>..]&, k: const Key&, pass: const u8[:], count: i64) -> i64 {
    var pub: u8[>..] = [];
    var sec: u8[>..] = [];
    var q:   u8[>..] = [];
    let lv = mlkem_level(k);
    let alg = if lv == 4 { "kyber1024" } else { "kyber768" };
    if k.curve == CURVE_X25519 {
        q.push(0x40);
        q.append(k.point);
        pub.append("(5:curve10:Curve25519)(5:flags9:djb-tweak)");
        put_pair(pub, "q", q);
        put_pair(sec, "d", reversed(k.scalar));
    } else {
        pub.push('(');
        put_atom(pub, "curve");
        put_atom(pub, agent_curve_name(k.curve));
        pub.push(')');
        put_pair(pub, "q", k.point);
        put_pair(sec, "d", k.scalar);
    }
    var ek: u8[>..] = [];
    var dk: u8[>..] = [];
    if k.pq_sec.len == MLKEM_SEED_LEN {
        let e1, d1 = bignum::mlkem_keys_from_seed(lv, k.pq_sec);
        ek.append(e1);
        dk.append(d1);
    } else {
        dk.append(k.pq_sec);
        ek.append(pq_pub(k));
    }
    var kpub: u8[>..] = [];
    var ksec: u8[>..] = [];
    put_pair(kpub, "p", ek);
    put_pair(ksec, "s", dk);
    if k.pq_sec.len == MLKEM_SEED_LEN { put_pair(ksec, "seed", k.pq_sec); }
    out.append("(13:composite-key");
    if pass.len == 0 {
        out.append("(11:private-key(3:ecc");
        out.append(pub);
        out.append(sec);
        out.append("))(11:private-key(");
        put_atom(out, alg);
        out.append(kpub);
        out.append(ksec);
        out.append(")))");
        return OK;
    }
    let e2 = agent_protect(out, "ecc", pub, sec, pass, count);
    if e2 != OK { return e2; }
    let e3 = agent_protect(out, alg, kpub, ksec, pass, count);
    if e3 != OK { return e3; }
    out.push(')');
    return OK;
}

// The secret fields of a key: MPIs (or native octets for X25519 and
// Ed25519), then, unless v6 and v4 says otherwise, a 2-octet checksum.
fn read_secret_material(k: Key&, data: const u8[:], checksum: bool) -> i64 {
    var p = 0;
    if is_rsa(k.algo) {
        let p1, ok1 = take_mpi(data, p, k.d);
        let p2, ok2 = take_mpi(data, p1, k.p);
        let p3, ok3 = take_mpi(data, p2, k.q);
        let p4, ok4 = take_mpi(data, p3, k.u);
        if !ok1 || !ok2 || !ok3 || !ok4 { return ERR_MALFORMED; }
        p = p4;
    } else if k.algo == PK_EDDSA || k.algo == PK_ECDSA || k.algo == PK_ECDH {
        let s, e, next, ok = read_mpi(data, p);
        if !ok { return ERR_MALFORMED; }
        if k.curve == CURVE_NONE { return ERR_MALFORMED; }
        // Big-endian, as an MPI is, but for the 448 curves' native octets.
        let full, okv = ecc_octets(k.curve, data[s..e], true);
        if !okv { return ERR_MALFORMED; }
        k.scalar.clear();
        // Curve25519's secret is stored big-endian: X25519 takes it the other way round.
        if k.curve == CURVE_X25519 { k.scalar.append(reversed(full)); } else { k.scalar.append(full); }
        p = next;
    } else if k.algo == PK_X25519 || k.algo == PK_ED25519 || k.algo == PK_X448 || k.algo == PK_ED448 {
        let n = if k.algo == PK_X448 { 56 } else if k.algo == PK_ED448 { 57 } else { 32 };
        if data.len < n { return ERR_MALFORMED; }
        k.scalar.clear();
        k.scalar.append(data[..n]);
        p = n;
    } else if k.algo == PK_KYBER {
        // As gpg's parse-packet.c reads it: the ECC secret (SOS), then the
        // ML-KEM secret with a 4-octet length (the seed, or expanded).
        if k.curve == CURVE_NONE { return ERR_UNSUPPORTED; }
        let s, e, next, ok = read_mpi(data, 0);
        if !ok || next + 4 > data.len { return ERR_MALFORMED; }
        let full, okv = ecc_octets(k.curve, data[s..e], true);
        if !okv { return ERR_MALFORMED; }
        k.scalar.clear();
        if k.curve == CURVE_X25519 { k.scalar.append(reversed(full)); } else { k.scalar.append(full); }
        let n = be32(data, next);
        let dkn = bignum::mlkem_dk_len(mlkem_level(k));
        if (n != MLKEM_SEED_LEN && n != dkn) || n > data.len - next - 4 { return ERR_MALFORMED; }
        k.pq_sec.clear();
        k.pq_sec.append(data[next + 4..next + 4 + n]);
        p = next + 4 + n;
    } else if k.algo == PK_MLKEM768_X25519 || k.algo == PK_MLDSA65_ED25519 {
        // RFC 9980: the ECC secret, then the seed (d || z, or xi).
        let n = if k.algo == PK_MLKEM768_X25519 { MLKEM_SEED_LEN } else { MLDSA_SEED_LEN };
        if data.len < 32 + n { return ERR_MALFORMED; }
        k.scalar.clear();
        k.scalar.append(data[..32]);
        k.pq_sec.clear();
        k.pq_sec.append(data[32..32 + n]);
        p = 32 + n;
    } else {
        return ERR_UNSUPPORTED;
    }
    if checksum {
        if p + 2 != data.len { return ERR_MALFORMED; }
        var sum: i64 = 0;
        for i in p { sum += data[i]; }
        if (sum & 0xffff) != be16(data, p) { return ERR_MALFORMED; }
    } else if p != data.len {
        return ERR_MALFORMED;
    }
    k.locked = false;
    return check_secret(k);
}

// Whether the secret matches the public key: RSA's n = pq, the EC public
// point from the scalar.
fn check_secret(k: const Key&) -> i64 {
    if is_rsa(k.algo) {
        let key, ok = bignum::rsa_key_from_bytes(k.n, k.e, k.d, k.p, k.q);
        return if ok { OK } else { ERR_KEY };
    }
    if k.algo == PK_ED448 || (k.algo == PK_EDDSA && k.curve == CURVE_ED448) {
        if k.scalar.len != 57 { return ERR_KEY; }
        let pub = bignum::ed448_public(k.scalar);
        return if pub[..] == k.point[..] { OK } else { ERR_KEY };
    }
    if k.algo == PK_EDDSA || k.algo == PK_ED25519 {
        let pub = bignum::ed25519_public(k.scalar);
        return if pub[..] == k.point[..] { OK } else { ERR_KEY };
    }
    if k.algo == PK_KYBER || k.algo == PK_MLKEM768_X25519 {
        if k.algo == PK_MLKEM768_X25519 && (k.scalar.len != 32 || k.point.len != 32) { return ERR_KEY; }
        if k.algo == PK_MLKEM768_X25519 && bignum::x25519_base(k.scalar)[..] != k.point[..] { return ERR_KEY; }
        if k.algo == PK_KYBER && !ecc_secret_matches(k) { return ERR_KEY; }
        let ek = pq_pub(k);
        let lv = mlkem_level(k);
        if k.pq_sec.len == MLKEM_SEED_LEN {
            let ek2, dk = bignum::mlkem_keys_from_seed(lv, k.pq_sec);
            return if ek2[..] == ek { OK } else { ERR_KEY };
        }
        // gpg's expanded key: dk' || ek || H(ek) || z.
        if k.pq_sec.len != bignum::mlkem_dk_len(lv) { return ERR_KEY; }
        return if k.pq_sec[384 * lv..384 * lv + ek.len] == ek { OK } else { ERR_KEY };
    }
    if k.algo == PK_MLDSA65_ED25519 {
        if k.scalar.len != 32 || k.pq_sec.len != MLDSA_SEED_LEN { return ERR_KEY; }
        let pub = bignum::ed25519_public(k.scalar);
        if pub[..] != k.point[..] { return ERR_KEY; }
        let pk = bignum::mldsa_public_key(65, k.pq_sec);
        return if pk[..] == pq_pub(k) { OK } else { ERR_KEY };
    }
    if k.algo == PK_X25519 {
        return if bignum::x25519_base(k.scalar)[..] == k.point[..] { OK } else { ERR_KEY };
    }
    if k.algo == PK_X448 {
        return if k.scalar.len == 56 && bignum::x448_base(k.scalar)[..] == k.point[..] { OK } else { ERR_KEY };
    }
    if k.curve == CURVE_X25519 || k.curve == CURVE_X448 || is_weierstrass(k.curve) {
        return if ecc_secret_matches(k) { OK } else { ERR_KEY };
    }
    return ERR_UNSUPPORTED;
}

// Whether k.scalar gives k.point on k.curve (X25519, X448 or Weierstrass).
fn ecc_secret_matches(k: const Key&) -> bool {
    if k.curve == CURVE_X25519 { return k.scalar.len == 32 && bignum::x25519_base(k.scalar)[..] == k.point[..]; }
    if k.curve == CURVE_X448 { return k.scalar.len == 56 && bignum::x448_base(k.scalar)[..] == k.point[..]; }
    if !is_weierstrass(k.curve) { return false; }
    let c = weierstrass_curve(k.curve);
    let sk, ok = bignum::ec_scalar(c, k.scalar);
    if !ok { return false; }
    return bignum::ec_public_key(c, k.scalar)[..] == k.point[..];
}

// Decrypts a locked secret with a passphrase. ERR_PASSPHRASE when the
// checksum (SHA-1 for usage 254) does not match.
fn unlock_key(k: Key&, pass: const u8[:]) -> i64 {
    if !k.has_secret || k.stub { return ERR_KEY; }
    if !k.locked { return OK; }
    if k.sexp { return read_gnu1003(k, pass); }
    let raw = k.sec_raw[..];
    let usage: i64 = raw[0];
    let s2k, iv_at, err = protection_of(k);
    if err != OK { return err; }
    let cipher: i64 = raw[if k.version >= 5 { 2 } else { 1 }];
    let ks = cipher_key_size(cipher);
    if ks == 0 { return ERR_UNSUPPORTED; }
    let key, e2 = s2k_key(s2k, pass, ks);
    if e2 != OK { return e2; }
    if usage == 253 { return unlock_aead(k, key, cipher, iv_at); }
    let bs = cipher_block_size(cipher);
    if iv_at + bs > raw.len { return ERR_MALFORMED; }
    let iv = raw[iv_at..iv_at + bs];
    var data: u8[>..] = [];
    // v5 puts the 4-octet length of what is encrypted before it.
    var at = iv_at + bs;
    if k.version == 5 {
        if at + 4 > raw.len || be32(raw, at) != raw.len - at - 4 { return ERR_MALFORMED; }
        at += 4;
    }
    data.append(raw[at..]);
    if !cfb(cipher, key, iv, data, true) { return ERR_UNSUPPORTED; }
    if usage == 254 {
        if data.len < 20 { return ERR_PASSPHRASE; }
        let body = data[..data.len - 20];
        let h = bignum::sha1(body);
        if bignum::ct_eq_bytes(h, data[data.len - 20..]) != 1 { return ERR_PASSPHRASE; }
        let e3 = read_secret_material(k, body, false);
        return if e3 == ERR_MALFORMED { ERR_PASSPHRASE } else { e3 };
    }
    let e4 = read_secret_material(k, data, true);
    return if e4 == ERR_MALFORMED { ERR_PASSPHRASE } else { e4 };
}

// RFC 9580 §5.5.3's AEAD protection (usage 253): HKDF-SHA256 of the S2K's
// key with info (packet tag, version, cipher, AEAD); the public key packet
// is the associated data. Only OCB over AES.
fn unlock_aead(k: Key&, s2k_key: const u8[:], cipher: i64, iv_at: i64) -> i64 {
    let raw = k.sec_raw[..];
    let aead: i64 = raw[if k.version >= 5 { 3 } else { 2 }];
    if aead != AEAD_OCB || !is_aes(cipher) { return ERR_UNSUPPORTED; }
    if iv_at + 15 + 16 > raw.len { return ERR_MALFORMED; }
    let tag = if k.subkey { TAG_SECRET_SUBKEY } else { TAG_SECRET_KEY };
    let info: u8[4] = [(0xC0 | tag) as! u8, k.version as! u8, cipher as! u8, aead as! u8];
    let kek = bignum::hkdf(256, "", s2k_key, info, cipher_key_size(cipher));
    var ad: u8[>..] = [];
    ad.push((0xC0 | (if k.subkey { TAG_PUBLIC_SUBKEY } else { TAG_PUBLIC_KEY })) as! u8);
    ad.append(k.body);
    let o = ocb_init(kek);
    var data: u8[>..] = [];
    data.append(raw[iv_at + 15..raw.len - 16]);
    if !ocb_decrypt(o, raw[iv_at..iv_at + 15], ad, data, raw[raw.len - 16..]) { return ERR_PASSPHRASE; }
    return read_secret_material(k, data, false);
}

// --- Writing ---------------------------------------------------------------------

// The secret fields of an unlocked key, as a secret key packet holds them
// without protection (usage 0 and, for v4, the checksum).
fn put_secret_material(out: u8[>..]&, k: const Key&) {
    let start = out.len;
    if is_rsa(k.algo) {
        put_mpi(out, k.d);
        put_mpi(out, k.p);
        put_mpi(out, k.q);
        put_mpi(out, k.u);
    } else if k.algo == PK_X25519 || k.algo == PK_ED25519 || k.algo == PK_X448 || k.algo == PK_ED448 {
        out.append(k.scalar);
    } else if k.algo == PK_MLKEM768_X25519 || k.algo == PK_MLDSA65_ED25519 {
        out.append(k.scalar);
        out.append(k.pq_sec);
    } else if k.algo == PK_KYBER {
        var es: u8[>..] = [];
        if k.curve == CURVE_X25519 { es = reversed(k.scalar); } else { es.append(k.scalar); }
        put_sos(out, es);
        put32(out, k.pq_sec.len);
        out.append(k.pq_sec);
    } else if k.curve == CURVE_X25519 {
        put_mpi(out, reversed(k.scalar));
    } else if k.curve == CURVE_ED448 || k.curve == CURVE_X448 {
        // gpg's: the native octets, every one.
        put_sos(out, k.scalar);
    } else {
        put_mpi(out, k.scalar);
    }
    if k.version != 6 {
        var sum: i64 = 0;
        for i in start..out.len { sum += out[i]; }
        put16(out, sum & 0xffff);
    }
}

// The secret key packet's body: the public body, then the secret part:
// as read (sec_raw) when keep_raw, else unprotected, or protected anew by
// pass with iterated S2K, AES-256 and the SHA-1 check (usage 254), as gpg
// exports keys.
fn put_secret_body(out: u8[>..]&, k: const Key&, pass: const u8[:] = "", keep_raw: bool = false,
                   coded: i64 = 255) -> i64 {
    out.append(k.body);
    if keep_raw || k.locked || k.stub { out.append(k.sec_raw); return OK; }
    if k.algo == PK_KYBER {
        // As gpg exports it (the only way it imports it): mode 1003, the
        // agent's S-expression; its OCB protection when pass is given.
        var sx: u8[>..] = [];
        let e = put_gnu1003(sx, k, pass, s2k_count(coded));
        if e != OK { return e; }
        out.append("\xff\x07\x00\x65\x00GNU\x03");
        put32(out, sx.len);
        out.append(sx);
        return OK;
    }
    if k.version == 5 {
        // v5: the count of the protection fields, the material's length.
        var mat: u8[>..] = [];
        put_secret_material(mat, k);
        if pass.len == 0 {
            out.push(0);
            out.push(0);
            put32(out, mat.len - 2);
            out.append(mat);
            return OK;
        }
        let s5 = new_s2k(coded);
        let key5, e5 = s2k_key(s5, pass, 32);
        if e5 != OK { return e5; }
        let iv5 = random(16);
        mat.resize(mat.len - 2);
        mat.append(bignum::sha1(mat));
        let ok5 = cfb(CIPHER_AES256, key5, iv5, mat, false);
        var fields: u8[>..] = [];
        fields.push(CIPHER_AES256 as! u8);
        put_s2k(fields, s5);
        fields.append(iv5);
        out.push(254);
        out.push(fields.len as! u8);
        out.append(fields);
        put32(out, mat.len);
        out.append(mat);
        return OK;
    }
    if pass.len == 0 {
        out.push(0);
        if k.version == 6 {
            // v6 has no checksum for usage 0.
            var tmp: u8[>..] = [];
            put_secret_material(tmp, k);
            out.append(tmp);
        } else {
            put_secret_material(out, k);
        }
        return OK;
    }
    let s2k = new_s2k(coded);
    let key, err = s2k_key(s2k, pass, 32);
    if err != OK { return err; }
    let iv = random(16);
    var plain: u8[>..] = [];
    let mark = plain.len;
    put_secret_material(plain, k);
    if k.version == 4 { plain.resize(plain.len - 2); }
    plain.append(bignum::sha1(plain[mark..]));
    let ok = cfb(CIPHER_AES256, key, iv, plain, false);
    out.push(254);
    if k.version == 6 {
        var fields: u8[>..] = [];
        put_s2k(fields, s2k);
        out.push((3 + fields.len + 16) as! u8);
        out.push(CIPHER_AES256 as! u8);
        out.push(fields.len as! u8);
        out.append(fields);
    } else {
        out.push(CIPHER_AES256 as! u8);
        put_s2k(out, s2k);
    }
    out.append(iv);
    out.append(plain);
    return OK;
}

// --- RSA, EC and Ed25519 operations ------------------------------------------------

fn rsa_pub(k: const Key&) -> bignum::RsaPublicKey, bool {
    return bignum::rsa_public_from(bignum::from_bytes_be(k.n), bignum::from_bytes_be(k.e));
}

// Two MPIs at data[at..], each left-padded to n bytes, concatenated.
fn two_mpis(data: const u8[:], n: i64) -> u8[>..], i64, bool {
    var out: u8[>..] = [];
    let s1, e1, n1, ok1 = read_mpi(data, 0);
    let s2, e2, n2, ok2 = read_mpi(data, n1);
    if !ok1 || !ok2 { return out, 0, false; }
    let r = strip_zeros(data[s1..e1]);
    let s = strip_zeros(data[s2..e2]);
    if r.len > n || s.len > n { return out, 0, false; }
    pad_left(out, r, n);
    pad_left(out, s, n);
    return out, n2, true;
}

// Verifies the signature material of a signature packet (sig: the MPIs,
// or Ed25519's 64 octets) over a digest made by hash.
fn verify_digest(k: const Key&, hash: i64, dg: const u8[:], sig: const u8[:]) -> i64 {
    if is_rsa(k.algo) {
        if k.algo == PK_RSA_E { return ERR_KEY; }
        let pub, okp = rsa_pub(k);
        if !okp { return ERR_UNSUPPORTED; }
        let bits = hash_bits(hash);
        if bits <= 0 || !bignum::has_digest_info(bits) { return ERR_UNSUPPORTED; }
        let s, e, next, ok = read_mpi(sig, 0);
        if !ok || next != sig.len { return ERR_MALFORMED; }
        let v = strip_zeros(sig[s..e]);
        let size = bignum::rsa_size(pub);
        if v.len > size { return ERR_BAD_SIGNATURE; }
        var full: u8[>..] = [];
        pad_left(full, v, size);
        return if bignum::rsa_verify_pkcs1_digest(pub, dg, full, bits) { OK } else { ERR_BAD_SIGNATURE };
    }
    if k.algo == PK_EDDSA {
        if k.curve == CURVE_ED448 {
            // gpg's: R and S (57 octets each) as MPIs; Ed448 (no context)
            // over the digest.
            let rs, n, ok = two_mpis(sig, 57);
            if !ok || n != sig.len { return ERR_MALFORMED; }
            return if bignum::ed448_verify(k.point, dg, rs) { OK } else { ERR_BAD_SIGNATURE };
        }
        if k.curve != CURVE_ED25519 { return ERR_UNSUPPORTED; }
        let rs, n, ok = two_mpis(sig, 32);
        if !ok || n != sig.len { return ERR_MALFORMED; }
        return if bignum::ed25519_verify(k.point, dg, rs) { OK } else { ERR_BAD_SIGNATURE };
    }
    if k.algo == PK_ED25519 {
        if sig.len != 64 { return ERR_MALFORMED; }
        return if bignum::ed25519_verify(k.point, dg, sig) { OK } else { ERR_BAD_SIGNATURE };
    }
    if k.algo == PK_ED448 {
        // RFC 9580 §5.2.3.4: a hash of 512 bits at least.
        if hash_size(hash) < 64 { return ERR_UNSUPPORTED; }
        if sig.len != 114 { return ERR_MALFORMED; }
        return if bignum::ed448_verify(k.point, dg, sig) { OK } else { ERR_BAD_SIGNATURE };
    }
    if k.algo == PK_ECDSA {
        if !is_weierstrass(k.curve) { return ERR_UNSUPPORTED; }
        let c = weierstrass_curve(k.curve);
        let rs, n, ok = two_mpis(sig, curve_size(k.curve));
        if !ok || n != sig.len { return ERR_MALFORMED; }
        return if bignum::ecdsa_verify_digest(c, k.point, dg, rs) { OK } else { ERR_BAD_SIGNATURE };
    }
    if k.algo == PK_MLDSA65_ED25519 {
        // RFC 9980 §5.3.1: a digest of 256 bits at least; both must hold.
        if hash_size(hash) < 32 { return ERR_UNSUPPORTED; }
        if sig.len != 64 + MLDSA65_SIG_LEN { return ERR_MALFORMED; }
        if !bignum::ed25519_verify(k.point, dg, sig[..64]) { return ERR_BAD_SIGNATURE; }
        return if bignum::mldsa_verify(65, pq_pub(k), dg, sig[64..]) { OK } else { ERR_BAD_SIGNATURE };
    }
    return ERR_UNSUPPORTED;
}

// Signs a digest made by hash: the signature material, as the packet holds it.
fn sign_digest(k: const Key&, hash: i64, dg: const u8[:], out: u8[>..]&) -> i64 {
    if !k.has_secret || k.stub { return ERR_KEY; }
    if k.locked { return ERR_PASSPHRASE; }
    if is_rsa(k.algo) {
        if k.algo == PK_RSA_E { return ERR_KEY; }
        let key, ok = bignum::rsa_key_from_bytes(k.n, k.e, k.d, k.p, k.q);
        if !ok { return ERR_KEY; }
        let bits = hash_bits(hash);
        if bits <= 0 || !bignum::has_digest_info(bits) { return ERR_UNSUPPORTED; }
        let s, oks = bignum::rsa_sign_pkcs1_digest(key, dg, bits);
        if !oks { return ERR_KEY; }
        put_mpi(out, s);
        return OK;
    }
    if k.algo == PK_ED448 || (k.algo == PK_EDDSA && k.curve == CURVE_ED448) {
        if k.algo == PK_ED448 && hash_size(hash) < 64 { return ERR_UNSUPPORTED; }
        let s = bignum::ed448_sign(k.scalar, dg);
        if k.algo == PK_ED448 { out.append(s); return OK; }
        put_sos(out, s[..57]);
        put_sos(out, s[57..]);
        return OK;
    }
    if k.algo == PK_EDDSA || k.algo == PK_ED25519 {
        if k.algo == PK_EDDSA && k.curve != CURVE_ED25519 { return ERR_UNSUPPORTED; }
        let s = bignum::ed25519_sign(k.scalar, dg);
        if k.algo == PK_ED25519 { out.append(s); return OK; }
        put_mpi(out, s[..32]);
        put_mpi(out, s[32..]);
        return OK;
    }
    if k.algo == PK_ECDSA {
        if !is_weierstrass(k.curve) { return ERR_UNSUPPORTED; }
        let c = weierstrass_curve(k.curve);
        let bits = hash_bits(hash);
        if bits <= 0 { return ERR_UNSUPPORTED; }
        let s = bignum::ecdsa_sign_digest(c, k.scalar, dg, bits);
        let n = curve_size(k.curve);
        put_mpi(out, s[..n]);
        put_mpi(out, s[n..]);
        return OK;
    }
    if k.algo == PK_MLDSA65_ED25519 {
        if hash_size(hash) < 32 { return ERR_UNSUPPORTED; }
        out.append(bignum::ed25519_sign(k.scalar, dg));
        // ML-DSA's default: hedged, the context empty.
        out.append(bignum::mldsa_sign(65, k.pq_sec, dg));
        return OK;
    }
    return ERR_UNSUPPORTED;
}

// --- Session keys ------------------------------------------------------------------

// RFC 6637 §7's KDF parameters and key: Hash(00 00 00 01 || Z || param).
fn ecdh_kek(k: const Key&, z: const u8[:]) -> u8[>..], i64 {
    var kek: u8[>..] = [];
    let ks = cipher_key_size(k.kdf_cipher);
    if !is_aes(k.kdf_cipher) || !hash_known(k.kdf_hash) || hash_size(k.kdf_hash) < ks { return kek, ERR_UNSUPPORTED; }
    var param: u8[>..] = [];
    let oid = oid_of_curve(k.curve);
    param.push(oid.len as! u8);
    param.append(oid);
    param.push(PK_ECDH as! u8);
    param.append("\x03\x01");
    param.push(k.kdf_hash as! u8);
    param.push(k.kdf_cipher as! u8);
    param.append("Anonymous Sender    ");
    param.append(k.fpr[..20]);
    let h = digest3(k.kdf_hash, "\x00\x00\x00\x01", z, param);
    kek.append(h[..ks]);
    return kek, OK;
}

// RFC 9580 §5.1.6's X25519: HKDF-SHA256 of ephemeral || recipient || shared.
fn x25519_kek(eph: const u8[:], pub: const u8[:], shared: const u8[:]) -> u8[>..] {
    var ikm: u8[>..] = [];
    ikm.append(eph);
    ikm.append(pub);
    ikm.append(shared);
    return bignum::hkdf(256, "", ikm, "OpenPGP X25519", 16);
}

// RFC 9580 §5.1.7's X448: HKDF-SHA512 of ephemeral || recipient || shared.
fn x448_kek(eph: const u8[:], pub: const u8[:], shared: const u8[:]) -> u8[>..] {
    var ikm: u8[>..] = [];
    ikm.append(eph);
    ikm.append(pub);
    ikm.append(shared);
    return bignum::hkdf(512, "", ikm, "OpenPGP X448", 32);
}

// ML-KEM decapsulation with k's secret: the seed, or gpg's expanded key.
fn mlkem_decaps_key(k: const Key&, ct: const u8[:]) -> u8[>..], bool {
    if k.pq_sec.len == MLKEM_SEED_LEN { return bignum::mlkem_decaps(mlkem_level(k), k.pq_sec, ct); }
    return bignum::mlkem_decaps_dk(mlkem_level(k), k.pq_sec, ct);
}

// The ECC half of a Kyber key as a KEM, as libgcrypt's raw ECC KEMs do it:
// the shared value of secret sk and public peer on curve (X25519's or
// X448's output; on a Weierstrass curve the whole point sk * peer, 04 || x
// || y, not its x alone as ECDH takes it).
fn kem_ecc_shared(curve: i64, sk: const u8[:], peer: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if curve == CURVE_X25519 {
        let sh, ok = bignum::x25519_shared(sk, peer);
        out.append(sh);
        return out, ok;
    }
    if curve == CURVE_X448 {
        let sh, ok = bignum::x448_shared(sk, peer);
        out.append(sh);
        return out, ok;
    }
    if !is_weierstrass(curve) { return out, false; }
    let c = weierstrass_curve(curve);
    let q, okq = bignum::ec_decode(c, peer);
    let d, okd = bignum::ec_scalar(c, sk);
    if !okq || !okd { return out, false; }
    let pt = bignum::ec_mul(c, d[..], q);
    let x, y, ok = bignum::ec_affine(c, pt);
    if !ok { return out, false; }
    out.append(bignum::ec_encode(c, pt));
    return out, true;
}

// A fresh ECC key pair on a Kyber key's curve: secret, public.
fn kem_ecc_keypair(curve: i64) -> u8[>..], u8[>..] {
    var sk: u8[>..] = [];
    var pk: u8[>..] = [];
    if curve == CURVE_X25519 {
        let s, p = bignum::x25519_keypair();
        sk.append(s);
        pk.append(p);
    } else if curve == CURVE_X448 {
        let s, p = bignum::x448_keypair();
        sk.append(s);
        pk.append(p);
    } else {
        let c = weierstrass_curve(curve);
        let s, p = bignum::ec_keypair(c);
        sk.append(s);
        pk.append(p);
    }
    return sk, pk;
}

// eccSS's SHA3 for a Kyber key's curve: 256 for the 256-bit ones, else 512.
fn kem_ecc_bits(curve: i64) -> i64 {
    if curve == CURVE_X25519 || curve == CURVE_P256 || curve == CURVE_BP256 { return 256; }
    return 512;
}

// The session key a PKESK for this key holds: mat is the algorithm's
// fields. The result is the cipher octet (v3 only: a v6 PKESK leaves the
// cipher to the encrypted data), the key, and (unless session_no_checksum)
// its 2-octet checksum, as the sender wrapped it; decode_session splits it.
fn decrypt_session(k: const Key&, mat: const u8[:], out: u8[>..]&, v6: bool = false) -> i64 {
    if !k.has_secret || k.stub { return ERR_KEY; }
    if k.locked { return ERR_PASSPHRASE; }
    if is_rsa(k.algo) {
        if k.algo == PK_RSA_S { return ERR_KEY; }
        let key, ok = bignum::rsa_key_from_bytes(k.n, k.e, k.d, k.p, k.q);
        if !ok { return ERR_KEY; }
        let s, e, next, okm = read_mpi(mat, 0);
        if !okm || next != mat.len { return ERR_MALFORMED; }
        let v = strip_zeros(mat[s..e]);
        let size = bignum::rsa_size(key);
        if v.len > size { return ERR_DECRYPT; }
        var full: u8[>..] = [];
        pad_left(full, v, size);
        let m, okd = bignum::rsa_decrypt_pkcs1(key, full);
        if !okd { return ERR_DECRYPT; }
        out.append(m);
        return OK;
    }
    if k.algo == PK_ECDH {
        let s, e, next, okm = read_mpi(mat, 0);
        if !okm || next >= mat.len { return ERR_MALFORMED; }
        let wl: i64 = mat[next];
        if next + 1 + wl != mat.len || wl < 16 || wl % 8 != 0 { return ERR_MALFORMED; }
        let wrapped = mat[next + 1..];
        let eph = mat[s..e];
        var z: u8[>..] = [];
        if k.curve == CURVE_X25519 {
            if eph.len != 33 || eph[0] != 0x40 { return ERR_MALFORMED; }
            let sh, ok = bignum::x25519_shared(k.scalar, eph[1..]);
            if !ok { return ERR_DECRYPT; }
            z.append(sh);
        } else if k.curve == CURVE_X448 {
            // gpg's cv448: the native 56 octets, no prefix.
            let ev, okv = ecc_octets(CURVE_X448, eph);
            if !okv { return ERR_MALFORMED; }
            let sh, ok = bignum::x448_shared(k.scalar, ev);
            if !ok { return ERR_DECRYPT; }
            z.append(sh);
        } else if is_weierstrass(k.curve) {
            let c = weierstrass_curve(k.curve);
            let sh, ok = bignum::ecdh_shared(c, k.scalar, eph);
            if !ok { return ERR_DECRYPT; }
            z.append(sh);
        } else {
            return ERR_UNSUPPORTED;
        }
        let kek, err = ecdh_kek(k, z);
        if err != OK { return err; }
        let m, oku = bignum::aes_key_unwrap(kek, wrapped);
        if !oku || m.len == 0 { return ERR_DECRYPT; }
        // PKCS #5 padding: the last octet says how many. RFC 6637 pads to
        // a multiple of 8, but some senders pad further (to 40 octets).
        let padn: i64 = m[m.len - 1];
        if padn == 0 || padn >= m.len { return ERR_DECRYPT; }
        for i in padn { if m[m.len - 1 - i] != padn { return ERR_DECRYPT; } }
        out.append(m[..m.len - padn]);
        return OK;
    }
    if k.algo == PK_X25519 {
        let c = if v6 { 0 } else { 1 };
        if mat.len < 33 + c + 16 { return ERR_MALFORMED; }
        let eph = mat[..32];
        let n: i64 = mat[32];
        if 33 + n != mat.len { return ERR_MALFORMED; }
        let sh, ok = bignum::x25519_shared(k.scalar, eph);
        if !ok { return ERR_DECRYPT; }
        let kek = x25519_kek(eph, k.point, sh);
        // v3: the cipher octet in the clear, then the wrapped key.
        let m, oku = bignum::aes_key_unwrap(kek, mat[33 + c..]);
        if !oku { return ERR_DECRYPT; }
        if !v6 { out.push(mat[33]); }
        out.append(m);
        return OK;
    }
    if k.algo == PK_X448 {
        let c = if v6 { 0 } else { 1 };
        if mat.len < 57 + c + 16 { return ERR_MALFORMED; }
        let eph = mat[..56];
        let n: i64 = mat[56];
        if 57 + n != mat.len { return ERR_MALFORMED; }
        let sh, ok = bignum::x448_shared(k.scalar, eph);
        if !ok { return ERR_DECRYPT; }
        let kek = x448_kek(eph, k.point, sh);
        let m, oku = bignum::aes_key_unwrap(kek, mat[57 + c..]);
        if !oku { return ERR_DECRYPT; }
        if !v6 { out.push(mat[57]); }
        out.append(m);
        return OK;
    }
    if k.algo == PK_MLKEM768_X25519 {
        // ecdhCT (32) || mlkemCT || size || (v3: cipher) || wrapped key.
        let c = if v6 { 0 } else { 1 };
        let at = 32 + MLKEM768_CT_LEN;
        if mat.len < at + 1 + c + 16 { return ERR_MALFORMED; }
        let n: i64 = mat[at];
        if at + 1 + n != mat.len { return ERR_MALFORMED; }
        let sym: i64 = mat[at + 1];
        if !v6 && !is_aes(sym) { return ERR_DECRYPT; }
        let eph = mat[..32];
        let ct = mat[32..at];
        let sh, ok = bignum::x25519_shared(k.scalar, eph);
        if !ok { return ERR_DECRYPT; }
        let ss, okd = mlkem_decaps_key(k, ct);
        if !okd { return ERR_DECRYPT; }
        let kek = ietf_kek(ss, sh, eph, k.point, k.algo);
        let m, oku = bignum::aes_key_unwrap(kek, mat[at + 1 + c..]);
        if !oku { return ERR_DECRYPT; }
        if !v6 { out.push(mat[at + 1]); }
        out.append(m);
        return OK;
    }
    if k.algo == PK_KYBER {
        // gpg's: SOS(ecdhCT), mlkemCT with a 4-octet length, the cipher,
        // then the wrapped key with its 1-octet length. v3 only.
        if v6 || k.curve == CURVE_NONE { return ERR_UNSUPPORTED; }
        let s, e, next, okm = read_mpi(mat, 0);
        if !okm || next + 4 > mat.len { return ERR_MALFORMED; }
        let eph, oke = ecc_octets(k.curve, mat[s..e]);
        if !oke { return ERR_MALFORMED; }
        let ctn = bignum::mlkem_ct_len(mlkem_level(k));
        if be32(mat, next) != ctn { return ERR_MALFORMED; }
        let at = next + 4 + ctn;
        if at + 2 > mat.len { return ERR_MALFORMED; }
        let ct = mat[next + 4..at];
        let cipher: i64 = mat[at];
        let n:      i64 = mat[at + 1];
        if at + 2 + n != mat.len || n < 24 { return ERR_MALFORMED; }
        let sh, ok = kem_ecc_shared(k.curve, k.scalar, eph);
        if !ok { return ERR_DECRYPT; }
        let ss, okd = mlkem_decaps_key(k, ct);
        if !okd { return ERR_DECRYPT; }
        let kek = librepgp_kek(sh, eph, k.point, ss, ct, cipher, k.fpr, kem_ecc_bits(k.curve));
        let m, oku = bignum::aes_key_unwrap(kek, mat[at + 2..]);
        if !oku { return ERR_DECRYPT; }
        out.push(cipher as! u8);
        out.append(m);
        return OK;
    }
    return ERR_UNSUPPORTED;
}

// The algorithm fields of a PKESK v3 that gives this key the session key
// (cipher octet || key || checksum, from encode_session; for X25519 the
// cipher goes in the clear and the checksum is dropped).
fn encrypt_session(k: const Key&, m: const u8[:], out: u8[>..]&) -> i64 {
    if is_rsa(k.algo) {
        if k.algo == PK_RSA_S { return ERR_KEY; }
        let pub, ok = rsa_pub(k);
        if !ok { return ERR_UNSUPPORTED; }
        if m.len > bignum::rsa_size(pub) - 11 { return ERR_KEY; }
        let c = bignum::rsa_encrypt_pkcs1(pub, m);
        put_mpi(out, c);
        return OK;
    }
    if k.algo == PK_ECDH {
        var eph: u8[>..] = [];
        var z:   u8[>..] = [];
        if k.curve == CURVE_X25519 {
            let sk, pk = bignum::x25519_keypair();
            let sh, ok = bignum::x25519_shared(sk, k.point);
            if !ok { return ERR_KEY; }
            eph.push(0x40);
            eph.append(pk);
            z.append(sh);
        } else if k.curve == CURVE_X448 {
            let sk, pk = bignum::x448_keypair();
            let sh, ok = bignum::x448_shared(sk, k.point);
            if !ok { return ERR_KEY; }
            eph.append(pk);
            z.append(sh);
        } else if is_weierstrass(k.curve) {
            let c = weierstrass_curve(k.curve);
            let sk, pk = bignum::ec_keypair(c);
            let sh, ok = bignum::ecdh_shared(c, sk, k.point);
            if !ok { return ERR_KEY; }
            eph.append(pk);
            z.append(sh);
        } else {
            return ERR_UNSUPPORTED;
        }
        let kek, err = ecdh_kek(k, z);
        if err != OK { return err; }
        var padded: u8[>..] = [];
        padded.append(m);
        let padn = 8 - padded.len % 8;
        for i in padn { padded.push(padn as! u8); }
        let w, okw = bignum::aes_key_wrap(kek, padded);
        if !okw { return ERR_KEY; }
        // X448's native octets go whole, as gpg writes them (an SOS).
        if k.curve == CURVE_X448 { put_sos(out, eph); } else { put_mpi(out, eph); }
        out.push(w.len as! u8);
        out.append(w);
        return OK;
    }
    if k.algo == PK_X25519 {
        let sk, pk = bignum::x25519_keypair();
        let sh, ok = bignum::x25519_shared(sk, k.point);
        if !ok { return ERR_KEY; }
        let kek = x25519_kek(pk, k.point, sh);
        let key = m[1..m.len - 2];
        let w, okw = bignum::aes_key_wrap(kek, key);
        if !okw { return ERR_KEY; }
        out.append(pk);
        out.push((1 + w.len) as! u8);
        out.push(m[0]);
        out.append(w);
        return OK;
    }
    if k.algo == PK_X448 {
        let sk, pk = bignum::x448_keypair();
        let sh, ok = bignum::x448_shared(sk, k.point);
        if !ok { return ERR_KEY; }
        let kek = x448_kek(pk, k.point, sh);
        let key = m[1..m.len - 2];
        let w, okw = bignum::aes_key_wrap(kek, key);
        if !okw { return ERR_KEY; }
        out.append(pk);
        out.push((1 + w.len) as! u8);
        out.push(m[0]);
        out.append(w);
        return OK;
    }
    if k.algo == PK_MLKEM768_X25519 || k.algo == PK_KYBER {
        if k.algo == PK_KYBER && k.curve == CURVE_NONE { return ERR_UNSUPPORTED; }
        if k.algo == PK_MLKEM768_X25519 && (k.point.len != 32 || k.pq_len != MLKEM768_EK_LEN) { return ERR_UNSUPPORTED; }
        let cipher: i64 = m[0];
        // RFC 9980 §4.3.1: AES only, in a v3 PKESK.
        if k.algo == PK_MLKEM768_X25519 && !is_aes(cipher) { return ERR_UNSUPPORTED; }
        let curve = if k.algo == PK_KYBER { k.curve } else { CURVE_X25519 };
        let sk, pk = kem_ecc_keypair(curve);
        let sh, ok = kem_ecc_shared(curve, sk, k.point);
        if !ok { return ERR_KEY; }
        let ss, ct, oke = bignum::mlkem_encaps(mlkem_level(k), pq_pub(k));
        if !oke { return ERR_KEY; }
        let key = m[1..m.len - 2];
        var kek: u8[>..] = [];
        if k.algo == PK_KYBER { kek = librepgp_kek(sh, pk, k.point, ss, ct, cipher, k.fpr, kem_ecc_bits(curve)); }
        else { kek = ietf_kek(ss, sh, pk, k.point, k.algo); }
        let w, okw = bignum::aes_key_wrap(kek, key);
        if !okw { return ERR_KEY; }
        if k.algo == PK_KYBER {
            // As gpg's do_encrypt_kem and do_pubkey_enc write it.
            put_sos(out, pk);
            put32(out, ct.len);
            out.append(ct);
            out.push(m[0]);
            out.push(w.len as! u8);
            out.append(w);
            return OK;
        }
        out.append(pk);
        out.append(ct);
        out.push((1 + w.len) as! u8);
        out.push(m[0]);
        out.append(w);
        return OK;
    }
    return ERR_UNSUPPORTED;
}

// cipher || key || checksum (the sum of the key's octets, mod 2^16).
fn encode_session(cipher: i64, key: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    m.push(cipher as! u8);
    m.append(key);
    var sum: i64 = 0;
    for b in key { sum += b; }
    put16(m, sum & 0xffff);
    return m;
}

// The cipher and key of a decrypted session key; ERR_DECRYPT unless the
// cipher is known, the key its size and the checksum right. X25519's and
// the composite KEMs' have no checksum (with_sum false).
fn decode_session(m: const u8[:], key: u8[>..]&, with_sum: bool = true) -> i64, i64 {
    if m.len < 1 { return 0, ERR_DECRYPT; }
    let cipher: i64 = m[0];
    let ks = cipher_key_size(cipher);
    let extra = if with_sum { 2 } else { 0 };
    if ks == 0 || m.len != 1 + ks + extra { return cipher, ERR_DECRYPT; }
    if with_sum {
        var sum: i64 = 0;
        for i in ks { sum += m[1 + i]; }
        if (sum & 0xffff) != be16(m, 1 + ks) { return cipher, ERR_DECRYPT; }
    }
    key.append(m[1..1 + ks]);
    return cipher, OK;
}

// The key of a session key from a v6 PKESK (no cipher octet: the encrypted
// data says which), checked against its checksum when it has one.
fn decode_session_v6(m: const u8[:], key: u8[>..]&, with_sum: bool) -> i64 {
    let extra = if with_sum { 2 } else { 0 };
    let ks = m.len - extra;
    if ks != 16 && ks != 24 && ks != 32 { return ERR_DECRYPT; }
    if with_sum {
        var sum: i64 = 0;
        for i in ks { sum += m[i]; }
        if (sum & 0xffff) != be16(m, ks) { return ERR_DECRYPT; }
    }
    key.append(m[..ks]);
    return OK;
}
