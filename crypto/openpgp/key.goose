// openpgp.key: one key (RFC 9580 §5.5): a public or secret key or subkey
// packet, version 4 or 6; its fingerprint and key ID; unlocking a secret
// key that a passphrase protects; and the operations of its algorithm:
// signing and verifying a digest, wrapping and unwrapping a session key.
//
//   RSA (1, 2, 3)          PKCS #1 v1.5 signatures and encryption
//   EdDSALegacy (22)       Ed25519 under its legacy OID, as gpg writes it
//   Ed25519 (27)           RFC 9580's own
//   ECDH (18)              Curve25519 (legacy OID) and P-256/384/521: the
//                          RFC 6637 KDF and AES key wrap
//   X25519 (25)            RFC 9580's: HKDF-SHA256 and AES-128 key wrap
//   ECDSA (19)             P-256, P-384, P-521
//
// DSA, ElGamal and the 448 curves parse (their keys list and fingerprint)
// but fail with ERR_UNSUPPORTED when used.
//
// A Key is fixed-size, so a keyring can hold an array of them: its numbers
// are in bounded arrays sized for RSA-8192.

namespace openpgp;

import std;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.ed25519;
import crypto.bignum.x25519;
import crypto.bignum.keywrap;
import crypto.bignum.hmac;
import crypto.bignum.sha1;
import crypto.openpgp;
import crypto.openpgp.packet;
import crypto.openpgp.ocb;

// Key flags (§5.2.3.29), as bits of Key.flags.
let FLAG_CERTIFY:         u32 = 0x01;
let FLAG_SIGN:            u32 = 0x02;
let FLAG_ENCRYPT_COMMS:   u32 = 0x04;
let FLAG_ENCRYPT_STORAGE: u32 = 0x08;
let FLAG_AUTH:            u32 = 0x20;
let FLAG_ENCRYPT:         u32 = 0x0C;

struct Key {
    version: i64        = 0,         // 4 or 6
    algo:    i64        = 0,
    created: i64        = 0,         // seconds since 1970
    subkey:  bool       = false,
    body:    u8[..1200] = [],        // the public key packet's body, as hashed and exported
    fpr:     u8[..32]   = [],        // 20 bytes (v4) or 32 (v6)
    keyid:   u8[8]      = [0; 8],
    // Public material.
    curve:    i64        = CURVE_NONE,
    n:        u8[..1024] = [], e: u8[..8] = [],  // RSA
    point:    u8[..133]  = [],       // EC: 32 bytes for the 25519 keys (no 0x40), else 04 || x || y
    kdf_hash: i64        = 0, kdf_cipher: i64 = 0, // ECDH
    // Secret material.
    has_secret: bool       = false,  // a secret key packet, its material maybe still locked
    locked:     bool       = false,  // protected by a passphrase and not yet unlocked
    stub:       bool       = false,  // gpg's gnu-dummy: no secret here at all
    sec_raw:    u8[..2800] = [],     // what followed the public part in the secret packet
    d:          u8[..1024] = [], p: u8[..512] = [], q: u8[..512] = [], u: u8[..512] = [], // RSA
    scalar:     u8[..66]   = [],     // EC: the seed (EdDSA), little-endian scalar (X25519), or big-endian scalar
    // Set by the keyring.
    primary:   i64  = -1,            // the index of this key's primary in the keyring
    flags:     u32  = 0,
    has_flags: bool = false,
    expires:   i64  = 0,             // seconds after creation; 0 never
    revoked:   bool = false,
    valid:     bool = false,         // a primary with a valid self-signature, a subkey with a valid binding
    bound_at:  i64  = 0,             // the creation time of the binding that counts
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
    return "unknown";
}

fn curve_name(c: i64) -> const u8[:] {
    if c == CURVE_ED25519 { return "ed25519"; }
    if c == CURVE_X25519 { return "cv25519"; }
    if c == CURVE_P256 { return "nistp256"; }
    if c == CURVE_P384 { return "nistp384"; }
    if c == CURVE_P521 { return "nistp521"; }
    return "";
}

// "rsa3072", "ed25519", "cv25519", "nistp256", as gpg lists keys.
fn key_type_name(k: const Key&) -> u8[>..] {
    if is_rsa(k.algo) { return str("rsa", rsa_key_bits(k)); }
    if k.algo == PK_ED25519 { return str("ed25519"); }
    if k.algo == PK_X25519 { return str("cv25519"); }
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
}

fn can_encrypt_algo(algo: i64) -> bool {
    algo == PK_RSA || algo == PK_RSA_E || algo == PK_ECDH || algo == PK_X25519
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
        // An EdDSALegacy key on another curve, or ECDH on Ed25519's, is not one.
        if k.algo == PK_EDDSA && k.curve != CURVE_ED25519 && k.curve != CURVE_NONE { k.curve = CURVE_NONE; }
        if k.algo == PK_ECDH && k.curve == CURVE_ED25519 { k.curve = CURVE_NONE; }
        if k.algo == PK_ECDSA && !is_nist(k.curve) { k.curve = CURVE_NONE; }
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
        return p + n, OK;
    }
    return p, ERR_UNSUPPORTED;
}

// The fingerprint and key ID of k.body.
fn set_fingerprint(k: Key&) {
    k.fpr.clear();
    if k.version == 6 {
        var pre: u8[>..] = [];
        pre.push(0x9B);
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
    if k.version != 4 && k.version != 6 { return k, ERR_UNSUPPORTED; }
    k.created = be32(body, 1);
    k.algo = body[5];
    var p = 6;
    var mat_end = body.len;
    if k.version == 6 {
        if body.len < 10 { return k, ERR_MALFORMED; }
        let ml = be32(body, 6);
        p = 10;
        if ml > body.len - 10 { return k, ERR_MALFORMED; }
        mat_end = 10 + ml;
    }
    let end, err = parse_public_material(k, body[..mat_end], p);
    if err != OK { return k, err; }
    if k.version == 6 && end != mat_end { return k, ERR_MALFORMED; }
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
        let e2 = read_secret_material(k, k.sec_raw[1..], k.version == 4);
        return k, e2;
    }
    // Protected: check that the S2K parses, so a stub is known now.
    let s2k, iv_at, e3 = protection_of(k);
    if e3 != OK && e3 != ERR_UNSUPPORTED { return k, e3; }
    if e3 == OK && s2k.kind == S2K_GNU_DUMMY { k.stub = true; return k, OK; }
    k.locked = true;
    return k, OK;
}

// The protection of a locked secret: its S2K and where its IV starts in
// sec_raw. usage 254 and 255 (v4 and v6) and 253 (AEAD, v6).
fn protection_of(k: const Key&) -> S2k, i64, i64 {
    let raw = k.sec_raw[..];
    var none = S2k { .. };
    if raw.len < 2 { return none, 0, ERR_MALFORMED; }
    let usage: i64 = raw[0];
    if usage != 254 && usage != 255 && usage != 253 { return none, 0, ERR_UNSUPPORTED; }
    var p = 1;
    if k.version == 6 { p++; }       // the count of the fields that follow
    p++;                              // the cipher
    if usage == 253 { p++; }          // the AEAD mode
    if k.version == 6 { p++; }       // the S2K's length
    let s, next, err = read_s2k(raw, p);
    return s, next, err;
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
        let v = strip_zeros(data[s..e]);
        let size = if k.curve == CURVE_ED25519 || k.curve == CURVE_X25519 { 32 } else { curve_size(k.curve) };
        if v.len > size || k.curve == CURVE_NONE { return ERR_MALFORMED; }
        var full: u8[>..] = [];
        pad_left(full, v, size);
        k.scalar.clear();
        // Curve25519's secret is stored big-endian: X25519 takes it the other way round.
        if k.curve == CURVE_X25519 { k.scalar.append(reversed(full)); } else { k.scalar.append(full); }
        p = next;
    } else if k.algo == PK_X25519 || k.algo == PK_ED25519 {
        if data.len < 32 { return ERR_MALFORMED; }
        k.scalar.clear();
        k.scalar.append(data[..32]);
        p = 32;
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
    if k.algo == PK_EDDSA || k.algo == PK_ED25519 {
        let pub = bignum::ed25519_public(k.scalar);
        return if pub[..] == k.point[..] { OK } else { ERR_KEY };
    }
    if k.curve == CURVE_X25519 || k.algo == PK_X25519 {
        let pub = bignum::x25519_base(k.scalar);
        return if pub[..] == k.point[..] { OK } else { ERR_KEY };
    }
    if is_nist(k.curve) {
        let c = nist_curve(k.curve);
        let sk, ok = bignum::ec_scalar(c, k.scalar);
        if !ok { return ERR_KEY; }
        let pub = bignum::ec_public_key(c, k.scalar);
        return if pub == k.point[..] { OK } else { ERR_KEY };
    }
    return ERR_UNSUPPORTED;
}

// Decrypts a locked secret with a passphrase. ERR_PASSPHRASE when the
// checksum (SHA-1 for usage 254) does not match.
fn unlock_key(k: Key&, pass: const u8[:]) -> i64 {
    if !k.has_secret || k.stub { return ERR_KEY; }
    if !k.locked { return OK; }
    let raw = k.sec_raw[..];
    let usage: i64 = raw[0];
    let s2k, iv_at, err = protection_of(k);
    if err != OK { return err; }
    let cipher: i64 = raw[if k.version == 6 { 2 } else { 1 }];
    let ks = cipher_key_size(cipher);
    if ks == 0 { return ERR_UNSUPPORTED; }
    let key, e2 = s2k_key(s2k, pass, ks);
    if e2 != OK { return e2; }
    if usage == 253 { return unlock_aead(k, key, cipher, iv_at); }
    let bs = cipher_block_size(cipher);
    if iv_at + bs > raw.len { return ERR_MALFORMED; }
    let iv = raw[iv_at..iv_at + bs];
    var data: u8[>..] = [];
    data.append(raw[iv_at + bs..]);
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
    let aead: i64 = raw[if k.version == 6 { 3 } else { 2 }];
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
    } else if k.algo == PK_X25519 || k.algo == PK_ED25519 {
        out.append(k.scalar);
    } else if k.curve == CURVE_X25519 {
        put_mpi(out, reversed(k.scalar));
    } else {
        put_mpi(out, k.scalar);
    }
    if k.version == 4 {
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
        if k.curve != CURVE_ED25519 { return ERR_UNSUPPORTED; }
        let rs, n, ok = two_mpis(sig, 32);
        if !ok || n != sig.len { return ERR_MALFORMED; }
        return if bignum::ed25519_verify(k.point, dg, rs) { OK } else { ERR_BAD_SIGNATURE };
    }
    if k.algo == PK_ED25519 {
        if sig.len != 64 { return ERR_MALFORMED; }
        return if bignum::ed25519_verify(k.point, dg, sig) { OK } else { ERR_BAD_SIGNATURE };
    }
    if k.algo == PK_ECDSA {
        if !is_nist(k.curve) { return ERR_UNSUPPORTED; }
        let c = nist_curve(k.curve);
        let rs, n, ok = two_mpis(sig, curve_size(k.curve));
        if !ok || n != sig.len { return ERR_MALFORMED; }
        return if bignum::ecdsa_verify_digest(c, k.point, dg, rs) { OK } else { ERR_BAD_SIGNATURE };
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
    if k.algo == PK_EDDSA || k.algo == PK_ED25519 {
        if k.algo == PK_EDDSA && k.curve != CURVE_ED25519 { return ERR_UNSUPPORTED; }
        let s = bignum::ed25519_sign(k.scalar, dg);
        if k.algo == PK_ED25519 { out.append(s); return OK; }
        put_mpi(out, s[..32]);
        put_mpi(out, s[32..]);
        return OK;
    }
    if k.algo == PK_ECDSA {
        if !is_nist(k.curve) { return ERR_UNSUPPORTED; }
        let c = nist_curve(k.curve);
        let bits = hash_bits(hash);
        if bits <= 0 { return ERR_UNSUPPORTED; }
        let s = bignum::ecdsa_sign_digest(c, k.scalar, dg, bits);
        let n = curve_size(k.curve);
        put_mpi(out, s[..n]);
        put_mpi(out, s[n..]);
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

// The session key a PKESK v3 for this key holds: mat is the algorithm's
// fields. The result is the cipher octet, the key, and (but for X25519)
// its 2-octet checksum, as the sender wrapped it; decode_session splits it.
fn decrypt_session(k: const Key&, mat: const u8[:], out: u8[>..]&) -> i64 {
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
        } else if is_nist(k.curve) {
            let c = nist_curve(k.curve);
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
        if mat.len < 34 { return ERR_MALFORMED; }
        let eph = mat[..32];
        let n: i64 = mat[32];
        if 33 + n != mat.len || n < 1 { return ERR_MALFORMED; }
        let sh, ok = bignum::x25519_shared(k.scalar, eph);
        if !ok { return ERR_DECRYPT; }
        let kek = x25519_kek(eph, k.point, sh);
        // v3: the cipher octet in the clear, then the wrapped key.
        let m, oku = bignum::aes_key_unwrap(kek, mat[34..]);
        if !oku { return ERR_DECRYPT; }
        out.push(mat[33]);
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
        } else if is_nist(k.curve) {
            let c = nist_curve(k.curve);
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
        put_mpi(out, eph);
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
// cipher is known, the key its size and the checksum right. X25519's has
// no checksum (with_sum false).
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
