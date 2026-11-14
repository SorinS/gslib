// openpgp.sig: signature packets (RFC 9580 §5.2), versions 4 and 6: their
// subpackets, what each type of signature hashes, and making and checking
// one with a key.
//
//   let s, err = openpgp::parse_signature(body);
//   let err = openpgp::verify_signature(key, s, data);   // data as the type hashes it
//   var p = openpgp::SigParams { sigtype: openpgp::SIG_BINARY, .. };
//   let err = openpgp::make_signature(key, p, data, out); // a whole packet
//
// A signature whose hashed area holds a critical subpacket this package
// does not know is refused (ERR_UNSUPPORTED), as §5.2.3.7 requires; other
// unknown subpackets, notations among them, are skipped.

namespace openpgp;

import std;
import os;
import crypto.openpgp;
import crypto.openpgp.packet;
import crypto.openpgp.key;

// Signature types.
let SIG_BINARY:            i64 = 0x00;
let SIG_TEXT:              i64 = 0x01;
let SIG_STANDALONE:        i64 = 0x02;
let SIG_CERT_GENERIC:      i64 = 0x10;
let SIG_CERT_PERSONA:      i64 = 0x11;
let SIG_CERT_CASUAL:       i64 = 0x12;
let SIG_CERT_POSITIVE:     i64 = 0x13;
let SIG_SUBKEY_BINDING:    i64 = 0x18;
let SIG_PRIMARY_BINDING:   i64 = 0x19;
let SIG_DIRECT_KEY:        i64 = 0x1F;
let SIG_KEY_REVOCATION:    i64 = 0x20;
let SIG_SUBKEY_REVOCATION: i64 = 0x28;
let SIG_CERT_REVOCATION:   i64 = 0x30;

// Subpacket types.
let SP_CREATED:           i64 = 2;
let SP_SIG_EXPIRES:       i64 = 3;
let SP_EXPORTABLE:        i64 = 4;
let SP_TRUST:             i64 = 5;
let SP_REGEX:             i64 = 6;
let SP_REVOCABLE:         i64 = 7;
let SP_KEY_EXPIRES:       i64 = 9;
let SP_PREF_CIPHERS:      i64 = 11;
let SP_REVOCATION_KEY:    i64 = 12;
let SP_ISSUER:            i64 = 16;
let SP_NOTATION:          i64 = 20;
let SP_PREF_HASHES:       i64 = 21;
let SP_PREF_COMPRESSION:  i64 = 22;
let SP_KEYSERVER_PREFS:   i64 = 23;
let SP_PREF_KEYSERVER:    i64 = 24;
let SP_PRIMARY_UID:       i64 = 25;
let SP_POLICY_URI:        i64 = 26;
let SP_KEY_FLAGS:         i64 = 27;
let SP_SIGNER_UID:        i64 = 28;
let SP_REVOCATION_REASON: i64 = 29;
let SP_FEATURES:          i64 = 30;
let SP_TARGET:            i64 = 31;
let SP_EMBEDDED:          i64 = 32;
let SP_ISSUER_FPR:        i64 = 33;
let SP_PREF_AEAD:         i64 = 34;  // LibrePGP's
let SP_RECIPIENT_FPR:     i64 = 35;
let SP_PREF_AEAD_SUITES:  i64 = 39;

fn sig_type_name(t: i64) -> const u8[:] {
    if t == SIG_BINARY { return "binary"; }
    if t == SIG_TEXT { return "text"; }
    if t == SIG_STANDALONE { return "standalone"; }
    if t >= SIG_CERT_GENERIC && t <= SIG_CERT_POSITIVE { return "certification"; }
    if t == SIG_SUBKEY_BINDING { return "subkey binding"; }
    if t == SIG_PRIMARY_BINDING { return "primary key binding"; }
    if t == SIG_DIRECT_KEY { return "direct key"; }
    if t == SIG_KEY_REVOCATION { return "key revocation"; }
    if t == SIG_SUBKEY_REVOCATION { return "subkey revocation"; }
    if t == SIG_CERT_REVOCATION { return "certification revocation"; }
    return "unknown";
}

struct Signature {
    version: i64        = 0,
    sigtype: i64        = 0,
    pk_algo: i64        = 0,
    hash:    i64        = 0,
    hashed:  u8[..4096] = [],        // the hashed subpacket area, as it is hashed
    left16:  u8[2]      = [0; 2],
    salt:    u8[..32]   = [],        // v6
    mat:     u8[..1100] = [],        // the signature material
    // From the subpackets (issuer data from either area, the rest hashed only).
    created:          i64        = 0,
    expires:          i64        = 0, // seconds after created; 0 never
    key_expires:      i64        = 0, // seconds after the key's creation; 0 never
    has_issuer:       bool       = false,
    issuer:           u8[8]      = [0; 8],
    issuer_fpr:       u8[..32]   = [],
    has_flags:        bool       = false,
    flags:            u32        = 0,
    primary_uid:      bool       = false,
    revocable:        bool       = true,
    exportable:       bool       = true,
    unknown_critical: bool       = false,
    features:         u8         = 0,
    pref_ciphers:     u8[..16]   = [],
    pref_hashes:      u8[..16]   = [],
    pref_compression: u8[..8]    = [],
    pref_aead:        u8[..16]   = [],
    signer_uid:       u8[..256]  = [],
    embedded:         u8[..1400] = [], // an embedded signature (a back-signature) packet body
}

// A subpacket length: one, two or five octets.
fn sub_length(data: const u8[:], at: i64) -> i64, i64, bool {
    if at >= data.len { return 0, at, false; }
    let a: i64 = data[at];
    if a < 192 { return a, at + 1, true; }
    if a < 255 {
        if at + 2 > data.len { return 0, at, false; }
        return ((a - 192) << 8) + data[at + 1] + 192, at + 2, true;
    }
    if at + 5 > data.len { return 0, at, false; }
    return be32(data, at + 1), at + 5, true;
}

fn sub_fits<A>(dst: A&, v: const u8[:]) {
    dst.clear();
    dst.append(v[.. ::min(v.len, dst.cap)]);
}

// Reads one subpacket area into s. In the unhashed area only the issuer
// data counts (it is not signed, so it only says which key to try).
fn read_subpackets(s: Signature&, area: const u8[:], hashed: bool) -> i64 {
    var p = 0;
    var has_created = false;
    while p < area.len {
        let len, h, ok = sub_length(area, p);
        if !ok || len < 1 || len > area.len - h { return ERR_MALFORMED; }
        let typ: i64 = area[h] & 0x7f;
        let critical = area[h] & 0x80 != 0;
        let v = area[h + 1..h + len];
        p = h + len;
        if typ == SP_ISSUER {
            if v.len != 8 { return ERR_MALFORMED; }
            if !s.has_issuer || hashed { for i in 8 { s.issuer[i] = v[i]; } }
            s.has_issuer = true;
            continue;
        }
        if typ == SP_ISSUER_FPR {
            if v.len < 1 || v.len - 1 > 32 { return ERR_MALFORMED; }
            if s.issuer_fpr.len == 0 || hashed { s.issuer_fpr.clear(); s.issuer_fpr.append(v[1..]); }
            continue;
        }
        if typ == SP_EMBEDDED {
            if v.len > s.embedded.cap { return ERR_UNSUPPORTED; }
            s.embedded.clear();
            s.embedded.append(v);
            continue;
        }
        if !hashed { continue; }
        if typ == SP_CREATED {
            if v.len != 4 { return ERR_MALFORMED; }
            s.created = be32(v, 0);
            has_created = true;
        } else if typ == SP_SIG_EXPIRES {
            if v.len != 4 { return ERR_MALFORMED; }
            s.expires = be32(v, 0);
        } else if typ == SP_KEY_EXPIRES {
            if v.len != 4 { return ERR_MALFORMED; }
            s.key_expires = be32(v, 0);
        } else if typ == SP_KEY_FLAGS {
            s.has_flags = true;
            s.flags = 0;
            if v.len > 0 { s.flags = v[0]; }
            if v.len > 1 { s.flags |= (v[1] as u32) << 8; }
        } else if typ == SP_PRIMARY_UID {
            s.primary_uid = v.len > 0 && v[0] != 0;
        } else if typ == SP_REVOCABLE {
            s.revocable = v.len > 0 && v[0] != 0;
        } else if typ == SP_EXPORTABLE {
            s.exportable = v.len > 0 && v[0] != 0;
        } else if typ == SP_FEATURES {
            if v.len > 0 { s.features = v[0]; }
        } else if typ == SP_PREF_CIPHERS {
            sub_fits(s.pref_ciphers, v);
        } else if typ == SP_PREF_HASHES {
            sub_fits(s.pref_hashes, v);
        } else if typ == SP_PREF_COMPRESSION {
            sub_fits(s.pref_compression, v);
        } else if typ == SP_PREF_AEAD || typ == SP_PREF_AEAD_SUITES {
            sub_fits(s.pref_aead, v);
        } else if typ == SP_SIGNER_UID {
            sub_fits(s.signer_uid, v);
        } else if typ == SP_NOTATION {
            // A critical notation is one this package cannot know: human-
            // readable or not, its meaning is the sender's.
            if critical { s.unknown_critical = true; }
        } else if typ == SP_TRUST || typ == SP_REGEX || typ == SP_REVOCATION_KEY || typ == SP_KEYSERVER_PREFS
                  || typ == SP_PREF_KEYSERVER || typ == SP_POLICY_URI || typ == SP_REVOCATION_REASON
                  || typ == SP_TARGET || typ == SP_RECIPIENT_FPR {
            // Known, and nothing here depends on them.
        } else if critical {
            s.unknown_critical = true;
        }
    }
    if hashed && !has_created { return ERR_MALFORMED; }
    return OK;
}

// A signature packet's body.
fn parse_signature(body: const u8[:]) -> Signature, i64 {
    var s = Signature { .. };
    if body.len < 1 { return s, ERR_MALFORMED; }
    s.version = body[0];
    if s.version != 4 && s.version != 6 { return s, ERR_UNSUPPORTED; }
    let lw = if s.version == 6 { 4 } else { 2 };
    if body.len < 4 + lw { return s, ERR_MALFORMED; }
    s.sigtype = body[1];
    s.pk_algo = body[2];
    s.hash = body[3];
    var p = 4;
    let hl = if lw == 4 { be32(body, p) } else { be16(body, p) };
    p += lw;
    if hl > body.len - p { return s, ERR_MALFORMED; }
    if hl > s.hashed.cap { return s, ERR_UNSUPPORTED; }
    s.hashed.append(body[p..p + hl]);
    p += hl;
    if p + lw > body.len { return s, ERR_MALFORMED; }
    let ul = if lw == 4 { be32(body, p) } else { be16(body, p) };
    p += lw;
    if ul > body.len - p { return s, ERR_MALFORMED; }
    let unhashed = body[p..p + ul];
    p += ul;
    if p + 2 > body.len { return s, ERR_MALFORMED; }
    s.left16[0] = body[p];
    s.left16[1] = body[p + 1];
    p += 2;
    if s.version == 6 {
        if p >= body.len { return s, ERR_MALFORMED; }
        let sl: i64 = body[p];
        if sl > 32 || p + 1 + sl > body.len { return s, ERR_MALFORMED; }
        s.salt.append(body[p + 1..p + 1 + sl]);
        p += 1 + sl;
    }
    if body.len - p > s.mat.cap { return s, ERR_UNSUPPORTED; }
    s.mat.append(body[p..]);
    let e1 = read_subpackets(s, s.hashed, true);
    if e1 != OK { return s, e1; }
    let e2 = read_subpackets(s, unhashed, false);
    if e2 != OK { return s, e2; }
    // A v6 signature's salt is as long as its hash says (§5.2.3).
    if s.version == 6 && s.salt.len != salt_size(s.hash) { return s, ERR_MALFORMED; }
    return s, OK;
}

// RFC 9580 §9.5: the salt of a v6 signature by hash.
fn salt_size(hash: i64) -> i64 {
    if hash == HASH_SHA256 || hash == HASH_SHA224 || hash == HASH_SHA3_256 { return 16; }
    if hash == HASH_SHA384 { return 24; }
    if hash == HASH_SHA512 || hash == HASH_SHA3_512 { return 32; }
    return 0;
}

// The trailer a signature hashes after its data.
fn sig_trailer(s: const Signature&) -> u8[>..] {
    var t: u8[>..] = [];
    t.push(s.version as! u8);
    t.push(s.sigtype as! u8);
    t.push(s.pk_algo as! u8);
    t.push(s.hash as! u8);
    if s.version == 6 { put32(t, s.hashed.len); } else { put16(t, s.hashed.len); }
    t.append(s.hashed);
    let n = t.len;
    t.push(s.version as! u8);
    t.push(0xFF);
    put32(t, n);
    return t;
}

// The digest a signature signs over data (its salt, data, trailer).
fn sig_digest(s: const Signature&, data: const u8[:]) -> u8[>..] {
    let t = sig_trailer(s);
    return digest3(s.hash, s.salt, data, t);
}

// What a key signature hashes of a key: 0x99 and a 2-octet length (v4),
// 0x9B and a 4-octet one (v6), then the public key packet's body.
fn put_key_hash(out: u8[>..]&, k: const Key&) {
    if k.version == 6 {
        out.push(0x9B);
        put32(out, k.body.len);
    } else {
        out.push(0x99);
        put16(out, k.body.len);
    }
    out.append(k.body);
}

// A user ID as a certification hashes it: 0xB4 and a 4-octet length.
fn put_uid_hash(out: u8[>..]&, uid: const u8[:]) {
    out.push(0xB4);
    put32(out, uid.len);
    out.append(uid);
}

// Whether the signature was made by k: its issuer fingerprint or key ID
// (neither: it may be, for a wildcard).
fn issued_by(s: const Signature&, k: const Key&) -> bool {
    if s.issuer_fpr.len > 0 { return s.issuer_fpr[..] == k.fpr[..]; }
    if s.has_issuer { return s.issuer == k.keyid; }
    return true;
}

// Checks s over data (prepared as its type hashes it) with key k: the
// algorithms agree, the hash is one this package takes, no critical
// subpacket is unknown, and the signature verifies.
fn verify_signature(k: const Key&, s: const Signature&, data: const u8[:]) -> i64 {
    if s.unknown_critical { return ERR_UNSUPPORTED; }
    if s.pk_algo != k.algo && !(is_rsa(s.pk_algo) && is_rsa(k.algo)) { return ERR_BAD_SIGNATURE; }
    if !hash_known(s.hash) || s.hash == HASH_MD5 { return ERR_UNSUPPORTED; }
    if s.version != k.version && (s.version == 6 || k.version == 6) { return ERR_BAD_SIGNATURE; }
    let dg = sig_digest(s, data);
    if dg[0] != s.left16[0] || dg[1] != s.left16[1] { return ERR_BAD_SIGNATURE; }
    return verify_digest(k, s.hash, dg, s.mat);
}

// --- Making signatures -------------------------------------------------------------

// What a new signature says. created 0 is now. The preferences go into
// self-signatures (prefs true): AES-256, AES-192, AES-128; SHA-512,
// SHA-384, SHA-256; ZLIB, ZIP, none; features: MDC (and v6 SEIPD).
struct SigParams {
    sigtype:     i64        = SIG_BINARY,
    hash:        i64        = HASH_SHA256,
    created:     i64        = 0,
    expires:     i64        = 0,     // signature lifetime, seconds; 0 never
    has_flags:   bool       = false,
    flags:       u32        = 0,
    key_expires: i64        = 0,
    primary_uid: bool       = false,
    prefs:       bool       = false,
    signer_uid:  u8[..256]  = [],
    embedded:    u8[..1400] = [],    // an embedded back-signature body
}

fn now() -> i64 { time_ns() / 1000000000 }

fn put_sub(out: u8[>..]&, typ: i64, v: const u8[:], critical: bool = false) {
    let n = v.len + 1;
    if n < 192 {
        out.push(n as! u8);
    } else if n < 16320 {
        let l = n - 192;
        out.push(((l >> 8) + 192) as! u8);
        out.push((l & 255) as! u8);
    } else {
        out.push(255);
        put32(out, n);
    }
    out.push((typ | (if critical { 0x80 } else { 0 })) as! u8);
    out.append(v);
}

fn be32_bytes(v: i64) -> u8[4] {
    return [(v >> 24 & 255) as! u8, (v >> 16 & 255) as! u8, (v >> 8 & 255) as! u8, (v & 255) as! u8];
}

// The hash a key signs with when asked for `hash`: ECDSA on P-384 and
// P-521 takes one at least as long as the curve (SHA-384, SHA-512), as gpg
// requires to verify it.
fn signing_hash(k: const Key&, hash: i64) -> i64 {
    if k.algo != PK_ECDSA { return hash; }
    let need = if k.curve == CURVE_P384 { 48 } else if k.curve == CURVE_P521 { 64 } else { 32 };
    if hash_size(hash) >= need { return hash; }
    return if need == 48 { HASH_SHA384 } else if need == 64 { HASH_SHA512 } else { HASH_SHA256 };
}

// A signature packet by key k over data (prepared as the type hashes it),
// appended to out. The hash is prm.hash, or a longer one when the key
// needs it (signing_hash).
fn make_signature(k: const Key&, prm: SigParams, data: const u8[:], out: u8[>..]&) -> i64 {
    if !can_sign_algo(k.algo) { return ERR_KEY; }
    let hash = signing_hash(k, prm.hash);
    if !hash_ok_for_signing(hash) { return ERR_UNSUPPORTED; }
    var s = Signature { .. };
    s.version = k.version;
    s.sigtype = prm.sigtype;
    s.pk_algo = k.algo;
    s.hash = hash;
    let created = if prm.created > 0 { prm.created } else { now() };
    var h:  u8[>..] = [];
    var fv: u8[>..] = [];
    fv.push(k.version as! u8);
    fv.append(k.fpr);
    put_sub(h, SP_ISSUER_FPR, fv);
    put_sub(h, SP_CREATED, be32_bytes(created));
    if prm.expires > 0 { put_sub(h, SP_SIG_EXPIRES, be32_bytes(prm.expires)); }
    if prm.has_flags {
        let f: u8[1] = [(prm.flags & 255) as! u8];
        put_sub(h, SP_KEY_FLAGS, f);
    }
    if prm.key_expires > 0 { put_sub(h, SP_KEY_EXPIRES, be32_bytes(prm.key_expires)); }
    if prm.primary_uid { put_sub(h, SP_PRIMARY_UID, "\x01"); }
    if prm.prefs {
        put_sub(h, SP_PREF_CIPHERS, "\x09\x08\x07");
        put_sub(h, SP_PREF_HASHES, "\x0a\x09\x08");
        put_sub(h, SP_PREF_COMPRESSION, "\x02\x01\x00");
        put_sub(h, SP_FEATURES, if k.version == 6 { "\x09" } else { "\x01" });
    }
    if prm.signer_uid.len > 0 { put_sub(h, SP_SIGNER_UID, prm.signer_uid); }
    if prm.embedded.len > 0 { put_sub(h, SP_EMBEDDED, prm.embedded); }
    if h.len > s.hashed.cap { return ERR_UNSUPPORTED; }
    s.hashed.append(h);
    if k.version == 6 { s.salt.append(random(salt_size(hash))); }
    let dg = sig_digest(s, data);
    var mat: u8[>..] = [];
    let err = sign_digest(k, hash, dg, mat);
    if err != OK { return err; }
    var b: u8[>..] = [];
    b.push(s.version as! u8);
    b.push(s.sigtype as! u8);
    b.push(s.pk_algo as! u8);
    b.push(s.hash as! u8);
    if k.version == 6 { put32(b, h.len); } else { put16(b, h.len); }
    b.append(h);
    // Unhashed: the issuer key ID (v4 only; v6 has the fingerprint).
    var u: u8[>..] = [];
    if k.version == 4 { put_sub(u, SP_ISSUER, k.keyid); }
    if k.version == 6 { put32(b, u.len); } else { put16(b, u.len); }
    b.append(u);
    b.push(dg[0]);
    b.push(dg[1]);
    if k.version == 6 {
        b.push(s.salt.len as! u8);
        b.append(s.salt);
    }
    b.append(mat);
    put_packet(out, TAG_SIGNATURE, b);
    return OK;
}

// A signature's body with the packet header stripped, from a packet that
// make_signature wrote (for embedding).
fn signature_body(packet: const u8[:]) -> const u8[:] {
    let p, err = next_packet(packet, 0);
    assert(err == OK);
    return packet[p.body..p.body_end];
}
