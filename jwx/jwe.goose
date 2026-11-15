// jwx.jwe: JSON Web Encryption (RFC 7516), compact and JSON (general and
// flattened, several recipients, additional authenticated data), with
// every key management algorithm of RFC 7518 §4 (RSA1_5, RSA-OAEP and
// its SHA-2 forms, A*KW, dir, ECDH-ES and ECDH-ES+A*KW on P-256, P-384,
// P-521, X25519 and X448, A*GCMKW, PBES2) and every content algorithm of §5
// (A*CBC-HS*, A*GCM), and "zip": "DEF".
//
//   let token, err = jwe::encrypt(plaintext, jwa::RSA_OAEP_256, jwa::A256GCM, public_key);
//   let plaintext, err = jwe::decrypt(token, jwa::RSA_OAEP_256, private_key);
//
// Decrypting takes the key management algorithm the caller expects; the
// content algorithm is the header's. Every failure to unwrap a key or open
// a ciphertext is ERR_DECRYPT, and RSA1_5 goes on with a random key when
// the padding is wrong (RFC 7516 §11.5), so no failure says more than that.

namespace jwe;

import std;
import json;
import jwx;
import jwx.jwa;
import jwx.jwk;
import jwx.jws;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.aes;
import crypto.bignum.gcm;
import crypto.bignum.modes;
import crypto.bignum.hmac;
import crypto.bignum.kdf;
import crypto.bignum.keywrap;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.x25519;
import crypto.bignum.x448;
import crypto.bignum.sha256;
import crypto.bignum.entropy;
import compress;
import compress.flate;
import compress.deflate;

// jwx v4's limits: the PBES2 counts accepted when decrypting, from RFC 7518
// §4.8.1.2's floor of 1000 to 1000000, and the most a "zip" payload may
// inflate to.
let MIN_P2C: i64 = 1000;
let MAX_P2C: i64 = 1000000;
let MAX_INFLATE: i64 = 10485760;
// The PBES2 counts used when encrypting, unless one is given: OWASP 2023's
// for PBKDF2, as jwx v4 has them (HS384 and HS512 need fewer for their
// longer output).
let DEFAULT_P2C_HS256: i64 = 600000;
let DEFAULT_P2C_HS384: i64 = 210000;
let DEFAULT_P2C_HS512: i64 = 210000;

// The PBES2 count used when encrypting with alg, unless one is given.
fn default_p2c(alg: i64) -> i64 {
    if alg == jwa::PBES2_HS384_A192KW { return DEFAULT_P2C_HS384; }
    if alg == jwa::PBES2_HS512_A256KW { return DEFAULT_P2C_HS512; }
    return DEFAULT_P2C_HS256;
}

// The header parameters of RFC 7516 §4.1 and RFC 7518 §4.6-4.8. Others go
// in `extra` when encrypting and are read with header_string.
struct Header {
    alg: i64 = jwa::UNKNOWN,
    enc: i64 = jwa::UNKNOWN,
    zip: bool = false,
    kid: u8[..256] = [],
    typ: u8[..128] = [],
    cty: u8[..128] = [],
    jku: u8[..512] = [],
    x5u: u8[..512] = [],
    x5t: u8[..20] = [],
    x5t256: u8[..32] = [],
    has_jwk: bool = false,
    jwk: jwk::Key = jwk::empty(),
    has_epk: bool = false,
    epk: jwk::Key = jwk::empty(),
    apu: u8[..256] = [],
    apv: u8[..256] = [],
    iv: u8[..12] = [],          // A*GCMKW's
    tag: u8[..16] = [],
    p2s: u8[..256] = [],
    p2c: i64 = 0,
    crit: u8[..256] = [],
}

// What encrypting would otherwise choose at random, for reproducing a
// message: the CEK, the content IV, the ephemeral ECDH-ES key (private),
// the A*GCMKW IV, and the PBES2 salt and count.
struct Options {
    cek: u8[..64] = [],
    iv: u8[..16] = [],
    has_epk: bool = false,
    epk: jwk::Key = jwk::empty(),
    kw_iv: u8[..12] = [],
    p2s: u8[..64] = [],
    p2c: i64 = 0,
}

// A recipient for encrypt_json: its key management algorithm and key, and
// header parameters of its own (kid, apu, ...) for its unprotected header.
struct Recipient {
    alg: i64,
    key: jwk::Key,
    header: Header = Header { .. },
}

// A recipient of a parsed message: its header (the protected header, the
// shared unprotected one and its own, together) and its encrypted key.
struct ParsedRecipient {
    header: Header,
    ek: u8[..1024],
}

// A parsed JWE. `text` holds the protected header's and the AAD's
// base64url text as they arrived.
root struct Message {
    text: u8[>..] = [],
    ciphertext: u8[>..] = [],
    recipients: ParsedRecipient[>..] = [],
    protected_len: i64 = 0,
    aad_at: i64 = 0,
    aad_len: i64 = -1,          // -1: no "aad"
    iv: u8[..16] = [],
    tag: u8[..32] = [],
    compact: bool = false,
}

// --- Content encryption (RFC 7518 §5) ------------------------------------------

// AL: the AAD's length in bits as a 64-bit big-endian integer (§5.2.2.1).
fn cbc_mac(hash: i64, mac_key: const u8[:], aad: const u8[:], iv: const u8[:], ct: const u8[:]) -> u8[>..] {
    var buf: u8[>..] = [];
    buf.append(aad);
    buf.append(iv);
    buf.append(ct);
    let bits = (aad.len * 8) as u64;
    for i in 8 { buf.push((bits >> (56 - 8 * i as u64)) as! u8); }
    return bignum::hmac(hash, mac_key, buf);
}

fn iv_len(enc: i64) -> i64 { if jwa::is_gcm(enc) { 12 } else { 16 } }

// The ciphertext and tag of pt under the CEK.
fn content_encrypt(enc: i64, cek: const u8[:], iv: const u8[:], aad: const u8[:], pt: const u8[:])
        -> u8[>..], u8[>..], i64 {
    var ct: u8[>..] = [];
    var tag: u8[>..] = [];
    if cek.len != jwa::cek_len(enc) || iv.len != iv_len(enc) { return ct, tag, jwx::ERR_KEY; }
    if jwa::is_gcm(enc) {
        let sealed = bignum::aes_gcm_seal(cek, iv, aad, pt);
        ct.append(sealed[..pt.len]);
        tag.append(sealed[pt.len..]);
        return ct, tag, jwx::OK;
    }
    let half = cek.len / 2;
    ct.append(bignum::pkcs7_pad(pt));
    let k = bignum::aes_init(cek[half..]);
    bignum::cbc_encrypt(k, iv, ct);
    let mac = cbc_mac(jwa::hash_of(enc), cek[..half], aad, iv, ct);
    tag.append(mac[..half]);
    return ct, tag, jwx::OK;
}

// The plaintext, and false for any fault: a wrong tag, bad padding.
fn content_decrypt(enc: i64, cek: const u8[:], iv: const u8[:], aad: const u8[:], ct: const u8[:],
                   tag: const u8[:]) -> u8[>..], bool {
    var pt: u8[>..] = [];
    if cek.len != jwa::cek_len(enc) || iv.len != iv_len(enc) { return pt, false; }
    if jwa::is_gcm(enc) {
        if tag.len != 16 { return pt, false; }
        var sealed: u8[>..] = [];
        sealed.append(ct);
        sealed.append(tag);
        let out, ok = bignum::aes_gcm_open(cek, iv, aad, sealed);
        pt.append(out);
        return pt, ok;
    }
    let half = cek.len / 2;
    if tag.len != half || ct.len == 0 || ct.len % 16 != 0 { return pt, false; }
    let mac = cbc_mac(jwa::hash_of(enc), cek[..half], aad, iv, ct);
    if bignum::ct_eq_bytes(mac[..half], tag) != 1 { return pt, false; }
    var data: u8[>..] = [];
    data.append(ct);
    let k = bignum::aes_init(cek[half..]);
    bignum::cbc_decrypt(k, iv, data);
    let out, ok = bignum::pkcs7_unpad(data);
    pt.append(out);
    return pt, ok;
}

// --- Key agreement (RFC 7518 §4.6) ---------------------------------------------

fn put32(out: u8[>..]&, v: i64) {
    for i in 4 { out.push((v >> (24 - 8 * i)) as! u8); }
}

// The Concat KDF of NIST SP 800-56A §5.8.1 with SHA-256, as §4.6.2 uses
// it: OtherInfo is AlgorithmID, PartyUInfo, PartyVInfo, each with a 32-bit
// length, and SuppPubInfo, the key's length in bits.
fn concat_kdf(z: const u8[:], alg_id: const u8[:], apu: const u8[:], apv: const u8[:], len: i64) -> u8[>..] {
    var other: u8[>..] = [];
    put32(other, alg_id.len);
    other.append(alg_id);
    put32(other, apu.len);
    other.append(apu);
    put32(other, apv.len);
    other.append(apv);
    put32(other, len * 8);
    var out: u8[>..] = [];
    var counter = 1;
    while out.len < len {
        var buf: u8[>..] = [];
        put32(buf, counter);
        buf.append(z);
        buf.append(other);
        out.append(bignum::sha256(buf));
        counter++;
    }
    out.resize(len);
    return out;
}

// Z: the shared secret of the private key `priv` with the public key `pub`,
// both of one curve; false when they are not, or the result is unusable.
fn agree(pub: const jwk::Key&, priv: const jwk::Key&) -> u8[>..], bool {
    var z: u8[>..] = [];
    if pub.kty != priv.kty || pub.crv != priv.crv || !priv.private { return z, false; }
    if pub.kty == jwa::KTY_EC {
        let c = jwk::curve(pub.crv);
        let s, ok = bignum::ecdh_shared(c, priv.d, jwk::ec_point(pub));
        z.append(s);
        return z, ok;
    }
    if pub.kty == jwa::KTY_OKP && pub.crv == jwa::CRV_X25519 {
        let s, ok = bignum::x25519_shared(priv.d, pub.x);
        z.append(s);
        return z, ok;
    }
    // RFC 8037 §3.2: Z is X448's 56 bytes, all-zero refused (RFC 7748 §6.2).
    if pub.kty == jwa::KTY_OKP && pub.crv == jwa::CRV_X448 {
        let s, ok = bignum::x448_shared(priv.d, pub.x);
        z.append(s);
        return z, ok;
    }
    return z, false;
}

// A new key on the curve of `like`.
fn ephemeral(like: const jwk::Key&) -> jwk::Key {
    if like.kty == jwa::KTY_EC { return jwk::generate_ec(like.crv); }
    return jwk::generate_okp(like.crv);
}

// --- Key management (RFC 7518 §4) ------------------------------------------------

fn random(n: i64) -> u8[>..] {
    var b: u8[>..] = [];
    b.resize(n, 0);
    bignum::random_bytes(b);
    return b;
}

// The PBES2 key-encrypting key (§4.8.1.1): the salt is the algorithm's
// name, a zero byte and p2s.
fn pbes2_kek(alg: i64, password: const u8[:], p2s: const u8[:], p2c: i64) -> u8[>..] {
    var salt: u8[>..] = [];
    salt.append(jwa::name(alg));
    salt.push(0);
    salt.append(p2s);
    return bignum::pbkdf2(jwa::hash_of(alg), password, salt, p2c, jwa::kek_len(alg));
}

// The CEK for a message to `key` by alg, and its encrypted form; the
// parameters the recipient needs (epk, iv, tag, p2s, p2c) go into h.
fn key_encrypt(h: Header&, alg: i64, enc: i64, key: const jwk::Key&, opts: const Options&)
        -> u8[>..], u8[>..], i64 {
    var cek: u8[>..] = [];
    var ek: u8[>..] = [];
    let clen = jwa::cek_len(enc);
    if clen == 0 || !jwa::is_key_management(alg) { return cek, ek, jwx::ERR_UNSUPPORTED; }
    if !jwk::fits(key, alg) { return cek, ek, jwx::ERR_KEY; }
    if alg == jwa::DIRECT {
        if key.k.len != clen { return cek, ek, jwx::ERR_KEY; }
        cek.append(key.k);
        return cek, ek, jwx::OK;
    }
    if opts.cek.len > 0 {
        if opts.cek.len != clen { return cek, ek, jwx::ERR_KEY; }
        cek.append(opts.cek);
    } else {
        cek.append(random(clen));
    }
    if jwa::is_ecdh(alg) {
        let eph = if opts.has_epk { opts.epk } else { ephemeral(key) };
        let z, ok = agree(key, eph);
        if !ok { return cek, ek, jwx::ERR_KEY; }
        h.epk = jwk::public_key(eph);
        h.has_epk = true;
        if alg == jwa::ECDH_ES {
            cek.resize(0);
            cek.append(concat_kdf(z, jwa::name(enc), h.apu, h.apv, clen));
            return cek, ek, jwx::OK;
        }
        let kek = concat_kdf(z, jwa::name(alg), h.apu, h.apv, jwa::kek_len(alg));
        let w, okw = bignum::aes_key_wrap(kek, cek);
        ek.append(w);
        return cek, ek, if okw { jwx::OK } else { jwx::ERR_KEY };
    }
    if jwa::is_rsa_kw(alg) {
        let pub = jwk::rsa_public(key);
        if alg == jwa::RSA1_5 {
            ek.append(bignum::rsa_encrypt_pkcs1(pub, cek));
        } else {
            let hash = jwa::hash_of(alg);
            if cek.len > bignum::rsa_oaep_max(pub, hash) { return cek, ek, jwx::ERR_KEY; }
            ek.append(bignum::rsa_encrypt_oaep(pub, cek, "", hash));
        }
        return cek, ek, jwx::OK;
    }
    if jwa::is_aes_kw(alg) {
        let w, ok = bignum::aes_key_wrap(key.k, cek);
        ek.append(w);
        return cek, ek, if ok { jwx::OK } else { jwx::ERR_KEY };
    }
    if jwa::is_gcm_kw(alg) {
        var iv: u8[>..] = [];
        if opts.kw_iv.len == 12 { iv.append(opts.kw_iv); } else { iv.append(random(12)); }
        let sealed = bignum::aes_gcm_seal(key.k, iv, "", cek);
        ek.append(sealed[..cek.len]);
        h.iv.resize(0);
        h.iv.append(iv[..12]);
        h.tag.resize(0);
        h.tag.append(sealed[cek.len..]);
        return cek, ek, jwx::OK;
    }
    // PBES2: the key's bytes are the password.
    var p2s: u8[>..] = [];
    if opts.p2s.len > 0 { p2s.append(opts.p2s); } else { p2s.append(random(16)); }
    let p2c = if opts.p2c > 0 { opts.p2c } else { default_p2c(alg) };
    let kek = pbes2_kek(alg, key.k, p2s, p2c);
    let w, ok = bignum::aes_key_wrap(kek, cek);
    ek.append(w);
    h.p2s.resize(0);
    h.p2s.append(p2s);
    h.p2c = p2c;
    return cek, ek, if ok { jwx::OK } else { jwx::ERR_KEY };
}

// The CEK of a recipient whose header is h and encrypted key ek, with key.
fn key_decrypt(h: const Header&, key: const jwk::Key&, ek: const u8[:], max_p2c: i64,
               min_p2c: i64 = MIN_P2C) -> u8[>..], i64 {
    var cek: u8[>..] = [];
    let alg = h.alg;
    let enc = h.enc;
    let clen = jwa::cek_len(enc);
    if clen == 0 { return cek, jwx::ERR_UNSUPPORTED; }
    if !jwk::fits(key, alg) || (alg != jwa::DIRECT && key.kty != jwa::KTY_OCT && !key.private) {
        return cek, jwx::ERR_KEY;
    }
    if alg == jwa::DIRECT {
        if ek.len != 0 || key.k.len != clen { return cek, jwx::ERR_DECRYPT; }
        cek.append(key.k);
        return cek, jwx::OK;
    }
    if jwa::is_ecdh(alg) {
        if !h.has_epk { return cek, jwx::ERR_MALFORMED; }
        // The ephemeral key was checked to be on its curve when the header
        // was read (jwk::from_node), so no invalid-curve point gets here.
        let z, ok = agree(h.epk, key);
        if !ok { return cek, jwx::ERR_DECRYPT; }
        if alg == jwa::ECDH_ES {
            if ek.len != 0 { return cek, jwx::ERR_DECRYPT; }
            cek.append(concat_kdf(z, jwa::name(enc), h.apu, h.apv, clen));
            return cek, jwx::OK;
        }
        let kek = concat_kdf(z, jwa::name(alg), h.apu, h.apv, jwa::kek_len(alg));
        let k, okk = bignum::aes_key_unwrap(kek, ek);
        if !okk || k.len != clen { return cek, jwx::ERR_DECRYPT; }
        cek.append(k);
        return cek, jwx::OK;
    }
    if alg == jwa::RSA1_5 {
        // A random CEK, replaced by the decrypted one only when the padding
        // is good and it has the right length; the tag check then fails
        // alike for a bad padding and a bad key (RFC 7516 §11.5).
        cek.append(random(clen));
        if !bignum::rsa_decrypt_pkcs1_session_key(key.rsa, ek, cek) { return cek, jwx::ERR_DECRYPT; }
        return cek, jwx::OK;
    }
    if jwa::is_rsa_kw(alg) {
        let k, ok = bignum::rsa_decrypt_oaep(key.rsa, ek, "", jwa::hash_of(alg));
        if !ok || k.len != clen { return cek, jwx::ERR_DECRYPT; }
        cek.append(k);
        return cek, jwx::OK;
    }
    if jwa::is_aes_kw(alg) {
        let k, ok = bignum::aes_key_unwrap(key.k, ek);
        if !ok || k.len != clen { return cek, jwx::ERR_DECRYPT; }
        cek.append(k);
        return cek, jwx::OK;
    }
    if jwa::is_gcm_kw(alg) {
        if h.iv.len != 12 || h.tag.len != 16 { return cek, jwx::ERR_MALFORMED; }
        var sealed: u8[>..] = [];
        sealed.append(ek);
        sealed.append(h.tag);
        let k, ok = bignum::aes_gcm_open(key.k, h.iv, "", sealed);
        if !ok || k.len != clen { return cek, jwx::ERR_DECRYPT; }
        cek.append(k);
        return cek, jwx::OK;
    }
    // PBES2: a salt of 8 bytes or more (§4.8.1.1), a count within limits.
    if h.p2s.len < 8 || h.p2c < 1 { return cek, jwx::ERR_MALFORMED; }
    if h.p2c > max_p2c || h.p2c < min_p2c { return cek, jwx::ERR_LIMIT; }
    let kek = pbes2_kek(alg, key.k, h.p2s, h.p2c);
    let k, ok = bignum::aes_key_unwrap(kek, ek);
    if !ok || k.len != clen { return cek, jwx::ERR_DECRYPT; }
    cek.append(k);
    return cek, jwx::OK;
}

// --- Headers -----------------------------------------------------------------------

// Which members header_json writes: all of them, those every recipient
// shares (enc, zip and the like), or one recipient's (alg and its key
// management parameters).
let PART_ALL: i64 = 0;
let PART_SHARED: i64 = 1;
let PART_RECIPIENT: i64 = 2;

fn put_string(out: u8[>..]&, name: const u8[:], v: const u8[:]) { jws::put_member_string(out, name, v); }
fn put_b64(out: u8[>..]&, name: const u8[:], v: const u8[:]) { jws::put_member_b64(out, name, v); }

fn header_json(h: const Header&, extra: const u8[:], part: i64) -> u8[>..] {
    let shared = part != PART_RECIPIENT;
    let own = part != PART_SHARED;
    var out: u8[>..] = [];
    out.push('{');
    if own && h.alg != jwa::UNKNOWN { put_string(out, "alg", jwa::name(h.alg)); }
    if shared && h.enc != jwa::UNKNOWN { put_string(out, "enc", jwa::name(h.enc)); }
    if own && h.apu.len > 0 { put_b64(out, "apu", h.apu); }
    if own && h.apv.len > 0 { put_b64(out, "apv", h.apv); }
    if shared && h.crit.len > 0 {
        jwx::put_comma(out);
        out.append("\"crit\":[");
        var first = true;
        for name in split(h.crit, 0) {
            if name.len == 0 { continue; }
            if !first { out.push(','); }
            json::format_string(out, name);
            first = false;
        }
        out.push(']');
    }
    if shared && h.cty.len > 0 { put_string(out, "cty", h.cty); }
    if own && h.has_epk {
        jwx::put_comma(out);
        json::format_key(out, "epk");
        jwk::marshal_to(out, h.epk, false);
    }
    if own && h.iv.len > 0 { put_b64(out, "iv", h.iv); }
    if own && h.jku.len > 0 { put_string(out, "jku", h.jku); }
    if own && h.has_jwk {
        jwx::put_comma(out);
        json::format_key(out, "jwk");
        jwk::marshal_to(out, h.jwk, false);
    }
    if own && h.kid.len > 0 { put_string(out, "kid", h.kid); }
    if own && h.p2c > 0 {
        jwx::put_comma(out);
        json::format_key(out, "p2c");
        json::format_int(out, h.p2c);
    }
    if own && h.p2s.len > 0 { put_b64(out, "p2s", h.p2s); }
    if own && h.tag.len > 0 { put_b64(out, "tag", h.tag); }
    if shared && h.typ.len > 0 { put_string(out, "typ", h.typ); }
    if own && h.x5t.len > 0 { put_b64(out, "x5t", h.x5t); }
    if own && h.x5t256.len > 0 { put_b64(out, "x5t#S256", h.x5t256); }
    if own && h.x5u.len > 0 { put_string(out, "x5u", h.x5u); }
    if shared && h.zip { put_string(out, "zip", "DEF"); }
    if extra.len > 0 {
        jwx::put_comma(out);
        out.append(extra);
    }
    out.push('}');
    return out;
}

// dst set to v, when v holds anything.
fn replace<A>(dst: A&, v: const u8[:]) {
    if v.len == 0 { return; }
    dst.resize(0);
    dst.append(v);
}

// One header object's parameters into h. "zip" and "crit" must be in the
// protected header (RFC 7516 §4.1.3, RFC 7515 §4.1.11).
fn read_header(n: json::Node&, h: Header&, protected: bool) -> i64 {
    match n.val {
        Obj => {},
        _ => { return jwx::ERR_MALFORMED; },
    }
    if jwk::has_duplicates(n) { return jwx::ERR_MALFORMED; }
    let am = json::member(n, "alg");
    if am {
        let s, ok = json::as_string(am);
        if !ok { return jwx::ERR_MALFORMED; }
        h.alg = jwa::lookup(s);
        if !jwa::is_key_management(h.alg) { return jwx::ERR_UNSUPPORTED; }
    }
    let em = json::member(n, "enc");
    if em {
        let s, ok = json::as_string(em);
        if !ok { return jwx::ERR_MALFORMED; }
        h.enc = jwa::lookup(s);
        if !jwa::is_content(h.enc) { return jwx::ERR_UNSUPPORTED; }
    }
    let zm = json::member(n, "zip");
    if zm {
        let s, ok = json::as_string(zm);
        if !ok || !protected { return jwx::ERR_MALFORMED; }
        if s != "DEF" { return jwx::ERR_UNSUPPORTED; }
        h.zip = true;
    }
    var kid: u8[>..] = [];
    var typ: u8[>..] = [];
    var cty: u8[>..] = [];
    var jku: u8[>..] = [];
    var x5u: u8[>..] = [];
    var x5t: u8[>..] = [];
    var x5t256: u8[>..] = [];
    var iv: u8[>..] = [];
    var tag: u8[>..] = [];
    if !jws::take_string(n, "kid", kid, 256) || !jws::take_string(n, "typ", typ, 128)
       || !jws::take_string(n, "cty", cty, 128) || !jws::take_string(n, "jku", jku, 512)
       || !jws::take_string(n, "x5u", x5u, 512) || !jws::take_b64(n, "x5t", x5t, 20)
       || !jws::take_b64(n, "x5t#S256", x5t256, 32) || !jws::take_b64(n, "iv", iv, 12)
       || !jws::take_b64(n, "tag", tag, 16) {
        return jwx::ERR_MALFORMED;
    }
    // A parameter read again (the same value in two headers) replaces.
    replace(h.kid, kid);
    replace(h.typ, typ);
    replace(h.cty, cty);
    replace(h.jku, jku);
    replace(h.x5u, x5u);
    replace(h.x5t, x5t);
    replace(h.x5t256, x5t256);
    replace(h.iv, iv);
    replace(h.tag, tag);
    for name in ["apu", "apv", "p2s"] {
        let m = json::member(n, name);
        if m {
            let s, ok = json::as_string(m);
            if !ok { return jwx::ERR_MALFORMED; }
            var b: u8[>..] = [];
            if !jwx::b64_decode_append(b, s) || b.len > 256 { return jwx::ERR_MALFORMED; }
            if name == "apu" { replace(h.apu, b); } else if name == "apv" { replace(h.apv, b); } else { replace(h.p2s, b); }
        }
    }
    let cm = json::member(n, "p2c");
    if cm {
        let v, ok = json::as_i64(cm);
        if !ok || v < 1 { return jwx::ERR_MALFORMED; }
        h.p2c = v;
    }
    for name in ["epk", "jwk"] {
        let m = json::member(n, name);
        if m {
            let k, e = jwk::from_node(m);
            if e != jwx::OK { return e; }
            if k.private || k.kty == jwa::KTY_OCT { return jwx::ERR_KEY; }
            // An ephemeral key is an ECDH one: EC, X25519 or X448, never,
            // say, an Ed448 key or an ML-DSA (AKP) key, which RFC 9964
            // defines for signatures only.
            if name == "epk" && k.kty != jwa::KTY_EC && !(k.kty == jwa::KTY_OKP && jwa::is_montgomery(k.crv)) {
                return jwx::ERR_KEY;
            }
            if name == "epk" { h.epk = k; h.has_epk = true; } else { h.jwk = k; h.has_jwk = true; }
        }
    }
    let crm = json::member(n, "crit");
    if crm {
        if !protected { return jwx::ERR_MALFORMED; }
        var bad = false;
        var count = 0;
        match crm.val {
            Arr => {},
            _ => { return jwx::ERR_MALFORMED; },
        }
        json::each(crm) { c =>
            let s, ok = json::as_string(c);
            count++;
            // A NUL in a name would split it in h.crit: malformed.
            if !ok || s.len == 0 || contains(s, 0) || jws::is_registered(s) || !json::member(n, s)
               || h.crit.len + s.len + 1 > 256 {
                bad = true;
            } else {
                h.crit.append(s);
                h.crit.push(0);
            }
        };
        if bad || count == 0 { return jwx::ERR_MALFORMED; }
    }
    return jwx::OK;
}

// --- Encrypting ---------------------------------------------------------------------

fn deflate(pt: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let e = compress::deflate_encode(pt, out);
    assert(e == 0);
    return out;
}

// The content IV: the one given, or a random one.
fn content_iv(enc: i64, opts: const Options&) -> u8[>..] {
    var iv: u8[>..] = [];
    if opts.iv.len > 0 { iv.append(opts.iv); } else { iv.append(random(iv_len(enc))); }
    return iv;
}

// A compact JWE of plaintext to `key`, by h.alg and h.enc, with the rest
// of h and the caller's own members `extra` in its protected header.
fn encrypt_with(plaintext: const u8[:], key: const jwk::Key&, h: const Header&, extra: const u8[:] = "")
        -> u8[>..], i64 {
    let opts = Options { .. };
    let out, err = encrypt_with_options(plaintext, key, h, extra, opts);
    return out, err;
}

// encrypt_with, with what it would choose at random given in opts.
fn encrypt_with_options(plaintext: const u8[:], key: const jwk::Key&, h: const Header&, extra: const u8[:],
                        opts: const Options&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    var hdr = h;
    let cek, ek, err = key_encrypt(hdr, h.alg, h.enc, key, opts);
    if err != jwx::OK { return out, err; }
    let protected_b64 = jwx::b64_encode(header_json(hdr, extra, PART_ALL));
    let iv = content_iv(h.enc, opts);
    if iv.len != iv_len(h.enc) { return out, jwx::ERR_MALFORMED; }
    var ct: u8[>..] = [];
    var tag: u8[>..] = [];
    var e2 = jwx::OK;
    if h.zip {
        let c, t, e = content_encrypt(h.enc, cek, iv, protected_b64, deflate(plaintext));
        ct.append(c); tag.append(t); e2 = e;
    } else {
        let c, t, e = content_encrypt(h.enc, cek, iv, protected_b64, plaintext);
        ct.append(c); tag.append(t); e2 = e;
    }
    if e2 != jwx::OK { return out, e2; }
    out.append(protected_b64);
    out.push('.');
    jwx::b64_append(out, ek);
    out.push('.');
    jwx::b64_append(out, iv);
    out.push('.');
    jwx::b64_append(out, ct);
    out.push('.');
    jwx::b64_append(out, tag);
    return out, jwx::OK;
}

// A compact JWE of plaintext to `key` by alg and enc, compressed first
// when zip is true. The key's "kid", if it has one, goes in the header.
fn encrypt(plaintext: const u8[:], alg: i64, enc: i64, key: const jwk::Key&, zip: bool = false) -> u8[>..], i64 {
    var h = Header { .. };
    h.alg = alg;
    h.enc = enc;
    h.zip = zip;
    h.kid.append(key.kid);
    let out, err = encrypt_with(plaintext, key, h);
    return out, err;
}

// A JWE in the JSON serialization to every recipient: general, or
// flattened when there is one recipient and `flattened` is true. `shared`
// holds enc (and zip, typ, cty) for the protected header; with one
// recipient its own parameters are protected too. `aad` is additional
// authenticated data (RFC 7516 §5.1 step 14).
fn encrypt_json(plaintext: const u8[:], shared: const Header&, recipients: const Recipient[:], aad: const u8[:] = "",
                flattened: bool = false) -> u8[>..], i64 {
    let opts = Options { .. };
    let out, err = encrypt_json_options(plaintext, shared, recipients, aad, flattened, opts);
    return out, err;
}

// encrypt_json, with what it would choose at random given in opts.
fn encrypt_json_options(plaintext: const u8[:], shared: const Header&, recipients: const Recipient[:],
                        aad: const u8[:], flattened: bool, opts: const Options&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let enc = shared.enc;
    if recipients.len == 0 || (flattened && recipients.len != 1) || jwa::cek_len(enc) == 0 {
        return out, jwx::ERR_MALFORMED;
    }
    // dir and ECDH-ES make the CEK from the key: one recipient only.
    for &r in recipients {
        if (r.alg == jwa::DIRECT || r.alg == jwa::ECDH_ES) && recipients.len > 1 { return out, jwx::ERR_MALFORMED; }
    }
    let single = recipients.len == 1;
    var o = opts;
    if o.cek.len == 0 && !single {
        o.cek.append(random(jwa::cek_len(enc)));
    }
    var heads: u8[][>..] = [];
    var eks: u8[][>..] = [];
    var cek: u8[>..] = [];
    var protected_json: u8[>..] = [];
    for &r in recipients {
        var h = r.header;
        h.alg = r.alg;
        h.enc = enc;
        let c, ek, err = key_encrypt(h, r.alg, enc, r.key, o);
        if err != jwx::OK { return out, err; }
        if cek.len == 0 { cek.append(c); }
        eks.push(copy(ek));
        if single {
            var all = h;
            all.zip = shared.zip;
            all.typ = shared.typ;
            all.cty = shared.cty;
            protected_json.append(header_json(all, "", PART_ALL));
            heads.push(str(""));
        } else {
            let own = header_json(h, "", PART_RECIPIENT);
            heads.push(copy(own));
        }
    }
    if !single { protected_json.append(header_json(shared, "", PART_SHARED)); }
    let protected_b64 = jwx::b64_encode(protected_json);
    var aad_full: u8[>..] = [];
    aad_full.append(protected_b64);
    if aad.len > 0 {
        aad_full.push('.');
        jwx::b64_append(aad_full, aad);
    }
    let iv = content_iv(enc, o);
    var body: u8[>..] = [];
    if shared.zip { body.append(deflate(plaintext)); } else { body.append(plaintext); }
    let ct, tag, e = content_encrypt(enc, cek, iv, aad_full, body);
    if e != jwx::OK { return out, e; }

    out.append("{\"protected\":\"");
    out.append(protected_b64);
    out.push('"');
    if flattened {
        for ek in eks {
            if ek.len > 0 {
                out.append(",\"encrypted_key\":\"");
                jwx::b64_append(out, ek);
                out.push('"');
            }
        }
    } else {
        out.append(",\"recipients\":[");
        var first = true;
        var i = 0;
        for hd in heads {
            if !first { out.push(','); }
            first = false;
            out.push('{');
            if hd.len > 2 {
                out.append("\"header\":");
                out.append(hd);
            }
            var j = 0;
            for ek in eks {
                if j == i && ek.len > 0 {
                    if hd.len > 2 { out.push(','); }
                    out.append("\"encrypted_key\":\"");
                    jwx::b64_append(out, ek);
                    out.push('"');
                }
                j++;
            }
            out.push('}');
            i++;
        }
        out.push(']');
    }
    if aad.len > 0 {
        out.append(",\"aad\":\"");
        jwx::b64_append(out, aad);
        out.push('"');
    }
    out.append(",\"iv\":\"");
    jwx::b64_append(out, iv);
    out.append("\",\"ciphertext\":\"");
    jwx::b64_append(out, ct);
    out.append("\",\"tag\":\"");
    jwx::b64_append(out, tag);
    out.append("\"}");
    return out, jwx::OK;
}

// --- Parsing ----------------------------------------------------------------------------

fn decode_into(out: u8[>..]&, s: const u8[:], cap: i64) -> bool {
    var b: u8[>..] = [];
    if !jwx::b64_decode_append(b, s) || b.len > cap { return false; }
    out.append(b);
    return true;
}

// Parses headers from text into h. RFC 7516 §7.2.1 has the protected,
// shared and per-recipient headers disjoint; Go's jwx repeats "alg" in the
// protected header and the recipient's, so a parameter may appear twice
// when both hold the same value. `seen` keeps each name and its value as
// JSON, NUL-separated, so a name holding a NUL is malformed: it would
// shift the names and values after it, and hide a clash.
fn merge(h: Header&, seen: u8[>..]&, text: const u8[:], protected: bool) -> i64 {
    if text.len == 0 { return jwx::OK; }
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return jwx::ERR_MALFORMED; }
    match root.val {
        Obj => {},
        _ => { return jwx::ERR_MALFORMED; },
    }
    var clash = false;
    json::each(root) { m =>
        if contains(m.key, 0) { clash = true; }
        var value: u8[>..] = [];
        jws::write_node(value, m);
        var is_name = true;
        var matched = false;
        for part in split(seen, 0) {
            if is_name { matched = part == m.key; }
            else if matched && part != value[..] { clash = true; }
            is_name = !is_name;
        }
    };
    if clash { return jwx::ERR_MALFORMED; }
    json::each(root) { m =>
        seen.append(m.key);
        seen.push(0);
        jws::write_node(seen, m);
        seen.push(0);
    };
    return read_header(root, h, protected);
}

fn add_recipient(m: Message&, protected_json: const u8[:], shared: const u8[:], own: const u8[:],
                 ek_b64: const u8[:]) -> i64 {
    var r = ParsedRecipient { header: Header { .. }, ek: [] };
    var seen: u8[>..] = [];
    var e = merge(r.header, seen, protected_json, true);
    if e == jwx::OK { e = merge(r.header, seen, shared, false); }
    if e == jwx::OK { e = merge(r.header, seen, own, false); }
    if e != jwx::OK { return e; }
    if r.header.alg == jwa::UNKNOWN || r.header.enc == jwa::UNKNOWN { return jwx::ERR_MALFORMED; }
    var ek: u8[>..] = [];
    if !decode_into(ek, ek_b64, 1024) { return jwx::ERR_MALFORMED; }
    r.ek.append(ek);
    m.recipients.push(r);
    return jwx::OK;
}

fn set_body(m: Message&, protected_b64: const u8[:], iv: const u8[:], ct: const u8[:], tag: const u8[:]) -> i64 {
    m.text.append(protected_b64);
    m.protected_len = protected_b64.len;
    var b: u8[>..] = [];
    if !decode_into(b, iv, 16) { return jwx::ERR_MALFORMED; }
    m.iv.append(b);
    var t: u8[>..] = [];
    if !decode_into(t, tag, 32) { return jwx::ERR_MALFORMED; }
    m.tag.append(t);
    if !jwx::b64_decode_append(m.ciphertext, ct) { return jwx::ERR_MALFORMED; }
    return jwx::OK;
}

fn parse_compact(m: Message&, token: const u8[:]) -> i64 {
    m.compact = true;
    let parts = split(token, '.');
    if parts.len != 5 { return jwx::ERR_MALFORMED; }
    var p: const u8[:][5] = ["", "", "", "", ""];
    var i = 0;
    for part in parts { p[i] = part; i++; }
    if p[0].len == 0 { return jwx::ERR_MALFORMED; }
    var hjson: u8[>..] = [];
    if !jwx::b64_decode_append(hjson, p[0]) { return jwx::ERR_MALFORMED; }
    let e = set_body(m, p[0], p[2], p[3], p[4]);
    if e != jwx::OK { return e; }
    return add_recipient(m, hjson, "", "", p[1]);
}

fn string_of(n: json::Node?, name: const u8[:], out: u8[>..]&) -> bool, bool {
    let v = json::member(n, name);
    guard v else { return false, true; }
    let s, ok = json::as_string(v);
    if !ok { return true, false; }
    out.append(s);
    return true, true;
}

fn object_of(n: json::Node?, name: const u8[:], out: u8[>..]&) -> bool {
    let v = json::member(n, name);
    guard v else { return true; }
    match v.val {
        Obj => {},
        _ => { return false; },
    }
    jws::write_node(out, v);
    return true;
}

fn parse_json(m: Message&, token: const u8[:]) -> i64 {
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(token, doc, decoded);
    guard root else { return jwx::ERR_MALFORMED; }
    match root.val {
        Obj => {},
        _ => { return jwx::ERR_MALFORMED; },
    }
    var protected_b64: u8[>..] = [];
    var iv: u8[>..] = [];
    var ct: u8[>..] = [];
    var tag: u8[>..] = [];
    var aad: u8[>..] = [];
    var shared: u8[>..] = [];
    let hp, okp = string_of(root, "protected", protected_b64);
    let hi, oki = string_of(root, "iv", iv);
    let hc, okc = string_of(root, "ciphertext", ct);
    let ht, okt = string_of(root, "tag", tag);
    let ha, oka = string_of(root, "aad", aad);
    if !okp || !oki || !okc || !okt || !oka || !hc || !object_of(root, "unprotected", shared) {
        return jwx::ERR_MALFORMED;
    }
    let e = set_body(m, protected_b64, iv, ct, tag);
    if e != jwx::OK { return e; }
    if ha {
        var check: u8[>..] = [];
        if !jwx::b64_decode_append(check, aad) { return jwx::ERR_MALFORMED; }
        m.aad_at = m.text.len;
        m.aad_len = aad.len;
        m.text.append(aad);
    }
    var hjson: u8[>..] = [];
    if !jwx::b64_decode_append(hjson, protected_b64) { return jwx::ERR_MALFORMED; }
    let list = json::member(root, "recipients");
    if list {
        if json::member(root, "encrypted_key") || json::member(root, "header") { return jwx::ERR_MALFORMED; }
        match list.val {
            Arr => {},
            _ => { return jwx::ERR_MALFORMED; },
        }
        var err = jwx::OK;
        json::each(list) { r =>
            var own: u8[>..] = [];
            var ek: u8[>..] = [];
            let he, oke = string_of(r, "encrypted_key", ek);
            if err == jwx::OK && (!oke || !object_of(r, "header", own)) { err = jwx::ERR_MALFORMED; }
            if err == jwx::OK { err = add_recipient(m, hjson, shared, own, ek); }
        };
        if err != jwx::OK { return err; }
        if m.recipients.len == 0 { return jwx::ERR_MALFORMED; }
        return jwx::OK;
    }
    var own: u8[>..] = [];
    var ek: u8[>..] = [];
    let he, oke = string_of(root, "encrypted_key", ek);
    if !oke || !object_of(root, "header", own) { return jwx::ERR_MALFORMED; }
    return add_recipient(m, hjson, shared, own, ek);
}

// Parses a JWE, compact or JSON, into m (a fresh Message).
fn parse(m: Message&, token: const u8[:]) -> i64 {
    let t = trim(token);
    if t.len > 0 && t[0] == '{' { return parse_json(m, t); }
    return parse_compact(m, t);
}

// The additional authenticated data of m (RFC 7516 §5.2 step 14).
fn aad_of(m: const Message&) -> u8[>..] {
    var a: u8[>..] = [];
    a.append(m.text[..m.protected_len]);
    if m.aad_len >= 0 {
        a.push('.');
        a.append(m.text[m.aad_at..m.aad_at + m.aad_len]);
    }
    return a;
}

// The plaintext of m for recipient i with key, if its alg is `alg`.
fn decrypt_recipient(m: const Message&, i: i64, alg: i64, key: const jwk::Key&, max_p2c: i64,
                     max_inflate: i64, min_p2c: i64) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let h = m.recipients[i].header;
    if h.alg != alg { return out, jwx::ERR_ALG_MISMATCH; }
    if h.crit.len > 0 { return out, jwx::ERR_CRIT; }
    let cek, e = key_decrypt(h, key, m.recipients[i].ek, max_p2c, min_p2c);
    if e != jwx::OK { return out, e; }
    let pt, ok = content_decrypt(h.enc, cek, m.iv, aad_of(m), m.ciphertext, m.tag);
    if !ok { return out, jwx::ERR_DECRYPT; }
    if !h.zip {
        out.append(pt);
        return out, jwx::OK;
    }
    let ze = compress::inflate_decode(pt, out, max_inflate);
    if ze == compress::ERR_LIMIT { out.resize(0); return out, jwx::ERR_LIMIT; }
    if ze != 0 { out.resize(0); return out, jwx::ERR_DECRYPT; }
    return out, jwx::OK;
}

fn worse(a: i64, b: i64) -> i64 {
    if a == jwx::ERR_ALG_MISMATCH || a == jwx::ERR_NO_KEY { return b; }
    return a;
}

// The plaintext of a JWE for `key` by the key management algorithm alg:
// that of the first recipient whose alg it is and whose key it opens.
fn decrypt(token: const u8[:], alg: i64, key: const jwk::Key&, max_p2c: i64 = MAX_P2C,
           max_inflate: i64 = MAX_INFLATE, min_p2c: i64 = MIN_P2C) -> u8[>..], i64 {
    var m = Message { .. };
    var out: u8[>..] = [];
    let e = parse(m, token);
    if e != jwx::OK { return out, e; }
    var err = jwx::ERR_ALG_MISMATCH;
    for i in m.recipients.len {
        let pt, r = decrypt_recipient(m, i, alg, key, max_p2c, max_inflate, min_p2c);
        if r == jwx::OK {
            out.append(pt);
            return out, jwx::OK;
        }
        err = worse(err, r);
    }
    return out, err;
}

// The plaintext of a JWE for a key of the set: the key whose "kid" is a
// recipient's, or every key when the recipient names none. The algorithm
// is the key's "alg", or with `infer` the recipient's if the key fits it.
fn decrypt_set(token: const u8[:], keys: const jwk::Key[:], infer: bool = false, max_p2c: i64 = MAX_P2C,
               max_inflate: i64 = MAX_INFLATE, min_p2c: i64 = MIN_P2C) -> u8[>..], i64 {
    var m = Message { .. };
    var out: u8[>..] = [];
    let e = parse(m, token);
    if e != jwx::OK { return out, e; }
    var err = jwx::ERR_NO_KEY;
    for i in m.recipients.len {
        let h = m.recipients[i].header;
        for &k in keys {
            if h.kid.len > 0 && k.kid[..] != h.kid[..] { continue; }
            if k.key_use == jwk::USE_SIG { continue; }
            var alg = k.alg;
            if jwa::is_content(alg) { alg = jwa::DIRECT; }       // a dir key naming its content algorithm
            if alg == jwa::UNKNOWN {
                if !infer || !jwk::fits(k, h.alg) { continue; }
                alg = h.alg;
            }
            let pt, r = decrypt_recipient(m, i, alg, k, max_p2c, max_inflate, min_p2c);
            if r == jwx::OK {
                out.append(pt);
                return out, jwx::OK;
            }
            err = worse(err, r);
        }
    }
    return out, err;
}

// A string member of the protected header, by name.
fn header_string(m: const Message&, name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var text: u8[>..] = [];
    if !jwx::b64_decode_append(text, m.text[..m.protected_len]) { return out, false; }
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    let v, ok = json::as_string(json::member(root, name));
    if ok { out.append(v); }
    return out, ok;
}
