// jwx.jwk: JSON Web Keys (RFC 7517) and key sets: RSA, EC (P-256, P-384,
// P-521), OKP (Ed25519, Ed448, X25519 and X448, RFC 8037), AKP
// (ML-DSA-44, -65 and -87, RFC 9964) and symmetric ("oct") keys, read from
// and written to JSON, checked for consistency, their RFC 7638
// thumbprints, the public half of a private key, and new keys. jwx.pem
// turns PEM keys and certificates into JWKs.
//
// A Key is a fixed-size value, so a set is a plain Key[>..]. The members
// RFC 7517, RFC 7518 and RFC 9964 define are kept; others, and "x5c", are
// not.

namespace jwk;

import std;
import json;
import jwx;
import jwx.jwa;
import crypto.bignum;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.ed25519;
import crypto.bignum.x25519;
import crypto.bignum.ed448;
import crypto.bignum.x448;
import crypto.bignum.mldsa;
import crypto.bignum.hmac;
import crypto.bignum.sha256;
import crypto.bignum.sha512;
import crypto.bignum.entropy;

// The longest "oct" key: HS512 wants 64 bytes; 512 leaves room for
// passwords (PBES2) and long HMAC keys.
let MAX_OCT: i64 = 512;

// "use" (RFC 7517 §4.2).
let USE_NONE: i64 = 0;
let USE_SIG: i64 = 1;
let USE_ENC: i64 = 2;

// "key_ops" (RFC 7517 §4.3), as bits.
let OP_SIGN: u32 = 1;
let OP_VERIFY: u32 = 2;
let OP_ENCRYPT: u32 = 4;
let OP_DECRYPT: u32 = 8;
let OP_WRAP_KEY: u32 = 16;
let OP_UNWRAP_KEY: u32 = 32;
let OP_DERIVE_KEY: u32 = 64;
let OP_DERIVE_BITS: u32 = 128;

let OP_NAMES: const u8[:][] = ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"];

// A key. EC keys hold x, y and d (d empty in a public key) at the curve's
// length; OKP keys x and d at the curve's (32 bytes for Ed25519 and
// X25519, 57 for Ed448, 56 for X448); oct keys k; RSA keys n and e, and
// d, p, q and the CRT values when private, in `rsa`. AKP keys (RFC 9964)
// hold "pub" in pub and "priv", the 32-byte ML-DSA seed, in d; their
// "alg" is required and says which ML-DSA they are.
struct Key {
    kty: i64,
    crv: i64,
    private: bool,
    alg: i64,                   // "alg" as a jwa id; UNKNOWN when absent or unknown
    key_use: i64,               // "use"
    key_ops: u32,               // "key_ops" as OP_* bits
    kid: u8[..256],
    x5t: u8[..20],              // "x5t": a certificate's SHA-1 digest, when given
    x5t256: u8[..32],           // "x5t#S256"
    x: u8[..66],
    y: u8[..66],
    d: u8[..66],
    k: u8[..512],
    pub: u8[..2592],            // AKP "pub": an ML-DSA public key, up to ML-DSA-87's
    rsa: bignum::RsaPrivateKey,
}

fn empty() -> Key {
    Key { kty: jwa::KTY_UNKNOWN, crv: jwa::CRV_UNKNOWN, private: false, alg: jwa::UNKNOWN,
          key_use: USE_NONE, key_ops: 0, kid: [], x5t: [], x5t256: [], x: [], y: [], d: [], k: [], pub: [],
          rsa: bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] } }
}

// The bignum curve of a NIST curve id.
fn curve(crv: i64) -> bignum::Curve {
    if crv == jwa::CRV_P384 { return bignum::p384(); }
    if crv == jwa::CRV_P521 { return bignum::p521(); }
    return bignum::p256();
}

// The uncompressed point 04 || x || y of an EC key.
fn ec_point(k: const Key&) -> u8[>..] {
    var p: u8[>..] = [];
    p.push(4);
    p.append(k.x);
    p.append(k.y);
    return p;
}

// The RSA public key of an RSA key.
fn rsa_public(k: const Key&) -> bignum::RsaPublicKey {
    var r = bignum::RsaPublicKey { n: [], e: [] };
    r.n.append(k.rsa.n);
    r.e.append(k.rsa.e);
    return r;
}

fn rsa_bits(k: const Key&) -> i64 { bignum::mag_bit_len(k.rsa.n) }

// The public half of a key: the same key with its private parts dropped.
// An oct key has no public half and is returned as it is.
fn public_key(k: const Key&) -> Key {
    var p = k;
    if k.kty == jwa::KTY_OCT { return p; }
    p.private = false;
    p.d.resize(0);
    p.rsa.d.resize(0);
    p.rsa.p.resize(0);
    p.rsa.q.resize(0);
    p.rsa.dp.resize(0);
    p.rsa.dq.resize(0);
    p.rsa.qinv.resize(0);
    return p;
}

// --- New keys ------------------------------------------------------------------------

fn generate_rsa(bits: i64 = 2048) -> Key {
    var k = empty();
    k.kty = jwa::KTY_RSA;
    k.private = true;
    k.rsa = bignum::rsa_generate(bits);
    return k;
}

fn generate_ec(crv: i64) -> Key {
    assert(jwa::is_nist(crv));
    var k = empty();
    k.kty = jwa::KTY_EC;
    k.crv = crv;
    k.private = true;
    let c = curve(crv);
    let sk, pk = bignum::ec_keypair(c);
    let n = jwa::crv_len(crv);
    k.d.append(sk);
    k.x.append(pk[1..1 + n]);
    k.y.append(pk[1 + n..]);
    return k;
}

// A new OKP key: Ed25519, Ed448, X25519 or X448.
fn generate_okp(crv: i64) -> Key {
    assert(jwa::is_okp(crv));
    var d: u8[>..] = [];
    d.resize(jwa::crv_len(crv), 0);
    bignum::random_bytes(d);
    return okp_from_private(crv, d);
}

// The OKP public key of a private one: an Ed25519 or Ed448 seed's, an
// X25519 or X448 scalar's.
fn okp_public(crv: i64, d: const u8[:]) -> u8[>..] {
    var x: u8[>..] = [];
    if crv == jwa::CRV_ED25519 { x.append(bignum::ed25519_public(d)); }
    else if crv == jwa::CRV_X25519 { x.append(bignum::x25519_base(d)); }
    else if crv == jwa::CRV_ED448 { x.append(bignum::ed448_public(d)); }
    else { x.append(bignum::x448_base(d)); }
    return x;
}

// An OKP key on crv from its private part (RFC 8037 §2's "d"), which must
// be the curve's length.
fn okp_from_private(crv: i64, d: const u8[:]) -> Key {
    assert(jwa::is_okp(crv) && d.len == jwa::crv_len(crv));
    var k = empty();
    k.kty = jwa::KTY_OKP;
    k.crv = crv;
    k.private = true;
    k.d.append(d);
    k.x.append(okp_public(crv, d));
    return k;
}

// An ML-DSA key (kty "AKP") for alg (jwa::ML_DSA_44, _65 or _87) from its
// 32-byte seed, the private key RFC 9964 §4 has in "priv".
fn akp_from_seed(alg: i64, seed: const u8[:]) -> Key {
    assert(jwa::is_mldsa(alg) && seed.len == 32);
    var k = empty();
    k.kty = jwa::KTY_AKP;
    k.alg = alg;
    k.private = true;
    k.d.append(seed);
    k.pub.append(bignum::mldsa_public_key(jwa::mldsa_set(alg), seed));
    return k;
}

// A new ML-DSA key for alg.
fn generate_akp(alg: i64) -> Key {
    assert(jwa::is_mldsa(alg));
    var seed: u8[>..] = [];
    seed.resize(32, 0);
    bignum::random_bytes(seed);
    return akp_from_seed(alg, seed);
}

// A symmetric key of the given bytes (at most MAX_OCT).
fn from_oct(secret: const u8[:]) -> Key {
    assert(secret.len <= MAX_OCT);
    var k = empty();
    k.kty = jwa::KTY_OCT;
    k.private = true;
    k.k.append(secret);
    return k;
}

fn generate_oct(len: i64) -> Key {
    var b: u8[>..] = [];
    b.resize(len, 0);
    bignum::random_bytes(b);
    return from_oct(b);
}

// --- Checking a key against what it says -----------------------------------------------

// OK when the key's parts agree with each other: a point on its curve, a
// private part that gives the public one, an RSA key bignum accepts.
fn validate(k: const Key&) -> i64 {
    if k.kty == jwa::KTY_EC {
        if !jwa::is_nist(k.crv) { return jwx::ERR_UNSUPPORTED; }
        let n = jwa::crv_len(k.crv);
        if k.x.len != n || k.y.len != n { return jwx::ERR_KEY; }
        let c = curve(k.crv);
        let pt = ec_point(k);
        let p, ok = bignum::ec_decode(c, pt);
        if !ok { return jwx::ERR_KEY; }
        if k.private {
            if k.d.len != n { return jwx::ERR_KEY; }
            let s, oks = bignum::ec_scalar(c, k.d);
            if !oks { return jwx::ERR_KEY; }
            if bignum::ec_public_key(c, k.d) != pt { return jwx::ERR_KEY; }
        }
        return jwx::OK;
    }
    if k.kty == jwa::KTY_OKP {
        if !jwa::is_okp(k.crv) { return jwx::ERR_UNSUPPORTED; }
        let n = jwa::crv_len(k.crv);
        if k.x.len != n { return jwx::ERR_KEY; }
        if k.private {
            if k.d.len != n { return jwx::ERR_KEY; }
            if okp_public(k.crv, k.d)[..] != k.x[..] { return jwx::ERR_KEY; }
        }
        return jwx::OK;
    }
    if k.kty == jwa::KTY_RSA {
        if k.rsa.n.len == 0 || k.rsa.e.len == 0 { return jwx::ERR_KEY; }
        return jwx::OK;
    }
    if k.kty == jwa::KTY_OCT {
        return if k.k.len > 0 { jwx::OK } else { jwx::ERR_KEY };
    }
    if k.kty == jwa::KTY_AKP {
        // RFC 9964 §3 and §7.3: "alg" names the algorithm, "pub" is its
        // length, "priv" is a 32-byte seed whose public key is "pub".
        if !jwa::is_mldsa(k.alg) { return jwx::ERR_UNSUPPORTED; }
        let set = jwa::mldsa_set(k.alg);
        if k.pub.len != bignum::mldsa_pk_len(set) { return jwx::ERR_KEY; }
        if k.private {
            if k.d.len != 32 { return jwx::ERR_KEY; }
            if bignum::mldsa_public_key(set, k.d)[..] != k.pub[..] { return jwx::ERR_KEY; }
        }
        return jwx::OK;
    }
    return jwx::ERR_UNSUPPORTED;
}

// Whether the key may be used for `alg`: its type and curve, the AES key
// length of A*KW and A*GCMKW, and its own "alg", which when set must be
// alg. As jwx, it does not hold HMAC keys to RFC 7518 §3.2's minimum (the
// hash's length) or RSA keys to 2048 bits: tokens signed with short
// secrets are common, and refusing them is the caller's choice
// (strong_enough).
fn fits(k: const Key&, alg: i64) -> bool {
    // A dir key may name the content algorithm it is for (RFC 7520 §5.6).
    if k.alg != jwa::UNKNOWN && k.alg != alg && !(alg == jwa::DIRECT && jwa::is_content(k.alg)) { return false; }
    if jwa::is_ecdsa(alg) { return k.kty == jwa::KTY_EC && k.crv == jwa::curve_of(alg); }
    // "EdDSA" takes either Edwards curve, "Ed25519" and "Ed448" their own.
    if jwa::is_eddsa(alg) { return k.kty == jwa::KTY_OKP && jwa::eddsa_fits(alg, k.crv); }
    // An AKP key's "alg" is always set, and was checked above.
    if jwa::is_mldsa(alg) { return k.kty == jwa::KTY_AKP && k.alg == alg; }
    if jwa::is_ecdh(alg) {
        return (k.kty == jwa::KTY_EC && jwa::is_nist(k.crv)) || (k.kty == jwa::KTY_OKP && jwa::is_montgomery(k.crv));
    }
    if jwa::is_hmac(alg) {
        return k.kty == jwa::KTY_OCT && k.k.len > 0;
    }
    if jwa::kty_of(alg) == jwa::KTY_RSA { return k.kty == jwa::KTY_RSA; }
    if jwa::is_aes_kw(alg) || jwa::is_gcm_kw(alg) { return k.kty == jwa::KTY_OCT && k.k.len == jwa::kek_len(alg); }
    if jwa::is_pbes2(alg) { return k.kty == jwa::KTY_OCT; }
    if alg == jwa::DIRECT { return k.kty == jwa::KTY_OCT; }
    return false;
}

// RFC 7518's minimums: an HMAC key at least as long as its hash (§3.2), an
// RSA key of 2048 bits (§3.3, §4.2).
fn strong_enough(k: const Key&, alg: i64) -> bool {
    if jwa::is_hmac(alg) { return k.k.len >= bignum::hash_len(jwa::hash_of(alg)); }
    if k.kty == jwa::KTY_RSA { return rsa_bits(k) >= 2048; }
    return true;
}

// --- Reading ---------------------------------------------------------------------------

// A string member: OK and its text, OK and "" when absent, ERR_MALFORMED
// when it is there but not a string.
fn string_member(n: json::Node&, name: const u8[:]) -> const u8[:], bool, i64 {
    let m = json::member(n, name);
    guard m else { return "", false, jwx::OK; }
    let s, ok = json::as_string(m);
    if !ok { return "", false, jwx::ERR_MALFORMED; }
    return s, true, jwx::OK;
}

// A base64url member decoded onto out: whether it was there, and an error.
fn bytes_member(n: json::Node&, name: const u8[:], out: u8[>..]&) -> bool, i64 {
    let s, present, err = string_member(n, name);
    if err != jwx::OK || !present { return false, err; }
    if !jwx::b64_decode_append(out, s) { return true, jwx::ERR_MALFORMED; }
    return true, jwx::OK;
}

// Where a member's name is in a buffer of names.
struct NameAt { at: i64, len: i64 }

// Whether two members of the object share a name (RFC 7517 §4 leaves that
// to the parser; refusing is the safe reading). The names sorted, so a
// header of many members costs n log n, not n².
fn has_duplicates(n: json::Node&) -> bool {
    var names: u8[>..] = [];
    var at: NameAt[>..] = [];
    json::each(n) { m =>
        at.push(NameAt { at: names.len, len: m.key.len });
        names.append(m.key);
    };
    sort(at) { a, b => compare(names[a.at..a.at + a.len], names[b.at..b.at + b.len]) < 0 };
    for i in at.len {
        if i > 0 && names[at[i - 1].at..at[i - 1].at + at[i - 1].len] == names[at[i].at..at[i].at + at[i].len] {
            return true;
        }
    }
    return false;
}

// A fixed-capacity field from a base64url member, which must be exactly
// `want` bytes (any length up to the capacity when want < 0).
fn fixed_member(n: json::Node&, name: const u8[:], want: i64, cap: i64, out: u8[>..]&) -> bool, i64 {
    let present, err = bytes_member(n, name, out);
    if err != jwx::OK || !present { return present, err; }
    if (want >= 0 && out.len != want) || out.len > cap || out.len == 0 { return true, jwx::ERR_KEY; }
    return true, jwx::OK;
}

// The key in a parsed JWK object.
fn from_node(n: json::Node&) -> Key, i64 {
    var k = empty();
    match n.val {
        Obj => {},
        _ => { return k, jwx::ERR_MALFORMED; },
    }
    if has_duplicates(n) { return k, jwx::ERR_MALFORMED; }
    let kty_s, has_kty, e1 = string_member(n, "kty");
    if e1 != jwx::OK || !has_kty { return k, jwx::ERR_MALFORMED; }
    k.kty = jwa::kty_lookup(kty_s);
    if k.kty == jwa::KTY_UNKNOWN { return k, jwx::ERR_UNSUPPORTED; }

    let alg_s, has_alg, e2 = string_member(n, "alg");
    if e2 != jwx::OK { return k, e2; }
    if has_alg { k.alg = jwa::lookup(alg_s); }
    // An AKP key must say its algorithm (RFC 9964 §3); one this package
    // does not know (or no ML-DSA) is a key it does not do.
    if k.kty == jwa::KTY_AKP {
        if !has_alg { return k, jwx::ERR_MALFORMED; }
        if k.alg == jwa::UNKNOWN { return k, jwx::ERR_UNSUPPORTED; }
        if !jwa::is_mldsa(k.alg) { return k, jwx::ERR_KEY; }
    }
    let use_s, has_use, e3 = string_member(n, "use");
    if e3 != jwx::OK { return k, e3; }
    if has_use { k.key_use = if use_s == "sig" { USE_SIG } else if use_s == "enc" { USE_ENC } else { USE_NONE }; }
    let kid_s, has_kid, e4 = string_member(n, "kid");
    if e4 != jwx::OK { return k, e4; }
    if has_kid {
        if kid_s.len > 256 { return k, jwx::ERR_KEY; }
        k.kid.append(kid_s);
    }
    let ops = json::member(n, "key_ops");
    if ops {
        var bad = false;
        match ops.val {
            Arr => {},
            _ => { return k, jwx::ERR_MALFORMED; },
        }
        json::each(ops) { op =>
            let s, ok = json::as_string(op);
            if !ok { bad = true; }
            for i in OP_NAMES.len {
                if OP_NAMES[i] == s { k.key_ops = k.key_ops | (1 << i as u32); }
            }
        };
        if bad { return k, jwx::ERR_MALFORMED; }
    }
    {
        var t: u8[>..] = [];
        let present, err = fixed_member(n, "x5t", 20, 20, t);
        if err != jwx::OK { return k, err; }
        k.x5t.append(t);
    }
    {
        var t: u8[>..] = [];
        let present, err = fixed_member(n, "x5t#S256", 32, 32, t);
        if err != jwx::OK { return k, err; }
        k.x5t256.append(t);
    }

    if k.kty == jwa::KTY_OCT {
        var b: u8[>..] = [];
        let present, err = fixed_member(n, "k", -1, MAX_OCT, b);
        if err != jwx::OK { return k, err; }
        if !present { return k, jwx::ERR_MALFORMED; }
        k.k.append(b);
        k.private = true;
        return k, jwx::OK;
    }
    if k.kty == jwa::KTY_AKP {
        let set = jwa::mldsa_set(k.alg);
        var pb: u8[>..] = [];
        let has_pub, ep = fixed_member(n, "pub", bignum::mldsa_pk_len(set), 2592, pb);
        if ep != jwx::OK { return k, ep; }
        if !has_pub { return k, jwx::ERR_MALFORMED; }
        k.pub.append(pb);
        var sb: u8[>..] = [];
        let has_priv, es = fixed_member(n, "priv", 32, 32, sb);
        if es != jwx::OK { return k, es; }
        if has_priv { k.d.append(sb); k.private = true; }
        let ev = validate(k);
        return k, ev;
    }
    if k.kty == jwa::KTY_EC || k.kty == jwa::KTY_OKP {
        let crv_s, has_crv, e5 = string_member(n, "crv");
        if e5 != jwx::OK || !has_crv { return k, jwx::ERR_MALFORMED; }
        k.crv = jwa::crv_lookup(crv_s);
        let nist = jwa::is_nist(k.crv);
        if k.kty == jwa::KTY_EC && !nist { return k, jwx::ERR_UNSUPPORTED; }
        if k.kty == jwa::KTY_OKP && nist { return k, jwx::ERR_KEY; }
        if k.crv == jwa::CRV_UNKNOWN { return k, jwx::ERR_UNSUPPORTED; }
        let len = jwa::crv_len(k.crv);
        var xb: u8[>..] = [];
        let has_x, ex = fixed_member(n, "x", len, 66, xb);
        if ex != jwx::OK { return k, ex; }
        if !has_x { return k, jwx::ERR_MALFORMED; }
        k.x.append(xb);
        if k.kty == jwa::KTY_EC {
            var yb: u8[>..] = [];
            let has_y, ey = fixed_member(n, "y", len, 66, yb);
            if ey != jwx::OK { return k, ey; }
            if !has_y { return k, jwx::ERR_MALFORMED; }
            k.y.append(yb);
        }
        var db: u8[>..] = [];
        let has_d, ed = fixed_member(n, "d", len, 66, db);
        if ed != jwx::OK { return k, ed; }
        if has_d { k.d.append(db); k.private = true; }
        let ev = validate(k);
        return k, ev;
    }
    // RSA: n and e; d, p, q (and dp, dq, qi, which are derived again and
    // must agree) when private.
    var nb: u8[>..] = [];
    var eb: u8[>..] = [];
    let has_n, en = bytes_member(n, "n", nb);
    let has_e, ee = bytes_member(n, "e", eb);
    if en != jwx::OK || ee != jwx::OK || !has_n || !has_e { return k, jwx::ERR_MALFORMED; }
    if nb.len == 0 || eb.len == 0 || nb.len > 1024 || eb.len > 8 { return k, jwx::ERR_KEY; }
    var db: u8[>..] = [];
    let has_d, ed = bytes_member(n, "d", db);
    if ed != jwx::OK { return k, ed; }
    if !has_d {
        let pub, ok = bignum::rsa_public_from(bignum::from_bytes_be(nb), bignum::from_bytes_be(eb));
        if !ok { return k, jwx::ERR_KEY; }
        k.rsa.n.append(pub.n);
        k.rsa.e.append(pub.e);
        return k, jwx::OK;
    }
    if json::member(n, "oth") { return k, jwx::ERR_UNSUPPORTED; }
    var pb: u8[>..] = [];
    var qb: u8[>..] = [];
    let has_p, ep = bytes_member(n, "p", pb);
    let has_q, eq = bytes_member(n, "q", qb);
    if ep != jwx::OK || eq != jwx::OK { return k, jwx::ERR_MALFORMED; }
    // A private key of n, e and d alone is RFC 7518's, but nothing here can
    // use one without its primes, as Go's crypto/rsa cannot.
    if !has_p || !has_q { return k, jwx::ERR_UNSUPPORTED; }
    if db.len > 1024 || pb.len > 512 || qb.len > 512 { return k, jwx::ERR_KEY; }
    let r, ok = bignum::rsa_key_from_bytes(nb, eb, db, pb, qb);
    if !ok { return k, jwx::ERR_KEY; }
    k.rsa = r;
    k.private = true;
    // The CRT values, when given, must be the ones derived.
    for name in ["dp", "dq", "qi"] {
        var v: u8[>..] = [];
        let present, err = bytes_member(n, name, v);
        if err != jwx::OK { return k, err; }
        if present {
            let mine = if name == "dp" { uint_bytes(k.rsa.dp) } else if name == "dq" { uint_bytes(k.rsa.dq) }
                       else { uint_bytes(k.rsa.qinv) };
            if bignum::cmp(bignum::from_bytes_be(v), bignum::from_bytes_be(mine)) != 0 { return k, jwx::ERR_KEY; }
        }
    }
    return k, jwx::OK;
}

// A key from JWK text.
fn parse(text: const u8[:]) -> Key, i64 {
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return empty(), jwx::ERR_MALFORMED; }
    let k, err = from_node(root);
    return k, err;
}

// The keys of a JWK Set ({"keys": [...]}) appended to keys. Keys of a type
// or curve this package does not do are passed over, as RFC 7517 §5 asks;
// any other fault fails the whole set. A lone JWK is taken as a set of one.
fn parse_set(text: const u8[:], keys: Key[>..]&) -> i64 {
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return jwx::ERR_MALFORMED; }
    let list = json::member(root, "keys");
    guard list else {
        let k, err = from_node(root);
        if err == jwx::OK { keys.push(k); }
        return err;
    }
    match list.val {
        Arr => {},
        _ => { return jwx::ERR_MALFORMED; },
    }
    var err = jwx::OK;
    json::each(list) { n =>
        let k, e = from_node(n);
        if e == jwx::OK { keys.push(k); }
        else if e != jwx::ERR_UNSUPPORTED && err == jwx::OK { err = e; }
    };
    return err;
}

// The first key of the set whose "kid" is kid; null if none.
fn lookup_kid(keys: Key[:], kid: const u8[:]) -> Key? {
    for &k in keys {
        if k.kid[..] == kid { return k; }
    }
    return null;
}

// --- Writing ------------------------------------------------------------------------------

// A big-endian unsigned integer from limbs, in the fewest bytes (RFC 7518
// §2's Base64urlUInt).
fn uint_bytes(xs: const u32[:]) -> u8[>..] {
    let v = bignum::big_of(xs);
    return bignum::to_bytes_be(v, max(1, (bignum::bit_len(v) + 7) / 8));
}

fn put_string(out: u8[>..]&, name: const u8[:], v: const u8[:]) {
    jwx::put_comma(out);
    json::format_key(out, name);
    json::format_string(out, v);
}

fn put_bytes(out: u8[>..]&, name: const u8[:], v: const u8[:]) {
    jwx::put_comma(out);
    json::format_key(out, name);
    out.push('"');
    jwx::b64_append(out, v);
    out.push('"');
}

// The key as JWK JSON, its members in lexical order (as jwx writes them,
// and as RFC 7638 wants a thumbprint's). The private parts go out only
// when `private` is true.
fn marshal_to(out: u8[>..]&, k: const Key&, private: bool = true) {
    let priv = private && k.private;
    out.push('{');
    if k.alg != jwa::UNKNOWN { put_string(out, "alg", jwa::name(k.alg)); }
    if k.kty == jwa::KTY_EC || k.kty == jwa::KTY_OKP { put_string(out, "crv", jwa::crv_name(k.crv)); }
    if k.kty == jwa::KTY_EC || k.kty == jwa::KTY_OKP {
        if priv { put_bytes(out, "d", k.d); }
    } else if k.kty == jwa::KTY_RSA && priv {
        put_bytes(out, "d", uint_bytes(k.rsa.d));
        put_bytes(out, "dp", uint_bytes(k.rsa.dp));
        put_bytes(out, "dq", uint_bytes(k.rsa.dq));
    }
    if k.kty == jwa::KTY_RSA { put_bytes(out, "e", uint_bytes(k.rsa.e)); }
    if k.kty == jwa::KTY_OCT { put_bytes(out, "k", k.k); }
    if k.key_ops != 0 {
        jwx::put_comma(out);
        json::format_key(out, "key_ops");
        out.push('[');
        for i in OP_NAMES.len {
            if k.key_ops & (1 << i as u32) != 0 {
                jwx::put_comma(out);
                json::format_string(out, OP_NAMES[i]);
            }
        }
        out.push(']');
    }
    if k.kid.len > 0 { put_string(out, "kid", k.kid); }
    put_string(out, "kty", jwa::kty_name(k.kty));
    if k.kty == jwa::KTY_AKP {
        if priv { put_bytes(out, "priv", k.d); }
        put_bytes(out, "pub", k.pub);
    }
    if k.kty == jwa::KTY_RSA {
        put_bytes(out, "n", uint_bytes(k.rsa.n));
        if priv {
            put_bytes(out, "p", uint_bytes(k.rsa.p));
            put_bytes(out, "q", uint_bytes(k.rsa.q));
            put_bytes(out, "qi", uint_bytes(k.rsa.qinv));
        }
    }
    if k.key_use == USE_SIG { put_string(out, "use", "sig"); }
    if k.key_use == USE_ENC { put_string(out, "use", "enc"); }
    if k.kty == jwa::KTY_EC || k.kty == jwa::KTY_OKP { put_bytes(out, "x", k.x); }
    if k.x5t.len > 0 { put_bytes(out, "x5t", k.x5t); }
    if k.x5t256.len > 0 { put_bytes(out, "x5t#S256", k.x5t256); }
    if k.kty == jwa::KTY_EC { put_bytes(out, "y", k.y); }
    out.push('}');
}

fn marshal(k: const Key&, private: bool = true) -> u8[>..] {
    var out: u8[>..] = [];
    marshal_to(out, k, private);
    return out;
}

// A JWK Set of the keys.
fn marshal_set(keys: const Key[:], private: bool = true) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("{\"keys\":[");
    for &k in keys {
        if out[out.len - 1] != '[' { out.push(','); }
        marshal_to(out, k, private);
    }
    out.append("]}");
    return out;
}

// --- Thumbprints (RFC 7638, RFC 8037 §2) ------------------------------------------------

// The JSON a thumbprint hashes: the required members only, in lexical
// order, no white space.
fn thumbprint_input(k: const Key&) -> u8[>..] {
    var out: u8[>..] = [];
    out.push('{');
    if k.kty == jwa::KTY_EC {
        put_string(out, "crv", jwa::crv_name(k.crv));
        put_string(out, "kty", "EC");
        put_bytes(out, "x", k.x);
        put_bytes(out, "y", k.y);
    } else if k.kty == jwa::KTY_OKP {
        put_string(out, "crv", jwa::crv_name(k.crv));
        put_string(out, "kty", "OKP");
        put_bytes(out, "x", k.x);
    } else if k.kty == jwa::KTY_AKP {
        // RFC 9964 §6: alg, kty and pub.
        put_string(out, "alg", jwa::name(k.alg));
        put_string(out, "kty", "AKP");
        put_bytes(out, "pub", k.pub);
    } else if k.kty == jwa::KTY_RSA {
        put_bytes(out, "e", uint_bytes(k.rsa.e));
        put_string(out, "kty", "RSA");
        put_bytes(out, "n", uint_bytes(k.rsa.n));
    } else {
        put_bytes(out, "k", k.k);
        put_string(out, "kty", "oct");
    }
    out.push('}');
    return out;
}

// The thumbprint under a bignum.hmac hash id (SHA-256 by default).
fn thumbprint(k: const Key&, hash: i64 = 256) -> u8[>..] {
    return bignum::hash_bits(hash, thumbprint_input(k));
}

// The thumbprint in base64url, the usual "kid" made from it.
fn thumbprint_b64(k: const Key&, hash: i64 = 256) -> u8[>..] {
    return jwx::b64_encode(thumbprint(k, hash));
}
