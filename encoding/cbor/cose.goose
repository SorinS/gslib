// cbor.cose: COSE_Key public keys (RFC 9052 §7, RFC 9053; RFC 8230 for
// RSA) as WebAuthn and CTAP carry them: EC2 on P-256, P-384 and P-521, OKP
// on Ed25519 and Ed448, and RSA; read from a CBOR map and checked (the
// point on its curve, the right lengths, no private parts), written in the
// deterministic encoding, and used to verify signatures by the COSE
// algorithms ES256, ES384, ES512 (and RFC 9864's ESP256, ESP384, ESP512),
// EdDSA, Ed25519, Ed448, RS256, RS384, RS512, PS256, PS384, PS512, and
// RS1 only when asked. A key and an algorithm must fit each other: ES256
// is P-256 only, Ed448 an Ed448 key, RS256 and PS256 an RSA key. Keys
// convert to and from jwx's JWKs, SubjectPublicKeyInfo DER and
// certificates' keys (through jwx.pem), so that what crypto/x509 holds can
// be compared with what an authenticator sent.
//
// A separate module, so that cbor alone brings in no cryptography.

namespace cose;

import std;
import encoding.cbor;
import jwx;
import jwx.jwa;
import jwx.jwk;
import jwx.pem;
import crypto.x509;
import crypto.bignum;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.ed25519;
import crypto.bignum.ed448;
import crypto.bignum.hmac;

// --- Names ----------------------------------------------------------------------

// Key types (RFC 9053 §7).
let KTY_OKP: i64 = 1;
let KTY_EC2: i64 = 2;
let KTY_RSA: i64 = 3;

// Curves (RFC 9053 §7.1).
let CRV_P256:    i64 = 1;
let CRV_P384:    i64 = 2;
let CRV_P521:    i64 = 3;
let CRV_X25519:  i64 = 4;
let CRV_X448:    i64 = 5;
let CRV_ED25519: i64 = 6;
let CRV_ED448:   i64 = 7;

// Algorithms (the IANA COSE Algorithms registry).
let ES256:   i64 = -7;
let ES384:   i64 = -35;
let ES512:   i64 = -36;
let ESP256:  i64 = -9;       // RFC 9864: ECDSA on P-256 with SHA-256, fully specified
let ESP384:  i64 = -51;
let ESP512:  i64 = -52;
let EDDSA:   i64 = -8;       // either Edwards curve, by the key
let ED25519: i64 = -19;      // RFC 9864
let ED448:   i64 = -53;      // RFC 9864
let PS256:   i64 = -37;
let PS384:   i64 = -38;
let PS512:   i64 = -39;
let RS256:   i64 = -257;     // RFC 8812: RSASSA-PKCS1-v1_5
let RS384:   i64 = -258;
let RS512:   i64 = -259;
let RS1:     i64 = -65535;   // RSASSA-PKCS1-v1_5 with SHA-1: old TPMs' attestation only

// Map labels.
let LABEL_KTY:     i64 = 1;
let LABEL_KID:     i64 = 2;
let LABEL_ALG:     i64 = 3;
let LABEL_KEY_OPS: i64 = 4;
let LABEL_CRV:     i64 = -1; // EC2 and OKP; RSA's n
let LABEL_X:       i64 = -2; // EC2 and OKP; RSA's e
let LABEL_Y:       i64 = -3; // EC2; RSA's d
let LABEL_D:       i64 = -4; // EC2 and OKP private key; RSA's p

// --- Errors ---------------------------------------------------------------------

let OK:               i64 = 0;
let ERR_MALFORMED:    i64 = 1;    // not a COSE_Key map, or a member of the wrong type
let ERR_UNSUPPORTED:  i64 = 2;    // a key type, curve or algorithm this package does not do
let ERR_KEY:          i64 = 3;    // a bad key: off its curve, a wrong length, private parts, RSA too short
let ERR_ALG_MISMATCH: i64 = 4;    // the algorithm does not fit the key, or is not the key's own
let ERR_SIGNATURE:    i64 = 5;    // the signature does not verify
let ERR_FORBIDDEN:    i64 = 6;    // an algorithm known but not allowed (RS1 unless asked)
let ERR_UNKNOWN_ALG:  i64 = 7;    // an algorithm this package does not know (a key's alg, or verify's)

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_MALFORMED { return "malformed COSE key"; }
    if e == ERR_UNSUPPORTED { return "unsupported key type, curve or algorithm"; }
    if e == ERR_KEY { return "invalid key"; }
    if e == ERR_ALG_MISMATCH { return "algorithm does not fit the key"; }
    if e == ERR_SIGNATURE { return "bad signature"; }
    if e == ERR_FORBIDDEN { return "algorithm not allowed"; }
    if e == ERR_UNKNOWN_ALG { return "unknown algorithm"; }
    return "unknown error";
}

fn alg_name(alg: i64) -> const u8[:] {
    if alg == ES256 { return "ES256"; }
    if alg == ES384 { return "ES384"; }
    if alg == ES512 { return "ES512"; }
    if alg == ESP256 { return "ESP256"; }
    if alg == ESP384 { return "ESP384"; }
    if alg == ESP512 { return "ESP512"; }
    if alg == EDDSA { return "EdDSA"; }
    if alg == ED25519 { return "Ed25519"; }
    if alg == ED448 { return "Ed448"; }
    if alg == PS256 { return "PS256"; }
    if alg == PS384 { return "PS384"; }
    if alg == PS512 { return "PS512"; }
    if alg == RS256 { return "RS256"; }
    if alg == RS384 { return "RS384"; }
    if alg == RS512 { return "RS512"; }
    if alg == RS1 { return "RS1"; }
    return "unknown";
}

// Every signature algorithm known here, RS1 included.
fn known_alg(alg: i64) -> bool {
    return alg == ES256 || alg == ES384 || alg == ES512 || alg == ESP256 || alg == ESP384 || alg == ESP512
        || alg == EDDSA || alg == ED25519 || alg == ED448 || alg == PS256 || alg == PS384 || alg == PS512
        || alg == RS256 || alg == RS384 || alg == RS512 || alg == RS1;
}

fn is_ecdsa(alg: i64) -> bool {
    alg == ES256 || alg == ES384 || alg == ES512 || alg == ESP256 || alg == ESP384 || alg == ESP512
}
fn is_eddsa(alg: i64) -> bool { alg == EDDSA || alg == ED25519 || alg == ED448 }
fn is_pss(alg: i64) -> bool { alg == PS256 || alg == PS384 || alg == PS512 }
fn is_pkcs1(alg: i64) -> bool { alg == RS256 || alg == RS384 || alg == RS512 || alg == RS1 }

// The hash of an algorithm, as bignum names them (160, 256, 384, 512); 0
// for EdDSA, which hashes inside.
fn hash_of(alg: i64) -> i64 {
    if alg == ES256 || alg == ESP256 || alg == PS256 || alg == RS256 { return 256; }
    if alg == ES384 || alg == ESP384 || alg == PS384 || alg == RS384 { return 384; }
    if alg == ES512 || alg == ESP512 || alg == PS512 || alg == RS512 { return 512; }
    if alg == RS1 { return 160; }
    return 0;
}

// The curve an ECDSA algorithm is for.
fn curve_of(alg: i64) -> i64 {
    if alg == ES256 || alg == ESP256 { return CRV_P256; }
    if alg == ES384 || alg == ESP384 { return CRV_P384; }
    if alg == ES512 || alg == ESP512 { return CRV_P521; }
    return 0;
}

// The length of a curve's coordinates (EC2) or keys (OKP).
fn crv_len(crv: i64) -> i64 {
    if crv == CRV_P256 || crv == CRV_ED25519 || crv == CRV_X25519 { return 32; }
    if crv == CRV_P384 { return 48; }
    if crv == CRV_P521 { return 66; }
    if crv == CRV_ED448 { return 57; }
    if crv == CRV_X448 { return 56; }
    return 0;
}

fn curve(crv: i64) -> bignum::Curve {
    if crv == CRV_P384 { return bignum::p384(); }
    if crv == CRV_P521 { return bignum::p521(); }
    return bignum::p256();
}

// --- Keys -----------------------------------------------------------------------

// A COSE public key. EC2 keys hold x and y at the curve's length, OKP keys
// x; RSA keys n and e, big-endian without leading zeros (up to 8192
// bits). `alg` is the key's own algorithm (label 3), 0 when absent.
struct Key {
    kty: i64,
    alg: i64,
    crv: i64,
    x:   u8[..66],
    y:   u8[..66],
    n:   u8[..1024],
    e:   u8[..8],
}

fn empty() -> Key { Key { kty: 0, alg: 0, crv: 0, x: [], y: [], n: [], e: [] } }

// The smallest RSA key a key check takes, in bits.
let MIN_RSA_BITS: i64 = 2048;

// Checks a key: a curve this package does, the point on it, lengths,
// and an RSA modulus of min_rsa_bits to 8192 bits with an odd exponent.
fn validate(k: const Key&, min_rsa_bits: i64 = MIN_RSA_BITS) -> i64 {
    if k.alg != 0 && !known_alg(k.alg) { return ERR_UNKNOWN_ALG; }
    if k.kty == KTY_EC2 {
        if k.crv != CRV_P256 && k.crv != CRV_P384 && k.crv != CRV_P521 { return ERR_UNSUPPORTED; }
        let n = crv_len(k.crv);
        if k.x.len != n || k.y.len != n { return ERR_KEY; }
        let c = curve(k.crv);
        let p, ok = bignum::ec_decode(c, ec_point(k));
        return if ok { OK } else { ERR_KEY };
    }
    if k.kty == KTY_OKP {
        if k.crv == CRV_ED25519 {
            if k.x.len != 32 { return ERR_KEY; }
            let p, ok = bignum::ed_decode(k.x);
            return if ok { OK } else { ERR_KEY };
        }
        if k.crv == CRV_ED448 {
            if k.x.len != 57 { return ERR_KEY; }
            let p, ok = bignum::e448_decode(k.x);
            return if ok { OK } else { ERR_KEY };
        }
        return ERR_UNSUPPORTED;
    }
    if k.kty == KTY_RSA {
        if k.n.len == 0 || k.e.len == 0 || k.n[0] == 0 || k.e[0] == 0 { return ERR_KEY; }
        let pub, ok = rsa_public(k);
        if !ok { return ERR_KEY; }
        if bignum::rsa_bits(pub) < min_rsa_bits { return ERR_KEY; }
        return OK;
    }
    return ERR_UNSUPPORTED;
}

// The uncompressed point 04 || x || y of an EC2 key.
fn ec_point(k: const Key&) -> u8[>..] {
    var p: u8[>..] = [];
    p.push(4);
    p.append(k.x);
    p.append(k.y);
    return p;
}

// bignum's RSA public key of an RSA key.
fn rsa_public(k: const Key&) -> bignum::RsaPublicKey, bool {
    let pub, ok = bignum::rsa_public_from(bignum::from_bytes_be(k.n), bignum::from_bytes_be(k.e));
    return pub, ok;
}

// Reads a COSE_Key from the map at doc[m]: OK, or why not. Only public
// keys are taken: a key with private parts (d, or RSA's) is ERR_KEY, a
// symmetric key ERR_UNSUPPORTED. Labels this package does not know are
// ignored, as RFC 9052 §7 asks; kid and key_ops too.
fn from_cbor(buf: const u8[:], doc: const cbor::Node[:], m: i64, min_rsa_bits: i64 = MIN_RSA_BITS) -> Key, i64 {
    var k = empty();
    if !cbor::is_map(doc, m) { return k, ERR_MALFORMED; }
    let kty, okt = cbor::as_i64(doc, cbor::map_get_int(doc, m, LABEL_KTY));
    if !okt { return k, ERR_MALFORMED; }
    if kty != KTY_EC2 && kty != KTY_OKP && kty != KTY_RSA { return k, ERR_UNSUPPORTED; }
    k.kty = kty;
    let ai = cbor::map_get_int(doc, m, LABEL_ALG);
    if ai >= 0 {
        let alg, oka = cbor::as_i64(doc, ai);
        if !oka { return k, ERR_MALFORMED; }
        k.alg = alg;
    }
    if kty == KTY_RSA {
        let nb, okn = cbor::as_bytes(buf, doc, cbor::map_get_int(doc, m, -1));
        let eb, oke = cbor::as_bytes(buf, doc, cbor::map_get_int(doc, m, -2));
        if !okn || !oke { return k, ERR_MALFORMED; }
        // d, p, q, dP, dQ, qInv (-3 to -8) and other primes (-9 to -12).
        for l in 3..13 { if cbor::map_get_int(doc, m, -l) >= 0 { return k, ERR_KEY; } }
        if nb.len > k.n.cap || eb.len > k.e.cap { return k, ERR_KEY; }
        k.n.append(nb);
        k.e.append(eb);
    } else {
        let crv, okc = cbor::as_i64(doc, cbor::map_get_int(doc, m, LABEL_CRV));
        if !okc { return k, ERR_MALFORMED; }
        k.crv = crv;
        let xb, okx = cbor::as_bytes(buf, doc, cbor::map_get_int(doc, m, LABEL_X));
        if !okx { return k, ERR_MALFORMED; }
        if xb.len > k.x.cap { return k, ERR_KEY; }
        k.x.append(xb);
        if cbor::map_get_int(doc, m, LABEL_D) >= 0 { return k, ERR_KEY; }
        if kty == KTY_EC2 {
            let yi = cbor::map_get_int(doc, m, LABEL_Y);
            // y as a bool is point compression (RFC 9053 §7.1.1): not taken.
            let yb, oky = cbor::as_bytes(buf, doc, yi);
            if !oky {
                let bv, isb = cbor::as_bool(doc, yi);
                return k, if isb { ERR_UNSUPPORTED } else { ERR_MALFORMED };
            }
            if yb.len > k.y.cap { return k, ERR_KEY; }
            k.y.append(yb);
        } else if cbor::map_get_int(doc, m, LABEL_Y) >= 0 {
            return k, ERR_MALFORMED;
        }
    }
    let e = validate(k, min_rsa_bits);
    return k, e;
}

// Reads the COSE_Key encoded at buf[at..]: the key, where its encoding
// ends, and OK or why not (a cbor error is ERR_MALFORMED). The encoding is
// decoded strictly, by cbor's defaults.
fn decode_at(buf: const u8[:], at: i64, min_rsa_bits: i64 = MIN_RSA_BITS) -> Key, i64, i64 {
    var doc: cbor::Node[>..] = [];
    let root, end, e = cbor::decode_at(buf, at, cbor::Options { .. }, doc);
    if e != cbor::OK { return empty(), at, ERR_MALFORMED; }
    let k, ek = from_cbor(buf, doc, root, min_rsa_bits);
    return k, end, ek;
}

// Reads a COSE_Key that is the whole of buf.
fn decode(buf: const u8[:], min_rsa_bits: i64 = MIN_RSA_BITS) -> Key, i64 {
    let k, end, e = decode_at(buf, 0, min_rsa_bits);
    if e == OK && end != buf.len { return k, ERR_MALFORMED; }
    return k, e;
}

// The key as a COSE_Key, deterministically encoded: kty, alg when set, and
// the public parameters.
fn encode(k: const Key&) -> u8[>..] {
    var out: u8[>..] = [];
    let pairs = if k.kty == KTY_RSA { 3 } else if k.kty == KTY_EC2 { 4 } else { 3 };
    let with_alg = if k.alg != 0 { 1 } else { 0 };
    cbor::put_map(out, pairs + with_alg);
    cbor::put_int(out, LABEL_KTY);
    cbor::put_int(out, k.kty);
    if k.alg != 0 {
        cbor::put_int(out, LABEL_ALG);
        cbor::put_int(out, k.alg);
    }
    if k.kty == KTY_RSA {
        cbor::put_int(out, -1);
        cbor::put_bytes(out, k.n);
        cbor::put_int(out, -2);
        cbor::put_bytes(out, k.e);
    } else {
        cbor::put_int(out, LABEL_CRV);
        cbor::put_int(out, k.crv);
        cbor::put_int(out, LABEL_X);
        cbor::put_bytes(out, k.x);
        if k.kty == KTY_EC2 {
            cbor::put_int(out, LABEL_Y);
            cbor::put_bytes(out, k.y);
        }
    }
    let e = cbor::sort_map(out, 0);
    return out;
}

// Whether a signature by alg can be made with the key: its type and curve,
// and its own alg when it has one.
fn fits(k: const Key&, alg: i64) -> bool {
    if k.alg != 0 && k.alg != alg { return false; }
    if is_ecdsa(alg) { return k.kty == KTY_EC2 && k.crv == curve_of(alg); }
    if alg == EDDSA { return k.kty == KTY_OKP && (k.crv == CRV_ED25519 || k.crv == CRV_ED448); }
    if alg == ED25519 { return k.kty == KTY_OKP && k.crv == CRV_ED25519; }
    if alg == ED448 { return k.kty == KTY_OKP && k.crv == CRV_ED448; }
    if is_pss(alg) || is_pkcs1(alg) { return k.kty == KTY_RSA; }
    return false;
}

// Verifies sig over msg by alg with the key. ECDSA signatures are DER
// (WebAuthn's and X.509's form) unless `raw_ecdsa`, when they are r || s
// (COSE_Sign1's). RS1 is ERR_FORBIDDEN unless allow_sha1.
fn verify(k: const Key&, alg: i64, msg: const u8[:], sig: const u8[:], raw_ecdsa: bool = false,
          allow_sha1: bool = false) -> i64 {
    if !known_alg(alg) { return ERR_UNKNOWN_ALG; }
    if alg == RS1 && !allow_sha1 { return ERR_FORBIDDEN; }
    if !fits(k, alg) { return ERR_ALG_MISMATCH; }
    if is_eddsa(alg) {
        let good = if k.crv == CRV_ED25519 { bignum::ed25519_verify(k.x, msg, sig) }
                   else { bignum::ed448_verify(k.x, msg, sig) };
        return if good { OK } else { ERR_SIGNATURE };
    }
    let h = hash_of(alg);
    let digest = bignum::hash_bits(h, msg);
    if is_ecdsa(alg) {
        let c = curve(k.crv);
        let pt = ec_point(k);
        if raw_ecdsa {
            if sig.len != 2 * c.len { return ERR_SIGNATURE; }
            return if bignum::ecdsa_verify_digest(c, pt, digest, sig) { OK } else { ERR_SIGNATURE };
        }
        let rs, okd = bignum::ecdsa_sig_from_der(c, sig);
        if !okd { return ERR_SIGNATURE; }
        return if bignum::ecdsa_verify_digest(c, pt, digest, rs) { OK } else { ERR_SIGNATURE };
    }
    let pub, ok = rsa_public(k);
    if !ok { return ERR_KEY; }
    // PSS with the salt as long as the hash (RFC 8230 §2).
    let good = if is_pss(alg) { bignum::rsa_verify_pss_digest(pub, digest, sig, bignum::hash_len(h), h) }
               else { bignum::rsa_verify_pkcs1_digest(pub, digest, sig, h) };
    return if good { OK } else { ERR_SIGNATURE };
}

// Whether two keys are the same public key (their algorithms aside).
fn same_key(a: const Key&, b: const Key&) -> bool {
    if a.kty != b.kty { return false; }
    if a.kty == KTY_RSA { return a.n[..] == b.n[..] && a.e[..] == b.e[..]; }
    return a.crv == b.crv && a.x[..] == b.x[..] && a.y[..] == b.y[..];
}

// --- Other forms ----------------------------------------------------------------

fn trim_zeros(b: const u8[:]) -> const u8[:] {
    var i = 0;
    while i + 1 < b.len && b[i] == 0 { i++; }
    return b[i..];
}

// The key as a JWK (jwx), its alg too when JOSE has one.
fn to_jwk(k: const Key&) -> jwk::Key, i64 {
    var j = jwk::empty();
    if k.kty == KTY_RSA {
        let pub, ok = rsa_public(k);
        if !ok { return j, ERR_KEY; }
        j.kty = jwa::KTY_RSA;
        j.rsa.n.append(pub.n);
        j.rsa.e.append(pub.e);
    } else if k.kty == KTY_EC2 {
        j.kty = jwa::KTY_EC;
        j.crv = if k.crv == CRV_P256 { jwa::CRV_P256 } else if k.crv == CRV_P384 { jwa::CRV_P384 }
                else if k.crv == CRV_P521 { jwa::CRV_P521 } else { jwa::CRV_UNKNOWN };
        if j.crv == jwa::CRV_UNKNOWN { return j, ERR_UNSUPPORTED; }
        j.x.append(k.x);
        j.y.append(k.y);
    } else if k.kty == KTY_OKP {
        j.kty = jwa::KTY_OKP;
        j.crv = if k.crv == CRV_ED25519 { jwa::CRV_ED25519 } else if k.crv == CRV_ED448 { jwa::CRV_ED448 }
                else { jwa::CRV_UNKNOWN };
        if j.crv == jwa::CRV_UNKNOWN { return j, ERR_UNSUPPORTED; }
        j.x.append(k.x);
    } else {
        return j, ERR_UNSUPPORTED;
    }
    j.alg = jose_alg(k.alg);
    return j, OK;
}

// The JOSE algorithm of a COSE one, or jwa::UNKNOWN.
fn jose_alg(alg: i64) -> i64 {
    if alg == ES256 || alg == ESP256 { return jwa::ES256; }
    if alg == ES384 || alg == ESP384 { return jwa::ES384; }
    if alg == ES512 || alg == ESP512 { return jwa::ES512; }
    if alg == EDDSA { return jwa::EDDSA; }
    if alg == ED25519 { return jwa::ED25519; }
    if alg == ED448 { return jwa::ED448; }
    if alg == RS256 { return jwa::RS256; }
    if alg == RS384 { return jwa::RS384; }
    if alg == RS512 { return jwa::RS512; }
    if alg == PS256 { return jwa::PS256; }
    if alg == PS384 { return jwa::PS384; }
    if alg == PS512 { return jwa::PS512; }
    return jwa::UNKNOWN;
}

// The public key of a JWK, without an alg.
fn from_jwk(j: const jwk::Key&) -> Key, i64 {
    var k = empty();
    if j.kty == jwa::KTY_RSA {
        k.kty = KTY_RSA;
        let nb = jwk::uint_bytes(j.rsa.n);
        let eb = jwk::uint_bytes(j.rsa.e);
        if nb.len > k.n.cap || eb.len > k.e.cap { return k, ERR_KEY; }
        k.n.append(nb);
        k.e.append(eb);
        return k, OK;
    }
    if j.kty == jwa::KTY_EC {
        k.kty = KTY_EC2;
        k.crv = if j.crv == jwa::CRV_P256 { CRV_P256 } else if j.crv == jwa::CRV_P384 { CRV_P384 }
                else if j.crv == jwa::CRV_P521 { CRV_P521 } else { 0 };
        if k.crv == 0 { return k, ERR_UNSUPPORTED; }
        k.x.append(j.x);
        k.y.append(j.y);
        return k, OK;
    }
    if j.kty == jwa::KTY_OKP && (j.crv == jwa::CRV_ED25519 || j.crv == jwa::CRV_ED448) {
        k.kty = KTY_OKP;
        k.crv = if j.crv == jwa::CRV_ED25519 { CRV_ED25519 } else { CRV_ED448 };
        k.x.append(j.x);
        return k, OK;
    }
    return k, ERR_UNSUPPORTED;
}

// The key as SubjectPublicKeyInfo DER, as crypto/x509 and jwx.pem read it.
fn to_spki(k: const Key&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let j, e = to_jwk(k);
    if e != OK { return out, e; }
    let der, ej = jwk::marshal_spki(j);
    if ej != jwx::OK { return out, ERR_UNSUPPORTED; }
    out.append(der);
    return out, OK;
}

// The key of a SubjectPublicKeyInfo's DER.
fn from_spki(der: const u8[:]) -> Key, i64 {
    let j, e = jwk::from_spki(der);
    if e != jwx::OK { return empty(), if e == jwx::ERR_UNSUPPORTED { ERR_UNSUPPORTED } else { ERR_KEY }; }
    let k, ek = from_jwk(j);
    return k, ek;
}

// The public key of a certificate.
fn from_cert(c: const x509::Cert&) -> Key, i64 {
    let j, e = jwk::from_spki_tlv(c.der, c.spki);
    if e != jwx::OK { return empty(), if e == jwx::ERR_UNSUPPORTED { ERR_UNSUPPORTED } else { ERR_KEY }; }
    let k, ek = from_jwk(j);
    return k, ek;
}
