// pkcs11.p11: the layer over pkcs11 that miekg/pkcs11's p11 package is: a
// Module, its Slots, Sessions on them, and the Objects of a token, with
// private, public and secret keys that sign, verify, encrypt, decrypt and
// derive.
//
//   var m, rv = p11::open_module("/usr/lib/softhsm/libsofthsm2.so");
//   let slots, rv2 = p11::slots(m);
//   var s, rv3 = p11::open_write_session(slots[0]);
//   p11::login(s, "1234");
//   let key, rv4 = p11::find_private_key(s, "signing key");
//   let sig, rv5 = p11::sign(key, pkcs11::mechanism(pkcs11::CKM_ECDSA_SHA256), message);
//
// Results come with a CK_RV, as in pkcs11; ERR_NO_OBJECT and
// ERR_MULTIPLE_OBJECTS are this module's own.

namespace p11;

import std;
import pkcs11;
import pkcs11.constants;
import crypto.bignum;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import encoding.asn1;
import crypto.x509;
import crypto.x509.keys;

let ERR_NO_OBJECT: u64 = 0x100000010;          // a find that wanted one object found none
let ERR_MULTIPLE_OBJECTS: u64 = 0x100000011;   // ... or more than one

fn error_text(rv: u64) -> u8[>..] {
    if rv == ERR_NO_OBJECT { return str("p11: no objects found"); }
    if rv == ERR_MULTIPLE_OBJECTS { return str("p11: too many objects matching template"); }
    return pkcs11::error_text(rv);
}

struct Module { ctx: pkcs11::Ctx }
struct Slot { ctx: pkcs11::Ctx, id: u64 }
struct Session { ctx: pkcs11::Ctx, slot: u64, handle: u64 }
struct Object { ctx: pkcs11::Ctx, session: u64, handle: u64 }
struct PrivateKey { object: Object }
struct PublicKey { object: Object }
struct SecretKey { object: Object }
struct KeyPair { public: PublicKey, private: PrivateKey }

// --- Modules ----------------------------------------------------------------------

// The module at path, loaded and initialized (a module some other part of
// the program initialized already is taken as it is).
fn open_module(path: const u8[:]) -> Module, u64 {
    var c, ok = pkcs11::new(path);
    if !ok { return Module { ctx: c }, pkcs11::ERR_LOAD; }
    let rv = pkcs11::initialize(c, pkcs11::CKF_OS_LOCKING_OK);
    if rv != pkcs11::CKR_OK && rv != pkcs11::CKR_CRYPTOKI_ALREADY_INITIALIZED {
        pkcs11::destroy(c);
        return Module { ctx: c }, rv;
    }
    return Module { ctx: c }, pkcs11::CKR_OK;
}

fn info(m: Module) -> pkcs11::Info, u64 {
    let i, rv = pkcs11::get_info(m.ctx);
    return i, rv;
}

// The slots with a token present.
fn slots(m: Module) -> Slot[>..], u64 {
    var out: Slot[>..] = [];
    let ids, rv = pkcs11::get_slot_list(m.ctx, true);
    for id in ids { out.push(Slot { ctx: m.ctx, id: id }); }
    return out, rv;
}

// Finalizes and unloads the module.
fn destroy(m: Module&) {
    pkcs11::finalize(m.ctx);
    pkcs11::destroy(m.ctx);
}

// --- Slots ------------------------------------------------------------------------------

fn info(s: Slot) -> pkcs11::SlotInfo, u64 {
    let i, rv = pkcs11::get_slot_info(s.ctx, s.id);
    return i, rv;
}

fn token_info(s: Slot) -> pkcs11::TokenInfo, u64 {
    let i, rv = pkcs11::get_token_info(s.ctx, s.id);
    return i, rv;
}

fn open_session_with_flags(s: Slot, flags: u64) -> Session, u64 {
    let h, rv = pkcs11::open_session(s.ctx, s.id, flags | pkcs11::CKF_SERIAL_SESSION);
    return Session { ctx: s.ctx, slot: s.id, handle: h }, rv;
}

// A read-only session.
fn open_session(s: Slot) -> Session, u64 {
    let r, rv = open_session_with_flags(s, 0);
    return r, rv;
}

// A read-write session, for creating, changing and deleting objects.
fn open_write_session(s: Slot) -> Session, u64 {
    let r, rv = open_session_with_flags(s, pkcs11::CKF_RW_SESSION);
    return r, rv;
}

fn close_all_sessions(s: Slot) -> u64 { pkcs11::close_all_sessions(s.ctx, s.id) }

// The mechanism types the token does; mechanism_info for each one's sizes
// and flags.
fn mechanisms(s: Slot) -> u64[>..], u64 {
    let m, rv = pkcs11::get_mechanism_list(s.ctx, s.id);
    return m, rv;
}

fn mechanism_info(s: Slot, mech: u64) -> pkcs11::MechanismInfo, u64 {
    let i, rv = pkcs11::get_mechanism_info(s.ctx, s.id, mech);
    return i, rv;
}

fn init_token(s: Slot, so_pin: const u8[:], label: const u8[:]) -> u64 { pkcs11::init_token(s.ctx, s.id, so_pin, label) }

// --- Sessions ------------------------------------------------------------------------------

fn close(s: Session) -> u64 { pkcs11::close_session(s.ctx, s.handle) }
fn login(s: Session, pin: const u8[:]) -> u64 { pkcs11::login(s.ctx, s.handle, pkcs11::CKU_USER, pin) }
fn login_security_officer(s: Session, pin: const u8[:]) -> u64 { pkcs11::login(s.ctx, s.handle, pkcs11::CKU_SO, pin) }
fn login_as(s: Session, user_type: u64, pin: const u8[:]) -> u64 { pkcs11::login(s.ctx, s.handle, user_type, pin) }
fn logout(s: Session) -> u64 { pkcs11::logout(s.ctx, s.handle) }
fn init_pin(s: Session, pin: const u8[:]) -> u64 { pkcs11::init_pin(s.ctx, s.handle, pin) }
fn set_pin(s: Session, old_pin: const u8[:], new_pin: const u8[:]) -> u64 {
    pkcs11::set_pin(s.ctx, s.handle, old_pin, new_pin)
}

fn generate_random(s: Session, n: i64) -> u8[>..], u64 {
    let r, rv = pkcs11::generate_random(s.ctx, s.handle, n);
    return r, rv;
}

fn object(s: Session, h: u64) -> Object { Object { ctx: s.ctx, session: s.handle, handle: h } }

fn create_object(s: Session, t: const u8[:]) -> Object, u64 {
    let h, rv = pkcs11::create_object(s.ctx, s.handle, t);
    return object(s, h), rv;
}

// Every object the template matches.
fn find_objects(s: Session, t: const u8[:]) -> Object[>..], u64 {
    var out: Object[>..] = [];
    var rv = pkcs11::find_objects_init(s.ctx, s.handle, t);
    if rv != pkcs11::CKR_OK { return out, rv; }
    loop {
        let hs, r = pkcs11::find_objects(s.ctx, s.handle, 100);
        rv = r;
        if rv != pkcs11::CKR_OK || hs.len == 0 { break; }
        for h in hs { out.push(object(s, h)); }
    }
    let rf = pkcs11::find_objects_final(s.ctx, s.handle);
    return out, if rv != pkcs11::CKR_OK { rv } else { rf };
}

// The one object the template matches: ERR_NO_OBJECT or
// ERR_MULTIPLE_OBJECTS otherwise.
fn find_object(s: Session, t: const u8[:]) -> Object, u64 {
    let all, rv = find_objects(s, t);
    var found = object(s, 0);
    if rv != pkcs11::CKR_OK { return found, rv; }
    if all.len == 0 { return found, ERR_NO_OBJECT; }
    if all.len > 1 { return found, ERR_MULTIPLE_OBJECTS; }
    return all[0], pkcs11::CKR_OK;
}

fn find_class_label(s: Session, class: u64, label: const u8[:]) -> Object, u64 {
    var t: u8[>..] = [];
    pkcs11::attr(t, pkcs11::CKA_CLASS, class);
    pkcs11::attr(t, pkcs11::CKA_LABEL, label);
    let o, rv = find_object(s, t);
    return o, rv;
}

fn find_private_key(s: Session, label: const u8[:]) -> PrivateKey, u64 {
    let o, rv = find_class_label(s, pkcs11::CKO_PRIVATE_KEY, label);
    return PrivateKey { object: o }, rv;
}

fn find_public_key(s: Session, label: const u8[:]) -> PublicKey, u64 {
    let o, rv = find_class_label(s, pkcs11::CKO_PUBLIC_KEY, label);
    return PublicKey { object: o }, rv;
}

fn find_secret_key(s: Session, label: const u8[:]) -> SecretKey, u64 {
    let o, rv = find_class_label(s, pkcs11::CKO_SECRET_KEY, label);
    return SecretKey { object: o }, rv;
}

// A key pair by mechanism (CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
// CKM_EC_EDWARDS_KEY_PAIR_GEN, ...) and the two templates (miekg's
// GenerateKeyPairRequest).
fn generate_key_pair(s: Session, mech: const u8[:], public: const u8[:], private: const u8[:]) -> KeyPair, u64 {
    let pub, priv, rv = pkcs11::generate_key_pair(s.ctx, s.handle, mech, public, private);
    return KeyPair { public: PublicKey { object: object(s, pub) }, private: PrivateKey { object: object(s, priv) } }, rv;
}

fn generate_key(s: Session, mech: const u8[:], t: const u8[:]) -> SecretKey, u64 {
    let h, rv = pkcs11::generate_key(s.ctx, s.handle, mech, t);
    return SecretKey { object: object(s, h) }, rv;
}

// --- Objects -----------------------------------------------------------------------------------

// The value of one attribute.
fn attribute(o: Object, kind: u64) -> u8[>..], u64 {
    var out: u8[>..] = [];
    let types: u64[1] = [kind];
    let attrs, rv = pkcs11::get_attribute_value(o.ctx, o.session, o.handle, types);
    if rv != pkcs11::CKR_OK { return out, rv; }
    let v, ok = pkcs11::attr_value(attrs, kind);
    if !ok { return out, pkcs11::CKR_ATTRIBUTE_TYPE_INVALID; }
    out.append(v);
    return out, rv;
}

fn label(o: Object) -> u8[>..], u64 {
    let v, rv = attribute(o, pkcs11::CKA_LABEL);
    return v, rv;
}

fn value(o: Object) -> u8[>..], u64 {
    let v, rv = attribute(o, pkcs11::CKA_VALUE);
    return v, rv;
}

fn set(o: Object, kind: u64, v: const u8[:]) -> u64 {
    var t: u8[>..] = [];
    pkcs11::attr(t, kind, v);
    return pkcs11::set_attribute_value(o.ctx, o.session, o.handle, t);
}

fn copy_object(o: Object, t: const u8[:]) -> Object, u64 {
    let h, rv = pkcs11::copy_object(o.ctx, o.session, o.handle, t);
    return Object { ctx: o.ctx, session: o.session, handle: h }, rv;
}

fn destroy(o: Object) -> u64 { pkcs11::destroy_object(o.ctx, o.session, o.handle) }

// --- Keys ------------------------------------------------------------------------------------------

fn sign(k: PrivateKey, mech: const u8[:], message: const u8[:]) -> u8[>..], u64 {
    let o = k.object;
    var out: u8[>..] = [];
    let rv = pkcs11::sign_init(o.ctx, o.session, mech, o.handle);
    if rv != pkcs11::CKR_OK { return out, rv; }
    let sig, rv2 = pkcs11::sign(o.ctx, o.session, message);
    return sig, rv2;
}

fn decrypt(k: PrivateKey, mech: const u8[:], ciphertext: const u8[:]) -> u8[>..], u64 {
    let o = k.object;
    var out: u8[>..] = [];
    let rv = pkcs11::decrypt_init(o.ctx, o.session, mech, o.handle);
    if rv != pkcs11::CKR_OK { return out, rv; }
    let pt, rv2 = pkcs11::decrypt(o.ctx, o.session, ciphertext);
    return pt, rv2;
}

// A key derived from this one (ECDH1, say), as an object.
fn derive(k: PrivateKey, mech: const u8[:], t: const u8[:]) -> Object, u64 {
    let o = k.object;
    let h, rv = pkcs11::derive_key(o.ctx, o.session, mech, o.handle, t);
    return Object { ctx: o.ctx, session: o.session, handle: h }, rv;
}

// The derived key's value (miekg's Derive): the template must let it out
// (CKA_SENSITIVE false, CKA_EXTRACTABLE true).
fn derive_value(k: PrivateKey, mech: const u8[:], t: const u8[:]) -> u8[>..], u64 {
    var out: u8[>..] = [];
    let d, rv = derive(k, mech, t);
    if rv != pkcs11::CKR_OK { return out, rv; }
    let v, rv2 = value(d);
    destroy(d);
    return v, rv2;
}

// CKR_OK when sig is good.
fn verify(k: PublicKey, mech: const u8[:], message: const u8[:], sig: const u8[:]) -> u64 {
    let o = k.object;
    let rv = pkcs11::verify_init(o.ctx, o.session, mech, o.handle);
    if rv != pkcs11::CKR_OK { return rv; }
    return pkcs11::verify(o.ctx, o.session, message, sig);
}

fn encrypt(k: PublicKey, mech: const u8[:], plaintext: const u8[:]) -> u8[>..], u64 {
    let o = k.object;
    var out: u8[>..] = [];
    let rv = pkcs11::encrypt_init(o.ctx, o.session, mech, o.handle);
    if rv != pkcs11::CKR_OK { return out, rv; }
    let ct, rv2 = pkcs11::encrypt(o.ctx, o.session, plaintext);
    return ct, rv2;
}

fn encrypt(k: SecretKey, mech: const u8[:], plaintext: const u8[:]) -> u8[>..], u64 {
    let o = k.object;
    var out: u8[>..] = [];
    let rv = pkcs11::encrypt_init(o.ctx, o.session, mech, o.handle);
    if rv != pkcs11::CKR_OK { return out, rv; }
    let ct, rv2 = pkcs11::encrypt(o.ctx, o.session, plaintext);
    return ct, rv2;
}

fn decrypt(k: SecretKey, mech: const u8[:], ciphertext: const u8[:]) -> u8[>..], u64 {
    let o = k.object;
    var out: u8[>..] = [];
    let rv = pkcs11::decrypt_init(o.ctx, o.session, mech, o.handle);
    if rv != pkcs11::CKR_OK { return out, rv; }
    let pt, rv2 = pkcs11::decrypt(o.ctx, o.session, ciphertext);
    return pt, rv2;
}

// --- Keys held on the token, for TLS, SSH, x509 and JWS ---------------------------------------

// The x509 key standing for a token's key pair in a configuration (a TLS
// server's, an SSH host's, an issuer's): the public key's
// SubjectPublicKeyInfo, from CKA_EC_PARAMS and CKA_EC_POINT (P-256, P-384,
// P-521, Ed25519) or CKA_MODULUS and CKA_PUBLIC_EXPONENT, as an
// x509::external_key. The signing is then done by sign_data with the
// private key, passed as the signer to the call that signs.
fn x509_key(k: PublicKey) -> x509::PrivateKey, bool {
    let o = k.object;
    var alg: u8[>..] = [];
    var key: u8[>..] = [];
    let ec_types: u64[2] = [pkcs11::CKA_EC_PARAMS, pkcs11::CKA_EC_POINT];
    let a, ra = pkcs11::get_attribute_value(o.ctx, o.session, o.handle, ec_types);
    let params, okp = pkcs11::attr_value(a, pkcs11::CKA_EC_PARAMS);
    let point, okpt = pkcs11::attr_value(a, pkcs11::CKA_EC_POINT);
    if ra == pkcs11::CKR_OK && okp && okpt && params.len > 0 {
        if params == pkcs11::EC_PARAMS_ED25519[..] {
            asn1::put_oid(alg, "1.3.101.112");
        } else {
            asn1::put_oid(alg, "1.2.840.10045.2.1");
            alg.append(params);                        // the named curve's OID, DER
        }
        key.append(pkcs11::ec_point(point));
    } else {
        let rsa_types: u64[2] = [pkcs11::CKA_MODULUS, pkcs11::CKA_PUBLIC_EXPONENT];
        let b, rb = pkcs11::get_attribute_value(o.ctx, o.session, o.handle, rsa_types);
        let n, okn = pkcs11::attr_value(b, pkcs11::CKA_MODULUS);
        let e, oke = pkcs11::attr_value(b, pkcs11::CKA_PUBLIC_EXPONENT);
        if rb != pkcs11::CKR_OK || !okn || !oke { return x509::empty_key(), false; }
        asn1::put_oid(alg, "1.2.840.113549.1.1.1");
        asn1::put_null(alg);
        var rk: u8[>..] = [];
        asn1::put_uint(rk, n);
        asn1::put_uint(rk, e);
        asn1::put(key, asn1::SEQUENCE, rk);
    }
    var body: u8[>..] = [];
    asn1::put(body, asn1::SEQUENCE, alg);
    asn1::put_bits(body, key);
    var spki: u8[>..] = [];
    asn1::put(spki, asn1::SEQUENCE, body);
    let x, ok = x509::external_key(spki);
    return x, ok;
}

// A signer for a token's private key (x509::sign_data describes signers):
// x509's algorithm and hash as the token's mechanisms over the digest it
// is given (CKM_ECDSA, CKM_RSA_PKCS over the DigestInfo, CKM_RSA_PKCS_PSS
// with MGF1 and a salt as long as the hash), CKM_EDDSA over the message
// for Ed25519; the answer as x509 signs (ECDSA as DER). Empty when the
// token refuses. The session must be logged in; a block names the key:
//
//   tls::feed(c, cfg, input, out, app) { k, alg, h, data => p11::sign_data(key, alg, h, data) }
fn sign_data(k: PrivateKey, alg: i64, h: i64, data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let hm = if h == 256 { pkcs11::CKM_SHA256 } else if h == 384 { pkcs11::CKM_SHA384 } else if h == 512 { pkcs11::CKM_SHA512 } else { 0 };
    let mgf = if h == 256 { pkcs11::CKG_MGF1_SHA256 } else if h == 384 { pkcs11::CKG_MGF1_SHA384 } else { pkcs11::CKG_MGF1_SHA512 };
    if alg == x509::SIG_ED25519 {
        let sig, rv = sign(k, pkcs11::mechanism(pkcs11::CKM_EDDSA), data);
        if rv == pkcs11::CKR_OK { out.append(sig); }
        return out;
    }
    if hm == 0 || data.len != bignum::hash_len(h) { return out; }
    if alg == x509::SIG_ECDSA {
        let raw, rv = sign(k, pkcs11::mechanism(pkcs11::CKM_ECDSA), data);
        if rv != pkcs11::CKR_OK || raw.len == 0 || raw.len % 2 != 0 || raw.len > 132 { return out; }
        out.append(bignum::ecdsa_sig_to_der(raw));
    } else if alg == x509::SIG_RSA_PKCS1 {
        var t = bignum::digest_info(h);
        t.append(data);
        let sig, rv = sign(k, pkcs11::mechanism(pkcs11::CKM_RSA_PKCS), t);
        if rv == pkcs11::CKR_OK { out.append(sig); }
    } else if alg == x509::SIG_RSA_PSS {
        let m = pkcs11::mechanism_pss(pkcs11::CKM_RSA_PKCS_PSS, hm, mgf, bignum::hash_len(h) as! u64);
        let sig, rv = sign(k, m, data);
        if rv == pkcs11::CKR_OK { out.append(sig); }
    }
    return out;
}
