// openpgp.keygen: new keys as gpg makes them by default: a v4 Ed25519
// primary (EdDSALegacy) that certifies and signs, with a Curve25519 ECDH
// subkey (SHA-256, AES-128 key wrap) that encrypts, one user ID and its
// positive certification, and the subkey's binding; or RSA, a primary
// and an encryption subkey of the same size. Other curves:
//
//   generate_brainpool_key  gpg's brainpoolP256r1/P384r1/P512r1: a v4 ECDSA
//                           primary with an ECDH subkey on the same curve
//                           (KDF SHA-256/AES-128, SHA-384/AES-256,
//                           SHA-512/AES-256, as gpg picks them)
//   generate_ed448_key      gpg's ed448: a v5 Ed448 primary (EdDSALegacy,
//                           v5 signatures) with a v5 cv448 ECDH subkey
//                           (SHA-512, AES-256); gpg makes 448 keys v5 only
//   generate_ed448_v6_key   RFC 9580's: a v6 Ed448 (28) primary with a v6
//                           X448 (26) subkey (gpg 2.5 reads neither)
//
// Post-quantum:
//
//   generate_pqc_bp_key   gpg 2.5's default ("pqc"): a v4 brainpoolP384r1
//                         ECDSA primary with a v5 Kyber subkey,
//                         ML-KEM-768+brainpoolP256r1 ("ky768_bp256")
//   generate_pqc_key      gpg 2.5's ed25519 + ky768_cv25519: the Ed25519
//                         primary with a v5 Kyber subkey, ML-KEM-768+X25519
//   generate_rfc9980_key  RFC 9980's: a v6 ML-DSA-65+Ed25519 primary with
//                         a v6 ML-KEM-768+X25519 subkey (gpg 2.5 reads
//                         neither)
//
//   var kr = openpgp::Keyring { .. };
//   let err = openpgp::generate_key(kr, "Test <test@example.com>", 0);   // 0: now
//   openpgp::export_secret(kr, k, out, true, passphrase);
//
// The keys go into the keyring the way add_keys reads any other key, so
// the signatures are checked as they would be coming from gpg. The new
// key does not advertise AEAD, so gpg encrypts to it with SEIPD v1.

namespace openpgp;

import std;
import crypto.bignum;
import crypto.bignum.ed25519;
import crypto.bignum.x25519;
import crypto.bignum.x448;
import crypto.bignum.ed448;
import crypto.bignum.ec;
import crypto.bignum.rsa;
import crypto.bignum.mlkem;
import crypto.bignum.mldsa;
import crypto.openpgp;
import crypto.openpgp.pqc;
import crypto.openpgp.packet;
import crypto.openpgp.key;
import crypto.openpgp.sig;
import crypto.openpgp.keyring;

fn new_key(algo: i64, created: i64, subkey: bool) -> Key {
    var k = Key { .. };
    k.version = 4;
    k.algo = algo;
    k.created = created;
    k.subkey = subkey;
    k.has_secret = true;
    return k;
}

fn finish_key(k: Key&, material: const u8[:]) {
    k.body.push(k.version as! u8);
    var t: u8[>..] = [];
    put32(t, k.created);
    k.body.append(t);
    k.body.push(k.algo as! u8);
    // v5 and v6: the material's 4-octet length.
    if k.version >= 5 { put32(t, material.len); k.body.append(t[4..]); }
    k.body.append(material);
    set_fingerprint(k);
    k.sec_raw.push(0);
}

// A clamped X25519 secret (little-endian) and its public key, into k.
fn x25519_secret(k: Key&) {
    var s = random(32);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    k.scalar.append(s);
    k.point.append(bignum::x25519_base(s));
}

// A clamped X448 secret (RFC 7748) and its public key, into k.
fn x448_secret(k: Key&) {
    var s = random(56);
    s[0] &= 252;
    s[55] |= 128;
    k.scalar.append(s);
    k.point.append(bignum::x448_base(s));
}

// A secret scalar and its point 04 || x || y on a Weierstrass curve, into k.
fn weierstrass_secret(k: Key&, curve: i64) {
    let c = weierstrass_curve(curve);
    let sk, pk = bignum::ec_keypair(c);
    k.scalar.append(sk);
    k.point.append(pk);
}

// gpg's Kyber subkey: v5, algo 8, the ECC half (X25519 under RFC 8410's
// OID, as gpg writes it, or brainpoolP256r1) with ML-KEM-768. Its secret is
// a fresh seed d || z.
fn kyber_key(created: i64, curve: i64 = CURVE_X25519) -> Key {
    var k = new_key(PK_KYBER, created, true);
    k.version = 5;
    k.curve = curve;
    var pt: u8[>..] = [];
    var oid = OID_X25519_RFC8410;
    if curve == CURVE_X25519 {
        x25519_secret(k);
        pt.push(0x40);
    } else {
        weierstrass_secret(k, curve);
        oid = oid_of_curve(curve);
    }
    pt.append(k.point);
    k.pq_sec.append(random(MLKEM_SEED_LEN));
    let ek, dk = bignum::mlkem_keys_from_seed(3, k.pq_sec);
    var m: u8[>..] = [];
    m.push(oid.len as! u8);
    m.append(oid);
    put_mpi(m, pt);
    put32(m, ek.len);
    k.pq_at = 10 + m.len;
    k.pq_len = ek.len;
    m.append(ek);
    finish_key(k, m);
    return k;
}

// RFC 9980's ML-KEM-768+X25519 subkey (v6, or v4 as §3.5 allows).
fn mlkem_x25519_key(created: i64, version: i64) -> Key {
    var k = new_key(PK_MLKEM768_X25519, created, true);
    k.version = version;
    x25519_secret(k);
    k.pq_sec.append(random(MLKEM_SEED_LEN));
    let ek, dk = bignum::mlkem_keys_from_seed(3, k.pq_sec);
    var m: u8[>..] = [];
    m.append(k.point);
    m.append(ek);
    k.pq_at = (if version >= 5 { 10 } else { 6 }) + 32;
    k.pq_len = ek.len;
    finish_key(k, m);
    return k;
}

// RFC 9980's ML-DSA-65+Ed25519 primary (v6).
fn mldsa_ed25519_key(created: i64) -> Key {
    var k = new_key(PK_MLDSA65_ED25519, created, false);
    k.version = 6;
    let seed = random(32);
    k.scalar.append(seed);
    k.point.append(bignum::ed25519_public(seed));
    k.pq_sec.append(random(MLDSA_SEED_LEN));
    let pk = bignum::mldsa_public_key(65, k.pq_sec);
    var m: u8[>..] = [];
    m.append(k.point);
    m.append(pk);
    k.pq_at = 10 + 32;
    k.pq_len = pk.len;
    finish_key(k, m);
    return k;
}

fn ed25519_key(created: i64) -> Key {
    var k = new_key(PK_EDDSA, created, false);
    k.curve = CURVE_ED25519;
    let seed = random(32);
    k.scalar.append(seed);
    let pub = bignum::ed25519_public(seed);
    k.point.append(pub);
    var m: u8[>..] = [];
    m.push(OID_ED25519.len as! u8);
    m.append(OID_ED25519);
    var pt: u8[>..] = [];
    pt.push(0x40);
    pt.append(pub);
    put_mpi(m, pt);
    finish_key(k, m);
    return k;
}

// An ECDSA primary on a Weierstrass curve (v4).
fn ecdsa_key(created: i64, curve: i64) -> Key {
    var k = new_key(PK_ECDSA, created, false);
    k.curve = curve;
    weierstrass_secret(k, curve);
    let oid = oid_of_curve(curve);
    var m: u8[>..] = [];
    m.push(oid.len as! u8);
    m.append(oid);
    put_mpi(m, k.point);
    finish_key(k, m);
    return k;
}

// An ECDH subkey on a Weierstrass curve (v4), with the KDF gpg picks for
// its size (ecdh.c's kek_params_table): SHA-256 and AES-128 up to 256
// bits, SHA-384 and AES-256 to 384, SHA-512 and AES-256 above.
fn ecdh_key(created: i64, curve: i64) -> Key {
    var k = new_key(PK_ECDH, created, true);
    k.curve = curve;
    let n = curve_size(curve);
    k.kdf_hash = if n <= 32 { HASH_SHA256 } else if n <= 48 { HASH_SHA384 } else { HASH_SHA512 };
    k.kdf_cipher = if n <= 32 { CIPHER_AES128 } else { CIPHER_AES256 };
    weierstrass_secret(k, curve);
    let oid = oid_of_curve(curve);
    var m: u8[>..] = [];
    m.push(oid.len as! u8);
    m.append(oid);
    put_mpi(m, k.point);
    m.append("\x03\x01");
    m.push(k.kdf_hash as! u8);
    m.push(k.kdf_cipher as! u8);
    finish_key(k, m);
    return k;
}

// gpg's ed448 primary: v5, EdDSALegacy under Ed448's OID, the native 57
// octets of the public key as an SOS (no prefix).
fn ed448_legacy_key(created: i64) -> Key {
    var k = new_key(PK_EDDSA, created, false);
    k.version = 5;
    k.curve = CURVE_ED448;
    let seed = random(57);
    k.scalar.append(seed);
    k.point.append(bignum::ed448_public(seed));
    var m: u8[>..] = [];
    m.push(OID_ED448.len as! u8);
    m.append(OID_ED448);
    put_sos(m, k.point);
    finish_key(k, m);
    return k;
}

// gpg's cv448 subkey: v5 ECDH under X448's OID (1.3.101.111), the native
// 56 octets, KDF SHA-512 and AES-256.
fn cv448_key(created: i64) -> Key {
    var k = new_key(PK_ECDH, created, true);
    k.version = 5;
    k.curve = CURVE_X448;
    k.kdf_hash = HASH_SHA512;
    k.kdf_cipher = CIPHER_AES256;
    x448_secret(k);
    var m: u8[>..] = [];
    m.push(OID_X448_RFC8410.len as! u8);
    m.append(OID_X448_RFC8410);
    put_sos(m, k.point);
    m.append("\x03\x01\x0a\x09");
    finish_key(k, m);
    return k;
}

// RFC 9580's Ed448 (28) primary and X448 (26) subkey: native octets.
fn ed448_native_key(created: i64, version: i64) -> Key {
    var k = new_key(PK_ED448, created, false);
    k.version = version;
    let seed = random(57);
    k.scalar.append(seed);
    k.point.append(bignum::ed448_public(seed));
    var m: u8[>..] = [];
    m.append(k.point);
    finish_key(k, m);
    return k;
}

fn x448_native_key(created: i64, version: i64) -> Key {
    var k = new_key(PK_X448, created, true);
    k.version = version;
    x448_secret(k);
    var m: u8[>..] = [];
    m.append(k.point);
    finish_key(k, m);
    return k;
}

fn cv25519_key(created: i64) -> Key {
    var k = new_key(PK_ECDH, created, true);
    k.curve = CURVE_X25519;
    k.kdf_hash = HASH_SHA256;
    k.kdf_cipher = CIPHER_AES128;
    var s = random(32);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    k.scalar.append(s);
    let pub = bignum::x25519_base(s);
    k.point.append(pub);
    var m: u8[>..] = [];
    m.push(OID_X25519.len as! u8);
    m.append(OID_X25519);
    var pt: u8[>..] = [];
    pt.push(0x40);
    pt.append(pub);
    put_mpi(m, pt);
    m.append("\x03\x01\x08\x07");
    finish_key(k, m);
    return k;
}

// Little-endian u32 limbs as big-endian bytes, leading zeros dropped.
fn limbs_be(l: const u32[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = l.len;
    while i > 0 {
        i--;
        let v = l[i];
        for j in 4 { out.push((v >> (24 - 8 * j) as u32) as! u8); }
    }
    var z = 0;
    while z < out.len && out[z] == 0 { z++; }
    var r: u8[>..] = [];
    r.append(out[z..]);
    return r;
}

fn rsa_key(bits: i64, created: i64, subkey: bool) -> Key {
    var k = new_key(PK_RSA, created, subkey);
    let r = bignum::rsa_generate(bits);
    let n = limbs_be(r.n);
    let e = limbs_be(r.e);
    let d = limbs_be(r.d);
    // OpenPGP keeps p < q and u = p^-1 mod q.
    let swapped = bignum::cmp(bignum::from_bytes_be(limbs_be(r.p)), bignum::from_bytes_be(limbs_be(r.q))) > 0;
    let p = if swapped { limbs_be(r.q) } else { limbs_be(r.p) };
    let q = if swapped { limbs_be(r.p) } else { limbs_be(r.q) };
    let ub, oku = bignum::modinv(bignum::from_bytes_be(p), bignum::from_bytes_be(q));
    let u = bignum::to_bytes_be(ub, (bignum::bit_len(ub) + 7) / 8);
    k.n.append(strip_zeros(n));
    k.e.append(strip_zeros(e));
    k.d.append(strip_zeros(d));
    k.p.append(strip_zeros(p));
    k.q.append(strip_zeros(q));
    k.u.append(strip_zeros(u));
    var m: u8[>..] = [];
    put_mpi(m, k.n);
    put_mpi(m, k.e);
    finish_key(k, m);
    return k;
}

// The packets of a new key: primary, user ID, certification, subkey,
// binding; then read into kr.
fn add_generated(kr: Keyring&, primary: const Key&, sub: const Key&, uid: const u8[:], created: i64) -> i64 {
    var bin:  u8[>..] = [];
    var body: u8[>..] = [];
    let e0 = put_secret_body(body, primary);
    if e0 != OK { return e0; }
    put_old_packet(bin, TAG_SECRET_KEY, body);
    if primary.version == 6 {
        // RFC 9580 §10.1.1: a v6 key's flags and preferences in a
        // direct-key signature.
        var dd: u8[>..] = [];
        put_key_hash(dd, primary);
        var dp = SigParams { .. };
        dp.sigtype = SIG_DIRECT_KEY;
        dp.hash = HASH_SHA512;
        dp.created = created;
        dp.has_flags = true;
        dp.flags = FLAG_CERTIFY | FLAG_SIGN;
        dp.prefs = true;
        let ed = make_signature(primary, dp, dd, bin);
        if ed != OK { return ed; }
    }
    put_old_packet(bin, TAG_USER_ID, uid);
    var data: u8[>..] = [];
    put_key_hash(data, primary);
    put_uid_hash(data, uid);
    var prm = SigParams { .. };
    prm.sigtype = SIG_CERT_POSITIVE;
    prm.hash = HASH_SHA512;
    prm.created = created;
    prm.has_flags = true;
    prm.flags = FLAG_CERTIFY | FLAG_SIGN;
    prm.primary_uid = true;
    prm.prefs = true;
    let e1 = make_signature(primary, prm, data, bin);
    if e1 != OK { return e1; }
    body.clear();
    let e2 = put_secret_body(body, sub);
    if e2 != OK { return e2; }
    put_old_packet(bin, TAG_SECRET_SUBKEY, body);
    data.clear();
    put_key_hash(data, primary);
    put_key_hash(data, sub);
    var bp = SigParams { .. };
    bp.sigtype = SIG_SUBKEY_BINDING;
    bp.hash = HASH_SHA512;
    bp.created = created;
    bp.has_flags = true;
    bp.flags = FLAG_ENCRYPT;
    let e3 = make_signature(primary, bp, data, bin);
    if e3 != OK { return e3; }
    let before = kr.keys.len;
    let e4 = add_keys(kr, bin);
    if e4 != OK { return e4; }
    if kr.keys.len != before + 2 || !kr.keys[before].valid || !kr.keys[before + 1].valid { return ERR_KEY; }
    return OK;
}

// An Ed25519 + Curve25519 key for uid ("Name <email>"), made at `created`
// (0: now), added to kr; its primary is the last primary of kr.
fn generate_key(kr: Keyring&, uid: const u8[:], created: i64 = 0) -> i64 {
    if uid.len == 0 || uid.len > 1024 { return ERR_KEY; }
    let t = if created > 0 { created } else { now() };
    let primary = ed25519_key(t);
    let sub = cv25519_key(t);
    return add_generated(kr, primary, sub, uid, t);
}

// An RSA key of `bits` (2048 to 4096) with an RSA encryption subkey.
fn generate_rsa_key(kr: Keyring&, uid: const u8[:], bits: i64 = 3072, created: i64 = 0) -> i64 {
    if uid.len == 0 || uid.len > 1024 || bits < 2048 || bits > 4096 { return ERR_KEY; }
    let t = if created > 0 { created } else { now() };
    let primary = rsa_key(bits, t, false);
    let sub = rsa_key(bits, t, true);
    return add_generated(kr, primary, sub, uid, t);
}

// gpg's Brainpool key, as `gpg --quick-gen-key UID brainpoolP384r1` then
// `--quick-add-key FPR brainpoolP384r1 encr` make it: a v4 ECDSA primary
// that certifies and signs with an ECDH subkey on the same curve. bits:
// 256, 384 or 512.
fn generate_brainpool_key(kr: Keyring&, uid: const u8[:], bits: i64 = 384, created: i64 = 0) -> i64 {
    if uid.len == 0 || uid.len > 1024 { return ERR_KEY; }
    let curve = if bits == 256 { CURVE_BP256 } else if bits == 384 { CURVE_BP384 } else if bits == 512 { CURVE_BP512 }
                else { CURVE_NONE };
    if curve == CURVE_NONE { return ERR_KEY; }
    let t = if created > 0 { created } else { now() };
    let primary = ecdsa_key(t, curve);
    let sub = ecdh_key(t, curve);
    return add_generated(kr, primary, sub, uid, t);
}

// gpg's Ed448 key, as `gpg --quick-gen-key UID ed448` then `--quick-add-key
// FPR cv448 encr` make it: v5 keys (gpg makes the 448 curves v5 only), an
// EdDSALegacy Ed448 primary whose signatures are v5, with a cv448 ECDH
// subkey.
fn generate_ed448_key(kr: Keyring&, uid: const u8[:], created: i64 = 0) -> i64 {
    if uid.len == 0 || uid.len > 1024 { return ERR_KEY; }
    let t = if created > 0 { created } else { now() };
    let primary = ed448_legacy_key(t);
    let sub = cv448_key(t);
    return add_generated(kr, primary, sub, uid, t);
}

// RFC 9580's Ed448 and X448: a v6 Ed448 (28) primary with a v6 X448 (26)
// subkey (HKDF-SHA512 and AES-256 key wrap). gpg 2.5 reads neither.
fn generate_ed448_v6_key(kr: Keyring&, uid: const u8[:], created: i64 = 0) -> i64 {
    if uid.len == 0 || uid.len > 1024 { return ERR_KEY; }
    let t = if created > 0 { created } else { now() };
    let primary = ed448_native_key(t, 6);
    let sub = x448_native_key(t, 6);
    return add_generated(kr, primary, sub, uid, t);
}

// gpg 2.5's default post-quantum key, as `gpg --quick-gen-key UID pqc`
// makes it: a v4 brainpoolP384r1 ECDSA primary that certifies and signs,
// with a v5 Kyber subkey (LibrePGP's ML-KEM-768+brainpoolP256r1,
// "ky768_bp256") that encrypts.
fn generate_pqc_bp_key(kr: Keyring&, uid: const u8[:], created: i64 = 0) -> i64 {
    if uid.len == 0 || uid.len > 1024 { return ERR_KEY; }
    let t = if created > 0 { created } else { now() };
    let primary = ecdsa_key(t, CURVE_BP384);
    let sub = kyber_key(t, CURVE_BP256);
    return add_generated(kr, primary, sub, uid, t);
}

// gpg 2.5's post-quantum key, as `gpg --quick-gen-key UID ed25519 cert`
// then `--quick-add-key FPR ky768_cv25519 encr` make it: a v4 Ed25519
// primary that certifies and signs, with a v5 Kyber subkey (LibrePGP's
// ML-KEM-768+X25519) that encrypts. gpg imports it, encrypts to it and,
// given its secret, decrypts with it.
fn generate_pqc_key(kr: Keyring&, uid: const u8[:], created: i64 = 0) -> i64 {
    if uid.len == 0 || uid.len > 1024 { return ERR_KEY; }
    let t = if created > 0 { created } else { now() };
    let primary = ed25519_key(t);
    let sub = kyber_key(t);
    return add_generated(kr, primary, sub, uid, t);
}

// RFC 9980's: a v6 ML-DSA-65+Ed25519 primary (a direct-key signature, the
// user ID's, the binding: all composite signatures) with a v6
// ML-KEM-768+X25519 subkey.
fn generate_rfc9980_key(kr: Keyring&, uid: const u8[:], created: i64 = 0) -> i64 {
    if uid.len == 0 || uid.len > 1024 { return ERR_KEY; }
    let t = if created > 0 { created } else { now() };
    let primary = mldsa_ed25519_key(t);
    let sub = mlkem_x25519_key(t, 6);
    return add_generated(kr, primary, sub, uid, t);
}
