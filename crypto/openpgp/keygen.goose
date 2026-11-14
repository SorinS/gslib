// openpgp.keygen: new keys as gpg makes them by default: a v4 Ed25519
// primary (EdDSALegacy) that certifies and signs, with a Curve25519 ECDH
// subkey (SHA-256, AES-128 key wrap) that encrypts, one user ID and its
// positive certification, and the subkey's binding; or RSA, a primary
// and an encryption subkey of the same size.
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
import crypto.bignum.rsa;
import crypto.openpgp;
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
    k.body.push(4);
    var t: u8[>..] = [];
    put32(t, k.created);
    k.body.append(t);
    k.body.push(k.algo as! u8);
    k.body.append(material);
    set_fingerprint(k);
    k.sec_raw.push(0);
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
