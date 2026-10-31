// bignum.hpke: Hybrid Public Key Encryption (RFC 9180), with the
// post-quantum KEMs and one-stage SHAKE KDFs that Go's crypto/hpke has
// (draft-ietf-hpke-pq).
//
// KEMs: DHKEM over P-256, P-384, P-521 and X25519; ML-KEM-512, -768 and
// -1024; and the hybrids MLKEM768-P256, MLKEM1024-P384 and
// MLKEM768-X25519 (X-Wing). KDFs: HKDF-SHA256, -SHA384, -SHA512, SHAKE128
// and SHAKE256. AEADs: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 and
// export-only. All four modes (base, PSK, auth, auth-PSK) for the HKDF
// KDFs; the authenticated modes need a DHKEM, and the SHAKE KDFs, like
// Go's, run in base mode only.
//
// A private key is what the KEM serializes: the scalar for a DHKEM, the
// 64-byte seed for ML-KEM, the 32-byte seed for a hybrid.

namespace bignum;

import std;
import ct;
import sha3;
import hmac;
import gcm;
import chacha20;
import x25519;
import ec;
import mlkem;
import entropy;

let HPKE_MODE_BASE: i64 = 0;
let HPKE_MODE_PSK: i64 = 1;
let HPKE_MODE_AUTH: i64 = 2;
let HPKE_MODE_AUTH_PSK: i64 = 3;

let HPKE_DHKEM_P256: i64 = 0x0010;
let HPKE_DHKEM_P384: i64 = 0x0011;
let HPKE_DHKEM_P521: i64 = 0x0012;
let HPKE_DHKEM_X25519: i64 = 0x0020;
let HPKE_MLKEM512: i64 = 0x0040;
let HPKE_MLKEM768: i64 = 0x0041;
let HPKE_MLKEM1024: i64 = 0x0042;
let HPKE_MLKEM768_P256: i64 = 0x0050;
let HPKE_MLKEM1024_P384: i64 = 0x0051;
let HPKE_MLKEM768_X25519: i64 = 0x647a;

let HPKE_HKDF_SHA256: i64 = 0x0001;
let HPKE_HKDF_SHA384: i64 = 0x0002;
let HPKE_HKDF_SHA512: i64 = 0x0003;
let HPKE_SHAKE128: i64 = 0x0010;
let HPKE_SHAKE256: i64 = 0x0011;

let HPKE_AES128GCM: i64 = 0x0001;
let HPKE_AES256GCM: i64 = 0x0002;
let HPKE_CHACHA20POLY1305: i64 = 0x0003;
let HPKE_EXPORT_ONLY: i64 = 0xffff;

// One direction's context (RFC 9180 §5.1): the AEAD key and base nonce,
// the exporter secret, and the sequence number.
struct HpkeContext {
    kdf: i64, aead: i64, seq: u64, suite: u8[10],
    key: u8[..32], nonce: u8[..12], exporter: u8[..64],
}

// --- Algorithms -----------------------------------------------------------

fn hpke_is_dh(kem: i64) -> bool {
    kem == HPKE_DHKEM_P256 || kem == HPKE_DHKEM_P384 || kem == HPKE_DHKEM_P521 || kem == HPKE_DHKEM_X25519
}

fn hpke_is_mlkem(kem: i64) -> bool { kem == HPKE_MLKEM512 || kem == HPKE_MLKEM768 || kem == HPKE_MLKEM1024 }

fn hpke_is_hybrid(kem: i64) -> bool {
    kem == HPKE_MLKEM768_P256 || kem == HPKE_MLKEM1024_P384 || kem == HPKE_MLKEM768_X25519
}

fn hpke_kem_ok(kem: i64) -> bool { hpke_is_dh(kem) || hpke_is_mlkem(kem) || hpke_is_hybrid(kem) }

fn hpke_kdf_ok(kdf: i64) -> bool { kdf >= 1 && kdf <= 3 || kdf == HPKE_SHAKE128 || kdf == HPKE_SHAKE256 }

fn hpke_aead_ok(aead: i64) -> bool { aead >= 1 && aead <= 3 || aead == HPKE_EXPORT_ONLY }

fn hpke_one_stage(kdf: i64) -> bool { kdf == HPKE_SHAKE128 || kdf == HPKE_SHAKE256 }

// The HKDF hash (256, 384 or 512) of a two-stage KDF.
fn hpke_kdf_bits(kdf: i64) -> i64 { if kdf == HPKE_HKDF_SHA256 { 256 } else if kdf == HPKE_HKDF_SHA384 { 384 } else { 512 } }

// Nh: the KDF's output size.
fn hpke_nh(kdf: i64) -> i64 {
    if kdf == HPKE_SHAKE128 { 32 } else if kdf == HPKE_SHAKE256 { 64 } else { hpke_kdf_bits(kdf) / 8 }
}

fn hpke_nk(aead: i64) -> i64 { if aead == HPKE_AES128GCM { 16 } else if aead == HPKE_EXPORT_ONLY { 0 } else { 32 } }
fn hpke_nn(aead: i64) -> i64 { if aead == HPKE_EXPORT_ONLY { 0 } else { 12 } }

// ML-KEM's k for an ML-KEM or hybrid KEM.
fn hpke_mlkem_k(kem: i64) -> i64 {
    if kem == HPKE_MLKEM512 { 2 } else if kem == HPKE_MLKEM1024 || kem == HPKE_MLKEM1024_P384 { 4 } else { 3 }
}

// The DHKEM or hybrid's curve as a DHKEM id.
fn hpke_dh_of(kem: i64) -> i64 {
    if kem == HPKE_MLKEM768_P256 { HPKE_DHKEM_P256 } else if kem == HPKE_MLKEM1024_P384 { HPKE_DHKEM_P384 }
    else if kem == HPKE_MLKEM768_X25519 { HPKE_DHKEM_X25519 } else { kem }
}

fn hpke_curve(dh: i64) -> Curve {
    if dh == HPKE_DHKEM_P256 { p256() } else if dh == HPKE_DHKEM_P384 { p384() } else { p521() }
}

// Nsk and Npk of a DHKEM.
fn hpke_dh_nsk(dh: i64) -> i64 {
    if dh == HPKE_DHKEM_X25519 || dh == HPKE_DHKEM_P256 { 32 } else if dh == HPKE_DHKEM_P384 { 48 } else { 66 }
}

fn hpke_dh_npk(dh: i64) -> i64 {
    if dh == HPKE_DHKEM_X25519 { 32 } else if dh == HPKE_DHKEM_P256 { 65 } else if dh == HPKE_DHKEM_P384 { 97 } else { 133 }
}

// The serialized sizes: private key, public key, encapsulated key.
fn hpke_nsk(kem: i64) -> i64 {
    if hpke_is_dh(kem) { hpke_dh_nsk(kem) } else if hpke_is_mlkem(kem) { 64 } else { 32 }
}

fn hpke_npk(kem: i64) -> i64 {
    if hpke_is_dh(kem) { return hpke_dh_npk(kem); }
    let n = mlkem_ek_len(hpke_mlkem_k(kem));
    return if hpke_is_mlkem(kem) { n } else { n + hpke_dh_npk(hpke_dh_of(kem)) };
}

fn hpke_nenc(kem: i64) -> i64 {
    if hpke_is_dh(kem) { return hpke_dh_npk(kem); }
    let n = mlkem_ct_len(hpke_mlkem_k(kem));
    return if hpke_is_mlkem(kem) { n } else { n + hpke_dh_npk(hpke_dh_of(kem)) };
}

fn hpke_put16(out: u8[>..]&, v: i64) {
    out.push((v >> 8) as! u8);
    out.push(v as! u8);
}

fn hpke_kem_suite(kem: i64) -> u8[>..] {
    var s: u8[>..] = [];
    s.append("KEM");
    hpke_put16(s, kem);
    return s;
}

// --- Labeled KDFs (§4, and the one-stage form of draft-ietf-hpke-pq) -------

fn hpke_labeled_extract(bits: i64, suite: const u8[:], salt: const u8[:], label: const u8[:], ikm: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    m.append("HPKE-v1");
    m.append(suite);
    m.append(label);
    m.append(ikm);
    return hkdf_extract(bits, salt, m);
}

fn hpke_labeled_expand(bits: i64, suite: const u8[:], prk: const u8[:], label: const u8[:], info: const u8[:],
                       n: i64) -> u8[>..] {
    var m: u8[>..] = [];
    hpke_put16(m, n);
    m.append("HPKE-v1");
    m.append(suite);
    m.append(label);
    m.append(info);
    return hkdf_expand(bits, prk, m, n);
}

fn hpke_labeled_derive(shake_bits: i64, suite: const u8[:], ikm: const u8[:], label: const u8[:], context: const u8[:],
                       n: i64) -> u8[>..] {
    var x = shake_init(shake_bits);
    sha3_update(x, ikm);
    sha3_update(x, "HPKE-v1");
    sha3_update(x, suite);
    var l: u8[>..] = [];
    hpke_put16(l, label.len);
    sha3_update(x, l);
    sha3_update(x, label);
    l.clear();
    hpke_put16(l, n);
    sha3_update(x, l);
    sha3_update(x, context);
    var out: u8[>..] = [];
    out.resize(n, 0);
    shake_read(x, out);
    return out;
}

// --- DHKEM (§4.1) ------------------------------------------------------------

// The public key of a DHKEM private key, and false for one out of range.
fn hpke_dh_public(dh: i64, sk: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if sk.len != hpke_dh_nsk(dh) { return out, false; }
    if dh == HPKE_DHKEM_X25519 { out.append(x25519_base(sk)); return out, true; }
    let c = hpke_curve(dh);
    let k, ok = ec_scalar(c, sk);
    if !ok { return out, false; }
    return ec_public_key(c, sk), true;
}

// DH(sk, pk): false for an invalid point or an all-zero X25519 output.
fn hpke_dh(dh: i64, sk: const u8[:], pk: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if sk.len != hpke_dh_nsk(dh) || pk.len != hpke_dh_npk(dh) { return out, false; }
    if dh == HPKE_DHKEM_X25519 {
        let s, ok = x25519_shared(sk, pk);
        out.append(s);
        return out, ok;
    }
    let c = hpke_curve(dh);
    return ecdh_shared(c, sk, pk);
}

// DeriveKeyPair (§7.1.3): X25519's key is expanded directly; a NIST
// curve's is the first candidate below the order.
fn hpke_dh_derive(dh: i64, ikm: const u8[:]) -> u8[>..], u8[>..] {
    let bits = if dh == HPKE_DHKEM_P384 { 384 } else if dh == HPKE_DHKEM_P521 { 512 } else { 256 };
    let suite = hpke_kem_suite(dh);
    let prk = hpke_labeled_extract(bits, suite, "", "dkp_prk", ikm);
    if dh == HPKE_DHKEM_X25519 {
        let sk = hpke_labeled_expand(bits, suite, prk, "sk", "", 32);
        let pk, ok = hpke_dh_public(dh, sk);
        return sk, pk;
    }
    var counter = 0;
    loop {
        assert(counter < 256);                 // DeriveKeyPairError: never in practice
        let ctr: u8[1] = [counter as! u8];
        var sk = hpke_labeled_expand(bits, suite, prk, "candidate", ctr, hpke_dh_nsk(dh));
        if dh == HPKE_DHKEM_P521 { sk[0] &= 0x01; }
        let pk, ok = hpke_dh_public(dh, sk);
        if ok { return sk, pk; }
        counter++;
    }
}

fn hpke_dh_shared(dh: i64, dhv: const u8[:], kem_context: const u8[:]) -> u8[>..] {
    let bits = if dh == HPKE_DHKEM_P384 { 384 } else if dh == HPKE_DHKEM_P521 { 512 } else { 256 };
    let suite = hpke_kem_suite(dh);
    let prk = hpke_labeled_extract(bits, suite, "", "eae_prk", dhv);
    return hpke_labeled_expand(bits, suite, prk, "shared_secret", kem_context, bits / 8);
}

// --- Hybrids (draft-ietf-hpke-pq) ---------------------------------------------

fn hpke_hybrid_label(kem: i64) -> const u8[:] {
    if kem == HPKE_MLKEM768_P256 { "MLKEM768-P256" } else if kem == HPKE_MLKEM1024_P384 { "MLKEM1024-P384" } else { "\\.//^\\" }
}

// A hybrid seed's two private keys: ML-KEM's 64-byte seed, then the
// curve's from the rest of SHAKE256(seed), the first in range.
fn hpke_hybrid_expand(kem: i64, seed: const u8[:]) -> u8[>..], u8[>..] {
    var x = shake_init(256);
    sha3_update(x, seed);
    var pq: u8[>..] = [];
    pq.resize(64, 0);
    shake_read(x, pq);
    let dh = hpke_dh_of(kem);
    var t: u8[>..] = [];
    t.resize(hpke_dh_nsk(dh), 0);
    loop {
        shake_read(x, t);
        let pk, ok = hpke_dh_public(dh, t);
        if ok { return pq, t; }
    }
}

fn hpke_hybrid_secret(kem: i64, ss_pq: const u8[:], ss_t: const u8[:], ct_t: const u8[:], ek_t: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    m.append(ss_pq);
    m.append(ss_t);
    m.append(ct_t);
    m.append(ek_t);
    m.append(hpke_hybrid_label(kem));
    return sha3(256, m);
}

// --- Keys ----------------------------------------------------------------------

// The public key of a private key, and false for a malformed one.
fn hpke_public_key(kem: i64, sk: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !hpke_kem_ok(kem) || sk.len != hpke_nsk(kem) { return out, false; }
    if hpke_is_dh(kem) { return hpke_dh_public(kem, sk); }
    if hpke_is_mlkem(kem) {
        let ek, dk = mlkem_keys_from_seed(hpke_mlkem_k(kem), sk);
        return ek, true;
    }
    let pq, t = hpke_hybrid_expand(kem, sk);
    let ek, dk = mlkem_keys_from_seed(hpke_mlkem_k(kem), pq);
    let pt, ok = hpke_dh_public(hpke_dh_of(kem), t);
    out.append(ek);
    out.append(pt);
    return out, true;
}

// DeriveKeyPair: a key pair from input keying material.
fn hpke_derive_key_pair(kem: i64, ikm: const u8[:]) -> u8[>..], u8[>..] {
    assert(hpke_kem_ok(kem));
    if hpke_is_dh(kem) { return hpke_dh_derive(kem, ikm); }
    let sk = hpke_labeled_derive(256, hpke_kem_suite(kem), ikm, "DeriveKeyPair", "", hpke_nsk(kem));
    let pk, ok = hpke_public_key(kem, sk);
    return sk, pk;
}

// A fresh key pair from the OS's entropy.
fn hpke_keygen(kem: i64) -> u8[>..], u8[>..] {
    var ikm: u8[>..] = [];
    ikm.resize(64, 0);
    random_bytes(ikm);
    return hpke_derive_key_pair(kem, ikm);
}

// The randomness one encapsulation takes: a DHKEM's ephemeral key
// material, ML-KEM's message, or a hybrid's message and curve key.
fn hpke_encap_rand(kem: i64) -> u8[>..] {
    var r: u8[>..] = [];
    if hpke_is_dh(kem) { r.resize(hpke_dh_nsk(kem), 0); random_bytes(r); return r; }
    r.resize(32, 0);
    random_bytes(r);
    if hpke_is_mlkem(kem) { return r; }
    let dh = hpke_dh_of(kem);
    var t: u8[>..] = [];
    t.resize(hpke_dh_nsk(dh), 0);
    loop {
        random_bytes(t);
        let pk, ok = hpke_dh_public(dh, t);
        if ok { break; }
    }
    r.append(t);
    return r;
}

// Encap / AuthEncap with the given randomness: the shared secret and the
// encapsulated key; false for a malformed recipient (or sender) key.
fn hpke_encap(kem: i64, pk: const u8[:], rand: const u8[:], sk_s: const u8[:]) -> u8[>..], u8[>..], bool {
    var ss: u8[>..] = [];
    var enc: u8[>..] = [];
    if pk.len != hpke_npk(kem) { return ss, enc, false; }
    if hpke_is_dh(kem) {
        let ske, pke = hpke_dh_derive(kem, rand);
        var dhv, ok = hpke_dh(kem, ske, pk);
        var kc: u8[>..] = [];
        kc.append(pke);
        kc.append(pk);
        if sk_s.len > 0 {
            let d2, ok2 = hpke_dh(kem, sk_s, pk);
            let pks, ok3 = hpke_dh_public(kem, sk_s);
            ok = ok && ok2 && ok3;
            dhv.append(d2);
            kc.append(pks);
        }
        if !ok { return ss, enc, false; }
        return hpke_dh_shared(kem, dhv, kc), pke, true;
    }
    let k = hpke_mlkem_k(kem);
    let ekl = mlkem_ek_len(k);
    let tl = if hpke_is_hybrid(kem) { hpke_dh_nsk(hpke_dh_of(kem)) } else { 0 };
    if rand.len < 32 + tl { return ss, enc, false; }
    let s1, c1, ok1 = mlkem_encaps_with(k, pk[..ekl], rand[..32]);
    if !ok1 { return ss, enc, false; }
    if hpke_is_mlkem(kem) { return s1, c1, true; }
    let dh = hpke_dh_of(kem);
    let ek_t = pk[ekl..];
    let ske = rand[32..32 + tl];
    let ct_t, okp = hpke_dh_public(dh, ske);
    let ss_t, okt = hpke_dh(dh, ske, ek_t);
    if !okp || !okt { return ss, enc, false; }
    enc.append(c1);
    enc.append(ct_t);
    return hpke_hybrid_secret(kem, s1, ss_t, ct_t, ek_t), enc, true;
}

// Decap / AuthDecap: the shared secret; false for a malformed key or an
// invalid point.
fn hpke_decap(kem: i64, enc: const u8[:], sk: const u8[:], pk_s: const u8[:]) -> u8[>..], bool {
    var ss: u8[>..] = [];
    if enc.len != hpke_nenc(kem) || sk.len != hpke_nsk(kem) { return ss, false; }
    if hpke_is_dh(kem) {
        var dhv, ok = hpke_dh(kem, sk, enc);
        let pkr, okr = hpke_dh_public(kem, sk);
        var kc: u8[>..] = [];
        kc.append(enc);
        kc.append(pkr);
        if pk_s.len > 0 {
            let d2, ok2 = hpke_dh(kem, sk, pk_s);
            ok = ok && ok2;
            dhv.append(d2);
            kc.append(pk_s);
        }
        if !ok || !okr { return ss, false; }
        return hpke_dh_shared(kem, dhv, kc), true;
    }
    let k = hpke_mlkem_k(kem);
    if hpke_is_mlkem(kem) { return mlkem_decaps(k, sk, enc); }
    let pq, t = hpke_hybrid_expand(kem, sk);
    let ctl = mlkem_ct_len(k);
    let s1, ok1 = mlkem_decaps(k, pq, enc[..ctl]);
    let dh = hpke_dh_of(kem);
    let ct_t = enc[ctl..];
    let ss_t, okt = hpke_dh(dh, t, ct_t);
    let ek_t, okp = hpke_dh_public(dh, t);
    if !ok1 || !okt || !okp { return ss, false; }
    return hpke_hybrid_secret(kem, s1, ss_t, ct_t, ek_t), true;
}

// --- The key schedule (§5.1) ------------------------------------------------------

fn hpke_suite(kem: i64, kdf: i64, aead: i64) -> u8[10] {
    var s: u8[10] = [0; 10];
    s[0] = 'H'; s[1] = 'P'; s[2] = 'K'; s[3] = 'E';
    s[4] = (kem >> 8) as! u8; s[5] = kem as! u8;
    s[6] = (kdf >> 8) as! u8; s[7] = kdf as! u8;
    s[8] = (aead >> 8) as! u8; s[9] = aead as! u8;
    return s;
}

// The mode a sender's or recipient's inputs call for, or -1 when they are
// inconsistent (a PSK without its id, or the other way) or not allowed
// (authentication without a DHKEM, PSK modes with a one-stage KDF).
fn hpke_mode(kem: i64, kdf: i64, psk: const u8[:], psk_id: const u8[:], auth: bool) -> i64 {
    if (psk.len == 0) != (psk_id.len == 0) { return -1; }
    if auth && !hpke_is_dh(kem) { return -1; }
    let mode = if psk.len > 0 { if auth { HPKE_MODE_AUTH_PSK } else { HPKE_MODE_PSK } }
               else { if auth { HPKE_MODE_AUTH } else { HPKE_MODE_BASE } };
    if hpke_one_stage(kdf) && mode != HPKE_MODE_BASE { return -1; }
    return mode;
}

fn hpke_schedule(kem: i64, kdf: i64, aead: i64, mode: i64, ss: const u8[:], info: const u8[:], psk: const u8[:],
                 psk_id: const u8[:]) -> HpkeContext {
    var c = HpkeContext { kdf: kdf, aead: aead, seq: 0, suite: hpke_suite(kem, kdf, aead), key: [], nonce: [], exporter: [] };
    let nk = hpke_nk(aead);
    let nn = hpke_nn(aead);
    let nh = hpke_nh(kdf);
    if hpke_one_stage(kdf) {
        var secrets: u8[>..] = [];
        hpke_put16(secrets, psk.len);
        secrets.append(psk);
        hpke_put16(secrets, ss.len);
        secrets.append(ss);
        var ksc: u8[>..] = [];
        ksc.push(mode as! u8);
        hpke_put16(ksc, psk_id.len);
        ksc.append(psk_id);
        hpke_put16(ksc, info.len);
        ksc.append(info);
        let bits = if kdf == HPKE_SHAKE128 { 128 } else { 256 };
        let s = hpke_labeled_derive(bits, c.suite, secrets, "secret", ksc, nk + nn + nh);
        c.key.append(s[..nk]);
        c.nonce.append(s[nk..nk + nn]);
        c.exporter.append(s[nk + nn..]);
        return c;
    }
    let bits = hpke_kdf_bits(kdf);
    var ksc: u8[>..] = [];
    ksc.push(mode as! u8);
    ksc.append(hpke_labeled_extract(bits, c.suite, "", "psk_id_hash", psk_id));
    ksc.append(hpke_labeled_extract(bits, c.suite, "", "info_hash", info));
    let secret = hpke_labeled_extract(bits, c.suite, ss, "secret", psk);
    if aead != HPKE_EXPORT_ONLY {
        c.key.append(hpke_labeled_expand(bits, c.suite, secret, "key", ksc, nk));
        c.nonce.append(hpke_labeled_expand(bits, c.suite, secret, "base_nonce", ksc, nn));
    }
    c.exporter.append(hpke_labeled_expand(bits, c.suite, secret, "exp", ksc, nh));
    return c;
}

fn hpke_empty_context() -> HpkeContext {
    HpkeContext { kdf: 0, aead: 0, seq: 0, suite: [0; 10], key: [], nonce: [], exporter: [] }
}

// SetupS (§5.1.1 to §5.1.4) with the encapsulation's randomness, for
// tests: the encapsulated key and the context. A PSK (with its id) and
// a sender private key choose the mode.
fn hpke_sender_with(kem: i64, kdf: i64, aead: i64, pk: const u8[:], info: const u8[:], rand: const u8[:],
                    psk: const u8[:] = "", psk_id: const u8[:] = "", sk_s: const u8[:] = "") -> u8[>..], HpkeContext, bool {
    var none: u8[>..] = [];
    if !hpke_kem_ok(kem) || !hpke_kdf_ok(kdf) || !hpke_aead_ok(aead) { return none, hpke_empty_context(), false; }
    let mode = hpke_mode(kem, kdf, psk, psk_id, sk_s.len > 0);
    if mode < 0 { return none, hpke_empty_context(), false; }
    let ss, enc, ok = hpke_encap(kem, pk, rand, sk_s);
    if !ok { return none, hpke_empty_context(), false; }
    return enc, hpke_schedule(kem, kdf, aead, mode, ss, info, psk, psk_id), true;
}

// SetupS with fresh randomness.
fn hpke_sender(kem: i64, kdf: i64, aead: i64, pk: const u8[:], info: const u8[:],
               psk: const u8[:] = "", psk_id: const u8[:] = "", sk_s: const u8[:] = "") -> u8[>..], HpkeContext, bool {
    if !hpke_kem_ok(kem) { var none: u8[>..] = []; return none, hpke_empty_context(), false; }
    return hpke_sender_with(kem, kdf, aead, pk, info, hpke_encap_rand(kem), psk, psk_id, sk_s);
}

// SetupR: the recipient's context from the encapsulated key. The sender's
// public key authenticates it.
fn hpke_recipient(kem: i64, kdf: i64, aead: i64, sk: const u8[:], enc: const u8[:], info: const u8[:],
                  psk: const u8[:] = "", psk_id: const u8[:] = "", pk_s: const u8[:] = "") -> HpkeContext, bool {
    if !hpke_kem_ok(kem) || !hpke_kdf_ok(kdf) || !hpke_aead_ok(aead) { return hpke_empty_context(), false; }
    let mode = hpke_mode(kem, kdf, psk, psk_id, pk_s.len > 0);
    if mode < 0 { return hpke_empty_context(), false; }
    let ss, ok = hpke_decap(kem, enc, sk, pk_s);
    if !ok { return hpke_empty_context(), false; }
    return hpke_schedule(kem, kdf, aead, mode, ss, info, psk, psk_id), true;
}

fn hpke_next_nonce(c: const HpkeContext&) -> u8[12] {
    var n: u8[12] = [0; 12];
    for i in 12 { n[i] = c.nonce[i]; }
    for i in 8 { n[11 - i] ^= (c.seq >> (8 * i)) as! u8; }
    return n;
}

// Seal: the next message's ciphertext and tag; false for an export-only
// context.
fn hpke_seal(c: HpkeContext&, aad: const u8[:], pt: const u8[:]) -> u8[>..], bool {
    if c.aead == HPKE_EXPORT_ONLY || c.seq == 0xffffffffffffffff { var none: u8[>..] = []; return none, false; }
    let n = hpke_next_nonce(c);
    c.seq++;
    if c.aead == HPKE_CHACHA20POLY1305 { return chacha20_poly1305_seal(c.key, n, aad, pt), true; }
    return aes_gcm_seal(c.key, n, aad, pt), true;
}

// Open: the next message's plaintext; false when it does not
// authenticate, which leaves the sequence number as it was.
fn hpke_open(c: HpkeContext&, aad: const u8[:], ct: const u8[:]) -> u8[>..], bool {
    if c.aead == HPKE_EXPORT_ONLY || c.seq == 0xffffffffffffffff { var none: u8[>..] = []; return none, false; }
    let n = hpke_next_nonce(c);
    if c.aead == HPKE_CHACHA20POLY1305 {
        let pt, ok = chacha20_poly1305_open(c.key, n, aad, ct);
        if ok { c.seq++; }
        return pt, ok;
    }
    let pt, ok = aes_gcm_open(c.key, n, aad, ct);
    if ok { c.seq++; }
    return pt, ok;
}

// Export (§5.3): n bytes for the exporter context.
fn hpke_export(c: const HpkeContext&, exporter_context: const u8[:], n: i64) -> u8[>..] {
    assert(n >= 0 && n <= 0xffff);
    if hpke_one_stage(c.kdf) {
        return hpke_labeled_derive(if c.kdf == HPKE_SHAKE128 { 128 } else { 256 }, c.suite, c.exporter, "sec",
                                   exporter_context, n);
    }
    return hpke_labeled_expand(hpke_kdf_bits(c.kdf), c.suite, c.exporter, "sec", exporter_context, n);
}

// Single-shot base mode, as Go's hpke.Seal and hpke.Open: the
// encapsulated key followed by the ciphertext, no associated data.
fn hpke_seal_once(kem: i64, kdf: i64, aead: i64, pk: const u8[:], info: const u8[:], pt: const u8[:]) -> u8[>..], bool {
    var enc, c, ok = hpke_sender(kem, kdf, aead, pk, info);
    if !ok { return enc, false; }
    let ct, oks = hpke_seal(c, "", pt);
    enc.append(ct);
    return enc, oks;
}

fn hpke_open_once(kem: i64, kdf: i64, aead: i64, sk: const u8[:], info: const u8[:], data: const u8[:]) -> u8[>..], bool {
    var none: u8[>..] = [];
    if !hpke_kem_ok(kem) || data.len < hpke_nenc(kem) { return none, false; }
    let n = hpke_nenc(kem);
    var c, ok = hpke_recipient(kem, kdf, aead, sk, data[..n], info);
    if !ok { return none, false; }
    return hpke_open(c, "", data[n..]);
}
