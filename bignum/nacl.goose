// bignum.nacl: the NaCl constructions of Go's x/crypto/nacl. secretbox
// (XSalsa20-Poly1305, the tag before the ciphertext), box (X25519 and
// HSalsa20 into secretbox), its anonymous form (an ephemeral key, the
// nonce from BLAKE2b), sign (Ed25519 with the message attached) and auth
// (HMAC-SHA-512 cut to 32 bytes).

namespace bignum;

import std;
import ct;
import salsa20;
import chacha20;
import x25519;
import ed25519;
import blake2;
import hmac;
import entropy;

let SECRETBOX_OVERHEAD: i64 = 16;
let BOX_ANONYMOUS_OVERHEAD: i64 = 48;

// The XSalsa20 subkey and its 8-byte nonce for a 24-byte nonce.
fn secretbox_keys(key: const u8[:], nonce: const u8[:]) -> u8[32], u8[8] {
    assert(key.len == 32 && nonce.len == 24);
    let sub = hsalsa20(key, nonce[..16]);
    var n8: u8[8] = [0; 8];
    for i in 8 { n8[i] = nonce[16 + i]; }
    return sub, n8;
}

// secretbox.Seal: Poly1305 tag || XSalsa20 ciphertext. The keystream's
// first 32 bytes key Poly1305, the message takes the rest.
fn secretbox_seal(msg: const u8[:], nonce: const u8[:], key: const u8[:]) -> u8[>..] {
    let sub, n8 = secretbox_keys(key, nonce);
    var buf: u8[>..] = [];
    buf.resize(32, 0);
    buf.append(msg);
    salsa20_xor_at(sub, n8, 0, buf);
    let tag = poly1305(buf[..32], buf[32..]);
    var out: u8[>..] = [];
    out.append(tag);
    out.append(buf[32..]);
    return out;
}

// secretbox.Open: the message, or false when the tag does not match.
fn secretbox_open(sealed: const u8[:], nonce: const u8[:], key: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if sealed.len < 16 { return out, false; }
    let sub, n8 = secretbox_keys(key, nonce);
    var otk: u8[32] = [0; 32];
    salsa20_xor_at(sub, n8, 0, otk);
    let tag = poly1305(otk, sealed[16..]);
    if ct_eq_bytes(tag, sealed[..16]) == 0 { return out, false; }
    var buf: u8[>..] = [];
    buf.resize(32, 0);
    buf.append(sealed[16..]);
    salsa20_xor_at(sub, n8, 0, buf);
    out.append(buf[32..]);
    return out, true;
}

// box.GenerateKey: the public key, then the private key.
fn box_keypair() -> u8[32], u8[32] {
    var sk: u8[32] = [0; 32];
    random_bytes(sk);
    return x25519_base(sk), sk;
}

// box.Precompute: HSalsa20 of the X25519 secret (not checked for zero,
// as NaCl and Go do not).
fn box_precompute(peer_pk: const u8[:], sk: const u8[:]) -> u8[32] {
    let s = x25519(sk, peer_pk);
    let zero: u8[16] = [0; 16];
    return hsalsa20(s, zero);
}

fn box_seal(msg: const u8[:], nonce: const u8[:], peer_pk: const u8[:], sk: const u8[:]) -> u8[>..] {
    let k = box_precompute(peer_pk, sk);
    return secretbox_seal(msg, nonce, k);
}

fn box_open(sealed: const u8[:], nonce: const u8[:], peer_pk: const u8[:], sk: const u8[:]) -> u8[>..], bool {
    let k = box_precompute(peer_pk, sk);
    return secretbox_open(sealed, nonce, k);
}

fn box_anonymous_nonce(epk: const u8[:], pk: const u8[:]) -> u8[>..] {
    var s = blake2b_init(24);
    blake2b_update(s, epk);
    blake2b_update(s, pk);
    return blake2b_final(s);
}

// box.SealAnonymous with the ephemeral private key given, for tests:
// ephemeral public key || box to the recipient.
fn box_seal_anonymous_with(msg: const u8[:], pk: const u8[:], esk: const u8[:]) -> u8[>..] {
    let epk = x25519_base(esk);
    let nonce = box_anonymous_nonce(epk, pk);
    var out: u8[>..] = [];
    out.append(epk);
    out.append(box_seal(msg, nonce, pk, esk));
    return out;
}

fn box_seal_anonymous(msg: const u8[:], pk: const u8[:]) -> u8[>..] {
    var esk: u8[32] = [0; 32];
    random_bytes(esk);
    return box_seal_anonymous_with(msg, pk, esk);
}

fn box_open_anonymous(sealed: const u8[:], pk: const u8[:], sk: const u8[:]) -> u8[>..], bool {
    if sealed.len < BOX_ANONYMOUS_OVERHEAD { var none: u8[>..] = []; return none, false; }
    let nonce = box_anonymous_nonce(sealed[..32], pk);
    return box_open(sealed[32..], nonce, sealed[..32], sk);
}

// sign.Sign: the signature followed by the message. The private key is
// Go's 64 bytes, seed || public key.
fn nacl_sign(msg: const u8[:], sk: const u8[:]) -> u8[>..] {
    assert(sk.len == 64);
    var out: u8[>..] = [];
    out.append(ed25519_sign(sk[..32], msg));
    out.append(msg);
    return out;
}

fn nacl_sign_open(signed: const u8[:], pk: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if signed.len < 64 || !ed25519_verify(pk, signed[64..], signed[..64]) { return out, false; }
    out.append(signed[64..]);
    return out, true;
}

// auth.Sum and auth.Verify: HMAC-SHA-512's first 32 bytes, keyed by 32.
fn nacl_auth(msg: const u8[:], key: const u8[:]) -> u8[32] {
    let h = hmac(512, key, msg);
    var out: u8[32] = [0; 32];
    for i in 32 { out[i] = h[i]; }
    return out;
}

fn nacl_auth_verify(digest: const u8[:], msg: const u8[:], key: const u8[:]) -> bool {
    return digest.len == 32 && ct_eq_bytes(nacl_auth(msg, key), digest) == 1;
}
