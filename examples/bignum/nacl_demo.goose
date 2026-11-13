// NaCl, as Go's x/crypto/nacl: secretbox (a shared key), box (two key
// pairs, also precomputed), anonymous sealed boxes (only the recipient's
// key), sign (Ed25519, signature then message) and auth (HMAC-SHA-512/256).
// Every one is opened again, and refused when changed.
//
//   goose examples/bignum/nacl_demo.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.nacl;
import gslib.crypto.bignum.ed25519;
import gslib.crypto.bignum.entropy;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:]) { print("nacl_demo: ", what); exit(1); }

fn main() {
    // secretbox: XSalsa20-Poly1305 under a 32-byte key; a random 24-byte
    // nonce is safe, and is sent with the box.
    var key: u8[32] = [0; 32];
    bignum::random_bytes(key);
    var nonce: u8[24] = [0; 24];
    bignum::random_bytes(nonce);
    let sb = bignum::secretbox_seal("meet at noon", nonce, key);
    let sp, sok = bignum::secretbox_open(sb, nonce, key);
    var sbad = copy(sb);
    sbad[sbad.len - 1] ^= 1;
    let x1, sbadok = bignum::secretbox_open(sbad, nonce, key);
    guard sok && sp == "meet at noon" && !sbadok else { fail("secretbox"); }
    print("secretbox: ", sb.len, " bytes (16 of tag first), opened");

    // box: Alice writes to Bob with her secret key and his public key; Bob
    // opens with his secret key and her public key.
    let alice_pk, alice_sk = bignum::box_keypair();
    let bob_pk, bob_sk = bignum::box_keypair();
    bignum::random_bytes(nonce);
    let bx = bignum::box_seal("from alice", nonce, bob_pk, alice_sk);
    let bp, bok = bignum::box_open(bx, nonce, alice_pk, bob_sk);
    let eve_pk, eve_sk = bignum::box_keypair();
    let x2, eveok = bignum::box_open(bx, nonce, alice_pk, eve_sk);
    guard bok && bp == "from alice" && !eveok else { fail("box"); }
    print("box: Bob opens Alice's message, Eve cannot");
    // For many messages between the same pair, precompute the shared key
    // once and use it with secretbox.
    let shared_a = bignum::box_precompute(bob_pk, alice_sk);
    let shared_b = bignum::box_precompute(alice_pk, bob_sk);
    guard shared_a[..] == shared_b[..] else { fail("box_precompute"); }

    // Sealed box: anyone can write to Bob knowing only his public key; the
    // sender stays anonymous (an ephemeral key travels in the box).
    let anon = bignum::box_seal_anonymous("an anonymous tip", bob_pk);
    let ap, aok = bignum::box_open_anonymous(anon, bob_pk, bob_sk);
    guard aok && ap == "an anonymous tip" else { fail("anonymous box"); }
    print("sealed box: ", anon.len, " bytes, opened by Bob");

    // sign: the private key is Go's 64 bytes, seed || public key.
    let seed, pk = bignum::ed25519_keypair();
    var sk64: u8[>..] = [];
    sk64.append(seed);
    sk64.append(pk);
    let signed = bignum::nacl_sign("release notes", sk64);
    let msg, gok = bignum::nacl_sign_open(signed, pk);
    var forged = copy(signed);
    forged[signed.len - 1] ^= 1;
    let x3, fok = bignum::nacl_sign_open(forged, pk);
    guard gok && msg == "release notes" && !fok else { fail("sign"); }
    print("sign: ", signed.len, " bytes, signature ", hex(signed[..16]), "...");

    // auth: a 32-byte authenticator under a 32-byte key.
    let tag = bignum::nacl_auth("ping", key);
    guard bignum::nacl_auth_verify(tag, "ping", key) && !bignum::nacl_auth_verify(tag, "pong", key) else { fail("auth"); }
    print("auth: ", hex(tag));
    print("all NaCl constructions checked");
}
