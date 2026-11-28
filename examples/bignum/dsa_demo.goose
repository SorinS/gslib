// DSA (FIPS 186-4), for legacy keys and formats only: domain parameters,
// a key on them, signatures over a SHA-256 digest with a random nonce and
// with RFC 6979's deterministic one, verification, the DER form that X.509
// and openssl use, and loading a public key from its parts. New designs
// should use Ed25519, ECDSA or ML-DSA instead.
//
//   goose examples/bignum/dsa_demo.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.dsa;
import gslib.crypto.bignum.sha256;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:]) { print("dsa_demo: ", what); exit(1); }

fn main() {
    // Parameters are slow to make and shared by many keys; (1024, 160)
    // keeps this quick. (2048, 224), (2048, 256) and (3072, 256) work too.
    let t0 = clock();
    let p, q, g = bignum::dsa_generate_parameters(1024, 160);
    print("parameters: p ", p.len * 8, " bits, q ", q.len * 8, " bits, made in ", ((clock() - t0) * 1000.0) as! i64, " ms");
    let key, ok = bignum::dsa_generate_key(p, q, g);
    guard ok else { fail("key generation"); }
    print("public y ", hex(key.y[..16]), "...");

    // DSA signs a digest, which it cuts to q's width (160 bits here).
    let msg = "an old signed document";
    let digest = bignum::sha256(msg);
    let sig = bignum::dsa_sign(key, digest);               // r || s, as wide as q each
    let det1 = bignum::dsa_sign_deterministic(key, digest, 256);
    let det2 = bignum::dsa_sign_deterministic(key, digest, 256);
    print("signature r || s ", hex(sig));
    guard bignum::dsa_verify(key, digest, sig) && det1 == det2 && bignum::dsa_verify(key, digest, det1) else {
        fail("signatures did not verify");
    }
    guard !bignum::dsa_verify(key, bignum::sha256("another document"), sig) else { fail("wrong digest verified"); }

    // X.509, CMS and openssl carry a signature as DER SEQUENCE { r, s }.
    let der = bignum::dsa_sig_to_der(sig);
    let raw, okd = bignum::dsa_sig_from_der(key, der);
    guard okd && raw == sig else { fail("DER round trip"); }
    print("DER signature ", der.len, " bytes");

    // A verifier holds only the public parts: load them and check.
    let pub, okp = bignum::dsa_key_from(key.p, key.q, key.g, key.y);
    guard okp && bignum::dsa_verify(pub, digest, sig) else { fail("public key from parts"); }
    // The public key drops x, so it cannot sign.
    guard bignum::dsa_public(key).x.len == 0 else { fail("dsa_public kept x"); }
    print("verified with the public key alone");
}
