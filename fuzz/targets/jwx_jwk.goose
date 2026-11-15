// Fuzz target: jwx_jwk. The input as a JWK (parse) and a JWK Set
// (parse_set; a lone JWK too); each key read back: validate, public_key,
// fits and strong_enough for every algorithm, thumbprints, lookup_kid,
// marshal (private and public, one key and the set) re-parsed, and the
// conversions to x509 and PEM (to_private, marshal_spki, to_pem). Input
// that looks like PEM or DER goes to jwx.pem's from_pem / from_spki.
// Known: has_duplicates is O(n^2) in the members (review finding
// jwx/jwk.goose:331).

import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.pem;

let MAX_KEYS: i64 = 16;

fn exercise(k: const jwk::Key&) {
    let _ = jwk::validate(k);
    let pub = jwk::public_key(k);
    let _ = jwk::validate(pub);
    for alg in 64 {
        if jwk::fits(k, alg) { let _ = jwk::strong_enough(k, alg); }
    }
    for h in [160, 256, 384, 512] { let _ = jwk::thumbprint(k, h); }
    let _ = jwk::thumbprint_b64(k);
    let _ = jwk::thumbprint_b64(pub);
    // Written back; only the public form re-parsed: a private RSA key's
    // parse checks it with a modexp, slow at 4096-8192 bits under ASan.
    let _ = jwk::marshal(k, true);
    let k2, e2 = jwk::parse(jwk::marshal(k, false));
    if e2 == jwx::OK { let _ = jwk::thumbprint(k2); }
    let _ = jwk::to_private(k);
    let _ = jwk::marshal_spki(k);
    let _ = jwk::to_pem(k);
    let _ = jwk::to_pem(k, true);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len > 0 && data[0] == '-' {
        let k, e = jwk::from_pem(data);
        if e == jwx::OK { exercise(k); }
        return 0;
    }
    if data.len > 0 && data[0] == 0x30 {
        let k, e = jwk::from_spki(data);
        if e == jwx::OK { exercise(k); }
        return 0;
    }
    // parse_set takes a lone JWK as a set of one: parse is called only for
    // what parse_set did not take, so a key is not checked twice.
    var keys: jwk::Key[>..] = [];
    let es = jwk::parse_set(data, keys);
    if es != jwx::OK && keys.len == 0 {
        let k, e = jwk::parse(data);
        if e == jwx::OK { exercise(k); }
    }
    for i in ::min(keys.len, MAX_KEYS) { exercise(keys[i]); }
    if keys.len > 0 {
        let _ = jwk::lookup_kid(keys, keys[0].kid[..]);
        let _ = jwk::lookup_kid(keys, "none");
        let _ = jwk::marshal_set(keys[.. ::min(keys.len, MAX_KEYS)], true);
        var back: jwk::Key[>..] = [];
        let _ = jwk::parse_set(jwk::marshal_set(keys[.. ::min(keys.len, MAX_KEYS)], false), back);
    }
    return 0;
}

fn main() {}
