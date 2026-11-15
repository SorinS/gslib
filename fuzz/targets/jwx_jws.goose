// Fuzz target: jwx_jws. A JWS, compact or JSON (general and flattened),
// parsed; each signature's headers read and, where a fixed key fits the
// header's alg, verified (HMAC, RSA, ECDSA P-521, Ed25519 keys from RFC 7520's
// cookbook and RFC 7515 A.1); then the public entry points: verify,
// verify_detached and verify_set (with alg inference).

import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;

let JWS_HS = """{"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig","alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}""";
let JWS_HS_RFC = """{"kty":"oct","alg":"HS256","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}""";
let JWS_RSA = """{"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig","n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw","e":"AQAB"}""";
let JWS_EC = """{"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"}""";
let JWS_ED = """{"kty":"OKP","use":"sig","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}""";

var KEYS: jwk::Key[>..] = [];

// At most this many signatures are verified one by one; a message with
// more is only parsed (each verify is a public-key operation).
let MAX_SIGS: i64 = 8;

export fn fuzz_one(data: const u8[:]) -> i32 {
    var m = jws::Message { .. };
    let e = jws::parse(m, data);
    var nsigs: i64 = 0;
    if e == jwx::OK {
        nsigs = m.sigs.len;
        for i in ::min(m.sigs.len, MAX_SIGS) {
            let _ = jws::protected_text(m, i);
            let _ = jws::header_string(m, i, "kid");
            let _ = jws::header_string(m, i, "typ");
            let _ = jws::header_int(m, i, "b64");
            let _ = jws::header_int(m, i, "iat");
            let alg = m.sigs[i].header.alg;
            let _ = jwa::name(alg);
            for &k in KEYS {
                if jwk::fits(k, alg) {
                    let _ = jws::verify_signature(m, i, alg, k);
                    if m.detached { let _ = jws::verify_signature(m, i, alg, k, "detached payload"); }
                }
            }
        }
    }
    if e == jwx::OK && nsigs <= MAX_SIGS {
        let _ = jws::verify(data, jwa::HS256, KEYS[0]);
        let _ = jws::verify(data, jwa::NONE, KEYS[0]);
        let _ = jws::verify_detached(data, "payload", jwa::HS256, KEYS[1]);
        let _ = jws::verify_set(data, KEYS, false);
        let _ = jws::verify_set(data, KEYS, true);
    }
    return 0;
}

fn add(text: const u8[:]) {
    let k, e = jwk::parse(text);
    if e != jwx::OK { abort(str("fuzz key: ", jwx::error_text(e))); }
    KEYS.push(k);
}

fn main() {
    add(JWS_HS);
    add(JWS_HS_RFC);
    add(JWS_RSA);
    add(JWS_EC);
    add(JWS_ED);
}
