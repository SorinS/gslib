// Fuzz target: jwx_jwt. The input as a claims set (parse_claims) and as a
// token: parsed without verifying (parse_insecure), verified with RFC 7515
// A.1's HMAC key (parse, parse_set with inference), decrypted with fixed
// symmetric keys (parse_encrypted by A128KW, parse_nested by dir then HS256);
// the claims validated against a fixed clock and read back (accessors,
// marshal).

import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jwt;

let HS_KEY = """{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}""";
let KW_KEY = """{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}""";
let DIR_KEY = """{"kty":"oct","kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a","use":"enc","alg":"A128GCM","k":"XctOhJAkA-pD9Lh7ZgW_2A"}""";

var KEYS: jwk::Key[>..] = [];

// RFC 7519 §3.1's token expires at 1300819380: the clock is just before.
let NOW: i64 = 1300819370;

fn validators() -> jwt::Validator[3] {
    var a = jwt::Validator { .. };
    a.now = NOW;
    var b = jwt::Validator { .. };
    b.now = NOW;
    b.skew = 60;
    b.issuer.append("joe");
    b.subject.append("sub");
    b.audience.append("api");
    b.jwt_id.append("id");
    b.max_age = 3600;
    b.required = jwt::CLAIM_EXP | jwt::CLAIM_AUD;
    var c = jwt::Validator { .. };
    c.validate = false;
    return [a, b, c];
}

fn read_back(c: const jwt::Claims&) {
    for v in validators() { let _ = jwt::validate(c, v); }
    let _ = jwt::audiences(c);
    let _ = jwt::has(c, jwt::CLAIM_ISS | jwt::CLAIM_NBF);
    let _ = jwt::get_string(c, "http://example.com/is_root");
    let _ = jwt::get_int(c, "n");
    let _ = jwt::get_raw(c, "nonce");
    let _ = jwt::marshal(c);
    let _ = jwt::marshal(c, true);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    let vs = validators();
    var c = jwt::new_claims();
    if jwt::parse_claims(data, c) == jwx::OK { read_back(c); }
    var c2 = jwt::new_claims();
    if jwt::parse_insecure(data, c2) == jwx::OK { read_back(c2); }
    var c3 = jwt::new_claims();
    if jwt::parse(data, jwa::HS256, KEYS[0], c3, vs[0]) == jwx::OK { read_back(c3); }
    var c4 = jwt::new_claims();
    let _ = jwt::parse_set(data, KEYS[..1], c4, vs[1], true);
    var c5 = jwt::new_claims();
    let _ = jwt::parse_encrypted(data, jwa::A128KW, KEYS[1], c5, vs[0]);
    var c6 = jwt::new_claims();
    let _ = jwt::parse_nested(data, jwa::DIRECT, KEYS[2], jwa::HS256, KEYS[0], c6, vs[2]);
    return 0;
}

fn add(text: const u8[:]) {
    let k, e = jwk::parse(text);
    if e != jwx::OK { abort(str("fuzz key: ", jwx::error_text(e))); }
    KEYS.push(k);
}

fn main() {
    add(HS_KEY);
    add(KW_KEY);
    add(DIR_KEY);
}
