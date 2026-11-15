// Fuzz target: cose_key. A COSE_Key decoded from the start of the input
// (cose::decode_at, RSA keys from 1024 bits); a key that decodes is validated, encoded again (which must
// decode to the same key), turned into a JWK and an SPKI and back, its
// EC point and RSA key made, checked against every algorithm, and the
// bytes after it verified as a signature over a fixed message by its own
// algorithm (DER and raw ECDSA).

import std;
import gslib from "../..";
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;

let ALGS: const i64[] = [cose::ES256, cose::ES384, cose::ES512, cose::ESP256, cose::ESP384, cose::ESP512,
                         cose::EDDSA, cose::ED25519, cose::ED448, cose::PS256, cose::PS384, cose::PS512,
                         cose::RS256, cose::RS384, cose::RS512, cose::RS1];

export fn fuzz_one(data: const u8[:]) -> i32 {
    // (cose::decode is decode_at and a check that nothing follows: not
    // called again, as Ed448 point decoding is costly in this build.)
    let k, end, e = cose::decode_at(data, 0, 1024);
    if e != cose::OK { return 0; }
    let _ = cose::validate(k, 1024);
    let _ = cose::alg_name(k.alg);
    let enc = cose::encode(k);
    let k2, e2 = cose::decode(enc, 1024);
    if e2 != cose::OK || !cose::same_key(k, k2) || k2.alg != k.alg { abort("encode does not decode to the same key"); }
    let j, ej = cose::to_jwk(k);
    if ej == cose::OK {
        let k3, e3 = cose::from_jwk(j);
        if e3 == cose::OK && !cose::same_key(k, k3) { abort("JWK round trip changed the key"); }
    }
    let spki, es = cose::to_spki(k);
    if es == cose::OK {
        let k4, e4 = cose::from_spki(spki);
        if e4 == cose::OK && !cose::same_key(k, k4) { abort("SPKI round trip changed the key"); }
    }
    if k.kty == cose::KTY_EC2 { let _ = cose::ec_point(k); }
    if k.kty == cose::KTY_RSA { let _ = cose::rsa_public(k); }
    for a in ALGS { let _ = cose::fits(k, a); }
    let sig = data[end..];
    let alg = if k.alg != 0 { k.alg } else if k.kty == cose::KTY_OKP { cose::EDDSA } else if k.kty == cose::KTY_RSA { cose::PS256 } else { cose::ES256 };
    let _ = cose::verify(k, alg, "fuzz message", sig);
    if k.kty == cose::KTY_EC2 || alg == cose::RS1 { let _ = cose::verify(k, alg, "fuzz message", sig, true, true); }
    return 0;
}

fn main() {}
