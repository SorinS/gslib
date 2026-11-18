// Keys held elsewhere in jwx: JWS and JWT signatures through a signer, as
// a TPM's or a PKCS#11 token's would make them, the key only its public JWK
// (jwk::from_spki). Each algorithm family: ECDSA on the three NIST curves
// (the signer's DER becoming JOSE's r || s), RSA PKCS #1 and PSS, EdDSA on
// Ed25519 and Ed448, ML-DSA-44; the tokens verify under the public key.
// The JSON serialization, and a JWT; then what fails: a signer that answers
// nothing, an HMAC key, no signer.
import std;
import os;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwt;
import gslib.jwx.pem;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import tv;

// One algorithm with a key of kind held elsewhere: signed through the
// signer, verified with the public JWK.
fn one(alg: i64, kind: i64) {
    let real = x509::generate_key(kind);
    let pub, e = jwk::from_spki(x509::marshal_public_key(real));
    tv::check(str(jwa::name(alg), ": the public JWK"), e == jwx::OK && !pub.private);
    var calls = 0;
    var asked: i64 = 0;
    fn tpm(k: const jwk::Key&, xa: i64, h: i64, data: const u8[:]) -> u8[>..] {
        calls++;
        asked = xa;
        return x509::sign_data(real, xa, h, data);
    }
    let token, es = jws::sign("held elsewhere", alg, pub, tpm);
    let payload, ev = jws::verify(token, alg, pub);
    tv::check(str(jwa::name(alg), ": signed through the signer, verified"),
              es == jwx::OK && ev == jwx::OK && payload == "held elsewhere" && calls == 1);
}

fn main() {
    one(jwa::ES256, x509::KEY_EC_P256);
    one(jwa::ES384, x509::KEY_EC_P384);
    one(jwa::ES512, x509::KEY_EC_P521);
    one(jwa::RS256, x509::KEY_RSA);
    one(jwa::PS384, x509::KEY_RSA);
    one(jwa::EDDSA, x509::KEY_ED25519);
    one(jwa::ED448, x509::KEY_ED448);
    one(jwa::ML_DSA_44, x509::KEY_MLDSA44);

    let real = x509::generate_key(x509::KEY_EC_P256);
    let pub, e = jwk::from_spki(x509::marshal_public_key(real));
    fn tpm(k: const jwk::Key&, xa: i64, h: i64, data: const u8[:]) -> u8[>..] { x509::sign_data(real, xa, h, data) }

    // The JSON serialization, one signer.
    let signers: jws::Signer[1] = [jws::Signer { key: pub, header: jws::Header { alg: jwa::ES256 } }];
    let json, ej = jws::sign_json("json held elsewhere", signers, true, tpm);
    let pj, evj = jws::verify(json, jwa::ES256, pub);
    tv::check("sign_json through the signer", ej == jwx::OK && evj == jwx::OK && pj == "json held elsewhere");

    // A JWT.
    var c = jwt::new_claims();
    c.sub.append("device-42");
    c.has |= jwt::CLAIM_SUB;
    let token, et = jwt::sign(c, jwa::ES256, pub, tpm);
    var got = jwt::new_claims();
    let v = jwt::Validator { validate: false };
    tv::check("a JWT through the signer", et == jwx::OK && jwt::parse(token, jwa::ES256, pub, got, v) == jwx::OK && got.sub == "device-42");

    // What fails.
    let none, en = jws::sign("x", jwa::ES256, pub) { k, xa, h, data => let e: u8[>..] = []; e };
    tv::check("a signer that answers nothing: ERR_KEY", en == jwx::ERR_KEY && none.len == 0);
    let nos, eno = jws::sign("x", jwa::ES256, pub);
    tv::check("no signer, a public key: ERR_KEY", eno == jwx::ERR_KEY);
    var hk = jwk::empty();
    hk.kty = jwa::KTY_OCT;
    hk.k.append("0123456789abcdef0123456789abcdef");
    let hs, eh = jws::sign("x", jwa::HS256, hk, tpm);
    tv::check("HMAC: a public oct key has no secret: ERR_KEY", eh == jwx::ERR_KEY);
    tv::done("signer");
}
