// sign_verify: JSON Web Signatures. Signs a payload in the compact form
// with HS256, RS256, ES256 and EdDSA and verifies it; shows that a changed
// token, the wrong key and an algorithm the token picks for itself are
// refused; signs once as JSON for two keys, either of which verifies; reads
// header parameters of the caller's own; and signs with a detached payload.
//
//   goose examples/jwx/sign_verify.goose
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;

fn fail(what: const u8[:], e: i64) {
    if e == jwx::OK { print("sign_verify: ", what); } else { print("sign_verify: ", what, ": ", jwx::error_text(e)); }
    exit(1);
}

fn main() {
    let payload = "{\"iss\":\"https://issuer.example.com\",\"msg\":\"hello\"}";

    // Compact: header.payload.signature, verified with the public key and
    // the algorithm the verifier expects.
    let algs = [jwa::HS256, jwa::RS256, jwa::ES256, jwa::EDDSA];
    let keys = [jwk::generate_oct(32), jwk::generate_rsa(2048), jwk::generate_ec(jwa::CRV_P256),
                jwk::generate_okp(jwa::CRV_ED25519)];
    for i in algs.len {
        let pub = if jwa::is_hmac(algs[i]) { keys[i] } else { jwk::public_key(keys[i]) };
        let token, e = jws::sign(payload, algs[i], keys[i]);
        if e != jwx::OK { fail("sign", e); }
        let got, ev = jws::verify(token, algs[i], pub);
        if ev != jwx::OK || got != payload { fail(str("verify ", jwa::name(algs[i])), ev); }
        print(jwa::name(algs[i]), ": ", token.len, " bytes, ", token[..min(40, token.len)], "...  verified");

        // One byte of the payload changed: the signature no longer holds.
        var bad: u8[>..] = [];
        bad.append(token);
        let dot = position(bad, '.');
        bad[dot + 2] = if bad[dot + 2] == 'A' { 'B' } else { 'A' };
        let x, ex = jws::verify(bad, algs[i], pub);
        guard ex != jwx::OK && x.len == 0 else { print("sign_verify: a changed token verified"); exit(1); }
    }

    // The wrong key, and an alg the token claims that the verifier did
    // not ask for.
    let ec = keys[2];
    let ec_pub = jwk::public_key(ec);
    let token, e = jws::sign(payload, jwa::ES256, ec);
    let stranger = jwk::generate_ec(jwa::CRV_P256);
    let other = jwk::public_key(stranger);
    let w, ew = jws::verify(token, jwa::ES256, other);
    guard ew == jwx::ERR_BAD_SIGNATURE else { fail("wrong key not refused", ew); }
    let m, em = jws::verify(token, jwa::ES384, ec_pub);
    guard em == jwx::ERR_ALG_MISMATCH else { fail("alg mismatch not refused", em); }
    print("wrong key: ", jwx::error_text(ew), "; another alg: ", jwx::error_text(em));

    // JSON serialization, two signatures over one payload: one with the
    // RSA key, one with the Ed25519 key, each with its kid.
    var signers: jws::Signer[>..] = [];
    signers.push(jws::Signer { key: keys[1], .. });
    signers[0].header.alg = jwa::RS256;
    signers[0].header.kid.append("rsa-1");
    signers.push(jws::Signer { key: keys[3], .. });
    signers[1].header.alg = jwa::EDDSA;
    signers[1].header.kid.append("ed-1");
    let json, ej = jws::sign_json(payload, signers);
    if ej != jwx::OK { fail("sign_json", ej); }
    let rsa_pub = jwk::public_key(keys[1]);
    let ed_pub = jwk::public_key(keys[3]);
    let p1, e1 = jws::verify(json, jwa::RS256, rsa_pub);
    let p2, e2 = jws::verify(json, jwa::EDDSA, ed_pub);
    guard e1 == jwx::OK && e2 == jwx::OK && p1 == payload && p2 == payload else { fail("JSON verify", if e1 != jwx::OK { e1 } else { e2 }); }
    var msg = jws::Message { .. };
    if jws::parse(msg, json) != jwx::OK { fail("parse", jwx::ERR_MALFORMED); }
    print("JSON: ", msg.sigs.len, " signatures (", msg.sigs[0].header.kid, ", ", msg.sigs[1].header.kid,
          "), each verifies alone");

    // A header of the caller's own: typ and a private parameter, read back
    // after verifying.
    var h = jws::Header { .. };
    h.alg = jwa::HS256;
    h.typ.append("example+jwt");
    let t3, e3 = jws::sign_with(payload, keys[0], h, "\"tenant\":\"acme\"");
    var m3 = jws::Message { .. };
    let v3, ev3 = jws::verify(t3, jwa::HS256, keys[0]);
    guard e3 == jwx::OK && ev3 == jwx::OK && jws::parse(m3, t3) == jwx::OK else { fail("own header", ev3); }
    let tenant, okt = jws::header_string(m3, 0, "tenant");
    guard okt && tenant == "acme" && m3.sigs[0].header.typ == "example+jwt" else { fail("header read", 0); }
    print("header: typ ", m3.sigs[0].header.typ, ", tenant ", tenant);

    // Detached: the token carries no payload; the verifier supplies it.
    let h4 = jws::Header { alg: jwa::ES256, .. };
    let t4, e4 = jws::sign_with(payload, ec, h4, "", true);
    guard e4 == jwx::OK && find(t4, "..") >= 0 else { fail("detached sign", e4); }
    guard jws::verify_detached(t4, payload, jwa::ES256, ec_pub) == jwx::OK else { fail("detached verify", 0); }
    guard jws::verify_detached(t4, "something else", jwa::ES256, ec_pub) != jwx::OK else {
        fail("detached: another payload verified", 0);
    }
    print("detached: ", t4.len, " bytes, verifies with the payload given separately");
}
