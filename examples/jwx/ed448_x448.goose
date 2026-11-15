// ed448_x448: the 448-bit curves of RFC 8037 in JOSE. An issuer with an
// Ed448 key (kty "OKP", crv "Ed448") publishes its public JWK and its
// thumbprint as the kid, signs a JWT under RFC 9864's fully specified
// "Ed448" (and once under RFC 8037's "EdDSA", which takes either Edwards
// curve), and a verifier checks it, refusing an Ed25519 key and the alg
// it did not ask for. Then a service with an X448 key receives a JWE by
// ECDH-ES+A256KW: the sender's ephemeral X448 key travels in the header's
// "epk", and the service, and nobody else, decrypts it.
//
//   goose examples/jwx/ed448_x448.goose
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwe;
import gslib.jwx.jwt;

fn fail(what: const u8[:], e: i64) {
    if e == jwx::OK { print("ed448_x448: ", what); } else { print("ed448_x448: ", what, ": ", jwx::error_text(e)); }
    exit(1);
}

fn main() {
    // The issuer's key, published without its private part.
    var issuer = jwk::generate_okp(jwa::CRV_ED448);
    issuer.kid.append(jwk::thumbprint_b64(issuer));
    let published = jwk::marshal(issuer, false);
    print("issuer's JWK: ", published.len, " bytes, x of ", issuer.x.len, " bytes, kid ", issuer.kid);
    let issuer_pub, ep = jwk::parse(published);
    if ep != jwx::OK { fail("parse the published key", ep); }

    // A JWT signed with "Ed448": a 114-byte signature.
    var c = jwt::new_claims();
    c.iss.append("https://issuer.example.com");
    c.sub.append("alice");
    let token, es = jwt::sign(c, jwa::ED448, issuer);
    if es != jwx::OK { fail("sign", es); }
    var m = jws::Message { .. };
    if jws::parse(m, token) != jwx::OK || m.sigs[0].sig.len != 114 { fail("an Ed448 signature", jwx::OK); }
    var got = jwt::new_claims();
    let r = jwt::parse(token, jwa::ED448, issuer_pub, got, jwt::Validator { .. });
    if r != jwx::OK || got.sub[..] != "alice" { fail("verify", r); }
    print("Ed448 JWT: ", token.len, " bytes, verified, sub ", got.sub);

    // Asked for "EdDSA" or "Ed25519", the verifier refuses a token whose
    // header says "Ed448"; an Ed25519 key does not verify "Ed448".
    var g2 = jwt::new_claims();
    let r1 = jwt::parse(token, jwa::EDDSA, issuer_pub, g2, jwt::Validator { .. });
    if r1 != jwx::ERR_ALG_MISMATCH { fail("EdDSA asked, Ed448 sent", r1); }
    let ed25519 = jwk::generate_okp(jwa::CRV_ED25519);
    let ed25519_pub = jwk::public_key(ed25519);
    let r2 = jwt::parse(token, jwa::ED448, ed25519_pub, g2, jwt::Validator { .. });
    if r2 != jwx::ERR_KEY { fail("an Ed25519 key for Ed448", r2); }
    print("refused: EdDSA asked for an Ed448 token; an Ed25519 key for Ed448");

    // RFC 8037's "EdDSA" names no curve: the key says Ed448.
    let t2, e2 = jws::sign("{\"msg\":\"hello\"}", jwa::EDDSA, issuer);
    let p2, ev2 = jws::verify(t2, jwa::EDDSA, issuer_pub);
    if e2 != jwx::OK || ev2 != jwx::OK || p2 != "{\"msg\":\"hello\"}" { fail("EdDSA with Ed448", ev2); }
    print("EdDSA with an Ed448 key: verified");

    // The service's X448 key; the sender knows its public half.
    let service = jwk::generate_okp(jwa::CRV_X448);
    let service_pub = jwk::public_key(service);
    let secret = "{\"note\":\"meet at noon\"}";
    let jwe_token, ee = jwe::encrypt(secret, jwa::ECDH_ES_A256KW, jwa::A256GCM, service_pub);
    if ee != jwx::OK { fail("encrypt", ee); }
    var jm = jwe::Message { .. };
    if jwe::parse(jm, jwe_token) != jwx::OK { fail("parse the JWE", jwx::OK); }
    let epk = jm.recipients[0].header.epk;
    print("X448 JWE: ", jwe_token.len, " bytes, epk crv ", jwa::crv_name(epk.crv), ", x of ", epk.x.len, " bytes");
    let pt, ed = jwe::decrypt(jwe_token, jwa::ECDH_ES_A256KW, service);
    if ed != jwx::OK || pt != secret { fail("decrypt", ed); }
    let eavesdropper = jwk::generate_okp(jwa::CRV_X448);
    let x, ex = jwe::decrypt(jwe_token, jwa::ECDH_ES_A256KW, eavesdropper);
    if ex != jwx::ERR_DECRYPT { fail("another X448 key decrypted", ex); }
    print("decrypted by the service; another X448 key refused");

    // ECDH-ES straight to the content key, A128CBC-HS256.
    let t3, e3 = jwe::encrypt("direct", jwa::ECDH_ES, jwa::A128CBC_HS256, service_pub);
    let p3, ed3 = jwe::decrypt(t3, jwa::ECDH_ES, service);
    if e3 != jwx::OK || ed3 != jwx::OK || p3 != "direct" { fail("ECDH-ES with X448", ed3); }
    print("ECDH-ES with X448: decrypted");
}
