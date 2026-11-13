// nested_jwt: tokens that are signed and then encrypted (a nested JWT,
// cty "JWT"), so that only the intended service can read the claims and
// it can tell who issued them. The issuer signs with its Ed25519 key and
// encrypts to the service's RSA key; the service decrypts, verifies and
// validates in one call. Also an encrypted-only token (to an X25519 key),
// and the refusals: the wrong decryption key, and a signer it does not trust.
//
//   goose examples/jwx/nested_jwt.goose
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jwe;
import gslib.jwx.jwt;

fn main() {
    let issuer = jwk::generate_okp(jwa::CRV_ED25519);        // signs
    let service = jwk::generate_rsa(2048);                   // decrypts
    let issuer_pub = jwk::public_key(issuer);
    let service_pub = jwk::public_key(service);

    var c = jwt::new_claims();
    c.iss.append("https://auth.example.com");
    c.sub.append("user-42");
    jwt::add_audience(c, "https://payments.example.com");
    jwt::set_expiry(c, 4000000000);
    jwt::set_string(c, "account", "acct-0001");

    // Sign with EdDSA, then encrypt with RSA-OAEP-256 and A256GCM.
    let token, e = jwt::sign_encrypt(c, jwa::EDDSA, issuer, jwa::RSA_OAEP_256, jwa::A256GCM, service_pub);
    guard e == jwx::OK else { print("nested_jwt: ", jwx::error_text(e)); exit(1); }
    var m = jwe::Message { .. };
    guard jwe::parse(m, token) == jwx::OK else { print("nested_jwt: not a JWE"); exit(1); }
    let cty, okc = jwe::header_string(m, "cty");
    guard okc && cty == "JWT" else { print("nested_jwt: no cty JWT"); exit(1); }
    print("nested token: ", token.len, " bytes, a JWE (", jwa::name(m.recipients[0].header.alg), ", ",
          jwa::name(m.recipients[0].header.enc), ", cty ", cty, ") around a JWS");

    // The claims are not readable without the service's key.
    guard find(token, "user-42") < 0 && find(token, "dXNlci00Mi") < 0 else { print("nested_jwt: claims in clear"); exit(1); }

    var v = jwt::Validator { .. };
    v.audience.append("https://payments.example.com");
    v.issuer.append("https://auth.example.com");
    var got = jwt::new_claims();
    let r = jwt::parse_nested(token, jwa::RSA_OAEP_256, service, jwa::EDDSA, issuer_pub, got, v);
    let account, oka = jwt::get_string(got, "account");
    guard r == jwx::OK && got.sub == "user-42" && oka else { print("nested_jwt: ", jwx::error_text(r)); exit(1); }
    print("decrypted, verified, validated: sub ", got.sub, ", account ", account);

    // Another service's key cannot open it; a signer the service does not
    // trust is refused even though the encryption is to the right key.
    let other_service = jwk::generate_rsa(2048);
    var g1 = jwt::new_claims();
    let r1 = jwt::parse_nested(token, jwa::RSA_OAEP_256, other_service, jwa::EDDSA, issuer_pub, g1, v);
    let impostor = jwk::generate_okp(jwa::CRV_ED25519);
    let forged, ef = jwt::sign_encrypt(c, jwa::EDDSA, impostor, jwa::RSA_OAEP_256, jwa::A256GCM, service_pub);
    var g2 = jwt::new_claims();
    let r2 = jwt::parse_nested(forged, jwa::RSA_OAEP_256, service, jwa::EDDSA, issuer_pub, g2, v);
    guard r1 == jwx::ERR_DECRYPT && ef == jwx::OK && r2 == jwx::ERR_BAD_SIGNATURE else {
        print("nested_jwt: a bad token was accepted"); exit(1);
    }
    print("another service's key: ", jwx::error_text(r1), "; an untrusted signer: ", jwx::error_text(r2));

    // Encrypted only: confidential, but anyone with the public key could
    // have made it. ECDH-ES to an X25519 key.
    let device = jwk::generate_okp(jwa::CRV_X25519);
    let device_pub = jwk::public_key(device);
    let sealed, es = jwt::encrypt(c, jwa::ECDH_ES, jwa::A128GCM, device_pub);
    var g3 = jwt::new_claims();
    let r3 = jwt::parse_encrypted(sealed, jwa::ECDH_ES, device, g3, v);
    guard es == jwx::OK && r3 == jwx::OK && g3.sub == "user-42" else { print("nested_jwt: encrypted token: ", jwx::error_text(r3)); exit(1); }
    print("encrypted-only token: ", sealed.len, " bytes, read back by the X25519 key");
}
