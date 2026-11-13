// keys: JSON Web Keys. Generates a key of each type, writes it as a JWK
// and reads it back, takes its public half and its RFC 7638 thumbprint,
// collects public keys in a key set (a JWKS document) and finds one by
// kid, and converts keys to PEM and back as OpenSSL writes them.
//
//   goose examples/jwx/keys.goose
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.pem;

// RFC 7638 §3.1's key, and its thumbprint.
let RFC_N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
let RFC_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

fn main() {
    // A published key, read and identified by its thumbprint.
    let rfc, e = jwk::parse(str("{\"kty\":\"RSA\",\"n\":\"", RFC_N, "\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}"));
    guard e == jwx::OK && jwk::thumbprint_b64(rfc) == RFC_THUMBPRINT else {
        print("keys: RFC 7638 thumbprint: ", jwx::error_text(e)); exit(1);
    }
    print("RFC 7638 key ", rfc.kid, ": ", jwa::kty_name(rfc.kty), ", ", jwk::rsa_bits(rfc), " bits, thumbprint ", RFC_THUMBPRINT);

    // One key of each kind, named by kid.
    var keys: jwk::Key[>..] = [];
    keys.push(jwk::generate_rsa(2048));
    keys.push(jwk::generate_ec(jwa::CRV_P256));
    keys.push(jwk::generate_okp(jwa::CRV_ED25519));
    keys.push(jwk::generate_oct(32));
    let kids = ["rsa-1", "ec-1", "ed-1", "hmac-1"];
    let algs = [jwa::RS256, jwa::ES256, jwa::EDDSA, jwa::HS256];
    for i in keys.len {
        keys[i].kid.append(kids[i]);
        keys[i].alg = algs[i];
        guard jwk::validate(keys[i]) == jwx::OK && jwk::fits(keys[i], algs[i]) && jwk::strong_enough(keys[i], algs[i]) else {
            print("keys: ", kids[i], " unfit for ", jwa::name(algs[i])); exit(1);
        }

        // To JSON and back: the same key, the same thumbprint.
        let text = jwk::marshal(keys[i]);
        let back, eb = jwk::parse(text);
        guard eb == jwx::OK && jwk::thumbprint(back) == jwk::thumbprint(keys[i]) else {
            print("keys: ", kids[i], " did not read back"); exit(1);
        }
        let crv: u8[>..] = if keys[i].crv == jwa::CRV_UNKNOWN { "" } else { str(" ", jwa::crv_name(keys[i].crv)) };
        print(kids[i], ": ", jwa::kty_name(keys[i].kty), crv, " for ", jwa::name(algs[i]),
              ", ", text.len, " bytes of JWK, thumbprint ", jwk::thumbprint_b64(keys[i]));
    }

    // A JWKS of the public keys, as a server publishes it (the HMAC
    // secret has no public half and stays out).
    var pubs: jwk::Key[>..] = [];
    for i in 3 { pubs.push(jwk::public_key(keys[i])); }
    let jwks = jwk::marshal_set(pubs, false);
    var set: jwk::Key[>..] = [];
    guard jwk::parse_set(jwks, set) == jwx::OK && set.len == 3 else { print("keys: the set did not parse"); exit(1); }
    let found = jwk::lookup_kid(set, "ec-1");
    guard found else { print("keys: ec-1 not in the set"); exit(1); }
    guard !found.private && found.d.len == 0 && jwk::thumbprint(found) == jwk::thumbprint(keys[1]) else {
        print("keys: ec-1 is not the public half"); exit(1);
    }
    print("JWKS of ", set.len, " public keys, ", jwks.len, " bytes; ec-1 found by kid");

    // PEM: the private key as PKCS #8, the public key as SPKI, each read
    // back to the same JWK.
    for i in 3 {
        let priv_pem, e1 = jwk::to_pem(keys[i]);
        let pub_pem, e2 = jwk::to_pem(keys[i], true);
        let k1, e3 = jwk::from_pem(priv_pem);
        let k2, e4 = jwk::from_pem(pub_pem);
        guard e1 == jwx::OK && e2 == jwx::OK && e3 == jwx::OK && e4 == jwx::OK && k1.private && !k2.private
              && jwk::thumbprint(k1) == jwk::thumbprint(keys[i]) && jwk::thumbprint(k2) == jwk::thumbprint(keys[i]) else {
            print("keys: ", kids[i], " PEM round trip failed"); exit(1);
        }
        print(kids[i], " as PEM: ", split(pub_pem, '\n')[0], " (", pub_pem.len, " bytes), and back");
    }
    let none, en = jwk::to_pem(keys[3]);
    guard en == jwx::ERR_KEY else { print("keys: an HMAC secret has no PEM"); exit(1); }
}
