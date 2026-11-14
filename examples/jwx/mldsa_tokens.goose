// mldsa_tokens: post-quantum JWTs with ML-DSA (FIPS 204) as RFC 9964 puts
// it in JOSE. Generates an ML-DSA-65 key, an "AKP" JWK whose private part
// is the 32-byte seed, prints its public JWK and RFC 7638 thumbprint (of
// alg, kty and pub) and its PEM; reads RFC 9964's ML-DSA-44 example key
// and checks its kid is that thumbprint; signs a JWT with ML-DSA-65 and
// verifies it through a JWKS by kid; then shows a changed token, the
// wrong algorithm and an ML-DSA-44 key refused.
//
//   goose examples/jwx/mldsa_tokens.goose
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jwt;
import gslib.jwx.pem;

let NOW: i64 = 1800000000;      // a fixed clock, so the example runs the same any day

// RFC 9964 Appendix A.1's ML-DSA-44 key is the seed of 32 zero bytes;
// its "kid" is its thumbprint.
let RFC_KID = "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o";

fn main() {
    // A new ML-DSA-65 key. AKP keys always carry their "alg".
    var key = jwk::generate_akp(jwa::ML_DSA_65);
    key.kid.append(jwk::thumbprint_b64(key));
    guard jwk::validate(key) == jwx::OK else { print("mldsa_tokens: the new key is not valid"); exit(1); }
    let pub = jwk::public_key(key);
    let pub_text = jwk::marshal(pub);
    print("ML-DSA-65 key ", key.kid, ": private JWK ", jwk::marshal(key).len, " bytes, public JWK ", pub_text.len,
          " bytes:");
    print("  ", pub_text[..120], "...", pub_text[pub_text.len - 24..]);
    guard find(pub_text, "\"priv\"") < 0 else { print("mldsa_tokens: the public JWK has the seed"); exit(1); }

    // The public JWK read back has the same thumbprint; the private one
    // (alg, kty, priv, pub) reads back the same key.
    let back, eb = jwk::parse(pub_text);
    guard eb == jwx::OK && !back.private && jwk::thumbprint_b64(back) == key.kid[..] else {
        print("mldsa_tokens: public JWK: ", jwx::error_text(eb)); exit(1);
    }
    let again, ea = jwk::parse(jwk::marshal(key));
    guard ea == jwx::OK && again.d[..] == key.d[..] && again.pub[..] == key.pub[..] else {
        print("mldsa_tokens: private JWK: ", jwx::error_text(ea)); exit(1);
    }

    // And as PEM: RFC 9881's SubjectPublicKeyInfo and seed-only PKCS #8.
    let pem_pub, ep = jwk::to_pem(key, true);
    let from_pem, ef = jwk::from_pem(pem_pub);
    guard ep == jwx::OK && ef == jwx::OK && jwk::thumbprint_b64(from_pem) == key.kid[..] else {
        print("mldsa_tokens: PEM: ", jwx::error_text(ef)); exit(1);
    }
    print("as PEM: ", pem_pub.len, " bytes of PUBLIC KEY, the same thumbprint");

    // RFC 9964's example: the key from its seed, and its kid.
    var zeros: u8[>..] = [];
    zeros.resize(32, 0);
    let rfc = jwk::akp_from_seed(jwa::ML_DSA_44, zeros);
    guard jwk::thumbprint_b64(rfc) == RFC_KID else { print("mldsa_tokens: RFC 9964 kid differs"); exit(1); }
    print("RFC 9964 ML-DSA-44 example key: thumbprint ", RFC_KID, " as the RFC has it");

    // A JWT signed with ML-DSA-65; the verifier has the JWKS.
    var c = jwt::new_claims();
    c.iss.append("https://pq.example.com");
    c.sub.append("user-42");
    jwt::add_audience(c, "orders-api");
    jwt::set_issued_at(c, NOW);
    jwt::set_expiry(c, NOW + 300);
    let token, e = jwt::sign(c, jwa::ML_DSA_65, key);
    guard e == jwx::OK else { print("mldsa_tokens: sign: ", jwx::error_text(e)); exit(1); }
    print("JWT signed with ML-DSA-65: ", token.len, " bytes (the signature alone is 3309)");

    var published: jwk::Key[>..] = [];
    published.push(jwk::generate_okp(jwa::CRV_ED25519));
    published.push(pub);
    let jwks = jwk::marshal_set(published, false);
    var keys: jwk::Key[>..] = [];
    guard jwk::parse_set(jwks, keys) == jwx::OK && keys.len == 2 else { print("mldsa_tokens: bad JWKS"); exit(1); }
    var v = jwt::Validator { .. };
    v.now = NOW + 60;
    v.issuer.append("https://pq.example.com");
    v.audience.append("orders-api");
    var got = jwt::new_claims();
    let r = jwt::parse_set(token, keys, got, v);
    guard r == jwx::OK && got.sub == "user-42" else { print("mldsa_tokens: verify: ", jwx::error_text(r)); exit(1); }
    print("verified through the JWKS (by kid, with the key's alg): sub ", got.sub);

    // Refusals.
    fn expect(what: const u8[:], r: i64, want: i64) {
        guard r == want else {
            print("mldsa_tokens: ", what, ": got \"", jwx::error_text(r), "\", wanted \"", jwx::error_text(want), "\"");
            exit(1);
        }
        print(what, ": refused, ", jwx::error_text(r));
    }
    var tampered: u8[>..] = [];
    tampered.append(token);
    let dot = find(token, ".");
    tampered[dot + 5] = if tampered[dot + 5] == 'A' { 'B' } else { 'A' };     // a byte of the claims
    var g1 = jwt::new_claims();
    expect("a changed token", jwt::parse(tampered, jwa::ML_DSA_65, pub, g1, v), jwx::ERR_BAD_SIGNATURE);
    var g2 = jwt::new_claims();
    expect("verified as ML-DSA-87", jwt::parse(token, jwa::ML_DSA_87, pub, g2, v), jwx::ERR_ALG_MISMATCH);
    var g3 = jwt::new_claims();
    expect("verified with an ML-DSA-44 key", jwt::parse(token, jwa::ML_DSA_65, rfc, g3, v), jwx::ERR_KEY);
    let x, es = jwt::sign(c, jwa::EDDSA, key);
    expect("an ML-DSA key signing EdDSA", es, jwx::ERR_KEY);
}
