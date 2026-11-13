// jwt_tokens: JSON Web Tokens as an issuer and an API use them. The issuer
// signs a token with its EC key, with the registered claims (iss, sub, aud,
// iat, nbf, exp, jti) and claims of its own; the API verifies it against
// the issuer's key set, by kid, and checks issuer, audience and times;
// then the same token is shown refused once expired, before it is valid,
// for another audience, and when a claim the API requires is missing.
//
//   goose examples/jwx/jwt_tokens.goose
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jwt;

let ISSUER = "https://auth.example.com";
let NOW: i64 = 1800000000;      // a fixed clock, so the example runs the same any day

// The API's checks, at a given time.
fn api_validator(now: i64) -> jwt::Validator {
    var v = jwt::Validator { .. };
    v.now = now;
    v.skew = 30;                // tolerate 30 seconds of clock difference
    v.issuer.append(ISSUER);
    v.audience.append("orders-api");
    v.required = jwt::CLAIM_SUB | jwt::CLAIM_EXP;
    return v;
}

fn main() {
    // The issuer's signing key, published as a JWKS with its kid and alg.
    var key = jwk::generate_ec(jwa::CRV_P256);
    key.kid.append("2026-11");
    key.alg = jwa::ES256;
    var published: jwk::Key[>..] = [];
    published.push(jwk::public_key(key));
    let jwks = jwk::marshal_set(published, false);

    // Issue: five minutes of validity, for two audiences.
    var c = jwt::new_claims();
    c.iss.append(ISSUER);
    c.sub.append("user-42");
    c.jti.append("a1b2c3");
    jwt::add_audience(c, "orders-api");
    jwt::add_audience(c, "billing-api");
    jwt::set_issued_at(c, NOW);
    jwt::set_not_before(c, NOW);
    jwt::set_expiry(c, NOW + 300);
    jwt::set_string(c, "scope", "orders:read orders:write");
    jwt::set_int(c, "tier", 2);
    jwt::set_raw(c, "roles", "[\"buyer\",\"admin\"]");
    let token, e = jwt::sign(c, jwa::ES256, key);
    guard e == jwx::OK else { print("jwt_tokens: sign: ", jwx::error_text(e)); exit(1); }
    print("token: ", token.len, " bytes, claims ", jwt::marshal(c));

    // Verify: the API knows the issuer's JWKS, not the key itself; the
    // token's kid picks the key, the key's alg the algorithm.
    var keys: jwk::Key[>..] = [];
    guard jwk::parse_set(jwks, keys) == jwx::OK else { print("jwt_tokens: bad JWKS"); exit(1); }
    var got = jwt::new_claims();
    let r = jwt::parse_set(token, keys, got, api_validator(NOW + 60));
    guard r == jwx::OK else { print("jwt_tokens: verify: ", jwx::error_text(r)); exit(1); }
    let scope, oks = jwt::get_string(got, "scope");
    let tier, okt = jwt::get_int(got, "tier");
    let roles, okr = jwt::get_raw(got, "roles");
    guard got.sub == "user-42" && oks && okt && okr && tier == 2 && jwt::audiences(got).len == 2 else {
        print("jwt_tokens: claims did not read back"); exit(1);
    }
    print("valid: sub ", got.sub, ", scope \"", scope, "\", tier ", tier, ", roles ", roles, ", expires in ",
          got.exp - (NOW + 60), " s");

    // Refusals, each with its reason.
    fn expect(what: const u8[:], v: jwt::Validator, want: i64) {
        var cl = jwt::new_claims();
        let r = jwt::parse_set(token, keys, cl, v);
        guard r == want else {
            print("jwt_tokens: ", what, ": got \"", jwx::error_text(r), "\", wanted \"", jwx::error_text(want), "\"");
            exit(1);
        }
        print(what, ": ", jwx::error_text(r));
    }
    expect("an hour later", api_validator(NOW + 3600), jwx::ERR_EXPIRED);
    expect("within the skew of exp", api_validator(NOW + 320), jwx::OK);
    expect("a minute before nbf", api_validator(NOW - 60), jwx::ERR_NOT_YET_VALID);
    var other = api_validator(NOW + 60);
    other.audience.resize(0);
    other.audience.append("admin-api");
    expect("for admin-api", other, jwx::ERR_AUDIENCE);
    var strict = api_validator(NOW + 60);
    strict.max_age = 20;
    expect("issued more than 20 s (and the skew) ago", strict, jwx::ERR_IAT);

    var c2 = jwt::new_claims();
    c2.iss.append(ISSUER);
    jwt::add_audience(c2, "orders-api");
    jwt::set_expiry(c2, NOW + 300);
    let anon, e2 = jwt::sign(c2, jwa::ES256, key);
    var g2 = jwt::new_claims();
    let r2 = jwt::parse_set(anon, keys, g2, api_validator(NOW));
    guard e2 == jwx::OK && r2 == jwx::ERR_MISSING_CLAIM else { print("jwt_tokens: a token without sub was accepted"); exit(1); }
    print("a token without sub: ", jwx::error_text(r2));

    // Reading claims without verifying (for logging or routing only).
    var peek = jwt::new_claims();
    guard jwt::parse_insecure(token, peek) == jwx::OK && peek.iss == ISSUER else { print("jwt_tokens: peek failed"); exit(1); }
    print("unverified peek: iss ", peek.iss);
}
