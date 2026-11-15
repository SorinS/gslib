// jwx.jwt: RFC 7519 §3.1's token (signed with RFC 7515 Appendix A.1's
// HMAC key) verified and its claims read; validation of exp, nbf, iat,
// iss, sub, aud, jti, max_age and required claims, at their edges and with
// skew; claims of the caller's own; signed, encrypted and nested tokens
// round-tripped; "aud" as a string and as an array, audiences holding a
// NUL kept whole in signed tokens; fractional dates.
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwt;
import tv;

let RFC_TOKEN = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
let RFC_KEY = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
let EXP: i64 = 1300819380;

fn at(now: i64) -> jwt::Validator {
    var v = jwt::Validator { .. };
    v.now = now;
    return v;
}

fn rfc() {
    let key, e = jwk::parse(RFC_KEY);
    tv::check_int("RFC key", e, jwx::OK);
    var c = jwt::new_claims();
    let v = at(EXP - 10);
    tv::check_int("RFC 7519 3.1 verified", jwt::parse(RFC_TOKEN, jwa::HS256, key, c, v), jwx::OK);
    tv::check_eq("iss", c.iss, "joe");
    tv::check("exp", jwt::has(c, jwt::CLAIM_EXP) && c.exp == EXP);
    let root, ok = jwt::get_raw(c, "http://example.com/is_root");
    tv::check("private claim", ok && root == "true");

    // exp: good until now reaches it, and skew seconds past it.
    var c2 = jwt::new_claims();
    tv::check_int("expired at exp", jwt::parse(RFC_TOKEN, jwa::HS256, key, c2, at(EXP)), jwx::ERR_EXPIRED);
    var v3 = at(EXP + 5);
    v3.skew = 10;
    var c3 = jwt::new_claims();
    tv::check_int("within skew", jwt::parse(RFC_TOKEN, jwa::HS256, key, c3, v3), jwx::OK);
    var v4 = at(EXP + 5);
    v4.validate = false;
    var c4 = jwt::new_claims();
    tv::check_int("validation off", jwt::parse(RFC_TOKEN, jwa::HS256, key, c4, v4), jwx::OK);
    var c5 = jwt::new_claims();
    tv::check_int("unverified read", jwt::parse_insecure(RFC_TOKEN, c5), jwx::OK);
    tv::check_eq("unverified iss", c5.iss, "joe");
}

fn validation() {
    let key = jwk::generate_ec(jwa::CRV_P256);
    let pub = jwk::public_key(key);
    let now: i64 = 1700000000;
    var c = jwt::new_claims();
    c.iss.append("https://issuer.example");
    c.sub.append("alice");
    c.jti.append("id-1");
    jwt::add_audience(c, "api");
    jwt::add_audience(c, "web");
    jwt::set_issued_at(c, now);
    jwt::set_not_before(c, now + 60);
    jwt::set_expiry(c, now + 3600);
    jwt::set_string(c, "scope", "read write");
    jwt::set_int(c, "level", 3);
    jwt::set_raw(c, "roles", "[\"admin\",\"dev\"]");
    let token, e = jwt::sign(c, jwa::ES256, key);
    tv::check_int("signed", e, jwx::OK);

    fn check_at(what: const u8[:], v: jwt::Validator, want: i64) {
        var got = jwt::new_claims();
        tv::check_int(what, jwt::parse(token, jwa::ES256, pub, got, v), want);
    }
    check_at("before nbf", at(now + 59), jwx::ERR_NOT_YET_VALID);
    check_at("at nbf", at(now + 60), jwx::OK);
    var vs = at(now + 30);
    vs.skew = 30;
    check_at("nbf within skew", vs, jwx::OK);
    check_at("before exp", at(now + 3599), jwx::OK);
    check_at("at exp", at(now + 3600), jwx::ERR_EXPIRED);

    var v = at(now + 100);
    v.issuer.append("https://issuer.example");
    v.subject.append("alice");
    v.audience.append("web");
    v.jwt_id.append("id-1");
    v.required = jwt::CLAIM_ISS | jwt::CLAIM_SUB | jwt::CLAIM_AUD | jwt::CLAIM_EXP | jwt::CLAIM_IAT | jwt::CLAIM_JTI;
    check_at("all claims as expected", v, jwx::OK);
    var vi = v;
    vi.issuer.resize(0);
    vi.issuer.append("https://other.example");
    check_at("other issuer", vi, jwx::ERR_ISSUER);
    var vsub = v;
    vsub.subject.resize(0);
    vsub.subject.append("bob");
    check_at("other subject", vsub, jwx::ERR_SUBJECT);
    var va = v;
    va.audience.resize(0);
    va.audience.append("mobile");
    check_at("other audience", va, jwx::ERR_AUDIENCE);
    var vj = v;
    vj.jwt_id.resize(0);
    vj.jwt_id.append("id-2");
    check_at("other jti", vj, jwx::ERR_JTI);
    var vm = v;
    vm.max_age = 50;
    check_at("older than max_age", vm, jwx::ERR_IAT);
    var vf = at(now - 1000);
    check_at("issued in the future", vf, jwx::ERR_NOT_YET_VALID);

    var got = jwt::new_claims();
    tv::check_int("claims read", jwt::parse(token, jwa::ES256, pub, got, v), jwx::OK);
    let scope, ok1 = jwt::get_string(got, "scope");
    let level, ok2 = jwt::get_int(got, "level");
    let roles, ok3 = jwt::get_raw(got, "roles");
    tv::check("own claims", ok1 && scope == "read write" && ok2 && level == 3 && ok3 && roles == "[\"admin\",\"dev\"]");
    tv::check_int("two audiences", jwt::audiences(got).len, 2);
    tv::check_eq("written the same", jwt::marshal(got), jwt::marshal(c));

    // A missing required claim.
    var bare = jwt::new_claims();
    bare.iss.append("x");
    let t2, e2 = jwt::sign(bare, jwa::ES256, key);
    var vr = at(now);
    vr.required = jwt::CLAIM_EXP;
    var g2 = jwt::new_claims();
    tv::check_int("required exp missing", jwt::parse(t2, jwa::ES256, pub, g2, vr), jwx::ERR_MISSING_CLAIM);
}

fn forms() {
    // "aud" as one string, dates with fractions.
    var c = jwt::new_claims();
    tv::check_int("aud string", jwt::parse_claims("{\"aud\":\"one\",\"exp\":1700000000.75}", c), jwx::OK);
    tv::check("aud string read", jwt::audiences(c).len == 1 && c.exp == 1700000000);
    for bad in ["{\"aud\":1}", "{\"aud\":[1]}", "{\"exp\":\"soon\"}", "{\"iss\":2}", "[]", "{\"iss\":\"a\",\"iss\":\"b\"}"] {
        var x = jwt::new_claims();
        tv::check(str("refused ", bad), jwt::parse_claims(bad, x) == jwx::ERR_MALFORMED);
    }
    var one = jwt::new_claims();
    jwt::add_audience(one, "api");
    tv::check_eq("aud as an array", jwt::marshal(one), "{\"aud\":[\"api\"]}");
    tv::check_eq("aud flattened", jwt::marshal(one, true), "{\"aud\":\"api\"}");
}

fn audience_of(want: const u8[:]) -> jwt::Validator {
    var v = jwt::Validator { .. };
    v.audience.append(want);
    return v;
}

// Audiences holding a NUL, in tokens signed with HMAC and with ECDSA, as a
// string and in an array: each is one audience, the very string, so a
// validator for "api" refuses "other\0api", "\0api" and "api\0".
fn nul_audiences() {
    var keys: jwk::Key[>..] = [];
    keys.push(jwk::generate_oct(32));
    keys.push(jwk::generate_ec(jwa::CRV_P256));
    let algs = [jwa::HS256, jwa::ES256];
    for i in 2 {
        let alg = algs[i];
        let pub = jwk::public_key(keys[i]);
        let name = jwa::name(alg);
        fn signed(payload: const u8[:]) -> u8[>..] {
            var h = jws::Header { .. };
            h.alg = alg;
            h.typ.append("JWT");
            let t, e = jws::sign_with(payload, keys[i], h);
            tv::check_int(str(name, " signed ", payload), e, jwx::OK);
            return t;
        }
        let auds = ["other\0api", "\0api", "api\0"];
        let texts = ["other\\u0000api", "\\u0000api", "api\\u0000"];
        for j in 3 {
            for form in 2 {
                let payload = if form == 0 { str("{\"aud\":\"", texts[j], "\"}") }
                              else { str("{\"aud\":[\"x\",\"", texts[j], "\"]}") };
                let t = signed(payload);
                var c = jwt::new_claims();
                tv::check_int(str(name, " NUL audience not api ", payload), jwt::parse(t, alg, pub, c, audience_of("api")),
                              jwx::ERR_AUDIENCE);
                var c2 = jwt::new_claims();
                tv::check_int(str(name, " NUL audience itself ", payload),
                              jwt::parse(t, alg, pub, c2, audience_of(auds[j])), jwx::OK);
                let got = jwt::audiences(c2);
                tv::check(str(name, " NUL audience kept whole ", payload),
                          got.len == form + 1 && got[form] == auds[j]);
                var c3 = jwt::new_claims();
                tv::check_int(str(name, " NUL audience not other ", payload),
                              jwt::parse(t, alg, pub, c3, audience_of("other")), jwx::ERR_AUDIENCE);
            }
        }
        // Ordinary audiences still work, an empty one is kept.
        let t = signed("{\"aud\":\"api\"}");
        var c = jwt::new_claims();
        tv::check_int(str(name, " aud string api"), jwt::parse(t, alg, pub, c, audience_of("api")), jwx::OK);
        let t2 = signed("{\"aud\":[\"web\",\"\",\"api\"]}");
        var c2 = jwt::new_claims();
        tv::check_int(str(name, " aud array api"), jwt::parse(t2, alg, pub, c2, audience_of("api")), jwx::OK);
        let got = jwt::audiences(c2);
        tv::check(str(name, " three audiences"), got.len == 3 && got[0] == "web" && got[1] == "" && got[2] == "api");
        var c3 = jwt::new_claims();
        tv::check_int(str(name, " aud array other"), jwt::parse(t2, alg, pub, c3, audience_of("mobile")), jwx::ERR_AUDIENCE);
    }

    // add_audience keeps a NUL too, and marshal writes it escaped.
    var c = jwt::new_claims();
    jwt::add_audience(c, "other\0api");
    jwt::add_audience(c, "");
    tv::check_eq("NUL audience written", jwt::marshal(c), "{\"aud\":[\"other\\u0000api\",\"\"]}");
    let t, e = jwt::sign(c, jwa::HS256, keys[0]);
    var got = jwt::new_claims();
    tv::check_int("NUL audience round trip", jwt::parse(t, jwa::HS256, keys[0], got, audience_of("api")), jwx::ERR_AUDIENCE);
    tv::check_eq("NUL audience read back", jwt::marshal(got), jwt::marshal(c));
}

fn tokens() {
    var c = jwt::new_claims();
    c.sub.append("carol");
    jwt::set_expiry(c, 4000000000);
    let v = jwt::Validator { .. };

    let rsa = jwk::generate_rsa(2048);
    let pub = jwk::public_key(rsa);
    let t, e = jwt::encrypt(c, jwa::RSA_OAEP_256, jwa::A256GCM, pub);
    var g = jwt::new_claims();
    tv::check("encrypted token", e == jwx::OK
              && jwt::parse_encrypted(t, jwa::RSA_OAEP_256, rsa, g, v) == jwx::OK && g.sub == "carol");

    let signer = jwk::generate_okp(jwa::CRV_ED25519);
    let t2, e2 = jwt::sign_encrypt(c, jwa::EDDSA, signer, jwa::RSA_OAEP_256, jwa::A128CBC_HS256, pub);
    var g2 = jwt::new_claims();
    let spub = jwk::public_key(signer);
    let r2 = jwt::parse_nested(t2, jwa::RSA_OAEP_256, rsa, jwa::EDDSA, spub, g2, v);
    tv::check("nested token", e2 == jwx::OK && r2 == jwx::OK && g2.sub == "carol");

    // A JWT is compact only (RFC 7519 §1): the same claims as a JSON JWS
    // or JWE are refused, though jws::verify and jwe::decrypt read them.
    var signers: jws::Signer[>..] = [];
    var sh = jws::Header { .. };
    sh.alg = jwa::EDDSA;
    signers.push(jws::Signer { key: signer, header: sh, .. });
    let body = jwt::marshal(c);
    for flat in [false, true] {
        let js, ejs = jws::sign_json(body, signers, flat);
        let jp, ejp = jws::verify(js, jwa::EDDSA, spub);
        tv::check(str("JSON JWS verifies, flattened ", flat), ejs == jwx::OK && ejp == jwx::OK);
        var gj = jwt::new_claims();
        tv::check_int(str("JSON JWS is not a JWT, flattened ", flat), jwt::parse(js, jwa::EDDSA, spub, gj, v), jwx::ERR_MALFORMED);
        var gs = jwt::new_claims();
        tv::check_int("JSON JWS not a JWT by set", jwt::parse_set(js, [spub], gs, v), jwx::ERR_MALFORMED);
        var gi = jwt::new_claims();
        tv::check_int("JSON JWS not read insecurely", jwt::parse_insecure(js, gi), jwx::ERR_MALFORMED);
    }
    var shared = jwe::Header { .. };
    shared.enc = jwa::A256GCM;
    var rs: jwe::Recipient[>..] = [];
    rs.push(jwe::Recipient { alg: jwa::RSA_OAEP_256, key: pub, .. });
    let je, eje = jwe::encrypt_json(body, shared, rs);
    var ge = jwt::new_claims();
    tv::check_int("JSON JWE is not a JWT", jwt::parse_encrypted(je, jwa::RSA_OAEP_256, rsa, ge, v), jwx::ERR_MALFORMED);

    // From a set of keys, by kid.
    var keys: jwk::Key[>..] = [];
    keys.push(jwk::generate_ec(jwa::CRV_P384));
    keys.push(jwk::generate_ec(jwa::CRV_P256));
    keys[0].kid.append("a");
    keys[1].kid.append("b");
    keys[1].alg = jwa::ES256;
    let t3, e3 = jwt::sign(c, jwa::ES256, keys[1]);
    var pubs: jwk::Key[>..] = [];
    for &k in keys { pubs.push(jwk::public_key(k)); }
    var g3 = jwt::new_claims();
    tv::check_int("by set", jwt::parse_set(t3, pubs, g3, v), jwx::OK);
    // An HS256 token claiming the EC key's kid is refused.
    var forged_key = jwk::from_oct("0123456789abcdef0123456789abcdef");
    forged_key.kid.append("b");
    let t4, e4 = jwt::sign(c, jwa::HS256, forged_key);
    var g4 = jwt::new_claims();
    tv::check("forged kid refused", jwt::parse_set(t4, pubs, g4, v, true) != jwx::OK);
}

fn main() {
    rfc();
    validation();
    forms();
    nul_audiences();
    tokens();
    tv::done("jwt");
}
