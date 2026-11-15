// jwx.jwk: RFC 7517 Appendix A's keys read and written back; RFC 7638
// §3.1's thumbprint and RFC 8037 Appendix A.3's; keys whose parts disagree
// refused; new keys of every type round-tripped through JSON; sets.
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import tv;

// RFC 7638 §3.1 (RFC 7517 A.1's RSA key).
let RSA_N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

// RFC 7517 A.1's EC key, with A.2's private part.
let EC_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\",\"use\":\"enc\",\"kid\":\"1\"}";

// RFC 8037 A.1 and A.2.
let ED_KEY = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";

fn main() {
    let rsa_text = str("{\"kty\":\"RSA\",\"n\":\"", RSA_N, "\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}");
    let rsa, e1 = jwk::parse(rsa_text);
    tv::check_int("RSA public key", e1, jwx::OK);
    tv::check_int("RSA bits", jwk::rsa_bits(rsa), 2048);
    tv::check_int("RSA alg", rsa.alg, jwa::RS256);
    tv::check_eq("RSA kid", rsa.kid, "2011-04-29");
    tv::check_eq("RFC 7638 thumbprint", jwk::thumbprint_b64(rsa), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    tv::check_eq("RSA written", jwk::marshal(rsa),
                 str("{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"2011-04-29\",\"kty\":\"RSA\",\"n\":\"", RSA_N, "\"}"));

    let ec, e2 = jwk::parse(EC_KEY);
    tv::check_int("EC private key", e2, jwx::OK);
    tv::check("EC is private", ec.private);
    tv::check_int("EC use", ec.key_use, jwk::USE_ENC);
    let ec_back, e3 = jwk::parse(jwk::marshal(ec));
    tv::check("EC round trip", e3 == jwx::OK && jwk::marshal(ec_back) == jwk::marshal(ec));
    let ec_pub = jwk::public_key(ec);
    tv::check("EC public half", !ec_pub.private && ec_pub.d.len == 0);
    tv::check_eq("EC public written",  jwk::marshal(ec, false), jwk::marshal(ec_pub));

    let ed, e4 = jwk::parse(ED_KEY);
    tv::check_int("Ed25519 key", e4, jwx::OK);
    tv::check_eq("RFC 8037 A.3 thumbprint", jwk::thumbprint_b64(ed), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");

    // Parts that disagree, malformed members, unknown types.
    let bad = [
        // d of another key
        "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}",
        // a point off the curve (y changed)
        "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyQ\"}",
        // x too short
        "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcH\"}",
        // padding
        "{\"kty\":\"oct\",\"k\":\"AQAB==\"}",
        // duplicate member
        "{\"kty\":\"oct\",\"k\":\"AQAB\",\"k\":\"AQAC\"}",
        // missing kty, kty not a string, empty k
        "{\"k\":\"AQAB\"}", "{\"kty\":1,\"k\":\"AQAB\"}", "{\"kty\":\"oct\",\"k\":\"\"}",
        "[1]", "{",
    ];
    for t in bad {
        let k, e = jwk::parse(t);
        tv::check(str("refused ", t), e != jwx::OK);
    }
    let x448, e5 = jwk::parse("{\"kty\":\"OKP\",\"crv\":\"X448\",\"x\":\"AQAB\"}");
    tv::check_int("X448 key of 3 bytes refused", e5, jwx::ERR_KEY);
    let k1, e6 = jwk::parse("{\"kty\":\"EC\",\"crv\":\"secp256k1\",\"x\":\"AQAB\",\"y\":\"AQAB\"}");
    tv::check_int("secp256k1 unsupported", e6, jwx::ERR_UNSUPPORTED);

    // New keys: valid, and the same after JSON both ways.
    var made: jwk::Key[>..] = [];
    made.push(jwk::generate_ec(jwa::CRV_P256));
    made.push(jwk::generate_ec(jwa::CRV_P384));
    made.push(jwk::generate_ec(jwa::CRV_P521));
    made.push(jwk::generate_okp(jwa::CRV_ED25519));
    made.push(jwk::generate_okp(jwa::CRV_X25519));
    made.push(jwk::generate_okp(jwa::CRV_ED448));
    made.push(jwk::generate_okp(jwa::CRV_X448));
    made.push(jwk::generate_oct(32));
    made.push(jwk::generate_rsa(2048));
    for &k in made {
        let what = str(jwa::kty_name(k.kty), " ", jwa::crv_name(k.crv));
        tv::check_int(str(what, " valid"), jwk::validate(k), jwx::OK);
        let text = jwk::marshal(k);
        let back, e = jwk::parse(text);
        tv::check_int(str(what, " parsed back"), e, jwx::OK);
        tv::check_eq(str(what, " written back"), jwk::marshal(back), text);
        tv::check_eq(str(what, " thumbprint"), jwk::thumbprint(back), jwk::thumbprint(k));
        let pub, ep = jwk::parse(jwk::marshal(k, false));
        tv::check(str(what, " public parsed"), ep == jwx::OK && (pub.kty == jwa::KTY_OCT || !pub.private));
    }
    made[0].kid.append("first");
    made[3].kid.append("ed");
    let set_text = jwk::marshal_set(made, false);
    var set: jwk::Key[>..] = [];
    tv::check_int("set parsed", jwk::parse_set(set_text, set), jwx::OK);
    tv::check_int("set size", set.len, made.len);
    let f = jwk::lookup_kid(set, "ed");
    tv::check("lookup by kid", f && f.crv == jwa::CRV_ED25519);
    // Keys of a type this package does not do are passed over.
    var set2: jwk::Key[>..] = [];
    let mixed = str("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed1174\",\"x\":\"AQAB\"},", ED_KEY, "]}");
    tv::check_int("unsupported key skipped", jwk::parse_set(mixed, set2), jwx::OK);
    tv::check_int("one key left", set2.len, 1);

    let hk = jwk::from_oct("0123456789abcdef0123456789abcdef");
    let short = jwk::from_oct("short");
    tv::check("HS256 key fits", jwk::fits(hk, jwa::HS256));
    tv::check("short HS256 key fits, as in jwx", jwk::fits(short, jwa::HS256));
    tv::check("but is not strong enough", !jwk::strong_enough(short, jwa::HS256) && jwk::strong_enough(hk, jwa::HS256));
    tv::check("RSA key for RS256", jwk::fits(rsa, jwa::RS256));
    tv::check("RSA key's alg binds it", !jwk::fits(rsa, jwa::PS256));
    tv::check("EC key for ES256", jwk::fits(ec, jwa::ES256) && !jwk::fits(ec, jwa::ES384));
    tv::check("X25519 key for ECDH-ES", jwk::fits(made[4], jwa::ECDH_ES) && !jwk::fits(made[4], jwa::EDDSA));
    tv::done("jwk");
}
