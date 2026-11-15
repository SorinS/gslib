// Ed448 and X448 (RFC 8037): RFC 8037 Appendix A.7's ECDH-ES with X448
// (the recipient Dave is RFC 7748 §6.2's Bob, the ephemeral key its
// Alice), reproduced: the keys' public halves, Z both ways, and a message
// with the appendix's header decrypted by Dave. Then Ed448 keys and
// signatures: a JWS made by Go's lestrrat-go/jwx v4 (with jwx-go/ed448)
// under RFC 8032 §7.4's first key, which Ed448 being deterministic must
// come out the same here, and its RFC 7638 thumbprint; "EdDSA" with either
// Edwards curve, RFC 9864's "Ed25519" and "Ed448" with their own only;
// JWK refusals; X448 with every ECDH-ES algorithm, a low-order peer and an
// Ed448 epk refused.
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwe;
import gslib.jwx.jwt;
import tv;

// RFC 7748 §6.2's X448 keys, which RFC 8037 A.7 uses.
let DAVE_D = "HDBqesKg4uCZCylEcMujOeZFN3KwdYEdj60NHWknwSC7XuiXKw0-ITdMnJIbCdGwNm8QtlFzmS0";
let DAVE_X = "PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk";
let EPH_D = "mo9JJdFRn1d1z0awS1gA1O6e6LrovFVl1JjCjdnJuvV0qUGXRIlzkQBjgqbxJ6sdmsLYwKWYcms";
let EPH_X = "mwj3zDG34-Z9ItWuoSEHSic70rg94Jxj-qc9LCLF2bvINmRyQdlT1AxbEtqIEg1TF3-A5TLEH6A";
let Z_HEX = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

// RFC 8032 §7.4's first Ed448 key, as Go's jwx writes it, and Go's JWS of
// "Example of Ed448 signing" under alg "Ed448" with it.
let ED448_JWK = "{\"crv\":\"Ed448\",\"d\":\"bIKlYsuAjRDWMr6JyFE-v2ySnzTd-oyfY8mWDvbjSKNSjIo_zC8ETjmj_FuUSS-PAy51SaIAmPlb\",\"kty\":\"OKP\",\"x\":\"X9dEm1m0Yf0s54fsYWrUah2hNCSFpw4fig6nXYDpZ3jt8SR2m0bHBhvWeD3x5Q9s0foavq_oJWGA\"}";
let ED448_PUB_HEX = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
let GO_JWS = "eyJhbGciOiJFZDQ0OCJ9.RXhhbXBsZSBvZiBFZDQ0OCBzaWduaW5n.gOQ6lahb0PKu49JlyQo-XrBgDZqr9HLOmW0wKYAoJnGNllHmTn78vn_xQ0YHrTTNcu6qQHcF9iqAwXvXWACuIiABO95BjzHtzpkEhY6_b8HtkCu3ac8yHoIm9uYl19Emy5Og-6z1ODxC4HBpg1DfehUA";

fn hex(b: const u8[:]) -> u8[>..] {
    let digits = "0123456789abcdef";
    var out: u8[>..] = [];
    for c in b { out.push(digits[c >> 4]); out.push(digits[c & 15]); }
    return out;
}

fn b64(s: const u8[:]) -> u8[>..] {
    let b, ok = jwx::b64_decode(s);
    assert(ok);
    return b;
}

fn rfc8037_a7() {
    let dave = jwk::okp_from_private(jwa::CRV_X448, b64(DAVE_D));
    let eph = jwk::okp_from_private(jwa::CRV_X448, b64(EPH_D));
    tv::check_eq("A.7 Dave's public key", jwx::b64_encode(dave.x), DAVE_X);
    tv::check_eq("A.7 ephemeral public key", jwx::b64_encode(eph.x), EPH_X);
    let dave_pub, ep = jwk::parse(str("{\"kty\":\"OKP\",\"crv\":\"X448\",\"kid\":\"Dave\",\"x\":\"", DAVE_X, "\"}"));
    tv::check_int("A.7 Dave's JWK", ep, jwx::OK);
    tv::check("A.7 Dave's JWK is the key", dave_pub.x[..] == dave.x[..] && dave_pub.kid[..] == "Dave");
    tv::check_int("A.7 Dave's private JWK valid", jwk::validate(dave), jwx::OK);
    let z1, ok1 = jwe::agree(dave_pub, eph);
    let eph_pub = jwk::public_key(eph);
    let z2, ok2 = jwe::agree(eph_pub, dave);
    tv::check("A.7 Z, sender", ok1 && hex(z1) == Z_HEX);
    tv::check("A.7 Z, receiver", ok2 && hex(z2) == Z_HEX);

    // The appendix's header: ECDH-ES+A256KW, A256GCM, kid "Dave".
    var h = jwe::Header { .. };
    h.alg = jwa::ECDH_ES_A256KW;
    h.enc = jwa::A256GCM;
    h.kid.append("Dave");
    var o = jwe::Options { .. };
    o.epk = eph;
    o.has_epk = true;
    let token, e = jwe::encrypt_with_options("Hello, Dave", dave_pub, h, "", o);
    tv::check_int("A.7 encrypted", e, jwx::OK);
    var m = jwe::Message { .. };
    tv::check_int("A.7 parsed", jwe::parse(m, token), jwx::OK);
    let hd = m.recipients[0].header;
    tv::check("A.7 epk sent", hd.has_epk && hd.epk.crv == jwa::CRV_X448 && !hd.epk.private
              && jwx::b64_encode(hd.epk.x) == EPH_X && hd.kid[..] == "Dave");
    let pt, ed = jwe::decrypt(token, jwa::ECDH_ES_A256KW, dave);
    tv::check("A.7 decrypted by Dave", ed == jwx::OK && pt == "Hello, Dave");
    let other = jwk::generate_okp(jwa::CRV_X448);
    let x1, e1 = jwe::decrypt(token, jwa::ECDH_ES_A256KW, other);
    tv::check_int("A.7 another X448 key refused", e1, jwx::ERR_DECRYPT);
    let x25519 = jwk::generate_okp(jwa::CRV_X25519);
    let x2, e2 = jwe::decrypt(token, jwa::ECDH_ES_A256KW, x25519);
    tv::check("A.7 an X25519 key refused", e2 != jwx::OK);
    tv::check_eq("A.7 Dave's thumbprint", jwk::thumbprint_b64(dave_pub), "rjT14KFppHOg_L80YOaujYr3L7L0XtD24UHups3cfWo");
}

fn ed448_known() {
    let key, ek = jwk::parse(ED448_JWK);
    tv::check_int("Ed448 JWK", ek, jwx::OK);
    tv::check("Ed448 JWK is RFC 8032's key", key.crv == jwa::CRV_ED448 && key.private && hex(key.x) == ED448_PUB_HEX
              && key.x.len == 57 && key.d.len == 57);
    tv::check_eq("Ed448 JWK written back", jwk::marshal(key), ED448_JWK);
    let pub = jwk::public_key(key);
    tv::check_eq("Ed448 thumbprint input", jwk::thumbprint_input(pub),
                 "{\"crv\":\"Ed448\",\"kty\":\"OKP\",\"x\":\"X9dEm1m0Yf0s54fsYWrUah2hNCSFpw4fig6nXYDpZ3jt8SR2m0bHBhvWeD3x5Q9s0foavq_oJWGA\"}");
    tv::check_eq("Ed448 thumbprint, as Go's", hex(jwk::thumbprint(pub)), "cd0b2d8ac2c50d665bf85895b1997ae3dd004d5831c3feb72fec5895d2b2b946");
    tv::check("thumbprint of the private key the same", jwk::thumbprint(key) == jwk::thumbprint(pub));

    let got, ev = jws::verify(GO_JWS, jwa::ED448, pub);
    tv::check("Go's Ed448 JWS verified", ev == jwx::OK && got == "Example of Ed448 signing");
    let mine, es = jws::sign("Example of Ed448 signing", jwa::ED448, key);
    tv::check_int("Ed448 signed", es, jwx::OK);
    tv::check_eq("the same JWS as Go's (Ed448 is deterministic)", mine, GO_JWS);
    let x1, e1 = jws::verify(GO_JWS, jwa::EDDSA, pub);
    tv::check_int("Go's Ed448 JWS under EdDSA: alg mismatch", e1, jwx::ERR_ALG_MISMATCH);
    let x2, e2 = jws::verify(GO_JWS, jwa::ED25519, pub);
    tv::check_int("Go's Ed448 JWS under Ed25519: alg mismatch", e2, jwx::ERR_ALG_MISMATCH);
    var bad: u8[>..] = [];
    bad.append(GO_JWS);
    bad[bad.len - 3] = if bad[bad.len - 3] == 'A' { 'B' } else { 'A' };
    let x3, e3 = jws::verify(bad, jwa::ED448, pub);
    tv::check_int("changed signature refused", e3, jwx::ERR_BAD_SIGNATURE);
    let short = GO_JWS[..GO_JWS.len - 4];
    let x4, e4 = jws::verify(short, jwa::ED448, pub);
    tv::check("short signature refused", e4 != jwx::OK);
}

// Which EdDSA algorithm signs with which key.
fn alg_confusion() {
    let ed448 = jwk::generate_okp(jwa::CRV_ED448);
    let ed25519 = jwk::generate_okp(jwa::CRV_ED25519);
    let x448 = jwk::generate_okp(jwa::CRV_X448);
    let p448 = jwk::public_key(ed448);
    let p25519 = jwk::public_key(ed25519);
    tv::check("Ed448 fits EdDSA and Ed448", jwk::fits(ed448, jwa::EDDSA) && jwk::fits(ed448, jwa::ED448));
    tv::check("Ed448 does not fit Ed25519", !jwk::fits(ed448, jwa::ED25519));
    tv::check("Ed25519 does not fit Ed448", !jwk::fits(ed25519, jwa::ED448) && jwk::fits(ed25519, jwa::ED25519));
    tv::check("X448 signs nothing", !jwk::fits(x448, jwa::EDDSA) && !jwk::fits(x448, jwa::ED448));
    tv::check("X448 fits ECDH-ES", jwk::fits(x448, jwa::ECDH_ES) && jwk::fits(x448, jwa::ECDH_ES_A256KW));
    tv::check("Ed448 agrees on no key", !jwk::fits(ed448, jwa::ECDH_ES) && !jwk::fits(ed448, jwa::ECDH_ES_A128KW));
    var named = ed448;
    named.alg = jwa::EDDSA;
    tv::check("Ed448 key's own alg holds", !jwk::fits(named, jwa::ED448) && jwk::fits(named, jwa::EDDSA));
    tv::check("jwa names", jwa::lookup("Ed448") == jwa::ED448 && jwa::name(jwa::ED448) == "Ed448"
              && jwa::is_signature(jwa::ED448) && jwa::is_eddsa(jwa::ED448) && jwa::kty_of(jwa::ED448) == jwa::KTY_OKP
              && jwa::crv_lookup("Ed448") == jwa::CRV_ED448 && jwa::crv_lookup("X448") == jwa::CRV_X448
              && jwa::crv_len(jwa::CRV_ED448) == 57 && jwa::crv_len(jwa::CRV_X448) == 56);

    let s1, e1 = jws::sign("p", jwa::ED448, ed25519);
    tv::check_int("Ed25519 key does not sign Ed448", e1, jwx::ERR_KEY);
    let s2, e2 = jws::sign("p", jwa::ED25519, ed448);
    tv::check_int("Ed448 key does not sign Ed25519", e2, jwx::ERR_KEY);
    let s3, e3 = jws::sign("p", jwa::EDDSA, x448);
    tv::check_int("X448 key does not sign EdDSA", e3, jwx::ERR_KEY);
    let s4, e4 = jws::sign("p", jwa::ED448, p448);
    tv::check_int("public key does not sign", e4, jwx::ERR_KEY);

    // "EdDSA" (RFC 8037) with an Ed448 key: 114-byte signatures.
    for alg in [jwa::EDDSA, jwa::ED448] {
        let what = jwa::name(alg);
        let t, e = jws::sign("{\"n\":448}", alg, ed448);
        tv::check_int(str(what, " Ed448 signed"), e, jwx::OK);
        var m = jws::Message { .. };
        tv::check_int(str(what, " parsed"), jws::parse(m, t), jwx::OK);
        tv::check_int(str(what, " signature length"), m.sigs[0].sig.len, 114);
        let p, ev = jws::verify(t, alg, p448);
        tv::check(str(what, " Ed448 verified"), ev == jwx::OK && p == "{\"n\":448}");
        let stranger = jwk::generate_okp(jwa::CRV_ED448);
        let stranger_pub = jwk::public_key(stranger);
        let x, ex = jws::verify(t, alg, stranger_pub);
        tv::check_int(str(what, " another Ed448 key refused"), ex, jwx::ERR_BAD_SIGNATURE);
    }
    // Under "EdDSA" the key decides the curve, so an Ed25519 key meets a
    // 114-byte signature, and an Ed448 key a 64-byte one: both refused.
    let t448, e5 = jws::sign("x", jwa::EDDSA, ed448);
    let t25519, e6 = jws::sign("x", jwa::EDDSA, ed25519);
    let y1, e7 = jws::verify(t448, jwa::EDDSA, p25519);
    tv::check_int("EdDSA Ed448 signature, Ed25519 key", e7, jwx::ERR_BAD_SIGNATURE);
    let y2, e8 = jws::verify(t25519, jwa::EDDSA, p448);
    tv::check_int("EdDSA Ed25519 signature, Ed448 key", e8, jwx::ERR_BAD_SIGNATURE);
    let y3, e9 = jws::verify(t25519, jwa::EDDSA, p25519);
    tv::check_int("EdDSA Ed25519 still verifies", e9, jwx::OK);
    let t2, e10 = jws::sign("x", jwa::ED448, ed448);
    let y4, e11 = jws::verify(t2, jwa::ED448, p25519);
    tv::check_int("Ed448 alg, Ed25519 key", e11, jwx::ERR_KEY);

    // JSON, two signers on two curves; a key set picks by the header.
    var signers: jws::Signer[>..] = [];
    signers.push(jws::Signer { key: ed448, .. });
    signers[0].header.alg = jwa::ED448;
    signers.push(jws::Signer { key: ed25519, .. });
    signers[1].header.alg = jwa::ED25519;
    let j, ej = jws::sign_json("both", signers);
    tv::check_int("JSON signed", ej, jwx::OK);
    let pj1, ej1 = jws::verify(j, jwa::ED448, p448);
    let pj2, ej2 = jws::verify(j, jwa::ED25519, p25519);
    tv::check("JSON verified by each", ej1 == jwx::OK && ej2 == jwx::OK && pj1 == "both" && pj2 == "both");
    var set: jwk::Key[>..] = [];
    set.push(p25519);
    set.push(p448);
    let ps, es = jws::verify_set(t2, set, true);
    tv::check("Ed448 JWS by a key set, inferred", es == jwx::OK && ps == "x");

    // A JWT signed with Ed448.
    var c = jwt::new_claims();
    c.iss.append("goose");
    let tok, et = jwt::sign(c, jwa::ED448, ed448);
    tv::check_int("JWT signed", et, jwx::OK);
    var got = jwt::new_claims();
    let r = jwt::parse(tok, jwa::ED448, p448, got, jwt::Validator { .. });
    tv::check("JWT verified", r == jwx::OK && got.iss[..] == "goose");
}

fn jwk_refusals() {
    let x = "X9dEm1m0Yf0s54fsYWrUah2hNCSFpw4fig6nXYDpZ3jt8SR2m0bHBhvWeD3x5Q9s0foavq_oJWGA";
    for t in [
        // 32-byte x on Ed448, 57-byte x on X448, 56-byte x on Ed448.
        "{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}",
        str("{\"kty\":\"OKP\",\"crv\":\"X448\",\"x\":\"", x, "\"}"),
        str("{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"x\":\"", DAVE_X, "\"}"),
        // d that is not x's, d of the wrong length.
        str("{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"x\":\"", x, "\",\"d\":\"", EPH_D, "A\"}"),
        str("{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"x\":\"", x, "\",\"d\":\"", EPH_D, "\"}"),
        str("{\"kty\":\"OKP\",\"crv\":\"X448\",\"x\":\"", DAVE_X, "\",\"d\":\"", EPH_D, "\"}"),
        // Ed448 as an EC curve.
        str("{\"kty\":\"EC\",\"crv\":\"Ed448\",\"x\":\"", x, "\",\"y\":\"", x, "\"}"),
    ] {
        let k, e = jwk::parse(t);
        tv::check(str("refused ", t), e != jwx::OK);
    }
}

fn x448_ecdh() {
    let key = jwk::generate_okp(jwa::CRV_X448);
    let pub = jwk::public_key(key);
    let encs = [jwa::A128CBC_HS256, jwa::A192CBC_HS384, jwa::A256CBC_HS512, jwa::A128GCM, jwa::A192GCM, jwa::A256GCM];
    var n = 0;
    for alg in [jwa::ECDH_ES, jwa::ECDH_ES_A128KW, jwa::ECDH_ES_A192KW, jwa::ECDH_ES_A256KW] {
        for enc in encs {
            n++;
            let what = str("X448 ", jwa::name(alg), " ", jwa::name(enc));
            let t, e = jwe::encrypt(str("secret ", n), alg, enc, pub, n % 3 == 0);
            tv::check_int(str(what, " encrypted"), e, jwx::OK);
            var m = jwe::Message { .. };
            tv::check_int(str(what, " parsed"), jwe::parse(m, t), jwx::OK);
            let hd = m.recipients[0].header;
            tv::check(str(what, " epk X448"), hd.has_epk && hd.epk.crv == jwa::CRV_X448 && hd.epk.x.len == 56);
            let p, ed = jwe::decrypt(t, alg, key);
            tv::check(str(what, " decrypted"), ed == jwx::OK && p == str("secret ", n));
        }
    }
    // A low-order peer (u = 0, u = 1) gives the all-zero Z: refused.
    for u in ["AA", "AQ"] {
        var zero: u8[>..] = [];
        zero.resize(56, 0);
        if u == "AQ" { zero[0] = 1; }
        let low, el = jwk::parse(str("{\"kty\":\"OKP\",\"crv\":\"X448\",\"x\":\"", jwx::b64_encode(zero), "\"}"));
        tv::check_int(str("low-order key ", u, " parsed"), el, jwx::OK);
        let z, ok = jwe::agree(low, key);
        tv::check(str("low-order key ", u, ": no Z"), !ok);
        let t, e = jwe::encrypt("x", jwa::ECDH_ES, jwa::A128GCM, low);
        tv::check_int(str("encrypting to low-order key ", u, " refused"), e, jwx::ERR_KEY);
    }
    // Curves must match: X25519 epk to an X448 key.
    let x25519 = jwk::generate_okp(jwa::CRV_X25519);
    let z, ok = jwe::agree(pub, x25519);
    tv::check("X448 and X25519 do not agree", !ok);
    // An Ed448 key is no epk.
    let ed_priv = jwk::generate_okp(jwa::CRV_ED448);
    let ed = jwk::public_key(ed_priv);
    var hdr: u8[>..] = [];
    hdr.append("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":");
    hdr.append(jwk::marshal(ed));
    hdr.push('}');
    let forged = str(jwx::b64_encode(hdr), "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA");
    let p, ef = jwe::decrypt(forged, jwa::ECDH_ES, key);
    tv::check_int("Ed448 epk refused", ef, jwx::ERR_KEY);
}

fn main() {
    rfc8037_a7();
    ed448_known();
    alg_confusion();
    jwk_refusals();
    x448_ecdh();
    tv::done("okp448");
}
