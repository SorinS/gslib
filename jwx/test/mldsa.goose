// ML-DSA in JOSE (RFC 9964): Appendix A.1's three keys and messages
// (test/vectors/rfc9964) read, their "kid" remade as the RFC 7638
// thumbprint of alg, kty and pub, each signature remade byte for byte
// (they are deterministic ML-DSA), each JWS verified with the private and
// the public key and refused when changed or asked for under another
// algorithm; AKP keys that are inconsistent or name no ML-DSA refused;
// new keys of each parameter set round-tripped through JSON and signing,
// compact and JSON, and in a JWT; algorithm and key-type confusion both
// ways; AKP keys kept out of JWE.
import std;
import os;
import json;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwe;
import gslib.jwx.jwt;
import gslib.crypto.bignum;
import gslib.crypto.bignum.mldsa;
import tv;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push(tv::unhex(s[i]) << 4 | tv::unhex(s[i + 1]));
        i += 2;
    }
    return out;
}

fn text_of(n: json::Node?) -> const u8[:] {
    let s, ok = json::as_string(n);
    if !ok { abort("no such string member"); }
    return s;
}

// Changes the byte at i of a copy of t.
fn changed(t: const u8[:], i: i64) -> u8[>..] {
    var b: u8[>..] = [];
    b.append(t);
    b[i] = if b[i] == 'A' { 'B' } else { 'A' };
    return b;
}

// One of RFC 9964 Appendix A.1's examples.
fn rfc(set: i64, alg: i64, other: i64) {
    let file = str("vectors/rfc9964/ml-dsa-", set, ".json");
    var text: u8[>..] = [];
    if !read_file(file, text) { abort(str("cannot read ", file)); }
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { abort(msg); }
    let what = str("RFC 9964 ML-DSA-", set);
    let jm = json::member(root, "jwk");
    guard jm else { abort("no jwk"); }
    let key, e = jwk::from_node(jm);
    tv::check_int(str(what, " key"), e, jwx::OK);
    tv::check(str(what, " AKP private key"), key.kty == jwa::KTY_AKP && key.alg == alg && key.private);
    tv::check_eq(str(what, " seed"), key.d, unhex(text_of(json::member(root, "priv"))));
    tv::check_eq(str(what, " pub"), key.pub, unhex(text_of(json::member(root, "raw_public_key"))));
    let kid = text_of(json::member(jm, "kid"));
    tv::check_eq(str(what, " kid is the thumbprint"), jwk::thumbprint_b64(key), kid);
    tv::check_eq(str(what, " kid read"), key.kid, kid);
    // The public key from the seed alone.
    let made = jwk::akp_from_seed(alg, key.d);
    tv::check_eq(str(what, " public key from the seed"), made.pub, key.pub);

    let pub_text = jwk::marshal(key, false);
    tv::check(str(what, " public JWK has no priv"), find(pub_text, "\"priv\"") < 0);
    let pub, ep = jwk::parse(pub_text);
    tv::check(str(what, " public JWK read"), ep == jwx::OK && !pub.private && pub.d.len == 0);
    tv::check_eq(str(what, " public thumbprint"), jwk::thumbprint_b64(pub), kid);
    let half = jwk::public_key(key);
    tv::check_eq(str(what, " public half"), jwk::marshal(half), pub_text);
    let back, eb = jwk::parse(jwk::marshal(key));
    tv::check(str(what, " private JWK round trip"), eb == jwx::OK && jwk::marshal(back) == jwk::marshal(key));

    let token = text_of(json::member(root, "jws"));
    let payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door.";
    let dot = find(token, ".");
    let last = rfind(token, ".");
    tv::check_eq(str(what, " signing input"), token[..last], unhex(text_of(json::member(root, "raw_to_be_signed"))));
    var m = jws::Message { .. };
    tv::check_int(str(what, " parsed"), jws::parse(m, token), jwx::OK);
    tv::check_eq(str(what, " signature"), m.sigs[0].sig, unhex(text_of(json::member(root, "raw_signature"))));
    tv::check(str(what, " header"), m.sigs[0].header.alg == alg && m.sigs[0].header.kid[..] == kid);
    tv::check(str(what, " signed with the empty context"),
              bignum::mldsa_verify(set, key.pub, token[..last], m.sigs[0].sig, ""));

    // Remade: jws::sign writes the RFC's header (alg, then the key's kid),
    // and the RFC's signatures are FIPS 204's deterministic variant.
    let mine, es = jws::sign(payload, alg, key);
    let mine_last = rfind(mine, ".");
    tv::check(str(what, " signing input remade"), es == jwx::OK && mine[..mine_last] == token[..last]);
    tv::check_eq(str(what, " signature remade"), bignum::mldsa_sign_deterministic(set, key.d, mine[..mine_last]),
                 m.sigs[0].sig);
    let mv, emv = jws::verify(mine, alg, pub);
    tv::check(str(what, " hedged signature verified"), emv == jwx::OK && mv == payload);

    let got, ev = jws::verify(token, alg, pub);
    tv::check_int(str(what, " verified"), ev, jwx::OK);
    tv::check_eq(str(what, " payload"), got, payload);
    let got2, ev2 = jws::verify(token, alg, key);
    tv::check_int(str(what, " verified with the private key"), ev2, jwx::OK);
    var set_keys: jwk::Key[>..] = [];
    set_keys.push(pub);
    let got3, ev3 = jws::verify_set(token, set_keys);
    tv::check_int(str(what, " verified by kid and the key's alg"), ev3, jwx::OK);
    let x1, e1 = jws::verify(changed(token, token.len - 2), alg, pub);
    tv::check_int(str(what, " changed signature refused"), e1, jwx::ERR_BAD_SIGNATURE);
    let x2, e2 = jws::verify(changed(token, dot + 3), alg, pub);
    tv::check_int(str(what, " changed payload refused"), e2, jwx::ERR_BAD_SIGNATURE);
    let x3, e3 = jws::verify(token, other, pub);
    tv::check_int(str(what, " under another ML-DSA refused"), e3, jwx::ERR_ALG_MISMATCH);
    let x4, e4 = jws::verify(token, jwa::EDDSA, pub);
    tv::check_int(str(what, " under EdDSA refused"), e4, jwx::ERR_ALG_MISMATCH);
}

// AKP JWKs that are not right.
fn refusals() {
    let k44 = jwk::akp_from_seed(jwa::ML_DSA_44, "0123456789abcdef0123456789abcdef");
    let k65 = jwk::akp_from_seed(jwa::ML_DSA_65, "0123456789abcdef0123456789abcdef");
    let pub44 = jwx::b64_encode(k44.pub);
    let pub65 = jwx::b64_encode(k65.pub);
    let seed = jwx::b64_encode(k44.d);
    let other_seed = jwx::b64_encode("fedcba9876543210fedcba9876543210");
    let good = str("{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"", pub44, "\",\"priv\":\"", seed, "\"}");
    let k, e = jwk::parse(good);
    tv::check_int("AKP key read", e, jwx::OK);
    tv::check_eq("AKP key written in lexical order", jwk::marshal(k),
                 str("{\"alg\":\"ML-DSA-44\",\"kty\":\"AKP\",\"priv\":\"", seed, "\",\"pub\":\"", pub44, "\"}"));

    // Each with the error it gets.
    var cases: u8[][>..] = [];
    // no alg (RFC 9964 §3: required)
    cases.push(str("{\"kty\":\"AKP\",\"pub\":\"", pub44, "\"}"));
    // no pub
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"priv\":\"", seed, "\"}"));
    // pub not a string
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":1}"));
    // an algorithm that is not an AKP one
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"ES256\",\"pub\":\"", pub44, "\"}"));
    // pub the wrong length for alg
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"ML-DSA-65\",\"pub\":\"", pub44, "\"}"));
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"AAAA\"}"));
    // priv not 32 bytes (RFC 9964 §4)
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"", pub44, "\",\"priv\":\"AAAA\"}"));
    // priv of another key (§7.4)
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"", pub44, "\",\"priv\":\"", other_seed, "\"}"));
    // the right seed, another parameter set's key
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"", pub65, "\",\"priv\":\"", seed, "\"}"));
    // an AKP algorithm this package does not do
    cases.push(str("{\"kty\":\"AKP\",\"alg\":\"SLH-DSA-SHA2-128s\",\"pub\":\"", pub44, "\"}"));
    let errs = [jwx::ERR_MALFORMED, jwx::ERR_MALFORMED, jwx::ERR_MALFORMED, jwx::ERR_KEY, jwx::ERR_KEY, jwx::ERR_KEY,
                jwx::ERR_KEY, jwx::ERR_KEY, jwx::ERR_KEY, jwx::ERR_UNSUPPORTED];
    var i = 0;
    var last: u8[>..] = [];
    for c in cases {
        let x, ex = jwk::parse(c);
        tv::check_int(str("AKP refused ", i, ": ", c[..min(c.len, 60)]), ex, errs[i]);
        last.clear();
        last.append(c);
        i++;
    }
    // A set passes over an AKP key of an algorithm it does not know.
    var set: jwk::Key[>..] = [];
    let text = str("{\"keys\":[", last, ",", good, "]}");
    tv::check_int("set with an unknown AKP alg", jwk::parse_set(text, set), jwx::OK);
    tv::check("one key kept", set.len == 1 && set[0].alg == jwa::ML_DSA_44);
}

fn round_trips() {
    let algs = [jwa::ML_DSA_44, jwa::ML_DSA_65, jwa::ML_DSA_87];
    let ed = jwk::generate_okp(jwa::CRV_ED25519);
    for i in algs.len {
        let alg = algs[i];
        let other = algs[(i + 1) % 3];
        let what = jwa::name(alg);
        var key = jwk::generate_akp(alg);
        key.kid.append("pq");
        let set = jwa::mldsa_set(alg);
        tv::check(str(what, " generated"), key.kty == jwa::KTY_AKP && key.alg == alg && key.private
                  && key.d.len == 32 && key.pub.len == bignum::mldsa_pk_len(set));
        tv::check_int(str(what, " valid"), jwk::validate(key), jwx::OK);
        let text = jwk::marshal(key);
        let back, e = jwk::parse(text);
        tv::check(str(what, " JWK round trip"), e == jwx::OK && jwk::marshal(back) == text);
        let pub, ep = jwk::parse(jwk::marshal(key, false));
        tv::check(str(what, " public JWK"), ep == jwx::OK && !pub.private && jwk::thumbprint(pub) == jwk::thumbprint(key));
        tv::check(str(what, " fits its alg only"), jwk::fits(key, alg) && !jwk::fits(key, other)
                  && !jwk::fits(key, jwa::EDDSA) && !jwk::fits(key, jwa::ES256) && !jwk::fits(key, jwa::RS256)
                  && !jwk::fits(key, jwa::HS256) && !jwk::fits(key, jwa::ECDH_ES) && !jwk::fits(key, jwa::RSA_OAEP));
        tv::check(str(what, " no other key fits it"), !jwk::fits(ed, alg));

        // Compact.
        let payload = str("{\"pq\":", set, "}");
        let token, es = jws::sign(payload, alg, key);
        tv::check_int(str(what, " signed"), es, jwx::OK);
        var m = jws::Message { .. };
        tv::check(str(what, " signature length"), jws::parse(m, token) == jwx::OK
                  && m.sigs[0].sig.len == bignum::mldsa_sig_len(set) && m.sigs[0].header.kid[..] == "pq");
        let got, ev = jws::verify(token, alg, pub);
        tv::check(str(what, " verified"), ev == jwx::OK && got == payload);
        let x1, e1 = jws::verify(changed(token, token.len - 3), alg, pub);
        tv::check_int(str(what, " changed refused"), e1, jwx::ERR_BAD_SIGNATURE);
        let x2, e2 = jws::verify(token, other, pub);
        tv::check_int(str(what, " other alg refused"), e2, jwx::ERR_ALG_MISMATCH);
        let x3, e3 = jws::verify(token, alg, ed);
        tv::check_int(str(what, " Ed25519 key refused"), e3, jwx::ERR_KEY);

        // JSON, flattened for one of them, with the key in the header.
        var signers: jws::Signer[>..] = [];
        signers.push(jws::Signer { key: key, .. });
        signers[0].header.alg = alg;
        signers[0].header.has_jwk = true;
        signers[0].header.jwk = pub;
        let j, ej = jws::sign_json(payload, signers, i == 1);
        tv::check_int(str(what, " JSON signed"), ej, jwx::OK);
        tv::check(str(what, " header key is public"), find(j, "priv") < 0);
        var mj = jws::Message { .. };
        tv::check(str(what, " header key read"), jws::parse(mj, j) == jwx::OK && mj.sigs[0].header.has_jwk
                  && jwk::thumbprint(mj.sigs[0].header.jwk) == jwk::thumbprint(key));
        let gotj, evj = jws::verify(j, alg, pub);
        tv::check(str(what, " JSON verified"), evj == jwx::OK && gotj == payload);

        // Keys that do not sign: the public key, another set's key, the
        // ML-DSA key under EdDSA, the Ed25519 key under ML-DSA.
        let t1, s1 = jws::sign(payload, alg, pub);
        tv::check_int(str(what, " public key does not sign"), s1, jwx::ERR_KEY);
        let t2, s2 = jws::sign(payload, other, key);
        tv::check_int(str(what, " key does not sign another ML-DSA"), s2, jwx::ERR_KEY);
        let t3, s3 = jws::sign(payload, jwa::EDDSA, key);
        tv::check_int(str(what, " key does not sign EdDSA"), s3, jwx::ERR_KEY);
        let t4, s4 = jws::sign(payload, alg, ed);
        tv::check_int(str(what, " Ed25519 key does not sign ML-DSA"), s4, jwx::ERR_KEY);
        // A header that says another ML-DSA than the key's: the key refuses it.
        var h = jws::Header { .. };
        h.alg = other;
        let k_other = jwk::generate_akp(other);
        let t5, s5 = jws::sign_with(payload, k_other, h);
        let x5, e5 = jws::verify(t5, other, pub);
        tv::check(str(what, " key under another ML-DSA's header refused"), s5 == jwx::OK && e5 == jwx::ERR_KEY);

        // An unsigned token offered to an ML-DSA key.
        let none, en = jws::sign(payload, jwa::NONE, key);
        let x6, e6 = jws::verify(none, alg, pub);
        tv::check_int(str(what, " none refused"), e6, jwx::ERR_NONE);
    }
}

fn tokens() {
    let key = jwk::generate_akp(jwa::ML_DSA_65);
    let pub = jwk::public_key(key);
    var c = jwt::new_claims();
    c.iss.append("https://issuer.example");
    jwt::add_audience(c, "api");
    jwt::set_expiry(c, 2000000000);
    let t, e = jwt::sign(c, jwa::ML_DSA_65, key);
    tv::check_int("JWT signed with ML-DSA-65", e, jwx::OK);
    var v = jwt::Validator { .. };
    v.now = 1900000000;
    v.issuer.append("https://issuer.example");
    v.audience.append("api");
    var got = jwt::new_claims();
    tv::check_int("JWT verified and valid", jwt::parse(t, jwa::ML_DSA_65, pub, got, v), jwx::OK);
    tv::check_eq("JWT issuer", got.iss, "https://issuer.example");
    var got2 = jwt::new_claims();
    tv::check_int("changed JWT refused", jwt::parse(changed(t, t.len - 4), jwa::ML_DSA_65, pub, got2, v),
                  jwx::ERR_BAD_SIGNATURE);
    var got3 = jwt::new_claims();
    tv::check_int("JWT under ML-DSA-44 refused", jwt::parse(t, jwa::ML_DSA_44, pub, got3, v), jwx::ERR_ALG_MISMATCH);
    // Through a JWKS, by kid and the key's alg.
    var keys: jwk::Key[>..] = [];
    keys.push(jwk::generate_okp(jwa::CRV_ED25519));
    var k2 = pub;
    k2.kid.append("pq-1");
    keys.push(k2);
    var signer = key;
    signer.kid.append("pq-1");
    let t2, e2 = jwt::sign(c, jwa::ML_DSA_65, signer);
    var got4 = jwt::new_claims();
    tv::check_int("JWT verified through a set", jwt::parse_set(t2, keys, got4, v), jwx::OK);
}

// RFC 9964 defines AKP keys for signatures: none is a JWE key, sender's or
// recipient's.
fn not_for_jwe() {
    let key = jwk::generate_akp(jwa::ML_DSA_44);
    let pub = jwk::public_key(key);
    for alg in [jwa::RSA_OAEP, jwa::ECDH_ES, jwa::ECDH_ES_A128KW, jwa::A128KW, jwa::DIRECT] {
        let x, e = jwe::encrypt("secret", alg, jwa::A128GCM, pub);
        tv::check_int(str("JWE ", jwa::name(alg), " to an AKP key refused"), e, jwx::ERR_KEY);
    }
    // An ephemeral key that is an AKP key.
    var h: u8[>..] = [];
    h.append("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":");
    jwk::marshal_to(h, pub, false);
    h.push('}');
    var msg: u8[>..] = [];
    jwx::b64_append(msg, h);
    msg.append("..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA");
    let ec = jwk::generate_ec(jwa::CRV_P256);
    let x, e = jwe::decrypt(msg, jwa::ECDH_ES, ec);
    tv::check_int("JWE with an AKP epk refused", e, jwx::ERR_KEY);
    // A set with an AKP key and the recipient's: the AKP key is passed over.
    let ec_pub = jwk::public_key(ec);
    let t, et = jwe::encrypt("secret", jwa::ECDH_ES, jwa::A128GCM, ec_pub);
    var keys: jwk::Key[>..] = [];
    keys.push(key);
    keys.push(ec);
    let got, ed = jwe::decrypt_set(t, keys, true);
    tv::check("JWE set passes over the AKP key", et == jwx::OK && ed == jwx::OK && got == "secret");
}

fn main() {
    rfc(44, jwa::ML_DSA_44, jwa::ML_DSA_65);
    rfc(65, jwa::ML_DSA_65, jwa::ML_DSA_87);
    rfc(87, jwa::ML_DSA_87, jwa::ML_DSA_44);
    refusals();
    round_trips();
    tokens();
    not_for_jwe();
    tv::done("mldsa");
}
