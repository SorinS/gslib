// jwx.jws against RFC 7520 §4's examples (the JOSE cookbook, test/vectors/
// cookbook/jws), RFC 7797's unencoded payload and RFC 8037's Ed25519: each
// output (compact, general and flattened JSON) verified with the example's
// key, the reproducible signatures (HMAC, RSA PKCS #1 v1.5, Ed25519)
// remade byte for byte, and each message refused with the wrong algorithm,
// the wrong key, or a changed byte. Then every algorithm signs and
// verifies its own messages, compact and JSON, with keys of its own and
// from sets; "none", alg confusion and unknown "crit" names are refused.
import std;
import os;
import json;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import tv;

let DIR = "vectors/cookbook/";

// The key of a JWK object node.
fn key_of(n: json::Node?) -> jwk::Key {
    guard n else { abort("no key"); }
    let k, e = jwk::from_node(n);
    if e != jwx::OK { abort(str("bad key: ", jwx::error_text(e))); }
    return k;
}

// A JSON member written out as text, as a message to verify.
fn json_of(n: json::Node?) -> u8[>..] {
    var t: u8[>..] = [];
    guard n else { abort("no such member"); }
    jws::write_node(t, n);
    return t;
}

fn text_of(n: json::Node?) -> const u8[:] {
    let s, ok = json::as_string(n);
    assert(ok);
    return s;
}

// One cookbook JWS example with a single key and algorithm.
fn example(file: const u8[:]) {
    var text: u8[>..] = [];
    if !read_file(str(DIR, file), text) { abort(str("cannot read ", file)); }
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { abort(msg); }
    let input = json::member(root, "input");
    let payload = text_of(json::member(input, "payload"));
    let alg = jwa::lookup(text_of(json::member(input, "alg")));
    let key = key_of(json::member(input, "key"));
    let pub = jwk::public_key(key);
    let detached = find(file, "detached") >= 0;
    let output = json::member(root, "output");

    // Every form of the output verifies, with the private and the public key.
    var forms: u8[][>..] = [];
    let compact, has_compact = json::as_string(json::member(output, "compact"));
    if has_compact { forms.push(compact); }
    for name in ["json", "json_flat"] {
        let n = json::member(output, name);
        if n {
            var t: u8[>..] = [];
            jws::write_node(t, n);
            forms.push(copy(t));
        }
    }
    tv::check(str(file, ": has outputs"), forms.len > 0);
    for f in forms {
        if detached {
            tv::check_int(str(file, " detached"), jws::verify_detached(f, payload, alg, pub), jwx::OK);
            continue;
        }
        let got, err = jws::verify(f, alg, pub);
        tv::check_int(str(file, " verify"), err, jwx::OK);
        tv::check_eq(str(file, " payload"), got, payload);
        let got2, err2 = jws::verify(f, alg, key);
        tv::check(str(file, " verify with private key"), err2 == jwx::OK && got2 == payload);
        // The wrong algorithm, and the right one with another key.
        let other = if alg == jwa::HS256 { jwa::HS384 } else { jwa::HS256 };
        let x, ex = jws::verify(f, other, pub);
        tv::check_int(str(file, " other alg refused"), ex, jwx::ERR_ALG_MISMATCH);
        let wrong = if key.kty == jwa::KTY_OCT { jwk::generate_oct(32) }
                    else if key.kty == jwa::KTY_RSA { jwk::generate_rsa(2048) }
                    else if key.kty == jwa::KTY_OKP { jwk::generate_okp(jwa::CRV_ED25519) }
                    else { jwk::generate_ec(key.crv) };
        let y, ey = jws::verify(f, alg, wrong);
        tv::check_int(str(file, " other key refused"), ey, jwx::ERR_BAD_SIGNATURE);
    }
    // A changed signature byte.
    if has_compact && !detached {
        var t: u8[>..] = [];
        t.append(compact);
        let last = t.len - 3;
        t[last] = if t[last] == 'A' { 'B' } else { 'A' };
        let z, ez = jws::verify(t, alg, pub);
        tv::check(str(file, " changed signature refused"), ez != jwx::OK && z.len == 0);
    }
    // The reproducible signatures, remade.
    let rep, has_rep = json::as_bool(json::member(root, "reproducible"));
    let signing = json::member(root, "signing");
    if has_rep && rep && signing {
        let input_text = text_of(json::member(signing, "sig-input"));
        let want = text_of(json::member(signing, "sig"));
        let sig, es = jws::sign_bytes(input_text, alg, key);
        tv::check(str(file, " signature remade"), es == jwx::OK && jwx::b64_encode(sig) == want);
    }
}

// RFC 7520 §4.8: three signatures (RS256, ES512, HS256), each verified with
// its own key, by algorithm and through a key set.
fn multiple() {
    let file = "jws/4_8.multiple_signatures.json";
    var text: u8[>..] = [];
    if !read_file(str(DIR, file), text) { abort(str("cannot read ", file)); }
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { abort(msg); }
    let input = json::member(root, "input");
    let payload = text_of(json::member(input, "payload"));
    var keys: jwk::Key[>..] = [];
    let kn = json::member(input, "key");
    guard kn else { abort("no keys"); }
    json::each(kn) { n => keys.push(key_of(n)); };
    var algs: i64[>..] = [];
    let an = json::member(input, "alg");
    guard an else { abort("no algs"); }
    json::each(an) { n => algs.push(jwa::lookup(text_of(n))); };
    let t = json_of(json::member(json::member(root, "output"), "json"));
    for i in keys.len {
        let pub = jwk::public_key(keys[i]);
        let got, err = jws::verify(t, algs[i], pub);
        tv::check(str("4.8 signature ", i), err == jwx::OK && got == payload);
    }
    var m = jws::Message { .. };
    tv::check_int("4.8 parsed", jws::parse(m, t), jwx::OK);
    tv::check_int("4.8 three signatures", m.sigs.len, 3);
    // As a set: RSA and EC keys share a kid, so their alg comes from the
    // header (infer); the HMAC key names its own.
    let got, err = jws::verify_set(t, keys, true);
    tv::check(str("4.8 by set ", jwx::error_text(err)), err == jwx::OK && got == payload);
}

fn rfc7797() {
    // The compact form, and the JSON forms with payloads that hold '.'.
    let file = "rfc7797/hmac-sha2_b64_false.json";
    var text: u8[>..] = [];
    if !read_file(str(DIR, file), text) { abort(str("cannot read ", file)); }
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { abort(msg); }
    let input = json::member(root, "input");
    let payload = text_of(json::member(input, "payload"));
    let key = key_of(json::member(input, "key"));
    let output = json::member(root, "output");
    let compact = text_of(json::member(output, "compact"));
    let got, err = jws::verify(compact, jwa::HS256, key);
    tv::check("RFC 7797 compact", err == jwx::OK && got == payload);
    for name in ["json", "json_flat"] {
        let t = json_of(json::member(output, name));
        let g, e = jws::verify(t, jwa::HS256, key);
        tv::check(str("RFC 7797 ", name), e == jwx::OK && g == payload);
    }
    // Signing it again gives RFC 7797 §4.2's token.
    var h = jws::Header { .. };
    h.alg = jwa::HS256;
    h.b64 = false;
    let mine, em = jws::sign_with(payload, key, h);
    tv::check_eq("RFC 7797 signed", mine, compact);

    // The cookbook's earlier draft of §4.2: b64 false without "crit", which
    // RFC 7797 §6 requires, so refused.
    let file2 = "rfc7797/4.2.hmac-sha2_b64_false.json";
    var text2: u8[>..] = [];
    if !read_file(str(DIR, file2), text2) { abort(str("cannot read ", file2)); }
    var doc2: json::Node[>..] = [];
    var decoded2: u8[>..] = [];
    let root2, msg2 = json::parse(text2, doc2, decoded2);
    guard root2 else { abort(msg2); }
    let t2 = json_of(json::member(json::member(root2, "output"), "json"));
    let g2, e2 = jws::verify(t2, jwa::HS256, key);
    tv::check_int("b64 false without crit refused", e2, jwx::ERR_MALFORMED);
}

// Every algorithm, with fresh keys: compact, JSON general and flattened,
// detached, from a set by kid.
fn round_trips() {
    let payload = "{\"iss\":\"goose\",\"n\":1}";
    let algs = [jwa::HS256, jwa::HS384, jwa::HS512, jwa::RS256, jwa::RS384, jwa::RS512, jwa::PS256, jwa::PS384,
                jwa::PS512, jwa::ES256, jwa::ES384, jwa::ES512, jwa::EDDSA, jwa::ED25519];
    let rsa = jwk::generate_rsa(2048);
    for alg in algs {
        var key = if jwa::is_hmac(alg) { jwk::generate_oct(64) }
                  else if jwa::kty_of(alg) == jwa::KTY_RSA { rsa }
                  else if jwa::is_eddsa(alg) { jwk::generate_okp(jwa::CRV_ED25519) }
                  else { jwk::generate_ec(jwa::curve_of(alg)) };
        key.kid.append(str("key-", jwa::name(alg)));
        let pub = jwk::public_key(key);
        let what = jwa::name(alg);
        let token, err = jws::sign(payload, alg, key);
        tv::check_int(str(what, " signed"), err, jwx::OK);
        let got, e2 = jws::verify(token, alg, pub);
        tv::check(str(what, " verified"), e2 == jwx::OK && got == payload);
        // The kid went into the header.
        var m = jws::Message { .. };
        tv::check_int(str(what, " parsed"), jws::parse(m, token), jwx::OK);
        tv::check_eq(str(what, " kid"), m.sigs[0].header.kid, key.kid);

        var signers: jws::Signer[>..] = [];
        signers.push(jws::Signer { key: key, .. });
        signers[0].header.alg = alg;
        signers[0].header.typ.append("JWT");
        for flat in [false, true] {
            let j, ej = jws::sign_json(payload, signers, flat);
            tv::check_int(str(what, " JSON signed"), ej, jwx::OK);
            let g, ev = jws::verify(j, alg, pub);
            tv::check(str(what, " JSON verified ", flat), ev == jwx::OK && g == payload);
        }
        var h = jws::Header { .. };
        h.alg = alg;
        let det, ed = jws::sign_with(payload, key, h, "", true);
        tv::check(str(what, " detached"), ed == jwx::OK && find(det, "..") > 0);
        tv::check_int(str(what, " detached verified"), jws::verify_detached(det, payload, alg, pub), jwx::OK);
        tv::check_int(str(what, " detached other payload"), jws::verify_detached(det, "x", alg, pub), jwx::ERR_BAD_SIGNATURE);

        var set: jwk::Key[>..] = [];
        set.push(jwk::generate_oct(32));
        set[0].kid.append("decoy");
        set[0].alg = jwa::HS256;
        var named = pub;
        named.alg = alg;
        set.push(named);
        let gs, es = jws::verify_set(token, set);
        tv::check(str(what, " by set"), es == jwx::OK && gs == payload);
    }
}

fn refusals() {
    let key = jwk::generate_oct(32);
    let payload = "hello";
    // "none" is refused unless asked for by name.
    let unsigned, eu = jws::sign(payload, jwa::NONE, key);
    tv::check("none signs", eu == jwx::OK && ends_with(unsigned, "."));
    let x, ex = jws::verify(unsigned, jwa::HS256, key);
    tv::check("none refused", ex != jwx::OK && x.len == 0);
    let y, ey = jws::verify(unsigned, jwa::NONE, key);
    tv::check("none by name", ey == jwx::OK && y == payload);

    // A set key that names "none" does not let an unsigned token in.
    var noneset: jwk::Key[>..] = [];
    noneset.push(jwk::from_oct("anything"));
    noneset[0].alg = jwa::NONE;
    let ns, ens = jws::verify_set(unsigned, noneset);
    tv::check("none through a set refused", ens != jwx::OK && ns.len == 0);

    // Alg confusion: an HS256 token made with an RSA public key's JSON as
    // the secret, verified with that RSA key as RS256.
    let rsa = jwk::generate_rsa(2048);
    let pub = jwk::public_key(rsa);
    let secret = jwk::from_oct(jwk::marshal(pub, false)[..min(512, jwk::marshal(pub, false).len)]);
    let forged, ef = jws::sign(payload, jwa::HS256, secret);
    let z, ez = jws::verify(forged, jwa::RS256, pub);
    tv::check_int("alg confusion refused", ez, jwx::ERR_ALG_MISMATCH);
    // An RSA key cannot be used as an HMAC secret.
    let w, ew = jws::verify(forged, jwa::HS256, pub);
    tv::check_int("RSA key for HS256 refused", ew, jwx::ERR_KEY);

    // A crit name this package does not understand.
    var h = jws::Header { .. };
    h.alg = jwa::HS256;
    h.crit.append("exp");
    h.crit.push(0);
    let t, et = jws::sign_with(payload, key, h, "\"exp\":1");
    let v, ev = jws::verify(t, jwa::HS256, key);
    tv::check_int("unknown crit refused", ev, jwx::ERR_CRIT);
    // crit naming a parameter the header lacks is malformed.
    let t2, et2 = jws::sign_with(payload, key, h);
    let v2, ev2 = jws::verify(t2, jwa::HS256, key);
    tv::check_int("crit without its parameter", ev2, jwx::ERR_MALFORMED);

    // crit names holding a NUL, signed with HMAC and with ECDSA: malformed,
    // never read as "b64" (or nothing) and so understood.
    var keys: jwk::Key[>..] = [];
    keys.push(key);
    keys.push(jwk::generate_ec(jwa::CRV_P256));
    let algs = [jwa::HS256, jwa::ES256];
    for i in 2 {
        let name = jwa::name(algs[i]);
        let pubk = jwk::public_key(keys[i]);
        var hn = jws::Header { .. };
        hn.alg = algs[i];
        let ok_t, eok = jws::sign_with(payload, keys[i], hn, "\"crit\":[\"b64\"],\"b64\":true");
        let ok_p, eokv = jws::verify(ok_t, algs[i], pubk);
        tv::check(str(name, " crit b64 understood"), eok == jwx::OK && eokv == jwx::OK && ok_p == payload);
        for extra in ["\"crit\":[\"b64\\u0000\"],\"b64\\u0000\":true", "\"crit\":[\"\\u0000b64\"],\"\\u0000b64\":true",
                      "\"crit\":[\"b6\\u00004\"],\"b6\\u00004\":true", "\"crit\":[\"\\u0000\"],\"\\u0000\":1",
                      "\"crit\":[\"b64\",\"b64\\u0000\"],\"b64\":true,\"b64\\u0000\":true"] {
            let tn, etn = jws::sign_with(payload, keys[i], hn, extra);
            let pn, en = jws::verify(tn, algs[i], pubk);
            tv::check(str(name, " NUL crit refused ", extra), etn == jwx::OK && en == jwx::ERR_MALFORMED && pn.len == 0);
        }
    }

    // The header {"alg":"HS256","crit":["b64\u0000"],"b64\u0000":true}
    // exactly, refused when parsed too.
    var hr = jws::Header { .. };
    hr.alg = jwa::HS256;
    let tr, etr = jws::sign_with(payload, key, hr, "\"crit\":[\"b64\\u0000\"],\"b64\\u0000\":true");
    let hb, okb = jwx::b64_decode(tr[..find(tr, ".")]);
    tv::check_eq("NUL crit header", hb, "{\"alg\":\"HS256\",\"crit\":[\"b64\\u0000\"],\"b64\\u0000\":true}");
    var mr = jws::Message { .. };
    tv::check_int("NUL crit header parsed", jws::parse(mr, tr), jwx::ERR_MALFORMED);
    let pr, er = jws::verify(tr, jwa::HS256, key);
    tv::check_int("NUL crit header verified", er, jwx::ERR_MALFORMED);

    // A caller's own header parameters, read back.
    var h3 = jws::Header { .. };
    h3.alg = jwa::HS256;
    let t3, et3 = jws::sign_with(payload, key, h3, "\"app\":\"goose\",\"n\":7");
    var m = jws::Message { .. };
    tv::check_int("own params parsed", jws::parse(m, t3), jwx::OK);
    let app, oka = jws::header_string(m, 0, "app");
    let n, okn = jws::header_int(m, 0, "n");
    tv::check("own params read", oka && app == "goose" && okn && n == 7);

    // Malformed tokens.
    for bad in ["", "a.b", "a.b.c.d", "!!.e30.", "e30.e30.", "{\"payload\":\"e30\"}",
                "{\"payload\":\"e30\",\"signatures\":[]}", "{\"payload\":1,\"signature\":\"\"}"] {
        let r, e = jws::verify(bad, jwa::HS256, key);
        tv::check(str("malformed refused ", bad), e != jwx::OK && r.len == 0);
    }
}

// A general JSON JWS of n signatures, each {"alg":"HS256"} over a
// payload of payload_len bytes, and each one byte long, so wrong.
fn many_signatures(n: i64, payload_len: i64) -> u8[>..] {
    var payload: u8[>..] = [];
    payload.resize(payload_len, 'A');
    var t: u8[>..] = [];
    t.append("{\"payload\":\"");
    t.append(jwx::b64_encode(payload));
    t.append("\",\"signatures\":[");
    for i in n {
        if i > 0 { t.push(','); }
        t.append("{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"AA\"}");
    }
    t.append("]}");
    return t;
}

// The work an attacker's message can ask for: signatures capped (each
// would be parsed, and verified over the whole payload), and a signature
// of the wrong length refused before the input is hashed.
fn costs() {
    let key = jwk::generate_oct(32);
    var hk = key;
    hk.alg = jwa::HS256;
    let set: jwk::Key[1] = [hk];
    let nine = many_signatures(jws::MAX_SIGNATURES + 1, 16);
    var m = jws::Message { .. };
    tv::check("9 signatures not parsed", jws::parse(m, nine) == jwx::ERR_LIMIT && m.sigs.len == 0);
    let p9, e9 = jws::verify(nine, jwa::HS256, key);
    tv::check_int("9 signatures refused", e9, jwx::ERR_LIMIT);
    let s9, es9 = jws::verify_set(nine, set);
    tv::check_int("9 signatures refused by set", es9, jwx::ERR_LIMIT);
    let r9, er9 = jws::verify(nine, jwa::HS256, key, 9);
    tv::check_int("9 signatures under a raised limit", er9, jwx::ERR_BAD_SIGNATURE);

    // Exactly the limit verifies, by the last signature; one more does
    // only under a raised limit. Detached likewise.
    var signers: jws::Signer[>..] = [];
    for i in jws::MAX_SIGNATURES + 1 {
        signers.push(jws::Signer { key: jwk::generate_oct(32), .. });
        signers[i].header.alg = jwa::HS256;
    }
    let last = copy(signers[jws::MAX_SIGNATURES - 1].key);
    let t8, e8 = jws::sign_json("x", signers[..jws::MAX_SIGNATURES]);
    let g8, ev8 = jws::verify(t8, jwa::HS256, last);
    tv::check("8 signatures verified by the last", e8 == jwx::OK && ev8 == jwx::OK && g8 == "x");
    let t9, et9 = jws::sign_json("x", signers);
    let g9, ev9 = jws::verify(t9, jwa::HS256, signers[8].key);
    tv::check("9 signers refused", et9 == jwx::OK && ev9 == jwx::ERR_LIMIT && g9.len == 0);
    let g9r, ev9r = jws::verify(t9, jwa::HS256, signers[8].key, 9);
    tv::check("9 signers under a raised limit", ev9r == jwx::OK && g9r == "x");
    let member = "\"payload\":\"eA\",";
    let pat = find(t9, member);
    tv::check("9 signers payload found", pat >= 0);
    var dt9: u8[>..] = [];
    dt9.append(t9[..pat]);
    dt9.append(t9[pat + member.len..]);
    tv::check_int("9 signers detached refused", jws::verify_detached(dt9, "x", jwa::HS256, signers[8].key),
                  jwx::ERR_LIMIT);
    tv::check_int("9 signers detached under a raised limit",
                  jws::verify_detached(dt9, "x", jwa::HS256, signers[8].key, 9), jwx::OK);

    // The reviewer's tokens: 2000 signatures over 400 KB (about 5 s of
    // HMAC natively before the limit), and 20000 small ones (some 300 MB
    // of Signatures). Both are refused, and quickly.
    let t0 = clock_ns();
    let big = many_signatures(2000, 400000);
    let gb, eb = jws::verify(big, jwa::HS256, key);
    tv::check_int("2000 signatures over 400 KB refused", eb, jwx::ERR_LIMIT);
    var small: u8[>..] = [];
    small.append("{\"payload\":\"\",\"signatures\":[");
    for i in 20000 {
        if i > 0 { small.push(','); }
        small.append("{\"header\":{\"alg\":\"HS256\"},\"signature\":\"\"}");
    }
    small.append("]}");
    var ms = jws::Message { .. };
    tv::check("20000 small signatures not parsed", jws::parse(ms, small) == jwx::ERR_LIMIT && ms.sigs.len == 0);
    tv::check("many signatures refused quickly", clock_ns() - t0 < 10000000000);

    // Signatures of the wrong length: refused as bad, without hashing.
    let th, eth = jws::sign("x", jwa::HS256, key);
    var short: u8[>..] = [];
    short.append(th[..rfind(th, ".") + 1]);
    short.append("AA");
    let gh, eh = jws::verify(short, jwa::HS256, key);
    tv::check("HS256 short signature refused", eth == jwx::OK && eh == jwx::ERR_BAD_SIGNATURE);
    let rsa = jwk::generate_rsa(2048);
    let pub = jwk::public_key(rsa);
    for alg in [jwa::RS256, jwa::PS256] {
        let tr, etr = jws::sign("x", alg, rsa);
        let gr, er = jws::verify(tr, alg, pub);
        tv::check(str(jwa::name(alg), " verified"), etr == jwx::OK && er == jwx::OK);
        // 342 base64url characters: 336 are 252 bytes, with no stray bits.
        var cut: u8[>..] = [];
        cut.append(tr[..tr.len - 6]);
        let gc, ec = jws::verify(cut, alg, pub);
        tv::check_int(str(jwa::name(alg), " short signature refused"), ec, jwx::ERR_BAD_SIGNATURE);
        cut.append("AAAAAAAAAAAA");
        let gl, el = jws::verify(cut, alg, pub);
        tv::check_int(str(jwa::name(alg), " long signature refused"), el, jwx::ERR_BAD_SIGNATURE);
    }
}

fn main() {
    for f in ["jws/4_1.rsa_v15_signature.json", "jws/4_2.rsa-pss_signature.json", "jws/4_3.ecdsa_signature.json",
              "jws/4_4.hmac-sha2_integrity_protection.json", "jws/4_5.signature_with_detached_content.json",
              "jws/4_6.protecting_specific_header_fields.json", "jws/4_7.protecting_content_only.json",
              "curve25519/jws.json"] {
        example(f);
    }
    multiple();
    rfc7797();
    round_trips();
    refusals();
    costs();
    tv::done("jws");
}
