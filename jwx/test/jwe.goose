// jwx.jwe against RFC 7520 §5's examples (the JOSE cookbook, test/vectors/
// cookbook/jwe) and RFC 8037's X25519: every output (compact, general and
// flattened JSON) decrypted with each recipient's key; the content
// encryption and the key wrapping remade byte for byte from the example's
// CEK, IV, ephemeral key, GCM IV and PBES2 salt; each message refused with
// a changed byte, the wrong algorithm or the wrong key. Then every key
// management algorithm with every content algorithm round-trips, compact
// and JSON, with and without "zip", to one recipient and to several; and
// the limits (PBES2 count, inflated size) hold.
import std;
import os;
import json;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwe;
import tv;

let DIR = "vectors/cookbook/";

// How many examples had their ciphertext and their encrypted key remade.
var content_remade = 0;
var key_remade = 0;

fn key_of(n: json::Node?) -> jwk::Key {
    guard n else { abort("no key"); }
    let k, e = jwk::from_node(n);
    if e != jwx::OK { abort(str("bad key: ", jwx::error_text(e))); }
    return k;
}

fn text_of(n: json::Node?) -> const u8[:] {
    let s, ok = json::as_string(n);
    if !ok {
        guard n else { abort("not a string: absent"); }
        abort(str("not a string: ", n.key));
    }
    return s;
}

fn json_of(n: json::Node?) -> u8[>..] {
    var t: u8[>..] = [];
    guard n else { abort("no such member"); }
    jws::write_node(t, n);
    return t;
}

fn b64(s: const u8[:]) -> u8[>..] {
    let d, ok = jwx::b64_decode(s);
    if !ok { abort(str("bad base64url ", s)); }
    return d;
}

fn example(file: const u8[:]) {
    var text: u8[>..] = [];
    if !read_file(str(DIR, file), text) { abort(str("cannot read ", file)); }
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { abort(msg); }
    let input = json::member(root, "input");
    let plaintext = text_of(json::member(input, "plaintext"));
    var keys: jwk::Key[>..] = [];
    var algs: i64[>..] = [];
    let kn = json::member(input, "key");
    let pwd, has_pwd = json::as_string(json::member(input, "pwd"));
    if has_pwd {
        keys.push(jwk::from_oct(pwd));
    } else {
        guard kn else { abort("no key"); }
        match kn.val {
            Arr => { json::each(kn) { n => keys.push(key_of(n)); }; },
            _ => { keys.push(key_of(kn)); },
        }
    }
    let an = json::member(input, "alg");
    guard an else { abort("no alg"); }
    match an.val {
        Arr => { json::each(an) { n => algs.push(jwa::lookup(text_of(n))); }; },
        _ => { algs.push(jwa::lookup(text_of(an))); },
    }
    let output = json::member(root, "output");
    var forms: u8[][>..] = [];
    let compact, has_compact = json::as_string(json::member(output, "compact"));
    if has_compact { forms.push(str(compact)); }
    for name in ["json", "json_flat"] {
        let n = json::member(output, name);
        if n { forms.push(json_of(n)); }
    }
    tv::check(str(file, ": has outputs"), forms.len > 0);
    for f in forms {
        for i in keys.len {
            let what = str(file, " ", jwa::name(algs[i]));
            let pt, err = jwe::decrypt(f, algs[i], keys[i]);
            tv::check_int(str(what, " decrypt"), err, jwx::OK);
            tv::check(str(what, " plaintext"), pt == plaintext);
            // Another algorithm is refused before any key is used.
            let other = if algs[i] == jwa::A128KW { jwa::A256KW } else { jwa::A128KW };
            let x, ex = jwe::decrypt(f, other, keys[i]);
            tv::check_int(str(what, " other alg refused"), ex, jwx::ERR_ALG_MISMATCH);
        }
        // Through a set holding every key: each names its kid.
        let ps, es = jwe::decrypt_set(f, keys, true);
        tv::check(str(file, " by set"), es == jwx::OK && ps == plaintext);
    }
    // A changed tag byte, and a changed ciphertext byte.
    if has_compact {
        for which in 2 {
            var t: u8[>..] = [];
            t.append(compact);
            let at = if which == 0 { t.len - 2 } else { find(t[find(t, ".") + 1..], ".") };
            var dots = 0;
            var pos = 0;
            for j in t.len {
                if t[j] == '.' { dots++; if dots == 3 { pos = j + 2; } }
            }
            let p = if which == 0 { t.len - 2 } else { pos };
            t[p] = if t[p] == 'A' { 'B' } else { 'A' };
            let z, ez = jwe::decrypt(t, algs[0], keys[0]);
            tv::check(str(file, " changed byte refused ", which), ez != jwx::OK && z.len == 0);
        }
    }

    // The content encryption remade from the example's CEK and IV.
    let gen = json::member(root, "generated");
    let cek_s, has_cek = json::as_string(json::member(gen, "cek"));
    let iv_s, has_iv = json::as_string(json::member(gen, "iv"));
    let content = json::member(root, "encrypting_content");
    let zip, has_zip = json::as_string(json::member(input, "zip"));
    let jn = json::member(output, "json");
    if has_cek && has_iv && content && jn && !has_zip {
        var m = jwe::Message { .. };
        let jt = json_of(jn);
        tv::check_int(str(file, " parsed"), jwe::parse(m, jt), jwx::OK);
        let enc = m.recipients[0].header.enc;
        let ct, tag, e = jwe::content_encrypt(enc, b64(cek_s), b64(iv_s), jwe::aad_of(m), plaintext);
        tv::check(str(file, " ciphertext remade"), e == jwx::OK
                  && jwx::b64_encode(ct) == text_of(json::member(content, "ciphertext")));
        tv::check(str(file, " tag remade"), jwx::b64_encode(tag) == text_of(json::member(content, "tag")));
        content_remade++;
    }

    // The key wrapping remade, for the algorithms that are deterministic
    // given the example's choices.
    let ekn = json::member(root, "encrypting_key");
    if ekn && has_cek && keys.len == 1 {
        let alg = algs[0];
        let ek_s, has_ek = json::as_string(json::member(ekn, "encrypted_key"));
        var opts = jwe::Options { .. };
        opts.cek.append(b64(cek_s));
        let kiv, has_kiv = json::as_string(json::member(ekn, "iv"));
        if has_kiv { opts.kw_iv.append(b64(kiv)); }
        let salt, has_salt = json::as_string(json::member(ekn, "salt"));
        if has_salt { opts.p2s.append(b64(salt)); }
        let count, has_count = json::as_i64(json::member(ekn, "iteration_count"));
        if has_count { opts.p2c = count; }
        let epk = json::member(ekn, "epk");
        if epk { opts.epk = key_of(epk); opts.has_epk = true; }
        let deterministic = jwa::is_aes_kw(alg) || jwa::is_gcm_kw(alg) || jwa::is_pbes2(alg)
                            || (jwa::is_ecdh(alg) && opts.has_epk);
        if deterministic && has_ek {
            var h = jwe::Header { .. };
            var m = jwe::Message { .. };
            var parsed = false;
            for f in forms {
                if !parsed { tv::check_int(str(file, " parsed for enc"), jwe::parse(m, f), jwx::OK); parsed = true; }
            }
            let enc = m.recipients[0].header.enc;
            let cek, ek, e = jwe::key_encrypt(h, alg, enc, keys[0], opts);
            tv::check(str(file, " encrypted key remade"), e == jwx::OK && jwx::b64_encode(ek) == ek_s);
            key_remade++;
            if has_kiv {
                tv::check_eq(str(file, " GCM key wrap tag"), jwx::b64_encode(h.tag),
                             text_of(json::member(ekn, "tag")));
            }
        }
    }
}

// Every key management algorithm with every content algorithm.
fn round_trips() {
    let plaintext = "The true sign of intelligence is not knowledge but imagination.";
    let rsa = jwk::generate_rsa(2048);
    let encs = [jwa::A128CBC_HS256, jwa::A192CBC_HS384, jwa::A256CBC_HS512, jwa::A128GCM, jwa::A192GCM, jwa::A256GCM];
    let algs = [jwa::RSA1_5, jwa::RSA_OAEP, jwa::RSA_OAEP_256, jwa::RSA_OAEP_384, jwa::RSA_OAEP_512,
                jwa::A128KW, jwa::A192KW, jwa::A256KW, jwa::DIRECT, jwa::ECDH_ES, jwa::ECDH_ES_A128KW,
                jwa::ECDH_ES_A192KW, jwa::ECDH_ES_A256KW, jwa::A128GCMKW, jwa::A192GCMKW, jwa::A256GCMKW,
                jwa::PBES2_HS256_A128KW, jwa::PBES2_HS384_A192KW, jwa::PBES2_HS512_A256KW];
    let curves = [jwa::CRV_P256, jwa::CRV_P384, jwa::CRV_P521, jwa::CRV_X25519];
    // PBES2 at its default counts takes seconds a message; here it runs at
    // the lowest count accepted, and limits() checks the defaults.
    var fast = jwe::Options { .. };
    fast.p2c = jwe::MIN_P2C;
    var n = 0;
    for alg in algs {
        for enc in encs {
            n++;
            let crv = curves[n % 4];
            let key = if jwa::is_rsa_kw(alg) { rsa }
                      else if alg == jwa::DIRECT { jwk::generate_oct(jwa::cek_len(enc)) }
                      else if jwa::is_ecdh(alg) {
                          if crv == jwa::CRV_X25519 { jwk::generate_okp(crv) } else { jwk::generate_ec(crv) }
                      }
                      else if jwa::is_pbes2(alg) { jwk::from_oct("correct horse battery staple") }
                      else { jwk::generate_oct(jwa::kek_len(alg)) };
            let pub = jwk::public_key(key);
            let what = str(jwa::name(alg), "/", jwa::name(enc));
            let zip = n % 3 == 0;
            var token: u8[>..] = [];
            var err = jwx::OK;
            if jwa::is_pbes2(alg) {
                var ch = jwe::Header { .. };
                ch.alg = alg;
                ch.enc = enc;
                ch.zip = zip;
                let t, e = jwe::encrypt_with_options(plaintext, pub, ch, "", fast);
                token.append(t);
                err = e;
            } else {
                let t, e = jwe::encrypt(plaintext, alg, enc, pub, zip);
                token.append(t);
                err = e;
            }
            tv::check_int(str(what, " encrypted"), err, jwx::OK);
            let pt, e2 = jwe::decrypt(token, alg, key);
            tv::check(str(what, " decrypted ", jwx::error_text(e2)), e2 == jwx::OK && pt == plaintext);
            if alg != jwa::DIRECT && !jwa::is_pbes2(alg) {
                let other = if jwa::is_rsa_kw(alg) { jwk::generate_rsa(2048) }
                            else if jwa::is_ecdh(alg) {
                                if crv == jwa::CRV_X25519 { jwk::generate_okp(crv) } else { jwk::generate_ec(crv) }
                            }
                            else { jwk::generate_oct(jwa::kek_len(alg)) };
                let x, ex = jwe::decrypt(token, alg, other);
                tv::check(str(what, " other key refused"), ex == jwx::ERR_DECRYPT && x.len == 0);
            }
            // JSON, flattened, with additional authenticated data.
            var h = jwe::Header { .. };
            h.enc = enc;
            h.zip = zip;
            var rs: jwe::Recipient[>..] = [];
            rs.push(jwe::Recipient { alg: alg, key: pub, .. });
            let j, ej = jwe::encrypt_json_options(plaintext, h, rs, "extra data", true, fast);
            tv::check_int(str(what, " JSON encrypted"), ej, jwx::OK);
            let pj, epj = jwe::decrypt(j, alg, key);
            tv::check(str(what, " JSON decrypted"), epj == jwx::OK && pj == plaintext);
        }
    }

    // Three recipients, each with its own algorithm and kid, decrypted by
    // each key and from a set.
    var keys: jwk::Key[>..] = [];
    keys.push(rsa);
    keys.push(jwk::generate_ec(jwa::CRV_P384));
    keys.push(jwk::generate_oct(32));
    keys[0].kid.append("rsa");
    keys[1].kid.append("ec");
    keys[2].kid.append("oct");
    let malgs = [jwa::RSA_OAEP_256, jwa::ECDH_ES_A256KW, jwa::A256GCMKW];
    var rs: jwe::Recipient[>..] = [];
    for i in 3 {
        rs.push(jwe::Recipient { alg: malgs[i], key: jwk::public_key(keys[i]), .. });
        rs[i].header.kid.append(keys[i].kid);
    }
    var h = jwe::Header { .. };
    h.enc = jwa::A256GCM;
    let j, ej = jwe::encrypt_json(plaintext, h, rs);
    tv::check_int("three recipients encrypted", ej, jwx::OK);
    var m = jwe::Message { .. };
    tv::check_int("three recipients parsed", jwe::parse(m, j), jwx::OK);
    tv::check_int("three recipients", m.recipients.len, 3);
    for i in 3 {
        let pt, e = jwe::decrypt(j, malgs[i], keys[i]);
        tv::check(str("recipient ", i), e == jwx::OK && pt == plaintext);
    }
    let ps, es = jwe::decrypt_set(j, keys, true);
    tv::check("three recipients by set", es == jwx::OK && ps == plaintext);
    // dir cannot have company.
    rs.push(jwe::Recipient { alg: jwa::DIRECT, key: jwk::generate_oct(32), .. });
    let d, ed = jwe::encrypt_json(plaintext, h, rs);
    tv::check_int("dir with other recipients refused", ed, jwx::ERR_MALFORMED);
}

fn limits() {
    let pw = jwk::from_oct("password");
    var h = jwe::Header { .. };
    h.alg = jwa::PBES2_HS256_A128KW;
    h.enc = jwa::A128GCM;
    var o = jwe::Options { .. };
    o.p2c = 2000;
    let t, e = jwe::encrypt_with_options("x", pw, h, "", o);
    tv::check_int("p2c 2000 encrypted", e, jwx::OK);
    let x, ex = jwe::decrypt(t, jwa::PBES2_HS256_A128KW, pw, 1500);
    tv::check_int("p2c over a lowered limit refused", ex, jwx::ERR_LIMIT);
    let y, ey = jwe::decrypt(t, jwa::PBES2_HS256_A128KW, pw);
    tv::check("p2c within the default limit", ey == jwx::OK && y == "x");

    // Below RFC 7518's floor of 1000: refused unless the floor is lowered.
    o.p2c = 999;
    let lo, elo = jwe::encrypt_with_options("x", pw, h, "", o);
    tv::check_int("p2c 999 encrypted", elo, jwx::OK);
    let lx, elx = jwe::decrypt(lo, jwa::PBES2_HS256_A128KW, pw);
    tv::check_int("p2c under the floor refused", elx, jwx::ERR_LIMIT);
    let ly, ely = jwe::decrypt(lo, jwa::PBES2_HS256_A128KW, pw, jwe::MAX_P2C, jwe::MAX_INFLATE, 0);
    tv::check("p2c under a lowered floor", ely == jwx::OK && ly == "x");

    // jwx v4's limits and its OWASP 2023 counts when none is given.
    tv::check_int("max p2c", jwe::MAX_P2C, 1000000);
    tv::check_int("min p2c", jwe::MIN_P2C, 1000);
    tv::check_int("default p2c HS256", jwe::default_p2c(jwa::PBES2_HS256_A128KW), 600000);
    tv::check_int("default p2c HS384", jwe::default_p2c(jwa::PBES2_HS384_A192KW), 210000);
    tv::check_int("default p2c HS512", jwe::default_p2c(jwa::PBES2_HS512_A256KW), 210000);
    // One message at a real default (HS512's, the cheaper one): the count
    // in its header, and it decrypts within the default limit.
    let d, ed = jwe::encrypt("x", jwa::PBES2_HS512_A256KW, jwa::A256GCM, pw);
    tv::check_int("default count encrypted", ed, jwx::OK);
    var dm = jwe::Message { .. };
    tv::check_int("default count parsed", jwe::parse(dm, d), jwx::OK);
    tv::check_int("default count in the header", dm.recipients[0].header.p2c, 210000);
    let dy, edy = jwe::decrypt(d, jwa::PBES2_HS512_A256KW, pw);
    tv::check("default count decrypted", edy == jwx::OK && dy == "x");

    // A zip bomb: 1 MB of zeros inflates past a 64 KB limit.
    var big: u8[>..] = [];
    big.resize(1048576, 0);
    let key = jwk::generate_oct(16);
    let z, ez = jwe::encrypt(big, jwa::A128KW, jwa::A128GCM, key, true);
    tv::check("zipped encrypted small", ez == jwx::OK && z.len < 10000);
    let b, eb = jwe::decrypt(z, jwa::A128KW, key, jwe::MAX_P2C, 65536);
    tv::check_int("inflate limit", eb, jwx::ERR_LIMIT);
    let b2, eb2 = jwe::decrypt(z, jwa::A128KW, key);
    tv::check("inflates within the default limit", eb2 == jwx::OK && b2.len == 1048576);

    // A crit name this package does not understand.
    var hc = jwe::Header { .. };
    hc.alg = jwa::A128KW;
    hc.enc = jwa::A128GCM;
    hc.crit.append("exp");
    hc.crit.push(0);
    let c, ec = jwe::encrypt_with("x", key, hc, "\"exp\":1");
    let cx, ecx = jwe::decrypt(c, jwa::A128KW, key);
    tv::check_int("unknown crit refused", ecx, jwx::ERR_CRIT);
    // A crit name holding a NUL is malformed.
    var hn = jwe::Header { .. };
    hn.alg = jwa::A128KW;
    hn.enc = jwa::A128GCM;
    for extra in ["\"crit\":[\"exp\\u0000\"],\"exp\\u0000\":1", "\"crit\":[\"\\u0000\"],\"\\u0000\":1"] {
        let cn, ecn = jwe::encrypt_with("x", key, hn, extra);
        let pn, epn = jwe::decrypt(cn, jwa::A128KW, key);
        tv::check(str("NUL crit refused ", extra), ecn == jwx::OK && epn == jwx::ERR_MALFORMED && pn.len == 0);
    }

    // ECDH-ES with an ephemeral key off the curve: refused when parsed.
    let rk = jwk::generate_ec(jwa::CRV_P256);
    let rpub = jwk::public_key(rk);
    let good, eg = jwe::encrypt("x", jwa::ECDH_ES, jwa::A128GCM, rpub);
    var m = jwe::Message { .. };
    tv::check_int("ECDH-ES parsed", jwe::parse(m, good), jwx::OK);
    var bad = m.recipients[0].header;
    bad.epk.y[5] = bad.epk.y[5] ^ 1;
    let be = jwe::header_json(bad, "", jwe::PART_ALL);
    let parts = split(good, '.');
    var forged: u8[>..] = [];
    jwx::b64_append(forged, be);
    var i = 0;
    for p in parts {
        if i > 0 { forged.push('.'); forged.append(p); }
        i++;
    }
    let f, ef = jwe::decrypt(forged, jwa::ECDH_ES, rk);
    tv::check_int("invalid curve point refused", ef, jwx::ERR_KEY);
}

// A parameter in two headers with different values is refused; the same
// value twice (as Go's jwx writes "alg") is not.
fn repeated() {
    let key = jwk::generate_oct(16);
    let prot = jwx::b64_encode("{\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}");
    for own in ["{\"alg\":\"A128KW\"}", "{\"alg\":\"A256KW\"}"] {
        let token = str("{\"protected\":\"", prot, "\",\"header\":", own,
                        ",\"encrypted_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"iv\":\"AAAAAAAAAAAAAAAA\",",
                        "\"ciphertext\":\"AAAA\",\"tag\":\"AAAAAAAAAAAAAAAAAAAAAA\"}");
        var m = jwe::Message { .. };
        let e = jwe::parse(m, token);
        if find(own, "A128KW") >= 0 {
            tv::check_int("same alg twice parses", e, jwx::OK);
        } else {
            tv::check_int("different alg twice refused", e, jwx::ERR_MALFORMED);
        }
    }
    // A header name holding a NUL is malformed: in the shared header it
    // would otherwise hide that the recipient's "kid" differs from it.
    for shared in ["{\"k\\u0000\":1,\"kid\":\"a\"}", "{\"\\u0000\":1}", "{\"kid\\u0000\":\"a\"}"] {
        let token = str("{\"protected\":\"", prot, "\",\"unprotected\":", shared, ",\"header\":{\"kid\":\"b\"},",
                        "\"encrypted_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"iv\":\"AAAAAAAAAAAAAAAA\",",
                        "\"ciphertext\":\"AAAA\",\"tag\":\"AAAAAAAAAAAAAAAAAAAAAA\"}");
        var m = jwe::Message { .. };
        tv::check_int(str("NUL header name refused ", shared), jwe::parse(m, token), jwx::ERR_MALFORMED);
    }
}

// The work an attacker's message can ask for: recipients capped, PBES2
// counts charged together, tries in a key set bounded, many header
// members compared sorted rather than pairwise.
fn costs() {
    var shared = jwe::Header { .. };
    shared.enc = jwa::A128GCM;
    var rs: jwe::Recipient[>..] = [];
    for i in jwe::MAX_RECIPIENTS + 1 { rs.push(jwe::Recipient { alg: jwa::A128KW, key: jwk::generate_oct(16), .. }); }
    let t, e = jwe::encrypt_json("x", shared, rs);
    tv::check_int("17 recipients encrypted", e, jwx::OK);
    let x, ex = jwe::decrypt(t, jwa::A128KW, rs[16].key);
    tv::check_int("17 recipients refused", ex, jwx::ERR_LIMIT);
    let y, ey = jwe::decrypt(t, jwa::A128KW, rs[16].key, jwe::MAX_P2C, jwe::MAX_INFLATE, jwe::MIN_P2C, 17);
    tv::check("17 recipients under a raised limit", ey == jwx::OK && y == "x");
    // A key set of two keys without "kid", against 16 recipients naming
    // none: at most 2 + 16 tries, not 32.
    var many: jwe::Recipient[>..] = [];
    for i in 16 { many.push(jwe::Recipient { alg: jwa::A128KW, key: jwk::generate_oct(16), .. }); }
    let tm, em = jwe::encrypt_json("x", shared, many);
    var set: jwk::Key[>..] = [];
    for i in 2 {
        var k = jwk::generate_oct(16);
        k.alg = jwa::A128KW;
        set.push(k);
    }
    let z, ez = jwe::decrypt_set(tm, set);
    tv::check_int("key set tries bounded", ez, jwx::ERR_LIMIT);
    set.push(copy(many[0].key));
    set[2].alg = jwa::A128KW;
    let z2, ez2 = jwe::decrypt_set(tm, set);
    tv::check("key set finds the first recipient's key", ez2 == jwx::OK && z2 == "x");

    // PBES2 counts add up across recipients: the attacker's recipient
    // first, at 2000, then the real one at 2000.
    let attacker = jwk::from_oct("attacker-password");
    let victim = jwk::from_oct("server-password");
    var ps: jwe::Recipient[>..] = [];
    ps.push(jwe::Recipient { alg: jwa::PBES2_HS256_A128KW, key: attacker, .. });
    ps.push(jwe::Recipient { alg: jwa::PBES2_HS256_A128KW, key: victim, .. });
    var o = jwe::Options { .. };
    o.p2c = 2000;
    let pt, ep = jwe::encrypt_json_options("x", shared, ps, "", false, o);
    tv::check_int("two PBES2 recipients encrypted", ep, jwx::OK);
    let p1, ep1 = jwe::decrypt(pt, jwa::PBES2_HS256_A128KW, victim, 3000);
    tv::check("PBES2 counts over the limit together refused", ep1 == jwx::ERR_LIMIT && p1.len == 0);
    let p2, ep2 = jwe::decrypt(pt, jwa::PBES2_HS256_A128KW, victim, 4000);
    tv::check("PBES2 counts within the limit together", ep2 == jwx::OK && p2 == "x");
    var pset: jwk::Key[>..] = [];
    pset.push(copy(victim));
    pset[0].alg = jwa::PBES2_HS256_A128KW;
    let p3, ep3 = jwe::decrypt_set(pt, pset, false, 3000);
    tv::check("key set: PBES2 counts over the limit together refused", ep3 == jwx::ERR_LIMIT && p3.len == 0);
    let p4, ep4 = jwe::decrypt_set(pt, pset, false, 4000);
    tv::check("key set: PBES2 counts within the limit together", ep4 == jwx::OK && p4 == "x");

    // As jws::verify reads a header of 20000 members before any signature
    // (review/jose/dup_dos.goose: 32000 took 20 s pairwise).
    let ek = jwk::generate_ec(jwa::CRV_P256);
    let epub = jwk::public_key(ek);
    for dup in [false, true] {
        var jh: u8[>..] = [];
        jh.append("{\"alg\":\"ES256\"");
        for i in 20000 { format(jh, ",\"m", i, "\":0"); }
        if dup { jh.append(",\"m7\":0"); }
        jh.push('}');
        var jt: u8[>..] = [];
        jwx::b64_append(jt, jh);
        jt.append(".e30.AAAA");
        var jm = jws::Message { .. };
        tv::check_int(str("JWS header of 20000 members, duplicate ", dup), jws::parse(jm, jt),
                      if dup { jwx::ERR_MALFORMED } else { jwx::OK });
        let jp, ej = jws::verify(jt, jwa::ES256, epub);
        tv::check(str("JWS of 20000 members refused, duplicate ", dup), ej != jwx::OK);
    }
    // A header of 20000 members: duplicates found (or not) sorted.
    let prot = jwx::b64_encode("{\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}");
    for dup in [false, true] {
        var hdr: u8[>..] = [];
        hdr.append("{\"kid\":\"a\"");
        for i in 20000 { format(hdr, ",\"m", i, "\":0"); }
        if dup { hdr.append(",\"m7\":0"); }
        hdr.push('}');
        let token = str("{\"protected\":\"", prot, "\",\"header\":", hdr,
                        ",\"encrypted_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"iv\":\"AAAAAAAAAAAAAAAA\",",
                        "\"ciphertext\":\"AAAA\",\"tag\":\"AAAAAAAAAAAAAAAAAAAAAA\"}");
        var m = jwe::Message { .. };
        tv::check_int(str("20000 header members, duplicate ", dup), jwe::parse(m, token),
                      if dup { jwx::ERR_MALFORMED } else { jwx::OK });
    }
}

fn main() {
    repeated();
    costs();
    for f in ["jwe/5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json",
              "jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json",
              "jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json",
              "jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json",
              "jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json",
              "jwe/5_6.direct_encryption_using_aes-gcm.json",
              "jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json",
              "jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json",
              "jwe/5_9.compressed_content.json",
              "jwe/5_10.including_additional_authentication_data.json",
              "jwe/5_11.protecting_specific_header_fields.json",
              "jwe/5_12.protecting_content_only.json",
              "jwe/5_13.encrypting_to_multiple_recipients.json"] {
        example(f);
    }
    print("cookbook: ", content_remade, " ciphertexts and ", key_remade, " encrypted keys remade");
    round_trips();
    limits();
    tv::done("jwe");
}
