// Responses built by a software authenticator (test/tv.goose), good and
// then changed one thing at a time: the challenge, origin, RP ID and type;
// UP missing, UV required and absent; flags that contradict each other or
// the data (BS without BE, AT missing, AT in an assertion, ED with
// nothing after, data after without ED); trailing bytes; CBOR with a
// duplicate key in the attestation object and in the COSE key; credential
// IDs of 1023 bytes (taken) and 1024 (refused), id and rawId that differ;
// attestation certificates with another AAGUID, a critical AAGUID
// extension, the wrong subject, a CA; packed self attestation by another
// algorithm; an ES256 key that says RS256, an alg nobody knows, RS1, an
// alg the RP did not ask for; formats unknown and not allowed; a
// signature changed; userHandle wrong or missing; crossOrigin and
// topOrigin; duplicate members in clientDataJSON; base64 that is not
// base64url; sizes over the limit.
import std;
import os;
import gslib from "../..";
import gslib.webauthn;
import gslib.webauthn.register;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.encoding.asn1;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import tv;

let CHAL = "0123456789abcdef0123456789abcdef";
let AAGUID = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
let CRED = "credential-0001";

fn reg(p: const webauthn::Policy&, json_text: const u8[:], roots: const u8[:], want: i64, what: const u8[:]) {
    var c = webauthn::Credential { .. };
    let e = webauthn::verify_registration(p, CHAL, json_text, roots, c);
    tv::check_code(what, e, want, c.message);
}

// A packed self-attested registration with flags and the rest as given.
fn self_reg(key: const x509::PrivateKey&, alg: i64, flags: u8, cdj: const u8[:], cred: const u8[:], tail: const u8[:]) -> u8[>..] {
    var ad = tv::auth_data(tv::RP, flags, 0, AAGUID, cred, tv::cose_key(key, alg));
    ad.append(tail);
    var signed = copy(ad);
    signed.append(bignum::sha256(cdj));
    let sig = tv::sign(key, alg, signed);
    let ao = tv::att_obj("packed", tv::packed_stmt(alg, sig, []), ad);
    return tv::reg_json(cred, cdj, ao);
}

fn client_data_cases(p: const webauthn::Policy&, key: const x509::PrivateKey&) {
    let good = tv::client_data("webauthn.create", CHAL, tv::ORIGIN);
    reg(p, self_reg(key, cose::ES256, 0x45, good, CRED, ""), "", webauthn::OK, "good packed self");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.get", CHAL, tv::ORIGIN), CRED, ""), "", webauthn::ERR_TYPE, "type webauthn.get");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", "0123456789abcdef0123456789abcdeF", tv::ORIGIN), CRED, ""), "", webauthn::ERR_CHALLENGE, "another challenge");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", "0123456789abcdef", tv::ORIGIN), CRED, ""), "", webauthn::ERR_CHALLENGE, "a shorter challenge");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, "https://example.org.evil.example"), CRED, ""), "", webauthn::ERR_ORIGIN, "another origin");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, "https://example.org/"), CRED, ""), "", webauthn::ERR_ORIGIN, "origin with a slash");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, "http://example.org"), CRED, ""), "", webauthn::ERR_ORIGIN, "origin over http");
    // Members twice: the second challenge would be the attacker's.
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, tv::ORIGIN, ",\"challenge\":\"AAAA\""), CRED, ""), "", webauthn::ERR_MALFORMED, "challenge twice");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, tv::ORIGIN, ",\"origin\":\"https://evil.example\""), CRED, ""), "", webauthn::ERR_MALFORMED, "origin twice");
    // crossOrigin and topOrigin.
    var cross = tv::client_data("webauthn.create", CHAL, tv::ORIGIN);
    let at = find(cross, "false");
    var cross_true: u8[>..] = [];
    cross_true.append(cross[..at]);
    cross_true.append("true");
    cross_true.append(cross[at + 5..]);
    reg(p, self_reg(key, cose::ES256, 0x45, cross_true, CRED, ""), "", webauthn::ERR_CROSS_ORIGIN, "crossOrigin true");
    var pc = p;
    pc.allow_cross_origin = true;
    reg(pc, self_reg(key, cose::ES256, 0x45, cross_true, CRED, ""), "", webauthn::OK, "crossOrigin true, allowed");
    var top = copy(cross_true);
    top.resize(top.len - 1);
    top.append(",\"topOrigin\":\"https://top.example\"}");
    reg(pc, self_reg(key, cose::ES256, 0x45, top, CRED, ""), "", webauthn::ERR_CROSS_ORIGIN, "topOrigin not listed");
    check_ok(webauthn::add_top_origin(pc, "https://top.example"));
    reg(pc, self_reg(key, cose::ES256, 0x45, top, CRED, ""), "", webauthn::OK, "topOrigin listed");
    reg(pc, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, tv::ORIGIN, ",\"topOrigin\":\"https://top.example\""), CRED, ""), "", webauthn::ERR_CROSS_ORIGIN, "topOrigin without crossOrigin");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, tv::ORIGIN, ",\"crossOrigin\":1"), CRED, ""), "", webauthn::ERR_MALFORMED, "crossOrigin twice");
    reg(p, self_reg(key, cose::ES256, 0x45, "{\"type\":\"webauthn.create\"", CRED, ""), "", webauthn::ERR_MALFORMED, "clientDataJSON not JSON");
    reg(p, self_reg(key, cose::ES256, 0x45, "[1]", CRED, ""), "", webauthn::ERR_MALFORMED, "clientDataJSON an array");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, tv::ORIGIN, ",\"x\":\"\xc3\""), CRED, ""), "", webauthn::ERR_MALFORMED, "clientDataJSON not UTF-8");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, tv::ORIGIN, ",\"tokenBinding\":{\"status\":\"not-supported\"}"), CRED, ""), "", webauthn::ERR_MALFORMED, "tokenBinding not-supported");
    reg(p, self_reg(key, cose::ES256, 0x45, tv::client_data("webauthn.create", CHAL, tv::ORIGIN, ",\"tokenBinding\":{\"status\":\"present\",\"id\":\"AA\"}"), CRED, ""), "", webauthn::OK, "tokenBinding present");
    // A challenge in base64url with its unused bits set: another encoding of it.
    var bad_chal = copy(good);
    let ci = find(bad_chal, "\"challenge\":\"") + 13;
    let clen = tv::b64(CHAL).len;
    bad_chal[ci + clen - 1] = if bad_chal[ci + clen - 1] == 'w' { 'x' } else { 'w' };
    reg(p, self_reg(key, cose::ES256, 0x45, bad_chal, CRED, ""), "", webauthn::ERR_CHALLENGE, "challenge with its unused bits set");
}

fn check_ok(ok: bool) { tv::check("set", ok); }

fn auth_data_cases(p: const webauthn::Policy&, key: const x509::PrivateKey&) {
    let good = tv::client_data("webauthn.create", CHAL, tv::ORIGIN);
    reg(p, self_reg(key, cose::ES256, 0x44, good, CRED, ""), "", webauthn::ERR_USER_PRESENCE, "UP missing");
    var puv = p;
    puv.user_verification = webauthn::REQ_REQUIRED;
    reg(puv, self_reg(key, cose::ES256, 0x41, good, CRED, ""), "", webauthn::ERR_USER_VERIFICATION, "UV required, absent");
    reg(puv, self_reg(key, cose::ES256, 0x45, good, CRED, ""), "", webauthn::OK, "UV required, set");
    var pnoup = p;
    pnoup.require_user_presence = false;
    reg(pnoup, self_reg(key, cose::ES256, 0x44, good, CRED, ""), "", webauthn::OK, "UP missing, conditional create");
    reg(p, self_reg(key, cose::ES256, 0x55, good, CRED, ""), "", webauthn::ERR_FLAGS, "BS without BE");
    reg(p, self_reg(key, cose::ES256, 0x5d, good, CRED, ""), "", webauthn::OK, "BE and BS");
    {
        let ad = tv::auth_data(tv::RP, 0x05, 0, "", "", "");
        reg(p, tv::reg_json(CRED, good, tv::att_obj("none", "\xa0", ad)), "", webauthn::ERR_FLAGS, "AT not set");
    }
    reg(p, self_reg(key, cose::ES256, 0x05, good, CRED, ""), "", webauthn::ERR_TRAILING, "AT not set, data there");
    reg(p, self_reg(key, cose::ES256, 0x45, good, CRED, "\x00"), "", webauthn::ERR_TRAILING, "a byte after the key");
    reg(p, self_reg(key, cose::ES256, 0x45, good, CRED, "\xa0"), "", webauthn::ERR_TRAILING, "extensions without ED");
    reg(p, self_reg(key, cose::ES256, 0xc5, good, CRED, "\xa1\x63abc\xf5"), "", webauthn::OK, "ED with extensions");
    reg(p, self_reg(key, cose::ES256, 0xc5, good, CRED, ""), "", webauthn::ERR_MALFORMED, "ED with nothing after");
    reg(p, self_reg(key, cose::ES256, 0xc5, good, CRED, "\x80"), "", webauthn::ERR_MALFORMED, "ED with an array");
    reg(p, self_reg(key, cose::ES256, 0xc5, good, CRED, "\xa1\x63abc\xf5\x00"), "", webauthn::ERR_TRAILING, "a byte after the extensions");
    // Credential IDs at the limit and over it.
    var long_id: u8[>..] = [];
    for i in 1023 { long_id.push((i % 251) as! u8); }
    reg(p, self_reg(key, cose::ES256, 0x45, good, long_id, ""), "", webauthn::OK, "credential ID of 1023 bytes");
    long_id.push(7);
    reg(p, self_reg(key, cose::ES256, 0x45, good, long_id, ""), "", webauthn::ERR_CREDENTIAL_ID, "credential ID of 1024 bytes");
    // The authenticator data's credential ID is not the response's id.
    var ad = tv::auth_data(tv::RP, 0x45, 0, AAGUID, "credential-0002", tv::cose_key(key, cose::ES256));
    var signed = copy(ad);
    signed.append(bignum::sha256(good));
    let ao = tv::att_obj("packed", tv::packed_stmt(cose::ES256, tv::sign(key, cose::ES256, signed), []), ad);
    reg(p, tv::reg_json(CRED, good, ao), "", webauthn::ERR_CREDENTIAL_ID, "authData's credential ID is not the id");
    // Another RP ID's hash.
    var ad2 = tv::auth_data("evil.example", 0x45, 0, AAGUID, CRED, tv::cose_key(key, cose::ES256));
    var signed2 = copy(ad2);
    signed2.append(bignum::sha256(good));
    let ao2 = tv::att_obj("packed", tv::packed_stmt(cose::ES256, tv::sign(key, cose::ES256, signed2), []), ad2);
    reg(p, tv::reg_json(CRED, good, ao2), "", webauthn::ERR_RP_ID, "another RP ID");
    // Shorter than 37 bytes.
    let ao3 = tv::att_obj("none", "\xa0", "\x01\x02\x03");
    reg(p, tv::reg_json(CRED, good, ao3), "", webauthn::ERR_MALFORMED, "authData of 3 bytes");
}

fn cbor_cases(p: const webauthn::Policy&, key: const x509::PrivateKey&) {
    let good = tv::client_data("webauthn.create", CHAL, tv::ORIGIN);
    let ad = tv::auth_data(tv::RP, 0x45, 0, AAGUID, CRED, tv::cose_key(key, cose::ES256));
    // fmt twice: the second one would be "none".
    var ao: u8[>..] = [];
    cbor::put_map(ao, 4);
    cbor::put_text(ao, "fmt"); cbor::put_text(ao, "packed");
    cbor::put_text(ao, "fmt"); cbor::put_text(ao, "none");
    cbor::put_text(ao, "attStmt"); cbor::put_map(ao, 0);
    cbor::put_text(ao, "authData"); cbor::put_bytes(ao, ad);
    reg(p, tv::reg_json(CRED, good, ao), "", webauthn::ERR_MALFORMED, "fmt twice in the attestation object");
    // A COSE key with a label twice.
    let ck = tv::cose_key(key, cose::ES256);
    var dupkey: u8[>..] = [0xa6];
    dupkey.append(ck[1..]);
    dupkey.append("\x03\x26");
    let ad2 = tv::auth_data(tv::RP, 0x45, 0, AAGUID, CRED, dupkey);
    reg(p, tv::reg_json(CRED, good, tv::att_obj("none", "\xa0", ad2)), "", webauthn::ERR_KEY, "alg twice in the COSE key");
    // Indefinite lengths (cbor's defaults refuse them).
    var indef: u8[>..] = [0xbf];
    cbor::put_text(indef, "fmt"); cbor::put_text(indef, "none");
    cbor::put_text(indef, "attStmt"); cbor::put_map(indef, 0);
    cbor::put_text(indef, "authData"); cbor::put_bytes(indef, ad);
    indef.push(0xff);
    reg(p, tv::reg_json(CRED, good, indef), "", webauthn::ERR_MALFORMED, "an indefinite-length map");
    var trailing = tv::att_obj("none", "\xa0", ad);
    trailing.push(0);
    reg(p, tv::reg_json(CRED, good, trailing), "", webauthn::ERR_MALFORMED, "a byte after the attestation object");
    reg(p, tv::reg_json(CRED, good, "\xa1\x63fmt\x64none"), "", webauthn::ERR_MALFORMED, "no attStmt or authData");
}

fn alg_cases(p: const webauthn::Policy&, key: const x509::PrivateKey&, ed: const x509::PrivateKey&) {
    let good = tv::client_data("webauthn.create", CHAL, tv::ORIGIN);
    // An ES256 key that says RS256.
    let ad = tv::auth_data(tv::RP, 0x45, 0, AAGUID, CRED, tv::cose_key(key, cose::RS256));
    reg(p, tv::reg_json(CRED, good, tv::att_obj("none", "\xa0", ad)), "", webauthn::ERR_KEY, "ES256 key says RS256");
    // An alg nobody knows; RS1; one not asked for; none at all.
    let ad2 = tv::auth_data(tv::RP, 0x45, 0, AAGUID, CRED, tv::cose_key(key, -260));
    reg(p, tv::reg_json(CRED, good, tv::att_obj("none", "\xa0", ad2)), "", webauthn::ERR_ALGORITHM, "unknown alg -260");
    let ad3 = tv::auth_data(tv::RP, 0x45, 0, AAGUID, CRED, tv::cose_key(key, cose::RS1));
    reg(p, tv::reg_json(CRED, good, tv::att_obj("none", "\xa0", ad3)), "", webauthn::ERR_ALGORITHM, "RS1 credential");
    var only256 = p;
    only256.algs.clear();
    only256.algs.push(cose::ES256);
    reg(only256, self_reg(ed, cose::EDDSA, 0x45, good, CRED, ""), "", webauthn::ERR_ALGORITHM, "EdDSA not asked for");
    reg(only256, self_reg(key, cose::ES256, 0x45, good, CRED, ""), "", webauthn::OK, "ES256 asked for");
    reg(p, self_reg(ed, cose::EDDSA, 0x45, good, CRED, ""), "", webauthn::OK, "EdDSA");
    reg(p, self_reg(ed, cose::ED25519, 0x45, good, CRED, ""), "", webauthn::OK, "Ed25519 by its RFC 9864 name");
    var nokey = tv::cose_key(key, cose::ES256);
    let k, ek = cose::decode(nokey);
    var k2 = k;
    k2.alg = 0;
    let ad4 = tv::auth_data(tv::RP, 0x45, 0, AAGUID, CRED, cose::encode(k2));
    reg(p, tv::reg_json(CRED, good, tv::att_obj("none", "\xa0", ad4)), "", webauthn::ERR_ALGORITHM, "key without alg");
    // Packed self attestation by another alg than the key's.
    var ad5 = tv::auth_data(tv::RP, 0x45, 0, AAGUID, CRED, tv::cose_key(key, cose::ES256));
    var s5 = copy(ad5);
    s5.append(bignum::sha256(good));
    let ao5 = tv::att_obj("packed", tv::packed_stmt(cose::ES384, tv::sign(key, cose::ES256, s5), []), ad5);
    reg(p, tv::reg_json(CRED, good, ao5), "", webauthn::ERR_ALGORITHM, "packed self by another alg");
    // The signature changed.
    var sig = tv::sign(key, cose::ES256, s5);
    sig[sig.len - 2] ^= 1;
    let ao6 = tv::att_obj("packed", tv::packed_stmt(cose::ES256, sig, []), ad5);
    reg(p, tv::reg_json(CRED, good, ao6), "", webauthn::ERR_ATTESTATION, "packed self signature changed");
    // Formats.
    reg(p, tv::reg_json(CRED, good, tv::att_obj("none", "\xa1\x63sig\x40", ad5)), "", webauthn::ERR_ATTESTATION, "none with a statement");
    reg(p, tv::reg_json(CRED, good, tv::att_obj("android-safetynet", "\xa0", ad5)), "", webauthn::ERR_FORMAT, "a format not handled");
    reg(p, tv::reg_json(CRED, good, tv::att_obj("nonsense", "\xa0", ad5)), "", webauthn::ERR_FORMAT, "an unknown format");
    var nonone = p;
    nonone.formats = webauthn::FORMATS_ALL & ~webauthn::format_bit(webauthn::FMT_NONE);
    reg(nonone, tv::reg_json(CRED, good, tv::att_obj("none", "\xa0", ad5)), "", webauthn::ERR_FORMAT, "none not allowed");
    var req = p;
    req.require_trusted = true;
    reg(req, tv::reg_json(CRED, good, tv::att_obj("none", "\xa0", ad5)), "", webauthn::ERR_TRUST, "none when trust is required");
    reg(req, self_reg(key, cose::ES256, 0x45, good, CRED, ""), "", webauthn::ERR_TRUST, "self when trust is required");
}

fn cert_cases(p: const webauthn::Policy&, key: const x509::PrivateKey&) {
    let good = tv::client_data("webauthn.create", CHAL, tv::ORIGIN);
    let ca_key = x509::generate_key(x509::KEY_EC_P256);
    let ca = tv::ca_cert(ca_key);
    let att_key = x509::generate_key(x509::KEY_EC_P256);
    let subj = "CN=Test Authenticator,OU=Authenticator Attestation,O=Example,C=AA";
    let ad = tv::auth_data(tv::RP, 0x45, 0, AAGUID, CRED, tv::cose_key(key, cose::ES256));
    var signed = copy(ad);
    signed.append(bignum::sha256(good));
    let sig = tv::sign(att_key, cose::ES256, signed);
    let cases: const u8[:][] = ["good", "other aaguid", "critical aaguid", "no aaguid", "wrong OU", "is a CA", "other key", "no CN"];
    for what in cases {
        var extra: u8[>..] = [];
        var s = subj;
        var want = webauthn::OK;
        if what == "good" { extra.append(tv::aaguid_ext(AAGUID)); }
        else if what == "other aaguid" { extra.append(tv::aaguid_ext("\x20\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f")); want = webauthn::ERR_ATTESTATION; }
        else if what == "critical aaguid" { extra.append(tv::aaguid_ext(AAGUID, true)); want = webauthn::ERR_ATTESTATION; }
        else if what == "wrong OU" { s = "CN=Test Authenticator,OU=Authenticator,O=Example,C=AA"; want = webauthn::ERR_ATTESTATION; }
        else if what == "no CN" { s = "OU=Authenticator Attestation,O=Example,C=AA"; want = webauthn::ERR_ATTESTATION; }
        else if what == "is a CA" { want = webauthn::ERR_ATTESTATION; }
        else if what == "other key" { want = webauthn::ERR_ATTESTATION; }
        let leaf = if what == "other key" { tv::att_cert(s, ca_key, ca, ca_key, extra, true) }
                   else { tv::att_cert(s, att_key, ca, ca_key, extra, what == "is a CA") };
        let certs: const u8[:][] = [leaf];
        let ao = tv::att_obj("packed", tv::packed_stmt(cose::ES256, sig, certs), ad);
        var c = webauthn::Credential { .. };
        let e = webauthn::verify_registration(p, CHAL, tv::reg_json(CRED, good, ao), ca, c);
        tv::check_code(str("packed x5c, ", what), e, want, c.message);
        if what == "good" {
            tv::check("packed x5c trusted", c.trusted && c.attestation_type == webauthn::ATT_BASIC && c.x5c[..] == leaf[..]);
            var c2 = webauthn::Credential { .. };
            var p0 = p;
            p0.now = 0;
            tv::check("roots without a time", webauthn::verify_registration(p0, CHAL, tv::reg_json(CRED, good, ao), ca, c2) == webauthn::ERR_ARG);
            // Not trusted by another CA; refused when trust is required.
            let other_key = x509::generate_key(x509::KEY_EC_P256);
            let other_ca = tv::ca_cert(other_key);
            var c3 = webauthn::Credential { .. };
            tv::check("another CA", webauthn::verify_registration(p, CHAL, tv::reg_json(CRED, good, ao), other_ca, c3) == webauthn::OK && !c3.trusted);
            var req = p;
            req.require_trusted = true;
            tv::check("another CA, trust required", webauthn::verify_registration(req, CHAL, tv::reg_json(CRED, good, ao), other_ca, c3) == webauthn::ERR_TRUST);
            // fido-u2f with this certificate: its own data.
            var u2f: u8[>..] = [0];
            u2f.append(bignum::sha256(tv::RP));
            u2f.append(bignum::sha256(good));
            u2f.append(CRED);
            let ck, eck = cose::decode(tv::cose_key(key, cose::ES256));
            u2f.push(4);
            u2f.append(ck.x);
            u2f.append(ck.y);
            let usig = tv::sign(att_key, cose::ES256, u2f);
            var st: u8[>..] = [];
            cbor::put_map(st, 2);
            cbor::put_text(st, "sig"); cbor::put_bytes(st, usig);
            cbor::put_text(st, "x5c"); cbor::put_array(st, 1); cbor::put_bytes(st, leaf);
            let e2 = cbor::sort_map(st, 0, true);
            let ad0 = tv::auth_data(tv::RP, 0x41, 0, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", CRED, tv::cose_key(key, cose::ES256));
            var c4 = webauthn::Credential { .. };
            tv::check_code("fido-u2f", webauthn::verify_registration(p, CHAL, tv::reg_json(CRED, good, tv::att_obj("fido-u2f", st, ad0)), ca, c4), webauthn::OK, c4.message);
            tv::check("fido-u2f trusted", c4.trusted);
            // Two certificates in a fido-u2f x5c.
            var st2: u8[>..] = [];
            cbor::put_map(st2, 2);
            cbor::put_text(st2, "sig"); cbor::put_bytes(st2, usig);
            cbor::put_text(st2, "x5c"); cbor::put_array(st2, 2); cbor::put_bytes(st2, leaf); cbor::put_bytes(st2, ca);
            let e3 = cbor::sort_map(st2, 0, true);
            tv::check_code("fido-u2f, two certificates", webauthn::verify_registration(p, CHAL, tv::reg_json(CRED, good, tv::att_obj("fido-u2f", st2, ad0)), ca, c4), webauthn::ERR_ATTESTATION, c4.message);
            // fido-u2f over another credential ID.
            tv::check_code("fido-u2f, another ID", webauthn::verify_registration(p, CHAL, tv::reg_json("credential-0003", good, tv::att_obj("fido-u2f", st, tv::auth_data(tv::RP, 0x41, 0, AAGUID, "credential-0003", tv::cose_key(key, cose::ES256)))), ca, c4), webauthn::ERR_ATTESTATION, c4.message);
            // x5c that is not a certificate.
            let junk: const u8[:][] = ["\x30\x03\x02\x01\x01"];
            tv::check_code("x5c junk", webauthn::verify_registration(p, CHAL, tv::reg_json(CRED, good, tv::att_obj("packed", tv::packed_stmt(cose::ES256, sig, junk), ad)), ca, c4), webauthn::ERR_ATTESTATION, c4.message);
        }
    }
}

fn response_cases(p: const webauthn::Policy&, key: const x509::PrivateKey&) {
    let good = tv::client_data("webauthn.create", CHAL, tv::ORIGIN);
    let j = self_reg(key, cose::ES256, 0x45, good, CRED, "");
    // id and rawId differ.
    var j2 = copy(j);
    let at = find(j2, "\"rawId\":\"") + 9;
    j2[at] = if j2[at] == 'A' { 'B' } else { 'A' };
    reg(p, j2, "", webauthn::ERR_CREDENTIAL_ID, "rawId not id");
    // type not public-key.
    var j3: u8[>..] = [];
    format_replaced(j3, j, "\"public-key\"", "\"password\"");
    reg(p, j3, "", webauthn::ERR_TYPE, "type password");
    // A member twice in the response.
    var j4 = copy(j);
    j4.resize(j4.len - 1);
    j4.append(",\"type\":\"public-key\"}");
    reg(p, j4, "", webauthn::ERR_MALFORMED, "type twice");
    // Standard base64 (padding): refused unless lenient.
    var j5: u8[>..] = [];
    let ci = find(j, "\"clientDataJSON\":\"") + 18;
    let ce = ci + find(j[ci..], "\"");
    j5.append(j[..ce]);
    j5.append("==");
    j5.append(j[ce..]);
    let padded = tv::b64(good).len % 4 != 0;
    if padded {
        reg(p, j5, "", webauthn::ERR_MALFORMED, "padded base64");
        var pl = p;
        pl.lenient_base64 = true;
        var j6: u8[>..] = [];
        j6.append(j[..ce]);
        j6.append(if (tv::b64(good).len % 4) == 2 { "==" } else { "=" });
        j6.append(j[ce..]);
        reg(pl, j6, "", webauthn::OK, "padded base64, lenient");
    }
    // Size.
    var small = p;
    small.max_response = 100;
    reg(small, j, "", webauthn::ERR_LIMIT, "response over the size limit");
    // Not JSON; not UTF-8.
    reg(p, "{\"id\":", "", webauthn::ERR_MALFORMED, "not JSON");
    reg(p, "{\"id\":\"\xff\"}", "", webauthn::ERR_MALFORMED, "not UTF-8");
    // An empty challenge or no origins is the caller's mistake.
    var c = webauthn::Credential { .. };
    tv::check("empty challenge", webauthn::verify_registration(p, "", j, "", c) == webauthn::ERR_ARG);
    var none = p;
    none.origins.clear();
    tv::check("no origins", webauthn::verify_registration(none, CHAL, j, "", c) == webauthn::ERR_ARG);
    tv::check("origin with a newline", !webauthn::add_origin(none, "https://a.example\nhttps://b.example"));
    var full = p;
    var n = 0;
    while webauthn::add_origin(full, "https://a-rather-long-origin-name-for-filling.example") { n++; }
    tv::check("origins fill up, then refuse", n > 10 && full.origins.len <= full.origins.cap);
}

fn assertion_cases(p: const webauthn::Policy&, key: const x509::PrivateKey&) {
    // Register, then sign in with the credential, changing things.
    let cdj = tv::client_data("webauthn.create", CHAL, tv::ORIGIN);
    var c = webauthn::Credential { .. };
    let e = webauthn::verify_registration(p, CHAL, self_reg(key, cose::ES256, 0x45, cdj, CRED, ""), "", c);
    tv::check_code("register for assertions", e, webauthn::OK, c.message);
    tv::check("record fields", c.attestation_type == webauthn::ATT_SELF && c.rk == 1
              && c.transports == (webauthn::TRANSPORT_USB | webauthn::TRANSPORT_HYBRID) && c.attachment == webauthn::ATTACH_CROSS_PLATFORM);
    let user = "user-handle-0001";
    fn assertion(k: const x509::PrivateKey&, alg: i64, flags: u8, count: i64, cd: const u8[:], id: const u8[:], uh: const u8[:], tail: const u8[:]) -> u8[>..] {
        var ad = tv::auth_data(tv::RP, flags, count, "", "", "");
        ad.append(tail);
        var signed = copy(ad);
        signed.append(bignum::sha256(cd));
        return tv::auth_json(id, cd, ad, tv::sign(k, alg, signed), uh);
    }
    fn auth(pp: const webauthn::Policy&, j: const u8[:], cr: const webauthn::Credential&, uh: const u8[:], req: bool, want: i64, what: const u8[:]) {
        var a = webauthn::Assertion { .. };
        let r = webauthn::verify_authentication(pp, CHAL, j, cr, uh, req, a);
        tv::check_code(what, r, want, a.message);
    }
    let get = tv::client_data("webauthn.get", CHAL, tv::ORIGIN);
    auth(p, assertion(key, cose::ES256, 0x05, 1, get, CRED, user, ""), c, user, true, webauthn::OK, "assertion");
    auth(p, assertion(key, cose::ES256, 0x05, 1, get, CRED, "", ""), c, user, false, webauthn::OK, "assertion without userHandle, not required");
    auth(p, assertion(key, cose::ES256, 0x05, 1, get, CRED, "", ""), c, user, true, webauthn::ERR_USER_HANDLE, "passkey without userHandle");
    auth(p, assertion(key, cose::ES256, 0x05, 1, get, CRED, "user-handle-0002", ""), c, user, true, webauthn::ERR_USER_HANDLE, "another userHandle");
    auth(p, assertion(key, cose::ES256, 0x05, 1, get, "credential-0009", user, ""), c, user, true, webauthn::ERR_UNKNOWN_CREDENTIAL, "another credential");
    auth(p, assertion(key, cose::ES256, 0x05, 1, tv::client_data("webauthn.create", CHAL, tv::ORIGIN), CRED, user, ""), c, user, true, webauthn::ERR_TYPE, "assertion of type create");
    auth(p, assertion(key, cose::ES256, 0x04, 1, get, CRED, user, ""), c, user, true, webauthn::ERR_USER_PRESENCE, "assertion without UP");
    auth(p, assertion(key, cose::ES256, 0x45, 1, get, CRED, user, ""), c, user, true, webauthn::ERR_MALFORMED, "AT without data");
    auth(p, assertion(key, cose::ES256, 0x05, 1, get, CRED, user, "\x00"), c, user, true, webauthn::ERR_TRAILING, "assertion with a byte after");
    auth(p, assertion(key, cose::ES256, 0x85, 1, get, CRED, user, "\xa0"), c, user, true, webauthn::OK, "assertion with ED and {}");
    auth(p, assertion(key, cose::ES256, 0x0d, 1, get, CRED, user, ""), c, user, true, webauthn::ERR_BACKUP, "BE now set");
    auth(p, assertion(key, cose::ES256, 0x15, 1, get, CRED, user, ""), c, user, true, webauthn::ERR_FLAGS, "BS without BE");
    let other = x509::generate_key(x509::KEY_EC_P256);
    auth(p, assertion(other, cose::ES256, 0x05, 1, get, CRED, user, ""), c, user, true, webauthn::ERR_SIGNATURE, "signed by another key");
    var c2 = copy(c);
    c2.alg = cose::RS256;
    auth(p, assertion(key, cose::ES256, 0x05, 1, get, CRED, user, ""), c2, user, true, webauthn::ERR_ALGORITHM, "record says RS256 for an ES256 key");
    var c3 = copy(c);
    c3.sign_count = 5;
    var a = webauthn::Assertion { .. };
    let r = webauthn::verify_authentication(p, CHAL, assertion(key, cose::ES256, 0x05, 5, get, CRED, user, ""), c3, user, true, a);
    tv::check(str("equal counter: regressed, reported: ", webauthn::error_text(r), " ", a.message), r == webauthn::OK && a.counter_regressed && a.sign_count == 5);
    let r2 = webauthn::verify_authentication(p, CHAL, assertion(key, cose::ES256, 0x05, 6, get, CRED, user, ""), c3, user, true, a);
    tv::check("counter forward", r2 == webauthn::OK && !a.counter_regressed && a.sign_count == 6);
    var c4 = copy(c);
    c4.sign_count = 0;
    let r3 = webauthn::verify_authentication(p, CHAL, assertion(key, cose::ES256, 0x05, 0, get, CRED, user, ""), c4, user, true, a);
    tv::check("counters both 0: not regressed (passkeys)", r3 == webauthn::OK && !a.counter_regressed);
    // UV required.
    var puv = p;
    puv.user_verification = webauthn::REQ_REQUIRED;
    auth(puv, assertion(key, cose::ES256, 0x01, 1, get, CRED, user, ""), c, user, true, webauthn::ERR_USER_VERIFICATION, "UV required, absent");
    // Backup state: BE stays, BS may change and is reported.
    var cb = copy(c);
    cb.backup_eligible = true;
    let r4 = webauthn::verify_authentication(p, CHAL, assertion(key, cose::ES256, 0x1d, 1, get, CRED, user, ""), cb, user, true, a);
    tv::check("BS changed, reported", r4 == webauthn::OK && a.backed_up && a.backup_changed);
}

fn main() {
    var p = tv::policy(tv::RP, tv::ORIGIN);
    let key = x509::generate_key(x509::KEY_EC_P256);
    let ed = x509::generate_key(x509::KEY_ED25519);
    client_data_cases(p, key);
    auth_data_cases(p, key);
    cbor_cases(p, key);
    alg_cases(p, key, ed);
    cert_cases(p, key);
    response_cases(p, key);
    assertion_cases(p, key);
    tv::done("hostile");
}
