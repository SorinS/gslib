// Published vectors: every registration and authentication of the
// WebAuthn L3 specification's §16 (none, self, crossOrigin, topOrigin, a
// long credential ID; packed with ES256, ES384, ES512, RS256, Ed25519 and
// Ed448 keys; TPM, Android Key, Apple and FIDO U2F attestation), their
// attestation chains checked against the spec's root (§16.1), and each
// authentication checked with the record its registration made; and
// py_webauthn's vectors from real authenticators (packed from YubiKeys,
// fido-u2f, tpm from a Surface Pro 4, a Dell XPS 13, a Lenovo X1 and an
// ECC TPM, android-key under Google's roots, apple under Apple's, none
// over caBLE), with the outcome py_webauthn's own tests expect.
import std;
import os;
import gslib from "../..";
import gslib.webauthn;
import gslib.webauthn.register;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import tv;

// The records the spec's registrations made, by credential ID, for the
// authentications that follow them.
var records: u8[][>..] = [];

fn registration(v: tv::Vector&, py: bool) {
    var p = tv::policy(v.rp_id, "x");
    p.origins.clear();
    for o in split(v.origins, '\n') { if o.len > 0 { check_add(webauthn::add_origin(p, o)); } }
    if v.top_origin.len > 0 { check_add(webauthn::add_top_origin(p, v.top_origin)); }
    p.allow_cross_origin = v.cross_origin;
    if v.require_uv { p.user_verification = webauthn::REQ_REQUIRED; }
    p.now = v.now;
    // py_webauthn's TPM vectors are from 2019: standard base64 and RS1.
    p.lenient_base64 = py;
    p.allow_rs1 = py;
    // The spec's TPM vector names the manufacturer id:00000000, which TCG
    // has not registered: refused unless the policy takes any.
    if !py && v.fmt[..] == "tpm" {
        var c0 = webauthn::Credential { .. };
        let e0 = webauthn::verify_registration(p, v.challenge, v.response, "", c0);
        tv::check_code(str(v.name, ": unregistered TPM vendor"), e0, webauthn::ERR_ATTESTATION, c0.message);
        p.tpm_any_vendor = true;
    }
    var roots: u8[>..] = [];
    if v.roots.len > 0 { roots.append(tv::roots_of(str("data/", v.roots))); }
    var c = webauthn::Credential { .. };
    let e = webauthn::verify_registration(p, v.challenge, v.response, roots, c);
    if v.expect[..] == "ok" {
        tv::check_code(v.name, e, webauthn::OK, c.message);
        if e != webauthn::OK { return; }
        tv::check(str(v.name, ": fmt"), webauthn::format_name(c.fmt) == v.fmt);
        tv::check(str(v.name, ": credential ID"), c.id[..] == v.cred_id[..]);
        if v.aaguid.len > 0 { tv::check(str(v.name, ": AAGUID"), c.aaguid[..] == v.aaguid[..]); }
        tv::check(str(v.name, ": trusted iff roots given and x5c (", c.message, ")"),
                  c.trusted == (roots.len > 0 && c.x5c.len > 0));
        let k, ek = cose::decode(c.public_key);
        tv::check(str(v.name, ": stored key"), ek == cose::OK && k.alg == c.alg);
        // The record survives its own bytes.
        let b = webauthn::marshal_credential(c);
        var c2 = webauthn::Credential { .. };
        let ep = webauthn::parse_credential(b, c2);
        tv::check(str(v.name, ": record round trip"), ep == webauthn::OK && webauthn::marshal_credential(c2)[..] == b[..]);
        records.push(copy(b));
        // With the policy strict, the py_webauthn TPM vectors fail.
        if py && v.fmt[..] == "tpm" {
            var strict = p;
            strict.lenient_base64 = false;
            strict.allow_rs1 = false;
            var c3 = webauthn::Credential { .. };
            let e3 = webauthn::verify_registration(strict, v.challenge, v.response, roots, c3);
            tv::check(str(v.name, ": refused when strict (", webauthn::error_text(e3), ")"), e3 != webauthn::OK);
        }
        // Wrong roots: still verified, not trusted; refused when trust is required.
        if roots.len > 0 {
            let other = tv::roots_of(if v.roots[..] == "spec_ca.pem" { "data/apple_root.pem" } else { "data/spec_ca.pem" });
            var c4 = webauthn::Credential { .. };
            let e4 = webauthn::verify_registration(p, v.challenge, v.response, other, c4);
            tv::check(str(v.name, ": other roots, not trusted"), e4 == webauthn::OK && !c4.trusted);
            var req = p;
            req.require_trusted = true;
            var c5 = webauthn::Credential { .. };
            let e5 = webauthn::verify_registration(req, v.challenge, v.response, other, c5);
            tv::check_code(str(v.name, ": other roots, trust required"), e5, webauthn::ERR_TRUST, c5.message);
            var c6 = webauthn::Credential { .. };
            let e6 = webauthn::verify_registration(req, v.challenge, v.response, roots, c6);
            tv::check_code(str(v.name, ": its roots, trust required"), e6, if c.x5c.len > 0 { webauthn::OK } else { webauthn::ERR_TRUST }, c6.message);
            // Before the chain's certificates were valid.
            var early = p;
            early.now = 946684800;
            var c7 = webauthn::Credential { .. };
            let e7 = webauthn::verify_registration(early, v.challenge, v.response, roots, c7);
            tv::check(str(v.name, ": in 2000, not trusted"), e7 == webauthn::OK && !c7.trusted);
        }
    } else {
        tv::check(str(v.name, ": refused (", c.message, ")"), e != webauthn::OK);
    }
}

fn check_add(ok: bool) { tv::check("add origin", ok); }

fn authentication(v: tv::Vector&, py: bool) {
    var p = tv::policy(v.rp_id, "x");
    p.origins.clear();
    for o in split(v.origins, '\n') { if o.len > 0 { check_add(webauthn::add_origin(p, o)); } }
    if v.top_origin.len > 0 { check_add(webauthn::add_top_origin(p, v.top_origin)); }
    p.allow_cross_origin = v.cross_origin;
    if v.require_uv { p.user_verification = webauthn::REQ_REQUIRED; }
    var id: u8[>..] = [];
    var uh: u8[>..] = [];
    let er = webauthn::response_ids(v.response, id, uh);
    tv::check(str(v.name, ": ids"), er == webauthn::OK);
    var c = webauthn::Credential { .. };
    c.id.append(id);
    c.public_key.append(v.public_key);
    let k, ek = cose::decode(v.public_key);
    tv::check(str(v.name, ": key"), ek == cose::OK);
    c.alg = k.alg;
    c.sign_count = v.sign_count;
    // A spec record from its registration: the same key.
    if !py {
        var found = false;
        for b in records {
            var r = webauthn::Credential { .. };
            if webauthn::parse_credential(b, r) == webauthn::OK && r.id[..] == id[..] {
                found = true;
                tv::check(str(v.name, ": the registration's key"), r.public_key[..] == v.public_key[..]);
                c.backup_eligible = r.backup_eligible;
                c.backed_up = r.backed_up;
            }
        }
        tv::check(str(v.name, ": registered"), found);
    } else {
        // py_webauthn keeps no BE: take the response's.
        var rr = webauthn::Response { .. };
        var m: u8[..256] = [];
        let e0 = webauthn::parse_response(rr, v.response, false, true, 1 << 20, m);
        if rr.authenticator_data.len > 32 { c.backup_eligible = rr.authenticator_data[32] & webauthn::FLAG_BE != 0; }
    }
    var a = webauthn::Assertion { .. };
    let e = webauthn::verify_authentication(p, v.challenge, v.response, c, uh, false, a);
    if v.expect[..] == "ok" {
        tv::check_code(v.name, e, webauthn::OK, a.message);
        if v.new_sign_count >= 0 { tv::check(str(v.name, ": sign count"), a.sign_count == v.new_sign_count); }
        tv::check(str(v.name, ": credential"), a.credential_id[..] == id[..] && a.user_handle[..] == uh[..]);
        if e != webauthn::OK { return; }
        // The same response with another challenge, origin or RP ID.
        var other: u8[>..] = copy(v.challenge);
        other[0] ^= 1;
        var a2 = webauthn::Assertion { .. };
        tv::check(str(v.name, ": another challenge"), webauthn::verify_authentication(p, other, v.response, c, uh, false, a2) == webauthn::ERR_CHALLENGE);
        var p2 = p;
        p2.origins.clear();
        check_add(webauthn::add_origin(p2, "https://evil.example"));
        tv::check(str(v.name, ": another origin"), webauthn::verify_authentication(p2, v.challenge, v.response, c, uh, false, a2) == webauthn::ERR_ORIGIN);
        var p3 = p;
        let okr = webauthn::set_rp(p3, "evil.example");
        tv::check(str(v.name, ": another RP ID"), webauthn::verify_authentication(p3, v.challenge, v.response, c, uh, false, a2) == webauthn::ERR_RP_ID);
        // The counter: a record that has seen more refuses when asked.
        var c2 = copy(c);
        c2.sign_count = a.sign_count + 1;
        var a3 = webauthn::Assertion { .. };
        let e3 = webauthn::verify_authentication(p, v.challenge, v.response, c2, uh, false, a3);
        tv::check(str(v.name, ": counter regressed, reported"), e3 == webauthn::OK && a3.counter_regressed);
        var p4 = p;
        p4.refuse_sign_count = true;
        tv::check(str(v.name, ": counter regressed, refused"), webauthn::verify_authentication(p4, v.challenge, v.response, c2, uh, false, a3) == webauthn::ERR_SIGN_COUNT);
        // BE not what the record says.
        var c5 = copy(c);
        c5.backup_eligible = !c.backup_eligible;
        tv::check(str(v.name, ": BE changed"), webauthn::verify_authentication(p, v.challenge, v.response, c5, uh, false, a3) == webauthn::ERR_BACKUP);
        // UV required.
        if !a.uv {
            var p5 = p;
            p5.user_verification = webauthn::REQ_REQUIRED;
            tv::check(str(v.name, ": UV required"), webauthn::verify_authentication(p5, v.challenge, v.response, c, uh, false, a3) == webauthn::ERR_USER_VERIFICATION);
        }
    } else {
        tv::check(str(v.name, ": refused (", a.message, ")"), e != webauthn::OK);
    }
}

fn main() {
    var n = 0;
    tv::each_vector("data/spec_vectors.txt") { v =>
        n++;
        if v.kind[..] == "registration" { registration(v, false); } else { authentication(v, false); }
    };
    tv::check("30 spec vectors", n == 30);
    var m = 0;
    tv::each_vector("data/py_webauthn_vectors.txt") { v =>
        m++;
        if v.kind[..] == "registration" { registration(v, true); } else { authentication(v, true); }
    };
    tv::check("23 py_webauthn vectors", m == 23);
    tv::done("vectors");
}
