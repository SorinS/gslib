// Options: registration options (rp, user, challenge made when empty,
// pubKeyCredParams by default and as asked, excludeCredentials with
// transports, authenticatorSelection, hints, attestation and its formats,
// credProps) and authentication options (allowCredentials, or none for a
// passkey), read back as JSON; the arguments refused (no RP, no user
// handle, an algorithm cose does not know, RS1); the related origins
// document; AAGUID text; credential records as bytes, and bytes that are
// not one.
import std;
import json;
import gslib from "../..";
import gslib.webauthn;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.jwx;
import tv;

fn parse_ok(text: const u8[:], what: const u8[:]) {
    var doc: json::Node[>..] = [];
    var dec: u8[>..]         = [];
    let root, err = json::parse(text, doc, dec);
    tv::check(str(what, " is JSON: ", err), root != null);
}

fn main() {
    var o = webauthn::RegistrationOptions { .. };
    o.rp_id.append("example.org");
    o.rp_name.append("Example");
    o.user_id.append("\x01\x02\x03\x04");
    o.user_name.append("alice@example.org");
    o.user_display_name.append("Alice \"A\" Example");
    var excl: webauthn::Descriptor[>..] = [];
    var d = webauthn::Descriptor { .. };
    d.id.append("\xff\xfe\xfd");
    d.transports = webauthn::TRANSPORT_USB | webauthn::TRANSPORT_HYBRID;
    excl.push(d);
    let j, e = webauthn::registration_options(o, excl);
    tv::check("registration options", e == webauthn::OK);
    tv::check("challenge made", o.challenge.len == 32);
    parse_ok(j, "registration options");
    var doc: json::Node[>..] = [];
    var dec: u8[>..]         = [];
    let root, err = json::parse(j, doc, dec);
    let rp_id, ok1 = json::as_string(json::member(json::member(root, "rp"), "id"));
    tv::check("rp.id", ok1 && rp_id == "example.org");
    let uid, ok2 = json::as_string(json::member(json::member(root, "user"), "id"));
    tv::check("user.id base64url", ok2 && uid == "AQIDBA");
    let dn, ok3 = json::as_string(json::member(json::member(root, "user"), "displayName"));
    tv::check("displayName escaped", ok3 && dn == "Alice \"A\" Example");
    let ch, ok4 = json::as_string(json::member(root, "challenge"));
    let chb, ok5 = jwx::b64_decode(ch);
    tv::check("challenge", ok4 && ok5 && chb[..] == o.challenge[..]);
    var algs: i64[>..] = [];
    let pkp = json::member(root, "pubKeyCredParams");
    if pkp {
        json::each(pkp) { it =>
            let a, ok = json::as_i64(json::member(it, "alg"));
            let t, okt = json::as_string(json::member(it, "type"));
            if ok && okt && t == "public-key" { algs.push(a); }
        };
    }
    tv::check("default algorithms", algs[..] == webauthn::DEFAULT_ALGS[..]);
    let ex = json::member(root, "excludeCredentials");
    var nex = 0;
    if ex {
        json::each(ex) { it =>
            nex++;
            let id, ok = json::as_string(json::member(it, "id"));
            tv::check("exclude id", ok && id == "__79");
            var ts: u8[>..] = [];
            let tl = json::member(it, "transports");
            if tl { json::each(tl) { t => let s, okt = json::as_string(t); ts.append(s); ts.push(' '); }; }
            tv::check(str("exclude transports ", ts), ts[..] == "usb hybrid ");
        };
    }
    tv::check("one exclusion", nex == 1);
    let sel = json::member(root, "authenticatorSelection");
    let rk, okrk = json::as_string(json::member(sel, "residentKey"));
    let rrk, okrrk = json::as_bool(json::member(sel, "requireResidentKey"));
    let uv, okuv = json::as_string(json::member(sel, "userVerification"));
    tv::check("authenticatorSelection", okrk && rk == "preferred" && okrrk && !rrk && okuv && uv == "preferred"
              && json::member(sel, "authenticatorAttachment") == null);
    let att, okatt = json::as_string(json::member(root, "attestation"));
    tv::check("attestation none", okatt && att == "none");
    let cp, okcp = json::as_bool(json::member(json::member(root, "extensions"), "credProps"));
    tv::check("credProps", okcp && cp);
    let to, okto = json::as_i64(json::member(root, "timeout"));
    tv::check("timeout", okto && to == 300000);

    // Everything asked for.
    var o2 = webauthn::RegistrationOptions { .. };
    o2.rp_id.append("example.org");
    o2.rp_name.append("Example");
    o2.user_id.append("u");
    o2.challenge.append("fixed challenge!");
    o2.algs.push(cose::ES256);
    o2.algs.push(cose::ED25519);
    o2.attachment = webauthn::ATTACH_PLATFORM;
    o2.resident_key = webauthn::REQ_REQUIRED;
    o2.user_verification = webauthn::REQ_REQUIRED;
    o2.attestation = webauthn::CONVEY_DIRECT;
    o2.attestation_formats.push(webauthn::FMT_PACKED);
    o2.attestation_formats.push(webauthn::FMT_TPM);
    o2.hints.push(webauthn::HINT_SECURITY_KEY);
    o2.hints.push(webauthn::HINT_HYBRID);
    o2.cred_props = false;
    let j2, e2 = webauthn::registration_options(o2, []);
    tv::check("options 2", e2 == webauthn::OK && o2.challenge[..] == "fixed challenge!");
    parse_ok(j2, "options 2");
    for want in ["\"alg\":-7}", "\"alg\":-19}", "\"authenticatorAttachment\":\"platform\"", "\"residentKey\":\"required\"",
                 "\"requireResidentKey\":true", "\"userVerification\":\"required\"", "\"attestation\":\"direct\"",
                 "\"attestationFormats\":[\"packed\",\"tpm\"]", "\"hints\":[\"security-key\",\"hybrid\"]",
                 "\"extensions\":{}", "\"excludeCredentials\":[]"] {
        tv::check(str("options 2 has ", want), find(j2, want) >= 0);
    }
    // Refused.
    var o3 = webauthn::RegistrationOptions { .. };
    o3.rp_id.append("example.org");
    o3.rp_name.append("Example");
    let j3, e3 = webauthn::registration_options(o3, []);
    tv::check("no user handle", e3 == webauthn::ERR_ARG && j3.len == 0);
    o3.user_id.append("u");
    o3.algs.push(-260);
    let j4, e4 = webauthn::registration_options(o3, []);
    tv::check("unknown alg", e4 == webauthn::ERR_ARG);
    o3.algs.clear();
    o3.algs.push(cose::RS1);
    let j5, e5 = webauthn::registration_options(o3, []);
    tv::check("RS1", e5 == webauthn::ERR_ARG);

    // Authentication options: a passkey sign-in (no allowCredentials), and
    // one for known credentials.
    var a = webauthn::AuthenticationOptions { .. };
    a.rp_id.append("example.org");
    a.user_verification = webauthn::REQ_REQUIRED;
    let ja, ea = webauthn::authentication_options(a, []);
    tv::check("authentication options", ea == webauthn::OK && a.challenge.len == 32);
    parse_ok(ja, "authentication options");
    tv::check("empty allowCredentials", find(ja, "\"allowCredentials\":[]") >= 0 && find(ja, "\"rpId\":\"example.org\"") >= 0
              && find(ja, "\"userVerification\":\"required\"") >= 0);
    var a2 = webauthn::AuthenticationOptions { .. };
    a2.rp_id.append("example.org");
    let ja2, ea2 = webauthn::authentication_options(a2, excl);
    tv::check("allowCredentials", ea2 == webauthn::OK && find(ja2, "\"allowCredentials\":[{\"type\":\"public-key\",\"id\":\"__79\",\"transports\":[\"usb\",\"hybrid\"]}]") >= 0);
    tv::check("two challenges differ", a.challenge[..] != a2.challenge[..]);
    var a3 = webauthn::AuthenticationOptions { .. };
    let ja3, ea3 = webauthn::authentication_options(a3, []);
    tv::check("no rp id", ea3 == webauthn::ERR_ARG);

    // The related origins document.
    var p = tv::policy("example.org", "https://example.org");
    tv::check("related", webauthn::add_origin(p, "https://example.co.uk"));
    let ro = webauthn::related_origins_json(p);
    tv::check(str("related origins: ", ro), ro[..] == "{\"origins\":[\"https://example.org\",\"https://example.co.uk\"]}");

    // AAGUID text.
    tv::check("aaguid text", webauthn::aaguid_text("\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef")[..]
              == "01234567-89ab-cdef-0123-456789abcdef");

    // Records: bytes that are not one.
    var c = webauthn::Credential { .. };
    tv::check("record from junk", webauthn::parse_credential("\x01\x02", c) == webauthn::ERR_MALFORMED);
    tv::check("record from an empty map", webauthn::parse_credential("\xa0", c) == webauthn::ERR_MALFORMED);
    var c2 = webauthn::Credential { .. };
    c2.id.append("id");
    c2.public_key.append("\xa0");
    c2.sign_count = 7;
    let b = webauthn::marshal_credential(c2);
    var c3 = webauthn::Credential { .. };
    tv::check("record round trip", webauthn::parse_credential(b, c3) == webauthn::OK && c3.sign_count == 7 && c3.id[..] == "id" && c3.rk == -1);
    var doc2: cbor::Node[>..] = [];
    let r2, e6 = cbor::decode(b, cbor::Options { deterministic: true, .. }, doc2);
    tv::check("record is deterministic CBOR", e6 == cbor::OK);
    tv::done("options");
}
