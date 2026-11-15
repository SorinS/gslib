// Fuzz target: webauthn. Selected by the first byte (data[0] % 6), the
// rest is:
//   0  authenticator data: parse_auth_data, the credential key decoded.
//   1  32 bytes of clientDataHash, then an attestation object: decoded as
//      verify_registration does, its authenticator data and key, then the
//      statement checked by verify_statement (every format), and the x5c
//      chain by check_trust against the spec's root.
//   2  clientDataJSON: check_client_data for create and for get.
//   3  a registration: a header (below), then the response JSON, through
//      verify_registration.
//   4  an authentication: the header, then the response JSON, through
//      response_ids and verify_authentication with a record holding the
//      header's COSE key.
//   5  a credential record: parse_credential, marshal_credential again;
//      and the same bytes as response JSON for response_ids.
// The header: flags (bit 0 lenient base64 and RS1, 1 any TPM vendor, 2
// cross-origin allowed, 3 UV required, 4-5 roots none/spec/Apple/Google,
// 6 trust required, 7 the record backup-eligible), now (8 bytes, BE), the
// record's sign count (4 bytes, BE), then rp_id, origins (one per line),
// top origin, challenge and COSE public key, each a 2-byte BE length and
// the bytes.

import std;
import gslib from "../..";
import gslib.webauthn;
import gslib.webauthn.register;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.crypto.x509;
import gslib.crypto.x509.pool;
import gslib.crypto.bignum;
import gslib.crypto.bignum.sha256;

let NOW: i64 = 1767225600;

var roots_spec:   u8[>..] = [];
var roots_apple:  u8[>..] = [];
var roots_google: u8[>..] = [];

fn der_of_pem(text: const u8[:]) -> u8[>..] {
    var p = x509::new_pool();
    let n = x509::pool_append_pem(p, text);
    assert(n > 0);
    return x509::pool_concatenated(p);
}

struct Reader { pos: i64 = 0, ok: bool = true }

fn take_n(b: const u8[:], r: Reader&, n: i64) -> u64 {
    if !r.ok || r.pos + n > b.len { r.ok = false; return 0; }
    var v: u64 = 0;
    for i in n { v = v << 8 | b[r.pos + i]; }
    r.pos += n;
    return v;
}

fn field(b: const u8[:], r: Reader&) -> const u8[:] {
    let n = take_n(b, r, 2) as i64;
    if !r.ok || r.pos + n > b.len { r.ok = false; return ""; }
    let s = b[r.pos..r.pos + n];
    r.pos += n;
    return s;
}

fn auth_data(b: const u8[:]) {
    var ad = webauthn::AuthData { .. };
    var msg: u8[..256] = [];
    let e = webauthn::parse_auth_data(b, ad, msg);
    if e == webauthn::OK && ad.key_end > ad.key_at {
        let _ = cose::decode(b[ad.key_at..ad.key_end], 1024);
    }
}

fn attestation(b: const u8[:]) {
    if b.len < 32 { return; }
    let cdh = b[..32];
    let ao = b[32..];
    var p = webauthn::Policy { .. };
    let _ = webauthn::set_rp(p, "example.org");
    let _ = webauthn::add_origin(p, "https://example.org");
    p.tpm_any_vendor = true;
    p.allow_rs1 = true;
    p.now = NOW;
    var c = webauthn::Credential { .. };
    var doc: cbor::Node[>..] = [];
    let root, ec = cbor::decode(ao, cbor::Options { max_bytes: p.max_response, .. }, doc);
    if ec != cbor::OK || !cbor::is_map(doc, root) { return; }
    let fmt_name, okf = cbor::as_text(ao, doc, cbor::map_get_text(ao, doc, root, "fmt"));
    let stmt = cbor::map_get_text(ao, doc, root, "attStmt");
    let ad_bytes, oka = cbor::as_bytes(ao, doc, cbor::map_get_text(ao, doc, root, "authData"));
    if !okf || !cbor::is_map(doc, stmt) || !oka { return; }
    var ad = webauthn::AuthData { .. };
    if webauthn::parse_auth_data(ad_bytes, ad, c.message) != webauthn::OK { return; }
    let _ = webauthn::check_flags(p, ad, c.message);
    if ad.flags & webauthn::FLAG_AT == 0 { return; }
    let key, ek = cose::decode(ad_bytes[ad.key_at..ad.key_end], 1024);
    if ek != cose::OK { return; }
    let fmt = webauthn::format_of(fmt_name);
    if fmt == 0 { return; }
    let att_type, ea = webauthn::verify_statement(p, fmt, ao, doc, stmt, ad_bytes, ad, key, cdh, c);
    let _ = webauthn::attestation_type_name(att_type);
    if ea == webauthn::OK && c.x5c.len > 0 {
        let _ = webauthn::check_trust(c.x5c, roots_spec, NOW, c.message);
    }
}

fn client_data(b: const u8[:]) {
    var p = webauthn::Policy { .. };
    let _ = webauthn::set_rp(p, "example.org");
    let _ = webauthn::add_origin(p, "https://example.org");
    let _ = webauthn::add_top_origin(p, "https://top.example");
    p.allow_cross_origin = true;
    var msg: u8[..256] = [];
    let chal: const u8[:] = "0123456789abcdef0123456789abcdef";
    let _ = webauthn::check_client_data(p, b, "webauthn.create", chal, msg);
    let _ = webauthn::check_client_data(p, b, "webauthn.get", chal, msg);
}

fn ceremony(b: const u8[:], registration: bool) {
    var r = Reader { .. };
    let flags = take_n(b, r, 1);
    let now = take_n(b, r, 8);
    let count = take_n(b, r, 4);
    let rp = field(b, r);
    let origins = field(b, r);
    let top = field(b, r);
    let chal = field(b, r);
    let pk = field(b, r);
    if !r.ok { return; }
    let json = b[r.pos..];
    var p = webauthn::Policy { .. };
    if !webauthn::set_rp(p, rp) { return; }
    each_split(origins, '\n') { let _ = webauthn::add_origin(p, it); };
    if top.len > 0 { let _ = webauthn::add_top_origin(p, top); }
    p.lenient_base64 = flags & 1 != 0;
    p.allow_rs1 = flags & 1 != 0;
    p.tpm_any_vendor = flags & 2 != 0;
    p.allow_cross_origin = flags & 4 != 0;
    if flags & 8 != 0 { p.user_verification = webauthn::REQ_REQUIRED; }
    p.require_trusted = flags & 64 != 0;
    p.now = (now & 0x7fffffffffff) as i64;
    let which = (flags >> 4) & 3;
    let roots: const u8[:] = if which == 1 { roots_spec[..] } else if which == 2 { roots_apple[..] }
                             else if which == 3 { roots_google[..] } else { "" };
    if registration {
        var c = webauthn::Credential { .. };
        let e = webauthn::verify_registration(p, chal, json, roots, c);
        if e == webauthn::OK {
            let rec = webauthn::marshal_credential(c);
            var c2 = webauthn::Credential { .. };
            let e2 = webauthn::parse_credential(rec, c2);
            assert(e2 == webauthn::OK && webauthn::marshal_credential(c2)[..] == rec[..]);
        }
        return;
    }
    var id: u8[>..] = [];
    var uh: u8[>..] = [];
    if webauthn::response_ids(json, id, uh, p.lenient_base64) != webauthn::OK { return; }
    var c = webauthn::Credential { .. };
    if id.len > c.id.cap || pk.len > c.public_key.cap { return; }
    c.id.append(id);
    c.public_key.append(pk);
    let k, ek = cose::decode(pk, 1024);
    c.alg = k.alg;
    c.sign_count = count as i64;
    c.backup_eligible = flags & 128 != 0;
    var a = webauthn::Assertion { .. };
    let _ = webauthn::verify_authentication(p, chal, json, c, uh, false, a);
    let _ = webauthn::verify_authentication(p, chal, json, c, "", true, a);
}

fn record(b: const u8[:]) {
    var c = webauthn::Credential { .. };
    if webauthn::parse_credential(b, c) == webauthn::OK {
        let rec = webauthn::marshal_credential(c);
        var c2 = webauthn::Credential { .. };
        let e2 = webauthn::parse_credential(rec, c2);
        assert(e2 == webauthn::OK && webauthn::marshal_credential(c2)[..] == rec[..]);
        let _ = webauthn::aaguid_text(c.aaguid);
    }
    var id: u8[>..] = [];
    var uh: u8[>..] = [];
    let _ = webauthn::response_ids(b, id, uh, true);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let rest = data[1..];
    let mode = data[0] % 6;
    if mode == 0 { auth_data(rest); }
    else if mode == 1 { attestation(rest); }
    else if mode == 2 { client_data(rest); }
    else if mode == 3 { ceremony(rest, true); }
    else if mode == 4 { ceremony(rest, false); }
    else { record(rest); }
    return 0;
}

fn main() {
    roots_spec = der_of_pem(embed_file("../../webauthn/test/data/spec_ca.pem"));
    roots_apple = der_of_pem(embed_file("../../webauthn/test/data/apple_root.pem"));
    roots_google = der_of_pem(embed_file("../../webauthn/test/data/google_roots.pem"));
}
