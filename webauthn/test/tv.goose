// tv: what webauthn's tests share: counting checks, hex, the published
// vectors in data/ (one block per vector: "[name]", then "key value"
// lines, a key given more than once for a list), roots read from PEM,
// and a policy that takes every algorithm.

namespace tv;

import std;
import os;
import gslib.webauthn;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.encoding.asn1;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.bignum;
import gslib.crypto.bignum.sha256;
import gslib.jwx;
import json;

var checks = 0;
var failures = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok {
        failures++;
        print("FAIL ", what);
    }
}

// That code is what came back, printing the message when not.
fn check_code(what: const u8[:], got: i64, want: i64, why: const u8[:]) {
    check(what, got == want);
    var verbose: u8[>..] = [];
    if env("WEBAUTHN_VERBOSE", verbose) { print("  ", what, ": ", webauthn::error_text(got), " (", why, ")"); }
    if got != want { print("      got ", webauthn::error_text(got), " (", why, "), want ", webauthn::error_text(want)); }
}

fn done(name: const u8[:]) {
    print(name, ": ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((ascii::hex_value(s[i]) * 16 + ascii::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    cbor::put_hex(out, b);
    return out;
}

fn read(path: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if !read_file(path, out) { print("cannot read ", path); exit(1); }
    return out;
}

// The certificates of a PEM file, as DER concatenated.
fn roots_of(path: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let text = read(path);
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    for d in ders { out.append(d); }
    return out;
}

// Every algorithm cose knows but RS1.
let ALL_ALGS: i64[] = [-7, -35, -36, -9, -51, -52, -8, -19, -53, -37, -38, -39, -257, -258, -259];

fn policy(rp_id: const u8[:], origin: const u8[:]) -> webauthn::Policy {
    var p = webauthn::Policy { now: 1767225600, .. };
    let ok1 = webauthn::set_rp(p, rp_id);
    let ok2 = webauthn::add_origin(p, origin);
    for a in ALL_ALGS { p.algs.push(a); }
    return p;
}

// One vector of data/*_vectors.txt; lists (origins) one per line.
root struct Vector {
    name:            u8[>..] = [],
    kind:            u8[>..] = [],
    expect:          u8[>..] = [],
    rp_id:           u8[>..] = [],
    origins:         u8[>..] = [],
    top_origin:      u8[>..] = [],
    challenge:       u8[>..] = [],
    response:        u8[>..] = [],
    fmt:             u8[>..] = [],
    cred_id:         u8[>..] = [],
    aaguid:          u8[>..] = [],
    roots:           u8[>..] = [],
    public_key:      u8[>..] = [],
    why:             u8[>..] = [],
    now:             i64     = 0,
    sign_count:      i64     = 0,
    new_sign_count:  i64     = -1,
    require_uv:      bool    = false,
    cross_origin:    bool    = false,
    backup_eligible: i64     = -1,
}

fn reset(v: Vector&) {
    v.name.clear(); v.kind.clear(); v.expect.clear(); v.rp_id.clear(); v.origins.clear(); v.top_origin.clear();
    v.challenge.clear(); v.response.clear(); v.fmt.clear(); v.cred_id.clear(); v.aaguid.clear(); v.roots.clear();
    v.public_key.clear(); v.why.clear();
    v.now = 0; v.sign_count = 0; v.new_sign_count = -1; v.require_uv = false; v.cross_origin = false; v.backup_eligible = -1;
}

fn set(v: Vector&, key: const u8[:], val: const u8[:]) {
    if key == "kind" { v.kind.append(val); }
    else if key == "expect" { v.expect.append(val); }
    else if key == "rp_id" { v.rp_id.append(val); }
    else if key == "origin" { v.origins.append(val); v.origins.push('\n'); }
    else if key == "top_origin" { v.top_origin.append(val); }
    else if key == "challenge" { v.challenge.append(unhex(val)); }
    else if key == "response" { v.response.append(val); }
    else if key == "fmt" { v.fmt.append(val); }
    else if key == "cred_id" { v.cred_id.append(unhex(val)); }
    else if key == "aaguid" { v.aaguid.append(unhex(val)); }
    else if key == "roots" { v.roots.append(val); }
    else if key == "public_key" { v.public_key.append(unhex(val)); }
    else if key == "why" { v.why.append(val); }
    else {
        let n, ok = parse_int(val);
        if key == "now" { v.now = n; }
        else if key == "sign_count" { v.sign_count = n; }
        else if key == "new_sign_count" { v.new_sign_count = n; }
        else if key == "require_uv" { v.require_uv = n != 0; }
        else if key == "cross_origin" { v.cross_origin = n != 0; }
        else if key == "backup_eligible" { v.backup_eligible = n; }
    }
}

// F(v) for each vector of a file.
fn each_vector<F>(path: const u8[:]) {
    let text = read(path);
    var v = Vector { .. };
    var open = false;
    for line in split(text, '\n') {
        if line.len == 0 || line[0] == '#' { continue; }
        if line[0] == '[' {
            if open { F(v); }
            reset(v);
            v.name.append(line[1..line.len - 1]);
            open = true;
            continue;
        }
        let k, val, ok = split_once(line, ' ');
        set(v, k, val);
    }
    if open { F(v); }
}

// --- A software authenticator ------------------------------------------------------------

// What the hostile tests build responses from, a piece at a time, so that
// each can be changed: clientDataJSON, authenticator data, attestation
// objects, the JSON of a response, signatures.

let RP = "example.org";
let ORIGIN = "https://example.org";
let NOW: i64 = 1767225600;     // 2026-01-01

fn b64(b: const u8[:]) -> u8[>..] { jwx::b64_encode(b) }

// clientDataJSON as browsers write it; `extra` is more members (",\"x\":1").
fn client_data(ty: const u8[:], challenge: const u8[:], origin: const u8[:], extra: const u8[:] = "") -> u8[>..] {
    var out: u8[>..] = [];
    out.append("{\"type\":");
    json::format_string(out, ty);
    out.append(",\"challenge\":\"");
    out.append(b64(challenge));
    out.append("\",\"origin\":");
    json::format_string(out, origin);
    out.append(",\"crossOrigin\":false");
    out.append(extra);
    out.push('}');
    return out;
}

// Authenticator data: the RP ID's hash, flags, counter, and the attested
// credential data when cred_id is not empty.
fn auth_data(rp_id: const u8[:], flags: u8, count: i64, aaguid: const u8[:], cred_id: const u8[:], cose_key: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(bignum::sha256(rp_id));
    out.push(flags);
    for k in 4 { out.push((count >> (24 - 8 * k)) as! u8); }
    if cred_id.len > 0 {
        out.append(aaguid);
        out.push((cred_id.len >> 8) as! u8);
        out.push(cred_id.len as! u8);
        out.append(cred_id);
        out.append(cose_key);
    }
    return out;
}

// The COSE key of an x509 key, with alg.
fn cose_key(k: const x509::PrivateKey&, alg: i64) -> u8[>..] {
    let spki = x509::marshal_public_key(k);
    var ck, e = cose::from_spki(spki);
    check("cose_key", e == cose::OK);
    ck.alg = alg;
    return cose::encode(ck);
}

// A signature by alg (ES256/384/512 as DER, EdDSA, RS256, PS256).
fn sign(k: const x509::PrivateKey&, alg: i64, msg: const u8[:]) -> u8[>..] {
    var sa = x509::SIG_ECDSA;
    var h: i64 = 256;
    if alg == cose::ES384 { h = 384; }
    else if alg == cose::ES512 { h = 512; }
    else if alg == cose::EDDSA || alg == cose::ED25519 { sa = if k.kind == x509::KEY_ED448 { x509::SIG_ED448 } else { x509::SIG_ED25519 }; h = 0; }
    else if alg == cose::RS256 { sa = x509::SIG_RSA_PKCS1; }
    else if alg == cose::PS256 { sa = x509::SIG_RSA_PSS; }
    let s, ok = x509::sign(k, sa, h, msg);
    check("sign", ok);
    return s;
}

// An attestation object: {fmt, attStmt, authData}, stmt being the
// statement's CBOR map.
fn att_obj(fmt: const u8[:], stmt: const u8[:], ad: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    cbor::put_map(out, 3);
    cbor::put_text(out, "fmt");
    cbor::put_text(out, fmt);
    cbor::put_text(out, "attStmt");
    out.append(stmt);
    cbor::put_text(out, "authData");
    cbor::put_bytes(out, ad);
    let e = cbor::sort_map(out, 0, true);
    return out;
}

// A packed statement: alg, sig, and x5c when certs (DER, concatenated) are given.
fn packed_stmt(alg: i64, sig: const u8[:], certs: const u8[:][:]) -> u8[>..] {
    var out: u8[>..] = [];
    cbor::put_map(out, if certs.len > 0 { 3 } else { 2 });
    cbor::put_text(out, "alg");
    cbor::put_int(out, alg);
    cbor::put_text(out, "sig");
    cbor::put_bytes(out, sig);
    if certs.len > 0 {
        cbor::put_text(out, "x5c");
        cbor::put_array(out, certs.len);
        for c in certs { cbor::put_bytes(out, c); }
    }
    let e = cbor::sort_map(out, 0, true);
    return out;
}

fn reg_json(id: const u8[:], cdj: const u8[:], ao: const u8[:], extra: const u8[:] = "") -> u8[>..] {
    var out: u8[>..] = [];
    format(out, "{\"id\":\"", b64(id), "\",\"rawId\":\"", b64(id), "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\"",
           b64(cdj), "\",\"attestationObject\":\"", b64(ao), "\",\"transports\":[\"usb\",\"hybrid\"]},",
           "\"authenticatorAttachment\":\"cross-platform\",\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}", extra, "}");
    return out;
}

fn auth_json(id: const u8[:], cdj: const u8[:], ad: const u8[:], sig: const u8[:], user_handle: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    format(out, "{\"id\":\"", b64(id), "\",\"rawId\":\"", b64(id), "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\"",
           b64(cdj), "\",\"authenticatorData\":\"", b64(ad), "\",\"signature\":\"", b64(sig), "\"");
    if user_handle.len > 0 { format(out, ",\"userHandle\":\"", b64(user_handle), "\""); }
    out.append("},\"authenticatorAttachment\":\"platform\",\"clientExtensionResults\":{}}");
    return out;
}

// A test CA and attestation certificates under it.
fn ca_cert(key: const x509::PrivateKey&) -> u8[>..] {
    var t, ok = x509::template("CN=Test Attestation CA,O=Example,C=AA", NOW - 86400, NOW + 86400 * 3650);
    t.basic_constraints = true;
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), "", key);
    check("ca cert", e == x509::OK);
    return der;
}

// An attestation certificate for key, issued by the CA, with `extra`
// extensions (DER Extension elements).
fn att_cert(subject: const u8[:], key: const x509::PrivateKey&, ca: const u8[:], ca_key: const x509::PrivateKey&,
            extra: const u8[:], is_ca: bool = false) -> u8[>..] {
    var t, ok = x509::template(subject, NOW - 86400, NOW + 86400 * 365);
    check("template", ok);
    t.basic_constraints = true;
    t.is_ca = is_ca;
    t.extra.append(extra);
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), ca, ca_key);
    check(str("att cert: ", x509::error_text(e)), e == x509::OK);
    return der;
}

// An Extension element: oid, critical, the value's DER.
fn extension(oid: const u8[:], critical: bool, value: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    x509::put_ext(out, oid, critical, value);
    return out;
}

// The FIDO AAGUID extension's value: an OCTET STRING of 16 bytes.
fn aaguid_ext(aaguid: const u8[:], critical: bool = false) -> u8[>..] {
    var v: u8[>..] = [];
    asn1::put_octets(v, aaguid);
    return extension("1.3.6.1.4.1.45724.1.1.4", critical, v);
}
