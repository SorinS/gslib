// goose-webauthn: WebAuthn on gslib's webauthn, from the command line:
// options for navigator.credentials.create() and .get(), registrations
// and authentications checked from files, an MDS3 BLOB verified and
// searched, and a small relying party over HTTP for trying a real
// browser and a real passkey or security key by hand.
//
//   goose-webauthn registration-options --rp-id ID --rp-name NAME --user-name NAME [--user-id B64URL]
//                  [--challenge B64URL] [--alg N ...] [--attestation none|indirect|direct|enterprise]
//                  [--resident-key discouraged|preferred|required] [--uv discouraged|preferred|required]
//                  [--attachment platform|cross-platform] [--exclude B64URL ...]
//   goose-webauthn authentication-options --rp-id ID [--challenge B64URL] [--allow B64URL ...] [--uv ...]
//   goose-webauthn verify-registration --rp-id ID --origin ORIGIN [--origin ...] --challenge B64URL
//                  [--roots PEM] [--now SECONDS] [--uv required] [--require-trusted] [--alg N ...]
//                  [--cross-origin] [--top-origin ORIGIN] [--lenient] [--allow-rs1] [--tpm-any-vendor]
//                  [--record-out FILE] RESPONSE.json
//   goose-webauthn verify-authentication --rp-id ID --origin ORIGIN --challenge B64URL --record FILE
//                  [--user-handle B64URL] [--require-user-handle] [--uv required] [--refuse-sign-count]
//                  [--cross-origin] [--top-origin ORIGIN] [--record-out FILE] RESPONSE.json
//   goose-webauthn mds BLOB --root PEM [--now SECONDS] [--aaguid HEX]
//   goose-webauthn serve [--port 8080] [--rp-id localhost] [--origin http://localhost:8080] [--uv required]
//
// verify-registration prints what it found, "key value" a line (fmt,
// attestation, trusted, aaguid, credential id, alg, sign count, flags),
// and writes the credential record (marshal_credential's bytes) to
// --record-out; verify-authentication takes such a record and writes it
// back with the new counter and backup state. RESPONSE.json is the
// PublicKeyCredential's toJSON(); - reads it from stdin.
//
// serve listens on 127.0.0.1 and serves a page whose buttons register a
// passkey (or a security key) for a user name and sign in with it, with
// or without the name (a discoverable credential). The browser must
// open it as http://localhost:PORT (a secure context; the RP ID is
// "localhost"). Credentials are kept in memory until it stops. One
// request at a time, each answered and closed; it logs to stderr.
//
// Exit status: 0 on success, 1 on failure, 2 on a usage error.

import std;
import os;
import json;
import gslib from "../..";
import gslib.webauthn;
import gslib.webauthn.register;
import gslib.webauthn.mds;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.encoding.asn1;
import gslib.jwx;
import gslib.net;
import gslib.net.http;
import gslib.net.http.conn1;

fn usage() {
    print("""
        usage: goose-webauthn registration-options --rp-id ID --rp-name NAME --user-name NAME [options]
               goose-webauthn authentication-options --rp-id ID [options]
               goose-webauthn verify-registration --rp-id ID --origin O --challenge B64URL [options] RESPONSE.json
               goose-webauthn verify-authentication --rp-id ID --origin O --challenge B64URL --record FILE [options] RESPONSE.json
               goose-webauthn mds BLOB --root PEM [--now SECONDS] [--aaguid HEX]
               goose-webauthn serve [--port N] [--rp-id ID] [--origin O]
        """);
    exit(2);
}

fn fail(s: const u8[:]) {
    print("goose-webauthn: ", s);
    exit(1);
}

fn requirement(s: const u8[:]) -> i64 {
    if s == "discouraged" { return webauthn::REQ_DISCOURAGED; }
    if s == "preferred" { return webauthn::REQ_PREFERRED; }
    if s == "required" { return webauthn::REQ_REQUIRED; }
    usage();
    return 0;
}

fn b64_arg(s: const u8[:], out: u8[>..]&) {
    if !jwx::b64_decode_append(out, s) { fail(str("not base64url: ", s)); }
}

fn read_input(path: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if path == "-" { read_stdin(out); return out; }
    if !read_file(path, out) { fail(str("cannot read ", path)); }
    return out;
}

// Certificates from a PEM file (or DER), concatenated.
fn certs_of(path: const u8[:]) -> u8[>..] {
    let text = read_input(path);
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    for d in ders { out.append(d); }
    if out.len == 0 { out.append(text); }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    cbor::put_hex(out, b);
    return out;
}

// The options every verify takes, into a policy.
root struct Args {
    file:                u8[>..]   = [],
    roots:               u8[>..]   = [],
    record:              u8[>..]   = [],
    record_out:          u8[>..]   = [],
    challenge:           u8[>..]   = [],
    user_handle:         u8[>..]   = [],
    rp_name:             u8[>..]   = [],
    user_name:           u8[>..]   = [],
    user_id:             u8[>..]   = [],
    aaguid:              u8[>..]   = [],
    root:                u8[>..]   = [],
    ids:                 u8[][>..] = [],
    require_user_handle: bool      = false,
    port:                i64       = 8080,
    attestation:         i64       = webauthn::CONVEY_NONE,
    resident_key:        i64       = webauthn::REQ_PREFERRED,
    attachment:          i64       = webauthn::ATTACH_ANY,
}

fn parse_args(a: u8[:][>..]&, p: webauthn::Policy&, x: Args&) {
    var i = 2;
    p.now = time() as i64;
    while i < a.len {
        let s = a[i];
        let has = i + 1 < a.len;
        if s == "--rp-id" && has { if !webauthn::set_rp(p, a[i + 1]) { fail("bad RP ID"); } i++; }
        else if s == "--origin" && has { if !webauthn::add_origin(p, a[i + 1]) { fail("bad origin, or too many"); } i++; }
        else if s == "--top-origin" && has { if !webauthn::add_top_origin(p, a[i + 1]) { fail("bad top origin"); } p.allow_cross_origin = true; i++; }
        else if s == "--cross-origin" { p.allow_cross_origin = true; }
        else if s == "--challenge" && has { b64_arg(a[i + 1], x.challenge); i++; }
        else if s == "--roots" && has { x.roots.append(certs_of(a[i + 1])); i++; }
        else if s == "--root" && has { x.root.append(certs_of(a[i + 1])); i++; }
        else if s == "--now" && has { let n, ok = parse_int(a[i + 1]); if !ok { usage(); } p.now = n; i++; }
        else if s == "--uv" && has { p.user_verification = requirement(a[i + 1]); i++; }
        else if s == "--require-trusted" { p.require_trusted = true; }
        else if s == "--lenient" { p.lenient_base64 = true; }
        else if s == "--allow-rs1" { p.allow_rs1 = true; }
        else if s == "--tpm-any-vendor" { p.tpm_any_vendor = true; }
        else if s == "--refuse-sign-count" { p.refuse_sign_count = true; }
        else if s == "--alg" && has {
            let n, ok = parse_int(a[i + 1]);
            if !ok || p.algs.len == p.algs.cap { usage(); }
            p.algs.push(n);
            i++;
        }
        else if s == "--record" && has { x.record.append(read_input(a[i + 1])); i++; }
        else if s == "--record-out" && has { x.record_out.append(a[i + 1]); i++; }
        else if s == "--user-handle" && has { b64_arg(a[i + 1], x.user_handle); i++; }
        else if s == "--require-user-handle" { x.require_user_handle = true; }
        else if s == "--rp-name" && has { x.rp_name.append(a[i + 1]); i++; }
        else if s == "--user-name" && has { x.user_name.append(a[i + 1]); i++; }
        else if s == "--user-id" && has { b64_arg(a[i + 1], x.user_id); i++; }
        else if s == "--aaguid" && has {
            var t: u8[>..] = [];
            for c in a[i + 1] { if c != '-' { t.push(c); } }
            if t.len != 32 { usage(); }
            var j = 0;
            while j < 32 { x.aaguid.push((ascii::hex_value(t[j]) * 16 + ascii::hex_value(t[j + 1])) as! u8); j += 2; }
            i++;
        }
        else if (s == "--exclude" || s == "--allow") && has { var id: u8[>..] = []; b64_arg(a[i + 1], id); x.ids.push(copy(id)); i++; }
        else if s == "--attestation" && has {
            let v = a[i + 1];
            x.attestation = if v == "none" { webauthn::CONVEY_NONE } else if v == "indirect" { webauthn::CONVEY_INDIRECT }
                            else if v == "direct" { webauthn::CONVEY_DIRECT } else if v == "enterprise" { webauthn::CONVEY_ENTERPRISE } else { -1 };
            if x.attestation < 0 { usage(); }
            i++;
        }
        else if s == "--resident-key" && has { x.resident_key = requirement(a[i + 1]); i++; }
        else if s == "--attachment" && has {
            let v = a[i + 1];
            x.attachment = if v == "platform" { webauthn::ATTACH_PLATFORM } else if v == "cross-platform" { webauthn::ATTACH_CROSS_PLATFORM } else { usage(); 0 };
            i++;
        }
        else if s == "--port" && has { let n, ok = parse_int(a[i + 1]); if !ok || n <= 0 || n > 65535 { usage(); } x.port = n; i++; }
        else if (s == "-" || (s.len > 0 && s[0] != '-')) && x.file.len == 0 { x.file.append(s); }
        else { usage(); }
        i++;
    }
}

fn descriptors(x: const Args&) -> webauthn::Descriptor[>..] {
    var out: webauthn::Descriptor[>..] = [];
    for id in x.ids {
        var d = webauthn::Descriptor { .. };
        if id.len > d.id.cap { fail("credential ID over 1023 bytes"); }
        d.id.append(id);
        out.push(d);
    }
    return out;
}

fn show_record(c: const webauthn::Credential&) {
    print("fmt ", webauthn::format_name(c.fmt));
    print("attestation ", webauthn::attestation_type_name(c.attestation_type));
    print("trusted ", c.trusted);
    print("aaguid ", webauthn::aaguid_text(c.aaguid));
    print("credential_id ", jwx::b64_encode(c.id));
    print("alg ", c.alg, " ", cose::alg_name(c.alg));
    print("sign_count ", c.sign_count);
    print("uv ", c.uv, " backup_eligible ", c.backup_eligible, " backed_up ", c.backed_up);
    print("rk ", c.rk, " transports ", c.transports);
}

fn main() {
    let a = args();
    guard a.len >= 2 else { usage(); }
    let cmd = a[1];
    var p = webauthn::Policy { .. };
    var x = Args { .. };
    parse_args(a, p, x);
    if cmd == "registration-options" {
        var o = webauthn::RegistrationOptions { .. };
        if p.rp_id.len == 0 || x.rp_name.len == 0 || x.user_name.len == 0 { usage(); }
        o.rp_id.append(p.rp_id);
        if x.rp_name.len > o.rp_name.cap || x.user_name.len > o.user_name.cap || x.challenge.len > o.challenge.cap
           || x.user_id.len > o.user_id.cap { fail("an argument too long"); }
        o.rp_name.append(x.rp_name);
        o.user_name.append(x.user_name);
        o.user_display_name.append(x.user_name);
        if x.user_id.len > 0 { o.user_id.append(x.user_id); } else { webauthn::new_random(o.user_id); }
        o.challenge.append(x.challenge);
        for alg in p.algs { o.algs.push(alg); }
        o.attestation = x.attestation;
        o.resident_key = x.resident_key;
        o.user_verification = p.user_verification;
        o.attachment = x.attachment;
        let ds = descriptors(x);
        let j, e = webauthn::registration_options(o, ds);
        if e != webauthn::OK { fail(webauthn::error_text(e)); }
        print(j);
        return;
    }
    if cmd == "authentication-options" {
        var o = webauthn::AuthenticationOptions { .. };
        if p.rp_id.len == 0 { usage(); }
        o.rp_id.append(p.rp_id);
        if x.challenge.len > o.challenge.cap { fail("challenge too long"); }
        o.challenge.append(x.challenge);
        o.user_verification = p.user_verification;
        let ds = descriptors(x);
        let j, e = webauthn::authentication_options(o, ds);
        if e != webauthn::OK { fail(webauthn::error_text(e)); }
        print(j);
        return;
    }
    if cmd == "verify-registration" {
        if x.file.len == 0 || x.challenge.len == 0 { usage(); }
        // Without --alg, every algorithm cose knows (but RS1) is taken.
        if p.algs.len == 0 { for alg in [-7, -35, -36, -9, -51, -52, -8, -19, -53, -37, -38, -39, -257, -258, -259] { p.algs.push(alg); } }
        let resp = read_input(x.file);
        var c = webauthn::Credential { .. };
        let e = webauthn::verify_registration(p, x.challenge, resp, x.roots, c);
        if e != webauthn::OK { fail(str(webauthn::error_text(e), ": ", c.message)); }
        show_record(c);
        if x.record_out.len > 0 && !write_file(x.record_out, webauthn::marshal_credential(c)) { fail("cannot write the record"); }
        return;
    }
    if cmd == "verify-authentication" {
        if x.file.len == 0 || x.challenge.len == 0 || x.record.len == 0 { usage(); }
        let resp = read_input(x.file);
        var c = webauthn::Credential { .. };
        if webauthn::parse_credential(x.record, c) != webauthn::OK { fail("not a credential record"); }
        var r = webauthn::Assertion { .. };
        let e = webauthn::verify_authentication(p, x.challenge, resp, c, x.user_handle, x.require_user_handle, r);
        if e != webauthn::OK { fail(str(webauthn::error_text(e), ": ", r.message)); }
        print("credential_id ", jwx::b64_encode(r.credential_id));
        print("user_handle ", jwx::b64_encode(r.user_handle));
        print("sign_count ", r.sign_count, " counter_regressed ", r.counter_regressed);
        print("uv ", r.uv, " backed_up ", r.backed_up, " backup_changed ", r.backup_changed);
        c.sign_count = r.sign_count;
        c.backed_up = r.backed_up;
        if x.record_out.len > 0 && !write_file(x.record_out, webauthn::marshal_credential(c)) { fail("cannot write the record"); }
        return;
    }
    if cmd == "mds" {
        if x.file.len == 0 || x.root.len == 0 { usage(); }
        let blob = read_input(x.file);
        var m = webauthn::Mds { .. };
        let e = webauthn::parse_mds(blob, x.root, p.now, m);
        if e != webauthn::OK { fail(str(webauthn::error_text(e), ": ", m.message)); }
        print("no ", m.no, " next_update ", m.next_update, " stale ", m.stale);
        if x.aaguid.len == 16 {
            var en = webauthn::MdsEntry { .. };
            if !webauthn::mds_lookup(m, x.aaguid, en) { fail("no entry for that AAGUID"); }
            print("description ", en.description);
            print("status ", webauthn::status_name(en.status), " reports ", en.reports, " allowed ", webauthn::mds_status_ok(en) == webauthn::OK);
            var n = 0;
            var at = 0;
            while at < en.roots.len {
                let t, ok = asn1::read(en.roots, at, en.roots.len);
                if !ok { break; }
                n++;
                at = t.end;
            }
            print("roots ", n);
        }
        return;
    }
    if cmd == "serve" {
        if p.rp_id.len == 0 { let ok = webauthn::set_rp(p, "localhost"); }
        if p.origins.len == 0 { let ok = webauthn::add_origin(p, str("http://localhost:", x.port)); }
        serve(p, x.port);
        return;
    }
    usage();
}

// --- The demo relying party ---------------------------------------------------------------

// A registered credential, kept in memory: its owner and record.
struct Stored {
    user:            u8[..64]   = [],
    handle:          u8[..64]   = [],
    id:              u8[..1023] = [],
    public_key:      u8[..1200] = [],
    alg:             i64        = 0,
    sign_count:      i64        = 0,
    backup_eligible: bool       = false,
    backed_up:       bool       = false,
    transports:      u32        = 0,
}

fn answer(c: i64, status: i64, ctype: const u8[:], body: const u8[:]) {
    var out: u8[>..] = [];
    let reason = if status == 200 { " OK" } else if status == 404 { " Not Found" } else { " Bad Request" };
    format(out, "HTTP/1.1 ", status, reason, "\r\nContent-Type: ", ctype, "\r\nContent-Length: ", body.len,
           "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body);
    net::write(c, out, 10000);
}

fn json_result(ok: bool, text: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    format(out, "{\"ok\":", ok, ",\"message\":");
    json::format_string(out, text);
    out.push('}');
    return out;
}

// The "username" member of a small JSON body.
fn username_of(body: const u8[:], out: u8[>..]&) -> bool {
    var doc: json::Node[>..] = [];
    var dec: u8[>..]         = [];
    let root, err = json::parse(body, doc, dec);
    let u, ok = json::as_string(json::member(root, "username"));
    if !ok || u.len > 64 { return false; }
    for ch in u { if ch < 0x20 { return false; } }
    out.append(u);
    return true;
}

fn serve(p: const webauthn::Policy&, port: i64) {
    let fd = net::listen("127.0.0.1", port);
    if fd < 0 { fail(str("cannot listen on 127.0.0.1:", port)); }
    write_stderr(str("goose-webauthn: serving ", trim(p.origins), " (RP ID ", p.rp_id, "): open http://localhost:", port, "/\n"));
    var creds:           Stored[>..] = [];
    var reg_user:        u8[..64]    = [];
    var reg_handle:      u8[..64]    = [];
    var reg_challenge:   u8[..64]    = [];
    var login_challenge: u8[..64]    = [];
    var login_user:      u8[..64]    = [];
    loop {
        let c = net::accept(fd, 1000);
        if c < 0 { continue; }
        var hc = http::server_conn(http::server_options());
        var raw:     u8[16384] = [0; 16384];
        var buf:     u8[>..]   = [];
        var body:    u8[>..]   = [];
        var trailer: u8[>..]   = [];
        var out:     u8[>..]   = [];
        var target:  u8[>..]   = [];
        var complete = false;
        var failed = false;
        while !complete && !failed && body.len < 1048576 {
            let n = net::read(c, raw, 10000);
            if n <= 0 { break; }
            buf.append(raw[..n]);
            loop {
                let ev, h = http::server_read(hc, buf, body, trailer, out);
                if ev.kind == http::EV_REQUEST { target.append(buf[h.target.pos..h.target.end]); }
                if ev.kind == http::EV_ERROR || ev.kind == http::EV_CLOSED { failed = true; break; }
                var rest: u8[>..] = [];
                rest.append(buf[ev.used..]);
                buf.clear();
                buf.append(rest);
                complete = (ev.kind == http::EV_REQUEST || ev.kind == http::EV_END) && http::request_complete(hc);
                if complete || ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT { break; }
            }
        }
        if !complete { net::close(c); continue; }
        write_stderr(str("goose-webauthn: ", target, "\n"));
        if target[..] == "/" {
            answer(c, 200, "text/html; charset=utf-8", PAGE);
        } else if target[..] == "/register/begin" {
            var user: u8[>..] = [];
            if !username_of(body, user) || user.len == 0 {
                answer(c, 400, "application/json", json_result(false, "a user name, please"));
            } else {
                var o = webauthn::RegistrationOptions { .. };
                o.rp_id.append(p.rp_id);
                o.rp_name.append("goose-webauthn demo");
                o.user_name.append(user);
                o.user_display_name.append(user);
                // The user's handle: the one they have, or a new random one.
                var have = false;
                for s in creds { if s.user[..] == user[..] && !have { o.user_id.append(s.handle); have = true; } }
                if !have { webauthn::new_random(o.user_id); }
                o.resident_key = webauthn::REQ_REQUIRED;
                o.user_verification = p.user_verification;
                o.attestation = webauthn::CONVEY_DIRECT;
                var excl: webauthn::Descriptor[>..] = [];
                for s in creds {
                    if s.user[..] == user[..] {
                        var d = webauthn::Descriptor { .. };
                        d.id.append(s.id);
                        d.transports = s.transports;
                        excl.push(d);
                    }
                }
                let j, e = webauthn::registration_options(o, excl);
                reg_user.clear(); reg_user.append(user);
                reg_handle.clear(); reg_handle.append(o.user_id);
                reg_challenge.clear(); reg_challenge.append(o.challenge);
                answer(c, 200, "application/json", j);
            }
        } else if target[..] == "/register/finish" {
            var cr = webauthn::Credential { .. };
            let e = if reg_challenge.len == 0 { webauthn::ERR_CHALLENGE } else { webauthn::verify_registration(p, reg_challenge, body, "", cr) };
            reg_challenge.clear();
            if e != webauthn::OK {
                answer(c, 400, "application/json", json_result(false, str(webauthn::error_text(e), ": ", cr.message)));
            } else {
                var s = Stored { .. };
                s.user.append(reg_user);
                s.handle.append(reg_handle);
                s.id.append(cr.id);
                s.public_key.append(cr.public_key);
                s.alg = cr.alg;
                s.sign_count = cr.sign_count;
                s.backup_eligible = cr.backup_eligible;
                s.backed_up = cr.backed_up;
                s.transports = cr.transports;
                creds.push(s);
                answer(c, 200, "application/json", json_result(true, str("registered for ", reg_user, ": ", webauthn::format_name(cr.fmt),
                    " attestation (", webauthn::attestation_type_name(cr.attestation_type), "), ", cose::alg_name(cr.alg),
                    ", AAGUID ", webauthn::aaguid_text(cr.aaguid), ", discoverable ", cr.rk, ", backup eligible ", cr.backup_eligible)));
            }
        } else if target[..] == "/login/begin" {
            var user: u8[>..] = [];
            let named = username_of(body, user) && user.len > 0;
            var o = webauthn::AuthenticationOptions { .. };
            o.rp_id.append(p.rp_id);
            o.user_verification = p.user_verification;
            var allow: webauthn::Descriptor[>..] = [];
            if named {
                for s in creds {
                    if s.user[..] == user[..] {
                        var d = webauthn::Descriptor { .. };
                        d.id.append(s.id);
                        d.transports = s.transports;
                        allow.push(d);
                    }
                }
            }
            let j, e = webauthn::authentication_options(o, allow);
            login_challenge.clear(); login_challenge.append(o.challenge);
            login_user.clear();
            if named { login_user.append(user); }
            answer(c, 200, "application/json", j);
        } else if target[..] == "/login/finish" {
            var id: u8[>..] = [];
            var uh: u8[>..] = [];
            let er = webauthn::response_ids(body, id, uh);
            var found = false;
            var msg: u8[>..] = [];
            var ok = false;
            for &s in creds {
                if !found && er == webauthn::OK && s.id[..] == id[..] && login_challenge.len > 0 {
                    found = true;
                    var cr = webauthn::Credential { .. };
                    cr.id.append(s.id);
                    cr.public_key.append(s.public_key);
                    cr.alg = s.alg;
                    cr.sign_count = s.sign_count;
                    cr.backup_eligible = s.backup_eligible;
                    cr.backed_up = s.backed_up;
                    var r = webauthn::Assertion { .. };
                    // Without a user name, a passkey: the user handle must come.
                    let e = webauthn::verify_authentication(p, login_challenge, body, cr, s.handle, login_user.len == 0, r);
                    if e == webauthn::OK && (login_user.len == 0 || login_user[..] == s.user[..]) {
                        s.sign_count = r.sign_count;
                        s.backed_up = r.backed_up;
                        ok = true;
                        format(msg, "signed in as ", s.user, " (counter ", r.sign_count, if r.counter_regressed { ", did not go forward" } else { "" },
                               ", user verified ", r.uv, ", backed up ", r.backed_up, ")");
                    } else {
                        format(msg, webauthn::error_text(if e == webauthn::OK { webauthn::ERR_USER_HANDLE } else { e }), ": ", r.message);
                    }
                }
            }
            login_challenge.clear();
            if !found && msg.len == 0 { msg.append("no such credential here"); }
            answer(c, if ok { 200 } else { 400 }, "application/json", json_result(ok, msg));
        } else {
            answer(c, 404, "text/plain", "not found\n");
        }
        net::close(c);
    }
}

let PAGE: const u8[:] = """
    <!doctype html>
    <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
    <title>goose-webauthn demo</title>
    <style>body{font:16px system-ui,sans-serif;max-width:40em;margin:2em auto;padding:0 1em}
    input,button{font:inherit;padding:.3em .6em;margin:.2em}pre{background:#f4f4f4;padding:.6em;white-space:pre-wrap}</style>
    </head><body>
    <h1>goose-webauthn demo</h1>
    <p>A relying party for trying a passkey or a security key with gslib's webauthn.</p>
    <p><input id="user" placeholder="user name" autocomplete="username webauthn">
    <button onclick="register()">Register</button>
    <button onclick="login(true)">Sign in as this user</button>
    <button onclick="login(false)">Sign in with a passkey</button></p>
    <pre id="log"></pre>
    <script>
    const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
    const log = t => { document.getElementById('log').textContent += t + '\n'; };
    async function post(path, body) {
      const r = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
      return r.json();
    }
    function creationOptions(o) {
      if (PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(o);
      o.challenge = dec(o.challenge); o.user.id = dec(o.user.id);
      o.excludeCredentials = (o.excludeCredentials || []).map(c => ({...c, id: dec(c.id)}));
      return o;
    }
    function requestOptions(o) {
      if (PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(o);
      o.challenge = dec(o.challenge);
      o.allowCredentials = (o.allowCredentials || []).map(c => ({...c, id: dec(c.id)}));
      return o;
    }
    function toJSON(c) {
      try { return c.toJSON(); } catch (e) {}
      const r = c.response, out = {id: c.id, rawId: enc(c.rawId), type: c.type,
        authenticatorAttachment: c.authenticatorAttachment, clientExtensionResults: c.getClientExtensionResults(),
        response: {clientDataJSON: enc(r.clientDataJSON)}};
      if (r.attestationObject) {
        out.response.attestationObject = enc(r.attestationObject);
        out.response.transports = r.getTransports ? r.getTransports() : [];
      } else {
        out.response.authenticatorData = enc(r.authenticatorData);
        out.response.signature = enc(r.signature);
        if (r.userHandle) out.response.userHandle = enc(r.userHandle);
      }
      return out;
    }
    async function register() {
      try {
        const o = await post('/register/begin', {username: document.getElementById('user').value});
        if (o.ok === false) { log(o.message); return; }
        const c = await navigator.credentials.create({publicKey: creationOptions(o)});
        log((await post('/register/finish', toJSON(c))).message);
      } catch (e) { log('error: ' + e); }
    }
    async function login(named) {
      try {
        const o = await post('/login/begin', {username: named ? document.getElementById('user').value : ''});
        const c = await navigator.credentials.get({publicKey: requestOptions(o)});
        log((await post('/login/finish', toJSON(c))).message);
      } catch (e) { log('error: ' + e); }
    }
    </script>
    </body></html>
    """;
