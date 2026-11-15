// rp_server: the smallest useful relying party with passkeys. It serves
// http://localhost:8080: a page whose buttons register a passkey for a
// user name and sign in with it (with the name, or as a passkey that
// names the user itself); POST /register/begin and /login/begin answer
// with options, /register/finish and /login/finish check what the
// browser's authenticator made. Credentials are kept in memory. One
// request at a time, an answer each, the connection closed. Needs a
// browser and an authenticator, so `make test` only type-checks it;
// goose-webauthn serve is the same with more options.
//
//   goose examples/webauthn/rp_server.goose [-- PORT]

import std;
import os;
import json;
import gslib from "../..";
import gslib.webauthn;
import gslib.webauthn.register;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.jwx;
import gslib.net;
import gslib.net.http;
import gslib.net.http.conn1;
import gslib.dns;
import gslib.dns.server;

fn fail(s: const u8[:]) {
    print("rp_server: ", s);
    exit(1);
}

fn main() {
    let a = args();
    var port: i64 = 8080;
    if a.len > 1 {
        let n, ok = parse_int(a[1]);
        guard ok && n > 0 && n < 65536 else { print("usage: rp_server [PORT]"); exit(2); }
        port = n;
    }
    var p = webauthn::Policy { .. };
    let ok1 = webauthn::set_rp(p, "localhost");
    let ok2 = webauthn::add_origin(p, str("http://localhost:", port));
    serve(p, port);
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
    let fd = dns::dnsnet_listen("127.0.0.1", port as i32, 8);
    if fd < 0 { fail(str("cannot listen on 127.0.0.1:", port)); }
    write_stderr(str("rp_server: serving ", trim(p.origins), " (RP ID ", p.rp_id, "): open http://localhost:", port, "/\n"));
    var creds:           Stored[>..] = [];
    var reg_user:        u8[..64]    = [];
    var reg_handle:      u8[..64]    = [];
    var reg_challenge:   u8[..64]    = [];
    var login_challenge: u8[..64]    = [];
    var login_user:      u8[..64]    = [];
    loop {
        let c = dns::dnsnet_accept(fd, 1000);
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
        write_stderr(str("rp_server: ", target, "\n"));
        if target[..] == "/" {
            answer(c, 200, "text/html; charset=utf-8", PAGE);
        } else if target[..] == "/register/begin" {
            var user: u8[>..] = [];
            if !username_of(body, user) || user.len == 0 {
                answer(c, 400, "application/json", json_result(false, "a user name, please"));
            } else {
                var o = webauthn::RegistrationOptions { .. };
                o.rp_id.append(p.rp_id);
                o.rp_name.append("rp_server");
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
    <title>rp_server</title>
    <style>body{font:16px system-ui,sans-serif;max-width:40em;margin:2em auto;padding:0 1em}
    input,button{font:inherit;padding:.3em .6em;margin:.2em}pre{background:#f4f4f4;padding:.6em;white-space:pre-wrap}</style>
    </head><body>
    <h1>rp_server</h1>
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
