// sp_server: the smallest useful service provider. It serves
// http://127.0.0.1:8001: /login sends the browser to the IdP with an
// AuthnRequest (Redirect binding), whose ID it keeps for that browser (a
// session cookie); /acs takes the Response the IdP's page posts, checks it
// against the IdP's metadata and the request that browser's session sent
// (each request answered once), refuses a replayed assertion, and greets
// the user. One request at a
// time, an answer each, the connection closed. Needs an IdP (goose-saml
// idp, for one), so `make test` only type-checks it.
//
//   goose examples/saml/sp_server.goose -- idp-metadata.xml sp.key sp.crt

import std;
import os;
import gslib from "../..";
import gslib.saml;
import gslib.saml.metadata;
import gslib.saml.logout;
import gslib.saml.sp;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.net;
import gslib.net.http;
import gslib.net.http.conn1;

fn answer(c: i64, status: i64, extra: const u8[:], ctype: const u8[:], body: const u8[:]) {
    var out: u8[>..] = [];
    format(out, "HTTP/1.1 ", status, if status == 200 { " OK" } else if status == 302 { " Found" } else { " Error" }, "\r\n", extra,
           "Content-Type: ", ctype, "\r\nContent-Length: ", body.len, "\r\nConnection: close\r\n\r\n", body);
    net::write(c, out, 10000);
}

// The value of the cookie `name` in a Cookie header, into out.
fn cookie_value(header: const u8[:], name: const u8[:], out: u8[>..]&) {
    var i = 0;
    while i < header.len {
        var e = i;
        while e < header.len && header[e] != ';' { e++; }
        var s = i;
        while s < e && header[s] == ' ' { s++; }
        let pair = header[s..e];
        if pair.len > name.len && pair[..name.len] == name && pair[name.len] == '=' { out.clear(); out.append(pair[name.len + 1..]); return; }
        i = e + 1;
    }
}

fn main() {
    let a = args();
    guard a.len == 4 else { print("usage: sp_server idp-metadata.xml sp.key sp.crt"); exit(2); }
    var sp = saml::Sp { .. };
    sp.entity_id.append("http://127.0.0.1:8001/metadata");
    sp.acs_url.append("http://127.0.0.1:8001/acs");
    var kt: u8[>..] = [];
    var ct: u8[>..] = [];
    var mt: u8[>..] = [];
    guard read_file(a[1], mt) && read_file(a[2], kt) && read_file(a[3], ct) else { print("cannot read the files"); exit(1); }
    let key, okk = x509::parse_private_key_pem(kt);
    let cert, ce = x509::parse_pem(ct);
    guard okk && ce == x509::OK else { print("bad key or certificate"); exit(1); }
    saml::sp_set_key(sp, key, cert.der);
    var idp = saml::Entity { .. };
    guard saml::parse_metadata(idp, mt, "") == saml::OK else { print("bad IdP metadata: ", idp.message); exit(1); }

    // The AuthnRequests sent, not yet answered: "session request-id" (both
    // saml::new_id()s, no spaces), the session the browser's cookie.
    var pending: u8[][>..] = [];
    var seen: u8[][>..] = [];         // the assertions taken
    let fd = net::listen("127.0.0.1", 8001);
    guard fd >= 0 else { print("cannot listen"); exit(1); }
    loop {
        let c = net::accept(fd, 1000);
        if c < 0 { continue; }
        // Read one request.
        var hc = http::server_conn(http::server_options());
        var raw: u8[16384] = [0; 16384];
        var buf: u8[>..] = [];
        var body: u8[>..] = [];
        var trailer: u8[>..] = [];
        var out: u8[>..] = [];
        var target: u8[>..] = [];
        var session: u8[>..] = [];        // the browser's saml_session cookie
        var complete = false;
        var failed = false;
        while !complete && !failed {
            let n = net::read(c, raw, 10000);
            if n <= 0 { break; }
            buf.append(raw[..n]);
            // Every event the bytes so far make: the head, the body, its end.
            loop {
                let ev, h = http::server_read(hc, buf, body, trailer, out);
                if ev.kind == http::EV_REQUEST {
                    target.append(buf[h.target.pos..h.target.end]);
                    let cv, hasc = http::get(buf, h, "Cookie");
                    if hasc { cookie_value(buf[cv.pos..cv.end], "saml_session", session); }
                }
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
        if starts_with(target, "/login") {
            var req = saml::Outgoing { .. };
            // saml checks endpoint URLs; a header is still never split here.
            if saml::authn_request(sp, idp, saml::BINDING_REDIRECT, "", req) == saml::OK && position(req.url, '\r') < 0 && position(req.url, '\n') < 0 {
                let sid = saml::new_id();
                if pending.len >= 1000 { pending.clear(); }
                pending.push(str(sid, " ", req.id));
                // SameSite=None: the IdP's page posts to /acs from another site.
                answer(c, 302, str("Location: ", req.url, "\r\nSet-Cookie: saml_session=", sid,
                                   "; Path=/acs; HttpOnly; Secure; SameSite=None\r\n"), "text/plain", "");
            } else {
                answer(c, 500, "", "text/plain", "no AuthnRequest\n");
            }
        } else if target[..] == "/acs" {
            var m = saml::Received { .. };
            var a = saml::Assertion { .. };
            var e = saml::read_post(m, body, sp.max_message);
            // The request this browser's session sent, taken off the list
            // whatever the answer: each is answered once.
            var request_id: u8[>..] = [];
            var left: u8[][>..] = [];
            for p in pending {
                let sp_at = position(p, ' ');
                if session.len > 0 && request_id.len == 0 && p[..sp_at] == session[..] { request_id.append(p[sp_at + 1..]); }
                else { left.push(copy(p)); }
            }
            pending = copy(left);
            if e == saml::OK && request_id.len == 0 { e = saml::ERR_IN_RESPONSE_TO; }
            if e == saml::OK {
                e = saml::process_response_replay(sp, idp, m, request_id, a) { aid, until =>
                    var known = false;
                    for s in seen { if s == aid { known = true; } }
                    if !known { seen.push(str(aid)); }
                    !known
                };
            }
            if e == saml::OK { answer(c, 200, "", "text/plain", str("hello, ", a.name_id, "\n")); }
            else { answer(c, 403, "", "text/plain", str("refused: ", saml::error_text(e), ": ", a.message, "\n")); }
        } else {
            answer(c, 404, "", "text/plain", "not found\n");
        }
        net::close(c);
    }
}
