// goose-saml: SAML 2.0 on gslib's saml, from the command line: metadata,
// a small service provider and a small test identity provider over HTTP,
// and a Response checked from a file.
//
//   goose-saml metadata sp|idp --base URL [--entity-id ID] [--cert FILE --key FILE] [--sign] [--enc-cert FILE]
//   goose-saml sp   --base URL --idp-metadata FILE [options] [--listen ADDR] --port N
//   goose-saml idp  --base URL --sp-metadata FILE [--sp-metadata FILE ...] --cert FILE --key FILE
//                   [--user NAME] [--attr NAME=VALUE ...] [options] [--listen ADDR] --port N
//   goose-saml verify --idp-metadata FILE --base URL (--in FILE | -) [--request-id ID] [--now TIME] [options]
//
// --base is the server's own URL (http://127.0.0.1:8001): its entityID is
// BASE/metadata unless --entity-id says otherwise, and its endpoints are
// BASE/acs and BASE/slo (an SP's) or BASE/sso and BASE/slo (an IdP's).
// Keys and certificates are PEM files. Options: --binding redirect|post
// (the SP's AuthnRequests and logouts; redirect by default),
// --sign-requests, --want-assertions-signed, --want-response-signed,
// --require-encrypted, --allow-idp-initiated, --allow-sha1, --allow-cbc
// (an SP's); --sign assertion|response|both, --encrypt,
// --want-signed-requests (an IdP's); --enc-cert FILE --enc-key FILE (an
// SP's decryption key, when not its signing key); --skew SECONDS;
// --metadata-cert FILE (the metadata given is signed, and verified with
// this certificate).
//
// The SP serves GET /metadata, GET /login[?RelayState=...] (an
// AuthnRequest to the IdP, the request ID kept), POST /acs (the Response
// checked: on success the verified assertion is printed on stdout as one
// line of JSON), GET /logout (a LogoutRequest for the last user), and
// GET and POST /slo (LogoutRequests and LogoutResponses, either binding).
// The IdP serves GET /metadata, GET and POST /sso (an AuthnRequest read
// and checked, answered for --user with its --attr values at once: a
// test IdP, it asks for no password), GET /init?sp=ENTITYID (an
// IdP-initiated Response), GET /logout?sp=ENTITYID[&binding=post] (a
// LogoutRequest to an SP), and GET and POST /slo. Both answer each
// request with Connection: close, one at a time, and log to stderr.
// Nothing secret is printed.
//
// Exit status: 0 on success, 1 on failure, 2 on a usage error.

import std;
import os;
import gslib from "../..";
import gslib.saml;
import gslib.saml.metadata;
import gslib.saml.logout;
import gslib.saml.sp;
import gslib.saml.idp;
import gslib.encoding.xml;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.net;
import gslib.net.http;
import gslib.net.http.conn1;
import gslib.net.http.url;
import gslib.dns;
import gslib.dns.server;

root struct Options {
    base:            u8[>..]   = [],
    entity_id:       u8[>..]   = [],
    cert:            u8[>..]   = [],
    key:             u8[>..]   = [],
    enc_cert:        u8[>..]   = [],
    enc_key:         u8[>..]   = [],
    idp_metadata:    u8[>..]   = [],
    sp_metadata:     u8[][>..] = [],
    metadata_cert:   u8[>..]   = [],
    input:           u8[>..]   = [],
    request_id:      u8[>..]   = [],
    user:            u8[>..]   = [],
    attrs:           u8[][>..] = [],
    listen:          u8[>..]   = [],
    port:            i64       = -1,
    binding:         i64       = 1,      // saml::BINDING_REDIRECT
    sign_metadata:   bool      = false,
    sign_requests:   bool      = false,
    want_asrt:       bool      = false,
    want_resp:       bool      = false,
    require_enc:     bool      = false,
    idp_initiated:   bool      = false,
    allow_sha1:      bool      = false,
    allow_cbc:       bool      = false,
    sign_assertion:  bool      = true,
    sign_response:   bool      = false,
    encrypt:         bool      = false,
    want_signed:     bool      = false,
    skew:            i64       = 120,
    now:             i64       = 0,
}

fn usage() -> i32 {
    write_stderr("usage: goose-saml metadata sp|idp | sp | idp | verify [options] (see the comment at the top of saml/tools/saml.goose)\n");
    return 2;
}

fn fail(s: const u8[:]) -> i32 {
    write_stderr(str("goose-saml: ", s, "\n"));
    return 1;
}

fn say(s: const u8[:]) { write_stderr(str("goose-saml: ", s, "\n")); }

fn read_or_fail(path: const u8[:], out: u8[>..]&) -> bool {
    if path == "-" { read_stdin(out); return true; }
    return read_file(path, out);
}

fn load_key(path: const u8[:]) -> x509::PrivateKey, bool {
    var t: u8[>..] = [];
    if !read_file(path, t) { return x509::empty_key(), false; }
    let k, ok = x509::parse_private_key_pem(t);
    return k, ok;
}

fn load_cert(path: const u8[:]) -> u8[>..], bool {
    var t: u8[>..] = [];
    var none: u8[>..] = [];
    if !read_file(path, t) { return none, false; }
    let c, e = x509::parse_pem(t);
    if e != x509::OK { return none, false; }
    return copy(c.der), true;
}

fn entity_id_of(o: const Options&) -> u8[>..] {
    if o.entity_id.len > 0 { return copy(o.entity_id); }
    return str(o.base, "/metadata");
}

// --- JSON -----------------------------------------------------------------------------

fn json_str(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    for c in s {
        if c == '"' { out.append("\\\""); }
        else if c == '\\' { out.append("\\\\"); }
        else if c == '\n' { out.append("\\n"); }
        else if c == '\r' { out.append("\\r"); }
        else if c == '\t' { out.append("\\t"); }
        else if c < 0x20 { out.append("\\u00"); out.push("0123456789abcdef"[c >> 4]); out.push("0123456789abcdef"[c & 15]); }
        else { out.push(c); }
    }
    out.push('"');
}

fn json_field(out: u8[>..]&, name: const u8[:], value: const u8[:]) {
    out.push(',');
    json_str(out, name);
    out.push(':');
    json_str(out, value);
}

fn assertion_json(a: const saml::Assertion&, out: u8[>..]&) {
    out.append("{\"event\":\"login\"");
    json_field(out, "name_id", a.name_id);
    json_field(out, "name_id_format", a.name_id_format);
    json_field(out, "issuer", a.issuer);
    json_field(out, "assertion_id", a.id);
    json_field(out, "in_response_to", a.in_response_to);
    json_field(out, "session_index", a.session_index);
    json_field(out, "authn_context", a.authn_context);
    json_field(out, "relay_state", a.relay_state);
    format(out, ",\"response_signed\":", a.response_signed, ",\"assertion_signed\":", a.assertion_signed,
           ",\"encrypted\":", a.encrypted, ",\"one_time_use\":", a.one_time_use, ",\"not_on_or_after\":", a.not_on_or_after,
           ",\"attributes\":{");
    var first = true;
    saml::each_attribute(a) { name, info =>
        if !first { out.push(','); }
        first = false;
        json_str(out, name);
        out.append(":[");
        var fv = true;
        var k: i64 = 0;
        for v in a.values {
            if k >= info.first && k < info.first + info.count {
                if !fv { out.push(','); }
                fv = false;
                json_str(out, v);
            }
            k++;
        }
        out.push(']');
    };
    out.append("}}");
}

fn emit(line: const u8[:]) {
    write_stdout(line);
    write_stdout("\n");
    flush_stdout();
}

// --- HTTP ------------------------------------------------------------------------------

// A request as the handlers see it, and what they answer.
root struct Req {
    method: u8[>..] = [],
    path:   u8[>..] = [],
    query:  u8[>..] = [],
    ctype:  u8[>..] = [],
    body:   u8[>..] = [],
}

root struct Reply {
    status:   i64     = 200,
    ctype:    u8[>..] = [],
    location: u8[>..] = [],
    body:     u8[>..] = [],
}

fn reply_text(r: Reply&, status: i64, text: const u8[:]) {
    r.status = status;
    r.ctype.clear();
    r.ctype.append("text/plain; charset=utf-8");
    r.body.clear();
    r.body.append(text);
    r.body.push('\n');
}

// An Outgoing message as the browser should get it: a redirect, or the page that posts.
fn reply_outgoing(r: Reply&, o: const saml::Outgoing&) {
    if o.binding == saml::BINDING_REDIRECT {
        // saml checks endpoint URLs; a header is still never split here.
        for c in o.url { if c == '\r' || c == '\n' || c == 0 { reply_text(r, 500, "a redirect URL with a line break"); return; } }
        r.status = 302;
        r.location.append(o.url);
        r.ctype.append("text/plain");
        r.body.append("redirecting\n");
    } else {
        r.status = 200;
        r.ctype.append("text/html; charset=utf-8");
        r.body.append(o.form);
    }
}

fn reason(status: i64) -> const u8[:] {
    if status == 200 { return "OK"; }
    if status == 302 { return "Found"; }
    if status == 400 { return "Bad Request"; }
    if status == 403 { return "Forbidden"; }
    if status == 404 { return "Not Found"; }
    if status == 405 { return "Method Not Allowed"; }
    return "Error";
}

fn listen(o: const Options&) -> i64 {
    let addr = if o.listen.len > 0 { o.listen[..] } else { "127.0.0.1" };
    let fd = dns::dnsnet_listen(addr, o.port as! i32, 1);
    if fd >= 0 { say(str("serving on ", addr, " port ", dns::dnsnet_local_port(fd))); }
    return fd;
}

// Reads one request from connection c into q; false when there is none.
fn read_request(c: i64, q: Req&) -> bool {
    var hc = http::server_conn(http::server_options());
    var raw: u8[16384] = [0; 16384];
    var buf: u8[>..] = [];
    var out: u8[>..] = [];
    var trailer: u8[>..] = [];
    var target: u8[>..] = [];
    loop {
        let n = net::read(c, raw, 10000);
        if n <= 0 { return false; }
        buf.append(raw[..n]);
        loop {
            let ev, h = http::server_read(hc, buf, q.body, trailer, out);
            if ev.kind == http::EV_REQUEST {
                q.method.clear();
                q.method.append(buf[h.method.pos..h.method.end]);
                target.clear();
                target.append(buf[h.target.pos..h.target.end]);
                q.ctype.clear();
                let s, has = http::get(buf, h, "content-type");
                if has { q.ctype.append(buf[s.pos..s.end]); }
                if ev.continue_expected { http::server_continue(hc, out); }
            }
            if ev.kind == http::EV_ERROR || ev.kind == http::EV_CLOSED { return false; }
            var rest: u8[>..] = [];
            rest.append(buf[ev.used..]);
            buf.clear();
            buf.append(rest);
            if (ev.kind == http::EV_REQUEST || ev.kind == http::EV_END) && http::request_complete(hc) {
                let qm = position(target, '?');
                q.path.clear();
                q.query.clear();
                if qm >= 0 { q.path.append(target[..qm]); q.query.append(target[qm + 1..]); } else { q.path.append(target); }
                return true;
            }
            if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT { break; }
        }
        if out.len > 0 { net::write(c, out, 10000); out.clear(); }
    }
    return false;
}

fn write_reply(c: i64, r: const Reply&) {
    var out: u8[>..] = [];
    format(out, "HTTP/1.1 ", r.status, " ", reason(r.status), "\r\n");
    if r.ctype.len > 0 { format(out, "Content-Type: ", r.ctype, "\r\n"); }
    if r.location.len > 0 { format(out, "Location: ", r.location, "\r\n"); }
    format(out, "Content-Length: ", r.body.len, "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    out.append(r.body);
    net::write(c, out, 10000);
}

fn query_value(q: const u8[:], name: const u8[:]) -> u8[>..] {
    let v, has = http::query_value(q, name);
    return v;
}

// --- The service provider -------------------------------------------------------------

fn sp_setup(o: const Options&, sp: saml::Sp&) -> i32 {
    sp.entity_id.append(entity_id_of(o));
    sp.acs_url.append(str(o.base, "/acs"));
    sp.slo_url.append(str(o.base, "/slo"));
    if o.key.len > 0 {
        let k, okk = load_key(o.key);
        let c, okc = load_cert(o.cert);
        if !okk || !okc { return fail("cannot read --key or --cert"); }
        saml::sp_set_key(sp, k, c);
    }
    if o.enc_key.len > 0 {
        let k, okk = load_key(o.enc_key);
        let c, okc = load_cert(o.enc_cert);
        if !okk || !okc { return fail("cannot read --enc-key or --enc-cert"); }
        sp.has_enc_key = true;
        sp.enc_key = k;
        sp.enc_cert_der.append(c);
    }
    sp.sign_requests = o.sign_requests;
    sp.want_assertions_signed = o.want_asrt;
    sp.want_response_signed = o.want_resp;
    sp.require_encrypted = o.require_enc;
    sp.allow_idp_initiated = o.idp_initiated;
    sp.allow_sha1 = o.allow_sha1;
    sp.allow_cbc = o.allow_cbc;
    sp.clock_skew = o.skew;
    sp.now = o.now;
    return 0;
}

fn load_peer(o: const Options&, path: const u8[:], e: saml::Entity&) -> i32 {
    var t: u8[>..] = [];
    if !read_file(path, t) { return fail(str("cannot read ", path)); }
    var r: i64 = 0;
    if o.metadata_cert.len > 0 {
        var ct: u8[>..] = [];
        if !read_file(o.metadata_cert, ct) { return fail("cannot read --metadata-cert"); }
        let c, ce = x509::parse_pem(ct);
        if ce != x509::OK { return fail("--metadata-cert is not a certificate"); }
        r = saml::parse_metadata_signed(e, t, "", c, saml::now_or(o.now));
    } else {
        r = saml::parse_metadata(e, t, "");
    }
    if r != saml::OK { return fail(str(path, ": ", saml::error_text(r), ": ", e.message)); }
    return 0;
}

// The InResponseTo of a Response, unverified: which of our requests it
// claims to answer (process_response then checks it).
// A replay cache's check: whether id is new, remembered if it is.
fn remember(seen: u8[][>..]&, id: const u8[:]) -> bool {
    for s in seen { if s == id { return false; } }
    var x: u8[>..] = [];
    x.append(id);
    seen.push(copy(x));
    return true;
}

fn claimed_in_response_to(xml_text: const u8[:]) -> u8[>..] {
    var d = xml::Doc { .. };
    var out: u8[>..] = [];
    if xml::parse(d, xml_text).code != xml::OK { return out; }
    let v, has = xml::attr(d, xml::root_element(d), "InResponseTo");
    if has { out.append(v); }
    return out;
}

fn run_sp(o: const Options&) -> i32 {
    var sp = saml::Sp { .. };
    let se = sp_setup(o, sp);
    if se != 0 { return se; }
    var idp = saml::Entity { .. };
    if o.idp_metadata.len == 0 { return usage(); }
    let le = load_peer(o, o.idp_metadata, idp);
    if le != 0 { return le; }
    let fd = listen(o);
    if fd < 0 { return fail("cannot listen"); }
    var pending: u8[][>..] = [];       // AuthnRequest IDs sent, not yet answered
    var seen: u8[][>..] = [];          // assertion IDs taken (a test tool: kept for the run)
    var pending_logout: u8[>..] = [];
    var last = saml::LogoutSubject { .. };
    var has_last = false;
    loop {
        let c = dns::dnsnet_accept(fd, 1000);
        if c < 0 { continue; }
        var q = Req { .. };
        var r = Reply { .. };
        if !read_request(c, q) { net::close(c); continue; }
        say(str(q.method, " ", q.path));
        if q.path[..] == "/metadata" {
            var md: u8[>..] = [];
            let e = saml::sp_metadata(sp, o.sign_metadata, md);
            if e != saml::OK { reply_text(r, 500, saml::error_text(e)); }
            else { r.ctype.append("application/samlmetadata+xml"); r.body.append(md); }
        } else if q.path[..] == "/login" {
            let relay = query_value(q.query, "RelayState");
            var out = saml::Outgoing { .. };
            let e = saml::authn_request(sp, idp, o.binding, relay, out);
            if e != saml::OK { reply_text(r, 500, str("no AuthnRequest: ", saml::error_text(e))); }
            else {
                if pending.len >= 1000 { pending.clear(); }
                pending.push(copy(out.id));
                reply_outgoing(r, out);
            }
        } else if q.path[..] == "/acs" {
            var m = saml::Received { .. };
            let re = saml::read_post(m, q.body, sp.max_message);
            if re != saml::OK { reply_text(r, 400, str("bad SAML POST: ", m.message)); }
            else {
                let claimed = claimed_in_response_to(m.xml);
                var request_id: u8[>..] = [];
                for p in pending { if claimed.len > 0 && p == claimed[..] { request_id.append(p); } }
                if claimed.len > 0 && request_id.len == 0 { request_id.append("(unknown request)"); }
                var a = saml::Assertion { .. };
                let e = saml::process_response_replay(sp, idp, m, request_id, a) { id, until =>
                    var known = false;
                    for s in seen { if s == id { known = true; } }
                    if !known { var x: u8[>..] = []; x.append(id); seen.push(copy(x)); }
                    !known
                };
                if e != saml::OK {
                    say(str("refused: ", saml::error_text(e), ": ", a.message));
                    var line: u8[>..] = [];
                    line.append("{\"event\":\"refused\"");
                    json_field(line, "error", saml::error_text(e));
                    json_field(line, "message", a.message);
                    line.push('}');
                    emit(line);
                    reply_text(r, 403, str("refused: ", saml::error_text(e), ": ", a.message));
                } else {
                    var line: u8[>..] = [];
                    assertion_json(a, line);
                    emit(line);
                    let w, okw = saml::logout_subject_of(a);
                    if okw { last = w; has_last = true; }
                    reply_text(r, 200, str("logged in as ", a.name_id));
                }
            }
        } else if q.path[..] == "/logout" {
            if !has_last { reply_text(r, 400, "nobody is logged in"); }
            else {
                var out = saml::Outgoing { .. };
                let e = saml::sp_logout_request(sp, idp, o.binding, last, "", out);
                if e != saml::OK { reply_text(r, 500, str("no LogoutRequest: ", saml::error_text(e))); }
                else { pending_logout.clear(); pending_logout.append(out.id); reply_outgoing(r, out); }
            }
        } else if q.path[..] == "/slo" {
            var m = saml::Received { .. };
            let re = if q.method[..] == "POST" { saml::read_post(m, q.body, sp.max_message) } else { saml::read_redirect(m, q.query, sp.max_message) };
            if re != saml::OK { reply_text(r, 400, str("bad SAML message: ", m.message)); }
            else if m.is_request {
                var msg = saml::Message { .. };
                let e = saml::sp_read_logout_request_replay(sp, idp, m, msg) { id, until => remember(seen, id) };
                var line: u8[>..] = [];
                line.append("{\"event\":\"logout-request\"");
                json_field(line, "result", saml::error_text(e));
                json_field(line, "name_id", msg.name_id);
                json_field(line, "message", msg.message);
                line.push('}');
                emit(line);
                if e != saml::OK { reply_text(r, 403, str("refused: ", msg.message)); }
                else {
                    has_last = false;
                    var out = saml::Outgoing { .. };
                    let e2 = saml::sp_logout_response(sp, idp, m.binding, msg.id, saml::STATUS_SUCCESS, m.relay_state, out);
                    if e2 != saml::OK { reply_text(r, 500, saml::error_text(e2)); } else { reply_outgoing(r, out); }
                }
            } else {
                var msg = saml::Message { .. };
                let e = saml::sp_read_logout_response(sp, idp, m, pending_logout, msg);
                var line: u8[>..] = [];
                line.append("{\"event\":\"logout-response\"");
                json_field(line, "result", saml::error_text(e));
                json_field(line, "status", msg.status);
                json_field(line, "message", msg.message);
                line.push('}');
                emit(line);
                if e == saml::OK { has_last = false; pending_logout.clear(); reply_text(r, 200, "logged out"); }
                else { reply_text(r, 403, str("refused: ", msg.message)); }
            }
        } else {
            reply_text(r, 404, "not found");
        }
        write_reply(c, r);
        net::close(c);
    }
    return 0;
}

// --- The identity provider ----------------------------------------------------------

fn idp_setup(o: const Options&, idp: saml::Idp&) -> i32 {
    idp.entity_id.append(entity_id_of(o));
    idp.sso_url.append(str(o.base, "/sso"));
    idp.slo_url.append(str(o.base, "/slo"));
    let k, okk = load_key(o.key);
    let c, okc = load_cert(o.cert);
    if !okk || !okc { return fail("cannot read --key or --cert"); }
    saml::idp_set_key(idp, k, c);
    idp.sign_assertion = o.sign_assertion;
    idp.sign_response = o.sign_response;
    idp.encrypt = o.encrypt;
    idp.want_authn_requests_signed = o.want_signed;
    idp.allow_sha1 = o.allow_sha1;
    idp.clock_skew = o.skew;
    idp.now = o.now;
    idp.name_id_formats.push(str(saml::NAMEID_UNSPECIFIED));
    idp.name_id_formats.push(str(saml::NAMEID_EMAIL));
    return 0;
}

// The SP's metadata, of those given, with this entityID.
fn find_sp(o: const Options&, entity_id: const u8[:], e: saml::Entity&) -> bool {
    for path in o.sp_metadata {
        var t: u8[>..] = [];
        if !read_file(path, t) { continue; }
        if saml::parse_metadata(e, t, "") == saml::OK && e.entity_id[..] == entity_id { return true; }
    }
    return false;
}

fn the_user(o: const Options&, user: saml::Login&, session: const u8[:]) {
    user.name_id.append(if o.user.len > 0 { o.user[..] } else { "alice@example.test" });
    user.name_id_format.append(saml::NAMEID_EMAIL);
    user.session_index.append(session);
    user.attr_name_format.append(saml::ATTRNAME_BASIC);
    for a in o.attrs {
        let n, v, has = split_once(a, '=');
        saml::add_value(user, n, v);
    }
}

fn run_idp(o: const Options&) -> i32 {
    var idp = saml::Idp { .. };
    let se = idp_setup(o, idp);
    if se != 0 { return se; }
    if o.sp_metadata.len == 0 { return usage(); }
    let fd = listen(o);
    if fd < 0 { return fail("cannot listen"); }
    let session = saml::new_id();
    var pending_logout: u8[>..] = [];
    var seen_logout: u8[][>..] = [];   // LogoutRequest IDs taken (a test tool: kept for the run)
    loop {
        let c = dns::dnsnet_accept(fd, 1000);
        if c < 0 { continue; }
        var q = Req { .. };
        var r = Reply { .. };
        if !read_request(c, q) { net::close(c); continue; }
        say(str(q.method, " ", q.path));
        if q.path[..] == "/metadata" {
            var md: u8[>..] = [];
            let e = saml::idp_metadata(idp, o.sign_metadata, md);
            if e != saml::OK { reply_text(r, 500, saml::error_text(e)); }
            else { r.ctype.append("application/samlmetadata+xml"); r.body.append(md); }
        } else if q.path[..] == "/sso" || q.path[..] == "/slo" {
            var m = saml::Received { .. };
            let re = if q.method[..] == "POST" { saml::read_post(m, q.body, idp.max_message) } else { saml::read_redirect(m, q.query, idp.max_message) };
            var who: u8[>..] = [];
            var sp = saml::Entity { .. };
            if re != saml::OK { reply_text(r, 400, str("bad SAML message: ", m.message)); }
            else if saml::peek_issuer(m, who) != saml::OK || !find_sp(o, who, sp) { reply_text(r, 403, str("unknown service provider ", who)); }
            else if q.path[..] == "/sso" {
                var req = saml::Message { .. };
                let e = saml::idp_read_authn_request(idp, sp, m, req);
                var line: u8[>..] = [];
                line.append("{\"event\":\"authn-request\"");
                json_field(line, "result", saml::error_text(e));
                json_field(line, "sp", who);
                json_field(line, "id", req.id);
                json_field(line, "message", req.message);
                format(line, ",\"signed\":", req.signed, "}");
                emit(line);
                if e != saml::OK { reply_text(r, 403, str("refused: ", saml::error_text(e), ": ", req.message)); }
                else {
                    var user = saml::Login { .. };
                    the_user(o, user, session);
                    var out = saml::Outgoing { .. };
                    let e2 = saml::idp_response(idp, sp, req, user, out);
                    if e2 != saml::OK { reply_text(r, 500, str("no Response: ", saml::error_text(e2))); } else { reply_outgoing(r, out); }
                }
            } else if m.is_request {
                var msg = saml::Message { .. };
                let e = saml::idp_read_logout_request_replay(idp, sp, m, msg) { id, until => remember(seen_logout, id) };
                var line: u8[>..] = [];
                line.append("{\"event\":\"logout-request\"");
                json_field(line, "result", saml::error_text(e));
                json_field(line, "sp", who);
                json_field(line, "name_id", msg.name_id);
                json_field(line, "message", msg.message);
                line.push('}');
                emit(line);
                if e != saml::OK { reply_text(r, 403, str("refused: ", msg.message)); }
                else {
                    var out = saml::Outgoing { .. };
                    let e2 = saml::idp_logout_response(idp, sp, m.binding, msg.id, saml::STATUS_SUCCESS, m.relay_state, out);
                    if e2 != saml::OK { reply_text(r, 500, saml::error_text(e2)); } else { reply_outgoing(r, out); }
                }
            } else {
                var msg = saml::Message { .. };
                let e = saml::idp_read_logout_response(idp, sp, m, pending_logout, msg);
                var line: u8[>..] = [];
                line.append("{\"event\":\"logout-response\"");
                json_field(line, "result", saml::error_text(e));
                json_field(line, "status", msg.status);
                json_field(line, "message", msg.message);
                line.push('}');
                emit(line);
                if e == saml::OK { reply_text(r, 200, "logged out"); } else { reply_text(r, 403, str("refused: ", msg.message)); }
            }
        } else if q.path[..] == "/init" || q.path[..] == "/logout" {
            let spid = query_value(q.query, "sp");
            var sp = saml::Entity { .. };
            if !find_sp(o, spid, sp) { reply_text(r, 404, str("unknown service provider ", spid)); }
            else if q.path[..] == "/init" {
                var user = saml::Login { .. };
                the_user(o, user, session);
                var out = saml::Outgoing { .. };
                let e = saml::idp_unsolicited_response(idp, sp, user, query_value(q.query, "RelayState"), out);
                if e != saml::OK { reply_text(r, 500, saml::error_text(e)); } else { reply_outgoing(r, out); }
            } else {
                var who = saml::LogoutSubject { .. };
                format(who.name_id, if o.user.len > 0 { o.user[..] } else { "alice@example.test" });
                format(who.format, saml::NAMEID_EMAIL);
                format(who.session_index, session);
                let b = if query_value(q.query, "binding")[..] == "post" { saml::BINDING_POST } else { saml::BINDING_REDIRECT };
                var out = saml::Outgoing { .. };
                let e = saml::idp_logout_request(idp, sp, b, who, "", out);
                if e != saml::OK { reply_text(r, 500, saml::error_text(e)); }
                else { pending_logout.clear(); pending_logout.append(out.id); reply_outgoing(r, out); }
            }
        } else {
            reply_text(r, 404, "not found");
        }
        write_reply(c, r);
        net::close(c);
    }
    return 0;
}

// --- verify and metadata --------------------------------------------------------------

fn run_verify(o: const Options&) -> i32 {
    var sp = saml::Sp { .. };
    let se = sp_setup(o, sp);
    if se != 0 { return se; }
    var idp = saml::Entity { .. };
    if o.idp_metadata.len == 0 || o.input.len == 0 { return usage(); }
    let le = load_peer(o, o.idp_metadata, idp);
    if le != 0 { return le; }
    var text: u8[>..] = [];
    if !read_or_fail(o.input, text) { return fail(str("cannot read ", o.input)); }
    var m = saml::Received { .. };
    // A file of XML, or a form body (SAMLResponse=...).
    let t = trim(text);
    let re = if t.len > 0 && t[0] == '<' { saml::read_xml(m, false, t, sp.max_message) } else { saml::read_post(m, t, sp.max_message) };
    if re != saml::OK { return fail(str(saml::error_text(re), ": ", m.message)); }
    var a = saml::Assertion { .. };
    let e = saml::process_response(sp, idp, m, o.request_id, a);
    if e != saml::OK { return fail(str(saml::error_text(e), ": ", a.message)); }
    var line: u8[>..] = [];
    assertion_json(a, line);
    emit(line);
    return 0;
}

fn run_metadata(o: const Options&, role: const u8[:]) -> i32 {
    var md: u8[>..] = [];
    var e: i64 = 0;
    if role == "sp" {
        var sp = saml::Sp { .. };
        let se = sp_setup(o, sp);
        if se != 0 { return se; }
        e = saml::sp_metadata(sp, o.sign_metadata, md);
    } else if role == "idp" {
        var idp = saml::Idp { .. };
        let se = idp_setup(o, idp);
        if se != 0 { return se; }
        e = saml::idp_metadata(idp, o.sign_metadata, md);
    } else {
        return usage();
    }
    if e != saml::OK { return fail(saml::error_text(e)); }
    write_stdout(md);
    write_stdout("\n");
    return 0;
}

// --- Arguments ----------------------------------------------------------------------------

fn run() -> i32 {
    let a = args();
    if a.len < 2 { return usage(); }
    let command = a[1];
    var o = Options { .. };
    var i = 2;
    var role: u8[>..] = [];
    if command == "metadata" {
        if a.len < 3 { return usage(); }
        role.append(a[2]);
        i = 3;
    }
    while i < a.len {
        let s = a[i];
        if s == "--sign" && command == "metadata" { o.sign_metadata = true; }
        else if s == "--sign-requests" { o.sign_requests = true; }
        else if s == "--want-assertions-signed" { o.want_asrt = true; }
        else if s == "--want-response-signed" { o.want_resp = true; }
        else if s == "--require-encrypted" { o.require_enc = true; }
        else if s == "--allow-idp-initiated" { o.idp_initiated = true; }
        else if s == "--allow-sha1" { o.allow_sha1 = true; }
        else if s == "--allow-cbc" { o.allow_cbc = true; }
        else if s == "--encrypt" { o.encrypt = true; }
        else if s == "--want-signed-requests" { o.want_signed = true; }
        else if s == "--sign-metadata" { o.sign_metadata = true; }
        else {
            i++;
            if i >= a.len { return usage(); }
            let v = a[i];
            if s == "--base" { o.base.append(v); }
            else if s == "--entity-id" { o.entity_id.append(v); }
            else if s == "--cert" { o.cert.append(v); }
            else if s == "--key" { o.key.append(v); }
            else if s == "--enc-cert" { o.enc_cert.append(v); }
            else if s == "--enc-key" { o.enc_key.append(v); }
            else if s == "--idp-metadata" { o.idp_metadata.append(v); }
            else if s == "--sp-metadata" { o.sp_metadata.push(str(v)); }
            else if s == "--metadata-cert" { o.metadata_cert.append(v); }
            else if s == "--in" { o.input.append(v); }
            else if s == "--request-id" { o.request_id.append(v); }
            else if s == "--user" { o.user.append(v); }
            else if s == "--attr" { if position(v, '=') <= 0 { return usage(); } o.attrs.push(str(v)); }
            else if s == "--listen" { o.listen.append(v); }
            else if s == "--port" { let n, ok = parse_int(v); if !ok || n < 0 || n > 65535 { return usage(); } o.port = n; }
            else if s == "--skew" { let n, ok = parse_int(v); if !ok || n < 0 { return usage(); } o.skew = n; }
            else if s == "--now" { let t, ok = saml::parse_time(v); if !ok { return usage(); } o.now = t; }
            else if s == "--binding" {
                if v == "redirect" { o.binding = saml::BINDING_REDIRECT; }
                else if v == "post" { o.binding = saml::BINDING_POST; }
                else { return usage(); }
            }
            else if s == "--sign" {
                o.sign_assertion = v == "assertion" || v == "both";
                o.sign_response = v == "response" || v == "both";
                if !o.sign_assertion && !o.sign_response { return usage(); }
            }
            else { return usage(); }
        }
        i++;
    }
    if o.base.len == 0 { return usage(); }
    if command == "metadata" { return run_metadata(o, role); }
    if command == "verify" { return run_verify(o); }
    if o.port < 0 { return usage(); }
    if command == "sp" { return run_sp(o); }
    if command == "idp" { return run_idp(o); }
    return usage();
}

fn main() { exit(run()); }
