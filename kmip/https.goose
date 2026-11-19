// kmip.https: KMIP over HTTPS (KMIP Profiles 2.1 §5.3), each message the
// body of an HTTP/1.1 POST, by default to /kmip, in TTLV
// (application/octet-stream), XML (text/xml) or JSON (application/json),
// with Content-Length and Cache-Control: no-cache, over the same TLS as
// KMIP's own port, client certificate and KMIP's suites included.
//
//   var c, e = kmip::https_dial("kms.example.com", 443, "/kmip", kmip::MSG_JSON, cc);
//   let uid, ec = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);   // every operation of kmip.client
//
// The server's side, for a program that has a TLS connection's plaintext
// (goose-kmipd --http): http_serve reads the requests in it, answers each
// with kmip.server's handle, in the encoding it came in, and says how much
// it used.

namespace kmip;

import std;
import net;
import crypto.tls;
import crypto.tls.handshake;
import net.http;
import net.http.h1;
import net.http.conn1;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.client;
import kmip.server;
import kmip.xml;
import kmip.json;

// The message encodings.
let MSG_TTLV: u8 = 1;
let MSG_XML: u8 = 2;
let MSG_JSON: u8 = 3;

fn content_type(enc: u8) -> const u8[:] {
    if enc == MSG_XML { return "text/xml"; }
    if enc == MSG_JSON { return "application/json"; }
    return "application/octet-stream";
}

// The encoding a Content-Type names (its parameters aside), or 0.
fn encoding_of(ct: const u8[:]) -> u8 {
    var k = 0;
    while k < ct.len && ct[k] != ';' { k++; }
    let t = http::trim_ows(ct[..k]);
    if http::eq_fold(t, "application/octet-stream") { return MSG_TTLV; }
    if http::eq_fold(t, "text/xml") || http::eq_fold(t, "application/xml") { return MSG_XML; }
    if http::eq_fold(t, "application/json") { return MSG_JSON; }
    return 0;
}

// A TTLV message in an encoding, onto out.
fn encode_as(enc: u8, ttlv: const u8[:], out: u8[>..]&) -> i64 {
    if enc == MSG_XML { return ttlv_to_xml(ttlv, out); }
    if enc == MSG_JSON { return ttlv_to_json(ttlv, out); }
    out.append(ttlv);
    return OK;
}

// A message in an encoding as TTLV, onto out.
fn decode_as(enc: u8, text: const u8[:], out: u8[>..]&) -> i64 {
    var why: u8[>..] = [];
    if enc == MSG_XML { return from_xml(text, out, Options { .. }, why); }
    if enc == MSG_JSON { return from_json(text, out, Options { .. }, why); }
    out.append(text);
    return OK;
}

// --- The client -------------------------------------------------------------------

// A client whose messages go by HTTPS. The fields the operations use are
// kmip::Client's; link is the TLS connection.
struct HttpClient {
    version: Version,          // what requests are sent as: 1.2 until negotiate or set
    cred: Credential,
    last_status: u32,
    last_reason: u32,
    last_message: u8[..1024],
    encoding: u8,              // MSG_TTLV, MSG_XML or MSG_JSON
    http_status: i64,          // the last response's HTTP status
    host: u8[..300],           // the Host field
    path: u8[..1024],          // the target, /kmip
    hc: http::ClientConn,
    link: Client,
}

// A client of the KMIP server at https://host:port/path, its messages in
// the encoding enc, the TLS as kmip::dial does it with cc.
fn https_dial(host: const u8[:], port: i64, path: const u8[:], enc: u8, cc: const tls::ClientConfig&) -> HttpClient, i64 {
    let link, e = dial(host, port, cc);
    var c = HttpClient {
        version: V1_2, cred: no_credential(), last_status: 0, last_reason: 0, last_message: [],
        encoding: if enc == 0 { MSG_TTLV } else { enc }, http_status: 0, host: [], path: [],
        hc: http::client_conn(), link: copy(link),
    };
    c.host.append(host[..::min(host.len, 250)]);
    if port != 443 {
        c.host.push(':');
        format_int(c.host, port, 10, 0, ' ');
    }
    c.path.append(if path.len > 0 { path[..::min(path.len, 1024)] } else { "/kmip" });
    return c, e;
}

fn close(c: HttpClient&) { close(c.link); }

// Sends a message as an HTTP request and reads the response's into resp,
// as TTLV. ERR_PROTOCOL for an answer that is not HTTP/1.1 or not 200 (the
// status in http_status).
fn exchange(c: HttpClient&, msg: const u8[:], resp: u8[>..]&) -> i64 {
    resp.clear();
    c.http_status = 0;
    var body: u8[>..] = [];
    let ee = encode_as(c.encoding, msg, body);
    if ee != OK { return ee; }
    var f: u8[>..] = [];
    let ok1 = http::add_field(f, "Content-Type", content_type(c.encoding));
    let ok2 = http::add_field(f, "Cache-Control", "no-cache");
    var wire: u8[>..] = [];
    if !http::client_request(c.hc, "POST", c.path, c.host, f, body.len, wire) { return ERR_PROTOCOL; }
    wire.append(body);
    var rec: u8[>..] = [];
    if !tls::send(c.link.conn, wire, rec) || net::write(c.link.fd, rec, c.link.timeout_ms) < 0 { return ERR_NETWORK; }
    var raw: u8[>..] = [];
    var used = 0;
    var enc: u8 = 0;
    var got: u8[>..] = [];
    var trailer: u8[>..] = [];
    var buf: u8[16384] = [0; 16384];
    loop {
        let ev, h = http::client_read(c.hc, raw[used..], got, trailer);
        if ev.kind == http::EV_RESPONSE {
            let m = raw[used..];
            var empty = false;
            if h.status >= 200 {
                c.http_status = h.status;
                let ct, ok = http::get(m, h, "Content-Type");
                enc = if ok { encoding_of(m[ct.pos..ct.end]) } else { 0 };
                empty = http::content_length(m, h) == 0;
            }
            used += ev.used;
            if h.status >= 200 && (empty || http::client_idle(c.hc) || http::client_closed(c.hc)) { break; }
            continue;
        }
        if ev.kind == http::EV_BODY {
            used += ev.used;
            if got.len > c.link.max_response { return ERR_TOO_LARGE; }
            continue;
        }
        if ev.kind == http::EV_END { used += ev.used; break; }
        if ev.kind != http::EV_NEED_MORE { return ERR_PROTOCOL; }
        let n = net::read(c.link.fd, buf, c.link.timeout_ms);
        if n <= 0 {
            let last = http::client_eof(c.hc);
            if last.kind == http::EV_END { break; }
            return ERR_NETWORK;
        }
        var out: u8[>..] = [];
        let fr = tls::feed(c.link.conn, c.link.cc, buf[..n], out, raw);
        if out.len > 0 { let w = net::write(c.link.fd, out, c.link.timeout_ms); }
        if fr < 0 { return ERR_TLS; }
    }
    if c.http_status != 200 { return ERR_PROTOCOL; }
    let de = decode_as(if enc != 0 { enc } else { c.encoding }, got, resp);
    if de != OK { return de; }
    if message_length(resp) != resp.len { return ERR_MALFORMED; }
    return OK;
}

// --- The server -------------------------------------------------------------------

// A connection's HTTP state on the server's side: what the request being
// read has been found to be, and its body so far.
struct HttpConn {
    hc: http::ServerConn,
    path: u8[..256],           // the target requests must name; empty: any
    status: i64,               // the request is refused with this status, or 0
    enc: u8,
    body: u8[..262144],
}

fn http_conn(path: const u8[:]) -> HttpConn {
    var o = http::server_options();
    o.max_body = 262144;
    var h = HttpConn { hc: http::server_conn(o), path: [], status: 0, enc: 0, body: [] };
    h.path.append(path[..::min(path.len, 256)]);
    return h;
}

fn http_answer(s: Server&, owner: const u8[:], h: HttpConn&, out: u8[>..]&) {
    var f: u8[>..] = [];
    var payload: u8[>..] = [];
    var status = h.status;
    if status == 0 {
        var req: u8[>..] = [];
        if decode_as(h.enc, h.body, req) != OK || message_length(req) != req.len {
            status = 400;
        } else {
            var reply: u8[>..] = [];
            handle(s, owner, req, reply);
            if encode_as(h.enc, reply, payload) != OK { status = 500; payload.clear(); } else { status = 200; }
        }
    }
    if status == 200 {
        let ok1 = http::add_field(f, "Content-Type", content_type(h.enc));
        let ok2 = http::add_field(f, "Cache-Control", "no-cache");
    }
    let r = http::server_respond(h.hc, status, f, payload.len, out);
    let b = http::server_body(h.hc, payload, out);
    let e = http::server_end(h.hc, "", out);
    h.body.clear();
    h.status = 0;
}

// Reads the HTTP/1.1 requests in input (a connection's plaintext, from
// its start or where the last call stopped), answering each whole one into
// out: a POST to h.path whose Content-Type is one of KMIP's encodings,
// handled by s for owner and answered in its encoding; 405, 404, 415, 413
// or 400 for the others. How many bytes of input it used (the caller drops
// them), and whether the connection is to close once out is sent.
fn http_serve(s: Server&, owner: const u8[:], h: HttpConn&, input: const u8[:], out: u8[>..]&) -> i64, bool {
    var used = 0;
    loop {
        var body: u8[>..] = [];
        var trailer: u8[>..] = [];
        let ev, hd = http::server_read(h.hc, input[used..], body, trailer, out);
        if ev.kind == http::EV_REQUEST {
            let m = input[used..];
            h.status = 0;
            h.body.clear();
            if m[hd.method.pos..hd.method.end] != "POST" { h.status = 405; }
            else if h.path.len > 0 && m[hd.target.pos..hd.target.end] != h.path[..] { h.status = 404; }
            else {
                let ct, ok = http::get(m, hd, "Content-Type");
                h.enc = if ok { encoding_of(m[ct.pos..ct.end]) } else { 0 };
                if h.enc == 0 { h.status = 415; }
            }
            used += ev.used;
            continue;
        }
        if ev.kind == http::EV_BODY || ev.kind == http::EV_END {
            if h.body.len + body.len > h.body.cap { h.status = 413; } else { h.body.append(body); }
            used += ev.used;
            if ev.kind == http::EV_END {
                http_answer(s, owner, h, out);
                if http::closing(h.hc) { return used, true; }
            }
            continue;
        }
        if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT { return used, false; }
        return used, true;     // ERROR (its answer is in out) or CLOSED
    }
    return used, false;
}
