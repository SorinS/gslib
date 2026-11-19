// websocket.handshake: the opening handshake (RFC 6455 §4) over
// HTTP/1.1, without I/O. A client writes its request (put_request) and
// checks the answer's head (check_response); a server checks a request
// head that net.http parsed (check_request) and writes the answer, 101 or
// the refusal (put_accept, put_refusal). Settings are gorilla's: the
// Dialer's and the Upgrader's.

namespace websocket;

import std;
import base64;
import net.http;
import websocket;
import websocket.deflate;

// --- The server's side ------------------------------------------------------------

// Whose pages may open connections (the Origin a browser sends, §10.2):
// gorilla's default, the one the request names in Host, or any, or a list.
let ORIGIN_SAME: u8 = 0;
let ORIGIN_ANY: u8 = 1;
let ORIGIN_LIST: u8 = 2;

struct Upgrader {
    origin_policy: u8,
    origins: u8[..2048],          // ORIGIN_LIST: origins separated by spaces ("https://a.example https://b.example:8443")
    subprotocols: u8[..1024],     // the server's, by preference, separated by commas
    compression: bool,            // take permessage-deflate offers
    pmd: PmdPolicy,               // and with what more
    fields: u8[..4096],           // more field lines for the 101 ("Name: value\r\n" each)
}

fn upgrader() -> Upgrader {
    Upgrader { origin_policy: ORIGIN_SAME, origins: [], subprotocols: [], compression: false,
               pmd: pmd_policy(), fields: [] }
}

// What check_request found: status 101 with the key, the subprotocol
// chosen (empty for none) and the extension agreed, or the status to
// refuse with (400, 403, 405, 426) and why.
struct Accepted {
    status: i64,
    why: u8[..128],
    key: u8[..24],
    subprotocol: u8[..256],
    pmd: Pmd,
}

fn refuse(a: Accepted&, status: i64, why: const u8[:]) -> Accepted {
    a.status = status;
    a.why.clear();
    a.why.append(why);
    return a;
}

// The comma-separated values of every field line named `name`, each
// trimmed, joined with ", ".
fn joined(m: const u8[:], h: const http::Head&, name: const u8[:], out: u8[>..]&) {
    for f in h.fields {
        if !http::eq_fold(m[f.name.pos..f.name.end], name) { continue; }
        if out.len > 0 { out.append(", "); }
        out.append(m[f.value.pos..f.value.end]);
    }
}

// Whether a comma-separated list holds the token t (exactly).
fn list_has(list: const u8[:], t: const u8[:]) -> bool {
    var found = false;
    each_split(list, ',') { if http::trim_ows(it) == t { found = true; } };
    return found;
}

// Whether every element of a comma-separated list is a token, and there is one.
fn token_list(list: const u8[:]) -> bool {
    var ok = true;
    var n = 0;
    each_split(list, ',') {
        let t = http::trim_ows(it);
        if t.len > 0 {
            n++;
            if !http::is_token(t) { ok = false; }
        }
    };
    return ok && n > 0;
}

// The host[:port] of an origin (scheme "://" host [":" port]), or empty.
fn origin_authority(o: const u8[:]) -> const u8[:] {
    let s = find(o, "://");
    if s <= 0 { return o[..0]; }
    let rest = o[s + 3..];
    var e: i64 = 0;
    while e < rest.len && rest[e] != '/' { e++; }
    if e != rest.len { return o[..0]; }      // an origin has no path
    return rest;
}

fn origin_ok(m: const u8[:], h: const http::Head&, u: const Upgrader&) -> bool {
    let os, has = http::get(m, h, "origin");
    if !has { return true; }                 // not a browser: no page to protect
    if u.origin_policy == ORIGIN_ANY { return true; }
    let o = m[os.pos..os.end];
    if u.origin_policy == ORIGIN_LIST {
        var found = false;
        each_split(u.origins[..], ' ') { if it.len > 0 && http::eq_fold(it, o) { found = true; } };
        return found;
    }
    let hs, hh = http::get(m, h, "host");
    if !hh { return false; }
    let a = origin_authority(o);
    return a.len > 0 && http::eq_fold(a, m[hs.pos..hs.end]);
}

// Checks an upgrade request (§4.2.1) whose head net.http parsed from m.
fn check_request(m: const u8[:], h: const http::Head&, u: const Upgrader&) -> Accepted {
    var a = Accepted { status: 101, why: [], key: [], subprotocol: [], pmd: no_pmd() };
    if m[h.method.pos..h.method.end] != "GET" { return refuse(a, 405, "the request method is not GET"); }
    if h.major != 1 || h.minor < 1 { return refuse(a, 400, "the request is not HTTP/1.1"); }
    if http::count(m, h, "host") != 1 { return refuse(a, 400, "no Host"); }
    if !http::has_token(m, h, "connection", "upgrade") { return refuse(a, 400, "'upgrade' token not found in 'Connection' header"); }
    if !http::has_token(m, h, "upgrade", "websocket") { return refuse(a, 400, "'websocket' token not found in 'Upgrade' header"); }
    let vs, hv = http::get(m, h, "sec-websocket-version");
    if !hv || http::count(m, h, "sec-websocket-version") != 1 || m[vs.pos..vs.end] != "13" {
        return refuse(a, 426, "unsupported version: 13 not found in 'Sec-Websocket-Version' header");
    }
    let ks, hk = http::get(m, h, "sec-websocket-key");
    if !hk || http::count(m, h, "sec-websocket-key") != 1 || !valid_key(m[ks.pos..ks.end]) {
        return refuse(a, 400, "'Sec-WebSocket-Key' header is missing or invalid");
    }
    if !origin_ok(m, h, u) { return refuse(a, 403, "request origin not allowed by Upgrader"); }
    a.key.append(m[ks.pos..ks.end]);
    var protos: u8[>..] = [];
    joined(m, h, "sec-websocket-protocol", protos);
    if protos.len > 0 {
        if !token_list(protos) { return refuse(a, 400, "bad 'Sec-WebSocket-Protocol' header"); }
        // The server's preference first (gorilla's selectSubprotocol).
        var done = false;
        each_split(u.subprotocols[..], ',') {
            let s = http::trim_ows(it);
            if !done && s.len > 0 && s.len <= 256 && list_has(protos, s) {
                a.subprotocol.append(s);
                done = true;
            }
        };
    }
    var exts: u8[>..] = [];
    joined(m, h, "sec-websocket-extensions", exts);
    if exts.len > 0 && u.compression {
        let p, ok = choose_offer(exts, u.pmd);
        if !ok { return refuse(a, 400, "bad 'Sec-WebSocket-Extensions' header"); }
        a.pmd = p;
    }
    return a;
}

// The 101 answer to a request check_request took.
fn put_accept(out: u8[>..]&, a: const Accepted&, u: const Upgrader&) {
    out.append("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
    out.append(accept_key(a.key)[..]);
    out.append("\r\n");
    if a.subprotocol.len > 0 {
        out.append("Sec-WebSocket-Protocol: ");
        out.append(a.subprotocol);
        out.append("\r\n");
    }
    if a.pmd.on {
        out.append("Sec-WebSocket-Extensions: ");
        put_answer(out, a.pmd);
        out.append("\r\n");
    }
    out.append(u.fields);
    out.append("\r\n");
}

// The refusal of a request check_request refused: its status, why as the
// body, and (426) the version this side speaks (§4.4).
fn put_refusal(out: u8[>..]&, a: const Accepted&) {
    out.append("HTTP/1.1 ");
    var n: u8[..8] = [];
    format_int(n, a.status, 10, 0, ' ');
    out.append(n);
    out.append(" ");
    out.append(http::reason_phrase(a.status));
    out.append("\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n");
    if a.status == 426 { out.append("Sec-WebSocket-Version: 13\r\n"); }
    out.append("Content-Length: ");
    var l: u8[..20] = [];
    format_int(l, a.why.len + 1, 10, 0, ' ');
    out.append(l);
    out.append("\r\n\r\n");
    out.append(a.why);
    out.append("\n");
}

// --- The client's side -----------------------------------------------------------------

// gorilla's Dialer, with permessage-deflate's offer and the proxy beside.
struct Dialer {
    subprotocols: u8[..1024],     // offered, separated by commas
    origin: u8[..1024],           // sent as Origin when not empty
    compression: bool,            // offer permessage-deflate
    offer: PmdOffer,              // with these parameters
    fields: u8[..4096],           // more request field lines ("Name: value\r\n" each)
    proxy: u8[..1024],            // "http://[user:pass@]host[:port]": CONNECT through it; empty: none
    timeout_ms: i32,              // for connecting and the handshake: 30000
    roots: u8[..65536],           // wss: the CAs trusted (DER concatenated); empty: the system's
    insecure: bool,               // wss: no check of the server's certificate
    server_name: u8[..255],       // wss: the name checked, when not the URL's host
}

fn dialer() -> Dialer {
    Dialer { subprotocols: [], origin: [], compression: false, offer: pmd_offer(), fields: [], proxy: [],
             timeout_ms: 30000, roots: [], insecure: false, server_name: [] }
}

// A new Sec-WebSocket-Key: 16 random bytes in base64 (§4.1).
fn new_key(random16: const u8[:]) -> u8[..24] {
    var t: u8[>..] = [];
    base64::encode(t, random16[..16]);
    var k: u8[..24] = [];
    k.append(t[..]);
    return k;
}

// The request (§4.1): GET target with Host (host[:port] as the URL has it).
fn put_request(out: u8[>..]&, host: const u8[:], target: const u8[:], key: const u8[:], d: const Dialer&) {
    out.append("GET ");
    out.append(target);
    out.append(" HTTP/1.1\r\nHost: ");
    out.append(host);
    out.append("\r\nUser-Agent: goose-websocket\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    out.append(key);
    out.append("\r\nSec-WebSocket-Version: 13\r\n");
    if d.origin.len > 0 {
        out.append("Origin: ");
        out.append(d.origin);
        out.append("\r\n");
    }
    if d.subprotocols.len > 0 {
        out.append("Sec-WebSocket-Protocol: ");
        out.append(d.subprotocols);
        out.append("\r\n");
    }
    if d.compression {
        out.append("Sec-WebSocket-Extensions: ");
        put_offer(out, d.offer);
        out.append("\r\n");
    }
    out.append(d.fields);
    out.append("\r\n");
}

// What check_response found.
struct Answer {
    err: i64,                     // OK or ERR_HANDSHAKE
    why: u8[..128],
    subprotocol: u8[..256],
    pmd: Pmd,
}

fn bad_answer(a: Answer&, why: const u8[:]) -> Answer {
    a.err = ERR_HANDSHAKE;
    a.why.clear();
    a.why.append(why);
    return a;
}

// Checks the server's answer (§4.1, the client's checks 1 to 6).
fn check_response(m: const u8[:], h: const http::Head&, key: const u8[:], d: const Dialer&) -> Answer {
    var a = Answer { err: OK, why: [], subprotocol: [], pmd: no_pmd() };
    if h.status != 101 { return bad_answer(a, "the server did not answer 101"); }
    if !http::has_token(m, h, "upgrade", "websocket") { return bad_answer(a, "no 'Upgrade: websocket' in the answer"); }
    if !http::has_token(m, h, "connection", "upgrade") { return bad_answer(a, "no 'Connection: upgrade' in the answer"); }
    let s, has = http::get(m, h, "sec-websocket-accept");
    if !has || http::count(m, h, "sec-websocket-accept") != 1 || m[s.pos..s.end] != accept_key(key)[..] {
        return bad_answer(a, "the answer's Sec-WebSocket-Accept is not the key's");
    }
    var protos: u8[>..] = [];
    joined(m, h, "sec-websocket-protocol", protos);
    if protos.len > 0 {
        let p = http::trim_ows(protos);
        if !http::is_token(p) || !list_has(d.subprotocols[..], p) {
            return bad_answer(a, "the server chose a subprotocol not offered");
        }
        a.subprotocol.append(p[..min(p.len, 256)]);
    }
    var exts: u8[>..] = [];
    joined(m, h, "sec-websocket-extensions", exts);
    if exts.len > 0 {
        if !d.compression { return bad_answer(a, "the server named an extension not offered"); }
        let p, ok = check_answer(exts, d.offer);
        if !ok { return bad_answer(a, "the server's permessage-deflate parameters are not the offer's"); }
        a.pmd = p;
    }
    return a;
}
