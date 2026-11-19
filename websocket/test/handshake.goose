// The opening handshake without sockets: §1.3's request and answer, every
// check a server makes (and the status it refuses with), origins,
// subprotocols, permessage-deflate's offers and answers (RFC 7692 §7.1),
// a client's checks of the answer, and a whole handshake between a
// client's bytes and a server Conn.

import std;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.h1;
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.handshake;
import gslib.websocket.conn;
import gslib.websocket.server;

var checks = 0;
let LIM = http::default_limits();

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

let BASE: const u8[:] = "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";

// A request: BASE's lines with `drop` left out, then `more`.
fn request(drop: const u8[:], more: const u8[:]) -> u8[>..] {
    var r: u8[>..] = [];
    each_split(BASE, "\r\n") {
        if it.len > 0 && (drop.len == 0 || !starts_with(it, drop)) {
            r.append(it);
            r.append("\r\n");
        }
    };
    if more.len > 0 {
        r.append(more);
        r.append("\r\n");
    }
    r.append("\r\n");
    return r;
}

fn check_with(m: const u8[:], u: const websocket::Upgrader&) -> websocket::Accepted {
    let h, n = http::parse_request(m, LIM);
    assert(n > 0);
    return websocket::check_request(m, h, u);
}

fn status(m: const u8[:]) -> i64 {
    let u = websocket::upgrader();
    return check_with(m, u).status;
}

fn server_checks() {
    let u = websocket::upgrader();
    let a = check_with(request("", ""), u);
    check(a.status == 101 && a.key[..] == "dGhlIHNhbXBsZSBub25jZQ==" && a.subprotocol.len == 0 && !a.pmd.on, "§1.3");
    var out: u8[>..] = [];
    websocket::put_accept(out, a, u);
    check(out[..] == "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", "§1.3's answer");
    // What a server refuses.
    var post = request("", "");
    post[0] = 'P'; post[1] = 'U'; post[2] = 'T';
    check(status(post) == 405, "PUT");
    check(status(request("Upgrade:", "")) == 400, "no Upgrade");
    check(status(request("Upgrade:", "Upgrade: h2c")) == 400, "Upgrade: h2c");
    check(status(request("Connection:", "")) == 400, "no Connection");
    check(status(request("Connection:", "Connection: keep-alive")) == 400, "Connection: keep-alive");
    check(status(request("Connection:", "Connection: keep-alive, Upgrade")) == 101, "a list with upgrade");
    check(status(request("Upgrade:", "Upgrade: WebSocket")) == 101, "WebSocket in any case");
    check(status(request("Sec-WebSocket-Version:", "")) == 426, "no version");
    check(status(request("Sec-WebSocket-Version:", "Sec-WebSocket-Version: 8")) == 426, "version 8");
    check(status(request("", "Sec-WebSocket-Version: 13")) == 426, "the version twice");
    check(status(request("Sec-WebSocket-Key:", "")) == 400, "no key");
    check(status(request("Sec-WebSocket-Key:", "Sec-WebSocket-Key: c2hvcnQ=")) == 400, "a short key");
    check(status(request("", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==")) == 400, "the key twice");
    var a426 = check_with(request("Sec-WebSocket-Version:", "Sec-WebSocket-Version: 7"), u);
    var r: u8[>..] = [];
    websocket::put_refusal(r, a426);
    check(find(r, "\r\nSec-WebSocket-Version: 13\r\n") > 0 && starts_with(r, "HTTP/1.1 426 "), "426 names 13");
    // HTTP/1.0.
    var old = request("", "");
    old[17] = '0';
    check(status(old) == 400, "HTTP/1.0");
    // Origins: none (not a browser), the same as Host, another.
    check(status(request("", "Origin: http://server.example.com")) == 101, "same origin");
    check(status(request("", "Origin: https://SERVER.example.com")) == 101, "same origin, any case");
    check(status(request("", "Origin: http://evil.example")) == 403, "another origin");
    check(status(request("", "Origin: null")) == 403, "origin null");
    check(status(request("", "Origin: http://server.example.com/path")) == 403, "an origin with a path");
    var any = websocket::upgrader();
    any.origin_policy = websocket::ORIGIN_ANY;
    check(check_with(request("", "Origin: http://evil.example"), any).status == 101, "any origin");
    var list = websocket::upgrader();
    list.origin_policy = websocket::ORIGIN_LIST;
    list.origins.append("https://app.example https://admin.example:8443");
    check(check_with(request("", "Origin: https://admin.example:8443"), list).status == 101, "a listed origin");
    check(check_with(request("", "Origin: https://admin.example"), list).status == 403, "not listed");
    // Subprotocols: the server's preference, across lines.
    var sp = websocket::upgrader();
    sp.subprotocols.append("v2.chat, v1.chat");
    let s1 = check_with(request("", "Sec-WebSocket-Protocol: v1.chat, v2.chat"), sp);
    check(s1.status == 101 && s1.subprotocol[..] == "v2.chat", "the server's preference");
    let s2 = check_with(request("", "Sec-WebSocket-Protocol: mqtt\r\nSec-WebSocket-Protocol: v1.chat"), sp);
    check(s2.status == 101 && s2.subprotocol[..] == "v1.chat", "two lines");
    let s3 = check_with(request("", "Sec-WebSocket-Protocol: mqtt"), sp);
    check(s3.status == 101 && s3.subprotocol.len == 0, "none in common");
    check(check_with(request("", "Sec-WebSocket-Protocol: a b"), sp).status == 400, "not tokens");
    var o2: u8[>..] = [];
    websocket::put_accept(o2, s1, sp);
    check(find(o2, "\r\nSec-WebSocket-Protocol: v2.chat\r\n") > 0, "the subprotocol answered");
}

fn chosen(list: const u8[:]) -> websocket::Pmd, bool {
    let pol = websocket::pmd_policy();
    return websocket::choose_offer(list, pol);
}

fn answer_of(p: websocket::Pmd) -> u8[>..] {
    var out: u8[>..] = [];
    websocket::put_answer(out, p);
    return out;
}

fn deflate_negotiation() {
    var p, ok = chosen("permessage-deflate");
    check(ok && p.on && !p.server_no_context_takeover && p.server_max_window_bits == 15, "plain offer");
    check(answer_of(p)[..] == "permessage-deflate", "plain answer");
    p, ok = chosen("permessage-deflate; client_max_window_bits");
    check(ok && p.on && p.client_max_window_bits == 15, "client_max_window_bits without a value");
    p, ok = chosen("permessage-deflate; server_no_context_takeover; server_max_window_bits=10");
    check(ok && p.server_no_context_takeover && p.server_max_window_bits == 10, "server parameters");
    check(answer_of(p)[..] == "permessage-deflate; server_no_context_takeover; server_max_window_bits=10", "their answer");
    p, ok = chosen("permessage-deflate; client_no_context_takeover; client_max_window_bits=9");
    check(ok && p.client_no_context_takeover && p.client_max_window_bits == 9, "client parameters");
    check(answer_of(p)[..] == "permessage-deflate; client_no_context_takeover; client_max_window_bits=9", "their answer");
    p, ok = chosen("permessage-deflate; server_max_window_bits=\"12\"");
    check(ok && p.server_max_window_bits == 12, "a quoted value");
    // Offers declined (§7.1): the next one is taken.
    let declined: const u8[:][8] = [
        "permessage-deflate; server_max_window_bits=7",
        "permessage-deflate; server_max_window_bits=16",
        "permessage-deflate; server_max_window_bits=010",
        "permessage-deflate; server_max_window_bits",
        "permessage-deflate; server_no_context_takeover=1",
        "permessage-deflate; client_max_window_bits=1x",
        "permessage-deflate; foo",
        "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
    ];
    for d in declined {
        var l: u8[>..] = [];
        l.append(d);
        p, ok = chosen(l);
        check(ok && !p.on, "declined");
        l.append(", permessage-deflate; client_max_window_bits");
        p, ok = chosen(l);
        check(ok && p.on && !p.server_no_context_takeover && p.server_max_window_bits == 15, "the next offer");
    }
    p, ok = chosen("x-webkit-deflate-frame, permessage-deflate");
    check(ok && p.on, "an unknown extension first");
    p, ok = chosen("permessage-deflate; a=\"b c\"");
    check(!ok, "a quoted value that is not a token");
    p, ok = chosen("permessage-deflate;;");
    check(!ok, "not the grammar");
    // The server's own wishes.
    var pol = websocket::pmd_policy();
    pol.server_no_context_takeover = true;
    pol.client_no_context_takeover = true;
    pol.client_max_window_bits = 10;
    p, ok = websocket::choose_offer("permessage-deflate", pol);
    check(ok && p.server_no_context_takeover && p.client_no_context_takeover && p.client_max_window_bits == 15,
          "no client window limit unless offered");
    p, ok = websocket::choose_offer("permessage-deflate; client_max_window_bits", pol);
    check(ok && p.client_max_window_bits == 10, "a client window limit when offered");
    // The client's side: its offer, and what it accepts in an answer.
    var o = websocket::pmd_offer();
    var t: u8[>..] = [];
    websocket::put_offer(t, o);
    check(t[..] == "permessage-deflate; client_max_window_bits", "the offer");
    var q, qok = websocket::check_answer("permessage-deflate", o);
    check(qok && q.on && q.client_max_window_bits == 15, "a plain answer");
    q, qok = websocket::check_answer("permessage-deflate; client_max_window_bits=11; server_max_window_bits=9", o);
    check(qok && q.client_max_window_bits == 11 && q.server_max_window_bits == 9, "windows");
    q, qok = websocket::check_answer("permessage-deflate; client_no_context_takeover; server_no_context_takeover", o);
    check(qok && q.client_no_context_takeover && q.server_no_context_takeover, "no context takeover");
    let refused: const u8[:][7] = [
        "permessage-deflate, permessage-deflate",
        "x-other",
        "permessage-deflate; client_max_window_bits",
        "permessage-deflate; server_max_window_bits=20",
        "permessage-deflate; foo=1",
        "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
        "permessage-deflate; client_no_context_takeover=x",
    ];
    for r in refused {
        q, qok = websocket::check_answer(r, o);
        check(!qok, "answer refused");
    }
    var o2 = websocket::pmd_offer();
    o2.server_no_context_takeover = true;
    o2.server_max_window_bits = 10;
    o2.client_max_window_bits = 12;
    t.clear();
    websocket::put_offer(t, o2);
    check(t[..] == "permessage-deflate; server_no_context_takeover; server_max_window_bits=10; client_max_window_bits=12", "an offer with values");
    q, qok = websocket::check_answer("permessage-deflate; server_max_window_bits=10", o2);
    check(!qok, "server_no_context_takeover asked for and not answered");
    q, qok = websocket::check_answer("permessage-deflate; server_no_context_takeover", o2);
    check(!qok, "server_max_window_bits asked for and not answered");
    q, qok = websocket::check_answer("permessage-deflate; server_no_context_takeover; server_max_window_bits=11", o2);
    check(!qok, "a server window above the offer's");
    q, qok = websocket::check_answer("permessage-deflate; server_no_context_takeover; server_max_window_bits=9; client_max_window_bits=13", o2);
    check(!qok, "a client window above the offer's");
    q, qok = websocket::check_answer("permessage-deflate; server_no_context_takeover; server_max_window_bits=9", o2);
    check(qok && q.server_max_window_bits == 9 && q.client_max_window_bits == 12, "the client keeps to its own offer");
}

fn response_checks() {
    var d = websocket::dialer();
    d.subprotocols.append("v1.chat, v2.chat");
    d.compression = true;
    let key: const u8[:] = "dGhlIHNhbXBsZSBub25jZQ==";
    let base: const u8[:] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
    var cases: u8[>..] = [];
    // (more fields, expected OK)
    let good: const u8[:][4] = ["", "Sec-WebSocket-Protocol: v2.chat\r\n", "Sec-WebSocket-Extensions: permessage-deflate\r\n",
                                "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\nSec-WebSocket-Protocol: v1.chat\r\n"];
    for g in good {
        var m: u8[>..] = [];
        m.append(base);
        m.append(g);
        m.append("\r\n");
        let h, n = http::parse_response(m, LIM);
        let a = websocket::check_response(m, h, key, d);
        check(n > 0 && a.err == websocket::OK, "answer taken");
    }
    let bad: const u8[:][6] = [
        "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions: x-foo\r\n\r\n",
    ];
    for b in bad {
        let h, n = http::parse_response(b, LIM);
        let a = websocket::check_response(b, h, key, d);
        check(n > 0 && a.err == websocket::ERR_HANDSHAKE, "answer refused");
    }
    // An extension answered when none was offered.
    var plain = websocket::dialer();
    let m2: const u8[:] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
    let h2, n2 = http::parse_response(m2, LIM);
    check(websocket::check_response(m2, h2, key, plain).err == websocket::ERR_HANDSHAKE, "deflate not offered");
    // The request a Dialer writes.
    var req: u8[>..] = [];
    websocket::put_request(req, "server.example.com", "/chat", key, d);
    let h3, n3 = http::parse_request(req, LIM);
    check(n3 == req.len, "a whole request");
    var srv = websocket::upgrader();
    srv.subprotocols.append("v2.chat");
    srv.compression = true;
    let a3 = websocket::check_request(req, h3, srv);
    check(a3.status == 101 && a3.subprotocol[..] == "v2.chat" && a3.pmd.on, "a Dialer's request is taken");
}

// A whole handshake between a client's bytes and a server Conn, frames
// right behind the request.
fn whole() {
    var d = websocket::dialer();
    d.compression = true;
    var req: u8[>..] = [];
    websocket::put_request(req, "localhost:9001", "/", "dGhlIHNhbXBsZSBub25jZQ==", d);
    var cl = websocket::Conn { .. };
    var u = websocket::upgrader();
    u.compression = true;
    let h, n = http::parse_request(req, LIM);
    var m: u8[>..] = [];
    m.append(req);
    websocket::put_frame(m, true, 0, websocket::TEXT, "first", true, "\x01\x02\x03\x04");
    var s = websocket::Conn { .. };
    check(websocket::upgrade(s, -1, m, h, m[n..], u) == websocket::OK, "upgraded");
    var out: u8[>..] = [];
    websocket::take_output(s, out);
    let rh, rn = http::parse_response(out, LIM);
    let a = websocket::check_response(out, rh, "dGhlIHNhbXBsZSBub25jZQ==", d);
    check(a.err == websocket::OK && a.pmd.on, "the client takes the answer");
    var msg: u8[>..] = [];
    let k, e = websocket::read_message(s, msg);
    check(e == websocket::OK && msg[..] == "first", "the frame behind the request");
    // A refusal.
    var bad: u8[>..] = [];
    bad.append(req);
    bad[0] = 'P';
    let bh, bn = http::parse_request(bad, LIM);
    var s2 = websocket::Conn { .. };
    check(websocket::upgrade(s2, -1, bad, bh, "", u) == websocket::ERR_HANDSHAKE && s2.status == 405, "refused");
    out.clear();
    websocket::take_output(s2, out);
    check(starts_with(out, "HTTP/1.1 405 Method Not Allowed\r\n"), "the refusal sent");
}

fn main() {
    server_checks();
    deflate_negotiation();
    response_checks();
    whole();
    print("handshake: ", checks, " checks");
}
