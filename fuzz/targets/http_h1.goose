// Fuzz target: http_h1. HTTP/1.1 (net/http h1 + conn1). The first byte
// picks: 0 a server connection fed the whole input (pipelined requests
// answered as they end), 1 the same fed a few bytes at a time, 2 a client
// connection reading responses to requests it sends (the method from the
// next byte), 3 the bare parsers: request and response heads, framing,
// keep-alive, and the chunked decoder over the rest of the input. The
// bits above the selector choose how the server answers (at REQUEST or at
// END, with a length or chunks, 100-continue).

import std;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.h1;
import gslib.net.http.conn1;
import gslib.net.http.url;

fn probe_head(m: const u8[:], h: const http::Head&) {
    for f in h.fields {
        let _ = http::is_token(m[f.name.pos..f.name.end]);
        let _ = http::is_field_value(m[f.value.pos..f.value.end]);
    }
    let _ = http::get(m, h, "host");
    let _ = http::count(m, h, "content-length");
    let _ = http::has_token(m, h, "connection", "close");
    let _ = http::keep_alive(m, h);
    if h.kind == http::KIND_REQUEST {
        let _ = http::target_form(m, h);
        let _ = http::check_request(m, h);
        let _ = http::request_framing(m, h);
        let u, e = http::url_parse(m[h.target.pos..h.target.end]);
        if e == 0 {
            var t: u8[>..] = [];
            http::request_target(u, t);
        }
    } else {
        let _ = http::reason_phrase(h.status);
        let _ = http::status_class(h.status);
        for head in [false, true] {
            for connect in [false, true] { let _ = http::response_framing(m, h, head, connect); }
        }
    }
}

// Answers the request being read: a short body, by length or in chunks.
fn answer(c: http::ServerConn&, mode: u8, out: u8[>..]&) {
    let chunked = (mode & 2) != 0;
    var fields: u8[>..] = [];
    let _ = http::add_field(fields, "Content-Type", "text/plain");
    let status: i64 = if (mode & 8) != 0 { 204 } else { 200 };
    if http::server_respond(c, status, fields, if chunked { -1 } else { 5 }, out) {
        let _ = http::server_body(c, "hello", out);
        let _ = http::server_end(c, if chunked { "X-T: 1\r\n" } else { "" }, out);
    }
}

fn server(data: const u8[:], mode: u8, step: i64) {
    var c = http::server_conn(http::server_options());
    var body:    u8[>..] = [];
    var trailer: u8[>..] = [];
    var out:     u8[>..] = [];
    var pos = 0;
    var avail = if step <= 0 { data.len } else { if step < data.len { step } else { data.len } };
    var iters = 0;
    var idle = 0;
    while iters < 20000 {
        iters++;
        let m = data[pos..avail];
        let ev, h = http::server_read(c, m, body, trailer, out);
        if ev.kind == http::EV_REQUEST {
            probe_head(m, h);
            if ev.continue_expected && (mode & 4) != 0 { http::server_continue(c, out); }
            if (mode & 1) != 0 && http::request_complete(c) { answer(c, mode, out); }
        } else if ev.kind == http::EV_END || ev.kind == http::EV_WAIT {
            answer(c, mode, out);
        }
        if ev.used < 0 || ev.used > m.len { abort("http_h1: event used past the buffer"); }
        pos += ev.used;
        if ev.kind == http::EV_CLOSED || ev.kind == http::EV_ERROR { break; }
        if ev.kind == http::EV_NEED_MORE {
            if avail >= data.len { break; }
            avail = if avail + step < data.len { avail + step } else { data.len };
        }
        if ev.kind == http::EV_WAIT { idle++; if idle > 8 { break; } } else { idle = 0; }
        body.clear();
        trailer.clear();
        if out.len > 65536 { out.clear(); }
    }
    let _ = http::closing(c);
}

fn client(data: const u8[:], sel: u8) {
    var c = http::client_conn();
    var body:    u8[>..] = [];
    var trailer: u8[>..] = [];
    var out:     u8[>..] = [];
    let methods = ["GET", "HEAD", "CONNECT", "POST"];
    let method = methods[(sel % 4) as i64];
    let target = if method == "CONNECT" { "example.com:443" } else { "/index.html" };
    var pos = 0;
    var iters = 0;
    var requests = 0;
    while iters < 20000 {
        iters++;
        if http::client_idle(c) {
            if requests >= 64 { break; }
            requests++;
            if !http::client_request(c, method, target, "example.com", "Accept: */*\r\n", if method == "POST" { 3 } else { 0 }, out) {
                break;
            }
        }
        let m = data[pos..];
        let ev, h = http::client_read(c, m, body, trailer);
        if ev.kind == http::EV_RESPONSE { probe_head(m, h); }
        if ev.used < 0 || ev.used > m.len { abort("http_h1: event used past the buffer"); }
        pos += ev.used;
        if ev.kind == http::EV_CLOSED || ev.kind == http::EV_ERROR { break; }
        if ev.kind == http::EV_NEED_MORE {
            let _ = http::client_eof(c);
            break;
        }
        body.clear();
        trailer.clear();
        out.clear();
    }
}

fn bare(data: const u8[:]) {
    let lim = http::default_limits();
    let rq, n = http::parse_request(data, lim);
    var rest = data;
    if n > 0 {
        probe_head(data, rq);
        rest = data[n..];
    }
    let rs, k = http::parse_response(data, lim);
    if k > 0 {
        probe_head(data, rs);
        if n <= 0 { rest = data[k..]; }
    }
    // The chunked decoder over what follows a head (or the whole input),
    // whole and then in pieces of 1..7 bytes: the same body and length.
    var d1 = http::chunked_decoder();
    var b1: u8[>..] = [];
    var t1: u8[>..] = [];
    let r1 = http::chunked_feed(d1, lim, rest, b1, t1);
    var d2 = http::chunked_decoder();
    var b2: u8[>..] = [];
    var t2: u8[>..] = [];
    var at = 0;
    var r2: i64 = 0;
    var step = 1;
    while at < rest.len && !http::chunked_done(d2) {
        let e = if at + step < rest.len { at + step } else { rest.len };
        let r = http::chunked_feed(d2, lim, rest[at..e], b2, t2);
        if r < 0 { r2 = r; break; }
        if r > e - at { abort("http_h1: chunked_feed took more than it was given"); }
        at += r;
        if r < e - at + r && !http::chunked_done(d2) { abort("http_h1: chunked_feed stopped short before the end"); }
        step = step % 7 + 1;
    }
    if (r1 < 0) != (r2 < 0) { abort("http_h1: chunked body refused one way and not the other"); }
    if r1 >= 0 && r2 >= 0 && http::chunked_done(d1) {
        if !http::chunked_done(d2) || at != r1 || b1[..] != b2[..] || t1[..] != t2[..] {
            abort("http_h1: chunked body differs fed in pieces");
        }
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let sel = data[0] % 4;
    let mode = data[0] / 4;
    let rest = data[1..];
    if sel == 0 { server(rest, mode, 0); }
    else if sel == 1 { server(rest, mode, ((mode as i64) % 13) + 1); }
    else if sel == 2 { if rest.len > 0 { client(rest[1..], rest[0]); } }
    else { bare(rest); }
    return 0;
}

fn main() {}
