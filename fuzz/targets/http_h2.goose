// Fuzz target: http_h2. HTTP/2 connections (net/http h2) without a
// socket: the input is what the peer sends. Byte 0 picks a server (the
// client preface is put before the rest, so the frames start at once) or a
// client (two requests already sent, a GET and a POST with a body); its
// other bits choose how the server answers. Every frame type is read:
// SETTINGS, HEADERS/CONTINUATION (through HPACK), DATA with padding,
// PRIORITY, RST_STREAM, PING, GOAWAY, WINDOW_UPDATE, PUSH_PROMISE.

import std;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.h1;
import gslib.net.http.hpack;
import gslib.net.http.h2;

fn run(c: http::H2Conn&, m: const u8[:], mode: u8, out: u8[>..]&) {
    var fields: u8[>..] = [];
    var body:   u8[>..] = [];
    var pos = 0;
    var iters = 0;
    var still = 0;
    while iters < 4096 {
        iters++;
        body.clear();
        let ev = http::h2_read(c, m[pos..], fields, body, out);
        if ev.used < 0 || ev.used > m.len - pos { abort("http_h2: event used past the buffer"); }
        pos += ev.used;
        if ev.kind == http::EV2_NEED_MORE || ev.kind == http::EV2_ERROR { break; }
        if ev.used == 0 { still++; if still > 4 { break; } } else { still = 0; }
        if ev.kind == http::EV2_HEADERS {
            let _ = http::h2_field(fields, ":method");
            let _ = http::h2_field(fields, ":path");
            let _ = http::h2_field(fields, ":status");
            let _ = http::h2_field(fields, "content-length");
            if c.opt.server && !ev.trailers && (mode & 1) == 0 {
                // Answer with the request's own fields (pseudo-headers are
                // skipped by the encoder): the encoder takes what the
                // decoder gave.
                if http::h2_respond(c, ev.stream, if (mode & 2) != 0 { 204 } else { 200 }, fields, false, out) {
                    let _ = http::h2_send_room(c, ev.stream);
                    if (mode & 4) != 0 {
                        let _ = http::h2_trailers(c, ev.stream, "x-trailer: 1\r\n", out);
                    } else {
                        let _ = http::h2_data(c, ev.stream, "hello", true, out);
                    }
                }
            }
        } else if ev.kind == http::EV2_DATA {
            http::h2_consumed(c, ev.stream, body.len, out);
        } else if ev.kind == http::EV2_WINDOW && ev.stream != 0 {
            let _ = http::h2_data(c, ev.stream, "more", false, out);
        }
        if out.len > 1 << 20 { out.clear(); }
    }
    if (mode & 8) != 0 && !http::h2_closed(c) { http::h2_goaway(c, out); }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let mode = data[0] >> 1;
    let rest = data[1..];
    var out: u8[>..] = [];
    if (data[0] & 1) == 0 {
        var c = http::h2_conn(http::h2_server_options());
        http::h2_start(c, out);
        var m: u8[>..] = [];
        m.append(http::H2_PREFACE);
        m.append(rest);
        run(c, m, mode, out);
    } else {
        var c = http::h2_conn(http::h2_client_options());
        http::h2_start(c, out);
        let _ = http::h2_request(c, "GET", "https", "example.com", "/a?b", "Accept: */*\r\nCookie: a=1; b=2\r\n", true, out);
        let s = http::h2_request(c, "POST", "https", "example.com", "/up", "Content-Length: 5\r\n", false, out);
        if s > 0 { let _ = http::h2_data(c, s, "hello", true, out); }
        run(c, rest, mode, out);
    }
    return 0;
}

fn main() {}
