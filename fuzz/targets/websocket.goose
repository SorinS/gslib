// Fuzz target: websocket. The first byte picks a path (data[0] % 4) and,
// for the Conns, what was agreed (data[0] / 4: permessage-deflate on, each
// side keeping no history, small windows, reading a frame at a time); the
// rest is the input:
//   0: a server Conn fed the input as a client's frames, read until it
//      fails or needs more: headers, masking, control frames among
//      fragments, closes, UTF-8 as it arrives, inflating, the limit.
//   1: a client Conn, the input as a server's frames.
//   2: the opening handshake: the input as a request a server checks (and
//      answers), and as an answer a client checks.
//   3: the extension header: a server's choice among offers, a client's
//      check of an answer.

import std;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.h1;
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.handshake;
import gslib.websocket.conn;

let KEY: const u8[:] = "dGhlIHNhbXBsZSBub25jZQ==";

fn conn(m: const u8[:], is_client: bool, flags: u8) {
    var p = websocket::no_pmd();
    p.on = (flags & 1) != 0;
    p.server_no_context_takeover = (flags & 2) != 0;
    p.client_no_context_takeover = (flags & 4) != 0;
    if (flags & 8) != 0 {
        p.server_max_window_bits = 9;
        p.client_max_window_bits = 9;
    }
    var c = websocket::Conn { .. };
    c.opt.read_limit = 1 << 20;
    websocket::start(c, is_client, p, "");
    // In two pieces, so that a frame may be cut anywhere.
    let cut = if m.len > 0 { (m[0] as i64) % (m.len + 1) } else { 0 };
    var msg: u8[>..] = [];
    for piece in 2 {
        websocket::feed(c, if piece == 0 { m[..cut] } else { m[cut..] });
        for k in 64 {
            if (flags & 16) != 0 {
                let kind, e = websocket::next_message(c);
                if e != websocket::OK { break; }
                var end = false;
                while !end {
                    msg.clear();
                    let n, done, re = websocket::read_part(c, msg);
                    if re != websocket::OK { break; }
                    end = done;
                }
                if !end { break; }
            } else {
                let kind, e = websocket::read_message(c, msg);
                if e != websocket::OK { break; }
                // Echo it, compressed when agreed.
                if kind == websocket::TEXT || kind == websocket::BINARY { websocket::write_message(c, kind, msg); }
            }
        }
    }
    var out: u8[>..] = [];
    websocket::take_output(c, out);
}

fn handshake(m: const u8[:]) {
    let lim = http::default_limits();
    var u = websocket::upgrader();
    u.compression = true;
    u.subprotocols.append("chat, superchat");
    let h, n = http::parse_request(m, lim);
    if n > 0 {
        let a = websocket::check_request(m, h, u);
        var out: u8[>..] = [];
        if a.status == 101 { websocket::put_accept(out, a, u); } else { websocket::put_refusal(out, a); }
    }
    var d = websocket::dialer();
    d.compression = true;
    d.subprotocols.append("chat");
    let rh, rn = http::parse_response(m, lim);
    if rn > 0 { let a = websocket::check_response(m, rh, KEY, d); }
}

fn extensions(m: const u8[:]) {
    let pol = websocket::pmd_policy();
    let p, ok = websocket::choose_offer(m, pol);
    var out: u8[>..] = [];
    if ok && p.on { websocket::put_answer(out, p); }
    let o = websocket::pmd_offer();
    let q, qok = websocket::check_answer(m, o);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let m = data[1..];
    let sel = data[0] % 4;
    let flags = data[0] / 4;
    if sel == 0 { conn(m, false, flags); }
    else if sel == 1 { conn(m, true, flags); }
    else if sel == 2 { handshake(m); }
    else { extensions(m); }
    return 0;
}

fn main() {}
