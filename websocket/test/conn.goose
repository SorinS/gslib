// Conns in memory, a client and a server joined by the bytes each sends
// (feed, take_output): messages of every size both ways, fed whole and a
// byte at a time; fragments; parts; pings among fragments; the closing
// handshake; and every way a peer breaks the protocol, each answered with
// the close the RFC names.

import std;
import gslib from "../..";
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.conn;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

// Moves what from has sent to to.
fn pump(from: websocket::Conn&, to: websocket::Conn&) {
    var b: u8[>..] = [];
    websocket::take_output(from, b);
    websocket::feed(to, b);
}

// The same, a byte at a time, reading after each: the message that came.
fn pump_slowly(from: websocket::Conn&, to: websocket::Conn&, msg: u8[>..]&) -> u8, i64 {
    var b: u8[>..] = [];
    websocket::take_output(from, b);
    var kind: u8 = 0;
    var e = websocket::ERR_NEED_MORE;
    for i in b.len {
        websocket::feed(to, b[i..i + 1]);
        kind, e = websocket::read_message(to, msg);
        if e != websocket::ERR_NEED_MORE { check(i == b.len - 1, "message before its last byte"); }
    }
    return kind, e;
}

fn data(n: i64, seed: i64) -> u8[>..] {
    var d: u8[>..] = [];
    var x: u64 = (seed * 2654435761 + 1) as! u64;
    for i in n {
        x = x * 6364136223846793005 + 1442695040888963407;
        d.push(((x >> 60) as! u8) + 'a');        // compressible text
    }
    return d;
}

fn round_trips() {
    var a = websocket::Conn { .. };
    var b = websocket::Conn { .. };
    websocket::start(a, true, websocket::no_pmd(), "");
    websocket::start(b, false, websocket::no_pmd(), "");
    let sizes: i64[9] = [0, 1, 125, 126, 127, 65535, 65536, 65537, 300000];
    var msg: u8[>..] = [];
    for n in sizes {
        let d = data(n, n);
        check(websocket::write_message(a, websocket::TEXT, d) == websocket::OK, "client writes");
        pump(a, b);
        let k, e = websocket::read_message(b, msg);
        check(e == websocket::OK && k == websocket::TEXT && msg[..] == d[..], "server reads");
        check(websocket::write_message(b, websocket::BINARY, d) == websocket::OK, "server writes");
        pump(b, a);
        let k2, e2 = websocket::read_message(a, msg);
        check(e2 == websocket::OK && k2 == websocket::BINARY && msg[..] == d[..], "client reads");
    }
    // Nothing more: more is needed.
    let k3, e3 = websocket::read_message(b, msg);
    check(e3 == websocket::ERR_NEED_MORE, "need more");
    // A byte at a time.
    let d = data(300, 7);
    websocket::write_message(a, websocket::TEXT, d);
    let k4, e4 = pump_slowly(a, b, msg);
    check(e4 == websocket::OK && msg[..] == d[..], "a byte at a time");
    // Fragmented by the writer, with a ping between the fragments.
    a.opt.fragment_size = 10;
    let d2 = data(95, 3);
    websocket::write_message(a, websocket::TEXT, d2);
    var wire: u8[>..] = [];
    websocket::take_output(a, wire);
    check(wire.len == 95 + 10 * 6, "ten fragments, masked");
    websocket::feed(b, wire[..32]);        // two whole frames
    websocket::ping(a, "are you there");
    pump(a, b);
    websocket::feed(b, wire[32..]);
    b.opt.control_events = true;
    let k5, e5 = websocket::read_message(b, msg);
    check(e5 == websocket::OK && k5 == websocket::PING && b.control[..] == "are you there", "the ping first");
    let k6, e6 = websocket::read_message(b, msg);
    check(e6 == websocket::OK && k6 == websocket::TEXT && msg[..] == d2[..], "then the message");
    b.opt.control_events = false;
    // The pong came back.
    a.opt.control_events = true;
    pump(b, a);
    let k7, e7 = websocket::read_message(a, msg);
    check(e7 == websocket::OK && k7 == websocket::PONG && a.control[..] == "are you there", "pong");
    a.opt.control_events = false;
    a.opt.fragment_size = 0;
    // Written in parts, read in parts.
    check(websocket::begin_message(b, websocket::BINARY) == websocket::OK, "begin");
    b.opt.write_buffer = 100;
    var all: u8[>..] = [];
    for i in 25 {
        let p = data(i * 3, i);
        all.append(p);
        check(websocket::write_part(b, p) == websocket::OK, "part");
    }
    check(websocket::write_message(b, websocket::TEXT, "no") == websocket::ERR_ARGUMENT, "no message inside a message");
    check(websocket::end_message(b) == websocket::OK, "end");
    pump(b, a);
    let k8, e8 = websocket::next_message(a);
    check(e8 == websocket::OK && k8 == websocket::BINARY, "next message");
    var got: u8[>..] = [];
    var parts = 0;
    loop {
        let n, end, e = websocket::read_part(a, got);
        check(e == websocket::OK, "read part");
        parts++;
        if end { break; }
    }
    check(got[..] == all[..] && parts > 5, "parts");
    // The closing handshake, started by the client.
    check(websocket::close(a, 1000, "bye") == websocket::OK, "close sent");
    check(!websocket::closed(a), "the client waits for the answer");
    check(websocket::write_message(a, websocket::TEXT, "late") == websocket::ERR_CLOSED, "nothing after close");
    pump(a, b);
    let k9, e9 = websocket::read_message(b, msg);
    check(e9 == websocket::ERR_CLOSED && b.close_code == 1000 && b.close_reason[..] == "bye", "server sees the close");
    check(websocket::closed(b), "the server closes");
    pump(b, a);
    let k10, e10 = websocket::read_message(a, msg);
    check(e10 == websocket::ERR_CLOSED && a.close_code == 1000 && websocket::closed(a), "client sees the echo");
}

// The close a server sent after a failure: its code.
fn sent_close_code(s: websocket::Conn&) -> i64 {
    var out: u8[>..] = [];
    websocket::take_output(s, out);
    // Skip any frames before the close.
    var p: i64 = 0;
    while p < out.len {
        let h, e = websocket::parse_header(out[p..]);
        if e != websocket::OK { return -1; }
        if h.opcode == websocket::CLOSE {
            let pl = out[p + h.size..p + h.size + h.length];
            if pl.len < 2 { return websocket::CLOSE_NO_STATUS; }
            return (pl[0] as i64) << 8 | pl[1];
        }
        p += h.size + h.length;
    }
    return -1;
}

// Raw bytes a client sends to a fresh server: the error the server's read
// ends with and the close code it sent.
fn server_gets(bytes: const u8[:]) -> i64, i64 {
    var s = websocket::Conn { .. };
    websocket::start(s, false, websocket::no_pmd(), "");
    s.opt.read_limit = 1000;
    websocket::feed(s, bytes);
    var msg: u8[>..] = [];
    var e = websocket::OK;
    loop {
        let k, e2 = websocket::read_message(s, msg);
        e = e2;
        if e != websocket::OK { break; }
    }
    return e, sent_close_code(s);
}

fn masked(fin: bool, rsv: u8, op: u8, payload: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    websocket::put_frame(out, fin, rsv, op, payload, true, "\x11\x22\x33\x44");
    return out;
}

fn violations() {
    // A frame a client did not mask (§5.1).
    var f: u8[>..] = [];
    websocket::put_frame(f, true, 0, websocket::TEXT, "hi", false, "");
    var e, code = server_gets(f);
    check(e == websocket::ERR_PROTOCOL && code == 1002, "unmasked");
    // Reserved opcodes (§5.2): 3 to 7, 11 to 15.
    let ops: u8[10] = [3, 4, 5, 6, 7, 11, 12, 13, 14, 15];
    for op in ops {
        e, code = server_gets(masked(true, 0, op, ""));
        check(e == websocket::ERR_PROTOCOL && code == 1002, "reserved opcode");
    }
    // RSV bits with no extension that defines them.
    let rsvs: u8[3] = [websocket::RSV1, websocket::RSV2, websocket::RSV3];
    for r in rsvs {
        e, code = server_gets(masked(true, r, websocket::TEXT, "x"));
        check(e == websocket::ERR_PROTOCOL && code == 1002, "rsv");
    }
    // Control frames: fragmented, too long (§5.5).
    e, code = server_gets(masked(false, 0, websocket::PING, "x"));
    check(e == websocket::ERR_PROTOCOL && code == 1002, "fragmented ping");
    var long: u8[>..] = [];
    long.resize(126, 'x');
    e, code = server_gets(masked(true, 0, websocket::PING, long));
    check(e == websocket::ERR_PROTOCOL && code == 1002, "ping of 126 bytes");
    // Continuation with nothing to continue; a new message inside one (§5.4).
    e, code = server_gets(masked(true, 0, websocket::CONTINUATION, "x"));
    check(e == websocket::ERR_PROTOCOL && code == 1002, "lone continuation");
    var two: u8[>..] = [];
    two.append(masked(false, 0, websocket::TEXT, "a"));
    two.append(masked(true, 0, websocket::TEXT, "b"));
    e, code = server_gets(two);
    check(e == websocket::ERR_PROTOCOL && code == 1002, "text inside text");
    // Text that is not UTF-8 (§8.1): whole, across fragments, and found
    // before the frame has all come.
    e, code = server_gets(masked(true, 0, websocket::TEXT, "\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80edited"));
    check(e == websocket::ERR_UTF8 && code == 1007, "invalid text");
    var split: u8[>..] = [];
    split.append(masked(false, 0, websocket::TEXT, "\xce\xba\xe1"));
    split.append(masked(true, 0, websocket::CONTINUATION, "\xbd"));
    e, code = server_gets(split);
    check(e == websocket::ERR_UTF8 && code == 1007, "text ends inside a character");
    let whole = masked(true, 0, websocket::TEXT, "ab\xf5cdefghijklmnop");
    e, code = server_gets(whole[..9]);
    check(e == websocket::ERR_UTF8 && code == 1007, "fails fast");
    // Close frames: one byte, codes not to be sent, a reason not UTF-8.
    e, code = server_gets(masked(true, 0, websocket::CLOSE, "\x03"));
    check(e == websocket::ERR_PROTOCOL && code == 1002, "one-byte close");
    let bad: i64[8] = [0, 999, 1004, 1005, 1006, 1015, 2000, 5000];
    for b in bad {
        var p: u8[>..] = [];
        p.push(((b >> 8) & 0xff) as! u8);
        p.push((b & 0xff) as! u8);
        e, code = server_gets(masked(true, 0, websocket::CLOSE, p));
        check(e == websocket::ERR_PROTOCOL && code == 1002, "bad close code");
    }
    e, code = server_gets(masked(true, 0, websocket::CLOSE, "\x03\xe8\xc0\xaf"));
    check(e == websocket::ERR_UTF8 && code == 1007, "close reason not UTF-8");
    // A valid close is echoed with its code; an empty one with an empty one.
    e, code = server_gets(masked(true, 0, websocket::CLOSE, "\x0f\xa0x"));
    check(e == websocket::ERR_CLOSED && code == 4000, "close 4000 echoed");
    e, code = server_gets(masked(true, 0, websocket::CLOSE, ""));
    check(e == websocket::ERR_CLOSED && code == websocket::CLOSE_NO_STATUS, "empty close echoed");
    // Past the read limit (1000 here): one frame, or fragments adding up.
    var big: u8[>..] = [];
    big.resize(1001, 'x');
    e, code = server_gets(masked(true, 0, websocket::BINARY, big));
    check(e == websocket::ERR_TOO_BIG && code == 1009, "too big");
    var frs: u8[>..] = [];
    frs.append(masked(false, 0, websocket::BINARY, big[..600]));
    frs.append(masked(true, 0, websocket::CONTINUATION, big[..401]));
    e, code = server_gets(frs);
    check(e == websocket::ERR_TOO_BIG && code == 1009, "too big in fragments");
    // A 64-bit length with its top bit set.
    e, code = server_gets("\x82\xff\x80\x00\x00\x00\x00\x00\x00\x00\x11\x22\x33\x44");
    check(e == websocket::ERR_PROTOCOL && code == 1002, "length's top bit");
    // A client takes no masked frames from a server.
    var c = websocket::Conn { .. };
    websocket::start(c, true, websocket::no_pmd(), "");
    websocket::feed(c, masked(true, 0, websocket::TEXT, "x"));
    var msg: u8[>..] = [];
    let k, ce = websocket::read_message(c, msg);
    check(ce == websocket::ERR_PROTOCOL && websocket::closed(c), "a masked frame to a client");
    // Pings and pongs among fragments are fine; an unsolicited pong too.
    var ok: u8[>..] = [];
    ok.append(masked(false, 0, websocket::TEXT, "Hel"));
    ok.append(masked(true, 0, websocket::PONG, "hb"));
    ok.append(masked(true, 0, websocket::PING, "p"));
    ok.append(masked(true, 0, websocket::CONTINUATION, "lo"));
    var s = websocket::Conn { .. };
    websocket::start(s, false, websocket::no_pmd(), "");
    websocket::feed(s, ok);
    let k2, e2 = websocket::read_message(s, msg);
    check(e2 == websocket::OK && msg[..] == "Hello", "controls among fragments");
    var out: u8[>..] = [];
    websocket::take_output(s, out);
    check(out[..] == "\x8a\x01p", "the ping answered");
    // Bytes that came with the handshake are the first frames.
    var t = websocket::Conn { .. };
    websocket::start(t, false, websocket::no_pmd(), masked(true, 0, websocket::TEXT, "early"));
    let k3, e3 = websocket::read_message(t, msg);
    check(e3 == websocket::OK && msg[..] == "early", "early frames");
    // write_close's arguments.
    check(websocket::write_close(t, 1006, "") == websocket::ERR_ARGUMENT, "1006 is not sent");
    check(websocket::write_close(t, 1000, "\xff") == websocket::ERR_ARGUMENT, "reason not UTF-8");
    check(websocket::ping(t, long) == websocket::ERR_ARGUMENT, "long ping");
}

// permessage-deflate between two Conns, with the parameters given.
fn deflate_pair(p: const websocket::Pmd&, level: i64) {
    var a = websocket::Conn { .. };
    var b = websocket::Conn { .. };
    a.opt.compress_level = level;
    b.opt.compress_level = level;
    websocket::start(a, true, p, "");
    websocket::start(b, false, p, "");
    var msg: u8[>..] = [];
    var sent: i64 = 0;
    var raw: i64 = 0;
    for i in 40 {
        let d = data(i * 97 % 3000, i % 5);      // repeats: context takeover helps
        raw += d.len;
        websocket::write_message(a, websocket::TEXT, d);
        var w: u8[>..] = [];
        websocket::take_output(a, w);
        sent += w.len;
        if d.len > 0 {
            let h, he = websocket::parse_header(w);
            check(h.rsv == websocket::RSV1, "compressed");
        }
        websocket::feed(b, w);
        let k, e = websocket::read_message(b, msg);
        check(e == websocket::OK && msg[..] == d[..], "deflate client to server");
        websocket::write_message(b, websocket::BINARY, d);
        pump(b, a);
        let k2, e2 = websocket::read_message(a, msg);
        check(e2 == websocket::OK && msg[..] == d[..], "deflate server to client");
    }
    check(sent < raw * 3 / 4, "smaller");
    // In parts, and fragmented.
    websocket::begin_message(a, websocket::TEXT);
    var all: u8[>..] = [];
    for i in 30 {
        let d = data(200, i % 3);
        all.append(d);
        websocket::write_part(a, d);
    }
    websocket::end_message(a);
    pump(a, b);
    let k3, e3 = websocket::read_message(b, msg);
    check(e3 == websocket::OK && msg[..] == all[..], "deflate in parts");
    b.opt.fragment_size = 7;
    websocket::write_message(b, websocket::TEXT, all);
    let k4, e4 = pump_slowly(b, a, msg);
    check(e4 == websocket::OK && msg[..] == all[..], "deflate fragmented, a byte at a time");
}

// RFC 7692 §7.2.3's examples, as a client reads them from a server.
fn rfc7692() {
    var c = websocket::Conn { .. };
    var p = websocket::no_pmd();
    p.on = true;
    websocket::start(c, true, p, "");
    var msg: u8[>..] = [];
    // §7.2.3.1, then §7.2.3.2: the same message using the first's history.
    websocket::feed(c, "\xc1\x07\xf2\x48\xcd\xc9\xc9\x07\x00");
    var k, e = websocket::read_message(c, msg);
    check(e == websocket::OK && msg[..] == "Hello", "7.2.3.1");
    websocket::feed(c, "\xc1\x05\xf2\x00\x11\x00\x00");
    k, e = websocket::read_message(c, msg);
    check(e == websocket::OK && msg[..] == "Hello", "7.2.3.2");
    // §7.2.3.1's fragmented form.
    websocket::feed(c, "\x41\x03\xf2\x48\xcd\x80\x04\xc9\xc9\x07\x00");
    k, e = websocket::read_message(c, msg);
    check(e == websocket::OK && msg[..] == "Hello", "7.2.3.1 fragmented");
    // §7.2.3.3: a stored block.
    websocket::feed(c, "\xc1\x0b\x00\x05\x00\xfa\xff\x48\x65\x6c\x6c\x6f\x00");
    k, e = websocket::read_message(c, msg);
    check(e == websocket::OK && msg[..] == "Hello", "7.2.3.3");
    // §7.2.3.5: two blocks.
    websocket::feed(c, "\xc1\x0d\xf2\x48\x05\x00\x00\x00\xff\xff\xca\xc9\xc9\x07\x00");
    k, e = websocket::read_message(c, msg);
    check(e == websocket::OK && msg[..] == "Hello", "7.2.3.5");
    // §7.2.3.4: a final block; the next message is a new stream that still
    // reaches back into this one's output.
    websocket::feed(c, "\xc1\x08\xf3\x48\xcd\xc9\xc9\x07\x00\x00");
    k, e = websocket::read_message(c, msg);
    check(e == websocket::OK && msg[..] == "Hello", "7.2.3.4");
    var z: u8[>..] = [];
    var w = compress::deflate_writer_dict(6, "Hello");
    compress::deflate_write(w, "Hello, Hello", z);
    compress::deflate_close(w, z);
    var f: u8[>..] = [];
    websocket::put_frame(f, true, websocket::RSV1, websocket::TEXT, z, false, "");
    websocket::feed(c, f);
    k, e = websocket::read_message(c, msg);
    check(e == websocket::OK && msg[..] == "Hello, Hello", "a new stream after a final block");
    // An uncompressed message between compressed ones (RSV1 clear).
    websocket::feed(c, "\x81\x02hi");
    k, e = websocket::read_message(c, msg);
    check(e == websocket::OK && msg[..] == "hi", "uncompressed among compressed");
    // RSV1 on a continuation is an error.
    websocket::feed(c, "\x41\x03\xf2\x48\xcd\xc0\x04\xc9\xc9\x07\x00");
    k, e = websocket::read_message(c, msg);
    check(e == websocket::ERR_PROTOCOL, "RSV1 on a continuation");
    // Data that does not inflate: 1007.
    var d = websocket::Conn { .. };
    websocket::start(d, false, p, "");
    var bad: u8[>..] = [];
    websocket::put_frame(bad, true, websocket::RSV1, websocket::BINARY, "\xff\xff\xff\xff", true, "\x01\x02\x03\x04");
    websocket::feed(d, bad);
    k, e = websocket::read_message(d, msg);
    check(e == websocket::ERR_COMPRESSION && sent_close_code(d) == 1007, "bad DEFLATE");
    // A bomb: the read limit counts what it inflates to.
    var bomb_src: u8[>..] = [];
    bomb_src.resize(1 << 20, 0);
    var bz: u8[>..] = [];
    var bw = compress::deflate_writer(9);
    compress::deflate_write(bw, bomb_src, bz);
    compress::deflate_flush(bw, bz);
    bz.resize(bz.len - 4);
    var g = websocket::Conn { .. };
    websocket::start(g, false, p, "");
    g.opt.read_limit = 100000;
    var bf: u8[>..] = [];
    websocket::put_frame(bf, true, websocket::RSV1, websocket::BINARY, bz, true, "\x01\x02\x03\x04");
    check(bf.len < 5000, "a small frame");
    websocket::feed(g, bf);
    k, e = websocket::read_message(g, msg);
    check(e == websocket::ERR_TOO_BIG && sent_close_code(g) == 1009, "inflated past the limit");
}

fn main() {
    round_trips();
    violations();
    // Every combination of the parameters, windows from 8 to 15 bits.
    for bits in 8..16 {
        for flags in 4 {
            var p = websocket::no_pmd();
            p.on = true;
            p.server_no_context_takeover = (flags & 1) != 0;
            p.client_no_context_takeover = (flags & 2) != 0;
            p.server_max_window_bits = bits;
            p.client_max_window_bits = 23 - bits;
            deflate_pair(p, if bits % 2 == 0 { 1 } else { 9 });
        }
    }
    rfc7692();
    print("conn: ", checks, " checks");
}
