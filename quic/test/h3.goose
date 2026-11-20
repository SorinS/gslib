// HTTP/3's framing without a connection: RFC 9000's varint examples;
// frames and SETTINGS (duplicates, HTTP/2's settings, reserved ones); the
// control stream fed a byte at a time, and the frames it may and may not
// carry; request and response streams in pieces, with trailers, interim
// responses, content-length, reserved frames, and the frames that break
// them.

import std;
import gslib from "../..";
import gslib.quic.qpack;
import gslib.quic.h3;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var hi = -1;
    for c in s {
        var v = -1;
        if c >= '0' && c <= '9' { v = c - '0'; }
        else if c >= 'a' && c <= 'f' { v = c - 'a' + 10; }
        if v < 0 { continue; }
        if hi < 0 { hi = v; } else { out.push((hi * 16 + v) as! u8); hi = -1; }
    }
    return out;
}

fn varints() {
    // RFC 9000 Appendix A.1.
    let hex: const u8[:][5] = ["c2197c5eff14e88c", "9d7f3e7d", "7bbd", "25", "4025"];
    let want: i64[5] = [151288809941952652, 494878333, 15293, 37, 37];
    for k in 5 {
        let b = unhex(hex[k]);
        let v, end = quic::h3_varint(b, 0);
        check(v == want[k] && end == b.len, "RFC 9000 A.1 varint");
        var out: u8[>..] = [];
        quic::h3_put_varint(out, want[k]);
        if k != 4 { check(out == b, "encoded in the fewest bytes"); }
    }
    let lims: i64[6] = [63, 64, 16383, 16384, 1073741823, 4611686018427387903];
    for x in lims {
        var out: u8[>..] = [];
        quic::h3_put_varint(out, x);
        let v, end = quic::h3_varint(out, 0);
        check(v == x && end == out.len, "a varint at a length's edge");
    }
    let cut = unhex("c2197c");
    let v, end = quic::h3_varint(cut, 0);
    check(end == -1, "a varint cut short waits");
}

fn settings() {
    var out: u8[>..] = [];
    var s = quic::h3_settings(16384);
    s.enable_connect_protocol = true;
    s.h3_datagram = true;
    quic::h3_put_settings(out, s);
    let t, len, start = quic::h3_frame_header(out, 0);
    check(t == quic::H3_SETTINGS && start + len == out.len, "a SETTINGS frame");
    let r, e = quic::h3_read_settings(out[start..]);
    check(e == 0 && r.max_field_section_size == 16384 && r.enable_connect_protocol && r.h3_datagram &&
          r.qpack_max_table_capacity == 0 && r.qpack_blocked_streams == 0, "read back, the reserved setting ignored");
    let r2, e2 = quic::h3_read_settings(unhex("06 10 06 10"));
    check(e2 == quic::H3_SETTINGS_ERROR, "a setting twice");
    let r3, e3 = quic::h3_read_settings(unhex("02 00"));
    check(e3 == quic::H3_SETTINGS_ERROR, "HTTP/2's ENABLE_PUSH");
    let r4, e4 = quic::h3_read_settings(unhex("08 02"));
    check(e4 == quic::H3_SETTINGS_ERROR, "ENABLE_CONNECT_PROTOCOL 2");
    let r5, e5 = quic::h3_read_settings(unhex("06"));
    check(e5 == quic::H3_FRAME_ERROR, "a setting cut short");
    let r6, e6 = quic::h3_read_settings(unhex("5f40 07 4021 00 01 80004000"));
    check(e6 == 0 && r6.qpack_max_table_capacity == 0x4000, "unknown settings ignored");
    let r7, e7 = quic::h3_read_settings("");
    check(e7 == 0 && r7.max_field_section_size == -1, "no settings: the defaults");
    check(quic::h3_reserved(0x21) && quic::h3_reserved(0x40) && !quic::h3_reserved(0x22), "reserved types");
}

// The control stream, fed a byte at a time: its error, or 0.
fn control(is_server: bool, bytes: const u8[:], fin: bool) -> i64 {
    var c = quic::h3_control(is_server);
    for i in bytes.len {
        let e = quic::h3_control_feed(c, bytes[i..i + 1], fin && i == bytes.len - 1);
        if e != 0 { return e; }
    }
    return 0;
}

fn control_stream() {
    var start: u8[>..] = [];
    let s = quic::h3_settings();
    quic::h3_control_start(start, s);
    let ty, rest = quic::h3_stream_type(start);
    check(ty == quic::H3_STREAM_CONTROL && rest == 1, "a control stream's type");
    let body = start[1..];
    var c = quic::h3_control(true);
    check(quic::h3_control_feed(c, body, false) == 0 && c.got_settings && c.settings.max_field_section_size == 65536, "SETTINGS taken");
    var more: u8[>..] = [];
    more.append(body);
    quic::h3_put_frame(more, 0x21, "ignored");
    quic::h3_put_goaway(more, 8);
    quic::h3_put_goaway(more, 4);
    check(control(false, more, false) == 0, "a reserved frame, then GOAWAYs going down");
    var up: u8[>..] = [];
    up.append(body);
    quic::h3_put_goaway(up, 4);
    quic::h3_put_goaway(up, 8);
    check(control(false, up, false) == quic::H3_ID_ERROR, "a GOAWAY going up");
    var odd: u8[>..] = [];
    odd.append(body);
    quic::h3_put_goaway(odd, 5);
    check(control(false, odd, false) == quic::H3_ID_ERROR, "a GOAWAY for a stream a client cannot open");
    check(control(true, odd, false) == 0, "a client's GOAWAY names a push id: any");
    var first: u8[>..] = [];
    quic::h3_put_goaway(first, 0);
    check(control(true, first, false) == quic::H3_MISSING_SETTINGS, "GOAWAY first");
    var unknown_first: u8[>..] = [];
    quic::h3_put_frame(unknown_first, 0x21, "x");
    check(control(true, unknown_first, false) == quic::H3_MISSING_SETTINGS, "a reserved frame first");
    var twice: u8[>..] = [];
    twice.append(body);
    twice.append(body);
    check(control(true, twice, false) == quic::H3_FRAME_UNEXPECTED, "SETTINGS twice");
    var data: u8[>..] = [];
    data.append(body);
    quic::h3_put_data(data, "x");
    check(control(true, data, false) == quic::H3_FRAME_UNEXPECTED, "DATA on the control stream");
    var h2: u8[>..] = [];
    h2.append(body);
    quic::h3_put_frame(h2, 0x09, "");
    check(control(true, h2, false) == quic::H3_FRAME_UNEXPECTED, "HTTP/2's CONTINUATION");
    var mpi: u8[>..] = [];
    mpi.append(body);
    quic::h3_put_id_frame(mpi, quic::H3_MAX_PUSH_ID, 3);
    check(control(true, mpi, false) == 0, "MAX_PUSH_ID to a server");
    check(control(false, mpi, false) == quic::H3_FRAME_UNEXPECTED, "MAX_PUSH_ID to a client");
    var bad_goaway: u8[>..] = [];
    bad_goaway.append(body);
    quic::h3_put_frame(bad_goaway, quic::H3_GOAWAY, "\x04\x00");
    check(control(true, bad_goaway, false) == quic::H3_FRAME_ERROR, "a GOAWAY with more than its id");
    check(control(true, body, true) == quic::H3_CLOSED_CRITICAL_STREAM, "the control stream ended");
}

// A message stream fed in pieces of n bytes: the error, and what came.
struct Got { headers: i64, interim: i64, trailers: i64, ended: bool, body: u8[>..] }

fn feed(is_request: bool, bytes: const u8[:], n: i64, fin: bool, got: Got&) -> i64 {
    var m = quic::h3_message(is_request);
    var i = 0;
    while i < bytes.len || (i == 0 && bytes.len == 0) {
        let j = ::min(i + n, bytes.len);
        let last = j == bytes.len;
        let e = quic::h3_message_feed(m, bytes[i..j], fin && last) { kind, b =>
            if kind == quic::H3_EV_HEADERS { got.headers++; }
            else if kind == quic::H3_EV_INTERIM { got.interim++; }
            else if kind == quic::H3_EV_TRAILERS { got.trailers++; }
            else if kind == quic::H3_EV_DATA { got.body.append(b); }
            else if kind == quic::H3_EV_END { got.ended = true; }
        };
        if e != 0 { return e; }
        if last { break; }
        i = j;
    }
    return 0;
}

fn got() -> Got { Got { headers: 0, interim: 0, trailers: 0, ended: false, body: [] } }

fn records(pairs: const u8[:][:]) -> u8[>..] {
    var r: u8[>..] = [];
    var i = 0;
    while i + 1 < pairs.len { quic::qpack_record(r, pairs[i], pairs[i + 1]); i += 2; }
    return r;
}

fn messages() {
    let hs = records(["user-agent", "goose", "content-length", "11"]);
    let tr = records(["x-checksum", "abc"]);
    var req: u8[>..] = [];
    quic::h3_request(req, "POST", "https", "example.com", "/upload", hs, "hello world", tr);
    for n in [1, 3, 7, 1000] {
        var g = got();
        let e = feed(true, req, n, true, g);
        check(e == 0 && g.headers == 1 && g.trailers == 1 && g.ended && g.body == "hello world", "a request in pieces, with trailers");
    }
    // The fields as they were written.
    var m = quic::h3_message(true);
    var path: u8[>..] = [];
    var trailer: u8[>..] = [];
    let e0 = quic::h3_message_feed(m, req, true) { kind, b =>
        if kind == quic::H3_EV_HEADERS { let p, ok = quic::qpack_get(b, ":path"); path.append(p); }
        if kind == quic::H3_EV_TRAILERS { let p, ok = quic::qpack_get(b, "x-checksum"); trailer.append(p); }
    };
    check(e0 == 0 && path == "/upload" && trailer == "abc", "the request's fields");
    // A response: 103 then 200, a reserved frame between DATA frames.
    var resp: u8[>..] = [];
    quic::h3_response(resp, 103, records(["link", "</a.css>; rel=preload"]), "", "");
    quic::h3_response(resp, 200, records(["content-type", "text/plain"]), "part one ", "");
    quic::h3_put_frame(resp, 0x21 + 0x1f * 2, "grease");
    quic::h3_put_data(resp, "part two");
    var g = got();
    check(feed(false, resp, 2, true, g) == 0 && g.interim == 1 && g.headers == 1 && g.body == "part one part two" && g.ended,
          "a response: interim, final, reserved frame ignored");
    // What breaks a stream.
    var d0: u8[>..] = [];
    quic::h3_put_data(d0, "x");
    var g1 = got();
    check(feed(true, d0, 100, true, g1) == quic::H3_FRAME_UNEXPECTED, "DATA before HEADERS");
    var after: u8[>..] = [];
    after.append(req);
    quic::h3_put_data(after, "late");
    var g2 = got();
    check(feed(true, after, 100, true, g2) == quic::H3_FRAME_UNEXPECTED, "DATA after trailers");
    var g3 = got();
    check(feed(true, req[..req.len - 2], 100, true, g3) == quic::H3_FRAME_ERROR, "a frame cut short by the end");
    var g4 = got();
    check(feed(true, "", 100, true, g4) == quic::H3_REQUEST_INCOMPLETE, "a request stream ended at once");
    var cl: u8[>..] = [];
    quic::h3_request(cl, "POST", "https", "a", "/", records(["content-length", "5"]), "four", "");
    var g5 = got();
    check(feed(true, cl, 100, true, g5) == quic::H3_MESSAGE_ERROR, "content-length 5, four bytes");
    var cl2: u8[>..] = [];
    quic::h3_request(cl2, "POST", "https", "a", "/", records(["content-length", "3"]), "four", "");
    var g6 = got();
    check(feed(true, cl2, 1, true, g6) == quic::H3_MESSAGE_ERROR, "content-length 3, four bytes");
    var cl3: u8[>..] = [];
    quic::h3_request(cl3, "POST", "https", "a", "/", records(["content-length", "4", "content-length", "5"]), "four", "");
    var g7 = got();
    check(feed(true, cl3, 100, true, g7) == quic::H3_MESSAGE_ERROR, "two content-lengths that differ");
    var bad: u8[>..] = [];
    quic::h3_request(bad, "GET", "https", "a", "/", records(["Upper", "x"]), "", "");
    var g8 = got();
    check(feed(true, bad, 100, true, g8) == quic::H3_MESSAGE_ERROR, "an uppercase name");
    var set: u8[>..] = [];
    quic::h3_request(set, "GET", "https", "a", "/", "", "", "");
    let s = quic::h3_settings();
    quic::h3_put_settings(set, s);
    var g9 = got();
    check(feed(true, set, 100, true, g9) == quic::H3_FRAME_UNEXPECTED, "SETTINGS on a request stream");
    var push: u8[>..] = [];
    quic::h3_put_frame(push, quic::H3_PUSH_PROMISE, "\x00\x00\x00");
    var g10 = got();
    check(feed(false, push, 100, true, g10) == quic::H3_ID_ERROR, "PUSH_PROMISE when none was allowed");
    var r101: u8[>..] = [];
    quic::h3_response(r101, 101, "", "", "");
    var g11 = got();
    check(feed(false, r101, 100, true, g11) == quic::H3_MESSAGE_ERROR, "101");
    var notq: u8[>..] = [];
    quic::h3_put_frame(notq, quic::H3_HEADERS, "\x01\x00");
    var g12 = got();
    check(feed(true, notq, 100, true, g12) == quic::QPACK_DECOMPRESSION_FAILED, "a section that is not QPACK");
    var nocl: u8[>..] = [];
    quic::h3_response(nocl, 204, records(["content-length", "10"]), "", "");
    var g13 = got();
    check(feed(false, nocl, 100, true, g13) == 0 && g13.ended, "204 with content-length and no content");
    var open: u8[>..] = [];
    quic::h3_request(open, "GET", "https", "a", "/", "", "", "");
    var g14 = got();
    check(feed(true, open, 100, false, g14) == 0 && g14.headers == 1 && !g14.ended, "a stream not yet ended");
    check(quic::h3_error_text(quic::H3_FRAME_UNEXPECTED) == "H3_FRAME_UNEXPECTED", "error text");
}

fn main() {
    varints();
    settings();
    control_stream();
    messages();
    print("h3: ", checks, " checks");
}
