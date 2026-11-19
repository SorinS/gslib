// RFC 6455's framing without a connection: §5.7's examples, lengths at
// their boundaries, headers cut short, masking in pieces, UTF-8 as it
// arrives (where it fails), close payloads, the accept key of §1.3.

import std;
import gslib from "../..";
import gslib.websocket;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

fn frame(fin: bool, op: u8, payload: const u8[:], key: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    websocket::put_frame(out, fin, 0, op, payload, key.len == 4, key);
    return out;
}

fn examples() {
    // §5.7.
    let k: const u8[:] = "\x37\xfa\x21\x3d";
    check(frame(true, websocket::TEXT, "Hello", "")[..] == "\x81\x05\x48\x65\x6c\x6c\x6f", "unmasked text");
    check(frame(true, websocket::TEXT, "Hello", k)[..] == "\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", "masked text");
    check(frame(false, websocket::TEXT, "Hel", "")[..] == "\x01\x03\x48\x65\x6c", "first fragment");
    check(frame(true, websocket::CONTINUATION, "lo", "")[..] == "\x80\x02\x6c\x6f", "last fragment");
    check(frame(true, websocket::PING, "Hello", "")[..] == "\x89\x05\x48\x65\x6c\x6c\x6f", "ping");
    check(frame(true, websocket::PONG, "Hello", k)[..] == "\x8a\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58", "masked pong");
    var b256: u8[>..] = [];
    b256.resize(256, 0);
    let f256 = frame(true, websocket::BINARY, b256, "");
    check(f256[..4] == "\x82\x7e\x01\x00" && f256.len == 260, "256 bytes");
    var b64k: u8[>..] = [];
    b64k.resize(65536, 0);
    let f64k = frame(true, websocket::BINARY, b64k, "");
    check(f64k[..10] == "\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x00" && f64k.len == 65546, "64 KiB");
}

fn lengths() {
    let sizes: i64[8] = [0, 125, 126, 127, 65535, 65536, 65537, 1 << 20];
    for n in sizes {
        var p: u8[>..] = [];
        p.resize(n, 0x5a);
        for masked in 2 {
            let key: const u8[:] = if masked == 1 { "\x01\x02\x03\x04" } else { "" };
            let f = frame(true, websocket::BINARY, p, key);
            let h, e = websocket::parse_header(f);
            check(e == websocket::OK && h.length == n && h.masked == (masked == 1) && h.fin, "header round trip");
            check(h.size + n == f.len, "header size");
            // Minimal lengths: 7 bits, 16, 64.
            var want: i64 = if n < 126 { 2 } else if n < 65536 { 4 } else { 10 };
            if masked == 1 { want += 4; }
            check(h.size == want, "minimal length");
            // Every prefix of the header is too short.
            for cut in h.size {
                let h2, e2 = websocket::parse_header(f[..cut]);
                check(e2 == websocket::ERR_NEED_MORE, "cut header");
            }
            if masked == 1 {
                var q: u8[>..] = [];
                q.append(f[h.size..]);
                websocket::mask_bytes(q, h.key, 0);
                check(q[..] == p[..], "unmasked");
            }
        }
    }
    // A 64-bit length with its top bit set (§5.2).
    let h, e = websocket::parse_header("\x82\x7f\x80\x00\x00\x00\x00\x00\x00\x00");
    check(e == websocket::ERR_PROTOCOL, "length's top bit");
    // RSV bits and opcode come through as they are: the Conn judges them.
    let h2, e2 = websocket::parse_header("\xf3\x00");
    check(e2 == websocket::OK && h2.rsv == 7 && h2.opcode == 3 && h2.fin, "rsv and opcode");
}

fn masking() {
    var data: u8[>..] = [];
    for i in 1000 { data.push(((i * 7 + 3) & 0xff) as! u8); }
    let key: const u8[:] = "\x9a\x01\xfe\x33";
    var whole: u8[>..] = [];
    whole.append(data);
    websocket::mask_bytes(whole, key, 0);
    let cuts: i64[7] = [0, 1, 2, 3, 5, 17, 999];
    for cut in cuts {
        var parts: u8[>..] = [];
        parts.append(data);
        websocket::mask_bytes(parts[..cut], key, 0);
        websocket::mask_bytes(parts[cut..], key, cut);
        check(parts[..] == whole[..], "masked in pieces");
    }
    websocket::mask_bytes(whole, key, 0);
    check(whole[..] == data[..], "masking twice");
}

// Where a byte string stops being UTF-8, fed a byte at a time: -1 when it
// is UTF-8 throughout (complete or not).
fn fail_at(s: const u8[:]) -> i64 {
    var st = websocket::utf8_state();
    for i in s.len {
        if !websocket::utf8_feed(st, s[i..i + 1]) { return i; }
    }
    return -1;
}

fn utf8() {
    check(websocket::valid_utf8(""), "empty");
    check(websocket::valid_utf8("Hello-\xc2\xb5@\xc3\x9f\xc3\xb6\xc3\xa4\xc3\xbc\xc3\xa0\xc3\xa1-UTF-8!!"), "Autobahn 6.2");
    check(websocket::valid_utf8("\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5"), "kosme");
    check(websocket::valid_utf8("\x7f\xdf\xbf\xef\xbf\xbf\xf4\x8f\xbf\xbf"), "the last of each length");
    check(websocket::valid_utf8("\x00\xc2\x80\xe0\xa0\x80\xf0\x90\x80\x80"), "the first of each length");
    check(websocket::valid_utf8("\xee\x80\x80\xef\xbf\xbd"), "private use and U+FFFD");
    // Fail fast: at the byte that cannot be UTF-8 (Autobahn 6.3, 6.4).
    check(fail_at("\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80edited") == 12, "a surrogate's second byte");
    check(fail_at("\xc0\xaf") == 0, "overlong lead");
    check(fail_at("\xe0\x80\xaf") == 1, "overlong 3-byte");
    check(fail_at("\xf0\x80\x80\xaf") == 1, "overlong 4-byte");
    check(fail_at("\xf4\x90\x80\x80") == 1, "past U+10FFFF");
    check(fail_at("\xf5") == 0, "F5");
    check(fail_at("\xff") == 0, "FF");
    check(fail_at("\x80") == 0, "a lone continuation");
    check(fail_at("\xc2\x41") == 1, "lead without continuation");
    check(fail_at("\xed\x9f\xbf") == -1, "U+D7FF");
    check(fail_at("\xed\xbf\xbf") == 1, "U+DFFF");
    // Incomplete is not invalid until the end.
    var st = websocket::utf8_state();
    check(websocket::utf8_feed(st, "abc\xe2\x82") && !websocket::utf8_complete(st), "incomplete");
    check(websocket::utf8_feed(st, "\xac") && websocket::utf8_complete(st), "completed");
    // The ASCII fast path, with a non-ASCII byte at every offset.
    for at in 40 {
        var s: u8[>..] = [];
        for i in 40 { s.push('a'); }
        s[at] = 0xff;
        check(!websocket::valid_utf8(s), "0xff among ASCII");
        if at + 1 < 40 {
            s[at] = 0xc3;
            s[at + 1] = 0xa9;
            check(websocket::valid_utf8(s), "e-acute among ASCII");
        }
    }
}

fn closes() {
    var p: u8[>..] = [];
    websocket::put_close_payload(p, 1000, "bye");
    check(p[..] == "\x03\xe8bye", "close payload");
    let code, reason, e = websocket::parse_close_payload(p);
    check(e == websocket::OK && code == 1000 && reason == "bye", "close read");
    let c0, r0, e0 = websocket::parse_close_payload("");
    check(e0 == websocket::OK && c0 == websocket::CLOSE_NO_STATUS, "empty close");
    let c1, r1, e1 = websocket::parse_close_payload("\x03");
    check(e1 == websocket::ERR_PROTOCOL, "one byte");
    let c2, r2, e2 = websocket::parse_close_payload("\x03\xe8\xff");
    check(e2 == websocket::ERR_UTF8, "reason not UTF-8");
    // §7.4.1 and IANA: which codes a close may carry.
    let good: i64[12] = [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1014, 3000, 4999];
    for g in good { check(websocket::valid_close_code(g), "valid code"); }
    let bad: i64[11] = [0, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000];
    for b in bad { check(!websocket::valid_close_code(b), "invalid code"); }
    var q: u8[>..] = [];
    websocket::put_close_payload(q, websocket::CLOSE_NO_STATUS, "ignored");
    check(q.len == 0, "no status: empty");
}

fn keys() {
    // §1.3's example.
    check(websocket::accept_key("dGhlIHNhbXBsZSBub25jZQ==")[..] == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "accept key");
    check(websocket::valid_key("dGhlIHNhbXBsZSBub25jZQ=="), "valid key");
    check(!websocket::valid_key("dGhlIHNhbXBsZSBub25jZQ"), "short key");
    check(!websocket::valid_key("dGhlIHNhbXBsZSBub25jZXg="), "17 bytes");
    check(!websocket::valid_key("dGhlIHNhbXBsZSBub25jZ!=="), "not base64");
}

fn main() {
    examples();
    lengths();
    masking();
    utf8();
    closes();
    keys();
    print("frames: ", checks, " checks");
}
