// websocket: the WebSocket protocol for the Goose language, both sides, as
// Go's gorilla/websocket has it: RFC 6455's framing and handshake, RFC
// 7692's permessage-deflate (its four parameters, window sizes included),
// over TCP or TLS. Messages are read whole or a frame at a time and
// written whole or as they come; pings are answered and closes echoed as
// the RFC asks; text is checked as UTF-8 as it arrives, and a peer that
// breaks the protocol is closed with the code the RFC names. Autobahn's
// testsuite runs against both sides (scripts/autobahn.py).
//
//   websocket            this module: opcodes, close codes, errors, frame
//                        headers, masking, UTF-8 checking, close payloads,
//                        Sec-WebSocket-Accept
//   websocket.deflate    permessage-deflate: the extension header, offers
//                        and answers, the parameters agreed
//   websocket.handshake  the opening handshake: a client's request and the
//                        check of its answer; a server's check of the
//                        request (origin, version, subprotocols,
//                        extensions) and its answer
//   websocket.conn       Conn: a connection after the handshake, reading
//                        and writing messages, control frames, closing;
//                        over a socket, TLS, or bytes the caller carries
//   websocket.client     dial: ws:// and wss:// URLs, an HTTP proxy
//   websocket.server     accept and accept_tls (the server reads the
//                        request), upgrade (a request an HTTP server read)
//
// All are in the namespace websocket.
//
//   var c = websocket::Conn { .. };
//   let e = websocket::dial(c, "wss://echo.example.com/chat", websocket::dialer());
//   websocket::write_message(c, websocket::TEXT, "hello");
//   var msg: u8[>..] = [];
//   let kind, err = websocket::read_message(c, msg);
//   websocket::close(c, websocket::CLOSE_NORMAL, "bye");

namespace websocket;

import std;
import base64;
import crypto.bignum;
import crypto.bignum.sha1;

// --- Errors -------------------------------------------------------------------

let OK: i64 = 0;
let ERR_NEED_MORE: i64 = -1;      // a Conn over bytes the caller carries: feed it more
let ERR_CLOSED: i64 = -2;         // the connection closed; close_code and close_reason say how
let ERR_PROTOCOL: i64 = -3;       // the peer broke the protocol (closed with 1002)
let ERR_UTF8: i64 = -4;           // text that is not UTF-8 (closed with 1007)
let ERR_TOO_BIG: i64 = -5;        // a message past the read limit (closed with 1009)
let ERR_NETWORK: i64 = -6;
let ERR_TLS: i64 = -7;
let ERR_TIMEOUT: i64 = -8;
let ERR_HANDSHAKE: i64 = -9;      // the opening handshake failed (Conn.status: the HTTP status)
let ERR_ARGUMENT: i64 = -10;      // a call that cannot be made now, or with these arguments
let ERR_URL: i64 = -11;
let ERR_PROXY: i64 = -12;
let ERR_COMPRESSION: i64 = -13;   // a compressed message that does not inflate (closed with 1007)

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_NEED_MORE { return "more input needed"; }
    if e == ERR_CLOSED { return "connection closed"; }
    if e == ERR_PROTOCOL { return "protocol error"; }
    if e == ERR_UTF8 { return "text is not UTF-8"; }
    if e == ERR_TOO_BIG { return "message too big"; }
    if e == ERR_NETWORK { return "network error"; }
    if e == ERR_TLS { return "TLS error"; }
    if e == ERR_TIMEOUT { return "timed out"; }
    if e == ERR_HANDSHAKE { return "bad handshake"; }
    if e == ERR_ARGUMENT { return "invalid argument"; }
    if e == ERR_URL { return "bad URL"; }
    if e == ERR_PROXY { return "proxy error"; }
    if e == ERR_COMPRESSION { return "bad compressed data"; }
    return "unknown error";
}

// --- Opcodes and close codes (RFC 6455 §5.2, §7.4) -----------------------------

let CONTINUATION: u8 = 0;
let TEXT: u8 = 1;
let BINARY: u8 = 2;
let CLOSE: u8 = 8;
let PING: u8 = 9;
let PONG: u8 = 10;

fn is_control(op: u8) -> bool { op >= 8 }
fn is_known_opcode(op: u8) -> bool { op <= 2 || (op >= 8 && op <= 10) }

let CLOSE_NORMAL: i64 = 1000;
let CLOSE_GOING_AWAY: i64 = 1001;
let CLOSE_PROTOCOL_ERROR: i64 = 1002;
let CLOSE_UNSUPPORTED_DATA: i64 = 1003;
let CLOSE_NO_STATUS: i64 = 1005;           // never sent: a close without a code
let CLOSE_ABNORMAL: i64 = 1006;            // never sent: the connection ended without a close
let CLOSE_INVALID_PAYLOAD: i64 = 1007;
let CLOSE_POLICY_VIOLATION: i64 = 1008;
let CLOSE_MESSAGE_TOO_BIG: i64 = 1009;
let CLOSE_MANDATORY_EXTENSION: i64 = 1010;
let CLOSE_INTERNAL_ERROR: i64 = 1011;
let CLOSE_SERVICE_RESTART: i64 = 1012;
let CLOSE_TRY_AGAIN_LATER: i64 = 1013;
let CLOSE_BAD_GATEWAY: i64 = 1014;
let CLOSE_TLS_HANDSHAKE: i64 = 1015;       // never sent

// A code a close frame may carry (§7.4.1, and IANA's registry): 1000-1003,
// 1007-1014, and 3000-4999 for libraries and applications.
fn valid_close_code(code: i64) -> bool {
    if code >= 1000 && code <= 1003 { return true; }
    if code >= 1007 && code <= 1014 { return true; }
    return code >= 3000 && code <= 4999;
}

// --- Frame headers (§5.2) -------------------------------------------------------

struct Header {
    fin: bool,
    rsv: u8,              // RSV1-3 as bits 4, 2, 1
    opcode: u8,
    masked: bool,
    key: u8[4],
    length: i64,          // of the payload
    size: i64,            // of the header: 2 to 14 bytes
}

let RSV1: u8 = 4;
let RSV2: u8 = 2;
let RSV3: u8 = 1;

fn empty_header() -> Header {
    Header { fin: false, rsv: 0, opcode: 0, masked: false, key: [0; 4], length: 0, size: 0 }
}

// The header at the start of m: (header, OK), (_, ERR_NEED_MORE) when m
// holds too little of it, (_, ERR_PROTOCOL) for a 64-bit length with its
// top bit set. Nothing else is checked here: what the opcode, the RSV
// bits and the mask may be depends on the connection.
fn parse_header(m: const u8[:]) -> Header, i64 {
    var h = empty_header();
    if m.len < 2 { return h, ERR_NEED_MORE; }
    h.fin = (m[0] & 0x80) != 0;
    h.rsv = (m[0] >> 4) & 7;
    h.opcode = m[0] & 15;
    h.masked = (m[1] & 0x80) != 0;
    let l7 = (m[1] & 0x7f) as i64;
    var p: i64 = 2;
    if l7 == 126 {
        if m.len < 4 { return h, ERR_NEED_MORE; }
        h.length = (m[2] as i64) << 8 | m[3];
        p = 4;
    } else if l7 == 127 {
        if m.len < 10 { return h, ERR_NEED_MORE; }
        if (m[2] & 0x80) != 0 { return h, ERR_PROTOCOL; }
        var v: i64 = 0;
        for k in 8 { v = v << 8 | m[2 + k]; }
        h.length = v;
        p = 10;
    } else {
        h.length = l7;
    }
    if h.masked {
        if m.len < p + 4 { return h, ERR_NEED_MORE; }
        for k in 4 { h.key[k] = m[p + k]; }
        p += 4;
    }
    h.size = p;
    return h, OK;
}

// Appends a frame header: the length in the fewest bytes (§5.2), the
// masking key when masked.
fn put_header(out: u8[>..]&, fin: bool, rsv: u8, op: u8, length: i64, masked: bool, key: const u8[:]) {
    var b0: u8 = op & 15 | (rsv & 7) << 4;
    if fin { b0 |= 0x80; }
    out.push(b0);
    let mbit: u8 = if masked { 0x80 } else { 0 };
    if length < 126 {
        out.push(mbit | length as! u8);
    } else if length < 65536 {
        out.push(mbit | 126);
        out.push((length >> 8) as! u8);
        out.push((length & 0xff) as! u8);
    } else {
        out.push(mbit | 127);
        var s: i64 = 56;
        while s >= 0 {
            out.push(((length >> s) & 0xff) as! u8);
            s -= 8;
        }
    }
    if masked { out.append(key[..4]); }
}

// XORs data with the masking key (§5.3), data starting at the payload's
// byte `pos` (so that a payload can be unmasked in pieces).
fn mask_bytes(data: u8[:], key: const u8[:], pos: i64) {
    var k: u8[4] = [0; 4];
    for j in 4 { k[j] = key[(pos + j) & 3]; }
    var i: i64 = 0;
    // Eight bytes at a time, as a word.
    if data.len >= 16 {
        let w32: u64 = k[0] | (k[1] as u64) << 8 | (k[2] as u64) << 16 | (k[3] as u64) << 24;
        let w = w32 | w32 << 32;
        while i + 8 <= data.len {
            var v: u64 = 0;
            for j in 8 { v |= (data[i + j] as u64) << (8 * j); }
            v ^= w;
            for j in 8 { data[i + j] = ((v >> (8 * j)) & 0xff) as! u8; }
            i += 8;
        }
    }
    while i < data.len {
        data[i] ^= k[i & 3];
        i++;
    }
}

// Appends a whole frame, masked with key when masked.
fn put_frame(out: u8[>..]&, fin: bool, rsv: u8, op: u8, payload: const u8[:], masked: bool, key: const u8[:]) {
    put_header(out, fin, rsv, op, payload.len, masked, key);
    let at = out.len;
    out.append(payload);
    if masked { mask_bytes(out[at..], key, 0); }
}

// --- UTF-8, checked as it arrives (RFC 3629 §4) --------------------------------
//
// A text message is checked byte by byte across its frames, so that one
// that cannot be UTF-8 is refused at the byte that shows it (Autobahn's
// "fail fast"): what may follow a lead byte is a range (overlong forms,
// surrogates and code points past U+10FFFF are left out of it).

struct Utf8 { rem: u8, lo: u8, hi: u8 }

fn utf8_state() -> Utf8 { Utf8 { rem: 0, lo: 0x80, hi: 0xbf } }

// Takes more bytes: false at the first that cannot belong to UTF-8.
fn utf8_feed(s: Utf8&, data: const u8[:]) -> bool {
    var i: i64 = 0;
    let n = data.len;
    var rem = s.rem;
    var lo = s.lo;
    var hi = s.hi;
    while i < n {
        let c = data[i];
        if rem == 0 {
            if c < 0x80 {
                i++;
                // ASCII runs, eight bytes at a time.
                while i + 8 <= n {
                    var v: u64 = 0;
                    for j in 8 { v |= data[i + j] as u64 << (8 * j); }
                    if (v & 0x8080808080808080) != 0 { break; }
                    i += 8;
                }
                continue;
            }
            lo = 0x80;
            hi = 0xbf;
            if c >= 0xc2 && c <= 0xdf { rem = 1; }
            else if c == 0xe0 { rem = 2; lo = 0xa0; }
            else if (c >= 0xe1 && c <= 0xec) || c == 0xee || c == 0xef { rem = 2; }
            else if c == 0xed { rem = 2; hi = 0x9f; }
            else if c == 0xf0 { rem = 3; lo = 0x90; }
            else if c >= 0xf1 && c <= 0xf3 { rem = 3; }
            else if c == 0xf4 { rem = 3; hi = 0x8f; }
            else {
                s.rem = rem;
                return false;
            }
        } else {
            if c < lo || c > hi {
                s.rem = rem;
                return false;
            }
            rem--;
            lo = 0x80;
            hi = 0xbf;
        }
        i++;
    }
    s.rem = rem;
    s.lo = lo;
    s.hi = hi;
    return true;
}

// Whether what was fed ends on a whole character.
fn utf8_complete(s: const Utf8&) -> bool { s.rem == 0 }

fn valid_utf8(data: const u8[:]) -> bool {
    var s = utf8_state();
    return utf8_feed(s, data) && utf8_complete(s);
}

// --- Close frames (§5.5.1) -------------------------------------------------------

// A close frame's payload: nothing, or the code and a reason of at most
// 123 bytes of UTF-8. CLOSE_NO_STATUS sends an empty one.
fn put_close_payload(out: u8[>..]&, code: i64, reason: const u8[:]) {
    if code == CLOSE_NO_STATUS { return; }
    out.push(((code >> 8) & 0xff) as! u8);
    out.push((code & 0xff) as! u8);
    out.append(reason[..min(reason.len, 123)]);
}

// Reads a close frame's payload: its code (CLOSE_NO_STATUS when empty) and
// reason, and OK, ERR_PROTOCOL (one byte, or a code that may not be sent)
// or ERR_UTF8 (a reason that is not UTF-8).
fn parse_close_payload(p: const u8[:]) -> i64, const u8[:], i64 {
    if p.len == 0 { return CLOSE_NO_STATUS, p[..0], OK; }
    if p.len == 1 { return 0, p[..0], ERR_PROTOCOL; }
    let code = (p[0] as i64) << 8 | p[1];
    if !valid_close_code(code) { return code, p[..0], ERR_PROTOCOL; }
    if !valid_utf8(p[2..]) { return code, p[..0], ERR_UTF8; }
    return code, p[2..], OK;
}

// --- The handshake's key (§4.2.2) -------------------------------------------------

let ACCEPT_GUID: const u8[:] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Sec-WebSocket-Accept for a Sec-WebSocket-Key: base64(SHA-1(key + GUID)).
fn accept_key(key: const u8[:]) -> u8[..28] {
    var s = bignum::sha1_init();
    bignum::sha1_update(s, key);
    bignum::sha1_update(s, ACCEPT_GUID);
    let d = bignum::sha1_final(s);
    var t: u8[>..] = [];
    base64::encode(t, d);
    var out: u8[..28] = [];
    out.append(t[..]);
    return out;
}

// Whether a Sec-WebSocket-Key is the base64 of 16 bytes (§4.2.1 point 5).
fn valid_key(key: const u8[:]) -> bool {
    if key.len != 24 { return false; }
    var d: u8[>..] = [];
    return base64::decode(d, key) && d.len == 16;
}
