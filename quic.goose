// quic: QUIC version 1 (RFC 9000, 9001, 9002) and HTTP/3 (RFC 9114, with
// QPACK, RFC 9204) for the Goose language, both sides. The connection is
// sans-IO: it takes datagrams and the time, and gives datagrams and the
// time it next wants to be woken; a driver carries them over UDP. TLS 1.3
// is gslib's tls, in its QUIC mode (RFC 9001 §4).
//
//   quic             this module: versions, transport error codes,
//                    variable-length integers
//   quic.packet      packet protection: Initial secrets, keys from a TLS
//                    secret, header protection, AEAD, packet numbers, the
//                    Retry integrity tag, long and short headers
//   quic.frame       every frame of RFC 9000 §19, read and written; which
//                    packets may carry which
//   quic.params      transport parameters (§18)
//   quic.recovery    RFC 9002: RTT, loss detection, PTO, NewReno
//   quic.stream      send and receive buffers: reassembly, retransmission,
//                    flow control's limits
//   quic.conn        Conn: a connection, sans-IO; streams
//   quic.transport   over UDP: dial and step for a client, listen and
//                    serve_step for a server
//   quic.qpack       QPACK, static table only
//   quic.h3          HTTP/3 frames, settings, the parsing of messages
//   quic.http3       HTTP/3 on a Conn: control streams, requests, responses
//
// All are in the namespace quic.
//
//   var c, fd, e = quic::dial("example.com", 443, cfg, 5000);   // cfg.alpn has "h3"
//   var h = quic::h3(false);
//   let id = quic::h3_send_request(c, h, "GET", "https", "example.com", "/", "", "");
//   while !quic::h3_done(h, id) { let r = quic::step(fd, c, cfg, 50); quic::h3_poll(c, h); }
//   let status = quic::h3_status(h, id);

namespace quic;

import std;

let VERSION_1: u32 = 0x00000001;

// Transport error codes (RFC 9000 §20.1); a TLS alert is CRYPTO_ERROR + it.
let NO_ERROR: u64                  = 0x00;
let INTERNAL_ERROR: u64            = 0x01;
let CONNECTION_REFUSED: u64        = 0x02;
let FLOW_CONTROL_ERROR: u64        = 0x03;
let STREAM_LIMIT_ERROR: u64        = 0x04;
let STREAM_STATE_ERROR: u64        = 0x05;
let FINAL_SIZE_ERROR: u64          = 0x06;
let FRAME_ENCODING_ERROR: u64      = 0x07;
let TRANSPORT_PARAMETER_ERROR: u64 = 0x08;
let CONNECTION_ID_LIMIT_ERROR: u64 = 0x09;
let PROTOCOL_VIOLATION: u64        = 0x0a;
let INVALID_TOKEN: u64             = 0x0b;
let APPLICATION_ERROR: u64         = 0x0c;
let CRYPTO_BUFFER_EXCEEDED: u64    = 0x0d;
let KEY_UPDATE_ERROR: u64          = 0x0e;
let AEAD_LIMIT_REACHED: u64        = 0x0f;
let NO_VIABLE_PATH: u64            = 0x10;
let CRYPTO_ERROR: u64              = 0x100;

let MAX_VARINT: u64 = 0x3fffffffffffffff;

// --- Variable-length integers (RFC 9000 §16) ---------------------------------------

// The bytes v takes: 1, 2, 4 or 8.
fn varint_len(v: u64) -> i64 {
    if v < 0x40 { return 1; }
    if v < 0x4000 { return 2; }
    if v < 0x40000000 { return 4; }
    return 8;
}

// Appends v (at most MAX_VARINT) in its shortest form.
fn put_varint(out: u8[>..]&, v: u64) {
    assert(v <= MAX_VARINT);
    let n = varint_len(v);
    let prefix: u64 = if n == 1 { 0 } else if n == 2 { 1 } else if n == 4 { 2 } else { 3 };
    var k = n;
    while k > 0 {
        k--;
        var b = (v >> (8 * k as! u64)) as! u8;
        if k == n - 1 { b = b | (prefix << 6) as! u8; }
        out.push(b);
    }
}

// Appends v in exactly n bytes (1, 2, 4 or 8), when it fits: a length
// written before what it measures is known.
fn put_varint_n(out: u8[>..]&, v: u64, n: i64) {
    let prefix: u64 = if n == 1 { 0 } else if n == 2 { 1 } else if n == 4 { 2 } else { 3 };
    assert(varint_len(v) <= n && (n == 1 || n == 2 || n == 4 || n == 8));
    var k = n;
    while k > 0 {
        k--;
        var b = (v >> (8 * k as! u64)) as! u8;
        if k == n - 1 { b = b | (prefix << 6) as! u8; }
        out.push(b);
    }
}

// The varint at b[at]: its value and the position after it, or false
// when b ends inside it.
fn read_varint(b: const u8[:], at: i64) -> u64, i64, bool {
    if at < 0 || at >= b.len { return 0, at, false; }
    let n: i64 = 1 << (b[at] >> 6);
    if at + n > b.len { return 0, at, false; }
    var v: u64 = b[at] & 0x3f;
    for k in 1..n { v = v << 8 | b[at + k]; }
    return v, at + n, true;
}

// A reader over a packet's or frame's bytes; bad once it ran out.
struct Rd { pos: i64, end: i64, bad: bool }

fn reader(b: const u8[:]) -> Rd { Rd { pos: 0, end: b.len, bad: false } }

fn rd_varint(r: Rd&, b: const u8[:]) -> u64 {
    if r.bad { return 0; }
    let v, next, ok = read_varint(b[..r.end], r.pos);
    if !ok { r.bad = true; return 0; }
    r.pos = next;
    return v;
}

fn rd_u8(r: Rd&, b: const u8[:]) -> u8 {
    if r.bad || r.pos >= r.end { r.bad = true; return 0; }
    r.pos++;
    return b[r.pos - 1];
}

// n bytes: their offset (b[at..at + n]), or bad.
fn rd_bytes(r: Rd&, n: i64) -> i64 {
    if r.bad || n < 0 || n > r.end - r.pos { r.bad = true; return r.pos; }
    let at = r.pos;
    r.pos += n;
    return at;
}

fn rd_done(r: const Rd&) -> bool { !r.bad && r.pos == r.end }

fn put_u32be(out: u8[>..]&, v: u32) {
    out.push((v >> 24) as! u8);
    out.push((v >> 16) as! u8);
    out.push((v >> 8) as! u8);
    out.push(v as! u8);
}

fn u32be(b: const u8[:], at: i64) -> u32 {
    (b[at] as u32) << 24 | (b[at + 1] as u32) << 16 | (b[at + 2] as u32) << 8 | b[at + 3]
}

// A transport error code's name, for messages.
fn error_name(code: u64) -> const u8[:] {
    if code == NO_ERROR { return "NO_ERROR"; }
    if code == INTERNAL_ERROR { return "INTERNAL_ERROR"; }
    if code == CONNECTION_REFUSED { return "CONNECTION_REFUSED"; }
    if code == FLOW_CONTROL_ERROR { return "FLOW_CONTROL_ERROR"; }
    if code == STREAM_LIMIT_ERROR { return "STREAM_LIMIT_ERROR"; }
    if code == STREAM_STATE_ERROR { return "STREAM_STATE_ERROR"; }
    if code == FINAL_SIZE_ERROR { return "FINAL_SIZE_ERROR"; }
    if code == FRAME_ENCODING_ERROR { return "FRAME_ENCODING_ERROR"; }
    if code == TRANSPORT_PARAMETER_ERROR { return "TRANSPORT_PARAMETER_ERROR"; }
    if code == CONNECTION_ID_LIMIT_ERROR { return "CONNECTION_ID_LIMIT_ERROR"; }
    if code == PROTOCOL_VIOLATION { return "PROTOCOL_VIOLATION"; }
    if code == INVALID_TOKEN { return "INVALID_TOKEN"; }
    if code == APPLICATION_ERROR { return "APPLICATION_ERROR"; }
    if code == CRYPTO_BUFFER_EXCEEDED { return "CRYPTO_BUFFER_EXCEEDED"; }
    if code == KEY_UPDATE_ERROR { return "KEY_UPDATE_ERROR"; }
    if code == AEAD_LIMIT_REACHED { return "AEAD_LIMIT_REACHED"; }
    if code == NO_VIABLE_PATH { return "NO_VIABLE_PATH"; }
    if code >= CRYPTO_ERROR && code < CRYPTO_ERROR + 0x100 { return "CRYPTO_ERROR"; }
    return "unknown";
}
