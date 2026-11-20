// websocket.conn: a connection after the opening handshake (RFC 6455 §5
// to §7): reading and writing messages, whole or in parts, ping, pong and
// close, permessage-deflate (RFC 7692) when it was agreed.
//
// A Conn is a root struct, declared where it is used and filled by dial,
// accept, accept_tls or upgrade (or by start, for bytes the caller
// carries). It reads from its socket (through TLS for wss) and writes to
// it itself; without a socket (fd -1) it takes bytes from feed, keeps
// what it would send for take_output, and read calls end with
// ERR_NEED_MORE when they need more.
//
//   var msg: u8[>..] = [];
//   loop {
//       let kind, e = websocket::read_message(c, msg);    // TEXT or BINARY
//       if e != websocket::OK { break; }                  // ERR_CLOSED: c.close_code, c.close_reason
//       websocket::write_message(c, kind, msg);
//   }
//
// As gorilla's, a Conn answers pings with pongs and echoes the peer's
// close by itself while it reads, and a failure closes it with the code
// the RFC names (1002 for a protocol error, 1007 for text that is not
// UTF-8 or data that does not inflate, 1009 past the read limit). Text is
// checked as it arrives, so that a message is refused at the first byte
// that cannot be UTF-8.

namespace websocket;

import std;
import net;
import crypto.tls;
import crypto.tls.handshake;
import crypto.bignum;
import crypto.bignum.chacha20;
import compress;
import compress.flate;
import compress.deflate;
import entropy;
import websocket;
import websocket.deflate;

// A connection's settings; gorilla's names where it has them.
struct Options {
    read_limit: i64,              // a message's most bytes (after inflating); 0: none. 32 MiB
    write_buffer: i64,            // the parts of a message written as they come go in frames this big: 4096
    fragment_size: i64,           // write_message splits a message into frames this big; 0: one frame
    compress_level: i64,          // DEFLATE's level, 1 (gorilla's) to 9; -2 Huffman only
    compress_threshold: i64,      // messages shorter than this are sent uncompressed: 0
    auto_pong: bool,              // answer pings: true
    control_events: bool,         // read_message hands pings and pongs over too (as PING, PONG): false
    read_timeout_ms: i32,         // for each read from the socket; 0: none
    write_timeout_ms: i32,        // for each write: 30000
    close_timeout_ms: i32,        // close's wait for the peer's close: 5000
}

fn options() -> Options {
    Options { read_limit: 33554432, write_buffer: 4096, fragment_size: 0, compress_level: 1,
              compress_threshold: 0, auto_pong: true, control_events: false, read_timeout_ms: 0,
              write_timeout_ms: 30000, close_timeout_ms: 5000 }
}

// What step found.
let EV_NEED_MORE: u8 = 0;
let EV_START: u8 = 1;         // a data message starts (st.msg_op)
let EV_DATA: u8 = 2;          // some of its payload was appended
let EV_END: u8 = 3;           // it is complete
let EV_PING: u8 = 4;          // control: payload in c.control
let EV_PONG: u8 = 5;
let EV_CLOSE: u8 = 6;         // the peer's close came (and was answered)
let EV_ERROR: u8 = 7;         // the connection failed: st.err

// The state of reading and writing, of fixed size.
struct State {
    open: bool,                  // started, and not yet closed or failed
    reading: bool,               // inside a data message
    msg_op: u8,                  // its opcode, TEXT or BINARY
    compressed: bool,            // it has RSV1
    z_ended: bool,               // its DEFLATE stream ended (a final block)
    msg_len: i64,                // its bytes so far (inflated)
    utf8: Utf8,
    in_frame: bool,              // a frame's header is read and its payload is not all used
    fr: Header,
    fr_done: i64,                // of its payload, used
    writing: bool,               // a message written in parts is open
    wop: u8,
    wfirst: bool,                // none of its frames has gone yet
    wcompress: bool,
    sent_close: bool,
    got_close: bool,
    done: bool,                  // the socket should be closed (and is, when the Conn has one)
    err: i64,                    // the error that ended it, if one did
}

fn new_state() -> State {
    State { open: false, reading: false, msg_op: 0, compressed: false, z_ended: false, msg_len: 0,
            utf8: utf8_state(), in_frame: false, fr: empty_header(), fr_done: 0, writing: false, wop: 0,
            wfirst: false, wcompress: false, sent_close: false, got_close: false, done: false, err: OK }
}

fn empty_server_config() -> tls::ServerConfig {
    let s, ok = tls::server_config("");
    return s;
}

root struct Conn {
    opt: Options = options(),
    is_client: bool = false,
    fd: i64 = -1,                 // -1: bytes the caller carries (feed, take_output)
    on_tls: bool = false,
    tc: tls::Conn[>..] = [],      // the TLS connection, when on_tls
    ccfg: tls::ClientConfig = tls::client_config("", ""),
    scfg: tls::ServerConfig = empty_server_config(),
    st: State = new_state(),
    pmd: Pmd = no_pmd(),          // permessage-deflate, when pmd.on
    subprotocol: u8[..256] = [],  // agreed in the handshake
    status: i64 = 0,              // a client's: the handshake's HTTP status
    why: u8[..128] = [],          // a failed handshake: why
    head: u8[>..] = [],           // the handshake: a client's answer, a server's request (head only)
    close_code: i64 = 0,          // the peer's close: its code (CLOSE_NO_STATUS: none; CLOSE_ABNORMAL: no close came)
    close_reason: u8[..123] = [],
    control: u8[..125] = [],      // the last ping's or pong's payload
    inbuf: u8[>..] = [],          // bytes come and not yet used, from inpos on
    inpos: i64 = 0,
    raw: u8[>..] = [],            // a read's bytes, before TLS
    wire: u8[>..] = [],           // frames to send
    rec: u8[>..] = [],            // the same, as TLS records
    zout: u8[>..] = [],           // a message compressed
    wbuf: u8[>..] = [],           // a message written in parts: what is not yet in a frame
    scratch: u8[>..] = [],        // messages skipped
    infl: compress::Inflate[>..] = [],
    defl: compress::Deflate[>..] = [],
    mk_key: u8[32] = [0; 32],     // masking keys: a ChaCha20 stream (§10.3: unpredictable)
    mk_block: u8[64] = [0; 64],
    mk_ctr: u32 = 0,
    mk_pos: i64 = 64,
}

// Starts a connection after its handshake: the side, what was agreed, and
// bytes that came after the handshake's head (already frames).
fn start(c: Conn&, is_client: bool, p: Pmd, early: const u8[:]) {
    c.is_client = is_client;
    c.st = new_state();
    c.st.open = true;
    c.pmd = p;
    c.close_code = 0;
    c.close_reason.clear();
    c.inbuf.clear();
    c.inbuf.append(early);
    c.inpos = 0;
    c.wire.clear();
    c.infl.clear();
    c.defl.clear();
    if p.on {
        c.infl.push(compress::inflate_reader());
        c.defl.push(compress::deflate_writer(c.opt.compress_level));
        let bits = if is_client { p.client_max_window_bits } else { p.server_max_window_bits };
        compress::deflate_set_window_bits(c.defl[0], bits);
    }
    if is_client {
        entropy::random_bytes(c.mk_key);
        c.mk_ctr = 0;
        c.mk_pos = 64;
    }
}

fn mask_key(c: Conn&) -> u8[4] {
    if c.mk_pos + 4 > 64 {
        let zero: u8[12] = [0; 12];
        c.mk_block = bignum::chacha20_block(c.mk_key, c.mk_ctr, zero);
        c.mk_ctr++;
        if c.mk_ctr == 0 { entropy::random_bytes(c.mk_key); }
        c.mk_pos = 0;
    }
    var k: u8[4] = [0; 4];
    for j in 4 { k[j] = c.mk_block[c.mk_pos + j]; }
    c.mk_pos += 4;
    return k;
}

// Appends a frame to the wire, masked when this is a client.
fn put_out(c: Conn&, fin: bool, rsv: u8, op: u8, payload: const u8[:]) {
    if c.is_client {
        let k = mask_key(c);
        put_frame(c.wire, fin, rsv, op, payload, true, k);
    } else {
        put_frame(c.wire, fin, rsv, op, payload, false, "");
    }
}

// --- I/O ------------------------------------------------------------------------

fn net_error(n: i64) -> i64 { if n == net::ERR_TIMEOUT { ERR_TIMEOUT } else { ERR_NETWORK } }

// Sends what is on the wire (a Conn without a socket keeps it for
// take_output).
fn flush(c: Conn&) -> i64 {
    if c.fd < 0 || c.wire.len == 0 { return OK; }
    var data = c.wire[..];
    if c.on_tls {
        c.rec.clear();
        if !tls::send(c.tc[0], c.wire, c.rec) { return ERR_TLS; }
        let n = net::write(c.fd, c.rec, c.opt.write_timeout_ms);
        c.wire.clear();
        if n < 0 { return net_error(n); }
        return OK;
    }
    let n = net::write(c.fd, data, c.opt.write_timeout_ms);
    c.wire.clear();
    if n < 0 { return net_error(n); }
    return OK;
}

// Reads more from the socket onto inbuf: OK, ERR_CLOSED at its end, or
// an error.
fn fill(c: Conn&, timeout_ms: i32) -> i64 {
    if c.inpos > 0 {
        if c.inpos >= c.inbuf.len {
            c.inbuf.clear();
        } else {
            c.raw.clear();
            c.raw.append(c.inbuf[c.inpos..]);
            c.inbuf.clear();
            c.inbuf.append(c.raw);
        }
        c.inpos = 0;
    }
    loop {
        c.raw.resize(65536, 0);
        let n = net::read(c.fd, c.raw, timeout_ms);
        if n == 0 { return ERR_CLOSED; }
        if n < 0 { return net_error(n); }
        if !c.on_tls {
            c.inbuf.append(c.raw[..n]);
            return OK;
        }
        var data: u8[>..] = [];
        data.append(c.raw[..n]);
        let before = c.inbuf.len;
        c.rec.clear();
        var r: i64 = 0;
        if c.is_client { r = tls::feed(c.tc[0], c.ccfg, data, c.rec, c.inbuf); }
        else { r = tls::server_feed(c.tc[0], c.scfg, data, c.rec, c.inbuf); }
        if c.rec.len > 0 { let w = net::write(c.fd, c.rec, c.opt.write_timeout_ms); }
        if r < 0 { return ERR_TLS; }
        if c.inbuf.len > before { return OK; }
        if tls::closed(c.tc[0]) { return ERR_CLOSED; }
    }
    return OK;
}

// Closes the socket: TLS's close_notify first; a server shuts its writing
// down and reads what still comes for a moment, so that its last frames
// are not overtaken by a reset.
fn shut(c: Conn&) {
    c.st.done = true;
    c.st.open = false;
    if c.fd < 0 { return; }
    if c.on_tls && tls::connected(c.tc[0]) {
        c.rec.clear();
        tls::close(c.tc[0], c.rec);
        let w = net::write(c.fd, c.rec, 1000);
    }
    net::shutdown(c.fd, net::SHUT_WRITE);
    c.raw.resize(65536, 0);
    for k in 20 {
        let n = net::read(c.fd, c.raw, 100);
        if n == 0 || (n < 0 && n != net::ERR_TIMEOUT) { break; }
    }
    net::close(c.fd);
    c.fd = -1;
}

// --- Bytes the caller carries ---------------------------------------------------------

// Bytes from the peer, for a Conn without a socket.
fn feed(c: Conn&, data: const u8[:]) {
    if c.inpos == c.inbuf.len {
        c.inbuf.clear();
        c.inpos = 0;
    }
    c.inbuf.append(data);
}

// What the Conn would send, appended to out and forgotten.
fn take_output(c: Conn&, out: u8[>..]&) {
    out.append(c.wire);
    c.wire.clear();
}

// Whether the connection is over: its socket closed, or to be closed by
// the caller (closing handshake done, or failed).
fn closed(c: const Conn&) -> bool { c.st.done }

// --- Reading -------------------------------------------------------------------------

// Fails the connection (§7.1.7): a close with the code, then the end.
fn fail(c: Conn&, code: i64, err: i64) -> u8 {
    if !c.st.sent_close && !c.st.done {
        var p: u8[>..] = [];
        put_close_payload(p, code, "");
        put_out(c, true, 0, CLOSE, p);
        c.st.sent_close = true;
        let e = flush(c);
    }
    if c.close_code == 0 { c.close_code = CLOSE_ABNORMAL; }
    c.st.err = err;
    shut(c);
    return EV_ERROR;
}

// Inflates input onto out within the read limit, checking text as it
// goes: OK or the event of the failure.
fn inflate_into(c: Conn&, input: const u8[:], out: u8[>..]&) -> u8 {
    var p: i64 = 0;
    loop {
        if c.st.z_ended { return EV_NONE_OK; }
        let start = out.len;
        out.resize(start + 65536, 0);
        let used, made, st = compress::inflate_read(c.infl[0], input[p..], out[start..]);
        p += used;
        out.resize(start + made);
        if st < 0 { return fail(c, CLOSE_INVALID_PAYLOAD, ERR_COMPRESSION); }
        if made > 0 {
            c.st.msg_len += made;
            if c.opt.read_limit > 0 && c.st.msg_len > c.opt.read_limit { return fail(c, CLOSE_MESSAGE_TOO_BIG, ERR_TOO_BIG); }
            if c.st.msg_op == TEXT && !utf8_feed(c.st.utf8, out[start..]) { return fail(c, CLOSE_INVALID_PAYLOAD, ERR_UTF8); }
        }
        if st == compress::STREAM_END { c.st.z_ended = true; }
        if p >= input.len && made < 65536 { return EV_NONE_OK; }
    }
    return EV_NONE_OK;
}

let EV_NONE_OK: u8 = 255;

// The tail RFC 7692 §7.2.2 has the reader put back.
let PMD_TAIL: u8[4] = [0, 0, 0xff, 0xff];

// Handles a control frame whose payload is all here.
fn control_frame(c: Conn&, h: const Header&, p: const u8[:]) -> u8 {
    if h.opcode == PING {
        c.control.clear();
        c.control.append(p);
        if c.opt.auto_pong && !c.st.sent_close {
            put_out(c, true, 0, PONG, p);
            let e = flush(c);
        }
        return EV_PING;
    }
    if h.opcode == PONG {
        c.control.clear();
        c.control.append(p);
        return EV_PONG;
    }
    let code, reason, e = parse_close_payload(p);
    if e == ERR_UTF8 { return fail(c, CLOSE_INVALID_PAYLOAD, ERR_UTF8); }
    if e != OK { return fail(c, CLOSE_PROTOCOL_ERROR, ERR_PROTOCOL); }
    c.close_code = code;
    c.close_reason.clear();
    c.close_reason.append(reason);
    c.st.got_close = true;
    if !c.st.sent_close {
        // §5.5.1: the answer echoes the code.
        var q: u8[>..] = [];
        put_close_payload(q, code, "");
        put_out(c, true, 0, CLOSE, q);
        c.st.sent_close = true;
        let fe = flush(c);
    }
    // §7.1.1: the server closes the TCP connection first; a client waits
    // a moment for it to.
    if c.is_client && c.fd >= 0 {
        c.raw.resize(65536, 0);
        for k in 20 {
            let n = net::read(c.fd, c.raw, 100);
            if n == 0 || (n < 0 && n != net::ERR_TIMEOUT) { break; }
        }
    }
    shut(c);
    return EV_CLOSE;
}

// Takes the next event from the bytes in inbuf: payload of data messages
// is appended to out.
fn step(c: Conn&, out: u8[>..]&) -> u8 {
    if c.st.err != OK { return EV_ERROR; }
    if c.st.got_close { return EV_CLOSE; }
    if c.st.done { return EV_ERROR; }
    loop {
        let avail = c.inbuf.len - c.inpos;
        if !c.st.in_frame {
            let h, e = parse_header(c.inbuf[c.inpos..]);
            if e == ERR_NEED_MORE { return EV_NEED_MORE; }
            if e != OK { return fail(c, CLOSE_PROTOCOL_ERROR, ERR_PROTOCOL); }
            if (h.rsv & (RSV2 | RSV3)) != 0 || !is_known_opcode(h.opcode) { return fail(c, CLOSE_PROTOCOL_ERROR, ERR_PROTOCOL); }
            // §5.1: a client masks every frame, a server none.
            if h.masked == c.is_client { return fail(c, CLOSE_PROTOCOL_ERROR, ERR_PROTOCOL); }
            if is_control(h.opcode) {
                if !h.fin || h.length > 125 || h.rsv != 0 { return fail(c, CLOSE_PROTOCOL_ERROR, ERR_PROTOCOL); }
                if avail < h.size + h.length { return EV_NEED_MORE; }
                let at = c.inpos + h.size;
                if h.masked { mask_bytes(c.inbuf[at..at + h.length], h.key, 0); }
                c.inpos = at + h.length;
                var p: u8[..125] = [];
                p.append(c.inbuf[at..at + h.length]);
                return control_frame(c, h, p);
            }
            var starts = false;
            if h.opcode == CONTINUATION {
                if !c.st.reading || h.rsv != 0 { return fail(c, CLOSE_PROTOCOL_ERROR, ERR_PROTOCOL); }
            } else {
                if c.st.reading { return fail(c, CLOSE_PROTOCOL_ERROR, ERR_PROTOCOL); }
                if (h.rsv & RSV1) != 0 && !c.pmd.on { return fail(c, CLOSE_PROTOCOL_ERROR, ERR_PROTOCOL); }
                starts = true;
            }
            let compressed = if starts { (h.rsv & RSV1) != 0 } else { c.st.compressed };
            // Compared without adding: a frame may say it is 2^63 - 1 bytes long.
            if !compressed && c.opt.read_limit > 0 && h.length > c.opt.read_limit - c.st.msg_len {
                return fail(c, CLOSE_MESSAGE_TOO_BIG, ERR_TOO_BIG);
            }
            c.inpos += h.size;
            c.st.fr = h;
            c.st.fr_done = 0;
            c.st.in_frame = true;
            if starts {
                c.st.reading = true;
                c.st.msg_op = h.opcode;
                c.st.compressed = compressed;
                c.st.msg_len = 0;
                c.st.utf8 = utf8_state();
                if compressed {
                    let peer_no_takeover = if c.is_client { c.pmd.server_no_context_takeover } else { c.pmd.client_no_context_takeover };
                    if peer_no_takeover { compress::inflate_reset(c.infl[0]); }
                    else if c.st.z_ended { compress::inflate_continue(c.infl[0]); }
                    c.st.z_ended = false;
                }
                return EV_START;
            }
            continue;
        }
        // The payload of a data frame, as much of it as is here.
        let h = c.st.fr;
        let take = min(avail, h.length - c.st.fr_done);
        var made = false;
        if take > 0 {
            let at = c.inpos;
            if h.masked { mask_bytes(c.inbuf[at..at + take], h.key, c.st.fr_done); }
            if c.st.compressed {
                let before = out.len;
                let ev = inflate_into(c, c.inbuf[at..at + take], out);
                if ev != EV_NONE_OK { return ev; }
                made = out.len > before;
            } else {
                let start = out.len;
                out.append(c.inbuf[at..at + take]);
                c.st.msg_len += take;
                if c.st.msg_op == TEXT && !utf8_feed(c.st.utf8, out[start..]) { return fail(c, CLOSE_INVALID_PAYLOAD, ERR_UTF8); }
                made = true;
            }
            c.inpos += take;
            c.st.fr_done += take;
        }
        if c.st.fr_done < h.length {
            if made { return EV_DATA; }
            return EV_NEED_MORE;
        }
        c.st.in_frame = false;
        if !h.fin {
            if made { return EV_DATA; }
            continue;
        }
        if c.st.compressed {
            let ev = inflate_into(c, PMD_TAIL, out);
            if ev != EV_NONE_OK { return ev; }
        }
        if c.st.msg_op == TEXT && !utf8_complete(c.st.utf8) { return fail(c, CLOSE_INVALID_PAYLOAD, ERR_UTF8); }
        c.st.reading = false;
        return EV_END;
    }
    return EV_NEED_MORE;
}

// What a read gives back when the connection ends.
fn ended(c: Conn&, ev: u8) -> i64 {
    if ev == EV_CLOSE { return ERR_CLOSED; }
    return c.st.err;
}

// Gets more bytes: OK, or the error that ends the read.
fn more(c: Conn&) -> i64 {
    if c.fd < 0 { return ERR_NEED_MORE; }
    let e = fill(c, c.opt.read_timeout_ms);
    if e == OK { return OK; }
    if e == ERR_TIMEOUT { return e; }
    // The connection ended without a close (§7.1.5: 1006).
    if c.close_code == 0 { c.close_code = CLOSE_ABNORMAL; }
    c.st.err = if e == ERR_CLOSED { ERR_CLOSED } else { e };
    shut(c);
    return c.st.err;
}

// Reads the next message whole into msg (cleared first): TEXT or BINARY
// and OK; PING or PONG (payload in c.control) when control_events is on;
// or 0 and the error: ERR_CLOSED once the peer closed (close_code,
// close_reason) or the connection ended, ERR_NEED_MORE without a socket
// (call again with the same msg once more is fed), or the failure.
fn read_message(c: Conn&, msg: u8[>..]&) -> u8, i64 {
    if !c.st.reading { msg.clear(); }
    loop {
        let ev = step(c, msg);
        if ev == EV_END { return c.st.msg_op, OK; }
        if ev == EV_START || ev == EV_DATA { continue; }
        if ev == EV_PING || ev == EV_PONG {
            if c.opt.control_events { return if ev == EV_PING { PING } else { PONG }, OK; }
            continue;
        }
        if ev == EV_CLOSE || ev == EV_ERROR { return 0, ended(c, ev); }
        let e = more(c);
        if e != OK { return 0, e; }
    }
    return 0, ERR_NETWORK;
}

// Waits for the next message to start (what is left of one being read is
// skipped): its type, TEXT or BINARY, and OK, or 0 and an error as
// read_message's. Its payload then comes from read_part.
fn next_message(c: Conn&) -> u8, i64 {
    loop {
        c.scratch.clear();
        let ev = step(c, c.scratch);
        if ev == EV_START { return c.st.msg_op, OK; }
        if ev == EV_DATA || ev == EV_END || ev == EV_PING || ev == EV_PONG { continue; }
        if ev == EV_CLOSE || ev == EV_ERROR { return 0, ended(c, ev); }
        let e = more(c);
        if e != OK { return 0, e; }
    }
    return 0, ERR_NETWORK;
}

// Appends the next part of the message next_message started to out (a
// frame's payload, or what it inflates to): how many bytes, whether the
// message is complete with them, and OK or an error as read_message's.
fn read_part(c: Conn&, out: u8[>..]&) -> i64, bool, i64 {
    if !c.st.reading { return 0, true, OK; }
    let start = out.len;
    loop {
        let ev = step(c, out);
        if ev == EV_DATA { return out.len - start, false, OK; }
        if ev == EV_END { return out.len - start, true, OK; }
        if ev == EV_PING || ev == EV_PONG { continue; }
        if ev == EV_CLOSE || ev == EV_ERROR { return out.len - start, false, ended(c, ev); }
        let e = more(c);
        if e != OK { return out.len - start, false, e; }
    }
    return 0, false, ERR_NETWORK;
}

// --- Writing -------------------------------------------------------------------------

fn can_write(c: const Conn&) -> i64 {
    if c.st.done || c.st.sent_close { return ERR_CLOSED; }
    if !c.st.open { return ERR_ARGUMENT; }
    return OK;
}

// The compressor, ready for a message.
fn deflater_for_message(c: Conn&) {
    let own_no_takeover = if c.is_client { c.pmd.client_no_context_takeover } else { c.pmd.server_no_context_takeover };
    if own_no_takeover { compress::deflate_reset(c.defl[0]); }
}

// Sends a message, TEXT (data must be UTF-8: it is not checked here) or
// BINARY: compressed when permessage-deflate was agreed and it is not
// shorter than compress_threshold, in frames of fragment_size if set.
fn write_message(c: Conn&, op: u8, data: const u8[:]) -> i64 {
    let e = can_write(c);
    if e != OK { return e; }
    if c.st.writing || (op != TEXT && op != BINARY) { return ERR_ARGUMENT; }
    var rsv: u8 = 0;
    var compressed = false;
    if c.pmd.on && data.len >= c.opt.compress_threshold {
        deflater_for_message(c);
        c.zout.clear();
        if compress::deflate_write(c.defl[0], data, c.zout) != 0 || compress::deflate_flush(c.defl[0], c.zout) != 0 {
            return ERR_COMPRESSION;
        }
        c.zout.resize(c.zout.len - 4);          // the sync flush's 00 00 ff ff (§7.2.1)
        rsv = RSV1;
        compressed = true;
    }
    let n = if compressed { c.zout.len } else { data.len };
    let size = if c.opt.fragment_size > 0 { c.opt.fragment_size } else { n };
    var p: i64 = 0;
    var first = true;
    loop {
        let q = min(n, p + size);
        let fin = q == n;
        let fop = if first { op } else { CONTINUATION };
        let frsv = if first { rsv } else { 0 };
        if compressed { put_out(c, fin, frsv, fop, c.zout[p..q]); }
        else { put_out(c, fin, frsv, fop, data[p..q]); }
        first = false;
        p = q;
        if fin { break; }
    }
    return flush(c);
}

// Starts a message written in parts (gorilla's NextWriter): write_part
// then end_message. Control frames may go between its frames.
fn begin_message(c: Conn&, op: u8) -> i64 {
    let e = can_write(c);
    if e != OK { return e; }
    if c.st.writing || (op != TEXT && op != BINARY) { return ERR_ARGUMENT; }
    c.st.writing = true;
    c.st.wop = op;
    c.st.wfirst = true;
    c.st.wcompress = c.pmd.on;
    c.wbuf.clear();
    if c.st.wcompress { deflater_for_message(c); }
    return OK;
}

fn emit_part(c: Conn&, fin: bool) {
    let op = if c.st.wfirst { c.st.wop } else { CONTINUATION };
    let rsv = if c.st.wfirst && c.st.wcompress { RSV1 } else { 0 };
    put_out(c, fin, rsv, op, c.wbuf);
    c.wbuf.clear();
    c.st.wfirst = false;
}

fn write_part(c: Conn&, data: const u8[:]) -> i64 {
    if !c.st.writing { return ERR_ARGUMENT; }
    let e = can_write(c);
    if e != OK { return e; }
    if c.st.wcompress {
        if compress::deflate_write(c.defl[0], data, c.wbuf) != 0 { return ERR_COMPRESSION; }
    } else {
        c.wbuf.append(data);
    }
    if c.wbuf.len >= c.opt.write_buffer {
        emit_part(c, false);
        return flush(c);
    }
    return OK;
}

fn end_message(c: Conn&) -> i64 {
    if !c.st.writing { return ERR_ARGUMENT; }
    c.st.writing = false;
    let e = can_write(c);
    if e != OK { return e; }
    if c.st.wcompress {
        if compress::deflate_flush(c.defl[0], c.wbuf) != 0 { return ERR_COMPRESSION; }
        c.wbuf.resize(c.wbuf.len - 4);
    }
    emit_part(c, true);
    return flush(c);
}

// A ping, with at most 125 bytes of payload; its pong comes to
// read_message as PONG when control_events is on.
fn ping(c: Conn&, data: const u8[:]) -> i64 {
    let e = can_write(c);
    if e != OK { return e; }
    if data.len > 125 { return ERR_ARGUMENT; }
    put_out(c, true, 0, PING, data);
    return flush(c);
}

// An unsolicited pong (a heartbeat, §5.5.3).
fn pong(c: Conn&, data: const u8[:]) -> i64 {
    let e = can_write(c);
    if e != OK { return e; }
    if data.len > 125 { return ERR_ARGUMENT; }
    put_out(c, true, 0, PONG, data);
    return flush(c);
}

// Sends a close (code CLOSE_NO_STATUS: one without a code) and no more:
// the peer's close then comes to a read as ERR_CLOSED.
fn write_close(c: Conn&, code: i64, reason: const u8[:]) -> i64 {
    let e = can_write(c);
    if e != OK { return e; }
    if (code != CLOSE_NO_STATUS && !valid_close_code(code)) || reason.len > 123 || !valid_utf8(reason) { return ERR_ARGUMENT; }
    var p: u8[>..] = [];
    put_close_payload(p, code, reason);
    put_out(c, true, 0, CLOSE, p);
    c.st.sent_close = true;
    return flush(c);
}

// The closing handshake (§7.1.2): a close, then the peer's, messages
// that come before it skipped, for at most close_timeout_ms; then the
// socket is closed. OK when the peer answered.
fn close(c: Conn&, code: i64, reason: const u8[:]) -> i64 {
    if c.st.done { return if c.st.got_close { OK } else { ERR_CLOSED }; }
    if !c.st.sent_close {
        let e = write_close(c, code, reason);
        if e == ERR_ARGUMENT { return e; }
        if e != OK {
            shut(c);
            return e;
        }
    }
    if c.fd < 0 { return OK; }       // the caller feeds the answer
    let saved = c.opt.read_timeout_ms;
    c.opt.read_timeout_ms = c.opt.close_timeout_ms;
    var r = OK;
    loop {
        c.scratch.clear();
        let ev = step(c, c.scratch);
        if ev == EV_CLOSE { break; }
        if ev == EV_ERROR { r = c.st.err; break; }
        if ev == EV_NEED_MORE {
            let e = more(c);
            if e != OK { r = e; break; }
        }
    }
    c.opt.read_timeout_ms = saved;
    if !c.st.done { shut(c); }
    return r;
}

// Ends the connection without a closing handshake.
fn close_now(c: Conn&) { shut(c); }
