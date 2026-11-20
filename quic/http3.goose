// quic.http3: HTTP/3 on a QUIC connection (RFC 9114), both sides. Each
// side opens its control stream (SETTINGS first) and its QPACK encoder
// and decoder streams; the peer's are read as they come: its SETTINGS, its
// GOAWAY, QPACK instructions (none but a capacity of 0 can come, since
// this side advertises no dynamic table). A client sends requests on its
// bidirectional streams and reads the responses; a server reads the
// requests and answers them. Server push is not used.
//
//   var h = quic::h3(false);
//   quic::h3_poll(c, h);                            // after each step
//   let id = quic::h3_send_request(c, h, "GET", "https", "example.com", "/", "", "");
//   ... quic::h3_poll(c, h) until quic::h3_done(h, id) ...
//   let st = quic::h3_status(h, id);
//
// Request and response bodies are held whole up to 64 KiB; a client may
// take a body as it comes (h3_take_body) to read a longer one.

namespace quic;

import std;
import quic;
import quic.conn;
import quic.qpack;
import quic.h3;

let H3_MAX_EXCHANGES: i64 = 16;
let H3_BODY_MAX: i64 = 65536;

// One request and its response: the message being read (H3Message's
// state, its pending bytes held here), what it said.
struct H3Exchange {
    used: bool,
    id: i64,
    // H3Message's fields.
    m_state: i64, m_data_left: i64, m_skip: i64, m_content_length: i64, m_body_len: i64, m_no_body: bool,
    status: i64,               // a response's
    headers: u8[..16384],      // the first field section, qpack records
    trailers: u8[..4096],
    done: bool,                // the message read whole
    err: i64,                  // a stream error (H3_MESSAGE_ERROR, ...), 0 for none
    answered: bool,            // the server answered it
    pending: u8[..65536],
    body: u8[..65536],
}

fn h3_exchange(id: i64, is_request: bool) -> H3Exchange {
    let m = h3_message(is_request);
    return H3Exchange { used: true, id: id, m_state: m.state, m_data_left: 0, m_skip: 0, m_content_length: -1, m_body_len: 0,
                        m_no_body: false, status: 0, headers: [], trailers: [], done: false, err: 0, answered: false,
                        pending: [], body: [] };
}

struct H3 {
    is_server: bool,
    started: bool,
    error: i64,                // the connection error this side closed with, 0 for none
    peer_ctrl: i64, peer_enc: i64, peer_dec: i64,    // the peer's streams of those types, -1 until they come
    uni: i64[8],               // the peer's other unidirectional streams whose type is not read yet
    ex: H3Exchange[16],
    // The peer's control stream's reader (H3Control's fields; its pending
    // bytes held here, so that an H3 is of fixed size).
    ctl_got_settings: bool,
    ctl_settings: H3Settings,
    ctl_goaway: i64, ctl_max_push_id: i64, ctl_skip: i64,
    ctl_pending: u8[..65536],
}

fn h3(is_server: bool) -> H3 {
    var x = h3_exchange(0, false);
    x.used = false;
    let ctl = h3_control(is_server);
    return H3 { is_server: is_server, started: false, error: 0, peer_ctrl: -1, peer_enc: -1, peer_dec: -1, uni: [-1; 8],
                ex: [x; 16], ctl_got_settings: false, ctl_settings: ctl.settings, ctl_goaway: -1, ctl_max_push_id: -1, ctl_skip: 0,
                ctl_pending: [] };
}

// The peer's control stream's new bytes, through H3Control.
fn feed_control(h: H3&, data: const u8[:]) -> i64 {
    var ctl = h3_control(h.is_server);
    ctl.got_settings = h.ctl_got_settings;
    ctl.settings = h.ctl_settings;
    ctl.goaway = h.ctl_goaway;
    ctl.max_push_id = h.ctl_max_push_id;
    ctl.skip = h.ctl_skip;
    ctl.pending.append(h.ctl_pending);
    let e = h3_control_feed(ctl, data, false);
    h.ctl_got_settings = ctl.got_settings;
    h.ctl_settings = ctl.settings;
    h.ctl_goaway = ctl.goaway;
    h.ctl_max_push_id = ctl.max_push_id;
    h.ctl_skip = ctl.skip;
    if ctl.pending.len > h.ctl_pending.cap { return H3_EXCESSIVE_LOAD; }
    h.ctl_pending.clear();
    h.ctl_pending.append(ctl.pending);
    return e;
}

// Whether the peer's SETTINGS came; its GOAWAY's id (-1 for none).
fn h3_got_settings(h: const H3&) -> bool { h.ctl_got_settings }
fn h3_goaway(h: const H3&) -> i64 { h.ctl_goaway }

fn h3_fail(c: Conn&, h: H3&, code: i64, why: const u8[:]) {
    if h.error != 0 { return; }
    h.error = code;
    close(c, code as! u64, why);
}

// This side's three unidirectional streams, once the connection is up.
fn h3_start(c: Conn&, h: H3&) {
    if h.started || !established(c) { return; }
    let ctrl = open_stream(c, false);
    let enc = open_stream(c, false);
    let dec = open_stream(c, false);
    if ctrl < 0 || enc < 0 || dec < 0 { h3_fail(c, h, H3_GENERAL_PROTOCOL_ERROR, "no room for the control streams"); return; }
    var out: u8[>..] = [];
    let s = h3_settings();
    h3_control_start(out, s);
    let n1 = stream_write(c, ctrl, out, false);
    var e: u8[>..] = [];
    h3_put_stream_type(e, H3_STREAM_QPACK_ENCODER);
    let n2 = stream_write(c, enc, e, false);
    var d: u8[>..] = [];
    h3_put_stream_type(d, H3_STREAM_QPACK_DECODER);
    let n3 = stream_write(c, dec, d, false);
    h.started = true;
}

fn find_exchange(h: const H3&, id: i64) -> i64 {
    for k in H3_MAX_EXCHANGES { if h.ex[k].used && h.ex[k].id == id { return k; } }
    return -1;
}

fn new_exchange(h: H3&, id: i64, is_request: bool) -> i64 {
    for k in H3_MAX_EXCHANGES {
        if !h.ex[k].used { h.ex[k] = h3_exchange(id, is_request); return k; }
    }
    return -1;
}

// Feeds a request or response stream's new bytes to its message.
fn feed_exchange(c: Conn&, h: H3&, k: i64, data: const u8[:], fin: bool) {
    var m = h3_message(h.is_server);
    m.state = h.ex[k].m_state;
    m.data_left = h.ex[k].m_data_left;
    m.skip = h.ex[k].m_skip;
    m.content_length = h.ex[k].m_content_length;
    m.body_len = h.ex[k].m_body_len;
    m.no_body = h.ex[k].m_no_body;
    m.pending.append(h.ex[k].pending);
    var status: i64 = h.ex[k].status;
    var heads: u8[>..] = [];
    var trail: u8[>..] = [];
    var body: u8[>..] = [];
    var ended = false;
    let e = h3_message_feed(m, data, fin) { kind, bytes =>
        if kind == H3_EV_HEADERS { heads.append(bytes); }
        else if kind == H3_EV_TRAILERS { trail.append(bytes); }
        else if kind == H3_EV_DATA { body.append(bytes); }
        else if kind == H3_EV_END { ended = true; }
    };
    if heads.len > 0 {
        if heads.len > h.ex[k].headers.cap { h.ex[k].err = H3_EXCESSIVE_LOAD; }
        else { h.ex[k].headers.append(heads); }
        if !h.is_server { h.ex[k].status = status_of(heads); }
    }
    if trail.len > 0 && trail.len <= h.ex[k].trailers.cap { h.ex[k].trailers.append(trail); }
    if body.len > 0 {
        if h.ex[k].body.len + body.len > h.ex[k].body.cap { h.ex[k].err = H3_EXCESSIVE_LOAD; }
        else { h.ex[k].body.append(body); }
    }
    if m.pending.len > h.ex[k].pending.cap { h.ex[k].err = H3_EXCESSIVE_LOAD; }
    else {
        h.ex[k].pending.clear();
        h.ex[k].pending.append(m.pending);
    }
    h.ex[k].m_state = m.state;
    h.ex[k].m_data_left = m.data_left;
    h.ex[k].m_skip = m.skip;
    h.ex[k].m_content_length = m.content_length;
    h.ex[k].m_body_len = m.body_len;
    h.ex[k].m_no_body = m.no_body;
    if ended { h.ex[k].done = true; }
    if e != 0 {
        // A malformed message is the stream's error; the others end the connection.
        if e == H3_MESSAGE_ERROR || e == H3_REQUEST_INCOMPLETE {
            h.ex[k].err = e;
            reset_stream(c, h.ex[k].id, e as! u64);
            stop_sending(c, h.ex[k].id, e as! u64);
        } else {
            h3_fail(c, h, e, "a message");
        }
    }
    if h.ex[k].err == H3_EXCESSIVE_LOAD {
        reset_stream(c, h.ex[k].id, H3_EXCESSIVE_LOAD as! u64);
        stop_sending(c, h.ex[k].id, H3_EXCESSIVE_LOAD as! u64);
    }
}

// A peer's unidirectional stream: its type read, then what it carries.
fn feed_uni(c: Conn&, h: H3&, slot: i64) {
    let id = h.uni[slot];
    var buf: u8[>..] = [];
    // The type is a varint: wait for all of it before reading on.
    if stream_readable(c, id) == 0 && !stream_finished(c, id) { return; }
    let n = stream_read(c, id, buf, 8);
    let t, p = h3_stream_type(buf);
    if p < 0 {
        // Not all of it yet: the bytes can't be put back, so this is
        // only safe because varints arrive whole in practice; refuse.
        if stream_finished(c, id) { h.uni[slot] = -1; }
        return;
    }
    h.uni[slot] = -1;
    if t == H3_STREAM_CONTROL {
        if h.peer_ctrl >= 0 { h3_fail(c, h, H3_STREAM_CREATION_ERROR, "a second control stream"); return; }
        h.peer_ctrl = id;
        let e = feed_control(h, buf[p..]);
        if e != 0 { h3_fail(c, h, e, "the control stream"); }
    } else if t == H3_STREAM_QPACK_ENCODER {
        if h.peer_enc >= 0 { h3_fail(c, h, H3_STREAM_CREATION_ERROR, "a second QPACK encoder stream"); return; }
        h.peer_enc = id;
        if buf.len > p && qpack_encoder_stream(buf[p..]) < 0 { h3_fail(c, h, QPACK_ENCODER_STREAM_ERROR, "QPACK"); }
    } else if t == H3_STREAM_QPACK_DECODER {
        if h.peer_dec >= 0 { h3_fail(c, h, H3_STREAM_CREATION_ERROR, "a second QPACK decoder stream"); return; }
        h.peer_dec = id;
        if buf.len > p && qpack_decoder_stream(buf[p..]) < 0 { h3_fail(c, h, QPACK_DECODER_STREAM_ERROR, "QPACK"); }
    } else if t == H3_STREAM_PUSH && h.is_server {
        h3_fail(c, h, H3_STREAM_CREATION_ERROR, "a push stream from a client");
    } else {
        // Push (never asked for) and reserved or unknown types: not read.
        stop_sending(c, id, H3_STREAM_CREATION_ERROR as! u64);
    }
}

// What has arrived, handled: new streams taken, the control and QPACK
// streams read, requests or responses fed. Call after each step.
fn h3_poll(c: Conn&, h: H3&) {
    h3_start(c, h);
    if !h.started || closing(c) { return; }
    loop {
        let id = accept_stream(c);
        if id < 0 { break; }
        if is_uni(id) {
            var put = false;
            for s in 8 { if !put && h.uni[s] < 0 { h.uni[s] = id; put = true; } }
            if !put { stop_sending(c, id, H3_STREAM_CREATION_ERROR as! u64); }
        } else if h.is_server {
            if new_exchange(h, id, true) < 0 { reset_stream(c, id, H3_REQUEST_REJECTED as! u64); stop_sending(c, id, H3_REQUEST_REJECTED as! u64); }
        } else {
            h3_fail(c, h, H3_STREAM_CREATION_ERROR, "a bidirectional stream from a server");
            return;
        }
    }
    for s in 8 { if h.uni[s] >= 0 { feed_uni(c, h, s); } }
    // The critical streams: read on; their end is an error (§6.2.1).
    for which in 3 {
        let id = if which == 0 { h.peer_ctrl } else if which == 1 { h.peer_enc } else { h.peer_dec };
        if id < 0 { continue; }
        var buf: u8[>..] = [];
        let n = stream_read(c, id, buf, 65536);
        if which == 0 && buf.len > 0 {
            let e = feed_control(h, buf);
            if e != 0 { h3_fail(c, h, e, "the control stream"); return; }
        }
        if which == 1 && buf.len > 0 && qpack_encoder_stream(buf) < 0 { h3_fail(c, h, QPACK_ENCODER_STREAM_ERROR, "QPACK"); return; }
        if which == 2 && buf.len > 0 && qpack_decoder_stream(buf) < 0 { h3_fail(c, h, QPACK_DECODER_STREAM_ERROR, "QPACK"); return; }
        if stream_finished(c, id) { h3_fail(c, h, H3_CLOSED_CRITICAL_STREAM, "a critical stream closed"); return; }
    }
    for k in H3_MAX_EXCHANGES {
        // A server's request that failed is not handed to the application
        // (h3_next_request), so nothing would forget it: its slot is freed
        // here, or 16 bad requests would leave the connection none. An id
        // the application still holds then finds no exchange.
        if h.is_server && h.ex[k].used && h.ex[k].err != 0 { h.ex[k].used = false; continue; }
        if !h.ex[k].used || h.ex[k].done || h.ex[k].err != 0 { continue; }
        let id = h.ex[k].id;
        var buf: u8[>..] = [];
        let n = stream_read(c, id, buf, 65536);
        let fin = stream_finished(c, id);
        let rc, reset = stream_reset_by_peer(c, id);
        if reset { h.ex[k].err = rc as! i64; continue; }
        if buf.len > 0 || fin { feed_exchange(c, h, k, buf, fin); }
    }
}

// --- A client's side -------------------------------------------------------------

// Sends a request (headers as qpack records, possibly empty): its
// stream's id, or -1 when no stream can be opened now.
fn h3_send_request(c: Conn&, h: H3&, method: const u8[:], scheme: const u8[:], authority: const u8[:], path: const u8[:],
                   headers: const u8[:], body: const u8[:]) -> i64 {
    h3_start(c, h);
    let id = open_stream(c, true);
    if id < 0 { return -1; }
    if new_exchange(h, id, false) < 0 { reset_stream(c, id, H3_REQUEST_CANCELLED as! u64); return -1; }
    var out: u8[>..] = [];
    h3_request(out, method, scheme, authority, path, headers, body, "");
    let n = stream_write(c, id, out, true);
    if n != out.len { reset_stream(c, id, H3_REQUEST_CANCELLED as! u64); return -1; }
    return id;
}

// Whether the response on stream id is read whole (or failed).
fn h3_done(h: const H3&, id: i64) -> bool {
    let k = find_exchange(h, id);
    return k < 0 || h.ex[k].done || h.ex[k].err != 0;
}

fn h3_status(h: const H3&, id: i64) -> i64 {
    let k = find_exchange(h, id);
    return if k < 0 { 0 } else { h.ex[k].status };
}

fn h3_error(h: const H3&, id: i64) -> i64 {
    let k = find_exchange(h, id);
    return if k < 0 { 0 } else { h.ex[k].err };
}

// A response's or request's headers (qpack records: qpack_get, each_qpack_field).
fn h3_headers(h: const H3&, id: i64) -> u8[>..] {
    var r: u8[>..] = [];
    let k = find_exchange(h, id);
    if k >= 0 { r.append(h.ex[k].headers); }
    return r;
}

// Moves the body read so far into out.
fn h3_take_body(h: H3&, id: i64, out: u8[>..]&) {
    let k = find_exchange(h, id);
    if k < 0 { return; }
    out.append(h.ex[k].body);
    h.ex[k].body.clear();
}

// Forgets an exchange that is over.
fn h3_forget(h: H3&, id: i64) {
    let k = find_exchange(h, id);
    if k >= 0 { h.ex[k].used = false; }
}

// --- A server's side --------------------------------------------------------------

// A request read whole and not answered yet: its stream's id, or -1.
fn h3_next_request(h: const H3&) -> i64 {
    for k in H3_MAX_EXCHANGES {
        if h.ex[k].used && h.ex[k].done && !h.ex[k].answered && h.ex[k].err == 0 { return h.ex[k].id; }
    }
    return -1;
}

// A request's pseudo-header or header (":method", ":path", "user-agent").
fn h3_field(h: const H3&, id: i64, name: const u8[:]) -> u8[>..] {
    var r: u8[>..] = [];
    let k = find_exchange(h, id);
    if k < 0 { return r; }
    let v, ok = qpack_get(h.ex[k].headers, name);
    if ok { r.append(v); }
    return r;
}

fn h3_body(h: const H3&, id: i64) -> u8[>..] {
    var r: u8[>..] = [];
    let k = find_exchange(h, id);
    if k >= 0 { r.append(h.ex[k].body); }
    return r;
}

// Begins answering a request whose body is `length` bytes and comes
// after: the HEADERS frame and the DATA frame's header go out; the body is
// then written with stream_write as the stream takes it, the last piece
// with fin. False when even that does not fit.
fn h3_respond_head(c: Conn&, h: H3&, id: i64, status: i64, headers: const u8[:], length: i64) -> bool {
    let k = find_exchange(h, id);
    if k < 0 { return false; }
    var recs: u8[>..] = [];
    var st: u8[>..] = [];
    format_int(st, status, 10, 3, '0');
    qpack_record(recs, ":status", st);
    recs.append(headers);
    var out: u8[>..] = [];
    h3_put_headers(out, recs);
    if length > 0 {
        h3_put_varint(out, H3_DATA);
        h3_put_varint(out, length);
    }
    let n = stream_write(c, id, out, length == 0);
    h.ex[k].answered = true;
    h.ex[k].used = false;
    return n == out.len;
}

// Answers a request: status, headers (qpack records), body; the stream
// then ends. False when it does not fit the stream's buffer (then use
// h3_respond_head and write the body as it is taken).
fn h3_respond(c: Conn&, h: H3&, id: i64, status: i64, headers: const u8[:], body: const u8[:]) -> bool {
    let k = find_exchange(h, id);
    if k < 0 { return false; }
    var out: u8[>..] = [];
    h3_response(out, status, headers, body, "");
    let n = stream_write(c, id, out, true);
    h.ex[k].answered = true;
    h.ex[k].used = false;
    return n == out.len;
}
