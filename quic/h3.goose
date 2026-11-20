// quic.h3: HTTP/3's framing (RFC 9114) without I/O: frames, the
// unidirectional streams' types, SETTINGS, the control stream, and a
// request or response stream read as it arrives and written whole. QUIC
// carries the bytes; this layer only says what they mean.
//
//   // A request stream (a client's bidirectional stream), written whole:
//   var req: u8[>..] = [];
//   quic::h3_request(req, "GET", "https", "example.com", "/", headers, "", "");
//
//   // ... and read as the server gets it, in pieces:
//   var m = quic::h3_message(true, 65536);
//   let e = quic::h3_message_feed(m, piece, fin) { kind, bytes =>
//       // H3_EV_HEADERS (records, as qpack writes them), H3_EV_DATA (body
//       // bytes), H3_EV_TRAILERS, H3_EV_INTERIM (a 1xx response), H3_EV_END
//   };
//   // e: 0, or the error the stream (H3_MESSAGE_ERROR, ...) or the
//   // connection (H3_FRAME_UNEXPECTED, QPACK_DECOMPRESSION_FAILED, ...)
//   // closes with.
//
//   // The peer's control stream, after its type byte:
//   var c = quic::h3_control(true);
//   let e2 = quic::h3_control_feed(c, piece, fin);    // SETTINGS first, ...
//
// Unknown frame types, stream types and settings are ignored, the reserved
// ones (0x1f * N + 0x21) among them; HTTP/2's frame types and settings are
// errors. Server push is not done: no MAX_PUSH_ID is sent, so a server may
// not push. Fields are QPACK's records (quic.qpack), validated as RFC 9114
// §4.2 and §4.3 ask.
//
// The varints are QUIC's (RFC 9000 §16); h3_varint and h3_put_varint are
// this module's own, so that it stands without the transport.

namespace quic;

import std;
import quic.qpack;

// --- Codes -------------------------------------------------------------------------

// Frame types (§7.2).
let H3_DATA: i64 = 0x00;
let H3_HEADERS: i64 = 0x01;
let H3_CANCEL_PUSH: i64 = 0x03;
let H3_SETTINGS: i64 = 0x04;
let H3_PUSH_PROMISE: i64 = 0x05;
let H3_GOAWAY: i64 = 0x07;
let H3_MAX_PUSH_ID: i64 = 0x0d;

// Unidirectional stream types (§6.2, RFC 9204 §4.2).
let H3_STREAM_CONTROL: i64 = 0x00;
let H3_STREAM_PUSH: i64 = 0x01;
let H3_STREAM_QPACK_ENCODER: i64 = 0x02;
let H3_STREAM_QPACK_DECODER: i64 = 0x03;

// Settings (§7.2.4.1, RFC 9204 §5, RFC 9220, RFC 9297).
let H3_SETTING_QPACK_MAX_TABLE_CAPACITY: i64 = 0x01;
let H3_SETTING_MAX_FIELD_SECTION_SIZE: i64 = 0x06;
let H3_SETTING_QPACK_BLOCKED_STREAMS: i64 = 0x07;
let H3_SETTING_ENABLE_CONNECT_PROTOCOL: i64 = 0x08;
let H3_SETTING_H3_DATAGRAM: i64 = 0x33;

// Error codes (§8.1).
let H3_NO_ERROR: i64 = 0x100;
let H3_GENERAL_PROTOCOL_ERROR: i64 = 0x101;
let H3_INTERNAL_ERROR: i64 = 0x102;
let H3_STREAM_CREATION_ERROR: i64 = 0x103;
let H3_CLOSED_CRITICAL_STREAM: i64 = 0x104;
let H3_FRAME_UNEXPECTED: i64 = 0x105;
let H3_FRAME_ERROR: i64 = 0x106;
let H3_EXCESSIVE_LOAD: i64 = 0x107;
let H3_ID_ERROR: i64 = 0x108;
let H3_SETTINGS_ERROR: i64 = 0x109;
let H3_MISSING_SETTINGS: i64 = 0x10a;
let H3_REQUEST_REJECTED: i64 = 0x10b;
let H3_REQUEST_CANCELLED: i64 = 0x10c;
let H3_REQUEST_INCOMPLETE: i64 = 0x10d;
let H3_MESSAGE_ERROR: i64 = 0x10e;
let H3_CONNECT_ERROR: i64 = 0x10f;
let H3_VERSION_FALLBACK: i64 = 0x110;

// The largest frame other than DATA kept whole while it arrives.
let H3_MAX_FRAME: i64 = 65536 + 64;

// A stream, frame or setting type of the reserved form 0x1f * N + 0x21,
// sent to exercise the rule that unknown ones are ignored (§7.2.8, §9).
fn h3_reserved(t: i64) -> bool { t >= 0x21 && (t - 0x21) % 0x1f == 0 }

// HTTP/2's frame types that HTTP/3 does not have: PRIORITY, PING,
// WINDOW_UPDATE, CONTINUATION (§7.2.8).
fn h3_http2_frame(t: i64) -> bool { t == 0x02 || t == 0x06 || t == 0x08 || t == 0x09 }

fn h3_error_text(e: i64) -> const u8[:] {
    if e == 0 || e == H3_NO_ERROR { return "no error"; }
    if e == H3_GENERAL_PROTOCOL_ERROR { return "H3_GENERAL_PROTOCOL_ERROR"; }
    if e == H3_INTERNAL_ERROR { return "H3_INTERNAL_ERROR"; }
    if e == H3_STREAM_CREATION_ERROR { return "H3_STREAM_CREATION_ERROR"; }
    if e == H3_CLOSED_CRITICAL_STREAM { return "H3_CLOSED_CRITICAL_STREAM"; }
    if e == H3_FRAME_UNEXPECTED { return "H3_FRAME_UNEXPECTED"; }
    if e == H3_FRAME_ERROR { return "H3_FRAME_ERROR"; }
    if e == H3_EXCESSIVE_LOAD { return "H3_EXCESSIVE_LOAD"; }
    if e == H3_ID_ERROR { return "H3_ID_ERROR"; }
    if e == H3_SETTINGS_ERROR { return "H3_SETTINGS_ERROR"; }
    if e == H3_MISSING_SETTINGS { return "H3_MISSING_SETTINGS"; }
    if e == H3_REQUEST_REJECTED { return "H3_REQUEST_REJECTED"; }
    if e == H3_REQUEST_CANCELLED { return "H3_REQUEST_CANCELLED"; }
    if e == H3_REQUEST_INCOMPLETE { return "H3_REQUEST_INCOMPLETE"; }
    if e == H3_MESSAGE_ERROR { return "H3_MESSAGE_ERROR"; }
    if e == H3_CONNECT_ERROR { return "H3_CONNECT_ERROR"; }
    if e == H3_VERSION_FALLBACK { return "H3_VERSION_FALLBACK"; }
    if e == QPACK_DECOMPRESSION_FAILED { return "QPACK_DECOMPRESSION_FAILED"; }
    if e == QPACK_ENCODER_STREAM_ERROR { return "QPACK_ENCODER_STREAM_ERROR"; }
    if e == QPACK_DECODER_STREAM_ERROR { return "QPACK_DECODER_STREAM_ERROR"; }
    return "unknown error";
}

// --- Varints (RFC 9000 §16) --------------------------------------------------------

// A varint at pos: its value and where it ends, or end -1 when the input
// ends first (more may come). Encodings longer than needed are taken.
fn h3_varint(b: const u8[:], pos: i64) -> i64, i64 {
    if pos >= b.len { return 0, -1; }
    let n: i64 = 1 << (b[pos] >> 6);
    if pos + n > b.len { return 0, -1; }
    var v = (b[pos] as i64) & 0x3f;
    for k in 1..n { v = (v << 8) | b[pos + k]; }
    return v, pos + n;
}

// v, at most 2^62 - 1, in the fewest bytes.
fn h3_put_varint(out: u8[>..]&, v: i64) {
    if v < 0x40 { out.push(v as! u8); return; }
    if v < 0x4000 { out.push((0x40 | (v >> 8)) as! u8); out.push((v & 0xff) as! u8); return; }
    if v < 0x40000000 {
        out.push((0x80 | (v >> 24)) as! u8);
        for k in 1..4 { out.push(((v >> ((3 - k) * 8)) & 0xff) as! u8); }
        return;
    }
    out.push((0xc0 | (v >> 56)) as! u8);
    for k in 1..8 { out.push(((v >> ((7 - k) * 8)) & 0xff) as! u8); }
}

// --- Frames (§7.1) -------------------------------------------------------------------

// A frame's header at pos: its type, its payload's length and where the
// payload starts; start -1 when the header is not all there yet.
fn h3_frame_header(b: const u8[:], pos: i64) -> i64, i64, i64 {
    let t, p = h3_varint(b, pos);
    if p < 0 { return 0, 0, -1; }
    let n, q = h3_varint(b, p);
    if q < 0 { return 0, 0, -1; }
    return t, n, q;
}

fn h3_put_frame(out: u8[>..]&, t: i64, payload: const u8[:]) {
    h3_put_varint(out, t);
    h3_put_varint(out, payload.len);
    out.append(payload);
}

// A frame whose payload is one varint: GOAWAY, MAX_PUSH_ID, CANCEL_PUSH.
fn h3_put_id_frame(out: u8[>..]&, t: i64, id: i64) {
    var p: u8[>..] = [];
    h3_put_varint(p, id);
    h3_put_frame(out, t, p);
}

fn h3_put_goaway(out: u8[>..]&, id: i64) { h3_put_id_frame(out, H3_GOAWAY, id); }

fn h3_put_data(out: u8[>..]&, body: const u8[:]) { h3_put_frame(out, H3_DATA, body); }

// A HEADERS frame of the records recs, QPACK-encoded.
fn h3_put_headers(out: u8[>..]&, recs: const u8[:], huff: bool = true) {
    var section: u8[>..] = [];
    qpack_encode(section, recs, huff);
    h3_put_frame(out, H3_HEADERS, section);
}

// The type that begins a unidirectional stream.
fn h3_put_stream_type(out: u8[>..]&, t: i64) { h3_put_varint(out, t); }

// A unidirectional stream's type at its start: the type and where the rest
// begins, or -1 while it is not all there.
fn h3_stream_type(b: const u8[:]) -> i64, i64 {
    let t, p = h3_varint(b, 0);
    return t, p;
}

// --- SETTINGS (§7.2.4) ---------------------------------------------------------------

struct H3Settings {
    qpack_max_table_capacity: i64 = 0,
    max_field_section_size: i64 = -1,      // -1: no limit (the default)
    qpack_blocked_streams: i64 = 0,
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
}

// What this side advertises: no dynamic table, field sections of at most
// max_field_section bytes (RFC 9114 §4.2.2's measure).
fn h3_settings(max_field_section: i64 = 65536) -> H3Settings {
    return H3Settings { max_field_section_size: max_field_section, .. };
}

// A SETTINGS frame. With grease, a reserved setting too (§7.2.4.1), as
// browsers send, so that peers keep ignoring the ones they do not know.
fn h3_put_settings(out: u8[>..]&, s: const H3Settings&, grease: bool = true) {
    var p: u8[>..] = [];
    if s.qpack_max_table_capacity != 0 { h3_put_varint(p, H3_SETTING_QPACK_MAX_TABLE_CAPACITY); h3_put_varint(p, s.qpack_max_table_capacity); }
    if s.max_field_section_size >= 0 { h3_put_varint(p, H3_SETTING_MAX_FIELD_SECTION_SIZE); h3_put_varint(p, s.max_field_section_size); }
    if s.qpack_blocked_streams != 0 { h3_put_varint(p, H3_SETTING_QPACK_BLOCKED_STREAMS); h3_put_varint(p, s.qpack_blocked_streams); }
    if s.enable_connect_protocol { h3_put_varint(p, H3_SETTING_ENABLE_CONNECT_PROTOCOL); h3_put_varint(p, 1); }
    if s.h3_datagram { h3_put_varint(p, H3_SETTING_H3_DATAGRAM); h3_put_varint(p, 1); }
    if grease { h3_put_varint(p, 0x1f * 7 + 0x21); h3_put_varint(p, 0); }
    h3_put_frame(out, H3_SETTINGS, p);
}

// A SETTINGS frame's payload: the settings, and 0 or the error. A setting
// twice, HTTP/2's (0x02 to 0x05), or a Boolean that is not 0 or 1 is
// H3_SETTINGS_ERROR; one cut short is H3_FRAME_ERROR; unknown ones are
// ignored.
fn h3_read_settings(payload: const u8[:]) -> H3Settings, i64 {
    var s = H3Settings { .. };
    var seen: i64[64] = [0; 64];
    var nseen = 0;
    var p = 0;
    while p < payload.len {
        let id, q = h3_varint(payload, p);
        if q < 0 { return s, H3_FRAME_ERROR; }
        let v, r = h3_varint(payload, q);
        if r < 0 { return s, H3_FRAME_ERROR; }
        p = r;
        for k in nseen { if seen[k] == id { return s, H3_SETTINGS_ERROR; } }
        if nseen == 64 { return s, H3_EXCESSIVE_LOAD; }
        seen[nseen] = id;
        nseen++;
        if id >= 0x02 && id <= 0x05 { return s, H3_SETTINGS_ERROR; }
        if id == H3_SETTING_QPACK_MAX_TABLE_CAPACITY { s.qpack_max_table_capacity = v; }
        else if id == H3_SETTING_MAX_FIELD_SECTION_SIZE { s.max_field_section_size = v; }
        else if id == H3_SETTING_QPACK_BLOCKED_STREAMS { s.qpack_blocked_streams = v; }
        else if id == H3_SETTING_ENABLE_CONNECT_PROTOCOL {
            if v > 1 { return s, H3_SETTINGS_ERROR; }
            s.enable_connect_protocol = v == 1;
        } else if id == H3_SETTING_H3_DATAGRAM {
            if v > 1 { return s, H3_SETTINGS_ERROR; }
            s.h3_datagram = v == 1;
        }
    }
    return s, 0;
}

// --- The control stream (§6.2.1) -------------------------------------------------------

struct H3Control {
    is_server: bool,                    // which side reads it: the peer is the other
    got_settings: bool,
    settings: H3Settings,               // the peer's
    goaway: i64,                        // the last GOAWAY's id, -1 for none
    max_push_id: i64,                   // a server's: the client's last MAX_PUSH_ID, -1 for none
    skip: i64,                          // bytes of an ignored frame still to come
    pending: u8[>..],
}

// The peer's control stream, read by a server (is_server) or a client.
fn h3_control(is_server: bool) -> H3Control {
    return H3Control { is_server: is_server, got_settings: false, settings: H3Settings { .. }, goaway: -1,
                       max_push_id: -1, skip: 0, pending: [] };
}

// One frame of the control stream, whole.
fn h3_control_frame(c: H3Control&, t: i64, payload: const u8[:]) -> i64 {
    if !c.got_settings {
        if t != H3_SETTINGS { return H3_MISSING_SETTINGS; }
        let s, e = h3_read_settings(payload);
        if e != 0 { return e; }
        c.settings = s;
        c.got_settings = true;
        return 0;
    }
    if t == H3_SETTINGS || t == H3_DATA || t == H3_HEADERS || t == H3_PUSH_PROMISE || h3_http2_frame(t) {
        return H3_FRAME_UNEXPECTED;
    }
    if t == H3_GOAWAY || t == H3_MAX_PUSH_ID || t == H3_CANCEL_PUSH {
        let id, p = h3_varint(payload, 0);
        if p != payload.len { return H3_FRAME_ERROR; }
        if t == H3_GOAWAY {
            // A server's GOAWAY names a client-initiated bidirectional
            // stream; either side's ids may only go down (§5.2).
            if !c.is_server && id % 4 != 0 { return H3_ID_ERROR; }
            if c.goaway >= 0 && id > c.goaway { return H3_ID_ERROR; }
            c.goaway = id;
        } else if t == H3_MAX_PUSH_ID {
            if !c.is_server { return H3_FRAME_UNEXPECTED; }
            if id < c.max_push_id { return H3_ID_ERROR; }
            c.max_push_id = id;
        } else if !c.is_server {
            // CANCEL_PUSH from a server: we allowed no push, so no id is valid.
            return H3_ID_ERROR;
        }
        return 0;
    }
    return 0;
}

// More of the peer's control stream: 0, or the connection's error. The
// stream may not end (H3_CLOSED_CRITICAL_STREAM).
fn h3_control_feed(c: H3Control&, data: const u8[:], fin: bool) -> i64 {
    var d = data[..];
    if c.skip > 0 {
        let n = ::min(c.skip, d.len);
        c.skip -= n;
        d = d[n..];
    }
    c.pending.append(d);
    var p = 0;
    while p < c.pending.len {
        if c.skip > 0 {
            let n = ::min(c.skip, c.pending.len - p);
            c.skip -= n;
            p += n;
            continue;
        }
        let t, len, start = h3_frame_header(c.pending, p);
        if start < 0 { break; }
        let known = t == H3_SETTINGS || t == H3_GOAWAY || t == H3_MAX_PUSH_ID || t == H3_CANCEL_PUSH ||
                    t == H3_DATA || t == H3_HEADERS || t == H3_PUSH_PROMISE || h3_http2_frame(t);
        if !known {
            // Unknown and reserved frames: ignored, after SETTINGS only.
            if !c.got_settings { return H3_MISSING_SETTINGS; }
            p = start;
            c.skip = len;
            continue;
        }
        if t == H3_DATA || t == H3_HEADERS || t == H3_PUSH_PROMISE || h3_http2_frame(t) {
            if !c.got_settings { return H3_MISSING_SETTINGS; }
            return H3_FRAME_UNEXPECTED;
        }
        if len > H3_MAX_FRAME { return H3_EXCESSIVE_LOAD; }
        if c.pending.len - start < len { break; }
        let e = h3_control_frame(c, t, c.pending[start..start + len]);
        if e != 0 { return e; }
        p = start + len;
    }
    var rest: u8[>..] = [];
    rest.append(c.pending[p..]);
    c.pending.clear();
    c.pending.append(rest);
    if fin { return H3_CLOSED_CRITICAL_STREAM; }
    return 0;
}

// --- Request and response streams (§4.1) ------------------------------------------------

// What h3_message_feed hands its block.
let H3_EV_HEADERS: i64 = 1;             // the first field section: records
let H3_EV_DATA: i64 = 2;                // content, as it comes
let H3_EV_TRAILERS: i64 = 3;            // the trailing field section: records
let H3_EV_INTERIM: i64 = 4;             // a 1xx response's fields (a client's)
let H3_EV_END: i64 = 5;                 // the stream ended, the message whole

let H3_MSG_HEADERS: i64 = 0;            // the first HEADERS is to come
let H3_MSG_BODY: i64 = 1;               // DATA, or trailers
let H3_MSG_DONE: i64 = 2;               // after trailers: nothing more but unknown frames

struct H3Message {
    is_request: bool,                   // a request (the server reads it), or a response
    state: i64,
    max_field_section: i64,             // this side's SETTINGS_MAX_FIELD_SECTION_SIZE
    data_left: i64,                     // bytes of the DATA frame in arrival still to come
    skip: i64,                          // bytes of an ignored frame still to come
    content_length: i64,                // the content-length field's, -1 for none
    body_len: i64,                      // content so far
    no_body: bool,                      // a response with no content (204, 304), as content-length allows
    pending: u8[>..],
}

fn h3_message(is_request: bool, max_field_section: i64 = 65536) -> H3Message {
    return H3Message { is_request: is_request, state: H3_MSG_HEADERS, max_field_section: max_field_section,
                       data_left: 0, skip: 0, content_length: -1, body_len: 0, no_body: false, pending: [] };
}

// A content-length value: digits only, or -1 (§4.1.2).
fn h3_content_length(v: const u8[:]) -> i64 {
    if v.len == 0 || v.len > 18 { return -1; }
    var n: i64 = 0;
    for c in v {
        if c < '0' || c > '9' { return -1; }
        n = n * 10 + (c - '0');
    }
    return n;
}

// A HEADERS frame's payload: decoded, validated, handed on. 0 or the error.
fn h3_message_headers<F>(m: H3Message&, section: const u8[:]) -> i64 {
    var recs: u8[>..] = [];
    let e = qpack_decode(section, m.max_field_section, recs);
    if e == QPACK_TOO_LARGE { return H3_EXCESSIVE_LOAD; }
    if e != QPACK_OK { return QPACK_DECOMPRESSION_FAILED; }
    if m.state == H3_MSG_BODY {
        if validate_trailers(recs) != FIELDS_OK { return H3_MESSAGE_ERROR; }
        m.state = H3_MSG_DONE;
        F(H3_EV_TRAILERS, recs);
        return 0;
    }
    if m.is_request {
        if validate_request(recs) != FIELDS_OK { return H3_MESSAGE_ERROR; }
    } else {
        if validate_response(recs) != FIELDS_OK { return H3_MESSAGE_ERROR; }
        let st = status_of(recs);
        // 101 has no place in HTTP/3 (§4.5); other 1xx are interim.
        if st == 101 { return H3_MESSAGE_ERROR; }
        if st >= 100 && st < 200 {
            F(H3_EV_INTERIM, recs);
            return 0;
        }
        m.no_body = st == 204 || st == 304;
    }
    // Several content-length fields must agree (RFC 9110 §8.6).
    var bad = false;
    var cl: i64 = -1;
    each_qpack_field(recs) { n, v, never =>
        if n == "content-length" {
            let x = h3_content_length(v);
            if x < 0 || (cl >= 0 && x != cl) { bad = true; }
            cl = x;
        }
    };
    if bad { return H3_MESSAGE_ERROR; }
    m.content_length = cl;
    m.state = H3_MSG_BODY;
    F(H3_EV_HEADERS, recs);
    return 0;
}

// More of a request or response stream; fin when the stream ends there.
// F(kind, bytes) gets each part as it is whole (DATA as it comes). 0, or
// the error: of the stream (H3_MESSAGE_ERROR: a malformed message, which
// a server answers by resetting the stream; H3_REQUEST_INCOMPLETE) or of
// the connection (H3_FRAME_UNEXPECTED, H3_FRAME_ERROR, H3_EXCESSIVE_LOAD,
// H3_ID_ERROR, QPACK_DECOMPRESSION_FAILED).
fn h3_message_feed<F>(m: H3Message&, data: const u8[:], fin: bool) -> i64 {
    var d = data[..];
    // Content of the DATA frame in arrival goes on without being kept.
    while d.len > 0 && (m.data_left > 0 || m.skip > 0) && m.pending.len == 0 {
        if m.data_left > 0 {
            let n = ::min(m.data_left, d.len);
            m.data_left -= n;
            m.body_len += n;
            if m.content_length >= 0 && m.body_len > m.content_length { return H3_MESSAGE_ERROR; }
            F(H3_EV_DATA, d[..n]);
            d = d[n..];
        } else {
            let n = ::min(m.skip, d.len);
            m.skip -= n;
            d = d[n..];
        }
    }
    m.pending.append(d);
    var p = 0;
    while p < m.pending.len {
        if m.data_left > 0 {
            let n = ::min(m.data_left, m.pending.len - p);
            m.data_left -= n;
            m.body_len += n;
            if m.content_length >= 0 && m.body_len > m.content_length { return H3_MESSAGE_ERROR; }
            F(H3_EV_DATA, m.pending[p..p + n]);
            p += n;
            continue;
        }
        if m.skip > 0 {
            let n = ::min(m.skip, m.pending.len - p);
            m.skip -= n;
            p += n;
            continue;
        }
        let t, len, start = h3_frame_header(m.pending, p);
        if start < 0 { break; }
        if t == H3_DATA {
            if m.state != H3_MSG_BODY { return H3_FRAME_UNEXPECTED; }
            p = start;
            m.data_left = len;
            continue;
        }
        if t == H3_HEADERS {
            if m.state == H3_MSG_DONE { return H3_FRAME_UNEXPECTED; }
            if len > H3_MAX_FRAME && len > m.max_field_section { return H3_EXCESSIVE_LOAD; }
            if m.pending.len - start < len { break; }
            let e = h3_message_headers(m, m.pending[start..start + len], F);
            if e != 0 { return e; }
            p = start + len;
            continue;
        }
        if t == H3_PUSH_PROMISE {
            // We allow no push: on a response, any push id is too high.
            return if m.is_request { H3_FRAME_UNEXPECTED } else { H3_ID_ERROR };
        }
        if t == H3_SETTINGS || t == H3_GOAWAY || t == H3_MAX_PUSH_ID || t == H3_CANCEL_PUSH || h3_http2_frame(t) {
            return H3_FRAME_UNEXPECTED;
        }
        // Unknown and reserved frames: ignored, anywhere.
        p = start;
        m.skip = len;
    }
    var rest: u8[>..] = [];
    rest.append(m.pending[p..]);
    m.pending.clear();
    m.pending.append(rest);
    if !fin { return 0; }
    if m.pending.len > 0 || m.data_left > 0 || m.skip > 0 { return H3_FRAME_ERROR; }
    if m.state == H3_MSG_HEADERS {
        return if m.is_request { H3_REQUEST_INCOMPLETE } else { H3_MESSAGE_ERROR };
    }
    if m.content_length >= 0 && m.body_len != m.content_length && !m.no_body { return H3_MESSAGE_ERROR; }
    F(H3_EV_END, "");
    return 0;
}

// --- Writing requests and responses ------------------------------------------------------

// A whole request stream: HEADERS (the pseudo-headers, then headers, records
// with lowercase names), the body in one DATA frame unless it is empty,
// the trailers in a HEADERS frame unless there are none. CONNECT is given
// an empty scheme and path.
fn h3_request(out: u8[>..]&, method: const u8[:], scheme: const u8[:], authority: const u8[:], path: const u8[:],
              headers: const u8[:], body: const u8[:], trailers: const u8[:]) {
    var recs: u8[>..] = [];
    qpack_record(recs, ":method", method);
    if scheme.len > 0 { qpack_record(recs, ":scheme", scheme); }
    if authority.len > 0 { qpack_record(recs, ":authority", authority); }
    if path.len > 0 { qpack_record(recs, ":path", path); }
    recs.append(headers);
    h3_put_headers(out, recs);
    if body.len > 0 { h3_put_data(out, body); }
    if trailers.len > 0 { h3_put_headers(out, trailers); }
}

// A whole response stream: HEADERS (:status, then headers), the body, the
// trailers, as h3_request.
fn h3_response(out: u8[>..]&, status: i64, headers: const u8[:], body: const u8[:], trailers: const u8[:]) {
    var recs: u8[>..] = [];
    var st: u8[>..] = [];
    format_int(st, status, 10, 3, '0');
    qpack_record(recs, ":status", st);
    recs.append(headers);
    h3_put_headers(out, recs);
    if body.len > 0 { h3_put_data(out, body); }
    if trailers.len > 0 { h3_put_headers(out, trailers); }
}

// What begins this side's control stream: its type and SETTINGS.
fn h3_control_start(out: u8[>..]&, s: const H3Settings&, grease: bool = true) {
    h3_put_stream_type(out, H3_STREAM_CONTROL);
    h3_put_settings(out, s, grease);
}
