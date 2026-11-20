// quic.frame: QUIC's frames (RFC 9000 §19), read and written. read_frame
// takes one frame from a packet's payload and checks what the RFC asks of
// its encoding: a frame type in its shortest varint form and one QUIC
// defines, lengths within the packet, an ACK's ranges that do not run
// below zero, stream and CRYPTO data that ends below 2^62, stream counts
// at most 2^60, a NEW_CONNECTION_ID's length and Retire Prior To; any of
// these broken is FRAME_ENCODING_ERROR. Byte strings (stream data, a
// token, a reason phrase, a connection ID) are offsets into the payload,
// not copies. frame_allowed says which packet types may carry a frame
// (§12.4), ack_eliciting which frames ask for an acknowledgment (§13.2).

namespace quic;

import std;
import quic;
import quic.packet;

let FT_PADDING: u64              = 0x00;
let FT_PING: u64                 = 0x01;
let FT_ACK: u64                  = 0x02;
let FT_ACK_ECN: u64              = 0x03;
let FT_RESET_STREAM: u64         = 0x04;
let FT_STOP_SENDING: u64         = 0x05;
let FT_CRYPTO: u64               = 0x06;
let FT_NEW_TOKEN: u64            = 0x07;
let FT_STREAM: u64               = 0x08;   // 0x08 to 0x0f: OFF 0x04, LEN 0x02, FIN 0x01
let FT_MAX_DATA: u64             = 0x10;
let FT_MAX_STREAM_DATA: u64      = 0x11;
let FT_MAX_STREAMS_BIDI: u64     = 0x12;
let FT_MAX_STREAMS_UNI: u64      = 0x13;
let FT_DATA_BLOCKED: u64         = 0x14;
let FT_STREAM_DATA_BLOCKED: u64  = 0x15;
let FT_STREAMS_BLOCKED_BIDI: u64 = 0x16;
let FT_STREAMS_BLOCKED_UNI: u64  = 0x17;
let FT_NEW_CONNECTION_ID: u64    = 0x18;
let FT_RETIRE_CONNECTION_ID: u64 = 0x19;
let FT_PATH_CHALLENGE: u64       = 0x1a;
let FT_PATH_RESPONSE: u64        = 0x1b;
let FT_CONNECTION_CLOSE: u64     = 0x1c;   // a transport error, with the frame type that caused it
let FT_APPLICATION_CLOSE: u64    = 0x1d;   // CONNECTION_CLOSE with an application's error code
let FT_HANDSHAKE_DONE: u64       = 0x1e;

// The 1-RTT packets' place beside packet.goose's long header types, for
// frame_allowed.
let PT_ONE_RTT: u8 = 4;

let MAX_STREAMS_LIMIT: u64 = 0x1000000000000000;   // 2^60 (§4.6)

// One frame. Which fields are set depends on its type:
//
//   PADDING                length (the run of padding bytes)
//   ACK, ACK_ECN           largest, ack_delay, first_range, range_count,
//                          ranges_at (the first Gap, offset into the
//                          payload), smallest (the lowest packet number
//                          acknowledged); ecn, ect0, ect1, ce
//   RESET_STREAM           stream_id, error_code, final_size
//   STOP_SENDING           stream_id, error_code
//   CRYPTO                 offset, data_at, length
//   NEW_TOKEN              data_at, length (the token)
//   STREAM                 stream_id, offset, data_at, length, fin
//   MAX_DATA, DATA_BLOCKED max
//   MAX_STREAM_DATA,       stream_id, max
//   STREAM_DATA_BLOCKED
//   MAX_STREAMS_*,         max (a count of streams)
//   STREAMS_BLOCKED_*
//   NEW_CONNECTION_ID      seq, retire_prior_to, cid_at, cid_len,
//                          token_at (16 bytes: the stateless reset token)
//   RETIRE_CONNECTION_ID   seq
//   PATH_CHALLENGE,        data_at (8 bytes)
//   PATH_RESPONSE
//   CONNECTION_CLOSE       error_code, frame_type (0x1c only), data_at,
//                          length (the reason phrase)
struct Frame {
    ftype: u64 = 0,
    stream_id: u64 = 0,
    offset: u64 = 0,
    data_at: i64 = 0,
    length: i64 = 0,
    fin: bool = false,
    error_code: u64 = 0,
    frame_type: u64 = 0,
    final_size: u64 = 0,
    max: u64 = 0,
    seq: u64 = 0,
    retire_prior_to: u64 = 0,
    cid_at: i64 = 0,
    cid_len: i64 = 0,
    token_at: i64 = 0,
    largest: u64 = 0,
    ack_delay: u64 = 0,
    first_range: u64 = 0,
    range_count: u64 = 0,
    ranges_at: i64 = 0,
    smallest: u64 = 0,
    ecn: bool = false,
    ect0: u64 = 0,
    ect1: u64 = 0,
    ce: u64 = 0,
}

fn is_stream_type(t: u64) -> bool { t >= 0x08 && t <= 0x0f }

// --- Reading ---------------------------------------------------------------------

// n bytes from a varint length: their offset, or bad when the payload is
// shorter.
fn rd_len_bytes(r: Rd&, n: u64) -> i64 {
    if r.bad || n > (r.end - r.pos) as! u64 { r.bad = true; return r.pos; }
    return rd_bytes(r, n as! i64);
}

// The frame at b[at..]: the frame, the offset after it, and 0 or the
// error (FRAME_ENCODING_ERROR) that its encoding is. A STREAM frame
// without a Length runs to the end of b.
fn read_frame(b: const u8[:], at: i64) -> Frame, i64, u64 {
    var f = Frame { .. };
    var r = Rd { pos: at, end: b.len, bad: false };
    let t = rd_varint(r, b);
    if r.bad || r.pos - at != varint_len(t) { return f, at, FRAME_ENCODING_ERROR; }
    f.ftype = t;
    if t == FT_PADDING {
        var n = 1;
        while r.pos < r.end && b[r.pos] == 0 { r.pos++; n++; }
        f.length = n;
        return f, r.pos, NO_ERROR;
    }
    if t == FT_PING || t == FT_HANDSHAKE_DONE { return f, r.pos, NO_ERROR; }
    if t == FT_ACK || t == FT_ACK_ECN {
        f.largest = rd_varint(r, b);
        f.ack_delay = rd_varint(r, b);
        f.range_count = rd_varint(r, b);
        f.first_range = rd_varint(r, b);
        if r.bad || f.first_range > f.largest { return f, at, FRAME_ENCODING_ERROR; }
        var smallest = f.largest - f.first_range;
        f.ranges_at = r.pos;
        var k: u64 = 0;
        while k < f.range_count {
            // Each Gap and ACK Range Length takes at least two bytes: a
            // count beyond what is left fails here, not after a long loop.
            if r.bad || r.pos >= r.end { return f, at, FRAME_ENCODING_ERROR; }
            let gap = rd_varint(r, b);
            let len = rd_varint(r, b);
            if r.bad || gap + 2 > smallest { return f, at, FRAME_ENCODING_ERROR; }
            let hi = smallest - gap - 2;
            if len > hi { return f, at, FRAME_ENCODING_ERROR; }
            smallest = hi - len;
            k++;
        }
        f.smallest = smallest;
        if t == FT_ACK_ECN {
            f.ecn = true;
            f.ect0 = rd_varint(r, b);
            f.ect1 = rd_varint(r, b);
            f.ce = rd_varint(r, b);
        }
        if r.bad { return f, at, FRAME_ENCODING_ERROR; }
        return f, r.pos, NO_ERROR;
    }
    if t == FT_RESET_STREAM {
        f.stream_id = rd_varint(r, b);
        f.error_code = rd_varint(r, b);
        f.final_size = rd_varint(r, b);
    } else if t == FT_STOP_SENDING {
        f.stream_id = rd_varint(r, b);
        f.error_code = rd_varint(r, b);
    } else if t == FT_CRYPTO {
        f.offset = rd_varint(r, b);
        let n = rd_varint(r, b);
        f.data_at = rd_len_bytes(r, n);
        f.length = n as! i64;
        if !r.bad && f.offset + n > MAX_VARINT { return f, at, FRAME_ENCODING_ERROR; }
    } else if t == FT_NEW_TOKEN {
        let n = rd_varint(r, b);
        if !r.bad && n == 0 { return f, at, FRAME_ENCODING_ERROR; }
        f.data_at = rd_len_bytes(r, n);
        f.length = n as! i64;
    } else if is_stream_type(t) {
        f.stream_id = rd_varint(r, b);
        if t & 0x04 != 0 { f.offset = rd_varint(r, b); }
        var n: u64 = 0;
        if t & 0x02 != 0 {
            n = rd_varint(r, b);
        } else if !r.bad {
            n = (r.end - r.pos) as! u64;
        }
        f.data_at = rd_len_bytes(r, n);
        f.length = n as! i64;
        f.fin = t & 0x01 != 0;
        if !r.bad && f.offset + n > MAX_VARINT { return f, at, FRAME_ENCODING_ERROR; }
    } else if t == FT_MAX_DATA || t == FT_DATA_BLOCKED {
        f.max = rd_varint(r, b);
    } else if t == FT_MAX_STREAM_DATA || t == FT_STREAM_DATA_BLOCKED {
        f.stream_id = rd_varint(r, b);
        f.max = rd_varint(r, b);
    } else if t == FT_MAX_STREAMS_BIDI || t == FT_MAX_STREAMS_UNI || t == FT_STREAMS_BLOCKED_BIDI || t == FT_STREAMS_BLOCKED_UNI {
        f.max = rd_varint(r, b);
        if !r.bad && f.max > MAX_STREAMS_LIMIT { return f, at, FRAME_ENCODING_ERROR; }
    } else if t == FT_NEW_CONNECTION_ID {
        f.seq = rd_varint(r, b);
        f.retire_prior_to = rd_varint(r, b);
        let n = rd_u8(r, b);
        if !r.bad && (n < 1 || n > MAX_CID || f.retire_prior_to > f.seq) { return f, at, FRAME_ENCODING_ERROR; }
        f.cid_at = rd_bytes(r, n);
        f.cid_len = n;
        f.token_at = rd_bytes(r, 16);
    } else if t == FT_RETIRE_CONNECTION_ID {
        f.seq = rd_varint(r, b);
    } else if t == FT_PATH_CHALLENGE || t == FT_PATH_RESPONSE {
        f.data_at = rd_bytes(r, 8);
        f.length = 8;
    } else if t == FT_CONNECTION_CLOSE || t == FT_APPLICATION_CLOSE {
        f.error_code = rd_varint(r, b);
        if t == FT_CONNECTION_CLOSE { f.frame_type = rd_varint(r, b); }
        let n = rd_varint(r, b);
        f.data_at = rd_len_bytes(r, n);
        f.length = n as! i64;
    } else {
        return f, at, FRAME_ENCODING_ERROR;
    }
    if r.bad { return f, at, FRAME_ENCODING_ERROR; }
    return f, r.pos, NO_ERROR;
}

// The ranges an ACK frame read from b acknowledges, highest first, as
// pairs (largest, smallest) appended to out: read_frame has checked them.
fn ack_ranges(b: const u8[:], f: const Frame&, out: u64[>..]&) {
    out.push(f.largest);
    var smallest = f.largest - f.first_range;
    out.push(smallest);
    var r = Rd { pos: f.ranges_at, end: b.len, bad: false };
    for k in f.range_count {
        let gap = rd_varint(r, b);
        let len = rd_varint(r, b);
        let hi = smallest - gap - 2;
        smallest = hi - len;
        out.push(hi);
        out.push(smallest);
    }
}

// --- Which frames go where (§12.4, §13.2) ---------------------------------------------

// Whether a frame of type t may be in a packet of type pt (PT_INITIAL,
// PT_ZERO_RTT, PT_HANDSHAKE, PT_ONE_RTT). Initial and Handshake packets
// carry only PADDING, PING, ACK, CRYPTO and a transport CONNECTION_CLOSE;
// 0-RTT packets none of ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN,
// PATH_RESPONSE and RETIRE_CONNECTION_ID (§17.2.3).
fn frame_allowed(t: u64, pt: u8) -> bool {
    if t == FT_PADDING || t == FT_PING || t == FT_CONNECTION_CLOSE { return true; }
    if t == FT_ACK || t == FT_ACK_ECN || t == FT_CRYPTO { return pt != PT_ZERO_RTT; }
    if pt == PT_INITIAL || pt == PT_HANDSHAKE { return false; }
    if t == FT_NEW_TOKEN || t == FT_HANDSHAKE_DONE || t == FT_PATH_RESPONSE || t == FT_RETIRE_CONNECTION_ID {
        return pt == PT_ONE_RTT;
    }
    return t <= FT_HANDSHAKE_DONE;
}

// Whether a frame asks for an acknowledgment: all but ACK, PADDING and
// CONNECTION_CLOSE (§13.2.1).
fn ack_eliciting(t: u64) -> bool {
    t != FT_ACK && t != FT_ACK_ECN && t != FT_PADDING && t != FT_CONNECTION_CLOSE && t != FT_APPLICATION_CLOSE
}

// --- Writing -------------------------------------------------------------------------

fn put_padding(out: u8[>..]&, n: i64) { for i in n { out.push(0); } }

fn put_ping(out: u8[>..]&) { out.push(0x01); }

fn put_handshake_done(out: u8[>..]&) { out.push(0x1e); }

// An ACK frame of ranges, pairs (largest, smallest) from the highest
// down, apart by at least one packet number; ack_delay already scaled by
// the ack_delay_exponent. With ecn, ACK_ECN and its three counts.
fn put_ack(out: u8[>..]&, ranges: const u64[:], ack_delay: u64, ecn: bool, ect0: u64, ect1: u64, ce: u64) {
    assert(ranges.len >= 2 && ranges.len % 2 == 0);
    put_varint(out, if ecn { FT_ACK_ECN } else { FT_ACK });
    put_varint(out, ranges[0]);
    put_varint(out, ack_delay);
    put_varint(out, (ranges.len / 2 - 1) as! u64);
    put_varint(out, ranges[0] - ranges[1]);
    var k = 2;
    while k < ranges.len {
        assert(ranges[k] + 2 <= ranges[k - 1] && ranges[k + 1] <= ranges[k]);
        put_varint(out, ranges[k - 1] - ranges[k] - 2);
        put_varint(out, ranges[k] - ranges[k + 1]);
        k += 2;
    }
    if ecn {
        put_varint(out, ect0);
        put_varint(out, ect1);
        put_varint(out, ce);
    }
}

fn put_reset_stream(out: u8[>..]&, stream_id: u64, error_code: u64, final_size: u64) {
    put_varint(out, FT_RESET_STREAM);
    put_varint(out, stream_id);
    put_varint(out, error_code);
    put_varint(out, final_size);
}

fn put_stop_sending(out: u8[>..]&, stream_id: u64, error_code: u64) {
    put_varint(out, FT_STOP_SENDING);
    put_varint(out, stream_id);
    put_varint(out, error_code);
}

fn put_crypto(out: u8[>..]&, offset: u64, data: const u8[:]) {
    put_varint(out, FT_CRYPTO);
    put_varint(out, offset);
    put_varint(out, data.len as! u64);
    out.append(data);
}

fn put_new_token(out: u8[>..]&, token: const u8[:]) {
    assert(token.len > 0);
    put_varint(out, FT_NEW_TOKEN);
    put_varint(out, token.len as! u64);
    out.append(token);
}

// A STREAM frame: the Offset field when the offset is not 0, the Length
// field when with_length (without, the data runs to the packet's end).
fn put_stream(out: u8[>..]&, stream_id: u64, offset: u64, data: const u8[:], fin: bool, with_length: bool) {
    var t = FT_STREAM;
    if offset != 0 { t = t | 0x04; }
    if with_length { t = t | 0x02; }
    if fin { t = t | 0x01; }
    put_varint(out, t);
    put_varint(out, stream_id);
    if offset != 0 { put_varint(out, offset); }
    if with_length { put_varint(out, data.len as! u64); }
    out.append(data);
}

// The bytes a STREAM frame's header takes (all but its data).
fn stream_header_len(stream_id: u64, offset: u64, n: i64, with_length: bool) -> i64 {
    var l = 1 + varint_len(stream_id);
    if offset != 0 { l += varint_len(offset); }
    if with_length { l += varint_len(n as! u64); }
    return l;
}

fn put_max_data(out: u8[>..]&, max: u64) {
    put_varint(out, FT_MAX_DATA);
    put_varint(out, max);
}

fn put_max_stream_data(out: u8[>..]&, stream_id: u64, max: u64) {
    put_varint(out, FT_MAX_STREAM_DATA);
    put_varint(out, stream_id);
    put_varint(out, max);
}

fn put_max_streams(out: u8[>..]&, bidi: bool, max: u64) {
    put_varint(out, if bidi { FT_MAX_STREAMS_BIDI } else { FT_MAX_STREAMS_UNI });
    put_varint(out, max);
}

fn put_data_blocked(out: u8[>..]&, max: u64) {
    put_varint(out, FT_DATA_BLOCKED);
    put_varint(out, max);
}

fn put_stream_data_blocked(out: u8[>..]&, stream_id: u64, max: u64) {
    put_varint(out, FT_STREAM_DATA_BLOCKED);
    put_varint(out, stream_id);
    put_varint(out, max);
}

fn put_streams_blocked(out: u8[>..]&, bidi: bool, max: u64) {
    put_varint(out, if bidi { FT_STREAMS_BLOCKED_BIDI } else { FT_STREAMS_BLOCKED_UNI });
    put_varint(out, max);
}

fn put_new_connection_id(out: u8[>..]&, seq: u64, retire_prior_to: u64, cid: const u8[:], reset_token: const u8[:]) {
    assert(cid.len >= 1 && cid.len <= MAX_CID && reset_token.len == 16 && retire_prior_to <= seq);
    put_varint(out, FT_NEW_CONNECTION_ID);
    put_varint(out, seq);
    put_varint(out, retire_prior_to);
    out.push(cid.len as! u8);
    out.append(cid);
    out.append(reset_token);
}

fn put_retire_connection_id(out: u8[>..]&, seq: u64) {
    put_varint(out, FT_RETIRE_CONNECTION_ID);
    put_varint(out, seq);
}

fn put_path_challenge(out: u8[>..]&, data: const u8[:]) {
    assert(data.len == 8);
    out.push(0x1a);
    out.append(data);
}

fn put_path_response(out: u8[>..]&, data: const u8[:]) {
    assert(data.len == 8);
    out.push(0x1b);
    out.append(data);
}

// A transport error's CONNECTION_CLOSE (0x1c), with the type of the frame
// that caused it (0: unknown).
fn put_connection_close(out: u8[>..]&, error_code: u64, frame_type: u64, reason: const u8[:]) {
    put_varint(out, FT_CONNECTION_CLOSE);
    put_varint(out, error_code);
    put_varint(out, frame_type);
    put_varint(out, reason.len as! u64);
    out.append(reason);
}

// An application's CONNECTION_CLOSE (0x1d).
fn put_application_close(out: u8[>..]&, error_code: u64, reason: const u8[:]) {
    put_varint(out, FT_APPLICATION_CLOSE);
    put_varint(out, error_code);
    put_varint(out, reason.len as! u64);
    out.append(reason);
}
