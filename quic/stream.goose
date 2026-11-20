// quic.stream: the buffers behind QUIC's streams and CRYPTO streams (RFC
// 9000 §2, §3, §4). A SendBuf holds what was written and not yet
// acknowledged: new data goes out in order, data in lost packets goes out
// again first, and acknowledgements free the room from the front. A
// RecvBuf reassembles data that arrives out of order, duplicated or
// overlapping (the first copy is kept), checks the final size and that
// nothing comes past the window, and gives the bytes back in order.
// Ranges beyond the front are kept in short fixed lists; when a list is
// full the buffers err on the safe side (a receiver drops what it cannot
// note, which the peer sends again; a sender may send acknowledged data
// again).

namespace quic;

import std;
import quic;

let STREAM_BUF: i64 = 65536;
let MAX_RANGES: i64 = 32;

// Half-open ranges [s, e), sorted, apart (neither overlapping nor touching).
struct Ranges { s: i64[32], e: i64[32], n: i64 }

fn ranges() -> Ranges { Ranges { s: [0; 32], e: [0; 32], n: 0 } }

fn rg_remove_at(r: Ranges&, k: i64) {
    var i = k;
    while i + 1 < r.n { r.s[i] = r.s[i + 1]; r.e[i] = r.e[i + 1]; i++; }
    r.n--;
}

fn rg_insert_at(r: Ranges&, k: i64, a: i64, b: i64) {
    var i = r.n;
    while i > k { r.s[i] = r.s[i - 1]; r.e[i] = r.e[i - 1]; i--; }
    r.s[k] = a;
    r.e[k] = b;
    r.n++;
}

// Adds [a, b), merging with what it overlaps or touches; false (nothing
// changed) when it needs a slot and the list is full.
fn rg_add(r: Ranges&, a: i64, b: i64) -> bool {
    if a >= b { return true; }
    // The first range that ends at or after a: it and those after it that
    // start at or before b merge with [a, b).
    var k = 0;
    while k < r.n && r.e[k] < a { k++; }
    if k == r.n || r.s[k] > b {
        if r.n == MAX_RANGES { return false; }
        rg_insert_at(r, k, a, b);
        return true;
    }
    r.s[k] = ::min(r.s[k], a);
    r.e[k] = ::max(r.e[k], b);
    while k + 1 < r.n && r.s[k + 1] <= r.e[k] {
        r.e[k] = ::max(r.e[k], r.e[k + 1]);
        rg_remove_at(r, k + 1);
    }
    return true;
}

// Takes [a, b) out; a range split in two when the list is full is left
// whole (false).
fn rg_sub(r: Ranges&, a: i64, b: i64) -> bool {
    if a >= b { return true; }
    var k = 0;
    while k < r.n {
        if r.e[k] <= a || r.s[k] >= b { k++; continue; }
        if r.s[k] < a && r.e[k] > b {
            if r.n == MAX_RANGES { return false; }
            rg_insert_at(r, k + 1, b, r.e[k]);
            r.e[k] = a;
            return true;
        }
        if r.s[k] >= a && r.e[k] <= b { rg_remove_at(r, k); continue; }
        if r.s[k] < a { r.e[k] = a; } else { r.s[k] = b; }
        k++;
    }
    return true;
}

// The bytes of ranges in r.
fn rg_total(r: const Ranges&) -> i64 {
    var t: i64 = 0;
    for k in r.n { t += r.e[k] - r.s[k]; }
    return t;
}

// The first piece of [a, b) that r does not cover: (start, end), or start
// == end when r covers all of it.
fn rg_first_gap(r: const Ranges&, a: i64, b: i64) -> i64, i64 {
    var x = a;
    for k in r.n {
        if r.e[k] <= x { continue; }
        if r.s[k] >= b { break; }
        if r.s[k] > x { return x, ::min(r.s[k], b); }
        x = r.e[k];
        if x >= b { return b, b; }
    }
    return x, b;
}

// Drops the first k bytes of a buffer, moving the rest to the front.
fn shift_front(d: u8[..65536]&, k: i64) {
    if k <= 0 { return; }
    if k >= d.len { d.clear(); return; }
    for i in d.len - k { d[i] = d[i + k]; }
    d.resize(d.len - k);
}

// --- Sending ----------------------------------------------------------------------

// Data written to a stream, from offset base on: sent up to sent_upto,
// the lost ranges to send again first, the acknowledged ranges beyond
// base (base moves up over them).
struct SendBuf {
    base: i64,
    sent_upto: i64,
    finished: bool,                // sb_finish: the stream ends at sb_end
    fin_sent: bool, fin_lost: bool, fin_acked: bool,
    lost: Ranges,
    acked: Ranges,
    data: u8[..65536],             // [base, sb_end)
}

fn send_buf() -> SendBuf {
    SendBuf { base: 0, sent_upto: 0, finished: false, fin_sent: false, fin_lost: false, fin_acked: false,
              lost: ranges(), acked: ranges(), data: [] }
}

fn sb_end(s: const SendBuf&) -> i64 { s.base + s.data.len }

// Takes what fits of data; the bytes taken.
fn sb_write(s: SendBuf&, data: const u8[:]) -> i64 {
    if s.finished { return 0; }
    let n = ::min(data.len, STREAM_BUF - s.data.len);
    s.data.append(data[..n]);
    return n;
}

fn sb_finish(s: SendBuf&) { s.finished = true; }

// The next chunk to send: lost data first, then new data up to limit (an
// absolute offset, the peer's flow control limit), at most max_len bytes;
// fin when the chunk ends the stream and the fin still has to go. A chunk
// of no bytes with fin is a lone FIN.
fn sb_next(s: const SendBuf&, max_len: i64, limit: i64) -> i64, i64, bool, bool {
    let end = sb_end(s);
    let fin_due = s.finished && (!s.fin_sent || s.fin_lost);
    if s.lost.n > 0 {
        let a = s.lost.s[0];
        let n = ::min(s.lost.e[0] - a, max_len);
        if n > 0 { return a, n, fin_due && a + n == end && s.sent_upto == end, true; }
        return 0, 0, false, false;
    }
    let a = s.sent_upto;
    let n = ::max(::min(::min(end - a, max_len), limit - a), 0);
    if n > 0 { return a, n, fin_due && a + n == end, true; }
    if fin_due && a == end { return end, 0, true, true; }
    return 0, 0, false, false;
}

// The data of [off, off + len), which the buffer must still hold.
fn sb_bytes(s: const SendBuf&, off: i64, len: i64) -> const u8[:] {
    assert(off >= s.base && off + len <= sb_end(s));
    return s.data[off - s.base..off - s.base + len];
}

fn sb_sent(s: SendBuf&, off: i64, len: i64, fin: bool) {
    let ok = rg_sub(s.lost, off, off + len);
    if off + len > s.sent_upto { s.sent_upto = off + len; }
    if fin { s.fin_sent = true; s.fin_lost = false; }
}

// Moves base over the acknowledged ranges that now start at it.
fn sb_advance(s: SendBuf&) {
    while s.acked.n > 0 && s.acked.s[0] <= s.base {
        let e = s.acked.e[0];
        rg_remove_at(s.acked, 0);
        if e > s.base {
            shift_front(s.data, e - s.base);
            s.base = e;
        }
    }
    if s.sent_upto < s.base { s.sent_upto = s.base; }
    let ok = rg_sub(s.lost, 0, s.base);
}

fn sb_acked(s: SendBuf&, off: i64, len: i64, fin: bool) {
    if fin { s.fin_acked = true; s.fin_lost = false; }
    let a = ::max(off, s.base);
    let b = off + len;
    if a < b {
        // Contiguous with base: base moves at once, whether or not the
        // list has room.
        if a == s.base {
            shift_front(s.data, b - s.base);
            s.base = b;
        } else {
            let ok = rg_add(s.acked, a, b);
        }
        let ok2 = rg_sub(s.lost, a, b);
    }
    sb_advance(s);
}

fn sb_lost(s: SendBuf&, off: i64, len: i64, fin: bool) {
    if fin && !s.fin_acked { s.fin_lost = true; }
    var a = ::max(off, s.base);
    let b = ::min(off + len, s.sent_upto);
    // The parts not acknowledged meanwhile go back; a full list takes the
    // piece into its last range (acknowledged data may then go again).
    while a < b {
        let ga, gb = rg_first_gap(s.acked, a, b);
        if ga >= gb { break; }
        if !rg_add(s.lost, ga, gb) {
            var k = s.lost.n - 1;
            s.lost.s[k] = ::min(s.lost.s[k], ga);
            s.lost.e[k] = ::max(s.lost.e[k], gb);
            // Merging may now overlap the ranges before it.
            while k > 0 && s.lost.e[k - 1] >= s.lost.s[k] {
                s.lost.s[k - 1] = ::min(s.lost.s[k - 1], s.lost.s[k]);
                s.lost.e[k - 1] = ::max(s.lost.e[k - 1], s.lost.e[k]);
                rg_remove_at(s.lost, k);
                k--;
            }
        }
        a = gb;
    }
}

fn sb_pending(s: const SendBuf&) -> bool {
    s.lost.n > 0 || s.sent_upto < sb_end(s) || (s.finished && (!s.fin_sent || s.fin_lost))
}

fn sb_all_acked(s: const SendBuf&) -> bool { s.finished && s.fin_acked && s.base == sb_end(s) }

fn sb_unacked(s: const SendBuf&) -> i64 { s.sent_upto - s.base - rg_total(s.acked) }

// --- Receiving --------------------------------------------------------------------

// Data received: read up to base; the ranges held beyond it, the bytes at
// [base, base + data.len) (gaps zero); the final size once known.
struct RecvBuf {
    base: i64,
    final_size: i64,               // -1 until a fin
    highest: i64,
    held: Ranges,
    data: u8[..65536],
}

fn recv_buf() -> RecvBuf { RecvBuf { base: 0, final_size: -1, highest: 0, held: ranges(), data: [] } }

// Data at off, with the stream's end after it if fin. 0, FINAL_SIZE_ERROR
// or FLOW_CONTROL_ERROR.
fn rb_insert(r: RecvBuf&, off: i64, data: const u8[:], fin: bool) -> u64 {
    let end = off + data.len;
    if fin {
        if r.final_size >= 0 && r.final_size != end { return FINAL_SIZE_ERROR; }
        if end < r.highest { return FINAL_SIZE_ERROR; }
        r.final_size = end;
    } else if r.final_size >= 0 && end > r.final_size {
        return FINAL_SIZE_ERROR;
    }
    if end > r.base + STREAM_BUF { return FLOW_CONTROL_ERROR; }
    r.highest = ::max(r.highest, end);
    // The pieces not read and not held yet, each kept if the list has room.
    var a = ::max(off, r.base);
    while a < end {
        let ga, gb = rg_first_gap(r.held, a, end);
        if ga >= gb { break; }
        if rg_add(r.held, ga, gb) {
            let at = ga - r.base;
            let to = gb - r.base;
            if r.data.len < to { r.data.resize(to, 0); }
            for i in gb - ga { r.data[at + i] = data[ga - off + i]; }
        }
        a = gb;
    }
    return 0;
}

fn rb_readable(r: const RecvBuf&) -> i64 {
    if r.held.n > 0 && r.held.s[0] <= r.base { return r.held.e[0] - r.base; }
    return 0;
}

// Appends up to max bytes in order; how many.
fn rb_read(r: RecvBuf&, out: u8[>..]&, max: i64) -> i64 {
    let k = ::min(rb_readable(r), max);
    if k <= 0 { return 0; }
    out.append(r.data[..k]);
    shift_front(r.data, k);
    r.base += k;
    r.held.s[0] = r.base;
    if r.held.s[0] >= r.held.e[0] { rg_remove_at(r.held, 0); }
    return k;
}

fn rb_fin_known(r: const RecvBuf&) -> bool { r.final_size >= 0 }

fn rb_final_size(r: const RecvBuf&) -> i64 { r.final_size }

fn rb_finished(r: const RecvBuf&) -> bool { r.final_size >= 0 && r.base == r.final_size }

fn rb_highest(r: const RecvBuf&) -> i64 { r.highest }
