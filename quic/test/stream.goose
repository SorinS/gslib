// QUIC's stream buffers: reassembly in order, out of order, overlapping
// and duplicated; the final size rules (every FINAL_SIZE_ERROR); flow
// control at the window's edge; reading in pieces, the room freed; on the
// sending side new data in order, lost data sent again before new data,
// acknowledgements freeing room, partly acknowledged lost ranges, a lone
// and a lost FIN, the peer's limit kept; and a stream carried through a
// channel that loses, reorders and duplicates, read back exactly.

import std;
import gslib from "../..";
import gslib.quic;
import gslib.quic.stream;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

fn bytes(n: i64, seed: i64) -> u8[>..] {
    var out: u8[>..] = [];
    for i in n { out.push(((i * 7 + seed * 13) & 0xff) as! u8); }
    return out;
}

fn read_all(r: quic::RecvBuf&) -> u8[>..] {
    var out: u8[>..] = [];
    let n = quic::rb_read(r, out, 1 << 30);
    return out;
}

fn reassembly() {
    let d = bytes(100, 1);
    var r = quic::recv_buf();
    check(quic::rb_insert(r, 0, d[..40], false) == 0 && quic::rb_readable(r) == 40, "in order");
    check(quic::rb_insert(r, 60, d[60..], true) == 0 && quic::rb_readable(r) == 40, "a gap: still 40 readable");
    check(quic::rb_fin_known(r) && quic::rb_final_size(r) == 100 && quic::rb_highest(r) == 100, "the final size known");
    check(quic::rb_insert(r, 30, d[30..70], false) == 0 && quic::rb_readable(r) == 100, "the gap filled, overlapping both sides");
    check(quic::rb_insert(r, 10, d[10..20], false) == 0, "a duplicate");
    let all = read_all(r);
    check(all == d && quic::rb_finished(r), "read back whole, finished");
    check(quic::rb_insert(r, 0, d[..50], false) == 0 && quic::rb_readable(r) == 0, "data already read ignored");

    // Out of order, then read in pieces.
    var r2 = quic::recv_buf();
    var at: i64 = 90;
    while at >= 0 { check(quic::rb_insert(r2, at, d[at..at + 10], at == 90) == 0, "backwards"); at -= 10; }
    var got: u8[>..] = [];
    while quic::rb_readable(r2) > 0 { let n = quic::rb_read(r2, got, 7); }
    check(got == d && quic::rb_finished(r2), "read 7 at a time");

    // The first copy is kept.
    var r3 = quic::recv_buf();
    check(quic::rb_insert(r3, 0, "abcdef", false) == 0 && quic::rb_insert(r3, 2, "XYZW", false) == 0, "an overlap that differs");
    check(read_all(r3) == "abcdef", "the first copy kept");
    // A lone FIN.
    var r4 = quic::recv_buf();
    check(quic::rb_insert(r4, 0, "", true) == 0 && quic::rb_finished(r4), "an empty stream");
}

fn final_size() {
    var r = quic::recv_buf();
    check(quic::rb_insert(r, 0, "0123456789", false) == 0, "ten bytes");
    check(quic::rb_insert(r, 0, "01234", true) == quic::FINAL_SIZE_ERROR, "a fin below data received");
    check(quic::rb_insert(r, 10, "ab", true) == 0 && quic::rb_final_size(r) == 12, "a fin at 12");
    check(quic::rb_insert(r, 12, "c", false) == quic::FINAL_SIZE_ERROR, "data past the final size");
    check(quic::rb_insert(r, 0, "0123456789abc", true) == quic::FINAL_SIZE_ERROR, "another final size");
    check(quic::rb_insert(r, 10, "ab", true) == 0, "the same fin again");
    check(quic::rb_insert(r, 5, "56789", false) == 0, "data within the final size");
}

fn flow_control() {
    var r = quic::recv_buf();
    let big = bytes(quic::STREAM_BUF, 2);
    check(quic::rb_insert(r, 0, big, false) == 0, "the whole window");
    check(quic::rb_insert(r, quic::STREAM_BUF, "x", false) == quic::FLOW_CONTROL_ERROR, "a byte past it");
    var out: u8[>..] = [];
    check(quic::rb_read(r, out, 1000) == 1000, "1000 read");
    check(quic::rb_insert(r, quic::STREAM_BUF, bytes(1000, 3), false) == 0, "and 1000 more fit");
    check(quic::rb_insert(r, quic::STREAM_BUF + 1000, "x", false) == quic::FLOW_CONTROL_ERROR, "but not 1001");
    out.clear();
    let n = quic::rb_read(r, out, 1 << 30);
    check(n == quic::STREAM_BUF && out[..quic::STREAM_BUF - 1000] == big[1000..] && out[quic::STREAM_BUF - 1000..] == bytes(1000, 3)[..],
          "read across the freed room");
}

fn too_many_ranges() {
    // Every other byte: the list fills, what does not fit is dropped and
    // comes again.
    let d = bytes(200, 4);
    var r = quic::recv_buf();
    var i: i64 = 1;
    while i < 200 { check(quic::rb_insert(r, i, d[i..i + 1], false) == 0, "scattered"); i += 2; }
    check(r.held.n == quic::MAX_RANGES, "the list full");
    check(quic::rb_insert(r, 0, d, true) == 0, "then all of it");
    check(read_all(r) == d && quic::rb_finished(r), "read whole");
}

fn sending() {
    let d = bytes(1000, 5);
    var s = quic::send_buf();
    check(quic::sb_write(s, d) == 1000 && quic::sb_end(s) == 1000 && quic::sb_pending(s), "written");
    quic::sb_finish(s);
    check(quic::sb_write(s, "more") == 0, "nothing after the end");
    // Chunks of 300, the peer's limit at 700.
    let o1, n1, f1, ok1 = quic::sb_next(s, 300, 700);
    check(ok1 && o1 == 0 && n1 == 300 && !f1, "first chunk");
    quic::sb_sent(s, o1, n1, f1);
    let o2, n2, f2, ok2 = quic::sb_next(s, 300, 700);
    quic::sb_sent(s, o2, n2, f2);
    let o3, n3, f3, ok3 = quic::sb_next(s, 300, 700);
    check(ok3 && o3 == 600 && n3 == 100 && !f3, "the limit cuts the third");
    quic::sb_sent(s, o3, n3, f3);
    let o4, n4, f4, ok4 = quic::sb_next(s, 300, 700);
    check(!ok4 && quic::sb_pending(s), "blocked at the limit, still pending");
    // The first chunk acknowledged, the second lost.
    quic::sb_acked(s, o1, n1, false);
    check(s.base == 300 && quic::sb_unacked(s) == 400, "the front acknowledged");
    quic::sb_lost(s, o2, n2, false);
    let o5, n5, f5, ok5 = quic::sb_next(s, 200, 2000);
    check(ok5 && o5 == 300 && n5 == 200 && !f5, "lost data first");
    quic::sb_sent(s, o5, n5, f5);
    // Part of the lost range acknowledged before it is sent again.
    quic::sb_acked(s, 500, 50, false);
    let o6, n6, f6, ok6 = quic::sb_next(s, 1000, 2000);
    check(ok6 && o6 == 550 && n6 == 50, "the acknowledged part not sent again");
    quic::sb_sent(s, o6, n6, f6);
    let o7, n7, f7, ok7 = quic::sb_next(s, 1000, 2000);
    check(ok7 && o7 == 700 && n7 == 300 && f7, "then new data, with the fin");
    quic::sb_sent(s, o7, n7, f7);
    check(!quic::sb_pending(s), "nothing left to send");
    // The fin lost alone: a lone FIN goes again.
    quic::sb_acked(s, 700, 300, false);
    quic::sb_lost(s, 1000, 0, true);
    let o8, n8, f8, ok8 = quic::sb_next(s, 1000, 2000);
    check(ok8 && o8 == 1000 && n8 == 0 && f8, "a lone FIN");
    quic::sb_sent(s, o8, n8, f8);
    quic::sb_acked(s, 1000, 0, true);
    check(!quic::sb_all_acked(s) && quic::sb_unacked(s) == 350, "not all acknowledged: 300-500, 550-700");
    quic::sb_acked(s, 300, 200, false);
    quic::sb_acked(s, 600, 100, false);
    check(s.base == 550 && quic::sb_unacked(s) == 50, "550-600 still out");
    quic::sb_acked(s, 550, 50, false);
    check(quic::sb_all_acked(s) && s.base == 1000 && s.data.len == 0, "all acknowledged, the room freed");
    check(quic::sb_bytes(s, 1000, 0).len == 0, "no bytes held");
}

fn full_buffer() {
    var s = quic::send_buf();
    let big = bytes(quic::STREAM_BUF + 100, 6);
    check(quic::sb_write(s, big) == quic::STREAM_BUF, "the buffer takes what fits");
    let o, n, f, ok = quic::sb_next(s, 1000, 1 << 40);
    quic::sb_sent(s, o, n, f);
    quic::sb_acked(s, o, n, false);
    check(quic::sb_write(s, big[quic::STREAM_BUF..]) == 100, "room after an acknowledgement");
    check(quic::sb_bytes(s, 1000, 10) == big[1000..1010], "the bytes held");
    // A lone FIN on an empty stream.
    var e = quic::send_buf();
    quic::sb_finish(e);
    let eo, en, ef, eok = quic::sb_next(e, 100, 0);
    check(eok && eo == 0 && en == 0 && ef, "an empty stream's FIN, even at limit 0");
}

// A deterministic PRNG.
var seed: u64 = 0x9e3779b97f4a7c15;

fn rnd(n: i64) -> i64 {
    seed = seed ^ (seed << 13);
    seed = seed ^ (seed >> 7);
    seed = seed ^ (seed << 17);
    return (seed % n as! u64) as! i64;
}

struct Pkt { off: i64, len: i64, fin: bool, live: bool }

fn lossy_channel(round: i64) {
    let total: i64 = 50000 + round * 3331;
    let d = bytes(total, 7 + round);
    var s = quic::send_buf();
    var r = quic::recv_buf();
    var written: i64 = 0;
    var got: u8[>..] = [];
    var flight: Pkt[64] = [Pkt { off: 0, len: 0, fin: false, live: false }; 64];
    var steps = 0;
    while steps < 200000 {
        steps++;
        if written < total { written += quic::sb_write(s, d[written..]); if written == total { quic::sb_finish(s); } }
        // Send a chunk into a free slot, the receiver's window as the limit.
        var slot: i64 = -1;
        for k in 64 { if slot < 0 && !flight[k].live { slot = k; } }
        if slot >= 0 {
            let limit = r.base + quic::STREAM_BUF;
            let o, n, f, ok = quic::sb_next(s, 1 + rnd(1400), limit);
            if ok {
                quic::sb_sent(s, o, n, f);
                flight[slot] = Pkt { off: o, len: n, fin: f, live: true };
            }
        }
        // Deliver, lose or keep a random packet in flight.
        let k = rnd(64);
        if flight[k].live {
            let p = flight[k];
            let fate = rnd(10);
            if fate < 2 {
                quic::sb_lost(s, p.off, p.len, p.fin);
                flight[k].live = false;
            } else if fate < 8 {
                let e = quic::rb_insert(r, p.off, sb_slice(s, p, d), p.fin);
                check(e == 0, "no error on the channel");
                if fate == 7 { let e2 = quic::rb_insert(r, p.off, sb_slice(s, p, d), p.fin); }   // a duplicate
                // The ack, or its loss (the data then goes again).
                if rnd(10) < 8 { quic::sb_acked(s, p.off, p.len, p.fin); } else { quic::sb_lost(s, p.off, p.len, p.fin); }
                flight[k].live = false;
            }
        }
        if rnd(3) == 0 { let n = quic::rb_read(r, got, rnd(5000)); }
        if quic::sb_all_acked(s) && quic::rb_finished(r) { break; }
        // Read the rest once the sender is done.
        if quic::sb_all_acked(s) { let n = quic::rb_read(r, got, 1 << 30); }
    }
    let n = quic::rb_read(r, got, 1 << 30);
    check(got == d && quic::rb_finished(r) && quic::sb_all_acked(s), "a stream through a lossy channel");
}

// A packet's bytes: the original data, since the sender may have freed them.
fn sb_slice(s: const quic::SendBuf&, p: const Pkt&, d: const u8[:]) -> const u8[:] { d[p.off..p.off + p.len] }

fn main() {
    reassembly();
    final_size();
    flow_control();
    too_many_ranges();
    sending();
    full_buffer();
    for round in 8 { lossy_channel(round); }
    print("stream: ", checks, " checks");
}
