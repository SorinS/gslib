// quic.recovery: loss detection and congestion control (RFC 9002): the
// packets in flight in each packet number space, the round-trip time
// estimate from acknowledgements, packets declared lost by the packet and
// time thresholds, the probe timeout (PTO), and NewReno with slow start,
// recovery and persistent congestion. Times are microseconds. What a
// packet carried is the connection's to know: each sent packet keeps an
// opaque reference (rec_at, rec_n) the connection hands back when the
// packet is acknowledged or lost.

namespace quic;

import std;
import quic;

let SPACE_INITIAL: i64 = 0;
let SPACE_HANDSHAKE: i64 = 1;
let SPACE_APP: i64 = 2;

let K_PACKET_THRESHOLD: i64 = 3;
let K_GRANULARITY: i64 = 1000;             // 1 ms
let K_INITIAL_RTT: i64 = 333000;           // 333 ms
let MAX_DATAGRAM: i64 = 1200;
let K_INITIAL_WINDOW: i64 = 10 * 1200;
let K_MINIMUM_WINDOW: i64 = 2 * 1200;
let K_PERSISTENT_CONGESTION_THRESHOLD: i64 = 3;
let MAX_SENT: i64 = 1024;                  // packets tracked in flight, all spaces

struct Sent {
    used: bool,
    space: i64,
    pn: i64,
    time: i64,
    size: i64,
    ack_eliciting: bool,
    in_flight: bool,
    rec_at: i64, rec_n: i64,   // the connection's record of what it carried
}

struct Recovery {
    sent: Sent[1024],
    n_sent: i64,
    largest_acked: i64[3],
    last_ack_eliciting: i64[3],            // time of the last ack-eliciting packet sent, per space
    loss_time: i64[3],
    // RTT (§5).
    latest_rtt: i64, smoothed_rtt: i64, rttvar: i64, min_rtt: i64, first_rtt_sample: i64,
    has_rtt: bool,
    max_ack_delay: i64,                    // the peer's, in microseconds
    pto_count: i64,
    // Congestion control (§7).
    cwnd: i64, bytes_in_flight: i64, ssthresh: i64, recovery_start: i64,
    // The client before it has Handshake keys, and before the server is
    // known to have validated its address, must keep a PTO armed (§6.2.2.1).
    peer_completed_address_validation: bool,
}

fn recovery() -> Recovery {
    var r = Recovery { sent: [Sent { used: false, space: 0, pn: 0, time: 0, size: 0, ack_eliciting: false, in_flight: false, rec_at: 0, rec_n: 0 }; 1024],
                       n_sent: 0, largest_acked: [-1; 3], last_ack_eliciting: [0; 3], loss_time: [0; 3],
                       latest_rtt: 0, smoothed_rtt: K_INITIAL_RTT, rttvar: K_INITIAL_RTT / 2, min_rtt: 0, first_rtt_sample: 0,
                       has_rtt: false, max_ack_delay: 25000, pto_count: 0,
                       cwnd: K_INITIAL_WINDOW, bytes_in_flight: 0, ssthresh: 0x7fffffffffffffff, recovery_start: 0,
                       peer_completed_address_validation: false };
    return r;
}

// Whether a slot is free for another packet; when false the connection
// must not send (more than MAX_SENT in flight).
fn can_track(r: const Recovery&) -> bool { r.n_sent < MAX_SENT }

// The congestion window's room for a packet of size bytes.
fn cwnd_allows(r: const Recovery&, size: i64) -> bool { r.bytes_in_flight + size <= r.cwnd }

fn on_packet_sent(r: Recovery&, space: i64, pn: i64, now: i64, size: i64, ack_eliciting: bool, in_flight: bool,
                  rec_at: i64, rec_n: i64) {
    // A packet of ACKs alone is kept only while the table is half empty: a
    // peer acknowledging nothing would otherwise fill it with them.
    if !in_flight && r.n_sent >= MAX_SENT / 2 { return; }
    var k: i64 = -1;
    for i in MAX_SENT { if k < 0 && !r.sent[i].used { k = i; } }
    if k < 0 { return; }
    r.sent[k] = Sent { used: true, space: space, pn: pn, time: now, size: size, ack_eliciting: ack_eliciting,
                       in_flight: in_flight, rec_at: rec_at, rec_n: rec_n };
    r.n_sent++;
    if in_flight {
        if ack_eliciting { r.last_ack_eliciting[space] = now; }
        r.bytes_in_flight += size;
    }
}

fn update_rtt(r: Recovery&, latest: i64, ack_delay: i64, confirmed: bool) {
    r.latest_rtt = latest;
    if !r.has_rtt {
        r.min_rtt = latest;
        r.smoothed_rtt = latest;
        r.rttvar = latest / 2;
        r.has_rtt = true;
        return;
    }
    r.min_rtt = ::min(r.min_rtt, latest);
    // The peer's ack delay counts only once the handshake is confirmed,
    // and never above max_ack_delay (§5.3).
    var delay = ack_delay;
    if confirmed { delay = ::min(delay, r.max_ack_delay); }
    var adjusted = latest;
    if latest >= r.min_rtt + delay { adjusted = latest - delay; }
    let diff = if r.smoothed_rtt > adjusted { r.smoothed_rtt - adjusted } else { adjusted - r.smoothed_rtt };
    r.rttvar = (3 * r.rttvar + diff) / 4;
    r.smoothed_rtt = (7 * r.smoothed_rtt + adjusted) / 8;
}

fn pto_base(r: const Recovery&) -> i64 { r.smoothed_rtt + ::max(4 * r.rttvar, K_GRANULARITY) }

// Whether pn is acknowledged by ranges: pairs (smallest, largest), any order.
fn in_ranges(ranges: const i64[:], pn: i64) -> bool {
    var i = 0;
    while i + 1 < ranges.len {
        if pn >= ranges[i] && pn <= ranges[i + 1] { return true; }
        i += 2;
    }
    return false;
}

// Removes a packet from flight; with congestion bookkeeping when it is in flight.
fn remove_sent(r: Recovery&, k: i64) {
    if r.sent[k].in_flight { r.bytes_in_flight -= r.sent[k].size; }
    r.sent[k].used = false;
    r.n_sent--;
}

// An ACK frame received in a space: ranges as (smallest, largest) pairs,
// ack_delay already scaled to microseconds. F is called for each packet
// newly acknowledged (sent, true) or declared lost (sent, false). Returns
// false when it acknowledges a packet never sent (PROTOCOL_VIOLATION).
// At most this many ranges of one ACK frame are looked at (the highest):
// each costs a pass over the table, and a frame can hold hundreds.
let MAX_ACK_RANGES: i64 = 64;

fn on_ack_received<F>(r: Recovery&, space: i64, all_ranges: const i64[:], ack_delay: i64, now: i64, confirmed: bool, next_pn: i64) -> bool {
    let ranges = all_ranges[..::min(all_ranges.len, 2 * MAX_ACK_RANGES)];
    var largest: i64 = -1;
    var i = 0;
    while i + 1 < ranges.len { largest = ::max(largest, ranges[i + 1]); i += 2; }
    if largest >= next_pn { return false; }
    r.largest_acked[space] = ::max(r.largest_acked[space], largest);
    // Newly acknowledged packets; the RTT from the largest when it is new
    // and ack-eliciting packets were among them (§5.1).
    var largest_time: i64 = -1;
    var any_eliciting = false;
    var acked_bytes: i64 = 0;
    var oldest_acked_time: i64 = -1;
    for k in MAX_SENT {
        if r.sent[k].used && r.sent[k].space == space && in_ranges(ranges, r.sent[k].pn) {
            let s = r.sent[k];
            if s.pn == largest { largest_time = s.time; }
            if s.ack_eliciting { any_eliciting = true; }
            if s.in_flight {
                acked_bytes += s.size;
                on_acked_cc(r, s);
            }
            remove_sent(r, k);
            F(s, true);
        }
    }
    if largest_time >= 0 && any_eliciting { update_rtt(r, now - largest_time, ack_delay, confirmed); }
    detect_lost(r, space, now, F);
    // The PTO backs off no more once a packet is acknowledged, except a
    // client's while the server may still be limited by amplification.
    if acked_bytes > 0 || any_eliciting { if r.peer_completed_address_validation || space != SPACE_INITIAL { r.pto_count = 0; } }
    return true;
}

// Congestion control on an acknowledged packet (§7.3).
fn on_acked_cc(r: Recovery&, s: const Sent&) {
    if s.time <= r.recovery_start { return; }               // sent before recovery began
    if r.cwnd < r.ssthresh { r.cwnd += s.size; }            // slow start
    else { r.cwnd += MAX_DATAGRAM * s.size / r.cwnd; }      // congestion avoidance
}

// A congestion event at time sent_time (the newest lost packet's).
fn on_congestion(r: Recovery&, sent_time: i64, now: i64) {
    if sent_time <= r.recovery_start { return; }
    r.recovery_start = now;
    r.ssthresh = ::max(r.cwnd / 2, K_MINIMUM_WINDOW);
    r.cwnd = r.ssthresh;
}

// Packets older than the largest acknowledged by the packet or time
// threshold are lost (§6.1); loss_time is when the next would be.
fn detect_lost<F>(r: Recovery&, space: i64, now: i64) {
    let la = r.largest_acked[space];
    r.loss_time[space] = 0;
    if la < 0 { return; }
    let rtt = ::max(r.latest_rtt, r.smoothed_rtt);
    let delay = ::max(rtt * 9 / 8, K_GRANULARITY);
    let lost_before = now - delay;
    var newest_lost_time: i64 = -1;
    var oldest_lost_time: i64 = 0x7fffffffffffffff;
    var lost_eliciting = 0;
    for k in MAX_SENT {
        if !r.sent[k].used || r.sent[k].space != space || r.sent[k].pn > la { continue; }
        let s = r.sent[k];
        if s.time <= lost_before || la >= s.pn + K_PACKET_THRESHOLD {
            if s.in_flight {
                newest_lost_time = ::max(newest_lost_time, s.time);
                oldest_lost_time = ::min(oldest_lost_time, s.time);
                if s.ack_eliciting { lost_eliciting++; }
            }
            remove_sent(r, k);
            F(s, false);
        } else {
            let t = s.time + delay;
            if r.loss_time[space] == 0 || t < r.loss_time[space] { r.loss_time[space] = t; }
        }
    }
    if newest_lost_time >= 0 {
        on_congestion(r, newest_lost_time, now);
        // Persistent congestion: lost ack-eliciting packets spanning more
        // than three PTOs, with an RTT sample (§7.6).
        let span = (pto_base(r) + r.max_ack_delay) * K_PERSISTENT_CONGESTION_THRESHOLD;
        if r.has_rtt && lost_eliciting >= 2 && newest_lost_time - oldest_lost_time > span {
            r.cwnd = K_MINIMUM_WINDOW;
            r.recovery_start = 0;
        }
    }
}

fn earliest_loss_time(r: const Recovery&) -> i64, i64 {
    var t: i64 = 0;
    var sp: i64 = -1;
    for s in 3 {
        if r.loss_time[s] != 0 && (t == 0 || r.loss_time[s] < t) { t = r.loss_time[s]; sp = s; }
    }
    return t, sp;
}

fn in_flight_eliciting(r: const Recovery&, space: i64) -> bool {
    for k in MAX_SENT { if r.sent[k].used && r.sent[k].space == space && r.sent[k].ack_eliciting && r.sent[k].in_flight { return true; } }
    return false;
}

// The PTO's time and space (§6.2.1): the earliest of the spaces with
// ack-eliciting packets in flight, the application space only once the
// handshake is confirmed; (0, -1) when none is armed. With no packet in
// flight, a client that has not seen its address validated still arms one
// (for the Handshake space once it has keys, else Initial).
fn pto_time(r: const Recovery&, confirmed: bool, has_hs_keys: bool, is_client: bool, discarded: const bool[:]) -> i64, i64 {
    let dur = pto_base(r) * (1 << ::min(r.pto_count, 20));
    var any = false;
    for s in 3 { if !discarded[s] && in_flight_eliciting(r, s) { any = true; } }
    if !any {
        if !is_client || r.peer_completed_address_validation { return 0, -1; }
        let sp = if has_hs_keys { SPACE_HANDSHAKE } else { SPACE_INITIAL };
        return r.last_ack_eliciting[sp] + dur, sp;
    }
    var t: i64 = 0;
    var sp: i64 = -1;
    for s in 3 {
        if discarded[s] || !in_flight_eliciting(r, s) { continue; }
        var d = dur;
        if s == SPACE_APP {
            if !confirmed { continue; }
            d += r.max_ack_delay * (1 << ::min(r.pto_count, 20));
        }
        let ts = r.last_ack_eliciting[s] + d;
        if t == 0 || ts < t { t = ts; sp = s; }
    }
    return t, sp;
}

// The loss detection timer: the earliest loss time, else the PTO; (0, -1,
// false) when none is armed. The bool says whether it is a PTO.
fn loss_timer(r: const Recovery&, confirmed: bool, has_hs_keys: bool, is_client: bool, discarded: const bool[:]) -> i64, i64, bool {
    let lt, ls = earliest_loss_time(r);
    if lt != 0 { return lt, ls, false; }
    let pt, ps = pto_time(r, confirmed, has_hs_keys, is_client, discarded);
    return pt, ps, true;
}

// The timer fired at now: either packets are declared lost (F, as in
// on_ack_received) and nothing more, or it was a PTO: pto_count goes up
// and the space to probe in is returned (-1 for none).
fn on_loss_timeout<F>(r: Recovery&, now: i64, confirmed: bool, has_hs_keys: bool, is_client: bool, discarded: const bool[:]) -> i64 {
    let lt, ls = earliest_loss_time(r);
    if lt != 0 {
        detect_lost(r, ls, now, F);
        return -1;
    }
    let pt, ps = pto_time(r, confirmed, has_hs_keys, is_client, discarded);
    if ps < 0 { return -1; }
    r.pto_count++;
    return ps;
}

// A space's keys are discarded (§6.4): its packets leave flight, not lost.
fn discard_space(r: Recovery&, space: i64) {
    for k in MAX_SENT { if r.sent[k].used && r.sent[k].space == space { remove_sent(r, k); } }
    r.last_ack_eliciting[space] = 0;
    r.loss_time[space] = 0;
    r.pto_count = 0;
}
