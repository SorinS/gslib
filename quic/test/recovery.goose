// RFC 9002 without a connection: the first RTT sample and the §5.3
// smoothing with the peer's ack delay, loss by the packet threshold and
// the time threshold, the PTO doubling as it backs off, a space's keys
// discarded taking its packets out of flight, slow start, recovery, and
// persistent congestion.

import std;
import gslib from "../..";
import gslib.quic;
import gslib.quic.recovery;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

// Acks ranges (smallest, largest pairs) in the application space; the
// packets acked and lost, by number.
fn ack(r: quic::Recovery&, ranges: const i64[:], delay: i64, now: i64, next_pn: i64) -> i64[>..], i64[>..], bool {
    var acked: i64[>..] = [];
    var lost: i64[>..] = [];
    let ok = quic::on_ack_received(r, quic::SPACE_APP, ranges, delay, now, true, next_pn) { s, a =>
        if a { acked.push(s.pn); } else { lost.push(s.pn); }
    };
    return acked, lost, ok;
}

fn rtt() {
    var r = quic::recovery();
    quic::on_packet_sent(r, quic::SPACE_APP, 0, 0, 1200, true, true, 0, 0);
    let one: i64[2] = [0, 0];
    let a, l, ok = ack(r, one, 0, 100000, 1);
    check(ok && a.len == 1 && r.smoothed_rtt == 100000 && r.rttvar == 50000 && r.min_rtt == 100000, "the first sample");
    // A later one of 130 ms with 10 ms of ack delay: adjusted to 120 ms.
    quic::on_packet_sent(r, quic::SPACE_APP, 1, 200000, 1200, true, true, 0, 0);
    let two: i64[2] = [1, 1];
    let a2, l2, ok2 = ack(r, two, 10000, 330000, 2);
    check(r.latest_rtt == 130000 && r.smoothed_rtt == (7 * 100000 + 120000) / 8 && r.rttvar == (3 * 50000 + 20000) / 4,
          "smoothed with the ack delay taken off (§5.3)");
    let bad: i64[2] = [5, 5];
    let a3, l3, ok3 = ack(r, bad, 0, 400000, 2);
    check(!ok3, "an ACK of a packet never sent");
}

fn loss_thresholds() {
    var r = quic::recovery();
    for pn in 5 { quic::on_packet_sent(r, quic::SPACE_APP, pn, pn * 1000, 1200, true, true, 0, 0); }
    // pn 4 acked: 0 and 1 are 3 or more behind it (§6.1.1).
    let four: i64[2] = [4, 4];
    let a, l, ok = ack(r, four, 0, 50000, 5);
    check(a.len == 1 && l.len == 2 && l[0] + l[1] == 1, "the packet threshold: 0 and 1 lost");
    check(r.loss_time[quic::SPACE_APP] != 0, "2 and 3 wait on the time threshold");
    // Time passes past 9/8 of the RTT: they are lost on the timer.
    let lt, ls, is_pto = quic::loss_timer(r, true, true, false, [false, false, false]);
    var lost: i64[>..] = [];
    let sp = quic::on_loss_timeout(r, lt, true, true, false, [false, false, false]) { s, a2 => if !a2 { lost.push(s.pn); } };
    check(!is_pto && sp == -1 && lost.len == 1 && lost[0] == 2, "the time threshold: 2 lost first");
    let lt2, ls2, is_pto2 = quic::loss_timer(r, true, true, false, [false, false, false]);
    let sp2 = quic::on_loss_timeout(r, lt2, true, true, false, [false, false, false]) { s, a2 => if !a2 { lost.push(s.pn); } };
    check(!is_pto2 && lt2 == lt + 1000 && lost.len == 2 && lost[1] == 3, "then 3, a millisecond later");
    check(r.bytes_in_flight == 0, "nothing left in flight");
}

fn pto() {
    var r = quic::recovery();
    quic::on_packet_sent(r, quic::SPACE_APP, 0, 0, 1200, true, true, 0, 0);
    let t1, s1, p1 = quic::loss_timer(r, true, true, false, [false, false, false]);
    let base = r.smoothed_rtt + 4 * r.rttvar + r.max_ack_delay;
    check(p1 && s1 == quic::SPACE_APP && t1 == base, "the PTO: smoothed RTT, 4 RTT variances, max_ack_delay");
    let sp = quic::on_loss_timeout(r, t1, true, true, false, [false, false, false]) { s, a => };
    let t2, s2, p2 = quic::loss_timer(r, true, true, false, [false, false, false]);
    check(sp == quic::SPACE_APP && r.pto_count == 1 && t2 == 2 * base, "doubled after it fires");
    let t3, s3, p3 = quic::loss_timer(r, false, true, false, [false, false, false]);
    check(t3 == 0, "no PTO in the application space before the handshake is confirmed");
    // A client with nothing in flight and its address not yet validated
    // still arms one (§6.2.2.1).
    var c = quic::recovery();
    let t4, s4, p4 = quic::loss_timer(c, false, false, true, [false, false, false]);
    check(p4 && s4 == quic::SPACE_INITIAL && t4 > 0, "the anti-deadlock PTO of a client");
}

fn discard() {
    var r = quic::recovery();
    quic::on_packet_sent(r, quic::SPACE_INITIAL, 0, 0, 1200, true, true, 0, 0);
    quic::on_packet_sent(r, quic::SPACE_HANDSHAKE, 0, 0, 1200, true, true, 0, 0);
    quic::discard_space(r, quic::SPACE_INITIAL);
    check(r.bytes_in_flight == 1200 && r.n_sent == 1, "a discarded space's packets leave flight, not lost");
}

fn congestion() {
    var r = quic::recovery();
    let w0 = r.cwnd;
    for pn in 4 { quic::on_packet_sent(r, quic::SPACE_APP, pn, 1000, 1200, true, true, 0, 0); }
    let all: i64[2] = [0, 3];
    let a, l, ok = ack(r, all, 0, 51000, 4);
    check(r.cwnd == w0 + 4 * 1200, "slow start: the window grows by what is acknowledged");
    for pn in 4..8 { quic::on_packet_sent(r, quic::SPACE_APP, pn, 60000, 1200, true, true, 0, 0); }
    let last: i64[2] = [7, 7];
    let a2, l2, ok2 = ack(r, last, 0, 120000, 8);
    let w1 = r.cwnd;
    check(l2.len == 1 && l2[0] == 4 && w1 == (w0 + 4 * 1200 + 1200) / 2 && r.ssthresh == w1, "a loss halves the window");
    // Lost packets spanning more than three PTOs: persistent congestion.
    var p = quic::recovery();
    quic::on_packet_sent(p, quic::SPACE_APP, 0, 0, 1200, true, true, 0, 0);
    let z: i64[2] = [0, 0];
    let a3, l3, ok3 = ack(p, z, 0, 10000, 1);
    quic::on_packet_sent(p, quic::SPACE_APP, 1, 20000, 1200, true, true, 0, 0);
    quic::on_packet_sent(p, quic::SPACE_APP, 2, 5000000, 1200, true, true, 0, 0);
    for pn in 3..7 { quic::on_packet_sent(p, quic::SPACE_APP, pn, 5000001, 1200, true, true, 0, 0); }
    let six: i64[2] = [6, 6];
    let a4, l4, ok4 = ack(p, six, 0, 5010000, 7);
    check(l4.len == 3 && p.cwnd == quic::K_MINIMUM_WINDOW, "persistent congestion: the minimum window");
}

fn main() {
    rtt();
    loss_thresholds();
    pto();
    discard();
    congestion();
    print("recovery: ", checks, " checks");
}
