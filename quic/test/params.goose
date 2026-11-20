// QUIC's transport parameters (RFC 9000 §18): the defaults, a client's
// and a server's written and read back, GREASE and unknown ids skipped,
// and what read_params refuses as TRANSPORT_PARAMETER_ERROR: a parameter
// twice, values out of range, lengths that do not fit, and from a client
// the parameters only a server sends.

import std;
import gslib from "../..";
import gslib.quic;
import gslib.quic.packet;
import gslib.quic.frame;
import gslib.quic.params;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

fn param(out: u8[>..]&, id: u64, v: const u8[:]) {
    quic::put_varint(out, id);
    quic::put_varint(out, v.len as! u64);
    out.append(v);
}

fn int_param(out: u8[>..]&, id: u64, v: u64) {
    var b: u8[>..] = [];
    quic::put_varint(b, v);
    param(out, id, b);
}

fn refused(b: const u8[:], from_server: bool, what: const u8[:]) {
    let p, e = quic::read_params(b, from_server);
    check(e == quic::TRANSPORT_PARAMETER_ERROR, what);
}

fn defaults() {
    let none: u8[0] = [];
    let p, e = quic::read_params(none, true);
    check(e == quic::NO_ERROR && p.max_udp_payload_size == 65527 && p.ack_delay_exponent == 3 && p.max_ack_delay == 25 &&
          p.active_connection_id_limit == 2 && p.max_idle_timeout == 0 && p.initial_max_data == 0 &&
          !p.has_original_dcid && !p.has_initial_scid && !p.has_retry_scid && !p.has_reset_token &&
          !p.disable_active_migration && !p.has_preferred_address, "nothing sent: the defaults");
    var out: u8[>..] = [];
    let d = quic::default_params();
    quic::put_params(out, d, true);
    check(out.len == 0, "the defaults are not written");
}

fn round_trips() {
    var c = quic::default_params();
    c.max_idle_timeout = 30000;
    c.max_udp_payload_size = 1452;
    c.initial_max_data = 1 << 20;
    c.initial_max_stream_data_bidi_local = 1 << 18;
    c.initial_max_stream_data_bidi_remote = 1 << 17;
    c.initial_max_stream_data_uni = 1 << 16;
    c.initial_max_streams_bidi = 100;
    c.initial_max_streams_uni = quic::MAX_STREAMS_LIMIT;
    c.ack_delay_exponent = 20;
    c.max_ack_delay = 16383;
    c.disable_active_migration = true;
    c.active_connection_id_limit = 8;
    c.has_initial_scid = true;
    c.initial_scid.append("client-cid");
    // What only a server sends is left out of a client's.
    c.has_original_dcid = true;
    c.original_dcid.append("ignored");
    var out: u8[>..] = [];
    quic::put_params(out, c, false);
    let p, e = quic::read_params(out, false);
    check(e == quic::NO_ERROR && p.max_idle_timeout == 30000 && p.max_udp_payload_size == 1452 && p.initial_max_data == 1 << 20 &&
          p.initial_max_stream_data_bidi_local == 1 << 18 && p.initial_max_stream_data_bidi_remote == 1 << 17 &&
          p.initial_max_stream_data_uni == 1 << 16 && p.initial_max_streams_bidi == 100 &&
          p.initial_max_streams_uni == quic::MAX_STREAMS_LIMIT && p.ack_delay_exponent == 20 && p.max_ack_delay == 16383 &&
          p.disable_active_migration && p.active_connection_id_limit == 8 && p.has_initial_scid &&
          p.initial_scid[..] == "client-cid" && !p.has_original_dcid, "a client's, read back");

    var s = quic::default_params();
    s.has_original_dcid = true;
    s.original_dcid.append("\x83\x94\xc8\xf0\x3e\x51\x57\x08");
    s.has_initial_scid = true;                          // empty: a zero-length connection ID
    s.has_retry_scid = true;
    s.retry_scid.append("retry-cid-twenty-byt");
    s.has_reset_token = true;
    for i in 16 { s.reset_token[i] = i as! u8; }
    s.has_preferred_address = true;
    s.pa_ipv4 = [192, 0, 2, 1];
    s.pa_ipv4_port = 4433;
    s.pa_ipv6[15] = 1;
    s.pa_ipv6_port = 4434;
    s.pa_cid.append("pref");
    s.pa_reset_token = [9; 16];
    s.initial_max_data = 5000;
    out.clear();
    quic::put_params(out, s, true);
    let q, e2 = quic::read_params(out, true);
    check(e2 == quic::NO_ERROR && q.has_original_dcid && q.original_dcid[..] == s.original_dcid[..] && q.has_initial_scid &&
          q.initial_scid.len == 0 && q.has_retry_scid && q.retry_scid[..] == "retry-cid-twenty-byt" && q.has_reset_token &&
          q.reset_token[..] == s.reset_token[..] && q.initial_max_data == 5000, "a server's, read back");
    check(q.has_preferred_address && q.pa_ipv4[..] == s.pa_ipv4[..] && q.pa_ipv4_port == 4433 && q.pa_ipv6[..] == s.pa_ipv6[..] &&
          q.pa_ipv6_port == 4434 && q.pa_cid[..] == "pref" && q.pa_reset_token[..] == s.pa_reset_token[..], "its preferred address");
    // GREASE (31 * N + 27) and unknown ids are skipped, wherever they are.
    var g: u8[>..] = [];
    param(g, 27, "grease");
    param(g, 31 * 1000 + 27, "");
    g.append(out);
    param(g, 0x2ab2, "\x00\x01");
    let r, e3 = quic::read_params(g, true);
    check(e3 == quic::NO_ERROR && r.initial_max_data == 5000 && r.has_preferred_address, "GREASE and unknown ids skipped");
    // A varint in more bytes than it needs is still one value.
    var long: u8[>..] = [];
    quic::put_varint(long, quic::TP_MAX_IDLE_TIMEOUT);
    quic::put_varint(long, 4);
    quic::put_varint_n(long, 10, 4);
    let lp, e4 = quic::read_params(long, false);
    check(e4 == quic::NO_ERROR && lp.max_idle_timeout == 10, "a value in a longer varint");
}

fn refusals() {
    var b: u8[>..] = [];
    int_param(b, quic::TP_INITIAL_MAX_DATA, 1);
    int_param(b, quic::TP_INITIAL_MAX_DATA, 2);
    refused(b, false, "a parameter twice");
    b.clear();
    param(b, quic::TP_INITIAL_SOURCE_CONNECTION_ID, "a");
    param(b, quic::TP_INITIAL_SOURCE_CONNECTION_ID, "a");
    refused(b, true, "a connection ID twice");
    b.clear();
    int_param(b, quic::TP_MAX_UDP_PAYLOAD_SIZE, 1199);
    refused(b, false, "max_udp_payload_size below 1200");
    b.clear();
    int_param(b, quic::TP_MAX_UDP_PAYLOAD_SIZE, 1200);
    let p1, e1 = quic::read_params(b, false);
    check(e1 == quic::NO_ERROR && p1.max_udp_payload_size == 1200, "1200 is fine");
    b.clear();
    int_param(b, quic::TP_ACK_DELAY_EXPONENT, 21);
    refused(b, false, "ack_delay_exponent past 20");
    b.clear();
    int_param(b, quic::TP_MAX_ACK_DELAY, 16384);
    refused(b, false, "max_ack_delay of 2^14");
    b.clear();
    int_param(b, quic::TP_ACTIVE_CONNECTION_ID_LIMIT, 1);
    refused(b, false, "active_connection_id_limit below 2");
    b.clear();
    int_param(b, quic::TP_INITIAL_MAX_STREAMS_BIDI, quic::MAX_STREAMS_LIMIT + 1);
    refused(b, false, "initial_max_streams_bidi past 2^60");
    b.clear();
    int_param(b, quic::TP_INITIAL_MAX_STREAMS_UNI, quic::MAX_STREAMS_LIMIT + 1);
    refused(b, true, "initial_max_streams_uni past 2^60");
    // The server's own, from a client.
    b.clear();
    param(b, quic::TP_ORIGINAL_DESTINATION_CONNECTION_ID, "x");
    refused(b, false, "original_destination_connection_id from a client");
    b.clear();
    param(b, quic::TP_RETRY_SOURCE_CONNECTION_ID, "x");
    refused(b, false, "retry_source_connection_id from a client");
    b.clear();
    let tok: u8[16] = [1; 16];
    param(b, quic::TP_STATELESS_RESET_TOKEN, tok);
    refused(b, false, "stateless_reset_token from a client");
    let ps, eps = quic::read_params(b, true);
    check(eps == quic::NO_ERROR && ps.has_reset_token, "from a server");
    // Lengths.
    b.clear();
    param(b, quic::TP_STATELESS_RESET_TOKEN, tok[..15]);
    refused(b, true, "a reset token of 15 bytes");
    b.clear();
    param(b, quic::TP_DISABLE_ACTIVE_MIGRATION, "\x00");
    refused(b, false, "disable_active_migration with a value");
    b.clear();
    param(b, quic::TP_INITIAL_SOURCE_CONNECTION_ID, "twenty-one bytes long");
    refused(b, false, "a connection ID of 21 bytes");
    b.clear();
    param(b, quic::TP_MAX_IDLE_TIMEOUT, "\x05\x00");
    refused(b, false, "an integer that does not fill its length");
    b.clear();
    param(b, quic::TP_MAX_IDLE_TIMEOUT, "\x40");
    refused(b, false, "an integer cut short");
    b.clear();
    param(b, quic::TP_MAX_IDLE_TIMEOUT, "");
    refused(b, false, "an empty integer");
    // A preferred address with no connection ID, or the wrong length.
    var pa: u8[>..] = [];
    for i in 24 { pa.push(0); }
    pa.push(0);
    for i in 16 { pa.push(0); }
    b.clear();
    param(b, quic::TP_PREFERRED_ADDRESS, pa);
    refused(b, true, "a preferred address without a connection ID");
    pa[24] = 4;
    b.clear();
    param(b, quic::TP_PREFERRED_ADDRESS, pa);
    refused(b, true, "a preferred address shorter than its connection ID says");
    // Cut short.
    b.clear();
    int_param(b, quic::TP_INITIAL_MAX_DATA, 1 << 30);
    for n in 1..b.len {
        let pc, ec = quic::read_params(b[..n], false);
        if ec != quic::TRANSPORT_PARAMETER_ERROR { print("FAIL cut at ", n); exit(1); }
    }
    checks++;
    b.clear();
    quic::put_varint(b, 27);
    quic::put_varint(b, 100);
    refused(b, false, "an unknown parameter longer than what is left");
}

fn main() {
    defaults();
    round_trips();
    refusals();
    print("params: ", checks, " checks");
}
