// QUIC's frames (RFC 9000 §19): every type written and read back, at
// boundary values; what read_frame refuses as FRAME_ENCODING_ERROR (frames
// cut at every byte, frame types not in their shortest form or unknown,
// ACK ranges below zero, stream data past 2^62, stream counts past 2^60,
// NEW_CONNECTION_ID's lengths and Retire Prior To, an empty NEW_TOKEN);
// which packet types carry which frames (§12.4) and which frames are
// ack-eliciting.

import std;
import gslib from "../..";
import gslib.quic;
import gslib.quic.packet;
import gslib.quic.frame;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let hi, ok1 = parse_int(s[i..i + 1], 16);
        let lo, ok2 = parse_int(s[i + 1..i + 2], 16);
        out.push((hi * 16 + lo) as! u8);
        i += 2;
    }
    return out;
}

// Reads the one frame in b: it must be all of b.
fn one(b: const u8[:], what: const u8[:]) -> quic::Frame {
    let f, next, e = quic::read_frame(b, 0);
    check(e == quic::NO_ERROR && next == b.len, what);
    return f;
}

fn refused(b: const u8[:], what: const u8[:]) {
    let f, next, e = quic::read_frame(b, 0);
    check(e == quic::FRAME_ENCODING_ERROR && next == 0, what);
}

// Every proper prefix of a frame is refused.
fn cut_everywhere(b: const u8[:], what: const u8[:]) {
    for n in b.len {
        let f, next, e = quic::read_frame(b[..n], 0);
        if e != quic::FRAME_ENCODING_ERROR { print("FAIL ", what, " cut at ", n); exit(1); }
    }
    checks++;
}

fn round_trips() {
    var b: u8[>..] = [];
    quic::put_padding(b, 3);
    quic::put_ping(b);
    let p, n1, e1 = quic::read_frame(b, 0);
    check(e1 == quic::NO_ERROR && p.ftype == quic::FT_PADDING && p.length == 3 && n1 == 3, "a run of PADDING read as one");
    let pg, n2, e2 = quic::read_frame(b, n1);
    check(e2 == quic::NO_ERROR && pg.ftype == quic::FT_PING && n2 == 4, "then PING");

    b.clear();
    quic::put_handshake_done(b);
    check(one(b, "HANDSHAKE_DONE").ftype == quic::FT_HANDSHAKE_DONE, "HANDSHAKE_DONE's type");

    // ACK: three ranges.
    let ranges: u64[6] = [100, 90, 80, 70, 10, 0];
    b.clear();
    quic::put_ack(b, ranges, 25, false, 0, 0, 0);
    let a = one(b, "ACK");
    check(a.ftype == quic::FT_ACK && a.largest == 100 && a.ack_delay == 25 && a.range_count == 2 && a.first_range == 10 &&
          a.smallest == 0 && !a.ecn, "ACK's fields");
    var got: u64[>..] = [];
    quic::ack_ranges(b, a, got);
    check(got[..] == ranges[..], "ACK's ranges back");
    b.clear();
    quic::put_ack(b, ranges, 0, true, 7, 8, 9);
    let ae = one(b, "ACK_ECN");
    check(ae.ftype == quic::FT_ACK_ECN && ae.ecn && ae.ect0 == 7 && ae.ect1 == 8 && ae.ce == 9, "ACK_ECN's counts");
    let single: u64[2] = [0x3fffffffffffffff, 0x3fffffffffffffff];
    b.clear();
    quic::put_ack(b, single, 0, false, 0, 0, 0);
    let as1 = one(b, "an ACK of the largest packet number");
    check(as1.largest == quic::MAX_VARINT && as1.smallest == quic::MAX_VARINT, "its one range");

    b.clear();
    quic::put_reset_stream(b, 4, 0x10c, 1000);
    let rs = one(b, "RESET_STREAM");
    check(rs.ftype == quic::FT_RESET_STREAM && rs.stream_id == 4 && rs.error_code == 0x10c && rs.final_size == 1000, "RESET_STREAM's fields");
    b.clear();
    quic::put_stop_sending(b, 8, 3);
    let ss = one(b, "STOP_SENDING");
    check(ss.stream_id == 8 && ss.error_code == 3, "STOP_SENDING's fields");

    b.clear();
    quic::put_crypto(b, 1200, "client hello");
    let cr = one(b, "CRYPTO");
    check(cr.ftype == quic::FT_CRYPTO && cr.offset == 1200 && b[cr.data_at..cr.data_at + cr.length] == "client hello", "CRYPTO's data");

    b.clear();
    quic::put_new_token(b, "a token");
    let nt = one(b, "NEW_TOKEN");
    check(b[nt.data_at..nt.data_at + nt.length] == "a token", "NEW_TOKEN's token");

    // STREAM in its eight forms.
    for t in 8 {
        let off: u64 = if t & 4 != 0 { 77 } else { 0 };
        let with_len = t & 2 != 0;
        let fin = t & 1 != 0;
        b.clear();
        quic::put_stream(b, 5, off, "stream data", fin, with_len);
        check(b.len == quic::stream_header_len(5, off, 11, with_len) + 11, "STREAM's header length");
        let s = one(b, "STREAM");
        check(quic::is_stream_type(s.ftype) && s.stream_id == 5 && s.offset == off && s.fin == fin &&
              b[s.data_at..s.data_at + s.length] == "stream data", "STREAM's fields");
    }
    // Without a Length, the data runs to the end; with one, a frame follows.
    b.clear();
    quic::put_stream(b, 0, 0, "abc", false, true);
    quic::put_ping(b);
    let s1, sn, se = quic::read_frame(b, 0);
    check(se == quic::NO_ERROR && s1.length == 3 && sn == b.len - 1, "STREAM with a Length, then PING");
    b.clear();
    quic::put_stream(b, 0, quic::MAX_VARINT - 3, "abc", true, true);
    check(one(b, "STREAM ending at 2^62 - 1").offset == quic::MAX_VARINT - 3, "its offset");

    b.clear();
    quic::put_max_data(b, 1 << 40);
    check(one(b, "MAX_DATA").max == 1 << 40, "MAX_DATA's value");
    b.clear();
    quic::put_max_stream_data(b, 9, 65536);
    let msd = one(b, "MAX_STREAM_DATA");
    check(msd.stream_id == 9 && msd.max == 65536, "MAX_STREAM_DATA's fields");
    b.clear();
    quic::put_max_streams(b, true, quic::MAX_STREAMS_LIMIT);
    let ms = one(b, "MAX_STREAMS at 2^60");
    check(ms.ftype == quic::FT_MAX_STREAMS_BIDI && ms.max == quic::MAX_STREAMS_LIMIT, "MAX_STREAMS (bidirectional)");
    b.clear();
    quic::put_max_streams(b, false, 3);
    check(one(b, "MAX_STREAMS (unidirectional)").ftype == quic::FT_MAX_STREAMS_UNI, "its type");
    b.clear();
    quic::put_data_blocked(b, 4096);
    check(one(b, "DATA_BLOCKED").max == 4096, "DATA_BLOCKED's limit");
    b.clear();
    quic::put_stream_data_blocked(b, 2, 100);
    let sdb = one(b, "STREAM_DATA_BLOCKED");
    check(sdb.stream_id == 2 && sdb.max == 100, "STREAM_DATA_BLOCKED's fields");
    b.clear();
    quic::put_streams_blocked(b, false, 10);
    let sb = one(b, "STREAMS_BLOCKED");
    check(sb.ftype == quic::FT_STREAMS_BLOCKED_UNI && sb.max == 10, "STREAMS_BLOCKED's fields");

    let token: u8[16] = [0xaa; 16];
    let lens: i64[3] = [1, 8, 20];
    for len in lens {
        var cid: u8[>..] = [];
        cid.resize(len, 0x5c);
        b.clear();
        quic::put_new_connection_id(b, 3, 3, cid, token);
        let nc = one(b, "NEW_CONNECTION_ID");
        check(nc.seq == 3 && nc.retire_prior_to == 3 && nc.cid_len == len && b[nc.cid_at..nc.cid_at + nc.cid_len] == cid[..] &&
              b[nc.token_at..nc.token_at + 16] == token[..], "NEW_CONNECTION_ID's fields");
    }
    b.clear();
    quic::put_retire_connection_id(b, 12);
    check(one(b, "RETIRE_CONNECTION_ID").seq == 12, "RETIRE_CONNECTION_ID's sequence number");

    let challenge: const u8[:] = "8 bytes!";
    b.clear();
    quic::put_path_challenge(b, challenge);
    let pc = one(b, "PATH_CHALLENGE");
    check(pc.ftype == quic::FT_PATH_CHALLENGE && b[pc.data_at..pc.data_at + 8] == challenge, "PATH_CHALLENGE's data");
    b.clear();
    quic::put_path_response(b, challenge);
    check(one(b, "PATH_RESPONSE").ftype == quic::FT_PATH_RESPONSE, "PATH_RESPONSE's type");

    b.clear();
    quic::put_connection_close(b, quic::PROTOCOL_VIOLATION, quic::FT_STREAM, "bad frame");
    let cc = one(b, "CONNECTION_CLOSE");
    check(cc.ftype == quic::FT_CONNECTION_CLOSE && cc.error_code == quic::PROTOCOL_VIOLATION && cc.frame_type == quic::FT_STREAM &&
          b[cc.data_at..cc.data_at + cc.length] == "bad frame", "CONNECTION_CLOSE's fields");
    b.clear();
    quic::put_application_close(b, 0x100, "");
    let ac = one(b, "CONNECTION_CLOSE (application)");
    check(ac.ftype == quic::FT_APPLICATION_CLOSE && ac.error_code == 0x100 && ac.length == 0, "its fields");
}

fn refusals() {
    refused(unhex("4001"), "PING's type in two bytes");
    refused(unhex("80000001"), "a type in four bytes");
    refused(unhex("1f"), "an unknown type");
    refused(unhex("21"), "another");
    refused(unhex("0205000106"), "an ACK's first range past its largest");
    // Largest 5, first range 1 (down to 4), then a gap of 3: below zero.
    refused(unhex("02050001010300"), "an ACK range below zero");
    // Gap 1 from 4 reaches 1; a range of 2 more goes below zero.
    refused(unhex("02050001010102"), "an ACK range length below zero");
    let ok = one(unhex("02050001010101"), "an ACK down to zero");
    check(ok.smallest == 0, "smallest 0");
    refused(unhex("0205000500"), "an ACK with more ranges than it carries");
    // STREAM at offset 2^62 - 1 with a byte.
    refused(unhex("0e00ffffffffffffffff0141"), "STREAM data past 2^62 - 1");
    refused(unhex("06ffffffffffffffff0141"), "CRYPTO data past 2^62 - 1");
    var b: u8[>..] = [];
    quic::put_varint(b, quic::FT_MAX_STREAMS_UNI);
    quic::put_varint(b, quic::MAX_STREAMS_LIMIT + 1);
    refused(b, "MAX_STREAMS past 2^60");
    b.clear();
    quic::put_varint(b, quic::FT_STREAMS_BLOCKED_BIDI);
    quic::put_varint(b, quic::MAX_STREAMS_LIMIT + 1);
    refused(b, "STREAMS_BLOCKED past 2^60");
    refused(unhex("18010000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "NEW_CONNECTION_ID with an empty connection ID");
    b.clear();
    b.append(unhex("18010015"));
    for i in 21 + 16 { b.push(1); }
    refused(b, "NEW_CONNECTION_ID with 21 bytes");
    refused(unhex("18010201aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "Retire Prior To past the sequence number");
    refused(unhex("0700"), "an empty NEW_TOKEN");
    refused(unhex("1a01020304050607"), "PATH_CHALLENGE short of 8 bytes");
    refused(unhex("1c0a000541"), "a reason phrase longer than the frame");
    // Every frame cut short, at every byte.
    let ranges: u64[4] = [1000, 900, 100, 50];
    var a: u8[>..] = [];
    quic::put_ack(a, ranges, 300, true, 1, 2, 3);
    cut_everywhere(a, "ACK_ECN");
    b.clear();
    quic::put_crypto(b, 70000, "data");
    cut_everywhere(b, "CRYPTO");
    b.clear();
    quic::put_stream(b, 1000000, 5, "abc", true, true);
    cut_everywhere(b, "STREAM with a Length");
    b.clear();
    let token: u8[16] = [7; 16];
    quic::put_new_connection_id(b, 70000, 2, "abcdefgh", token);
    cut_everywhere(b, "NEW_CONNECTION_ID");
    b.clear();
    quic::put_reset_stream(b, 1 << 30, 1 << 20, 1 << 40);
    cut_everywhere(b, "RESET_STREAM");
    b.clear();
    quic::put_connection_close(b, 0x10a, 0x1234, "why");
    cut_everywhere(b, "CONNECTION_CLOSE");
    b.clear();
    quic::put_new_token(b, "tok");
    cut_everywhere(b, "NEW_TOKEN");
    b.clear();
    quic::put_path_response(b, "abcdefgh");
    cut_everywhere(b, "PATH_RESPONSE");
    b.clear();
    quic::put_max_stream_data(b, 1 << 50, 1 << 61);
    cut_everywhere(b, "MAX_STREAM_DATA");
}

fn placement() {
    let all: u8[4] = [quic::PT_INITIAL, quic::PT_ZERO_RTT, quic::PT_HANDSHAKE, quic::PT_ONE_RTT];
    // §12.4 Table 3: for each type, I 0 H 1.
    let want: const u8[:] = "1111111110111011010101011011000101010101010101010101010101010101010101010101010101010101010101010101000101010001111101010001";
    for t in 0x1f {
        for k in 4 {
            let allowed = quic::frame_allowed(t as! u64, all[k]);
            if allowed != (want[t * 4 + k] == '1') { print("FAIL frame type ", t, " in packet type ", all[k]); exit(1); }
        }
    }
    checks++;
    check(!quic::ack_eliciting(quic::FT_ACK) && !quic::ack_eliciting(quic::FT_ACK_ECN) && !quic::ack_eliciting(quic::FT_PADDING) &&
          !quic::ack_eliciting(quic::FT_CONNECTION_CLOSE) && !quic::ack_eliciting(quic::FT_APPLICATION_CLOSE), "not ack-eliciting");
    check(quic::ack_eliciting(quic::FT_PING) && quic::ack_eliciting(quic::FT_CRYPTO) && quic::ack_eliciting(0x0f) &&
          quic::ack_eliciting(quic::FT_HANDSHAKE_DONE), "ack-eliciting");
}

fn main() {
    round_trips();
    refusals();
    placement();
    print("frame: ", checks, " checks");
}
