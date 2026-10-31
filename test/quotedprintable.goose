// mime.quotedprintable against Go's own tests: TestReader's and
// testWriter's tables and TestRoundTrip's message (test/vectors, from
// $GOROOT/src/mime/quotedprintable by scripts/gen_vectors.py), each row
// checked against what Go returns; TestExhaustive ported (every input of
// up to six bytes over "0A \r\n=", the counts of outcomes as Go's test
// has them); and every input fed in every two-piece split.

import std;
import os;
import mime from "..";
import mime.quotedprintable;
import tv;

// Decodes src fed in two pieces at `split`; the output and the message.
fn decode_split(src: const u8[:], split: i64, out: u8[>..]&, msg: u8[>..]&) {
    var r = quotedprintable::new_reader();
    var rc = quotedprintable::decode(r, out, src[..split]);
    if rc == 0 { rc = quotedprintable::decode(r, out, src[split..]); }
    if rc == 0 { rc = quotedprintable::finish(r, out); }
    quotedprintable::error_message(r, msg);
}

fn reader() {
    tv::each_row("vectors/go_qp_reader.txt") { r: tv::Row& =>
        let input = r.next();
        r.to_results();
        let go = r.next();
        let go_err = r.next();
        var out: u8[>..] = [];
        var msg: u8[>..] = [];
        let rc = quotedprintable::decode_all(out, input, msg);
        tv::check_eq(str("qp decode ", input), out, go);
        tv::check_eq(str("qp decode error ", input), msg, go_err);
        tv::check(str("qp decode code ", input), (rc != 0) == (go_err.len > 0));
        for split in input.len + 1 {
            var o2: u8[>..] = [];
            var m2: u8[>..] = [];
            decode_split(input, split, o2, m2);
            tv::check_eq(str("qp decode split ", split, " ", input), o2, go);
            tv::check_eq(str("qp decode split error ", split, " ", input), m2, go_err);
        }
    };
}

fn writer() {
    tv::each_row("vectors/go_qp_writer.txt") { r: tv::Row& =>
        let input = r.next();
        r.to_results();
        let go = r.next();
        let go_binary = r.next();
        var out: u8[>..] = [];
        quotedprintable::encode_all(out, input);
        tv::check_eq(str("qp encode ", input), out, go);
        var outb: u8[>..] = [];
        quotedprintable::encode_all(outb, input, true);
        tv::check_eq(str("qp encode binary ", input), outb, go_binary);
        // and written a byte at a time
        var w = quotedprintable::new_writer();
        var o3: u8[>..] = [];
        for i in input.len { quotedprintable::write(w, o3, input[i..i + 1]); }
        quotedprintable::close(w, o3);
        tv::check_eq(str("qp encode bytewise ", input), o3, go);
    };
    tv::each_row("vectors/go_qp_testmsg.txt") { r: tv::Row& =>
        r.next_int();
        let msg = r.next();
        r.to_results();
        let go = r.next();
        var enc: u8[>..] = [];
        quotedprintable::encode_all(enc, msg);
        tv::check_eq("TestRoundTrip encoded", enc, go);
        var back: u8[>..] = [];
        tv::check_int("TestRoundTrip decodes", quotedprintable::decode_all(back, enc), 0);
        tv::check_eq("TestRoundTrip", back, msg);
    };
}

// TestExhaustive: Go's outcome counts, which its source states.
fn exhaustive() {
    let alpha = "0A \r\n=";
    var ok = 0;
    var after_equals = 0;
    var hex_0d = 0;
    var unexpected_eof = 0;
    var other = 0;
    var s: u8[..6] = [];
    var idx: i64[6] = [0, 0, 0, 0, 0, 0];
    var total = 1;
    for k in 6 { total *= alpha.len; }
    for n in total {
        var v = n;
        s.clear();
        for k in 6 { idx[5 - k] = v % alpha.len; v = v / alpha.len; }
        for k in 6 { s.push(alpha[idx[k]]); }
        if s[5] == '=' || find(s, "==") >= 0 { continue; }
        var out: u8[>..] = [];
        var msg: u8[>..] = [];
        let rc = quotedprintable::decode_all(out, s, msg);
        if rc == 0 { ok++; continue; }
        if starts_with(msg, "quotedprintable: invalid bytes after =:") { after_equals++; }
        else if msg == "quotedprintable: invalid hex byte 0x0d" { hex_0d++; }
        else if msg == "unexpected EOF" { unexpected_eof++; }
        else { other++; print("      other outcome for ", s, ": ", msg); }
    }
    tv::check_int("exhaustive OK", ok, 30638);
    tv::check_int("exhaustive invalid bytes after =", after_equals, 2243);
    tv::check_int("exhaustive invalid hex byte 0x0d", hex_0d, 2050);
    tv::check_int("exhaustive unexpected EOF", unexpected_eof, 194);
    tv::check_int("exhaustive other", other, 0);
}

// Lines longer than Go's 4096-byte buffer (what Go does, checked with it).
fn long_line(n: i64, tail: const u8[:], want_rc: i64, want_len: i64) {
    var line: u8[>..] = [];
    for i in n { line.push('a'); }
    line.append(tail);
    var out: u8[>..] = [];
    var msg: u8[>..] = [];
    tv::check_int(str(n, "-byte line"), quotedprintable::decode_all(out, line, msg), want_rc);
    tv::check_int(str(n, "-byte line output"), out.len, want_len);
    if want_rc != 0 { tv::check_eq(str(n, "-byte line message"), msg, "bufio: buffer full"); }
}

fn long_lines() {
    long_line(4094, "\r\nb", 0, 4097);                       // the CRLF ends within 4096 bytes
    long_line(4095, "\r\nb", mime::ERR_BUFFER_FULL, 4095);
    long_line(4096, "", mime::ERR_BUFFER_FULL, 4096);
    long_line(5000, "", mime::ERR_BUFFER_FULL, 4096);
}

fn main() {
    reader();
    writer();
    exhaustive();
    long_lines();
    tv::done("quotedprintable");
}
