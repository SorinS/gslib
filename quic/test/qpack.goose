// QPACK without a dynamic table: RFC 9204 Appendix B's sections, those that
// use the static table read and those that use the dynamic table refused;
// every static entry through the encoder and back; RFC 7541's Huffman
// examples and every byte; integers and strings cut short or too long;
// the encoder and decoder streams' instructions; the limit on a section;
// RFC 9114's rules for requests, responses and trailers.

import std;
import gslib from "../..";
import gslib.quic.qpack;

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
    var hi = -1;
    for c in s {
        var v = -1;
        if c >= '0' && c <= '9' { v = c - '0'; }
        else if c >= 'a' && c <= 'f' { v = c - 'a' + 10; }
        if v < 0 { continue; }
        if hi < 0 { hi = v; } else { out.push((hi * 16 + v) as! u8); hi = -1; }
    }
    return out;
}

fn decode(hex: const u8[:]) -> i64 {
    var recs: u8[>..] = [];
    let b = unhex(hex);
    return quic::qpack_decode(b, 65536, recs);
}

fn records(pairs: const u8[:][:]) -> u8[>..] {
    var r: u8[>..] = [];
    var i = 0;
    while i + 1 < pairs.len { quic::qpack_record(r, pairs[i], pairs[i + 1]); i += 2; }
    return r;
}

fn appendix_b() {
    // B.1: a literal with a static name reference.
    let b1 = unhex("0000 510b 2f69 6e64 6578 2e68 746d 6c");
    var recs: u8[>..] = [];
    check(quic::qpack_decode(b1, 65536, recs) == quic::QPACK_OK, "B.1 decodes");
    let path, ok = quic::qpack_get(recs, ":path");
    check(ok && path == "/index.html", "B.1 :path=/index.html");
    var enc: u8[>..] = [];
    quic::qpack_begin(enc);
    quic::qpack_field(enc, ":path", "/index.html", false, false);
    check(enc == b1, "B.1 encoded the same, without Huffman");
    // B.2 to B.5's sections refer to the dynamic table, which this side
    // never has: refused.
    check(decode("0381 10 11") == quic::QPACK_DECOMPRESSION_FAILED, "B.2: Required Insert Count 2");
    check(decode("0500 80 c1 81") == quic::QPACK_DECOMPRESSION_FAILED, "B.4: dynamic references");
    check(decode("0000 10") == quic::QPACK_DECOMPRESSION_FAILED, "a post-base index");
    check(decode("0000 00 01 61") == quic::QPACK_DECOMPRESSION_FAILED, "a post-base name reference");
    check(decode("0000 80") == quic::QPACK_DECOMPRESSION_FAILED, "a dynamic index");
    check(decode("0000 4f 00") == quic::QPACK_DECOMPRESSION_FAILED, "a dynamic name reference");
    // The encoder stream: B.2's capacity 220 and inserts refused, capacity 0 taken.
    let es = unhex("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d");
    check(quic::qpack_encoder_stream(es) == -quic::QPACK_ENCODER_STREAM_ERROR, "B.2: capacity 220 refused");
    check(quic::qpack_encoder_stream(unhex("20")) == 1, "capacity 0 taken");
    check(quic::qpack_encoder_stream(unhex("3f")) == 0, "an instruction cut short waits");
    check(quic::qpack_encoder_stream(unhex("20 4a")) == -quic::QPACK_ENCODER_STREAM_ERROR, "B.3: insert with a literal name");
    check(quic::qpack_encoder_stream(unhex("20 02")) == -quic::QPACK_ENCODER_STREAM_ERROR, "B.4: duplicate");
    // The decoder stream: acknowledgments of what was never sent refused,
    // cancellation taken.
    check(quic::qpack_decoder_stream(unhex("84")) == -quic::QPACK_DECODER_STREAM_ERROR, "B.2: Section Acknowledgment");
    check(quic::qpack_decoder_stream(unhex("01")) == -quic::QPACK_DECODER_STREAM_ERROR, "B.3: Insert Count Increment");
    check(quic::qpack_decoder_stream(unhex("48 7f")) == 1, "B.5: Stream Cancellation, then one cut short");
    check(quic::qpack_decoder_stream(unhex("7f 01")) == 2, "a cancellation past the prefix");
}

fn static_table() {
    var all_ok = true;
    var one_byte = true;
    for i in 99 {
        let n = quic::QPACK_STATIC_NAMES[i];
        let v = quic::QPACK_STATIC_VALUES[i];
        var enc: u8[>..] = [];
        quic::qpack_begin(enc);
        quic::qpack_field(enc, n, v, false);
        if i < 63 && enc.len != 3 { one_byte = false; }
        var recs: u8[>..] = [];
        let e = quic::qpack_decode(enc, 65536, recs);
        var got = 0;
        quic::each_qpack_field(recs) { gn, gv, never => if gn == n && gv == v && !never { got++; } };
        if e != quic::QPACK_OK || got != 1 { all_ok = false; }
    }
    check(all_ok, "every static entry encoded and decoded");
    check(one_byte, "entries 0 to 62 indexed in one byte");
    // Literal forms: a static name with another value, a new name, never indexed.
    let f = records([":path", "/a/b?c=d", "x-custom", "Value 1", "authorization", "secret"]);
    var enc: u8[>..] = [];
    quic::qpack_begin(enc);
    quic::each_qpack_field(f) { n, v, never => quic::qpack_field(enc, n, v, n == "authorization"); };
    var recs: u8[>..] = [];
    check(quic::qpack_decode(enc, 65536, recs) == quic::QPACK_OK, "literals decode");
    var never_auth = false;
    var count = 0;
    quic::each_qpack_field(recs) { n, v, never =>
        count++;
        if n == "authorization" { never_auth = never && v == "secret"; }
    };
    check(count == 3 && never_auth, "the never-indexed bit kept");
    let xc, xok = quic::qpack_get(recs, "x-custom");
    check(xok && xc == "Value 1", "a literal name and value");
    var plain: u8[>..] = [];
    quic::qpack_encode(plain, f, false);
    var r2: u8[>..] = [];
    check(quic::qpack_decode(plain, 65536, r2) == quic::QPACK_OK && r2 == f, "without Huffman, the same records");
}

fn huffman() {
    // RFC 7541 C.4.
    let cases: const u8[:][4] = ["www.example.com", "no-cache", "custom-key", "custom-value"];
    let codes: const u8[:][4] = ["f1e3c2e5f23a6ba0ab90f4ff", "a8eb10649cbf", "25a849e95ba97d7f", "25a849e95bb8e8b4bf"];
    for k in 4 {
        var h: u8[>..] = [];
        quic::qpack_huffman_encode(h, cases[k]);
        check(h == unhex(codes[k]), "RFC 7541 C.4 Huffman code");
        var back: u8[>..] = [];
        check(quic::qpack_huffman_decode(h, back) && back == cases[k], "and back");
    }
    var every: u8[>..] = [];
    for b in 256 { every.push(b as! u8); }
    var h: u8[>..] = [];
    quic::qpack_huffman_encode(h, every);
    var back: u8[>..] = [];
    check(quic::qpack_huffman_decode(h, back) && back == every, "every byte");
    var x: u8[>..] = [];
    check(!quic::qpack_huffman_decode(unhex("18"), x), "padding of zeros");
    x.clear();
    check(!quic::qpack_huffman_decode(unhex("1fff"), x), "padding of more than 7 bits");
    x.clear();
    check(!quic::qpack_huffman_decode(unhex("ffffffff"), x), "EOS");
}

fn malformed() {
    check(decode("") == quic::QPACK_DECOMPRESSION_FAILED, "an empty section");
    check(decode("00") == quic::QPACK_DECOMPRESSION_FAILED, "no Base");
    check(decode("0100") == quic::QPACK_DECOMPRESSION_FAILED, "a Required Insert Count");
    check(decode("0080") == quic::QPACK_DECOMPRESSION_FAILED, "a negative Base");
    check(decode("0000 ff") == quic::QPACK_DECOMPRESSION_FAILED, "an index cut short");
    check(decode("0000 ff 80 80 80 80 80 80 80 80 80 01") == quic::QPACK_DECOMPRESSION_FAILED, "an index past 2^62");
    check(decode("0000 ff 24") == quic::QPACK_DECOMPRESSION_FAILED, "a static index past 98");
    check(decode("0000 51 05 61") == quic::QPACK_DECOMPRESSION_FAILED, "a value cut short");
    check(decode("0000 51 81 18") == quic::QPACK_DECOMPRESSION_FAILED, "a value with bad Huffman padding");
    check(decode("0000 23 61 62") == quic::QPACK_DECOMPRESSION_FAILED, "a literal name with no value");
    check(decode("0000 3f") == quic::QPACK_DECOMPRESSION_FAILED, "a name length cut short");
    check(decode("0000 d1") == quic::QPACK_OK, "an indexed field is enough");
    check(decode("0000 ff 80 80 80 80 80 80 80 80 80 80 00") == quic::QPACK_DECOMPRESSION_FAILED, "zeros past 63 bits");
    // The limit: each field's name and value plus 32.
    var big: u8[>..] = [];
    quic::qpack_begin(big);
    quic::qpack_field(big, "x-a", "0123456789", false);
    var recs: u8[>..] = [];
    check(quic::qpack_decode(big, 45, recs) == quic::QPACK_OK, "a field of 45 under 45");
    check(quic::qpack_decode(big, 44, recs) == quic::QPACK_TOO_LARGE, "over 44");
}

fn validation() {
    let ok = records([":method", "GET", ":scheme", "https", ":authority", "a.example", ":path", "/", "accept", "*/*"]);
    check(quic::validate_request(ok) == quic::FIELDS_OK, "a request");
    let host = records([":method", "GET", ":scheme", "https", ":path", "/", "host", "a.example"]);
    check(quic::validate_request(host) == quic::FIELDS_OK, "Host for :authority");
    let te = records([":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/", "te", "trailers"]);
    check(quic::validate_request(te) == quic::FIELDS_OK, "TE: trailers");
    let connect = records([":method", "CONNECT", ":authority", "a.example:443"]);
    check(quic::validate_request(connect) == quic::FIELDS_OK, "CONNECT");
    let ext = records([":method", "CONNECT", ":protocol", "websocket", ":scheme", "https", ":authority", "a", ":path", "/chat"]);
    check(quic::validate_request(ext) == quic::FIELDS_OK, "extended CONNECT");
    let cases_n = 12;
    var n_bad = 0;
    let b1 = records([":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/", "Accept", "x"]);
    if quic::validate_request(b1) == quic::FIELDS_MALFORMED { n_bad++; }
    let b2 = records([":method", "GET", "accept", "x", ":scheme", "https", ":authority", "a", ":path", "/"]);
    if quic::validate_request(b2) == quic::FIELDS_MALFORMED { n_bad++; }
    let b3 = records([":method", "GET", ":scheme", "https", ":authority", "a"]);
    if quic::validate_request(b3) == quic::FIELDS_MALFORMED { n_bad++; }
    let b4 = records([":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/", "connection", "close"]);
    if quic::validate_request(b4) == quic::FIELDS_MALFORMED { n_bad++; }
    let b5 = records([":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/", "te", "gzip"]);
    if quic::validate_request(b5) == quic::FIELDS_MALFORMED { n_bad++; }
    let b6 = records([":method", "CONNECT", ":authority", "a", ":path", "/"]);
    if quic::validate_request(b6) == quic::FIELDS_MALFORMED { n_bad++; }
    let b7 = records([":method", "GET", ":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/"]);
    if quic::validate_request(b7) == quic::FIELDS_MALFORMED { n_bad++; }
    let b8 = records([":method", "GET", ":scheme", "https", ":path", "/"]);
    if quic::validate_request(b8) == quic::FIELDS_MALFORMED { n_bad++; }
    let b9 = records([":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/", ":status", "200"]);
    if quic::validate_request(b9) == quic::FIELDS_MALFORMED { n_bad++; }
    let b10 = records([":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/", "x", "a\nb"]);
    if quic::validate_request(b10) == quic::FIELDS_MALFORMED { n_bad++; }
    let b11 = records([":method", "GET", ":scheme", "https", ":authority", "a", ":path", ""]);
    if quic::validate_request(b11) == quic::FIELDS_MALFORMED { n_bad++; }
    let b12 = records([":method", "GET", ":scheme", "https", ":authority", "a", ":path", "/", "x", " padded"]);
    if quic::validate_request(b12) == quic::FIELDS_MALFORMED { n_bad++; }
    check(n_bad == cases_n, "twelve malformed requests refused");
    check(quic::validate_response(records([":status", "200", "content-type", "text/plain"])) == quic::FIELDS_OK, "a response");
    check(quic::validate_response(records([":status", "20x"])) == quic::FIELDS_MALFORMED, "a status not of digits");
    check(quic::validate_response(records([":status", "200", ":path", "/"])) == quic::FIELDS_MALFORMED, "a request's pseudo-header");
    check(quic::validate_response(records(["content-type", "x"])) == quic::FIELDS_MALFORMED, "no :status");
    check(quic::status_of(records([":status", "404"])) == 404, "status_of");
    check(quic::validate_trailers(records(["x-checksum", "abc"])) == quic::FIELDS_OK, "trailers");
    check(quic::validate_trailers(records([":status", "200"])) == quic::FIELDS_MALFORMED, "trailers with a pseudo-header");
}

fn main() {
    appendix_b();
    static_table();
    huffman();
    malformed();
    validation();
    print("qpack: ", checks, " checks");
}
