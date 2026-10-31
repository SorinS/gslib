// mime.encodedword: RFC 2047 encoded-words against Go's own test tables
// (from $GOROOT/src/mime/encodedword_test.go by scripts/gen_vectors.py),
// each row checked against what Go returns, and the error messages.

import std;
import gslib from "../..";
import gslib.mime;
import gslib.mime.encodedword;
import tv;

fn encode() {
    tv::each_row("vectors/go_encode_word.txt") { r: tv::Row& =>
        let enc = r.next_int() as u8;
        let charset = r.next();
        let src = r.next();
        let want = r.next();
        r.to_results();
        let go = r.next();
        let got = mime::encode_word(enc, charset, src);
        tv::check_eq(str("encode_word ", src), got, go);
        tv::check_eq(str("encode_word (table) ", src), got, want);
    };
    tv::each_row("vectors/go_encoded_word_length.txt") { r: tv::Row& =>
        let enc = r.next_int() as u8;
        let src = r.next();
        r.to_results();
        let go = r.next();
        let got = mime::encode_word(enc, "utf-8", src);
        tv::check_eq(str("encode_word length ", src), got, go);
        var longest = 0;
        each_split(got, ' ') { longest = max(longest, it.len); };
        tv::check(str("words of at most 75 characters ", src), longest <= 75);
    };
}

fn decode() {
    tv::each_row("vectors/go_decode_word.txt") { r: tv::Row& =>
        let src = r.next();
        r.next();
        r.next();
        r.to_results();
        let go = r.next();
        let go_err = r.next();
        var got: u8[>..] = [];
        let rc = mime::decode_word(got, src);
        tv::check_eq(str("decode_word ", src), got, go);
        var msg: u8[>..] = [];
        mime::word_error(msg, src);
        tv::check_eq(str("decode_word error ", src), msg, go_err);
        tv::check(str("decode_word code ", src), (rc != 0) == (go_err.len > 0));
    };
    tv::each_row("vectors/go_decode_header.txt") { r: tv::Row& =>
        let src = r.next();
        r.next();
        r.to_results();
        let go = r.next();
        let go_err = r.next();
        var got: u8[>..] = [];
        let rc = mime::decode_header(got, src);
        tv::check_eq(str("decode_header ", src), got, go);
        var msg: u8[>..] = [];
        mime::header_error(msg, src);
        tv::check_eq(str("decode_header error ", src), msg, go_err);
        tv::check(str("decode_header code ", src), (rc != 0) == (go_err.len > 0));
    };
}

// TestCharsetDecoder: a CharsetReader that checks the charset (in lower
// case) and the content it is given, and hands the bytes back unchanged.
fn charset_reader() {
    tv::each_row("vectors/go_charset_decoder.txt") { r: tv::Row& =>
        let src = r.next();
        let want = r.next();
        var charsets: u8[>..] = [];
        var contents: u8[>..] = [];
        if !r.next_is_nil() { let n = r.next_int(); for i in n { charsets.append(r.next()); charsets.push(0); } }
        if !r.next_is_nil() { let n = r.next_int(); for i in n { contents.append(r.next()); contents.push(0); } }
        var seen_cs: u8[>..] = [];
        var seen_content: u8[>..] = [];
        var got: u8[>..] = [];
        let rc = mime::decode_header_charset(got, src) { cs: const u8[:], content: const u8[:], o: u8[>..]& =>
            seen_cs.append(cs); seen_cs.push(0);
            seen_content.append(content); seen_content.push(0);
            o.append(content);
            0
        };
        tv::check_int(str("charset decoder code ", src), rc, 0);
        tv::check_eq(str("charset decoder ", src), got, want);
        tv::check_eq(str("charset decoder charsets ", src), seen_cs, charsets);
        tv::check_eq(str("charset decoder contents ", src), seen_content, contents);
    };
    // TestCharsetDecoderError: the block's error is the result.
    var out: u8[>..] = [];
    out.append("kept");
    let rc = mime::decode_header_charset(out, "=?charset?Q?foo?=") { cs: const u8[:], c: const u8[:], o: u8[>..]& =>
        o.append("partial");
        77
    };
    tv::check_int("charset reader error", rc, 77);
    tv::check_eq("output left as it was", out, "kept");
}

fn messages() {
    var m: u8[>..] = [];
    mime::word_error(m, "=?UTF-8?Q?=G0?=");
    tv::check_eq("hex message", m, "mime: invalid hex byte 0x47");
    m.clear();
    mime::word_error(m, "=?UTF-8?B?QW5k=?=");
    tv::check_eq("base64 message", m, "illegal base64 data at input byte 4");
    m.clear();
    mime::word_error(m, "=?k\xc3\xa9?Q?a?=");
    tv::check_eq("charset message", m, "mime: unhandled charset \"k\xc3\xa9\"");
    m.clear();
    mime::header_error(m, "a =?x-unknown?Q?a?= b");
    tv::check_eq("header charset message", m, "mime: unhandled charset \"x-unknown\"");
    // Unicode case folding of the built-in charset names (strings.EqualFold).
    var o: u8[>..] = [];
    tv::check_int("long s folds to s", mime::decode_word(o, "=?u\xc5\xbf-a\xc5\xbfcii?Q?a=FF?="), 0);
    tv::check_eq("long s charset", o, "a\xef\xbf\xbd");
}

fn main() {
    encode();
    decode();
    charset_reader();
    messages();
    tv::done("encodedword");
}
