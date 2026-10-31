// mime.encodedword: RFC 2047 encoded-words, as Go's mime.WordEncoder and
// mime.WordDecoder write and read them.
//
// Encoding: encode_word(out, B_ENCODING or Q_ENCODING, charset, s) leaves s
// as it is when it is printable ASCII (tab allowed), and otherwise writes
// "=?charset?b?...?=" or "=?charset?q?...?=", split into several words
// joined by a space when the charset is UTF-8 and a word would pass 75
// characters (never inside a UTF-8 sequence).
//
// Decoding: decode_word for one encoded-word, decode_header for a header
// value with encoded-words among other text (the white space between two
// adjacent words dropped; a word whose B or Q text is malformed left as it
// is). UTF-8, ISO-8859-1 and US-ASCII are built in; the *_charset forms take
// a block for any other charset, Go's CharsetReader:
//
//     mime::decode_header_charset(out, h) { cs: const u8[:], text: const u8[:], o: u8[>..]& =>
//         // cs is the charset in lower case, text the decoded bytes;
//         // append their UTF-8 to o and give 0, or give an error code
//         0
//     };
//
// On an error the output is left as it was. word_error and header_error
// give Go's message for a failed decode_word or decode_header.

namespace mime;

import std;
import base64;
import mime;

let B_ENCODING: u8 = 'b';      // Go's BEncoding: base64
let Q_ENCODING: u8 = 'q';      // Go's QEncoding: RFC 2047's Q

// RFC 2047 §2: an encoded-word is at most 75 characters. Go reserves the
// room of "=?UTF-8?q?" and "?=" whatever the charset is.
let MAX_ENCODED_WORD_LEN: i64 = 75;
let MAX_CONTENT_LEN: i64 = 63;         // 75 - len("=?UTF-8?q?") - len("?=")
let MAX_BASE64_LEN: i64 = 45;          // base64.StdEncoding.DecodedLen(63)

fn is_utf8_charset(charset: const u8[:]) -> bool { eq_fold(charset, "utf-8") }

// WordEncoder.Encode.
fn encode_word(out: u8[>..]&, enc: u8, charset: const u8[:], s: const u8[:]) {
    if !needs_encoding(s) { out.append(s); return; }
    open_word(out, enc, charset);
    if enc == B_ENCODING { b_encode(out, enc, charset, s); } else { q_encode(out, enc, charset, s); }
    out.append("?=");
}

fn encode_word(enc: u8, charset: const u8[:], s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    encode_word(out, enc, charset, s);
    return out;
}

fn open_word(out: u8[>..]&, enc: u8, charset: const u8[:]) {
    out.append("=?");
    out.append(charset);
    out.push('?');
    out.push(enc);
    out.push('?');
}

fn split_word(out: u8[>..]&, enc: u8, charset: const u8[:]) {
    out.append("?= ");
    open_word(out, enc, charset);
}

fn b_encode(out: u8[>..]&, enc: u8, charset: const u8[:], s: const u8[:]) {
    if !is_utf8_charset(charset) || (s.len + 2) / 3 * 4 <= MAX_CONTENT_LEN {
        base64::encode(out, s);
        return;
    }
    var current = 0;
    var last = 0;
    var i = 0;
    while i < s.len {
        let r, n = decode_rune(s, i);
        if current + n <= MAX_BASE64_LEN {
            current += n;
        } else {
            base64::encode(out, s[last..i]);
            split_word(out, enc, charset);
            last = i;
            current = n;
        }
        i += n;
    }
    base64::encode(out, s[last..]);
}

fn q_encode(out: u8[>..]&, enc: u8, charset: const u8[:], s: const u8[:]) {
    if !is_utf8_charset(charset) { write_q_string(out, s); return; }
    var current = 0;
    var i = 0;
    while i < s.len {
        let b = s[i];
        var n = 1;
        var enc_len = 1;
        if !(b >= ' ' && b <= '~' && b != '=' && b != '?' && b != '_') {
            let r, rn = decode_rune(s, i);
            n = rn;
            enc_len = 3 * rn;
        }
        if current + enc_len > MAX_CONTENT_LEN {
            split_word(out, enc, charset);
            current = 0;
        }
        write_q_string(out, s[i..i + n]);
        current += enc_len;
        i += n;
    }
}

fn write_q_string(out: u8[>..]&, s: const u8[:]) {
    for b in s {
        if b == ' ' { out.push('_'); }
        else if b >= '!' && b <= '~' && b != '=' && b != '?' && b != '_' { out.push(b); }
        else { out.push('='); push_hex_upper(out, b); }
    }
}

// --- Decoding -----------------------------------------------------------------

// Where a decode failed, for the message: a byte (invalid hex), an offset
// (base64), or the charset's place in the input.
struct WordError { code: i64, b: u8, at: i64, cs: Span }

fn no_word_error() -> WordError { WordError { code: OK, b: 0, at: 0, cs: Span { pos: 0, end: 0 } } }

fn count_byte(s: const u8[:], c: u8) -> i64 {
    var n = 0;
    for x in s { if x == c { n++; } }
    return n;
}

fn index_of(s: const u8[:], from: i64, sub: const u8[:]) -> i64 {
    let k = find(s[from..], sub);
    return if k < 0 { -1 } else { from + k };
}

fn base64_value(c: u8) -> i64 {
    if c >= 'A' && c <= 'Z' { return c - 'A'; }
    if c >= 'a' && c <= 'z' { return c - 'a' + 26; }
    if c >= '0' && c <= '9' { return c - '0' + 52; }
    if c == '+' { return 62; }
    if c == '/' { return 63; }
    return -1;
}

// base64.StdEncoding.DecodeString: padding required, CR and LF ignored,
// the bits past the end not checked. Appends to out; false with the
// offset Go reports (CorruptInputError) on bad input.
fn base64_decode(out: u8[>..]&, src: const u8[:], e: WordError&) -> bool {
    var si = 0;
    while si < src.len {
        var dbuf: i64[4] = [0, 0, 0, 0];
        var dlen = 4;
        var j = 0;
        var trailing = -1;
        while j < 4 {
            if si == src.len {
                if j == 0 { return true; }
                e.code = ERR_BASE64; e.at = si - j; return false;
            }
            let c = src[si];
            si++;
            let v = base64_value(c);
            if v >= 0 { dbuf[j] = v; j++; continue; }
            if c == '\n' || c == '\r' { continue; }
            if c != '=' { e.code = ERR_BASE64; e.at = si - 1; return false; }
            if j < 2 { e.code = ERR_BASE64; e.at = si - 1; return false; }
            if j == 2 {
                while si < src.len && (src[si] == '\n' || src[si] == '\r') { si++; }
                if si == src.len { e.code = ERR_BASE64; e.at = src.len; return false; }
                if src[si] != '=' { e.code = ERR_BASE64; e.at = si - 1; return false; }
                si++;
            }
            while si < src.len && (src[si] == '\n' || src[si] == '\r') { si++; }
            if si < src.len { trailing = si; }
            dlen = j;
            break;
        }
        let val = (dbuf[0] << 18) | (dbuf[1] << 12) | (dbuf[2] << 6) | dbuf[3];
        out.push(((val >> 16) & 0xFF) as u8);
        if dlen >= 3 { out.push(((val >> 8) & 0xFF) as u8); }
        if dlen == 4 { out.push((val & 0xFF) as u8); }
        if trailing >= 0 { e.code = ERR_BASE64; e.at = trailing; return false; }
        if dlen < 4 { return true; }
    }
    return true;
}

fn from_hex(b: u8) -> i64 {
    if b >= '0' && b <= '9' { return b - '0'; }
    if b >= 'A' && b <= 'F' { return b - 'A' + 10; }
    if b >= 'a' && b <= 'f' { return b - 'a' + 10; }     // Go accepts lower case too
    return -1;
}

// qDecode.
fn q_decode(out: u8[>..]&, s: const u8[:], e: WordError&) -> bool {
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c == '_' { out.push(' '); }
        else if c == '=' {
            if i + 2 >= s.len { e.code = ERR_INVALID_WORD; return false; }
            let hb = from_hex(s[i + 1]);
            if hb < 0 { e.code = ERR_INVALID_HEX; e.b = s[i + 1]; return false; }
            let lb = from_hex(s[i + 2]);
            if lb < 0 { e.code = ERR_INVALID_HEX; e.b = s[i + 2]; return false; }
            out.push(((hb << 4) | lb) as u8);
            i += 2;
        }
        else if (c <= '~' && c >= ' ') || c == '\n' || c == '\r' || c == '\t' { out.push(c); }
        else { e.code = ERR_INVALID_WORD; return false; }
        i++;
    }
    return true;
}

fn decode_text(out: u8[>..]&, encoding: u8, text: const u8[:], e: WordError&) -> bool {
    if encoding == 'B' || encoding == 'b' { return base64_decode(out, text, e); }
    if encoding == 'Q' || encoding == 'q' { return q_decode(out, text, e); }
    e.code = ERR_INVALID_WORD;
    return false;
}

// WordDecoder.convert: content in the charset at input[cs] as UTF-8.
fn convert<F>(out: u8[>..]&, input: const u8[:], cs: Span, content: const u8[:], e: WordError&) -> bool {
    let charset = input[cs.pos..cs.end];
    if eq_fold(charset, "utf-8") { out.append(content); return true; }
    if eq_fold(charset, "iso-8859-1") {
        for c in content { push_rune(out, c); }
        return true;
    }
    if eq_fold(charset, "us-ascii") {
        for c in content { if c >= 0x80 { push_rune(out, RUNE_ERROR); } else { out.push(c); } }
        return true;
    }
    var lower: u8[>..] = [];
    go_to_lower(lower, charset);
    let mark = out.len;
    let rc = F(lower, content, out);
    if rc != OK {
        out.resize(mark);
        e.code = rc;
        e.cs = cs;
        return false;
    }
    return true;
}

// WordDecoder.Decode.
fn decode_word_impl<F>(out: u8[>..]&, word: const u8[:], e: WordError&) -> bool {
    if word.len < 8 || word[..2] != "=?" || word[word.len - 2..] != "?=" || count_byte(word, '?') != 4 {
        e.code = ERR_INVALID_WORD;
        return false;
    }
    let inner = word[2..word.len - 2];
    let q1 = index_byte(inner, '?');
    if q1 <= 0 { e.code = ERR_INVALID_WORD; return false; }
    let rest = inner[q1 + 1..];
    let q2 = index_byte(rest, '?');
    let enc_len = if q2 < 0 { rest.len } else { q2 };
    if enc_len != 1 { e.code = ERR_INVALID_WORD; return false; }
    let text = rest[2..];
    var content: u8[>..] = [];
    if !decode_text(content, rest[0], text, e) { return false; }
    let mark = out.len;
    if !convert(out, word, Span { pos: 2, end: 2 + q1 }, content, e, F) { out.resize(mark); return false; }
    return true;
}

// WordDecoder.DecodeHeader.
fn decode_header_impl<F>(out: u8[>..]&, header: const u8[:], e: WordError&) -> bool {
    let first = find(header, "=?");
    if first < 0 { out.append(header); return true; }
    let mark = out.len;
    out.append(header[..first]);
    var h = first;                   // header[h..] is what is left
    var between = false;
    var content: u8[>..] = [];
    loop {
        let start = index_of(header, h, "=?");
        if start < 0 { break; }
        var cur = start + 2;
        let qm = index_byte(header[cur..], '?');
        if qm < 0 { break; }
        let cs = Span { pos: cur, end: cur + qm };
        cur += qm + 1;
        if header.len < cur + 4 { break; }
        let encoding = header[cur];
        cur++;
        if header[cur] != '?' { break; }
        cur++;
        let j = index_of(header, cur, "?=");
        if j < 0 { break; }
        let text = header[cur..j];
        let end = j + 2;
        content.clear();
        var te = no_word_error();
        if !decode_text(content, encoding, text, te) {
            between = false;
            out.append(header[h..end]);
            h = end;
            continue;
        }
        if start > h && (!between || has_non_whitespace(header[h..start])) { out.append(header[h..start]); }
        if !convert(out, header, cs, content, e, F) { out.resize(mark); return false; }
        h = end;
        between = true;
    }
    out.append(header[h..]);
    return true;
}

fn has_non_whitespace(s: const u8[:]) -> bool {
    for b in s { if b != ' ' && b != '\t' && b != '\n' && b != '\r' { return true; } }
    return false;
}

// The decoders without a CharsetReader: any other charset is an error.
fn decode_word(out: u8[>..]&, word: const u8[:]) -> i64 {
    var e = no_word_error();
    decode_word_impl(out, word, e) { cs: const u8[:], c: const u8[:], o: u8[>..]& => ERR_UNHANDLED_CHARSET };
    return e.code;
}

fn decode_header(out: u8[>..]&, header: const u8[:]) -> i64 {
    var e = no_word_error();
    decode_header_impl(out, header, e) { cs: const u8[:], c: const u8[:], o: u8[>..]& => ERR_UNHANDLED_CHARSET };
    return e.code;
}

// The decoders with a CharsetReader block F(charset, content, out) -> code.
fn decode_word_charset<F>(out: u8[>..]&, word: const u8[:]) -> i64 {
    var e = no_word_error();
    decode_word_impl(out, word, e, F);
    return e.code;
}

fn decode_header_charset<F>(out: u8[>..]&, header: const u8[:]) -> i64 {
    var e = no_word_error();
    decode_header_impl(out, header, e, F);
    return e.code;
}

// Go's message for an error of these decoders.
fn word_error_message(out: u8[>..]&, input: const u8[:], e: const WordError&) {
    if e.code == ERR_INVALID_HEX {
        out.append("mime: invalid hex byte 0x");
        out.push(LOWERHEX[e.b >> 4]);
        out.push(LOWERHEX[e.b & 15]);
    } else if e.code == ERR_BASE64 {
        format(out, "illegal base64 data at input byte ", e.at);
    } else if e.code == ERR_UNHANDLED_CHARSET {
        out.append("mime: unhandled charset ");
        go_quote(out, input[e.cs.pos..e.cs.end]);
    } else {
        out.append(error_text(e.code));
    }
}

// The message of decode_word(word)'s error ("" if it decodes).
fn word_error(out: u8[>..]&, word: const u8[:]) {
    var e = no_word_error();
    var scratch: u8[>..] = [];
    decode_word_impl(scratch, word, e) { cs: const u8[:], c: const u8[:], o: u8[>..]& => ERR_UNHANDLED_CHARSET };
    if e.code != OK { word_error_message(out, word, e); }
}

// The message of decode_header(header)'s error ("" if it decodes).
fn header_error(out: u8[>..]&, header: const u8[:]) {
    var e = no_word_error();
    var scratch: u8[>..] = [];
    decode_header_impl(scratch, header, e) { cs: const u8[:], c: const u8[:], o: u8[>..]& => ERR_UNHANDLED_CHARSET };
    if e.code != OK { word_error_message(out, header, e); }
}
