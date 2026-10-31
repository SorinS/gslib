// mime.quotedprintable: the quoted-printable content-transfer-encoding
// (RFC 2045 §6.7), as Go's mime/quotedprintable reads and writes it.
//
// Reading is Go's, leniencies included: "=\n" is a soft line break as
// "=\r\n" is; a CR or LF not after '=' passes through; a '=' at the very
// end of the input is dropped; '=' not followed by two hex digits (upper
// or lower case) is a literal '=' unless the line ends right after it;
// bytes >= 0x80 pass through; white space at the end of a line is dropped.
// Like Go, which reads lines through a 4096-byte bufio.Reader, a line of
// more than 4096 bytes is an error (ERR_BUFFER_FULL) after the decoded
// text of its first 4096 bytes.
//
// The decoder is fed: decode(r, out, data) as the bytes come, then
// finish(r, out) at the end; each appends what it decoded to out and
// returns 0 or an error code, which stays. decode_all is the same for a
// whole buffer. The writer appends to the caller's builder: write(w, out,
// data) and close(w, out); w.binary is Go's Writer.Binary.

namespace quotedprintable;

import std;
import mime;

let MAX_LINE: i64 = 4096;       // Go's bufio.Reader default size

struct Reader {
    line: u8[..4096] = [],       // a line not yet ended by '\n'
    err: i64 = 0,                // the sticky error, once there is one
    err_byte: u8 = 0,            // its byte, for ERR_QP_INVALID_HEX / ERR_QP_UNESCAPED
    detail: u8[..4096] = [],     // the bytes after '=', for ERR_QP_AFTER_EQUALS
    ended: bool = false,
}

fn new_reader() -> Reader { Reader { .. } }

fn is_discard_space(c: u8) -> bool { c == '\n' || c == '\r' || c == ' ' || c == '\t' }

fn hex_value(b: u8) -> i64 {
    if b >= '0' && b <= '9' { return b - '0'; }
    if b >= 'A' && b <= 'F' { return b - 'A' + 10; }
    if b >= 'a' && b <= 'f' { return b - 'a' + 10; }
    return -1;
}

fn fail(r: Reader&, code: i64, b: u8) -> i64 {
    r.err = code;
    r.err_byte = b;
    return code;
}

// Decodes the bytes of a line after Go's trimming (core), as Go's Read loop
// does; the line's ending is passed through by the caller. Returns 0 or an
// error code.
fn decode_core(r: Reader&, out: u8[>..]&, l: const u8[:]) -> i64 {
    var i = 0;
    var run = 0;                         // l[run..i] is plain and not yet written
    while i < l.len {
        let b = l[i];
        if b == '=' {
            out.append(l[run..i]);
            // readHexByte(line[1:]): two hex digits, else an error that
            // makes the '=' literal unless the line ends right after it
            var err = 0;
            var eb: u8 = 0;
            var v = 0;
            if l.len - i < 3 {
                err = mime::ERR_UNEXPECTED_EOF;
            } else {
                let hb = hex_value(l[i + 1]);
                let lb = hex_value(l[i + 2]);
                if hb < 0 { err = mime::ERR_QP_INVALID_HEX; eb = l[i + 1]; }
                else if lb < 0 { err = mime::ERR_QP_INVALID_HEX; eb = l[i + 2]; }
                else { v = (hb << 4) | lb; }
            }
            if err != 0 {
                if l.len - i >= 2 && l[i + 1] != '\r' && l[i + 1] != '\n' {
                    out.push('=');
                    i++;
                    run = i;
                    continue;
                }
                return fail(r, err, eb);
            }
            out.push(v as u8);
            i += 3;
            run = i;
            continue;
        }
        if b == '\t' || b == '\r' || b == '\n' || b >= 0x80 || (b >= ' ' && b <= '~') { i++; continue; }
        out.append(l[run..i]);
        return fail(r, mime::ERR_QP_UNESCAPED, b);
    }
    out.append(l[run..]);
    return 0;
}

// One line as Go's Reader takes it from ReadSlice('\n'): `whole` with its
// '\n' if it has one, and the error that came with it (0, ERR_EOF,
// ERR_UNEXPECTED_EOF or ERR_BUFFER_FULL).
fn process_line(r: Reader&, out: u8[>..]&, whole: const u8[:], rerr: i64) -> i64 {
    let has_lf = whole.len > 0 && whole[whole.len - 1] == '\n';
    let has_cr = has_lf && whole.len > 1 && whole[whole.len - 2] == '\r';
    var e = whole.len;
    while e > 0 && is_discard_space(whole[e - 1]) { e--; }
    var after_err = rerr;
    var ending = "";
    var core_end = e;
    if e > 0 && whole[e - 1] == '=' {
        var k = e;
        while k < whole.len && (whole[k] == ' ' || whole[k] == '\t') { k++; }
        let right = whole[k..];
        core_end = e - 1;
        let ok = (right.len > 0 && right[0] == '\n') || (right.len > 1 && right[0] == '\r' && right[1] == '\n') ||
                 (right.len == 0 && core_end > 0 && rerr == mime::ERR_EOF);
        if !ok {
            after_err = mime::ERR_QP_AFTER_EQUALS;
            r.detail.clear();
            r.detail.append(right);
        }
    } else if has_lf {
        ending = if has_cr { "\r\n" } else { "\n" };
    }
    let rc = decode_core(r, out, whole[..core_end]);
    if rc != 0 { return rc; }
    out.append(ending);
    if after_err != 0 && after_err != mime::ERR_EOF { r.err = after_err; return after_err; }
    return 0;
}

// Feeds data; appends the decoded bytes to out. 0 or the (sticky) error.
fn decode(r: Reader&, out: u8[>..]&, data: const u8[:]) -> i64 {
    if r.err != 0 { return r.err; }
    var p = 0;
    while p < data.len {
        // the next '\n' within what fits in Go's buffer with the pending line
        let room = MAX_LINE - r.line.len;
        let lim = ::min(data.len, p + room);
        var nl = -1;
        for k in p..lim { if data[k] == '\n' { nl = k; break; } }
        if nl >= 0 {
            var rc = 0;
            if r.line.len == 0 {
                rc = process_line(r, out, data[p..nl + 1], 0);
            } else {
                r.line.append(data[p..nl + 1]);
                rc = process_line(r, out, r.line, 0);
                if rc == 0 { r.line.clear(); }
            }
            if rc != 0 { return rc; }
            p = nl + 1;
            continue;
        }
        if lim - p < room {          // no '\n' yet: keep the bytes
            r.line.append(data[p..lim]);
            return 0;
        }
        // Go's buffer fills without a '\n': ErrBufferFull, after the chunk.
        r.line.append(data[p..lim]);
        let rc = process_line(r, out, r.line, mime::ERR_BUFFER_FULL);
        if rc != 0 { return rc; }
        r.err = mime::ERR_BUFFER_FULL;
        return r.err;
    }
    return 0;
}

// The end of the input (io.EOF, or another error such as a truncated
// multipart body's ERR_UNEXPECTED_EOF): decodes what is left.
fn finish(r: Reader&, out: u8[>..]&, eof: i64 = mime::ERR_EOF) -> i64 {
    if r.err != 0 { return r.err; }
    if r.ended { return 0; }
    r.ended = true;
    if r.line.len > 0 || eof != mime::ERR_EOF {
        let rc = if r.line.len > 0 { process_line(r, out, r.line, eof) } else { 0 };
        if rc != 0 { return rc; }
        if eof != mime::ERR_EOF { r.err = eof; return eof; }
    }
    return 0;
}

// Go's message for the reader's error ("" if none).
fn error_message(r: const Reader&, out: u8[>..]&) {
    if r.err == mime::ERR_QP_INVALID_HEX || r.err == mime::ERR_QP_UNESCAPED {
        out.append(if r.err == mime::ERR_QP_INVALID_HEX { "quotedprintable: invalid hex byte 0x" }
                   else { "quotedprintable: invalid unescaped byte 0x" });
        out.push(mime::LOWERHEX[r.err_byte >> 4]);
        out.push(mime::LOWERHEX[r.err_byte & 15]);
        if r.err == mime::ERR_QP_UNESCAPED { out.append(" in body"); }
    } else if r.err == mime::ERR_QP_AFTER_EQUALS {
        out.append("quotedprintable: invalid bytes after =: ");
        mime::go_quote(out, r.detail);
    } else if r.err != 0 {
        out.append(mime::error_text(r.err));
    }
}

// A whole buffer: io.Copy(out, NewReader(src)). 0 or the error code;
// what was decoded before an error is in out, as Go's Read returns it.
fn decode_all(out: u8[>..]&, src: const u8[:]) -> i64 {
    var r = Reader { .. };
    let rc = decode(r, out, src);
    if rc != 0 { return rc; }
    return finish(r, out);
}

// The same, with Go's error message in msg.
fn decode_all(out: u8[>..]&, src: const u8[:], msg: u8[>..]&) -> i64 {
    var r = Reader { .. };
    var rc = decode(r, out, src);
    if rc == 0 { rc = finish(r, out); }
    error_message(r, msg);
    return rc;
}

// --- The writer ---------------------------------------------------------------

let LINE_MAX_LEN: i64 = 76;

struct Writer {
    binary: bool = false,        // Go's Writer.Binary: CR and LF are data, encoded
    line: u8[..78] = [],
    cr: bool = false,
}

fn new_writer() -> Writer { Writer { .. } }

fn is_whitespace(b: u8) -> bool { b == ' ' || b == '\t' }

fn flush(w: Writer&, out: u8[>..]&) {
    out.append(w.line);
    w.line.clear();
}

fn insert_crlf(w: Writer&, out: u8[>..]&) {
    w.line.push('\r');
    w.line.push('\n');
    flush(w, out);
}

fn insert_soft_line_break(w: Writer&, out: u8[>..]&) {
    w.line.push('=');
    insert_crlf(w, out);
}

fn encode_byte(w: Writer&, out: u8[>..]&, b: u8) {
    if LINE_MAX_LEN - 1 - w.line.len < 3 { insert_soft_line_break(w, out); }
    w.line.push('=');
    w.line.push(mime::UPPERHEX[b >> 4]);
    w.line.push(mime::UPPERHEX[b & 15]);
}

fn check_last_byte(w: Writer&, out: u8[>..]&) {
    if w.line.len == 0 { return; }
    let b = w.line[w.line.len - 1];
    if is_whitespace(b) {
        w.line.pop();
        encode_byte(w, out, b);
    }
}

fn write_plain(w: Writer&, out: u8[>..]&, p: const u8[:]) {
    for b in p {
        if b == '\n' || b == '\r' {
            if w.cr && b == '\n' { w.cr = false; continue; }
            if b == '\r' { w.cr = true; }
            check_last_byte(w, out);
            insert_crlf(w, out);
            continue;
        }
        if w.line.len == LINE_MAX_LEN - 1 { insert_soft_line_break(w, out); }
        w.line.push(b);
        w.cr = false;
    }
}

// Writer.Write: encodes p, appending whole lines to out as they end.
fn write(w: Writer&, out: u8[>..]&, p: const u8[:]) {
    var n = 0;
    for i in p.len {
        let b = p[i];
        if b >= '!' && b <= '~' && b != '=' { continue; }
        if is_whitespace(b) || (!w.binary && (b == '\n' || b == '\r')) { continue; }
        if i > n { write_plain(w, out, p[n..i]); n = i; }
        encode_byte(w, out, b);
        n++;
    }
    if n < p.len { write_plain(w, out, p[n..]); }
}

// Writer.Close: the last line, its trailing white space encoded.
fn close(w: Writer&, out: u8[>..]&) {
    check_last_byte(w, out);
    flush(w, out);
}

// A whole buffer, encoded.
fn encode_all(out: u8[>..]&, src: const u8[:], binary: bool = false) {
    var w = Writer { binary: binary, .. };
    write(w, out, src);
    close(w, out);
}
