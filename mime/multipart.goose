// mime.multipart: multipart bodies (RFC 2046 §5.1, RFC 7578 forms) as Go's
// mime/multipart reads and writes them.
//
// The Reader does no I/O. The caller feeds it the body as it comes and
// asks for events:
//
//     var r = multipart::Reader { .. };
//     multipart::init(r, boundary);
//     multipart::feed(r, bytes);              // as they come
//     multipart::finish(r);                   // at the end of the body
//     loop {
//         let ev = multipart::next(r, data);  // appends body bytes to data
//         // EV_PART: a part's header is r.header (form_name(r), file_name(r));
//         // EV_DATA: more of its body in data; EV_PART_END: its body ended,
//         // r.part_err its error (0, ERR_UNEXPECTED_EOF or a quoted-printable
//         // error); EV_END: no more parts (Go's io.EOF); EV_ERROR: r.err,
//         // message(r); EV_NEED_MORE: feed more, or finish
//     }
//
// The boundary rules are Go's: a boundary line is "--boundary" with
// optional white space after it and CRLF, or LF only if the first one ends
// so (Go switches to LF lines then); the final one is "--boundary--"; a
// part may end with "--boundary" right after its header; lines before the
// first boundary are skipped; a line before a boundary line longer than
// Go's 4096-byte buffer is an error ("bufio: buffer full"). A part's
// header is read as textproto's reader does, with Go's limits (10 MiB,
// 10000 fields: max_header_bytes, max_headers). A part with
// Content-Transfer-Encoding: quoted-printable is decoded, and that field
// removed, unless r.raw is set (Go's NextRawPart). next_part skips what is
// left of the current part (Go's NextPart).

namespace multipart;

import std;
import dictionary;
import mime;
import textproto;
import quotedprintable;

let EV_NEED_MORE: i64 = 0;
let EV_PART: i64 = 1;
let EV_DATA: i64 = 2;
let EV_PART_END: i64 = 3;
let EV_END: i64 = 4;
let EV_ERROR: i64 = 5;

let PEEK_BUFFER_SIZE: i64 = 4096;                // Go's bufio buffer for the body
let MAX_MIME_HEADER_SIZE: i64 = 10485760;        // 10 << 20
let MAX_MIME_HEADERS: i64 = 10000;               // GODEBUG multipartmaxheaders default

let S_LINES: i64 = 0;          // NextPart's loop: looking for a boundary line
let S_HEADERS: i64 = 1;        // a part's header
let S_BODY: i64 = 2;
let S_SKIP: i64 = 3;           // the raw rest of a part whose decoding failed
let S_END: i64 = 4;
let S_ERROR: i64 = 5;

root struct Reader {
    b: u8[>..] = [],                 // "\r\n--" boundary "--": every form of it is a part of this
    nl_len: i64 = 2,                 // 2 (CRLF), or 1 once the first boundary line ended in LF only
    buf: u8[>..] = [],               // the input not yet consumed is buf[pos..]
    pos: i64 = 0,
    eof: bool = false,
    state: i64 = S_LINES,
    parts_read: i64 = 0,
    expect_new_part: bool = false,
    raw: bool = false,               // Go's NextRawPart: no quoted-printable decoding
    max_header_bytes: i64 = MAX_MIME_HEADER_SIZE,
    max_headers: i64 = MAX_MIME_HEADERS,
    header: textproto::Header = textproto::Header { .. },
    disp: mime::MediaType = mime::MediaType { err: 0, typ: "", params: [] },
    err: i64 = 0,                    // the error of EV_ERROR
    detail: u8[>..] = [],            // its line, for message()
    part_err: i64 = 0,               // the error that ended the part's body (EV_PART_END)
    part_err_text: u8[>..] = [],     // its message
    total: i64 = 0,                  // body bytes of the part read so far (before decoding)
    qp_on: bool = false,
    qp: quotedprintable::Reader = quotedprintable::Reader { .. },
    hr: textproto::HeaderReader = textproto::header_reader(0, 0, 0),   // the part's header, as it comes
    seen: dictionary<u64, bool> = dictionary<u64, bool> {},
    cr_set: ByteSet = byte_set("\r"),    // the first byte of "\r\n--boundary", for find_any (memchr)
    lf_set: ByteSet = byte_set("\n"),
}

// NewReader: a reader for the body of a multipart message with this
// boundary (from the Content-Type's "boundary" parameter).
fn init(r: Reader&, boundary: const u8[:]) {
    r.b.clear();
    r.b.append("\r\n--");
    r.b.append(boundary);
    r.b.append("--");
    r.nl_len = 2;
    r.buf.clear();
    r.pos = 0;
    r.eof = false;
    r.state = S_LINES;
    r.parts_read = 0;
    r.expect_new_part = false;
    r.header.fields.clear();
    r.err = 0;
    r.detail.clear();
    r.part_err = 0;
    r.part_err_text.clear();
    r.total = 0;
    r.qp_on = false;
}

fn dash_boundary(r: const Reader&) -> const u8[:] { r.b[2..r.b.len - 2] }
fn dash_boundary_dash(r: const Reader&) -> const u8[:] { r.b[2..] }
fn nl(r: const Reader&) -> const u8[:] { r.b[2 - r.nl_len..2] }
fn nl_dash_boundary(r: const Reader&) -> const u8[:] { r.b[2 - r.nl_len..r.b.len - 2] }

// Appends input. What has been consumed is dropped first.
fn feed(r: Reader&, data: const u8[:]) {
    if r.pos > 0 && (r.pos >= 65536 || r.pos * 2 >= r.buf.len) {
        let rest = r.buf.len - r.pos;
        for i in rest { r.buf[i] = r.buf[r.pos + i]; }
        r.buf.resize(rest);
        if r.state == S_HEADERS { textproto::shift(r.hr, r.pos); }
        r.pos = 0;
    }
    r.buf.append(data);
}

// The end of the input.
fn finish(r: Reader&) { r.eof = true; }

fn has_prefix(s: const u8[:], p: const u8[:]) -> bool { s.len >= p.len && s[..p.len] == p }

fn skip_lwsp(s: const u8[:]) -> const u8[:] {
    var i = 0;
    while i < s.len && (s[i] == ' ' || s[i] == '\t') { i++; }
    return s[i..];
}

// isFinalBoundary: ^--boundary--[ \t]*(\r\n)?$ (or \n in LF mode).
fn is_final_boundary(r: const Reader&, line: const u8[:]) -> bool {
    let dbd = dash_boundary_dash(r);
    if !has_prefix(line, dbd) { return false; }
    let rest = skip_lwsp(line[dbd.len..]);
    return rest.len == 0 || rest == nl(r);
}

// isBoundaryDelimiterLine: "--boundary", LWSP, then the line's end; on
// the first part an LF-only end switches the reader to LF lines.
fn is_boundary_delimiter_line(r: Reader&, line: const u8[:]) -> bool {
    let db = dash_boundary(r);
    if !has_prefix(line, db) { return false; }
    let rest = skip_lwsp(line[db.len..]);
    if r.parts_read == 0 && rest.len == 1 && rest[0] == '\n' { r.nl_len = 1; }
    return rest == nl(r);
}

fn set_error(r: Reader&, code: i64, line: const u8[:]) -> i64 {
    r.err = code;
    r.detail.clear();
    r.detail.append(line);
    r.state = S_ERROR;
    return EV_ERROR;
}

// NextPart's loop over lines, up to a boundary line (to S_HEADERS), the
// final boundary (EV_END) or an error. -1 to go on.
fn lines(r: Reader&) -> i64 {
    if dash_boundary(r) == "--" { return set_error(r, mime::ERR_EMPTY_BOUNDARY, ""); }
    loop {
        let rest = r.buf[r.pos..];
        let lim = ::min(rest.len, PEEK_BUFFER_SIZE);
        var k = -1;
        for i in lim { if rest[i] == '\n' { k = i; break; } }
        var line_len = 0;
        var at_eof = false;
        if k >= 0 {
            line_len = k + 1;
        } else if rest.len >= PEEK_BUFFER_SIZE {
            return set_error(r, mime::ERR_NEXTPART_BUFFER_FULL, "");
        } else if !r.eof {
            return EV_NEED_MORE;
        } else {
            line_len = rest.len;
            at_eof = true;
        }
        let line = rest[..line_len];
        if at_eof {
            if is_final_boundary(r, line) { r.state = S_END; return EV_END; }
            return set_error(r, mime::ERR_NEXTPART_EOF, "");
        }
        r.pos += line_len;
        if is_boundary_delimiter_line(r, line) {
            r.parts_read++;
            r.state = S_HEADERS;
            r.hr = textproto::header_reader(r.pos, r.max_header_bytes, r.max_headers);
            r.header.fields.clear();
            r.seen.clear();
            return -1;
        }
        if is_final_boundary(r, line) { r.state = S_END; return EV_END; }
        if r.expect_new_part { return set_error(r, mime::ERR_EXPECTING_NEW_PART, line); }
        if r.parts_read == 0 { continue; }
        if line == nl(r) { r.expect_new_part = true; continue; }
        return set_error(r, mime::ERR_UNEXPECTED_LINE, line);
    }
}

// The part's header, then the part.
fn headers(r: Reader&) -> i64 {
    let code = textproto::read_mime_header_step(r.buf, r.hr, r.eof, r.header, r.detail, r.seen, true);
    if code == textproto::NEED_MORE { return EV_NEED_MORE; }
    let end = r.hr.pos;
    if code == mime::ERR_EOF { r.state = S_END; return EV_END; }       // Go's NextPart returns io.EOF
    if code == mime::ERR_MESSAGE_TOO_LARGE { return set_error(r, mime::ERR_MULTIPART_TOO_LARGE, ""); }
    if code != mime::OK {
        r.err = code;
        r.state = S_ERROR;
        return EV_ERROR;
    }
    r.pos = end;
    r.total = 0;
    r.part_err = 0;
    r.part_err_text.clear();
    r.qp_on = false;
    if !r.raw && mime::eq_fold(textproto::get(r.header, "Content-Transfer-Encoding"), "quoted-printable") {
        textproto::del(r.header, "Content-Transfer-Encoding");
        r.qp_on = true;
        r.qp = quotedprintable::new_reader();
    }
    r.disp = mime::parse_media_type(textproto::get(r.header, "Content-Disposition"));
    r.state = S_BODY;
    return EV_PART;
}

// matchAfterPrefix: +1 the boundary matches (then "--", white space, CR,
// LF or the end of input), -1 it does not, 0 more input is needed.
fn match_after_prefix(buf: const u8[:], plen: i64, read_err: bool) -> i64 {
    if buf.len == plen { return if read_err { 1 } else { 0 }; }
    let c = buf[plen];
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' { return 1; }
    if c == '-' {
        if buf.len == plen + 1 { return if read_err { -1 } else { 0 }; }
        if buf[plen + 1] == '-' { return 1; }
    }
    return -1;
}

// bytes.Index(buf, pat) for pat = nl_dash_boundary: memchr for its first
// byte, then a compare.
fn index_boundary(r: const Reader&, buf: const u8[:], pat: const u8[:]) -> i64 {
    var i = 0;
    while i + pat.len <= buf.len {
        let k = if pat[0] == '\r' { find_any(buf[i..buf.len - pat.len + 1], r.cr_set) }
                else { find_any(buf[i..buf.len - pat.len + 1], r.lf_set) };
        if k < 0 { return -1; }
        let at = i + k;
        if buf[at..at + pat.len] == pat { return at; }
        i = at + 1;
    }
    return -1;
}

// scanUntilBoundary: how many bytes of buf are body for certain, and
// whether the body ends after them (1: io.EOF, the boundary; 2: the input
// ended first, io.ErrUnexpectedEOF; 0 not yet).
fn scan_until_boundary(r: const Reader&, buf: const u8[:], total: i64, read_err: bool) -> i64, i64 {
    let rerr = if read_err { 2 } else { 0 };
    let db = dash_boundary(r);
    let ndb = nl_dash_boundary(r);
    if total == 0 {
        if has_prefix(buf, db) {
            let m = match_after_prefix(buf, db.len, read_err);
            if m == -1 { return db.len, 0; }
            if m == 0 { return 0, 0; }
            return 0, 1;
        }
        if has_prefix(db, buf) { return 0, rerr; }
    }
    let i = index_boundary(r, buf, ndb);
    if i >= 0 {
        let m = match_after_prefix(buf[i..], ndb.len, read_err);
        if m == -1 { return i + ndb.len, 0; }
        if m == 0 { return i, 0; }
        return i, 1;
    }
    if has_prefix(ndb, buf) { return 0, rerr; }
    var j = buf.len - 1;
    while j >= 0 && buf[j] != ndb[0] { j--; }
    if j >= 0 && has_prefix(ndb, buf[j..]) { return j, 0; }
    return buf.len, rerr;
}

fn end_part(r: Reader&, out: u8[>..]&, how: i64) -> i64 {
    var err = if how == 2 { mime::ERR_UNEXPECTED_EOF } else { 0 };
    if r.qp_on {
        let rc = quotedprintable::finish(r.qp, out, if how == 2 { mime::ERR_UNEXPECTED_EOF } else { mime::ERR_EOF });
        if rc != 0 { err = rc; quotedprintable::error_message(r.qp, r.part_err_text); }
    } else if err != 0 {
        r.part_err_text.append(mime::error_text(err));
    }
    r.part_err = err;
    r.state = S_LINES;
    r.expect_new_part = false;
    return EV_PART_END;
}

// The body: data, then its end.
fn body(r: Reader&, out: u8[>..]&) -> i64 {
    let window = r.buf[r.pos..];
    let n, how = scan_until_boundary(r, window, r.total, r.eof);
    if n > 0 {
        let data = window[..n];
        r.pos += n;
        r.total += n;
        if r.state == S_SKIP { return -1; }
        if r.qp_on {
            let rc = quotedprintable::decode(r.qp, out, data);
            if rc != 0 {
                quotedprintable::error_message(r.qp, r.part_err_text);
                r.part_err = rc;
                r.state = S_SKIP;
                return EV_PART_END;
            }
        } else {
            out.append(data);
        }
        return EV_DATA;
    }
    if how == 0 { return EV_NEED_MORE; }
    if r.state == S_SKIP { r.state = S_LINES; r.expect_new_part = false; return -1; }
    return end_part(r, out, how);
}

// The next event; body bytes go to out.
fn next(r: Reader&, out: u8[>..]&) -> i64 {
    loop {
        var ev = -1;
        if r.state == S_LINES { ev = lines(r); }
        else if r.state == S_HEADERS { ev = headers(r); }
        else if r.state == S_BODY || r.state == S_SKIP { ev = body(r, out); }
        else if r.state == S_END { return EV_END; }
        else { return EV_ERROR; }
        if ev >= 0 { return ev; }
    }
}

// Go's NextPart: past what is left of the current part, to the next
// EV_PART, EV_END, EV_ERROR or EV_NEED_MORE.
fn next_part(r: Reader&) -> i64 {
    var sink: u8[>..] = [];
    loop {
        sink.clear();
        let ev = next(r, sink);
        if ev == EV_PART || ev == EV_END || ev == EV_ERROR || ev == EV_NEED_MORE { return ev; }
    }
}

// Go's message for EV_ERROR.
fn message(r: const Reader&, out: u8[>..]&) {
    let c = r.err;
    if c == mime::ERR_EXPECTING_NEW_PART {
        out.append("multipart: expecting a new Part; got line ");
        mime::go_quote(out, r.detail);
    } else if c == mime::ERR_UNEXPECTED_LINE {
        out.append("multipart: unexpected line in Next(): ");
        mime::go_quote(out, r.detail);
    } else {
        textproto::error_message(out, c, r.detail);
    }
}

// Part.FormName: the "name" parameter of a form-data Content-Disposition.
fn form_name(r: const Reader&) -> const u8[:] {
    if r.disp.err != 0 || r.disp.typ != "form-data" { return ""; }
    return mime::get_or(r.disp, "name");
}

// Part.FileName: the "filename" parameter, through filepath.Base (RFC 7578
// §4.2: no directories).
fn file_name(r: const Reader&) -> const u8[:] {
    if r.disp.err != 0 { return ""; }
    let f = mime::get_or(r.disp, "filename");
    if f.len == 0 { return ""; }
    return base_name(f);
}

// filepath.Base: the last element of the path, its trailing separators
// removed; "." for "", the separator for one made of separators only.
// Windows' rules (both slashes, a volume name kept apart) when built for
// Windows, as Go's are.
fn base_name(path: const u8[:]) -> const u8[:] {
    let win = mime::is_windows();
    if path.len == 0 { return "."; }
    var p = path;
    if win { p = p[volume_name_len(p)..]; }
    var e = p.len;
    while e > 0 && (p[e - 1] == '/' || (win && p[e - 1] == '\\')) { e--; }
    if e == 0 { return if win { "\\" } else { "/" }; }
    var s = e;
    while s > 0 && !(p[s - 1] == '/' || (win && p[s - 1] == '\\')) { s--; }
    return p[s..e];
}

// filepath.VolumeName's length on Windows: "C:" or a UNC "\\host\share".
fn volume_name_len(p: const u8[:]) -> i64 {
    if p.len >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) { return 2; }
    let sep = p.len >= 2 && (p[0] == '/' || p[0] == '\\') && (p[1] == '/' || p[1] == '\\');
    if !sep || p.len < 3 || p[2] == '/' || p[2] == '\\' || p[2] == '.' || p[2] == '?' { return 0; }
    var n = 3;
    while n < p.len && p[n] != '/' && p[n] != '\\' { n++; }
    if n >= p.len { return p.len; }
    n++;
    if n >= p.len || p[n] == '/' || p[n] == '\\' { return 0; }
    while n < p.len && p[n] != '/' && p[n] != '\\' { n++; }
    return n;
}

// --- The writer --------------------------------------------------------------

struct Writer {
    boundary: u8[..70] = [],
    started: bool = false,       // a part has been created (Go's lastpart != nil)
}

// NewWriter: a writer with a random boundary (30 bytes from the OS, in hex).
fn new_writer() -> Writer {
    var w = Writer { .. };
    var raw: u8[30] = [0; 30];
    mime::random_bytes(raw);
    for b in raw { w.boundary.push(mime::LOWERHEX[b >> 4]); w.boundary.push(mime::LOWERHEX[b & 15]); }
    return w;
}

fn boundary(w: const Writer&) -> const u8[:] { w.boundary }

// SetBoundary: 1 to 70 bytes of RFC 2046's bchars, a space not last.
fn set_boundary(w: Writer&, b: const u8[:]) -> i64 {
    if w.started { return mime::ERR_SET_BOUNDARY_AFTER_WRITE; }
    if b.len < 1 || b.len > 70 { return mime::ERR_BOUNDARY_LENGTH; }
    var i = 0;
    while i < b.len {
        let c = b[i];
        let ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                 c == '\'' || c == '(' || c == ')' || c == '+' || c == '_' || c == ',' || c == '-' ||
                 c == '.' || c == '/' || c == ':' || c == '=' || c == '?' || (c == ' ' && i != b.len - 1);
        if !ok { return mime::ERR_BOUNDARY_CHARACTER; }
        i++;
    }
    w.boundary.clear();
    w.boundary.append(b);
    return 0;
}

// FormDataContentType: "multipart/form-data; boundary=...", the boundary
// quoted if it has a tspecial or a space.
fn form_data_content_type(w: const Writer&, out: u8[>..]&) {
    out.append("multipart/form-data; boundary=");
    var quote = false;
    for c in w.boundary {
        if c == '(' || c == ')' || c == '<' || c == '>' || c == '@' || c == ',' || c == ';' || c == ':' ||
           c == '\\' || c == '"' || c == '/' || c == '[' || c == ']' || c == '?' || c == '=' || c == ' ' {
            quote = true;
        }
    }
    if quote { out.push('"'); out.append(w.boundary); out.push('"'); } else { out.append(w.boundary); }
}

fn form_data_content_type(w: const Writer&) -> u8[>..] {
    var out: u8[>..] = [];
    form_data_content_type(w, out);
    return out;
}

// CreatePart: the boundary line and the header, its keys sorted (each
// key's values in their order), as written; the caller then appends the
// part's body to out.
fn create_part(w: Writer&, out: u8[>..]&, fields: const mime::KV[:]) {
    if w.started { out.append("\r\n--"); } else { out.append("--"); }
    out.append(w.boundary);
    out.append("\r\n");
    var order: i64[>..] = [];
    for i in fields.len { order.push(i); }
    stable_sort(order) { a, b => compare(fields[a].key, fields[b].key) < 0 };
    for i in order {
        out.append(fields[i].key);
        out.append(": ");
        out.append(fields[i].value);
        out.append("\r\n");
    }
    out.append("\r\n");
    w.started = true;
}

fn create_part(w: Writer&, out: u8[>..]&, h: const textproto::Header&) {
    var kvs: mime::KV[>..] = [];
    for f in h.fields { kvs.push(mime::KV { key: f.key, value: f.value }); }
    create_part(w, out, kvs);
}

// escapeQuotes: \ and " escaped, CR and LF percent-encoded.
fn escape_quotes(out: u8[>..]&, s: const u8[:]) {
    for c in s {
        if c == '\\' { out.append("\\\\"); }
        else if c == '"' { out.append("\\\""); }
        else if c == '\r' { out.append("%0D"); }
        else if c == '\n' { out.append("%0A"); }
        else { out.push(c); }
    }
}

// FileContentDisposition.
fn file_content_disposition(out: u8[>..]&, fieldname: const u8[:], filename: const u8[:]) {
    out.append("form-data; name=\"");
    escape_quotes(out, fieldname);
    out.append("\"; filename=\"");
    escape_quotes(out, filename);
    out.push('"');
}

fn file_content_disposition(fieldname: const u8[:], filename: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    file_content_disposition(out, fieldname, filename);
    return out;
}

// CreateFormFile: a part for a file field, application/octet-stream.
fn create_form_file(w: Writer&, out: u8[>..]&, fieldname: const u8[:], filename: const u8[:]) {
    var cd: u8[>..] = [];
    file_content_disposition(cd, fieldname, filename);
    create_part(w, out, [mime::KV { key: "Content-Disposition", value: cd },
                         mime::KV { key: "Content-Type", value: "application/octet-stream" }]);
}

// CreateFormField: a part for a plain field.
fn create_form_field(w: Writer&, out: u8[>..]&, fieldname: const u8[:]) {
    var cd: u8[>..] = [];
    cd.append("form-data; name=\"");
    escape_quotes(cd, fieldname);
    cd.push('"');
    create_part(w, out, [mime::KV { key: "Content-Disposition", value: cd }]);
}

// WriteField: a plain field and its value.
fn write_field(w: Writer&, out: u8[>..]&, fieldname: const u8[:], value: const u8[:]) {
    create_form_field(w, out, fieldname);
    out.append(value);
}

// Close: the final boundary line.
fn close(w: Writer&, out: u8[>..]&) {
    out.append("\r\n--");
    out.append(w.boundary);
    out.append("--\r\n");
    w.started = false;
}
