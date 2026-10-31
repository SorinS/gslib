// mime: MIME media types (RFC 2045, RFC 2046, RFC 2183) and their
// parameters (RFC 2231), as Go's mime package reads and writes them, plus
// the error codes and helpers that the other modules share.
//
//   mime.encodedword      RFC 2047 encoded-words: WordEncoder, WordDecoder
//   mime.types            file extensions and media types (Go's table, mime.types)
//   mime.quotedprintable  the quoted-printable coding (namespace quotedprintable)
//   mime.textproto        MIME header sections (namespace textproto)
//   mime.multipart        multipart bodies and forms (namespace multipart)
//
// Nothing here does I/O except mime.types reading the system's tables and
// multipart forms spilling large files to disk, as Go does.

namespace mime;

import std;
import dictionary;
import mime.unicode;

// --- Errors ------------------------------------------------------------------
//
// Every fallible function returns one of these codes (0 for success).
// error_text gives Go's message; the codes whose Go message carries a
// detail (a byte, a charset, a line) have a function beside the one that
// failed that writes the whole message.

let OK: i64 = 0;

// mime
let ERR_NO_MEDIA_TYPE: i64 = 1;
let ERR_NO_SLASH: i64 = 2;
let ERR_NO_TOKEN_AFTER_SLASH: i64 = 3;
let ERR_UNEXPECTED_CONTENT: i64 = 4;
let ERR_INVALID_MEDIA_PARAMETER: i64 = 5;    // Go's ErrInvalidMediaParameter: the type is still returned
let ERR_DUPLICATE_PARAM_NAME: i64 = 6;
let ERR_INVALID_WORD: i64 = 7;
let ERR_INVALID_HEX: i64 = 8;                // "mime: invalid hex byte %#02x"
let ERR_UNHANDLED_CHARSET: i64 = 9;          // "mime: unhandled charset %q"
let ERR_BASE64: i64 = 10;                    // "illegal base64 data at input byte %d"
let ERR_CHARSET: i64 = 11;                   // a CharsetReader block's own error
let ERR_EXTENSION_NO_DOT: i64 = 12;          // "mime: extension %q missing leading dot"

// quotedprintable
let ERR_QP_INVALID_HEX: i64 = 20;            // "quotedprintable: invalid hex byte 0x%02x"
let ERR_QP_UNESCAPED: i64 = 21;              // "quotedprintable: invalid unescaped byte 0x%02x in body"
let ERR_QP_AFTER_EQUALS: i64 = 22;           // "quotedprintable: invalid bytes after =: %q"
let ERR_UNEXPECTED_EOF: i64 = 23;            // io.ErrUnexpectedEOF
let ERR_BUFFER_FULL: i64 = 24;               // bufio.ErrBufferFull: a line longer than Go's 4096-byte buffer

// textproto
let ERR_MESSAGE_TOO_LARGE: i64 = 30;         // textproto's "message too large"
let ERR_MALFORMED_INITIAL_LINE: i64 = 31;    // "malformed MIME header initial line: %q"
let ERR_MALFORMED_LINE: i64 = 32;            // "malformed MIME header line: %q"
let ERR_MISSING_COLON: i64 = 33;             // "malformed MIME header: missing colon: %q"
let ERR_EOF: i64 = 34;                       // io.EOF where Go returns it as an error

// multipart
let ERR_MULTIPART_TOO_LARGE: i64 = 40;       // multipart.ErrMessageTooLarge
let ERR_EMPTY_BOUNDARY: i64 = 41;            // "multipart: boundary is empty"
let ERR_NEXTPART_EOF: i64 = 42;              // "multipart: NextPart: EOF"
let ERR_NEXTPART_BUFFER_FULL: i64 = 43;      // "multipart: NextPart: bufio: buffer full"
let ERR_EXPECTING_NEW_PART: i64 = 44;        // "multipart: expecting a new Part; got line %q"
let ERR_UNEXPECTED_LINE: i64 = 45;           // "multipart: unexpected line in Next(): %q"
let ERR_SET_BOUNDARY_AFTER_WRITE: i64 = 46;  // "mime: SetBoundary called after write"
let ERR_BOUNDARY_LENGTH: i64 = 47;           // "mime: invalid boundary length"
let ERR_BOUNDARY_CHARACTER: i64 = 48;        // "mime: invalid boundary character"
let ERR_FINISHED_PART: i64 = 49;             // "multipart: can't write to finished part"
let ERR_FILE: i64 = 50;                      // a temporary file could not be written or read

// Go's text for an error code, without the detail that some carry.
fn error_text(code: i64) -> const u8[:] {
    match code {
        OK => "",
        ERR_NO_MEDIA_TYPE => "mime: no media type",
        ERR_NO_SLASH => "mime: expected slash after first token",
        ERR_NO_TOKEN_AFTER_SLASH => "mime: expected token after slash",
        ERR_UNEXPECTED_CONTENT => "mime: unexpected content after media subtype",
        ERR_INVALID_MEDIA_PARAMETER => "mime: invalid media parameter",
        ERR_DUPLICATE_PARAM_NAME => "mime: duplicate parameter name",
        ERR_INVALID_WORD => "mime: invalid RFC 2047 encoded-word",
        ERR_INVALID_HEX => "mime: invalid hex byte",
        ERR_UNHANDLED_CHARSET => "mime: unhandled charset",
        ERR_BASE64 => "illegal base64 data at input byte",
        ERR_CHARSET => "mime: charset conversion failed",
        ERR_EXTENSION_NO_DOT => "mime: extension missing leading dot",
        ERR_QP_INVALID_HEX => "quotedprintable: invalid hex byte",
        ERR_QP_UNESCAPED => "quotedprintable: invalid unescaped byte in body",
        ERR_QP_AFTER_EQUALS => "quotedprintable: invalid bytes after =",
        ERR_UNEXPECTED_EOF => "unexpected EOF",
        ERR_BUFFER_FULL => "bufio: buffer full",
        ERR_MESSAGE_TOO_LARGE => "message too large",
        ERR_MALFORMED_INITIAL_LINE => "malformed MIME header initial line",
        ERR_MALFORMED_LINE => "malformed MIME header line",
        ERR_MISSING_COLON => "malformed MIME header: missing colon",
        ERR_EOF => "EOF",
        ERR_MULTIPART_TOO_LARGE => "multipart: message too large",
        ERR_EMPTY_BOUNDARY => "multipart: boundary is empty",
        ERR_NEXTPART_EOF => "multipart: NextPart: EOF",
        ERR_NEXTPART_BUFFER_FULL => "multipart: NextPart: bufio: buffer full",
        ERR_EXPECTING_NEW_PART => "multipart: expecting a new Part",
        ERR_UNEXPECTED_LINE => "multipart: unexpected line in Next()",
        ERR_SET_BOUNDARY_AFTER_WRITE => "mime: SetBoundary called after write",
        ERR_BOUNDARY_LENGTH => "mime: invalid boundary length",
        ERR_BOUNDARY_CHARACTER => "mime: invalid boundary character",
        ERR_FINISHED_PART => "multipart: can't write to finished part",
        ERR_FILE => "multipart: temporary file error",
        _ => "mime: unknown error",
    }
}

// Whether the program is built for Windows (mime/src/path.c): multipart's
// file names and mime.types depend on it.
extern fn mime_path_windows() -> i64;
fn is_windows() -> bool { mime_path_windows() != 0 }

// --- Grammar (RFC 2045 §5.1) -------------------------------------------------

// tspecials := "(" / ")" / "<" / ">" / "@" / "," / ";" / ":" / "\" / <">
//              "/" / "[" / "]" / "?" / "="
fn is_tspecial(c: u8) -> bool {
    c == '(' || c == ')' || c == '<' || c == '>' || c == '@' || c == ',' || c == ';' ||
    c == ':' || c == '\\' || c == '"' || c == '/' || c == '[' || c == ']' || c == '?' || c == '='
}

// token := 1*<any (US-ASCII) CHAR except SPACE, CTLs, or tspecials>
fn is_token_char(c: u8) -> bool { c > 0x20 && c < 0x7f && !is_tspecial(c) }

fn is_token(s: const u8[:]) -> bool {
    if s.len == 0 { return false; }
    for c in s { if !is_token_char(c) { return false; } }
    return true;
}

fn lower_byte(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }
fn upper_byte(c: u8) -> u8 { if c >= 'a' && c <= 'z' { c - 32 } else { c } }

// ASCII case-insensitive equality (Go's strings.EqualFold restricted to the
// ASCII the callers compare against).
fn eq_fold_ascii(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len { if lower_byte(a[i]) != lower_byte(b[i]) { return false; } }
    return true;
}

fn append_lower(out: u8[>..]&, s: const u8[:]) { for c in s { out.push(lower_byte(c)); } }

fn index_byte(s: const u8[:], c: u8) -> i64 {
    for i in s.len { if s[i] == c { return i; } }
    return -1;
}

fn is_hex(c: u8) -> bool { (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }

fn unhex(c: u8) -> u8 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return 0;
}

let UPPERHEX = "0123456789ABCDEF";
let LOWERHEX = "0123456789abcdef";

fn push_hex_upper(out: u8[>..]&, c: u8) { out.push(UPPERHEX[c >> 4]); out.push(UPPERHEX[c & 15]); }

// --- UTF-8 and Unicode, as Go's unicode/utf8 see them ----------------------

let RUNE_ERROR: i64 = 0xFFFD;

// The rune at s[i] and its length in bytes, as utf8.DecodeRune: an invalid
// or cut-short sequence is (RuneError, 1).
fn decode_rune(s: const u8[:], i: i64) -> i64, i64 {
    if i >= s.len { return RUNE_ERROR, 0; }
    let c0 = s[i];
    if c0 < 0x80 { return c0, 1; }
    if c0 < 0xC2 || c0 > 0xF4 { return RUNE_ERROR, 1; }
    var lo: u8 = 0x80;
    var hi: u8 = 0xBF;
    if c0 == 0xE0 { lo = 0xA0; } else if c0 == 0xED { hi = 0x9F; }
    else if c0 == 0xF0 { lo = 0x90; } else if c0 == 0xF4 { hi = 0x8F; }
    if i + 1 >= s.len { return RUNE_ERROR, 1; }
    let c1 = s[i + 1];
    if c1 < lo || c1 > hi { return RUNE_ERROR, 1; }
    let b0: i64 = c0;
    let b1: i64 = c1 & 0x3F;
    if c0 < 0xE0 { return ((b0 & 0x1F) << 6) | b1, 2; }
    if i + 2 >= s.len { return RUNE_ERROR, 1; }
    let c2 = s[i + 2];
    if c2 < 0x80 || c2 > 0xBF { return RUNE_ERROR, 1; }
    let b2: i64 = c2 & 0x3F;
    if c0 < 0xF0 { return ((b0 & 0x0F) << 12) | (b1 << 6) | b2, 3; }
    if i + 3 >= s.len { return RUNE_ERROR, 1; }
    let c3 = s[i + 3];
    if c3 < 0x80 || c3 > 0xBF { return RUNE_ERROR, 1; }
    let b3: i64 = c3 & 0x3F;
    return ((b0 & 0x07) << 18) | (b1 << 12) | (b2 << 6) | b3, 4;
}

// The rune that ends at s[..end] and its length, as utf8.DecodeLastRune.
fn decode_last_rune(s: const u8[:], end: i64) -> i64, i64 {
    if end <= 0 { return RUNE_ERROR, 0; }
    if s[end - 1] < 0x80 { return s[end - 1], 1; }
    var start = end - 1;
    let lim = ::max(end - 4, 0);
    while start > lim && (s[start] & 0xC0) == 0x80 { start--; }
    let r, size = decode_rune(s[..end], start);
    if start + size != end { return RUNE_ERROR, 1; }
    return r, size;
}

// UTF-8 for a rune (a surrogate or out-of-range rune as U+FFFD, as Go writes them).
fn push_rune(out: u8[>..]&, r0: i64) {
    var r = r0;
    if r < 0 || r > 0x10FFFF || (r >= 0xD800 && r <= 0xDFFF) { r = RUNE_ERROR; }
    if r < 0x80 { out.push(r as u8); return; }
    if r < 0x800 { out.push((0xC0 | (r >> 6)) as u8); out.push((0x80 | (r & 0x3F)) as u8); return; }
    if r < 0x10000 {
        out.push((0xE0 | (r >> 12)) as u8); out.push((0x80 | ((r >> 6) & 0x3F)) as u8);
        out.push((0x80 | (r & 0x3F)) as u8);
        return;
    }
    out.push((0xF0 | (r >> 18)) as u8); out.push((0x80 | ((r >> 12) & 0x3F)) as u8);
    out.push((0x80 | ((r >> 6) & 0x3F)) as u8); out.push((0x80 | (r & 0x3F)) as u8);
}

// unicode.IsSpace.
fn is_space_rune(r: i64) -> bool {
    if r < 0x80 { return r == ' ' || (r >= 0x09 && r <= 0x0D); }
    if r == 0x85 || r == 0xA0 || r == 0x1680 || r == 0x2028 || r == 0x2029 || r == 0x202F ||
       r == 0x205F || r == 0x3000 { return true; }
    return r >= 0x2000 && r <= 0x200A;
}

// The index of the first rune of s from `from` that is not a Unicode space
// (strings.TrimLeftFunc(s, unicode.IsSpace)).
fn skip_space(s: const u8[:], from: i64) -> i64 {
    var i = from;
    while i < s.len {
        let c = s[i];
        if c < 0x80 {
            if c == ' ' || (c >= 0x09 && c <= 0x0D) { i++; continue; }
            return i;
        }
        let r, n = decode_rune(s, i);
        if !is_space_rune(r) { return i; }
        i += n;
    }
    return i;
}

// The end of s without its trailing Unicode spaces.
fn trim_space_end(s: const u8[:], from: i64, end: i64) -> i64 {
    var e = end;
    while e > from {
        let r, n = decode_last_rune(s[from..e], e - from);
        if !is_space_rune(r) { break; }
        e -= n;
    }
    return e;
}

// strings.TrimSpace.
fn trim_space(s: const u8[:]) -> const u8[:] {
    let a = skip_space(s, 0);
    let b = trim_space_end(s, a, s.len);
    return s[a..b];
}

// strings.ToLower as far as an ASCII grammar can see it: ASCII letters fold,
// U+0130 and U+212A fold to 'i' and 'k' as Go's tables have them, and every
// other non-ASCII rune (or invalid byte) becomes 0x80, which no token holds.
fn append_unicode_lower(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c < 0x80 { out.push(lower_byte(c)); i++; continue; }
        let r, n = decode_rune(s, i);
        if r == 0x130 { out.push('i'); } else if r == 0x212A { out.push('k'); } else { out.push(0x80); }
        i += n;
    }
}

// strings.ToLower: every rune lowered by Go's tables, invalid bytes as U+FFFD.
fn go_to_lower(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c < 0x80 { out.push(lower_byte(c)); i++; continue; }
        let r, n = decode_rune(s, i);
        push_rune(out, to_lower_rune(r));
        i += n;
    }
}

// strings.EqualFold(s, t) for a t of lower-case ASCII: Unicode simple case
// folding puts only U+212A (Kelvin) with 'k' and U+017F (long s) with 's'
// beside the ASCII letters.
fn eq_fold(s: const u8[:], t: const u8[:]) -> bool {
    var i = 0;
    var j = 0;
    while i < s.len {
        if j >= t.len { return false; }
        let c = s[i];
        if c < 0x80 {
            if lower_byte(c) != t[j] { return false; }
            i++;
        } else {
            let r, n = decode_rune(s, i);
            if !((r == 0x212A && t[j] == 'k') || (r == 0x17F && t[j] == 's')) { return false; }
            i += n;
        }
        j++;
    }
    return j == t.len;
}

// --- Go's %q (strconv.Quote), for the error messages that quote input -----

// Writes s as strconv.Quote does: printable runes as they are, the usual
// backslash escapes, \x for invalid bytes, \u and \U for unprintable runes.
fn go_quote(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c >= 0x80 {
            let r, n = decode_rune(s, i);
            if n == 1 { out.append("\\x"); out.push(LOWERHEX[c >> 4]); out.push(LOWERHEX[c & 15]); i++; continue; }
            if is_print(r) { out.append(s[i..i + n]); }
            else if r < 0x10000 { out.append("\\u"); push_hex_digits(out, r, 4); }
            else { out.append("\\U"); push_hex_digits(out, r, 8); }
            i += n;
            continue;
        }
        if c == '"' || c == '\\' { out.push('\\'); out.push(c); }
        else if c >= 0x20 && c < 0x7F { out.push(c); }
        else if c == 0x07 { out.append("\\a"); }
        else if c == 0x08 { out.append("\\b"); }
        else if c == 0x0C { out.append("\\f"); }
        else if c == '\n' { out.append("\\n"); }
        else if c == '\r' { out.append("\\r"); }
        else if c == '\t' { out.append("\\t"); }
        else if c == 0x0B { out.append("\\v"); }
        else { out.append("\\x"); out.push(LOWERHEX[c >> 4]); out.push(LOWERHEX[c & 15]); }
        i++;
    }
    out.push('"');
}

fn push_hex_digits(out: u8[>..]&, v: i64, digits: i64) {
    var k = digits - 1;
    while k >= 0 { out.push(LOWERHEX[(v >> (4 * k)) & 15]); k--; }
}

// --- Media types --------------------------------------------------------------

// A parameter of a media type, its name in lower case.
struct Param { name: u8[varint], value: u8[varint] }

// A parameter to format: a view of the caller's name and value.
struct KV { key: const u8[:], value: const u8[:] }

// ParseMediaType's result: err, the media type (lower case, trimmed; ""
// on an error other than ERR_INVALID_MEDIA_PARAMETER), and the parameters
// sorted by name (none on any error).
struct MediaType { err: i64, typ: u8[varint], params: Param[>..] }

// The value of the parameter `name` (lower case), and whether it is there.
fn param(mt: const MediaType&, name: const u8[:]) -> const u8[:], bool {
    for p in mt.params { if p.name == name { return p.value, true; } }
    return "", false;
}

// The value of `name`, "" when it is absent (Go's params[name]).
fn get_or(mt: const MediaType&, name: const u8[:]) -> const u8[:] {
    let v, ok = param(mt, name);
    return v;
}

fn param_count(mt: const MediaType&) -> i64 { mt.params.len }

// consumeToken: the end of the token at v[pos..] (pos itself if none).
fn consume_token(v: const u8[:], pos: i64) -> i64 {
    var i = pos;
    while i < v.len && is_token_char(v[i]) { i++; }
    return i;
}

// checkMediaTypeDisposition.
fn check_media_type(s: const u8[:]) -> i64 {
    var i = consume_token(s, 0);
    if i == 0 { return ERR_NO_MEDIA_TYPE; }
    if i == s.len { return OK; }
    if s[i] != '/' { return ERR_NO_SLASH; }
    i++;
    let sub = i;
    i = consume_token(s, i);
    if i == sub { return ERR_NO_TOKEN_AFTER_SLASH; }
    if i != s.len { return ERR_UNEXPECTED_CONTENT; }
    return OK;
}

struct Span { pos: i64, end: i64 }

// A parameter while parsing: its name and value in the arena.
struct Ent { key: Span, val: Span }

// A parameter of the result: its name, and its value in the arena.
struct Out { key: const u8[:], val: Span }

// consumeValue: a token, or a quoted-string with its escapes undone (a
// backslash escapes only a tspecial; CR or LF ends it in failure). The
// value goes into arena; returns the index after it, or -1.
fn consume_value(v: const u8[:], pos: i64, arena: u8[>..]&) -> i64 {
    if pos >= v.len { return -1; }
    if v[pos] != '"' {
        var i = pos;
        while i < v.len && is_token_char(v[i]) { i++; }
        if i == pos { return -1; }
        arena.append(v[pos..i]);
        return i;
    }
    let mark = arena.len;
    var i = pos + 1;
    while i < v.len {
        let r = v[i];
        if r == '"' { return i + 1; }
        if r == '\\' && i + 1 < v.len && is_tspecial(v[i + 1]) {
            arena.push(v[i + 1]);
            i += 2;
            continue;
        }
        if r == '\r' || r == '\n' { arena.resize(mark); return -1; }
        arena.push(r);
        i++;
    }
    arena.resize(mark);
    return -1;
}

// consumeMediaParam at v[pos..]: "; name = value". Appends the name (lower
// case) and value to the arena; the index after it, or -1.
fn consume_media_param(v: const u8[:], pos: i64, arena: u8[>..]&, e: Ent&) -> i64 {
    var i = skip_space(v, pos);
    if i >= v.len || v[i] != ';' { return -1; }
    i = skip_space(v, i + 1);
    let k0 = i;
    while i < v.len && is_token_char(v[i]) { i++; }
    if i == k0 { return -1; }
    let mark = arena.len;
    append_lower(arena, v[k0..i]);
    e.key = Span { pos: mark, end: arena.len };
    i = skip_space(v, i);
    if i >= v.len || v[i] != '=' { arena.resize(mark); return -1; }
    i = skip_space(v, i + 1);
    let vmark = arena.len;
    let after = consume_value(v, i, arena);
    if after < 0 { arena.resize(mark); return -1; }
    e.val = Span { pos: vmark, end: arena.len };
    return after;
}

// percentHexUnescape: every '%' must have two hex digits after it.
fn percent_hex_unescape(out: u8[>..]&, s: const u8[:]) -> bool {
    var i = 0;
    while i < s.len {
        if s[i] != '%' { i++; continue; }
        if i + 2 >= s.len || !is_hex(s[i + 1]) || !is_hex(s[i + 2]) { return false; }
        i += 3;
    }
    i = 0;
    while i < s.len {
        if s[i] == '%' { out.push((unhex(s[i + 1]) << 4) | unhex(s[i + 2])); i += 3; }
        else { out.push(s[i]); i++; }
    }
    return true;
}

// decode2231Enc: charset'language'percent-encoded, for the charsets
// us-ascii and utf-8 only (compared as strings.ToLower does).
fn decode_2231(out: u8[>..]&, v: const u8[:]) -> bool {
    let q1 = index_byte(v, '\'');
    if q1 < 0 { return false; }
    let rest = v[q1 + 1..];
    let q2 = index_byte(rest, '\'');
    if q2 < 0 { return false; }
    var cs: u8[>..] = [];
    append_unicode_lower(cs, v[..q1]);
    if cs != "us-ascii" && cs != "utf-8" { return false; }
    let mark = out.len;
    if !percent_hex_unescape(out, rest[q2 + 1..]) { out.resize(mark); return false; }
    return true;
}

// ParseMediaType: a media type and its parameters (RFC 1521, RFC 2231),
// with Go's leniencies (MSIE's unescaped backslashes, trailing semicolons,
// repeated parameters with the same value) and its errors.
fn parse_media_type(v: const u8[:]) -> MediaType {
    var semi = index_byte(v, ';');
    if semi < 0 { semi = v.len; }
    let b0 = skip_space(v, 0);
    let b1 = trim_space_end(v, b0, semi);
    var typ: u8[>..] = [];
    append_unicode_lower(typ, v[b0..b1]);
    let e0 = check_media_type(typ);
    if e0 != OK { return MediaType { err: e0, typ: "", params: [] }; }

    var arena: u8[>..] = [];
    var ents: Ent[>..] = [];
    var seen = dictionary<const u8[:], i64> {};      // key -> index in ents
    var bases: Span[>..] = [];                       // continuation base names
    var tmp: u8[>..] = [];
    var base_seen = dictionary<const u8[:], bool> {};
    var pos = semi;
    while pos < v.len {
        pos = skip_space(v, pos);
        if pos >= v.len { break; }
        var e = Ent { key: Span { pos: 0, end: 0 }, val: Span { pos: 0, end: 0 } };
        tmp.clear();
        let after = consume_media_param(v, pos, tmp, e);
        if after < 0 {
            if trim_space(v[pos..]) == ";" { break; }       // trailing semicolons
            return MediaType { err: ERR_INVALID_MEDIA_PARAMETER, typ: typ[..], params: [] };
        }
        let at = arena.len;
        arena.append(tmp);
        e.key = Span { pos: at + e.key.pos, end: at + e.key.end };
        e.val = Span { pos: at + e.val.pos, end: at + e.val.end };
        let key = arena[e.key.pos..e.key.end];
        let val = arena[e.val.pos..e.val.end];
        let prev = seen.get(key);
        if prev {
            let pe = ents[prev];
            if arena[pe.val.pos..pe.val.end] != val {
                return MediaType { err: ERR_DUPLICATE_PARAM_NAME, typ: "", params: [] };
            }
            ents[prev].val = e.val;
        } else {
            seen.insert(key, ents.len);
            ents.push(e);
            let star = index_byte(key, '*');
            if star >= 0 {
                let base = key[..star];
                if !base_seen.contains(base) {
                    base_seen.insert(base, true);
                    bases.push(Span { pos: e.key.pos, end: e.key.pos + star });
                }
            }
        }
        pos = after;
    }

    // The result: plain parameters, then the stitched RFC 2231 ones over them.
    var result = dictionary<const u8[:], Span> {};
    for e in ents {
        let key = arena[e.key.pos..e.key.end];
        if index_byte(key, '*') < 0 { result.insert(key, e.val); }
    }
    var name: u8[>..] = [];
    for b in bases {
        let base = arena[b.pos..b.end];
        name.clear();
        name.append(base);
        name.push('*');
        let single = seen.get(name);
        if single {
            let sv = ents[single].val;
            tmp.clear();
            if decode_2231(tmp, arena[sv.pos..sv.end]) {
                let mark = arena.len;
                arena.append(tmp);
                let got .= result.get_or_insert(base, Span { pos: 0, end: 0 });
                got = Span { pos: mark, end: arena.len };
            }
            continue;
        }
        var valid = false;
        let mark = arena.len;
        var n = 0;
        loop {
            name.clear();
            format(name, base, "*", n);
            let simple = seen.get(name);
            if simple {
                valid = true;
                let sv = ents[simple].val;
                arena.append(arena[sv.pos..sv.end]);
                n++;
                continue;
            }
            name.push('*');
            let enc = seen.get(name);
            if !enc { break; }
            valid = true;
            let ev = ents[enc].val;
            tmp.clear();
            let ok = if n == 0 { decode_2231(tmp, arena[ev.pos..ev.end]) } else { percent_hex_unescape(tmp, arena[ev.pos..ev.end]) };
            if ok { arena.append(tmp); }
            n++;
        }
        if valid {
            let got .= result.get_or_insert(base, Span { pos: 0, end: 0 });
            got = Span { pos: mark, end: arena.len };
        }
    }

    var outs: Out[>..] = [];
    result.each() { k, s => outs.push(Out { key: k, val: s }); };
    sort(outs) { a, b => compare(a.key, b.key) < 0 };
    var mt = MediaType { err: OK, typ: typ[..], params: [] };
    for o in outs { mt.params.push(Param { name: o.key, value: arena[o.val.pos..o.val.end] }); }
    return mt;
}

// FormatMediaType: the type (lower case) and the parameters sorted by
// name, each value a token, a quoted-string, or RFC 2231's utf-8''
// percent-encoding when it holds a control (other than tab) or a non-ASCII
// byte. Appends to out; false (out unchanged) when the type or a name is
// not a token. The names must be distinct, as a Go map's keys are.
fn format_media_type(out: u8[>..]&, t: const u8[:], params: const KV[:]) -> bool {
    let mark = out.len;
    let slash = index_byte(t, '/');
    if slash < 0 {
        if !is_token(t) { return false; }
        append_lower(out, t);
    } else {
        if !is_token(t[..slash]) || !is_token(t[slash + 1..]) { return false; }
        append_lower(out, t);
    }
    var order: i64[>..] = [];
    for i in params.len { order.push(i); }
    sort(order) { a, b => compare(params[a].key, params[b].key) < 0 };
    for i in order {
        let attribute = params[i].key;
        let value = params[i].value;
        out.append("; ");
        if !is_token(attribute) { out.resize(mark); return false; }
        append_lower(out, attribute);
        if needs_encoding(value) {
            out.append("*=utf-8''");
            for ch in value {
                if ch <= ' ' || ch >= 0x7F || ch == '*' || ch == '\'' || ch == '%' || is_tspecial(ch) {
                    out.push('%');
                    push_hex_upper(out, ch);
                } else {
                    out.push(ch);
                }
            }
            continue;
        }
        out.push('=');
        if is_token(value) { out.append(value); continue; }
        out.push('"');
        for ch in value {
            if ch == '"' || ch == '\\' { out.push('\\'); }
            out.push(ch);
        }
        out.push('"');
    }
    return true;
}

// The same, as a fresh string ("" on failure, as Go returns).
fn format_media_type(t: const u8[:], params: const KV[:]) -> u8[>..] {
    var out: u8[>..] = [];
    format_media_type(out, t, params);
    return out;
}

// FormatMediaType of a parsed media type's own parameters.
fn format_media_type(out: u8[>..]&, t: const u8[:], mt: const MediaType&) -> bool {
    var kvs: KV[>..] = [];
    for p in mt.params { kvs.push(KV { key: p.name, value: p.value }); }
    return format_media_type(out, t, kvs);
}

// needsEncoding: a byte outside printable ASCII other than tab (Go walks
// runes, and every non-ASCII rune or invalid byte is past '~').
fn needs_encoding(s: const u8[:]) -> bool {
    for b in s { if (b < ' ' || b > '~') && b != '\t' { return true; } }
    return false;
}

// The message of a parse_media_type error.
fn media_type_error(code: i64) -> const u8[:] { error_text(code) }
