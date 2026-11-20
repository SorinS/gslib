// quic.qpack: QPACK (RFC 9204), the field compression of HTTP/3, without
// I/O, as a side that uses no dynamic table: it advertises
// SETTINGS_QPACK_MAX_TABLE_CAPACITY 0 and QPACK_BLOCKED_STREAMS 0, so the
// peer may refer to the static table only, and it encodes with the static
// table only. That is conformant both ways, and what quic-go does.
//
//   var out: u8[>..] = [];
//   quic::qpack_begin(out);                         // Required Insert Count 0, Base 0
//   quic::qpack_field(out, ":method", "GET", false);
//
//   var fields: u8[>..] = [];
//   let e = quic::qpack_decode(section, 65536, fields);    // QPACK_OK, ...
//   quic::each_qpack_field(fields) { name, value, never => ... };
//   let v = quic::validate_request(fields);                // FIELDS_OK, ...
//
// The peer's encoder stream may only set the capacity to 0; any insert is
// QPACK_ENCODER_STREAM_ERROR. Its decoder stream may cancel streams; a
// Section Acknowledgment or an Insert Count Increment, for entries never
// inserted, is QPACK_DECODER_STREAM_ERROR. Both streams' instructions may
// arrive in pieces: qpack_encoder_stream and qpack_decoder_stream take
// what is complete and say how much.
//
// Fields decoded go to a buffer as records (u32 name length, u32 value
// length, u8 1 if never to be indexed, the name, the value), read with
// each_qpack_field; qpack_record writes one, so a caller builds field
// lists for h3's requests and responses the same way.

namespace quic;

import std;

// The error codes (§6), as the connection closes with them.
let QPACK_DECOMPRESSION_FAILED: i64 = 0x200;
let QPACK_ENCODER_STREAM_ERROR: i64 = 0x201;
let QPACK_DECODER_STREAM_ERROR: i64 = 0x202;

let QPACK_OK: i64 = 0;
let QPACK_TOO_LARGE: i64 = 1;          // the section passes the limit (§4.2.2 of RFC 9114's measure)

// The static table (Appendix A): 99 entries, names then values ("" for none).
let QPACK_STATIC_NAMES: const u8[:][99] = [
    ":authority", ":path", "age", "content-disposition", "content-length", "cookie", "date", "etag",
    "if-modified-since", "if-none-match", "last-modified", "link", "location", "referer", "set-cookie",
    ":method", ":method", ":method", ":method", ":method", ":method", ":method",
    ":scheme", ":scheme", ":status", ":status", ":status", ":status", ":status",
    "accept", "accept", "accept-encoding", "accept-ranges", "access-control-allow-headers",
    "access-control-allow-headers", "access-control-allow-origin", "cache-control", "cache-control",
    "cache-control", "cache-control", "cache-control", "cache-control", "content-encoding",
    "content-encoding", "content-type", "content-type", "content-type", "content-type", "content-type",
    "content-type", "content-type", "content-type", "content-type", "content-type", "content-type",
    "range", "strict-transport-security", "strict-transport-security", "strict-transport-security",
    "vary", "vary", "x-content-type-options", "x-xss-protection", ":status", ":status", ":status",
    ":status", ":status", ":status", ":status", ":status", ":status", "accept-language",
    "access-control-allow-credentials", "access-control-allow-credentials", "access-control-allow-headers",
    "access-control-allow-methods", "access-control-allow-methods", "access-control-allow-methods",
    "access-control-expose-headers", "access-control-request-headers", "access-control-request-method",
    "access-control-request-method", "alt-svc", "authorization", "content-security-policy", "early-data",
    "expect-ct", "forwarded", "if-range", "origin", "purpose", "server", "timing-allow-origin",
    "upgrade-insecure-requests", "user-agent", "x-forwarded-for", "x-frame-options", "x-frame-options",
];

let QPACK_STATIC_VALUES: const u8[:][99] = [
    "", "/", "0", "", "0", "", "", "",
    "", "", "", "", "", "", "",
    "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT",
    "http", "https", "103", "200", "304", "404", "503",
    "*/*", "application/dns-message", "gzip, deflate, br", "bytes", "cache-control",
    "content-type", "*", "max-age=0", "max-age=2592000",
    "max-age=604800", "no-cache", "no-store", "public, max-age=31536000", "br",
    "gzip", "application/dns-message", "application/javascript", "application/json", "application/x-www-form-urlencoded", "image/gif",
    "image/jpeg", "image/png", "text/css", "text/html; charset=utf-8", "text/plain", "text/plain;charset=utf-8",
    "bytes=0-", "max-age=31536000", "max-age=31536000; includesubdomains", "max-age=31536000; includesubdomains; preload",
    "accept-encoding", "origin", "nosniff", "1; mode=block", "100", "204", "206",
    "302", "400", "403", "421", "425", "500", "",
    "FALSE", "TRUE", "*",
    "get", "get, post, options", "options",
    "content-length", "content-type", "get",
    "post", "clear", "", "script-src 'none'; object-src 'none'; base-uri 'none'", "1",
    "", "", "", "", "prefetch", "", "*",
    "1", "", "", "deny", "sameorigin",
];

// --- Integers and strings (§4.1) -----------------------------------------------

// A prefix integer of n bits at pos: the value and where it ends; end -1
// if it is more than 2^62 - 1 or the input ends first (more may come).
fn qpack_int(b: const u8[:], pos: i64, n: i64) -> i64, i64 {
    if pos >= b.len { return 0, -1; }
    let mask = (1 << n) - 1;
    var v = b[pos] & mask;
    var p = pos + 1;
    if v < mask { return v, p; }
    var shift = 0;
    while true {
        if p >= b.len { return 0, -1; }
        let c = (b[p] as i64) & 0x7f;
        let more = (b[p] & 0x80) != 0;
        p++;
        if c != 0 {
            if shift > 55 { return 0, -2; }
            v += c << shift;
            if v > 0x3fffffffffffffff { return 0, -2; }
        }
        shift += 7;
        if !more { return v, p; }
        if shift > 63 { return 0, -2; }
    }
    return 0, -2;
}

// first holds the bits above the prefix of n bits.
fn qpack_put_int(out: u8[>..]&, first: u8, n: i64, v: i64) {
    let mask = (1 << n) - 1;
    if v < mask { out.push(first | (v as! u8)); return; }
    out.push(first | (mask as! u8));
    var r = v - mask;
    while r >= 128 { out.push(((r & 0x7f) | 0x80) as! u8); r = r >> 7; }
    out.push(r as! u8);
}

// A string literal at pos whose length has a prefix of n bits, the bit
// above them (hbit) saying Huffman, decoded onto out: where it ends, -1 if
// the input ends first, -2 if it is malformed. limit bounds its length.
fn qpack_string(b: const u8[:], pos: i64, n: i64, hbit: u8, limit: i64, out: u8[>..]&) -> i64 {
    if pos >= b.len { return -1; }
    let huff = (b[pos] & hbit) != 0;
    let len, p = qpack_int(b, pos, n);
    if p < 0 { return p; }
    if len > limit { return -2; }
    if len > b.len - p { return -1; }
    if !huff { out.append(b[p..p + len]); return p + len; }
    if !qpack_huffman_decode(b[p..p + len], out) { return -2; }
    return p + len;
}

// A string literal: Huffman when that is shorter. hbit is the Huffman
// flag, the length's prefix the n bits below it; first the bits above.
fn qpack_put_string(out: u8[>..]&, first: u8, n: i64, hbit: u8, s: const u8[:], huff: bool) {
    let h = qpack_huffman_length(s);
    if huff && h < s.len {
        qpack_put_int(out, first | hbit, n, h);
        qpack_huffman_encode(out, s);
    } else {
        qpack_put_int(out, first, n, s.len);
        out.append(s);
    }
}

// --- Huffman (RFC 7541 Appendix B, as QPACK uses it) ------------------------------

// Appends the decoding of s: false if it holds EOS, a code that does not
// end, or padding longer than 7 bits or not all ones.
fn qpack_huffman_decode(s: const u8[:], out: u8[>..]&) -> bool {
    var code: u32 = 0;
    var len: i64 = 0;
    var ones = true;                    // the bits since the last symbol are all 1
    for byte in s {
        var bit = 7;
        while bit >= 0 {
            let x = ((byte >> (bit as! u8)) & 1) as u32;
            bit--;
            code = (code << 1) | x;
            len++;
            if x == 0 { ones = false; }
            if len > 30 { return false; }
            let cnt = QHUFF_COUNT[len] as u32;
            if cnt > 0 && code >= QHUFF_FIRST[len] && code - QHUFF_FIRST[len] < cnt {
                let sym = QHUFF_SYMS[(QHUFF_OFFSET[len] as i64) + (code - QHUFF_FIRST[len])];
                if sym == 256 { return false; }
                out.push(sym as! u8);
                code = 0;
                len = 0;
                ones = true;
            }
        }
    }
    return len <= 7 && ones;
}

fn qpack_huffman_length(s: const u8[:]) -> i64 {
    var bits: i64 = 0;
    for c in s { bits += QHUFF_LEN[c]; }
    return (bits + 7) / 8;
}

fn qpack_huffman_encode(out: u8[>..]&, s: const u8[:]) {
    var acc: u64 = 0;
    var n: i64 = 0;
    for c in s {
        let l = QHUFF_LEN[c] as i64;
        acc = (acc << (l as! u64)) | QHUFF_CODE[c];
        n += l;
        while n >= 8 {
            n -= 8;
            out.push(((acc >> (n as! u64)) & 0xff) as! u8);
        }
    }
    if n > 0 {
        // Padded with the high bits of EOS: ones.
        let padn = 8 - n;
        out.push((((acc << (padn as! u64)) | ((1 << (padn as! u64)) - 1)) & 0xff) as! u8);
    }
}

// --- Field records -------------------------------------------------------------

// One field onto a record buffer: u32 name length, u32 value length, u8 1
// if it must never be indexed (the N bit), the name, the value.
fn qpack_record(out: u8[>..]&, name: const u8[:], value: const u8[:], never: bool = false) {
    for k in 4 { out.push(((name.len >> ((3 - k) * 8)) & 0xff) as! u8); }
    for k in 4 { out.push(((value.len >> ((3 - k) * 8)) & 0xff) as! u8); }
    out.push(if never { 1 } else { 0 });
    out.append(name);
    out.append(value);
}

// F(name, value, never) for each record.
fn each_qpack_field<F>(recs: const u8[:]) {
    var p = 0;
    while p + 9 <= recs.len {
        var n: i64 = 0;
        var v: i64 = 0;
        for k in 4 { n = (n << 8) | recs[p + k]; }
        for k in 4 { v = (v << 8) | recs[p + 4 + k]; }
        let never = recs[p + 8] == 1;
        let at = p + 9;
        F(recs[at..at + n], recs[at + n..at + n + v], never);
        p = at + n + v;
    }
}

// The value of the first record named name, and whether there is one.
fn qpack_get(recs: const u8[:], name: const u8[:]) -> const u8[:], bool {
    var p = 0;
    while p + 9 <= recs.len {
        var n: i64 = 0;
        var v: i64 = 0;
        for k in 4 { n = (n << 8) | recs[p + k]; }
        for k in 4 { v = (v << 8) | recs[p + 4 + k]; }
        let at = p + 9;
        if recs[at..at + n] == name { return recs[at + n..at + n + v], true; }
        p = at + n + v;
    }
    return "", false;
}

// --- Decoding (§4.5) -------------------------------------------------------------

// Decodes an encoded field section (a HEADERS frame's payload) into records
// on out. Only the static table may be referred to: a Required Insert Count
// other than 0, a dynamic or post-base reference, is
// QPACK_DECOMPRESSION_FAILED, and so is a section that is not QPACK. A
// section larger than max_size (each field's name and value lengths plus
// 32, RFC 9114 §4.2.2) is QPACK_TOO_LARGE, with nothing added to out.
fn qpack_decode(b: const u8[:], max_size: i64, out: u8[>..]&) -> i64 {
    let start = out.len;
    // The prefix: Required Insert Count (8-bit prefix), then the sign and
    // Delta Base (7-bit prefix). With no dynamic table the count is 0, and
    // a Base below 0 (sign 1) is an error (§4.5.1.2).
    let ric, p1 = qpack_int(b, 0, 8);
    if p1 < 0 || ric != 0 { return QPACK_DECOMPRESSION_FAILED; }
    if p1 >= b.len { return QPACK_DECOMPRESSION_FAILED; }
    let sign = (b[p1] & 0x80) != 0;
    let db, p2 = qpack_int(b, p1, 7);
    if p2 < 0 || sign { return QPACK_DECOMPRESSION_FAILED; }
    var p = p2;
    var size: i64 = 0;
    var name: u8[>..] = [];
    var value: u8[>..] = [];
    while p < b.len {
        let c = b[p];
        name.clear();
        value.clear();
        var never = false;
        if (c & 0x80) != 0 {
            // §4.5.2: indexed, 1 T index(6); T 0 is the dynamic table.
            if (c & 0x40) == 0 { return QPACK_DECOMPRESSION_FAILED; }
            let i, q = qpack_int(b, p, 6);
            if q < 0 || i >= 99 { return QPACK_DECOMPRESSION_FAILED; }
            name.append(QPACK_STATIC_NAMES[i]);
            value.append(QPACK_STATIC_VALUES[i]);
            p = q;
        } else if (c & 0xc0) == 0x40 {
            // §4.5.4: literal with name reference, 01 N T index(4).
            never = (c & 0x20) != 0;
            if (c & 0x10) == 0 { return QPACK_DECOMPRESSION_FAILED; }
            let i, q = qpack_int(b, p, 4);
            if q < 0 || i >= 99 { return QPACK_DECOMPRESSION_FAILED; }
            name.append(QPACK_STATIC_NAMES[i]);
            p = qpack_string(b, q, 7, 0x80, max_size, value);
            if p < 0 { return QPACK_DECOMPRESSION_FAILED; }
        } else if (c & 0xe0) == 0x20 {
            // §4.5.6: literal with literal name, 001 N H length(3).
            never = (c & 0x10) != 0;
            p = qpack_string(b, p, 3, 0x08, max_size, name);
            if p < 0 { return QPACK_DECOMPRESSION_FAILED; }
            p = qpack_string(b, p, 7, 0x80, max_size, value);
            if p < 0 { return QPACK_DECOMPRESSION_FAILED; }
        } else {
            // §4.5.3 and §4.5.5: post-base references, dynamic only.
            return QPACK_DECOMPRESSION_FAILED;
        }
        size += name.len + value.len + 32;
        if size > max_size {
            out.resize(start);
            return QPACK_TOO_LARGE;
        }
        qpack_record(out, name, value, never);
    }
    return QPACK_OK;
}

// --- Encoding (§4.5) -------------------------------------------------------------

// Starts an encoded field section: Required Insert Count 0, Base 0.
fn qpack_begin(out: u8[>..]&) {
    out.push(0);
    out.push(0);
}

// The static index with this name and value (exact true), or of one with
// this name (exact false), or -1.
fn qpack_search(name: const u8[:], value: const u8[:]) -> i64, bool {
    var name_at: i64 = -1;
    for k in 99 {
        if QPACK_STATIC_NAMES[k] == name {
            if QPACK_STATIC_VALUES[k] == value { return k, true; }
            if name_at < 0 { name_at = k; }
        }
    }
    return name_at, false;
}

// A field: indexed if the static table has it; else a literal with the
// static name, or with its own; never to be indexed (the N bit) when
// never. Strings in Huffman when shorter, unless huff is false. Names are
// lowercase (RFC 9114 §4.2); the caller lowers them.
fn qpack_field(out: u8[>..]&, name: const u8[:], value: const u8[:], never: bool, huff: bool = true) {
    let i, exact = qpack_search(name, value);
    if exact && !never {
        qpack_put_int(out, 0xc0, 6, i);
        return;
    }
    let nbit: u8 = if never { 0x20 } else { 0 };
    if i >= 0 {
        qpack_put_int(out, 0x50 | nbit, 4, i);
    } else {
        qpack_put_string(out, 0x20 | (nbit >> 1), 3, 0x08, name, huff);
    }
    qpack_put_string(out, 0, 7, 0x80, value, huff);
}

// A whole encoded field section of the records recs.
fn qpack_encode(out: u8[>..]&, recs: const u8[:], huff: bool = true) {
    qpack_begin(out);
    each_qpack_field(recs) { name, value, never => qpack_field(out, name, value, never, huff); };
}

// --- The encoder and decoder streams (§4.3, §4.4) --------------------------------

// The peer's encoder stream instructions in data: how many bytes were
// complete instructions (the rest waits for more), or a negative error:
// -QPACK_ENCODER_STREAM_ERROR. With our capacity 0, Set Dynamic Table
// Capacity may only say 0; inserts and duplicates refer to a table that
// cannot hold anything.
fn qpack_encoder_stream(data: const u8[:]) -> i64 {
    var p = 0;
    while p < data.len {
        let c = data[p];
        if (c & 0xe0) == 0x20 {
            let cap, q = qpack_int(data, p, 5);
            if q == -1 { return p; }
            if q < 0 || cap != 0 { return -QPACK_ENCODER_STREAM_ERROR; }
            p = q;
        } else {
            // Insert with name reference (1T), with literal name (01),
            // Duplicate (000): nothing can be inserted.
            return -QPACK_ENCODER_STREAM_ERROR;
        }
    }
    return p;
}

// The peer's decoder stream instructions in data: how many bytes were
// complete instructions, or -QPACK_DECODER_STREAM_ERROR. We insert nothing
// and send no section that refers to the table, so a Section
// Acknowledgment or an Insert Count Increment is an error (§4.4.1,
// §4.4.3); Stream Cancellation is taken.
fn qpack_decoder_stream(data: const u8[:]) -> i64 {
    var p = 0;
    while p < data.len {
        let c = data[p];
        if (c & 0x80) != 0 { return -QPACK_DECODER_STREAM_ERROR; }
        if (c & 0xc0) == 0x40 {
            let s, q = qpack_int(data, p, 6);
            if q == -1 { return p; }
            if q < 0 { return -QPACK_DECODER_STREAM_ERROR; }
            p = q;
        } else {
            return -QPACK_DECODER_STREAM_ERROR;
        }
    }
    return p;
}

// --- Field validation (RFC 9114 §4.2, §4.3) -----------------------------------------

let FIELDS_OK: i64 = 0;
let FIELDS_MALFORMED: i64 = 1;         // H3_MESSAGE_ERROR on the stream

// A name: lowercase token characters (RFC 9110 §5.6.2), or a pseudo-header
// (":" then lowercase letters).
fn field_name_ok(n: const u8[:]) -> bool {
    if n.len == 0 { return false; }
    var start = 0;
    if n[0] == ':' {
        if n.len == 1 { return false; }
        start = 1;
    }
    for i in start..n.len {
        let c = n[i];
        let ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                 c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
                 c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
        if !ok { return false; }
    }
    return true;
}

// A value: no NUL, CR or LF, and no space or tab at either end (RFC 9110
// §5.5).
fn field_value_ok(v: const u8[:]) -> bool {
    for c in v { if c == 0 || c == '\r' || c == '\n' { return false; } }
    if v.len > 0 {
        let a = v[0];
        let z = v[v.len - 1];
        if a == ' ' || a == '\t' || z == ' ' || z == '\t' { return false; }
    }
    return true;
}

// The connection-specific fields HTTP/3 refuses (§4.2), TE but "trailers".
fn connection_specific(n: const u8[:], v: const u8[:]) -> bool {
    if n == "connection" || n == "keep-alive" || n == "proxy-connection" || n == "transfer-encoding" || n == "upgrade" {
        return true;
    }
    return n == "te" && v != "trailers";
}

// The regular fields: valid, not connection-specific, after every
// pseudo-header. pseudo counts the pseudo-headers at the front.
fn regular_ok(recs: const u8[:], pseudo: i64&) -> bool {
    var ok = true;
    var seen_regular = false;
    pseudo = 0;
    each_qpack_field(recs) { n, v, never =>
        if !field_name_ok(n) || !field_value_ok(v) { ok = false; }
        if n.len > 0 && n[0] == ':' {
            if seen_regular { ok = false; }
            pseudo++;
        } else {
            seen_regular = true;
            if connection_specific(n, v) { ok = false; }
        }
    };
    return ok;
}

// A request's fields (§4.3.1): :method, and :scheme and :path (not empty)
// unless it is CONNECT, each once; an http or https request has
// :authority or Host, the same when it has both, and a :path that starts
// with "/" (or is "*", for OPTIONS); CONNECT has :authority and no
// :scheme or :path, unless it is extended (:protocol, RFC 9220); no other
// pseudo-headers. A proxy or router that read one name from :authority
// and another from Host could be steered by the difference.
fn validate_request(recs: const u8[:]) -> i64 {
    var pseudo: i64 = 0;
    if !regular_ok(recs, pseudo) { return FIELDS_MALFORMED; }
    var method = 0;
    var scheme = 0;
    var path = 0;
    var authority = 0;
    var protocol = 0;
    var bad = false;
    var host = false;
    var is_connect = false;
    var http_scheme = false;
    var path_empty = false;
    var path_form = false;              // "/..." or "*"
    var path_star = false;
    var is_options = false;
    var authority_v: u8[>..] = [];
    var host_v: u8[>..] = [];
    var hosts = 0;
    each_qpack_field(recs) { n, v, never =>
        if n == ":method" { method++; is_connect = v == "CONNECT"; is_options = v == "OPTIONS"; if v.len == 0 { bad = true; } }
        else if n == ":scheme" { scheme++; http_scheme = v == "http" || v == "https"; }
        else if n == ":path" {
            path++;
            path_empty = v.len == 0;
            path_star = v == "*";
            path_form = path_star || (v.len > 0 && v[0] == '/');
        }
        else if n == ":authority" { authority++; authority_v.clear(); authority_v.append(v); }
        else if n == ":protocol" { protocol++; }
        else if n.len > 0 && n[0] == ':' { bad = true; }
        else if n == "host" { host = true; hosts++; host_v.clear(); host_v.append(v); }
    };
    if bad || method != 1 || scheme > 1 || path > 1 || authority > 1 || protocol > 1 { return FIELDS_MALFORMED; }
    if is_connect && protocol == 0 {
        if authority != 1 || scheme != 0 || path != 0 { return FIELDS_MALFORMED; }
        return FIELDS_OK;
    }
    if protocol > 0 && !is_connect { return FIELDS_MALFORMED; }
    if scheme != 1 || path != 1 || path_empty { return FIELDS_MALFORMED; }
    if http_scheme && authority == 0 && !host { return FIELDS_MALFORMED; }
    if hosts > 1 || (authority == 1 && host && authority_v != host_v) { return FIELDS_MALFORMED; }
    if http_scheme && (!path_form || (path_star && !is_options)) { return FIELDS_MALFORMED; }
    return FIELDS_OK;
}

// A response's fields (§4.3.2): :status, three digits, and no other
// pseudo-header.
fn validate_response(recs: const u8[:]) -> i64 {
    var pseudo: i64 = 0;
    if !regular_ok(recs, pseudo) { return FIELDS_MALFORMED; }
    var status = 0;
    var bad = false;
    each_qpack_field(recs) { n, v, never =>
        if n == ":status" {
            status++;
            if v.len != 3 { bad = true; }
            for c in v { if c < '0' || c > '9' { bad = true; } }
        } else if n.len > 0 && n[0] == ':' { bad = true; }
    };
    if bad || status != 1 { return FIELDS_MALFORMED; }
    return FIELDS_OK;
}

// Trailers (§4.1): no pseudo-headers at all.
fn validate_trailers(recs: const u8[:]) -> i64 {
    var pseudo: i64 = 0;
    if !regular_ok(recs, pseudo) || pseudo != 0 { return FIELDS_MALFORMED; }
    return FIELDS_OK;
}

// A response's status code from its fields, or -1.
fn status_of(recs: const u8[:]) -> i64 {
    let v, ok = qpack_get(recs, ":status");
    if !ok || v.len != 3 { return -1; }
    var s: i64 = 0;
    for c in v {
        if c < '0' || c > '9' { return -1; }
        s = s * 10 + (c - '0');
    }
    return s;
}

// --- The Huffman code (RFC 7541 Appendix B; net/http's hpacktab, copied so
// that quic does not need http) --------------------------------------------------

// Each symbol's code (256 is EOS) and its length in bits.
let QHUFF_CODE: u32[257] = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
    0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
    0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
    0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
    0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
    0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
    0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
    0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
    0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
    0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
    0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
    0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
    0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    0x3fffffff,
];
let QHUFF_LEN: u8[257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7,
    7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21,
    23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24,
    21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
];

// The code is canonical: of each length L, QHUFF_COUNT[L] codes from
// QHUFF_FIRST[L], for the symbols QHUFF_SYMS[QHUFF_OFFSET[L]..] in order.
let QHUFF_FIRST: u32[31] = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x5c,
    0xf8, 0x0, 0x3f8, 0x7fa, 0xffa, 0x1ff8, 0x3ffc, 0x7ffc,
    0x0, 0x0, 0x0, 0x7fff0, 0xfffe6, 0x1fffdc, 0x3fffd2, 0x7fffd8,
    0xffffea, 0x1ffffec, 0x3ffffe0, 0x7ffffde, 0xfffffe2, 0x0, 0x3ffffffc,
];
let QHUFF_COUNT: u16[31] = [
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3,
    0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4,
];
let QHUFF_OFFSET: u16[31] = [
    0, 0, 0, 0, 0, 0, 10, 36, 68, 0, 74, 79, 82, 84, 90, 92,
    0, 0, 0, 95, 98, 106, 119, 145, 174, 186, 190, 205, 224, 0, 253,
];
let QHUFF_SYMS: u16[257] = [
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51,
    52, 53, 54, 55, 56, 57, 61, 65, 95, 98, 100, 102, 103, 104, 108, 109,
    110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118,
    119, 120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39,
    43, 124, 35, 62, 0, 36, 64, 91, 93, 126, 94, 125, 60, 96, 123, 92,
    195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161, 167, 172, 176, 177,
    179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156, 160,
    163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232,
    233, 1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157,
    158, 165, 166, 168, 174, 175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142,
    144, 145, 148, 159, 171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193,
    200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242, 243, 255, 203, 204, 211,
    212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252, 253, 254,
    2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20,
    21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127, 220, 249, 10, 13, 22,
    256,
];
