// kmip: the Key Management Interoperability Protocol (OASIS KMIP 1.0 to
// 1.4, 2.0 and 2.1) for the Goose language, both sides: TTLV, its binary
// encoding, and the XML and JSON encodings of KMIP's Profiles; the
// request and response messages and their batches; the attributes,
// rendered as KMIP 1.x's Template-Attribute and Attribute Name or as
// 2.x's Attributes; the managed objects in every key format; wrapped
// keys; a client over TLS or HTTPS for every operation; and a server
// with an in-memory store.
//
//   kmip                 this module: TTLV, decoded into Nodes and written
//   kmip.tables          the tags, enumerations and names of KMIP 2.1
//   kmip.messages        request and response messages, batch items, results
//   kmip.attributes      attributes, one list rendered for 1.x or 2.x
//   kmip.objects         managed objects
//   kmip.formats         key formats, converted
//   kmip.crypto          the ciphers, MACs, hashes and signatures KMIP names
//   kmip.wrap            wrapped keys
//   kmip.split           split keys
//   kmip.text, .xml, .json  the XML and JSON encodings
//   kmip.client          a client over TLS; client_ops, client_pki,
//                        client_session: the operations past the basic ones
//   kmip.https           KMIP over HTTPS, both sides
//   kmip.server          a server: requests checked, operations on a store
//                        (server_manage, server_crypto, server_lifecycle,
//                        server_pki, server_session)
//   kmip.local           a client whose server is in the program
//
// All are in the namespace kmip. A decode never copies: it fills an array
// of fixed-size Nodes, one per item in the order they appear, as cbor's
// does, each with offsets into the caller's buffer.
//
//   var doc: kmip::Node[>..] = [];
//   let root, e = kmip::decode(bytes, kmip::Options { .. }, doc);
//   let uid = kmip::child(doc, root, kmip::TAG_UNIQUE_IDENTIFIER);
//   let text, ok = kmip::as_text(bytes, doc, uid);
//
//   var out: u8[>..] = [];
//   let s = kmip::begin(out, kmip::TAG_PROTOCOL_VERSION);
//   kmip::put_int(out, kmip::TAG_PROTOCOL_VERSION_MAJOR, 1);
//   kmip::put_int(out, kmip::TAG_PROTOCOL_VERSION_MINOR, 2);
//   kmip::end(out, s);

namespace kmip;

import std;
import binary;
import kmip.tables;

// --- Item types -----------------------------------------------------------------

let STRUCTURE:          u8 = 0x01;
let INTEGER:            u8 = 0x02;   // 32 bits, signed
let LONG_INTEGER:       u8 = 0x03;   // 64 bits, signed
let BIG_INTEGER:        u8 = 0x04;   // two's complement, big-endian, a multiple of 8 bytes
let ENUMERATION:        u8 = 0x05;   // 32 bits, unsigned
let BOOLEAN:            u8 = 0x06;   // 64 bits, 0 or 1
let TEXT_STRING:        u8 = 0x07;   // UTF-8
let BYTE_STRING:        u8 = 0x08;
let DATE_TIME:          u8 = 0x09;   // 64 bits, seconds since 1970 (POSIX time)
let INTERVAL:           u8 = 0x0A;   // 32 bits, unsigned seconds
let DATE_TIME_EXTENDED: u8 = 0x0B;   // 64 bits, microseconds since 1970 (KMIP 2.0)

fn type_name(t: u8) -> const u8[:] {
    if t == STRUCTURE { return "Structure"; }
    if t == INTEGER { return "Integer"; }
    if t == LONG_INTEGER { return "LongInteger"; }
    if t == BIG_INTEGER { return "BigInteger"; }
    if t == ENUMERATION { return "Enumeration"; }
    if t == BOOLEAN { return "Boolean"; }
    if t == TEXT_STRING { return "TextString"; }
    if t == BYTE_STRING { return "ByteString"; }
    if t == DATE_TIME { return "DateTime"; }
    if t == INTERVAL { return "Interval"; }
    if t == DATE_TIME_EXTENDED { return "DateTimeExtended"; }
    return "?";
}

// --- Errors ---------------------------------------------------------------------

let OK:            i64 = 0;
let ERR_TRUNCATED: i64 = 1;   // the input ends inside an item
let ERR_MALFORMED: i64 = 2;   // a length wrong for the type, a Boolean not 0 or 1, padding not zero, children that do not fill their Structure
let ERR_TYPE:      i64 = 3;   // an unknown item type, or not the type asked for (accessors)
let ERR_DEPTH:     i64 = 4;   // nested deeper than max_depth
let ERR_TOO_MANY:  i64 = 5;   // more items than max_items
let ERR_TOO_LARGE: i64 = 6;   // input longer than max_bytes
let ERR_TRAILING:  i64 = 7;   // bytes after the item
let ERR_TAG:       i64 = 8;   // a tag outside 0x420000-0x42FFFF and 0x540000-0x54FFFF
let ERR_MISSING:   i64 = 9;   // a field the message must have is not there
let ERR_UTF8:      i64 = 10;  // a Text String that is not UTF-8
let ERR_ARG:       i64 = 11;  // an argument that cannot be used
let ERR_NETWORK:   i64 = 12;  // the socket or the TLS connection failed
let ERR_TLS:       i64 = 13;  // the TLS handshake failed
let ERR_VERSION:   i64 = 14;  // no protocol version both sides speak
let ERR_FAILED:    i64 = 15;  // the server answered with a Result Status that is not Success (see the result)
let ERR_PROTOCOL:  i64 = 16;  // an answer that does not match the request: batch count, operation, item ID

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_TRUNCATED { return "truncated"; }
    if e == ERR_MALFORMED { return "malformed"; }
    if e == ERR_TYPE { return "wrong type"; }
    if e == ERR_DEPTH { return "nested too deeply"; }
    if e == ERR_TOO_MANY { return "too many items"; }
    if e == ERR_TOO_LARGE { return "too large"; }
    if e == ERR_TRAILING { return "trailing bytes"; }
    if e == ERR_TAG { return "bad tag"; }
    if e == ERR_MISSING { return "required field missing"; }
    if e == ERR_UTF8 { return "text string not UTF-8"; }
    if e == ERR_ARG { return "bad argument"; }
    if e == ERR_NETWORK { return "network error"; }
    if e == ERR_TLS { return "TLS error"; }
    if e == ERR_VERSION { return "no common protocol version"; }
    if e == ERR_FAILED { return "operation failed"; }
    if e == ERR_PROTOCOL { return "response does not match the request"; }
    return "unknown error";
}

// --- Decoding -------------------------------------------------------------------

// What a decode allows. The defaults take any message a key manager sends
// in practice: 32 levels, 1 << 20 items, 16 MiB.
struct Options {
    max_depth: i64  = 32,
    max_items: i64  = 1048576,
    max_bytes: i64  = 16777216,
    check_utf8: bool = true,   // refuse a Text String that is not UTF-8
}

// One item. Its value is buf[off..off+len]; `end` is past its padding. The
// children of a Structure follow it in the array; `count` says how many
// there are, and each child's `next` is the index of its next sibling (-1
// for the last).
struct Node {
    tag:   u32,
    typ:   u8,
    start: i64,   // the tag
    off:   i64,   // the value
    len:   i64,   // the value's length, without padding
    end:   i64,   // past the item and its padding
    count: i64,
    next:  i64,
}

fn padded(n: i64) -> i64 { (n + 7) / 8 * 8 }

fn tag_ok(t: u32) -> bool { (t >> 16) == 0x42 || (t >> 16) == 0x54 }

fn utf8_ok(b: const u8[:]) -> bool {
    var i = 0;
    while i < b.len {
        let c = b[i];
        if c < 0x80 { i++; continue; }
        var n = 0;
        var min: u32 = 0;
        var v: u32 = 0;
        if c & 0xE0 == 0xC0 { n = 1; min = 0x80; v = c & 0x1F; }
        else if c & 0xF0 == 0xE0 { n = 2; min = 0x800; v = c & 0x0F; }
        else if c & 0xF8 == 0xF0 { n = 3; min = 0x10000; v = c & 0x07; }
        else { return false; }
        if i + n >= b.len { return false; }
        for k in n {
            let d = b[i + 1 + k];
            if d & 0xC0 != 0x80 { return false; }
            v = (v << 6) | (d & 0x3F);
        }
        if v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF) { return false; }
        i += n + 1;
    }
    return true;
}

// The fixed length of a type's value, or -1 for the ones of any length.
fn fixed_len(t: u8) -> i64 {
    if t == INTEGER || t == ENUMERATION || t == INTERVAL { return 4; }
    if t == LONG_INTEGER || t == BOOLEAN || t == DATE_TIME || t == DATE_TIME_EXTENDED { return 8; }
    return -1;
}

recursive fn decode_at(buf: const u8[:], at: i64, limit: i64, depth: i64, opts: Options, doc: Node[>..]&) -> i64, i64, i64 {
    if depth > opts.max_depth { return -1, at, ERR_DEPTH; }
    if doc.len >= opts.max_items { return -1, at, ERR_TOO_MANY; }
    if limit - at < 8 { return -1, at, ERR_TRUNCATED; }
    let tag = (binary::u32be(buf, at) >> 8);
    let typ = buf[at + 3];
    let len = binary::u32be(buf, at + 4) as i64;
    if !tag_ok(tag) { return -1, at, ERR_TAG; }
    if typ < STRUCTURE || typ > DATE_TIME_EXTENDED { return -1, at, ERR_TYPE; }
    let off = at + 8;
    let fl = fixed_len(typ);
    if fl >= 0 && len != fl { return -1, at, ERR_MALFORMED; }
    if typ == BIG_INTEGER && (len == 0 || len % 8 != 0) { return -1, at, ERR_MALFORMED; }
    let end = off + padded(len);
    if typ == STRUCTURE && len % 8 != 0 { return -1, at, ERR_MALFORMED; }
    if len > limit - off || end > limit { return -1, at, ERR_TRUNCATED; }
    for k in off + len..end {
        if buf[k] != 0 { return -1, at, ERR_MALFORMED; }
    }
    if typ == BOOLEAN {
        let v = binary::u64be(buf, off);
        if v > 1 { return -1, at, ERR_MALFORMED; }
    }
    if typ == TEXT_STRING && opts.check_utf8 && !utf8_ok(buf[off..off + len]) { return -1, at, ERR_UTF8; }
    let me = doc.len;
    doc.push(Node { tag: tag, typ: typ, start: at, off: off, len: len, end: end, count: 0, next: -1 });
    if typ == STRUCTURE {
        var p = off;
        var last = -1;
        var count = 0;
        while p < end {
            let c, q, e = decode_at(buf, p, end, depth + 1, opts, doc);
            if e != OK { return -1, q, e; }
            if last >= 0 { doc[last].next = c; }
            last = c;
            count++;
            p = q;
        }
        doc[me].count = count;
    }
    return me, end, OK;
}

// Decodes the one item that fills buf (a whole message), appending its
// Nodes to doc; the index of the first, or -1 and the error.
fn decode(buf: const u8[:], opts: Options, doc: Node[>..]&) -> i64, i64 {
    if buf.len > opts.max_bytes { return -1, ERR_TOO_LARGE; }
    let root, end, e = decode_at(buf, 0, buf.len, 0, opts, doc);
    if e != OK { return -1, e; }
    if end != buf.len { return -1, ERR_TRAILING; }
    return root, OK;
}

// How long the message whose first 8 bytes are head is, all of it, or -1
// when it is no TTLV Structure. A reader of a stream needs this.
fn message_length(head: const u8[:]) -> i64 {
    if head.len < 8 || head[3] != STRUCTURE { return -1; }
    let t = binary::u32be(head, 0) >> 8;
    if !tag_ok(t) { return -1; }
    let len = binary::u32be(head, 4) as i64;
    if len % 8 != 0 { return -1; }
    return 8 + len;
}

// --- Reading --------------------------------------------------------------------

fn is_type(doc: const Node[:], i: i64, t: u8) -> bool { i >= 0 && doc[i].typ == t }

// The index of the first child of a Structure with the tag, or -1.
fn child(doc: const Node[:], i: i64, tag: u32) -> i64 {
    if !is_type(doc, i, STRUCTURE) || doc[i].count == 0 { return -1; }
    var c = i + 1;
    while c >= 0 {
        if doc[c].tag == tag { return c; }
        c = doc[c].next;
    }
    return -1;
}

// The next sibling after c with the same tag as c, or -1: for fields that
// repeat.
fn next_same(doc: const Node[:], c: i64) -> i64 {
    if c < 0 { return -1; }
    var n = doc[c].next;
    while n >= 0 {
        if doc[n].tag == doc[c].tag { return n; }
        n = doc[n].next;
    }
    return -1;
}

// The number of children of a Structure with the tag.
fn count(doc: const Node[:], i: i64, tag: u32) -> i64 {
    var n = 0;
    var c = child(doc, i, tag);
    while c >= 0 { n++; c = next_same(doc, c); }
    return n;
}

// F(child) for each child of a Structure, in order.
fn each<F>(doc: const Node[:], i: i64) {
    if !is_type(doc, i, STRUCTURE) { return; }
    var c = if doc[i].count > 0 { i + 1 } else { -1 };
    while c >= 0 {
        F(c);
        c = doc[c].next;
    }
}

fn raw(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:] { buf[doc[i].start..doc[i].end] }
fn value(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:] { buf[doc[i].off..doc[i].off + doc[i].len] }

fn as_int(buf: const u8[:], doc: const Node[:], i: i64) -> i32, bool {
    if !is_type(doc, i, INTEGER) { return 0, false; }
    return binary::u32be(buf, doc[i].off) as! i32, true;
}

fn as_long(buf: const u8[:], doc: const Node[:], i: i64) -> i64, bool {
    if !is_type(doc, i, LONG_INTEGER) { return 0, false; }
    return binary::u64be(buf, doc[i].off) as! i64, true;
}

fn as_enum(buf: const u8[:], doc: const Node[:], i: i64) -> u32, bool {
    if !is_type(doc, i, ENUMERATION) { return 0, false; }
    return binary::u32be(buf, doc[i].off), true;
}

fn as_bool(buf: const u8[:], doc: const Node[:], i: i64) -> bool, bool {
    if !is_type(doc, i, BOOLEAN) { return false, false; }
    return binary::u64be(buf, doc[i].off) == 1, true;
}

fn as_text(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:], bool {
    if !is_type(doc, i, TEXT_STRING) { return "", false; }
    return value(buf, doc, i), true;
}

fn as_bytes(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:], bool {
    if !is_type(doc, i, BYTE_STRING) { return "", false; }
    return value(buf, doc, i), true;
}

// Seconds since 1970; a Date-Time Extended's microseconds are cut to seconds.
fn as_datetime(buf: const u8[:], doc: const Node[:], i: i64) -> i64, bool {
    if is_type(doc, i, DATE_TIME) { return binary::u64be(buf, doc[i].off) as! i64, true; }
    if is_type(doc, i, DATE_TIME_EXTENDED) { return (binary::u64be(buf, doc[i].off) as! i64) / 1000000, true; }
    return 0, false;
}

fn as_interval(buf: const u8[:], doc: const Node[:], i: i64) -> u32, bool {
    if !is_type(doc, i, INTERVAL) { return 0, false; }
    return binary::u32be(buf, doc[i].off), true;
}

// A Big Integer's two's complement bytes, big-endian, as they are written.
fn as_bigint(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:], bool {
    if !is_type(doc, i, BIG_INTEGER) { return "", false; }
    return value(buf, doc, i), true;
}

// A non-negative Big Integer's magnitude with its leading zeros dropped
// (an RSA modulus, an exponent); false for a negative one.
fn as_biguint(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:], bool {
    let v, ok = as_bigint(buf, doc, i);
    if !ok || v[0] & 0x80 != 0 { return "", false; }
    var k = 0;
    while k < v.len - 1 && v[k] == 0 { k++; }
    return v[k..], true;
}

// The child's value, for the common case of a field that must be there.
fn child_text(buf: const u8[:], doc: const Node[:], i: i64, tag: u32) -> const u8[:], bool { let v, ok = as_text(buf, doc, child(doc, i, tag)); return v, ok; }
fn child_bytes(buf: const u8[:], doc: const Node[:], i: i64, tag: u32) -> const u8[:], bool { let v, ok = as_bytes(buf, doc, child(doc, i, tag)); return v, ok; }
fn child_enum(buf: const u8[:], doc: const Node[:], i: i64, tag: u32) -> u32, bool { let v, ok = as_enum(buf, doc, child(doc, i, tag)); return v, ok; }
fn child_int(buf: const u8[:], doc: const Node[:], i: i64, tag: u32) -> i32, bool { let v, ok = as_int(buf, doc, child(doc, i, tag)); return v, ok; }
fn child_long(buf: const u8[:], doc: const Node[:], i: i64, tag: u32) -> i64, bool { let v, ok = as_long(buf, doc, child(doc, i, tag)); return v, ok; }
fn child_bool(buf: const u8[:], doc: const Node[:], i: i64, tag: u32) -> bool, bool { let v, ok = as_bool(buf, doc, child(doc, i, tag)); return v, ok; }

// --- Writing --------------------------------------------------------------------

fn put_head(out: u8[>..]&, tag: u32, typ: u8, len: i64) {
    out.push((tag >> 16) as! u8);
    out.push((tag >> 8) as! u8);
    out.push(tag as! u8);
    out.push(typ);
    out.push((len >> 24) as! u8);
    out.push((len >> 16) as! u8);
    out.push((len >> 8) as! u8);
    out.push(len as! u8);
}

fn put_be(out: u8[>..]&, v: u64, n: i64) {
    var k = n - 1;
    while k >= 0 { out.push((v >> (8 * k) as u64) as! u8); k--; }
}

fn put_pad(out: u8[>..]&, len: i64) {
    for k in padded(len) - len { out.push(0); }
}

fn put_int(out: u8[>..]&, tag: u32, v: i32) { put_head(out, tag, INTEGER, 4); put_be(out, v as! u32, 4); put_pad(out, 4); }
fn put_long(out: u8[>..]&, tag: u32, v: i64) { put_head(out, tag, LONG_INTEGER, 8); put_be(out, v as! u64, 8); }
fn put_enum(out: u8[>..]&, tag: u32, v: u32) { put_head(out, tag, ENUMERATION, 4); put_be(out, v, 4); put_pad(out, 4); }
fn put_bool(out: u8[>..]&, tag: u32, v: bool) { put_head(out, tag, BOOLEAN, 8); put_be(out, if v { 1 } else { 0 }, 8); }
fn put_datetime(out: u8[>..]&, tag: u32, secs: i64) { put_head(out, tag, DATE_TIME, 8); put_be(out, secs as! u64, 8); }
fn put_datetime_ext(out: u8[>..]&, tag: u32, usecs: i64) { put_head(out, tag, DATE_TIME_EXTENDED, 8); put_be(out, usecs as! u64, 8); }
fn put_interval(out: u8[>..]&, tag: u32, secs: u32) { put_head(out, tag, INTERVAL, 4); put_be(out, secs, 4); put_pad(out, 4); }

fn put_text(out: u8[>..]&, tag: u32, s: const u8[:]) { put_head(out, tag, TEXT_STRING, s.len); out.append(s); put_pad(out, s.len); }
fn put_bytes(out: u8[>..]&, tag: u32, b: const u8[:]) { put_head(out, tag, BYTE_STRING, b.len); out.append(b); put_pad(out, b.len); }

// A Big Integer from a two's complement value, big-endian, sign-extended
// on the left to a multiple of 8 bytes. Empty is zero.
fn put_bigint(out: u8[>..]&, tag: u32, v: const u8[:]) {
    let neg = v.len > 0 && v[0] & 0x80 != 0;
    let n = if v.len == 0 { 8 } else { padded(v.len) };
    put_head(out, tag, BIG_INTEGER, n);
    for k in n - v.len { out.push(if neg { 0xFF } else { 0 }); }
    out.append(v);
}

// A Big Integer from a non-negative magnitude, big-endian (a modulus, an
// exponent): a zero byte goes in front when its top bit is set.
fn put_biguint(out: u8[>..]&, tag: u32, mag: const u8[:]) {
    var k = 0;
    while k < mag.len && mag[k] == 0 { k++; }
    let m = mag[k..];
    let n = if m.len == 0 { 8 } else if m[0] & 0x80 != 0 { padded(m.len + 1) } else { padded(m.len) };
    put_head(out, tag, BIG_INTEGER, n);
    for j in n - m.len { out.push(0); }
    out.append(m);
}

// A Structure: begin writes its head and gives where it starts; end, once
// its children are written, puts their length in it.
fn begin(out: u8[>..]&, tag: u32) -> i64 {
    let at = out.len;
    put_head(out, tag, STRUCTURE, 0);
    return at;
}

fn end(out: u8[>..]&, at: i64) {
    let len = out.len - at - 8;
    out[at + 4] = (len >> 24) as! u8;
    out[at + 5] = (len >> 16) as! u8;
    out[at + 6] = (len >> 8) as! u8;
    out[at + 7] = len as! u8;
}

// An item as it is, from another message (its tag, type, length, value
// and padding): raw(buf, doc, i).
fn put_raw(out: u8[>..]&, item: const u8[:]) { out.append(item); }

// The same item with another tag: what KMIP 1.x's Attribute Value is to
// 2.0's attribute.
fn put_retagged(out: u8[>..]&, tag: u32, item: const u8[:]) {
    if item.len < 8 { return; }
    out.push((tag >> 16) as! u8);
    out.push((tag >> 8) as! u8);
    out.push(tag as! u8);
    out.append(item[3..]);
}

// --- Names ----------------------------------------------------------------------

// A tag's name as KMIP's XML encoding writes it (UniqueIdentifier), or ""
// for one not known here (an extension, 0x54xxxx).
fn tag_name(tag: u32) -> const u8[:] {
    var lo = 0;
    var hi = TAG_NAMES.len;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if TAG_NAMES[mid].tag == tag { return TAG_NAMES[mid].name; }
        if TAG_NAMES[mid].tag < tag { lo = mid + 1; } else { hi = mid; }
    }
    return "";
}

// The name of an Enumeration's value, by the tag it is under, or "".
fn enum_name(tag: u32, v: u32) -> const u8[:] {
    var lo = 0;
    var hi = ENUM_NAMES.len;
    while lo < hi {
        let mid = (lo + hi) / 2;
        let e = ENUM_NAMES[mid];
        if e.tag == tag && e.value == v { return e.name; }
        if e.tag < tag || (e.tag == tag && e.value < v) { lo = mid + 1; } else { hi = mid; }
    }
    return "";
}

// The tag of a KMIP 1.x Attribute Name ("Cryptographic Algorithm"), or 0.
fn attribute_tag(name: const u8[:]) -> u32 {
    for a in ATTRIBUTE_NAMES {
        if a.name == name { return a.tag; }
    }
    return 0;
}

fn attribute_name(tag: u32) -> const u8[:] {
    for a in ATTRIBUTE_NAMES {
        if a.tag == tag { return a.name; }
    }
    return "";
}

// --- Dumping --------------------------------------------------------------------

fn hex_into(out: u8[>..]&, b: const u8[:]) {
    let digits = "0123456789abcdef";
    for c in b { out.push(digits[(c >> 4) as i64]); out.push(digits[(c & 15) as i64]); }
}

recursive fn dump_at(out: u8[>..]&, buf: const u8[:], doc: const Node[:], i: i64, depth: i64) {
    for k in depth { out.append("  "); }
    let n = doc[i];
    let name = tag_name(n.tag);
    if name.len > 0 { out.append(name); } else { out.append("0x"); format_uint(out, n.tag, 16, 6, '0'); }
    out.append(" (");
    out.append(type_name(n.typ));
    out.append(")");
    if n.typ == STRUCTURE {
        out.push('\n');
        each(doc, i) { c => dump_at(out, buf, doc, c, depth + 1); };
        return;
    }
    out.append(": ");
    if n.typ == INTEGER { let v, ok = as_int(buf, doc, i); format_int(out, v, 10, 0, ' '); }
    else if n.typ == LONG_INTEGER { let v, ok = as_long(buf, doc, i); format_int(out, v, 10, 0, ' '); }
    else if n.typ == ENUMERATION {
        let v, ok = as_enum(buf, doc, i);
        let en = enum_name(n.tag, v);
        if en.len > 0 { out.append(en); } else { out.append("0x"); format_uint(out, v, 16, 8, '0'); }
    }
    else if n.typ == BOOLEAN { let v, ok = as_bool(buf, doc, i); out.append(if v { "true" } else { "false" }); }
    else if n.typ == TEXT_STRING { out.push('"'); out.append(value(buf, doc, i)); out.push('"'); }
    else if n.typ == INTERVAL { let v, ok = as_interval(buf, doc, i); format_int(out, v, 10, 0, ' '); }
    else if n.typ == DATE_TIME || n.typ == DATE_TIME_EXTENDED { format_int(out, binary::u64be(buf, n.off) as! i64, 10, 0, ' '); }
    else { hex_into(out, value(buf, doc, i)); }
    out.push('\n');
}

// The items as text, one a line, children indented under their Structure:
// "UniqueIdentifier (TextString): "1"".
fn dump(buf: const u8[:], doc: const Node[:], i: i64) -> u8[>..] {
    var out: u8[>..] = [];
    if i >= 0 { dump_at(out, buf, doc, i, 0); }
    return out;
}
