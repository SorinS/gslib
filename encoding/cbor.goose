// cbor: CBOR (RFC 8949), decoded strictly for data from strangers and
// encoded deterministically. A decode never copies: it fills an array of
// fixed-size Nodes, one per data item in the order they appear, each with
// offsets into the caller's buffer, as asn1's Tlvs and json's Nodes do.
// The decoder takes definite lengths only unless indefinite ones are
// opted into, refuses a map with two equal keys, malformed UTF-8 in a
// text string, a simple value written in two bytes below 32, and the
// reserved additional information values, and stops at limits on nesting,
// on the number of items and on the input's size; asked, it also refuses
// heads and floats longer than they need to be, or anything but the core
// deterministic encoding (§4.2.1). Tags are kept as they are, with the
// item they enclose, and not interpreted.
//
// What this package writes is the core deterministic encoding: the
// shortest heads, definite lengths, floats in the shortest form that keeps
// their value, and map keys in the bytewise order of their encodings
// (sort_map, canonical), or the length-first order of RFC 7049 and CTAP2
// when asked.
//
//   var doc: cbor::Node[>..] = [];
//   let root, e = cbor::decode(bytes, cbor::Options { .. }, doc);
//   let v = cbor::map_get_int(bytes, doc, root, 3);    // the value of key 3, or -1
//   let alg, ok = cbor::as_i64(doc, v);
//
//   var out: u8[>..] = [];
//   cbor::put_map(out, 2);
//   cbor::put_int(out, 1); cbor::put_int(out, 2);
//   cbor::put_int(out, 3); cbor::put_int(out, -7);
//
// Nothing is kept in part: a value that does not fit where it goes is an
// error, never cut.

namespace cbor;

import std;
import binary;

// --- Major types and simple values ----------------------------------------------

let UINT:   u8 = 0;
let NEGINT: u8 = 1;
let BYTES:  u8 = 2;
let TEXT:   u8 = 3;
let ARRAY:  u8 = 4;
let MAP:    u8 = 5;
let TAG:    u8 = 6;
let SIMPLE: u8 = 7;      // simple values and floats

let FALSE:     u64 = 20;
let TRUE:      u64 = 21;
let NULL:      u64 = 22;
let UNDEFINED: u64 = 23;

// --- Errors ---------------------------------------------------------------------

let OK:                    i64 = 0;
let ERR_TRUNCATED:         i64 = 1;  // the input ends inside an item
let ERR_MALFORMED:         i64 = 2;  // reserved additional information, a stray break, a bad chunk, a simple value in two bytes below 32
let ERR_INDEFINITE:        i64 = 3;  // an indefinite length, not opted into
let ERR_NOT_SHORTEST:      i64 = 4;  // a head or float longer than it needs to be (asked for)
let ERR_DUPLICATE_KEY:     i64 = 5;  // a map with two equal keys
let ERR_DEPTH:             i64 = 6;  // nested deeper than max_depth
let ERR_TOO_MANY:          i64 = 7;  // more items than max_items
let ERR_TOO_LARGE:         i64 = 8;  // input longer than max_bytes
let ERR_TRAILING:          i64 = 9;  // bytes after the item
let ERR_UTF8:              i64 = 10; // a text string that is not well-formed UTF-8
let ERR_NOT_DETERMINISTIC: i64 = 11;   // not the core deterministic encoding (asked for)
let ERR_TYPE:              i64 = 12; // not the type asked for (accessors, sort_map)

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_TRUNCATED { return "truncated"; }
    if e == ERR_MALFORMED { return "malformed"; }
    if e == ERR_INDEFINITE { return "indefinite length not allowed"; }
    if e == ERR_NOT_SHORTEST { return "not in the shortest form"; }
    if e == ERR_DUPLICATE_KEY { return "duplicate map key"; }
    if e == ERR_DEPTH { return "nested too deeply"; }
    if e == ERR_TOO_MANY { return "too many items"; }
    if e == ERR_TOO_LARGE { return "too large"; }
    if e == ERR_TRAILING { return "trailing bytes"; }
    if e == ERR_UTF8 { return "text string not UTF-8"; }
    if e == ERR_NOT_DETERMINISTIC { return "not deterministically encoded"; }
    if e == ERR_TYPE { return "wrong type"; }
    return "unknown error";
}

// --- Decoding -------------------------------------------------------------------

// What a decode allows. The defaults suit a small security token
// (WebAuthn's attestation objects, COSE keys): definite lengths, no
// duplicate keys, 16 levels, 4096 items, 1 MiB.
struct Options {
    indefinite:       bool = false,   // take indefinite-length strings, arrays and maps
    require_shortest: bool = false,   // refuse heads with more bytes than the value needs (preferred serialization)
    deterministic:    bool = false,   // refuse anything but the core deterministic encoding (§4.2.1)
    max_depth:        i64  = 16,      // arrays, maps and tags inside one another
    max_items:        i64  = 4096,    // data items in all, chunks of indefinite strings included
    max_bytes:        i64  = 1048576, // the input, from where the item starts
}

// One data item. `arg` is the head's argument: an integer's value (n for
// the negative integer -1-n), a string's length in bytes, the elements of
// an array, the pairs of a map, a tag's number, a simple value, or a
// float's bits (by `info`: 25 half, 26 single, 27 double). A definite
// string's bytes are buf[off..end]; an indefinite one's are in its chunks.
// The children of an array, map, tag or indefinite string follow it in
// the array; `count` says how many there are (2 per map pair) and each
// child's `next` is the index of its next sibling (-1 for the last).
struct Node {
    major:      u8,
    info:       u8,
    indefinite: bool,
    arg:        u64,
    start:      i64,  // the head
    off:        i64,  // past the head
    end:        i64,  // past the item, its children included
    count:      i64,
    next:       i64,
}

// A container being read: its node, the children still to come (-1 when
// indefinite), and its last child so far (to link the next one to).
struct Open { node: i64, left: i64, last: i64 }

// The head at `at`: major type, additional information, argument, and
// where the head ends; ERR_TRUNCATED or ERR_MALFORMED. Additional
// information 31 (indefinite, or a break) comes back as itself.
fn read_head(buf: const u8[:], at: i64, end: i64) -> u8, u8, u64, i64, i64 {
    if at >= end { return 0, 0, 0, at, ERR_TRUNCATED; }
    let b = buf[at];
    let major = b >> 5;
    let info = b & 31;
    if info < 24 { return major, info, info, at + 1, OK; }
    if info >= 28 && info <= 30 { return major, info, 0, at + 1, ERR_MALFORMED; }
    if info == 31 { return major, info, 0, at + 1, OK; }
    let n: i64 = if info == 24 { 1 } else if info == 25 { 2 } else if info == 26 { 4 } else { 8 };
    if n > end - at - 1 { return major, info, 0, at, ERR_TRUNCATED; }
    var v: u64 = 0;
    for i in n { v = (v << 8) | buf[at + 1 + i]; }
    return major, info, v, at + 1 + n, OK;
}

// Whether the head's argument could have been written in fewer bytes.
fn head_longer(info: u8, v: u64) -> bool {
    if info == 24 { return v < 24; }
    if info == 25 { return v < 256; }
    if info == 26 { return v < 65536; }
    if info == 27 { return v < 0x100000000; }
    return false;
}

// Whether b is well-formed UTF-8 (RFC 3629): no overlong forms, no
// surrogates, nothing past U+10FFFF.
fn valid_utf8(b: const u8[:]) -> bool {
    var i = 0;
    while i < b.len {
        let c = b[i];
        if c < 0x80 { i++; continue; }
        var n = 0;
        var lo: u8 = 0x80;
        var hi: u8 = 0xbf;
        if c >= 0xc2 && c <= 0xdf { n = 1; }
        else if c >= 0xe0 && c <= 0xef {
            n = 2;
            if c == 0xe0 { lo = 0xa0; }
            if c == 0xed { hi = 0x9f; }
        } else if c >= 0xf0 && c <= 0xf4 {
            n = 3;
            if c == 0xf0 { lo = 0x90; }
            if c == 0xf4 { hi = 0x8f; }
        } else { return false; }
        if i + n >= b.len { return false; }
        let c1 = b[i + 1];
        if c1 < lo || c1 > hi { return false; }
        for k in 2..n + 1 {
            let ck = b[i + k];
            if ck < 0x80 || ck > 0xbf { return false; }
        }
        i += n + 1;
    }
    return true;
}

// Decodes the one data item at buf[at..] into doc (cleared first): the
// index of its node (0), where it ends, and OK or the error. What follows
// the item is left alone. Map keys are compared by value (their
// deterministic encodings), so 1 and a 1 written in two bytes are the same
// key when require_shortest is off.
fn decode_at(buf: const u8[:], at: i64, opts: Options, doc: Node[>..]&) -> i64, i64, i64 {
    doc.clear();
    if at < 0 || at > buf.len { return -1, at, ERR_TRUNCATED; }
    var limit = buf.len;
    if buf.len - at > opts.max_bytes { return -1, at, ERR_TOO_LARGE; }
    var stack: Open[>..<] = [];
    var pos = at;
    loop {
        // Close the containers that are full.
        while stack.len > 0 && stack[stack.len - 1].left == 0 {
            let o = stack.pop();
            doc[o.node].end = pos;
            if doc[o.node].major == MAP {
                let e = check_keys(buf, doc, o.node);
                if e != OK { return -1, pos, e; }
            }
            if stack.len > 0 && stack[stack.len - 1].left > 0 { stack[stack.len - 1].left -= 1; }
        }
        if stack.len == 0 && doc.len > 0 { break; }
        let major, info, v, after, he = read_head(buf, pos, limit);
        if he != OK { return -1, pos, he; }
        // A break ends the indefinite container on top.
        if info == 31 && major == SIMPLE {
            guard stack.len > 0 && stack[stack.len - 1].left < 0 else { return -1, pos, ERR_MALFORMED; }
            let o = stack.pop();
            let n = doc[o.node];
            if n.major == MAP && n.count % 2 != 0 { return -1, pos, ERR_MALFORMED; }
            doc[o.node].end = after;
            if n.major == MAP {
                doc[o.node].arg = (n.count / 2) as u64;
                let e = check_keys(buf, doc, o.node);
                if e != OK { return -1, pos, e; }
            } else if n.major == ARRAY {
                doc[o.node].arg = n.count as u64;
            }
            pos = after;
            if stack.len > 0 && stack[stack.len - 1].left > 0 { stack[stack.len - 1].left -= 1; }
            if stack.len == 0 { break; }
            continue;
        }
        if info == 31 && (major == UINT || major == NEGINT || major == TAG) { return -1, pos, ERR_MALFORMED; }
        if info == 31 && !opts.indefinite { return -1, pos, ERR_INDEFINITE; }
        if major == SIMPLE && info == 24 && v < 32 { return -1, pos, ERR_MALFORMED; }
        if (opts.require_shortest || opts.deterministic) && major != SIMPLE && head_longer(info, v) {
            return -1, pos, ERR_NOT_SHORTEST;
        }
        // Inside an indefinite string, only definite chunks of its own type.
        if stack.len > 0 {
            let p = doc[stack[stack.len - 1].node];
            if (p.major == BYTES || p.major == TEXT) && p.indefinite {
                if major != p.major || info == 31 { return -1, pos, ERR_MALFORMED; }
            }
        }
        if doc.len >= opts.max_items { return -1, pos, ERR_TOO_MANY; }
        let idx = doc.len;
        doc.push(Node { major: major, info: info, indefinite: info == 31, arg: v, start: pos, off: after,
                        end: after, count: 0, next: -1 });
        // Link it to its parent's previous child.
        if stack.len > 0 {
            let t = stack.len - 1;
            if stack[t].last >= 0 { doc[stack[t].last].next = idx; }
            stack[t].last = idx;
            doc[stack[t].node].count += 1;
        }
        pos = after;
        var opens = false;
        var left: i64 = 0;
        if major == BYTES || major == TEXT {
            if info == 31 {
                opens = true;
                left = -1;
            } else {
                if v > (limit - pos) as u64 { return -1, pos, ERR_TRUNCATED; }
                let n = v as i64;
                if major == TEXT && !valid_utf8(buf[pos..pos + n]) { return -1, pos, ERR_UTF8; }
                pos += n;
                doc[idx].end = pos;
            }
        } else if major == ARRAY || major == MAP {
            if info == 31 {
                opens = true;
                left = -1;
            } else {
                // Every item takes a byte at least: a count the input
                // cannot hold is cut short, whatever the limits say.
                let per: u64 = if major == MAP { 2 } else { 1 };
                if v > (limit - pos) as u64 / per { return -1, pos, ERR_TRUNCATED; }
                left = v as i64 * per as i64;
                opens = left > 0;
            }
        } else if major == TAG {
            opens = true;
            left = 1;
        }
        if opens {
            if stack.len >= opts.max_depth { return -1, pos, ERR_DEPTH; }
            stack.push(Open { node: idx, left: left, last: -1 });
        } else {
            if stack.len > 0 && stack[stack.len - 1].left > 0 { stack[stack.len - 1].left -= 1; }
            if stack.len == 0 { break; }
        }
    }
    if opts.deterministic {
        var again: u8[>..] = [];
        canonical(buf, doc, 0, again);
        if again[..] != buf[at..pos] { return -1, pos, ERR_NOT_DETERMINISTIC; }
    }
    return 0, pos, OK;
}

// Decodes buf, which must hold exactly one data item: the root's index
// (0) and OK, or an error (ERR_TRAILING for bytes after it).
fn decode(buf: const u8[:], opts: Options, doc: Node[>..]&) -> i64, i64 {
    let root, end, e = decode_at(buf, 0, opts, doc);
    if e != OK { return -1, e; }
    if end != buf.len {
        doc.clear();
        return -1, ERR_TRAILING;
    }
    return root, OK;
}

// A map's keys, all different: compared by their deterministic encodings,
// sorted so that equal ones are neighbours.
struct KeyRange { s: i64, e: i64 }

fn check_keys(buf: const u8[:], doc: const Node[:], m: i64) -> i64 {
    let n = doc[m].count / 2;
    if n < 2 { return OK; }
    var enc:    u8[>..]       = [];
    var ranges: KeyRange[>..] = [];
    var k = m + 1;
    for i in n {
        let s = enc.len;
        canonical(buf, doc, k, enc);
        ranges.push(KeyRange { s: s, e: enc.len });
        k = doc[doc[k].next].next;
    }
    sort(ranges) { a, b => compare(enc[a.s..a.e], enc[b.s..b.e]) < 0 };
    for i in 1..ranges.len {
        let a = ranges[i - 1];
        let b = ranges[i];
        if enc[a.s..a.e] == enc[b.s..b.e] { return ERR_DUPLICATE_KEY; }
    }
    return OK;
}

// --- Reading the tree ------------------------------------------------------------

// The item's bytes as they were encoded, head and children included.
fn raw(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:] { buf[doc[i].start..doc[i].end] }

fn is_int(doc: const Node[:], i: i64) -> bool { i >= 0 && (doc[i].major == UINT || doc[i].major == NEGINT) }
fn is_bytes(doc: const Node[:], i: i64) -> bool { i >= 0 && doc[i].major == BYTES }
fn is_text(doc: const Node[:], i: i64) -> bool { i >= 0 && doc[i].major == TEXT }
fn is_array(doc: const Node[:], i: i64) -> bool { i >= 0 && doc[i].major == ARRAY }
fn is_map(doc: const Node[:], i: i64) -> bool { i >= 0 && doc[i].major == MAP }
fn is_tag(doc: const Node[:], i: i64) -> bool { i >= 0 && doc[i].major == TAG }
fn is_null(doc: const Node[:], i: i64) -> bool { i >= 0 && doc[i].major == SIMPLE && doc[i].info == 22 }
fn is_undefined(doc: const Node[:], i: i64) -> bool { i >= 0 && doc[i].major == SIMPLE && doc[i].info == 23 }
fn is_float(doc: const Node[:], i: i64) -> bool {
    i >= 0 && doc[i].major == SIMPLE && doc[i].info >= 25 && doc[i].info <= 27
}

// An integer that fits an i64.
fn as_i64(doc: const Node[:], i: i64) -> i64, bool {
    if i < 0 { return 0, false; }
    let n = doc[i];
    if n.major == UINT {
        if n.arg > 0x7fffffffffffffff { return 0, false; }
        return n.arg as i64, true;
    }
    if n.major == NEGINT {
        if n.arg > 0x7fffffffffffffff { return 0, false; }
        return -1 - n.arg as i64, true;
    }
    return 0, false;
}

// An unsigned integer.
fn as_u64(doc: const Node[:], i: i64) -> u64, bool {
    if i < 0 || doc[i].major != UINT { return 0, false; }
    return doc[i].arg, true;
}

fn as_bool(doc: const Node[:], i: i64) -> bool, bool {
    if i < 0 || doc[i].major != SIMPLE || (doc[i].info != 20 && doc[i].info != 21) { return false, false; }
    return doc[i].info == 21, true;
}

// A simple value's number (false is 20, true 21, null 22, undefined 23).
fn as_simple(doc: const Node[:], i: i64) -> u64, bool {
    if i < 0 || doc[i].major != SIMPLE || doc[i].info > 24 { return 0, false; }
    return doc[i].arg, true;
}

// A half-precision float's value.
fn half_value(h: u64) -> f64 {
    let e = (h >> 10) & 0x1f;
    let m = (h & 0x3ff) as f64;
    var v = 0.0;
    if e == 0 { v = m * 0.000000059604644775390625; }
    else if e == 31 { v = if m == 0.0 { binary::f64_of_bits(0x7ff0000000000000) } else { binary::f64_of_bits(0x7ff8000000000000) }; }
    else {
        // (1024 + m) * 2^(e - 25), exactly: build the double's bits.
        let bits: u64 = ((e + 1008) << 52) | ((h & 0x3ff) << 42);
        v = binary::f64_of_bits(bits);
    }
    return if h & 0x8000 != 0 { -v } else { v };
}

// A float (half, single or double), as a double.
fn as_f64(doc: const Node[:], i: i64) -> f64, bool {
    if !is_float(doc, i) { return 0.0, false; }
    let n = doc[i];
    if n.info == 25 { return half_value(n.arg), true; }
    if n.info == 26 { let f: f64 = binary::f32_of_bits(n.arg as! u32);
        return f, true; }
    return binary::f64_of_bits(n.arg), true;
}

// A definite byte string's bytes, a slice of buf; false for anything else
// (an indefinite one included: see string_into).
fn as_bytes(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:], bool {
    if i < 0 || doc[i].major != BYTES || doc[i].indefinite { return buf[0..0], false; }
    return buf[doc[i].off..doc[i].end], true;
}

// A definite text string's bytes.
fn as_text(buf: const u8[:], doc: const Node[:], i: i64) -> const u8[:], bool {
    if i < 0 || doc[i].major != TEXT || doc[i].indefinite { return buf[0..0], false; }
    return buf[doc[i].off..doc[i].end], true;
}

// A byte or text string's bytes, its chunks joined when indefinite,
// appended to out.
fn string_into(buf: const u8[:], doc: const Node[:], i: i64, out: u8[>..]&) -> bool {
    if i < 0 || (doc[i].major != BYTES && doc[i].major != TEXT) { return false; }
    if !doc[i].indefinite {
        out.append(buf[doc[i].off..doc[i].end]);
        return true;
    }
    var c = if doc[i].count > 0 { i + 1 } else { -1 };
    while c >= 0 {
        out.append(buf[doc[c].off..doc[c].end]);
        c = doc[c].next;
    }
    return true;
}

// A tag's number, and the index of the item it encloses.
fn as_tag(doc: const Node[:], i: i64) -> u64, i64, bool {
    if i < 0 || doc[i].major != TAG { return 0, -1, false; }
    return doc[i].arg, i + 1, true;
}

// The number of elements of an array, pairs of a map.
fn length(doc: const Node[:], i: i64) -> i64 {
    if i < 0 { return 0; }
    if doc[i].major == ARRAY { return doc[i].count; }
    if doc[i].major == MAP { return doc[i].count / 2; }
    return 0;
}

// The index of element k of an array, or -1.
fn element(doc: const Node[:], i: i64, k: i64) -> i64 {
    if !is_array(doc, i) || k < 0 || k >= doc[i].count { return -1; }
    var c = i + 1;
    for j in k { c = doc[c].next; }
    return c;
}

// F(child) for each element of an array, or F(key, value) for each pair of
// a map, in order.
fn each<F>(doc: const Node[:], i: i64) {
    if !is_array(doc, i) { return; }
    var c = if doc[i].count > 0 { i + 1 } else { -1 };
    while c >= 0 {
        F(c);
        c = doc[c].next;
    }
}

fn each_pair<F>(doc: const Node[:], i: i64) {
    if !is_map(doc, i) { return; }
    var k = if doc[i].count > 0 { i + 1 } else { -1 };
    while k >= 0 {
        let v = doc[k].next;
        F(k, v);
        k = doc[v].next;
    }
}

// The index of the value of the map's integer key, or -1.
fn map_get_int(doc: const Node[:], m: i64, key: i64) -> i64 {
    if !is_map(doc, m) { return -1; }
    var found = -1;
    each_pair(doc, m) { k, v =>
        let kv, ok = as_i64(doc, k);
        if ok && kv == key && found < 0 { found = v; }
    };
    return found;
}

// The index of the value of the map's text key, or -1. A key written in
// chunks is joined to compare.
fn map_get_text(buf: const u8[:], doc: const Node[:], m: i64, key: const u8[:]) -> i64 {
    if !is_map(doc, m) { return -1; }
    var found = -1;
    each_pair(doc, m) { k, v =>
        if found < 0 && doc[k].major == TEXT {
            if !doc[k].indefinite {
                if buf[doc[k].off..doc[k].end] == key { found = v; }
            } else {
                var joined: u8[>..] = [];
                let ok = string_into(buf, doc, k, joined);
                if joined[..] == key { found = v; }
            }
        }
    };
    return found;
}

// --- Encoding -------------------------------------------------------------------

// A head in the fewest bytes.
fn put_head(out: u8[>..]&, major: u8, v: u64) {
    let m: u8 = major << 5;
    if v < 24 { out.push(m | v as! u8); return; }
    if v < 256 { out.push(m | 24); out.push(v as! u8); return; }
    if v < 65536 { out.push(m | 25); out.push((v >> 8) as! u8); out.push(v as! u8); return; }
    if v < 0x100000000 {
        out.push(m | 26);
        for k in 4 { out.push((v >> (24 - 8 * k)) as! u8); }
        return;
    }
    out.push(m | 27);
    for k in 8 { out.push((v >> (56 - 8 * k)) as! u8); }
}

fn put_uint(out: u8[>..]&, v: u64) { put_head(out, UINT, v); }

fn put_int(out: u8[>..]&, v: i64) {
    if v >= 0 { put_head(out, UINT, v as u64); }
    else { put_head(out, NEGINT, (-1 - v) as u64); }
}

// The negative integer -1-n, all of whose values an i64 cannot hold.
fn put_negint(out: u8[>..]&, n: u64) { put_head(out, NEGINT, n); }

fn put_bytes(out: u8[>..]&, b: const u8[:]) {
    put_head(out, BYTES, b.len as u64);
    out.append(b);
}

// A text string; false, and nothing written, when s is not UTF-8.
fn put_text(out: u8[>..]&, s: const u8[:]) -> bool {
    if !valid_utf8(s) { return false; }
    put_head(out, TEXT, s.len as u64);
    out.append(s);
    return true;
}

fn put_array(out: u8[>..]&, n: i64) { put_head(out, ARRAY, n as u64); }
fn put_map(out: u8[>..]&, pairs: i64) { put_head(out, MAP, pairs as u64); }
fn put_tag(out: u8[>..]&, tag: u64) { put_head(out, TAG, tag); }
fn put_bool(out: u8[>..]&, b: bool) { out.push(if b { 0xf5 } else { 0xf4 }); }
fn put_null(out: u8[>..]&) { out.push(0xf6); }
fn put_undefined(out: u8[>..]&) { out.push(0xf7); }

// A simple value: 0 to 23 and 32 to 255; false for the others (24 to 31
// cannot be written).
fn put_simple(out: u8[>..]&, v: u64) -> bool {
    if v > 255 || (v >= 24 && v < 32) { return false; }
    put_head(out, SIMPLE, v);
    return true;
}

// The half-precision bits of d, when a half holds d exactly.
fn half_of(d: f64) -> u64, bool {
    let bits = binary::bits_of_f64(d);
    let sign = (bits >> 63) << 15;
    let ex = ((bits >> 52) & 0x7ff) as i64;
    let mant = bits & 0xfffffffffffff;
    if ex == 0x7ff {
        if mant != 0 { return 0x7e00, true; }       // NaN: the one quiet NaN
        return sign | 0x7c00, true;
    }
    if ex == 0 && mant == 0 { return sign, true; }
    if ex == 0 { return 0, false; }                   // a double subnormal: far below a half's
    let e = ex - 1023;
    if e >= -14 && e <= 15 {
        if mant & 0x3ffffffffff != 0 { return 0, false; }
        return sign | ((e + 15) as u64 << 10) | (mant >> 42), true;
    }
    if e >= -24 && e < -14 {
        let shift = 28 - e;              // 42 + (-14 - e)
        let full = mant | 0x10000000000000;
        if full & ((1 << shift as u64) - 1) != 0 { return 0, false; }
        return sign | (full >> shift as u64), true;
    }
    return 0, false;
}

// The single-precision bits of d, when a single holds d exactly.
fn single_of(d: f64) -> u64, bool {
    let bits = binary::bits_of_f64(d);
    let sign = (bits >> 63) << 31;
    let ex = ((bits >> 52) & 0x7ff) as i64;
    let mant = bits & 0xfffffffffffff;
    if ex == 0x7ff {
        if mant != 0 {
            if mant & 0x1fffffff != 0 { return 0, false; }
            return sign | 0x7f800000 | (mant >> 29), true;
        }
        return sign | 0x7f800000, true;
    }
    if ex == 0 && mant == 0 { return sign, true; }
    if ex == 0 { return 0, false; }
    let e = ex - 1023;
    if e >= -126 && e <= 127 {
        if mant & 0x1fffffff != 0 { return 0, false; }
        return sign | ((e + 127) as u64 << 23) | (mant >> 29), true;
    }
    if e >= -149 && e < -126 {
        let shift = 29 + (-126 - e);
        let full = mant | 0x10000000000000;
        if full & ((1 << shift as u64) - 1) != 0 { return 0, false; }
        return sign | (full >> shift as u64), true;
    }
    return 0, false;
}

// A float in the shortest of half, single and double that holds it
// exactly (§4.2.1); every NaN as the half 0x7e00 (§4.2.2's choice).
fn put_float(out: u8[>..]&, d: f64) {
    let h, okh = half_of(d);
    if okh {
        out.push(0xf9);
        out.push((h >> 8) as! u8);
        out.push(h as! u8);
        return;
    }
    let s, oks = single_of(d);
    if oks {
        out.push(0xfa);
        for k in 4 { out.push((s >> (24 - 8 * k)) as! u8); }
        return;
    }
    put_double(out, d);
}

// A float as a double, whatever its value.
fn put_double(out: u8[>..]&, d: f64) {
    let b = binary::bits_of_f64(d);
    out.push(0xfb);
    for k in 8 { out.push((b >> (56 - 8 * k)) as! u8); }
}

// Where the definite item at buf[at..] ends, without building nodes;
// -1 if it is not one well-formed definite item.
fn skip(buf: const u8[:], at: i64) -> i64 {
    var pos = at;
    var pending: u64 = 1;
    while pending > 0 {
        let major, info, v, after, e = read_head(buf, pos, buf.len);
        if e != OK || info == 31 { return -1; }
        pending -= 1;
        pos = after;
        if major == BYTES || major == TEXT {
            if v > (buf.len - pos) as u64 { return -1; }
            pos += v as i64;
        } else if major == ARRAY || major == MAP {
            let more = if major == MAP { v * 2 } else { v };
            if v > (buf.len - pos) as u64 || more > (buf.len - pos) as u64 { return -1; }
            pending += more;
        } else if major == TAG {
            pending += 1;
        }
    }
    return pos;
}

// Sorts the pairs of the definite map whose head is at out[at..] (the
// rest of out being its pairs) by their keys' encodings: bytewise
// (§4.2.1), or shorter first when length_first (RFC 7049 §3.9, CTAP2).
// The keys are compared as written, so they should be deterministic
// already, as everything this package writes is. ERR_DUPLICATE_KEY for
// two equal keys, ERR_TYPE when out[at..] is not one definite map.
fn sort_map(out: u8[>..]&, at: i64, length_first: bool = false) -> i64 {
    let major, info, v, after, e = read_head(out, at, out.len);
    if e != OK || major != MAP || info == 31 { return ERR_TYPE; }
    var pairs: KeyPair[>..] = [];
    var pos = after;
    for i in v {
        let ke = skip(out, pos);
        if ke < 0 { return ERR_TYPE; }
        let ve = skip(out, ke);
        if ve < 0 { return ERR_TYPE; }
        pairs.push(KeyPair { ks: pos, ke: ke, ve: ve });
        pos = ve;
    }
    if pos != out.len { return ERR_TYPE; }
    let src = out[..];
    if length_first {
        stable_sort(pairs) { a, b =>
            let la = a.ke - a.ks;
            let lb = b.ke - b.ks;
            la < lb || (la == lb && compare(src[a.ks..a.ke], src[b.ks..b.ke]) < 0)
        };
    } else {
        stable_sort(pairs) { a, b => compare(src[a.ks..a.ke], src[b.ks..b.ke]) < 0 };
    }
    for i in 1..pairs.len {
        let a = pairs[i - 1];
        let b = pairs[i];
        if src[a.ks..a.ke] == src[b.ks..b.ke] { return ERR_DUPLICATE_KEY; }
    }
    var body: u8[>..] = [];
    for p in pairs { body.append(src[p.ks..p.ve]); }
    for i in body.len { out[after + i] = body[i]; }
    return OK;
}

struct KeyPair { ks: i64, ke: i64, ve: i64 }

// --- Re-encoding and diagnostic notation ------------------------------------------

struct Writer { buf: const u8[:], doc: const Node[:], out: u8[>..]&, length_first: bool }

// The item at doc[i] again, in the core deterministic encoding (or with
// map keys length-first): shortest heads, definite lengths, strings
// joined, floats shortest, map keys sorted. Equal values give equal bytes.
fn canonical(buf: const u8[:], doc: const Node[:], i: i64, out: u8[>..]&, length_first: bool = false) {
    var w = Writer { buf: buf, doc: doc, out: out, length_first: length_first };
    let next = canon_item(w, i);
}

// Writes item i; returns its next sibling.
recursive fn canon_item(w: Writer&, i: i64) -> i64 {
    let n = w.doc[i];
    if n.major == UINT || n.major == NEGINT || n.major == TAG {
        put_head(w.out, n.major, n.arg);
        if n.major == TAG { let c = canon_item(w, i + 1); }
        return n.next;
    }
    if n.major == BYTES || n.major == TEXT {
        if !n.indefinite {
            put_head(w.out, n.major, n.arg);
            w.out.append(w.buf[n.off..n.end]);
            return n.next;
        }
        var len: u64 = 0;
        var c = if n.count > 0 { i + 1 } else { -1 };
        while c >= 0 { len += w.doc[c].arg; c = w.doc[c].next; }
        put_head(w.out, n.major, len);
        c = if n.count > 0 { i + 1 } else { -1 };
        while c >= 0 { w.out.append(w.buf[w.doc[c].off..w.doc[c].end]); c = w.doc[c].next; }
        return n.next;
    }
    if n.major == ARRAY || n.major == MAP {
        let at = w.out.len;
        put_head(w.out, n.major, if n.major == MAP { (n.count / 2) as u64 } else { n.count as u64 });
        var c = if n.count > 0 { i + 1 } else { -1 };
        while c >= 0 { c = canon_item(w, c); }
        if n.major == MAP && n.count > 2 { let e = sort_map(w.out, at, w.length_first); }
        return n.next;
    }
    // Simple values and floats.
    if n.info >= 25 && n.info <= 27 {
        let v, ok = as_f64(w.doc, i);
        put_float(w.out, v);
    } else {
        put_head(w.out, SIMPLE, n.arg);
    }
    return n.next;
}

// Decodes buf and writes it again deterministically into out.
fn to_canonical(buf: const u8[:], opts: Options, out: u8[>..]&, length_first: bool = false) -> i64 {
    var doc: Node[>..] = [];
    let root, e = decode(buf, opts, doc);
    if e != OK { return e; }
    canonical(buf, doc, root, out, length_first);
    return OK;
}

let HEX: const u8[:] = "0123456789abcdef";

fn put_hex(out: u8[>..]&, b: const u8[:]) {
    for c in b {
        out.push(HEX[(c >> 4) as i64]);
        out.push(HEX[(c & 15) as i64]);
    }
}

// A double in diagnostic notation: 1.0, 1.5e+300, 5.960464477539063e-8,
// Infinity, NaN.
fn put_diag_float(out: u8[>..]&, v: f64) {
    if v != v { out.append("NaN"); return; }
    if v > 1.7976931348623157e308 { out.append("Infinity"); return; }
    if v < -1.7976931348623157e308 { out.append("-Infinity"); return; }
    var t: u8[>..] = [];
    format(t, v);
    let e = find(t, "e");
    var mant: u8[>..] = [];
    mant.append(if e >= 0 { t[..e] } else { t[..] });
    if find(mant, ".") < 0 { mant.append(".0"); }
    out.append(mant);
    if e >= 0 {
        out.push('e');
        var p = e + 1;
        var sign: u8 = '+';
        if t[p] == '-' || t[p] == '+' { sign = t[p]; p++; }
        while p < t.len - 1 && t[p] == '0' { p++; }
        out.push(sign);
        out.append(t[p..]);
    }
}

fn put_diag_text(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c == '"' || c == '\\' { out.push('\\'); out.push(c); i++; continue; }
        if c >= 0x20 && c < 0x7f { out.push(c); i++; continue; }
        // A code point: below 0x80 as itself, the rest as \u escapes
        // (UTF-16, a pair for the astral planes).
        var cp: i64 = c;
        var n = 0;
        if c >= 0xf0 { cp = c & 7; n = 3; }
        else if c >= 0xe0 { cp = c & 15; n = 2; }
        else if c >= 0xc0 { cp = c & 31; n = 1; }
        for k in 1..n + 1 { cp = (cp << 6) | (s[i + k] & 0x3f); }
        i += n + 1;
        if cp >= 0x10000 {
            let u = cp - 0x10000;
            put_u_escape(out, 0xd800 + (u >> 10));
            put_u_escape(out, 0xdc00 + (u & 0x3ff));
        } else {
            put_u_escape(out, cp);
        }
    }
    out.push('"');
}

fn put_u_escape(out: u8[>..]&, v: i64) {
    out.append("\\u");
    for k in 4 { out.push(HEX[(v >> (12 - 4 * k)) & 15]); }
}

// The item at doc[i] in diagnostic notation (RFC 8949 §8): integers,
// h'..' byte strings, "..." text (\u escapes past ASCII), [..], {..: ..},
// tags as n(..), floats as 1.5, simple values as false, true, null,
// undefined and simple(n); indefinite lengths as (_ ..), [_ ..], {_ ..}.
fn diag(buf: const u8[:], doc: const Node[:], i: i64, out: u8[>..]&) {
    var w = Writer { buf: buf, doc: doc, out: out, length_first: false };
    let next = diag_item(w, i);
}

recursive fn diag_item(w: Writer&, i: i64) -> i64 {
    let n = w.doc[i];
    if n.major == UINT { format(w.out, n.arg); return n.next; }
    if n.major == NEGINT {
        if n.arg == 0xffffffffffffffff { w.out.append("-18446744073709551616"); }
        else { w.out.push('-'); format(w.out, n.arg + 1); }
        return n.next;
    }
    if n.major == BYTES || n.major == TEXT {
        if !n.indefinite {
            if n.major == BYTES {
                w.out.append("h'");
                put_hex(w.out, w.buf[n.off..n.end]);
                w.out.push('\'');
            } else {
                put_diag_text(w.out, w.buf[n.off..n.end]);
            }
            return n.next;
        }
        w.out.append("(_ ");
        var c = if n.count > 0 { i + 1 } else { -1 };
        var first = true;
        while c >= 0 {
            if !first { w.out.append(", "); }
            first = false;
            c = diag_item(w, c);
        }
        w.out.push(')');
        return n.next;
    }
    if n.major == ARRAY || n.major == MAP {
        w.out.push(if n.major == ARRAY { '[' } else { '{' });
        if n.indefinite { w.out.append("_ "); }
        var c = if n.count > 0 { i + 1 } else { -1 };
        var k = 0;
        while c >= 0 {
            if k > 0 { w.out.append(if n.major == MAP && k % 2 == 1 { ": " } else { ", " }); }
            c = diag_item(w, c);
            k++;
        }
        w.out.push(if n.major == ARRAY { ']' } else { '}' });
        return n.next;
    }
    if n.major == TAG {
        format(w.out, n.arg, "(");
        let c = diag_item(w, i + 1);
        w.out.push(')');
        return n.next;
    }
    if n.info >= 25 && n.info <= 27 {
        let v, ok = as_f64(w.doc, i);
        put_diag_float(w.out, v);
        return n.next;
    }
    if n.arg == 20 { w.out.append("false"); }
    else if n.arg == 21 { w.out.append("true"); }
    else if n.arg == 22 { w.out.append("null"); }
    else if n.arg == 23 { w.out.append("undefined"); }
    else { format(w.out, "simple(", n.arg, ")"); }
    return n.next;
}
