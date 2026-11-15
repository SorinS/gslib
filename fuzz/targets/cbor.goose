// Fuzz target: cbor. The first byte picks the decode options (bit 0
// indefinite lengths, bit 1 shortest heads required, bit 2 deterministic
// required, bit 3 small limits); the rest is decoded. Every node is read
// by every accessor, maps looked up by int and text keys and their keys
// checked; then the whole item in diagnostic notation, written again
// deterministically (and length-first), which must decode again under
// the deterministic rules to the same bytes; skip and sort_map too.

import std;
import gslib from "../..";
import gslib.encoding.cbor;

fn probe(buf: const u8[:], doc: const cbor::Node[:], i: i64) {
    let _ = cbor::raw(buf, doc, i);
    let _ = cbor::as_i64(doc, i);
    let _ = cbor::as_u64(doc, i);
    let _ = cbor::as_bool(doc, i);
    let _ = cbor::as_simple(doc, i);
    let _ = cbor::as_f64(doc, i);
    let _ = cbor::as_bytes(buf, doc, i);
    let _ = cbor::as_text(buf, doc, i);
    let _ = cbor::as_tag(doc, i);
    let _ = cbor::is_null(doc, i);
    let _ = cbor::is_undefined(doc, i);
    let _ = cbor::is_float(doc, i);
    let _ = cbor::length(doc, i);
    let _ = cbor::element(doc, i, 0);
    let _ = cbor::element(doc, i, 1);
    var s: u8[>..] = [];
    let _ = cbor::string_into(buf, doc, i, s);
    if cbor::is_map(doc, i) {
        let _ = cbor::map_get_int(doc, i, 1);
        let _ = cbor::map_get_int(doc, i, -1);
        let _ = cbor::map_get_text(buf, doc, i, "fmt");
        let _ = cbor::check_keys(buf, doc, i);
    }
    var n = 0;
    cbor::each(doc, i) { c => n++; };
    cbor::each_pair(doc, i) { k, v => n++; };
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let sel = data[0];
    let buf = data[1..];
    var o = cbor::Options { .. };
    o.indefinite = sel & 1 != 0;
    o.require_shortest = sel & 2 != 0;
    o.deterministic = sel & 4 != 0;
    if sel & 8 != 0 { o.max_depth = 4; o.max_items = 64; o.max_bytes = 512; }
    var doc: cbor::Node[>..] = [];
    let root, e = cbor::decode(buf, o, doc);
    let _ = cbor::skip(buf, 0);
    if e != cbor::OK { return 0; }
    for i in doc.len { probe(buf, doc, i); }
    var d: u8[>..] = [];
    cbor::diag(buf, doc, root, d);
    // The deterministic encoding decodes again, deterministically, to itself.
    var canon: u8[>..] = [];
    cbor::canonical(buf, doc, root, canon);
    var doc2: cbor::Node[>..] = [];
    let det = cbor::Options { deterministic: true, max_depth: 1000, max_items: 1 << 30, max_bytes: 1 << 30, .. };
    let root2, e2 = cbor::decode(canon, det, doc2);
    if e2 != cbor::OK { abort(str("canonical output does not decode deterministically: ", cbor::error_text(e2))); }
    var canon2: u8[>..] = [];
    cbor::canonical(canon, doc2, root2, canon2);
    if canon2[..] != canon[..] { abort("canonical is not idempotent"); }
    var lf: u8[>..] = [];
    cbor::canonical(buf, doc, root, lf, true);
    var t: u8[>..] = [];
    let _ = cbor::to_canonical(buf, o, t);
    if cbor::is_map(doc, root) {
        var m = copy(canon);
        let _ = cbor::sort_map(m, 0);
        let _ = cbor::sort_map(m, 0, true);
    }
    return 0;
}

fn main() {}
