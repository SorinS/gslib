// Encoding: integers at every head size and both ends of i64 and u64;
// floats in the shortest form that keeps them (half, single, double, the
// subnormals at each width's edge, infinities, -0.0, every NaN as 7e00);
// strings, arrays, maps, tags and simple values; text that is not UTF-8
// and simple values 24 to 31 refused; sort_map in both orders, and its
// duplicate keys; canonical re-encoding; and values read back as written.
import std;
import binary;
import gslib from "../../..";
import gslib.encoding.cbor;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    cbor::put_hex(out, b);
    return out;
}

fn int_is(v: i64, want: const u8[:]) {
    var out: u8[>..] = [];
    cbor::put_int(out, v);
    let h = hex(out);
    check(str("int ", v, ": ", h, " want ", want), h[..] == want);
    var doc: cbor::Node[>..] = [];
    let root, e = cbor::decode(out, cbor::Options { deterministic: true, .. }, doc);
    let back, ok = cbor::as_i64(doc, root);
    check(str("int ", v, " back"), e == cbor::OK && ok && back == v);
}

fn float_is(v: f64, want: const u8[:]) {
    var out: u8[>..] = [];
    cbor::put_float(out, v);
    let h = hex(out);
    check(str("float ", v, ": ", h, " want ", want), h[..] == want);
    var doc: cbor::Node[>..] = [];
    let opts = cbor::Options { deterministic: true, .. };
    let root, e = cbor::decode(out, opts, doc);
    let back, ok = cbor::as_f64(doc, root);
    let same = if v != v { back != back } else { binary::bits_of_f64(back) == binary::bits_of_f64(v) };
    check(str("float ", v, " back: ", back), e == cbor::OK && ok && same);
}

fn main() {
    int_is(0, "00");
    int_is(23, "17");
    int_is(24, "1818");
    int_is(255, "18ff");
    int_is(256, "190100");
    int_is(65535, "19ffff");
    int_is(65536, "1a00010000");
    int_is(4294967295, "1affffffff");
    int_is(4294967296, "1b0000000100000000");
    int_is(9223372036854775807, "1b7fffffffffffffff");
    int_is(-1, "20");
    int_is(-24, "37");
    int_is(-25, "3818");
    int_is(-256, "38ff");
    int_is(-257, "390100");
    int_is(-9223372036854775807 - 1, "3b7fffffffffffffff");
    var u: u8[>..] = [];
    cbor::put_uint(u, 0xffffffffffffffff);
    cbor::put_negint(u, 0xffffffffffffffff);
    check("u64 max and its negative", hex(u)[..] == "1bffffffffffffffff3bffffffffffffffff");
    var d2: cbor::Node[>..] = [];
    let r2, end2, e2 = cbor::decode_at(u, 0, cbor::Options { .. }, d2);
    let big, okbig = cbor::as_i64(d2, r2);
    let bigu, okbigu = cbor::as_u64(d2, r2);
    check("u64 max is no i64", e2 == cbor::OK && !okbig && okbigu && bigu == 0xffffffffffffffff && end2 == 9);

    float_is(0.0, "f90000");
    float_is(-0.0, "f98000");
    float_is(1.0, "f93c00");
    float_is(1.5, "f93e00");
    float_is(65504.0, "f97bff");
    float_is(65505.0, "fa477fe100");
    float_is(100000.0, "fa47c35000");
    float_is(0.000000059604644775390625, "f90001");      // the smallest half subnormal
    float_is(0.00006103515625, "f90400");                // the smallest half normal
    float_is(0.00006097555160522461, "f903ff");          // the largest half subnormal
    float_is(0.0000000298023223876953125, "fa33000000"); // half of the smallest half: a single
    float_is(3.4028234663852886e38, "fa7f7fffff");
    float_is(1.401298464324817e-45, "fa00000001");       // the smallest single subnormal
    float_is(1.1754943508222875e-38, "fa00800000");      // the smallest single normal
    float_is(1.1, "fb3ff199999999999a");
    float_is(1.0e300, "fb7e37e43c8800759c");
    float_is(5e-324, "fb0000000000000001");
    float_is(-4.0, "f9c400");
    float_is(binary::f64_of_bits(0x7ff0000000000000), "f97c00");
    float_is(binary::f64_of_bits(0xfff0000000000000), "f9fc00");
    float_is(binary::f64_of_bits(0x7ff8000000000001), "f97e00");
    float_is(binary::f64_of_bits(0xfff8000000000000), "f97e00");
    var dd: u8[>..] = [];
    cbor::put_double(dd, 1.0);
    check("put_double", hex(dd)[..] == "fb3ff0000000000000");

    // Strings, arrays, maps, tags, simple values.
    var o: u8[>..] = [];
    cbor::put_bytes(o, "\x01\x02");
    check("text ok", cbor::put_text(o, "\xc3\xbc"));
    check("text not UTF-8", !cbor::put_text(o, "\xc3"));
    cbor::put_array(o, 2);
    cbor::put_bool(o, true);
    cbor::put_null(o);
    cbor::put_tag(o, 1000);
    cbor::put_undefined(o);
    check("simple 16", cbor::put_simple(o, 16));
    check("simple 24", !cbor::put_simple(o, 24));
    check("simple 31", !cbor::put_simple(o, 31));
    check("simple 32", cbor::put_simple(o, 32));
    check("simple 256", !cbor::put_simple(o, 256));
    check("mixed", hex(o)[..] == "42010262c3bc82f5f6d903e8f7f0f820");

    // sort_map: bytewise and length-first.
    var m: u8[>..] = [];
    cbor::put_map(m, 5);
    cbor::put_text(m, "aa"); cbor::put_int(m, 1);
    cbor::put_text(m, "b"); cbor::put_int(m, 2);
    cbor::put_int(m, 100); cbor::put_int(m, 3);
    cbor::put_int(m, -1); cbor::put_int(m, 4);
    cbor::put_int(m, 10); cbor::put_int(m, 5);
    var m2 = copy(m);
    check("sort_map bytewise", cbor::sort_map(m, 0) == cbor::OK);
    check("bytewise order", hex(m)[..] == "a50a05186403200461620262616101");
    check("sort_map length-first", cbor::sort_map(m2, 0, true) == cbor::OK);
    check("length-first order", hex(m2)[..] == "a50a05200418640361620262616101");
    // A map inside other things: sort_map takes the tail of out.
    var nested: u8[>..] = [];
    cbor::put_array(nested, 2);
    cbor::put_int(nested, 7);
    let at = nested.len;
    cbor::put_map(nested, 2);
    cbor::put_int(nested, 3); cbor::put_int(nested, 0);
    cbor::put_int(nested, 1); cbor::put_int(nested, 0);
    check("sort_map at", cbor::sort_map(nested, at) == cbor::OK && hex(nested)[..] == "8207a201000300");
    var dup: u8[>..] = [];
    cbor::put_map(dup, 2);
    cbor::put_int(dup, 1); cbor::put_int(dup, 1);
    cbor::put_int(dup, 1); cbor::put_int(dup, 2);
    check("sort_map duplicate", cbor::sort_map(dup, 0) == cbor::ERR_DUPLICATE_KEY);
    var notmap: u8[>..] = [];
    cbor::put_array(notmap, 0);
    check("sort_map not a map", cbor::sort_map(notmap, 0) == cbor::ERR_TYPE);
    var short: u8[>..] = [];
    cbor::put_map(short, 2);
    cbor::put_int(short, 1);
    check("sort_map short", cbor::sort_map(short, 0) == cbor::ERR_TYPE);

    // canonical: from a lax encoding to the deterministic one.
    let lax: const u8[:] = "\xbf\x63Fun\xf5\x63Amt\x21\x18\x01\x9f\x5f\x41\x01\xff\xff\xfa\x3f\x80\x00\x00\x01\xff";
    var c: u8[>..] = [];
    let ec = cbor::to_canonical(lax, cbor::Options { indefinite: true, .. }, c);
    check(str("to_canonical: ", cbor::error_text(ec), " ", hex(c)), ec == cbor::OK && hex(c)[..] == "a40181410163416d74216346756ef5f93c0001");
    var c2: u8[>..] = [];
    let ec2 = cbor::to_canonical(lax, cbor::Options { indefinite: true, .. }, c2, true);
    check(str("to_canonical length-first: ", hex(c2)), ec2 == cbor::OK && hex(c2)[..] == "a401814101f93c000163416d74216346756ef5");
    var c3: u8[>..] = [];
    check("to_canonical strict refuses", cbor::to_canonical(lax, cbor::Options { .. }, c3) == cbor::ERR_INDEFINITE && c3.len == 0);

    // Reading: maps by key, elements, strings, tags.
    var t: u8[>..] = [];
    cbor::put_map(t, 3);
    cbor::put_int(t, 1);
    cbor::put_int(t, 2);
    cbor::put_int(t, 3);
    cbor::put_int(t, -7);
    cbor::put_text(t, "x");
    cbor::put_array(t, 3);
    cbor::put_bytes(t, "abc");
    cbor::put_tag(t, 24);
    cbor::put_bytes(t, "\xa0");
    cbor::put_float(t, 2.5);
    var doc: cbor::Node[>..] = [];
    let root, e = cbor::decode(t, cbor::Options { .. }, doc);
    check("decode built map", e == cbor::OK && cbor::length(doc, root) == 3);
    let alg, okalg = cbor::as_i64(doc, cbor::map_get_int(doc, root, 3));
    check("key 3", okalg && alg == -7);
    check("key 4 absent", cbor::map_get_int(doc, root, 4) == -1);
    let arr = cbor::map_get_text(t, doc, root, "x");
    check("text key", cbor::is_array(doc, arr) && cbor::length(doc, arr) == 3);
    let b0, okb = cbor::as_bytes(t, doc, cbor::element(doc, arr, 0));
    check("element 0", okb && b0 == "abc");
    let tn, inner, okt = cbor::as_tag(doc, cbor::element(doc, arr, 1));
    let ib, okib = cbor::as_bytes(t, doc, inner);
    check("tag 24", okt && tn == 24 && okib && ib == "\xa0");
    let fv, okf = cbor::as_f64(doc, cbor::element(doc, arr, 2));
    check("float element", okf && fv == 2.5);
    check("element 3 absent", cbor::element(doc, arr, 3) == -1);
    let nb, oknb = cbor::as_bytes(t, doc, cbor::element(doc, arr, 2));
    check("not bytes", !oknb);
    var seen = 0;
    cbor::each(doc, arr) { it => seen++; };
    check("each", seen == 3);
    var keys = 0;
    cbor::each_pair(doc, root) { k, v => keys++; };
    check("each_pair", keys == 3);
    check("raw", cbor::raw(t, doc, arr)[..] == t[doc[arr].start..]);

    print("encode: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
