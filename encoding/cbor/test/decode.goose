// Decoding: every example of RFC 8949 Appendix A, read back in diagnostic
// notation and written again deterministically; every strict prefix of
// each one refused as truncated, and a byte after each as trailing; the
// indefinite ones refused unless opted into; and the hostile inputs: the
// reserved additional information values, stray and misplaced breaks,
// simple values in two bytes, chunks of the wrong type, duplicate map keys
// (also written in two forms), UTF-8 that is malformed, overlong or a
// surrogate, lengths and counts past the input, nesting, item and size
// limits, heads and floats longer than needed, and encodings that are not
// deterministic.
import std;
import os;
import gslib from "../../..";
import gslib.encoding.cbor;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((ascii::hex_value(s[i]) * 16 + ascii::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn code_of(hex: const u8[:], o: const cbor::Options&) -> i64 {
    let b = unhex(hex);
    var doc: cbor::Node[>..] = [];
    let root, e = cbor::decode(b, o, doc);
    return e;
}

fn expect(what: const u8[:], hex: const u8[:], o: cbor::Options, want: i64) {
    let got = code_of(hex, o);
    check(str(what, " (", hex, "): ", cbor::error_text(got)), got == want);
}

fn appendix_a() {
    var text: u8[>..] = [];
    guard read_file("data/appendix_a.txt", text) else { print("cannot read data/appendix_a.txt"); exit(1); }
    let lax = cbor::Options { indefinite: true, .. };
    let strict = cbor::Options { .. };
    let det = cbor::Options { indefinite: true, deterministic: true, .. };
    var n = 0;
    for raw_line in split(text, '\n') {
        let line = trim(raw_line);
        if line.len == 0 || line[0] == '#' { continue; }
        let parts = split(line, " | ");
        guard parts.len == 3 else { check(str("vector line: ", line), false); continue; }
        n++;
        let b = unhex(parts[0]);
        let indef = find(parts[1], "(_") >= 0 || find(parts[1], "[_") >= 0 || find(parts[1], "{_") >= 0;
        var doc: cbor::Node[>..] = [];
        let root, e = cbor::decode(b, lax, doc);
        check(str("decode ", parts[0], ": ", cbor::error_text(e)), e == cbor::OK);
        if e != cbor::OK { continue; }
        var d: u8[>..] = [];
        cbor::diag(b, doc, root, d);
        check(str("diag ", parts[0], ": ", d, " want ", parts[1]), d[..] == parts[1]);
        var c: u8[>..] = [];
        cbor::canonical(b, doc, root, c);
        let wantc = unhex(if parts[2] == "=" { parts[0] } else { parts[2] });
        check(str("canonical ", parts[0]), c[..] == wantc[..]);
        // The whole item, and nothing after it.
        check(str("end ", parts[0]), doc[root].end == b.len);
        // Strict: no indefinite lengths.
        let es = code_of(parts[0], strict);
        check(str("strict ", parts[0], ": ", cbor::error_text(es)), es == (if indef { cbor::ERR_INDEFINITE } else { cbor::OK }));
        // Deterministic: exactly the vectors that are their own encoding.
        let ed = code_of(parts[0], det);
        let is_det = parts[2] == "=";
        check(str("deterministic ", parts[0], ": ", cbor::error_text(ed)),
              (ed == cbor::OK) == is_det && (is_det || ed == cbor::ERR_NOT_DETERMINISTIC));
        // Every strict prefix is cut short; a byte more is trailing.
        for k in b.len {
            var doc2: cbor::Node[>..] = [];
            let r2, e2 = cbor::decode(b[..k], lax, doc2);
            if e2 != cbor::ERR_TRUNCATED { check(str("prefix ", k, " of ", parts[0], ": ", cbor::error_text(e2)), false); }
        }
        var more: u8[>..] = copy(b);
        more.push(0);
        var doc3: cbor::Node[>..] = [];
        let r3, e3 = cbor::decode(more, lax, doc3);
        check(str("trailing ", parts[0]), e3 == cbor::ERR_TRAILING);
        let r4, end4, e4 = cbor::decode_at(more, 0, lax, doc3);
        check(str("decode_at ", parts[0]), e4 == cbor::OK && end4 == b.len);
    }
    check("81 vectors", n == 81);
}

fn hostile() {
    let o = cbor::Options { .. };
    let lax = cbor::Options { indefinite: true, .. };
    // Reserved additional information, for every major type.
    for m in 8 {
        for ai in 28..31 {
            var h: u8[>..] = [];
            cbor::put_hex(h, [((m << 5) | ai) as! u8]);
            expect("reserved", h, lax, cbor::ERR_MALFORMED);
        }
    }
    expect("break alone", "ff", lax, cbor::ERR_MALFORMED);
    expect("break after a definite array", "8101ff", lax, cbor::ERR_TRAILING);
    expect("break in a definite array", "8201ff", lax, cbor::ERR_MALFORMED);
    expect("break in a definite map", "a201ff0000", lax, cbor::ERR_MALFORMED);
    expect("indefinite integer", "1f", lax, cbor::ERR_MALFORMED);
    expect("indefinite negative", "3f", lax, cbor::ERR_MALFORMED);
    expect("indefinite tag", "df00", lax, cbor::ERR_MALFORMED);
    expect("simple 0 in two bytes", "f800", lax, cbor::ERR_MALFORMED);
    expect("simple 31 in two bytes", "f81f", lax, cbor::ERR_MALFORMED);
    expect("simple 32 in two bytes", "f820", lax, cbor::OK);
    expect("text chunk in bytes", "5f6161ff", lax, cbor::ERR_MALFORMED);
    expect("indefinite chunk", "5f5fffff", lax, cbor::ERR_MALFORMED);
    expect("integer chunk", "7f01ff", lax, cbor::ERR_MALFORMED);
    expect("indefinite map, a key alone", "bf01ff", lax, cbor::ERR_MALFORMED);
    expect("indefinite array unclosed", "9f0102", lax, cbor::ERR_TRUNCATED);
    expect("tag with nothing", "c0", o, cbor::ERR_TRUNCATED);
    expect("bytes past the end", "5bffffffffffffffff00", o, cbor::ERR_TRUNCATED);
    expect("text past the end", "7a7fffffff61", o, cbor::ERR_TRUNCATED);
    expect("array count past the end", "9b000000010000000001", o, cbor::ERR_TRUNCATED);
    expect("map count past the end", "bbffffffffffffffff", o, cbor::ERR_TRUNCATED);
    // Duplicate keys, also by value through a longer head, and in an
    // indefinite map; nested maps as keys.
    expect("duplicate int key", "a201010102", o, cbor::ERR_DUPLICATE_KEY);
    expect("duplicate key, two forms", "a20101180102", o, cbor::ERR_DUPLICATE_KEY);
    expect("duplicate key, shortest asked", "a20101180102", cbor::Options { require_shortest: true, .. }, cbor::ERR_NOT_SHORTEST);
    expect("duplicate text key", "a2616101616102", o, cbor::ERR_DUPLICATE_KEY);
    expect("duplicate key, chunked text", "a26161017f6161ff02", lax, cbor::ERR_DUPLICATE_KEY);
    expect("duplicate key, indefinite map", "bf01010102ff", lax, cbor::ERR_DUPLICATE_KEY);
    expect("duplicate float key", "a2f93c0001fb3ff000000000000002", o, cbor::ERR_DUPLICATE_KEY);
    expect("int and float keys differ", "a201f9f93c0002", o, cbor::OK);
    expect("map keys that are maps", "a2a1010201a1010203", o, cbor::ERR_DUPLICATE_KEY);
    expect("map keys, maps in two orders", "a2a20102030401a2030401020203", o, cbor::ERR_DUPLICATE_KEY);
    expect("nested duplicate", "a101a201010102", o, cbor::ERR_DUPLICATE_KEY);
    expect("different keys", "a3010102020303", o, cbor::OK);
    // UTF-8.
    expect("bad UTF-8", "62c328", o, cbor::ERR_UTF8);
    expect("overlong UTF-8", "62c080", o, cbor::ERR_UTF8);
    expect("overlong three", "63e08080", o, cbor::ERR_UTF8);
    expect("surrogate", "63eda080", o, cbor::ERR_UTF8);
    expect("past U+10FFFF", "64f4908080", o, cbor::ERR_UTF8);
    expect("cut UTF-8", "61e2", o, cbor::ERR_UTF8);
    expect("cut UTF-8 in a chunk", "7f61e261829cff", lax, cbor::ERR_UTF8);
    expect("UTF-8 ok", "64f48fbfbf", o, cbor::OK);
    expect("bytes need no UTF-8", "42c328", o, cbor::OK);
    // Limits.
    var deep: u8[>..] = [];
    for i in 16 { deep.push(0x81); }
    deep.push(0);
    var h16: u8[>..] = [];
    cbor::put_hex(h16, deep);
    expect("16 levels", h16, o, cbor::OK);
    var deeper: u8[>..] = [0x81];
    deeper.append(deep);
    var h17: u8[>..] = [];
    cbor::put_hex(h17, deeper);
    expect("17 levels", h17, o, cbor::ERR_DEPTH);
    expect("17 levels, allowed", h17, cbor::Options { max_depth: 17, .. }, cbor::OK);
    expect("tags count as levels", "c1c1c101", cbor::Options { max_depth: 2, .. }, cbor::ERR_DEPTH);
    expect("items", "83010203", cbor::Options { max_items: 3, .. }, cbor::ERR_TOO_MANY);
    expect("items, enough", "83010203", cbor::Options { max_items: 4, .. }, cbor::OK);
    expect("chunks are items", "5f41014102ff", cbor::Options { indefinite: true, max_items: 2, .. }, cbor::ERR_TOO_MANY);
    expect("size", "4401020304", cbor::Options { max_bytes: 4, .. }, cbor::ERR_TOO_LARGE);
    expect("size, enough", "4401020304", cbor::Options { max_bytes: 5, .. }, cbor::OK);
    // Heads longer than needed, when asked; and deterministic encoding.
    let sh = cbor::Options { require_shortest: true, .. };
    expect("1817", "1817", sh, cbor::ERR_NOT_SHORTEST);
    expect("1818", "1818", sh, cbor::OK);
    expect("190000", "190000", sh, cbor::ERR_NOT_SHORTEST);
    expect("1a0000ffff", "1a0000ffff", sh, cbor::ERR_NOT_SHORTEST);
    expect("1b00000000ffffffff", "1b00000000ffffffff", sh, cbor::ERR_NOT_SHORTEST);
    expect("length 5800", "5800", sh, cbor::ERR_NOT_SHORTEST);
    expect("count 9800", "9800", sh, cbor::ERR_NOT_SHORTEST);
    expect("tag d800 00", "d80000", sh, cbor::ERR_NOT_SHORTEST);
    expect("1817 lax", "1817", o, cbor::OK);
    let det = cbor::Options { deterministic: true, .. };
    expect("unsorted map", "a203040102", det, cbor::ERR_NOT_DETERMINISTIC);
    expect("sorted map", "a201020304", det, cbor::OK);
    expect("length-first is not bytewise", "a20a036161f5", det, cbor::OK);
    expect("1.0 as single", "fa3f800000", det, cbor::ERR_NOT_DETERMINISTIC);
    expect("NaN with a payload", "f97e01", det, cbor::ERR_NOT_DETERMINISTIC);
    expect("non-shortest head", "1801", det, cbor::ERR_NOT_SHORTEST);
    expect("unsorted nested map", "81a2616201616101", det, cbor::ERR_NOT_DETERMINISTIC);
}

fn main() {
    appendix_a();
    hostile();
    print("decode: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
