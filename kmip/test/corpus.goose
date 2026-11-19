// PyKMIP's encodings (test/vectors/pykmip.txt, from its unit tests):
// each decoded, written again from what was decoded, and compared. The
// ones refused are printed with why: those are malformed on purpose.

import std;
import gslib from "../..";
import gslib.kmip;

let VECTORS = embed_file("vectors/pykmip.txt");

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

recursive fn rewrite(out: u8[>..]&, buf: const u8[:], doc: const kmip::Node[:], i: i64) {
    let n = doc[i];
    if n.typ == kmip::STRUCTURE {
        let s = kmip::begin(out, n.tag);
        kmip::each(doc, i) { c => rewrite(out, buf, doc, c); };
        kmip::end(out, s);
    } else if n.typ == kmip::INTEGER { let v, ok = kmip::as_int(buf, doc, i); kmip::put_int(out, n.tag, v); }
    else if n.typ == kmip::LONG_INTEGER { let v, ok = kmip::as_long(buf, doc, i); kmip::put_long(out, n.tag, v); }
    else if n.typ == kmip::BIG_INTEGER { let v, ok = kmip::as_bigint(buf, doc, i); kmip::put_bigint(out, n.tag, v); }
    else if n.typ == kmip::ENUMERATION { let v, ok = kmip::as_enum(buf, doc, i); kmip::put_enum(out, n.tag, v); }
    else if n.typ == kmip::BOOLEAN { let v, ok = kmip::as_bool(buf, doc, i); kmip::put_bool(out, n.tag, v); }
    else if n.typ == kmip::TEXT_STRING { let v, ok = kmip::as_text(buf, doc, i); kmip::put_text(out, n.tag, v); }
    else if n.typ == kmip::BYTE_STRING { let v, ok = kmip::as_bytes(buf, doc, i); kmip::put_bytes(out, n.tag, v); }
    else if n.typ == kmip::DATE_TIME { let v, ok = kmip::as_datetime(buf, doc, i); kmip::put_datetime(out, n.tag, v); }
    else if n.typ == kmip::INTERVAL { let v, ok = kmip::as_interval(buf, doc, i); kmip::put_interval(out, n.tag, v); }
    else { kmip::put_raw(out, kmip::raw(buf, doc, i)); }
}

fn main() {
    var total = 0;
    var same = 0;
    var refused = 0;
    var differ = 0;
    var start = 0;
    while start < VECTORS.len {
        var stop = start;
        while stop < VECTORS.len && VECTORS[stop] != '\n' { stop++; }
        let line = VECTORS[start..stop];
        start = stop + 1;
        var sp = 0;
        while sp < line.len && line[sp] != ' ' { sp++; }
        if sp >= line.len { continue; }
        let name = line[..sp];
        let enc = unhex(line[sp + 1..]);
        total++;
        var doc: kmip::Node[>..] = [];
        let root, e = kmip::decode(enc, kmip::Options { .. }, doc);
        if e != kmip::OK {
            refused++;
            print("refused ", name, ": ", kmip::error_text(e));
            continue;
        }
        var out: u8[>..] = [];
        rewrite(out, enc, doc, root);
        if out[..] == enc[..] { same++; } else { differ++; print("DIFFERS ", name); }
    }
    print(total, " encodings: ", same, " written again the same, ", refused, " refused, ", differ, " different");
    if differ > 0 { exit(1); }
}
