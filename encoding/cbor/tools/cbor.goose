// cbor: CBOR from a file or standard input, checked and shown.
//
//   goose encoding/cbor/tools/cbor.goose -- diag [OPTIONS] [FILE]
//   goose encoding/cbor/tools/cbor.goose -- canonical [OPTIONS] [FILE]
//   goose encoding/cbor/tools/cbor.goose -- batch [OPTIONS] < lines-of-hex
//
// diag prints the item in diagnostic notation; canonical writes it again
// in the core deterministic encoding (as hex with --hex); batch reads one
// item in hex per line and prints, for each, "ok CANONICAL-HEX DIAG" or
// "err CODE" (scripts/differential.py uses it). The input is binary, or
// hex with --hex-in. Options: --indefinite (allow indefinite lengths),
// --shortest (refuse longer heads), --deterministic, --length-first (sort
// map keys length-first, as RFC 7049 and CTAP2 do), --depth N,
// --items N.

import std;
import os;
import gslib from "../../..";
import gslib.encoding.cbor;

fn usage() {
    print("usage: cbor diag|canonical|batch [--hex-in] [--hex] [--indefinite] [--shortest] [--deterministic] [--length-first] [--depth N] [--items N] [FILE]");
    exit(2);
}

fn unhex(s: const u8[:], out: u8[>..]&) -> bool {
    let t = trim(s);
    if t.len % 2 != 0 { return false; }
    var i = 0;
    while i < t.len {
        let a = ascii::hex_value(t[i]);
        let b = ascii::hex_value(t[i + 1]);
        if a < 0 || b < 0 { return false; }
        out.push((a * 16 + b) as! u8);
        i += 2;
    }
    return true;
}

fn main() {
    let a = args();
    guard a.len >= 2 else { usage(); }
    let cmd = a[1];
    var opts = cbor::Options { max_bytes: 1 << 30, .. };
    var hex_in = false;
    var hex_out = false;
    var length_first = false;
    var path: u8[>..] = [];
    var i = 2;
    while i < a.len {
        let s = a[i];
        if s == "--hex-in" { hex_in = true; }
        else if s == "--hex" { hex_out = true; }
        else if s == "--indefinite" { opts.indefinite = true; }
        else if s == "--shortest" { opts.require_shortest = true; }
        else if s == "--deterministic" { opts.deterministic = true; }
        else if s == "--length-first" { length_first = true; }
        else if (s == "--depth" || s == "--items") && i + 1 < a.len {
            let n, ok = parse_int(a[i + 1]);
            guard ok && n > 0 else { usage(); }
            if s == "--depth" { opts.max_depth = n; } else { opts.max_items = n; }
            i++;
        } else if s.len > 0 && s[0] != '-' && path.len == 0 { path.append(s); }
        else { usage(); }
        i++;
    }
    var input: u8[>..] = [];
    if path.len > 0 {
        guard read_file(path, input) else { print("cbor: cannot read ", path); exit(1); }
    } else {
        read_stdin(input);
    }
    if cmd == "batch" {
        for line in split(input, '\n') {
            if trim(line).len == 0 { continue; }
            var b: u8[>..] = [];
            if !unhex(line, b) { print("err badhex"); continue; }
            var doc: cbor::Node[>..] = [];
            let root, e = cbor::decode(b, opts, doc);
            if e != cbor::OK { print("err ", e); continue; }
            var c: u8[>..] = [];
            cbor::canonical(b, doc, root, c, length_first);
            var ch: u8[>..] = [];
            cbor::put_hex(ch, c);
            var d: u8[>..] = [];
            cbor::diag(b, doc, root, d);
            print("ok ", ch, " ", d);
        }
        return;
    }
    var b: u8[>..] = [];
    if hex_in {
        guard unhex(input, b) else { print("cbor: not hex"); exit(1); }
    } else {
        b.append(input);
    }
    var doc: cbor::Node[>..] = [];
    let root, e = cbor::decode(b, opts, doc);
    guard e == cbor::OK else { print("cbor: ", cbor::error_text(e)); exit(1); }
    if cmd == "diag" {
        var d: u8[>..] = [];
        cbor::diag(b, doc, root, d);
        print(d);
    } else if cmd == "canonical" {
        var c: u8[>..] = [];
        cbor::canonical(b, doc, root, c, length_first);
        if hex_out {
            var h: u8[>..] = [];
            cbor::put_hex(h, c);
            print(h);
        } else {
            write_stdout(c);
        }
    } else {
        usage();
    }
}
