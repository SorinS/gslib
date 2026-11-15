// tour: CBOR written deterministically, read back strictly, shown in
// diagnostic notation; what the strict decoder refuses; and a COSE key
// (the WebAuthn spec's ES256 test key) read, checked and turned into a
// SubjectPublicKeyInfo for crypto/x509. With a FILE, its CBOR shown
// instead (indefinite lengths allowed).
//
//   goose examples/cbor/tour.goose [-- FILE]

import std;
import os;
import gslib from "../..";
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.encoding.asn1;

fn show(what: const u8[:], b: const u8[:], o: cbor::Options) {
    var doc: cbor::Node[>..] = [];
    let root, e = cbor::decode(b, o, doc);
    var h: u8[>..] = [];
    cbor::put_hex(h, b);
    if e != cbor::OK { print(what, ": ", h, " -> refused: ", cbor::error_text(e)); return; }
    var d: u8[>..] = [];
    cbor::diag(b, doc, root, d);
    print(what, ": ", h, " -> ", d);
}

fn main() {
    let a = args();
    if a.len > 1 {
        var b: u8[>..] = [];
        guard read_file(a[1], b) else { print("tour: cannot read ", a[1]); exit(1); }
        show(a[1], b, cbor::Options { indefinite: true, max_bytes: 1 << 30, max_items: 1 << 24, .. });
        return;
    }
    // A map written in any order, then sorted into the deterministic order.
    var out: u8[>..] = [];
    cbor::put_map(out, 4);
    cbor::put_text(out, "name"); cbor::put_text(out, "goose");
    cbor::put_int(out, 1); cbor::put_float(out, 1.5);
    cbor::put_int(out, -7); cbor::put_bytes(out, "\x01\x02");
    cbor::put_text(out, "ok"); cbor::put_bool(out, true);
    let e = cbor::sort_map(out, 0);
    let o = cbor::Options { deterministic: true, .. };
    show("written", out, o);

    // The strict decoder at work.
    let strict = cbor::Options { .. };
    show("a duplicate key", "\xa2\x01\x01\x01\x02", strict);
    show("an indefinite array", "\x9f\x01\xff", strict);
    show("the same, allowed", "\x9f\x01\xff", cbor::Options { indefinite: true, .. });
    show("text that is not UTF-8", "\x62\xc3\x28", strict);
    show("a longer head than needed", "\x18\x01", cbor::Options { require_shortest: true, .. });
    show("cut short", "\x83\x01\x02", strict);

    // A COSE key: ES256 on P-256, as authenticators send them.
    var key: u8[>..] = [];
    let hex = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220";
    var i = 0;
    while i < hex.len { key.push((ascii::hex_value(hex[i]) * 16 + ascii::hex_value(hex[i + 1])) as! u8); i += 2; }
    show("COSE key", key, strict);
    let k, ek = cose::decode(key);
    print("COSE key: ", cose::error_text(ek), ", ", cose::alg_name(k.alg), ", curve ", k.crv);
    let spki, es = cose::to_spki(k);
    let text, okd = asn1::dump(spki);
    print("as SubjectPublicKeyInfo:\n", text);
}
