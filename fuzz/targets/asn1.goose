// Fuzz target: asn1. DER and BER parses, every constructed element's
// children walked (a work list, to a bound), and the typed readers tried
// on each element; then the dump and PEM.

import std;
import gslib from "../..";
import gslib.encoding.asn1;

fn probe(buf: const u8[:], t: asn1::Tlv, ber: bool) {
    let _ = asn1::read_bool(buf, t, ber);
    let _ = asn1::read_i64(buf, t, asn1::INTEGER, ber);
    let _ = asn1::read_uint(buf, t);
    let _ = asn1::read_bits(buf, t);
    let _ = asn1::read_octets(buf, t);
    let _ = asn1::read_oid(buf, t);
    let _ = asn1::read_time(buf, t);
    let _ = asn1::read_string(buf, t);
}

fn walk(buf: const u8[:], top: asn1::Tlv, ber: bool) {
    var todo: asn1::Tlv[>..] = [top];
    var seen = 0;
    while todo.len > 0 && seen < 4096 {
        let t = todo[todo.len - 1];
        todo.resize(todo.len - 1);
        seen += 1;
        probe(buf, t, ber);
        let kids, ok = asn1::children(buf, t, ber);
        if ok { todo.append(kids); }
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    for ber in [false, true] {
        let t, ok = asn1::parse(data, ber);
        if ok { walk(data, t, ber); }
    }
    let _ = asn1::dump(data);
    let _ = asn1::pem_decode(data, "CERTIFICATE");
    return 0;
}

fn main() {}
