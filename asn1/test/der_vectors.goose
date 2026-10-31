// The DER reader against openssl, on vectors/der.txt: certificates (RSA,
// P-256, P-384, Ed25519) with their keys, a SEC 1 key, a CSR, and a
// document of the rarer types. The dump of every document must match
// `openssl asn1parse` element for element, and each integer, OID, time and
// string must decode to the value openssl and Python give. Each header,
// rewritten by put_header, must come out the same; each document must
// survive PEM and back.
import std;
import asn1 from "..";

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var o: u8[>..] = [];
    for x in b { format_int(o, x, 16, 2, '0'); }
    return o;
}

// An integer's two's-complement content as openssl prints it: sign and
// the magnitude's bytes in hex.
fn int_text(c: const u8[:]) -> u8[>..] {
    var mag: u8[>..] = [];
    mag.append(c);
    var out: u8[>..] = [];
    if c[0] >= 0x80 {
        out.push('-');
        // Negate: invert and add one.
        var carry: u32 = 1;
        var i = mag.len;
        while i > 0 {
            i--;
            let v: u32 = (~mag[i] & 0xff) + carry;
            mag[i] = v as! u8;
            carry = v >> 8;
        }
    }
    var start = 0;
    while start < mag.len - 1 && mag[start] == 0 { start++; }
    out.append(hex(mag[start..]));
    return out;
}

fn main() {
    var der: u8[>..] = [];
    var want: u8[>..] = [];
    var docs = 0;
    for line in split(embed_file("vectors/der.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "der" {
            der = unhex(w[1]);
            want.clear();
            let top, ok = asn1::parse(der);
            check("parse", ok && top.end == der.len);
            continue;
        }
        if w[0] == "dump" {
            for i in 1..w.len {
                if i > 1 { want.push(' '); }
                want.append(w[i]);
            }
            want.push('\n');
            let off, ok = parse_int(w[1], 10);
            let t, okt = asn1::read(der, off, der.len);
            var hdr: u8[>..] = [];
            asn1::put_header(hdr, t.tag, asn1::content_len(t));
            check("header round trip", okt && hdr == der[t.start..t.off]);
            continue;
        }
        if w[0] == "end" {
            docs++;
            let got, ok = asn1::dump(der);
            check("dump", ok && got == want);
            if got != want && failures < 3 { print(got); print(want); }
            var pem: u8[>..] = [];
            asn1::pem_encode(pem, "TEST", der);
            let back, okp = asn1::pem_decode(pem, "TEST");
            var same = back.len == 1;
            for b in back { same = same && b == der; }
            check("pem", okp && same);
            continue;
        }
        let off, okoff = parse_int(w[1], 10);
        let t, ok = asn1::read(der, off, der.len);
        check(line, ok);
        if w[0] == "int" {
            let c, okc = asn1::read_int_bytes(der, t);
            check(line, okc && int_text(c) == w[2]);
            if asn1::content_len(t) <= 8 {
                let v, okv = asn1::read_i64(der, t);
                var re: u8[>..] = [];
                asn1::put_i64(re, v);
                check(line, okv && re == der[t.start..t.end]);
            }
            if der[t.off] < 0x80 {
                let mag, okm = asn1::read_uint(der, t);
                var re: u8[>..] = [];
                asn1::put_uint(re, mag);
                check(line, okm && re == der[t.start..t.end]);
            }
        } else if w[0] == "oid" {
            let o, oko = asn1::read_oid(der, t);
            check(line, oko && o == w[2] && asn1::oid_is(der, t, w[2]));
            var re: u8[>..] = [];
            asn1::put_oid(re, o);
            check(line, re == der[t.start..t.end]);
        } else if w[0] == "time" {
            let v, okv = asn1::read_time(der, t);
            let expect, oke = parse_int(w[2], 10);
            check(line, okv && v == expect);
            var re: u8[>..] = [];
            asn1::put_time(re, v);
            // put_time picks the type RFC 5280 asks for, which these follow
            // except 99991231235959Z, its "no expiry" value, also GeneralizedTime.
            check(line, re == der[t.start..t.end]);
        } else if w[0] == "str" {
            let s, oks = asn1::read_string(der, t);
            check(line, oks && s == unhex(w[2]));
        }
    }
    print("der vectors: ", docs, " documents, ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
