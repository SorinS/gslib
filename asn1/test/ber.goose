// BER as LDAP sends it (RFC 4511 §5.1), read with `ber`: lengths in more
// octets than they need (Active Directory's 84 00 00 00 nn), booleans
// other than ff, integers with redundant leading octets; the same input
// refused as DER, and BER's indefinite length refused either way.
import std;
import asn1 from "..";

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn ber_parses(h: const u8[:]) -> bool {
    let b = unhex(h);
    let t, ok = asn1::parse(b, true);
    return ok;
}

fn main() {
    // SEQUENCE { INTEGER 5, BOOLEAN TRUE (01), ENUMERATED 0 } with long lengths throughout.
    let m = unhex("30840000000e0204000000050101010a82000100");
    let t0, ok0 = asn1::parse(m);
    check("not DER", !ok0);
    let t, ok = asn1::parse(m, true);
    check("parses as BER", ok && t.tag == asn1::SEQUENCE && asn1::content_len(t) == 14);
    let cs, okc = asn1::children(m, t, true);
    check("children", okc && cs.len == 3);
    let c0, okc0 = asn1::children(m, t);
    check("children not DER", !okc0);
    let n, okn = asn1::read_i64(m, cs[0], asn1::INTEGER, true);
    check("padded integer", okn && n == 5);
    let n0, okn0 = asn1::read_i64(m, cs[0]);
    check("padded integer not DER", !okn0);
    let b, okb = asn1::read_bool(m, cs[1], true);
    check("boolean 01 is true", okb && b);
    let b0, okb0 = asn1::read_bool(m, cs[1]);
    check("boolean 01 not DER", !okb0);
    let e, oke = asn1::read_i64(m, cs[2], asn1::ENUMERATED, true);
    check("enumerated", oke && e == 0);

    let neg = unhex("0203ffff80");
    let tn, oktn = asn1::parse(neg, true);
    let v, okv = asn1::read_i64(neg, tn, asn1::INTEGER, true);
    check("padded negative", oktn && okv && v == -128);
    let wide = unhex("020a00000000000000000001");
    let tw, oktw = asn1::parse(wide, true);
    let w, okw = asn1::read_i64(wide, tw, asn1::INTEGER, true);
    check("ten octets, one significant", oktw && okw && w == 1);
    let big = unhex("0209010000000000000000");
    let tb, oktb = asn1::parse(big, true);
    let x, okx = asn1::read_i64(big, tb, asn1::INTEGER, true);
    check("past 64 bits", oktb && !okx);

    let ctx = unhex("870100");
    let tc, oktc = asn1::parse(ctx, true);
    let f, okf = asn1::read_bool(ctx, tc, true, 0x87);
    check("implicit boolean", oktc && okf && !f);

    check("indefinite", !ber_parses("30800201050000"));
    check("length past the end", !ber_parses("3084000000050201"));
    check("huge length", !ber_parses("0488ffffffffffffffff00"));
    check("trailing bytes", !ber_parses("02010500"));

    print("ber: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
