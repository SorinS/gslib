// DER the reader must refuse: BER's indefinite and non-minimal lengths,
// lengths past the buffer, trailing bytes, non-minimal identifiers and
// integers, booleans other than 00 and ff, bit strings with stray or too
// many unused bits, OIDs with padded or unfinished arcs, malformed times,
// and strings outside their character sets. Then the writer's encodings
// of edge values.
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

fn hex(b: const u8[:]) -> u8[>..] {
    var o: u8[>..] = [];
    for x in b { format_int(o, x, 16, 2, '0'); }
    return o;
}

fn parses(h: const u8[:]) -> bool {
    let b = unhex(h);
    let t, ok = asn1::parse(b);
    if !ok { return false; }
    // Constructed elements must hold whole elements too.
    if t.constructed {
        let d, okd = asn1::dump(b);
        return okd;
    }
    return true;
}

// Whether the one element in h decodes with the reader its tag calls for.
fn decodes(h: const u8[:]) -> bool {
    let b = unhex(h);
    let t, ok = asn1::parse(b);
    if !ok { return false; }
    if t.tag == asn1::BOOLEAN { let v, okv = asn1::read_bool(b, t); return okv; }
    if t.tag == asn1::INTEGER { let v, okv = asn1::read_int_bytes(b, t); return okv; }
    if t.tag == asn1::BIT_STRING { let v, u, okv = asn1::read_bits(b, t); return okv; }
    if t.tag == asn1::OID { let v, okv = asn1::read_oid(b, t); return okv; }
    if t.tag == asn1::UTC_TIME || t.tag == asn1::GENERALIZED_TIME { let v, okv = asn1::read_time(b, t); return okv; }
    let v, okv = asn1::read_string(b, t);
    return okv;
}

fn enc_i64(v: i64) -> u8[>..] { var o: u8[>..] = []; asn1::put_i64(o, v); return hex(o); }

fn main() {
    // Framing.
    check("good", parses("3003020101"));
    check("indefinite", !parses("30800201010000"));
    check("long form for short", !parses("308103020101"));
    check("leading zero length", !parses("30820003020101"));
    check("five length bytes", !parses("3085000000000302"));
    check("past the end", !parses("3004020101"));
    check("trailing byte", !parses("300302010100"));
    check("child past parent", !parses("3003020201"));
    check("child short of parent", !parses("3004020101"));
    check("empty", !parses(""));
    check("header only", !parses("30"));
    check("high tag", parses("9f1f00"));
    check("high tag under 31", !parses("9f1e00"));
    check("high tag padded", !parses("9f801f00"));
    check("high tag unfinished", !parses("9f81"));

    // Contents.
    check("bool ff", decodes("0101ff"));
    check("bool 01", !decodes("010101"));
    check("bool long", !decodes("01020000"));
    check("int 0", decodes("020100"));
    check("int empty", !decodes("0200"));
    check("int padded", !decodes("02020001"));
    check("int padded negative", !decodes("0202ff80"));
    check("int 0080", decodes("02020080"));
    check("bits", decodes("03020780"));
    check("bits empty", decodes("030100"));
    check("bits empty with unused", !decodes("030101"));
    check("bits unused 8", !decodes("03020800"));
    check("bits stray", !decodes("03020181"));
    check("oid", decodes("06032a0304"));
    check("oid padded arc", !decodes("06042a800104"));
    check("oid unfinished", !decodes("06022a83"));
    check("oid empty", !decodes("0600"));
    check("utc", decodes("170d3233303130313030303030305a"));
    check("utc no Z", !decodes("170d32333031303130303030303030"));
    check("utc no seconds", !decodes("170b323330313031303030305a"));
    check("utc feb 30", !decodes("170d3233303233303030303030305a"));
    check("utc hour 24", !decodes("170d3233303130313234303030305a"));
    check("gen fraction", !decodes("181132303233303130313030303030302e315a"));
    check("gen feb 29 leap", decodes("180f32303234303232393030303030305a"));
    check("gen feb 29 not leap", !decodes("180f32303233303232393030303030305a"));
    check("printable", decodes("13024142"));
    check("printable @", !decodes("130140"));
    check("ia5 high", !decodes("160180"));
    check("utf8 overlong", !decodes("0c02c0af"));
    check("utf8 surrogate", !decodes("0c03eda080"));
    check("utf8 truncated", !decodes("0c02e282"));
    check("utf8 too big", !decodes("0c04f4908080"));
    check("bmp odd", !decodes("1e03006100"));
    check("bmp surrogate", !decodes("1e02d800"));
    check("universal big", !decodes("1c0400110000"));

    // The writer.
    check("i64 0", enc_i64(0) == "020100");
    check("i64 127", enc_i64(127) == "02017f");
    check("i64 128", enc_i64(128) == "02020080");
    check("i64 -128", enc_i64(-128) == "020180");
    check("i64 -129", enc_i64(-129) == "0202ff7f");
    check("i64 max", enc_i64(9223372036854775807) == "02087fffffffffffffff");
    check("i64 min", enc_i64(-9223372036854775807 - 1) == "02088000000000000000");
    var u: u8[>..] = [];
    asn1::put_uint(u, unhex("0000ff"));
    check("uint", hex(u) == "020200ff");
    var h: u8[>..] = [];
    asn1::put_header(h, asn1::OCTET_STRING, 300);
    check("long header", hex(h) == "0482012c");
    var ht: u8[>..] = [];
    asn1::put_header(ht, asn1::ctx(200, true), 0);
    check("high tag header", hex(ht) == "bf814800");
    let enc, okoid = asn1::oid_encode("2.999.3");
    check("oid 2.999", okoid && hex(enc) == "883703");
    let bad1, okb1 = asn1::oid_encode("1.40");
    let bad2, okb2 = asn1::oid_encode("1.02");
    let bad3, okb3 = asn1::oid_encode("3.1");
    let bad4, okb4 = asn1::oid_encode("1");
    check("bad oid text", !okb1 && !okb2 && !okb3 && !okb4);
    let max, okmax = asn1::oid_encode("1.2.18446744073709551615");
    let over, okover = asn1::oid_encode("1.2.18446744073709551616");
    check("oid arc 2^64 - 1", okmax && !okover);
    check("oid arc past 64 bits", !decodes("060b2a82808080808080808000"));
    var tm: u8[>..] = [];
    asn1::put_time(tm, -1);
    check("before 1970", hex(tm) == "170d3639313233313233353935395a");
    let tmt, okp = asn1::parse(tm);
    let back, okt = asn1::read_time(tm, tmt);
    check("time back", okt && back == -1);

    // PEM.
    let text = "junk\n-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n-----BEGIN KEY-----\nBQA=\n-----END KEY-----\n";
    let certs, okc = asn1::pem_decode(text, "CERTIFICATE");
    var first: u8[>..] = [];
    for c in certs { first = hex(c); }
    check("pem label", okc && certs.len == 1 && first == "3003020101");
    let all, oka = asn1::pem_decode(text, "");
    check("pem any", oka && all.len == 2);
    let broken, okbr = asn1::pem_decode("-----BEGIN X-----\nM!==\n-----END X-----\n", "X");
    check("pem bad base64", !okbr);
    let unended, oku = asn1::pem_decode("-----BEGIN X-----\nMAMCAQE=\n", "X");
    check("pem no end", !oku);

    print("der reject: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
