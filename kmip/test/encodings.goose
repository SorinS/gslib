// KMIP's XML and JSON encodings (kmip.xml, kmip.json, kmip.text): the
// forms of KMIP Profiles 2.1 §5.4 and §5.5, each type's, read and written;
// what is refused; and PyKMIP's 245 TTLV encodings (test/vectors) each
// written as XML and as JSON and read back to the same bytes.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.xml;
import gslib.kmip.json;
import gslib.kmip.text;

let VECTORS = embed_file("vectors/pykmip.txt");

var checks = 0;
var failures = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL  ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// One item from XML, as TTLV, or the error.
fn x(text: const u8[:]) -> u8[>..], i64 {
    var out: u8[>..] = [];
    var why: u8[>..] = [];
    let e = kmip::from_xml(text, out, kmip::Options { .. }, why);
    return out, e;
}

fn j(text: const u8[:]) -> u8[>..], i64 {
    var out: u8[>..] = [];
    var why: u8[>..] = [];
    let e = kmip::from_json(text, out, kmip::Options { .. }, why);
    return out, e;
}

fn ttlv_int(tag: u32, v: i32) -> u8[>..] { var o: u8[>..] = []; kmip::put_int(o, tag, v); return o; }
fn ttlv_enum(tag: u32, v: u32) -> u8[>..] { var o: u8[>..] = []; kmip::put_enum(o, tag, v); return o; }

// The XML of one item, without its line end.
fn xml_of(t: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let e = kmip::ttlv_to_xml(t, out);
    if out.len > 0 && out[out.len - 1] == '\n' { out.pop(); }
    return out;
}

fn json_of(t: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let e = kmip::ttlv_to_json(t, out);
    if out.len > 0 && out[out.len - 1] == '\n' { out.pop(); }
    return out;
}

fn forms() {
    // Integers, decimal and hex; the profiles' -1, 0, 1.
    let a, ea = x("<BatchCount type=\"Integer\" value=\"10\"/>");
    check("Integer decimal", ea == kmip::OK && a[..] == ttlv_int(kmip::TAG_BATCH_COUNT, 10)[..]);
    let b, eb = x("<BatchCount type=\"Integer\" value=\"0xffffffff\"/>");
    check("Integer hex -1", eb == kmip::OK && b[..] == ttlv_int(kmip::TAG_BATCH_COUNT, -1)[..]);
    let c, ec = x("<BatchCount type=\"Integer\" value=\"2147483648\"/>");
    check("Integer past 32 bits refused", ec == kmip::ERR_MALFORMED);
    let d, ed = x("<BatchCount type=\"Integer\" value=\"0x1\"/>");
    check("Integer hex without its leading zeros refused", ed == kmip::ERR_MALFORMED);

    // Masks: names in any order, hex parts, separators.
    let want = ttlv_int(kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK, 0x100c);
    let m1, em1 = x("<CryptographicUsageMask type=\"Integer\" value=\"0x0000100c\"/>");
    let m2, em2 = x("<CryptographicUsageMask type=\"Integer\" value=\"Encrypt Decrypt CertificateSign\"/>");
    let m3, em3 = x("<CryptographicUsageMask type=\"Integer\" value=\"CertificateSign 0x00000004 0x00000008\"/>");
    let m4, em4 = j("{\"tag\":\"CryptographicUsageMask\",\"type\":\"Integer\",\"value\":\"CertificateSign|0x0000000c\"}");
    check("mask, hex", em1 == kmip::OK && m1[..] == want[..]);
    check("mask, names", em2 == kmip::OK && m2[..] == want[..]);
    check("mask, names and hex", em3 == kmip::OK && m3[..] == want[..]);
    check("mask, JSON", em4 == kmip::OK && m4[..] == want[..]);
    check("mask written", xml_of(want)[..] == "<CryptographicUsageMask type=\"Integer\" value=\"Encrypt Decrypt CertificateSign\"/>");
    check("mask written, JSON", json_of(want)[..] == "{\"tag\":\"CryptographicUsageMask\", \"type\":\"Integer\", \"value\":\"Encrypt|Decrypt|CertificateSign\"}");
    let mb, emb = x("<CryptographicUsageMask type=\"Integer\" value=\"Encrypt Fly\"/>");
    check("mask, unknown name refused", emb == kmip::ERR_MALFORMED);
    let odd = ttlv_int(kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK, 0x40000001);
    check("mask, an unnamed bit", xml_of(odd)[..] == "<CryptographicUsageMask type=\"Integer\" value=\"Sign 0x40000000\"/>");

    // Enumerations: name, hex, JSON number; KMIP 1.x's Attribute Value by
    // its Attribute Name; Attribute Reference by tag names.
    let ot = ttlv_enum(kmip::TAG_OBJECT_TYPE, kmip::OBJ_SYMMETRIC_KEY);
    let e1, ee1 = x("<ObjectType type=\"Enumeration\" value=\"SymmetricKey\"/>");
    let e2, ee2 = x("<ObjectType type=\"Enumeration\" value=\"0x00000002\"/>");
    let e3, ee3 = j("{\"tag\":\"0x420057\",\"type\":\"Enumeration\",\"value\":2}");
    check("enum by name", ee1 == kmip::OK && e1[..] == ot[..]);
    check("enum by hex", ee2 == kmip::OK && e2[..] == ot[..]);
    check("enum by number, tag by hex (JSON)", ee3 == kmip::OK && e3[..] == ot[..]);
    let e4, ee4 = x("<ObjectType type=\"Enumeration\" value=\"Dragon\"/>");
    check("enum, unknown name refused", ee4 == kmip::ERR_MALFORMED);
    check("enum written", xml_of(ot)[..] == "<ObjectType type=\"Enumeration\" value=\"SymmetricKey\"/>");
    let alg = ttlv_enum(kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_TRIPLE_DES);
    check("3DES is DES3", xml_of(alg)[..] == "<CryptographicAlgorithm type=\"Enumeration\" value=\"DES3\"/>");
    let un = ttlv_enum(kmip::TAG_OBJECT_TYPE, 0x80000001);
    check("an extension's value in hex", xml_of(un)[..] == "<ObjectType type=\"Enumeration\" value=\"0x80000001\"/>");

    let attr_xml = "<Attribute>\n  <AttributeName type=\"TextString\" value=\"Cryptographic Algorithm\"/>\n  <AttributeValue type=\"Enumeration\" value=\"AES\"/>\n</Attribute>";
    let at, eat = x(attr_xml);
    check("1.x Attribute Value by its name", eat == kmip::OK && xml_of(at)[..] == attr_xml);
    let um_xml = "<Attribute>\n  <AttributeName type=\"TextString\" value=\"Cryptographic Usage Mask\"/>\n  <AttributeValue type=\"Integer\" value=\"Encrypt Decrypt\"/>\n</Attribute>";
    let um, eum = x(um_xml);
    check("1.x Attribute Value, a mask", eum == kmip::OK && xml_of(um)[..] == um_xml);
    let ar, ear = x("<AttributeReference type=\"Enumeration\" value=\"ActivationDate\"/>");
    check("Attribute Reference by tag name", ear == kmip::OK && ar[..] == ttlv_enum(kmip::TAG_ATTRIBUTE_REFERENCE, kmip::TAG_ACTIVATION_DATE)[..]);
    check("Attribute Reference written", xml_of(ar)[..] == "<AttributeReference type=\"Enumeration\" value=\"ActivationDate\"/>");

    // Long Integers, JSON's limit of 2^52.
    var l1: u8[>..] = [];
    kmip::put_long(l1, kmip::TAG_USAGE_LIMITS_COUNT, 1152921504606846976);
    check("Long Integer, XML", xml_of(l1)[..] == "<UsageLimitsCount type=\"LongInteger\" value=\"1152921504606846976\"/>");
    check("Long Integer past 2^52 in hex, JSON", json_of(l1)[..] == "{\"tag\":\"UsageLimitsCount\", \"type\":\"LongInteger\", \"value\":\"0x1000000000000000\"}");
    let l2, el2 = j("{\"tag\":\"UsageLimitsCount\",\"type\":\"LongInteger\",\"value\":\"0x1000000000000000\"}");
    check("Long Integer hex read", el2 == kmip::OK && l2[..] == l1[..]);
    var l3: u8[>..] = [];
    kmip::put_long(l3, 0x540001, -2);
    let l4, el4 = x("<x540001 type=\"LongInteger\" value=\"-2\"/>");
    check("an element named by hex tag (x540001)", el4 == kmip::OK && l4[..] == l3[..]);
    check("unknown tag written as TTLV", xml_of(l3)[..] == "<TTLV tag=\"0x540001\" type=\"LongInteger\" value=\"-2\"/>");
    let l5, el5 = x("<TTLV tag=\"0x540001\" name=\"SomeExtension\" type=\"LongInteger\" value=\"-2\"/>");
    check("the general form read", el5 == kmip::OK && l5[..] == l3[..]);
    let l6, el6 = j("{\"tag\":\"0x540001\",\"type\":\"LongInteger\",\"value\":-2}");
    check("JSON negative number", el6 == kmip::OK && l6[..] == l3[..]);

    // Big Integers: sign extension to 8 bytes.
    var bi: u8[>..] = [];
    kmip::put_bigint(bi, kmip::TAG_MODULUS, unhex("0123"));
    let b1, eb1 = x("<Modulus type=\"BigInteger\" value=\"0000000000000123\"/>");
    let b2, eb2 = j("{\"tag\":\"Modulus\",\"type\":\"BigInteger\",\"value\":\"0x0123\"}");
    let b3, eb3 = j("{\"tag\":\"Modulus\",\"type\":\"BigInteger\",\"value\":291}");
    check("Big Integer, XML", eb1 == kmip::OK && b1[..] == bi[..]);
    check("Big Integer, short hex sign-extended", eb2 == kmip::OK && b2[..] == bi[..]);
    check("Big Integer, JSON number", eb3 == kmip::OK && b3[..] == bi[..]);
    var bn: u8[>..] = [];
    kmip::put_bigint(bn, kmip::TAG_MODULUS, unhex("ff"));
    let b4, eb4 = x("<Modulus type=\"BigInteger\" value=\"f\"/>");
    check("Big Integer, -1 from one digit", eb4 == kmip::OK && b4[..] == bn[..]);

    // Booleans, Byte Strings, Text Strings with escapes.
    var t: u8[>..] = [];
    kmip::put_bool(t, kmip::TAG_BATCH_ORDER_OPTION, true);
    let o1, eo1 = x("<BatchOrderOption type=\"Boolean\" value=\"true\"/>");
    let o2, eo2 = j("{\"tag\":\"BatchOrderOption\",\"type\":\"Boolean\",\"value\":\"0x0000000000000001\"}");
    let o3, eo3 = j("{\"tag\":\"BatchOrderOption\",\"type\":\"Boolean\",\"value\":true}");
    let o4, eo4 = x("<BatchOrderOption type=\"Boolean\" value=\"yes\"/>");
    check("Boolean", eo1 == kmip::OK && o1[..] == t[..] && eo2 == kmip::OK && o2[..] == t[..] && eo3 == kmip::OK && o3[..] == t[..]);
    check("Boolean, other text refused", eo4 == kmip::ERR_MALFORMED);
    var bs: u8[>..] = [];
    kmip::put_bytes(bs, kmip::TAG_MAC_SIGNATURE, unhex("c50f77"));
    let s1, es1 = x("<MACSignature type=\"ByteString\" value=\"C50F77\"/>");
    check("Byte String, upper case", es1 == kmip::OK && s1[..] == bs[..]);
    check("Byte String written", xml_of(bs)[..] == "<MACSignature type=\"ByteString\" value=\"c50f77\"/>");
    let s2, es2 = x("<MACSignature type=\"ByteString\" value=\"C50F7\"/>");
    check("Byte String, odd digits refused", es2 == kmip::ERR_MALFORMED);
    var ts: u8[>..] = [];
    kmip::put_text(ts, kmip::TAG_NAME_VALUE, "a<b & \"c\"\n");
    let t1, et1 = x(xml_of(ts));
    let t2, et2 = j(json_of(ts));
    check("Text String with escapes, XML", et1 == kmip::OK && t1[..] == ts[..]);
    check("Text String with escapes, JSON", et2 == kmip::OK && t2[..] == ts[..]);
    var ctl: u8[>..] = [];
    kmip::put_text(ctl, kmip::TAG_NAME_VALUE, "bell\x07");
    var cx: u8[>..] = [];
    check("a control character XML cannot carry", kmip::ttlv_to_xml(ctl, cx) == kmip::ERR_UTF8);
    let t3, et3 = j(json_of(ctl));
    check("... which JSON can", et3 == kmip::OK && t3[..] == ctl[..]);

    // Date-Times: zones, fractions dropped, a zone required; hex in JSON.
    var dt: u8[>..] = [];
    kmip::put_datetime(dt, kmip::TAG_ARCHIVE_DATE, 978307200);    // 2001-01-01T00:00:00Z
    let d1, ed1 = x("<ArchiveDate type=\"DateTime\" value=\"2001-01-01T10:00:00+10:00\"/>");
    let d2, ed2 = x("<ArchiveDate type=\"DateTime\" value=\"2000-12-31T23:00:00.75-01:00\"/>");
    let d3, ed3 = j("{\"tag\":\"ArchiveDate\",\"type\":\"DateTime\",\"value\":\"0x000000003a4fc880\"}");
    let d4, ed4 = x("<ArchiveDate type=\"DateTime\" value=\"2001-01-01T00:00:00\"/>");
    let d5, ed5 = x("<ArchiveDate type=\"DateTime\" value=\"2001-02-29T00:00:00Z\"/>");
    check("Date-Time with +10:00", ed1 == kmip::OK && d1[..] == dt[..]);
    check("Date-Time with a fraction and -01:00", ed2 == kmip::OK && d2[..] == dt[..]);
    check("Date-Time in hex (JSON)", ed3 == kmip::OK && d3[..] == dt[..]);
    check("Date-Time without a zone refused", ed4 == kmip::ERR_MALFORMED);
    check("Date-Time, 29 February 2001 refused", ed5 == kmip::ERR_MALFORMED);
    check("Date-Time written in UTC", xml_of(dt)[..] == "<ArchiveDate type=\"DateTime\" value=\"2001-01-01T00:00:00+00:00\"/>");
    var early: u8[>..] = [];
    kmip::put_datetime(early, kmip::TAG_ARCHIVE_DATE, -86401);
    let d6, ed6 = x(xml_of(early));
    var far: u8[>..] = [];
    kmip::put_datetime(far, kmip::TAG_ARCHIVE_DATE, 0x010000003a505520);
    let d7, ed7 = x(xml_of(far));
    check("Date-Time past the year 9999 in hex", xml_of(far)[..] == "<ArchiveDate type=\"DateTime\" value=\"0x010000003a505520\"/>" && ed7 == kmip::OK && d7[..] == far[..]);
    check("Date-Time before 1970", xml_of(early)[..] == "<ArchiveDate type=\"DateTime\" value=\"1969-12-30T23:59:59+00:00\"/>" && ed6 == kmip::OK && d6[..] == early[..]);

    // Interval and Date-Time Extended.
    var iv: u8[>..] = [];
    kmip::put_interval(iv, kmip::TAG_OFFSET, 27);
    let i1, ei1 = x("<Offset type=\"Interval\" value=\"27\"/>");
    let i2, ei2 = j("{\"tag\":\"Offset\",\"type\":\"Interval\",\"value\":\"0x0000001b\"}");
    let i3, ei3 = x("<Offset type=\"Interval\" value=\"-1\"/>");
    check("Interval", ei1 == kmip::OK && i1[..] == iv[..] && ei2 == kmip::OK && i2[..] == iv[..]);
    check("Interval, negative refused", ei3 == kmip::ERR_MALFORMED);
    var dx: u8[>..] = [];
    kmip::put_datetime_ext(dx, 0x540001, 2);
    let x1, ex1 = x("<X540001 type=\"DateTimeExtended\" value=\"2\"/>");
    check("Date-Time Extended", ex1 == kmip::OK && x1[..] == dx[..]);

    // Structures: type optional, namespace, empty ones, null in JSON.
    let pv = "<ProtocolVersion xmlns=\"urn:oasis:tc:kmip:xmlns\" type=\"Structure\"><ProtocolVersionMajor type=\"Integer\" value=\"1\"/><ProtocolVersionMinor type=\"Integer\" value=\"0\"/></ProtocolVersion>";
    let p1, ep1 = x(pv);
    var want_pv: u8[>..] = [];
    let s = kmip::begin(want_pv, kmip::TAG_PROTOCOL_VERSION);
    kmip::put_int(want_pv, kmip::TAG_PROTOCOL_VERSION_MAJOR, 1);
    kmip::put_int(want_pv, kmip::TAG_PROTOCOL_VERSION_MINOR, 0);
    kmip::end(want_pv, s);
    check("Structure with its namespace and type", ep1 == kmip::OK && p1[..] == want_pv[..]);
    let p2, ep2 = j("{\"tag\":\"ProtocolVersion\",\"value\":[{\"tag\":\"ProtocolVersionMajor\",\"type\":\"Integer\",\"value\":1},{\"tag\":\"ProtocolVersionMinor\",\"type\":\"Integer\",\"value\":0}]}");
    check("Structure, JSON", ep2 == kmip::OK && p2[..] == want_pv[..]);
    var empty: u8[>..] = [];
    let se = kmip::begin(empty, kmip::TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE);
    kmip::end(empty, se);
    let p3, ep3 = x("<PrivateKeyTemplateAttribute type=\"Structure\"/>");
    let p4, ep4 = j("{\"tag\":\"PrivateKeyTemplateAttribute\",\"type\":\"Structure\",\"value\":null}");
    check("empty Structure", ep3 == kmip::OK && p3[..] == empty[..] && ep4 == kmip::OK && p4[..] == empty[..]);

    // Refused: unknown names, attributes and members; text; values on Structures.
    let r1, er1 = x("<NoSuchTag type=\"Integer\" value=\"1\"/>");
    let r2, er2 = x("<BatchCount type=\"Int\" value=\"1\"/>");
    let r3, er3 = x("<BatchCount type=\"Integer\" value=\"1\" colour=\"blue\"/>");
    let r4, er4 = x("<ProtocolVersion>text</ProtocolVersion>");
    let r5, er5 = x("<ProtocolVersion value=\"1\"/>");
    let r6, er6 = x("<BatchCount type=\"Integer\"/>");
    let r7, er7 = x("<BatchCount xmlns=\"urn:other\" type=\"Integer\" value=\"1\"/>");
    let r8, er8 = j("{\"tag\":\"BatchCount\",\"type\":\"Integer\",\"value\":1,\"extra\":2}");
    let r9, er9 = j("{\"tag\":\"BatchCount\",\"type\":\"Integer\",\"value\":1.5}");
    let r10, er10 = j("{\"tag\":\"BatchCount\",\"tag\":\"BatchCount\",\"type\":\"Integer\",\"value\":1}");
    let r11, er11 = j("[1]");
    check("unknown tag", er1 == kmip::ERR_TAG);
    check("unknown type", er2 == kmip::ERR_TYPE);
    check("unknown attribute", er3 == kmip::ERR_MALFORMED);
    check("text in a Structure", er4 == kmip::ERR_MALFORMED);
    check("a Structure's value", er5 == kmip::ERR_MALFORMED);
    check("no value", er6 == kmip::ERR_MISSING);
    check("another namespace", er7 == kmip::ERR_MALFORMED);
    check("unknown member", er8 == kmip::ERR_MALFORMED);
    check("a fraction", er9 == kmip::ERR_MALFORMED);
    check("a member twice", er10 == kmip::ERR_MALFORMED);
    check("not an object", er11 == kmip::ERR_MALFORMED);

    // Depth.
    var deep: u8[>..] = [];
    for k in 40 { deep.append("<Attributes>"); }
    for k in 40 { deep.append("</Attributes>"); }
    let r12, er12 = x(deep);
    check("nested past max_depth", er12 == kmip::ERR_DEPTH);
}

// Each of PyKMIP's encodings as XML and as JSON, read back to its bytes,
// and the text written again the same.
fn corpus() {
    var total = 0;
    var same = 0;
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
        var xt: u8[>..] = [];
        if kmip::ttlv_to_xml(enc, xt) != kmip::OK { continue; }    // the six malformed on purpose
        total++;
        var jt: u8[>..] = [];
        let ej = kmip::ttlv_to_json(enc, jt);
        let back_x, ex = x(xt);
        let back_j, ejj = j(jt);
        var xt2: u8[>..] = [];
        var jt2: u8[>..] = [];
        let ex2 = kmip::ttlv_to_xml(back_x, xt2);
        let ej2 = kmip::ttlv_to_json(back_j, jt2);
        let ok = ex == kmip::OK && ejj == kmip::OK && back_x[..] == enc[..] && back_j[..] == enc[..]
                 && xt2[..] == xt[..] && jt2[..] == jt[..];
        if ok { same++; } else { print("DIFFERS ", name); }
    }
    print(total, " encodings: ", same, " through XML and JSON and back the same");
    check("PyKMIP's encodings through XML and JSON", total == 239 && same == total);
}

fn main() {
    forms();
    corpus();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
