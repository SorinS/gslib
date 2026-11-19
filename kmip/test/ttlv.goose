// TTLV: the encodings of KMIP 1.2's §9.1.2 (each type, and a Structure),
// written and read back; what a decode refuses; the names.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.tables;

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
        if s[i] == ' ' || s[i] == '|' { i++; continue; }
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

let TAG: u32 = 0x420020;

fn decodes(what: const u8[:], enc: const u8[:]) -> bool {
    var doc: kmip::Node[>..] = [];
    let root, e = kmip::decode(enc, kmip::Options { .. }, doc);
    if e != kmip::OK { print(what, ": ", kmip::error_text(e)); return false; }
    return root == 0 && doc[0].tag == TAG;
}

fn refuses(what: const u8[:], hex: const u8[:], want: i64) {
    let enc = unhex(hex);
    var doc: kmip::Node[>..] = [];
    let root, e = kmip::decode(enc, kmip::Options { .. }, doc);
    check(what, root == -1 && e == want);
}

fn main() {
    // §9.1.2: an Integer containing the decimal value 8
    {
        let want = unhex("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00");
        var out: u8[>..] = [];
        kmip::put_int(out, TAG, 8);
        check("integer write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_int(want, doc, r);
        check("integer read", ok && v == 8);
    }
    // a Long Integer containing 123456789000000000
    {
        let want = unhex("42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00");
        var out: u8[>..] = [];
        kmip::put_long(out, TAG, 123456789000000000);
        check("long write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_long(want, doc, r);
        check("long read", ok && v == 123456789000000000);
    }
    // a Big Integer containing 1234567890000000000000000000
    {
        let want = unhex("42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08 00 00");
        let mag = unhex("03 FD 35 EB 6B C2 DF 46 18 08 00 00");
        var out: u8[>..] = [];
        kmip::put_biguint(out, TAG, mag);
        check("bigint write", out[..] == want[..]);
        var out2: u8[>..] = [];
        kmip::put_bigint(out2, TAG, mag);
        check("bigint write, two's complement", out2[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_biguint(want, doc, r);
        check("bigint read", ok && v == mag[..]);
    }
    // an Enumeration with value 255
    {
        let want = unhex("42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00");
        var out: u8[>..] = [];
        kmip::put_enum(out, TAG, 255);
        check("enum write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_enum(want, doc, r);
        check("enum read", ok && v == 255);
    }
    // a Boolean with the value True
    {
        let want = unhex("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01");
        var out: u8[>..] = [];
        kmip::put_bool(out, TAG, true);
        check("bool write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_bool(want, doc, r);
        check("bool read", ok && v);
    }
    // a Text String with the value "Hello World"
    {
        let want = unhex("42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00");
        var out: u8[>..] = [];
        kmip::put_text(out, TAG, "Hello World");
        check("text write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_text(want, doc, r);
        check("text read", ok && v == "Hello World");
    }
    // a Byte String with the value { 0x01, 0x02, 0x03 }
    {
        let want = unhex("42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00");
        var out: u8[>..] = [];
        let b: u8[3] = [1, 2, 3];
        kmip::put_bytes(out, TAG, b);
        check("bytes write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_bytes(want, doc, r);
        check("bytes read", ok && v == b[..]);
    }
    // a Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT
    {
        let want = unhex("42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8");
        var out: u8[>..] = [];
        kmip::put_datetime(out, TAG, 0x47DA67F8);
        check("datetime write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_datetime(want, doc, r);
        check("datetime read", ok && v == 1205495800);
    }
    // an Interval, containing the value for 10 days
    {
        let want = unhex("42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00");
        var out: u8[>..] = [];
        kmip::put_interval(out, TAG, 864000);
        check("interval write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        let v, ok = kmip::as_interval(want, doc, r);
        check("interval read", ok && v == 864000);
    }
    // a Structure containing an Enumeration, value 254, followed by an
    // Integer, value 255, having tags 420004 and 420005 respectively
    {
        let want = unhex("42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE 00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00");
        var out: u8[>..] = [];
        let s = kmip::begin(out, TAG);
        kmip::put_enum(out, 0x420004, 254);
        kmip::put_int(out, 0x420005, 255);
        kmip::end(out, s);
        check("structure write", out[..] == want[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(want, kmip::Options { .. }, doc);
        check("structure decodes", e == kmip::OK && doc.len == 3 && doc[0].count == 2);
        let a, ok1 = kmip::child_enum(want, doc, r, 0x420004);
        let b, ok2 = kmip::child_int(want, doc, r, 0x420005);
        check("structure children", ok1 && a == 254 && ok2 && b == 255);
        check("structure missing child", kmip::child(doc, r, 0x420006) == -1);
        check("message length", kmip::message_length(want[..8]) == want.len);
        let d = kmip::dump(want, doc, r);
        check("dump", d[..] == "CompromiseDate (Structure)\n  ApplicationSpecificInformation (Enumeration): 0x000000fe\n  ArchiveDate (Integer): 255\n");
        check("wrong type", { let v, ok = kmip::as_text(want, doc, r + 1); !ok });
    }
    // Negative numbers.
    {
        var out: u8[>..] = [];
        kmip::put_int(out, TAG, -2);
        check("negative integer", out[..] == unhex("42002002 00000004 FFFFFFFE 00000000")[..]);
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(out, kmip::Options { .. }, doc);
        let v, ok = kmip::as_int(out, doc, r);
        check("negative integer read", ok && v == -2);
        var o2: u8[>..] = [];
        let m: u8[1] = [0xFC];
        kmip::put_bigint(o2, TAG, m);   // -4, as PyKMIP's test writes it
        check("negative bigint", o2[..] == unhex("42002004 00000008 FFFFFFFFFFFFFFFC")[..]);
        var o3: u8[>..] = [];
        let top: u8[1] = [0x80];
        kmip::put_biguint(o3, TAG, top);
        check("biguint with top bit", o3[..] == unhex("42002004 00000008 0000000000000080")[..]);
        var o4: u8[>..] = [];
        kmip::put_biguint(o4, TAG, "");
        check("biguint zero", o4[..] == unhex("42002004 00000008 0000000000000000")[..]);
    }
    // What a decode refuses.
    refuses("truncated head", "42 00 20 02 00 00 00", kmip::ERR_TRUNCATED);
    refuses("truncated value", "42 00 20 02 00 00 00 04 00 00 00 08", kmip::ERR_TRUNCATED);
    refuses("integer of 8 bytes", "42 00 20 02 00 00 00 08 00 00 00 00 00 00 00 08", kmip::ERR_MALFORMED);
    refuses("boolean of 2", "42 00 20 06 00 00 00 08 00 00 00 00 00 00 00 02", kmip::ERR_MALFORMED);
    refuses("padding not zero", "42 00 20 02 00 00 00 04 00 00 00 08 00 00 00 01", kmip::ERR_MALFORMED);
    refuses("text padding not zero", "42 00 20 07 00 00 00 01 41 00 00 00 00 00 00 01", kmip::ERR_MALFORMED);
    refuses("big integer of 3", "42 00 20 04 00 00 00 03 01 02 03 00 00 00 00 00", kmip::ERR_MALFORMED);
    refuses("unknown type", "42 00 20 0C 00 00 00 00", kmip::ERR_TYPE);
    refuses("bad tag", "43 00 20 02 00 00 00 04 00 00 00 08 00 00 00 00", kmip::ERR_TAG);
    refuses("trailing", "42 00 20 02 00 00 00 04 00 00 00 08 00 00 00 00 00", kmip::ERR_TRAILING);
    refuses("child past its structure", "42 00 20 01 00 00 00 08 42 00 04 02 00 00 00 04 00 00 00 08 00 00 00 00", kmip::ERR_TRUNCATED);
    refuses("structure length not a multiple of 8", "42 00 20 01 00 00 00 04 00 00 00 00", kmip::ERR_MALFORMED);
    {
        // UTF-8 beyond ASCII is taken: "é€😀".
        let enc = unhex("42 00 20 07 00 00 00 09 C3 A9 E2 82 AC F0 9F 98 80 00 00 00 00 00 00 00");
        check("text UTF-8", decodes("text UTF-8", enc));
    }
    refuses("text overlong UTF-8", "42 00 20 07 00 00 00 02 C0 AF 00 00 00 00 00 00", kmip::ERR_UTF8);
    refuses("text surrogate", "42 00 20 07 00 00 00 03 ED A0 80 00 00 00 00 00", kmip::ERR_UTF8);
    refuses("text not UTF-8", "42 00 20 07 00 00 00 02 C3 28 00 00 00 00 00 00", kmip::ERR_UTF8);
    {
        // Nesting past max_depth.
        var enc: u8[>..] = [];
        var at: i64[>..] = [];
        for k in 40 { at.push(kmip::begin(enc, TAG)); }
        var k = 39;
        while k >= 0 { kmip::end(enc, at[k]); k--; }
        var doc: kmip::Node[>..] = [];
        let r, e = kmip::decode(enc, kmip::Options { .. }, doc);
        check("too deep", e == kmip::ERR_DEPTH);
        var doc2: kmip::Node[>..] = [];
        let r2, e2 = kmip::decode(enc, kmip::Options { max_depth: 64 }, doc2);
        check("deep allowed", e2 == kmip::OK && doc2.len == 40);
        var doc3: kmip::Node[>..] = [];
        let r3, e3 = kmip::decode(enc, kmip::Options { max_depth: 64, max_items: 10 }, doc3);
        check("too many", e3 == kmip::ERR_TOO_MANY);
    }
    // Names.
    check("tag name", kmip::tag_name(kmip::TAG_UNIQUE_IDENTIFIER) == "UniqueIdentifier");
    check("tag name, batch item", kmip::tag_name(0x42000F) == "BatchItem");
    check("tag name unknown", kmip::tag_name(0x540001) == "");
    check("enum name", kmip::enum_name(kmip::TAG_OBJECT_TYPE, kmip::OBJ_SYMMETRIC_KEY) == "SymmetricKey");
    check("enum name, operation", kmip::enum_name(kmip::TAG_OPERATION, kmip::OP_DISCOVER_VERSIONS) == "DiscoverVersions");
    check("enum name unknown", kmip::enum_name(kmip::TAG_OPERATION, 0x7777) == "");
    check("attribute tag", kmip::attribute_tag("Cryptographic Algorithm") == kmip::TAG_CRYPTOGRAPHIC_ALGORITHM);
    check("attribute name", kmip::attribute_name(kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK) == "Cryptographic Usage Mask");
    check("attribute unknown", kmip::attribute_tag("x-mine") == 0);
    // Retagging, 1.x's Attribute Value from 2.0's attribute.
    {
        var a: u8[>..] = [];
        kmip::put_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
        var b: u8[>..] = [];
        kmip::put_retagged(b, kmip::TAG_ATTRIBUTE_VALUE, a);
        check("retagged", b[..] == unhex("42 00 0B 05 00 00 00 04 00 00 00 03 00 00 00 00")[..]);
    }
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
