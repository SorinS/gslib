// Fuzz target: kmip_text, KMIP's XML and JSON encodings. The first byte
// picks the reader (data[0] % 2: XML, JSON), the rest is the text. What a
// reader accepts must be TTLV the decoder takes, and must come back the
// same through both writers and readers: TTLV to XML to TTLV, and TTLV to
// JSON to TTLV (a Text String with a character XML cannot carry excepted,
// which the XML writer refuses).

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.xml;
import gslib.kmip.json;

fn check_ttlv(t: const u8[:]) {
    var doc: kmip::Node[>..] = [];
    let r, e = kmip::decode(t, kmip::Options { .. }, doc);
    assert(e == kmip::OK || e == kmip::ERR_TOO_MANY);
    if e != kmip::OK { return; }
    var why: u8[>..] = [];
    var x: u8[>..] = [];
    let ex = kmip::ttlv_to_xml(t, x);
    assert(ex == kmip::OK || ex == kmip::ERR_UTF8);
    if ex == kmip::OK {
        var back: u8[>..] = [];
        let eb = kmip::from_xml(x, back, kmip::Options { .. }, why);
        assert(eb == kmip::OK && back[..] == t);
    }
    var j: u8[>..] = [];
    assert(kmip::ttlv_to_json(t, j) == kmip::OK);
    var back2: u8[>..] = [];
    let ej = kmip::from_json(j, back2, kmip::Options { .. }, why);
    assert(ej == kmip::OK && back2[..] == t);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let m = data[1..];
    var t: u8[>..] = [];
    var why: u8[>..] = [];
    let e = if data[0] % 2 == 0 { kmip::from_xml(m, t, kmip::Options { .. }, why) }
            else { kmip::from_json(m, t, kmip::Options { .. }, why) };
    if e == kmip::OK { check_ttlv(t); }
    return 0;
}
