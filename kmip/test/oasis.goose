// OASIS's KMIP test cases (the KMIP Profiles' mandatory and optional
// ones and the KMIP Test Cases, 1.4 to 2.1), which scripts/oasis.py
// fetches and runs: each file a test case, a <KMIP> of RequestMessages
// each followed by the ResponseMessage a server gives, in XML.
//
//   oasis roundtrip FILE...   every message read from XML to TTLV, written
//                             as XML and JSON and read back to the same
//                             bytes
//   oasis replay FILE...      each request played against kmip.server's
//                             in-memory server and its response compared
//                             with the one in the file
//
// The files hold placeholders: $UNIQUE_IDENTIFIER_0 and the like for what
// the server chooses, $NOW and $NOW-3600 for times. A replay binds each to
// what the server answers the first time it is seen in a response and
// puts that in the requests after; $NOW is the time the replay runs at.
// A Result Message's text is the server's own and is not compared, nor
// need either side have one. Each file prints PASS or FAIL with the first
// difference, and what the server answered there.
//
// What no two servers answer alike is not compared as a value: a Random
// Number Generator attribute (the server's own generator); the key
// material of what the server made (Create, Create Key Pair, Derive Key,
// Re-key, Certify...) wherever a Get or Export returns it, and its Digest
// wherever Get Attributes does; a response's
// Time Stamp; and an Encrypt's or Sign's output under an asymmetric key
// (RSA OAEP and PKCS #1 encryption, ECDSA and PSS signatures are
// randomized), which is instead decrypted or verified by the server, and
// must give back the plaintext or be valid.

import std;
import os;
import gslib from "../..";
import gslib.encoding.xml;
import gslib.kmip;
import gslib.kmip.tables;
import gslib.kmip.messages;
import gslib.kmip.text;
import gslib.kmip.xml_encoding;
import gslib.kmip.json_encoding;
import gslib.kmip.server;

// --- Placeholders -----------------------------------------------------------------

// Names bound to values: name i is names[at[4i]..+at[4i+1]], its value
// vals[at[4i+2]..+at[4i+3]] (the text of a Text String, the hex of a Byte
// String).
root struct Binds {
    loose: bool,               // comparing a payload whose key material the server made
    random_ok: bool,           // comparing an Encrypt's or Sign's payload under an asymmetric key
    random_used: bool,         // ... and its output differed: checked by verify_random
    random_lens: bool,         // ... and is as long as the file's
    derived: bool,             // comparing an Encrypt's, MAC's or Sign's payload under a key the server made
    names: u8[>..],
    vals: u8[>..],
    at: i64[>..],
    made: u8[>..],             // the identifiers of what the server made, each followed by '\n'
    asym: u8[>..],             // the identifiers of asymmetric keys, the same
}

fn listed(list: const u8[:], id: const u8[:]) -> bool {
    var k = 0;
    while k < list.len {
        var e = k;
        while e < list.len && list[e] != '\n' { e++; }
        if list[k..e] == id { return true; }
        k = e + 1;
    }
    return false;
}

fn list_add(list: u8[>..]&, id: const u8[:]) {
    list.append(id);
    list.push('\n');
}


// The last value a name was bound to.
fn bound(b: const Binds&, name: const u8[:]) -> const u8[:], bool {
    var k = b.at.len - 4;
    while k >= 0 {
        if b.names[b.at[k]..b.at[k] + b.at[k + 1]] == name { return b.vals[b.at[k + 2]..b.at[k + 2] + b.at[k + 3]], true; }
        k -= 4;
    }
    return "", false;
}

fn bind(b: Binds&, name: const u8[:], v: const u8[:]) {
    b.at.push(b.names.len);
    b.at.push(name.len);
    b.at.push(b.vals.len);
    b.at.push(v.len);
    b.names.append(name);
    b.vals.append(v);
}

// $NOW, $NOW-n or $NOW+n: the seconds, and whether it is one.
fn now_value(v: const u8[:], now: i64) -> i64, bool {
    if v.len < 4 || v[..4] != "$NOW" { return 0, false; }
    if v.len == 4 { return now, true; }
    let d, ok = parse_int(v[5..], 10);
    if !ok || (v[4] != '-' && v[4] != '+') { return 0, false; }
    return if v[4] == '-' { now - d } else { now + d }, true;
}

// The value an element's placeholder stands for in a request, as the
// value attribute's text.
fn substitute(out: u8[>..]&, typ: const u8[:], v: const u8[:], b: const Binds&, now: i64) {
    if typ == "ByteString" && v.len > 0 && v[0] != '$' {
        var alias: u8[>..] = [];
        alias.push('#');
        alias.append(v);
        let av, aok = bound(b, alias);
        if aok { out.append(av); return; }
    }
    if v.len == 0 || v[0] != '$' { out.append(v); return; }
    let t, isnow = now_value(v, now);
    if isnow {
        if typ == "DateTimeExtended" { format_int(out, t * 1000000, 10, 0, ' '); }
        else { kmip::datetime_text(out, t); }
        return;
    }
    let bv, ok = bound(b, v);
    if ok { out.append(bv); return; }
    // Some files bind $NAME_0 and then send $NAME.
    var first: u8[>..] = [];
    first.append(v);
    first.append("_0");
    let fv, fok = bound(b, first);
    if fok { out.append(fv); return; }
    // Not bound yet: a Text String keeps its name (an identifier no object
    // has); a Byte String gets a byte.
    if typ == "ByteString" { out.append("00"); } else { out.append(v); }
}

// The element el written again as XML with its placeholders filled in.
recursive fn render(d: const xml::Doc&, el: i64, out: u8[>..]&, b: const Binds&, now: i64) {
    let name = xml::local_name(d, el);
    out.push('<');
    out.append(name);
    let tag, has_tag = xml::attr(d, el, "tag");
    if has_tag { out.append(" tag=\""); xml::escape_attr(out, tag); out.push('"'); }
    let typ, has_type = xml::attr(d, el, "type");
    if has_type { out.append(" type=\""); xml::escape_attr(out, typ); out.push('"'); }
    let v, has_value = xml::attr(d, el, "value");
    if has_value {
        out.append(" value=\"");
        render_value(out, typ, v, b, now);
        out.push('"');
    }
    var c = xml::first_element(d, el);
    if c < 0 { out.append("/>"); return; }
    out.push('>');
    while c >= 0 {
        render(d, c, out, b, now);
        c = xml::next_element(d, c);
    }
    out.append("</");
    out.append(name);
    out.push('>');
}

fn render_value(out: u8[>..]&, typ: const u8[:], v: const u8[:], b: const Binds&, now: i64) {
    var s: u8[>..] = [];
    substitute(s, typ, v, b, now);
    xml::escape_attr(out, s);
}

// --- Comparing --------------------------------------------------------------------

fn prepend(why: u8[>..]&, name: const u8[:]) {
    var w: u8[>..] = [];
    w.append(name);
    w.push('/');
    w.append(why);
    why.clear();
    why.append(w);
}

fn element_tag_of(d: const xml::Doc&, el: i64) -> u32, bool {
    if xml::local_name(d, el) == "TTLV" {
        let t, ok = xml::attr(d, el, "tag");
        if !ok { return 0, false; }
        let v, vok = kmip::tag_from_text(t);
        return v, vok;
    }
    let v, ok = kmip::element_tag(xml::local_name(d, el));
    return v, ok;
}

// A value against the expected one: a placeholder binds or must match
// what it is bound to; anything else must be the same item.
fn leaf_same(d: const xml::Doc&, el: i64, buf: const u8[:], doc: const kmip::Node[:], i: i64, attr: u32,
             b: Binds&, why: u8[>..]&) -> bool {
    let n = doc[i];
    if n.tag == kmip::TAG_RESULT_MESSAGE { return true; }
    let v, ok = xml::attr(d, el, "value");
    var got: u8[>..] = [];
    kmip::value_text(got, buf, doc, i, kmip::names_tag(n.tag, attr), ' ');
    if n.tag == kmip::TAG_TIME_STAMP { return n.typ == kmip::DATE_TIME; }
    // The server's own record of when (TC-IMPEXP-* give the dates of the
    // run they were made on, not $NOW).
    if (n.tag == kmip::TAG_INITIAL_DATE || n.tag == kmip::TAG_LAST_CHANGE_DATE) && ok && v.len > 0 && v[0] != '$' {
        return n.typ == kmip::DATE_TIME;
    }
    let keyish = n.typ == kmip::BYTE_STRING || n.typ == kmip::BIG_INTEGER;
    if b.loose && keyish && !(ok && v.len > 0 && v[0] == '$') { return true; }
    if b.derived && n.typ == kmip::BYTE_STRING && ok && v.len > 0 && v[0] != '$' {
        var alias: u8[>..] = [];
        alias.push('#');
        alias.append(v);
        let bv, bok = bound(b, alias);
        if !bok { bind(b, alias, got); return true; }
        if bv == got[..] { return true; }
    }
    if ok && v.len > 0 && v[0] == '$' {
        let t, isnow = now_value(v, 0);
        if isnow { return n.typ == kmip::DATE_TIME || n.typ == kmip::DATE_TIME_EXTENDED; }
        let bv, bok = bound(b, v);
        if !bok { bind(b, v, got); return true; }
        if bv == got[..] { return true; }
        // A file names every stream $CORRELATION_VALUE: a new stream's
        // value is bound in place of the last.
        if n.tag == kmip::TAG_CORRELATION_VALUE { bind(b, v, got); return true; }
        why.append(kmip::tag_name(n.tag));
        why.append(": expected ");
        why.append(v);
        why.append(" (");
        why.append(bv);
        why.append("), got ");
        why.append(got);
        return false;
    }
    var want: u8[>..] = [];
    let e = kmip::put_from_text(want, n.tag, n.typ, v, kmip::names_tag(n.tag, attr));
    if e == kmip::OK && want[..] == kmip::raw(buf, doc, i) { return true; }
    if b.random_ok && (n.tag == kmip::TAG_DATA || n.tag == kmip::TAG_SIGNATURE_DATA) {
        b.random_used = true;
        b.random_lens = e == kmip::OK && want.len == kmip::raw(buf, doc, i).len;
        return true;
    }
    why.append(kmip::tag_name(n.tag));
    why.append(": expected ");
    why.append(v);
    why.append(", got ");
    why.append(got);
    return false;
}

// Items one side may have and the other not: a Result Message (its text
// is the server's own), Located Items (a server may leave it out), a
// Server Correlation Value (a server SHOULD give one, 2.1 §9.10), an
// Attribute Index of 0 (KMIP 1.x's default).
fn optional_el(d: const xml::Doc&, el: i64) -> bool {
    if el < 0 { return false; }
    let n = xml::local_name(d, el);
    if n == "ResultMessage" || n == "LocatedItems" || n == "ServerCorrelationValue" { return true; }
    let v, ok = xml::attr(d, el, "value");
    return n == "AttributeIndex" && ok && v == "0";
}

fn optional_item(buf: const u8[:], doc: const kmip::Node[:], c: i64) -> bool {
    if c < 0 { return false; }
    let t = doc[c].tag;
    if t == kmip::TAG_RESULT_MESSAGE || t == kmip::TAG_LOCATED_ITEMS || t == kmip::TAG_SERVER_CORRELATION_VALUE { return true; }
    let v, ok = kmip::as_int(buf, doc, c);
    return t == kmip::TAG_ATTRIBUTE_INDEX && ok && v == 0;
}

fn tag_of_el(d: const xml::Doc&, el: i64) -> u32 {
    if el < 0 { return 0; }
    let t, ok = element_tag_of(d, el);
    return t;
}


recursive fn same(d: const xml::Doc&, el: i64, buf: const u8[:], doc: const kmip::Node[:], i: i64, attr: u32,
                  b: Binds&, why: u8[>..]&) -> bool {
    let n = doc[i];
    let tag, tok = element_tag_of(d, el);
    let tn, has_type = xml::attr(d, el, "type");
    let typ = if has_type { kmip::type_from_text(tn) } else { kmip::STRUCTURE };
    if !tok || tag != n.tag || typ != n.typ {
        why.append("expected ");
        why.append(xml::local_name(d, el));
        why.append(" (");
        why.append(if has_type { tn } else { "Structure" });
        why.append("), got ");
        kmip::tag_text(why, n.tag);
        why.append(" (");
        why.append(kmip::type_name(n.typ));
        why.push(')');
        return false;
    }
    if n.typ != kmip::STRUCTURE { return leaf_same(d, el, buf, doc, i, attr, b, why); }
    // A Random Number Generator attribute describes the server's own.
    if n.tag == kmip::TAG_RANDOM_NUMBER_GENERATOR || (n.tag == kmip::TAG_ATTRIBUTE_VALUE && attr == kmip::TAG_RANDOM_NUMBER_GENERATOR) {
        return true;
    }
    if unordered(n.tag) { return same_unordered(d, el, buf, doc, i, b, why); }
    let a = kmip::attribute_of(buf, doc, i);
    // Query's answer is the server's own (the profiles say the operations
    // and objects it lists may vary), and RNG Retrieve's is random.
    let op, has_op = kmip::child_enum(buf, doc, i, kmip::TAG_OPERATION);
    let any_payload = n.tag == kmip::TAG_BATCH_ITEM && has_op && (op == kmip::OP_QUERY || op == kmip::OP_RNG_RETRIEVE);
    // Get's and Export's key material of what the server made; Encrypt's
    // and Sign's output under an asymmetric key.
    let pl = kmip::child(doc, i, kmip::TAG_RESPONSE_PAYLOAD);
    let uid, has_uid = kmip::child_text(buf, doc, pl, kmip::TAG_UNIQUE_IDENTIFIER);
    // (and its Digest, which Get Attributes gives)
    let loose = n.tag == kmip::TAG_BATCH_ITEM && has_op && (op == kmip::OP_GET || op == kmip::OP_EXPORT || op == kmip::OP_GET_ATTRIBUTES) &&
                has_uid && listed(b.made, uid);
    let random = n.tag == kmip::TAG_BATCH_ITEM && has_op && (op == kmip::OP_ENCRYPT || op == kmip::OP_SIGN) &&
                 has_uid && listed(b.asym, uid);
    let derived = n.tag == kmip::TAG_BATCH_ITEM && has_op && (op == kmip::OP_ENCRYPT || op == kmip::OP_DECRYPT || op == kmip::OP_SIGN || op == kmip::OP_MAC) &&
                  has_uid && listed(b.made, uid) && !listed(b.asym, uid);
    var e = xml::first_element(d, el);
    var c = if n.count > 0 { i + 1 } else { -1 };
    loop {
        if any_payload && c >= 0 && e >= 0 && doc[c].tag == kmip::TAG_RESPONSE_PAYLOAD && xml::local_name(d, e) == "ResponsePayload" {
            e = xml::next_element(d, e);
            c = doc[c].next;
            continue;
        }
        // What is optional, on one side only, is let be.
        if optional_el(d, e) && (c < 0 || doc[c].tag != tag_of_el(d, e)) { e = xml::next_element(d, e); continue; }
        if optional_item(buf, doc, c) && (e < 0 || tag_of_el(d, e) != doc[c].tag) { c = doc[c].next; continue; }
        if e < 0 && c < 0 { return true; }
        if e < 0 {
            why.append("unexpected ");
            kmip::tag_text(why, doc[c].tag);
            prepend(why, xml::local_name(d, el));
            return false;
        }
        if c < 0 {
            why.append("missing ");
            why.append(xml::local_name(d, e));
            prepend(why, xml::local_name(d, el));
            return false;
        }
        let in_payload = doc[c].tag == kmip::TAG_RESPONSE_PAYLOAD;
        if in_payload { b.loose = loose; b.random_ok = random; b.derived = derived; }
        let r = same(d, e, buf, doc, c, a, b, why);
        if in_payload { b.loose = false; b.random_ok = false; b.derived = false; }
        if !r {
            prepend(why, xml::local_name(d, el));
            return false;
        }
        e = xml::next_element(d, e);
        c = doc[c].next;
    }
}

// What the server made, and which keys are asymmetric, from a request and
// its response.
fn note_made(req: const u8[:], resp: const u8[:], b: Binds&) {
    var rdoc: kmip::Node[>..] = [];
    var qdoc: kmip::Node[>..] = [];
    let root, e = kmip::decode(resp, kmip::Options { .. }, rdoc);
    let qroot, qe = kmip::decode(req, kmip::Options { .. }, qdoc);
    if e != kmip::OK || qe != kmip::OK { return; }
    let qit = kmip::child(qdoc, qroot, kmip::TAG_BATCH_ITEM);
    let qpl = kmip::child(qdoc, qit, kmip::TAG_REQUEST_PAYLOAD);
    kmip::each(rdoc, root) { it =>
        if rdoc[it].tag == kmip::TAG_BATCH_ITEM {
            let op, ook = kmip::child_enum(resp, rdoc, it, kmip::TAG_OPERATION);
            let st, sok = kmip::child_enum(resp, rdoc, it, kmip::TAG_RESULT_STATUS);
            let pl = kmip::child(rdoc, it, kmip::TAG_RESPONSE_PAYLOAD);
            if ook && sok && st == kmip::STATUS_SUCCESS && pl >= 0 {
                let made = op == kmip::OP_CREATE || op == kmip::OP_CREATE_KEY_PAIR || op == kmip::OP_DERIVE_KEY ||
                           op == kmip::OP_REKEY || op == kmip::OP_REKEY_KEY_PAIR || op == kmip::OP_CREATE_SPLIT_KEY ||
                           op == kmip::OP_CERTIFY || op == kmip::OP_RECERTIFY;
                // A Register of a private or public key.
                let reg_asym = op == kmip::OP_REGISTER &&
                               (kmip::child(qdoc, qpl, kmip::TAG_PRIVATE_KEY) >= 0 || kmip::child(qdoc, qpl, kmip::TAG_PUBLIC_KEY) >= 0);
                let pair = op == kmip::OP_CREATE_KEY_PAIR || op == kmip::OP_REKEY_KEY_PAIR;
                kmip::each(rdoc, pl) { c =>
                    let t = rdoc[c].tag;
                    if t == kmip::TAG_UNIQUE_IDENTIFIER || t == kmip::TAG_PRIVATE_KEY_UNIQUE_IDENTIFIER ||
                       t == kmip::TAG_PUBLIC_KEY_UNIQUE_IDENTIFIER {
                        let id, iok = kmip::as_text(resp, rdoc, c);
                        if iok && made { list_add(b.made, id); }
                        if iok && (pair || reg_asym) { list_add(b.asym, id); }
                    }
                };
            }
        }
    };
}

// An Encrypt's output decrypted, or a Sign's verified, by the server
// with the key itself or another asymmetric key of the test case's (the
// other half of the pair: the files register them apart, unlinked):
// whether one gives the request's data back, or calls it valid. When no
// key of the case can (a case may hold only the public key it encrypts
// with), the output must be as long as the file's.
fn verify_random(srv: kmip::Server&, req: const u8[:], resp: const u8[:], asym: const u8[:], same_len: bool) -> bool {
    var rdoc: kmip::Node[>..] = [];
    let rroot, re = kmip::decode(resp, kmip::Options { .. }, rdoc);
    if re != kmip::OK { return false; }
    let rit = kmip::child(rdoc, rroot, kmip::TAG_BATCH_ITEM);
    let rpl = kmip::child(rdoc, rit, kmip::TAG_RESPONSE_PAYLOAD);
    let uid, uok = kmip::child_text(resp, rdoc, rpl, kmip::TAG_UNIQUE_IDENTIFIER);
    if !uok { return false; }
    var wrong = false;
    let r0 = verify_with(srv, req, resp, uid);
    if r0 == 1 { return true; }
    if r0 == 0 { wrong = true; }
    var k = 0;
    while k < asym.len {
        var e = k;
        while e < asym.len && asym[e] != '\n' { e++; }
        if asym[k..e] != uid {
            let r = verify_with(srv, req, resp, asym[k..e]);
            if r == 1 { return true; }
            if r == 0 { wrong = true; }
        }
        k = e + 1;
    }
    return !wrong && same_len;
}

// 1: the key decrypts the output to the data, or finds the signature
// valid; 0: it does the operation and does not; -1: it does not do it.
fn verify_with(srv: kmip::Server&, req: const u8[:], resp: const u8[:], key: const u8[:]) -> i64 {
    var qdoc: kmip::Node[>..] = [];
    var rdoc: kmip::Node[>..] = [];
    let qroot, qe = kmip::decode(req, kmip::Options { .. }, qdoc);
    let rroot, re = kmip::decode(resp, kmip::Options { .. }, rdoc);
    if qe != kmip::OK || re != kmip::OK { return -1; }
    let hd = kmip::child(qdoc, qroot, kmip::TAG_REQUEST_HEADER);
    let v, vok = kmip::read_version(req, qdoc, kmip::child(qdoc, hd, kmip::TAG_PROTOCOL_VERSION));
    let qit = kmip::child(qdoc, qroot, kmip::TAG_BATCH_ITEM);
    let qpl = kmip::child(qdoc, qit, kmip::TAG_REQUEST_PAYLOAD);
    let rit = kmip::child(rdoc, rroot, kmip::TAG_BATCH_ITEM);
    let rpl = kmip::child(rdoc, rit, kmip::TAG_RESPONSE_PAYLOAD);
    let op, ook = kmip::child_enum(req, qdoc, qit, kmip::TAG_OPERATION);
    if !vok || qpl < 0 || rpl < 0 || !ook { return -1; }
    let data, dok = kmip::child_bytes(req, qdoc, qpl, kmip::TAG_DATA);
    let encrypt = op == kmip::OP_ENCRYPT;
    let outv, ok2 = kmip::child_bytes(resp, rdoc, rpl, if encrypt { kmip::TAG_DATA } else { kmip::TAG_SIGNATURE_DATA });
    if !dok || !ok2 { return -1; }
    var out: u8[>..] = [];
    let cred = kmip::no_credential();
    let m = kmip::begin_request(out, v, 1, cred);
    let it, p = kmip::begin_item(out, if encrypt { kmip::OP_DECRYPT } else { kmip::OP_SIGNATURE_VERIFY }, "");
    kmip::put_text(out, kmip::TAG_UNIQUE_IDENTIFIER, key);
    kmip::each(qdoc, qpl) { c =>
        let t = qdoc[c].tag;
        if t != kmip::TAG_UNIQUE_IDENTIFIER && t != kmip::TAG_DATA { kmip::put_raw(out, kmip::raw(req, qdoc, c)); }
    };
    if encrypt { kmip::put_bytes(out, kmip::TAG_DATA, outv); }
    else { kmip::put_bytes(out, kmip::TAG_DATA, data); kmip::put_bytes(out, kmip::TAG_SIGNATURE_DATA, outv); }
    kmip::end_item(out, it, p);
    kmip::end(out, m);
    var back: u8[>..] = [];
    kmip::handle(srv, "oasis", out, back);
    var bdoc: kmip::Node[>..] = [];
    let broot, be = kmip::decode(back, kmip::Options { .. }, bdoc);
    if be != kmip::OK { return -1; }
    let bit = kmip::child(bdoc, broot, kmip::TAG_BATCH_ITEM);
    let st, sok = kmip::child_enum(back, bdoc, bit, kmip::TAG_RESULT_STATUS);
    let bpl = kmip::child(bdoc, bit, kmip::TAG_RESPONSE_PAYLOAD);
    if !sok || st != kmip::STATUS_SUCCESS { return -1; }
    if encrypt {
        let plain, pok = kmip::child_bytes(back, bdoc, bpl, kmip::TAG_DATA);
        return if pok && plain == data { 1 } else { 0 };
    }
    let valid, vok2 = kmip::child_enum(back, bdoc, bpl, kmip::TAG_VALIDITY_INDICATOR);
    return if vok2 && valid == kmip::VALIDITY_VALID { 1 } else { 0 };
}

// Structures whose children may come in any order: attribute lists, and
// a payload (Get Attributes' attributes in KMIP 1.x, Locate's identifiers).
fn unordered(tag: u32) -> bool {
    tag == kmip::TAG_ATTRIBUTES || tag == kmip::TAG_COMMON_ATTRIBUTES || tag == kmip::TAG_PRIVATE_KEY_ATTRIBUTES ||
    tag == kmip::TAG_PUBLIC_KEY_ATTRIBUTES || tag == kmip::TAG_RESPONSE_PAYLOAD
}

fn rollback(b: Binds&, names: i64, vals: i64, at: i64) {
    b.names.resize(names);
    b.vals.resize(vals);
    b.at.resize(at);
}

// Each expected child matched to an actual one not matched yet, the first
// that is the same; none left over on either side.
recursive fn same_unordered(d: const xml::Doc&, el: i64, buf: const u8[:], doc: const kmip::Node[:], i: i64,
                            b: Binds&, why: u8[>..]&) -> bool {
    let a = kmip::attribute_of(buf, doc, i);
    var used: u64[64] = [0; 64];
    var e = xml::first_element(d, el);
    while e >= 0 {
        if optional_el(d, e) { e = xml::next_element(d, e); continue; }
        var c = if doc[i].count > 0 { i + 1 } else { -1 };
        var k = 0;
        var found = false;
        var first_same_tag = -1;
        while c >= 0 && !found {
            if k < 4096 && used[k / 64] & ((1 as u64) << (k % 64) as u64) == 0 {
                let t, tok = element_tag_of(d, e);
                if tok && t == doc[c].tag && first_same_tag < 0 { first_same_tag = c; }
                let nl = b.names.len;
                let vl = b.vals.len;
                let al = b.at.len;
                let wl = why.len;
                if same(d, e, buf, doc, c, a, b, why) {
                    used[k / 64] |= (1 as u64) << (k % 64) as u64;
                    found = true;
                } else {
                    rollback(b, nl, vl, al);
                    why.resize(wl);
                }
            }
            if !found { c = doc[c].next; k++; }
        }
        if !found {
            // Say how it differs from the first of its tag, if any.
            if first_same_tag >= 0 {
                let nl = b.names.len;
                let vl = b.vals.len;
                let al = b.at.len;
                let r = same(d, e, buf, doc, first_same_tag, a, b, why);
                rollback(b, nl, vl, al);
            } else {
                why.append("missing ");
                why.append(xml::local_name(d, e));
            }
            prepend(why, xml::local_name(d, el));
            return false;
        }
        e = xml::next_element(d, e);
    }
    var c = if doc[i].count > 0 { i + 1 } else { -1 };
    var k = 0;
    while c >= 0 {
        if (k >= 4096 || used[k / 64] & ((1 as u64) << (k % 64) as u64) == 0) && !optional_item(buf, doc, c) {
            why.append("unexpected ");
            kmip::tag_text(why, doc[c].tag);
            prepend(why, xml::local_name(d, el));
            return false;
        }
        c = doc[c].next;
        k++;
    }
    return true;
}

// What the server answered: each batch item's operation, status, reason
// and message.
fn answered(buf: const u8[:], doc: const kmip::Node[:], root: i64, out: u8[>..]&) {
    kmip::each(doc, root) { it =>
        if doc[it].tag == kmip::TAG_BATCH_ITEM {
            let op, ook = kmip::child_enum(buf, doc, it, kmip::TAG_OPERATION);
            let st, sok = kmip::child_enum(buf, doc, it, kmip::TAG_RESULT_STATUS);
            let rr, rok = kmip::child_enum(buf, doc, it, kmip::TAG_RESULT_REASON);
            let msg, mok = kmip::child_text(buf, doc, it, kmip::TAG_RESULT_MESSAGE);
            if out.len > 0 { out.append("; "); }
            if ook { kmip::enum_text(out, kmip::TAG_OPERATION, op); } else { out.append("?"); }
            out.push(' ');
            if sok { kmip::enum_text(out, kmip::TAG_RESULT_STATUS, st); }
            if rok { out.push('/'); kmip::enum_text(out, kmip::TAG_RESULT_REASON, rr); }
            if mok { out.append(" \""); out.append(msg); out.push('"'); }
        }
    };
}

// --- The two modes ----------------------------------------------------------------

fn messages(d: const xml::Doc&) -> i64[>..] {
    var out: i64[>..] = [];
    let root = xml::root_element(d);
    var e = xml::first_element(d, root);
    while e >= 0 {
        let n = xml::local_name(d, e);
        if n == "RequestMessage" || n == "ResponseMessage" { out.push(e); }
        e = xml::next_element(d, e);
    }
    return out;
}

fn roundtrip(name: const u8[:], d: const xml::Doc&) -> bool {
    var b = Binds { loose: false, random_ok: false, random_used: false, random_lens: false, derived: false, names: [], vals: [], at: [], made: [], asym: [] };
    var step = 0;
    for el in messages(d) {
        var x0: u8[>..] = [];
        render(d, el, x0, b, 1600000000);
        var t1: u8[>..] = [];
        var why: u8[>..] = [];
        let e1 = kmip::from_xml(x0, t1, kmip::Options { .. }, why);
        if e1 != kmip::OK { print("FAIL ", name, " message ", step, ": ", kmip::error_text(e1), ": ", why); return false; }
        var x1: u8[>..] = [];
        var j1: u8[>..] = [];
        let ex = kmip::ttlv_to_xml(t1, x1);
        let ej = kmip::ttlv_to_json(t1, j1);
        var t2: u8[>..] = [];
        var t3: u8[>..] = [];
        let e2 = kmip::from_xml(x1, t2, kmip::Options { .. }, why);
        let e3 = kmip::from_json(j1, t3, kmip::Options { .. }, why);
        var x2: u8[>..] = [];
        let ex2 = kmip::ttlv_to_xml(t2, x2);
        if ex != kmip::OK || ej != kmip::OK || e2 != kmip::OK || e3 != kmip::OK || t2[..] != t1[..] || t3[..] != t1[..] || x2[..] != x1[..] {
            print("FAIL ", name, " message ", step, ": not the same through XML and JSON ", why);
            return false;
        }
        step++;
    }
    print("PASS ", name, " (", step, " messages)");
    return true;
}

fn replay(name: const u8[:], d: const xml::Doc&) -> bool {
    var b = Binds { loose: false, random_ok: false, random_used: false, random_lens: false, derived: false, names: [], vals: [], at: [], made: [], asym: [] };
    var srv = kmip::server();
    let now = time_ns() / 1000000000;
    srv.now = now;
    let ms = messages(d);
    var k = 0;
    var step = 0;
    while k < ms.len {
        let el = ms[k];
        k++;
        if xml::local_name(d, el) != "RequestMessage" { continue; }
        var x: u8[>..] = [];
        render(d, el, x, b, now);
        var req: u8[>..] = [];
        var why: u8[>..] = [];
        let e = kmip::from_xml(x, req, kmip::Options { .. }, why);
        if e != kmip::OK { print("FAIL ", name, " step ", step, ": the request is not KMIP's XML: ", why); return false; }
        var resp: u8[>..] = [];
        kmip::handle(srv, "oasis", req, resp);
        note_made(req, resp, b);
        if k < ms.len && xml::local_name(d, ms[k]) == "ResponseMessage" {
            var doc: kmip::Node[>..] = [];
            let root, de = kmip::decode(resp, kmip::Options { .. }, doc);
            if de != kmip::OK { print("FAIL ", name, " step ", step, ": the response is not TTLV: ", kmip::error_text(de)); return false; }
            var diff: u8[>..] = [];
            if !same(d, ms[k], resp, doc, root, 0, b, diff) {
                var said: u8[>..] = [];
                answered(resp, doc, root, said);
                print("FAIL ", name, " step ", step, ": ", diff, " [server: ", said, "]");
                return false;
            }
            if b.random_used {
                b.random_used = false;
                if !verify_random(srv, req, resp, b.asym, b.random_lens) {
                    print("FAIL ", name, " step ", step, ": the server's ciphertext or signature does not decrypt or verify");
                    return false;
                }
            }
            k++;
        }
        step++;
    }
    print("PASS ", name, " (", step, " requests)");
    return true;
}

fn base_name(path: const u8[:]) -> const u8[:] {
    var k = path.len;
    while k > 0 && path[k - 1] != '/' { k--; }
    return path[k..];
}

fn main() {
    let a = args();
    if a.len < 2 || (a[1] != "roundtrip" && a[1] != "replay") {
        print("usage: oasis roundtrip|replay FILE...");
        exit(2);
    }
    var failed = 0;
    for k in 2..a.len {
        let path = a[k];
        var text: u8[>..] = [];
        if !read_file(path, text) { print("FAIL ", base_name(path), ": cannot read it"); failed++; continue; }
        var d = xml::Doc { .. };
        let pe = xml::parse(d, text);
        if !xml::ok(pe) {
            print("FAIL ", base_name(path), ": the file is not well-formed XML (line ", pe.line, ": ", pe.message, ")");
            failed++;
            continue;
        }
        let ok = if a[1] == "roundtrip" { roundtrip(base_name(path), d) } else { replay(base_name(path), d) };
        if !ok { failed++; }
    }
    if failed > 0 { exit(1); }
}
