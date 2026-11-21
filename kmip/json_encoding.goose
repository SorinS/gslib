// kmip.json_encoding: KMIP's JSON encoding (KMIP Profiles 2.1 §5.5), to
// and from TTLV. Each item is an object with its tag, type and value; a
// Structure's value is the array of its children, and its type is left
// out:
//
//   {"tag":"RequestHeader", "value":[
//     {"tag":"ProtocolVersion", "value":[
//       {"tag":"ProtocolVersionMajor", "type":"Integer", "value":2},
//   ...
//
// Written: numbers as JSON numbers where they fit one exactly (a Long
// Integer or Date-Time Extended past 2^52 as 0x and sixteen hex digits),
// a Big Integer as 0x and its hex, Enumerations and masks by name
// ("Sign|Verify"), Byte Strings in hex, Date-Times as xsd:dateTime in UTC.
// Read: every form the profiles allow (numbers, hex strings, names), a
// `name` member (ignored), a Structure's value null or absent for none.
// Anything else (another member, a member twice, a number with a
// fraction) is refused.

namespace kmip;

import std;
import binary;
import json;
import kmip;
import kmip.tables;
import kmip.text;

// --- Writing ----------------------------------------------------------------------

// What a JSON number holds exactly: |v| below 2^52, as the profiles say.
fn json_safe(v: i64) -> bool { v > -4503599627370496 && v < 4503599627370496 }

fn json_value(out: u8[>..]&, buf: const u8[:], doc: const Node[:], i: i64, ntag: u32) {
    let n = doc[i];
    if n.typ == INTEGER {
        let v, ok = as_int(buf, doc, i);
        if is_mask(ntag) && v != 0 {
            var t: u8[>..] = [];
            mask_text(t, ntag, v as! u32, '|');
            json::format_string(out, t);
        } else {
            format_int(out, v, 10, 0, ' ');
        }
    } else if n.typ == LONG_INTEGER || n.typ == DATE_TIME_EXTENDED {
        let v = binary::u64be(buf, n.off) as! i64;
        if json_safe(v) { format_int(out, v, 10, 0, ' '); }
        else { out.append("\"0x"); format_uint(out, v as! u64, 16, 16, '0'); out.push('"'); }
    } else if n.typ == BIG_INTEGER {
        out.append("\"0x");
        hex_text(out, value(buf, doc, i));
        out.push('"');
    } else if n.typ == BOOLEAN {
        let v, ok = as_bool(buf, doc, i);
        out.append(if v { "true" } else { "false" });
    } else if n.typ == INTERVAL {
        let v, ok = as_interval(buf, doc, i);
        format_uint(out, v, 10, 0, ' ');
    } else {
        var t: u8[>..] = [];
        value_text(t, buf, doc, i, ntag, '|');
        json::format_string(out, t);
    }
}

recursive fn json_at(out: u8[>..]&, buf: const u8[:], doc: const Node[:], i: i64, depth: i64, attr: u32) {
    for k in depth { out.append("  "); }
    let n = doc[i];
    out.append("{\"tag\":\"");
    tag_text(out, n.tag);
    out.push('"');
    if n.typ == STRUCTURE {
        if n.count == 0 { out.append(", \"value\":[]}"); return; }
        out.append(", \"value\":[\n");
        let a = attribute_of(buf, doc, i);
        var first = true;
        each(doc, i) { c =>
            if !first { out.append(",\n"); }
            first = false;
            json_at(out, buf, doc, c, depth + 1, a);
        };
        out.push('\n');
        for k in depth { out.append("  "); }
        out.append("]}");
        return;
    }
    out.append(", \"type\":\"");
    out.append(type_name(n.typ));
    out.append("\", \"value\":");
    json_value(out, buf, doc, i, names_tag(n.tag, attr));
    out.push('}');
}

// The item doc[i] and what it holds as JSON, indented two spaces a level
// from `depth`.
fn to_json(out: u8[>..]&, buf: const u8[:], doc: const Node[:], i: i64, depth: i64) {
    if i >= 0 { json_at(out, buf, doc, i, depth, 0); }
}

// A TTLV message (or any one item) as JSON.
fn ttlv_to_json(ttlv: const u8[:], out: u8[>..]&) -> i64 {
    var doc: Node[>..] = [];
    let root, e = decode(ttlv, Options { .. }, doc);
    if e != OK { return e; }
    json_at(out, ttlv, doc, root, 0, 0);
    out.push('\n');
    return OK;
}

// --- Reading ----------------------------------------------------------------------

fn json_fail(why: u8[>..]&, tag: const u8[:], what: const u8[:], detail: const u8[:]) {
    if why.len > 0 { return; }
    why.append(if tag.len > 0 { tag } else { "item" });
    why.append(": ");
    why.append(what);
    if detail.len > 0 { why.append(" \""); why.append(detail); why.push('"'); }
}

fn json_is_object(n: json::Node&) -> bool {
    match n.val {
        Obj => { return true; },
        _ => { return false; },
    }
}

// An item whose value is a JSON number.
fn put_from_number(out: u8[>..]&, tag: u32, typ: u8, v: i64) -> i64 {
    if typ == INTEGER {
        if v < -2147483648 || v > 2147483647 { return ERR_MALFORMED; }
        put_int(out, tag, v as! i32);
        return OK;
    }
    if typ == LONG_INTEGER { put_long(out, tag, v); return OK; }
    if typ == DATE_TIME_EXTENDED { put_datetime_ext(out, tag, v); return OK; }
    if typ == ENUMERATION || typ == INTERVAL {
        if v < 0 || v > 4294967295 { return ERR_MALFORMED; }
        if typ == ENUMERATION { put_enum(out, tag, v as! u32); } else { put_interval(out, tag, v as! u32); }
        return OK;
    }
    if typ == BIG_INTEGER {
        put_head(out, tag, BIG_INTEGER, 8);
        put_be(out, v as! u64, 8);
        return OK;
    }
    return ERR_MALFORMED;
}

// The attribute an Attribute object names in its Attribute Name child.
fn json_attribute_of(list: json::Node?) -> u32 {
    guard list else { return 0; }
    var found: u32 = 0;
    json::each(list) { c =>
        let t, tok = json::as_string(json::member(c, "tag"));
        if tok && t == "AttributeName" {
            let v, vok = json::as_string(json::member(c, "value"));
            if vok && found == 0 { found = attribute_tag(v); }
        }
    };
    return found;
}

// Whether an item's members are tag, type, value and name, each once.
fn json_members(n: json::Node&, tag: const u8[:], why: u8[>..]&) -> i64 {
    var seen: i64[4] = [0, 0, 0, 0];
    var bad: u8[>..] = [];
    json::each(n) { m =>
        let k = m.key;
        if k == "tag" { seen[0]++; }
        else if k == "type" { seen[1]++; }
        else if k == "value" { seen[2]++; }
        else if k == "name" { seen[3]++; }
        else if bad.len == 0 { bad.append(k); }
    };
    if bad.len > 0 { json_fail(why, tag, "unknown member", bad); return ERR_MALFORMED; }
    if seen[0] > 1 || seen[1] > 1 || seen[2] > 1 || seen[3] > 1 { json_fail(why, tag, "a member twice", ""); return ERR_MALFORMED; }
    return OK;
}

recursive fn json_item(n: json::Node&, out: u8[>..]&, depth: i64, attr: u32, opts: Options, why: u8[>..]&) -> i64 {
    if depth > opts.max_depth { json_fail(why, "", "nested too deeply", ""); return ERR_DEPTH; }
    if out.len > opts.max_bytes { json_fail(why, "", "too large", ""); return ERR_TOO_LARGE; }
    if !json_is_object(n) { json_fail(why, "", "not an object", ""); return ERR_MALFORMED; }
    let tag_text_, tok = json::as_string(json::member(n, "tag"));
    if !tok { json_fail(why, "", "no tag", ""); return ERR_TAG; }
    let me = json_members(n, tag_text_, why);
    if me != OK { return me; }
    let tag, known = tag_from_text(tag_text_);
    if !known { json_fail(why, tag_text_, "unknown tag", tag_text_); return ERR_TAG; }
    var typ = STRUCTURE;
    let tm = json::member(n, "type");
    if tm {
        let tn, ok = json::as_string(tm);
        typ = if ok { type_from_text(tn) } else { 0 };
        if typ == 0 { json_fail(why, tag_text_, "unknown type", tn); return ERR_TYPE; }
    }
    let v = json::member(n, "value");
    if typ == STRUCTURE {
        let s = begin(out, tag);
        if v {
            var is_list = false;
            var is_null = false;
            match v.val {
                Arr => { is_list = true; },
                Null => { is_null = true; },
                _ => {},
            }
            if !is_list && !is_null { json_fail(why, tag_text_, "a Structure's value is not an array", ""); return ERR_MALFORMED; }
            if is_list {
                let a = if tag == TAG_ATTRIBUTE { json_attribute_of(v) } else { 0 };
                var err = OK;
                json::each(v) { c =>
                    if err == OK { err = json_item(c, out, depth + 1, a, opts, why); }
                };
                if err != OK { return err; }
            }
        }
        end(out, s);
        return OK;
    }
    guard v else { json_fail(why, tag_text_, "no value", ""); return ERR_MISSING; }
    let ntag = names_tag(tag, attr);
    var r = ERR_MALFORMED;
    var shown: u8[>..] = [];
    match v.val {
        Str t => { r = put_from_text(out, tag, typ, t.s, ntag); shown.append(t.s); },
        Int x => {
            r = put_from_number(out, tag, typ, x.v);
            format_int(shown, x.v, 10, 0, ' ');
        },
        Bool b => {
            if typ == BOOLEAN { put_bool(out, tag, b.v); r = OK; }
            shown.append(if b.v { "true" } else { "false" });
        },
        _ => {},
    }
    if r != OK { json_fail(why, tag_text_, str("not a valid ", type_name(typ)), shown); }
    return r;
}

// JSON text holding one item (a message) as TTLV; why says what was wrong
// when it was not KMIP's JSON.
fn from_json(text: const u8[:], out: u8[>..]&, opts: Options, why: u8[>..]&) -> i64 {
    if text.len > opts.max_bytes * 16 { return ERR_TOO_LARGE; }
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { why.append(msg); return ERR_MALFORMED; }
    let r = json_item(root, out, 0, 0, opts, why);
    if r == OK && out.len > opts.max_bytes { return ERR_TOO_LARGE; }
    return r;
}

fn from_json(text: const u8[:], out: u8[>..]&) -> i64 {
    var why: u8[>..] = [];
    return from_json(text, out, Options { .. }, why);
}
