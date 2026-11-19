// kmip.xml: KMIP's XML encoding (KMIP Profiles 2.1 §5.4), to and from
// TTLV. Each item is an element named by its tag, with its type and value
// in attributes; a Structure's children are its elements:
//
//   <RequestHeader>
//     <ProtocolVersion>
//       <ProtocolVersionMajor type="Integer" value="2"/>
//       ...
//     <BatchCount type="Integer" value="1"/>
//   </RequestHeader>
//
// A tag not named here is written <TTLV tag="0x540001" type=... value=...>,
// the general form. Read: both forms, element names that are a tag's hex
// after an x (x540001), the namespace urn:oasis:tc:kmip:xmlns or none, a
// `name` attribute (ignored), and every value form of kmip.text. Anything
// else (an unknown attribute, text inside an element, a Structure with a
// value) is refused, as the TTLV decoder refuses.
//
//   var x: u8[>..] = [];
//   let e = kmip::ttlv_to_xml(message, x);
//   var back: u8[>..] = [];
//   let e2 = kmip::from_xml(x, back);

namespace kmip;

import std;
import encoding.xml;
import kmip;
import kmip.tables;
import kmip.text;

let KMIP_XMLNS: const u8[:] = "urn:oasis:tc:kmip:xmlns";

// --- Writing ----------------------------------------------------------------------

recursive fn xml_at(out: u8[>..]&, buf: const u8[:], doc: const Node[:], i: i64, depth: i64, attr: u32) -> i64 {
    for k in depth { out.append("  "); }
    let n = doc[i];
    let name = tag_name(n.tag);
    if name.len == 0 {
        out.append("<TTLV tag=\"0x");
        format_uint(out, n.tag, 16, 6, '0');
        out.push('"');
    } else {
        out.push('<');
        out.append(name);
    }
    if n.typ == STRUCTURE {
        if n.count == 0 { out.append("/>\n"); return OK; }
        out.append(">\n");
        let a = attribute_of(buf, doc, i);
        var c = i + 1;
        while c >= 0 {
            let r = xml_at(out, buf, doc, c, depth + 1, a);
            if r != OK { return r; }
            c = doc[c].next;
        }
        for k in depth { out.append("  "); }
        out.append("</");
        out.append(if name.len == 0 { "TTLV" } else { name });
        out.append(">\n");
        return OK;
    }
    // XML 1.0 has no way to write some characters (most of the C0
    // controls), even as references.
    if n.typ == TEXT_STRING && !xml::is_text(value(buf, doc, i)) { return ERR_UTF8; }
    out.append(" type=\"");
    out.append(type_name(n.typ));
    out.append("\" value=\"");
    var v: u8[>..] = [];
    value_text(v, buf, doc, i, names_tag(n.tag, attr), ' ');
    xml::escape_attr(out, v);
    out.append("\"/>\n");
    return OK;
}

// The item doc[i] and what it holds as XML, indented two spaces a level
// from `depth`, one element a line. ERR_UTF8 for a Text String holding a
// character XML cannot carry (a control character other than tab, line
// feed and carriage return).
fn to_xml(out: u8[>..]&, buf: const u8[:], doc: const Node[:], i: i64, depth: i64) -> i64 {
    if i < 0 { return ERR_ARG; }
    return xml_at(out, buf, doc, i, depth, 0);
}

// A TTLV message (or any one item) as XML.
fn ttlv_to_xml(ttlv: const u8[:], out: u8[>..]&) -> i64 {
    var doc: Node[>..] = [];
    let root, e = decode(ttlv, Options { .. }, doc);
    if e != OK { return e; }
    return xml_at(out, ttlv, doc, root, 0, 0);
}

// --- Reading ----------------------------------------------------------------------

fn xml_fail(why: u8[>..]&, d: const xml::Doc&, el: i64, what: const u8[:], detail: const u8[:]) {
    if why.len > 0 { return; }
    why.append(xml::local_name(d, el));
    why.append(": ");
    why.append(what);
    if detail.len > 0 { why.append(" \""); why.append(detail); why.push('"'); }
}

// The tag an element names: its own name, or the hex after an x.
fn element_tag(name: const u8[:]) -> u32, bool {
    if name.len == 7 && (name[0] == 'x' || name[0] == 'X') {
        var hex: u8[>..] = "0x";
        hex.append(name[1..]);
        let h, hok = hex_number(hex, 6);
        if hok { return h as! u32, tag_ok(h as! u32); }
    }
    let t, ok = tag_by_name(name);
    return t, ok;
}

// The attribute an Attribute element names in its Attribute Name child.
fn xml_attribute_of(d: const xml::Doc&, el: i64) -> u32 {
    var c = xml::first_element(d, el);
    while c >= 0 {
        if xml::local_name(d, c) == "AttributeName" {
            let v, ok = xml::attr(d, c, "value");
            if ok { return attribute_tag(v); }
        }
        c = xml::next_element(d, c);
    }
    return 0;
}

recursive fn xml_item(d: const xml::Doc&, el: i64, out: u8[>..]&, depth: i64, attr: u32, opts: Options,
                      why: u8[>..]&) -> i64 {
    if depth > opts.max_depth { xml_fail(why, d, el, "nested too deeply", ""); return ERR_DEPTH; }
    if out.len > opts.max_bytes { xml_fail(why, d, el, "too large", ""); return ERR_TOO_LARGE; }
    let ns = xml::ns_uri(d, el);
    if ns.len > 0 && ns != KMIP_XMLNS { xml_fail(why, d, el, "not in KMIP's namespace", ns); return ERR_MALFORMED; }
    let name = xml::local_name(d, el);
    let general = name == "TTLV";
    var tag: u32 = 0;
    if general {
        let t, tok = xml::attr(d, el, "tag");
        if !tok { xml_fail(why, d, el, "no tag", ""); return ERR_TAG; }
        let v, ok = tag_from_text(t);
        if !ok { xml_fail(why, d, el, "unknown tag", t); return ERR_TAG; }
        tag = v;
    } else {
        let v, ok = element_tag(name);
        if !ok { xml_fail(why, d, el, "unknown tag", name); return ERR_TAG; }
        tag = v;
    }
    var bad: i64 = -1;
    xml::each_attr(d, el) { a =>
        let an = xml::local_name(d, a);
        let known = xml::ns_uri(d, a).len == 0 &&
                    (an == "type" || an == "value" || an == "name" || (general && an == "tag"));
        if !known && bad < 0 { bad = a; }
    };
    if bad >= 0 { xml_fail(why, d, el, "unknown attribute", xml::local_name(d, bad)); return ERR_MALFORMED; }
    var typ = STRUCTURE;
    let tn, has_type = xml::attr(d, el, "type");
    if has_type {
        typ = type_from_text(tn);
        if typ == 0 { xml_fail(why, d, el, "unknown type", tn); return ERR_TYPE; }
    }
    let v, has_value = xml::attr(d, el, "value");
    // Only white space and comments between elements; no text.
    var c = xml::first_child(d, el);
    while c >= 0 {
        let k = xml::kind(d, c);
        if k == xml::TEXT || k == xml::CDATA {
            if !is_blank(xml::value(d, c)) { xml_fail(why, d, el, "text inside an element", ""); return ERR_MALFORMED; }
        } else if k == xml::ELEMENT && typ != STRUCTURE {
            xml_fail(why, d, el, "elements inside a value", ""); return ERR_MALFORMED;
        }
        c = xml::next_sibling(d, c);
    }
    if typ == STRUCTURE {
        if has_value { xml_fail(why, d, el, "a Structure with a value", ""); return ERR_MALFORMED; }
        let s = begin(out, tag);
        let a = if tag == TAG_ATTRIBUTE { xml_attribute_of(d, el) } else { 0 };
        var e = xml::first_element(d, el);
        while e >= 0 {
            let r = xml_item(d, e, out, depth + 1, a, opts, why);
            if r != OK { return r; }
            e = xml::next_element(d, e);
        }
        end(out, s);
        return OK;
    }
    if !has_value { xml_fail(why, d, el, "no value", ""); return ERR_MISSING; }
    let r = put_from_text(out, tag, typ, v, names_tag(tag, attr));
    if r != OK { xml_fail(why, d, el, str("not a valid ", type_name(typ)), v); }
    return r;
}

fn is_blank(s: const u8[:]) -> bool {
    for c in s {
        if c != ' ' && c != '\t' && c != '\n' && c != '\r' { return false; }
    }
    return true;
}

// The element el of a parsed document and what it holds as TTLV, onto
// out; why says what was wrong when it was not KMIP's XML.
fn xml_element_to_ttlv(d: const xml::Doc&, el: i64, out: u8[>..]&, opts: Options, why: u8[>..]&) -> i64 {
    let r = xml_item(d, el, out, 0, 0, opts, why);
    if r == OK && out.len > opts.max_bytes { return ERR_TOO_LARGE; }
    return r;
}

// An XML document whose root element is one item (a message) as TTLV.
fn from_xml(text: const u8[:], out: u8[>..]&, opts: Options, why: u8[>..]&) -> i64 {
    if text.len > opts.max_bytes * 16 { return ERR_TOO_LARGE; }
    var d = xml::Doc { .. };
    let pe = xml::parse(d, text);
    if !xml::ok(pe) {
        why.append("xml: ");
        why.append(pe.message);
        return ERR_MALFORMED;
    }
    let root = xml::root_element(d);
    if root < 0 { why.append("no element"); return ERR_MALFORMED; }
    let r = xml_element_to_ttlv(d, root, out, opts, why);
    return r;
}

fn from_xml(text: const u8[:], out: u8[>..]&) -> i64 {
    var why: u8[>..] = [];
    let opts = Options { .. };
    return from_xml(text, out, opts, why);
}
