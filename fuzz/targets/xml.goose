// Fuzz target: xml. The first byte picks options (DOCTYPE allowed, unique
// IDs, smaller limits, a fragment parse); the rest is parsed, every node
// walked (kind, names, values, attributes, namespaces in scope, IDs,
// text and base64 content), the document written out and parsed again,
// and canonicalized: the whole document by all six methods, and up to
// eight element subsets (some by ID, with a PrefixList and an excluded
// subtree).

import std;
import gslib from "../..";
import gslib.encoding.xml;
import gslib.encoding.xml.c14n;

let MAX_SUBSETS:     i64 = 8;
let MAX_SCOPE_WALKS: i64 = 64;

fn visit(d: const xml::Doc&, n: i64, els: i64[>..]&, scoped: i64&) {
    let k = xml::kind(d, n);
    let _ = xml::parent(d, n);
    let _ = xml::last_child(d, n);
    let _ = xml::prev_sibling(d, n);
    let _ = xml::local_name(d, n);
    let _ = xml::prefix(d, n);
    let _ = xml::ns_uri(d, n);
    let _ = xml::value(d, n);
    if k != xml::ELEMENT { return; }
    els.push(n);
    let _ = xml::attached(d, n);
    let _ = xml::within(d, 0, n);
    let _, _ = xml::id_of(d, n);
    let _, _ = xml::attr(d, n, "Id");
    let _, _ = xml::attr(d, n, xml::XML_NS, "lang");
    let _ = xml::child(d, n, xml::ns_uri(d, n), "Signature");
    let _ = xml::count_children(d, n, "", "a");
    let _, _ = xml::lookup_ns(d, n, xml::prefix(d, n));
    let _, _ = xml::lookup_ns(d, n, "");
    xml::each_attr(d, n) { a => let _ = xml::value(d, a); };
    xml::each_element(d, n) { c => let _ = xml::local_name(d, c); };
    if scoped < MAX_SCOPE_WALKS {
        scoped++;
        xml::each_in_scope(d, n) { ns, uri => let _ = uri.len; };
    }
    if els.len <= MAX_SUBSETS {
        var t: u8[>..] = [];
        xml::text_content(d, n, t);
    }
    var b: u8[>..] = [];
    let _ = xml::base64_content(d, n, b);
    let _ = xml::only_elements(d, n);
}

fn walk_doc(d: const xml::Doc&) -> i64[>..] {
    var els: i64[>..] = [];
    var scoped = 0;
    xml::walk(d, 0) { n, entering =>
        if entering { visit(d, n, els, scoped); }
        true
    };
    return els;
}

fn canon(d: const xml::Doc&, n: i64, method: i64, comments: bool, prefixes: const u8[:], exclude: i64) {
    var m = xml::C14n { .. };
    m.method = method;
    m.comments = comments;
    m.exclude = exclude;
    format(m.inclusive, prefixes);
    var out: u8[>..] = [];
    let _ = xml::canonicalize(d, n, m, out);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let sel = data[0];
    let text = data[1..];
    var o = xml::options();
    o.allow_doctype = sel & 1 != 0;
    o.unique_ids = sel & 2 == 0;
    if sel & 4 != 0 { o.max_depth = 8; o.max_attrs = 4; o.max_nodes = 64; o.max_namespaces = 4; o.max_name = 16; }
    var d = xml::Doc { .. };
    if sel & 8 != 0 {
        // A fragment parsed into an element of a small document.
        xml::new_document(d);
        let root = xml::element(d, 0, "p", "root", "urn:x");
        let _ = xml::declare_ns(d, root, "p", "urn:x");
        let e = xml::parse_fragment(d, root, -1, text, o);
        if !xml::ok(e) { return 0; }
    } else {
        let e = xml::parse(d, text, o);
        let _ = xml::error_name(e.code);
        if !xml::ok(e) { return 0; }
    }
    let els = walk_doc(d);
    let _ = xml::root_element(d);
    var out: u8[>..] = [];
    xml::write_document(d, out);
    var d2 = xml::Doc { .. };
    let _ = xml::parse(d2, out[..], o);

    for method in [xml::C14N_10, xml::C14N_11, xml::EXC_C14N] {
        for comments in [false, true] { canon(d, 0, method, comments, "", -1); }
    }
    var k = 0;
    for el in els {
        if k >= MAX_SUBSETS { break; }
        let method = [xml::C14N_10, xml::C14N_11, xml::EXC_C14N][(k + (sel >> 4)) % 3];
        let inner = xml::first_element(d, el);
        let prefixes = if k % 2 == 0 { "#default p ds" } else { "" };
        canon(d, el, method, k % 3 == 0, prefixes, inner);
        let id, has = xml::id_of(d, el);
        if has { let _, _ = xml::by_id(d, id); }
        k++;
    }
    return 0;
}

fn main() {}
