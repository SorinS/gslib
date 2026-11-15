// xml.c14n: Canonical XML 1.0 and 1.1 and Exclusive XML Canonicalization
// 1.0, with and without comments, of a whole document or of the subtree
// of one element (a document subset, as XML Signature's same-document
// references give it), optionally leaving out one subtree inside it (the
// enveloped-signature transform). Exclusive canonicalization takes an
// InclusiveNamespaces PrefixList.
//
// The subset of an element is the element, its descendants and their
// attributes and namespaces, as an XPath node-set selects them: so its
// namespace axis holds every namespace in scope, and for Canonical XML
// 1.0 the xml: attributes of the ancestors left out (xml:lang, xml:space,
// xml:base, xml:id) are carried onto it; Canonical XML 1.1 carries only
// xml:lang and xml:space, and joins xml:base values into it (§2.4).

namespace xml;

import std;
import encoding.xml;

let C14N_10:  i64 = 1;   // Canonical XML 1.0
let C14N_11:  i64 = 2;   // Canonical XML 1.1
let EXC_C14N: i64 = 3;   // Exclusive XML Canonicalization 1.0

let URI_C14N_10:           const u8[:] = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
let URI_C14N_10_COMMENTS:  const u8[:] = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
let URI_C14N_11:           const u8[:] = "http://www.w3.org/2006/12/xml-c14n11";
let URI_C14N_11_COMMENTS:  const u8[:] = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
let URI_EXC_C14N:          const u8[:] = "http://www.w3.org/2001/10/xml-exc-c14n#";
let URI_EXC_C14N_COMMENTS: const u8[:] = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

// A canonicalization: the method, comments kept or not, for EXC_C14N the
// InclusiveNamespaces PrefixList (prefixes separated by white space,
// "#default" for the default namespace), and a subtree to leave out (-1:
// none).
struct C14n {
    method:    i64        = EXC_C14N,
    comments:  bool       = false,
    inclusive: u8[..1024] = [],
    exclude:   i64        = -1,
}

// The algorithm URI of a method.
fn c14n_uri(method: i64, comments: bool) -> const u8[:] {
    if method == C14N_10 { return if comments { URI_C14N_10_COMMENTS } else { URI_C14N_10 }; }
    if method == C14N_11 { return if comments { URI_C14N_11_COMMENTS } else { URI_C14N_11 }; }
    return if comments { URI_EXC_C14N_COMMENTS } else { URI_EXC_C14N };
}

// The method of an algorithm URI, with comments or not; false for one
// that is not a canonicalization.
fn c14n_of_uri(uri: const u8[:]) -> i64, bool, bool {
    if uri == URI_C14N_10 { return C14N_10, false, true; }
    if uri == URI_C14N_10_COMMENTS { return C14N_10, true, true; }
    if uri == URI_C14N_11 { return C14N_11, false, true; }
    if uri == URI_C14N_11_COMMENTS { return C14N_11, true, true; }
    if uri == URI_EXC_C14N { return EXC_C14N, false, true; }
    if uri == URI_EXC_C14N_COMMENTS { return EXC_C14N, true, true; }
    return 0, false, false;
}

// A namespace declaration written by an output element at a depth.
struct Rendered { prefix: const u8[:], uri: const u8[:], depth: i64 }

// An attribute to write: its namespace, local name, qualified name and value.
struct AttrOut { ns: const u8[:], prefix: const u8[:], local: const u8[:], value: const u8[:] }

// The URI a prefix was last written with by an output ancestor, and
// whether one was.
fn rendered(r: const Rendered[:], prefix: const u8[:]) -> const u8[:], bool {
    var i = r.len - 1;
    while i >= 0 {
        if r[i].prefix == prefix { return r[i].uri, true; }
        i--;
    }
    return "", false;
}

// Whether a prefix is in the PrefixList (the empty prefix as #default).
fn in_prefix_list(list: const u8[:], prefix: const u8[:]) -> bool {
    var found = false;
    each_word(list) {
        if (prefix.len == 0 && it == "#default") || (prefix.len > 0 && it == prefix) { found = true; }
    };
    return found;
}

// Whether the PrefixList is well formed: NCNames and #default.
fn prefix_list_ok(list: const u8[:]) -> bool {
    var good = true;
    each_word(list) { if it != "#default" && !is_ncname(it) { good = false; } };
    return good;
}

// --- RFC 3986 reference resolution, for xml:base in Canonical XML 1.1 ------------

// The scheme, authority, path, query and fragment of a URI reference:
// bounds into it, and whether each is present.
struct UriParts { scheme: i64 = -1, auth_from: i64 = -1, auth_to: i64 = -1, path_from: i64 = 0, path_to: i64 = 0,
                  query_from: i64 = -1, query_to: i64 = -1, frag_from: i64 = -1 }

fn uri_parts(u: const u8[:]) -> UriParts {
    var r = UriParts { .. };
    var i = 0;
    // scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"
    var j = 0;
    while j < u.len && (ascii::is_alnum(u[j]) || u[j] == '+' || u[j] == '-' || u[j] == '.') { j++; }
    if j > 0 && j < u.len && u[j] == ':' && ascii::is_alpha(u[0]) { r.scheme = j; i = j + 1; }
    if i + 1 < u.len && u[i] == '/' && u[i + 1] == '/' {
        r.auth_from = i + 2;
        var k = i + 2;
        while k < u.len && u[k] != '/' && u[k] != '?' && u[k] != '#' { k++; }
        r.auth_to = k;
        i = k;
    }
    r.path_from = i;
    while i < u.len && u[i] != '?' && u[i] != '#' { i++; }
    r.path_to = i;
    if i < u.len && u[i] == '?' {
        r.query_from = i + 1;
        while i < u.len && u[i] != '#' { i++; }
        r.query_to = i;
    }
    if i < u.len && u[i] == '#' { r.frag_from = i + 1; }
    return r;
}

// remove_dot_segments (RFC 3986 §5.2.4), as Canonical XML 1.1 §2.4
// changes it: the ".." segments that would climb above a relative path's
// start are kept.
fn remove_dots(path: const u8[:], out: u8[>..]&) {
    var segs: const u8[:][>..<] = [];
    let absolute = path.len > 0 && path[0] == '/';
    let parts = split(if absolute { path[1..] } else { path }, '/');
    var i = 0;
    var trailing = false;
    for s in parts {
        let last = i == parts.len - 1;
        if s == "." {
            trailing = last;
        } else if s == ".." {
            if segs.len > 0 && segs[segs.len - 1] != ".." { segs.pop(); }
            else if !absolute { segs.push(s); }
            trailing = last;
        } else {
            segs.push(s);
            trailing = false;
        }
        i++;
    }
    if absolute { out.push('/'); }
    var first = true;
    for s in segs {
        if !first { out.push('/'); }
        out.append(s);
        first = false;
    }
    if trailing && segs.len > 0 { out.push('/'); }
}

// The path of base with its last segment replaced by rel (RFC 3986 §5.2.3).
fn merge_paths(base: const u8[:], has_authority: bool, rel: const u8[:], out: u8[>..]&) {
    if has_authority && base.len == 0 { out.push('/'); out.append(rel); return; }
    let slash = rfind(base, "/");
    if slash >= 0 { out.append(base[..slash + 1]); }
    out.append(rel);
}

// The reference ref resolved against base (RFC 3986 §5.2.2; a relative
// base stays relative), into out. The fragment of ref is kept.
fn join_uri(base: const u8[:], r: const u8[:], out: u8[>..]&) {
    let b = uri_parts(base);
    let p = uri_parts(r);
    var path: u8[>..] = [];
    if p.scheme >= 0 {
        out.append(r[..p.scheme + 1]);
        if p.auth_from >= 0 { out.append("//"); out.append(r[p.auth_from..p.auth_to]); }
        remove_dots(r[p.path_from..p.path_to], out);
        if p.query_from >= 0 { out.push('?'); out.append(r[p.query_from..p.query_to]); }
    } else {
        if b.scheme >= 0 { out.append(base[..b.scheme + 1]); }
        if p.auth_from >= 0 {
            out.append("//"); out.append(r[p.auth_from..p.auth_to]);
            remove_dots(r[p.path_from..p.path_to], out);
            if p.query_from >= 0 { out.push('?'); out.append(r[p.query_from..p.query_to]); }
        } else {
            if b.auth_from >= 0 { out.append("//"); out.append(base[b.auth_from..b.auth_to]); }
            let rp = r[p.path_from..p.path_to];
            if rp.len == 0 {
                out.append(base[b.path_from..b.path_to]);
                if p.query_from >= 0 { out.push('?'); out.append(r[p.query_from..p.query_to]); }
                else if b.query_from >= 0 { out.push('?'); out.append(base[b.query_from..b.query_to]); }
            } else {
                if rp[0] == '/' { remove_dots(rp, out); }
                else {
                    merge_paths(base[b.path_from..b.path_to], b.auth_from >= 0, rp, path);
                    remove_dots(path, out);
                }
                if p.query_from >= 0 { out.push('?'); out.append(r[p.query_from..p.query_to]); }
            }
        }
    }
    if p.frag_from >= 0 { out.push('#'); out.append(r[p.frag_from..]); }
}

// --- canonicalization ---------------------------------------------------------------

fn attr_less(a: const AttrOut&, b: const AttrOut&) -> bool {
    let c = compare(a.ns, b.ns);
    if c != 0 { return c < 0; }
    return compare(a.local, b.local) < 0;
}

// Writes the start tag of el: its namespace declarations as the method
// renders them, and its attributes, sorted, with the xml: attributes and
// xml:base the subset's apex takes from its ancestors.
fn c14n_start(d: const Doc&, el: i64, apex: i64, m: const C14n&, depth: i64, r: Rendered[>..<]&,
              base_value: const u8[:], out: u8[>..]&) {
    out.push('<');
    let pre = prefix(d, el);
    if pre.len > 0 { out.append(pre); out.push(':'); }
    out.append(local_name(d, el));

    // Namespace declarations, collected then sorted by prefix.
    var decls: Rendered[>..<] = [];
    fn consider(p: const u8[:], uri: const u8[:]) {
        for x in decls { if x.prefix == p { return; } }
        let have, was = rendered(r, p);
        if p.len == 0 && uri.len == 0 {
            if was && have.len > 0 { decls.push(Rendered { prefix: p, uri: "", depth: depth }); }
            return;
        }
        if !was || have != uri { decls.push(Rendered { prefix: p, uri: uri, depth: depth }); }
    }
    if m.method == EXC_C14N {
        let eu, ebound = lookup_ns(d, el, pre);
        consider(pre, if ebound { eu } else { "" });
        each_attr(d, el) { a =>
            let ap = prefix(d, a);
            if ap.len > 0 && ap != "xml" {
                let au, ab = lookup_ns(d, el, ap);
                if ab { consider(ap, au); }
            }
        };
        each_word(m.inclusive[..]) {
            let p = if it == "#default" { "" } else { it };
            let iu, ib = lookup_ns(d, el, p);
            if ib || p.len == 0 { consider(p, if ib { iu } else { "" }); }
        };
    } else if el == apex || parent(d, el) == apex && kind(d, apex) == DOCUMENT {
        // The apex: every namespace in scope.
        each_in_scope(d, el) { decl, uri => consider(local_name(d, decl), uri); };
    } else {
        // Below it the parent is output too, and has written everything in
        // its scope, so only the element's own declarations can differ.
        var a = first_attr(d, el);
        while a >= 0 {
            if kind(d, a) == NAMESPACE { consider(local_name(d, a), value(d, a)); }
            a = next_sibling(d, a);
        }
    }
    sort(decls) { a, b => compare(a.prefix, b.prefix) < 0 };
    for x in decls {
        out.append(if x.prefix.len == 0 { " xmlns=\"" } else { " xmlns:" });
        if x.prefix.len > 0 { out.append(x.prefix); out.append("=\""); }
        escape_attr(out, x.uri);
        out.push('"');
        r.push(x);
    }

    // Attributes.
    var attrs: AttrOut[>..<] = [];
    each_attr(d, el) { a =>
        if !(el == apex && base_value.len > 0 && m.method == C14N_11 && ns_uri(d, a) == XML_NS && local_name(d, a) == "base") {
            attrs.push(AttrOut { ns: ns_uri(d, a), prefix: prefix(d, a), local: local_name(d, a), value: value(d, a) });
        }
    };
    if el == apex && m.method != EXC_C14N && parent(d, el) > 0 {
        // The xml: attributes of the ancestors left out, the nearest of each.
        var e = parent(d, el);
        while e > 0 {
            each_attr(d, e) { a =>
                if ns_uri(d, a) == XML_NS {
                    let l = local_name(d, a);
                    let inherit = if m.method == C14N_10 { true } else { l == "lang" || l == "space" };
                    var have = false;
                    for x in attrs { if x.ns == XML_NS && x.local == l { have = true; } }
                    if inherit && !have {
                        attrs.push(AttrOut { ns: XML_NS, prefix: "xml", local: l, value: value(d, a) });
                    }
                }
            };
            e = parent(d, e);
        }
    }
    if el == apex && base_value.len > 0 && m.method == C14N_11 {
        attrs.push(AttrOut { ns: XML_NS, prefix: "xml", local: "base", value: base_value });
    }
    sort(attrs) { a, b => attr_less(a, b) };
    for x in attrs {
        out.push(' ');
        if x.prefix.len > 0 { out.append(x.prefix); out.push(':'); }
        out.append(x.local);
        out.append("=\"");
        escape_attr(out, x.value);
        out.push('"');
    }
    out.push('>');
}

// The xml:base Canonical XML 1.1 gives the apex el: its own and its
// ancestors' joined, outermost first; empty when none has one.
fn joined_base(d: const Doc&, el: i64, out: u8[>..]&) {
    var chain: i64[>..<] = [];
    var e = el;
    while e > 0 {
        if attr_node(d, e, XML_NS, "base") >= 0 { chain.push(e); }
        e = parent(d, e);
    }
    if chain.len == 0 || (chain.len == 1 && chain[0] == el) { return; }
    var acc: u8[>..] = [];
    var i = chain.len - 1;
    while i >= 0 {
        let v, ok = attr(d, chain[i], XML_NS, "base");
        var next: u8[>..] = [];
        if acc.len == 0 { next.append(v); } else { join_uri(acc, v, next); }
        acc.clear();
        acc.append(next);
        i--;
    }
    out.append(acc);
}

// Canonicalizes the subtree of n (the document for 0) by m, appending the
// octets to out. False for a PrefixList that is not well formed.
fn canonicalize(d: const Doc&, n: i64, m: const C14n&, out: u8[>..]&) -> bool {
    if !prefix_list_ok(m.inclusive[..]) { return false; }
    var r:          Rendered[>..<] = [];
    var base_value: u8[>..]        = [];
    if m.method == C14N_11 && kind(d, n) == ELEMENT { joined_base(d, n, base_value); }
    var depth = 0;
    let whole = kind(d, n) == DOCUMENT;
    var after_root = false;
    fn end_tag(c: i64) {
        out.append("</");
        let pre = prefix(d, c);
        if pre.len > 0 { out.append(pre); out.push(':'); }
        out.append(local_name(d, c));
        out.push('>');
        depth--;
        while r.len > 0 && r[r.len - 1].depth >= depth { r.pop(); }
        if whole && parent(d, c) == 0 { after_root = true; }
    }
    walk(d, n) { c, entering =>
        let k = kind(d, c);
        var down = true;
        if c == m.exclude && c != n {
            down = false;
        } else if k == ELEMENT {
            if entering {
                c14n_start(d, c, n, m, depth, r, base_value, out);
                depth++;
                if first_child(d, c) < 0 { end_tag(c); }
            } else {
                end_tag(c);
            }
        } else if entering && k != DOCUMENT {
            let top = whole && parent(d, c) == 0;
            if k == TEXT || k == CDATA {
                escape_text(out, value(d, c));
            } else if k == PI || (k == COMMENT && m.comments) {
                if top && after_root { out.push('\n'); }
                if k == PI {
                    out.append("<?");
                    out.append(local_name(d, c));
                    let v = value(d, c);
                    if v.len > 0 { out.push(' '); out.append(v); }
                    out.append("?>");
                } else {
                    out.append("<!--");
                    out.append(value(d, c));
                    out.append("-->");
                }
                if top && !after_root { out.push('\n'); }
            }
        }
        down
    };
    return true;
}
