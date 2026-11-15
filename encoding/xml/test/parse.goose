// The parser, the document, the builder and the writer: well-formed
// documents and their nodes; every hostile input refused with its error
// (DOCTYPE and entities: XXE and billion laughs; deep nesting, many and
// huge attributes, long names, too many nodes; duplicate attributes, also
// under two prefixes of one namespace; duplicate IDs; namespace misuse;
// bad characters and UTF-8); line-end and attribute-value normalization;
// fragments; building documents and writing them back.
import std;
import gslib from "../../..";
import gslib.encoding.xml;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

// Parses text with o; the error code.
fn code_of(text: const u8[:], o: const xml::Options&) -> i64 {
    var d = xml::Doc { .. };
    let e = xml::parse(d, text, o);
    return e.code;
}

fn code(text: const u8[:]) -> i64 {
    let o = xml::options();
    return code_of(text, o);
}

fn refused(what: const u8[:], text: const u8[:], want: i64) {
    let got = code(text);
    check(str(what, " (", xml::error_name(want), ", got ", xml::error_name(got), ")"), got == want);
}

fn accepted(what: const u8[:], text: const u8[:]) {
    var d = xml::Doc { .. };
    let e = xml::parse(d, text);
    check(str(what, ": ", e.message), e.code == xml::OK);
}

// Parses and writes back.
fn round(text: const u8[:]) -> u8[>..] {
    var d = xml::Doc { .. };
    let e = xml::parse(d, text);
    var out: u8[>..] = [];
    if e.code != xml::OK { out.append(e.message); return out; }
    xml::write(d, 0, out);
    return out;
}

fn well_formed() {
    accepted("a root", "<a/>");
    accepted("declaration, comments, PIs", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<!-- c --><?p d?><a/><!-- e -->\n");
    accepted("a BOM", "\xEF\xBB\xBF<a/>");
    accepted("single quotes", "<?xml version='1.0' encoding='utf-8'?><a b='c\"'/>");
    accepted("non-ASCII names and text", "<\xC3\xA9l\xC3\xA9ment attr\xC3\xADbuto=\"\xE2\x82\xAC\">\xF0\x9F\x98\x80</\xC3\xA9l\xC3\xA9ment>");
    accepted("CDATA", "<a><![CDATA[<not> &markup;]]></a>");
    accepted("end tag with space", "<a></a  >");
    accepted("names with dots and dashes", "<a.b-c_d><e:f xmlns:e=\"urn:e\"/></a.b-c_d>");
    accepted("all predefined entities", "<a>&lt;&gt;&amp;&apos;&quot;</a>");
    accepted("character references", "<a>&#65;&#x42;&#x1F600;</a>");
    accepted("a prefix redeclared", "<p:a xmlns:p=\"urn:1\"><p:b xmlns:p=\"urn:2\"/></p:a>");
    accepted("xml prefix declared as itself", "<a xmlns:xml=\"http://www.w3.org/XML/1998/namespace\" xml:lang=\"en\"/>");
    accepted("default namespace undeclared", "<a xmlns=\"urn:a\"><b xmlns=\"\"/></a>");
    accepted("same local name, different namespaces", "<a xmlns:p=\"urn:1\" xmlns:q=\"urn:2\" p:x=\"1\" q:x=\"2\" x=\"3\"/>");

    var d = xml::Doc { .. };
    let e = xml::parse(d, "<?xml version=\"1.0\"?><r:root xmlns:r=\"urn:r\" xmlns=\"urn:d\" a=\"1\" r:b=\"2\" ID=\"x1\"><child>t&amp;t<![CDATA[c]]></child><!--k--><?pi da ta?><r:e/></r:root>");
    check("parse", e.code == xml::OK);
    let root = xml::root_element(d);
    check("root", xml::local_name(d, root) == "root" && xml::prefix(d, root) == "r" && xml::ns_uri(d, root) == "urn:r");
    let c = xml::first_element(d, root);
    check("default namespace of child", xml::local_name(d, c) == "child" && xml::ns_uri(d, c) == "urn:d" && xml::prefix(d, c) == "");
    var t: u8[>..] = [];
    xml::text_content(d, c, t);
    check("text content", t == "t&tc");
    let a, has_a = xml::attr(d, root, "a");
    check("unprefixed attribute has no namespace", has_a && a == "1");
    let b, has_b = xml::attr(d, root, "urn:r", "b");
    check("prefixed attribute", has_b && b == "2");
    let nb, has_nb = xml::attr(d, root, "b");
    check("prefixed attribute not found unprefixed", !has_nb);
    let e2 = xml::next_element(d, c);
    check("next element", xml::is(d, e2, "urn:r", "e") && xml::next_element(d, e2) < 0);
    check("child()", xml::child(d, root, "urn:r", "e") == e2 && xml::child(d, root, "urn:r", "none") < 0);
    let byid, n = xml::by_id(d, "x1");
    check("by_id", byid == root && n == 1);
    let none, n0 = xml::by_id(d, "x2");
    check("by_id missing", n0 == 0);
    let u, bound = xml::lookup_ns(d, e2, "r");
    check("lookup_ns", bound && u == "urn:r");
    let ux, boundx = xml::lookup_ns(d, e2, "nope");
    check("lookup_ns unbound", !boundx);
    var kinds: u8[>..] = [];
    var k = xml::first_child(d, root);
    while k >= 0 { kinds.push('0' + xml::kind(d, k)); k = xml::next_sibling(d, k); }
    check("child kinds: element, comment, PI, element", kinds == "2782");
    let pi = xml::next_sibling(d, xml::next_sibling(d, c));
    check("PI target and data", xml::local_name(d, pi) == "pi" && xml::value(d, pi) == "da ta");
}

fn hostile() {
    // DTDs: every DOCTYPE is refused by default.
    refused("DOCTYPE", "<!DOCTYPE a><a/>", xml::ERR_DOCTYPE);
    refused("billion laughs", "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>&lol1;</lolz>", xml::ERR_DOCTYPE);
    refused("XXE, external entity", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", xml::ERR_DOCTYPE);
    refused("external DTD", "<!DOCTYPE foo SYSTEM \"http://example.com/evil.dtd\"><foo/>", xml::ERR_DOCTYPE);
    refused("parameter entity", "<!DOCTYPE foo [<!ENTITY % pe SYSTEM \"http://example.com/x\"> %pe;]><foo/>", xml::ERR_DOCTYPE);
    refused("undeclared entity", "<a>&xxe;</a>", xml::ERR_ENTITY);
    refused("undeclared entity in an attribute", "<a b=\"&xxe;\"/>", xml::ERR_ENTITY);
    refused("entity without ;", "<a>&amp</a>", xml::ERR_SYNTAX);
    var o = xml::options();
    o.allow_doctype = true;
    check("allowed DOCTYPE without a subset", code_of("<!DOCTYPE a PUBLIC \"-//x//y\" \"a.dtd\"><a/>", o) == xml::OK);
    check("allowed DOCTYPE: internal subset still refused",
          code_of("<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>", o) == xml::ERR_DOCTYPE);
    check("allowed DOCTYPE: entities still undeclared", code_of("<!DOCTYPE a SYSTEM \"a.dtd\"><a>&x;</a>", o) == xml::ERR_ENTITY);
    check("DOCTYPE after the root", code_of("<a/><!DOCTYPE a>", o) == xml::ERR_SYNTAX);
    refused("other markup declaration", "<!ENTITY x \"y\"><a/>", xml::ERR_SYNTAX);

    // Limits.
    var deep: u8[>..] = [];
    for i in 300 { deep.append("<a>"); }
    for i in 300 { deep.append("</a>"); }
    refused("nesting deeper than max_depth", deep, xml::ERR_LIMIT);
    var deep_ok: u8[>..] = [];
    for i in 256 { deep_ok.append("<a>"); }
    for i in 256 { deep_ok.append("</a>"); }
    check("nesting at max_depth", code(deep_ok) == xml::OK);
    var unclosed: u8[>..] = [];
    for i in 100000 { unclosed.append("<a>"); }
    refused("a hundred thousand open elements", unclosed, xml::ERR_LIMIT);
    var many: u8[>..] = [];
    many.append("<a");
    for i in 65 { format(many, " a", i, "=\"x\""); }
    many.append("/>");
    refused("more attributes than max_attrs", many, xml::ERR_LIMIT);
    var big_attr: u8[>..] = [];
    big_attr.append("<a b=\"");
    for i in (16 << 20) / 8 { big_attr.append("xxxxxxxx"); }
    big_attr.append("\"/>");
    refused("an attribute over max_size", big_attr, xml::ERR_LIMIT);
    var small = xml::options();
    small.max_size = 100;
    check("max_size", code_of("<a>0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789</a>", small) == xml::ERR_LIMIT);
    var long_name: u8[>..] = [];
    long_name.push('<');
    for i in 1025 { long_name.push('n'); }
    long_name.append("/>");
    refused("a name over max_name", long_name, xml::ERR_LIMIT);
    var nsdeep: u8[>..] = [];
    for i in 9 {
        nsdeep.append("<a");
        for j in 30 { format(nsdeep, " xmlns:p", j, "=\"urn:", i, "\""); }
        nsdeep.push('>');
    }
    for i in 9 { nsdeep.append("</a>"); }
    refused("more namespaces in scope than max_namespaces", nsdeep, xml::ERR_LIMIT);
    var nodes = xml::options();
    nodes.max_nodes = 10;
    check("max_nodes", code_of("<a><b/><b/><b/><b/><b/><b/><b/><b/><b/><b/><b/></a>", nodes) == xml::ERR_LIMIT);

    // Attributes and IDs.
    refused("duplicate attribute", "<a b=\"1\" b=\"2\"/>", xml::ERR_DUP_ATTR);
    refused("one attribute under two prefixes of a namespace", "<a xmlns:p=\"urn:x\" xmlns:q=\"urn:x\" p:b=\"1\" q:b=\"2\"/>", xml::ERR_DUP_ATTR);
    refused("duplicate namespace declaration", "<a xmlns:p=\"urn:x\" xmlns:p=\"urn:y\"/>", xml::ERR_DUP_ATTR);
    refused("duplicate ID", "<a><b ID=\"x\"/><c ID=\"x\"/></a>", xml::ERR_DUP_ID);
    refused("duplicate ID, two attribute names", "<a><b ID=\"x\"/><c Id=\"x\"/></a>", xml::ERR_DUP_ID);
    refused("duplicate xml:id", "<a xml:id=\"x\"><b ID=\"x\"/></a>", xml::ERR_DUP_ID);
    accepted("same value, not an ID attribute", "<a><b ref=\"x\"/><c ref=\"x\"/><d ID=\"x\"/></a>");
    accepted("prefixed ID is not an ID", "<a xmlns:p=\"urn:p\"><b p:ID=\"x\"/><c ID=\"x\"/></a>");
    var noids = xml::options();
    noids.unique_ids = false;
    check("unique_ids off", code_of("<a><b ID=\"x\"/><c ID=\"x\"/></a>", noids) == xml::OK);
    var d = xml::Doc { .. };
    xml::parse(d, "<a><b ID=\"x\"/><c ID=\"x\"/></a>", noids);
    let el, n = xml::by_id(d, "x");
    check("by_id counts duplicates", n == 2);

    // Namespaces.
    refused("unbound element prefix", "<p:a/>", xml::ERR_NAMESPACE);
    refused("unbound attribute prefix", "<a p:b=\"1\"/>", xml::ERR_NAMESPACE);
    refused("prefix undeclared (NS 1.0)", "<a xmlns:p=\"\"/>", xml::ERR_NAMESPACE);
    refused("xmlns declared", "<a xmlns:xmlns=\"urn:x\"/>", xml::ERR_NAMESPACE);
    refused("xml bound elsewhere", "<a xmlns:xml=\"urn:x\"/>", xml::ERR_NAMESPACE);
    refused("the XML namespace bound to another prefix", "<a xmlns:p=\"http://www.w3.org/XML/1998/namespace\"/>", xml::ERR_NAMESPACE);
    refused("the xmlns namespace as default", "<a xmlns=\"http://www.w3.org/2000/xmlns/\"/>", xml::ERR_NAMESPACE);
    refused("element prefix xmlns", "<xmlns:a xmlns:xmlns=\"urn:x\"/>", xml::ERR_NAMESPACE);
    refused("two colons", "<a:b:c xmlns:a=\"urn:a\"/>", xml::ERR_NAMESPACE);
    refused("colon at the end", "<a: xmlns:a=\"urn:a\"/>", xml::ERR_NAMESPACE);
    refused("prefix out of scope", "<a><b xmlns:p=\"urn:p\"/><p:c/></a>", xml::ERR_NAMESPACE);
    refused("colon in a PI target", "<a><?p:i x?></a>", xml::ERR_NAMESPACE);

    // Characters and encodings.
    refused("UTF-16 BOM", "\xFF\xFE<\x00a\x00/\x00>\x00", xml::ERR_ENCODING);
    refused("other encoding declared", "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>", xml::ERR_ENCODING);
    refused("XML 1.1", "<?xml version=\"1.1\"?><a/>", xml::ERR_SYNTAX);
    refused("bad UTF-8", "<a>\xC3\x28</a>", xml::ERR_CHAR);
    refused("overlong UTF-8", "<a>\xC0\xAF</a>", xml::ERR_CHAR);
    refused("UTF-8 surrogate", "<a>\xED\xA0\x80</a>", xml::ERR_CHAR);
    refused("UTF-8 past U+10FFFF", "<a>\xF4\x90\x80\x80</a>", xml::ERR_CHAR);
    refused("cut-short UTF-8", "<a>\xE2\x82</a>", xml::ERR_CHAR);
    refused("control character", "<a>\x01</a>", xml::ERR_CHAR);
    refused("NUL", "<a>\x00</a>", xml::ERR_CHAR);
    refused("U+FFFE", "<a>\xEF\xBF\xBE</a>", xml::ERR_CHAR);
    refused("&#0;", "<a>&#0;</a>", xml::ERR_CHAR);
    refused("&#x1;", "<a>&#x1;</a>", xml::ERR_CHAR);
    refused("&#xD800;", "<a>&#xD800;</a>", xml::ERR_CHAR);
    refused("character reference past U+10FFFF", "<a>&#x110000;</a>", xml::ERR_CHAR);
    refused("huge character reference", "<a>&#99999999999999999999999;</a>", xml::ERR_CHAR);
    refused("bad decimal reference", "<a>&#1a;</a>", xml::ERR_SYNTAX);
    refused("empty reference", "<a>&#;</a>", xml::ERR_SYNTAX);
    refused("control character in an attribute", "<a b=\"\x1F\"/>", xml::ERR_CHAR);
    refused("bad UTF-8 in a name", "<a\xFF/>", xml::ERR_CHAR);

    // Structure.
    refused("empty", "", xml::ERR_SYNTAX);
    refused("only a declaration", "<?xml version=\"1.0\"?>", xml::ERR_SYNTAX);
    refused("two roots", "<a/><b/>", xml::ERR_SYNTAX);
    refused("text before the root", "x<a/>", xml::ERR_SYNTAX);
    refused("text after the root", "<a/>x", xml::ERR_SYNTAX);
    refused("reference outside the root", "<a/>&amp;", xml::ERR_SYNTAX);
    refused("CDATA outside the root", "<![CDATA[x]]><a/>", xml::ERR_SYNTAX);
    refused("mismatched end tag", "<a><b></a></b>", xml::ERR_TAG);
    refused("end tag of another prefix", "<p:a xmlns:p=\"urn:p\" xmlns:q=\"urn:p\"></q:a>", xml::ERR_TAG);
    refused("unclosed", "<a><b>", xml::ERR_TAG);
    refused("stray end tag", "</a>", xml::ERR_TAG);
    refused("]]> in text", "<a>]]></a>", xml::ERR_SYNTAX);
    refused("-- in a comment", "<a><!-- a -- b --></a>", xml::ERR_SYNTAX);
    refused("comment ending in -", "<a><!-- a ---></a>", xml::ERR_SYNTAX);
    refused("unclosed comment", "<a><!-- a </a>", xml::ERR_SYNTAX);
    refused("unclosed CDATA", "<a><![CDATA[ </a>", xml::ERR_SYNTAX);
    refused("PI named xml", "<a><?xml version=\"1.0\"?></a>", xml::ERR_SYNTAX);
    refused("PI named XmL", "<a><?XmL x?></a>", xml::ERR_SYNTAX);
    refused("declaration not first", " <?xml version=\"1.0\"?><a/>", xml::ERR_SYNTAX);
    refused("declaration without version", "<?xml encoding=\"UTF-8\"?><a/>", xml::ERR_SYNTAX);
    refused("declaration out of order", "<?xml encoding=\"UTF-8\" version=\"1.0\"?><a/>", xml::ERR_SYNTAX);
    refused("bad standalone", "<?xml version=\"1.0\" standalone=\"maybe\"?><a/>", xml::ERR_SYNTAX);
    refused("< in an attribute", "<a b=\"<\"/>", xml::ERR_SYNTAX);
    refused("unquoted attribute", "<a b=c/>", xml::ERR_SYNTAX);
    refused("attribute without a value", "<a b/>", xml::ERR_SYNTAX);
    refused("attributes without space", "<a b=\"1\"c=\"2\"/>", xml::ERR_SYNTAX);
    refused("unclosed attribute value", "<a b=\"1/>", xml::ERR_SYNTAX);
    refused("bad name start", "<1a/>", xml::ERR_SYNTAX);
    refused("unclosed start tag", "<a", xml::ERR_SYNTAX);
    refused("space before the name", "< a/>", xml::ERR_SYNTAX);

    // Errors say where.
    var de = xml::Doc { .. };
    let err = xml::parse(de, "<a>\n  <b>\n</a>");
    check(str("error position: ", err.message), err.code == xml::ERR_TAG && err.line == 3 && err.column == 1);
}

fn normalization() {
    check("CRLF and CR in text", round("<a>1\r\n2\r3\n4</a>") == "<a>1\n2\n3\n4</a>");
    check("CRLF in an attribute", round("<a b=\"1\r\n2\"/>") == "<a b=\"1 2\"/>");
    check("tab and newline in an attribute", round("<a b=\"1\t2\n3\"/>") == "<a b=\"1 2 3\"/>");
    check("character references kept in an attribute", round("<a b=\"1&#9;2&#10;3&#13;4\"/>") == "<a b=\"1&#x9;2&#xA;3&#xD;4\"/>");
    check("CR by reference in text", round("<a>x&#13;y</a>") == "<a>x&#xD;y</a>");
    check("CDATA kept", round("<a><![CDATA[<x>]]></a>") == "<a><![CDATA[<x>]]></a>");
    check("CRLF in a comment", round("<a><!--1\r\n2--></a>") == "<a><!--1\n2--></a>");
    check("escaping", round("<a b=\"&quot;&lt;&amp;&gt;'\">&lt;&gt;&amp;\"'</a>") == "<a b=\"&quot;&lt;&amp;>'\">&lt;&gt;&amp;\"'</a>");
    check("top-level nodes on their own lines", round("<?xml version=\"1.0\"?>\n\n<!--a-->\n\n<r/>\n\n<?p?>") == "<!--a-->\n<r/>\n<?p?>");
}

fn building() {
    var d = xml::Doc { .. };
    xml::new_document(d);
    let root = xml::element(d, 0, "samlp", "Response", "urn:oasis:names:tc:SAML:2.0:protocol");
    check("element", root > 0);
    check("ID", xml::set_attr(d, root, "ID", "_r1"));
    let issuer = xml::element(d, root, "saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
    xml::text(d, issuer, "https://idp.example.com & co <x>");
    let st = xml::element(d, root, "samlp", "Status", "urn:oasis:names:tc:SAML:2.0:protocol");
    let dflt = xml::element(d, root, "", "Extra", "urn:x");
    let plain = xml::element(d, dflt, "", "Plain", "");
    check("namespaced attribute", xml::set_attr(d, plain, "q", "a", "urn:q", "v\t1"));
    check("replace an attribute", xml::set_attr(d, root, "ID", "_r2"));
    check("bad element name", xml::element(d, root, "", "1bad", "") < 0);
    check("prefix without namespace", xml::element(d, root, "p", "x", "") < 0);
    check("bad text", xml::text(d, root, "\x01") < 0);
    check("bad comment", xml::comment(d, root, "a--b") < 0);
    check("bad PI", xml::pi(d, root, "xml", "x") < 0);
    check("bad attribute value", !xml::set_attr(d, root, "x", "\xFF"));
    check("xmlns attribute refused", !xml::set_attr(d, root, "xmlns", "x", "urn:z", "1"));
    var out: u8[>..] = [];
    xml::write(d, 0, out);
    check(str("written: ", out), out == "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_r2\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://idp.example.com &amp; co &lt;x&gt;</saml:Issuer><samlp:Status/><Extra xmlns=\"urn:x\"><Plain xmlns=\"\" xmlns:q=\"urn:q\" q:a=\"v&#x9;1\"/></Extra></samlp:Response>");
    // It parses back to the same.
    var d2 = xml::Doc { .. };
    let e = xml::parse(d2, out);
    var out2: u8[>..] = [];
    xml::write(d2, 0, out2);
    check("written document parses back the same", e.code == xml::OK && out2 == out);
    let byid, n = xml::by_id(d2, "_r2");
    check("ID after a round trip", n == 1 && byid == xml::root_element(d2));

    // A subtree written alone declares what it inherits.
    var sub: u8[>..] = [];
    xml::write(d, plain, sub);
    check(str("subtree: ", sub), sub == "<Plain xmlns=\"\" xmlns:q=\"urn:q\" q:a=\"v&#x9;1\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>");
    var sub2: u8[>..] = [];
    xml::write(d, st, sub2);
    check(str("subtree with inherited prefix: ", sub2), sub2 == "<samlp:Status xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>");

    // Detach, move, set_text.
    xml::detach(d, st);
    check("detached", xml::next_element(d, issuer) == dflt && !xml::attached(d, st));
    xml::move_to(d, st, root, issuer);
    check("moved before Issuer", xml::first_element(d, root) == st);
    xml::set_text(d, issuer, "new");
    var t: u8[>..] = [];
    xml::text_content(d, issuer, t);
    check("set_text", t == "new");
}

fn fragments() {
    var d = xml::Doc { .. };
    xml::parse(d, "<r xmlns:p=\"urn:p\" xmlns=\"urn:d\"><a ID=\"one\"/><b/></r>");
    let root = xml::root_element(d);
    let b = xml::child(d, root, "urn:d", "b");
    let e = xml::parse_fragment(d, root, b, "<p:x>t</p:x>text<y/>");
    check(str("fragment: ", e.message), e.code == xml::OK);
    var out: u8[>..] = [];
    xml::write(d, 0, out);
    check(str("fragment in place: ", out), out == "<r xmlns:p=\"urn:p\" xmlns=\"urn:d\"><a ID=\"one\"/><p:x>t</p:x>text<y/><b/></r>");
    let y = xml::child(d, root, "urn:d", "y");
    check("fragment's default namespace from the parent", y > 0);
    let dup = xml::parse_fragment(d, root, -1, "<c ID=\"one\"/>");
    check("fragment repeating an ID", dup.code == xml::ERR_DUP_ID);
    let unbound = xml::parse_fragment(d, root, -1, "<q:c/>");
    check("fragment with an unbound prefix", unbound.code == xml::ERR_NAMESPACE);
    let bad = xml::parse_fragment(d, root, -1, "<c><d></c>");
    check("bad fragment", bad.code == xml::ERR_TAG);
    let dt = xml::parse_fragment(d, root, -1, "<!DOCTYPE x><c/>");
    check("DOCTYPE in a fragment", dt.code == xml::ERR_SYNTAX || dt.code == xml::ERR_DOCTYPE);
    var out2: u8[>..] = [];
    xml::write(d, 0, out2);
    check("failed fragments link nothing", out2 == out);
}

// The review's: DOCTYPE literals by character, US-ASCII declared and
// kept, namespace URIs with white space, and a builder that cannot write
// what parses back to another namespace.
fn review_fixes() {
    var o = xml::options();
    o.allow_doctype = true;
    check("DOCTYPE SYSTEM literal with a two-byte character", code_of("<!DOCTYPE a SYSTEM \"\xc3\xa9\"><a/>", o) == xml::OK);
    check("  PUBLIC with a three-byte one", code_of("<!DOCTYPE a PUBLIC \"\xe2\x82\xac\" \"x\"><a/>", o) == xml::OK);
    check("  a bad byte in it still refused", code_of("<!DOCTYPE a SYSTEM \"\xc3\"><a/>", o) == xml::ERR_CHAR);
    refused("US-ASCII declared, a UTF-8 byte in it", "<?xml version=\"1.0\" encoding=\"us-ascii\"?><a>\xc3\xa9</a>", xml::ERR_ENCODING);
    refused("  ascii, in an attribute", "<?xml version=\"1.0\" encoding=\"ASCII\"?><a b=\"\xc3\xa9\"/>", xml::ERR_ENCODING);
    accepted("  US-ASCII that is", "<?xml version=\"1.0\" encoding=\"US-ASCII\"?><a>e</a>");
    accepted("  UTF-8 declared, non-ASCII", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a>\xc3\xa9</a>");
    refused("a prefix bound to a space", "<a xmlns:p=\" \"/>", xml::ERR_NAMESPACE);
    refused("the default namespace a space", "<a xmlns=\" \"/>", xml::ERR_NAMESPACE);
    refused("a namespace URI with a space in it", "<a xmlns:p=\"urn:a b\"/>", xml::ERR_NAMESPACE);
    refused("  a tab, as a reference", "<a xmlns=\"urn:a&#9;\"/>", xml::ERR_NAMESPACE);
    accepted("  xmlns=\"\" still undeclares", "<a xmlns=\"urn:a\"><b xmlns=\"\"/></a>");

    // Builder: an unprefixed xmlns attribute would declare a namespace.
    var d = xml::Doc { .. };
    xml::new_document(d);
    let root = xml::element(d, 0, "", "a", "urn:a");
    let ch = xml::element(d, root, "", "b", "urn:a");
    check("set_attr xmlns refused", !xml::set_attr(d, ch, "xmlns", "urn:evil"));
    check("set_attr xmlns, the long form", !xml::set_attr(d, ch, "", "xmlns", "", "urn:evil"));
    check("an element in a namespace with a space", xml::element(d, root, "", "c", "urn:a b") < 0);
    check("declare_ns of a URI with a space", !xml::declare_ns(d, root, "q", "urn:a b"));
    // A prefix the element, an attribute or a descendant uses: not rebound.
    var d3 = xml::Doc { .. };
    xml::new_document(d3);
    let r3 = xml::element(d3, 0, "p", "a", "urn:one");
    check("set_attr p:x in another namespace than the element's p", !xml::set_attr(d3, r3, "p", "x", "urn:two", "v"));
    check("  in its own", xml::set_attr(d3, r3, "p", "x", "urn:one", "v"));
    check("declare_ns rebinding the element's prefix", !xml::declare_ns(d3, r3, "p", "urn:two"));
    check("  the same binding again", xml::declare_ns(d3, r3, "p", "urn:one"));
    let k3 = xml::element(d3, r3, "", "k", "");
    check("  a default namespace over an element in none", !xml::declare_ns(d3, r3, "", "urn:d"));
    let c3 = xml::element(d3, k3, "q", "c", "urn:q");
    check("  a descendant's prefix", !xml::declare_ns(d3, r3, "q", "urn:other"));
    let l3 = xml::element(d3, r3, "", "l", "");
    check("  an attribute's prefix on a descendant", xml::set_attr(d3, l3, "s", "y", "urn:s", "1") && !xml::declare_ns(d3, r3, "s", "urn:t"));
    check("  a prefix nobody uses", xml::declare_ns(d3, r3, "z", "urn:z"));
    var out3: u8[>..] = [];
    xml::write(d3, 0, out3);
    var d4 = xml::Doc { .. };
    let pe = xml::parse(d4, out3);
    let r4 = xml::root_element(d4);
    check(str("what was built parses back the same: ", out3), pe.code == xml::OK && xml::ns_uri(d4, r4) == "urn:one" &&
          xml::ns_uri(d4, xml::first_element(d4, xml::first_element(d4, r4))) == "urn:q");

    // move_to under a scope that binds p (and the default) otherwise: the
    // moved element declares what its names need, so they keep their
    // namespaces when written and parsed back.
    var d5 = xml::Doc { .. };
    xml::parse(d5, "<r xmlns:p=\"urn:one\"><p:a p:x=\"1\"><p:b/><c/><p:e xmlns:p=\"urn:own\"/></p:a><s xmlns:p=\"urn:two\" xmlns=\"urn:d\"/></r>");
    let r5 = xml::root_element(d5);
    let a5 = xml::first_element(d5, r5);
    let s5 = xml::next_element(d5, a5);
    check("move_to under a rebinding scope", xml::move_to(d5, a5, s5, -1));
    var out5: u8[>..] = [];
    xml::write(d5, 0, out5);
    check(str("  written: ", out5), out5 == "<r xmlns:p=\"urn:one\"><s xmlns:p=\"urn:two\" xmlns=\"urn:d\"><p:a p:x=\"1\" xmlns:p=\"urn:one\" xmlns=\"\"><p:b/><c/><p:e xmlns:p=\"urn:own\"/></p:a></s></r>");
    var d6 = xml::Doc { .. };
    let pe6 = xml::parse(d6, out5);
    let a6 = xml::first_element(d6, xml::first_element(d6, xml::root_element(d6)));
    let b6 = xml::first_element(d6, a6);
    let c6 = xml::next_element(d6, b6);
    let e6 = xml::next_element(d6, c6);
    let x6, hx6 = xml::attr(d6, a6, "urn:one", "x");
    check("  parses back with the namespaces it had", pe6.code == xml::OK && xml::ns_uri(d6, a6) == "urn:one" && hx6 &&
          xml::ns_uri(d6, b6) == "urn:one" && xml::ns_uri(d6, c6) == "" && xml::ns_uri(d6, e6) == "urn:own");
    // Moved where the scope already binds the same: nothing declared.
    var d7 = xml::Doc { .. };
    xml::parse(d7, "<r xmlns:p=\"urn:one\"><p:a/><p:s/></r>");
    let a7 = xml::first_element(d7, xml::root_element(d7));
    check("move_to under the same binding", xml::move_to(d7, a7, xml::next_element(d7, a7), -1));
    var out7: u8[>..] = [];
    xml::write(d7, 0, out7);
    check(str("  declares nothing: ", out7), out7 == "<r xmlns:p=\"urn:one\"><p:s><p:a/></p:s></r>");
}

fn main() {
    well_formed();
    review_fixes();
    hostile();
    normalization();
    building();
    fragments();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
