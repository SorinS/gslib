// Canonicalization against the W3C's examples: Canonical XML 1.0 §3
// (those that need no DTD, and the DTD ones with the DTD left out),
// Exclusive XML Canonicalization §2.2, Canonical XML 1.1's xml:base
// fix-up; subsets of an element, an excluded subtree, InclusiveNamespaces,
// the default namespace undeclared, and RFC 3986 §5.4's reference
// resolution examples for the xml:base join.
import std;
import gslib from "../../..";
import gslib.encoding.xml;
import gslib.encoding.xml.c14n;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

// The canonical form of text's document (id empty) or of its element with
// that ID, by method, comments, the PrefixList.
fn canon(text: const u8[:], method: i64, comments: bool, id: const u8[:], prefixes: const u8[:]) -> u8[>..] {
    var d = xml::Doc { .. };
    var out: u8[>..] = [];
    let e = xml::parse(d, text);
    if e.code != xml::OK { out.append(e.message); return out; }
    var m = xml::C14n { .. };
    m.method = method;
    m.comments = comments;
    format(m.inclusive, prefixes);
    var n = 0;
    if id.len > 0 {
        let el, count = xml::by_id(d, id);
        if count != 1 { out.append("no such ID"); return out; }
        n = el;
    }
    if !xml::canonicalize(d, n, m, out) { out.append("refused"); }
    return out;
}

fn expect(what: const u8[:], got: const u8[:], want: const u8[:]) {
    check(str(what, "\n--- got:\n", got, "\n--- want:\n", want), got == want);
}

let EX31 = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->";

let EX32 = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";

let EX33 = "<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>";

let EX33_OUT = "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6 xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9 xmlns:a=\"http://www.ietf.org\"></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>";

let EX34 = "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>";

let EX34_OUT = "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>";

// Exclusive XML Canonicalization §2.2, with IDs to select elem2.
let EXC1 = "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\">\n  <n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\" ID=\"e2\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n  </n1:elem2>\n</n0:local>";
let EXC2 = "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\">\n  <n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\" ID=\"e2\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n  </n1:elem2>\n</n2:pdu>";

// Canonical XML 1.1 §3.2.? (xml:base): the document of the xml:base
// fix-up example, with IDs.
let BASE = "<ietf:c14n11XmlBaseDoc1 xmlns:ietf=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"http://xmlbase.example.org/xmlbase0/\">\n   <ietf:e1 xml:base=\"/xmlbase1/\">\n      <ietf:e11 xml:base=\"/xmlbase11/\" ID=\"e11\">\n         <ietf:e111 xml:base=\"/xmlbase111/\"/>\n      </ietf:e11>\n      <ietf:e12 at=\"2\" ID=\"e12\">\n         <ietf:e121 xml:base=\"/xmlbase121/\"/>\n      </ietf:e12>\n   </ietf:e1>\n   <ietf:e2 >\n      <ietf:e21 xml:base=\"/xmlbase21/\"/>\n   </ietf:e2>\n   <ietf:e3 xml:base=\"../xmlbase3\" ID=\"e3\">\n      <ietf:e31 xml:base=\"../xmlbase31\" ID=\"e31\" xml:id=\"x31\" xml:lang=\"de\"/>\n   </ietf:e3>\n</ietf:c14n11XmlBaseDoc1>";

fn w3c() {
    expect("3.1 with comments", canon(EX31, xml::C14N_10, true, "", ""),
           "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->");
    expect("3.1 without comments", canon(EX31, xml::C14N_10, false, "", ""),
           "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>");
    expect("3.1, 1.1 the same", canon(EX31, xml::C14N_11, true, "", ""), canon(EX31, xml::C14N_10, true, "", ""));
    expect("3.1, exclusive the same", canon(EX31, xml::EXC_C14N, false, "", ""), canon(EX31, xml::C14N_10, false, "", ""));
    expect("3.2 white space", canon(EX32, xml::C14N_10, false, "", ""), EX32);
    expect("3.3 start and end tags", canon(EX33, xml::C14N_10, false, "", ""), EX33_OUT);
    expect("3.4 character modifications", canon(EX34, xml::C14N_10, false, "", ""), EX34_OUT);
    expect("3.6 UTF-8", canon("<doc>&#169;</doc>", xml::C14N_10, false, "", ""), "<doc>\xC2\xA9</doc>");

    expect("exc §2.2 first, inclusive", canon(EXC1, xml::C14N_10, false, "e2", ""),
           "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\" xmlns:n3=\"ftp://example.org\" ID=\"e2\" xml:lang=\"en\">\n    <n3:stuff></n3:stuff>\n  </n1:elem2>");
    expect("exc §2.2 second, inclusive", canon(EXC2, xml::C14N_10, false, "e2", ""),
           "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\" ID=\"e2\" xml:lang=\"en\" xml:space=\"retain\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>");
    let exc_out = "<n1:elem2 xmlns:n1=\"http://example.net\" ID=\"e2\" xml:lang=\"en\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>";
    expect("exc §2.2 first, exclusive", canon(EXC1, xml::EXC_C14N, false, "e2", ""), exc_out);
    expect("exc §2.2 second, exclusive", canon(EXC2, xml::EXC_C14N, false, "e2", ""), exc_out);
    expect("exclusive with n0 in the PrefixList", canon(EXC1, xml::EXC_C14N, false, "e2", "n0"),
           "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\" ID=\"e2\" xml:lang=\"en\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>");
    expect("exclusive with n3 in the PrefixList", canon(EXC1, xml::EXC_C14N, false, "e2", "n3 n9"),
           "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n3=\"ftp://example.org\" ID=\"e2\" xml:lang=\"en\">\n    <n3:stuff></n3:stuff>\n  </n1:elem2>");
    expect("a bad PrefixList", canon(EXC1, xml::EXC_C14N, false, "e2", "1bad"), "refused");

    // xml:base: 1.0 inherits the nearest, 1.1 joins them.
    expect("1.1 xml:base of e11", canon(BASE, xml::C14N_11, false, "e11", ""),
           "<ietf:e11 xmlns:ietf=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" ID=\"e11\" xml:base=\"http://xmlbase.example.org/xmlbase11/\">\n         <ietf:e111 xml:base=\"/xmlbase111/\"></ietf:e111>\n      </ietf:e11>");
    expect("1.1 xml:base of e12", canon(BASE, xml::C14N_11, false, "e12", ""),
           "<ietf:e12 xmlns:ietf=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" ID=\"e12\" at=\"2\" xml:base=\"http://xmlbase.example.org/xmlbase1/\">\n         <ietf:e121 xml:base=\"/xmlbase121/\"></ietf:e121>\n      </ietf:e12>");
    expect("1.0 xml:base of e12, inherited", canon(BASE, xml::C14N_10, false, "e12", ""),
           "<ietf:e12 xmlns:ietf=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" ID=\"e12\" at=\"2\" xml:base=\"/xmlbase1/\">\n         <ietf:e121 xml:base=\"/xmlbase121/\"></ietf:e121>\n      </ietf:e12>");
    expect("1.1 xml:base of e3", canon(BASE, xml::C14N_11, false, "e3", ""),
           "<ietf:e3 xmlns:ietf=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" ID=\"e3\" xml:base=\"http://xmlbase.example.org/xmlbase3\">\n      <ietf:e31 ID=\"e31\" xml:base=\"../xmlbase31\" xml:id=\"x31\" xml:lang=\"de\"></ietf:e31>\n   </ietf:e3>");
    expect("1.1 xml:base of e31", canon(BASE, xml::C14N_11, false, "e31", ""),
           "<ietf:e31 xmlns:ietf=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" ID=\"e31\" xml:base=\"http://xmlbase.example.org/xmlbase31\" xml:id=\"x31\" xml:lang=\"de\"></ietf:e31>");
    expect("exclusive: no xml:base fix-up", canon(BASE, xml::EXC_C14N, false, "e12", ""),
           "<ietf:e12 xmlns:ietf=\"http://www.ietf.org\" ID=\"e12\" at=\"2\">\n         <ietf:e121 xml:base=\"/xmlbase121/\"></ietf:e121>\n      </ietf:e12>");
    // xml:id is not inherited by 1.1, xml:lang and xml:space are; 1.0 takes all.
    let LANG = "<a xml:lang=\"en\" xml:space=\"preserve\" xml:id=\"top\" xml:foo=\"bar\"><b ID=\"b\"/></a>";
    expect("1.1 inherits xml:lang and xml:space", canon(LANG, xml::C14N_11, false, "b", ""),
           "<b ID=\"b\" xml:lang=\"en\" xml:space=\"preserve\"></b>");
    expect("1.0 inherits every xml: attribute", canon(LANG, xml::C14N_10, false, "b", ""),
           "<b ID=\"b\" xml:foo=\"bar\" xml:id=\"top\" xml:lang=\"en\" xml:space=\"preserve\"></b>");
    expect("its own xml:lang wins", canon("<a xml:lang=\"en\"><b ID=\"b\" xml:lang=\"fr\"/></a>", xml::C14N_10, false, "b", ""),
           "<b ID=\"b\" xml:lang=\"fr\"></b>");
}

fn namespaces() {
    let U = "<a xmlns=\"urn:a\"><b xmlns=\"\" ID=\"b\"><c/></b><d xmlns=\"urn:a\"/></a>";
    expect("default undeclared, whole", canon(U, xml::C14N_10, false, "", ""), "<a xmlns=\"urn:a\"><b xmlns=\"\" ID=\"b\"><c></c></b><d></d></a>");
    expect("default undeclared, subset", canon(U, xml::C14N_10, false, "b", ""), "<b ID=\"b\"><c></c></b>");
    expect("default undeclared, exclusive", canon(U, xml::EXC_C14N, false, "", ""), "<a xmlns=\"urn:a\"><b xmlns=\"\" ID=\"b\"><c></c></b><d></d></a>");
    expect("default undeclared, exclusive subset", canon(U, xml::EXC_C14N, false, "b", ""), "<b ID=\"b\"><c></c></b>");
    let P = "<p:a xmlns:p=\"urn:p\" xmlns:q=\"urn:q\" xmlns:r=\"urn:r\"><p:b q:x=\"1\" ID=\"b\"><r:c/><p:d/></p:b></p:a>";
    expect("exclusive: prefixes visibly used", canon(P, xml::EXC_C14N, false, "b", ""),
           "<p:b xmlns:p=\"urn:p\" xmlns:q=\"urn:q\" ID=\"b\" q:x=\"1\"><r:c xmlns:r=\"urn:r\"></r:c><p:d></p:d></p:b>");
    expect("inclusive: every namespace in scope", canon(P, xml::C14N_10, false, "b", ""),
           "<p:b xmlns:p=\"urn:p\" xmlns:q=\"urn:q\" xmlns:r=\"urn:r\" ID=\"b\" q:x=\"1\"><r:c></r:c><p:d></p:d></p:b>");
    expect("exclusive: #default in the PrefixList", canon("<a xmlns=\"urn:d\" xmlns:p=\"urn:p\"><p:b ID=\"b\"/></a>", xml::EXC_C14N, false, "b", "#default"),
           "<p:b xmlns=\"urn:d\" xmlns:p=\"urn:p\" ID=\"b\"></p:b>");
    expect("redeclared to the same is dropped", canon("<p:a xmlns:p=\"urn:p\"><p:b xmlns:p=\"urn:p\"/></p:a>", xml::C14N_10, false, "", ""),
           "<p:a xmlns:p=\"urn:p\"><p:b></p:b></p:a>");
    expect("redeclared to another is kept", canon("<p:a xmlns:p=\"urn:p\"><p:b xmlns:p=\"urn:q\"/></p:a>", xml::EXC_C14N, false, "", ""),
           "<p:a xmlns:p=\"urn:p\"><p:b xmlns:p=\"urn:q\"></p:b></p:a>");
    expect("attributes sorted by namespace, then name", canon("<a xmlns:z=\"urn:a\" xmlns:y=\"urn:b\" b=\"1\" a=\"2\" y:a=\"3\" z:b=\"4\" z:a=\"5\"/>", xml::C14N_10, false, "", ""),
           "<a xmlns:y=\"urn:b\" xmlns:z=\"urn:a\" a=\"2\" b=\"1\" z:a=\"5\" z:b=\"4\" y:a=\"3\"></a>");
    expect("exclusive: a sibling's declaration repeated", canon("<a><p:b xmlns:p=\"urn:p\"/><p:c xmlns:p=\"urn:p\"/></a>", xml::EXC_C14N, false, "", ""),
           "<a><p:b xmlns:p=\"urn:p\"></p:b><p:c xmlns:p=\"urn:p\"></p:c></a>");
    expect("exclusive: unused declarations dropped", canon("<a xmlns:p=\"urn:p\"><b xmlns:q=\"urn:q\"/></a>", xml::EXC_C14N, false, "", ""),
           "<a><b></b></a>");
}

fn subsets() {
    var d = xml::Doc { .. };
    xml::parse(d, "<r xmlns=\"urn:r\"><a ID=\"a\">x<!--c--><s>signature<t/></s>y</a></r>");
    let a, n = xml::by_id(d, "a");
    let s = xml::child(d, a, "urn:r", "s");
    var m = xml::C14n { method: xml::EXC_C14N, comments: true, exclude: s, .. };
    var out: u8[>..] = [];
    xml::canonicalize(d, a, m, out);
    expect("a subtree excluded", out, "<a xmlns=\"urn:r\" ID=\"a\">x<!--c-->y</a>");
    var whole: u8[>..] = [];
    m.comments = false;
    xml::canonicalize(d, 0, m, whole);
    expect("excluded within the whole document, no comments", whole, "<r xmlns=\"urn:r\"><a ID=\"a\">xy</a></r>");
    var selfx: u8[>..] = [];
    m.exclude = a;
    xml::canonicalize(d, a, m, selfx);
    expect("excluding the apex itself does nothing", selfx, "<a xmlns=\"urn:r\" ID=\"a\">x<s>signature<t></t></s>y</a>");
    var d2 = xml::Doc { .. };
    xml::parse(d2, "<a>&#xD;&#x9;\t<![CDATA[&<>]]>\"'</a>");
    var o2: u8[>..] = [];
    let m2 = xml::C14n { .. };
    xml::canonicalize(d2, 0, m2, o2);
    expect("text escaping, CDATA as text", o2, "<a>&#xD;\t\t&amp;&lt;&gt;\"'</a>");
}

// Many namespaces in scope and many elements under them: canonical forms
// in linear time (each element below the apex looks at its own
// declarations only), the same by every method.
fn wide() {
    var text: u8[>..] = [];
    text.append("<r");
    for j in 200 { format(text, " xmlns:p", j, "=\"urn:", j, "\""); }
    text.append("><p0:a ID=\"a\">");
    for i in 20000 { format(text, "<p", i % 200, ":b p", (i + 1) % 200, ":x=\"1\"/>"); }
    text.append("</p0:a></r>");
    var d = xml::Doc { .. };
    var o = xml::options();
    o.max_attrs = 256;
    let e = xml::parse(d, text, o);
    check("wide document parses", e.code == xml::OK);
    let a, n = xml::by_id(d, "a");
    var lens: i64[>..] = [];
    for method in [xml::C14N_10, xml::C14N_11, xml::EXC_C14N] {
        let m = xml::C14n { method: method, .. };
        var out: u8[>..] = [];
        xml::canonicalize(d, a, m, out);
        lens.push(out.len);
    }
    check("wide: inclusive forms declare everything once", lens[0] == lens[1] && lens[0] < lens[2]);
}

fn join(base: const u8[:], r: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    xml::join_uri(base, r, out);
    return out;
}

fn uris() {
    let B = "http://a/b/c/d;p?q";
    expect("g", join(B, "g"), "http://a/b/c/g");
    expect("./g", join(B, "./g"), "http://a/b/c/g");
    expect("g/", join(B, "g/"), "http://a/b/c/g/");
    expect("/g", join(B, "/g"), "http://a/g");
    expect("//g", join(B, "//g"), "http://g");
    expect("?y", join(B, "?y"), "http://a/b/c/d;p?y");
    expect("g?y", join(B, "g?y"), "http://a/b/c/g?y");
    expect("#s", join(B, "#s"), "http://a/b/c/d;p?q#s");
    expect("g#s", join(B, "g#s"), "http://a/b/c/g#s");
    expect("empty", join(B, ""), "http://a/b/c/d;p?q");
    expect(".", join(B, "."), "http://a/b/c/");
    expect("./", join(B, "./"), "http://a/b/c/");
    expect("..", join(B, ".."), "http://a/b/");
    expect("../g", join(B, "../g"), "http://a/b/g");
    expect("../..", join(B, "../.."), "http://a/");
    expect("../../g", join(B, "../../g"), "http://a/g");
    expect("../../../g", join(B, "../../../g"), "http://a/g");
    expect("/./g", join(B, "/./g"), "http://a/g");
    expect("g.", join(B, "g."), "http://a/b/c/g.");
    expect("./g/.", join(B, "./g/."), "http://a/b/c/g/");
    expect("g;x=1/../y", join(B, "g;x=1/../y"), "http://a/b/c/y");
    expect("g:h", join(B, "g:h"), "g:h");
    expect("relative base keeps ..", join("../xmlbase3", "../xmlbase31"), "../../xmlbase31");
    expect("relative base", join("a/b/", "c"), "a/b/c");
}

fn main() {
    w3c();
    namespaces();
    subsets();
    wide();
    uris();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
