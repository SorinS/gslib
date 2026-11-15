// canonicalize: the three canonical forms of an element and of a whole
// document. Exclusive XML Canonicalization's example (§2.2): the subset of
// elem2 by Canonical XML 1.0 takes every namespace in scope and the xml:
// attributes of its ancestors; 1.1 takes xml:lang and xml:space only;
// exclusive takes the namespaces the subset uses. With a FILE, its whole
// document in each form.
//
//   goose examples/xml/canonicalize.goose [-- FILE]

import std;
import os;
import gslib from "../..";
import gslib.encoding.xml;
import gslib.encoding.xml.c14n;

let SAMPLE = "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\" xml:id=\"pdu\">\n  <n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\" ID=\"elem2\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n  </n1:elem2>\n</n2:pdu>";

fn main() {
    let a = args();
    var text: u8[>..] = [];
    if a.len > 1 {
        guard read_file(a[1], text) else { print("canonicalize: cannot read ", a[1]); exit(1); }
    } else {
        text.append(SAMPLE);
    }
    var d = xml::Doc { .. };
    let e = xml::parse(d, text);
    guard e.code == xml::OK else { print("canonicalize: ", e.message); exit(1); }
    var n = 0;
    if a.len <= 1 {
        let el, count = xml::by_id(d, "elem2");
        n = el;
    }
    var forms: u8[][>..] = [];
    for method in [xml::C14N_10, xml::C14N_11, xml::EXC_C14N] {
        let m = xml::C14n { method: method, .. };
        var out: u8[>..] = [];
        xml::canonicalize(d, n, m, out);
        print(xml::c14n_uri(method, false), ":\n", out, "\n");
        forms.push(copy(out));
    }
    if a.len <= 1 {
        var i = 0;
        var good = true;
        for f in forms {
            let want = if i == 0 {
                "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\" ID=\"elem2\" xml:id=\"pdu\" xml:lang=\"en\" xml:space=\"retain\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>"
            } else if i == 1 {
                "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\" ID=\"elem2\" xml:lang=\"en\" xml:space=\"retain\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>"
            } else {
                "<n1:elem2 xmlns:n1=\"http://example.net\" ID=\"elem2\" xml:lang=\"en\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>"
            };
            if f != want { good = false; }
            i++;
        }
        guard good else { print("canonicalize: wrong forms"); exit(1); }
    }
}
