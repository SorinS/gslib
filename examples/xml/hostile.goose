// hostile: what the parser refuses, and why, before anything is built
// from it. Entity expansion (billion laughs), external entities (XXE),
// DTDs at all, nesting a hundred thousand deep, an attribute twice under
// two prefixes of one namespace, an ID twice (the signature-wrapping
// setup), a character XML does not allow, bad UTF-8. Each in a few bytes,
// each refused with its error and where.
//
//   goose examples/xml/hostile.goose

import std;
import gslib from "../..";
import gslib.encoding.xml;

fn try_parse(what: const u8[:], text: const u8[:], want: i64) -> bool {
    var d = xml::Doc { .. };
    let e = xml::parse(d, text);
    print(what, ": ", xml::error_name(e.code), if e.code != xml::OK { str(" - ", e.message) } else { str("") });
    return e.code == want;
}

fn main() {
    var deep: u8[>..] = [];
    for i in 100000 { deep.append("<a>"); }
    var good = true;
    good = try_parse("billion laughs", "<!DOCTYPE l [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><l>&b;</l>", xml::ERR_DOCTYPE) && good;
    good = try_parse("XXE", "<!DOCTYPE x [<!ENTITY f SYSTEM \"file:///etc/passwd\">]><x>&f;</x>", xml::ERR_DOCTYPE) && good;
    good = try_parse("an undeclared entity", "<x>&f;</x>", xml::ERR_ENTITY) && good;
    good = try_parse("100000 deep", deep, xml::ERR_LIMIT) && good;
    good = try_parse("one attribute, two prefixes", "<x xmlns:p=\"urn:a\" xmlns:q=\"urn:a\" p:id=\"1\" q:id=\"2\"/>", xml::ERR_DUP_ATTR) && good;
    good = try_parse("an ID twice", "<r><a ID=\"_1\">signed</a><a ID=\"_1\">evil</a></r>", xml::ERR_DUP_ID) && good;
    good = try_parse("&#0;", "<x>&#0;</x>", xml::ERR_CHAR) && good;
    good = try_parse("bad UTF-8", "<x>\xC0\x80</x>", xml::ERR_CHAR) && good;
    good = try_parse("well formed", "<x xmlns=\"urn:x\">fine &amp; dandy</x>", xml::OK) && good;
    guard good else { print("hostile: wrong results"); exit(1); }
}
