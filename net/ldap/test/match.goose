// Filters matched against an entry (RFC 4511 §4.5.1.7): each kind of
// filter, and, or and not nested, with Undefined carried through them;
// attribute descriptions without regard to case or options; values as
// caseIgnoreMatch compares them and octet by octet; escapes; extensible
// matches by each rule known and not; the same entry read from LDIF and
// from a SearchResultEntry; a filter taken from a SearchRequest; and
// filters and entries that are not well formed.
import std;
import gslib from "../../..";
import gslib.net.ldap;
import gslib.encoding.asn1;
import gslib.net.ldap.filter;
import gslib.net.ldap.ldif;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn verdict(r: i64) -> const u8[:] {
    return if r == ldap::MATCH_TRUE { "TRUE" } else if r == ldap::MATCH_FALSE { "FALSE" } else if r == ldap::MATCH_UNDEFINED { "Undefined" } else { "invalid" };
}

let T = ldap::MATCH_TRUE;
let F = ldap::MATCH_FALSE;
let U = ldap::MATCH_UNDEFINED;

// A filter, what it is for the entry, and what it is when values match exactly.
struct Case { filter: const u8[:], want: i64, exact: i64 }

let ENTRY = "dn: cn=Alice Smith,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: Alice  Smith\ncn;lang-fr: Alice Lef\xc3\xa8vre\nsn: Smith\nmail: alice@Example.COM\nuidNumber: 1500\ndescription: a*b(c)d\\e\ntitle: aba\ndisplayName: \xc3\x89lodie\n";

fn cases() -> Case[>..] {
    var cs: Case[>..] = [];
    // equality: names fold, values fold and lose their extra spaces.
    cs.push(Case { filter: "(objectClass=person)", want: T, exact: T });
    cs.push(Case { filter: "(OBJECTCLASS=PERSON)", want: T, exact: F });
    cs.push(Case { filter: "(cn=alice smith)", want: T, exact: F });
    cs.push(Case { filter: "(cn=  Alice Smith )", want: T, exact: F });
    cs.push(Case { filter: "(cn=Alice  Smith)", want: T, exact: T });
    cs.push(Case { filter: "(cn=bob)", want: F, exact: F });
    // options left out on both sides
    cs.push(Case { filter: "(cn=Alice Lef\xc3\xa8vre)", want: T, exact: T });
    cs.push(Case { filter: "(cn;lang-fr=alice smith)", want: T, exact: F });
    cs.push(Case { filter: "(CN;LANG-EN=*)", want: T, exact: T });
    // present, and a missing attribute
    cs.push(Case { filter: "(seeAlso=*)", want: F, exact: F });
    cs.push(Case { filter: "(seeAlso=x)", want: U, exact: U });
    cs.push(Case { filter: "(!(seeAlso=*))", want: T, exact: T });
    cs.push(Case { filter: "(!(seeAlso=x))", want: U, exact: U });
    cs.push(Case { filter: "(!(!(seeAlso=x)))", want: U, exact: U });
    cs.push(Case { filter: "(!(cn=bob))", want: T, exact: T });
    // and, or, not
    cs.push(Case { filter: "(&)", want: T, exact: T });
    cs.push(Case { filter: "(|)", want: F, exact: F });
    cs.push(Case { filter: "(!(&))", want: F, exact: F });
    cs.push(Case { filter: "(!(|))", want: T, exact: T });
    cs.push(Case { filter: "(&(objectClass=person)(seeAlso=x))", want: U, exact: U });
    cs.push(Case { filter: "(&(objectClass=device)(seeAlso=x))", want: F, exact: F });
    cs.push(Case { filter: "(|(objectClass=device)(seeAlso=x))", want: U, exact: U });
    cs.push(Case { filter: "(|(cn=alice*)(seeAlso=x))", want: T, exact: U });
    cs.push(Case { filter: "(&(objectClass=person)(|(cn=bob*)(mail=*@example.com))(!(sn=jones)))", want: T, exact: F });
    cs.push(Case { filter: "(|(&(sn=smith)(!(seeAlso=x)))(uidNumber=1500))", want: T, exact: T });
    // substrings: in order, not overlapping
    cs.push(Case { filter: "(cn=ali*)", want: T, exact: F });
    cs.push(Case { filter: "(cn=*smith)", want: T, exact: F });
    cs.push(Case { filter: "(cn=*ce sm*)", want: T, exact: F });
    cs.push(Case { filter: "(cn=A*i*S*h)", want: T, exact: T });
    cs.push(Case { filter: "(cn=*S*H*)", want: T, exact: F });
    cs.push(Case { filter: "(title=*ab*ba*)", want: F, exact: F });
    cs.push(Case { filter: "(title=ab*ba)", want: F, exact: F });
    cs.push(Case { filter: "(title=a*a)", want: T, exact: T });
    cs.push(Case { filter: "(title=*b*)", want: T, exact: T });
    cs.push(Case { filter: "(seeAlso=a*)", want: U, exact: U });
    // escapes: literal * ( ) \ in a value
    cs.push(Case { filter: "(description=a\\2ab\\28c\\29d\\5ce)", want: T, exact: T });
    cs.push(Case { filter: "(description=*\\28c\\29*)", want: T, exact: T });
    cs.push(Case { filter: "(description=a\\2a*\\5c*)", want: T, exact: T });
    cs.push(Case { filter: "(description=\\2a)", want: F, exact: F });
    cs.push(Case { filter: "(cn=\\41lice smith)", want: T, exact: F });
    // ordering: the strings, byte by byte (no schema: 900 > 1500)
    cs.push(Case { filter: "(uidNumber>=1000)", want: T, exact: T });
    cs.push(Case { filter: "(uidNumber>=900)", want: F, exact: F });
    cs.push(Case { filter: "(uidNumber<=2000)", want: T, exact: T });
    cs.push(Case { filter: "(sn<=SMITH)", want: T, exact: F });
    cs.push(Case { filter: "(sn>=SMITH)", want: T, exact: T });
    cs.push(Case { filter: "(sn>=a)", want: T, exact: F });
    cs.push(Case { filter: "(seeAlso>=a)", want: U, exact: U });
    // approximate is equality
    cs.push(Case { filter: "(cn~=ALICE SMITH)", want: T, exact: F });
    // UTF-8: only ASCII folds
    cs.push(Case { filter: "(displayName=\xc3\x89lodie)", want: T, exact: T });
    cs.push(Case { filter: "(displayName=\\c3\\89LODIE)", want: T, exact: F });
    cs.push(Case { filter: "(displayName=\xc3\xa9lodie)", want: F, exact: F });
    // extensible: a rule named wins over exact
    cs.push(Case { filter: "(cn:caseExactMatch:=Alice Smith)", want: T, exact: T });
    cs.push(Case { filter: "(cn:caseExactMatch:=alice smith)", want: F, exact: F });
    cs.push(Case { filter: "(cn:2.5.13.5:=ALICE SMITH)", want: F, exact: F });
    cs.push(Case { filter: "(cn:2.5.13.2:=ALICE SMITH)", want: T, exact: T });
    cs.push(Case { filter: "(cn:caseignorematch:=ALICE SMITH)", want: T, exact: T });
    cs.push(Case { filter: "(cn:octetStringMatch:=Alice Smith)", want: F, exact: F });
    cs.push(Case { filter: "(cn:=alice smith)", want: T, exact: F });
    cs.push(Case { filter: "(:caseIgnoreMatch:=smith)", want: T, exact: T });
    cs.push(Case { filter: "(:2.5.13.17:=Smith)", want: T, exact: T });
    cs.push(Case { filter: "(:2.5.13.17:=smith)", want: F, exact: F });
    cs.push(Case { filter: "(sn:caseIgnoreMatch:=jones)", want: F, exact: F });
    cs.push(Case { filter: "(seeAlso:caseIgnoreMatch:=x)", want: U, exact: U });
    cs.push(Case { filter: "(cn:dn:=Alice Smith)", want: U, exact: U });
    cs.push(Case { filter: "(cn:1.2.3.4:=x)", want: U, exact: U });
    cs.push(Case { filter: "(!(cn:1.2.3.4:=x))", want: U, exact: U });
    cs.push(Case { filter: "(|(cn:1.2.3.4:=x)(sn=smith))", want: T, exact: U });
    return cs;
}

// The entry, read as an LDIF add record.
fn record_attrs() -> u8[>..] {
    var pos = 0;
    var lineno = 0;
    var r = ldap::empty_record();
    var err: u8[>..] = [];
    let k = ldap::next_record(ENTRY, pos, lineno, r, err, true) { url, value => false };
    assert(k == 1 && r.kind == ldap::CHANGE_ADD);
    var out: u8[>..] = [];
    out.append(r.body);
    return out;
}

// The same attributes in a SearchResultEntry.
fn entry_message(attrs: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_octets(b, "cn=Alice Smith,dc=example,dc=com");
    asn1::put(b, asn1::SEQUENCE, attrs);
    var out: u8[>..] = [];
    ldap::put_message(out, 2, ldap::OP_SEARCH_ENTRY, b, "");
    return out;
}

fn table() {
    let attrs = record_attrs();
    let msgs = entry_message(attrs);
    var pos = 0;
    let m, okm = ldap::next_message(msgs, pos);
    check("entry message", okm && ldap::entry_attributes(msgs, m) == attrs);
    for c in cases() {
        let ber, ok = ldap::compile(c.filter);
        check(str("compiles ", c.filter), ok);
        let r = ldap::filter_match(ber, attrs);
        let x = ldap::filter_match(ber, attrs, true);
        check(str(c.filter, " is ", verdict(r), ", not ", verdict(c.want)), r == c.want);
        check(str(c.filter, " exactly is ", verdict(x), ", not ", verdict(c.exact)), x == c.exact);
        check(str(c.filter, " matches"), ldap::filter_matches(ber, attrs) == (c.want == T));
        // The SearchResultEntry says the same as the record.
        let e = ldap::filter_match(ber, ldap::entry_attributes(msgs, m));
        check(str(c.filter, " from the message"), e == r && ldap::entry_matches(ber, msgs, m) == (r == T) &&
                                                  ldap::entry_matches(ber, msgs, m, true) == (x == T));
    }
}

// A filter as a server finds it, in a decoded SearchRequest.
fn from_request() {
    let attrs = record_attrs();
    let f, ok = ldap::compile("(&(objectClass=person)(cn=*smith))");
    var req: u8[>..] = [];
    ldap::put_message(req, 3, ldap::OP_SEARCH_REQUEST, ldap::search_body("dc=example,dc=com", ldap::SCOPE_SUB, 0, 0, 0, false, f, "cn"), "");
    let t, okt = asn1::parse(req, true);
    let cs, okc = asn1::children(req, t, true);
    let parts, okp = asn1::children(req, cs[1], true);
    let ft = parts[6];
    check("request filter", ok && okt && okc && okp && req[ft.start..ft.end] == f);
    check("request filter matches", ldap::filter_matches(req[ft.start..ft.end], attrs));
}

// A types-only entry: attributes without values.
fn types_only() {
    var attrs: u8[>..] = [];
    ldap::put_attribute(attrs, "cn", "");
    let p, okp = ldap::compile("(cn=*)");
    let e, oke = ldap::compile("(cn=alice)");
    check("types only present", ldap::filter_match(p, attrs) == T);
    check("types only equality", ldap::filter_match(e, attrs) == F);
    let a, oka = ldap::compile("(&)");
    check("no attributes at all", ldap::filter_match(a, "") == T && ldap::filter_match(p, "") == F && ldap::filter_match(e, "") == U);
}

fn bad(what: const u8[:], filter: const u8[:], attrs: const u8[:]) {
    let r = ldap::filter_match(filter, attrs);
    check(str(what, " is ", verdict(r)), r == ldap::MATCH_INVALID && !ldap::filter_matches(filter, attrs));
}

fn invalid() {
    let attrs = record_attrs();
    let good, ok = ldap::compile("(cn=alice smith)");
    check("good", ok && ldap::filter_match(good, attrs) == T);
    bad("empty filter", "", attrs);
    bad("garbage", "\x01\x02", attrs);
    bad("trailing bytes", str(good, "\x00"), attrs);
    bad("universal tag", "\x04\x01a", attrs);
    bad("unknown choice", "\x8a\x01a", attrs);
    // not with two terms
    var two: u8[>..] = [];
    two.append(good);
    two.append(good);
    var not2: u8[>..] = [];
    asn1::put(not2, 0xa2, two);
    bad("not of two", not2, attrs);
    // A bad term past a FALSE one still makes the and invalid.
    let no, okn = ldap::compile("(cn=bob)");
    var and_bad: u8[>..] = [];
    asn1::put(and_bad, 0xa0, str(no, "\x8a\x01a"));
    bad("and with a bad term", and_bad, attrs);
    // substrings: final before an any, initial after one, none at all
    var sub: u8[>..] = [];
    asn1::put_octets(sub, "cn");
    var pieces: u8[>..] = [];
    asn1::put(pieces, 0x82, "a");
    asn1::put(pieces, 0x81, "b");
    asn1::put(sub, asn1::SEQUENCE, pieces);
    var subf: u8[>..] = [];
    asn1::put(subf, 0xa4, sub);
    bad("final first", subf, attrs);
    var sub0: u8[>..] = [];
    asn1::put_octets(sub0, "cn");
    asn1::put(sub0, asn1::SEQUENCE, "");
    var subf0: u8[>..] = [];
    asn1::put(subf0, 0xa4, sub0);
    bad("no pieces", subf0, attrs);
    // extensible without a rule or a type
    var ext: u8[>..] = [];
    asn1::put(ext, 0x83, "x");
    var extf: u8[>..] = [];
    asn1::put(extf, 0xa9, ext);
    bad("extensible with neither", extf, attrs);
    // An entry that is not attributes.
    bad("attributes not well formed", good, "\x30\x03\x04\x01a");
    bad("attributes cut short", good, attrs[..attrs.len - 1]);
    // Nesting: 256 nots deep are a filter, 257 are not.
    var deep: u8[>..] = [];
    deep.append(good);
    for i in 256 {
        var w: u8[>..] = [];
        asn1::put(w, 0xa2, deep);
        deep = copy(w);
    }
    check("256 deep", ldap::filter_match(deep, attrs) == T);
    var deeper: u8[>..] = [];
    asn1::put(deeper, 0xa2, deep);
    bad("257 deep", deeper, attrs);
    // Not an entry.
    var done: u8[>..] = [];
    var body: u8[>..] = [];
    asn1::put_i64(body, 0, asn1::ENUMERATED);
    asn1::put_octets(body, "");
    asn1::put_octets(body, "");
    ldap::put_message(done, 4, ldap::OP_SEARCH_DONE, body, "");
    var pos = 0;
    let m, okm = ldap::next_message(done, pos);
    let all, oka = ldap::compile("(&)");
    check("a SearchResultDone is no entry", okm && !ldap::entry_matches(all, done, m) && ldap::entry_attributes(done, m) == "");
}

fn main() {
    table();
    from_request();
    types_only();
    invalid();
    print("match: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
