// filters: search filters (RFC 4515). A filter is compiled to the BER a
// search request carries and written back as text from that BER (as a
// server's log, or a proxy, would read one); a value typed by a user is
// escaped before it goes into a filter, so it cannot change the filter's
// meaning; filters that are not well formed are refused with the
// reason; and an entry is matched against filters, as a server (or a
// client sifting what it already has) would match it.
//
//   goose examples/ldap/filters.goose

import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.net.ldap;
import gslib.net.ldap.filter;
import gslib.net.ldap.ldif;

fn hex(b: const u8[:]) -> u8[>..] {
    var o: u8[>..] = [];
    for x in b { format_uint(o, x, 16, 2, '0'); }
    return o;
}

// A filter, and whether the entry matches it, and matches it exactly.
struct Want { filter: const u8[:], matches: bool, exact: bool }

fn main() {
    // Compiled and back: the text from the BER is the filter again.
    let filters = [
        "(objectClass=person)",
        "(&(objectClass=person)(|(cn=Ali*)(mail=*@example.com))(!(employeeType=contractor)))",
        "(uidNumber>=1000)",
        "(cn~=jon smith)",
        "(description=*)",
        "(cn:caseExactMatch:=Bob)",
    ];
    for f in filters {
        let ber, ok = ldap::compile(f);
        guard ok else { print("filters: refused: ", f); exit(1); }
        let back, okb = ldap::decompile(ber);
        guard okb && back == f else { print("filters: ", f, " came back as ", back); exit(1); }
        print(f, "\n  ", ber.len, " bytes of BER: ", if ber.len <= 24 { hex(ber) } else { str(hex(ber[..24]), "...") });
    }

    // A value from a user, escaped: its * ( ) \ cannot make it a wildcard
    // or another filter.
    let typed = "*)(uid=*))(|(uid=*";
    var f: u8[>..] = [];
    format(f, "(&(objectClass=person)(cn=", ldap::escape_filter(typed), "))");
    print("with a user's value: ", f);
    let ber, ok = ldap::compile(f);
    guard ok else { print("filters: the escaped filter was refused"); exit(1); }
    // It is still one AND of two equality matches, the value whole.
    let t, okt = asn1::parse(ber, true);
    let parts, okp = asn1::children(ber, t, true);
    guard okt && okp && parts.len == 2 && parts[1].number == 3 else { print("filters: the value changed the filter"); exit(1); }
    let ava, oka = asn1::children(ber, parts[1], true);
    guard oka && ldap::bytes(ber, ava[1]) == typed else { print("filters: the value changed"); exit(1); }
    print("  still two terms; cn's value is '", ldap::bytes(ber, ava[1]), "'");
    // Pasted in unescaped, the same input would be refused, or worse.
    var raw: u8[>..] = [];
    format(raw, "(&(objectClass=person)(cn=", typed, "))");
    let rb, rok = ldap::compile(raw);
    print("unescaped: ", if rok { "taken, with another meaning" } else { "refused" });

    // Filters that are not filters, and why.
    for bad in ["cn=alice", "(cn=alice", "(&(cn=a)x", "(cn=\\zz)", "()"] {
        var out: u8[>..] = [];
        var err: u8[>..] = [];
        guard !ldap::compile_filter(bad, out, err) else { print("filters: taken: ", bad); exit(1); }
        print("refused '", bad, "': ", err);
    }

    // An entry, here an LDIF add record's attributes (a SearchResultEntry's
    // are ldap::entry_attributes(buf, m)), matched against filters: values
    // compare as caseIgnoreMatch does (case and extra spaces aside) unless
    // exact; a filter on an attribute the entry lacks is Undefined, which
    // is not a match, and stays Undefined under a NOT.
    let ldif = "dn: uid=alice,ou=people,dc=example,dc=com\nobjectClass: person\nuid: alice\ncn: Alice  Smith\nmail: alice@example.com\nemployeeType: staff\n";
    var pos = 0;
    var lineno = 0;
    var r = ldap::empty_record();
    var lerr: u8[>..] = [];
    let k = ldap::next_record(ldif, pos, lineno, r, lerr, true) { url, value => false };
    guard k == 1 else { print("filters: ", lerr); exit(1); }
    let names = ["FALSE", "TRUE", "Undefined"];
    for w in [Want { filter: "(&(objectClass=person)(|(cn=Ali*)(mail=*@example.com))(!(employeeType=contractor)))", matches: true, exact: true },
              Want { filter: "(cn=alice smith)", matches: true, exact: false },
              Want { filter: "(cn:caseExactMatch:=Alice Smith)", matches: true, exact: true },
              Want { filter: "(manager=*)", matches: false, exact: false },
              Want { filter: "(!(manager=cn=bob))", matches: false, exact: false }] {
        let ber, okw = ldap::compile(w.filter);
        let v = ldap::filter_match(ber, r.body);
        guard okw && v >= 0 && ldap::filter_matches(ber, r.body) == w.matches && ldap::filter_matches(ber, r.body, true) == w.exact else {
            print("filters: ", w.filter, " was not matched as it should be");
            exit(1);
        }
        print("match ", w.filter, ": ", names[v], if w.matches != w.exact { " (exactly: no match)" } else { "" });
    }
}
