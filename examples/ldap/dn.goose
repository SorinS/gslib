// dn: distinguished names (RFC 4514). A DN is parsed into its RDNs and
// their attribute=value pairs, escapes undone; written back in go-ldap's
// normal form; built safely from a value that has commas and other
// special characters in it; compared, with and without regard to case;
// and checked for being under a base, as a client does with the entries
// a search returns. A DN that is not one is refused, with the reason.
//
//   goose examples/ldap/dn.goose

import std;
import gslib from "../..";
import gslib.net.ldap;
import gslib.net.ldap.dn;

fn parsed(s: const u8[:]) -> ldap::Dn {
    let d, ok = ldap::parse_dn(s);
    guard ok else { print("dn: not a DN: ", s, ": ", ldap::dn_error(s)); exit(1); }
    return d;
}

fn main() {
    // The parts of a DN, its escapes (\, and \2B, a '+') undone.
    let d = parsed("CN=Smith\\, John+uid=jsmith, OU=R\\2BD , DC=example,DC=com");
    print(d.rdns, " RDNs, ", d.avas.len, " attribute=value pairs:");
    for a in d.avas { print("  RDN ", a.rdn, ": ", ldap::ava_type(d, a), " = ", ldap::ava_value(d, a)); }
    guard ldap::ava_value(d, d.avas[0]) == "Smith, John" && ldap::ava_value(d, d.avas[2]) == "R+D" else {
        print("dn: the values came out wrong"); exit(1);
    }
    // The normal form: types in lower case, a multi-valued RDN's pairs
    // sorted, the spaces around them gone, values escaped again.
    let s = ldap::dn_string(d);
    guard s == "cn=Smith\\, John+uid=jsmith,ou=R\\+D,dc=example,dc=com" else { print("dn: dn_string gave ", s); exit(1); }
    print("normal form: ", s);

    // A DN built from a user's name: each value escaped, never pasted in.
    let name = " #1 Fan, \"Joe\" ";
    var built: u8[>..] = [];
    format(built, "cn=", ldap::escape_dn_value(name), ",ou=People,dc=example,dc=com");
    print("built: ", built);
    let b = parsed(built);
    guard b.rdns == 4 && ldap::ava_value(b, b.avas[0]) == name else { print("dn: the name did not survive"); exit(1); }

    // Comparing: attribute types are matched without regard to case, and
    // values exactly, or without regard to case too (most directories
    // compare names so).
    let x = parsed("uid=alice,ou=People,dc=example,dc=com");
    let y = parsed("UID=Alice, OU=people, DC=Example, DC=COM");
    print("equal: ", ldap::dn_equal(x, y), "; equal ignoring case: ", ldap::dn_equal_fold(x, y));
    guard !ldap::dn_equal(x, y) && ldap::dn_equal_fold(x, y) else { print("dn: comparison"); exit(1); }

    // Under a base? (A search's entries should be.)
    let base = parsed("dc=example,dc=com");
    let other = parsed("dc=example,dc=org");
    guard ldap::dn_ancestor_of(base, x) && !ldap::dn_ancestor_of(other, x) && !ldap::dn_ancestor_of(x, x) &&
          ldap::dn_ancestor_of_fold(base, y) else { print("dn: ancestry"); exit(1); }
    print("dc=example,dc=com is above ", ldap::dn_string(x));

    // What is refused, and why.
    for bad in ["cn=a,", "cn", "=a", "cn=a\\zz"] {
        let e = ldap::dn_error(bad);
        guard e.len > 0 else { print("dn: taken: ", bad); exit(1); }
        print("refused '", bad, "': ", e);
    }
}
