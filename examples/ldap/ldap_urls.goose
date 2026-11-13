// ldap_urls: LDAP URLs (RFC 4516), as ldapsearch -H and go-ldap's DialURL
// take them: where to connect (ldap:// on 389, ldaps:// on 636, ldapi://
// for a Unix socket whose path is percent-encoded as the host), and a
// whole search in one URL: base DN, attributes, scope and filter, each
// percent-decoded.
//
//   goose examples/ldap/ldap_urls.goose

import std;
import gslib from "../..";
import gslib.net.ldap;
import gslib.net.ldap.url;

fn parsed(s: const u8[:]) -> ldap::Url {
    let u, ok = ldap::parse_url(s);
    guard ok else { print("ldap_urls: not an LDAP URL: ", s); exit(1); }
    return u;
}

fn main() {
    // Where to connect.
    for s in ["ldap://ldap.example.com", "ldaps://ldap.example.com", "ldap://[2001:db8::1]:10389",
              "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi"] {
        let u = parsed(s);
        if u.scheme == "ldapi" { print(s, ": the socket ", u.host); }
        else { print(s, ": ", u.scheme, " to ", u.host, " port ", u.port, if u.scheme == "ldaps" { ", TLS from the start" } else { "" }); }
    }
    let i = parsed("ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi");
    guard i.host == "/var/run/slapd/ldapi" && i.port == 0 else { print("ldap_urls: ldapi"); exit(1); }

    // A search in a URL: base, attributes, scope, filter (and extensions).
    let q = parsed("ldap://ldap.example.com/ou=People,dc=example,dc=com?cn,mail?sub?(&(objectClass=person)(cn=Ann%20Lee))");
    let scopes = ["base", "one", "sub", "children"];
    print("base:       ", q.dn);
    print("attributes: ", q.attrs);
    print("scope:      ", scopes[q.scope]);
    print("filter:     ", q.filter);
    guard q.scope == ldap::SCOPE_SUB && q.filter == "(&(objectClass=person)(cn=Ann Lee))" && q.attrs == "cn,mail" else {
        print("ldap_urls: the search parts came out wrong"); exit(1);
    }
    // Parts left out: no scope is -1 (a client's default is base).
    let b = parsed("ldap://ldap.example.com/dc=example,dc=com");
    guard b.scope == -1 && b.filter.len == 0 else { print("ldap_urls: defaults"); exit(1); }

    // Not LDAP URLs.
    for bad in ["http://ldap.example.com", "ldap://ldap.example.com:0", "ldap://[::1", "ldap://h/dc=x??wide"] {
        let u, ok = ldap::parse_url(bad);
        guard !ok else { print("ldap_urls: taken: ", bad); exit(1); }
        print("refused: ", bad);
    }
}
