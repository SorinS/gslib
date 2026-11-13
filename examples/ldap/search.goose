// search: a search against a live LDAP server, its entries printed as
// LDIF, as ldapsearch prints them. The URL says where and what: host,
// port, base DN, attributes, scope and filter (RFC 4516); a bind DN and
// password are optional (else the search is anonymous). Plain ldap://
// only: for ldaps:// or StartTLS the bytes would go through tlsgoose, as
// the goose-ldap* tools in net/ldap/tools do. The socket is gslib's net
// module's (net::dial); ldap itself does no I/O.
//
//   goose examples/ldap/search.goose -- URL [BINDDN PASSWORD]
//   goose examples/ldap/search.goose -- 'ldap://127.0.0.1:389/dc=example,dc=com?cn,mail?sub?(objectClass=person)'

import std;
import os;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.crypto.bignum;
import gslib.net.ldap;
import gslib.net.ldap.conn;
import gslib.net.ldap.filter;
import gslib.net.ldap.url;
import gslib.net.ldap.ldif;
import gslib.net;

let TIMEOUT_MS: i32 = 10000;

// Sends what the connection wrote, then reads until the response to `id`
// has come whole: the messages are appended to msgs.
fn exchange(fd: i64, c: ldap::Conn&, out: u8[>..]&, id: i64, msgs: u8[>..]&) {
    guard net::write(fd, out, TIMEOUT_MS) == out.len else { print("search: the server took nothing"); exit(1); }
    out.clear();
    var buf: u8[16384] = [0; 16384];
    while ldap::outstanding(c, id) {
        let n = net::read(fd, buf, TIMEOUT_MS);
        guard n > 0 else { print("search: ", if n == 0 { "the server closed the connection" } else { "no answer" }); exit(1); }
        guard ldap::feed(c, buf[..n], msgs) == 0 else { print("search: ", ldap::conn_error(c)); exit(1); }
    }
}

fn main() {
    let a = args();
    guard a.len == 2 || a.len == 4 else { print("usage: search URL [BINDDN PASSWORD]"); exit(2); }
    let u, ok = ldap::parse_url(a[1]);
    guard ok && u.scheme == "ldap" else { print("search: an ldap:// URL, please: ", a[1]); exit(2); }
    let filter = if u.filter.len > 0 { u.filter[..] } else { "(objectClass=*)" };
    let scope = if u.scope >= 0 { u.scope } else { ldap::SCOPE_SUB };

    let fd = net::dial(u.host, u.port as! i32, TIMEOUT_MS);
    guard fd >= 0 else { print("search: cannot connect to ", u.host, " port ", u.port); exit(1); }
    var c = ldap::client();
    var out:  u8[>..] = [];
    var msgs: u8[>..] = [];

    if a.len == 4 {
        let id = ldap::bind(c, a[2], a[3], out);
        guard id > 0 else { print("search: ", ldap::conn_error(c)); exit(2); }
        exchange(fd, c, out, id, msgs);
        var pos = 0;
        let m, okm = ldap::next_message(msgs, pos);
        let e = ldap::result_error(msgs, m);
        guard okm && e.len == 0 else { print("search: bind: ", e); exit(1); }
        msgs.clear();
    }

    // The search; with the attributes from the URL ("" for all of them).
    let id = ldap::search(c, u.dn, scope, filter, u.attrs, out);
    guard id > 0 else { print("search: ", ldap::conn_error(c)); exit(2); }
    exchange(fd, c, out, id, msgs);
    var ldif: u8[>..] = [];
    var entries = 0;
    var code: i64 = 0;
    var pos = 0;
    loop {
        let m, okm = ldap::next_message(msgs, pos);
        if !okm { break; }
        if m.op == ldap::OP_SEARCH_ENTRY {
            ldap::ldif_entry(ldif, msgs, m);
            ldif.push('\n');
            entries++;
        } else if m.op == ldap::OP_SEARCH_REFERENCE {
            for r in ldap::referrals(msgs, m) { format(ldif, "# refldap: ", r, "\n\n"); }
        } else if m.op == ldap::OP_SEARCH_DONE {
            code = ldap::result_code(msgs, m);
            if code != ldap::RESULT_SUCCESS { print("# ", ldap::result_error(msgs, m)); }
        }
    }
    write_stdout(ldif);
    print("# ", entries, " entries, result ", code, " (", ldap::result_name(code), ")");

    ldap::unbind(c, out);
    net::write(fd, out, TIMEOUT_MS);
    net::close(fd);
    if code != ldap::RESULT_SUCCESS { exit(1); }
}
