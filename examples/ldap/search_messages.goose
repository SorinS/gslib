// search_messages: an LDAP bind and a paged search, client and server
// both played here, in memory. The client's Conn writes the requests;
// the server side reads them from the BER (the bind DN, the search's
// base and filter) and answers with entries and a SearchResultDone that
// carries a paging cookie; the client is fed the answer a few bytes at a
// time, as a socket would give it, and writes each entry as LDIF, as
// ldapsearch prints it.
//
//   goose examples/ldap/search_messages.goose

import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.crypto.bignum;
import gslib.net.ldap;
import gslib.net.ldap.conn;
import gslib.net.ldap.filter;
import gslib.net.ldap.ldif;

// The server's side: one request message taken off the front of `wire`
// into `req`: its id, its operation, and its body's parts (offsets into
// req).
fn take_request(wire: u8[>..]&, req: u8[>..]&, id: i64&, op: u32&) -> asn1::Tlv[>..] {
    let n = ldap::frame_len(wire, 1 << 20);
    guard n > 0 else { print("search_messages: no whole request"); exit(1); }
    req.clear();
    req.append(wire[..n]);
    var rest: u8[>..] = [];
    rest.append(wire[n..]);
    wire.clear();
    wire.append(rest);
    let t, ok = asn1::parse(req, true);
    let cs, okc = asn1::children(req, t, true);
    guard ok && okc && cs.len >= 2 else { print("search_messages: not an LDAPMessage"); exit(1); }
    let v, oki = asn1::read_i64(req, cs[0], asn1::INTEGER, true);
    id = v;
    op = cs[1].tag;
    let parts, okb = asn1::children(req, cs[1], true);
    return parts;
}

// An LDAPResult: code, matched DN, message.
fn result_body(code: i64) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_i64(b, code, asn1::ENUMERATED);
    asn1::put_octets(b, "");
    asn1::put_octets(b, "");
    return b;
}

fn entry(out: u8[>..]&, id: i64, dn: const u8[:], cn: const u8[:], mail: const u8[:], photo: const u8[:]) {
    var attrs: u8[>..] = [];
    var v:     u8[>..] = [];
    ldap::put_value(v, "top");
    ldap::put_value(v, "inetOrgPerson");
    ldap::put_attribute(attrs, "objectClass", v);
    v.clear();
    ldap::put_value(v, cn);
    ldap::put_attribute(attrs, "cn", v);
    v.clear();
    ldap::put_value(v, mail);
    ldap::put_attribute(attrs, "mail", v);
    v.clear();
    ldap::put_value(v, photo);
    ldap::put_attribute(attrs, "jpegPhoto", v);
    var b: u8[>..] = [];
    asn1::put_octets(b, dn);
    asn1::put(b, asn1::SEQUENCE, attrs);
    ldap::put_message(out, id, ldap::OP_SEARCH_ENTRY, b, "");
}

fn main() {
    var c = ldap::client();
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];

    // The client: a simple bind, then the first page of a search.
    let bind_id = ldap::bind(c, "cn=reader,dc=example,dc=com", "example-password", to_server);
    var ctl: u8[>..] = [];
    ldap::put_paging(ctl, 2, "");
    let search_id = ldap::search(c, "ou=People,dc=example,dc=com", ldap::SCOPE_SUB, "(&(objectClass=person)(cn=A*))",
                                 "cn mail jpegPhoto", to_server, ctl);
    guard bind_id > 0 && search_id > 0 else { print("search_messages: ", ldap::conn_error(c)); exit(1); }

    // The server reads both requests.
    var id:  i64     = 0;
    var op:  u32     = 0;
    var req: u8[>..] = [];
    let bind = take_request(to_server, req, id, op);
    guard op == ldap::OP_BIND_REQUEST else { print("search_messages: not a bind"); exit(1); }
    print("server: bind ", id, " as ", ldap::bytes(req, bind[1]));
    ldap::put_message(to_client, id, ldap::OP_BIND_RESPONSE, result_body(ldap::RESULT_SUCCESS), "");
    let search = take_request(to_server, req, id, op);
    guard op == ldap::OP_SEARCH_REQUEST else { print("search_messages: not a search"); exit(1); }
    // Its parts: base, scope, deref, limits, typesOnly, the filter, attributes.
    let filter, okf = ldap::decompile(req[search[6].start..search[6].end]);
    print("server: search ", id, " under ", ldap::bytes(req, search[0]), " for ", filter);
    entry(to_client, id, "cn=Alice Liddell,ou=People,dc=example,dc=com", "Alice Liddell", "alice@example.com", "\xff\xd8\xff");
    entry(to_client, id, "cn=Arthur Dent,ou=People,dc=example,dc=com", "Arthur Dent", "arthur@example.com", "\xff\xd8\xff");
    var done_ctl: u8[>..] = [];
    ldap::put_paging(done_ctl, 0, "page-2");
    ldap::put_message(to_client, id, ldap::OP_SEARCH_DONE, result_body(ldap::RESULT_SUCCESS), done_ctl);

    // The client is fed the answer 5 bytes at a time; whole messages come out.
    var msgs: u8[>..] = [];
    var p = 0;
    while p < to_client.len {
        let n = min(5, to_client.len - p);
        guard ldap::feed(c, to_client[p..p + n], msgs) == 0 else { print("search_messages: ", ldap::conn_error(c)); exit(1); }
        p += n;
    }
    var ldif: u8[>..] = [];
    var entries = 0;
    var cookie: u8[>..] = [];
    var pos = 0;
    loop {
        let m, ok = ldap::next_message(msgs, pos);
        if !ok { break; }
        if m.op == ldap::OP_BIND_RESPONSE {
            guard ldap::result_error(msgs, m).len == 0 else { print("bind: ", ldap::result_error(msgs, m)); exit(1); }
            print("client: bound");
        } else if m.op == ldap::OP_SEARCH_ENTRY {
            print("client: entry ", ldap::entry_dn(msgs, m), ", mail ", ldap::get_value(msgs, m, "mail"));
            ldap::ldif_entry(ldif, msgs, m);
            ldif.push('\n');
            entries++;
        } else if m.op == ldap::OP_SEARCH_DONE {
            guard ldap::result_code(msgs, m) == ldap::RESULT_SUCCESS else { print("search: ", ldap::result_error(msgs, m)); exit(1); }
            cookie.append(ldap::paging_cookie(msgs, m));
        }
    }
    guard entries == 2 && cookie == "page-2" && !ldap::outstanding(c, search_id) else { print("search_messages: wrong answer"); exit(1); }
    print("client: ", entries, " entries; the next page's cookie: ", cookie, "\n");
    print(ldif[..ldif.len - 1]);

    // The next page would be asked for with the cookie; then unbind.
    to_server.clear();
    var next_ctl: u8[>..] = [];
    ldap::put_paging(next_ctl, 2, cookie);
    ldap::search(c, "ou=People,dc=example,dc=com", ldap::SCOPE_SUB, "(&(objectClass=person)(cn=A*))", "cn mail", to_server, next_ctl);
    ldap::unbind(c, to_server);
    print("next page and unbind: ", to_server.len, " bytes to send");
}
