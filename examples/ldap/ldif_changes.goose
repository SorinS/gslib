// ldif_changes: applying an LDIF file of changes, as ldapmodify does. Each
// record (add, modify, delete, modrdn) is read with its line number, and
// becomes the request that carries it out on a connection; a value given
// by URL ("jpegPhoto:< file:///...") is fetched through the caller's
// block. A broken record is reported with the line it is on.
//
//   goose examples/ldap/ldif_changes.goose

import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.crypto.bignum;
import gslib.net.ldap;
import gslib.net.ldap.conn;
import gslib.net.ldap.filter;
import gslib.net.ldap.ldif;

let CHANGES: const u8[:] = """
    version: 1

    # A new person, a photo given by URL.
    dn: uid=ford,ou=People,dc=example,dc=com
    changetype: add
    objectClass: top
    objectClass: inetOrgPerson
    uid: ford
    cn: Ford Prefect
    sn: Prefect
    description:: QSBoaXRjaGhpa2VyLCDDqXRvaWxlIGZpbGFudGU=
    jpegPhoto:< file:///photos/ford.jpg

    dn: uid=arthur,ou=People,dc=example,dc=com
    changetype: modify
    replace: mail
    mail: arthur@example.com
    -
    add: telephoneNumber
    telephoneNumber: +44 20 7946 0000
    telephoneNumber: +44 20 7946 0001
    -
    delete: description
    -

    dn: uid=marvin,ou=People,dc=example,dc=com
    changetype: modrdn
    newrdn: uid=marvin-the-android
    deleteoldrdn: 1
    newsuperior: ou=Robots,dc=example,dc=com

    dn: uid=zaphod,ou=People,dc=example,dc=com
    changetype: delete

    """;

fn main() {
    var c = ldap::client();
    var out: u8[>..] = [];
    var r = ldap::empty_record();
    var err: u8[>..] = [];
    var pos = 0;
    var line = 0;
    let kinds = ["add", "delete", "modify", "modrdn"];
    var n = 0;
    loop {
        // The block fetches a URL's value: here, a made-up file.
        let k = ldap::next_record(CHANGES, pos, line, r, err) { url, value =>
            if url == "file:///photos/ford.jpg" { value.append("\xff\xd8\xff\xe0"); true } else { false }
        };
        guard k >= 0 else { print("ldif_changes: line ", r.error_line, ": ", err); exit(1); }
        if k == 0 { break; }
        // The record, ready for its request.
        var id: i64 = -1;
        if r.kind == ldap::CHANGE_ADD { id = ldap::add(c, r.dn, r.body, out, r.controls); }
        else if r.kind == ldap::CHANGE_MODIFY { id = ldap::modify(c, r.dn, r.body, out, r.controls); }
        else if r.kind == ldap::CHANGE_DELETE { id = ldap::delete(c, r.dn, out, r.controls); }
        else {
            id = ldap::modify_dn(c, r.dn, r.new_rdn, r.delete_old, if r.has_new_superior { r.new_superior[..] } else { "" }, out,
                                 r.controls);
        }
        guard id > 0 else { print("ldif_changes: ", ldap::conn_error(c)); exit(1); }
        var what: u8[>..] = [];
        format(what, "line ", r.line, ": ", kinds[r.kind], " ", r.dn, " -> request ", id);
        if r.kind == ldap::CHANGE_ADD || r.kind == ldap::CHANGE_MODIFY { format(what, ", ", r.body.len, " bytes of BER"); }
        if r.kind == ldap::CHANGE_MODDN { format(what, ", to ", r.new_rdn, " under ", r.new_superior); }
        print(what);
        n++;
    }
    guard n == 4 else { print("ldif_changes: ", n, " records"); exit(1); }
    print(n, " requests, ", out.len, " bytes to send");

    // The add's attributes, read back from its BER: the base64 value
    // decoded, the URL's value fetched.
    var pos2 = 0;
    var line2 = 0;
    ldap::next_record(CHANGES, pos2, line2, r, err) { url, value => value.append("\xff\xd8\xff\xe0"); true };
    var p = 0;
    while p < r.body.len {
        let a, ok = asn1::read(r.body, p, r.body.len, true);
        let cs, okc = asn1::children(r.body, a, true);
        let vals, okv = asn1::children(r.body, cs[1], true);
        guard ok && okc && okv else { print("ldif_changes: the attributes do not read"); exit(1); }
        print("  ", ldap::bytes(r.body, cs[0]), ": ", vals.len, " value(s), the first ", asn1::content_len(vals[0]), " bytes");
        p = a.end;
    }

    // A broken record: the error and its line.
    var bp = 0;
    var bl = 0;
    let bad = "dn: uid=x,dc=example,dc=com\nchangetype: modify\nreplace: mail\nmail: a@example.com\nbogus: line\n";
    let k = ldap::next_record(bad, bp, bl, r, err) { url, value => false };
    guard k < 0 else { print("ldif_changes: a broken record was taken"); exit(1); }
    print("refused, line ", r.error_line, ": ", err);
}
