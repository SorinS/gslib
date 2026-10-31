// ldap against go-ldap (test/vectors/goldap.txt, from tools/goldap.sh
// vectors): every request go-ldap writes, written here byte for byte
// (go-ldap's booleans as FF, as RFC 4511 has them); every filter
// compiled to the same BER or refused as go-ldap refuses it, decompiled
// to the same text, escaped the same; every DN read to the same String()
// or refused, and compared as Equal, EqualFold and AncestorOf compare.
import std;
import gslib from "../..";
import gslib.ldap;
import gslib.asn1;
import gslib.bignum;
import gslib.ldap.filter;
import gslib.ldap.dn;
import gslib.ldap.conn;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var o: u8[>..] = [];
    for x in b { format_int(o, x, 16, 2, '0'); }
    return o;
}

// What this package writes for each of tools/goldap's requests.
fn request(name: const u8[:]) -> u8[>..] {
    let dn = "cn=alice,ou=People,dc=example,dc=com";
    var c = ldap::client();
    var out: u8[>..] = [];
    var id: i64 = 0;
    if name == "bind" { id = ldap::bind(c, "cn=admin,dc=example,dc=com", "secret", out); }
    else if name == "unauthenticated_bind" { id = ldap::unauthenticated_bind(c, "cn=nobody", out); }
    else if name == "anonymous_bind" { id = ldap::unauthenticated_bind(c, "", out); }
    else if name == "external_bind" { id = ldap::external_bind(c, out); }
    else if name == "digest_md5_bind" { id = ldap::sasl_bind(c, "DIGEST-MD5", "", false, out); }
    else if name == "search" { id = ldap::search(c, "dc=example,dc=com", ldap::SCOPE_SUB, "(objectClass=*)", "", out); }
    else if name == "search_full" {
        id = ldap::search(c, "dc=example,dc=com", ldap::SCOPE_ONE,
                          "(&(objectClass=person)(|(cn=a*)(sn~=smith))(!(mail=*))(uidNumber>=1000))", "cn,mail,+", out, "",
                          ldap::DEREF_ALWAYS, 10, 5, true);
    } else if name == "search_controls" {
        var ctl: u8[>..] = [];
        ldap::put_paging(ctl, 100, "cookie\x00\xff");
        ldap::put_manage_dsa_it(ctl, true);
        ldap::put_control(ctl, "1.2.3.4", true, "value", true);
        ldap::put_control(ctl, "1.2.3.5", false, "", false);
        ldap::put_control(ctl, ldap::CONTROL_MICROSOFT_SHOW_DELETED, false, "", false);
        ldap::put_ppolicy_request(ctl);
        id = ldap::search(c, "", ldap::SCOPE_BASE, "(objectClass=*)", "1.1", out, ctl);
    } else if name == "search_paging" {
        var ctl: u8[>..] = [];
        ldap::put_paging(ctl, 2, "");
        id = ldap::search(c, "dc=example,dc=com", ldap::SCOPE_SUB, "(cn=*)", "", out, ctl);
    } else if name == "add" {
        var attrs: u8[>..] = [];
        var v: u8[>..] = [];
        ldap::put_value(v, "top");
        ldap::put_value(v, "person");
        ldap::put_value(v, "inetOrgPerson");
        ldap::put_attribute(attrs, "objectClass", v);
        v.clear(); ldap::put_value(v, "alice"); ldap::put_attribute(attrs, "cn", v);
        v.clear(); ldap::put_value(v, "Liddell"); ldap::put_attribute(attrs, "sn", v);
        v.clear(); ldap::put_value(v, "é\x00\n"); ldap::put_attribute(attrs, "description", v);
        id = ldap::add(c, dn, attrs, out);
    } else if name == "modify" {
        var ch: u8[>..] = [];
        var v: u8[>..] = [];
        ldap::put_value(v, "Smith");
        ldap::put_change(ch, ldap::MOD_REPLACE, "sn", v);
        v.clear(); ldap::put_value(v, "a@example.com"); ldap::put_value(v, "b@example.com");
        ldap::put_change(ch, ldap::MOD_ADD, "mail", v);
        ldap::put_change(ch, ldap::MOD_DELETE, "description", "");
        v.clear(); ldap::put_value(v, "+1 555");
        ldap::put_change(ch, ldap::MOD_DELETE, "telephoneNumber", v);
        v.clear(); ldap::put_value(v, "5");
        ldap::put_change(ch, ldap::MOD_INCREMENT, "uidNumber", v);
        id = ldap::modify(c, dn, ch, out);
    } else if name == "delete" { id = ldap::delete(c, dn, out); }
    else if name == "delete_subtree" {
        var ctl: u8[>..] = [];
        ldap::put_subtree_delete(ctl);
        id = ldap::delete(c, dn, out, ctl);
    } else if name == "moddn" { id = ldap::modify_dn(c, dn, "cn=bob", true, "", out); }
    else if name == "moddn_superior" { id = ldap::modify_dn(c, dn, "cn=alice", false, "ou=Staff,dc=example,dc=com", out); }
    else if name == "compare" { id = ldap::compare(c, dn, "sn", "Liddell", out); }
    else if name == "password_modify" { id = ldap::password_modify(c, "uid=alice,dc=example,dc=com", "old", "new", out); }
    else if name == "password_modify_self" { id = ldap::password_modify(c, "", "", "new", out); }
    else if name == "password_modify_generate" { id = ldap::password_modify(c, "", "", "", out); }
    else if name == "who_am_i" { id = ldap::who_am_i(c, out); }
    else if name == "start_tls" { id = ldap::start_tls(c, out); }
    else if name == "unbind" { ldap::unbind(c, out); id = 1; }
    else { print("unknown request ", name); }
    check(str(name, " id"), id == 1);
    return out;
}

fn main() {
    var kinds = 0;
    for line in split(embed_file("vectors/goldap.txt"), '\n') {
        if line.len == 0 { continue; }
        let f = split(line, ' ');
        if f[0] == "request" {
            let got = request(f[1]);
            check(str("request ", f[1], " ", hex(got)), hex(got) == f[2]);
        } else if f[0] == "filter" {
            let text = unhex(f[1]);
            let ber, ok = ldap::compile(text);
            if f[2] == "ERR" { check(str("filter refused ", text), !ok); }
            else { check(str("filter ", text, " ", hex(ber)), ok && hex(ber) == f[2]); }
        } else if f[0] == "decompile" {
            let back, ok = ldap::decompile(unhex(f[1]));
            check(str("decompile ", f[1], " ", back), ok && back == unhex(f[2]));
        } else if f[0] == "escape" {
            check(str("escape ", f[1]), ldap::escape_filter(unhex(f[1])) == unhex(f[2]));
        } else if f[0] == "dn" {
            let text = unhex(f[1]);
            let d, ok = ldap::parse_dn(text);
            if f[2] == "ERR" { check(str("dn refused ", text), !ok); }
            else { check(str("dn ", f[1], " ", hex(ldap::dn_string(d)), " want ", f[2]), ok && ldap::dn_string(d) == unhex(f[2])); }
        } else if f[0] == "dncmp" {
            let a, oka = ldap::parse_dn(unhex(f[1]));
            let b, okb = ldap::parse_dn(unhex(f[2]));
            var got: u8[>..] = [];
            got.push(if ldap::dn_equal(a, b) { '1' } else { '0' });
            got.push(if ldap::dn_equal_fold(a, b) { '1' } else { '0' });
            got.push(if ldap::dn_ancestor_of(a, b) { '1' } else { '0' });
            got.push(if ldap::dn_ancestor_of_fold(a, b) { '1' } else { '0' });
            check(str("dncmp ", unhex(f[1]), " | ", unhex(f[2]), " ", got), oka && okb && got == f[3]);
        } else {
            check(str("unknown line ", f[0]), false);
        }
        kinds++;
    }
    check("all the vectors", kinds > 1700);
    print("goldap: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
