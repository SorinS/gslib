// The string forms: LDIF written (base64 where LDIF needs it, folding)
// and read (each change type, controls, URL values through the caller's
// block, the errors and the lines they are on); LDAP URLs; the inputs
// go-ldap gets wrong, which this refuses or reads as RFC 4514 and 4515
// say; and DIGEST-MD5 against RFC 2831's example.
import std;
import ldap from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import ldap.ldif;
import ldap.url;
import ldap.dn;
import ldap.filter;
import ldap.conn;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn hex(b: const u8[:]) -> u8[>..] {
    var o: u8[>..] = [];
    for x in b { format_int(o, x, 16, 2, '0'); }
    return o;
}

fn line(name: const u8[:], v: const u8[:], wrap: i64 = 78) -> u8[>..] {
    var o: u8[>..] = [];
    ldap::ldif_line(o, name, v, wrap);
    return o;
}

fn writing() {
    check("plain", line("cn", "Alice") == "cn: Alice\n");
    check("empty", line("description", "") == "description:\n");
    check("leading space", line("cn", " a") == "cn:: IGE=\n");
    check("leading colon", line("cn", ":a") == "cn:: OmE=\n");
    check("leading <", line("cn", "<a") == "cn:: PGE=\n");
    check("trailing space", line("cn", "a ") == "cn:: YSA=\n");
    check("utf-8", line("cn", "é") == "cn:: w6k=\n");
    check("newline", line("cn", "a\nb") == "cn:: YQpi\n");
    check("inner colon and space", line("cn", "a: b") == "cn: a: b\n");
    check("userPassword", line("userPassword", "secret") == "userPassword:: c2VjcmV0\n");
    let long = line("description", "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");
    let parts = split(long, '\n');
    check("folded at 78", parts.len == 3 && parts[0].len == 78 && parts[1].len == 36 && parts[1][0] == ' ');
    check("not folded", line("description", "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", 0).len == 114);
}

fn read_all(text: const u8[:], default_add: bool, out: u8[>..]&) -> i64 {
    var pos = 0;
    var lineno = 0;
    var r = ldap::empty_record();
    var err: u8[>..] = [];
    var n = 0;
    loop {
        let k = ldap::next_record(text, pos, lineno, r, err, default_add) { url, value =>
            if url == "file:///photo" { value.append("\x00\x01"); true } else { false }
        };
        if k < 0 { format(out, "error line ", if r.error_line > 0 { r.error_line } else { r.line }, ": ", err, "\n"); return -1; }
        if k == 0 { break; }
        format(out, r.line, " ", r.kind, " ", r.dn, " ", hex(r.body), " ", hex(r.controls), " ", r.new_rdn, " ", r.delete_old, " ",
               r.has_new_superior, " ", r.new_superior, "\n");
        n++;
    }
    return n;
}

fn reading() {
    var out: u8[>..] = [];
    check("add record", read_all("version: 1\n\n# a comment\n# more\ndn: cn=a,dc=x\nobjectClass: top\ncn: a\nobjectclass: person\njpegPhoto:< file:///photo\n", true, out) == 1);
    var want: u8[>..] = [];
    var attrs: u8[>..] = [];
    var v: u8[>..] = [];
    ldap::put_value(v, "top");
    ldap::put_value(v, "person");
    ldap::put_attribute(attrs, "objectClass", v);
    v.clear(); ldap::put_value(v, "a"); ldap::put_attribute(attrs, "cn", v);
    v.clear(); ldap::put_value(v, "\x00\x01"); ldap::put_attribute(attrs, "jpegPhoto", v);
    format(want, "5 0 cn=a,dc=x ", hex(attrs), "  ", " false false \n");
    check(str("add grouped by name ", out), out == want);

    out.clear();
    check(str("plain records refused without -a ", out), read_all("dn: cn=a,dc=x\nsn: b\nsn: c\n", false, out) == -1 &&
                                                         find(out, "error line 2: modify operation type is missing") >= 0);
    var ch: u8[>..] = [];

    out.clear();
    let mods = "dn: cn=a,dc=x\ncontrol: 1.2.840.113556.1.4.805 true\ncontrol: 1.2.3 false:: AAE=\nchangetype: modify\nadd: mail\nmail: a@x\nmail: b@\n x\n-\ndelete: description\n-\nreplace: sn\nsn: z\n-\nincrement: uidNumber\nuidNumber: 1\n";
    check("modify record", read_all(mods, false, out) == 1);
    ch.clear();
    v.clear(); ldap::put_value(v, "a@x"); ldap::put_value(v, "b@x");
    ldap::put_change(ch, ldap::MOD_ADD, "mail", v);
    ldap::put_change(ch, ldap::MOD_DELETE, "description", "");
    v.clear(); ldap::put_value(v, "z");
    ldap::put_change(ch, ldap::MOD_REPLACE, "sn", v);
    v.clear(); ldap::put_value(v, "1");
    ldap::put_change(ch, ldap::MOD_INCREMENT, "uidNumber", v);
    var ctl: u8[>..] = [];
    ldap::put_control(ctl, ldap::CONTROL_SUBTREE_DELETE, true, "", false);
    ldap::put_control(ctl, "1.2.3", false, "\x00\x01", true);
    want.clear();
    format(want, "1 2 cn=a,dc=x ", hex(ch), " ", hex(ctl), "  false false \n");
    check(str("modify body ", out), out == want);

    out.clear();
    let more = "dn: cn=a,dc=x\nchangetype: delete\n\ndn: cn=a,dc=x\nchangetype: modrdn\nnewrdn: cn=b\ndeleteoldrdn: 1\nnewsuperior: ou=y,dc=x\n\ndn:: Y249w6ksZGM9eA==\r\nchangetype: moddn\r\nnewrdn: cn=c\r\ndeleteoldrdn: 0\r\n";
    check("three records", read_all(more, false, out) == 3);
    let lines = split(out, '\n');
    check("delete", lines[0] == "1 1 cn=a,dc=x    false false ");
    check("modrdn", lines[1] == "4 3 cn=a,dc=x   cn=b true true ou=y,dc=x");
    check("base64 dn, CRLF", lines[2] == "10 3 cn=é,dc=x   cn=c false false ");

    // Errors, with their lines.
    let bad = [
        "dn: cn=a\nchangetype: frobnicate\n",
        "cn: a\n",
        "dn: cn=a\nchangetype: modify\nfrob: x\n",
        "dn: cn=a\nchangetype: modify\nadd: mail\ncn: x\n",
        "dn: cn=a\nchangetype: modify\nincrement: n\nn: 1\nn: 2\n",
        "dn: cn=a\nchangetype: delete\ncn: a\n",
        "dn: cn=a\nchangetype: modrdn\ndeleteoldrdn: 1\n",
        "dn: cn=a\nchangetype: modrdn\nnewrdn: cn=b\ndeleteoldrdn: 2\n",
        "dn: cn=a\ncn:: !!!\n",
        "dn: cn=a\ncn:< file:///nope\n",
        "dn: cn=a\ncn\n",
        " folded first\n",
        "version: 2\n",
        "dn: cn=a,dc=x\nchangetype: add\n",
    ];
    for b in bad {
        out.clear();
        check(str("refused: ", b), read_all(b, true, out) == -1);
    }
    out.clear();
    let k = read_all("dn: cn=a\ncn: a\n\n\n# c\ndn: cn=b\nchangetype: frob\n", true, out);
    check(str("error line ", out), k == -1 && find(out, "error line 7: unknown changetype \"frob\"") >= 0);
}

fn urls() {
    let u, ok = ldap::parse_url("ldap://ldap.example.com");
    check("ldap default port", ok && u.scheme == "ldap" && u.host == "ldap.example.com" && u.port == 389 && u.scope == -1);
    let s, oks = ldap::parse_url("LDAPS://ldap.example.com:3636/");
    check("ldaps port", oks && s.scheme == "ldaps" && s.port == 3636 && s.dn.len == 0);
    let d, okd = ldap::parse_url("ldaps://h");
    check("ldaps default", okd && d.port == 636);
    let i, oki = ldap::parse_url("ldapi://%2Ftmp%2Fldap%2Fsock");
    check("ldapi path", oki && i.scheme == "ldapi" && i.host == "/tmp/ldap/sock" && i.port == 0);
    let f, okf = ldap::parse_url("ldap://h/ou=a%2Cdc=x?cn,mail?one?(cn=a%20b)?!x-ext");
    check("all parts", okf && f.dn == "ou=a,dc=x" && f.attrs == "cn,mail" && f.scope == ldap::SCOPE_ONE && f.filter == "(cn=a b)" && f.exts == "!x-ext");
    let six, ok6 = ldap::parse_url("ldap://[2001:db8::1]:10389/??sub");
    check("ipv6", ok6 && six.host == "2001:db8::1" && six.port == 10389 && six.scope == ldap::SCOPE_SUB);
    let e, oke = ldap::parse_url("ldap://h/??children");
    check("children scope", oke && e.scope == ldap::SCOPE_CHILDREN);
    let bad = ["http://h", "ldap:/h", "ldap://h:0", "ldap://h:65536", "ldap://h:x", "ldap://[::1", "ldap://h/%zz", "ldap://h/??wide",
               "ldap://h/a?b?base?c?d?e", "://h"];
    for b in bad {
        let x, okx = ldap::parse_url(b);
        check(str("bad url ", b), !okx);
    }
}

// Where go-ldap and RFC 4514/4515 part, this follows the RFCs.
fn go_quirks() {
    let filters = ["(!(cn=a)x", "(&(cn=a)x", "(|(cn=a)x", "(!cn=a)", "((cn=a)x"];
    for f in filters {
        let b, ok = ldap::compile(f);
        check(str("filter refused, go-ldap takes it: ", f), !ok);
    }
    let d, ok = ldap::parse_dn("cn=a=b,dc=x");
    check("= in a value", ok && d.avas.len == 2 && ldap::ava_type(d, d.avas[0]) == "cn" && ldap::ava_value(d, d.avas[0]) == "a=b");
    let e, oke = ldap::parse_dn("cn=a,ou=");
    check("empty last value kept", oke && e.rdns == 2 && ldap::ava_value(e, e.avas[1]).len == 0);
    let dns = ["cn=a,", "cn=a+", "cn=\\", "cn=a;"];
    for s in dns {
        let x, okx = ldap::parse_dn(s);
        check(str("dn refused, go-ldap takes it: ", s), !okx);
    }
    check("dn error text", ldap::dn_error("cn=a,dc") == "DN ended with incomplete type, value pair");
    check("escape dn value", ldap::escape_dn_value(" a#b,c\x01 ") == "\\ a\\#b\\,c\\01\\ ");
    // Filters nested past the limit.
    var deep: u8[>..] = [];
    for i in 300 { deep.append("(!"); }
    deep.append("(cn=a)");
    for i in 300 { deep.push(')'); }
    let df, okdf = ldap::compile(deep);
    check("too deep", !okdf);
    var fine: u8[>..] = [];
    for i in 100 { fine.append("(!"); }
    fine.append("(cn=a)");
    for i in 100 { fine.push(')'); }
    let ff, okff = ldap::compile(fine);
    let back, okb = ldap::decompile(ff);
    check("deep enough", okff && okb && back == fine);
    // A long filter, whose lengths take more than one octet at each level.
    var wide: u8[>..] = [];
    wide.append("(&");
    for i in 50 { format(wide, "(cn=", i, "xxxxxxxxxxxxxxxxxxxx)"); }
    wide.push(')');
    let wf, okw = ldap::compile(wide);
    let t, okt = asn1::parse(wf);
    let wb, okwb = ldap::decompile(wf);
    check("long set", okw && okt && wf[1] == 0x82 && okwb && wb == wide);
}

fn digest() {
    // RFC 2831 §4.
    let challenge = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8";
    let r, ok = ldap::digest_md5_response(challenge, "elwood.innosoft.com", "chris", "secret", "OA6MHXh6VqTrRk", "imap");
    check(str("rfc 2831 response ", r), ok && find(r, "response=d388dad90d4bbd760a152321f2143af7") >= 0);
    check("fields", ok && starts_with(r, "username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",nc=00000001,qop=auth,digest-uri=\"imap/elwood.innosoft.com\",") &&
                    ends_with(r, ",charset=utf-8"));
    let x, okx = ldap::digest_md5_response("realm=\"r\",qop=\"auth-int\"", "h", "u", "p", "c");
    check("no nonce", !okx);
    let y, oky = ldap::digest_md5_response("nonce=\"n\",qop=\"auth-conf\"", "h", "u", "p", "c");
    check("auth-conf only", !oky);
    let z, okz = ldap::digest_md5_response("nonce=\"n\",qop=\"auth-conf,auth\"", "h", "u", "p", "c");
    check("auth in a list", okz);
}

fn main() {
    writing();
    reading();
    urls();
    go_quirks();
    digest();
    print("text: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
