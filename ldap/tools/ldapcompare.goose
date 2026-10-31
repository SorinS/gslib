// goose-ldapcompare: OpenLDAP's ldapcompare on the ldap package.
//
//   goose-ldapcompare [options] [-z] dn attr:value | dn attr::base64value
//
// Prints TRUE or FALSE (nothing with -z) and exits 6 or 5, compareTrue's
// and compareFalse's codes, as ldapcompare does. The common options are
// cli's.
import std;
import os;
import base64;
import gslib from "../..";
import gslib.ldap;
import gslib.asn1;
import gslib.bignum;
import gslib.x509;
import gslib.tls;
import gslib.ldap.conn;
import gslib.ldap.ldif;
import gslib.ldap.dn;
import gslib.ldap.filter;
import .sysnet;
import .cli;

fn usage(o: const cli::Opts&) -> i32 {
    sysnet::eprint(str("usage: ", o.prog, " [options] [-z] dn <attr:value|attr::b64value>\nCompare options:\n  -z          quiet: print nothing\n", cli::COMMON_USAGE));
    return 2;
}

fn run() -> i32 {
    let a = args();
    var o = cli::opts("goose-ldapcompare");
    var quiet = false;
    var dn: u8[>..] = [];
    var ava: u8[>..] = [];
    var n = 0;
    var i = 1;
    while i < a.len {
        let w = a[i];
        let r = cli::common_flag(o, a, i);
        if r < 0 { return usage(o); }
        if r > 0 { continue; }
        if w == "-z" { quiet = true; i++; continue; }
        if w.len > 0 && w[0] == '-' { return usage(o); }
        if n == 0 { dn.append(w); } else if n == 1 { ava.append(w); } else { return usage(o); }
        n++;
        i++;
    }
    if n != 2 { return usage(o); }
    let colon = position(ava, ':');
    if colon <= 0 { return usage(o); }
    var value: u8[>..] = [];
    if colon + 1 < ava.len && ava[colon + 1] == ':' {
        if !base64::decode(value, ava[colon + 2..]) { return usage(o); }
    } else {
        value.append(ava[colon + 1..]);
    }
    if o.dry_run { return 0; }
    var l = cli::link();
    var cfg = tls::client_config("", "");
    var c = ldap::client();
    let code = cli::open(o, l, cfg, c);
    if code != 0 { return code as! i32; }
    var extra: u8[>..] = [];
    if !cli::controls(o, extra) { return 1; }
    var out: u8[>..] = [];
    var msgs: u8[>..] = [];
    let rc = cli::run(o, l, cfg, c, "ldap_compare", ldap::compare(c, dn, ava[..colon], value, out, extra), out, msgs,
                      "Compare Result");
    if !quiet {
        if rc == ldap::RESULT_COMPARE_TRUE { write_stdout("TRUE\n"); }
        else if rc == ldap::RESULT_COMPARE_FALSE { write_stdout("FALSE\n"); }
        else if rc < 200 { write_stdout("UNDEFINED\n"); }
    }
    cli::close(l, c);
    return cli::status(rc);
}

fn main() { exit(run()); }
