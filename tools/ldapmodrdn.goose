// goose-ldapmodrdn: OpenLDAP's ldapmodrdn on the ldap package.
//
//   goose-ldapmodrdn [options] [-r] [-s newsuperior] [-c] [-f file] [dn newrdn]
//
// Renames dn to newrdn (pairs of lines from -f, or standard input,
// without them); -r deletes the old RDN's values, -s moves the entry
// under a new superior. The common options are cli's.
import std;
import os;
import base64;
import ldap from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509 from "../../x509goose.git";
import tls from "../../tlsgoose.git";
import ldap.conn;
import ldap.ldif;
import ldap.dn;
import ldap.filter;
import .sysnet;
import .cli;

fn usage(o: const cli::Opts&) -> i32 {
    sysnet::eprint(str("usage: ", o.prog, " [options] [-r] [-s newsuperior] [-c] [-f file] [dn newrdn]\nRename options:\n  -r          remove the old RDN's values\n  -s newsup   the new superior entry\n  -c          continue after errors\n  -f file     read DN and new RDN lines from file\n", cli::COMMON_USAGE));
    return 2;
}

fn run() -> i32 {
    let a = args();
    var o = cli::opts("goose-ldapmodrdn");
    var remove = false;
    var newsup: u8[>..] = [];
    var file: u8[>..] = [];
    var pairs: u8[>..] = [];
    var n = 0;
    var i = 1;
    while i < a.len {
        let w = a[i];
        let r = cli::common_flag(o, a, i);
        if r < 0 { return usage(o); }
        if r > 0 { continue; }
        if w == "-r" { remove = true; i++; continue; }
        if w == "-s" && i + 1 < a.len { newsup.clear(); newsup.append(a[i + 1]); i += 2; continue; }
        if w == "-f" && i + 1 < a.len { file.clear(); file.append(a[i + 1]); i += 2; continue; }
        if w.len > 0 && w[0] == '-' { return usage(o); }
        pairs.append(w);
        pairs.push('\n');
        n++;
        i++;
    }
    if n == 0 {
        var t: u8[>..] = [];
        if file.len > 0 { if !read_file(file, t) { return cli::fail(o, str("cannot read ", file)); } }
        else { read_stdin(t); }
        for ln in split(t, '\n') {
            let x = trim(ln);
            if x.len > 0 { pairs.append(x); pairs.push('\n'); n++; }
        }
    }
    if n % 2 != 0 { return usage(o); }
    var l = cli::link();
    var cfg = tls::client_config("", "");
    var c = ldap::client();
    let code = cli::open(o, l, cfg, c);
    if code != 0 { return code as! i32; }
    var extra: u8[>..] = [];
    if !cli::controls(o, extra) { return 1; }
    var first_failure: i64 = 0;
    var out: u8[>..] = [];
    var msgs: u8[>..] = [];
    let items = split(pairs, '\n');
    var k = 0;
    while k + 1 < items.len {
        let dn = items[k];
        let rdn = items[k + 1];
        k += 2;
        if dn.len == 0 { continue; }
        if o.verbose { write_stdout(str("Renaming \"", dn, "\"\n\tnew rdn=\"", rdn, "\" (", if remove { "delete" } else { "keep" }, " old rdn)\n")); }
        msgs.clear();
        let rc = cli::run(o, l, cfg, c, "ldap_rename", ldap::modify_dn(c, dn, rdn, remove, newsup, out, extra), out, msgs,
                          "Rename Result");
        if rc != 0 {
            if first_failure == 0 { first_failure = rc; }
            if !o.continuous || ldap::closed(c) { break; }
        }
    }
    cli::close(l, c);
    return cli::status(first_failure);
}

fn main() { exit(run()); }
