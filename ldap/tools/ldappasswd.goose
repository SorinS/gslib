// goose-ldappasswd: OpenLDAP's ldappasswd on the ldap package: the
// Password Modify operation (RFC 3062).
//
//   goose-ldappasswd [options] [-a oldpw | -A | -t file] [-s newpw | -S | -T file] [user]
//
// Without a user, the bound user's password changes; without a new
// password the server makes one up, which is printed. The common options
// are cli's.
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
    sysnet::eprint(str("usage: ", o.prog, " [options] [user]\nPassword options:\n  -a old      the old password\n  -A          prompt for the old password\n  -t file     read the old password from file\n  -s new      the new password\n  -S          prompt for the new password\n  -T file     read the new password from file\n", cli::COMMON_USAGE));
    return 2;
}

fn run() -> i32 {
    let a = args();
    var o = cli::opts("goose-ldappasswd");
    var old: u8[>..] = [];
    var new: u8[>..] = [];
    var ask_old = false;
    var ask_new = false;
    var user: u8[>..] = [];
    var i = 1;
    while i < a.len {
        let w = a[i];
        let r = cli::common_flag(o, a, i);
        if r < 0 { return usage(o); }
        if r > 0 { continue; }
        if w == "-A" { ask_old = true; i++; continue; }
        if w == "-S" { ask_new = true; i++; continue; }
        if (w == "-a" || w == "-s" || w == "-t" || w == "-T") && i + 1 < a.len {
            let v = a[i + 1];
            i += 2;
            if w == "-a" { old.clear(); old.append(v); }
            else if w == "-s" { new.clear(); new.append(v); }
            else {
                var t: u8[>..] = [];
                if !read_file(v, t) { return cli::fail(o, str("cannot read ", v)); }
                if w == "-t" { old.clear(); old.append(t); } else { new.clear(); new.append(t); }
            }
            continue;
        }
        if w.len > 0 && w[0] == '-' { return usage(o); }
        user.clear();
        user.append(w);
        i++;
    }
    if ask_old {
        let p, ok = sysnet::secret("Old password: ");
        if !ok { return cli::fail(o, "cannot read the password"); }
        old.clear();
        old.append(p);
    }
    if ask_new {
        let p, ok = sysnet::secret("New password: ");
        let q, ok2 = sysnet::secret("Re-enter new password: ");
        if !ok || !ok2 { return cli::fail(o, "cannot read the password"); }
        if p != q { sysnet::eprint("passwords do not match\n"); return 1; }
        new.clear();
        new.append(p);
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
    let id = ldap::password_modify(c, user, old, new, out, extra);
    let rc = cli::run(o, l, cfg, c, "ldap_passwd", id, out, msgs, "Result");
    if rc == 0 {
        let m, ok = cli::response(msgs, id);
        let gen, okg = ldap::generated_password(msgs, m);
        if okg { write_stdout(str("New password: ", gen, "\n")); }
    }
    cli::close(l, c);
    // As ldappasswd exits: 1 for any failure.
    return if rc == 0 { 0 } else { 1 };
}

fn main() { exit(run()); }
