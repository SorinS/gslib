// goose-ldapmodify (and goose-ldapadd, which is it with -a): OpenLDAP's
// ldapmodify on the ldap package.
//
//   goose-ldapmodify [options] [-a] [-c] [-f file]
//
// The LDIF of -f (else standard input) applied record by record: change
// records (add, delete, modify, modrdn) and plain entries, added with -a
// or replacing an entry's attributes without. A value "name:< file:///path"
// is read from the file. -c goes on after a failure; the exit status is
// the first failure's result code. The common options are cli's.
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
    sysnet::eprint(str("usage: ", o.prog, " [options] [-a] [-c] [-f file]\nModify options:\n  -a          add plain entries (the default for goose-ldapadd)\n  -c          continue after errors\n  -f file     read the LDIF from file, not standard input\n", cli::COMMON_USAGE));
    return 2;
}

fn run() -> i32 {
    let a = args();
    let base_name = if a.len > 0 { a[0] } else { "" };
    let adding = ends_with(base_name, "ldapadd");
    var o = cli::opts(if adding { "goose-ldapadd" } else { "goose-ldapmodify" });
    var default_add = adding;
    var file: u8[>..] = [];
    var i = 1;
    while i < a.len {
        let w = a[i];
        let r = cli::common_flag(o, a, i);
        if r < 0 { return usage(o); }
        if r > 0 { continue; }
        if w == "-a" { default_add = true; i++; continue; }
        if w == "-f" && i + 1 < a.len { file.clear(); file.append(a[i + 1]); i += 2; continue; }
        return usage(o);
    }
    var text: u8[>..] = [];
    if file.len > 0 {
        if !read_file(file, text) { return cli::fail(o, str("cannot read ", file)); }
    } else {
        read_stdin(text);
    }

    var l = cli::link();
    var cfg = tls::client_config("", "");
    var c = ldap::client();
    if !o.dry_run {
        let code = cli::open(o, l, cfg, c);
        if code != 0 { return code as! i32; }
    }
    var extra: u8[>..] = [];
    if !cli::controls(o, extra) { return 1; }

    var pos = 0;
    var lineno = 0;
    var r = ldap::empty_record();
    var err: u8[>..] = [];
    var failure: i64 = 0;          // the last one's code, as ldapmodify exits with it
    var out: u8[>..] = [];
    var msgs: u8[>..] = [];
    loop {
        err.clear();
        let k = ldap::next_record(text, pos, lineno, r, err, default_add) { url, value =>
            if starts_with(url, "file://") { read_file(url[7..], value) } else { false }
        };
        if k == 0 { break; }
        if k < 0 {
            let at = if r.error_line > 0 { r.error_line } else { r.line };
            if starts_with(err, "modify operation type is missing") {
                sysnet::eprint(str("ldapmodify: ", err, " at line ", at, ", entry \"", r.dn, "\"\n"));
            } else {
                sysnet::eprint(str("ldapmodify: ", err, " (line ", at, ", entry \"", r.dn, "\")\n"));
            }
            failure = ldap::RESULT_PARAM_ERROR;
            if !o.continuous { break; }
            continue;
        }
        var ctl: u8[>..] = [];
        ctl.append(extra);
        ctl.append(r.controls);
        var what: const u8[:] = "";
        var op: const u8[:] = "";
        var id: i64 = 0;
        if r.kind == ldap::CHANGE_ADD { what = "adding new entry"; op = "ldap_add"; }
        else if r.kind == ldap::CHANGE_DELETE { what = "deleting entry"; op = "ldap_delete"; }
        else if r.kind == ldap::CHANGE_MODDN { what = "modifying rdn of entry"; op = "ldap_rename"; }
        else { what = "modifying entry"; op = "ldap_modify"; }
        write_stdout(str(if o.dry_run { "!" } else { "" }, what, " \"", r.dn, "\"\n"));
        if o.dry_run { write_stdout("\n"); continue; }
        if r.kind == ldap::CHANGE_ADD { id = ldap::add(c, r.dn, r.body, out, ctl); }
        else if r.kind == ldap::CHANGE_DELETE { id = ldap::delete(c, r.dn, out, ctl); }
        else if r.kind == ldap::CHANGE_MODDN { id = ldap::modify_dn(c, r.dn, r.new_rdn, r.delete_old, r.new_superior, out, ctl); }
        else { id = ldap::modify(c, r.dn, r.body, out, ctl); }
        msgs.clear();
        let rc = cli::run(o, l, cfg, c, op, id, out, msgs);
        write_stdout("\n");
        if rc != 0 {
            failure = rc;
            if !o.continuous || ldap::closed(c) { break; }
        }
    }
    if !o.dry_run { cli::close(l, c); }
    return cli::status(failure);
}

fn main() { exit(run()); }
