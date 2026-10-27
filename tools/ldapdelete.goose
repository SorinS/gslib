// goose-ldapdelete: OpenLDAP's ldapdelete on the ldap package.
//
//   goose-ldapdelete [options] [-r] [-c] [-f file] [dn...]
//
// Deletes each DN given, else each line of -f (or standard input). -r
// deletes the entries below a DN first, deepest first. The common
// options are cli's.
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
    sysnet::eprint(str("usage: ", o.prog, " [options] [-r] [-c] [-f file] [dn...]\nDelete options:\n  -r          delete recursively\n  -c          continue after errors\n  -f file     read the DNs from file\n", cli::COMMON_USAGE));
    return 2;
}

// The DNs below dn, deepest first.
fn below(o: const cli::Opts&, l: cli::Link&, cfg: const tls::ClientConfig&, c: ldap::Conn&, dn: const u8[:], found: u8[>..]&) -> i64 {
    var out: u8[>..] = [];
    var msgs: u8[>..] = [];
    let id = ldap::search(c, dn, ldap::SCOPE_SUB, "(objectClass=*)", "1.1", out);
    let code = cli::wait(o, l, cfg, c, id, out, msgs);
    if code != 0 { return code; }
    var depth: i64[>..] = [];
    var at: i64[>..] = [];
    var names: u8[>..] = [];
    var ends: i64[>..] = [];
    var pos = 0;
    loop {
        let m, ok = ldap::next_message(msgs, pos);
        if !ok { break; }
        if m.op == ldap::OP_SEARCH_DONE {
            // As ldapdelete -r: the search's failure said, and the entry
            // itself deleted all the same.
            let rc = ldap::result_code(msgs, m);
            if rc != 0 { sysnet::eprint(str("ldap_search: ", cli::err2string(rc), " (", rc, ")\n")); }
        }
        if m.op != ldap::OP_SEARCH_ENTRY { continue; }
        let e = ldap::entry_dn(msgs, m);
        let d, okd = ldap::parse_dn(e);
        at.push(names.len);
        names.append(e);
        ends.push(names.len);
        depth.push(if okd { d.rdns } else { 0 });
    }
    var idx: i64[>..] = [];
    for k in depth.len { idx.push(k); }
    sort(idx) { x, y => depth[x] > depth[y] };
    for k in idx {
        found.append(names[at[k]..ends[k]]);
        found.push('\n');
    }
    return 0;
}

fn run() -> i32 {
    let a = args();
    var o = cli::opts("goose-ldapdelete");
    var subtree = false;
    var file: u8[>..] = [];
    var dns: u8[>..] = [];
    var i = 1;
    while i < a.len {
        let w = a[i];
        let r = cli::common_flag(o, a, i);
        if r < 0 { return usage(o); }
        if r > 0 { continue; }
        if w == "-r" { subtree = true; i++; continue; }
        if w == "-f" && i + 1 < a.len { file.clear(); file.append(a[i + 1]); i += 2; continue; }
        if w.len > 0 && w[0] == '-' { return usage(o); }
        dns.append(w);
        dns.push('\n');
        i++;
    }
    if dns.len == 0 {
        var t: u8[>..] = [];
        if file.len > 0 { if !read_file(file, t) { return cli::fail(o, str("cannot read ", file)); } }
        else { read_stdin(t); }
        for ln in split(t, '\n') {
            let x = trim(ln);
            if x.len > 0 { dns.append(x); dns.push('\n'); }
        }
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
    var first_failure: i64 = 0;
    var out: u8[>..] = [];
    var msgs: u8[>..] = [];
    for dn in split(dns, '\n') {
        if dn.len == 0 { continue; }
        var targets: u8[>..] = [];
        if subtree && !o.dry_run {
            let rc = below(o, l, cfg, c, dn, targets);
            if rc != 0 {
                if first_failure == 0 { first_failure = rc; }
                if !o.continuous { break; }
                continue;
            }
        } else {
            targets.append(dn);
            targets.push('\n');
        }
        var stop = false;
        for t in split(targets, '\n') {
            if t.len == 0 { continue; }
            if o.verbose || o.dry_run { write_stdout(str(if o.dry_run { "!" } else { "" }, "deleting entry \"", t, "\"\n")); }
            if o.dry_run { continue; }
            msgs.clear();
            let rc = cli::run(o, l, cfg, c, "ldap_delete", ldap::delete(c, t, out, extra), out, msgs);
            if rc != 0 {
                if first_failure == 0 { first_failure = rc; }
                if !o.continuous || ldap::closed(c) { stop = true; break; }
            }
        }
        if stop { break; }
    }
    if !o.dry_run { cli::close(l, c); }
    return cli::status(first_failure);
}

fn main() { exit(run()); }
