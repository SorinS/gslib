// goose-ldapwhoami: OpenLDAP's ldapwhoami on the ldap package: binds, then
// asks the server who it took the client to be (RFC 4532) and prints it,
// "anonymous" for nobody. The common options are cli's.
import std;
import os;
import base64;
import gslib from "../../..";
import gslib.net.ldap;
import gslib.encoding.asn1;
import gslib.crypto.bignum;
import gslib.crypto.x509;
import gslib.crypto.tls;
import gslib.net.ldap.conn;
import gslib.net.ldap.ldif;
import gslib.net.ldap.dn;
import gslib.net.ldap.filter;
import .sysnet;
import .cli;

fn usage(o: const cli::Opts&) -> i32 {
    sysnet::eprint(str("usage: ", o.prog, " [options]\n", cli::COMMON_USAGE));
    return 2;
}

fn run() -> i32 {
    let a = args();
    var o = cli::opts("goose-ldapwhoami");
    var i = 1;
    while i < a.len {
        let r = cli::common_flag(o, a, i);
        if r <= 0 { return usage(o); }
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
    let id = ldap::who_am_i(c, out, extra);
    let rc = cli::run(o, l, cfg, c, "ldap_extended_operation", id, out, msgs);
    if rc == 0 {
        let m, ok = cli::response(msgs, id);
        let v, okv = ldap::response_value(msgs, m);
        write_stdout(if v.len > 0 { v } else { "anonymous" });
        write_stdout("\n");
    }
    cli::close(l, c);
    return cli::status(rc);
}

fn main() { exit(run()); }
