// Fuzz target: krb5_files. The first byte picks:
//   0  a keytab (MIT format, versions 1 and 2): parsed, encoded again and
//      read back, and the lookups a service and kinit -k make;
//   1  a credential cache (FILE: formats 1-4): parsed, encoded again and
//      read back, credential and configuration lookups, entries added,
//      and each credential's ticket decoded as a client would send it.

import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ccache;

fn keytab(b: const u8[:]) {
    let kt, err = krb5::keytab_parse(b);
    var out: u8[>..] = [];
    krb5::keytab_encode(out, kt);
    let kt2, err2 = krb5::keytab_parse(out);
    let prefer: i32[3] = [18, 17, 23];
    for e in kt {
        let k, kvno, ke = krb5::keytab_key(kt, e.name, e.realm, e.key.etype, 0);
        let k2, kvno2, ke2 = krb5::keytab_key(kt, e.name, e.realm, 0, e.kvno);
        let ets = krb5::keytab_etypes(kt, e.name, e.realm, prefer);
        let ps = krb5::principal_string(e.name, e.realm);
        let parts = krb5::name_parts(e.name);
    }
}

fn ccache(b: const u8[:]) {
    let cc, err = krb5::ccache_parse(b);
    if err != krb5::OK { return; }
    var out: u8[>..] = [];
    krb5::ccache_encode(out, cc);
    let cc2, err2 = krb5::ccache_parse(out);
    let cfg, has = krb5::ccache_config(cc, "fast_avail", "");
    let cc3 = krb5::ccache_with_config(cc, "pa_type", "", "2");
    let cc4 = krb5::ccache_with_offset(cc3, 5);
    var out2: u8[>..] = [];
    krb5::ccache_encode(out2, cc4);
    for c in cc.creds {
        let f, ok = krb5::ccache_find(cc, c.server, c.server_realm, 0);
        let f2, ok2 = krb5::ccache_find(cc, c.server, c.server_realm, 1800000000);
        let cc5 = krb5::ccache_add(cc, c);
        let t, te = krb5::decode_ticket(c.ticket);
        if c.second_ticket.len > 0 { let t2, te2 = krb5::decode_ticket(c.second_ticket); }
        let cs = krb5::principal_string(c.client, c.client_realm);
        let ss = krb5::principal_string(c.server, c.server_realm);
        let p0 = krb5::name_part(c.server, 0);
        let p1 = krb5::name_part(c.server, 1);
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let rest = data[1..];
    if data[0] % 2 == 0 { keytab(rest); } else { ccache(rest); }
    return 0;
}

fn main() {}
