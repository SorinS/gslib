// krb5: kinit, kvno and klist on the krb5 package, for trying it and for
// scripts/interop.py, which runs it against MIT's KDC and tools. The
// configuration is $KRB5_CONFIG (else /etc/krb5.conf), the cache
// $KRB5CCNAME (else /tmp/krb5cc_<uid>).
//
//   krb5 kinit PRINCIPAL            the password from stdin's first line
//   krb5 kinit -k KEYTAB PRINCIPAL
//   krb5 kinit -T ARMOR_CACHE [-k KEYTAB] PRINCIPAL   armored with FAST by the cache's TGT
//   krb5 kvno [-gss] SERVICE        service/host[@REALM], or service@host with -gss
//   krb5 klist                      the cache
//   krb5 klist -k KEYTAB            the keytab
//   krb5 renew                      renews the cache's TGT
//
// Exit status 0 on success, 1 with the error on stderr.

import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.config;
import gslib.krb5.keytab;
import gslib.krb5.ccache;
import gslib.krb5.client;

fn fail(what: const u8[:], err: i64) {
    write_stderr(str("krb5: ", what, ": ", krb5::error_text(err), "\n"));
    exit(1);
}

fn time_text(t: i64) -> u8[>..] {
    var out: u8[>..] = [];
    if t == 0 { out.append("-"); return out; }
    var b: u8[>..] = [];
    krb5::put_ktime(b, t);
    out.append(b[2..]);
    return out;
}

fn flags_text(f: u32) -> u8[>..] {
    var out: u8[>..] = [];
    let bits: i64[13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    let chars = "FfPpDdiRIAHTO";
    for i in 13 { if f & krb5::flag(bits[i]) != 0 { out.push(chars[i]); } }
    return out;
}

fn klist(ccname: const u8[:]) {
    let cc, err = krb5::ccache_load(ccname);
    if err != krb5::OK { fail(ccname, err); }
    print("Ticket cache: ", ccname);
    print("Default principal: ", krb5::principal_string(cc.principal, cc.realm));
    for c in cc.creds {
        if krb5::is_config_cred(c) { continue; }
        print(time_text(c.starttime), "  ", time_text(c.endtime), "  ", krb5::principal_string(c.server, c.server_realm),
              "  ", krb5::etype_name(c.key.etype), "  ", flags_text(c.flags));
    }
}

fn klist_keytab(path: const u8[:]) {
    let es, err = krb5::keytab_load(path);
    if err != krb5::OK { fail(path, err); }
    print("Keytab name: FILE:", path);
    for e in es { print(e.kvno, " ", krb5::principal_string(e.name, e.realm), " (", krb5::etype_name(e.key.etype), ")"); }
}

fn kinit_done(c: const krb5::Credential&, err: i64) {
    if err != krb5::OK { fail("kinit", err); }
    print(krb5::principal_string(c.client, c.client_realm));
}

fn main() {
    let a = args();
    if a.len < 2 { write_stderr("usage: krb5 kinit|kvno|klist|renew ...\n"); exit(2); }
    let cfg, cerr = krb5::default_config();
    if cerr != krb5::OK { fail("krb5.conf", cerr); }
    let ccname = krb5::default_ccache_name();
    let cmd = a[1];
    if cmd == "kinit" {
        var keytab: u8[>..] = [];
        var armor: u8[>..] = [];
        var i = 2;
        while i + 1 < a.len && (a[i] == "-k" || a[i] == "-T") {
            if a[i] == "-k" { keytab.append(a[i + 1]); } else { armor.append(a[i + 1]); }
            i += 2;
        }
        if i != a.len - 1 { write_stderr("usage: krb5 kinit [-T ARMOR_CACHE] [-k KEYTAB] PRINCIPAL\n"); exit(2); }
        let principal = a[i];
        if keytab.len > 0 {
            let kt, kerr = krb5::keytab_load(keytab);
            if kerr != krb5::OK { fail(keytab, kerr); }
            if armor.len > 0 {
                let c, err = krb5::kinit_keytab_fast(cfg, ccname, principal, kt, armor);
                kinit_done(c, err);
            } else {
                let c, err = krb5::kinit_keytab(cfg, ccname, principal, kt);
                kinit_done(c, err);
            }
            return;
        }
        var pw: u8[>..] = [];
        read_line(pw);
        if armor.len > 0 {
            let c, err = krb5::kinit_password_fast(cfg, ccname, principal, pw, armor);
            kinit_done(c, err);
        } else {
            let c, err = krb5::kinit_password(cfg, ccname, principal, pw);
            kinit_done(c, err);
        }
        return;
    }
    if cmd == "kvno" {
        let gss = a.len == 4 && a[2] == "-gss";
        if a.len != 3 && !gss { write_stderr("usage: krb5 kvno [-gss] SERVICE\n"); exit(2); }
        let c, err = krb5::get_service_ticket_cached(cfg, ccname, a[a.len - 1], gss);
        if err != krb5::OK { fail("kvno", err); }
        let t, terr = krb5::decode_ticket(c.ticket);
        print(krb5::principal_string(c.server, c.server_realm), ": kvno = ", t.enc_part.kvno, ", ",
              krb5::etype_name(t.enc_part.etype));
        return;
    }
    if cmd == "klist" {
        if a.len == 4 && a[2] == "-k" { klist_keytab(a[3]); return; }
        klist(ccname);
        return;
    }
    if cmd == "renew" {
        let cc, err = krb5::ccache_load(ccname);
        if err != krb5::OK { fail(ccname, err); }
        let tgt, ok = krb5::ccache_find(cc, krb5::name_join("krbtgt", cc.realm), cc.realm, 0);
        if !ok { fail("renew", krb5::ERR_NO_CREDS); }
        let n, rerr = krb5::renew(cfg, tgt);
        if rerr != krb5::OK { fail("renew", rerr); }
        let next = krb5::ccache_add(cc, n);
        let serr = krb5::ccache_save(ccname, next);
        if serr != krb5::OK { fail(ccname, serr); }
        print("renewed until ", time_text(n.renew_till));
        return;
    }
    write_stderr(str("krb5: unknown command ", cmd, "\n"));
    exit(2);
}
