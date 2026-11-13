// kinit: gets alice's TGT from her realm's KDC and keeps it in a
// credential cache, as MIT's kinit does: with a password (read from
// stdin), a keytab (-k), or a certificate (-X, PKINIT); armored with FAST
// by another cache's TGT (-T). SPAKE is used by itself when the KDC
// offers it, the encrypted timestamp otherwise. Needs a KDC: the realm's
// KDCs are those of the krb5.conf given.
//
//   echo PASSWORD | goose examples/krb5/kinit.goose -- KRB5_CONF CCACHE alice@EXAMPLE.COM
//   goose examples/krb5/kinit.goose -- KRB5_CONF CCACHE -k KEYTAB host/client.example.com@EXAMPLE.COM
//   goose examples/krb5/kinit.goose -- KRB5_CONF CCACHE -X FILE:cert.pem,key.pem alice@EXAMPLE.COM
//   echo PASSWORD | goose examples/krb5/kinit.goose -- KRB5_CONF CCACHE -T ARMOR_CCACHE alice@EXAMPLE.COM
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
import gslib.krb5.pkinit;

fn fail(what: const u8[:], err: i64) {
    print("kinit: ", what, ": ", krb5::error_text(err));
    exit(1);
}

fn main() {
    let a = args();
    guard a.len == 4 || a.len == 6 else {
        print("usage: kinit KRB5_CONF CCACHE [-k KEYTAB | -X FILE:cert,key | -T ARMOR_CCACHE] PRINCIPAL");
        exit(2);
    }
    let cfg, cerr = krb5::config_load(a[1]);
    if cerr != krb5::OK { fail(a[1], cerr); }
    let ccache = str("FILE:", a[2]);
    let principal = a[a.len - 1];
    let opt = if a.len == 6 { a[3] } else { "" };

    if opt == "-k" {
        let kt, kerr = krb5::keytab_load(a[4]);
        if kerr != krb5::OK { fail(a[4], kerr); }
        let c, err = krb5::kinit_keytab(cfg, ccache, principal, kt);
        if err != krb5::OK { fail("kinit", err); }
    } else if opt == "-X" {
        let id, ierr = krb5::pkinit_load_identity(a[4], "");
        if ierr != krb5::OK { fail(a[4], ierr); }
        let c, err = krb5::kinit_identity(cfg, ccache, principal, id, "");
        if err != krb5::OK { fail("kinit", err); }
    } else {
        // The password: the first line of stdin.
        var pw: u8[>..] = [];
        guard read_line(pw) else { print("kinit: no password on stdin"); exit(2); }
        if opt == "-T" {
            let c, err = krb5::kinit_password_fast(cfg, ccache, principal, pw, str("FILE:", a[4]));
            if err != krb5::OK { fail("kinit", err); }
        } else if opt == "" {
            let c, err = krb5::kinit_password(cfg, ccache, principal, pw);
            if err != krb5::OK { fail("kinit", err); }
        } else {
            print("kinit: unknown option ", opt);
            exit(2);
        }
    }

    // What the cache now holds.
    let cc, lerr = krb5::ccache_load(ccache);
    if lerr != krb5::OK { fail(ccache, lerr); }
    print("Default principal: ", krb5::principal_string(cc.principal, cc.realm));
    for c in cc.creds {
        if krb5::is_config_cred(c) { continue; }
        print("  ", krb5::principal_string(c.server, c.server_realm), ", ", krb5::etype_name(c.key.etype), ", valid for ",
              c.endtime - c.starttime, " s");
    }
    let fast, okf = krb5::ccache_config(cc, "fast_avail", krb5::principal_string(krb5::name_join("krbtgt", cc.realm), cc.realm));
    if okf { print("the KDC does FAST: ", fast); }
}
