// krb5.keytab and krb5.ccache against files MIT's tools wrote (go-krb5's
// test data, in test/vectors/files.txt): the keys in testuser1's keytab
// are our string-to-key of its password; every keytab survives our
// encoding; the cache reads as go-krb5 reads it and encodes back to the
// same bytes; then holes, version 1, saving, and malformed files.

import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ccache;
import tv;

fn same_entries(what: const u8[:], a: const krb5::KeytabEntry[:], b: const krb5::KeytabEntry[:]) {
    var na = 0;
    for x in a { na++; }
    var nb = 0;
    for y in b {
        var k = 0;
        for x in a {
            if k == nb {
                tv::check(str(what, " entry ", k), x.name == y.name && x.realm == y.realm && x.name_type == y.name_type &&
                          x.timestamp == y.timestamp && x.kvno == y.kvno && x.key.etype == y.key.etype &&
                          x.key.value == y.key.value);
            }
            k++;
        }
        nb++;
    }
    tv::check_int(str(what, " entries"), nb, na);
}

fn keytabs() {
    var n = 0;
    tv::each_row("vectors/files.txt") { r: tv::Row& =>
        let name = r.next();
        let b = tv::hex(r.next());
        if !name.starts_with("CCACHE") {
            n++;
            let es, err = krb5::keytab_parse(b);
            tv::check_int(str("parse ", name), err, krb5::OK);
            var out: u8[>..] = [];
            krb5::keytab_encode(out, es);
            let back, err2 = krb5::keytab_parse(out);
            tv::check_int(str("reparse ", name), err2, krb5::OK);
            same_entries(name, es, back);
        }
        if name == "KEYTAB_TESTUSER1_TEST_GOKRB5" {
            // MIT's ktutil, given "passwordvalue" for each type.
            let es, err = krb5::keytab_parse(b);
            var checked = 0;
            for e in es {
                tv::check_eq("testuser1 name", e.name, "testuser1");
                tv::check_eq("testuser1 realm", e.realm, "TEST.GOKRB5");
                if krb5::etype_supported(e.key.etype) {
                    let k, kerr = krb5::string_to_key(e.key.etype, "passwordvalue", "TEST.GOKRB5testuser1");
                    tv::check(str("testuser1 key ", e.key.etype), kerr == krb5::OK && k.value == e.key.value);
                    checked++;
                }
            }
            tv::check("testuser1 types", checked >= 4);
            let k, kv, kerr = krb5::keytab_key(es, "testuser1", "TEST.GOKRB5", krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 0);
            tv::check("keytab_key", kerr == krb5::OK && k.value.len == 32 && kv >= 1);
            let k2, kv2, kerr2 = krb5::keytab_key(es, "testuser1", "OTHER.REALM", krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 0);
            tv::check_int("keytab_key other realm", kerr2, krb5::ERR_NO_KEY);
            let k3, kv3, kerr3 = krb5::keytab_key(es, "testuser1", "TEST.GOKRB5", krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 250);
            tv::check_int("keytab_key missing kvno", kerr3, krb5::ERR_NO_KEY);
        }
        if name == "HTTP_KEYTAB" {
            let es, err = krb5::keytab_parse(b);
            for e in es { tv::check("HTTP keytab name", e.name == "HTTP/host.test.gokrb5" && e.name_type == krb5::NT_PRINCIPAL); }
        }
    };
    tv::check_int("keytabs read", n, 10);
}

fn ccache() {
    tv::each_row("vectors/files.txt") { r: tv::Row& =>
        let name = r.next();
        let b = tv::hex(r.next());
        if name != "CCACHE_TEST" { return; }
        let cc, err = krb5::ccache_parse(b);
        tv::check_int("ccache parse", err, krb5::OK);
        tv::check_int("ccache version", cc.version, 4);
        tv::check("ccache offset", cc.has_time_offset);
        tv::check_eq("ccache realm", cc.realm, "TEST.GOKRB5");
        tv::check_eq("ccache principal", cc.principal, "testuser1");
        var n = 0;
        for c in cc.creds { n++; }
        tv::check_int("ccache creds", n, 3);
        let tgt, ok = krb5::ccache_find(cc, "krbtgt/TEST.GOKRB5", "TEST.GOKRB5", 0);
        tv::check("ccache has the TGT", ok && tgt.server_type == krb5::NT_SRV_INST);
        let t, terr = krb5::decode_ticket(tgt.ticket);
        tv::check("TGT ticket decodes", terr == krb5::OK && t.sname.name == "krbtgt/TEST.GOKRB5");
        let http, ok2 = krb5::ccache_find(cc, "HTTP/host.test.gokrb5", "TEST.GOKRB5", 0);
        tv::check("ccache has HTTP", ok2 && http.client == "testuser1");
        let none, ok3 = krb5::ccache_find(cc, "HTTP/host.test.gokrb5", "TEST.GOKRB5", 4000000000);
        tv::check("expired is not found", !ok3);
        var out: u8[>..] = [];
        krb5::ccache_encode(out, cc);
        tv::check_hex("ccache re-encodes", out, tv::to_hex(b));
        // Version 3 has the encryption type twice; as version 3 the same
        // cache is longer by two bytes per credential, and reads the same.
        let cc2 = krb5::ccache_add(cc, tgt);
        var m = 0;
        for c in cc2.creds { m++; }
        tv::check_int("ccache_add replaces", m, 3);
    };
}

// A version 1 keytab (native byte order, the realm counted, no name type)
// and holes in a version 2 one.
fn odd_keytabs() {
    let le = krb5::native_le();
    var v1: u8[>..] = [5, 1];
    var e: u8[>..] = [];
    fn u16n(out: u8[>..]&, v: u32) { if le { out.push(v as! u8); out.push((v >> 8) as! u8); } else { krb5::put_u16(out, v); } }
    fn u32n(out: u8[>..]&, v: u32) {
        if le { out.push(v as! u8); out.push((v >> 8) as! u8); out.push((v >> 16) as! u8); out.push((v >> 24) as! u8); }
        else { krb5::put_u32(out, v); }
    }
    u16n(e, 3);                   // realm + 2 components
    u16n(e, 1); e.append("R");
    u16n(e, 4); e.append("host");
    u16n(e, 1); e.append("h");
    u32n(e, 1234);                // timestamp
    e.push(7);                    // kvno
    u16n(e, 23);
    u16n(e, 16);
    for i in 16 { e.push(i as! u8); }
    u32n(v1, e.len as! u32);
    v1.append(e);
    let es, err = krb5::keytab_parse(v1);
    tv::check_int("v1 parse", err, krb5::OK);
    for x in es { tv::check("v1 entry", x.name == "host/h" && x.realm == "R" && x.kvno == 7 && x.key.etype == 23 && x.timestamp == 1234); }

    // A hole, an entry with a 32-bit kvno, and a record longer than its entry.
    let k = krb5::make_key(17, "0123456789abcdef");
    var list: krb5::KeytabEntry[>..] = [];
    list.push(krb5::KeytabEntry { name_type: 1, name: "u", realm: "R", timestamp: 5, kvno: 300, key: k });
    var b: u8[>..] = [];
    krb5::keytab_encode(b, list);
    var holed: u8[>..] = [5, 2];
    krb5::put_u32(holed, 0xfffffff8);   // -8: a hole of 8
    for i in 8 { holed.push(0); }
    // The entry, its record 3 bytes longer.
    let rec = b[6..];
    krb5::put_u32(holed, (rec.len + 3) as! u32);
    holed.append(rec);
    holed.push(0); holed.push(0); holed.push(0);
    let hs, herr = krb5::keytab_parse(holed);
    tv::check_int("holes parse", herr, krb5::OK);
    var hn = 0;
    for x in hs { hn++; tv::check("32-bit kvno", x.kvno == 300); }
    tv::check_int("holes entries", hn, 1);

    // Truncations fail cleanly; a bad version is refused.
    for n in 2..b.len {
        let t, terr = krb5::keytab_parse(b[..n]);
        tv::check(str("truncated keytab ", n), terr == krb5::ERR_MALFORMED || (terr == krb5::OK && n - 2 < 4));
    }
    let bad: u8[2] = [5, 3];
    let bt, berr = krb5::keytab_parse(bad);
    tv::check_int("keytab version 3", berr, krb5::ERR_FORMAT);
}

fn saving() {
    let path = "/tmp/krb5_files_test.keytab";
    let es, err = krb5::keytab_entries_from_password(krb5::NT_PRINCIPAL, "alice", "EXAMPLE.COM", "secret", 2,
                                                     [18, 17, 23], 1700000000);
    tv::check_int("from password", err, krb5::OK);
    tv::check_int("save private", krb5::keytab_save_private(path, es), krb5::OK);
    let back, lerr = krb5::keytab_load(path);
    tv::check_int("load", lerr, krb5::OK);
    same_entries("saved keytab", es, back);
    let k, kv, kerr = krb5::keytab_key(back, "alice", "EXAMPLE.COM", 23, 0);
    let want, werr = krb5::string_to_key(23, "secret", "");
    tv::check("rc4 key from keytab", kerr == krb5::OK && k.value == want.value && kv == 2);
    delete_file(path);

    let cpath = "FILE:/tmp/krb5_files_test.ccache";
    let cc = krb5::ccache_new(krb5::NT_PRINCIPAL, "alice", "EXAMPLE.COM");
    tv::check_int("ccache save", krb5::ccache_save(cpath, cc), krb5::OK);
    let cb, cerr = krb5::ccache_load(cpath);
    tv::check("ccache load", cerr == krb5::OK && cb.principal == "alice" && cb.realm == "EXAMPLE.COM");
    delete_file("/tmp/krb5_files_test.ccache");
    let p, ok = krb5::ccache_path("KCM:1000");
    tv::check("KCM is not a file", !ok);
    let p2, ok2 = krb5::ccache_path("C:\\Users\\x\\krb5cc");
    tv::check("a drive letter is a path", ok2);
}

fn main() {
    keytabs();
    ccache();
    odd_keytabs();
    saving();
    tv::done("files");
}
