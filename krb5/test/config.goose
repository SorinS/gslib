// krb5.config: go-krb5's test krb5.conf, MIT's syntax corners (comments,
// quoting, nested subsections, final markers, includes), durations,
// enctype lists (des3 and rc4 only when allowed), KDC addresses,
// domain_realm, capaths and the hierarchical realm path; the floor on a
// KDC's s2kparams.

import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.config;
import gslib.krb5.client;
import tv;

fn parse() {
    var text: u8[>..] = [];
    tv::check("read krb5.conf", read_file("vectors/krb5.conf", text));
    let cfg, err = krb5::config_parse(text);
    tv::check_int("parse", err, krb5::OK);
    let r, ok = krb5::default_realm(cfg);
    tv::check("default realm", ok && r == "TEST.GOKRB5");
    tv::check("forwardable", krb5::conf_bool(cfg, "libdefaults/forwardable", false));
    tv::check("noaddresses", !krb5::conf_bool(cfg, "libdefaults/noaddresses", true));
    tv::check("absent bool", krb5::conf_bool(cfg, "libdefaults/rdns", true));
    tv::check_int("ticket lifetime", krb5::conf_duration(cfg, "libdefaults/ticket_lifetime", 0), 86400);
    let et = krb5::conf_etypes(cfg, "default_tkt_enctypes");
    tv::check("tkt enctypes", et.len == 1 && et[0] == 18);
    let pe = krb5::conf_etypes(cfg, "permitted_enctypes");
    let want_pe: i32[6] = [18, 17, 20, 19, 26, 25];
    tv::check("permitted default: no des3, no rc4", pe[..] == want_pe[..]);

    let kdcs = krb5::realm_kdcs(cfg, "TEST.GOKRB5");
    var n = 0;
    for k in kdcs {
        tv::check(str("kdc ", n), k.host == (if n == 0 { "127.0.0.1" } else { "127.0.0.2" }) && k.port == 88 && !k.tcp_only);
        n++;
    }
    tv::check_int("kdcs", n, 2);
    let sub = krb5::realm_kdcs(cfg, "SUB.TEST.GOKRB5");
    var m = 0;
    for k in sub {
        if m == 0 { tv::check("tcp kdc", k.host == "127.0.0.1" && k.port == 288 && k.tcp_only); }
        if m == 1 { tv::check("v6 kdc", k.host == "::1" && k.port == 289); }
        if m == 2 { tv::check("bare v6 kdc", k.host == "fe80::1" && k.port == 88); }
        m++;
    }
    tv::check_int("sub kdcs", m, 3);

    tv::check_eq("host realm", krb5::realm_for_host(cfg, "host.test.krb5"), "TEST.GOKRB5");
    tv::check_eq("domain realm", krb5::realm_for_host(cfg, "TEST.KRB5."), "TEST.GOKRB5");
    tv::check_eq("sub host realm", krb5::realm_for_host(cfg, "a.b.sub.test.gokrb5"), "SUB.TEST.GOKRB5");
    tv::check_eq("unknown host", krb5::realm_for_host(cfg, "example.org"), "");

    let p1, ok1 = krb5::capath(cfg, "ANL.GOV", "TEST.ANL.GOV");
    tv::check("capath direct", ok1 && p1.len == 0);
    let p2, ok2 = krb5::capath(cfg, "ANL.GOV", "PNL.GOV");
    tv::check("capath one", ok2 && p2.len == 1);
    for x in p2 { tv::check_eq("capath via", x, "ES.NET"); }
    let p3, ok3 = krb5::capath(cfg, "TEST.ANL.GOV", "PNL.GOV");
    var k3 = 0;
    for x in p3 { tv::check_eq(str("capath two ", k3), x, if k3 == 0 { "ANL.GOV" } else { "ES.NET" }); k3++; }
    let p4, ok4 = krb5::capath(cfg, "PNL.GOV", "ANL.GOV");
    tv::check("capath unknown", !ok4);

    let dv, dok = krb5::conf_get(cfg, "appdefaults/pam/debug");
    tv::check("quoted value", dok && dv == "a \"quoted\"\tvalue");
    let nv, nok = krb5::conf_get(cfg, "appdefaults/pam/nested/deep");
    tv::check("nested value", nok && nv == "1");
}

fn bad() {
    fn refuse(what: const u8[:], text: const u8[:]) {
        let c, err = krb5::config_parse(text);
        tv::check_int(what, err, krb5::ERR_CONFIG);
    }
    refuse("relation outside a section", "a = b\n");
    refuse("unclosed subsection", "[realms]\n R = {\n kdc = x\n");
    refuse("stray brace", "[realms]\n}\n");
    refuse("no equals", "[libdefaults]\n default_realm\n");
    refuse("section inside subsection", "[realms]\n R = {\n[x]\n}\n");
    refuse("unclosed section name", "[realms\n");
}

fn durations() {
    fn d(s: const u8[:], want: i64) {
        let v, ok = krb5::parse_duration(s);
        tv::check(str("duration ", s), ok && v == want);
    }
    fn nd(s: const u8[:]) {
        let v, ok = krb5::parse_duration(s);
        tv::check(str("bad duration ", s), !ok);
    }
    d("36000", 36000);
    d("10h", 36000);
    d("1d", 86400);
    d("1d 2h30m", 86400 + 9000);
    d("1h30m15s", 5415);
    d("1:30", 5400);
    d("1:30:15", 5415);
    d("90", 90);
    nd("");
    nd("h");
    nd("1m1h");
    nd("1x");
    nd("1:2:3:4");
    nd("::");
}

fn etypes() {
    fn e(s: const u8[:], want: const i32[:]) {
        let got = krb5::parse_etypes(s);
        tv::check(str("etypes ", s), got == want);
    }
    e("aes256-cts aes128-cts", [18, 17]);
    e("aes", [18, 17, 20, 19]);
    e("DEFAULT -rc4 -des3", [18, 17, 20, 19, 26, 25]);
    e("DEFAULT -rc4 -des3 -camellia", [18, 17, 20, 19]);
    e("camellia aes128-cts", [26, 25, 17]);
    e("camellia128-cts 26 -camellia256-cts-cmac", [25]);
    e("aes256-sha2,aes128-sha2", [20, 19]);
    e("rc4-hmac des3-cbc-sha1 rc4-hmac", [23, 16]);
    e("camellia256-cts-cmac aes256-cts", [26, 18]);
    e("des-cbc-crc 23", [23]);
}

// des3 and rc4 only with allow_des3 and allow_rc4, listed or not.
fn weak_etypes() {
    fn c(what: const u8[:], text: const u8[:], want: const i32[:]) {
        let cfg, err = krb5::config_parse(text);
        tv::check_int(str(what, " parse"), err, krb5::OK);
        let got = krb5::conf_etypes(cfg, "default_tkt_enctypes");
        tv::check(str(what), got == want);
    }
    c("listed, not allowed", "[libdefaults]\n default_tkt_enctypes = aes256-cts rc4-hmac des3-cbc-sha1\n", [18]);
    c("listed, rc4 allowed", "[libdefaults]\n allow_rc4 = true\n default_tkt_enctypes = aes256-cts rc4-hmac des3-cbc-sha1\n",
      [18, 23]);
    c("permitted, both allowed",
      "[libdefaults]\n allow_rc4 = true\n allow_des3 = yes\n permitted_enctypes = rc4-hmac des3-cbc-sha1 aes128-cts\n", [23, 16, 17]);
    c("DEFAULT with rc4 allowed", "[libdefaults]\n allow_rc4 = true\n default_tkt_enctypes = DEFAULT\n", [18, 17, 20, 19, 26, 25]);
    c("DEFAULT +rc4", "[libdefaults]\n allow_rc4 = true\n default_tkt_enctypes = DEFAULT rc4\n", [18, 17, 20, 19, 26, 25, 23]);
}

// A KDC's s2kparams: iteration counts below the type's default refused
// unless allow_weak_s2kparams.
fn s2kparams() {
    tv::check("none", krb5::s2kparams_ok(18, "", false));
    tv::check("aes 4096", krb5::s2kparams_ok(18, "\x00\x00\x10\x00", false));
    tv::check("aes 1 refused", !krb5::s2kparams_ok(18, "\x00\x00\x00\x01", false));
    tv::check("aes 4095 refused", !krb5::s2kparams_ok(17, "\x00\x00\x0f\xff", false));
    tv::check("aes 1 allowed", krb5::s2kparams_ok(18, "\x00\x00\x00\x01", true));
    tv::check("sha2 4096 refused", !krb5::s2kparams_ok(20, "\x00\x00\x10\x00", false));
    tv::check("sha2 32768", krb5::s2kparams_ok(19, "\x00\x00\x80\x00", false));
    tv::check("camellia 4096 refused", !krb5::s2kparams_ok(26, "\x00\x00\x10\x00", false));
    tv::check("wrong length", !krb5::s2kparams_ok(18, "\x00\x10\x00", false));
    tv::check("2^24", krb5::s2kparams_ok(18, "\x01\x00\x00\x00", false));
}

fn paths() {
    fn hp(c: const u8[:], s: const u8[:], want: const u8[:]) {
        var got: u8[>..] = [];
        for r in krb5::hierarchical_path(c, s) { if got.len > 0 { got.push(' '); } got.append(r); }
        tv::check_eq(str("path ", c, " -> ", s), got, want);
    }
    hp("A.EXAMPLE.COM", "B.EXAMPLE.COM", "EXAMPLE.COM");
    hp("EXAMPLE.COM", "B.EXAMPLE.COM", "");
    hp("B.EXAMPLE.COM", "EXAMPLE.COM", "");
    hp("A.B.EXAMPLE.COM", "C.EXAMPLE.COM", "B.EXAMPLE.COM EXAMPLE.COM");
    hp("C.EXAMPLE.COM", "A.B.EXAMPLE.COM", "EXAMPLE.COM B.EXAMPLE.COM");
    hp("A.COM", "B.ORG", "COM ORG");
    hp("X.Y", "X.Y", "");
}

fn includes() {
    let dir = "/tmp/krb5_config_test.d";
    make_dir(dir);
    write_file("/tmp/krb5_config_test.d/10-realms", "[realms]\n INC.REALM = {\n  kdc = inc.example:750\n }\n");
    write_file("/tmp/krb5_config_test.d/skip.txt", "[libdefaults]\n default_realm = WRONG\n");
    write_file("/tmp/krb5_config_test.inc", "[libdefaults]\n clockskew = 10m\n");
    let text = "include /tmp/krb5_config_test.inc\nincludedir /tmp/krb5_config_test.d\n[libdefaults]\n default_realm = INC.REALM\n";
    write_file("/tmp/krb5_config_test.conf", text);
    let cfg, err = krb5::config_load("/tmp/nonexistent_krb5.conf:/tmp/krb5_config_test.conf");
    tv::check_int("load", err, krb5::OK);
    let r, ok = krb5::default_realm(cfg);
    tv::check("default realm after includes", ok && r == "INC.REALM");
    tv::check_int("included clockskew", krb5::conf_duration(cfg, "libdefaults/clockskew", 300), 600);
    let ks = krb5::realm_kdcs(cfg, "INC.REALM");
    for k in ks { tv::check("includedir kdc", k.host == "inc.example" && k.port == 750); }
    delete_file("/tmp/krb5_config_test.d/10-realms");
    delete_file("/tmp/krb5_config_test.d/skip.txt");
    delete_dir(dir);
    delete_file("/tmp/krb5_config_test.inc");
    delete_file("/tmp/krb5_config_test.conf");
}

// A path that cannot be read is ERR_FILE, alone or with every other
// file of the list; with one file that can, the others are skipped.
fn missing() {
    let c1, e1 = krb5::config_load("/tmp/nonexistent_krb5.conf");
    tv::check_int("missing file", e1, krb5::ERR_FILE);
    let c2, e2 = krb5::config_load("/tmp/nonexistent_krb5.conf:/tmp/nonexistent_krb5_2.conf");
    tv::check_int("missing list", e2, krb5::ERR_FILE);
    let c3, e3 = krb5::config_load("");
    tv::check_int("empty list", e3, krb5::ERR_FILE);
    write_file("/tmp/krb5_config_missing.conf", "[libdefaults]\n default_realm = ONE.REALM\n");
    let c4, e4 = krb5::config_load("/tmp/nonexistent_krb5.conf:/tmp/krb5_config_missing.conf");
    tv::check_int("missing then present", e4, krb5::OK);
    let r, ok = krb5::default_realm(c4);
    tv::check("realm of the present file", ok && r == "ONE.REALM");
    delete_file("/tmp/krb5_config_missing.conf");
}

fn main() {
    parse();
    bad();
    durations();
    etypes();
    weak_etypes();
    s2kparams();
    paths();
    includes();
    missing();
    tv::done("config");
}
