// krb5.messages against MIT's reference encodings
// (test/vectors/mit_encodings.txt): every message decodes, its fields are
// what MIT's test put in, and encoding it again gives the same bytes.
// Then names, malformed input and the lenient readings.

import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.encoding.asn1;
import tv;

// MIT's test values (src/tests/asn.1/ktest.c).
let REALM = "ATHENA.MIT.EDU";
let NAME = "hftsai/extra";
let T = 771228197;        // 19940610060317Z
let CIPHER = "krbASN.1 test message";

fn rt(what: const u8[:], got: const u8[:], want: const u8[:]) { tv::check_hex(str("re-encode ", what), got, tv::to_hex(want)); }

fn one(name: const u8[:], der: const u8[:]) {
    var out: u8[>..] = [];
    if name.starts_with("MarshaledKRB5authenticator") {
        let a, err = krb5::decode_authenticator(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_eq("authenticator crealm", a.crealm, REALM);
        tv::check_eq("authenticator cname", a.cname.name, NAME);
        tv::check_int("authenticator ctime", a.ctime, T);
        tv::check_int("authenticator cusec", a.cusec, 123456);
        if name == "MarshaledKRB5authenticator" {
            tv::check("authenticator optionals", a.has_cksum && a.has_subkey && a.has_seq_number && a.has_authz);
            tv::check_int("authenticator seq", a.seq_number, 17);
        }
        krb5::encode_authenticator(out, a);
    } else if name == "MarshaledKRB5ticket" {
        let t, err = krb5::decode_ticket(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_eq("ticket realm", t.realm, REALM);
        tv::check_eq("ticket sname", t.sname.name, NAME);
        tv::check_eq("ticket cipher", t.enc_part.cipher, CIPHER);
        tv::check("ticket kvno", t.enc_part.has_kvno && t.enc_part.kvno == 5);
        krb5::encode_ticket(out, t);
    } else if name == "MarshaledKRB5keyblock" {
        let k, err = krb5::decode_key(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check("keyblock", k.etype == 1 && k.value == "12345678");
        krb5::encode_key(out, k);
    } else if name.starts_with("MarshaledKRB5enc_tkt_part") {
        let p, err = krb5::decode_enc_ticket_part(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check("enc_tkt_part flags", p.flags == 0xfedcba98);
        tv::check_eq("enc_tkt_part crealm", p.crealm, REALM);
        tv::check_int("enc_tkt_part authtime", p.authtime, T);
        krb5::encode_enc_ticket_part(out, p);
    } else if name.starts_with("MarshaledKRB5enc_kdc_rep_part") {
        let p, err = krb5::decode_enc_kdc_rep_part(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_int("enc_kdc_rep_part nonce", p.nonce, 42);
        tv::check_eq("enc_kdc_rep_part sname", p.sname.name, NAME);
        tv::check("enc_kdc_rep_part key", p.key.value == "12345678");
        krb5::encode_enc_kdc_rep_part(out, p);
    } else if name.starts_with("MarshaledKRB5as_rep") || name.starts_with("MarshaledKRB5tgs_rep") {
        let r, err = krb5::decode_kdc_rep(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_int("kdc_rep type", r.msg_type, if name.starts_with("MarshaledKRB5as") { 11 } else { 13 });
        tv::check_eq("kdc_rep cname", r.cname.name, NAME);
        tv::check_eq("kdc_rep cipher", r.enc_part.cipher, CIPHER);
        let t, terr = krb5::decode_ticket(r.ticket);
        tv::check("kdc_rep ticket", terr == krb5::OK && t.realm == REALM);
        krb5::encode_kdc_rep(out, r);
    } else if name.starts_with("MarshaledKRB5as_req") || name.starts_with("MarshaledKRB5tgs_req") {
        let r, err = krb5::decode_kdc_req(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_int("kdc_req type", r.msg_type, if name.starts_with("MarshaledKRB5as") { 10 } else { 12 });
        tv::check_eq("kdc_req realm", r.body.realm, REALM);
        tv::check_int("kdc_req nonce", r.body.nonce, 42);
        krb5::encode_kdc_req(out, r);
    } else if name.starts_with("MarshaledKRB5kdc_req_body") {
        let b, err = krb5::decode_req_body(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_int("req_body till", b.till, T);
        krb5::encode_req_body(out, b);
    } else if name == "MarshaledKRB5ap_req" {
        let r, err = krb5::decode_ap_req(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check("ap_req options", r.ap_options == 0xfedcba98);
        tv::check_eq("ap_req cipher", r.authenticator.cipher, CIPHER);
        krb5::encode_ap_req(out, r);
    } else if name == "MarshaledKRB5ap_rep" {
        let r, err = krb5::decode_ap_rep(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        krb5::encode_ap_rep(out, r);
    } else if name.starts_with("MarshaledKRB5ap_rep_enc_part") {
        let p, err = krb5::decode_enc_ap_rep_part(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check("ap_rep_enc_part", p.ctime == T && p.cusec == 123456);
        krb5::encode_enc_ap_rep_part(out, p);
    } else if name.starts_with("MarshaledKRB5safe") {
        let m, err = krb5::decode_krb_safe(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_eq("safe user data", m.body.user_data, "krb5data");
        krb5::encode_krb_safe(out, m);
    } else if name == "MarshaledKRB5priv" {
        let m, err = krb5::decode_krb_priv(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        krb5::encode_krb_priv(out, m);
    } else if name.starts_with("MarshaledKRB5enc_priv_part") {
        let b, err = krb5::decode_enc_krb_priv_part(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_eq("enc_priv_part user data", b.user_data, "krb5data");
        krb5::encode_enc_krb_priv_part(out, b);
    } else if name == "MarshaledKRB5cred" {
        let m, err = krb5::decode_krb_cred(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        var n = 0;
        for t in m.tickets { n++; }
        tv::check_int("cred tickets", n, 2);
        krb5::encode_krb_cred(out, m);
    } else if name.starts_with("MarshaledKRB5enc_cred_part") {
        let p, err = krb5::decode_enc_krb_cred_part(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        var n = 0;
        for i in p.ticket_info { n++; }
        tv::check_int("enc_cred_part infos", n, 2);
        krb5::encode_enc_krb_cred_part(out, p);
    } else if name.starts_with("MarshaledKRB5error") {
        let e, err = krb5::decode_krb_error(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_int("error code", e.error_code, krb5::KRB_ERR_GENERIC);
        tv::check_eq("error realm", e.realm, REALM);
        if name == "MarshaledKRB5error" { tv::check_eq("error e-text", e.etext, "krb5data"); }
        krb5::encode_krb_error(out, e);
    } else if name == "MarshaledKRB5authorization_data" {
        let a, err = krb5::decode_authdata(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        for x in a { tv::check("authorization_data", x.ad_type == 1 && x.data == "foobar"); }
        krb5::encode_authdata(out, a);
    } else if name.starts_with("MarshaledKRB5padata") {
        let p, err = krb5::decode_padata(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        for x in p { tv::check("padata", x.pa_type == 13 && x.value == "pa-data"); }
        krb5::encode_padata(out, p);
    } else if name == "MarshaledKRB5typed_data" {
        let td, err = krb5::decode_typed_data(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        krb5::encode_typed_data(out, td);
    } else if name.starts_with("MarshaledKRB5etype_info2") {
        let e, err = krb5::decode_etype_info(der, false);
        tv::check_int(str("decode ", name), err, krb5::OK);
        krb5::encode_etype_info(out, e, false);
    } else if name.starts_with("MarshaledKRB5etype_info") {
        let e, err = krb5::decode_etype_info(der, true);
        tv::check_int(str("decode ", name), err, krb5::OK);
        krb5::encode_etype_info(out, e, true);
    } else if name.starts_with("MarshaledKRB5pa_enc_ts") {
        let ts, has_us, us, err = krb5::decode_pa_enc_ts(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_int("pa_enc_ts", ts, T);
        krb5::encode_pa_enc_ts(out, ts, has_us, us);
    } else if name == "MarshaledKRB5enc_data" {
        let d, err = krb5::decode_enc_data(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        krb5::encode_enc_data(out, d);
    } else if name == "MarshaledKRB5enc_dataMSBSetkvno" || name == "MarshaledKRB5enc_dataKVNONegOne" {
        // MIT writes key versions as signed 32-bit INTEGERs; we read those,
        // and write UInt32 as RFC 4120 defines it.
        let d, err = krb5::decode_enc_data(der);
        tv::check_int(str("decode ", name), err, krb5::OK);
        tv::check_int(str("kvno ", name), d.kvno, if name.ends_with("NegOne") { 0xffffffff } else { 0xff000000 });
        return;
    } else {
        return;   // FAST, OTP, SAM, IAKERB, S4U, CAMMAC: not ours
    }
    rt(name, out, der);
}

fn mit_vectors() {
    var n = 0;
    tv::each_row("vectors/mit_encodings.txt") { r: tv::Row& =>
        let name = r.next();
        let der = tv::hex(r.next());
        one(name, der);
        n++;
    };
    tv::check_int("vectors read", n, 74);
}

fn names() {
    let parts = krb5::name_parts("HTTP/host.example.com");
    var k = 0;
    for p in parts { tv::check_eq(str("part ", k), p, if k == 0 { "HTTP" } else { "host.example.com" }); k++; }
    tv::check_int("count", krb5::name_count("a/b/c"), 3);
    tv::check_eq("part 2", krb5::name_part("a/b/c", 2), "c");
    var esc: u8[>..] = [];
    krb5::name_escape(esc, "x/y@z\\w\n");
    tv::check_eq("escape", esc, "x\\/y\\@z\\\\w\\n");
    tv::check_eq("unescape", krb5::name_part(esc, 0), "x/y@z\\w\n");
    let n, r, has, ok = krb5::parse_principal("user\\@corp.com@EXAMPLE.COM");
    tv::check("enterprise parse", ok && has && n == "user\\@corp.com" && r == "EXAMPLE.COM");
    tv::check_eq("enterprise part", krb5::name_part(n, 0), "user@corp.com");
    let n2, r2, has2, ok2 = krb5::parse_principal("host/a.b");
    tv::check("no realm", ok2 && !has2 && n2 == "host/a.b" && r2.len == 0);
    let n3, r3, has3, ok3 = krb5::parse_principal("bad\\");
    tv::check("lone backslash", !ok3);
    tv::check_eq("principal_string", krb5::principal_string("a/b", "R@X"), "a/b@R\\@X");
    // A name's components survive an encode and decode, escapes and all.
    let p = krb5::principal_name(krb5::NT_ENTERPRISE, "user\\@corp.com");
    var der: u8[>..] = [];
    krb5::encode_principal(der, p);
    let back, err = krb5::decode_principal(der);
    tv::check("principal round trip", err == krb5::OK && back.name == p.name && back.name_type == krb5::NT_ENTERPRISE);
}

fn malformed() {
    tv::each_row("vectors/mit_encodings.txt") { r: tv::Row& =>
        let name = r.next();
        let der = tv::hex(r.next());
        if name == "MarshaledKRB5ticket" {
            // Every truncation fails cleanly.
            for n in der.len {
                let t, err = krb5::decode_ticket(der[..n]);
                tv::check(str("truncated ticket ", n), err == krb5::ERR_MALFORMED);
            }
            // So does a wrong tag.
            var w: u8[>..] = [];
            w.append(der);
            w[0] = 0x62;
            let t, err = krb5::decode_ticket(w);
            tv::check("ticket with authenticator tag", err == krb5::ERR_MALFORMED);
        }
        if name == "MarshaledKRB5as_rep" {
            for n in der.len {
                let rep, err = krb5::decode_kdc_rep(der[..n]);
                tv::check(str("truncated as_rep ", n), err == krb5::ERR_MALFORMED);
            }
            // An AS-REP is not an AP-REQ.
            let a, err = krb5::decode_ap_req(der);
            tv::check("as_rep as ap_req", err == krb5::ERR_MALFORMED);
            tv::check_int("message_type", krb5::message_type(der), 11);
        }
    };
    // Flags of fewer than 32 bits read with the missing bits zero.
    var bad = false;
    let short: u8[4] = [0x03, 0x02, 0x00, 0x40];   // BIT STRING, 1 byte, no unused bits: 0x40 = bit 1
    let t, ok = asn1::parse(short, true);
    tv::check("short flags parse", ok);
    let f = krb5::flags_at(short, t, bad);
    tv::check("short flags", !bad && f == krb5::flag(krb5::KDC_OPT_FORWARDABLE));
    // A KerberosTime with fractions is refused.
    let frac = "\x18\x1119940610060317.5Z";
    let t2, ok2 = asn1::parse(frac, true);
    var bad2 = false;
    let x = krb5::ktime_at(frac, t2, bad2);
    tv::check("fractional time refused", ok2 && bad2);
    // Times encode as GeneralizedTime with four-digit years.
    var g: u8[>..] = [];
    krb5::put_ktime(g, T);
    tv::check_eq("ktime", g, "\x18\x0f19940610060317Z");
    var g2: u8[>..] = [];
    krb5::put_ktime(g2, 2524608000);   // 2050-01-01
    tv::check_eq("ktime 2050", g2, "\x18\x0f20500101000000Z");
}

// FAST: MIT's reference encodings of KrbFastResponse and PA-FX-FAST-REPLY
// (src/tests/asn.1/reference_encode.out, 1.22), and round trips of the
// request side, which MIT's file does not have.
fn fast() {
    let resp_der = tv::hex(str(
        "30 81 9F A0 26 30 24 30 10 A1 03 02 01 0D A2 09 04 07 70 61 2D 64 61 74 61 30 10 A1 03 02 01 0D A2 09 04 07 70 61 2D 64 ",
        "61 74 61 A1 13 30 11 A0 03 02 01 01 A1 0A 04 08 31 32 33 34 35 36 37 38 A2 5B 30 59 A0 11 18 0F 31 39 39 34 30 36 31 30 ",
        "30 36 30 33 31 37 5A A1 05 02 03 01 E2 40 A2 10 1B 0E 41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 A3 1A 30 18 A0 03 02 01 ",
        "01 A1 11 30 0F 1B 06 68 66 74 73 61 69 1B 05 65 78 74 72 61 A4 0F 30 0D A0 03 02 01 01 A1 06 04 04 31 32 33 34 A3 03 02 ",
        "01 2A "));
    let r, err = krb5::decode_fast_response(resp_der);
    tv::check_int("decode fast_response", err, krb5::OK);
    var n = 0;
    for p in r.padata { tv::check(str("fast_response padata ", n), p.pa_type == 13 && p.value == "pa-data"); n++; }
    tv::check_int("fast_response padata count", n, 2);
    tv::check("fast_response strengthen key", r.has_strengthen_key && r.strengthen_key.etype == 1 && r.strengthen_key.value == "12345678");
    tv::check("fast_response finished", r.has_finished && r.finished.timestamp == T && r.finished.usec == 123456
              && r.finished.crealm == REALM && r.finished.cname.name == NAME && r.finished.ticket_checksum.ctype == 1
              && r.finished.ticket_checksum.sum == "1234");
    tv::check_int("fast_response nonce", r.nonce, 42);
    var out: u8[>..] = [];
    krb5::encode_fast_response(out, r);
    rt("fast_response", out, resp_der);
    for i in resp_der.len {
        let x, e = krb5::decode_fast_response(resp_der[..i]);
        tv::check(str("truncated fast_response ", i), e == krb5::ERR_MALFORMED);
    }

    let reply_der = tv::hex("A0293027A0253023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765");
    let d, derr = krb5::decode_pa_fx_fast_reply(reply_der);
    tv::check("decode pa_fx_fast_reply", derr == krb5::OK && d.etype == 0 && d.has_kvno && d.kvno == 5 && d.cipher == CIPHER);
    var out2: u8[>..] = [];
    krb5::encode_pa_fx_fast_reply(out2, d);
    rt("pa_fx_fast_reply", out2, reply_der);
    // A reply's CHOICE is [0]; a bare EncryptedData is not one.
    var bare: u8[>..] = [];
    krb5::encode_enc_data(bare, d);
    let b, berr = krb5::decode_pa_fx_fast_reply(bare);
    tv::check("bare enc data refused", berr == krb5::ERR_MALFORMED);

    let body = krb5::KdcReqBody {
        kdc_options: 0x40810010, has_cname: true, cname: krb5::principal_name(1, NAME), realm: REALM, has_sname: true,
        sname: krb5::principal_name(2, "krbtgt/ATHENA.MIT.EDU"), has_from: false, from: 0, till: T, has_rtime: false, rtime: 0,
        nonce: 42, etypes: [18, 17], has_addresses: false, addresses: [], has_enc_authz: false, enc_authz: krb5::no_enc_data(),
        has_tickets: false, tickets: [],
    };
    let fr = krb5::KrbFastReq { fast_options: 0, padata: [krb5::PaData { pa_type: 133, value: "cookie" }], req_body: copy(body) };
    var fder: u8[>..] = [];
    krb5::encode_fast_req(fder, fr);
    let fr2, ferr = krb5::decode_fast_req(fder);
    tv::check("fast_req round trip", ferr == krb5::OK && fr2.fast_options == 0 && fr2.req_body.nonce == 42
              && fr2.req_body.cname.name == NAME && fr2.req_body.etypes.len == 2);
    var fder2: u8[>..] = [];
    krb5::encode_fast_req(fder2, fr2);
    rt("fast_req", fder2, fder);

    for with_armor in 2 {
        let ar = krb5::KrbFastArmoredReq {
            has_armor: with_armor == 1, armor: krb5::KrbFastArmor { armor_type: krb5::FX_FAST_ARMOR_AP_REQUEST, value: "ap-req" },
            req_checksum: krb5::Checksum { ctype: 16, sum: "sum" },
            enc_fast_req: krb5::EncryptedData { etype: 18, has_kvno: false, kvno: 0, cipher: "cipher" },
        };
        var ader: u8[>..] = [];
        krb5::encode_pa_fx_fast_request(ader, ar);
        tv::check(str("armored req is [0] ", with_armor), ader[0] == 0xa0);
        let ar2, aerr = krb5::decode_pa_fx_fast_request(ader);
        tv::check(str("armored req round trip ", with_armor), aerr == krb5::OK && ar2.has_armor == (with_armor == 1)
                  && ar2.req_checksum.sum == "sum" && ar2.enc_fast_req.cipher == "cipher"
                  && (with_armor == 0 || (ar2.armor.armor_type == 1 && ar2.armor.value == "ap-req")));
        var ader2: u8[>..] = [];
        krb5::encode_pa_fx_fast_request(ader2, ar2);
        rt(str("armored req ", with_armor), ader2, ader);
    }
}

fn main() {
    mit_vectors();
    names();
    malformed();
    fast();
    tv::done("messages");
}
