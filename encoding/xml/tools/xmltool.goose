// xmltool: the xml package from the command line, for the differential
// and interop scripts (scripts/differential.py, scripts/interop.py):
//
//   goose xmltool.goose -- parse FILE                 ok, or the error's code and message
//   goose xmltool.goose -- c14n METHOD COMMENTS FILE [ID [PREFIXES]]
//        canonical form of FILE, or of the element with ID, to stdout;
//        METHOD c14n10 | c14n11 | exc, COMMENTS 0 | 1
//   goose xmltool.goose -- sign KEY CERT FILE ID SIGALG HASH DIGEST METHOD [BEFORE_LOCAL]
//        FILE with the element ID signed (enveloped), to stdout; SIGALG
//        rsa | pss | ecdsa | ed25519 | default; BEFORE_LOCAL: the Signature
//        goes before the first child of that local name, else after the
//        first child element (SAML's Issuer), else last
//   goose xmltool.goose -- verify CERT FILE [ID] [sha1]
//        "ok" and each reference's local name, or the error
//   goose xmltool.goose -- encrypt CERT FILE ID ALG KEYALG    the element ID encrypted
//   goose xmltool.goose -- decrypt KEY FILE [cbc] [rsa15]     every EncryptedData decrypted, to stdout

import std;
import os;
import gslib from "../../..";
import gslib.encoding.xml;
import gslib.encoding.xml.c14n;
import gslib.encoding.xml.dsig;
import gslib.encoding.xml.enc;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;

fn die(msg: const u8[:]) {
    write_stderr(msg);
    write_stderr("\n");
    exit(1);
}

fn read_or_die(path: const u8[:], out: u8[>..]&) {
    if !read_file(path, out) { die(str("cannot read ", path)); }
}

fn parse_or_die(d: xml::Doc&, path: const u8[:]) {
    var text: u8[>..] = [];
    read_or_die(path, text);
    let e = xml::parse(d, text);
    if e.code != xml::OK { write_stdout(str("error ", e.code, " ", e.message, "\n")); exit(3); }
}

fn method_of(s: const u8[:]) -> i64 {
    if s == "c14n10" { return xml::C14N_10; }
    if s == "c14n11" { return xml::C14N_11; }
    if s == "exc" { return xml::EXC_C14N; }
    die(str("no method ", s));
    return 0;
}

fn element_or_die(d: const xml::Doc&, id: const u8[:]) -> i64 {
    let el, n = xml::by_id(d, id);
    if n != 1 { die(str("ID ", id, " found ", n, " times")); }
    return el;
}

fn main() {
    let a = args();
    if a.len < 3 { die("usage: xmltool parse|c14n|sign|verify|encrypt|decrypt ..."); }
    let cmd = a[1];
    if cmd == "parse" {
        var d = xml::Doc { .. };
        var text: u8[>..] = [];
        read_or_die(a[2], text);
        let e = xml::parse(d, text);
        if e.code == xml::OK { write_stdout("ok\n"); } else { write_stdout(str("error ", e.code, " ", e.message, "\n")); }
    } else if cmd == "c14n" {
        guard a.len >= 5 else { die("c14n METHOD COMMENTS FILE [ID [PREFIXES]]"); }
        var d = xml::Doc { .. };
        parse_or_die(d, a[4]);
        var m = xml::C14n { .. };
        m.method = method_of(a[2]);
        m.comments = a[3] == "1";
        var n = 0;
        if a.len > 5 && a[5].len > 0 { n = element_or_die(d, a[5]); }
        if a.len > 6 { format(m.inclusive, a[6]); }
        var out: u8[>..] = [];
        if !xml::canonicalize(d, n, m, out) { die("bad prefix list"); }
        write_stdout(out);
    } else if cmd == "sign" {
        guard a.len >= 10 else { die("sign KEY CERT FILE ID SIGALG HASH DIGEST METHOD [BEFORE_LOCAL]"); }
        var kt: u8[>..] = [];
        read_or_die(a[2], kt);
        let key, okk = x509::parse_private_key_pem(kt);
        if !okk { die("bad key"); }
        var ct: u8[>..] = [];
        read_or_die(a[3], ct);
        let cert, ce = x509::parse_pem(ct);
        if ce != x509::OK { die("bad certificate"); }
        var d = xml::Doc { .. };
        parse_or_die(d, a[4]);
        let el = if a[5].len == 0 { xml::root_element(d) } else { element_or_die(d, a[5]) };
        var o = xml::sign_options();
        let sa = a[6];
        o.alg = if sa == "rsa" { x509::SIG_RSA_PKCS1 } else if sa == "pss" { x509::SIG_RSA_PSS }
                else if sa == "ecdsa" { x509::SIG_ECDSA } else if sa == "ed25519" { x509::SIG_ED25519 } else { 0 };
        let h, okh = parse_int(a[7]);
        let dg, okd = parse_int(a[8]);
        o.hash = h;
        o.digest = dg;
        o.c14n = method_of(a[9]);
        var before = -1;
        if a.len > 10 {
            before = xml::child(d, el, xml::ns_uri(d, el), a[10]);
        } else {
            let first = xml::first_element(d, el);
            if first >= 0 { before = xml::next_element(d, first); }
        }
        let sig, e = xml::sign_enveloped(d, el, before, key, cert.der, o);
        if e != xml::OK { die(str("sign: ", xml::dsig_error_name(e))); }
        var out: u8[>..] = [];
        xml::write_document(d, out);
        write_stdout(out);
    } else if cmd == "verify" {
        guard a.len >= 4 else { die("verify CERT FILE [ID] [sha1]"); }
        var ct: u8[>..] = [];
        read_or_die(a[2], ct);
        let cert, ce = x509::parse_pem(ct);
        if ce != x509::OK { die("bad certificate"); }
        var d = xml::Doc { .. };
        parse_or_die(d, a[3]);
        var o = xml::verify_options();
        o.allow_sha1 = a.len > 5 && a[5] == "sha1";
        var v = xml::Verified { .. };
        if a.len > 4 && a[4].len > 0 {
            v = xml::verify_enveloped(d, element_or_die(d, a[4]), cert, o);
        } else {
            var sigs: i64[>..<] = [];
            xml::find_signatures(d, sigs);
            if sigs.len != 1 { die(str(sigs.len, " signatures")); }
            v = xml::verify(d, sigs[0], cert, o);
        }
        if v.code != xml::OK { write_stdout(str("error ", v.code, " ", v.message, "\n")); exit(4); }
        var line: u8[>..] = [];
        line.append("ok");
        for r in v.refs { line.push(' '); line.append(if r == 0 { "/" } else { xml::local_name(d, r) }); }
        line.push('\n');
        write_stdout(line);
    } else if cmd == "encrypt" {
        guard a.len >= 7 else { die("encrypt CERT FILE ID ALG KEYALG"); }
        var ct: u8[>..] = [];
        read_or_die(a[2], ct);
        let cert, ce = x509::parse_pem(ct);
        if ce != x509::OK { die("bad certificate"); }
        var d = xml::Doc { .. };
        parse_or_die(d, a[3]);
        let el = element_or_die(d, a[4]);
        var o = xml::encrypt_options();
        let an = a[5];
        o.alg = if an == "aes128-gcm" { xml::ENC_AES128_GCM } else if an == "aes192-gcm" { xml::ENC_AES192_GCM } else { xml::ENC_AES256_GCM };
        let kn = a[6];
        if kn == "rsa-oaep-mgf1p" { o.key_alg = xml::KEY_RSA_OAEP_MGF1P; }
        else if kn == "rsa-oaep" { o.key_alg = xml::KEY_RSA_OAEP; o.oaep_digest = 256; o.oaep_mgf = 256; }
        else if kn == "ecdh-es" { o.key_alg = xml::KEY_ECDH_ES; }
        let ed, e = xml::encrypt_element(d, el, cert, o);
        if e != xml::OK { die(str("encrypt: ", xml::enc_error_name(e))); }
        var out: u8[>..] = [];
        xml::write_document(d, out);
        write_stdout(out);
    } else if cmd == "decrypt" {
        guard a.len >= 4 else { die("decrypt KEY FILE [cbc] [rsa15]"); }
        var kt: u8[>..] = [];
        read_or_die(a[2], kt);
        let key, okk = x509::parse_private_key_pem(kt);
        if !okk { die("bad key"); }
        var d = xml::Doc { .. };
        parse_or_die(d, a[3]);
        var o = xml::decrypt_options();
        for i in 4..a.len {
            if a[i] == "cbc" { o.allow_cbc = true; }
            if a[i] == "rsa15" { o.allow_rsa15 = true; }
        }
        var eds: i64[>..<] = [];
        xml::find_encrypted(d, eds);
        if eds.len == 0 { die("no EncryptedData"); }
        for ed in eds {
            let e = xml::decrypt_replace(d, ed, key, o);
            if e != xml::OK { write_stdout(str("error ", e, " ", xml::enc_error_name(e), "\n")); exit(4); }
        }
        var out: u8[>..] = [];
        xml::write(d, 0, out);
        write_stdout(out);
    } else {
        die(str("no command ", cmd));
    }
}
