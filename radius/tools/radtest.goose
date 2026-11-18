// radtest: one RADIUS exchange, as FreeRADIUS's radtest and
// wpa_supplicant's eapol_test make them, from gslib's client.
//
//   radtest [options] HOST METHOD [USER PASSWORD]
//
// METHOD: pap, chap, mschapv2, eap-md5, eap-mschapv2, eap-tls, peap,
// ttls-pap, ttls-mschapv2, acct (a Start then a Stop), status; to a NAS
// (port 3799): disconnect and coa (Session-Timeout = 60) for USER.
//
//   --secret S        the shared secret (testing123); RadSec's is radsec
//   --port N          1812 (2083 with --radsec, 1813 for acct)
//   --radsec          RADIUS over TLS (RFC 6614)
//   --ca FILE         the CA of the server's certificate (PEM), RadSec's
//                     and the EAP methods'
//   --name NAME       the name in the server's certificate (radius.example.com)
//   --cert FILE --key FILE   a client certificate: RadSec's
//   --eap-cert FILE --eap-key FILE   EAP-TLS's certificate
//   --anon NAME       the outer identity of PEAP and TTLS
//   --tls12           TLS 1.2 only (EAP methods and RadSec)
//   --fragment N      EAP-TLS fragment size (1000)
//
// It prints the answer's code and attributes, and for the EAP methods
// whether the MS-MPPE keys are the peer's MSK; it exits 0 when accepted.

import std;
import os;
import gslib from "../..";
import gslib.radius;
import gslib.radius.mschap;
import gslib.radius.eap;
import gslib.radius.client;
import gslib.encoding.asn1;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;

fn die(what: const u8[:]) { print("radtest: ", what); exit(2); }

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { die(str("cannot read ", path)); }
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    if out.len == 0 { die(str("no ", label, " in ", path)); }
    return out;
}

// The client: UDP, or RadSec with a client certificate.
fn connect(host: const u8[:], port: i64, radsec: bool, method: const u8[:], secret: const u8[:],
           cc: const tls::ClientConfig&, cert: const u8[:], key: const u8[:]) -> radius::Client, i64 {
    if radsec {
        var rc = copy(cc);
        if cert.len > 0 && !tls::set_client_certificate(rc, pem_der(cert, "CERTIFICATE"), pem_der(key, "PRIVATE KEY")) {
            die("the client certificate");
        }
        return radius::dial_radsec(host, if port > 0 { port } else { 2083 }, rc);
    }
    let p = if port > 0 { port } else if method == "acct" { 1813 }
            else if method == "disconnect" || method == "coa" { 3799 } else { 1812 };
    return radius::dial(host, p, secret);
}

fn show(p: const radius::Packet&) {
    print(radius::code_name(p.code));
    let rm = radius::get_text(p, radius::REPLY_MESSAGE);
    if rm.len > 0 { print("  Reply-Message = \"", rm, "\""); }
    let un = radius::get_text(p, radius::USER_NAME);
    if un.len > 0 { print("  User-Name = \"", un, "\""); }
    let n = radius::count(p, radius::VENDOR_SPECIFIC);
    if n > 0 { print("  ", n, " vendor-specific attribute", if n == 1 { "" } else { "s" }); }
}

fn main() {
    let a = args();
    var secret: u8[>..] = [];
    secret.append("testing123");
    var port: i64 = 0;
    var radsec = false;
    var ca: u8[>..] = [];
    var name: u8[>..] = [];
    name.append("radius.example.com");
    var cert: u8[>..] = [];
    var key: u8[>..] = [];
    var eap_cert: u8[>..] = [];
    var eap_key: u8[>..] = [];
    var anon: u8[>..] = [];
    var tls12 = false;
    var fragment: i64 = 1000;
    var pos: i64[>..] = [];
    var i = 1;
    while i < a.len {
        let o = a[i];
        let more = i + 1 < a.len;
        if o == "--secret" && more { secret.clear(); secret.append(a[i + 1]); i += 2; }
        else if o == "--port" && more { let v, ok = parse_int(a[i + 1], 10); port = v; i += 2; }
        else if o == "--radsec" { radsec = true; i++; }
        else if o == "--ca" && more { ca.append(a[i + 1]); i += 2; }
        else if o == "--name" && more { name.clear(); name.append(a[i + 1]); i += 2; }
        else if o == "--cert" && more { cert.append(a[i + 1]); i += 2; }
        else if o == "--key" && more { key.append(a[i + 1]); i += 2; }
        else if o == "--eap-cert" && more { eap_cert.append(a[i + 1]); i += 2; }
        else if o == "--eap-key" && more { eap_key.append(a[i + 1]); i += 2; }
        else if o == "--anon" && more { anon.append(a[i + 1]); i += 2; }
        else if o == "--tls12" { tls12 = true; i++; }
        else if o == "--fragment" && more { let v, ok = parse_int(a[i + 1], 10); fragment = v; i += 2; }
        else { pos.push(i); i++; }
    }
    guard pos.len >= 2 else { die("usage: radtest [options] HOST METHOD [USER PASSWORD]"); }
    let host = a[pos[0]];
    let method = a[pos[1]];
    var user: u8[>..] = [];
    var pw: u8[>..] = [];
    if pos.len >= 3 { user.append(a[pos[2]]); }
    if pos.len >= 4 { pw.append(a[pos[3]]); }

    // The TLS of RadSec and of the EAP methods.
    var roots: u8[>..] = [];
    if ca.len > 0 { roots.append(pem_der(ca, "CERTIFICATE")); }
    var cc = tls::client_config(name, roots);
    if tls12 { cc.max_version = tls::VERSION_TLS12; }

    var c, e = connect(host, port, radsec, method, secret, cc, cert, key);
    if e != radius::OK { die(str("cannot connect: ", radius::error_text(e))); }

    var resp = radius::request(radius::ACCOUNTING_REQUEST);
    var r = radius::OK;
    var eap_method: u8 = 0;
    var inner: u8 = radius::INNER_MSCHAPV2;
    if method == "pap" { let p, er = radius::authenticate_pap(c, user, pw); resp = p; r = er; }
    else if method == "chap" { let p, er = radius::authenticate_chap(c, user, pw); resp = p; r = er; }
    else if method == "mschapv2" { let p, er = radius::authenticate_mschapv2(c, user, pw); resp = p; r = er; }
    else if method == "status" { let p, er = radius::status(c); resp = p; r = er; }
    else if method == "disconnect" || method == "coa" {
        var attrs = radius::request(radius::ACCOUNTING_REQUEST);
        radius::add(attrs, radius::USER_NAME, user);
        if method == "coa" {
            radius::add_u32(attrs, radius::SESSION_TIMEOUT, 60);
            let p, er = radius::change_of_authorization(c, attrs);
            resp = p;
            r = er;
        } else {
            let p, er = radius::disconnect(c, attrs);
            resp = p;
            r = er;
        }
        let cause, okc = radius::get_u32(resp, radius::ERROR_CAUSE);
        if okc { print("Error-Cause = ", cause); }
    }
    else if method == "acct" {
        let none = radius::request(radius::ACCOUNTING_REQUEST);
        let p1, e1 = radius::account(c, radius::ACCT_START, "gslib-1", user, none);
        print("Start: ", radius::error_text(e1));
        let p2, e2 = radius::account(c, radius::ACCT_STOP, "gslib-1", user, none);
        resp = p2;
        r = if e1 != radius::OK { e1 } else { e2 };
    }
    else if method == "eap-md5" { eap_method = radius::EAP_MD5; }
    else if method == "eap-mschapv2" { eap_method = radius::EAP_MSCHAPV2; }
    else if method == "eap-tls" { eap_method = radius::EAP_TLS; }
    else if method == "peap" { eap_method = radius::EAP_PEAP; }
    else if method == "ttls-pap" { eap_method = radius::EAP_TTLS; inner = radius::INNER_PAP; }
    else if method == "ttls-mschapv2" { eap_method = radius::EAP_TTLS; }
    else { die(str("no such method: ", method)); }

    if eap_method != 0 {
        var pc = radius::peer_config(user, pw, eap_method);
        pc.inner = inner;
        pc.fragment = fragment;
        pc.outer_identity.append(anon);
        pc.tls = copy(cc);
        if eap_cert.len > 0 &&
           !tls::set_client_certificate(pc.tls, pem_der(eap_cert, "CERTIFICATE"), pem_der(eap_key, "PRIVATE KEY")) {
            die("the EAP-TLS certificate");
        }
        var p = radius::peer(pc);
        let pr, er = radius::authenticate_eap(c, p, pc);
        resp = pr;
        r = er;
        if er == radius::OK && radius::peer_msk(p).len > 0 {
            let tunnel = eap_method == radius::EAP_TLS || eap_method == radius::EAP_PEAP || eap_method == radius::EAP_TTLS;
            if !tunnel { print("MPPE keys OK"); }
            else { print("MPPE keys OK, TLS 1.", if tls::version(p.layer.conn) == tls::VERSION_TLS13 { 3 } else { 2 }); }
        }
    }
    radius::close(c);
    if resp.code != 0 { show(resp); }
    print("result: ", radius::error_text(r));
    exit(if r == radius::OK { 0 } else { 1 });
}
