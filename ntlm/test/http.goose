// ntlm.http: the NTLM and Negotiate header values both ways, refused
// ones (another scheme, bad base64, too long), the leaf of a certificate
// chain, and RFC 5929's tls-server-end-point binding by the certificate's
// signature hash (SHA-256 for an ECDSA P-256 certificate signed with
// SHA-256, SHA-384 for one signed with SHA-384).
import std;
import os;
import gslib from "../..";
import gslib.ntlm;
import gslib.ntlm.messages;
import gslib.ntlm.crypto;
import gslib.ntlm.http;
import gslib.crypto.bignum;
import gslib.crypto.bignum.hmac;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import tv;

fn headers() {
    let h = ntlm::http_header(ntlm::SCHEME_NTLM, "NTLMSSP\x00\x01\x00\x00\x00");
    tv::check("NTLM header", h[..] == "NTLM TlRMTVNTUAABAAAA");
    let s, t, ok = ntlm::http_token(h);
    tv::check("read back", ok && s == ntlm::SCHEME_NTLM && t[..] == "NTLMSSP\x00\x01\x00\x00\x00" && ntlm::is_ntlmssp(t));
    let s2, t2, ok2 = ntlm::http_token("  negotiate   YWJj \r\n");
    tv::check("Negotiate, any case, spaces", ok2 && s2 == ntlm::SCHEME_NEGOTIATE && t2[..] == "abc" && !ntlm::is_ntlmssp(t2));
    let s3, t3, ok3 = ntlm::http_token("NTLM");
    tv::check("bare scheme", ok3 && s3 == ntlm::SCHEME_NTLM && t3.len == 0);
    let s4, t4, ok4 = ntlm::http_token("Basic YWJj");
    tv::check("Basic is not ours", !ok4 && s4 == ntlm::SCHEME_NONE);
    let s5, t5, ok5 = ntlm::http_token("NTLM ***");
    tv::check("bad base64", !ok5 && t5.len == 0);
    var big: u8[>..] = [];
    big.append("NTLM ");
    for i in 100000 { big.push('A'); }
    let s6, t6, ok6 = ntlm::http_token(big);
    tv::check("too long", !ok6);
    let s7, t7, ok7 = ntlm::http_token("NTLMX YWJj");
    tv::check("not the scheme's name", !ok7);
    tv::check("Negotiate header", ntlm::http_header(ntlm::SCHEME_NEGOTIATE, "")[..] == "Negotiate");
}

fn cert(kind: i64, hash: i64) -> u8[>..] {
    let key = x509::generate_key(kind);
    var t, ok = x509::template("CN=web.example.test", 1767225600, 1798761600);
    if hash != 0 { t.sig_hash = hash; }
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), "", key);
    tv::check(str("certificate ", kind, " ", hash), ok && e == x509::OK);
    return der;
}

fn end_point() {
    let c1 = cert(x509::KEY_EC_P256, 256);
    let c2 = cert(x509::KEY_EC_P384, 384);
    var chain: u8[>..] = [];
    chain.append(c1);
    chain.append(c2);
    let leaf, lok = ntlm::leaf_certificate(chain);
    tv::check("leaf of a chain", lok && leaf == c1[..]);
    let leaf2, lok2 = ntlm::leaf_certificate("\x30\x82\xff");
    tv::check("not DER", !lok2);
    let b1, ok1 = ntlm::tls_server_end_point(c1);
    var w1: u8[>..] = [];
    w1.append("tls-server-end-point:");
    w1.append(bignum::hash_bits(256, c1));
    tv::check("SHA-256 certificate", ok1 && b1[..] == w1[..] && b1.len == 21 + 32);
    let b2, ok2 = ntlm::tls_server_end_point(c2);
    tv::check("SHA-384 certificate", ok2 && b2.len == 21 + 48 && b2[21..] == bignum::hash_bits(384, c2)[..]);
    let b3, ok3 = ntlm::tls_server_end_point("not a certificate");
    tv::check("not a certificate", !ok3);
    // The hash MsvAvChannelBindings carries for it.
    tv::check("bindings hash differs by certificate", ntlm::bindings_hash(b1) != ntlm::bindings_hash(b2));
}

fn main() {
    headers();
    end_point();
    tv::done("http");
}
