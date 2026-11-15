// ntlm.http: NTLM as HTTP carries it ([MS-NTHT]): "Authorization: NTLM
// <base64>" and "WWW-Authenticate: NTLM <base64>", or the same NTLMSSP
// tokens under the Negotiate scheme (RFC 4559) when the peer offers only
// Negotiate and there is no Kerberos: IIS and http.sys take a raw
// NTLMSSP token there, as they take a SPNEGO one. The authentication is
// the connection's: the three messages go on one kept-alive connection,
// over HTTP/1.1 (never HTTP/2, which has no connection-bound
// authentication).
//
// Channel bindings over HTTPS are RFC 5929's tls-server-end-point: the
// hash of the server's certificate, by its signature's hash (SHA-256 for
// MD5, SHA-1 and signatures that name none).

namespace ntlm;

import std;
import base64;
import encoding.asn1;
import crypto.x509;
import crypto.bignum;
import crypto.bignum.hmac;

let SCHEME_NONE:      i64 = 0;
let SCHEME_NTLM:      i64 = 1;
let SCHEME_NEGOTIATE: i64 = 2;

fn scheme_name(s: i64) -> const u8[:] { if s == SCHEME_NEGOTIATE { "Negotiate" } else { "NTLM" } }

// "NTLM <base64 token>" (or "Negotiate ..."), for Authorization or
// WWW-Authenticate.
fn http_header(scheme: i64, token: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(scheme_name(scheme));
    if token.len > 0 {
        out.push(' ');
        base64::encode(out, token);
    }
    return out;
}

fn lower_eq(a: const u8[:], b: const u8[:]) -> bool { eq_fold_ascii(a, b) }

// The scheme and token of an Authorization or WWW-Authenticate value
// that is NTLM or Negotiate ("NTLM" alone: an empty token); ok false for
// another scheme or a token that is not base64 (or larger than
// MAX_MESSAGE).
fn http_token(value: const u8[:]) -> i64, u8[>..], bool {
    var out: u8[>..] = [];
    var v = value;
    while v.len > 0 && (v[0] == ' ' || v[0] == '\t') { v = v[1..]; }
    while v.len > 0 && (v[v.len - 1] == ' ' || v[v.len - 1] == '\t' || v[v.len - 1] == '\r' || v[v.len - 1] == '\n') { v = v[..v.len - 1]; }
    var sp = 0;
    while sp < v.len && v[sp] != ' ' && v[sp] != '\t' { sp++; }
    let name = v[..sp];
    let scheme = if lower_eq(name, "NTLM") { SCHEME_NTLM } else if lower_eq(name, "Negotiate") { SCHEME_NEGOTIATE } else { SCHEME_NONE };
    if scheme == SCHEME_NONE { return scheme, out, false; }
    var rest = v[sp..];
    while rest.len > 0 && (rest[0] == ' ' || rest[0] == '\t') { rest = rest[1..]; }
    if rest.len == 0 { return scheme, out, true; }
    if rest.len > MAX_MESSAGE * 4 / 3 + 4 { return scheme, out, false; }
    if !base64::decode(out, rest) { out.clear(); return scheme, out, false; }
    return scheme, out, true;
}

// The first certificate of a DER chain (tls::peer_certificates' leaf).
fn leaf_certificate(chain: const u8[:]) -> const u8[:], bool {
    let t, ok = asn1::read(chain, 0, chain.len, false);
    if !ok { return chain[..0], false; }
    return chain[t.start..t.end], true;
}

// RFC 5929's tls-server-end-point channel binding of a certificate (DER):
// "tls-server-end-point:" and its hash, as the application data of
// gss_channel_bindings_struct.
fn tls_server_end_point(cert_der: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let c, e = x509::parse(cert_der);
    if e != x509::OK { return out, false; }
    let hashed = c.sig_alg == x509::SIG_RSA_PKCS1 || c.sig_alg == x509::SIG_RSA_PSS || c.sig_alg == x509::SIG_ECDSA ||
                 c.sig_alg == x509::SIG_DSA;
    let bits = if hashed && (c.sig_hash == 384 || c.sig_hash == 512) { c.sig_hash } else { 256 };
    out.append("tls-server-end-point:");
    out.append(bignum::hash_bits(bits, cert_der));
    return out, true;
}
