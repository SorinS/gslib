// est: an EST client (RFC 7030, with RFC 8951's clarifications), for
// getting certificates over HTTPS from the CAs and RAs that speak it:
// Cisco's and the other network vendors' CAs, EJBCA, Dogtag, AWS Private
// CA's connectors, GlobalSign's and DigiCert's EST services, and the IoT
// enrolment servers. /cacerts, /simpleenroll, /simplereenroll, /csrattrs
// and /serverkeygen, under /.well-known/est/ or a label's own path
// segment; authentication by TLS client certificate or HTTP Basic, and a
// request the CA holds (202 and Retry-After) asked again until it is
// done. And the server side of the same requests, for a test CA
// (est::serve; goose-est serve runs it over TLS).
//
//   var hc = http::Client { .. };            // its TLS roots: the EST server's (an "explicit TA", §3.6.1)
//   http::set_credentials(hc, "user", "password");   // Basic, answered to the server's 401
//   var c = est::Client { .. };
//   est::set_server(c, "https://est.example.org");
//   let cas, err = est::cacerts(c, hc);       // the CA's certificates, DER laid end to end
//   let attrs, aerr = est::csrattrs(c, hc);    // what the CA wants in the CSR
//   let certs, eerr = est::enroll(c, hc, csr_der, false);   // waits while the CA holds it
//   // certs: the issued certificate first; its key is the CSR's
//
// Bodies are base64 (RFC 8951 §3: whatever Content-Transfer-Encoding
// says, line breaks and other white space taken out first), certificates
// travel in certs-only CMS (RFC 5652 §5 with no signers), /csrattrs is a
// CsrAttrs SEQUENCE (§4.5.2), /serverkeygen a multipart/mixed of the
// PKCS #8 key and the certificate (§4.4.2). Replies are bounded by
// c.max_body (1 MiB): larger ones are refused, not cut short.
//
// Channel binding (§3.5, tls-unique in the CSR's challengePassword) is
// not done: gslib's HTTP client does not hand a connection's TLS
// unique or exporter values to its caller.

namespace est;

import std;
import base64;
import mime;
import mime.multipart;
import mime.textproto;
import crypto.x509;
import crypto.x509.keys;
import crypto.x509.create;
import crypto.x509.cms;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.ct;
import net.http;
import net.http.client;
import net.http.fetch;
import net.http.cookie;

// --- Errors -------------------------------------------------------------------

let OK:              i64 = 0;
let ERR_ARG:         i64 = 1;  // an argument that cannot be used
let ERR_HTTP:        i64 = 2;  // no response: the connection, TLS, a timeout, a body too large (c.http_err says which)
let ERR_STATUS:      i64 = 3;  // the server answered with an HTTP error (c.status; c.detail its text)
let ERR_MALFORMED:   i64 = 4;  // a response that is not what RFC 7030 says it is
let ERR_AUTH:        i64 = 5;  // 401: credentials were needed, or refused
let ERR_PENDING:     i64 = 6;  // 202: the CA holds the request; c.retry_after_ms says when to ask again
let ERR_TIMEOUT:     i64 = 7;  // still held when poll_timeout_ms ran out
let ERR_KEY:         i64 = 8;  // the certificate issued is not for the request's key (or the key sent)
let ERR_UNSUPPORTED: i64 = 9;  // a server-generated key encrypted to us (§4.4.2's CMS key): not read

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "an argument that cannot be used"; }
    if e == ERR_HTTP { return "the request failed"; }
    if e == ERR_STATUS { return "the server answered with an HTTP error"; }
    if e == ERR_MALFORMED { return "the server's response is not EST"; }
    if e == ERR_AUTH { return "the server wants credentials, or refused them"; }
    if e == ERR_PENDING { return "the CA holds the request"; }
    if e == ERR_TIMEOUT { return "the CA did not decide in time"; }
    if e == ERR_KEY { return "the certificate is not for the request's key"; }
    if e == ERR_UNSUPPORTED { return "an encrypted server-generated key, which this does not read"; }
    return "";
}

let PREFIX: const u8[:] = "/.well-known/est/";

// An EST client: the server, the label (the CA's path segment, §3.2.2),
// and what the last request left.
root struct Client {
    base:            u8[>..] = [],        // https://est.example.org[:port]
    label:           u8[>..] = [],
    http_err:        i64     = 0,
    status:          i64     = 0,         // the last HTTP status
    detail:          u8[>..] = [],        // an error response's text (the first 512 bytes, printable)
    retry_after_ms:  i64     = 0,         // the last 202's Retry-After
    max_body:        i64     = 1 << 20,
    poll_ms:         i64     = 10000,     // between tries when a 202 has no Retry-After
    poll_timeout_ms: i64     = 300000,    // how long enroll asks again
    max_retry_ms:    i64     = 60000,     // a Retry-After longer than this is waited only this long (and the deadline holds)
}

// The server: its scheme and authority, without a path. ERR_ARG for one
// with a path, query or fragment.
fn set_server(c: Client&, base: const u8[:]) -> i64 {
    let sep = find(base, "://");
    if sep <= 0 { return ERR_ARG; }
    let rest = base[sep + 3..];
    if rest.len == 0 || position(rest, '/') >= 0 || position(rest, '?') >= 0 || position(rest, '#') >= 0 { return ERR_ARG; }
    c.base.clear();
    c.base.append(base);
    return OK;
}

// Whether a label is one path segment (§3.2.2): no '/', '?', '#', '%',
// white space or control characters; empty for none.
fn label_ok(label: const u8[:]) -> bool {
    if label.len > 128 { return false; }
    for ch in label {
        if ch <= 0x20 || ch >= 0x7f || ch == '/' || ch == '?' || ch == '#' || ch == '%' || ch == '\\' { return false; }
    }
    return label != "." && label != "..";
}

fn set_label(c: Client&, label: const u8[:]) -> i64 {
    if !label_ok(label) { return ERR_ARG; }
    c.label.clear();
    c.label.append(label);
    return OK;
}

// The URL of an operation: base, /.well-known/est/, the label, the name.
fn op_url(c: const Client&, op: const u8[:]) -> u8[>..] {
    var u: u8[>..] = [];
    u.append(c.base);
    u.append(PREFIX);
    if c.label.len > 0 { u.append(c.label); u.push('/'); }
    u.append(op);
    return u;
}

// --- Base64 and certs-only ----------------------------------------------------

// A base64 body: line breaks and other white space taken out (RFC 8951
// §3), then decoded. False if what is left is not base64.
fn decode_base64(body: const u8[:]) -> u8[>..], bool {
    var text: u8[>..] = [];
    for ch in body {
        if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' { continue; }
        text.push(ch);
    }
    var out: u8[>..] = [];
    if text.len == 0 || !base64::decode(out, text) { out.clear(); return out, false; }
    return out, true;
}

// base64 in lines of 64, as RFC 7030's examples send it (CRLF).
fn encode_base64(der: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    base64::encode(b, der);
    var out: u8[>..] = [];
    var at = 0;
    while at < b.len {
        let end = min(at + 64, b.len);
        out.append(b[at..end]);
        out.append("\r\n");
        at = end;
    }
    return out;
}

// The certificates of a certs-only CMS (DER), laid end to end, each one
// parsed: ERR_MALFORMED for anything else (one with signers, or none).
fn read_certs_only(der: const u8[:]) -> u8[>..], i64 {
    var certs: u8[>..] = [];
    let sd, e = x509::cms_parse_signed_ber(der);
    if e != x509::OK || x509::cms_signed(sd) { return certs, ERR_MALFORMED; }
    certs.append(x509::cms_certs(sd));
    var good = certs.len > 0;
    var at = 0;
    while good && at < certs.len {
        let t, ok = asn1::read(certs, at, certs.len);
        good = ok;
        if ok {
            let c, ce = x509::parse(certs[t.start..t.end]);
            good = ce == x509::OK;
            at = t.end;
        }
    }
    if !good { certs.clear(); }
    return certs, if good { OK } else { ERR_MALFORMED };
}

// Puts the certificate whose key is `spki` first; false if none has it.
fn issued_first(certs: const u8[:], spki: const u8[:]) -> u8[>..], bool {
    var out:  u8[>..] = [];
    var rest: u8[>..] = [];
    var at = 0;
    while at < certs.len {
        let t, ok = asn1::read(certs, at, certs.len);
        if !ok { break; }
        at = t.end;
        let c, e = x509::parse(certs[t.start..t.end]);
        if e != x509::OK { continue; }
        if out.len == 0 && c.der[c.spki.start..c.spki.end] == spki { out.append(certs[t.start..t.end]); }
        else { rest.append(certs[t.start..t.end]); }
    }
    if out.len == 0 { return out, false; }
    out.append(rest);
    return out, true;
}

// The first certificate of several laid end to end, or empty.
fn first_cert(certs: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let t, ok = asn1::read(certs, 0, certs.len);
    if ok { out.append(certs[t.start..t.end]); }
    return out;
}

// --- CSR attributes (§4.5.2) ------------------------------------------------

// What /csrattrs asks for: one line an item, either a bare OID ("1.2.840.
// 113549.1.9.7": put this in the CSR, challengePassword here), or an
// attribute's OID, '=' and its values separated by ',' (each a dotted OID,
// or '#' and the hex of its DER when it is not an OID). Only digits, dots
// and those separators, so a value cannot pass for another line.
struct CsrAttrs {
    items: u8[>..] = [],
}

fn put_hex(out: u8[>..]&, b: const u8[:]) { x509::hex_upper(out, b); }

// Reads CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID (DER).
fn parse_csrattrs(der: const u8[:]) -> CsrAttrs, i64 {
    var a = CsrAttrs { .. };
    let top, ok = asn1::parse(der);
    let items, oki = asn1::children_of(der, top, asn1::SEQUENCE);
    if !ok || !oki { return a, ERR_MALFORMED; }
    for it in items {
        if it.tag == asn1::OID {
            let s, oks = asn1::read_oid(der, it);
            if !oks { return a, ERR_MALFORMED; }
            a.items.append(s);
            a.items.push('\n');
            continue;
        }
        let p, okp = asn1::children_of(der, it, asn1::SEQUENCE);
        if !okp || p.len != 2 || p[0].tag != asn1::OID || p[1].tag != asn1::SET { return a, ERR_MALFORMED; }
        let s, oks = asn1::read_oid(der, p[0]);
        let vals, okv = asn1::children(der, p[1]);
        if !oks || !okv { return a, ERR_MALFORMED; }
        a.items.append(s);
        a.items.push('=');
        var first = true;
        for v in vals {
            if !first { a.items.push(','); }
            first = false;
            if v.tag == asn1::OID {
                let vs, okvs = asn1::read_oid(der, v);
                if !okvs { return a, ERR_MALFORMED; }
                a.items.append(vs);
            } else {
                a.items.push('#');
                put_hex(a.items, der[v.start..v.end]);
            }
        }
        a.items.push('\n');
    }
    return a, OK;
}

// Whether the server asks for `oid`, bare or as an attribute.
fn csrattrs_has(a: const CsrAttrs&, oid: const u8[:]) -> bool {
    for line in split(a.items, '\n') {
        let name, rest, has = split_once(line, '=');
        if name == oid { return true; }
    }
    return false;
}

// The values of attribute `oid` as /csrattrs gives them ("1.3.132.0.34"
// for an EC key's curve, say), separated by ','; empty if absent.
fn csrattrs_values(a: const CsrAttrs&, oid: const u8[:]) -> const u8[:] {
    for line in split(a.items, '\n') {
        let name, rest, has = split_once(line, '=');
        if has && name == oid { return rest; }
    }
    return "";
}

// --- The client ---------------------------------------------------------------

fn limit_body(c: const Client&, hc: http::Client&) {
    if hc.opt.max_body > c.max_body { hc.opt.max_body = c.max_body; }
}

fn take_detail(c: Client&, r: const http::Response&) {
    c.detail.clear();
    let b = http::response_body(r);
    for ch in b[..min(b.len, 512)] {
        c.detail.push(if (ch >= 0x20 && ch < 0x7f) || ch == '\n' { ch } else { '?' });
    }
}

// Retry-After (RFC 9110 §10.2.3) as milliseconds from now: seconds, or an
// HTTP-date; 0 when absent, past or unreadable.
fn retry_after_ms(value: const u8[:], now_ms: i64) -> i64 {
    let v = trim(value);
    if v.len == 0 { return 0; }
    var all_digits = true;
    for ch in v { if ch < '0' || ch > '9' { all_digits = false; } }
    if all_digits {
        if v.len > 9 { return 0; }
        var s = 0;
        for ch in v { s = s * 10 + (ch - '0'); }
        return s * 1000;
    }
    let at, ok = http::parse_cookie_date(v);
    if !ok || at <= now_ms { return 0; }
    return at - now_ms;
}

// The status of a response as an error: OK for 200, ERR_PENDING for 202
// (c.retry_after_ms set), ERR_AUTH for 401, else ERR_STATUS.
fn status_error(c: Client&, r: const http::Response&) -> i64 {
    c.status = r.status;
    if r.status == 200 { return OK; }
    take_detail(c, r);
    if r.status == 202 {
        let v, ok = http::response_header(r, "Retry-After");
        c.retry_after_ms = if ok { retry_after_ms(v, time_ns() / 1000000) } else { 0 };
        return ERR_PENDING;
    }
    if r.status == 401 { return ERR_AUTH; }
    return ERR_STATUS;
}

fn media_type_is(r: const http::Response&, want: const u8[:]) -> bool {
    let v, ok = http::response_header(r, "Content-Type");
    if !ok { return false; }
    let mt = mime::parse_media_type(v);
    return mt.err == 0 && mt.typ[..] == want;
}

// GET /cacerts (§4.1): the CA's certificates, DER laid end to end. The
// caller's TLS configuration said whom to trust for this (§4.1.1: an
// explicit trust anchor, or a manual check of what comes back).
fn cacerts(c: Client&, hc: http::Client&) -> u8[>..], i64 {
    var none: u8[>..] = [];
    if c.base.len == 0 { return none, ERR_ARG; }
    limit_body(c, hc);
    let r = http::request(hc, "GET", op_url(c, "cacerts"), "", "");
    if r.err != 0 { c.http_err = r.err; return none, ERR_HTTP; }
    let se = status_error(c, r);
    if se != OK { return none, se; }
    if !media_type_is(r, "application/pkcs7-mime") { return none, ERR_MALFORMED; }
    let der, ok = decode_base64(http::response_body(r));
    if !ok { return none, ERR_MALFORMED; }
    let certs, e = read_certs_only(der);
    return certs, e;
}

// GET /csrattrs (§4.5): what the CA wants in a CSR. A server with nothing
// to ask (204, or 404 as §4.5.2 allows) gives none, which is not an error.
fn csrattrs(c: Client&, hc: http::Client&) -> CsrAttrs, i64 {
    var a = CsrAttrs { .. };
    if c.base.len == 0 { return a, ERR_ARG; }
    limit_body(c, hc);
    let r = http::request(hc, "GET", op_url(c, "csrattrs"), "", "");
    if r.err != 0 { c.http_err = r.err; return a, ERR_HTTP; }
    c.status = r.status;
    if r.status == 204 || r.status == 404 { return a, OK; }
    let se = status_error(c, r);
    if se != OK { return a, se; }
    if !media_type_is(r, "application/csrattrs") { return a, ERR_MALFORMED; }
    let body = http::response_body(r);
    if trim(body).len == 0 { return a, OK; }
    let der, ok = decode_base64(body);
    if !ok { return a, ERR_MALFORMED; }
    let parsed, e = parse_csrattrs(der);
    return parsed, e;
}

// POSTs a CSR (DER) to op, as application/pkcs10 in base64 (§4.2.1).
fn post_csr(c: Client&, hc: http::Client&, op: const u8[:], csr: const u8[:]) -> http::Response {
    limit_body(c, hc);
    var f: u8[>..] = [];
    http::add_field(f, "Content-Type", "application/pkcs10");
    http::add_field(f, "Content-Transfer-Encoding", "base64");
    return http::request(hc, "POST", op_url(c, op), f, encode_base64(csr));
}

// POST /simpleenroll (or /simplereenroll with `reenroll`, §4.2.2: the
// client's TLS certificate, set in hc.tlscfg before its first request,
// is the one renewed). One try: ERR_PENDING when the CA holds it. The
// issued certificate first (its key the CSR's), then any others sent.
fn simple_enroll(c: Client&, hc: http::Client&, csr: const u8[:], reenroll: bool) -> u8[>..], i64 {
    var none: u8[>..] = [];
    if c.base.len == 0 { return none, ERR_ARG; }
    let req, pe = x509::parse_csr(csr);
    if pe != x509::OK { return none, ERR_ARG; }
    let r = post_csr(c, hc, if reenroll { "simplereenroll" } else { "simpleenroll" }, csr);
    if r.err != 0 { c.http_err = r.err; return none, ERR_HTTP; }
    let se = status_error(c, r);
    if se != OK { return none, se; }
    if !media_type_is(r, "application/pkcs7-mime") { return none, ERR_MALFORMED; }
    let der, ok = decode_base64(http::response_body(r));
    if !ok { return none, ERR_MALFORMED; }
    let certs, e = read_certs_only(der);
    if e != OK { return none, e; }
    let out, found = issued_first(certs, req.der[req.spki.start..req.spki.end]);
    if !found { return none, ERR_KEY; }
    return out, OK;
}

// simple_enroll, asked again while the CA answers 202: after its
// Retry-After (at most max_retry_ms; poll_ms without one), until
// poll_timeout_ms.
fn enroll(c: Client&, hc: http::Client&, csr: const u8[:], reenroll: bool) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let deadline = clock_ns() + c.poll_timeout_ms * 1000000;
    loop {
        let certs, e = simple_enroll(c, hc, csr, reenroll);
        if e != ERR_PENDING { return certs, e; }
        var wait = if c.retry_after_ms > 0 { c.retry_after_ms } else { c.poll_ms };
        if wait > c.max_retry_ms { wait = c.max_retry_ms; }
        if clock_ns() + wait * 1000000 > deadline { return none, ERR_TIMEOUT; }
        sleep_ms(wait);
    }
    return none, ERR_TIMEOUT;
}

// POST /serverkeygen (§4.4): the CA makes the key. The CSR names the
// subject (signed by any key of the client's; the CA uses only its
// fields). The key (PKCS #8 DER, unencrypted, §4.4.2's application/pkcs8)
// and the certificates, the issued one first, its key the one sent.
// ERR_UNSUPPORTED for a key encrypted to the client (application/pkcs7-mime;
// smime-type=server-generated-key).
fn server_keygen(c: Client&, hc: http::Client&, csr: const u8[:]) -> u8[>..], u8[>..], i64 {
    var none:  u8[>..] = [];
    var none2: u8[>..] = [];
    if c.base.len == 0 { return none, none2, ERR_ARG; }
    let r = post_csr(c, hc, "serverkeygen", csr);
    if r.err != 0 { c.http_err = r.err; return none, none2, ERR_HTTP; }
    let se = status_error(c, r);
    if se != OK { return none, none2, se; }
    let ct, okct = http::response_header(r, "Content-Type");
    let key, certs, e = read_keygen(ct, http::response_body(r));
    return key, certs, e;
}

// A /serverkeygen response: its Content-Type (multipart/mixed with a
// boundary) and body. The key and the certificates, issued first.
fn read_keygen(content_type: const u8[:], body: const u8[:]) -> u8[>..], u8[>..], i64 {
    var key:   u8[>..] = [];
    var certs: u8[>..] = [];
    let mt = mime::parse_media_type(content_type);
    let boundary, hasb = mime::param(mt, "boundary");
    if mt.err != 0 || mt.typ[..] != "multipart/mixed" || !hasb || boundary.len == 0 { return key, certs, ERR_MALFORMED; }
    var r = multipart::Reader { .. };
    multipart::init(r, boundary);
    multipart::feed(r, body);
    multipart::finish(r);
    var data:      u8[>..] = [];
    var part_type: u8[>..] = [];
    var keys = 0;
    var cert_parts = 0;
    var encrypted = false;
    loop {
        let ev = multipart::next(r, data);
        if ev == multipart::EV_PART {
            data.clear();
            part_type.clear();
            part_type.append(textproto::get(r.header, "Content-Type"));
        } else if ev == multipart::EV_PART_END {
            if r.part_err != 0 { return key, certs, ERR_MALFORMED; }
            let pt = mime::parse_media_type(part_type);
            if pt.err != 0 { return key, certs, ERR_MALFORMED; }
            let der, ok = decode_base64(data);
            if !ok { return key, certs, ERR_MALFORMED; }
            if pt.typ[..] == "application/pkcs8" {
                keys++;
                key = copy(der);
            } else if pt.typ[..] == "application/pkcs7-mime" {
                let smime, hs = mime::param(pt, "smime-type");
                if hs && smime == "server-generated-key" { encrypted = true; }
                else {
                    cert_parts++;
                    let cs, ce = read_certs_only(der);
                    if ce != OK { return key, certs, ce; }
                    certs = copy(cs);
                }
            }
        } else if ev == multipart::EV_END {
            break;
        } else if ev == multipart::EV_ERROR || ev == multipart::EV_NEED_MORE {
            return key, certs, ERR_MALFORMED;
        }
    }
    if encrypted && keys == 0 { key.clear(); certs.clear(); return key, certs, ERR_UNSUPPORTED; }
    if keys != 1 || cert_parts != 1 { key.clear(); certs.clear(); return key, certs, ERR_MALFORMED; }
    let k, okk = x509::parse_private_key(key);
    if !okk { key.clear(); certs.clear(); return key, certs, ERR_MALFORMED; }
    let ordered, found = issued_first(certs, x509::marshal_public_key(k));
    if !found { key.clear(); certs.clear(); return key, certs, ERR_KEY; }
    return key, ordered, OK;
}

// --- A test CA ------------------------------------------------------------------
//
// The server side, for tests and goose-est serve: /cacerts, /csrattrs
// (`attrs`, DER), /simpleenroll and /simplereenroll (a client certificate
// this CA issued, or Basic credentials when set; a re-enrolment needs the
// client's certificate and the CSR's subject must be its subject),
// /serverkeygen (an RSA or P-256 key by the CSR's key type), and a 202 with
// Retry-After for the first `pending` tries of each key. Under any label.
// Not a CA to run: what it issues is kept nowhere.

root struct Server {
    ca_key:     x509::PrivateKey = x509::empty_key(),
    ca_cert:    u8[>..]          = [],
    user:       u8[>..]          = [],      // Basic credentials; empty: none asked
    password:   u8[>..]          = [],
    attrs:      u8[>..]          = [],      // /csrattrs' CsrAttrs DER; empty: 204
    pending:    i64              = 0,       // 202s each key gets before it is issued
    retry_s:    i64              = 1,       // their Retry-After
    validity_s: i64              = 30 * 86400,
    seen:       u8[>..]          = [],      // the keys answered 202: SEQUENCE { key hash, count } laid end to end
    log:        u8[>..]          = [],
}

struct Answer {
    status:       i64       = 200,
    content_type: u8[..128] = [],
    fields:       u8[..512] = [],           // more header lines, each "Name: value\r\n"
    body:         u8[>..]   = [],
}

fn answer(status: i64, ct: const u8[:], body: const u8[:]) -> Answer {
    var a = Answer { .. };
    a.status = status;
    a.content_type.append(ct);
    a.body.append(body);
    return a;
}

fn log_line(s: Server&, what: const u8[:]) {
    if s.log.len < 65536 { s.log.append(what); s.log.push('\n'); }
}

// The value of a header field in `fields` ("Name: value\r\n" lines).
fn field(fields: const u8[:], name: const u8[:]) -> const u8[:], bool {
    let v, ok = http::field_value(fields, name);
    return v, ok;
}

// Whether the Authorization field holds the server's Basic credentials.
fn basic_ok(s: const Server&, fields: const u8[:]) -> bool {
    let v, ok = field(fields, "Authorization");
    if !ok || v.len < 6 || !x509::eq_nocase(v[..6], "basic ") { return false; }
    var raw: u8[>..] = [];
    if !base64::decode(raw, trim(v[6..])) { return false; }
    var want: u8[>..] = [];
    want.append(s.user);
    want.push(':');
    want.append(s.password);
    return raw.len == want.len && bignum::ct_eq_bytes(raw, want) == 1;
}

// Whether `chain` (the TLS client's, DER laid end to end) starts with a
// certificate this CA issued.
fn client_cert_ok(s: const Server&, chain: const u8[:]) -> x509::Cert, bool {
    let leaf = first_cert(chain);
    let c, e = x509::parse(leaf);
    let ca, cae = x509::parse(s.ca_cert);
    if e != x509::OK || cae != x509::OK { return c, false; }
    // The CA's own certificate is signed by itself, and is no client's.
    return c, leaf[..] != s.ca_cert[..] && !c.is_ca && x509::check_signature(c, ca) == x509::OK;
}

// One more try by the key with this hash: whether it must wait.
fn held(s: Server&, key_hash: const u8[:]) -> bool {
    if s.pending <= 0 { return false; }
    var kept: u8[>..] = [];
    let all = copy(s.seen);
    var count: i64 = 0;
    var at = 0;
    while at < all.len {
        let t, ok = asn1::read(all, at, all.len);
        if !ok { break; }
        at = t.end;
        let p, okp = asn1::children_of(all, t, asn1::SEQUENCE);
        if okp && p.len == 2 && all[p[0].off..p[0].end] == key_hash {
            let n, okn = asn1::read_i64(all, p[1]);
            count = n;
        } else {
            kept.append(all[t.start..t.end]);
        }
    }
    count++;
    var b: u8[>..] = [];
    asn1::put_octets(b, key_hash);
    asn1::put_i64(b, count);
    asn1::put(kept, asn1::SEQUENCE, b);
    s.seen = copy(kept);
    return count <= s.pending;
}

fn issue(s: const Server&, r: const x509::Csr&, spki: const u8[:], now: i64) -> u8[>..], bool {
    var none: u8[>..] = [];
    let d = r.der[..];
    var t, okt = x509::template("", now - 300, now + s.validity_s);
    if r.subject.end - r.subject.start > t.subject.cap { return none, false; }
    t.subject.clear();
    t.subject.append(d[r.subject.start..r.subject.end]);
    if r.has_san {
        if r.san.end - r.san.off > t.san.cap { return none, false; }
        t.san.append(d[r.san.off..r.san.end]);
    }
    t.basic_constraints = true;
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = x509::EKU_CLIENT_AUTH | x509::EKU_SERVER_AUTH;
    let cert, e = x509::create_certificate(t, spki, s.ca_cert, s.ca_key);
    return cert, e == x509::OK;
}

fn certs_only_answer(certs: const u8[:]) -> Answer {
    var a = answer(200, "application/pkcs7-mime; smime-type=certs-only", encode_base64(x509::cms_certs_only(certs, "")));
    a.fields.append("Content-Transfer-Encoding: base64\r\n");
    return a;
}

fn unauthorized() -> Answer {
    var a = answer(401, "text/plain", "credentials needed\n");
    a.fields.append("WWW-Authenticate: Basic realm=\"estserver\"\r\n");
    return a;
}

// The CSR of a request body (base64 of DER), checked.
fn read_csr_body(body: const u8[:]) -> x509::Csr, bool {
    let der, ok = decode_base64(body);
    let r, e = x509::parse_csr(der);
    return r, ok && e == x509::OK && x509::check_csr(r) == x509::OK;
}

fn enroll_answer(s: Server&, op: const u8[:], fields: const u8[:], body: const u8[:], chain: const u8[:], now: i64) -> Answer {
    let reenroll = op == "simplereenroll";
    let keygen = op == "serverkeygen";
    let cc, has_cert = client_cert_ok(s, chain);
    if reenroll && !has_cert {
        log_line(s, "simplereenroll without a client certificate this CA issued");
        return answer(403, "text/plain", "re-enrolment needs the certificate being renewed\n");
    }
    if !has_cert && s.user.len > 0 && !basic_ok(s, fields) {
        log_line(s, str(op, ": no credentials, or the wrong ones: 401"));
        return unauthorized();
    }
    let r, okr = read_csr_body(body);
    if !okr { log_line(s, str(op, ": not a CSR that verifies")); return answer(400, "text/plain", "not a CSR\n"); }
    let d = r.der[..];
    if reenroll && d[r.subject.start..r.subject.end] != cc.der[cc.subject.start..cc.subject.end] {
        log_line(s, "simplereenroll for another subject");
        return answer(400, "text/plain", "the subject is not the certificate's\n");
    }
    let spki = d[r.spki.start..r.spki.end];
    if !keygen && held(s, bignum::sha256(spki)[..]) {
        log_line(s, str(op, ": held, 202"));
        var a = answer(202, "text/plain", "the request is held\n");
        a.fields.append("Retry-After: ");
        format(a.fields, s.retry_s);
        a.fields.append("\r\n");
        return a;
    }
    if keygen {
        // A key of the CSR's key's kind: P-256 for EC, else RSA 2048.
        let k = if x509::is_ec(r.key_type) { x509::generate_key(x509::KEY_EC_P256) } else { x509::generate_key(x509::KEY_RSA, 2048) };
        let cert, ok = issue(s, r, x509::marshal_public_key(k), now);
        if !ok { return answer(500, "text/plain", "cannot issue\n"); }
        let boundary = "estServerKeyGenBoundary";
        var b: u8[>..] = [];
        b.append("--estServerKeyGenBoundary\r\nContent-Type: application/pkcs8\r\nContent-Transfer-Encoding: base64\r\n\r\n");
        b.append(encode_base64(x509::marshal_pkcs8(k)));
        b.append("--estServerKeyGenBoundary\r\nContent-Type: application/pkcs7-mime; smime-type=certs-only\r\nContent-Transfer-Encoding: base64\r\n\r\n");
        b.append(encode_base64(x509::cms_certs_only(cert, "")));
        b.append("--estServerKeyGenBoundary--\r\n");
        log_line(s, "serverkeygen: issued");
        return answer(200, str("multipart/mixed; boundary=", boundary), b);
    }
    let cert, ok = issue(s, r, spki, now);
    if !ok { return answer(500, "text/plain", "cannot issue\n"); }
    log_line(s, str(op, ": issued"));
    return certs_only_answer(cert);
}

// Answers one request: method, target (path and query), the header
// fields ("Name: value\r\n" lines), the body, the TLS client's
// certificates (DER laid end to end, empty for none; the TLS layer has
// checked they chain to the CA), and the time.
fn serve(s: Server&, method: const u8[:], target: const u8[:], fields: const u8[:], body: const u8[:], chain: const u8[:],
         now: i64) -> Answer {
    var path = target;
    let q = position(target, '?');
    if q >= 0 { path = target[..q]; }
    if path.len <= PREFIX.len || path[..PREFIX.len] != PREFIX { return answer(404, "text/plain", "not EST\n"); }
    var rest = path[PREFIX.len..];
    let slash = position(rest, '/');
    if slash >= 0 {
        if !label_ok(rest[..slash]) { return answer(404, "text/plain", "no such label\n"); }
        rest = rest[slash + 1..];
    }
    if rest == "cacerts" && method == "GET" {
        log_line(s, "cacerts");
        return certs_only_answer(s.ca_cert);
    }
    if rest == "csrattrs" && method == "GET" {
        if s.attrs.len == 0 { return answer(204, "application/csrattrs", ""); }
        return answer(200, "application/csrattrs", encode_base64(s.attrs));
    }
    if (rest == "simpleenroll" || rest == "simplereenroll" || rest == "serverkeygen") && method == "POST" {
        let ct, okct = field(fields, "Content-Type");
        let mt = mime::parse_media_type(ct);
        if !okct || mt.err != 0 || mt.typ[..] != "application/pkcs10" {
            return answer(415, "text/plain", "the body must be application/pkcs10\n");
        }
        return enroll_answer(s, rest, fields, body, chain, now);
    }
    return answer(404, "text/plain", "no such operation\n");
}
