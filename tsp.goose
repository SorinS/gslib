// tsp: the Time-Stamp Protocol (RFC 3161, with RFC 5816's ESSCertIDv2):
// asking a time-stamping authority (TSA) to sign the hash of some data
// with the time, checking what it answers, and being one.
//
//   let req, err = tsp::new_request(tsp::SHA256, data);      // a nonce, certReq
//   let der, eq = tsp::request_der(req);
//   let reply, err2, status = tsp::post(hc, "http://tsa.example.org/tsr", der);
//   let r, perr = tsp::parse_response(reply);
//   var roots = x509::new_pool();                            // the TSA's roots
//   let info, verr, why = tsp::verify_reply(r, req, roots, "", tsp::VerifyOptions { .. });
//   // info.gen_time: seconds since 1970; why: the x509 error behind ERR_CHAIN and the like
//
// A reply is checked as RFC 3161 §2.4.2 has it: granted, its token a
// SignedData of a TSTInfo signed by one signer, the signature and signed
// attributes good, the signer named by an ESSCertID (signingCertificate)
// or ESSCertIDv2 (signingCertificateV2), the TSA's certificate with a
// critical extended key usage of id-kp-timeStamping alone (§2.3) and a path
// to the roots at the time stamped, the imprint and nonce those asked for,
// the policy the one asked for, the TSA's name its certificate's.
//
// A TSA: a Tsa (its key, certificate, chain, policy, accuracy) answers a
// request's DER with a reply's DER (`respond`), a token signed with
// signingCertificateV2, the serial numbers random or counted, refusing
// (with PKIStatusInfo's failInfo) what it does not take.
//
// A token over a CMS signature (RFC 3161 Appendix A): `add_signature_token`
// puts it in a SignerInfo's unsigned attributes as
// id-aa-signatureTimeStampToken, `verify_signature_token` checks it.

namespace tsp;

import std;
import crypto.bignum;
import crypto.bignum.hmac;
import crypto.x509;
import crypto.x509.keys;
import crypto.x509.cms;
import crypto.x509.pool;
import crypto.x509.verify;
import encoding.asn1;
import net.http;
import net.http.client;
import net.http.fetch;

// --- Errors -------------------------------------------------------------------

let OK:              i64 = 0;
let ERR_ARG:         i64 = 1;    // an argument that cannot be used
let ERR_MALFORMED:   i64 = 2;    // not DER, not what RFC 3161 says, or a field too long to keep
let ERR_REJECTED:    i64 = 3;    // the TSA refused (status rejection or worse; r.fail_info says why)
let ERR_UNSUPPORTED: i64 = 4;    // a hash not taken (SHA-1 unless allowed, or unknown)
let ERR_IMPRINT:     i64 = 5;    // the token's message imprint is not the data's
let ERR_NONCE:       i64 = 6;    // the nonce is not the request's
let ERR_POLICY:      i64 = 7;    // the policy is not the one asked for
let ERR_SIGNATURE:   i64 = 8;    // the CMS signature or its attributes do not verify (why: the x509 error)
let ERR_SIGNER:      i64 = 9;    // no certificate for the signer, or no signingCertificate(V2) naming it
let ERR_TSA_CERT:    i64 = 10;   // the signer's certificate is not a TSA's (§2.3: critical EKU, timeStamping only)
let ERR_CHAIN:       i64 = 11;   // no path to the roots at the time stamped (why: the x509 error)
let ERR_TSA_NAME:    i64 = 12;   // the token's TSA name is not its certificate's
let ERR_CERT_REQ:    i64 = 13;   // certReq asked for the TSA's certificate, and it is not in the token
let ERR_TIME:        i64 = 14;   // the time is further from the clock than allowed
let ERR_HTTP:        i64 = 15;   // no reply over HTTP, or not a timestamp-reply
let ERR_SIGNING:     i64 = 16;   // the TSA could not sign
let ERR_NO_TOKEN:    i64 = 17;   // a CMS signature without a signatureTimeStampToken

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "an argument that cannot be used"; }
    if e == ERR_MALFORMED { return "malformed"; }
    if e == ERR_REJECTED { return "the TSA refused the request"; }
    if e == ERR_UNSUPPORTED { return "a hash algorithm not taken"; }
    if e == ERR_IMPRINT { return "the message imprint does not match"; }
    if e == ERR_NONCE { return "the nonce does not match"; }
    if e == ERR_POLICY { return "the policy is not the one asked for"; }
    if e == ERR_SIGNATURE { return "the signature does not verify"; }
    if e == ERR_SIGNER { return "the signer's certificate is missing or not the one named"; }
    if e == ERR_TSA_CERT { return "the signer's certificate is not a TSA's"; }
    if e == ERR_CHAIN { return "the TSA's certificate does not chain to the roots"; }
    if e == ERR_TSA_NAME { return "the TSA name is not the certificate's"; }
    if e == ERR_CERT_REQ { return "the TSA's certificate was asked for and not sent"; }
    if e == ERR_TIME { return "the time is too far from the clock"; }
    if e == ERR_HTTP { return "no time-stamp reply over HTTP"; }
    if e == ERR_SIGNING { return "the TSA could not sign"; }
    if e == ERR_NO_TOKEN { return "no signature time-stamp token"; }
    return "";
}

// Hashes, by their bits as x509 and bignum name them.
let SHA1:   i64 = 160;
let SHA256: i64 = 256;
let SHA384: i64 = 384;
let SHA512: i64 = 512;

// PKIStatus (§2.4.2).
let GRANTED:                 i64 = 0;
let GRANTED_WITH_MODS:       i64 = 1;
let REJECTION:               i64 = 2;
let WAITING:                 i64 = 3;
let REVOCATION_WARNING:      i64 = 4;
let REVOCATION_NOTIFICATION: i64 = 5;

// PKIFailureInfo's bits, as masks of fail_info.
let FAIL_BAD_ALG:                u32 = 1;         // 0: unrecognized or unsupported algorithm
let FAIL_BAD_REQUEST:            u32 = 4;         // 2: transaction not permitted or supported
let FAIL_BAD_DATA_FORMAT:        u32 = 32;        // 5: the data submitted has the wrong format
let FAIL_TIME_NOT_AVAILABLE:     u32 = 16384;     // 14: the TSA's time source is not available
let FAIL_UNACCEPTED_POLICY:      u32 = 32768;     // 15: the policy is not supported by the TSA
let FAIL_UNACCEPTED_EXTENSION:   u32 = 65536;     // 16: the extension is not supported by the TSA
let FAIL_ADD_INFO_NOT_AVAILABLE: u32 = 131072;    // 17: the additional information is not available
let FAIL_SYSTEM_FAILURE:         u32 = 33554432;  // 25: the request cannot be handled by a system failure

let OID_TST_INFO:         const u8[:] = "1.2.840.113549.1.9.16.1.4";
let OID_SIGNING_CERT:     const u8[:] = "1.2.840.113549.1.9.16.2.12";
let OID_SIGNING_CERT_V2:  const u8[:] = "1.2.840.113549.1.9.16.2.47";
let OID_SIGNATURE_TST:    const u8[:] = "1.2.840.113549.1.9.16.2.14";
let OID_KP_TIME_STAMPING: const u8[:] = "1.3.6.1.5.5.7.3.8";
let OID_SHA1:             const u8[:] = "1.3.14.3.2.26";

let MAX_OID:    i64 = 128;  // a policy's dotted text
let MAX_NONCE:  i64 = 32;   // a nonce's INTEGER content
let MAX_SERIAL: i64 = 32;   // a serial number's (RFC 3161: up to 160 bits must be taken)
let MAX_TEXT:   i64 = 2048; // a status string's text

// --- Types ----------------------------------------------------------------------

// A request (TimeStampReq, §2.4.1): the hash of the data and its
// algorithm, the policy wanted (a dotted OID, or empty), a nonce (the
// INTEGER's content bytes, or empty), whether the TSA's certificate should
// come back in the token. `imprint_der` is the MessageImprint as sent or
// read, which a TSA echoes; `extensions` that the request had some.
struct Request {
    hash:        i64       = SHA256,
    imprint:     u8[..64]  = [],
    policy:      u8[..128] = [],
    nonce:       u8[..32]  = [],
    cert_req:    bool      = false,
    extensions:  bool      = false,
    imprint_der: u8[..128] = [],
}

// What a token says (TSTInfo, §2.4.2). gen_time is seconds since 1970;
// gen_frac the fraction of a second as sent (digits, without the dot) and
// gen_ns its first nine digits as nanoseconds. Accuracy's parts are -1
// when absent (and has_accuracy false when it is). `tsa` is the TSA's
// GeneralName, DER, or empty. `serial` and `nonce` are their INTEGERs'
// content bytes.
struct TstInfo {
    version:      i64        = 0,
    policy:       u8[..128]  = [],
    hash:         i64        = 0,
    imprint:      u8[..64]   = [],
    serial:       u8[..32]   = [],
    gen_time:     i64        = 0,
    gen_frac:     u8[..32]   = [],
    gen_ns:       i64        = 0,
    has_accuracy: bool       = false,
    acc_seconds:  i64        = -1,
    acc_millis:   i64        = -1,
    acc_micros:   i64        = -1,
    ordering:     bool       = false,
    nonce:        u8[..32]   = [],
    tsa:          u8[..1024] = [],
    extensions:   bool       = false,
}

// A reply (TimeStampResp): the status, its text (the statusString's
// strings, one a line), the failInfo bits (FAIL_*), and the token (a
// ContentInfo, DER) when granted.
struct Response {
    status:      i64        = -1,
    status_text: u8[..2048] = [],
    fail_info:   u32        = 0,
    token:       u8[>..]    = [],
}

// How tokens are checked. `now` (seconds since 1970) and `max_skew`
// (seconds, plus the token's accuracy) check genTime against the clock
// when now > 0. `policy` is the policy wanted when not empty.
struct VerifyOptions {
    allow_sha1: bool      = false,
    now:        i64       = 0,
    max_skew:   i64       = 300,
    policy:     u8[..128] = [],
}

// --- Small things ------------------------------------------------------------------

fn hash_len(h: i64) -> i64 {
    if h == SHA1 { return 20; }
    if h == SHA256 { return 32; }
    if h == SHA384 { return 48; }
    if h == SHA512 { return 64; }
    return 0;
}

fn hash_name(h: i64) -> const u8[:] {
    if h == SHA1 { return "SHA-1"; }
    if h == SHA256 { return "SHA-256"; }
    if h == SHA384 { return "SHA-384"; }
    if h == SHA512 { return "SHA-512"; }
    return "unknown";
}

// The hash a name gives (sha1, sha256, SHA-384, ...), or 0.
fn hash_by_name(name: const u8[:]) -> i64 {
    var n: u8[>..] = [];
    for c in name { if c != '-' { n.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); } }
    if n == "sha1" { return SHA1; }
    if n == "sha256" { return SHA256; }
    if n == "sha384" { return SHA384; }
    if n == "sha512" { return SHA512; }
    return 0;
}

fn digest(h: i64, data: const u8[:]) -> u8[>..] { bignum::hash_bits(h, data) }

// The AlgorithmIdentifier of a hash, parameters NULL as openssl writes it.
fn put_hash_alg(out: u8[>..]&, h: i64) {
    var body: u8[>..] = [];
    asn1::put_oid(body, if h == SHA1 { OID_SHA1 } else { x509::hash_oid(h) });
    asn1::put_null(body);
    asn1::put(out, asn1::SEQUENCE, body);
}

// MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
fn put_imprint(out: u8[>..]&, h: i64, d: const u8[:]) {
    var body: u8[>..] = [];
    put_hash_alg(body, h);
    asn1::put_octets(body, d);
    asn1::put(out, asn1::SEQUENCE, body);
}

// A MessageImprint read: the hash (0 if not one of the four) and the
// digest; false if malformed or the digest is not the hash's length.
fn read_imprint(d: const u8[:], t: asn1::Tlv, h: i64&, out: u8[..64]&) -> bool {
    let p, ok = asn1::children_of(d, t, asn1::SEQUENCE);
    if !ok || p.len != 2 || p[1].tag != asn1::OCTET_STRING || p[0].tag != asn1::SEQUENCE { return false; }
    let hh = x509::cms_digest_of(d, p[0]);
    h = if hash_len(hh) > 0 { hh } else { 0 };
    let n = asn1::content_len(p[1]);
    if n > 64 || (h != 0 && n != hash_len(h)) { return false; }
    out.clear();
    out.append(d[p[1].off..p[1].end]);
    return true;
}

// An OID's dotted text into a field, false if it is too long to keep.
fn read_oid_into(d: const u8[:], t: asn1::Tlv, out: u8[..128]&) -> bool {
    let s, ok = asn1::read_oid(d, t);
    if !ok || s.len > MAX_OID { return false; }
    out.clear();
    out.append(s);
    return true;
}

fn valid_oid(text: const u8[:]) -> bool {
    if text.len == 0 || text.len > MAX_OID { return false; }
    let b, ok = asn1::oid_encode(text);
    return ok;
}

// An INTEGER's content into a field, DER-minimal, false if too long.
fn read_int_into(d: const u8[:], t: asn1::Tlv, out: u8[..32]&) -> bool {
    let b, ok = asn1::read_int_bytes(d, t);
    if !ok || b.len > 32 { return false; }
    out.clear();
    out.append(b);
    return true;
}

// Random positive INTEGER content of n bytes, minimal.
fn random_int(n: i64) -> u8[>..] {
    var b: u8[>..] = [];
    b.resize(n, 0);
    entropy::random_bytes(b);
    b[0] = (b[0] & 0x7f) | 0x01;
    return b;
}

fn hex(out: u8[>..]&, b: const u8[:]) {
    let digits = "0123456789abcdef";
    for c in b { out.push(digits[c >> 4]); out.push(digits[c & 15]); }
}

// Hex text as bytes; false for an odd length or a character not hex.
fn unhex(s: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if s.len % 2 != 0 { return out, false; }
    var i = 0;
    while i < s.len {
        let a = ascii::hex_value(s[i]);
        let b = ascii::hex_value(s[i + 1]);
        if a < 0 || b < 0 { out.clear(); return out, false; }
        out.push((a * 16 + b) as! u8);
        i += 2;
    }
    return out, true;
}

// --- Requests ------------------------------------------------------------------------

// A request for `data` hashed by h (SHA256, SHA384, SHA512; SHA1 only with
// allow_sha1), with a random 64-bit nonce, asking for the TSA's
// certificate when cert_req.
fn new_request(h: i64, data: const u8[:], cert_req: bool = true, allow_sha1: bool = false) -> Request, i64 {
    let d = digest(if hash_len(h) > 0 { h } else { SHA256 }, data);
    let r, e = request_for_digest(h, d, cert_req, allow_sha1);
    return r, e;
}

// A request for a digest already made.
fn request_for_digest(h: i64, d: const u8[:], cert_req: bool = true, allow_sha1: bool = false) -> Request, i64 {
    var r = Request { .. };
    if hash_len(h) == 0 || (h == SHA1 && !allow_sha1) { return r, ERR_UNSUPPORTED; }
    if d.len != hash_len(h) { return r, ERR_ARG; }
    r.hash = h;
    r.imprint.append(d);
    r.nonce.append(random_int(8));
    r.cert_req = cert_req;
    return r, OK;
}

// TimeStampReq ::= SEQUENCE { version INTEGER { v1(1) }, messageImprint MessageImprint,
//     reqPolicy TSAPolicyId OPTIONAL, nonce INTEGER OPTIONAL,
//     certReq BOOLEAN DEFAULT FALSE, extensions [0] IMPLICIT Extensions OPTIONAL }
fn request_der(r: const Request&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if hash_len(r.hash) == 0 || r.imprint.len != hash_len(r.hash) { return out, ERR_ARG; }
    if r.policy.len > 0 && !valid_oid(r.policy) { return out, ERR_ARG; }
    if r.nonce.len > 0 && !int_bytes_ok(r.nonce) { return out, ERR_ARG; }
    var body: u8[>..] = [];
    asn1::put_i64(body, 1);
    put_imprint(body, r.hash, r.imprint);
    if r.policy.len > 0 { asn1::put_oid(body, r.policy); }
    if r.nonce.len > 0 { asn1::put(body, asn1::INTEGER, r.nonce); }
    if r.cert_req { asn1::put_bool(body, true); }
    asn1::put(out, asn1::SEQUENCE, body);
    return out, OK;
}

// Whether bytes are a minimal INTEGER's content.
fn int_bytes_ok(b: const u8[:]) -> bool {
    if b.len == 0 { return false; }
    if b.len == 1 { return true; }
    return !(b[0] == 0 && b[1] < 0x80) && !(b[0] == 0xff && b[1] >= 0x80);
}

// Reads a TimeStampReq. A hash that is not one of the four leaves r.hash 0
// (a TSA refuses it with badAlg); extensions set r.extensions.
fn parse_request(der: const u8[:]) -> Request, i64 {
    var r = Request { .. };
    let top, ok = asn1::parse(der);
    let f, okf = asn1::children_of(der, top, asn1::SEQUENCE);
    if !ok || !okf || f.len < 2 { return r, ERR_MALFORMED; }
    let v, okv = asn1::read_i64(der, f[0]);
    if !okv || v != 1 { return r, ERR_MALFORMED; }
    var h = 0;
    if !read_imprint(der, f[1], h, r.imprint) { return r, ERR_MALFORMED; }
    r.hash = h;
    if asn1::content_len(f[1]) + 4 > 128 { return r, ERR_MALFORMED; }
    r.imprint_der.append(der[f[1].start..f[1].end]);
    var i = 2;
    if i < f.len && f[i].tag == asn1::OID {
        if !read_oid_into(der, f[i], r.policy) { return r, ERR_MALFORMED; }
        i++;
    }
    if i < f.len && f[i].tag == asn1::INTEGER {
        if !read_int_into(der, f[i], r.nonce) { return r, ERR_MALFORMED; }
        i++;
    }
    if i < f.len && f[i].tag == asn1::BOOLEAN {
        let b, okb = asn1::read_bool(der, f[i]);
        if !okb || !b { return r, ERR_MALFORMED; }     // DER leaves a FALSE default out
        r.cert_req = true;
        i++;
    }
    if i < f.len && f[i].tag == asn1::ctx(0, true) {
        r.extensions = true;
        i++;
    }
    if i != f.len { return r, ERR_MALFORMED; }
    return r, OK;
}

// --- Times ----------------------------------------------------------------------------

// GeneralizedTime as RFC 3161 has it: YYYYMMDDhhmmss[.f*]Z, the fraction
// without trailing zeros. Seconds since 1970, and the fraction's digits.
fn read_gen_time(d: const u8[:], t: asn1::Tlv, frac: u8[..32]&) -> i64, bool {
    if t.tag != asn1::GENERALIZED_TIME { return 0, false; }
    let s = d[t.off..t.end];
    if s.len < 15 || s[s.len - 1] != 'Z' { return 0, false; }
    var whole: u8[>..] = [];
    whole.append(s[..14]);
    whole.push('Z');
    if s.len > 15 {
        if s[14] != '.' || s.len < 17 || s.len - 16 > 32 { return 0, false; }
        let f = s[15..s.len - 1];
        for c in f { if c < '0' || c > '9' { return 0, false; } }
        if f[f.len - 1] == '0' { return 0, false; }
        frac.clear();
        frac.append(f);
    }
    // read_time on the whole seconds.
    var tmp: u8[>..] = [];
    asn1::put(tmp, asn1::GENERALIZED_TIME, whole);
    let tt, okt = asn1::parse(tmp);
    let secs, oks = asn1::read_time(tmp, tt);
    return secs, okt && oks;
}

// Nanoseconds of a fraction's digits: the first nine.
fn frac_ns(frac: const u8[:]) -> i64 {
    var ns: i64 = 0;
    for i in 9 { ns = ns * 10 + (if i < frac.len { (frac[i] - '0') as i64 } else { 0 }); }
    return ns;
}

// GeneralizedTime of a time in nanoseconds, with `digits` (0 to 9) of the
// fraction, trailing zeros dropped.
fn put_gen_time(out: u8[>..]&, unix_ns: i64, digits: i64) {
    let secs = if unix_ns >= 0 { unix_ns / 1000000000 } else { (unix_ns - 999999999) / 1000000000 };
    let ns = unix_ns - secs * 1000000000;
    let days = if secs >= 0 { secs / 86400 } else { (secs - 86399) / 86400 };
    let sod = secs - days * 86400;
    let y, m, dd = asn1::civil_from_days(days);
    var s: u8[>..] = [];
    format_int(s, y, 10, 4, '0');
    format_int(s, m, 10, 2, '0');
    format_int(s, dd, 10, 2, '0');
    format_int(s, sod / 3600, 10, 2, '0');
    format_int(s, sod / 60 % 60, 10, 2, '0');
    format_int(s, sod % 60, 10, 2, '0');
    if digits > 0 {
        var f: u8[>..] = [];
        format_int(f, ns, 10, 9, '0');
        var n = ::min(digits, 9);
        while n > 0 && f[n - 1] == '0' { n--; }
        if n > 0 { s.push('.'); s.append(f[..n]); }
    }
    s.push('Z');
    asn1::put(out, asn1::GENERALIZED_TIME, s);
}

// --- Tokens ------------------------------------------------------------------------------

// TSTInfo ::= SEQUENCE { version INTEGER { v1(1) }, policy TSAPolicyId,
//     messageImprint MessageImprint, serialNumber INTEGER, genTime GeneralizedTime,
//     accuracy Accuracy OPTIONAL, ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
//     tsa [0] GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL }
fn parse_tst_info(der: const u8[:]) -> TstInfo, i64 {
    var info = TstInfo { .. };
    let top, ok = asn1::parse(der);
    let f, okf = asn1::children_of(der, top, asn1::SEQUENCE);
    if !ok || !okf || f.len < 5 { return info, ERR_MALFORMED; }
    let v, okv = asn1::read_i64(der, f[0]);
    if !okv || v != 1 { return info, ERR_MALFORMED; }
    info.version = v;
    if f[1].tag != asn1::OID || !read_oid_into(der, f[1], info.policy) { return info, ERR_MALFORMED; }
    var h = 0;
    if !read_imprint(der, f[2], h, info.imprint) { return info, ERR_MALFORMED; }
    info.hash = h;
    if f[3].tag != asn1::INTEGER || !read_int_into(der, f[3], info.serial) { return info, ERR_MALFORMED; }
    if info.serial[0] >= 0x80 { return info, ERR_MALFORMED; }         // a serial number is positive
    let gt, okg = read_gen_time(der, f[4], info.gen_frac);
    if !okg { return info, ERR_MALFORMED; }
    info.gen_time = gt;
    info.gen_ns = frac_ns(info.gen_frac);
    var i = 5;
    if i < f.len && f[i].tag == asn1::SEQUENCE {
        // Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER (1..999) OPTIONAL,
        //                         micros [1] INTEGER (1..999) OPTIONAL }
        let a, oka = asn1::children(der, f[i]);
        if !oka || a.len > 3 { return info, ERR_MALFORMED; }
        info.has_accuracy = true;
        var j = 0;
        if j < a.len && a[j].tag == asn1::INTEGER {
            let s, oks = asn1::read_i64(der, a[j]);
            if !oks || s < 0 { return info, ERR_MALFORMED; }
            info.acc_seconds = s;
            j++;
        }
        if j < a.len && a[j].tag == asn1::ctx(0, false) {
            let m, okm = asn1::read_i64(der, a[j], asn1::ctx(0, false));
            if !okm || m < 1 || m > 999 { return info, ERR_MALFORMED; }
            info.acc_millis = m;
            j++;
        }
        if j < a.len && a[j].tag == asn1::ctx(1, false) {
            let u, oku = asn1::read_i64(der, a[j], asn1::ctx(1, false));
            if !oku || u < 1 || u > 999 { return info, ERR_MALFORMED; }
            info.acc_micros = u;
            j++;
        }
        if j != a.len { return info, ERR_MALFORMED; }
        i++;
    }
    if i < f.len && f[i].tag == asn1::BOOLEAN {
        let b, okb = asn1::read_bool(der, f[i]);
        if !okb || !b { return info, ERR_MALFORMED; }
        info.ordering = true;
        i++;
    }
    if i < f.len && f[i].tag == asn1::INTEGER {
        if !read_int_into(der, f[i], info.nonce) { return info, ERR_MALFORMED; }
        i++;
    }
    if i < f.len && f[i].tag == asn1::ctx(0, true) {
        let g, okg2 = asn1::explicit(der, f[i]);
        if !okg2 || g.end != f[i].end || g.end - g.start > 1024 { return info, ERR_MALFORMED; }
        info.tsa.append(der[g.start..g.end]);
        i++;
    }
    if i < f.len && f[i].tag == asn1::ctx(1, true) {
        info.extensions = true;
        i++;
    }
    if i != f.len { return info, ERR_MALFORMED; }
    return info, OK;
}

// Reads a TimeStampToken (a ContentInfo of a SignedData whose content is a
// TSTInfo): the SignedData, and what the TSTInfo says. Nothing is checked
// but the form: verify_token does that.
fn parse_token(der: const u8[:]) -> x509::SignedData, TstInfo, i64 {
    let sd, e = x509::cms_parse_signed(der);
    if e != x509::OK { return sd, TstInfo { .. }, ERR_MALFORMED; }
    let d = sd.der[..];
    if !asn1::oid_is(d, sd.content_type, OID_TST_INFO) || !sd.has_content || !x509::cms_signed(sd) {
        return sd, TstInfo { .. }, ERR_MALFORMED;
    }
    let info, ie = parse_tst_info(x509::cms_content(sd));
    return sd, info, ie;
}

// --- Responses ------------------------------------------------------------------------

// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
// PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL,
//                              failInfo PKIFailureInfo OPTIONAL }
// A granted reply must have a token, a refusal must not.
fn parse_response(der: const u8[:]) -> Response, i64 {
    var r = Response { .. };
    let top, ok = asn1::parse(der);
    let f, okf = asn1::children_of(der, top, asn1::SEQUENCE);
    if !ok || !okf || f.len < 1 || f.len > 2 { return r, ERR_MALFORMED; }
    let si, oks = asn1::children_of(der, f[0], asn1::SEQUENCE);
    if !oks || si.len < 1 || si.len > 3 { return r, ERR_MALFORMED; }
    let st, okst = asn1::read_i64(der, si[0]);
    if !okst || st < 0 || st > 5 { return r, ERR_MALFORMED; }
    r.status = st;
    var i = 1;
    if i < si.len && si[i].tag == asn1::SEQUENCE {
        let strs, okt = asn1::children(der, si[i]);
        if !okt || strs.len == 0 { return r, ERR_MALFORMED; }
        for s in strs {
            if s.tag != asn1::UTF8_STRING { return r, ERR_MALFORMED; }
            let text = der[s.off..s.end];
            // One a line: a line end or NUL in one would make two.
            if !asn1::utf8_valid(text) || position(text, '\n') >= 0 || position(text, 0) >= 0 {
                return r, ERR_MALFORMED;
            }
            if r.status_text.len + text.len + 1 > MAX_TEXT { return r, ERR_MALFORMED; }
            if r.status_text.len > 0 { r.status_text.push('\n'); }
            r.status_text.append(text);
        }
        i++;
    }
    if i < si.len && si[i].tag == asn1::BIT_STRING {
        let bits, unused, okb = asn1::read_bits(der, si[i]);
        if !okb { return r, ERR_MALFORMED; }
        for b in bits.len * 8 {
            if asn1::bit(bits, b) {
                if b > 31 { return r, ERR_MALFORMED; }
                r.fail_info = r.fail_info | (1 << (b as u32));
            }
        }
        i++;
    }
    if i != si.len { return r, ERR_MALFORMED; }
    let granted = st == GRANTED || st == GRANTED_WITH_MODS;
    if granted != (f.len == 2) { return r, ERR_MALFORMED; }
    if f.len == 2 {
        if f[1].tag != asn1::SEQUENCE { return r, ERR_MALFORMED; }
        r.token.append(der[f[1].start..f[1].end]);
    }
    return r, OK;
}

// The names of the failInfo bits set, separated by spaces.
fn fail_info_text(bits: u32) -> u8[>..] {
    var out: u8[>..] = [];
    let names = ["badAlg", "", "badRequest", "", "", "badDataFormat", "", "", "", "", "", "", "", "", "timeNotAvailable",
                 "unacceptedPolicy", "unacceptedExtension", "addInfoNotAvailable", "", "", "", "", "", "", "", "systemFailure"];
    for i in 32 {
        if bits & (1 << (i as u32)) == 0 { continue; }
        if out.len > 0 { out.push(' '); }
        if i < names.len && names[i].len > 0 { out.append(names[i]); } else { out.append("bit"); format(out, i); }
    }
    return out;
}

fn status_name(s: i64) -> const u8[:] {
    if s == GRANTED { return "granted"; }
    if s == GRANTED_WITH_MODS { return "grantedWithMods"; }
    if s == REJECTION { return "rejection"; }
    if s == WAITING { return "waiting"; }
    if s == REVOCATION_WARNING { return "revocationWarning"; }
    if s == REVOCATION_NOTIFICATION { return "revocationNotification"; }
    return "unknown";
}

// A refusal: status (REJECTION, say), its text (one string, or none),
// and the failInfo bits.
fn error_response(status: i64, text: const u8[:], fail: u32) -> u8[>..] {
    var si: u8[>..] = [];
    asn1::put_i64(si, status);
    if text.len > 0 {
        var s: u8[>..] = [];
        asn1::put_utf8_string(s, text);
        asn1::put(si, asn1::SEQUENCE, s);
    }
    if fail != 0 { put_fail_bits(si, fail); }
    var body: u8[>..] = [];
    asn1::put(body, asn1::SEQUENCE, si);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}

// A BIT STRING of the bits set in mask (bit i of the mask, the string's
// bit i), DER's trailing zero bits dropped.
fn put_fail_bits(out: u8[>..]&, mask: u32) {
    var last = -1;
    for i in 32 { if mask & (1 << (i as u32)) != 0 { last = i; } }
    var bytes: u8[>..] = [];
    bytes.resize(last / 8 + 1, 0);
    for i in last + 1 {
        if mask & (1 << (i as u32)) != 0 { bytes[i / 8] = bytes[i / 8] | ((0x80 >> (i % 8)) as! u8); }
    }
    asn1::put_bits(out, bytes, 7 - last % 8);
}

// --- Checking tokens ----------------------------------------------------------------------

// The signed attributes of a SignedData's one signer, and false if none.
fn signed_attrs(sd: const x509::SignedData&) -> asn1::Tlv[>..], bool {
    let d = sd.der[..];
    var none: asn1::Tlv[>..] = [];
    let p, ok = asn1::children_of(d, sd.signer, asn1::SEQUENCE);
    if !ok || p.len < 4 || p[3].tag != asn1::ctx(0, true) { return none, false; }
    let list, okl = asn1::children(d, p[3]);
    return list, okl;
}

// Whether a GeneralNames holds a directoryName equal to `name` (DER).
fn names_hold(d: const u8[:], gns: asn1::Tlv, name: const u8[:]) -> bool {
    let ns, ok = asn1::children_of(d, gns, asn1::SEQUENCE);
    if !ok { return false; }
    for n in ns {
        if n.tag != asn1::ctx(4, true) { continue; }
        let inner, oki = asn1::explicit(d, n);
        if oki && d[inner.start..inner.end] == name { return true; }
    }
    return false;
}

// Whether ESSCertID or ESSCertIDv2 `id` names certificate c: its hash, and
// its issuer and serial number if they are there. An ESSCertIDv2 by SHA-1
// only with allow_sha1 (ESSCertID is SHA-1 by definition, RFC 3161's).
fn cert_id_names(d: const u8[:], id: asn1::Tlv, v2: bool, c: const x509::Cert&, allow_sha1: bool) -> bool {
    let p, ok = asn1::children_of(d, id, asn1::SEQUENCE);
    if !ok || p.len < 1 || p.len > 3 { return false; }
    var i = 0;
    var h = SHA1;
    if v2 {
        h = SHA256;                                      // hashAlgorithm DEFAULT sha256
        if p[0].tag == asn1::SEQUENCE {
            h = x509::cms_digest_of(d, p[0]);
            if hash_len(h) == 0 || (h == SHA1 && !allow_sha1) { return false; }
            i = 1;
        }
    }
    if i >= p.len || p[i].tag != asn1::OCTET_STRING { return false; }
    let want = digest(h, c.der);
    if d[p[i].off..p[i].end] != want[..] { return false; }
    i++;
    if i < p.len {
        // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }
        let is, oki = asn1::children_of(d, p[i], asn1::SEQUENCE);
        if !oki || is.len != 2 { return false; }
        let cd = c.der[..];
        if !names_hold(d, is[0], cd[c.issuer.start..c.issuer.end]) { return false; }
        if d[is[1].start..is[1].end] != cd[c.serial.start..c.serial.end] { return false; }
        i++;
    }
    return i == p.len;
}

// The signingCertificateV2 (or, without it, signingCertificate) attribute
// names the signer's certificate in its first ESSCertID: OK or ERR_SIGNER.
fn check_signing_cert(sd: const x509::SignedData&, c: const x509::Cert&, allow_sha1: bool) -> i64 {
    let d = sd.der[..];
    let attrs, ok = signed_attrs(sd);
    if !ok { return ERR_SIGNER; }
    var found = asn1::Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: 0, off: 0, end: 0 };
    var v2 = false;
    var n1 = 0;
    var n2 = 0;
    for a in attrs {
        let av, oka = asn1::children_of(d, a, asn1::SEQUENCE);
        if !oka || av.len != 2 { return ERR_SIGNER; }
        let is1 = asn1::oid_is(d, av[0], OID_SIGNING_CERT);
        let is2 = asn1::oid_is(d, av[0], OID_SIGNING_CERT_V2);
        if !is1 && !is2 { continue; }
        let vals, okv = asn1::children(d, av[1]);
        if !okv || vals.len != 1 { return ERR_SIGNER; }
        if is2 { n2++; found = vals[0]; v2 = true; }
        if is1 { n1++; if !v2 { found = vals[0]; } }
    }
    if n1 > 1 || n2 > 1 || n1 + n2 == 0 { return ERR_SIGNER; }
    // SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies ... OPTIONAL }
    let sc, oks = asn1::children_of(d, found, asn1::SEQUENCE);
    if !oks || sc.len < 1 || sc.len > 2 { return ERR_SIGNER; }
    let ids, oki = asn1::children_of(d, sc[0], asn1::SEQUENCE);
    if !oki || ids.len == 0 { return ERR_SIGNER; }
    return if cert_id_names(d, ids[0], v2, c, allow_sha1) { OK } else { ERR_SIGNER };
}

// Whether a certificate is a TSA's (RFC 3161 §2.3): an extended key usage
// extension, critical, of id-kp-timeStamping alone.
fn is_tsa_cert(c: const x509::Cert&) -> bool {
    let d = c.der[..];
    let tbs, ok = asn1::children_of(d, c.tbs, asn1::SEQUENCE);
    if !ok { return false; }
    for t in tbs {
        if t.tag != asn1::ctx(3, true) { continue; }
        let wrap, okw = asn1::explicit(d, t);
        let exts, oke = asn1::children_of(d, wrap, asn1::SEQUENCE);
        if !okw || !oke { return false; }
        for e in exts {
            let f, okf = asn1::children_of(d, e, asn1::SEQUENCE);
            if !okf || f.len != 3 || !asn1::oid_is(d, f[0], "2.5.29.37") { continue; }
            let crit, okc = asn1::read_bool(d, f[1]);
            if !okc || !crit || f[2].tag != asn1::OCTET_STRING { return false; }
            let inner, oki = asn1::read(d, f[2].off, f[2].end);
            let ks, okk = asn1::children_of(d, inner, asn1::SEQUENCE);
            return oki && okk && ks.len == 1 && asn1::oid_is(d, ks[0], OID_KP_TIME_STAMPING);
        }
    }
    return false;
}

// Whether the token's TSA name (a GeneralName, DER) is the certificate's:
// its subject for a directoryName, else one of its subjectAltName entries.
fn tsa_name_matches(tsa: const u8[:], c: const x509::Cert&) -> bool {
    let g, ok = asn1::parse(tsa);
    if !ok { return false; }
    let cd = c.der[..];
    if g.tag == asn1::ctx(4, true) {
        let inner, oki = asn1::explicit(tsa, g);
        return oki && tsa[inner.start..inner.end] == cd[c.subject.start..c.subject.end];
    }
    if !c.has_san { return false; }
    let ns, okn = asn1::children_of(cd, c.san, asn1::SEQUENCE);
    if !okn { return false; }
    for n in ns { if cd[n.start..n.end] == tsa { return true; } }
    return false;
}

// Checks a token: that it is a TSTInfo signed by its one signer; the
// imprint is `d` hashed by h; the signer's certificate (sent, or among
// `untrusted`, DER laid end to end) is a TSA's, named by the
// signingCertificate(V2) attribute, and chains through the certificates
// sent and `untrusted` to `roots` at genTime; the policy and the TSA name
// fit. Returns what the token says, OK or why not, and for ERR_SIGNATURE
// and ERR_CHAIN the x509 error behind it.
fn verify_token(token: const u8[:], h: i64, d: const u8[:], roots: const x509::CertPool&, untrusted: const u8[:],
                o: const VerifyOptions&) -> TstInfo, i64, i64 {
    let sd, info, e = parse_token(token);
    if e != OK { return info, e, 0; }
    let ve, why = verify_parsed(sd, info, h, d, roots, untrusted, o, false);
    return info, ve, why;
}

fn verify_parsed(sd: const x509::SignedData&, info: const TstInfo&, h: i64, d: const u8[:],
                 roots: const x509::CertPool&, untrusted: const u8[:], o: const VerifyOptions&,
                 need_cert: bool) -> i64, i64 {
    if hash_len(h) == 0 || (h == SHA1 && !o.allow_sha1) { return ERR_UNSUPPORTED, 0; }
    if info.hash != h || info.imprint[..] != d { return ERR_IMPRINT, 0; }
    if o.policy.len > 0 && info.policy[..] != o.policy[..] { return ERR_POLICY, 0; }
    let signer, ce = x509::cms_verify_with_certs(sd, untrusted, o.allow_sha1);
    if ce == x509::ERR_UNKNOWN_ISSUER { return ERR_SIGNER, ce; }
    if ce != x509::OK { return ERR_SIGNATURE, ce; }
    let sent = x509::cms_certs(sd);
    if need_cert && !sent_holds(sent, signer.der) { return ERR_CERT_REQ, 0; }
    let se = check_signing_cert(sd, signer, o.allow_sha1);
    if se != OK { return se, 0; }
    if !is_tsa_cert(signer) { return ERR_TSA_CERT, 0; }
    if info.tsa.len > 0 && !tsa_name_matches(info.tsa, signer) { return ERR_TSA_NAME, 0; }
    var inters: u8[>..] = [];
    inters.append(sent);
    inters.append(untrusted);
    let pool, okp = x509::pool_of(inters);
    if !okp { return ERR_CHAIN, x509::ERR_MALFORMED; }
    var opts = x509::options();
    opts.key_usages = x509::EKU_TIME_STAMPING;
    let xe = x509::verify_pools(signer.der, pool, roots, "", info.gen_time, "", opts);
    if xe != x509::OK { return ERR_CHAIN, xe; }
    if o.now > 0 {
        var slack = o.max_skew;
        if info.acc_seconds > 0 { slack += info.acc_seconds; }
        if info.acc_millis > 0 || info.acc_micros > 0 { slack += 1; }
        let diff = if info.gen_time > o.now { info.gen_time - o.now } else { o.now - info.gen_time };
        if diff > slack { return ERR_TIME, 0; }
    }
    return OK, 0;
}

fn sent_holds(list: const u8[:], der: const u8[:]) -> bool {
    var at = 0;
    while at < list.len {
        let t, ok = asn1::read(list, at, list.len);
        if !ok { return false; }
        if list[t.start..t.end] == der { return true; }
        at = t.end;
    }
    return false;
}

// Checks a reply to `req`: granted (else ERR_REJECTED, r.fail_info and
// r.status_text saying why), then the token as verify_token does with the
// request's imprint, its nonce, its policy if it asked for one, and the
// TSA's certificate in the token if it asked with certReq.
fn verify_reply(r: const Response&, req: const Request&, roots: const x509::CertPool&, untrusted: const u8[:],
                o: const VerifyOptions&) -> TstInfo, i64, i64 {
    if r.status != GRANTED && r.status != GRANTED_WITH_MODS { return TstInfo { .. }, ERR_REJECTED, 0; }
    let sd, info, e = parse_token(r.token);
    if e != OK { return info, e, 0; }
    if req.nonce.len > 0 && info.nonce[..] != req.nonce[..] { return info, ERR_NONCE, 0; }
    if req.policy.len > 0 && info.policy[..] != req.policy[..] { return info, ERR_POLICY, 0; }
    let ve, why = verify_parsed(sd, info, req.hash, req.imprint, roots, untrusted, o, req.cert_req);
    return info, ve, why;
}

// What a token says, as lines of text.
fn info_text(info: const TstInfo&) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("Version: "); format(out, info.version);
    out.append("\nPolicy OID: "); out.append(info.policy);
    out.append("\nHash Algorithm: "); out.append(hash_name(info.hash));
    out.append("\nMessage data: "); hex(out, info.imprint);
    out.append("\nSerial number: 0x"); hex(out, info.serial);
    out.append("\nTime stamp: "); format(out, info.gen_time);
    if info.gen_frac.len > 0 { out.push('.'); out.append(info.gen_frac); }
    out.append(" (seconds since 1970)\nAccuracy: ");
    if !info.has_accuracy { out.append("unspecified"); }
    else {
        format(out, ::max(info.acc_seconds, 0)); out.append(" seconds, ");
        format(out, ::max(info.acc_millis, 0)); out.append(" millis, ");
        format(out, ::max(info.acc_micros, 0)); out.append(" micros");
    }
    out.append("\nOrdering: "); out.append(if info.ordering { "yes" } else { "no" });
    out.append("\nNonce: "); if info.nonce.len > 0 { out.append("0x"); hex(out, info.nonce); } else { out.append("unspecified"); }
    out.append("\nTSA: ");
    if info.tsa.len == 0 { out.append("unspecified"); }
    else {
        let g, ok = asn1::parse(info.tsa);
        let inner, oki = asn1::explicit(info.tsa, g);
        if ok && oki && g.tag == asn1::ctx(4, true) { out.append(x509::name_text(info.tsa, inner)); }
        else { out.append("(a GeneralName, "); format(out, info.tsa.len); out.append(" bytes)"); }
    }
    out.append("\nExtensions: "); out.append(if info.extensions { "yes" } else { "none" });
    out.push('\n');
    return out;
}

// --- A TSA ---------------------------------------------------------------------------------

// A time-stamping authority: its key and certificate (a TSA's, §2.3), more
// certificates to send with it when asked (its chain, DER laid end to
// end), the policy it stamps under and those others it takes (dotted, one
// a line), accuracy (-1 parts left out; all -1: none), ordering, whether
// it names itself in the token (its subject), how many fraction digits
// genTime has, whether it takes SHA-1 imprints, and its serial numbers:
// random 128-bit ones, or counted from next_serial when it is above 0.
root struct Tsa {
    key:         x509::PrivateKey = x509::empty_key(),
    cert:        u8[>..]          = [],
    chain:       u8[>..]          = [],
    policy:      u8[..128]        = [],
    policies:    u8[..1024]       = [],
    acc_seconds: i64              = -1,
    acc_millis:  i64              = -1,
    acc_micros:  i64              = -1,
    ordering:    bool             = false,
    tsa_name:    bool             = false,
    precision:   i64              = 0,
    allow_sha1:  bool             = false,
    sig_hash:    i64              = 0,       // the signature's hash, 0 for the key's default
    next_serial: i64              = 0,
}

// Sets up a TSA with its certificate (DER), key and chain: ERR_TSA_CERT if
// the certificate is not a TSA's, ERR_ARG if the key is not its key or
// the policy is not an OID.
fn tsa_init(t: Tsa&, cert_der: const u8[:], key: const x509::PrivateKey&, chain: const u8[:], policy: const u8[:]) -> i64 {
    let c, e = x509::parse(cert_der);
    if e != x509::OK { return ERR_MALFORMED; }
    if !is_tsa_cert(c) { return ERR_TSA_CERT; }
    if x509::marshal_public_key(key) != c.der[c.spki.start..c.spki.end] { return ERR_ARG; }
    if !valid_oid(policy) { return ERR_ARG; }
    let pool, okc = x509::pool_of(chain);
    if !okc { return ERR_MALFORMED; }
    t.key = copy(key);
    t.cert.clear();
    t.cert.append(cert_der);
    t.chain.clear();
    t.chain.append(chain);
    t.policy.clear();
    t.policy.append(policy);
    return OK;
}

// Another policy the TSA takes when a request asks for it.
fn tsa_add_policy(t: Tsa&, policy: const u8[:]) -> i64 {
    if !valid_oid(policy) { return ERR_ARG; }
    if t.policies.len + policy.len + 1 > 1024 { return ERR_ARG; }
    t.policies.append(policy);
    t.policies.push('\n');
    return OK;
}

fn tsa_takes_policy(t: const Tsa&, policy: const u8[:]) -> bool {
    if policy == t.policy[..] { return true; }
    for p in split(t.policies, '\n') { if p.len > 0 && p == policy { return true; } }
    return false;
}

// SigningCertificateV2 with one ESSCertIDv2 (SHA-256, so no hashAlgorithm,
// and the issuer and serial number), as an Attribute.
fn signing_cert_v2_attr(c: const x509::Cert&) -> u8[>..] {
    let cd = c.der[..];
    var id: u8[>..] = [];
    asn1::put_octets(id, digest(SHA256, cd));
    var gn: u8[>..] = [];
    asn1::put(gn, asn1::ctx(4, true), cd[c.issuer.start..c.issuer.end]);
    var is: u8[>..] = [];
    asn1::put(is, asn1::SEQUENCE, gn);
    is.append(cd[c.serial.start..c.serial.end]);
    asn1::put(id, asn1::SEQUENCE, is);
    var ids: u8[>..] = [];
    asn1::put(ids, asn1::SEQUENCE, id);
    var certs: u8[>..] = [];
    asn1::put(certs, asn1::SEQUENCE, ids);
    var sc: u8[>..] = [];
    asn1::put(sc, asn1::SEQUENCE, certs);
    var out: u8[>..] = [];
    x509::cms_attr(out, OID_SIGNING_CERT_V2, sc);
    return out;
}

// The next serial number's INTEGER content.
fn next_serial(t: Tsa&) -> u8[>..] {
    if t.next_serial <= 0 { return random_int(16); }
    var tmp: u8[>..] = [];
    asn1::put_i64(tmp, t.next_serial);
    t.next_serial++;
    let tt, ok = asn1::parse(tmp);
    var out: u8[>..] = [];
    out.append(tmp[tt.off..tt.end]);
    return out;
}

// The TSTInfo of a request taken, at now_ns (nanoseconds since 1970).
fn tst_info_der(t: Tsa&, req: const Request&, policy: const u8[:], c: const x509::Cert&, now_ns: i64) -> u8[>..] {
    var body: u8[>..] = [];
    asn1::put_i64(body, 1);
    asn1::put_oid(body, policy);
    // The request's MessageImprint as it came, or made for one built here.
    if req.imprint_der.len > 0 { body.append(req.imprint_der); } else { put_imprint(body, req.hash, req.imprint); }
    asn1::put(body, asn1::INTEGER, next_serial(t));
    put_gen_time(body, now_ns, t.precision);
    if t.acc_seconds > 0 || t.acc_millis > 0 || t.acc_micros > 0 {
        var acc: u8[>..] = [];
        if t.acc_seconds > 0 { asn1::put_i64(acc, t.acc_seconds); }
        if t.acc_millis > 0 { asn1::put_i64(acc, t.acc_millis, asn1::ctx(0, false)); }
        if t.acc_micros > 0 { asn1::put_i64(acc, t.acc_micros, asn1::ctx(1, false)); }
        asn1::put(body, asn1::SEQUENCE, acc);
    }
    if t.ordering { asn1::put_bool(body, true); }
    if req.nonce.len > 0 { asn1::put(body, asn1::INTEGER, req.nonce); }
    if t.tsa_name {
        let cd = c.der[..];
        var gn: u8[>..] = [];
        asn1::put(gn, asn1::ctx(4, true), cd[c.subject.start..c.subject.end]);
        asn1::put(body, asn1::ctx(0, true), gn);
    }
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}

// The reply to a request's DER at now_ns: a token, or a refusal with the
// failInfo that says why (badDataFormat for what does not parse, badAlg
// for a hash not taken, unacceptedPolicy, unacceptedExtension,
// systemFailure when signing fails). The status is returned too.
fn respond(t: Tsa&, req_der: const u8[:], now_ns: i64) -> u8[>..], i64 {
    let req, e = parse_request(req_der);
    if e != OK { return error_response(REJECTION, "the request is not a TimeStampReq", FAIL_BAD_DATA_FORMAT), REJECTION; }
    if req.hash == 0 || (req.hash == SHA1 && !t.allow_sha1) {
        return error_response(REJECTION, "the message imprint's hash is not taken", FAIL_BAD_ALG), REJECTION;
    }
    if req.policy.len > 0 && !tsa_takes_policy(t, req.policy) {
        return error_response(REJECTION, "the policy asked for is not taken", FAIL_UNACCEPTED_POLICY), REJECTION;
    }
    if req.extensions {
        return error_response(REJECTION, "extensions are not taken", FAIL_UNACCEPTED_EXTENSION), REJECTION;
    }
    let c, ce = x509::parse(t.cert);
    if ce != x509::OK || t.policy.len == 0 {
        return error_response(REJECTION, "the TSA is not set up", FAIL_SYSTEM_FAILURE), REJECTION;
    }
    let policy = if req.policy.len > 0 { req.policy[..] } else { t.policy[..] };
    let tst = tst_info_der(t, req, policy, c, now_ns);
    var alg, h = x509::default_sig(t.key.kind);
    if t.sig_hash > 0 && (alg == x509::SIG_RSA_PKCS1 || alg == x509::SIG_RSA_PSS || alg == x509::SIG_ECDSA) { h = t.sig_hash; }
    var o = x509::CmsSignOptions { no_certs: !req.cert_req, .. };
    o.extra_attrs.append(signing_cert_v2_attr(c));
    let token, ok = x509::cms_sign_with(OID_TST_INFO, tst, t.key, c, if req.cert_req { t.chain[..] } else { "" }, alg, h, o);
    if !ok { return error_response(REJECTION, "the TSA could not sign", FAIL_SYSTEM_FAILURE), REJECTION; }
    var si: u8[>..] = [];
    asn1::put_i64(si, GRANTED);
    var body: u8[>..] = [];
    asn1::put(body, asn1::SEQUENCE, si);
    body.append(token);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out, GRANTED;
}

// The current time in nanoseconds since 1970, for respond.
fn now_ns() -> i64 { time_ns() }

// --- Over HTTP ------------------------------------------------------------------------------

// Whether a Content-Type is a time-stamp reply: application/timestamp-reply,
// or the application/timestamp-response some TSAs sent from drafts;
// parameters and case aside.
fn is_reply_type(ct: const u8[:]) -> bool {
    let semi = position(ct, ';');
    let base = trim(if semi >= 0 { ct[..semi] } else { ct });
    return http::eq_fold(base, "application/timestamp-reply") || http::eq_fold(base, "application/timestamp-response");
}

// Sends a request's DER to a TSA (POST, application/timestamp-query) and
// returns the reply's DER: OK, or ERR_HTTP with the client's error or the
// HTTP status in the third value. A reply past max_body (1 MiB) is
// refused (http::ERR_TOO_LARGE), not cut short.
fn post(hc: http::Client&, url: const u8[:], req_der: const u8[:], max_body: i64 = 1 << 20) -> u8[>..], i64, i64 {
    var out: u8[>..] = [];
    if hc.opt.max_body > max_body { hc.opt.max_body = max_body; }
    let r = http::post(hc, url, "application/timestamp-query", req_der);
    if r.err != http::ERR_NONE { return out, ERR_HTTP, r.err; }
    if r.status != 200 { return out, ERR_HTTP, r.status; }
    let ct, has = http::response_header(r, "content-type");
    if !has || !is_reply_type(ct) { return out, ERR_HTTP, r.status; }
    out.append(http::response_body(r));
    return out, OK, r.status;
}

// --- Time-stamping CMS signatures (RFC 3161 Appendix A) ------------------------------------

// The signature value (the OCTET STRING's content) of a SignedData's one
// SignerInfo, the data its time-stamp is over; false if there is none.
fn signature_value(sd: const x509::SignedData&) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !x509::cms_signed(sd) { return out, false; }
    let d = sd.der[..];
    let p, ok = asn1::children_of(d, sd.signer, asn1::SEQUENCE);
    if !ok || p.len < 5 { return out, false; }
    // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature, [1]?
    let i = if p[3].tag == asn1::ctx(0, true) { 5 } else { 4 };
    if i >= p.len || p[i].tag != asn1::OCTET_STRING { return out, false; }
    out.append(d[p[i].off..p[i].end]);
    return out, true;
}

// The request for a time-stamp of a CMS signature (a ContentInfo of a
// SignedData, DER or BER, one signer): its signature value hashed by h.
fn signature_request(cms: const u8[:], h: i64, cert_req: bool = true) -> Request, i64 {
    let sd, e = x509::cms_parse_signed_ber(cms);
    if e != x509::OK { return Request { .. }, ERR_MALFORMED; }
    let sig, ok = signature_value(sd);
    if !ok { return Request { .. }, ERR_MALFORMED; }
    let r, re = new_request(h, sig, cert_req);
    return r, re;
}

// The CMS signature with `token` (a TimeStampToken, DER) added to its
// SignerInfo's unsigned attributes as id-aa-signatureTimeStampToken,
// beside any already there. DER out; the signature is unchanged.
fn add_signature_token(cms: const u8[:], token: const u8[:]) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let tt, okt = asn1::parse(token);
    if !okt || tt.end != token.len || tt.tag != asn1::SEQUENCE { return out, ERR_ARG; }
    let d, okd = x509::cms_der(cms);
    if !okd { return out, ERR_MALFORMED; }
    let sd, e = x509::cms_parse_signed(d);
    if e != x509::OK || !x509::cms_signed(sd) { return out, ERR_MALFORMED; }
    // ContentInfo { contentType, [0] { SignedData { ..., signerInfos SET { SignerInfo } } } }
    let top, ok = asn1::parse(d);
    let ci, okc = asn1::children(d, top);
    let inner, oki = asn1::explicit(d, ci[1]);
    let f, okf = asn1::children(d, inner);
    if !ok || !okc || !oki || !okf { return out, ERR_MALFORMED; }
    let sis = f[f.len - 1];
    let p, okp = asn1::children(d, sd.signer);
    if !okp { return out, ERR_MALFORMED; }
    // The new attribute, with those already unsigned.
    var attrs: u8[>..] = [];
    x509::cms_attr(attrs, OID_SIGNATURE_TST, token);
    var si: u8[>..] = [];
    for x in p {
        if x.tag == asn1::ctx(1, true) { attrs.append(d[x.off..x.end]); continue; }
        si.append(d[x.start..x.end]);
    }
    var set: u8[>..] = [];
    x509::cms_set_of(set, attrs);
    let st, oks = asn1::parse(set);
    asn1::put(si, asn1::ctx(1, true), set[st.off..]);
    var si_seq: u8[>..] = [];
    asn1::put(si_seq, asn1::SEQUENCE, si);
    var sd_body: u8[>..] = [];
    for x in f {
        if x.start == sis.start { asn1::put(sd_body, asn1::SET, si_seq); } else { sd_body.append(d[x.start..x.end]); }
    }
    var sd_seq: u8[>..] = [];
    asn1::put(sd_seq, asn1::SEQUENCE, sd_body);
    var ci_body: u8[>..] = [];
    ci_body.append(d[ci[0].start..ci[0].end]);
    asn1::put(ci_body, asn1::ctx(0, true), sd_seq);
    asn1::put(out, asn1::SEQUENCE, ci_body);
    return out, OK;
}

// The signatureTimeStampToken of a CMS signature's signer (the first, if
// more than one): its DER, OK, or ERR_NO_TOKEN.
fn signature_token(sd: const x509::SignedData&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if !x509::cms_signed(sd) { return out, ERR_MALFORMED; }
    let d = sd.der[..];
    let p, ok = asn1::children_of(d, sd.signer, asn1::SEQUENCE);
    if !ok || p.len < 6 || p[p.len - 1].tag != asn1::ctx(1, true) { return out, ERR_NO_TOKEN; }
    let attrs, oka = asn1::children(d, p[p.len - 1]);
    if !oka { return out, ERR_MALFORMED; }
    for a in attrs {
        let av, okv = asn1::children_of(d, a, asn1::SEQUENCE);
        if !okv || av.len != 2 || av[1].tag != asn1::SET { return out, ERR_MALFORMED; }
        if !asn1::oid_is(d, av[0], OID_SIGNATURE_TST) { continue; }
        let vals, okl = asn1::children(d, av[1]);
        if !okl || vals.len == 0 { return out, ERR_MALFORMED; }
        out.append(d[vals[0].start..vals[0].end]);
        return out, OK;
    }
    return out, ERR_NO_TOKEN;
}

// Checks the signatureTimeStampToken of a CMS signature (DER or BER): a
// token as verify_token checks it, over the signer's signature value by
// the token's own hash. The CMS signature itself is the caller's to check
// (x509::cms_verify): the unsigned attributes are outside it.
fn verify_signature_token(cms: const u8[:], roots: const x509::CertPool&, untrusted: const u8[:],
                          o: const VerifyOptions&) -> TstInfo, i64, i64 {
    let sd, e = x509::cms_parse_signed_ber(cms);
    if e != x509::OK { return TstInfo { .. }, ERR_MALFORMED, e; }
    let token, te = signature_token(sd);
    if te != OK { return TstInfo { .. }, te, 0; }
    let sig, oks = signature_value(sd);
    let tsd, info, pe = parse_token(token);
    if pe != OK || !oks { return info, ERR_MALFORMED, 0; }
    if hash_len(info.hash) == 0 { return info, ERR_UNSUPPORTED, 0; }
    let ve, why = verify_parsed(tsd, info, info.hash, digest(info.hash, sig), roots, untrusted, o, false);
    return info, ve, why;
}
