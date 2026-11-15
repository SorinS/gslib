// scep: a SCEP client (RFC 8894), for getting certificates from the CAs
// that speak it: Microsoft's NDES, EJBCA, Dogtag, step-ca, micromdm, the
// MDM servers and network gear that enrol devices. GetCACaps, GetCACert
// (the CA alone, or certs-only with its RA), PKIOperation over POST (or
// GET when the server lacks POSTPKIOperation) carrying PKCSReq and
// RenewalReq, CertPoll (GetCertInitial) while the CA holds a request,
// GetCert and GetCRL. And the server side of the same messages, for a
// test CA (scep::serve; goose-scep serve runs it).
//
//   var hc = http::Client { .. };
//   var c = scep::Client { .. };
//   scep::set_url(c, "http://ca.example.org/scep");
//   scep::get_caps(c, hc);                        // AES, SHA-256, POSTPKIOperation, Renewal, ...
//   scep::get_ca_cert(c, hc);                     // c.ca_certs: the CA's, and an RA's if it has one
//   let key = x509::generate_key(x509::KEY_RSA, 2048);
//   let csr, e = scep::make_csr(subject_der, san, key, "the challenge password");
//   let signer, se = scep::self_signed(csr, key); // the request's signer, as §2.3 has it
//   let certs, err = scep::enroll(c, hc, csr, key, signer, false);   // waits while PENDING
//   // certs: the issued certificate first (DER), then any others the CA sent
//
// A pkiMessage (§3) is a SignedData over id-data whose content is an
// EnvelopedData (the pkcsPKIEnvelope) encrypted to the CA or its RA, with
// the authenticated attributes transactionID, messageType, senderNonce,
// recipientNonce, pkiStatus and failInfo among the signed attributes. The
// CA's CertRep is checked before anything in it is used: signed by the CA
// or RA certificate GetCACert gave (not merely by one the reply carries),
// its signature good, its transactionID ours, its recipientNonce the
// senderNonce we sent, its messageType CertRep; an issued certificate's key
// must be the request's.
//
// Algorithms: AES-128-CBC (or AES-256-CBC when asked) and SHA-256 when the
// server's caps list them (AES, SHA-256, SCEPStandard), SHA-512 if only
// that; DES-EDE3-CBC and SHA-1 only for a server whose caps have neither,
// and only when the client allows it (c.legacy). A reply signed with SHA-1
// or encrypted with DES or DES-EDE3 is taken only with c.legacy too: Go's
// pkcs7, which micromdm and others are built on, sends exactly that
// whatever its caps say. The client's key must be RSA: the CA encrypts its
// reply to the signer's certificate by RSA key transport.

namespace scep;

import std;
import base64;
import crypto.x509;
import crypto.x509.keys;
import crypto.x509.create;
import crypto.x509.cms;
import crypto.x509.cms_env;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.sha256;
import crypto.bignum.entropy;
import crypto.bignum.ct;
import net.http;
import net.http.client;
import net.http.fetch;
import net.http.url;

// --- Errors -------------------------------------------------------------------

let OK:            i64 = 0;
let ERR_ARG:       i64 = 1;    // an argument that cannot be used
let ERR_HTTP:      i64 = 2;    // no response: the connection, TLS, a timeout, a body too large (c.http_err says which)
let ERR_STATUS:    i64 = 3;    // the server answered with an HTTP error (c.status)
let ERR_MALFORMED: i64 = 4;    // a response that is not what RFC 8894 says it is
let ERR_SIGNATURE: i64 = 5;    // a reply unsigned, badly signed, or signed by a certificate not the CA's or RA's
let ERR_MISMATCH:  i64 = 6;    // a reply to another request: transactionID, recipientNonce or messageType
let ERR_FAILURE:   i64 = 7;    // the CA refused (pkiStatus FAILURE; c.fail_info says why)
let ERR_PENDING:   i64 = 8;    // the CA holds the request (pkiStatus PENDING): poll
let ERR_DECRYPT:   i64 = 9;    // the reply's envelope does not decrypt with the request's key
let ERR_ALGORITHM: i64 = 10;   // only legacy algorithms (DES, SHA-1) would do, and c.legacy is off
let ERR_TIMEOUT:   i64 = 11;   // still PENDING when poll_timeout_ms ran out
let ERR_NO_CA:     i64 = 12;   // no CA certificate yet (get_ca_cert first)

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "an argument that cannot be used"; }
    if e == ERR_HTTP { return "the request failed"; }
    if e == ERR_STATUS { return "the server answered with an HTTP error"; }
    if e == ERR_MALFORMED { return "the server's response is not SCEP"; }
    if e == ERR_SIGNATURE { return "the reply is not signed by the CA"; }
    if e == ERR_MISMATCH { return "the reply is not to this request"; }
    if e == ERR_FAILURE { return "the CA refused the request"; }
    if e == ERR_PENDING { return "the CA holds the request"; }
    if e == ERR_DECRYPT { return "the reply does not decrypt"; }
    if e == ERR_ALGORITHM { return "only DES or SHA-1 would do (the server's caps, or its reply), and legacy is off"; }
    if e == ERR_TIMEOUT { return "the CA did not decide in time"; }
    if e == ERR_NO_CA { return "no CA certificate"; }
    return "";
}

// messageType (§3.2.1.2).
let MSG_CERT_REP:    i64 = 3;
let MSG_RENEWAL_REQ: i64 = 17;
let MSG_PKCS_REQ:    i64 = 19;
let MSG_CERT_POLL:   i64 = 20;
let MSG_GET_CERT:    i64 = 21;
let MSG_GET_CRL:     i64 = 22;

// pkiStatus (§3.2.1.3).
let STATUS_SUCCESS: i64 = 0;
let STATUS_FAILURE: i64 = 2;
let STATUS_PENDING: i64 = 3;

// failInfo (§3.2.1.4).
let FAIL_BAD_ALG:           i64 = 0;
let FAIL_BAD_MESSAGE_CHECK: i64 = 1;
let FAIL_BAD_REQUEST:       i64 = 2;
let FAIL_BAD_TIME:          i64 = 3;
let FAIL_BAD_CERT_ID:       i64 = 4;

let FAIL_NAMES: const u8[:][] = ["badAlg", "badMessageCheck", "badRequest", "badTime", "badCertId"];

fn fail_name(f: i64) -> const u8[:] { if f >= 0 && f < FAIL_NAMES.len { FAIL_NAMES[f] } else { "" } }

let OID_MESSAGE_TYPE:       const u8[:] = "2.16.840.1.113733.1.9.2";
let OID_PKI_STATUS:         const u8[:] = "2.16.840.1.113733.1.9.3";
let OID_FAIL_INFO:          const u8[:] = "2.16.840.1.113733.1.9.4";
let OID_SENDER_NONCE:       const u8[:] = "2.16.840.1.113733.1.9.5";
let OID_RECIPIENT_NONCE:    const u8[:] = "2.16.840.1.113733.1.9.6";
let OID_TRANSACTION_ID:     const u8[:] = "2.16.840.1.113733.1.9.7";
let OID_FAIL_INFO_TEXT:     const u8[:] = "1.3.6.1.5.5.7.24.1";
let OID_CHALLENGE_PASSWORD: const u8[:] = "1.2.840.113549.1.9.7";

// What this reads of a reply, and how much of it.
let MAX_TRANSACTION_ID: i64 = 128;
let MAX_NONCE:          i64 = 64;
let MAX_SIGNER:         i64 = 16384;

// --- Types --------------------------------------------------------------------

// GetCACaps (§3.5.2), as flags.
struct Caps {
    aes:           bool = false,     // AES (AES-128-CBC)
    des3:          bool = false,     // DES3
    get_next_ca:   bool = false,     // GetNextCACert
    post:          bool = false,     // POSTPKIOperation
    renewal:       bool = false,     // Renewal
    sha1:          bool = false,
    sha256:        bool = false,
    sha512:        bool = false,
    scep_standard: bool = false,     // SCEPStandard: AES, POSTPKIOperation and SHA-256 at least
    update:        bool = false,     // Update (the old name of Renewal)
}

// The authenticated attributes of a pkiMessage (§3.2.1). -1 for an
// integer one that is absent.
struct Attrs {
    message_type:    i64                      = -1,
    status:          i64                      = -1,    // pkiStatus
    fail_info:       i64                      = -1,
    transaction_id:  u8[..MAX_TRANSACTION_ID] = [],
    sender_nonce:    u8[..MAX_NONCE]          = [],
    recipient_nonce: u8[..MAX_NONCE]          = [],
    fail_text:       u8[..256]                = [],    // failInfoText (RFC 8894 §3.2.1.4), if any
}

// A pkiMessage as read: its attributes, the signer's certificate, and the
// pkcsPKIEnvelope (an EnvelopedData's ContentInfo, DER), empty if absent.
struct Message {
    attrs:    Attrs            = Attrs { .. },
    signer:   u8[..MAX_SIGNER] = [],
    sha1:     bool             = false,     // signed with SHA-1
    envelope: u8[>..]          = [],
}

// A SCEP client: the server's URL, the CA's caps and certificates, and
// what the last request left. `fail_info` is the last FAILURE's, and
// `transaction_id` the last request's, for polling.
root struct Client {
    url:             u8[>..] = [],         // the CGI URL: http://ca.example.org/scep, .../certsrv/mscep/mscep.dll
    label:           u8[>..] = [],         // GetCACert's message: which CA, for servers with several
    caps:            Caps    = Caps { .. },
    has_caps:        bool    = false,
    ca_certs:        u8[>..] = [],         // from GetCACert, DER laid end to end
    legacy:          bool    = false,      // DES-EDE3 and SHA-1 to a server with nothing newer; DES and SHA-1 replies taken
    aes256:          bool    = false,      // AES-256-CBC in place of AES-128-CBC (servers on Go's pkcs7 take it)
    http_err:        i64     = 0,
    status:          i64     = 0,          // the last HTTP status
    fail_info:       i64     = -1,
    fail_text:       u8[>..] = [],
    transaction_id:  u8[>..] = [],
    max_body:        i64     = 1 << 20,    // replies larger than this are refused (ERR_HTTP, http::ERR_TOO_LARGE)
    poll_ms:         i64     = 5000,       // between CertPolls
    poll_timeout_ms: i64     = 300000,     // how long enroll polls a PENDING request
}

fn set_url(c: Client&, url: const u8[:]) -> i64 {
    if url.len == 0 || position(url, '?') >= 0 || position(url, '#') >= 0 { return ERR_ARG; }
    c.url.clear();
    c.url.append(url);
    return OK;
}

// --- Caps ---------------------------------------------------------------------

fn lower_eq(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for x, i in a {
        let y = b[i];
        let lx = if x >= 'A' && x <= 'Z' { x + 32 } else { x };
        let ly = if y >= 'A' && y <= 'Z' { y + 32 } else { y };
        if lx != ly { return false; }
    }
    return true;
}

// The caps from GetCACaps' text: one keyword a line, compared without
// regard to case (§3.5.2); unknown ones are passed over.
fn parse_caps(text: const u8[:]) -> Caps {
    var k = Caps { .. };
    for raw in split(text, '\n') {
        let w = trim(raw);
        if lower_eq(w, "AES") { k.aes = true; }
        else if lower_eq(w, "DES3") { k.des3 = true; }
        else if lower_eq(w, "GetNextCACert") { k.get_next_ca = true; }
        else if lower_eq(w, "POSTPKIOperation") { k.post = true; }
        else if lower_eq(w, "Renewal") { k.renewal = true; }
        else if lower_eq(w, "SHA-1") { k.sha1 = true; }
        else if lower_eq(w, "SHA-256") { k.sha256 = true; }
        else if lower_eq(w, "SHA-512") { k.sha512 = true; }
        else if lower_eq(w, "SCEPStandard") { k.scep_standard = true; }
        else if lower_eq(w, "Update") { k.update = true; }
    }
    if k.scep_standard { k.aes = true; k.post = true; k.sha256 = true; }
    return k;
}

// The content cipher and digest for requests to a server with these caps:
// AES and SHA-256 (or -512) when it has them, DES-EDE3 and SHA-1 only with
// `legacy`. ERR_ALGORITHM when nothing allowed would do.
fn choose_algorithms(k: const Caps&, legacy: bool, aes256: bool) -> i64, i64, i64 {
    var cipher: i64 = 0;
    var h:      i64 = 0;
    if k.aes { cipher = if aes256 { x509::CMS_AES256_CBC } else { x509::CMS_AES128_CBC }; }
    else if legacy { cipher = x509::CMS_DES3_CBC; }
    if k.sha256 { h = 256; }
    else if k.sha512 { h = 512; }
    else if legacy { h = 160; }
    if cipher == 0 || h == 0 { return 0, 0, ERR_ALGORITHM; }
    return cipher, h, OK;
}

// --- Attributes ---------------------------------------------------------------

fn printable_ok(s: const u8[:]) -> bool {
    for ch in s { if !asn1::printable_char(ch) { return false; } }
    return true;
}

fn put_attr(out: u8[>..]&, oid: const u8[:], value: const u8[:]) {
    var a: u8[>..] = [];
    asn1::put_oid(a, oid);
    asn1::put(a, asn1::SET, value);
    asn1::put(out, asn1::SEQUENCE, a);
}

fn put_printable_attr(out: u8[>..]&, oid: const u8[:], s: const u8[:]) {
    var v: u8[>..] = [];
    asn1::put_printable(v, s);
    put_attr(out, oid, v);
}

fn put_number_attr(out: u8[>..]&, oid: const u8[:], n: i64) {
    var s: u8[>..] = [];
    format(s, n);
    put_printable_attr(out, oid, s);
}

fn put_octets_attr(out: u8[>..]&, oid: const u8[:], b: const u8[:]) {
    var v: u8[>..] = [];
    asn1::put_octets(v, b);
    put_attr(out, oid, v);
}

// The attributes as Attribute elements laid end to end, for
// CmsSignOptions.extra_attrs. False if a transactionID is not printable.
fn attrs_der(a: const Attrs&) -> u8[>..], bool {
    var out: u8[>..] = [];
    if a.transaction_id.len == 0 || !printable_ok(a.transaction_id) || a.message_type < 0 { return out, false; }
    put_printable_attr(out, OID_TRANSACTION_ID, a.transaction_id);
    put_number_attr(out, OID_MESSAGE_TYPE, a.message_type);
    if a.status >= 0 { put_number_attr(out, OID_PKI_STATUS, a.status); }
    if a.fail_info >= 0 { put_number_attr(out, OID_FAIL_INFO, a.fail_info); }
    if a.sender_nonce.len > 0 { put_octets_attr(out, OID_SENDER_NONCE, a.sender_nonce); }
    if a.recipient_nonce.len > 0 { put_octets_attr(out, OID_RECIPIENT_NONCE, a.recipient_nonce); }
    if a.fail_text.len > 0 {
        var v: u8[>..] = [];
        asn1::put_utf8_string(v, a.fail_text);
        put_attr(out, OID_FAIL_INFO_TEXT, v);
    }
    return out, true;
}

// A small decimal from a PrintableString: -1 if it is not one.
fn read_number(d: const u8[:], t: asn1::Tlv) -> i64 {
    if t.tag != asn1::PRINTABLE_STRING { return -1; }
    let s = d[t.off..t.end];
    if s.len == 0 || s.len > 4 { return -1; }
    var n: i64 = 0;
    for ch in s {
        if ch < '0' || ch > '9' { return -1; }
        n = n * 10 + (ch - '0');
    }
    return n;
}

// The attributes of a SignedData's signer: false if one is malformed or
// there more than once, or transactionID or messageType is missing.
fn read_attrs(sd: const x509::SignedData&) -> Attrs, bool {
    var a = Attrs { .. };
    let d = sd.der[..];
    let tid, ntid = x509::cms_signed_attr(sd, OID_TRANSACTION_ID);
    if ntid != 1 || tid.tag != asn1::PRINTABLE_STRING || asn1::content_len(tid) == 0 ||
       asn1::content_len(tid) > MAX_TRANSACTION_ID { return a, false; }
    a.transaction_id.append(d[tid.off..tid.end]);
    let mt, nmt = x509::cms_signed_attr(sd, OID_MESSAGE_TYPE);
    if nmt != 1 { return a, false; }
    a.message_type = read_number(d, mt);
    if a.message_type < 0 { return a, false; }
    let st, nst = x509::cms_signed_attr(sd, OID_PKI_STATUS);
    if nst < 0 { return a, false; }
    if nst == 1 {
        a.status = read_number(d, st);
        if a.status < 0 { return a, false; }
    }
    let fi, nfi = x509::cms_signed_attr(sd, OID_FAIL_INFO);
    if nfi < 0 { return a, false; }
    if nfi == 1 {
        a.fail_info = read_number(d, fi);
        if a.fail_info < 0 { return a, false; }
    }
    for which in [0, 1] {
        let n, nn = x509::cms_signed_attr(sd, if which == 0 { OID_SENDER_NONCE } else { OID_RECIPIENT_NONCE });
        if nn < 0 { return a, false; }
        if nn == 1 {
            if n.tag != asn1::OCTET_STRING || asn1::content_len(n) == 0 || asn1::content_len(n) > MAX_NONCE { return a, false; }
            if which == 0 { a.sender_nonce.append(d[n.off..n.end]); } else { a.recipient_nonce.append(d[n.off..n.end]); }
        }
    }
    // failInfoText is for a person to read: its first 256 bytes are kept.
    let ft, nft = x509::cms_signed_attr(sd, OID_FAIL_INFO_TEXT);
    if nft < 0 { return a, false; }
    if nft == 1 {
        let s, oks = asn1::read_string(d, ft);
        if oks { a.fail_text.append(s[..min(s.len, 256)]); }
    }
    return a, true;
}

// --- Messages -----------------------------------------------------------------

// A fresh senderNonce: 16 random bytes (§3.2.1.5).
fn new_nonce() -> u8[16] {
    var n: u8[16] = [0; 16];
    bignum::random_bytes(n);
    return n;
}

// A transactionID for a key (§3.2.1.1): the SHA-256 of its
// SubjectPublicKeyInfo, in upper-case hex.
fn transaction_id(spki: const u8[:]) -> u8[>..] {
    let h = bignum::sha256(spki);
    var out: u8[>..] = [];
    x509::hex_upper(out, h[..]);
    return out;
}

// A pkiMessage: `payload` (the request's content: a CSR, an
// IssuerAndSubject, an IssuerAndSerialNumber) enveloped to `recipient` (a
// certificate, DER) by `cipher`, then signed with `attrs` by `key`, whose
// certificate is `signer`, with digest h (256, 512, or 160 for SHA-1). An
// empty payload and recipient make a message without a pkcsPKIEnvelope (a
// CertRep that is PENDING or FAILURE).
fn build_message(attrs: const Attrs&, payload: const u8[:], recipient: const u8[:], cipher: i64,
                 key: const x509::PrivateKey&, signer: const u8[:], h: i64) -> u8[>..], i64 {
    var none: u8[>..] = [];
    if key.kind != x509::KEY_RSA { return none, ERR_ARG; }
    let sc, e = x509::parse(signer);
    if e != x509::OK { return none, ERR_ARG; }
    var env: u8[>..] = [];
    if recipient.len > 0 {
        var o = x509::CmsEncryptOptions { .. };
        o.cipher = cipher;
        o.rsa_pkcs1 = true;        // what every SCEP server decrypts (§3.2.2)
        o.any_usage = true;        // a CA without an RA is the recipient, keyEncipherment or not (§2.2)
        let ev, ee = x509::cms_encrypt(x509::OID_CMS_DATA, payload, recipient, o);
        if ee != x509::OK { return none, ERR_ARG; }
        env = copy(ev);
    }
    let ad, ok = attrs_der(attrs);
    if !ok { return none, ERR_ARG; }
    var so = x509::CmsSignOptions { .. };
    so.extra_attrs.append(ad);
    let msg, oks = x509::cms_sign_with(x509::OID_CMS_DATA, env, key, sc, "", x509::SIG_RSA_PKCS1, h, so);
    if !oks { return none, ERR_ARG; }
    return msg, OK;
}

// Reads a pkiMessage (BER or DER) and checks its signature. With
// `trusted` (certificates, DER laid end to end) the signer must be one of
// them; without, any signer whose certificate the message carries (a
// server reading a request signed by a self-signed certificate). SHA-1 is
// taken only with allow_sha1. ERR_MALFORMED, ERR_SIGNATURE or
// ERR_ALGORITHM.
fn read_message(der: const u8[:], trusted: const u8[:], allow_sha1: bool) -> Message, i64 {
    var m = Message { .. };
    let sd, e = x509::cms_parse_signed_ber(der);
    if e != x509::OK { return m, ERR_MALFORMED; }
    let d = sd.der[..];
    if !asn1::oid_is(d, sd.content_type, x509::OID_CMS_DATA) { return m, ERR_MALFORMED; }
    if !x509::cms_signed(sd) { return m, ERR_SIGNATURE; }
    let signer, ve = verify_any(sd, allow_sha1);
    if ve == x509::ERR_UNSUPPORTED_ALGORITHM {
        // SHA-1 when not allowed comes here too: say which.
        let c2, v2 = verify_any(sd, true);
        return m, if !allow_sha1 && v2 == x509::OK { ERR_ALGORITHM } else { ERR_SIGNATURE };
    }
    if ve == x509::ERR_MALFORMED { return m, ERR_MALFORMED; }
    if ve != x509::OK { return m, ERR_SIGNATURE; }
    if signer.der.len > MAX_SIGNER { return m, ERR_MALFORMED; }
    if trusted.len > 0 && !contains_cert(trusted, signer.der) { return m, ERR_SIGNATURE; }
    m.signer.append(signer.der);
    m.sha1 = signed_with_sha1(sd);
    let a, oka = read_attrs(sd);
    if !oka { return m, ERR_MALFORMED; }
    m.attrs = a;
    if sd.has_content { m.envelope.append(x509::cms_content(sd)); }
    return m, OK;
}

// The signer's certificate and the check of its signature, over the
// content or, without one, over nothing (a CertRep with no envelope).
fn verify_any(sd: const x509::SignedData&, allow_sha1: bool) -> x509::Cert, i64 {
    if sd.has_content {
        let c, v = x509::cms_verify(sd, allow_sha1);
        return c, v;
    }
    let c, v = x509::cms_verify_detached(sd, "", allow_sha1);
    return c, v;
}

// Whether the signer's digest algorithm is SHA-1.
fn signed_with_sha1(sd: const x509::SignedData&) -> bool {
    let d = sd.der[..];
    let p, ok = asn1::children_of(d, sd.signer, asn1::SEQUENCE);
    return ok && p.len > 2 && x509::cms_digest_of(d, p[2]) == 160;
}

// Whether `cert` (DER) is among `certs` (DER laid end to end).
fn contains_cert(certs: const u8[:], cert: const u8[:]) -> bool {
    var at = 0;
    while at < certs.len {
        let t, ok = asn1::read(certs, at, certs.len);
        if !ok { return false; }
        if certs[t.start..t.end] == cert { return true; }
        at = t.end;
    }
    return false;
}

// The pkcsPKIEnvelope's content, decrypted with the key of `cert` (DER).
// DES and DES-EDE3 only with `legacy`. ERR_DECRYPT, ERR_ALGORITHM or
// ERR_MALFORMED.
fn open_envelope(m: const Message&, key: const x509::PrivateKey&, cert: const u8[:], legacy: bool) -> u8[>..], i64 {
    var none: u8[>..] = [];
    if m.envelope.len == 0 { return none, ERR_MALFORMED; }
    let rc, e = x509::parse(cert);
    if e != x509::OK { return none, ERR_ARG; }
    let pt, ctype, de = x509::cms_decrypt_with(m.envelope, key, rc, legacy);
    if de == x509::ERR_UNSUPPORTED_ALGORITHM && !legacy {
        let p2, t2, de2 = x509::cms_decrypt_legacy(m.envelope, key, rc);
        if de2 == x509::OK { return none, ERR_ALGORITHM; }
    }
    if de == x509::ERR_MALFORMED { return none, ERR_MALFORMED; }
    if de != x509::OK { return none, ERR_DECRYPT; }
    if ctype != x509::OID_CMS_DATA { return none, ERR_MALFORMED; }
    return pt, OK;
}

// The certificates of a certs-only SignedData, DER laid end to end, and
// its CRLs. ERR_MALFORMED if it is not one (it has signers).
fn read_certs_only(der: const u8[:]) -> u8[>..], u8[>..], i64 {
    var certs: u8[>..] = [];
    var crls:  u8[>..] = [];
    let sd, e = x509::cms_parse_signed_ber(der);
    if e != x509::OK || x509::cms_signed(sd) { return certs, crls, ERR_MALFORMED; }
    certs.append(x509::cms_certs(sd));
    // Each must be a certificate.
    var at = 0;
    while at < certs.len {
        let t, ok = asn1::read(certs, at, certs.len);
        var good = ok;
        if ok {
            let c, ce = x509::parse(certs[t.start..t.end]);
            good = ce == x509::OK;
            at = t.end;
        }
        if !good { certs.clear(); return certs, crls, ERR_MALFORMED; }
    }
    crls.append(x509::cms_crls(sd));
    return certs, crls, OK;
}

// --- Requests' contents -------------------------------------------------------

// A CSR for SCEP: subject (Name DER), the SAN entries `san` (a GeneralNames
// builder's contents, empty for none), and the challengePassword
// (§3.3.1; empty for none, as a renewal may send), signed by key (RSA).
fn make_csr(subject: const u8[:], san: const u8[:], key: const x509::PrivateKey&, challenge: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    if key.kind != x509::KEY_RSA { return none, ERR_ARG; }
    var more: u8[>..] = [];
    if challenge.len > 0 {
        // DirectoryString: PrintableString when it fits, else UTF8String.
        var v: u8[>..] = [];
        if printable_ok(challenge) { asn1::put_printable(v, challenge); }
        else {
            if !asn1::utf8_valid(challenge) { return none, ERR_ARG; }
            asn1::put_utf8_string(v, challenge);
        }
        put_attr(more, OID_CHALLENGE_PASSWORD, v);
    }
    let csr, e = x509::create_csr_attrs(subject, san, key, more);
    if e != x509::OK { return none, ERR_ARG; }
    return csr, OK;
}

// The self-signed certificate that signs an initial request (§2.3): the
// CSR's subject and key, valid for a day around now.
fn self_signed(csr: const u8[:], key: const x509::PrivateKey&) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let r, e = x509::parse_csr(csr);
    if e != x509::OK { return none, ERR_ARG; }
    let d = r.der[..];
    let now = time_ns() / 1000000000;
    var t, okt = x509::template("", now - 3600, now + 86400);
    t.subject.clear();
    if r.subject.end - r.subject.start > t.subject.cap { return none, ERR_ARG; }
    t.subject.append(d[r.subject.start..r.subject.end]);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_ENCIPHERMENT;
    let cert, ce = x509::create_certificate(t, d[r.spki.start..r.spki.end], "", key);
    if ce != x509::OK { return none, ERR_ARG; }
    return cert, OK;
}

// IssuerAndSubject (§3.3.3): CertPoll's content, the CA's Name and the
// request's subject Name (DER).
fn issuer_and_subject(issuer: const u8[:], subject: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    b.append(issuer);
    b.append(subject);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, b);
    return out;
}

// IssuerAndSerialNumber (§3.3.4, §3.3.5): GetCert's and GetCRL's content,
// from a certificate (DER).
fn issuer_and_serial(cert: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let c, e = x509::parse(cert);
    if e != x509::OK { return out, false; }
    let d = c.der[..];
    var b: u8[>..] = [];
    b.append(d[c.issuer.start..c.issuer.end]);
    b.append(d[c.serial.start..c.serial.end]);
    asn1::put(out, asn1::SEQUENCE, b);
    return out, true;
}

// --- The client -----------------------------------------------------------------

fn op_url(c: const Client&, op: const u8[:], message: const u8[:]) -> u8[>..] {
    var u: u8[>..] = [];
    u.append(c.url);
    u.append("?operation=");
    u.append(op);
    if message.len > 0 {
        u.append("&message=");
        http::query_escape(u, message);
    }
    return u;
}

fn limit_body(c: const Client&, hc: http::Client&) {
    if hc.opt.max_body > c.max_body { hc.opt.max_body = c.max_body; }
}

fn content_type_is(r: const http::Response&, want: const u8[:]) -> bool {
    let v, ok = http::response_header(r, "Content-Type");
    if !ok { return false; }
    var end = position(v, ';');
    if end < 0 { end = v.len; }
    return lower_eq(trim(v[..end]), want);
}

// GetCACaps: c.caps. A server that answers with an error or nothing has no
// caps (RFC 8894 §3.5.1: assume the minimum), which is not an error.
fn get_caps(c: Client&, hc: http::Client&) -> i64 {
    if c.url.len == 0 { return ERR_ARG; }
    limit_body(c, hc);
    let r = http::request(hc, "GET", op_url(c, "GetCACaps", c.label), "", "");
    if r.err != 0 { c.http_err = r.err; return ERR_HTTP; }
    c.status = r.status;
    c.has_caps = true;
    c.caps = if r.status == 200 { parse_caps(http::response_body(r)) } else { Caps { .. } };
    return OK;
}

// GetCACert: c.ca_certs, the CA's certificate alone (x-x509-ca-cert) or
// the CA's and an RA's (x-x509-ca-ra-cert, certs-only).
fn get_ca_cert(c: Client&, hc: http::Client&) -> i64 {
    if c.url.len == 0 { return ERR_ARG; }
    limit_body(c, hc);
    let r = http::request(hc, "GET", op_url(c, "GetCACert", c.label), "", "");
    if r.err != 0 { c.http_err = r.err; return ERR_HTTP; }
    c.status = r.status;
    if r.status != 200 { return ERR_STATUS; }
    let certs, e = ca_certs_of(http::response_body(r), content_type_is(r, "application/x-x509-ca-ra-cert"));
    if e != OK { return e; }
    c.ca_certs = copy(certs);
    return OK;
}

// GetCACert's body as certificates: one DER certificate, or a certs-only
// SignedData (`chain`, or when the body is not a certificate).
fn ca_certs_of(body: const u8[:], chain: bool) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if !chain {
        let c, e = x509::parse(body);
        if e == x509::OK { out.append(body); return out, OK; }
    }
    let certs, crls, e2 = read_certs_only(body);
    if e2 != OK || certs.len == 0 { return out, ERR_MALFORMED; }
    return certs, OK;
}

// The certificate requests are encrypted to: an RA's (a certificate that
// is not a CA's and may encipher keys) if there is one, else the CA's.
fn recipient_cert(certs: const u8[:]) -> u8[>..] {
    var ca: u8[>..] = [];
    var ra: u8[>..] = [];
    var at = 0;
    while at < certs.len {
        let t, ok = asn1::read(certs, at, certs.len);
        if !ok { break; }
        at = t.end;
        let c, e = x509::parse(certs[t.start..t.end]);
        if e != x509::OK || c.key_type != x509::KEY_RSA { continue; }
        let enc = !c.has_key_usage || c.key_usage & x509::KU_KEY_ENCIPHERMENT != 0;
        if c.is_ca && ca.len == 0 { ca.append(certs[t.start..t.end]); }
        else if !c.is_ca && enc && ra.len == 0 { ra.append(certs[t.start..t.end]); }
    }
    if ra.len > 0 { ca = copy(ra); }
    else if ca.len == 0 {
        // A lone certificate without basicConstraints: take it as the CA's.
        let t, ok = asn1::read(certs, 0, certs.len);
        if ok { ca.append(certs[t.start..t.end]); }
    }
    return ca;
}

// The CA's own certificate among c.ca_certs (the one that is a CA), for its
// Name in CertPoll.
fn ca_cert(certs: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var at = 0;
    while at < certs.len {
        let t, ok = asn1::read(certs, at, certs.len);
        if !ok { break; }
        at = t.end;
        let c, e = x509::parse(certs[t.start..t.end]);
        if e == x509::OK && c.is_ca && out.len == 0 { out.append(certs[t.start..t.end]); }
    }
    if out.len == 0 {
        let t, ok = asn1::read(certs, 0, certs.len);
        if ok { out.append(certs[t.start..t.end]); }
    }
    return out;
}

// Sends a pkiMessage (PKIOperation): POST when the server says it takes
// it, else GET with the message in base64 (§4.3). The reply's body.
fn pki_operation(c: Client&, hc: http::Client&, msg: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    limit_body(c, hc);
    var r = http::empty_response(0);
    if c.caps.post {
        r = http::post(hc, op_url(c, "PKIOperation", ""), "application/x-pki-message", msg);
    } else {
        var b: u8[>..] = [];
        base64::encode(b, msg);
        r = http::request(hc, "GET", op_url(c, "PKIOperation", b), "", "");
    }
    if r.err != 0 { c.http_err = r.err; return none, ERR_HTTP; }
    c.status = r.status;
    if r.status == 200 { none.append(http::response_body(r)); }
    return none, if r.status == 200 { OK } else { ERR_STATUS };
}

// Checks a CertRep against the request it answers: its messageType,
// transactionID and recipientNonce, then its status. OK for SUCCESS (with
// an envelope), ERR_PENDING, ERR_FAILURE (c.fail_info set), ERR_MISMATCH,
// ERR_MALFORMED.
fn check_reply(c: Client&, m: const Message&, sent: const Attrs&) -> i64 {
    let a = m.attrs;
    if a.message_type != MSG_CERT_REP || a.transaction_id[..] != sent.transaction_id[..] ||
       a.recipient_nonce[..] != sent.sender_nonce[..] {
        return ERR_MISMATCH;
    }
    if a.status == STATUS_SUCCESS {
        if m.envelope.len == 0 { return ERR_MALFORMED; }
        return OK;
    }
    if a.status == STATUS_PENDING { return ERR_PENDING; }
    if a.status == STATUS_FAILURE {
        c.fail_info = a.fail_info;
        c.fail_text.clear();
        c.fail_text.append(a.fail_text);
        return ERR_FAILURE;
    }
    return ERR_MALFORMED;
}

// One request and its CertRep: the message of type `mt` with `payload`,
// signed by key and `signer` (DER) under transaction `tid`; the reply
// checked, decrypted with the same key, and its certs-only content read.
// The certificates and CRLs it carries, DER laid end to end.
fn transact(c: Client&, hc: http::Client&, mt: i64, tid: const u8[:], payload: const u8[:],
            key: const x509::PrivateKey&, signer: const u8[:]) -> u8[>..], u8[>..], i64 {
    var none:  u8[>..] = [];
    var none2: u8[>..] = [];
    if c.ca_certs.len == 0 { return none, none2, ERR_NO_CA; }
    if !c.has_caps {
        let ce = get_caps(c, hc);
        if ce != OK { return none, none2, ce; }
    }
    let cipher, h, ae = choose_algorithms(c.caps, c.legacy, c.aes256);
    if ae != OK { return none, none2, ae; }
    var sent = Attrs { .. };
    sent.message_type = mt;
    if tid.len > MAX_TRANSACTION_ID { return none, none2, ERR_ARG; }
    sent.transaction_id.append(tid);
    let nonce = new_nonce();
    sent.sender_nonce.append(nonce[..]);
    c.transaction_id.clear();
    c.transaction_id.append(tid);
    let msg, be = build_message(sent, payload, recipient_cert(c.ca_certs), cipher, key, signer, h);
    if be != OK { return none, none2, be; }
    let body, pe = pki_operation(c, hc, msg);
    if pe != OK { return none, none2, pe; }
    let m, re = read_message(body, c.ca_certs, c.legacy);
    if re != OK { return none, none2, re; }
    let ce = check_reply(c, m, sent);
    if ce != OK { return none, none2, ce; }
    let inner, oe = open_envelope(m, key, signer, c.legacy);
    if oe != OK { return none, none2, oe; }
    let certs, crls, ie = read_certs_only(inner);
    if ie != OK { return none, none2, ie; }
    return certs, crls, OK;
}

// The first certificate of several laid end to end (the issued one, after
// enroll), or empty.
fn first_cert(certs: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let t, ok = asn1::read(certs, 0, certs.len);
    if ok { out.append(certs[t.start..t.end]); }
    return out;
}

// Puts the certificate whose key is `spki` first among certs, or false if
// none has it.
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

// PKCSReq (or RenewalReq with `renewal`: signer is then the certificate
// being renewed, and key its key... and the CSR's; RFC 8894 §3.3.1.2)
// for `csr`, signed with `key` and `signer`; while the CA answers
// PENDING, CertPoll every poll_ms until poll_timeout_ms. The issued
// certificate first, then the others the CA sent, DER laid end to end.
// The issued certificate must carry the CSR's key.
fn enroll(c: Client&, hc: http::Client&, csr: const u8[:], key: const x509::PrivateKey&, signer: const u8[:],
          renewal: bool) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let r, e = x509::parse_csr(csr);
    if e != x509::OK { return none, ERR_ARG; }
    let d = r.der[..];
    let tid = transaction_id(d[r.spki.start..r.spki.end]);
    let certs, crls, te = transact(c, hc, if renewal { MSG_RENEWAL_REQ } else { MSG_PKCS_REQ }, tid, csr, key, signer);
    var got = copy(certs);
    var err = te;
    let deadline = clock_ns() + c.poll_timeout_ms * 1000000;
    while err == ERR_PENDING {
        if clock_ns() >= deadline { return none, ERR_TIMEOUT; }
        sleep_ms(c.poll_ms);
        let pc, pe = poll(c, hc, csr, key, signer);
        got = copy(pc);
        err = pe;
    }
    if err != OK { return none, err; }
    let out, ok = issued_first(got, d[r.spki.start..r.spki.end]);
    if !ok { return none, ERR_MALFORMED; }
    return out, OK;
}

// CertPoll (GetCertInitial, §3.3.3) for the request `csr` was sent in:
// the same transactionID, the CA's Name and the CSR's subject. ERR_PENDING
// while the CA still holds it.
fn poll(c: Client&, hc: http::Client&, csr: const u8[:], key: const x509::PrivateKey&, signer: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let r, e = x509::parse_csr(csr);
    if e != x509::OK { return none, ERR_ARG; }
    let ca = ca_cert(c.ca_certs);
    let cc, ce = x509::parse(ca);
    if ce != x509::OK { return none, ERR_NO_CA; }
    let d = r.der[..];
    let cd = cc.der[..];
    let content = issuer_and_subject(cd[cc.subject.start..cc.subject.end], d[r.subject.start..r.subject.end]);
    let tid = transaction_id(d[r.spki.start..r.spki.end]);
    let certs, crls, te = transact(c, hc, MSG_CERT_POLL, tid, content, key, signer);
    if te != OK { return none, te; }
    let out, ok = issued_first(certs, d[r.spki.start..r.spki.end]);
    if !ok { return none, ERR_MALFORMED; }
    return out, OK;
}

// A fresh transactionID for GetCert and GetCRL, which have no key of
// their own to name it by.
fn random_tid() -> u8[>..] {
    let n = new_nonce();
    var out: u8[>..] = [];
    x509::hex_upper(out, n[..]);
    return out;
}

// GetCert (§3.3.4): a certificate the CA issued, by its issuer and serial
// (taken from `cert`, DER), asked by key and `signer` (the requester's
// own, which the CA encrypts the reply to). The certificates the CA sent.
fn get_cert(c: Client&, hc: http::Client&, cert: const u8[:], key: const x509::PrivateKey&, signer: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let ias, ok = issuer_and_serial(cert);
    if !ok { return none, ERR_ARG; }
    let certs, crls, te = transact(c, hc, MSG_GET_CERT, random_tid(), ias, key, signer);
    if te != OK { return none, te; }
    return certs, OK;
}

// GetCRL (§3.3.5): the CRL for a certificate (DER) of the CA's. The CRLs
// the CA sent, DER laid end to end.
fn get_crl(c: Client&, hc: http::Client&, cert: const u8[:], key: const x509::PrivateKey&, signer: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let ias, ok = issuer_and_serial(cert);
    if !ok { return none, ERR_ARG; }
    let certs, crls, te = transact(c, hc, MSG_GET_CRL, random_tid(), ias, key, signer);
    if te != OK { return none, te; }
    if crls.len == 0 { return none, ERR_MALFORMED; }
    return crls, OK;
}

// --- A test CA ------------------------------------------------------------------
//
// The server side of the same messages, for tests and goose-scep serve:
// GetCACaps, GetCACert (the CA's certificate alone), PKIOperation by POST
// or GET; PKCSReq checked for its challengePassword, RenewalReq for a
// signer this CA issued; PENDING for `pending` CertPolls when asked;
// GetCert by issuer and serial among what it issued; GetCRL (an empty
// CRL). Not a CA to run: it keeps what it issued in memory only.

root struct Server {
    ca_key:     x509::PrivateKey = x509::empty_key(),
    ca_cert:    u8[>..]          = [],
    challenge:  u8[>..]          = [],       // PKCSReq's challengePassword; empty: none asked
    caps:       u8[>..]          = [],       // GetCACaps' answer; empty: the default below
    pending:    i64              = 0,        // CertPolls a new request waits through (0: issued at once)
    legacy:     bool             = false,    // DES, DES-EDE3 and SHA-1 requests taken
    validity_s: i64              = 30 * 86400,
    issued:     u8[>..]          = [],       // the certificates issued, DER laid end to end
    held:       u8[>..]          = [],       // requests PENDING: SEQUENCE { tid, polls left, CSR } laid end to end
    log:        u8[>..]          = [],       // one line a PKIOperation, for the operator
}

let DEFAULT_CAPS: const u8[:] = "AES\nPOSTPKIOperation\nRenewal\nSCEPStandard\nSHA-256\nSHA-512\n";

// A server's answer: the HTTP status, the Content-Type, the body.
struct Answer {
    status:       i64      = 200,
    content_type: u8[..64] = [],
    body:         u8[>..]  = [],
}

fn answer(status: i64, ct: const u8[:], body: const u8[:]) -> Answer {
    var a = Answer { .. };
    a.status = status;
    a.content_type.append(ct);
    a.body.append(body);
    return a;
}

fn log_line(s: Server&, what: const u8[:]) {
    if s.log.len < 65536 {
        s.log.append(what);
        s.log.push('\n');
    }
}

// The certificate this CA issues for a request: its subject, key and SAN.
fn issue(s: Server&, r: const x509::Csr&, now: i64) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let d = r.der[..];
    var t, okt = x509::template("", now - 300, now + s.validity_s);
    if r.subject.end - r.subject.start > t.subject.cap { return none, FAIL_BAD_REQUEST; }
    t.subject.clear();
    t.subject.append(d[r.subject.start..r.subject.end]);
    if r.has_san {
        if r.san.end - r.san.off > t.san.cap { return none, FAIL_BAD_REQUEST; }
        t.san.append(d[r.san.off..r.san.end]);
    }
    t.basic_constraints = true;
    t.key_usage = x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_ENCIPHERMENT;
    t.ext_key_usage = x509::EKU_CLIENT_AUTH;
    let cert, e = x509::create_certificate(t, d[r.spki.start..r.spki.end], s.ca_cert, s.ca_key);
    if e != x509::OK { return none, FAIL_BAD_REQUEST; }
    s.issued.append(cert);
    return cert, OK;
}

// A CertRep to request m: SUCCESS with `certs` (and `crls`) in a
// certs-only SignedData encrypted to the requester, or PENDING, or
// FAILURE with fail_info.
fn cert_rep(s: const Server&, m: const Message&, status: i64, fail_info: i64, certs: const u8[:], crls: const u8[:]) -> Answer {
    var a = Attrs { .. };
    a.message_type = MSG_CERT_REP;
    a.status = status;
    a.fail_info = if status == STATUS_FAILURE { fail_info } else { -1 };
    a.transaction_id.append(m.attrs.transaction_id);
    let n = new_nonce();
    a.sender_nonce.append(n[..]);
    a.recipient_nonce.append(m.attrs.sender_nonce);
    var payload:   u8[>..] = [];
    var recipient: u8[>..] = [];
    if status == STATUS_SUCCESS {
        payload = x509::cms_certs_only(certs, crls);
        recipient.append(m.signer);
    }
    let msg, e = build_message(a, payload, recipient, x509::CMS_AES128_CBC, s.ca_key, s.ca_cert, 256);
    if e != OK { return answer(500, "text/plain", "cannot sign the reply\n"); }
    return answer(200, "application/x-pki-message", msg);
}

fn ca_name(s: const Server&) -> u8[>..] {
    var out: u8[>..] = [];
    let c, e = x509::parse(s.ca_cert);
    if e == x509::OK { out.append(c.der[c.subject.start..c.subject.end]); }
    return out;
}

// The issued certificate with this issuer and serial (an
// IssuerAndSerialNumber's DER), or empty.
fn find_issued(s: const Server&, ias: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let top, ok = asn1::parse(ias);
    let p, okp = asn1::children_of(ias, top, asn1::SEQUENCE);
    if !ok || !okp || p.len != 2 { return out; }
    var at = 0;
    let all = s.issued[..];
    while at < all.len {
        let t, okt = asn1::read(all, at, all.len);
        if !okt { break; }
        at = t.end;
        let c, e = x509::parse(all[t.start..t.end]);
        if e != x509::OK { continue; }
        let cd = c.der[..];
        if cd[c.issuer.start..c.issuer.end] == ias[p[0].start..p[0].end] && cd[c.serial.start..c.serial.end] == ias[p[1].start..p[1].end] {
            out.append(all[t.start..t.end]);
            return out;
        }
    }
    return out;
}

// Takes the request held under tid one poll on: its CSR when it is due
// (removed then), else empty; `found` false if none is held.
fn take_held(s: Server&, tid: const u8[:]) -> u8[>..], bool {
    var csr:  u8[>..] = [];
    var kept: u8[>..] = [];
    var found = false;
    let all = copy(s.held);
    var at = 0;
    while at < all.len {
        let t, ok = asn1::read(all, at, all.len);
        if !ok { break; }
        at = t.end;
        let p, okp = asn1::children_of(all, t, asn1::SEQUENCE);
        if !okp || p.len != 3 { continue; }
        if all[p[0].off..p[0].end] != tid || found {
            kept.append(all[t.start..t.end]);
            continue;
        }
        found = true;
        let polls, oki = asn1::read_i64(all, p[1]);
        if polls <= 1 {
            csr.append(all[p[2].start..p[2].end]);
        } else {
            var b: u8[>..] = [];
            asn1::put_printable(b, tid);
            asn1::put_i64(b, polls - 1);
            b.append(all[p[2].start..p[2].end]);
            asn1::put(kept, asn1::SEQUENCE, b);
        }
    }
    s.held = copy(kept);
    return csr, found;
}

fn hold(s: Server&, tid: const u8[:], csr: const u8[:]) {
    var b: u8[>..] = [];
    asn1::put_printable(b, tid);
    asn1::put_i64(b, s.pending);
    b.append(csr);
    asn1::put(s.held, asn1::SEQUENCE, b);
}

// A PKCSReq or RenewalReq's CSR: checked, then issued, held, or refused.
fn handle_request(s: Server&, m: const Message&, csr_der: const u8[:], now: i64) -> Answer {
    let r, e = x509::parse_csr(csr_der);
    if e != x509::OK || x509::check_csr(r) != x509::OK {
        log_line(s, "a request whose CSR does not verify: badMessageCheck");
        return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_MESSAGE_CHECK, "", "");
    }
    if m.attrs.message_type == MSG_RENEWAL_REQ {
        // Renewal: signed by a certificate this CA issued.
        if !contains_cert(s.issued, m.signer) {
            log_line(s, "RenewalReq not signed by a certificate issued here: badRequest");
            return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_REQUEST, "", "");
        }
    } else if s.challenge.len > 0 {
        let pw, n = x509::csr_attribute(r, OID_CHALLENGE_PASSWORD);
        let d = r.der[..];
        var good = false;
        if n == 1 {
            let text, okt = asn1::read_string(d, pw);
            good = okt && text.len == s.challenge.len && bignum::ct_eq_bytes(text, s.challenge) == 1;
        }
        if !good {
            log_line(s, "PKCSReq with a wrong or no challengePassword: badRequest");
            return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_REQUEST, "", "");
        }
    }
    if s.pending > 0 {
        hold(s, m.attrs.transaction_id, csr_der);
        log_line(s, "request held: PENDING");
        return cert_rep(s, m, STATUS_PENDING, -1, "", "");
    }
    let cert, ie = issue(s, r, now);
    if ie != OK { return cert_rep(s, m, STATUS_FAILURE, ie, "", ""); }
    log_line(s, if m.attrs.message_type == MSG_RENEWAL_REQ { "RenewalReq: issued" } else { "PKCSReq: issued" });
    // The issued certificate alone: clients on Go's pkcs7 take the first of
    // the set, which DER sorts, as theirs.
    return cert_rep(s, m, STATUS_SUCCESS, -1, cert, "");
}

// The PKIOperation of a pkiMessage (DER).
fn handle_pki(s: Server&, msg: const u8[:], now: i64) -> Answer {
    let m, e = read_message(msg, "", s.legacy);
    if e != OK {
        log_line(s, str("a pkiMessage refused: ", error_text(e)));
        return answer(400, "text/plain", "not a pkiMessage this server takes\n");
    }
    if m.sha1 && !s.legacy { return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_ALG, "", ""); }
    if m.attrs.sender_nonce.len == 0 { return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_REQUEST, "", ""); }
    let ca = copy(s.ca_cert);
    let inner, oe = open_envelope(m, s.ca_key, ca, s.legacy);
    if oe == ERR_ALGORITHM { return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_ALG, "", ""); }
    if oe != OK {
        log_line(s, "a pkiMessage that does not decrypt: badMessageCheck");
        return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_MESSAGE_CHECK, "", "");
    }
    let mt = m.attrs.message_type;
    if mt == MSG_PKCS_REQ || mt == MSG_RENEWAL_REQ { return handle_request(s, m, inner, now); }
    if mt == MSG_CERT_POLL {
        let top, ok = asn1::parse(inner);
        let p, okp = asn1::children_of(inner, top, asn1::SEQUENCE);
        if !ok || !okp || p.len != 2 || inner[p[0].start..p[0].end] != ca_name(s)[..] {
            return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_CERT_ID, "", "");
        }
        let csr, found = take_held(s, m.attrs.transaction_id);
        if !found { return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_CERT_ID, "", ""); }
        if csr.len == 0 { log_line(s, "CertPoll: still PENDING"); return cert_rep(s, m, STATUS_PENDING, -1, "", ""); }
        let r, re = x509::parse_csr(csr);
        if re != x509::OK { return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_REQUEST, "", ""); }
        let cert, ie = issue(s, r, now);
        if ie != OK { return cert_rep(s, m, STATUS_FAILURE, ie, "", ""); }
        log_line(s, "CertPoll: issued");
        return cert_rep(s, m, STATUS_SUCCESS, -1, cert, "");
    }
    if mt == MSG_GET_CERT {
        let cert = find_issued(s, inner);
        if cert.len == 0 { return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_CERT_ID, "", ""); }
        log_line(s, "GetCert: found");
        return cert_rep(s, m, STATUS_SUCCESS, -1, cert, "");
    }
    if mt == MSG_GET_CRL {
        let top, ok = asn1::parse(inner);
        let p, okp = asn1::children_of(inner, top, asn1::SEQUENCE);
        if !ok || !okp || p.len != 2 || inner[p[0].start..p[0].end] != ca_name(s)[..] {
            return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_CERT_ID, "", "");
        }
        var none: x509::Revoked[>..] = [];
        let crl, ce = x509::create_crl(s.ca_cert, s.ca_key, none, now, now + 86400, 1);
        if ce != x509::OK { return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_REQUEST, "", ""); }
        log_line(s, "GetCRL: sent");
        return cert_rep(s, m, STATUS_SUCCESS, -1, "", crl);
    }
    return cert_rep(s, m, STATUS_FAILURE, FAIL_BAD_REQUEST, "", "");
}

// Answers one HTTP request: its method, its target (the path and query),
// and its body. `now` is the time, seconds since 1970.
fn serve(s: Server&, method: const u8[:], target: const u8[:], body: const u8[:], now: i64) -> Answer {
    let q = position(target, '?');
    if q < 0 { return answer(404, "text/plain", "no operation\n"); }
    let query = target[q + 1..];
    let op, has_op = http::query_value(query, "operation");
    if !has_op { return answer(400, "text/plain", "no operation\n"); }
    if op == "GetCACaps" && method == "GET" {
        return answer(200, "text/plain", if s.caps.len > 0 { s.caps[..] } else { DEFAULT_CAPS });
    }
    if op == "GetCACert" && method == "GET" { return answer(200, "application/x-x509-ca-cert", s.ca_cert); }
    if op == "PKIOperation" && method == "POST" { return handle_pki(s, body, now); }
    if op == "PKIOperation" && method == "GET" {
        let msg64, has = http::query_value(query, "message");
        // A '+' that was not escaped reads as a space.
        var fixed: u8[>..] = [];
        for ch in msg64 { fixed.push(if ch == ' ' { '+' } else { ch }); }
        var der: u8[>..] = [];
        if !has || !base64::decode(der, fixed) { return answer(400, "text/plain", "the message is not base64\n"); }
        return handle_pki(s, der, now);
    }
    return answer(400, "text/plain", "unknown operation\n");
}
