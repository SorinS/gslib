// mail.smime: S/MIME 4.0 (RFC 8551), messages signed, encrypted or both,
// and read back, over x509's CMS (crypto/x509/cms.goose, cms_env.goose).
//
//     var o = smime::Options { .. };
//     var out: u8[>..] = [];
//     var rc = smime::sign(m, key, cert, chain, o, out);           // multipart/signed
//     rc = smime::encrypt(m, recipients, o, out);                  // application/pkcs7-mime
//     rc = smime::sign_encrypt(m, key, cert, chain, recipients, o, out);
//
//     var r = smime::Opened { .. };                    // a root struct: a local
//     let rc2 = smime::open(received, key, cert, r);   // every layer, decrypted and verified
//     // r.entity is the MIME entity inside, r.signer the signer's certificate
//     let rc3 = smime::check_signer(r, roots, now, smime::from_address(received));
//
// Each of sign, sign_opaque, encrypt and sign_encrypt takes a mail::Msg,
// which it writes, or a message already written (RFC 5322, CRLF or LF
// lines). The header fields that are not Content-* (Date, From, To,
// Subject, Message-ID, MIME-Version, ...) stay outside, as they were; the
// Content-* fields and the body become the entity that is protected.
// sign_entity, sign_opaque_entity and encrypt_entity protect an entity
// alone (its Content-* fields, a blank line, its body) and give the
// entity that replaces it.
//
// Signing makes multipart/signed (RFC 8551 §3.5.3): the entity as it is
// sent, with CRLF line ends, is what is signed, so it must be 7bit (a
// Msg with ENC_8BIT is refused: set quoted-printable or base64); micalg
// names the digest; the signature, a detached SignedData over id-data
// with signingTime and smimeCapabilities, is application/pkcs7-signature
// (smime.p7s) in base64. RSA signs with PKCS #1 v1.5 (or PSS when asked),
// EC keys with ECDSA, Ed25519 keys with Ed25519 (RFC 8419, micalg
// sha-512), ML-DSA keys with pure ML-DSA (RFC 9882, micalg sha-512; the
// digest is SHA-512 whatever Options.hash says). sign_opaque makes application/pkcs7-mime; smime-type=
// signed-data instead, the entity inside the SignedData. encrypt makes
// application/pkcs7-mime; smime-type=enveloped-data (AES-CBC), or
// authEnveloped-data for AES-GCM (RFC 8551 §3.3, §3.4), to the
// recipients' certificates: RSA, EC or ML-KEM (RFC 9936, through x509's
// cms_env); the sender reads it later only if their own
// certificate is among them. sign_encrypt signs, then encrypts that.
//
// Reading, open goes through the layers as it finds them, decrypting
// with the key given and verifying signatures, until an entity that is
// neither: it returns that entity, whether it was signed and encrypted,
// and the signer's certificate and the certificates sent with it. It
// reads application/x-pkcs7-* too, and CMS in BER. Whether the signer
// is who they say is the caller's to decide: check_signer checks the
// certificate's path to the roots given (for email protection) and that
// one of its addresses is the From address.
//
// Errors: ERR_SIGNATURE (a signature that does not verify, or by SHA-1),
// ERR_DECRYPT (not encrypted to this certificate, or not decrypting with
// this key), ERR_CERT (no certificate for the signer, a recipient's
// certificate that cannot be encrypted to, a signer that check_signer
// refuses), ERR_KEY (a key that cannot sign, or not the certificate's;
// a message encrypted when there is no key), ERR_FORMAT (malformed MIME
// or CMS, a body to sign that is not 7bit, or no S/MIME at all), ERR_ARG.

namespace smime;

import std;
import base64;
import mime;
import encoding.asn1;
import crypto.x509;
import crypto.x509.keys;
import crypto.x509.pool;
import crypto.x509.verify;
import crypto.x509.cms;
import crypto.x509.cms_env;
import crypto.bignum;
import crypto.bignum.entropy;
import mail;
import mail.address;
import mail.message;

// How the functions here sign and encrypt; Options { .. } is the default.
struct Options {
    hash:         i64      = 256,                   // the digest: 256, 384 or 512 (Ed25519, ML-DSA: always 512)
    pss:          bool     = false,                 // RSA keys sign with PSS, not PKCS #1 v1.5
    signing_time: i64      = 0,                     // signingTime, seconds since 1970: 0 now, -1 none
    cipher:       i64      = x509::CMS_AES256_CBC,  // or CMS_AES128_CBC, CMS_AES128_GCM, CMS_AES256_GCM
    rsa_pkcs1:    bool     = false,                 // RSA recipients by RSAES-PKCS1-v1_5, not OAEP
    by_key_id:    bool     = false,                 // signer and recipients by subject key identifier
    boundary:     u8[..70] = [],                    // multipart/signed's boundary; random if empty
}

// What open found (a root struct: it lives in a local or a global).
root struct Opened {
    entity:           u8[>..]    = [],                  // the entity inside: Content-* fields, a blank line, the body
    message:          u8[>..]    = [],                  // the message's other header fields, then entity
    signed:           bool       = false,
    encrypted:        bool       = false,
    signer:           x509::Cert = x509::empty_cert(),  // when signed (the innermost signature's)
    certs:            u8[>..]    = [],                  // the certificates sent with it, DER laid end to end
    signing_time:     i64        = 0,
    has_signing_time: bool       = false,
    cms_error:        i64        = 0,                   // x509's error behind a failure, if one was
}

// --- Text ----------------------------------------------------------------------

// s with each bare LF made CRLF, appended to out.
fn crlf(out: u8[>..]&, s: const u8[:]) {
    for i in s.len {
        if s[i] == '\n' && (i == 0 || s[i - 1] != '\r') { out.push('\r'); }
        out.push(s[i]);
    }
}

fn find(s: const u8[:], pat: const u8[:], from: i64) -> i64 {
    var i = from;
    while i + pat.len <= s.len {
        if s[i..i + pat.len] == pat { return i; }
        i++;
    }
    return -1;
}

fn starts_with(s: const u8[:], at: i64, pat: const u8[:]) -> bool {
    return at >= 0 && at + pat.len <= s.len && s[at..at + pat.len] == pat;
}

// Whether s can travel as 7bit (RFC 2045 §2.7): no NUL or byte over 127,
// CR and LF only as CRLF, lines of at most 998 bytes.
fn is_7bit(s: const u8[:]) -> bool {
    var line = 0;
    for i in s.len {
        let c = s[i];
        if c == 0 || c >= 0x80 { return false; }
        if c == '\r' && (i + 1 >= s.len || s[i + 1] != '\n') { return false; }
        if c == '\n' {
            if i == 0 || s[i - 1] != '\r' { return false; }
            line = 0;
        } else if c != '\r' {
            line++;
            if line > mail::MAX_LINE { return false; }
        }
    }
    return true;
}

// Base64 in lines of 76, each ended by CRLF.
fn put_base64(out: u8[>..]&, data: const u8[:]) {
    var enc: u8[>..] = [];
    base64::encode(enc, data);
    var i = 0;
    while i < enc.len {
        let e = ::min(i + 76, enc.len);
        out.append(enc[i..e]);
        out.append("\r\n");
        i = e;
    }
}

fn unbase64(s: const u8[:]) -> u8[>..], bool {
    var clean: u8[>..] = [];
    for c in s { if c != ' ' && c != '\t' && c != '\r' && c != '\n' { clean.push(c); } }
    var out: u8[>..] = [];
    let ok = base64::decode(out, clean);
    return out, ok;
}

// --- Header fields ---------------------------------------------------------------

// Where an entity's header ends (after its last field's CRLF) and its body
// starts (after the blank line); both its end when there is no blank line.
fn split_entity(e: const u8[:]) -> i64, i64 {
    if starts_with(e, 0, "\r\n") { return 0, 2; }
    let i = find(e, "\r\n\r\n", 0);
    if i < 0 { return e.len, e.len; }
    return i + 2, i + 4;
}

// The end of the field starting at `at`: its line and the folded lines
// after it (those starting with a space or tab).
fn next_field(h: const u8[:], at: i64) -> i64 {
    var p = at;
    loop {
        let e = find(h, "\r\n", p);
        if e < 0 { return h.len; }
        p = e + 2;
        if p >= h.len || (h[p] != ' ' && h[p] != '\t') { return p; }
    }
}

fn field_name(f: const u8[:]) -> const u8[:] {
    var i = 0;
    while i < f.len && f[i] != ':' { i++; }
    var j = i;
    while j > 0 && (f[j - 1] == ' ' || f[j - 1] == '\t') { j--; }
    return f[..j];
}

// A field's value, unfolded, without the white space around it.
fn field_value(f: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < f.len && f[i] != ':' { i++; }
    i++;
    while i < f.len {
        if f[i] != '\r' && f[i] != '\n' { out.push(f[i]); }
        i++;
    }
    var a = 0;
    while a < out.len && (out[a] == ' ' || out[a] == '\t') { a++; }
    var b = out.len;
    while b > a && (out[b - 1] == ' ' || out[b - 1] == '\t') { b--; }
    var v: u8[>..] = [];
    v.append(out[a..b]);
    return v;
}

// The value of the first field named `name` (without case), and whether
// there is one.
fn header_get(h: const u8[:], name: const u8[:]) -> u8[>..], bool {
    var at = 0;
    while at < h.len {
        let e = next_field(h, at);
        if mail::eq_fold(field_name(h[at..e]), name) { return field_value(h[at..e]), true; }
        at = e;
    }
    var none: u8[>..] = [];
    return none, false;
}

fn is_content_field(name: const u8[:]) -> bool { name.len > 8 && mail::eq_fold(name[..8], "Content-") }

// A message (CRLF lines) split in two: its fields that are not Content-*,
// appended to outer, and the entity, its Content-* fields, the blank line
// and the body, appended to inner.
fn split_message(m: const u8[:], outer: u8[>..]&, inner: u8[>..]&) {
    let he, bs = split_entity(m);
    let h = m[..he];
    var at = 0;
    while at < h.len {
        let e = next_field(h, at);
        if is_content_field(field_name(h[at..e])) { inner.append(h[at..e]); } else { outer.append(h[at..e]); }
        at = e;
    }
    inner.append("\r\n");
    inner.append(m[bs..]);
}

// The addr-spec of a message's From field, "" if it has none that parses.
fn from_address(msg: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    crlf(m, msg);
    let he, bs = split_entity(m);
    var out: u8[>..] = [];
    let v, ok = header_get(m[..he], "From");
    if !ok { return out; }
    let a, rc = mail::parse_address(v);
    if rc == mail::OK { out.append(a.addr); }
    return out;
}

// --- Writing ---------------------------------------------------------------------

// The signature algorithm for a key: SIG_* and its hash, or ERR_KEY.
fn sig_alg(key: const x509::PrivateKey&, o: const Options&) -> i64, i64, i64 {
    if o.hash != 256 && o.hash != 384 && o.hash != 512 { return 0, 0, mail::ERR_ARG; }
    if key.kind == x509::KEY_RSA { return if o.pss { x509::SIG_RSA_PSS } else { x509::SIG_RSA_PKCS1 }, o.hash, mail::OK; }
    if key.kind == x509::KEY_EC_P256 || key.kind == x509::KEY_EC_P384 || key.kind == x509::KEY_EC_P521 {
        return x509::SIG_ECDSA, o.hash, mail::OK;
    }
    if key.kind == x509::KEY_ED25519 { return x509::SIG_ED25519, 512, mail::OK; }
    if x509::is_mldsa(key.kind) { return x509::SIG_MLDSA, 512, mail::OK; }     // RFC 9882: SHA-512
    return 0, 0, mail::ERR_KEY;
}

// Whether key is the private key of cert's public key.
fn key_matches(key: const x509::PrivateKey&, cert: const x509::Cert&) -> bool {
    let kb, ok = x509::key_bytes(cert.der, cert.key);
    return ok && x509::public_key_bytes(key)[..] == kb[..];
}

// RFC 2046's bchars, without the space.
fn boundary_ok(b: const u8[:]) -> bool {
    if b.len < 1 || b.len > 70 { return false; }
    for c in b {
        let ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                 c == '\'' || c == '(' || c == ')' || c == '+' || c == '_' || c == ',' || c == '-' ||
                 c == '.' || c == '/' || c == ':' || c == '=' || c == '?';
        if !ok { return false; }
    }
    return true;
}

// The boundary for multipart/signed: o's, which must not be in the
// entity, or a random one.
fn make_boundary(o: const Options&, entity: const u8[:]) -> u8[>..], bool {
    var b: u8[>..] = [];
    if o.boundary.len > 0 {
        b.append(o.boundary);
        var d: u8[>..] = [];
        d.append("--");
        d.append(b);
        return b, boundary_ok(b) && find(entity, d, 0) < 0;
    }
    loop {
        var raw: u8[24] = [0; 24];
        bignum::random_bytes(raw);
        b.clear();
        b.append("smime-");
        for x in raw { b.push(mime::LOWERHEX[x >> 4]); b.push(mime::LOWERHEX[x & 15]); }
        var d: u8[>..] = [];
        d.append("--");
        d.append(b);
        if find(entity, d, 0) < 0 { return b, true; }
    }
}

fn signing_time(o: const Options&) -> i64 {
    if o.signing_time == 0 { return time_ns() / 1000000000; }
    if o.signing_time < 0 { return -1; }
    return o.signing_time;
}

// A SignedData over id-data of e, detached or not.
fn sign_cms(e: const u8[:], key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
            o: const Options&, detached: bool) -> u8[>..], i64, i64 {
    var none: u8[>..] = [];
    let alg, h, rc = sig_alg(key, o);
    if rc != mail::OK { return none, 0, rc; }
    if !key_matches(key, cert) { return none, 0, mail::ERR_KEY; }
    if o.by_key_id && cert.ski.end == cert.ski.start { return none, 0, mail::ERR_CERT; }
    let so = x509::CmsSignOptions { detached: detached, signing_time: signing_time(o), capabilities: true,
                                    by_key_id: o.by_key_id };
    let der, ok = x509::cms_sign_with(x509::OID_CMS_DATA, e, key, cert, chain, alg, h, so);
    if !ok { return none, 0, mail::ERR_KEY; }
    return der, h, mail::OK;
}

// application/pkcs7-mime of a ContentInfo, base64.
fn put_pkcs7_mime(out: u8[>..]&, smime_type: const u8[:], der: const u8[:]) {
    out.append("Content-Type: application/pkcs7-mime; smime-type=");
    out.append(smime_type);
    out.append("; name=smime.p7m\r\nContent-Transfer-Encoding: base64\r\n");
    out.append("Content-Disposition: attachment; filename=smime.p7m\r\n\r\n");
    put_base64(out, der);
}

// The multipart/signed entity of `entity` (its Content-* fields, a blank
// line, its body), appended to out: the entity, CRLF line ends, must be
// 7bit (ERR_FORMAT). key signs; cert is its certificate, sent with the
// certificates of chain (DER laid end to end). On an error out is as it
// was.
fn sign_entity(entity: const u8[:], key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
               o: const Options&, out: u8[>..]&) -> i64 {
    var e: u8[>..] = [];
    crlf(e, entity);
    if !is_7bit(e) { return mail::ERR_FORMAT; }
    let b, okb = make_boundary(o, e);
    if !okb { return mail::ERR_ARG; }
    let der, h, rc = sign_cms(e, key, cert, chain, o, true);
    if rc != mail::OK { return rc; }
    var ct: u8[>..] = [];
    ct.append("multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-");
    format_int(ct, h, 10, 0, '0');
    ct.append("; boundary=\"");
    ct.append(b);
    ct.push('"');
    let mark = out.len;
    let rcf = mail::write_field(out, "Content-Type", ct, true);
    if rcf != mail::OK { out.resize(mark); return rcf; }
    out.append("\r\nThis is an S/MIME signed message.\r\n\r\n--");
    out.append(b);
    out.append("\r\n");
    out.append(e);                          // exactly what was signed
    out.append("\r\n--");
    out.append(b);
    out.append("\r\nContent-Type: application/pkcs7-signature; name=smime.p7s\r\n");
    out.append("Content-Transfer-Encoding: base64\r\n");
    out.append("Content-Disposition: attachment; filename=smime.p7s\r\n\r\n");
    put_base64(out, der);
    out.append("--");
    out.append(b);
    out.append("--\r\n");
    return mail::OK;
}

// The application/pkcs7-mime; smime-type=signed-data entity of `entity`,
// which goes inside the SignedData (so it need not be 7bit).
fn sign_opaque_entity(entity: const u8[:], key: const x509::PrivateKey&, cert: const x509::Cert&,
                      chain: const u8[:], o: const Options&, out: u8[>..]&) -> i64 {
    var e: u8[>..] = [];
    crlf(e, entity);
    let der, h, rc = sign_cms(e, key, cert, chain, o, false);
    if rc != mail::OK { return rc; }
    put_pkcs7_mime(out, "signed-data", der);
    return mail::OK;
}

// The application/pkcs7-mime entity of `entity` encrypted to each of
// `recipients` (certificates, DER laid end to end): enveloped-data, or
// authEnveloped-data for a GCM cipher.
fn encrypt_entity(entity: const u8[:], recipients: const u8[:], o: const Options&, out: u8[>..]&) -> i64 {
    let c = o.cipher;
    if c != x509::CMS_AES128_CBC && c != x509::CMS_AES256_CBC && c != x509::CMS_AES128_GCM &&
       c != x509::CMS_AES256_GCM { return mail::ERR_ARG; }
    var e: u8[>..] = [];
    crlf(e, entity);
    let eo = x509::CmsEncryptOptions { cipher: c, rsa_pkcs1: o.rsa_pkcs1, by_key_id: o.by_key_id, .. };
    let der, xe = x509::cms_encrypt(x509::OID_CMS_DATA, e, recipients, eo);
    if xe != x509::OK { return mail::ERR_CERT; }
    put_pkcs7_mime(out, if x509::cms_cipher_gcm(c) { "authEnveloped-data" } else { "enveloped-data" }, der);
    return mail::OK;
}

let DO_SIGN:         i64 = 0;
let DO_SIGN_OPAQUE:  i64 = 1;
let DO_ENCRYPT:      i64 = 2;
let DO_SIGN_ENCRYPT: i64 = 3;

// A message with its entity protected: the fields that are not Content-*
// as they were (MIME-Version added if missing), then the new entity.
fn protect(msg: const u8[:], what: i64, key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
           recipients: const u8[:], o: const Options&, out: u8[>..]&) -> i64 {
    var m: u8[>..] = [];
    crlf(m, msg);
    var outer: u8[>..] = [];
    var inner: u8[>..] = [];
    split_message(m, outer, inner);
    var ent: u8[>..] = [];
    var rc = mail::OK;
    if what == DO_SIGN {
        rc = sign_entity(inner, key, cert, chain, o, ent);
    } else if what == DO_SIGN_OPAQUE {
        rc = sign_opaque_entity(inner, key, cert, chain, o, ent);
    } else if what == DO_ENCRYPT {
        rc = encrypt_entity(inner, recipients, o, ent);
    } else {
        var s: u8[>..] = [];
        rc = sign_entity(inner, key, cert, chain, o, s);
        if rc == mail::OK { rc = encrypt_entity(s, recipients, o, ent); }
    }
    if rc != mail::OK { return rc; }
    out.append(outer);
    let mv, has = header_get(outer, "MIME-Version");
    if !has { out.append("MIME-Version: 1.0\r\n"); }
    out.append(ent);
    return mail::OK;
}

// The message written, for signing detached: refused (ERR_ARG) with
// 8bit bodies, which multipart/signed cannot carry unchanged.
fn write_msg(m: mail::Msg&, out: u8[>..]&, seven_bit: bool) -> i64 {
    if seven_bit && m.encoding == mail::ENC_8BIT { return mail::ERR_ARG; }
    return mail::write(m, out);
}

// The message signed: multipart/signed, the header outside.
fn sign(msg: const u8[:], key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
        o: const Options&, out: u8[>..]&) -> i64 {
    return protect(msg, DO_SIGN, key, cert, chain, "", o, out);
}

fn sign(m: mail::Msg&, key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
        o: const Options&, out: u8[>..]&) -> i64 {
    var raw: u8[>..] = [];
    let rc = write_msg(m, raw, true);
    if rc != mail::OK { return rc; }
    return protect(raw, DO_SIGN, key, cert, chain, "", o, out);
}

// The message signed opaquely: application/pkcs7-mime; smime-type=signed-data.
fn sign_opaque(msg: const u8[:], key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
               o: const Options&, out: u8[>..]&) -> i64 {
    return protect(msg, DO_SIGN_OPAQUE, key, cert, chain, "", o, out);
}

fn sign_opaque(m: mail::Msg&, key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
               o: const Options&, out: u8[>..]&) -> i64 {
    var raw: u8[>..] = [];
    let rc = write_msg(m, raw, false);
    if rc != mail::OK { return rc; }
    return protect(raw, DO_SIGN_OPAQUE, key, cert, chain, "", o, out);
}

// The message encrypted to `recipients` (certificates, DER laid end to end).
fn encrypt(msg: const u8[:], recipients: const u8[:], o: const Options&, out: u8[>..]&) -> i64 {
    let k = x509::empty_key();
    let c = x509::empty_cert();
    return protect(msg, DO_ENCRYPT, k, c, "", recipients, o, out);
}

fn encrypt(m: mail::Msg&, recipients: const u8[:], o: const Options&, out: u8[>..]&) -> i64 {
    var raw: u8[>..] = [];
    let rc = write_msg(m, raw, false);
    if rc != mail::OK { return rc; }
    return encrypt(raw, recipients, o, out);
}

// The message signed (multipart/signed), then that encrypted.
fn sign_encrypt(msg: const u8[:], key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
                recipients: const u8[:], o: const Options&, out: u8[>..]&) -> i64 {
    return protect(msg, DO_SIGN_ENCRYPT, key, cert, chain, recipients, o, out);
}

fn sign_encrypt(m: mail::Msg&, key: const x509::PrivateKey&, cert: const x509::Cert&, chain: const u8[:],
                recipients: const u8[:], o: const Options&, out: u8[>..]&) -> i64 {
    var raw: u8[>..] = [];
    let rc = write_msg(m, raw, true);
    if rc != mail::OK { return rc; }
    return protect(raw, DO_SIGN_ENCRYPT, key, cert, chain, recipients, o, out);
}

// --- Reading ---------------------------------------------------------------------

fn sig_error(e: i64) -> i64 {
    if e == x509::ERR_BAD_SIGNATURE || e == x509::ERR_UNSUPPORTED_ALGORITHM { return mail::ERR_SIGNATURE; }
    if e == x509::ERR_UNKNOWN_ISSUER { return mail::ERR_CERT; }
    return mail::ERR_FORMAT;
}

fn decrypt_error(e: i64) -> i64 {
    if e == x509::ERR_MALFORMED { return mail::ERR_FORMAT; }
    return mail::ERR_DECRYPT;
}

// A body decoded by its Content-Transfer-Encoding (base64, or 7bit,
// 8bit and binary as they are).
fn decode_body(h: const u8[:], body: const u8[:]) -> u8[>..], bool {
    let cte, has = header_get(h, "Content-Transfer-Encoding");
    if has && mail::eq_fold(cte, "base64") {
        let out, ok = unbase64(body);
        return out, ok;
    }
    var out: u8[>..] = [];
    out.append(body);
    return out, !has || mail::eq_fold(cte, "7bit") || mail::eq_fold(cte, "8bit") || mail::eq_fold(cte, "binary");
}

// multipart/signed's body split at its boundary: the first part exactly
// (without the CRLF before the next delimiter, which is the delimiter's),
// and the second, the signature, as an entity.
fn split_signed(body: const u8[:], boundary: const u8[:]) -> i64, i64, i64, i64, bool {
    var d: u8[>..] = [];
    d.append("\r\n--");
    d.append(boundary);
    let dd = d[2..];
    // The first delimiter, at the start or after the preamble.
    var p = if starts_with(body, 0, dd) { 0 } else { find(body, d, 0) + 2 };
    if p < 2 && !starts_with(body, 0, dd) { return 0, 0, 0, 0, false; }
    var parts: i64[4] = [0; 4];
    for k in 2 {
        var q = p + dd.len;
        if starts_with(body, q, "--") { return 0, 0, 0, 0, false; }     // the close, too early
        while q < body.len && (body[q] == ' ' || body[q] == '\t') { q++; }
        if !starts_with(body, q, "\r\n") { return 0, 0, 0, 0, false; }
        q += 2;
        let e = find(body, d, q);
        if e < 0 { return 0, 0, 0, 0, false; }
        parts[2 * k] = q;
        parts[2 * k + 1] = e;
        p = e + 2;
    }
    return parts[0], parts[1], parts[2], parts[3], true;
}

// An entity from inside a CMS structure, appended to out: as it is, or
// with CRLF line ends if it has only LFs (what openssl -binary keeps from
// a file with LF lines), so that its header reads.
fn entity_lines(out: u8[>..]&, s: const u8[:]) {
    if find(s, "\r\n", 0) < 0 { crlf(out, s); } else { out.append(s); }
}

fn open_with(msg: const u8[:], key: const x509::PrivateKey&, cert: const x509::Cert&, can_decrypt: bool,
             r: Opened&) -> i64 {
    r.entity.clear();
    r.message.clear();
    r.signed = false;
    r.encrypted = false;
    r.signer = x509::empty_cert();
    r.certs.clear();
    r.signing_time = 0;
    r.has_signing_time = false;
    r.cms_error = 0;
    var m: u8[>..] = [];
    crlf(m, msg);
    var outer: u8[>..] = [];
    var ent:   u8[>..] = [];
    split_message(m, outer, ent);
    var depth = 0;
    loop {
        if depth == 8 { return mail::ERR_FORMAT; }
        depth++;
        let he, bs = split_entity(ent);
        let ctv, has = header_get(ent[..he], "Content-Type");
        if !has { break; }
        let mt = mime::parse_media_type(ctv);
        if mt.err != mime::OK { break; }
        var next: u8[>..] = [];
        if mt.typ == "multipart/signed" {
            let proto, okp = mime::param(mt, "protocol");
            if !okp || !(mail::eq_fold(proto, "application/pkcs7-signature") ||
                         mail::eq_fold(proto, "application/x-pkcs7-signature")) { break; }
            let b, okb = mime::param(mt, "boundary");
            if !okb { return mail::ERR_FORMAT; }
            let body = ent[bs..];
            let c0, c1, s0, s1, oks = split_signed(body, b);
            if !oks { return mail::ERR_FORMAT; }
            let sig = body[s0..s1];
            let she, sbs = split_entity(sig);
            let der, okd = decode_body(sig[..she], sig[sbs..]);
            if !okd { return mail::ERR_FORMAT; }
            let sd, ep = x509::cms_parse_signed_ber(der);
            if ep != x509::OK { r.cms_error = ep; return mail::ERR_FORMAT; }
            let c, ev = x509::cms_verify_detached(sd, body[c0..c1]);
            if ev != x509::OK { r.cms_error = ev; return sig_error(ev); }
            r.signed = true;
            r.signer = copy(c);
            r.certs = x509::cms_certs(sd);
            let t, okt = x509::cms_signing_time(sd);
            r.signing_time = t;
            r.has_signing_time = okt;
            next.append(body[c0..c1]);
        } else if mt.typ == "application/pkcs7-mime" || mt.typ == "application/x-pkcs7-mime" {
            let der, okd = decode_body(ent[..he], ent[bs..]);
            if !okd { return mail::ERR_FORMAT; }
            var kind: u8[>..] = [];
            let st, okst = mime::param(mt, "smime-type");
            if okst { mime::append_lower(kind, st); }
            let ci = x509::cms_content_type(der);
            if ci == x509::OID_CMS_SIGNED_DATA && (!okst || kind == "signed-data") {
                let sd, ep = x509::cms_parse_signed_ber(der);
                if ep != x509::OK { r.cms_error = ep; return mail::ERR_FORMAT; }
                let c, ev = x509::cms_verify(sd);
                if ev != x509::OK { r.cms_error = ev; return sig_error(ev); }
                r.signed = true;
                r.signer = copy(c);
                r.certs = x509::cms_certs(sd);
                let t, okt = x509::cms_signing_time(sd);
                r.signing_time = t;
                r.has_signing_time = okt;
                entity_lines(next, x509::cms_content(sd));
            } else if (ci == x509::OID_CMS_ENVELOPED_DATA && (!okst || kind == "enveloped-data")) ||
                      (ci == x509::OID_CMS_AUTH_ENVELOPED_DATA && (!okst || kind == "authenveloped-data")) {
                if !can_decrypt { return mail::ERR_KEY; }
                let pt, ctype, ed = x509::cms_decrypt(der, key, cert);
                if ed != x509::OK { r.cms_error = ed; return decrypt_error(ed); }
                r.encrypted = true;
                entity_lines(next, pt);
            } else {
                return mail::ERR_FORMAT;         // certs-only, compressed-data, or a mismatch
            }
        } else {
            break;
        }
        ent.clear();
        ent.append(next);
    }
    if !r.signed && !r.encrypted { return mail::ERR_FORMAT; }
    r.entity.append(ent);
    r.message.append(outer);
    r.message.append(ent);
    return mail::OK;
}

// A received message (or entity) read: every S/MIME layer decrypted with
// key, whose certificate is cert, and verified, outermost first. What was
// found goes in r; returns OK, or the first error (ERR_FORMAT if there is
// no S/MIME at all), r then holding what was found before it.
fn open(msg: const u8[:], key: const x509::PrivateKey&, cert: const x509::Cert&, r: Opened&) -> i64 {
    return open_with(msg, key, cert, true, r);
}

// open for a message only signed: an encrypted layer is ERR_KEY.
fn verify(msg: const u8[:], r: Opened&) -> i64 {
    let k = x509::empty_key();
    let c = x509::empty_cert();
    return open_with(msg, k, c, false, r);
}

// --- The signer --------------------------------------------------------------------

// A certificate's email addresses: its rfc822Name subject alternative
// names, or, when it has none, its subject's emailAddress attributes
// (RFC 8550 §3).
fn cert_addresses(c: const x509::Cert&) -> u8[][>..] {
    var out: u8[][>..] = [];
    if c.has_san {
        let ns, ok = asn1::children(c.der, c.san);
        for n in ns {
            if n.tag == asn1::ctx(1, false) {
                var s: u8[>..] = [];
                s.append(c.der[n.off..n.end]);
                out.push(copy(s));
            }
        }
    }
    if out.len == 0 { out = x509::name_values(c.der, c.subject, "1.2.840.113549.1.9.1"); }
    return out;
}

// Whether one of the certificate's addresses is addr ("user@host" or
// "Name <user@host>"): the domain compared without case, the local part
// as it is.
fn has_address(c: const x509::Cert&, addr: const u8[:]) -> bool {
    let a, rc = mail::parse_address(addr);
    if rc != mail::OK { return false; }
    for s in cert_addresses(c) { if mail::msg_same_addr(s, a.addr) { return true; } }
    return false;
}

// The signer's certificate checked: a path through the certificates sent
// with it to one of roots, valid at now (seconds since 1970), for email
// protection, and a key usage that allows signing. x509's error, or OK.
fn check_path(r: const Opened&, roots: const x509::CertPool&, now: i64) -> i64 {
    if !r.signed { return x509::ERR_MALFORMED; }
    let inters, ok = x509::pool_of(r.certs);
    if !ok { return x509::ERR_MALFORMED; }
    var opts = x509::options();
    opts.key_usages = x509::EKU_EMAIL_PROTECTION;
    let e = x509::verify_pools(r.signer.der, inters, roots, "", now, "", opts);
    if e != x509::OK { return e; }
    if r.signer.has_key_usage && r.signer.key_usage & (x509::KU_DIGITAL_SIGNATURE | x509::KU_NON_REPUDIATION) == 0 {
        return x509::ERR_KEY_USAGE;
    }
    return x509::OK;
}

// check_path, and that `from` (the From address; "" for no check) is one
// of the signer's addresses: OK, ERR_SIGNATURE when not signed, or
// ERR_CERT.
fn check_signer(r: const Opened&, roots: const x509::CertPool&, now: i64, from: const u8[:]) -> i64 {
    if !r.signed { return mail::ERR_SIGNATURE; }
    if check_path(r, roots, now) != x509::OK { return mail::ERR_CERT; }
    if from.len > 0 && !has_address(r.signer, from) { return mail::ERR_CERT; }
    return mail::OK;
}
