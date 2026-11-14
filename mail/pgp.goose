// mail.pgp: PGP/MIME (RFC 3156), messages signed, encrypted or both, and
// read back, over crypto.openpgp.
//
//     var kr = openpgp::Keyring { .. };              // keys, secret ones unlocked
//     let o = pgp::Options { .. };
//     var out: u8[>..] = [];
//     var rc = pgp::sign(m, kr, signer, o, out);      // multipart/signed
//     rc = pgp::encrypt(m, kr, recipients, o, out);   // multipart/encrypted
//     rc = pgp::sign_encrypt(m, kr, signer, recipients, o, out);
//
//     var r = pgp::Opened { .. };                     // a root struct: a local
//     let rc2 = pgp::open(received, kr, "", r);       // every layer, decrypted and verified
//     // r.entity is the MIME entity inside, r.signer the signing key's index
//
// Each of sign, encrypt and sign_encrypt takes a mail::Msg, which it
// writes, or a message already written (RFC 5322, CRLF or LF lines). The
// header fields that are not Content-* (Date, From, To, Subject,
// Message-ID, MIME-Version, ...) stay outside, as they were; the Content-*
// fields and the body become the entity that is protected. sign_entity
// and encrypt_entity protect an entity alone (its Content-* fields, a
// blank line, its body) and give the entity that replaces it.
//
// Signing makes multipart/signed; protocol="application/pgp-signature";
// micalg=pgp-sha256 (RFC 3156 §5): a detached OpenPGP signature over the
// entity as sent, with CRLF line ends, so it must be 7bit (a Msg with
// ENC_8BIT is refused: set quoted-printable or base64). Encrypting makes
// multipart/encrypted; protocol="application/pgp-encrypted" (§4): the
// "Version: 1" part, then the armored message as application/octet-
// stream. sign_encrypt signs and encrypts in one OpenPGP message, RFC
// 3156 §6.2's combined form, as Thunderbird and gpg's mail clients do.
// The keys are crypto.openpgp's: a signer and recipients are indices into
// the keyring (primary keys, which pick their signing and encryption
// subkeys), as openpgp::find_key gives them.
//
// Reading, open goes through the layers as it finds them, decrypting with
// the keyring's unlocked secret keys (or the passphrase) and verifying
// signatures, until an entity that is neither: it returns that entity,
// whether it was signed and encrypted, and the signing key. It reads both
// forms of signed and encrypted mail: the combined one and multipart/
// signed inside multipart/encrypted (§6.1). The signing key is whatever
// the keyring says it is; whether it belongs to the From address is the
// caller's to decide.
//
// Errors: ERR_SIGNATURE (a signature that does not verify, or none where
// one should be), ERR_DECRYPT (not encrypted to a key here, a wrong
// passphrase, changed ciphertext), ERR_KEY (no key here for the signer,
// a recipient or signer that cannot be used, a locked secret key),
// ERR_FORMAT (malformed MIME or OpenPGP, a body to sign that is not
// 7bit, or no PGP/MIME at all), ERR_UNSUPPORTED (an algorithm openpgp
// does not have), ERR_ARG.

namespace pgp;

import std;
import mime;
import crypto.bignum;
import crypto.bignum.entropy;
import crypto.openpgp;
import crypto.openpgp.armor;
import crypto.openpgp.packet;
import crypto.openpgp.key;
import crypto.openpgp.sig;
import crypto.openpgp.keyring;
import crypto.openpgp.message;
import mail;
import mail.address;
import mail.message;

// How the functions here sign and encrypt; Options { .. } is the default.
struct Options {
    hash:        i64      = openpgp::HASH_SHA256,    // micalg=pgp-sha256; or HASH_SHA384, HASH_SHA512
    cipher:      i64      = openpgp::CIPHER_AES256,
    compression: i64      = openpgp::COMP_NONE,      // of the encrypted message
    created:     i64      = 0,                       // the signature's time, seconds since 1970: 0 now
    boundary:    u8[..70] = [],                      // the multipart boundary; random if empty
}

// What open found (a root struct: it lives in a local or a global).
root struct Opened {
    entity:     u8[>..]  = [],       // the entity inside: Content-* fields, a blank line, the body
    message:    u8[>..]  = [],       // the message's other header fields, then entity
    signed:     bool     = false,
    encrypted:  bool     = false,
    signer:     i64      = -1,       // the signing key's index in the keyring, when signed
    signer_fpr: u8[..32] = [],
    signed_at:  i64      = 0,
    pgp_error:  i64      = 0,        // openpgp's error behind a failure, if one was
}

// --- Text ----------------------------------------------------------------------

// s with each bare LF made CRLF, appended to out.
fn crlf(out: u8[>..]&, s: const u8[:]) {
    for i in s.len {
        if s[i] == '\n' && (i == 0 || s[i - 1] != '\r') { out.push('\r'); }
        out.push(s[i]);
    }
}

fn is_7bit(s: const u8[:]) -> bool {
    for i in s.len {
        let c = s[i];
        if c == 0 || c >= 0x80 { return false; }
        if c == '\r' && (i + 1 >= s.len || s[i + 1] != '\n') { return false; }
        if c == '\n' && (i == 0 || s[i - 1] != '\r') { return false; }
    }
    return true;
}

// Where an entity's header ends (its blank line's CRLF CRLF, or the end)
// and its body starts.
fn split_entity(e: const u8[:]) -> i64, i64 {
    if starts_with(e, "\r\n") { return 0, 2; }
    let at = find(e, "\r\n\r\n");
    if at < 0 { return e.len, e.len; }
    return at + 2, at + 4;
}

// The end of the header field at h[at..] (its CRLF included, its folded
// lines too).
fn next_field(h: const u8[:], at: i64) -> i64 {
    var p = at;
    loop {
        let nl = find(h[p..], "\r\n");
        if nl < 0 { return h.len; }
        p += nl + 2;
        if p >= h.len || (h[p] != ' ' && h[p] != '\t') { return p; }
    }
    return p;
}

fn field_name(f: const u8[:]) -> const u8[:] {
    let c = find(f, ":");
    if c < 0 { return ""; }
    var e = c;
    while e > 0 && (f[e - 1] == ' ' || f[e - 1] == '\t') { e--; }
    return f[..e];
}

// A field's value, unfolded, white space at its ends gone.
fn field_value(f: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let c = find(f, ":");
    if c < 0 { return out; }
    for b in f[c + 1..] {
        if b == '\r' || b == '\n' { continue; }
        if out.len == 0 && (b == ' ' || b == '\t') { continue; }
        out.push(b);
    }
    while out.len > 0 && (out[out.len - 1] == ' ' || out[out.len - 1] == '\t') { out.resize(out.len - 1); }
    return out;
}

// The value of the first field of that name in a header.
fn header_get(h: const u8[:], name: const u8[:]) -> u8[>..], bool {
    var at = 0;
    while at < h.len {
        let end = next_field(h, at);
        let f = h[at..end];
        if mail::eq_fold(field_name(f), name) { return field_value(f), true; }
        at = end;
    }
    var none: u8[>..] = [];
    return none, false;
}

fn is_content_field(name: const u8[:]) -> bool { name.len > 8 && mail::eq_fold(name[..8], "Content-") }

// A message (CRLF lines) split in two: the fields that stay outside, and
// the entity: the Content-* fields, a blank line, the body.
fn split_message(m: const u8[:], outer: u8[>..]&, inner: u8[>..]&) {
    let hend, body = split_entity(m);
    let h = m[..hend];
    var at = 0;
    while at < h.len {
        let end = next_field(h, at);
        let f = h[at..end];
        if is_content_field(field_name(f)) { inner.append(f); } else { outer.append(f); }
        at = end;
    }
    inner.append("\r\n");
    inner.append(m[body..]);
}

// --- Errors ---------------------------------------------------------------------

// openpgp's error as mail's: while reading a signature (sig) or decrypting.
fn mail_error(e: i64, sig: bool) -> i64 {
    if e == openpgp::OK { return mail::OK; }
    if e == openpgp::ERR_MALFORMED || e == openpgp::ERR_CHECKSUM || e == openpgp::ERR_LIMIT { return mail::ERR_FORMAT; }
    if e == openpgp::ERR_UNSUPPORTED { return mail::ERR_UNSUPPORTED; }
    if e == openpgp::ERR_BAD_SIGNATURE || e == openpgp::ERR_NO_SIGNATURE { return mail::ERR_SIGNATURE; }
    if e == openpgp::ERR_KEY || e == openpgp::ERR_REVOKED || e == openpgp::ERR_EXPIRED { return mail::ERR_KEY; }
    if e == openpgp::ERR_NO_KEY { return if sig { mail::ERR_KEY } else { mail::ERR_DECRYPT }; }
    if e == openpgp::ERR_PASSPHRASE && sig { return mail::ERR_KEY; }
    return mail::ERR_DECRYPT;
}

// --- Writing ---------------------------------------------------------------------

fn boundary_ok(b: const u8[:]) -> bool {
    if b.len < 1 || b.len > 70 || b[b.len - 1] == ' ' { return false; }
    for c in b {
        let ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                 || c == '\'' || c == '(' || c == ')' || c == '+' || c == '_' || c == ',' || c == '-'
                 || c == '.' || c == '/' || c == ':' || c == '=' || c == '?' || c == ' ';
        if !ok { return false; }
    }
    return true;
}

// The boundary: the options', or 24 random bytes in hex; one that the
// entity holds is refused (a random one is drawn again).
fn make_boundary(o: Options, entity: const u8[:]) -> u8[>..], bool {
    var b: u8[>..] = [];
    if o.boundary.len > 0 {
        b.append(o.boundary);
        return b, boundary_ok(b) && find(entity, b) < 0;
    }
    loop {
        b.clear();
        var r: u8[24] = [0; 24];
        bignum::random_bytes(r);
        b.append("pgp-");
        openpgp::hex_append(b, r, false);
        if find(entity, b) < 0 { return b, true; }
    }
    return b, false;
}

fn write_opts(o: Options) -> openpgp::WriteOptions {
    var w = openpgp::WriteOptions { .. };
    w.hash = o.hash;
    w.cipher = o.cipher;
    w.compression = o.compression;
    w.created = o.created;
    w.armored = true;
    return w;
}

// The micalg of a hash: "pgp-" and its name, lower case (RFC 3156 §5).
fn micalg(hash: i64) -> u8[>..] {
    var m: u8[>..] = [];
    m.append("pgp-");
    for c in openpgp::hash_name(hash) { m.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); }
    return m;
}

// The entity signed: multipart/signed, the entity then its signature.
fn sign_entity(entity: const u8[:], kr: const openpgp::Keyring&, signer: i64, o: Options, out: u8[>..]&) -> i64 {
    var e: u8[>..] = [];
    crlf(e, entity);
    if !is_7bit(e) { return mail::ERR_FORMAT; }
    let b, okb = make_boundary(o, e);
    if !okb { return mail::ERR_ARG; }
    var sig: u8[>..] = [];
    let rc = openpgp::sign_detached(kr, signer, e, sig, write_opts(o));
    if rc != openpgp::OK { return mail_error(rc, true); }
    // micalg names the hash used, which a key may have made longer.
    let idx, er = openpgp::resolve_signer(kr, signer);
    let hash = openpgp::signing_hash(kr.keys[idx], o.hash);
    out.append("Content-Type: multipart/signed; boundary=\"");
    out.append(b);
    out.append("\"; micalg=");
    out.append(micalg(hash));
    out.append(";\r\n protocol=\"application/pgp-signature\"\r\n\r\n");
    out.append("This is an OpenPGP/MIME signed message (RFC 4880 and 3156)\r\n--");
    out.append(b);
    out.append("\r\n");
    out.append(e);
    out.append("\r\n--");
    out.append(b);
    out.append("\r\nContent-Type: application/pgp-signature; name=\"signature.asc\"\r\n");
    out.append("Content-Description: OpenPGP digital signature\r\n");
    out.append("Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n");
    crlf(out, sig);
    out.append("\r\n--");
    out.append(b);
    out.append("--\r\n");
    return mail::OK;
}

// The entity encrypted to the recipients (primary keys of the keyring),
// signed in the same OpenPGP message by signer unless it is -1:
// multipart/encrypted.
fn encrypt_entity(entity: const u8[:], kr: const openpgp::Keyring&, recipients: const i64[:], signer: i64,
                  o: Options, out: u8[>..]&) -> i64 {
    if recipients.len == 0 { return mail::ERR_ARG; }
    var e: u8[>..] = [];
    crlf(e, entity);
    var msg: u8[>..] = [];
    let rc = openpgp::encrypt(kr, recipients, "", e, msg, write_opts(o), signer);
    if rc != openpgp::OK { return mail_error(rc, true); }
    let b, okb = make_boundary(o, "");
    if !okb { return mail::ERR_ARG; }
    out.append("Content-Type: multipart/encrypted; boundary=\"");
    out.append(b);
    out.append("\";\r\n protocol=\"application/pgp-encrypted\"\r\n\r\n");
    out.append("This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n--");
    out.append(b);
    out.append("\r\nContent-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\n");
    out.append("Version: 1\r\n\r\n--");
    out.append(b);
    out.append("\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n");
    out.append("Content-Description: OpenPGP encrypted message\r\n");
    out.append("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n");
    crlf(out, msg);
    out.append("\r\n--");
    out.append(b);
    out.append("--\r\n");
    return mail::OK;
}

let DO_SIGN:         i64 = 0;
let DO_ENCRYPT:      i64 = 1;
let DO_SIGN_ENCRYPT: i64 = 2;

// A message with its entity protected: the fields that are not Content-*
// as they were (MIME-Version added if missing), then the new entity.
fn protect(msg: const u8[:], what: i64, kr: const openpgp::Keyring&, signer: i64, recipients: const i64[:],
           o: Options, out: u8[>..]&) -> i64 {
    var m: u8[>..] = [];
    crlf(m, msg);
    var outer: u8[>..] = [];
    var inner: u8[>..] = [];
    split_message(m, outer, inner);
    var ent: u8[>..] = [];
    var rc = mail::OK;
    if what == DO_SIGN {
        rc = sign_entity(inner, kr, signer, o, ent);
    } else {
        rc = encrypt_entity(inner, kr, recipients, if what == DO_SIGN_ENCRYPT { signer } else { -1 }, o, ent);
    }
    if rc != mail::OK { return rc; }
    out.append(outer);
    let mv, has = header_get(outer, "MIME-Version");
    if !has { out.append("MIME-Version: 1.0\r\n"); }
    out.append(ent);
    return mail::OK;
}

// The message written, for signing: refused (ERR_ARG) with 8bit bodies,
// which multipart/signed cannot carry unchanged.
fn write_msg(m: mail::Msg&, out: u8[>..]&, seven_bit: bool) -> i64 {
    if seven_bit && m.encoding == mail::ENC_8BIT { return mail::ERR_ARG; }
    return mail::write(m, out);
}

// The message signed: multipart/signed, the header outside.
fn sign(msg: const u8[:], kr: const openpgp::Keyring&, signer: i64, o: Options, out: u8[>..]&) -> i64 {
    var none: i64[0] = [];
    return protect(msg, DO_SIGN, kr, signer, none, o, out);
}

fn sign(m: mail::Msg&, kr: const openpgp::Keyring&, signer: i64, o: Options, out: u8[>..]&) -> i64 {
    var raw: u8[>..] = [];
    let rc = write_msg(m, raw, true);
    if rc != mail::OK { return rc; }
    return sign(raw, kr, signer, o, out);
}

// The message encrypted to the recipients: multipart/encrypted.
fn encrypt(msg: const u8[:], kr: const openpgp::Keyring&, recipients: const i64[:], o: Options,
           out: u8[>..]&) -> i64 {
    return protect(msg, DO_ENCRYPT, kr, -1, recipients, o, out);
}

fn encrypt(m: mail::Msg&, kr: const openpgp::Keyring&, recipients: const i64[:], o: Options,
           out: u8[>..]&) -> i64 {
    var raw: u8[>..] = [];
    let rc = write_msg(m, raw, false);
    if rc != mail::OK { return rc; }
    return encrypt(raw, kr, recipients, o, out);
}

// The message signed and encrypted (RFC 3156 §6.2, one OpenPGP message).
fn sign_encrypt(msg: const u8[:], kr: const openpgp::Keyring&, signer: i64, recipients: const i64[:],
                o: Options, out: u8[>..]&) -> i64 {
    if signer < 0 { return mail::ERR_ARG; }
    return protect(msg, DO_SIGN_ENCRYPT, kr, signer, recipients, o, out);
}

fn sign_encrypt(m: mail::Msg&, kr: const openpgp::Keyring&, signer: i64, recipients: const i64[:],
                o: Options, out: u8[>..]&) -> i64 {
    var raw: u8[>..] = [];
    let rc = write_msg(m, raw, false);
    if rc != mail::OK { return rc; }
    return sign_encrypt(raw, kr, signer, recipients, o, out);
}

// --- Reading ---------------------------------------------------------------------

// A multipart body's parts, as [start, end) pairs: what lies between each
// delimiter line and the CRLF before the next (RFC 2046 §5.1.1).
fn parts_of(body: const u8[:], boundary: const u8[:], spans: i64[>..]&) -> bool {
    var delim: u8[>..] = [];
    delim.append("--");
    delim.append(boundary);
    var at = 0;
    var start: i64 = -1;
    while at <= body.len {
        // A delimiter starts a line: at the body's start or after CRLF.
        var hit = -1;
        var p = at;
        loop {
            let i = find(body[p..], delim);
            if i < 0 { break; }
            let q = p + i;
            if q == 0 || (q >= 2 && body[q - 2] == '\r' && body[q - 1] == '\n') { hit = q; break; }
            p = q + 1;
        }
        if hit < 0 { return false; }
        if start >= 0 {
            let end = if hit >= 2 { hit - 2 } else { 0 };
            if end < start { return false; }
            spans.push(start);
            spans.push(end);
        }
        let after = hit + delim.len;
        if after + 2 <= body.len && body[after..after + 2] == "--" { return spans.len > 0; }
        let nl = find(body[after..], "\r\n");
        if nl < 0 { return false; }
        start = after + nl + 2;
        at = start;
    }
    return false;
}

// The media type (lower case) and boundary and protocol parameters of an
// entity's Content-Type.
fn content_type(h: const u8[:]) -> u8[>..], u8[>..], u8[>..] {
    var t: u8[>..] = [];
    var b: u8[>..] = [];
    var p: u8[>..] = [];
    let v, has = header_get(h, "Content-Type");
    if !has { t.append("text/plain"); return t, b, p; }
    let mt = mime::parse_media_type(v);
    t.append(mt.typ);
    let bv, hb = mime::param(mt, "boundary");
    b.append(bv);
    let pv, hp = mime::param(mt, "protocol");
    for c in pv { p.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); }
    return t, b, p;
}

// The entity of one layer read: its next entity into next.
fn open_layer(ent: const u8[:], kr: const openpgp::Keyring&, pass: const u8[:], r: Opened&, next: u8[>..]&) -> bool, i64 {
    let hend, bstart = split_entity(ent);
    let h = ent[..hend];
    let body = ent[bstart..];
    let t, b, proto = content_type(h);
    if t[..] == "multipart/signed" && proto[..] == "application/pgp-signature" {
        var spans: i64[>..] = [];
        if b.len == 0 || !parts_of(body, b, spans) || spans.len != 4 { return false, mail::ERR_FORMAT; }
        let signed = body[spans[0]..spans[1]];
        let sigpart = body[spans[2]..spans[3]];
        let sh, sb = split_entity(sigpart);
        var m = openpgp::Message { .. };
        let e = openpgp::verify_detached(kr, signed, sigpart[sb..], m);
        r.pgp_error = e;
        if e != openpgp::OK { return false, mail_error(e, true); }
        for s in m.sigs {
            if s.err == openpgp::OK {
                r.signer = s.key;
                r.signer_fpr.clear();
                r.signer_fpr.append(kr.keys[s.key].fpr);
                r.signed_at = s.created;
                break;
            }
        }
        r.signed = true;
        next.append(signed);
        return true, mail::OK;
    }
    if t[..] == "multipart/encrypted" && proto[..] == "application/pgp-encrypted" {
        var spans: i64[>..] = [];
        if b.len == 0 || !parts_of(body, b, spans) || spans.len != 4 { return false, mail::ERR_FORMAT; }
        let vpart = body[spans[0]..spans[1]];
        let vh, vb = split_entity(vpart);
        let vt, x1, x2 = content_type(vpart[..vh]);
        if vt[..] != "application/pgp-encrypted" || find(vpart[vb..], "Version: 1") < 0 { return false, mail::ERR_FORMAT; }
        let cpart = body[spans[2]..spans[3]];
        let ch, cb = split_entity(cpart);
        var m = openpgp::Message { .. };
        var o = openpgp::ReadOptions { .. };
        o.passphrase.append(pass[.. ::min(pass.len, 256)]);
        let e = openpgp::read_message(kr, cpart[cb..], m, o);
        r.pgp_error = e;
        if e != openpgp::OK { return false, mail_error(e, false); }
        if !m.encrypted { return false, mail::ERR_FORMAT; }
        r.encrypted = true;
        if m.sigs.len > 0 {
            let st = openpgp::signature_status(m);
            if st != openpgp::OK { r.pgp_error = st; return false, mail_error(st, true); }
            for s in m.sigs {
                if s.err == openpgp::OK {
                    r.signer = s.key;
                    r.signer_fpr.clear();
                    r.signer_fpr.append(kr.keys[s.key].fpr);
                    r.signed_at = s.created;
                    break;
                }
            }
            r.signed = true;
        }
        crlf(next, m.data);
        return true, mail::OK;
    }
    return false, mail::OK;
}

// Opens a message received (CRLF or LF lines): each PGP/MIME layer
// decrypted (with the keyring's unlocked keys, or pass) and verified,
// until an entity that is neither. ERR_FORMAT if the message is not
// PGP/MIME at all.
fn open(msg: const u8[:], kr: const openpgp::Keyring&, pass: const u8[:], r: Opened&) -> i64 {
    var m: u8[>..] = [];
    crlf(m, msg);
    var outer: u8[>..] = [];
    var cur:   u8[>..] = [];
    split_message(m, outer, cur);
    var next: u8[>..] = [];
    var layers = 0;
    loop {
        next.clear();
        let more, rc = open_layer(cur, kr, pass, r, next);
        if rc != mail::OK { return rc; }
        if !more { break; }
        layers++;
        if layers > 4 { return mail::ERR_FORMAT; }
        cur.clear();
        cur.append(next);
    }
    if layers == 0 { return mail::ERR_FORMAT; }
    r.entity.append(cur);
    r.message.append(outer);
    r.message.append(cur);
    return mail::OK;
}

// open, failing with ERR_SIGNATURE unless the message was signed.
fn verify(msg: const u8[:], kr: const openpgp::Keyring&, r: Opened&) -> i64 {
    let rc = open(msg, kr, "", r);
    if rc != mail::OK { return rc; }
    return if r.signed { mail::OK } else { mail::ERR_SIGNATURE };
}

// open, failing with ERR_DECRYPT unless the message was encrypted.
fn decrypt(msg: const u8[:], kr: const openpgp::Keyring&, pass: const u8[:], r: Opened&) -> i64 {
    let rc = open(msg, kr, pass, r);
    if rc != mail::OK { return rc; }
    return if r.encrypted { mail::OK } else { mail::ERR_DECRYPT };
}
