// openpgp.message: OpenPGP messages (RFC 9580 §10.3): signing (inline,
// detached and cleartext), verifying, encrypting to public keys and
// passphrases, and decrypting, with literal and compressed data.
//
//   var w = openpgp::WriteOptions { .. };
//   var out: u8[>..] = [];
//   openpgp::sign_detached(kr, signer, data, out, w);       // armored by default
//   openpgp::encrypt(kr, [bob], "", data, out, w, signer);  // sign, then encrypt
//
//   var m = openpgp::Message { .. };
//   let err = openpgp::read_message(kr, input, m, openpgp::ReadOptions { .. });
//   // m.data: the literal data; m.sigs: each signature's result
//   let err = openpgp::verify_detached(kr, data, sig, m);
//   let err = openpgp::verify_cleartext(kr, text, m);
//
// What is read:
// - public-key encrypted session keys (PKESK v3) for RSA, ECDH (Curve25519
//   and the NIST curves) and X25519; passphrase ones (SKESK v4);
// - SEIPD v1 (CFB with the MDC), and gpg's OCB-encrypted data (LibrePGP's
//   packet 20, which gpg 2.3 and later write for keys that advertise it);
//   data with no integrity protection (packet 9) only when the options
//   allow it;
// - compressed data: ZIP, ZLIB and BZip2, within a size limit;
// - signed messages, one-pass or not, binary or text, by RSA, Ed25519 (both
//   forms) and ECDSA keys.
//
// What is written: PKESK v3, SKESK v4, SEIPD v1 with the MDC (which every
// OpenPGP implementation reads), one-pass signed messages, compressed with
// ZIP, ZLIB or BZip2 if asked; signatures v4 (v6 for v6 keys).

namespace openpgp;

import std;
import base64;
import compress;
import compress.flate;
import compress.deflate;
import compress.zlib;
import compress.bzip2;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.sha1;
import crypto.bignum.hmac;
import crypto.openpgp;
import crypto.openpgp.armor;
import crypto.openpgp.packet;
import crypto.openpgp.ocb;
import crypto.openpgp.key;
import crypto.openpgp.sig;
import crypto.openpgp.keyring;

let INTEGRITY_NONE: i64 = 0;
let INTEGRITY_MDC:  i64 = 1;
let INTEGRITY_AEAD: i64 = 2;

let MAX_DEPTH:   i64 = 8;            // layers of encryption and compression
let MAX_PACKETS: i64 = 4096;         // packets in one layer

// One signature of a message and how it checked out.
struct SigResult {
    err:     i64      = ERR_NO_KEY,  // OK when it verifies
    key:     i64      = -1,          // the signing key's index in the keyring, -1 if not there
    keyid:   u8[8]    = [0; 8],
    fpr:     u8[..32] = [],          // the issuer fingerprint, when the signature names it
    sigtype: i64      = 0,
    hash:    i64      = 0,
    pk_algo: i64      = 0,
    created: i64      = 0,
}

root struct Message {
    data:           u8[>..]        = [], // the literal data
    filename:       u8[..255]      = [],
    format:         u8             = 'b',
    mtime:          i64            = 0,
    encrypted:      bool           = false,
    integrity:      i64            = INTEGRITY_NONE,
    cipher:         i64            = 0,
    aead:           i64            = 0,
    decrypted_with: i64            = -1, // the key that opened it, -1 for a passphrase or none
    compression:    i64            = COMP_NONE,
    sigs:           SigResult[>..] = [],
    sig_packets:    u8[>..]        = [], // the signature packets, for checking
}

struct ReadOptions {
    passphrase:        u8[..256] = [],
    allow_unprotected: bool      = false,   // decrypt packet 9 (no MDC), as gpg does only when told to
    max_size:          i64       = 1 << 30, // of decompressed data
    now:               i64       = 0,       // the time keys must be valid at; 0 is each signature's time
}

struct WriteOptions {
    hash:        i64       = HASH_SHA256,
    cipher:      i64       = CIPHER_AES256,
    compression: i64       = COMP_NONE,
    level:       i64       = 6,
    armored:     bool      = true,
    text:        bool      = false,  // a text literal ('u') and a text signature (0x01)
    filename:    u8[..255] = [],
    mtime:       i64       = 0,
    created:     i64       = 0,      // the signature's time; 0 is now
    s2k_coded:   i64       = 255,    // SKESK's iteration count, coded
}

fn signature_status(m: const Message&) -> i64 {
    if m.sigs.len == 0 { return ERR_NO_SIGNATURE; }
    for r in m.sigs { if r.err == OK { return OK; } }
    return m.sigs[0].err;
}

// --- Checking signatures -----------------------------------------------------------

// The data a document signature hashes: as it is (binary) or with CRLF line
// ends (text).
fn sig_data(out: u8[>..]&, sigtype: i64, data: const u8[:]) {
    if sigtype == SIG_TEXT { canonical_text(out, data); } else { out.append(data); }
}

// Checks one signature packet body over data with the keyring's keys.
// lit_meta: what a v5 signature hashes of the literal packet (inline
// messages; empty for detached and cleartext signatures).
fn check_signature(kr: const Keyring&, body: const u8[:], data: const u8[:], canonical: bool, now: i64,
                   lit_meta: const u8[:] = "") -> SigResult {
    var r = SigResult { .. };
    let s, err = parse_signature(body);
    r.sigtype = s.sigtype;
    r.hash = s.hash;
    r.pk_algo = s.pk_algo;
    r.created = s.created;
    r.keyid = s.issuer;
    r.fpr.append(s.issuer_fpr);
    if s.version >= 5 && s.issuer_fpr.len >= 8 { for i in 8 { r.keyid[i] = s.issuer_fpr[i]; } }
    if err != OK { r.err = err; return r; }
    if s.sigtype != SIG_BINARY && s.sigtype != SIG_TEXT { r.err = ERR_UNSUPPORTED; return r; }
    var idx = -1;
    if s.issuer_fpr.len > 0 { idx = key_by_fpr(kr, s.issuer_fpr); }
    if idx < 0 && s.has_issuer { idx = key_by_id(kr, s.issuer); }
    if idx < 0 { r.err = ERR_NO_KEY; return r; }
    r.key = idx;
    let k = kr.keys[idx];
    var input: u8[>..] = [];
    if canonical { input.append(data); } else { sig_data(input, s.sigtype, data); }
    let e = verify_signature(k, s, input, lit_meta);
    if e != OK { r.err = e; return r; }
    // The key, at the signature's time: bound, not revoked or expired,
    // allowed to sign.
    let t = if now > 0 { now } else { s.created };
    if k.revoked || kr.keys[k.primary].revoked { r.err = ERR_REVOKED; return r; }
    if !k.valid || !kr.keys[k.primary].valid { r.err = ERR_KEY; return r; }
    if s.expires > 0 && now > 0 && s.created + s.expires <= now { r.err = ERR_EXPIRED; return r; }
    if !usable(kr, idx, FLAG_SIGN, t) {
        let pk = kr.keys[k.primary];
        let expired = (k.expires > 0 && k.created + k.expires <= t) || (pk.expires > 0 && pk.created + pk.expires <= t);
        r.err = if expired { ERR_EXPIRED } else { ERR_KEY };
        return r;
    }
    r.err = OK;
    return r;
}

// Checks every signature packet in m.sig_packets over m.data; inline when
// m's literal packet was read with them (v5 signatures hash its header).
fn check_signatures(kr: const Keyring&, m: Message&, now: i64, inline: bool = false) {
    var meta: u8[>..] = [];
    if inline { meta = literal_meta(m.format, m.filename, m.mtime); }
    var at = 0;
    while at < m.sig_packets.len {
        let p, err = next_packet(m.sig_packets, at);
        if err != OK { break; }
        let r = check_signature(kr, m.sig_packets[p.body..p.body_end], m.data, false, now, meta);
        m.sigs.push(r);
        at = p.end;
    }
}

// --- Decrypting -------------------------------------------------------------------

// A session key found: its cipher, the key, and whether a passphrase gave it.
struct Session { cipher: i64 = 0, key: u8[..32] = [], from_pass: bool = false, by: i64 = -1 }

// The session key of a PKESK, if a secret key of the keyring opens it.
// v3: key ID, algorithm, fields; v6 (RFC 9580 §5.1.2): the length of the
// key version and fingerprint that follow (0: anyone's), the algorithm,
// fields, and no cipher: SEIPD v2 names it.
fn open_pkesk(kr: const Keyring&, body: const u8[:], ss: Session[>..]&) -> i64 {
    if body.len < 10 { return ERR_MALFORMED; }
    if body[0] != 3 && body[0] != 6 { return ERR_UNSUPPORTED; }
    let v6 = body[0] == 6;
    var at = 9;
    var id = body[1..9];
    if v6 {
        let n: i64 = body[1];
        if n != 0 && n != 21 && n != 33 { return ERR_MALFORMED; }
        if 2 + n >= body.len { return ERR_MALFORMED; }
        id = body[3..2 + n];
        at = 2 + n;
        if n == 0 { id = body[..0]; }
    }
    let algo: i64 = body[at];
    let mat = body[at + 1..];
    let wildcard = id.len == 0 || id == "\x00\x00\x00\x00\x00\x00\x00\x00";
    var result = ERR_NO_KEY;
    for i in kr.keys.len {
        let k = kr.keys[i];
        if !k.has_secret || k.stub { continue; }
        if !wildcard && (if id.len == 8 { k.keyid[..] != id } else { k.fpr[..] != id || k.version != body[2] }) { continue; }
        if k.algo != algo && !(is_rsa(k.algo) && is_rsa(algo)) { continue; }
        if k.locked { result = ERR_PASSPHRASE; continue; }
        var m: u8[>..] = [];
        let e = decrypt_session(k, mat, m, v6);
        if e != OK { if result == ERR_NO_KEY { result = e; } continue; }
        var key:    u8[>..] = [];
        var cipher: i64     = 0;
        var e2 = OK;
        if v6 { e2 = decode_session_v6(m, key, !session_no_checksum(algo)); }
        else {
            let c, ec = decode_session(m, key, !session_no_checksum(algo));
            cipher = c;
            e2 = ec;
        }
        if e2 != OK { if result == ERR_NO_KEY { result = e2; } continue; }
        var s = Session { cipher: cipher, by: i };
        s.key.append(key);
        ss.push(s);
        return OK;
    }
    return result;
}

// The session key of an SKESK v4 and a passphrase.
fn open_skesk(body: const u8[:], pass: const u8[:], ss: Session[>..]&) -> i64 {
    if body.len < 2 { return ERR_MALFORMED; }
    if body[0] != 4 { return ERR_UNSUPPORTED; }
    let cipher: i64 = body[1];
    let ks = cipher_key_size(cipher);
    if ks == 0 { return ERR_UNSUPPORTED; }
    let s2k, at, err = read_s2k(body, 2);
    if err != OK { return err; }
    if s2k.kind == S2K_GNU_DUMMY || s2k.kind == S2K_SIMPLE { return ERR_UNSUPPORTED; }
    let key, e2 = s2k_key(s2k, pass, ks);
    if e2 != OK { return e2; }
    var s = Session { from_pass: true };
    if at == body.len {
        s.cipher = cipher;
        s.key.append(key);
        ss.push(s);
        return OK;
    }
    // An encrypted session key: CFB with a zero IV, its cipher first.
    var esk: u8[>..] = [];
    esk.append(body[at..]);
    var iv: u8[>..] = [];
    iv.resize(cipher_block_size(cipher), 0);
    if !cfb(cipher, key, iv, esk, true) { return ERR_UNSUPPORTED; }
    let c2: i64 = esk[0];
    let ks2 = cipher_key_size(c2);
    if ks2 == 0 || esk.len != 1 + ks2 { return ERR_PASSPHRASE; }
    s.cipher = c2;
    s.key.append(esk[1..]);
    ss.push(s);
    return OK;
}

// SEIPD v1: CFB with a zero IV over a random block, its last two octets
// again, the plaintext and the MDC packet (D3 14 and SHA-1 of everything
// before it). The plaintext is appended to out.
fn open_seipd1(s: const Session&, ct: const u8[:], out: u8[>..]&) -> i64 {
    let bs = cipher_block_size(s.cipher);
    if ct.len < bs + 2 + 22 { return ERR_MALFORMED; }
    var buf: u8[>..] = [];
    buf.append(ct);
    var iv: u8[>..] = [];
    iv.resize(bs, 0);
    if !cfb(s.cipher, s.key, iv, buf, true) { return ERR_UNSUPPORTED; }
    // The quick check tells a wrong passphrase from changed data.
    if s.from_pass && (buf[bs] != buf[bs - 2] || buf[bs + 1] != buf[bs - 1]) { return ERR_PASSPHRASE; }
    let n = buf.len;
    let h = bignum::sha1(buf[..n - 20]);
    let tag_ok = buf[n - 22] == 0xD3 && buf[n - 21] == 0x14;
    if bignum::ct_eq_bytes(h, buf[n - 20..]) != 1 || !tag_ok { return ERR_INTEGRITY; }
    out.append(buf[bs + 2..n - 22]);
    return OK;
}

// Packet 9: OpenPGP's CFB with the resynchronization, no integrity.
fn open_sed(s: const Session&, ct: const u8[:], out: u8[>..]&) -> i64 {
    let bs = cipher_block_size(s.cipher);
    if ct.len < bs + 2 { return ERR_MALFORMED; }
    var head: u8[>..] = [];
    head.append(ct[..bs + 2]);
    var iv: u8[>..] = [];
    iv.resize(bs, 0);
    if !cfb(s.cipher, s.key, iv, head, true) { return ERR_UNSUPPORTED; }
    if s.from_pass && (head[bs] != head[bs - 2] || head[bs + 1] != head[bs - 1]) { return ERR_PASSPHRASE; }
    var rest: u8[>..] = [];
    rest.append(ct[bs + 2..]);
    let ok = cfb(s.cipher, s.key, ct[2..bs + 2], rest, true);
    out.append(rest);
    return OK;
}

fn put_index(ad: u8[>..]&, v: i64) { put64(ad, v); }

// AEAD-encrypted data in chunks: LibrePGP's packet 20 (v2 false: the
// nonce is the IV XOR the chunk index, the index in the associated data)
// or RFC 9580's SEIPD v2 (the nonce is the IV and the index; the
// associated data is the header alone). hdr is the packet's first five
// octets as the associated data takes them.
fn open_chunks(key: const u8[:], iv: const u8[:], hdr: const u8[:], chunk: i64, ct: const u8[:], v2: bool,
               out: u8[>..]&) -> i64 {
    if ct.len < 16 { return ERR_MALFORMED; }
    let o = ocb_init(key);
    let n = ct.len - 16;
    var pos = 0;
    var index: i64 = 0;
    var total: i64 = 0;
    let mark = out.len;
    var nonce: u8[15] = [0; 15];
    while pos < n {
        let clen = ::min(chunk, n - pos - 16);
        if clen < 0 { out.resize(mark); return ERR_MALFORMED; }
        var ad: u8[>..] = [];
        ad.append(hdr);
        if !v2 { put_index(ad, index); }
        var idx: u8[>..] = [];
        put_index(idx, index);
        for i in 15 { nonce[i] = if i < iv.len { iv[i] } else { 0 }; }
        if v2 { for i in 8 { nonce[7 + i] = idx[i]; } } else { for i in 8 { nonce[7 + i] ^= idx[i]; } }
        let start = out.len;
        out.append(ct[pos..pos + clen]);
        if !ocb_decrypt(o, nonce[..iv.len + (if v2 { 8 } else { 0 })], ad, out[start..], ct[pos + clen..pos + clen + 16]) {
            out.resize(mark);
            return ERR_INTEGRITY;
        }
        total += clen;
        pos += clen + 16;
        index++;
    }
    var ad: u8[>..] = [];
    ad.append(hdr);
    if !v2 { put_index(ad, index); }
    put_index(ad, total);
    var idx: u8[>..] = [];
    put_index(idx, index);
    for i in 15 { nonce[i] = if i < iv.len { iv[i] } else { 0 }; }
    if v2 { for i in 8 { nonce[7 + i] = idx[i]; } } else { for i in 8 { nonce[7 + i] ^= idx[i]; } }
    var empty: u8[0] = [];
    if !ocb_decrypt(o, nonce[..iv.len + (if v2 { 8 } else { 0 })], ad, empty, ct[n..]) {
        out.resize(mark);
        return ERR_INTEGRITY;
    }
    return OK;
}

// LibrePGP's OCB Encrypted Data packet (20), version 1.
fn open_aead20(s: const Session&, body: const u8[:], out: u8[>..]&) -> i64 {
    if body.len < 4 + 15 + 16 { return ERR_MALFORMED; }
    if body[0] != 1 { return ERR_UNSUPPORTED; }
    let cipher: i64 = body[1];
    let mode:   i64 = body[2];
    let c:      i64 = body[3];
    if mode != AEAD_OCB || !is_aes(cipher) || c > 16 { return ERR_UNSUPPORTED; }
    if cipher != s.cipher || s.key.len != cipher_key_size(cipher) { return ERR_DECRYPT; }
    let hdr: u8[5] = [0xD4, 1, cipher as! u8, mode as! u8, c as! u8];
    return open_chunks(s.key, body[4..19], hdr, 1 << (c + 6), body[19..], false, out);
}

// RFC 9580's SEIPD v2 (OCB over AES): HKDF-SHA256 gives the key and IV.
fn open_seipd2(s: const Session&, body: const u8[:], out: u8[>..]&) -> i64 {
    if body.len < 4 + 32 + 16 { return ERR_MALFORMED; }
    let cipher: i64 = body[1];
    let mode:   i64 = body[2];
    let c:      i64 = body[3];
    if mode != AEAD_OCB || !is_aes(cipher) || c > 16 { return ERR_UNSUPPORTED; }
    let ks = cipher_key_size(cipher);
    if s.key.len != ks { return ERR_DECRYPT; }
    let hdr: u8[5] = [0xD2, 2, cipher as! u8, mode as! u8, c as! u8];
    let okm = bignum::hkdf(256, body[4..36], s.key, hdr, ks + 7);
    return open_chunks(okm[..ks], okm[ks..], hdr, 1 << (c + 6), body[36..], true, out);
}

// --- Reading messages --------------------------------------------------------------

fn decompress(algo: i64, data: const u8[:], out: u8[>..]&, limit: i64) -> i64 {
    var rc: i64 = 0;
    if algo == COMP_NONE { if data.len > limit { return ERR_LIMIT; } out.append(data); return OK; }
    if algo == COMP_ZIP { rc = compress::inflate_decode(data, out, limit); }
    else if algo == COMP_ZLIB { rc = compress::zlib_decode(data, out, limit); }
    else if algo == COMP_BZIP2 { rc = compress::bzip2_decode(data, out, limit); }
    else { return ERR_UNSUPPORTED; }
    if rc == compress::ERR_LIMIT { return ERR_LIMIT; }
    return if rc == 0 { OK } else { ERR_MALFORMED };
}

// One layer of packets: what it holds goes into m, and the next layer (the
// plaintext of encrypted data, or decompressed data) into next. Whether
// there is a next layer.
fn read_layer(kr: const Keyring&, cur: const u8[:], m: Message&, opt: ReadOptions, next: u8[>..]&,
              outer: bool) -> bool, i64 {
    var sessions: Session[>..] = [];
    var esk_err = ERR_NO_KEY;
    var saw_esk = false;
    var saw_literal = false;
    var at = 0;
    var count = 0;
    while at < cur.len {
        let p, err = next_packet(cur, at);
        if err != OK { return false, ERR_MALFORMED; }
        count++;
        if count > MAX_PACKETS { return false, ERR_LIMIT; }
        at = p.end;
        let t = p.tag;
        if t == TAG_MARKER || t == TAG_PADDING || t == TAG_TRUST { continue; }
        if t == TAG_PKESK || t == TAG_SKESK {
            saw_esk = true;
            if p.partial { return false, ERR_MALFORMED; }
            let body = cur[p.body..p.body_end];
            var e = OK;
            if t == TAG_PKESK { e = open_pkesk(kr, body, sessions); }
            else if opt.passphrase.len > 0 { e = open_skesk(body, opt.passphrase, sessions); }
            else { e = ERR_PASSPHRASE; }
            if e != OK && (esk_err == ERR_NO_KEY || e == ERR_PASSPHRASE) { esk_err = e; }
            continue;
        }
        if t == TAG_SEIPD || t == TAG_AEAD || t == TAG_SED {
            if saw_literal || m.encrypted { return false, ERR_MALFORMED; }
            m.encrypted = true;
            if t == TAG_SED && !opt.allow_unprotected { return false, ERR_UNPROTECTED; }
            if !saw_esk { return false, ERR_MALFORMED; }
            if sessions.len == 0 { return false, esk_err; }
            var body: u8[>..] = [];
            packet_body(cur, p, body);
            if body.len < 1 { return false, ERR_MALFORMED; }
            var last = ERR_DECRYPT;
            for s in sessions {
                next.clear();
                var e = OK;
                if t == TAG_SEIPD && body[0] == 1 { e = open_seipd1(s, body[1..], next); }
                else if t == TAG_SEIPD && body[0] == 2 { e = open_seipd2(s, body, next); }
                else if t == TAG_SEIPD { e = ERR_UNSUPPORTED; }
                else if t == TAG_AEAD { e = open_aead20(s, body, next); }
                else { e = open_sed(s, body, next); }
                if e == OK {
                    m.cipher = if t == TAG_AEAD { body[1] } else { s.cipher };
                    m.aead = if t == TAG_AEAD { body[2] } else if t == TAG_SEIPD && body[0] == 2 { body[2] } else { 0 };
                    m.integrity = if t == TAG_SED { INTEGRITY_NONE } else if t == TAG_SEIPD && body[0] == 1 { INTEGRITY_MDC } else { INTEGRITY_AEAD };
                    m.decrypted_with = s.by;
                    // Nothing may follow the encrypted data but padding.
                    while at < cur.len {
                        let q, eq = next_packet(cur, at);
                        if eq != OK || (q.tag != TAG_PADDING && q.tag != TAG_MARKER) { return false, ERR_MALFORMED; }
                        at = q.end;
                    }
                    return true, OK;
                }
                last = e;
            }
            next.clear();
            return false, last;
        }
        if t == TAG_COMPRESSED {
            if saw_literal { return false, ERR_MALFORMED; }
            var body: u8[>..] = [];
            packet_body(cur, p, body);
            if body.len < 1 { return false, ERR_MALFORMED; }
            m.compression = body[0];
            next.clear();
            let e = decompress(body[0], body[1..], next, opt.max_size);
            if e != OK { return false, e; }
            return true, OK;
        }
        if t == TAG_ONE_PASS { continue; }
        if t == TAG_SIGNATURE {
            m.sig_packets.append(cur[p.at..p.end]);
            continue;
        }
        if t == TAG_LITERAL {
            if saw_literal { return false, ERR_MALFORMED; }
            saw_literal = true;
            var body: u8[>..] = [];
            packet_body(cur, p, body);
            if body.len < 6 { return false, ERR_MALFORMED; }
            m.format = body[0];
            let nl: i64 = body[1];
            if 2 + nl + 4 > body.len { return false, ERR_MALFORMED; }
            m.filename.clear();
            m.filename.append(body[2..2 + nl]);
            m.mtime = be32(body, 2 + nl);
            if body.len - 6 - nl > opt.max_size { return false, ERR_LIMIT; }
            m.data.append(body[6 + nl..]);
            continue;
        }
        // A key, or anything else: not a message.
        return false, if t == TAG_PUBLIC_KEY || t == TAG_SECRET_KEY || t == TAG_USER_ID { ERR_MALFORMED } else { ERR_UNSUPPORTED };
    }
    if saw_esk { return false, ERR_MALFORMED; }   // session keys but no encrypted data
    if !saw_literal { return false, ERR_MALFORMED; }
    return false, OK;
}

// Reads a message (armored or binary): decrypts it with the keyring's
// unlocked secret keys or the passphrase, decompresses it, and checks its
// signatures (m.sigs; signature_status says whether one is good). The
// error is for the message itself: malformed, not decryptable, changed.
fn read_message(kr: const Keyring&, input: const u8[:], m: Message&, opt: ReadOptions) -> i64 {
    var cur: u8[>..] = [];
    let e0 = decode_input(input, cur);
    if e0 != OK { return e0; }
    var next: u8[>..] = [];
    for depth in MAX_DEPTH {
        let more, err = read_layer(kr, cur, m, opt, next, depth == 0);
        if err != OK { return err; }
        if !more {
            check_signatures(kr, m, opt.now, true);
            return OK;
        }
        cur.clear();
        cur.append(next);
        next.clear();
    }
    return ERR_LIMIT;
}

// read_message, failing unless the message was encrypted.
fn decrypt(kr: const Keyring&, input: const u8[:], m: Message&, opt: ReadOptions) -> i64 {
    let e = read_message(kr, input, m, opt);
    if e != OK { return e; }
    return if m.encrypted { OK } else { ERR_NOT_ENCRYPTED };
}

// read_message, failing unless a signature verified.
fn verify(kr: const Keyring&, input: const u8[:], m: Message&, opt: ReadOptions) -> i64 {
    let e = read_message(kr, input, m, opt);
    if e != OK { return e; }
    return signature_status(m);
}

// A detached signature (armored or binary, one or more signature packets)
// over data: m.sigs gets the results, m.data the data. OK if one verifies.
fn verify_detached(kr: const Keyring&, data: const u8[:], sig: const u8[:], m: Message&, now: i64 = 0) -> i64 {
    var bin: u8[>..] = [];
    let e = decode_input(sig, bin);
    if e != OK { return e; }
    var at = 0;
    while at < bin.len {
        let p, err = next_packet(bin, at);
        if err != OK || p.partial { return ERR_MALFORMED; }
        if p.tag != TAG_SIGNATURE { return ERR_MALFORMED; }
        m.sig_packets.append(bin[p.at..p.end]);
        at = p.end;
    }
    m.data.append(data);
    check_signatures(kr, m, now);
    return signature_status(m);
}

// A cleartext signed message: m.data gets the text as it reads (LF line
// ends), m.sigs the results. A signature over a hash that a "Hash:"
// header leaves out is refused.
fn verify_cleartext(kr: const Keyring&, text: const u8[:], m: Message&, now: i64 = 0) -> i64 {
    var ct = Cleartext { .. };
    let e = parse_cleartext(text, ct);
    if e != OK { return e; }
    cleartext_body(m.data, ct);
    var at = 0;
    while at < ct.sigs.len {
        let p, err = next_packet(ct.sigs, at);
        if err != OK || p.partial || p.tag != TAG_SIGNATURE { return ERR_MALFORMED; }
        at = p.end;
        let body = ct.sigs[p.body..p.body_end];
        // A v5 signature hashes the literal packet gpg fakes for the text:
        // format 't', no name, date 0.
        var r = check_signature(kr, body, ct.text, true, now, literal_meta('t', "", 0));
        let hash: i64 = if body.len > 3 { body[3] } else { 0 };
        // No Hash: header puts no limit on the hash (RFC 9580 §7.1).
        let listed = ct.hashes.len == 0 || contains(ct.hashes[..], hash);
        if r.err == OK && !listed { r.err = ERR_BAD_SIGNATURE; }
        if r.err == OK && r.sigtype != SIG_TEXT { r.err = ERR_BAD_SIGNATURE; }
        m.sigs.push(r);
    }
    return signature_status(m);
}

// --- Writing messages ---------------------------------------------------------------

// The key to sign with for `signer`: a primary (its signing key) or a key
// index that can sign itself.
fn resolve_signer(kr: const Keyring&, signer: i64) -> i64, i64 {
    if signer < 0 || signer >= kr.keys.len { return -1, ERR_KEY; }
    let k = kr.keys[signer];
    var idx = signer;
    if is_primary(kr, signer) { idx = signing_key(kr, signer); }
    else if !usable(kr, signer, FLAG_SIGN) { idx = -1; }
    if idx < 0 { return -1, ERR_KEY; }
    if kr.keys[idx].locked { return idx, ERR_PASSPHRASE; }
    return idx, OK;
}

// A literal data packet; text goes in with CRLF line ends (RFC 9580 §5.9),
// as gpg writes it and as a text signature hashes it.
fn put_literal(out: u8[>..]&, data: const u8[:], opt: WriteOptions) {
    var b: u8[>..] = [];
    b.push(if opt.text { 'u' } else { 'b' });
    b.push(opt.filename.len as! u8);
    b.append(opt.filename);
    put32(b, opt.mtime);
    if opt.text { canonical_text(b, data); } else { b.append(data); }
    put_packet(out, TAG_LITERAL, b);
}

// A one-pass signature packet for key k (v3 for v4 keys, v6 with the salt).
fn put_one_pass(out: u8[>..]&, k: const Key&, sigtype: i64, hash: i64, salt: const u8[:]) {
    var b: u8[>..] = [];
    b.push(if k.version == 6 { 6 } else { 3 });
    b.push(sigtype as! u8);
    b.push(hash as! u8);
    b.push(k.algo as! u8);
    if k.version == 6 {
        b.push(salt.len as! u8);
        b.append(salt);
        b.append(k.fpr);
    } else {
        b.append(k.keyid);
    }
    b.push(1);
    put_packet(out, TAG_ONE_PASS, b);
}

fn sig_params(opt: WriteOptions, sigtype: i64) -> SigParams {
    var p = SigParams { .. };
    p.sigtype = sigtype;
    p.hash = opt.hash;
    p.created = opt.created;
    return p;
}

// The packets of a signed message (one-pass, literal, signature), or of
// the literal alone when signer is -1.
fn put_signed_literal(kr: const Keyring&, signer: i64, data: const u8[:], opt: WriteOptions, out: u8[>..]&) -> i64 {
    if signer < 0 { put_literal(out, data, opt); return OK; }
    let idx, err = resolve_signer(kr, signer);
    if err != OK { return err; }
    let k = kr.keys[idx];
    let sigtype = if opt.text { SIG_TEXT } else { SIG_BINARY };
    var prm = sig_params(opt, sigtype);
    var input: u8[>..] = [];
    sig_data(input, sigtype, data);
    var sig: u8[>..] = [];
    let e = make_signature(k, prm, input, sig, literal_meta(if opt.text { 'u' } else { 'b' }, opt.filename, opt.mtime));
    if e != OK { return e; }
    var salt: u8[>..] = [];
    if k.version == 6 {
        let s, es = parse_signature(signature_body(sig));
        salt.append(s.salt);
    }
    put_one_pass(out, k, sigtype, signing_hash(k, opt.hash), salt);
    put_literal(out, data, opt);
    out.append(sig);
    return OK;
}

fn compress_packet(algo: i64, level: i64, data: const u8[:], out: u8[>..]&) -> i64 {
    var b: u8[>..] = [];
    b.push(algo as! u8);
    var rc: i64 = 0;
    if algo == COMP_ZIP { rc = compress::deflate_encode(data, b, level); }
    else if algo == COMP_ZLIB { rc = compress::zlib_encode(data, b, level); }
    else if algo == COMP_BZIP2 { rc = compress::bzip2_encode(data, b, 9); }
    else { return ERR_UNSUPPORTED; }
    if rc != 0 { return ERR_UNSUPPORTED; }
    put_packet(out, TAG_COMPRESSED, b);
    return OK;
}

fn finish(out: u8[>..]&, bin: const u8[:], label: const u8[:], armored: bool) {
    if armored { armor(out, label, bin); } else { out.append(bin); }
}

// An inline signed message (one-pass signature, literal data, signature),
// compressed if the options say so.
fn sign(kr: const Keyring&, signer: i64, data: const u8[:], out: u8[>..]&, opt: WriteOptions) -> i64 {
    var inner: u8[>..] = [];
    let e = put_signed_literal(kr, signer, data, opt, inner);
    if e != OK { return e; }
    var bin: u8[>..] = [];
    if opt.compression != COMP_NONE {
        let ec = compress_packet(opt.compression, opt.level, inner, bin);
        if ec != OK { return ec; }
    } else {
        bin.append(inner);
    }
    finish(out, bin, ARMOR_MESSAGE, opt.armored);
    return OK;
}

// A detached signature over data (binary, or text with opt.text).
fn sign_detached(kr: const Keyring&, signer: i64, data: const u8[:], out: u8[>..]&, opt: WriteOptions) -> i64 {
    let idx, err = resolve_signer(kr, signer);
    if err != OK { return err; }
    let sigtype = if opt.text { SIG_TEXT } else { SIG_BINARY };
    var input: u8[>..] = [];
    sig_data(input, sigtype, data);
    var sig: u8[>..] = [];
    let prm = sig_params(opt, sigtype);
    let e = make_signature(kr.keys[idx], prm, input, sig);
    if e != OK { return e; }
    finish(out, sig, ARMOR_SIGNATURE, opt.armored);
    return OK;
}

// A cleartext signed message (§7): the text dash-escaped, then the armored
// signature (type 0x01 over the text's lines, trailing white space and the
// last line end excluded).
fn sign_cleartext(kr: const Keyring&, signer: i64, text: const u8[:], out: u8[>..]&, opt: WriteOptions) -> i64 {
    let idx, err = resolve_signer(kr, signer);
    if err != OK { return err; }
    var body = text;
    if ends_with(body, "\r\n") { body = body[..body.len - 2]; } else if ends_with(body, "\n") { body = body[..body.len - 1]; }
    var input: u8[>..] = [];
    canonical_text(input, body, true);
    var sig: u8[>..] = [];
    let prm = sig_params(opt, SIG_TEXT);
    let e = make_signature(kr.keys[idx], prm, input, sig, literal_meta('t', "", 0));
    if e != OK { return e; }
    out.append("-----BEGIN PGP SIGNED MESSAGE-----\nHash: ");
    out.append(hash_name(signing_hash(kr.keys[idx], opt.hash)));
    out.append("\n\n");
    dash_escape(out, body);
    armor(out, ARMOR_SIGNATURE, sig);
    return OK;
}

// SEIPD v1 of plaintext under a session key.
fn put_seipd1(out: u8[>..]&, cipher: i64, key: const u8[:], plain: const u8[:]) {
    let bs = cipher_block_size(cipher);
    var buf: u8[>..] = [];
    buf.append(random(bs));
    buf.push(buf[bs - 2]);
    buf.push(buf[bs - 1]);
    buf.append(plain);
    buf.push(0xD3);
    buf.push(0x14);
    let h = bignum::sha1(buf);
    buf.append(h);
    var iv: u8[>..] = [];
    iv.resize(bs, 0);
    let ok = cfb(cipher, key, iv, buf, false);
    assert(ok);
    put_header(out, TAG_SEIPD, buf.len + 1);
    out.push(1);
    out.append(buf);
}

// Encrypts data to the recipients (primary keys: each one's encryption
// key) and, when pass is not "", to a passphrase too; signed first by
// signer when it is not -1. ERR_KEY if a recipient has no key to encrypt
// to.
fn encrypt(kr: const Keyring&, recipients: const i64[:], pass: const u8[:], data: const u8[:], out: u8[>..]&,
           opt: WriteOptions, signer: i64 = -1) -> i64 {
    if recipients.len == 0 && pass.len == 0 { return ERR_KEY; }
    let cipher = opt.cipher;
    let ks = cipher_key_size(cipher);
    if ks == 0 || cipher == CIPHER_3DES || cipher == CIPHER_BLOWFISH { return ERR_UNSUPPORTED; }
    var bin: u8[>..] = [];
    let session = random(ks);
    let m = encode_session(cipher, session);
    for r in recipients {
        if r < 0 || r >= kr.keys.len { return ERR_KEY; }
        let ek = if is_primary(kr, r) { encryption_key(kr, r) } else if usable(kr, r, FLAG_ENCRYPT) { r } else { -1 };
        if ek < 0 { return ERR_KEY; }
        let k = kr.keys[ek];
        var b: u8[>..] = [];
        b.push(3);
        b.append(k.keyid);
        b.push(k.algo as! u8);
        let e = encrypt_session(k, m, b);
        if e != OK { return e; }
        put_packet(bin, TAG_PKESK, b);
    }
    if pass.len > 0 {
        let s2k = new_s2k(opt.s2k_coded);
        let kek, e = s2k_key(s2k, pass, ks);
        if e != OK { return e; }
        var b: u8[>..] = [];
        b.push(4);
        b.push(cipher as! u8);
        put_s2k(b, s2k);
        var esk: u8[>..] = [];
        esk.push(cipher as! u8);
        esk.append(session);
        var iv: u8[>..] = [];
        iv.resize(cipher_block_size(cipher), 0);
        let ok = cfb(cipher, kek, iv, esk, false);
        b.append(esk);
        put_packet(bin, TAG_SKESK, b);
    }
    var inner: u8[>..] = [];
    let e1 = put_signed_literal(kr, signer, data, opt, inner);
    if e1 != OK { return e1; }
    if opt.compression != COMP_NONE {
        var c: u8[>..] = [];
        let ec = compress_packet(opt.compression, opt.level, inner, c);
        if ec != OK { return ec; }
        put_seipd1(bin, cipher, session, c);
    } else {
        put_seipd1(bin, cipher, session, inner);
    }
    finish(out, bin, ARMOR_MESSAGE, opt.armored);
    return OK;
}
