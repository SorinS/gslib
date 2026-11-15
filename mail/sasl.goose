// mail.sasl: the client side of the SASL mechanisms SMTP's AUTH (RFC 4954)
// and POP3's AUTH (RFC 5034) use, as go-mail's smtp package has them:
// PLAIN (RFC 4616), LOGIN, CRAM-MD5 (RFC 2195), SCRAM-SHA-1 and
// SCRAM-SHA-256 (RFC 5802, RFC 7677; without channel binding) and XOAUTH2,
// and NTLM (gslib's ntlm, NTLMv2 only; "DOMAIN\user" as the user), which
// Exchange servers offer: the NEGOTIATE as the initial response, the
// AUTHENTICATE answering the CHALLENGE. NTLM is used only when asked for.
// The protocols carry the exchange, base64-encoded; this module works on
// the decoded bytes:
//
//   var s = mail::sasl_new(mail::AUTH_SCRAM_SHA256, user, password);
//   var out: u8[>..] = [];
//   if mail::sasl_initial(s, out) { ... send out with the command ... }
//   ... each challenge: mail::sasl_step(s, challenge, out), send out ...
//   mail::sasl_done(s)        // SCRAM: the server proved it knows the password
//
// The password is used as it is: SCRAM's SASLprep is the identity for
// ASCII passwords, which is all this does.

namespace mail;

import std;
import base64;
import os;
import mail;
import crypto.bignum;
import crypto.bignum.hmac;
import crypto.bignum.kdf;
import crypto.bignum.entropy;
import ntlm;
import ntlm.messages;
import ntlm.client;

let AUTH_AUTO:         i64 = 0;  // the best the server offers: auth_choose
let AUTH_PLAIN:        i64 = 1;
let AUTH_LOGIN:        i64 = 2;
let AUTH_CRAM_MD5:     i64 = 3;
let AUTH_SCRAM_SHA1:   i64 = 4;
let AUTH_SCRAM_SHA256: i64 = 5;
let AUTH_XOAUTH2:      i64 = 6;  // the secret is an OAuth 2 access token
let AUTH_NTLM:         i64 = 7;  // NTLMv2 (MS-SMTPX, MS-POP3, MS-OXIMAP); the user may be DOMAIN\user

fn auth_name(mech: i64) -> const u8[:] {
    match mech {
        AUTH_PLAIN => "PLAIN",
        AUTH_LOGIN => "LOGIN",
        AUTH_CRAM_MD5 => "CRAM-MD5",
        AUTH_SCRAM_SHA1 => "SCRAM-SHA-1",
        AUTH_SCRAM_SHA256 => "SCRAM-SHA-256",
        AUTH_XOAUTH2 => "XOAUTH2",
        AUTH_NTLM => "NTLM",
        _ => "",
    }
}

// Whether the mechanism sends the password itself (or a token), readable to
// anyone on the path without TLS.
fn auth_plaintext(mech: i64) -> bool { mech == AUTH_PLAIN || mech == AUTH_LOGIN || mech == AUTH_XOAUTH2 }

// Whether a space-separated list of mechanism names (EHLO's AUTH line,
// POP3's SASL capability) has this one, the names compared without case.
fn auth_offered(list: const u8[:], mech: i64) -> bool {
    let name = auth_name(mech);
    var i = 0;
    while i < list.len {
        while i < list.len && list[i] == ' ' { i++; }
        var j = i;
        while j < list.len && list[j] != ' ' { j++; }
        if j - i == name.len && eq_fold(list[i..j], name) { return true; }
        i = j;
    }
    return false;
}

// AUTH_AUTO's choice from what the server offers, as go-mail's
// autodiscovery orders them: SCRAM-SHA-256, SCRAM-SHA-1, CRAM-MD5, PLAIN,
// LOGIN. XOAUTH2 only when asked for. AUTH_AUTO (0) when none fits.
fn auth_choose(list: const u8[:]) -> i64 {
    for m in [AUTH_SCRAM_SHA256, AUTH_SCRAM_SHA1, AUTH_CRAM_MD5, AUTH_PLAIN, AUTH_LOGIN] {
        if auth_offered(list, m) { return m; }
    }
    return AUTH_AUTO;
}

// One exchange's state. For SCRAM: the client nonce, the messages so far
// (RFC 5802's AuthMessage) and the server signature to expect.
struct Sasl {
    mech:         i64,
    step:         i64,
    done:         bool,          // the exchange finished as it should (SCRAM: the server's signature checked)
    user:         u8[..512],
    secret:       u8[..8192],
    nonce:        u8[..64],
    client_first: u8[..1024],
    server_sig:   u8[..64],
    nt:           ntlm::Initiator,   // AUTH_NTLM's context
}

fn sasl_new(mech: i64, user: const u8[:], secret: const u8[:]) -> Sasl {
    var s = Sasl { mech: mech, step: 0, done: false, user: [], secret: [], nonce: [], client_first: [], server_sig: [],
                   nt: ntlm::initiator(ntlm::anonymous_credentials(), "", 0) };
    s.user.append(user[.. ::min(user.len, 512)]);
    s.secret.append(secret[.. ::min(secret.len, 8192)]);
    return s;
}

// A fresh client nonce: 24 random bytes, base64 (no ',' in it).
fn sasl_set_nonce(s: Sasl&, nonce: const u8[:]) {
    s.nonce.clear();
    s.nonce.append(nonce[.. ::min(nonce.len, 64)]);
}

fn hex_lower(out: u8[>..]&, b: const u8[:]) {
    let digits = "0123456789abcdef";
    for c in b { out.push(digits[c >> 4]); out.push(digits[c & 15]); }
}

// SCRAM's saslname: '=' and ',' escaped (RFC 5802 §5.1).
fn scram_name(out: u8[>..]&, name: const u8[:]) {
    for c in name {
        if c == '=' { out.append("=3D"); } else if c == ',' { out.append("=2C"); } else { out.push(c); }
    }
}

fn scram_bits(mech: i64) -> i64 { if mech == AUTH_SCRAM_SHA1 { 160 } else { 256 } }

// The value of attribute `key` in a SCRAM message ("r=...,s=...,i=..."),
// and whether it is there.
fn scram_attr(m: const u8[:], key: u8) -> const u8[:], bool {
    var i = 0;
    while i < m.len {
        var j = i;
        while j < m.len && m[j] != ',' { j++; }
        if j - i >= 2 && m[i] == key && m[i + 1] == '=' { return m[i + 2..j], true; }
        i = j + 1;
    }
    return m[0..0], false;
}

// The initial response, sent with the command itself: true and the bytes
// in out for the mechanisms that have one (all but LOGIN and CRAM-MD5).
fn sasl_initial(s: Sasl&, out: u8[>..]&) -> bool {
    out.clear();
    if s.mech == AUTH_PLAIN {
        out.push(0);
        out.append(s.user);
        out.push(0);
        out.append(s.secret);
        s.done = true;
        s.step = 1;
        return true;
    }
    if s.mech == AUTH_XOAUTH2 {
        out.append("user=");
        out.append(s.user);
        out.append("\x01auth=Bearer ");
        out.append(s.secret);
        out.append("\x01\x01");
        s.done = true;
        s.step = 1;
        return true;
    }
    if s.mech == AUTH_NTLM {
        // The NEGOTIATE; credentials that will not do give no initial
        // response, and the first challenge then fails the exchange.
        let cred, ce = ntlm::credentials(s.user, "", s.secret);
        if ce != ntlm::OK { return false; }
        s.nt = ntlm::initiator(cred, "", 0);
        s.step = 1;
        return ntlm::negotiate(s.nt, out) == ntlm::OK;
    }
    if s.mech != AUTH_SCRAM_SHA1 && s.mech != AUTH_SCRAM_SHA256 { return false; }
    if s.nonce.len == 0 {
        var r: u8[18] = [0; 18];
        bignum::random_bytes(r);
        var n: u8[>..] = [];
        base64::encode(n, r);
        s.nonce.append(n);
    }
    var name: u8[>..] = [];
    scram_name(name, s.user);
    if name.len + s.nonce.len > 1000 { return false; }
    s.client_first.clear();
    s.client_first.append("n=");
    s.client_first.append(name);
    s.client_first.append(",r=");
    s.client_first.append(s.nonce);
    out.append("n,,");
    out.append(s.client_first);
    s.step = 1;
    return true;
}

// The response to a challenge (decoded), into out: OK, or ERR_AUTH for a
// challenge that is malformed or does not check out (SCRAM: the wrong
// nonce, the wrong server signature, or the server's e= error).
fn sasl_step(s: Sasl&, challenge: const u8[:], out: u8[>..]&) -> i64 {
    out.clear();
    let step = s.step;
    s.step++;
    if s.mech == AUTH_PLAIN {
        // Asked for after an empty challenge, when no initial response went.
        if step != 0 { return ERR_AUTH; }
        out.push(0);
        out.append(s.user);
        out.push(0);
        out.append(s.secret);
        s.done = true;
        return OK;
    }
    if s.mech == AUTH_XOAUTH2 {
        // A failure comes as a JSON challenge; the client answers it with
        // nothing, and the server then sends its error reply.
        s.done = false;
        return OK;
    }
    if s.mech == AUTH_LOGIN {
        // "Username:" then "Password:", in that order whatever their words
        // (servers localize them).
        if step == 0 { out.append(s.user); return OK; }
        if step == 1 { out.append(s.secret); s.done = true; return OK; }
        return ERR_AUTH;
    }
    if s.mech == AUTH_CRAM_MD5 {
        if step != 0 { return ERR_AUTH; }
        let mac = bignum::hmac(128, s.secret, challenge);
        out.append(s.user);
        out.push(' ');
        hex_lower(out, mac);
        s.done = true;
        return OK;
    }
    if s.mech == AUTH_SCRAM_SHA1 || s.mech == AUTH_SCRAM_SHA256 { return scram_step(s, step, challenge, out); }
    if s.mech == AUTH_NTLM {
        // The CHALLENGE, answered once.
        if step != 1 || ntlm::authenticate(s.nt, challenge, time_ns() / 1000000000, out) != ntlm::OK { out.clear(); return ERR_AUTH; }
        s.done = true;
        return OK;
    }
    return ERR_AUTH;
}

fn scram_step(s: Sasl&, step: i64, m: const u8[:], out: u8[>..]&) -> i64 {
    let bits = scram_bits(s.mech);
    if step == 1 {
        // server-first-message: r=nonce,s=salt,i=iterations
        if m.len > 2048 { return ERR_AUTH; }
        let e, has_e = scram_attr(m, 'e');
        if has_e { return ERR_AUTH; }
        let r, ok_r = scram_attr(m, 'r');
        let salt64, ok_s = scram_attr(m, 's');
        let it, ok_i = scram_attr(m, 'i');
        if !ok_r || !ok_s || !ok_i || r.len <= s.nonce.len || r[..s.nonce.len] != s.nonce { return ERR_AUTH; }
        let iter, ok_n = parse_int(it);
        // RFC 7677 asks for 4096 at least; far more is a server stalling us.
        if !ok_n || iter < 1 || iter > 10000000 { return ERR_AUTH; }
        var salt: u8[>..] = [];
        if !base64::decode(salt, salt64) { return ERR_AUTH; }
        let hlen = bits / 8;
        let salted = bignum::pbkdf2(bits, s.secret, salt, iter, hlen);
        let client_key = bignum::hmac(bits, salted, "Client Key");
        let stored_key = bignum::hash_bits(bits, client_key);
        var without_proof: u8[>..] = [];
        without_proof.append("c=biws,r=");      // biws: base64 of "n,,", no channel binding
        without_proof.append(r);
        var auth_message: u8[>..] = [];
        auth_message.append(s.client_first);
        auth_message.push(',');
        auth_message.append(m);
        auth_message.push(',');
        auth_message.append(without_proof);
        let client_sig = bignum::hmac(bits, stored_key, auth_message);
        var proof: u8[>..] = [];
        for i in hlen { proof.push(client_key[i] ^ client_sig[i]); }
        let server_key = bignum::hmac(bits, salted, "Server Key");
        s.server_sig.clear();
        s.server_sig.append(bignum::hmac(bits, server_key, auth_message));
        out.append(without_proof);
        out.append(",p=");
        base64::encode(out, proof);
        return OK;
    }
    if step == 2 {
        // server-final-message: v=signature, or e=error
        let v, ok_v = scram_attr(m, 'v');
        if !ok_v { return ERR_AUTH; }
        var sig: u8[>..] = [];
        if !base64::decode(sig, v) || sig[..] != s.server_sig[..] { return ERR_AUTH; }
        s.done = true;
        return OK;
    }
    return ERR_AUTH;
}

// Whether the exchange finished as it should. For SCRAM, the server proved
// it knows the password: an exchange whose server never sent its final
// message (a server that said yes to anything) is not done.
fn sasl_done(s: const Sasl&) -> bool { s.done }
