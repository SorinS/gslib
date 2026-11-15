// ntlm: NTLM authentication ([MS-NLMP]), NTLMv2 only, both sides: the
// NTLMSSP messages (NEGOTIATE, CHALLENGE with its target info AV_PAIRs,
// AUTHENTICATE, VERSION) and their flags (ntlm/messages.goose); NTOWFv2,
// the NTLMv2 response and its session key, KEY_EXCH, the MIC over the
// three messages, channel bindings and the target name
// (ntlm/crypto.goose); an initiator (ntlm/client.goose) and an acceptor
// that finds the user's NT hash through a block (ntlm/server.goose);
// session security with extended session security: signing and sealing
// with HMAC-MD5 and RC4 and sequence numbers, as GSS wrap, unwrap and MIC
// (ntlm/session.goose); and NTLM over HTTP, "WWW-Authenticate: NTLM" and
// Negotiate carrying raw NTLMSSP, with tls-server-end-point channel
// bindings (ntlm/http.goose). SPNEGO with NTLM as its mechanism is
// krb5.spnego's.
//
// NTLM is legacy. Its keys come from an unsalted MD4 of the password, so
// an NT hash is as good as the password and a captured exchange can be
// brute-forced offline; RC4 and HMAC-MD5 are its only ciphers. Use it
// only where a peer offers nothing else. NTLMv1 and LM are not here at
// all: no LM or NTLMv1 response is ever computed, and the acceptor
// refuses one (24-byte NT responses, LM-only, LM_KEY), since an NTLMv1
// response can be cracked back to the NT hash outright.
//
//   var cred, e = ntlm::credentials("alice", "EXAMPLE", "password");
//   var cli = ntlm::initiator(cred, "HTTP/web.example.test", ntlm::WANT_SIGN | ntlm::WANT_SEAL);
//   var t1: u8[>..] = [];
//   ntlm::negotiate(cli, t1);                               // to the server
//   var srv = ntlm::acceptor("WEB", "EXAMPLE", "web.example.test", "example.test");
//   var t2: u8[>..] = [];
//   ntlm::accept_negotiate(srv, t1, now, t2);               // back to the client
//   var t3: u8[>..] = [];
//   ntlm::authenticate(cli, t2, now, t3);                   // to the server
//   let err = ntlm::accept_authenticate(srv, t3, now) { user, domain, hash => lookup(user, domain, hash) };
//
// Nothing is kept in part: a name or message that does not fit where it
// goes is an error, never cut.

namespace ntlm;

import std;
import crypto.bignum;
import crypto.bignum.md4;
import crypto.bignum.md5;
import crypto.bignum.hmac;
import crypto.bignum.rc4;
import crypto.bignum.ct;

// --- Negotiate flags (§2.2.2.5) ---------------------------------------------------

let NEGOTIATE_UNICODE:                  u32 = 0x00000001;
let NEGOTIATE_OEM:                      u32 = 0x00000002;
let REQUEST_TARGET:                     u32 = 0x00000004;
let NEGOTIATE_SIGN:                     u32 = 0x00000010;
let NEGOTIATE_SEAL:                     u32 = 0x00000020;
let NEGOTIATE_DATAGRAM:                 u32 = 0x00000040;
let NEGOTIATE_LM_KEY:                   u32 = 0x00000080;
let NEGOTIATE_NTLM:                     u32 = 0x00000200;
let NEGOTIATE_ANONYMOUS:                u32 = 0x00000800;
let NEGOTIATE_OEM_DOMAIN_SUPPLIED:      u32 = 0x00001000;
let NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x00002000;
let NEGOTIATE_ALWAYS_SIGN:              u32 = 0x00008000;
let TARGET_TYPE_DOMAIN:                 u32 = 0x00010000;
let TARGET_TYPE_SERVER:                 u32 = 0x00020000;
let NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
let NEGOTIATE_IDENTIFY:                 u32 = 0x00100000;
let REQUEST_NON_NT_SESSION_KEY:         u32 = 0x00400000;
let NEGOTIATE_TARGET_INFO:              u32 = 0x00800000;
let NEGOTIATE_VERSION:                  u32 = 0x02000000;
let NEGOTIATE_128:                      u32 = 0x20000000;
let NEGOTIATE_KEY_EXCH:                 u32 = 0x40000000;
let NEGOTIATE_56:                       u32 = 0x80000000;

// What an initiator asks for beyond authentication.
let WANT_SIGN: u32 = 1;          // integrity: get_mic / verify_mic, and wrap without sealing
let WANT_SEAL: u32 = 2;          // confidentiality: wrap and unwrap

// --- AV_PAIR ids (§2.2.2.1) ---------------------------------------------------------

let AV_EOL:               u16 = 0;
let AV_NB_COMPUTER_NAME:  u16 = 1;
let AV_NB_DOMAIN_NAME:    u16 = 2;
let AV_DNS_COMPUTER_NAME: u16 = 3;
let AV_DNS_DOMAIN_NAME:   u16 = 4;
let AV_DNS_TREE_NAME:     u16 = 5;
let AV_FLAGS:             u16 = 6;
let AV_TIMESTAMP:         u16 = 7;
let AV_SINGLE_HOST:       u16 = 8;
let AV_TARGET_NAME:       u16 = 9;
let AV_CHANNEL_BINDINGS:  u16 = 10;

// MsvAvFlags.
let AVF_CONSTRAINED:   u32 = 1;   // the account's authentication is constrained
let AVF_MIC:           u32 = 2;   // the AUTHENTICATE message carries a MIC
let AVF_UNTRUSTED_SPN: u32 = 4;   // the target name came from an untrusted source

// The messages' types.
let MSG_NEGOTIATE:    u32 = 1;
let MSG_CHALLENGE:    u32 = 2;
let MSG_AUTHENTICATE: u32 = 3;

let SIGNATURE: const u8[:] = "NTLMSSP\x00";

// The largest message read; their fields' lengths are 16-bit anyway.
let MAX_MESSAGE: i64 = 65536;

// Channel binding policy of an acceptor (Windows' Extended Protection).
let CB_NONE:      i64 = 0;    // not checked
let CB_SUPPORTED: i64 = 1;    // checked when the client sent bindings that are not zeros
let CB_REQUIRED:  i64 = 2;    // the client must send the right ones

// --- Errors ------------------------------------------------------------------------------

let OK:               i64 = 0;
let ERR_ARG:          i64 = 1;    // an argument that cannot be used (a name too long, not UTF-8)
let ERR_MALFORMED:    i64 = 2;    // not an NTLMSSP message of the right type, or a field out of range or overlapping
let ERR_LIMIT:        i64 = 3;    // larger than a limit
let ERR_STATE:        i64 = 4;    // a step out of order
let ERR_NTLMV1:       i64 = 5;    // an LM or NTLMv1 response (refused, never made)
let ERR_FLAGS:        i64 = 6;    // flags that cannot be used: no UNICODE, no extended session security, a downgrade
let ERR_LOGON:        i64 = 7;    // unknown user or wrong password (one error, so as not to tell which)
let ERR_MIC:          i64 = 8;    // the MIC is wrong, or missing where MsvAvFlags or the policy wants one
let ERR_TIMESTAMP:    i64 = 9;    // the response's time is outside the clock skew, or not the challenge's
let ERR_BINDINGS:     i64 = 10;   // channel bindings missing or not the channel's
let ERR_TARGET:       i64 = 11;   // the target name (SPN) is missing or not ours
let ERR_ANONYMOUS:    i64 = 12;   // anonymous authentication, not allowed
let ERR_AV_PAIRS:     i64 = 13;   // target info that is not AV_PAIRs ending in MsvAvEOL, a pair twice, a wrong size
let ERR_SIGNATURE:    i64 = 14;   // a message signature (MIC, wrap) that does not verify, or out of sequence
let ERR_NO_SESSION:   i64 = 15;   // signing or sealing that was not negotiated
let ERR_REJECTED:     i64 = 16;   // the peer rejected the exchange (SPNEGO reject), or offered no NTLM

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "bad argument"; }
    if e == ERR_MALFORMED { return "malformed NTLM message"; }
    if e == ERR_LIMIT { return "too large"; }
    if e == ERR_STATE { return "out of order"; }
    if e == ERR_NTLMV1 { return "LM or NTLMv1 refused"; }
    if e == ERR_FLAGS { return "unacceptable negotiate flags"; }
    if e == ERR_LOGON { return "logon failure"; }
    if e == ERR_MIC { return "bad or missing MIC"; }
    if e == ERR_TIMESTAMP { return "timestamp outside the allowed skew"; }
    if e == ERR_BINDINGS { return "channel bindings mismatch"; }
    if e == ERR_TARGET { return "target name mismatch"; }
    if e == ERR_ANONYMOUS { return "anonymous authentication refused"; }
    if e == ERR_AV_PAIRS { return "bad AV_PAIR list"; }
    if e == ERR_SIGNATURE { return "bad message signature"; }
    if e == ERR_NO_SESSION { return "no session security negotiated"; }
    if e == ERR_REJECTED { return "rejected by the peer"; }
    return "unknown error";
}

// --- Little-endian ----------------------------------------------------------------------

fn put16(out: u8[>..]&, v: u16) { out.push(v as! u8); out.push((v >> 8) as! u8); }
fn put32(out: u8[>..]&, v: u32) { for i in 4 { out.push((v >> (8 * i)) as! u8); } }
fn put64(out: u8[>..]&, v: u64) { for i in 8 { out.push((v >> (8 * i)) as! u8); } }

fn get16(b: const u8[:], at: i64) -> u16 {
    let lo: u16 = b[at];
    let hi: u16 = b[at + 1];
    return lo | hi << 8;
}

fn get32(b: const u8[:], at: i64) -> u32 {
    var v: u32 = 0;
    for i in 4 { v |= (b[at + i] as u32) << (8 * i); }
    return v;
}

fn get64(b: const u8[:], at: i64) -> u64 {
    var v: u64 = 0;
    for i in 8 { v |= (b[at + i] as u64) << (8 * i); }
    return v;
}

// --- Time -------------------------------------------------------------------------------

// FILETIME: 100-nanosecond intervals since 1601-01-01.
let FILETIME_UNIX: u64 = 116444736000000000;

fn filetime(unix_secs: i64) -> u64 {
    if unix_secs < 0 { return FILETIME_UNIX; }
    return FILETIME_UNIX + (unix_secs as u64) * 10000000;
}

// Seconds since 1970 of a FILETIME (before 1970: negative).
fn filetime_unix(ft: u64) -> i64 {
    if ft >= FILETIME_UNIX { return ((ft - FILETIME_UNIX) / 10000000) as! i64; }
    return -(((FILETIME_UNIX - ft) / 10000000) as! i64);
}

// --- Text: UTF-8 and UTF-16LE -----------------------------------------------------------

// UTF-8 to UTF-16LE (code points above U+FFFF as surrogate pairs); false
// for text that is not UTF-8 (overlong forms and surrogates too).
fn utf16le(out: u8[>..]&, s: const u8[:]) -> bool {
    var i = 0;
    while i < s.len {
        let c: u32 = s[i];
        var cp: u32 = 0;
        var n = 0;
        if c < 0x80 { cp = c; n = 1; }
        else if c >= 0xc2 && c <= 0xdf { cp = c & 0x1f; n = 2; }
        else if c >= 0xe0 && c <= 0xef { cp = c & 0x0f; n = 3; }
        else if c >= 0xf0 && c <= 0xf4 { cp = c & 0x07; n = 4; }
        else { return false; }
        if i + n > s.len { return false; }
        for k in 1..n {
            let d: u32 = s[i + k];
            if d & 0xc0 != 0x80 { return false; }
            cp = cp << 6 | (d & 0x3f);
        }
        if (n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10ffff)) { return false; }
        if cp >= 0xd800 && cp <= 0xdfff { return false; }
        if cp >= 0x10000 {
            let v = cp - 0x10000;
            put16(out, (0xd800 | (v >> 10)) as! u16);
            put16(out, (0xdc00 | (v & 0x3ff)) as! u16);
        } else {
            put16(out, cp as! u16);
        }
        i += n;
    }
    return true;
}

// UTF-16LE to UTF-8; false for an odd length or a lone surrogate.
fn utf8_of_utf16le(out: u8[>..]&, b: const u8[:]) -> bool {
    if b.len % 2 != 0 { return false; }
    var i = 0;
    while i < b.len {
        var cp: u32 = get16(b, i);
        i += 2;
        if cp >= 0xdc00 && cp <= 0xdfff { return false; }
        if cp >= 0xd800 && cp <= 0xdbff {
            if i + 2 > b.len { return false; }
            let lo: u32 = get16(b, i);
            if lo < 0xdc00 || lo > 0xdfff { return false; }
            i += 2;
            cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
        }
        if cp < 0x80 { out.push(cp as! u8); }
        else if cp < 0x800 { out.push((0xc0 | (cp >> 6)) as! u8); out.push((0x80 | (cp & 0x3f)) as! u8); }
        else if cp < 0x10000 {
            out.push((0xe0 | (cp >> 12)) as! u8);
            out.push((0x80 | ((cp >> 6) & 0x3f)) as! u8);
            out.push((0x80 | (cp & 0x3f)) as! u8);
        } else {
            out.push((0xf0 | (cp >> 18)) as! u8);
            out.push((0x80 | ((cp >> 12) & 0x3f)) as! u8);
            out.push((0x80 | ((cp >> 6) & 0x3f)) as! u8);
            out.push((0x80 | (cp & 0x3f)) as! u8);
        }
    }
    return true;
}

// ASCII letters upper-cased, every other byte as it is: NTOWFv2's
// Uppercase(User). Windows upper-cases all of Unicode; a user name with
// letters outside ASCII is a quirk here (README).
fn upper_ascii(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for c in s { out.push(if c >= 'a' && c <= 'z' { c - 32 } else { c }); }
    return out;
}

fn eq_fold_ascii(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len {
        let x = if a[i] >= 'a' && a[i] <= 'z' { a[i] - 32 } else { a[i] };
        let y = if b[i] >= 'a' && b[i] <= 'z' { b[i] - 32 } else { b[i] };
        if x != y { return false; }
    }
    return true;
}

// Constant-time equality of two byte strings of public lengths.
fn same(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    return bignum::ct_eq_bytes(a, b) == 1;
}

// --- Credentials --------------------------------------------------------------------------

// Who an initiator is: the user and domain as UTF-8, and the NT hash
// (MD4 of the UTF-16LE password; the password itself is not kept). An
// empty user and an anonymous flag: anonymous authentication.
struct Credentials {
    user:        u8[..256],
    domain:      u8[..256],
    workstation: u8[..64],
    nt_hash:     u8[16],
    anonymous:   bool,
}

// MD4(UTF-16LE(password)); false if the password is not UTF-8.
fn nt_hash(password: const u8[:]) -> u8[16], bool {
    var u: u8[>..] = [];
    if !utf16le(u, password) { return [0; 16], false; }
    return bignum::md4(u), true;
}

fn credentials_hash(user: const u8[:], domain: const u8[:], hash: const u8[:]) -> Credentials, i64 {
    var c = Credentials { user: [], domain: [], workstation: [], nt_hash: [0; 16], anonymous: false };
    if hash.len != 16 || user.len > c.user.cap || domain.len > c.domain.cap { return c, ERR_ARG; }
    var t: u8[>..] = [];
    if !utf16le(t, user) || !utf16le(t, domain) { return c, ERR_ARG; }
    c.user.append(user);
    c.domain.append(domain);
    for i in 16 { c.nt_hash[i] = hash[i]; }
    return c, OK;
}

// Credentials from a password. A user given as "DOMAIN\user" with an
// empty domain is split there; "user@realm" (a UPN) stays whole with
// the domain empty, as Windows sends it.
fn credentials(user: const u8[:], domain: const u8[:], password: const u8[:]) -> Credentials, i64 {
    let h, ok = nt_hash(password);
    if !ok { return Credentials { user: [], domain: [], workstation: [], nt_hash: [0; 16], anonymous: false }, ERR_ARG; }
    let bs = position(user, '\\');
    if domain.len == 0 && bs >= 0 { return credentials_hash(user[bs + 1..], user[..bs], h); }
    return credentials_hash(user, domain, h);
}

// Anonymous: no user, no password; the AUTHENTICATE message carries no
// response and no key, and nothing can be signed or sealed.
fn anonymous_credentials() -> Credentials {
    return Credentials { user: [], domain: [], workstation: [], nt_hash: [0; 16], anonymous: true };
}

fn set_workstation(c: Credentials&, name: const u8[:]) -> i64 {
    if name.len > c.workstation.cap { return ERR_ARG; }
    var t: u8[>..] = [];
    if !utf16le(t, name) { return ERR_ARG; }
    c.workstation.clear();
    c.workstation.append(name);
    return OK;
}

// A 32-digit hex NT hash (as pwdump and impacket print them).
fn parse_nt_hash(hex: const u8[:]) -> u8[16], bool {
    var h: u8[16] = [0; 16];
    if hex.len != 32 { return h, false; }
    for i in 32 {
        let c = hex[i];
        var v: u8 = 0;
        if c >= '0' && c <= '9' { v = c - '0'; }
        else if c >= 'a' && c <= 'f' { v = c - 'a' + 10; }
        else if c >= 'A' && c <= 'F' { v = c - 'A' + 10; }
        else { return h, false; }
        h[i / 2] |= if i % 2 == 0 { v << 4 } else { v };
    }
    return h, true;
}
