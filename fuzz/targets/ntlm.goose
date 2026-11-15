// Fuzz target: ntlm. The first byte picks a path (data[0] % 6), the rest
// is the input:
//   0: the message parsers: parse_negotiate, parse_challenge (its target
//      info's AV_PAIRs checked and read) and parse_authenticate (its
//      fields, the NTLMv2 blob's AV_PAIRs, the names as UTF-16LE).
//   1: an acceptor after a fixed NEGOTIATE/CHALLENGE (accept_negotiate_with,
//      fixed challenge and time) given the input as AUTHENTICATE. When
//      (data[0] / 6) & 8, the NTProofStr in it is first replaced by the right
//      one for the names it carries and a fixed NT hash, so the checks
//      after the proof (blob, timestamp, channel bindings, target name,
//      key exchange, MIC) are reached.
//   2: an initiator after its NEGOTIATE given the input as CHALLENGE
//      (authenticate_with: fixed time, client challenge and key).
//   3: a session's unwrap and verify_mic on the input.
//   4: SPNEGO and HTTP token parsing (krb5.spnego's read_neg_init after
//      gss_unframe, read_neg_resp, negotiate_token; ntlm's http_token).
//   5: krb5's SPNEGO-NTLM acceptor, past its first step (set up with
//      accept_negotiate_with), given the input as its NegTokenResp.
// Paths that draw random bytes (accept_negotiate, authenticate, a fresh
// SPNEGO acceptor's first step) are not driven.

import std;
import gslib from "../..";
import gslib.ntlm;
import gslib.ntlm.crypto;
import gslib.ntlm.messages;
import gslib.ntlm.client;
import gslib.ntlm.server;
import gslib.ntlm.session;
import gslib.ntlm.http;
import gslib.krb5;
import gslib.krb5.gssapi;
import gslib.krb5.spnego;
import gslib.encoding.asn1;

let NOW: i64         = 1800000000;
let SC:  const u8[:] = "\x01\x23\x45\x67\x89\xab\xcd\xef";
let CC:  const u8[:] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
let RK:  const u8[:] = "UUUUUUUUUUUUUUUU";

var NEG:  u8[>..] = [];
var HASH: u8[16]  = [0; 16];

fn probe_av(ti: const u8[:]) {
    if ntlm::av_check(ti) != ntlm::OK { return; }
    for id in [ntlm::AV_NB_DOMAIN_NAME, ntlm::AV_NB_COMPUTER_NAME, ntlm::AV_DNS_DOMAIN_NAME, ntlm::AV_DNS_COMPUTER_NAME,
               ntlm::AV_TIMESTAMP, ntlm::AV_FLAGS, ntlm::AV_TARGET_NAME, ntlm::AV_CHANNEL_BINDINGS] {
        let v, ok = ntlm::av_get(ti, id);
        if ok {
            var t: u8[>..] = [];
            let _ = ntlm::utf8_of_utf16le(t, v);
        }
    }
    var out: u8[>..] = [];
    ntlm::av_copy_without(out, ti, ntlm::AV_TARGET_NAME);
}

fn parsers(m: const u8[:]) {
    let nf, ne = ntlm::parse_negotiate(m);
    let c, ce = ntlm::parse_challenge(m);
    if ce == ntlm::OK {
        probe_av(ntlm::field_bytes(m, c.target_info));
        var t: u8[>..] = [];
        let _ = ntlm::utf8_of_utf16le(t, ntlm::field_bytes(m, c.target_name));
    }
    let a, ae = ntlm::parse_authenticate(m);
    if ae == ntlm::OK {
        for f in [a.domain, a.user, a.workstation] {
            var t: u8[>..] = [];
            let _ = ntlm::utf8_of_utf16le(t, ntlm::field_bytes(m, f));
        }
        let nt = ntlm::field_bytes(m, a.nt);
        if nt.len >= 16 + 28 { probe_av(nt[16 + 28..]); }
    }
}

fn acceptor_auth(m0: const u8[:], forge: bool, variant: u8) {
    var acc = ntlm::acceptor("SERVER", "DOMAIN", "server.example.test", "example.test");
    if variant & 1 != 0 { let _ = ntlm::set_acceptor_spn(acc, "HTTP/server.example.test", variant & 2 != 0); }
    if variant & 4 != 0 { ntlm::set_acceptor_bindings(acc, "tls-server-end-point:0123456789abcdef", ntlm::CB_REQUIRED); }
    acc.require_mic = variant & 2 != 0;
    acc.allow_anonymous = variant & 4 != 0;
    var ch: u8[>..] = [];
    let e0 = ntlm::accept_negotiate_with(acc, NEG, SC, ntlm::filetime(NOW), ch);
    if e0 != ntlm::OK { return; }
    var m: u8[>..] = [];
    m.append(m0);
    if forge {
        let a, ae = ntlm::parse_authenticate(m);
        if ae == ntlm::OK && a.nt.len >= 16 + 28 + 4 {
            var user:   u8[>..] = [];
            var domain: u8[>..] = [];
            if ntlm::utf8_of_utf16le(user, ntlm::field_bytes(m, a.user)) &&
               ntlm::utf8_of_utf16le(domain, ntlm::field_bytes(m, a.domain)) {
                let key, kok = ntlm::ntowfv2(HASH, user, domain);
                if kok {
                    let proof = ntlm::nt_proof(key, SC, m[a.nt.off + 16..a.nt.off + a.nt.len]);
                    for i in 16 { m[a.nt.off + i] = proof[i]; }
                }
            }
        }
    }
    let e = ntlm::accept_authenticate(acc, m, NOW) { user, domain, h => for i in 16 { h[i] = HASH[i]; } true };
    if e == ntlm::OK {
        var w: u8[>..] = [];
        let _ = ntlm::wrap(acc.session, "hello", ntlm::sealed(acc.session), w);
        var u: u8[>..] = [];
        let _ = ntlm::unwrap(acc.session, w, u);
    }
}

fn initiator_auth(m: const u8[:], variant: u8) {
    let cred, ce = ntlm::credentials("User", "Domain", "Password");
    let want = if variant & 1 != 0 { ntlm::WANT_SIGN | ntlm::WANT_SEAL } else { 0 as u32 };
    var c = ntlm::initiator(cred, if variant & 2 != 0 { "HTTP/server.example.test" } else { "" }, want);
    if variant & 4 != 0 { ntlm::set_channel_bindings(c, "tls-server-end-point:0123456789abcdef"); }
    var neg: u8[>..] = [];
    if ntlm::negotiate(c, neg) != ntlm::OK { return; }
    var out: u8[>..] = [];
    let e = ntlm::authenticate_with(c, m, ntlm::filetime(NOW), CC, RK, variant & 8 != 0, out);
    if e == ntlm::OK {
        // Our own AUTHENTICATE parses.
        parsers(out);
    }
}

fn session(m: const u8[:], variant: u8) {
    let flags = ntlm::NEGOTIATE_SIGN | ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY | ntlm::NEGOTIATE_128 |
                (if variant & 1 != 0 { ntlm::NEGOTIATE_SEAL } else { 0 as u32 }) |
                (if variant & 2 != 0 { ntlm::NEGOTIATE_KEY_EXCH } else { 0 as u32 });
    var s = ntlm::new_session(flags, RK, variant & 4 != 0);
    var out: u8[>..] = [];
    let _ = ntlm::unwrap(s, m, out);
    if m.len >= 16 { let _ = ntlm::verify_mic(s, m[16..], m[..16]); }
}

fn spnego(m: const u8[:]) {
    let id, at, err = krb5::gss_unframe(m, krb5::SPNEGO_OID, false);
    if err == krb5::OK {
        let t, ok = asn1::read(m, at, m.len, true);
        if ok {
            let inner, iok = asn1::explicit(m, t, true);
            if iok {
                let list, oids, tok, mic, good = krb5::read_neg_init(m, inner);
                if good && tok.len > 0 { parsers(tok); }
            }
        }
    }
    let t, ok = asn1::parse(m, true);
    if ok {
        let inner, iok = asn1::explicit(m, t, true);
        if iok {
            let state, mech, resp, mic, good = krb5::read_neg_resp(m, inner);
            if good && resp.len > 0 { parsers(resp); }
        }
    }
    let nt, nok = krb5::negotiate_token(m);
    let sch, ht, hok = ntlm::http_token(m);
    if hok && ht.len > 0 { parsers(ht); }
}

fn spnego_accept(m: const u8[:]) {
    var acc = ntlm::acceptor("SERVER", "DOMAIN", "server.example.test", "example.test");
    var ch: u8[>..] = [];
    if ntlm::accept_negotiate_with(acc, NEG, SC, ntlm::filetime(NOW), ch) != ntlm::OK { return; }
    var ctx = krb5::spnego_ntlm_acceptor(acc);
    ctx.started = true;
    var out: u8[>..] = [];
    let done, e = krb5::spnego_ntlm_accept(ctx, m, NOW, out) { user, domain, h => for i in 16 { h[i] = HASH[i]; } true };
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let m = data[1..];
    let sel = data[0] % 6;
    let variant = data[0] / 6;
    if sel == 0 { parsers(m); }
    else if sel == 1 { acceptor_auth(m, variant & 8 != 0, variant); }
    else if sel == 2 { initiator_auth(m, variant); }
    else if sel == 3 { session(m, variant); }
    else if sel == 4 { spnego(m); }
    else { spnego_accept(m); }
    return 0;
}

fn main() {
    let h, ok = ntlm::nt_hash("Password");
    HASH = h;
    let cred, ce = ntlm::credentials("User", "Domain", "Password");
    var c = ntlm::initiator(cred, "HTTP/server.example.test", ntlm::WANT_SIGN | ntlm::WANT_SEAL);
    let e = ntlm::negotiate(c, NEG);
    assert(e == ntlm::OK);
}
