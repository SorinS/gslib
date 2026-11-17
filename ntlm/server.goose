// ntlm.server: the acceptor (server) side of NTLM ([MS-NLMP] §3.2): it
// answers a NEGOTIATE message with a CHALLENGE (a random server challenge;
// target info with our NetBIOS and DNS names and the time), then checks
// the AUTHENTICATE message. The user's NT hash comes from the caller's
// block, `{ user, domain, hash => ... }`: given the user and domain as the
// client sent them (UTF-8), it writes the 16-byte NT hash into `hash` and
// yields true, or yields false for a user it does not know.
//
// What accept_authenticate checks, in this order:
//   - the message: size, signature, type, every field inside it and none
//     overlapping;
//   - anonymous (no user, no NT response, LM empty or Z(1)): refused
//     unless allow_anonymous;
//   - no LM or NTLMv1: LM_KEY, an NT response of 24 bytes, or LM alone,
//     are ERR_NTLMV1;
//   - flags: UNICODE and extended session security; none of SIGN, SEAL,
//     KEY_EXCH, 128 or 56 that the CHALLENGE did not offer; none of SIGN,
//     SEAL, KEY_EXCH or 128 that the NEGOTIATE asked for and the
//     AUTHENTICATE dropped; with SIGN or SEAL, 128 (require_128);
//   - the NTLMv2 response: the block's NT hash, NTOWFv2 with the user and
//     domain as sent, NTProofStr over our server challenge and the
//     client's blob, compared in constant time (ERR_LOGON for an unknown
//     user and a wrong password alike);
//   - the blob: version 1, its AV_PAIRs well formed; its time within
//     `skew` seconds of ours (skew < 0: not checked) and its
//     MsvAvTimestamp, if any, the one we sent;
//   - channel bindings as cb_mode says; the target name, when `spn` is
//     set, ours (and present, with spn_required);
//   - the exported session key (KEY_EXCH), and the MIC over the three
//     messages when MsvAvFlags says there is one, or require_mic.
//
// The LMv2 response is not read when there is an NT response (clients
// send Z(24), or a real LMv2 that adds nothing).

namespace ntlm;

import std;
import entropy;
import ntlm.crypto;
import ntlm.messages;
import ntlm.session;

let ACC_NEW: i64 = 0;
let ACC_CHALLENGED: i64 = 1;
let ACC_DONE: i64 = 2;
let ACC_FAILED: i64 = 3;

struct Acceptor {
    // Policy.
    skew:            i64 = 300,      // seconds the client's time may differ from ours; < 0: not checked
    require_mic:     bool = false,   // refuse an AUTHENTICATE without a MIC
    allow_anonymous: bool = false,
    require_128:     bool = true,    // signing or sealing only with 128-bit keys
    cb_mode:         i64 = CB_SUPPORTED,
    has_cb:          bool = false,   // the channel's bindings are known (set_acceptor_bindings)
    cb_hash:         u8[16] = [0; 16],
    spn:             u8[..512] = [], // our service name ("HTTP/web.example.test"); empty: not checked
    spn_required:    bool = false,
    // Our names, for the target info.
    nb_computer:     u8[..64] = [],
    nb_domain:       u8[..64] = [],
    dns_computer:    u8[..256] = [],
    dns_domain:      u8[..256] = [],
    names_ok:        bool = true,    // false: a name given to acceptor() did not fit (ERR_ARG at the first step)
    // The exchange.
    state:           i64 = ACC_NEW,
    neg_flags:       u32 = 0,        // the NEGOTIATE's
    flags:           u32 = 0,        // the CHALLENGE's, then the AUTHENTICATE's
    server_challenge: u8[8] = [0; 8],
    timestamp:       u64 = 0,        // the MsvAvTimestamp we sent (0: none)
    negotiate:       u8[..1024] = [],
    challenge:       u8[..2048] = [],
    // The outcome.
    user:            u8[..256] = [],
    domain:          u8[..256] = [],
    workstation:     u8[..256] = [],
    anonymous:       bool = false,
    had_mic:         bool = false,   // the AUTHENTICATE carried a MIC (SPNEGO then wants mechListMIC)
    session:         Session = no_session(),
}

// An acceptor named by its NetBIOS computer and domain names and their DNS
// forms (any may be empty; a workgroup server has no domain).
fn acceptor(nb_computer: const u8[:], nb_domain: const u8[:], dns_computer: const u8[:], dns_domain: const u8[:]) -> Acceptor {
    var a = Acceptor { .. };
    if nb_computer.len > a.nb_computer.cap || nb_domain.len > a.nb_domain.cap || dns_computer.len > a.dns_computer.cap ||
       dns_domain.len > a.dns_domain.cap {
        // Names that do not fit, never cut: an acceptor whose first step
        // fails with ERR_ARG.
        a.names_ok = false;
        return a;
    }
    a.nb_computer.append(nb_computer);
    a.nb_domain.append(nb_domain);
    a.dns_computer.append(dns_computer);
    a.dns_domain.append(dns_domain);
    return a;
}

// The channel's bindings, as gss_channel_bindings_struct's application
// data ("tls-server-end-point:" and the hash, http.goose's
// tls_server_end_point), with cb_mode CB_SUPPORTED or CB_REQUIRED.
fn set_acceptor_bindings(a: Acceptor&, application_data: const u8[:], mode: i64) {
    a.cb_hash = bindings_hash(application_data);
    a.has_cb = true;
    a.cb_mode = mode;
}

fn set_acceptor_spn(a: Acceptor&, spn: const u8[:], required: bool) -> i64 {
    if spn.len > a.spn.cap { return ERR_ARG; }
    a.spn.clear();
    a.spn.append(spn);
    a.spn_required = required;
    return OK;
}

// The CHALLENGE for a NEGOTIATE, with a fresh server challenge and the
// time `now` (seconds since 1970).
fn accept_negotiate(a: Acceptor&, msg: const u8[:], now: i64, out: u8[>..]&) -> i64 {
    var sc: u8[8] = [0; 8];
    entropy::random_bytes(sc);
    return accept_negotiate_with(a, msg, sc, filetime(now), out);
}

// accept_negotiate with the server challenge and the FILETIME given.
fn accept_negotiate_with(a: Acceptor&, msg: const u8[:], server_challenge: const u8[:], time: u64, out: u8[>..]&) -> i64 {
    if !a.names_ok { a.state = ACC_FAILED; return ERR_ARG; }
    if a.state != ACC_NEW { a.state = ACC_FAILED; return ERR_STATE; }
    a.state = ACC_FAILED;
    if server_challenge.len != 8 { return ERR_ARG; }
    let nf, e = parse_negotiate(msg);
    if e != OK { return e; }
    if msg.len > a.negotiate.cap { return ERR_LIMIT; }
    // Only Unicode is spoken: a client offering OEM alone (curl) gets
    // UNICODE back and answers in it.
    var cf = NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_TARGET_INFO |
             NEGOTIATE_ALWAYS_SIGN | (if a.nb_domain.len > 0 { TARGET_TYPE_DOMAIN } else { TARGET_TYPE_SERVER });
    cf |= nf & (REQUEST_TARGET | NEGOTIATE_SIGN | NEGOTIATE_SEAL | NEGOTIATE_KEY_EXCH | NEGOTIATE_128 | NEGOTIATE_56 |
                NEGOTIATE_VERSION | NEGOTIATE_IDENTIFY);
    var ti: u8[>..] = [];
    var ok = true;
    if a.nb_domain.len > 0 { ok = ok && av_put_name(ti, AV_NB_DOMAIN_NAME, a.nb_domain); }
    if a.nb_computer.len > 0 { ok = ok && av_put_name(ti, AV_NB_COMPUTER_NAME, a.nb_computer); }
    if a.dns_domain.len > 0 { ok = ok && av_put_name(ti, AV_DNS_DOMAIN_NAME, a.dns_domain); }
    if a.dns_computer.len > 0 { ok = ok && av_put_name(ti, AV_DNS_COMPUTER_NAME, a.dns_computer); }
    var ts: u8[>..] = [];
    put64(ts, time);
    av_put(ti, AV_TIMESTAMP, ts);
    av_end(ti);
    var tname: u8[>..] = [];
    ok = ok && utf16le(tname, if a.nb_domain.len > 0 { a.nb_domain[..] } else { a.nb_computer[..] });
    if !ok { return ERR_ARG; }
    var c: u8[>..] = [];
    challenge_message(c, cf, server_challenge, tname, ti);
    if c.len > a.challenge.cap { return ERR_LIMIT; }
    a.negotiate.clear();
    a.negotiate.append(msg);
    a.challenge.clear();
    a.challenge.append(c);
    a.neg_flags = nf;
    a.flags = cf;
    for i in 8 { a.server_challenge[i] = server_challenge[i]; }
    a.timestamp = time;
    a.state = ACC_CHALLENGED;
    out.append(c);
    return OK;
}

// The acceptor as if it had sent `challenge` in answer to `negotiate`
// (which may be empty: then the NEGOTIATE's flags are not compared): for
// test vectors, and for a CHALLENGE made elsewhere.
fn adopt_challenge(a: Acceptor&, negotiate: const u8[:], challenge: const u8[:]) -> i64 {
    if !a.names_ok { return ERR_ARG; }
    if a.state != ACC_NEW { return ERR_STATE; }
    var nf: u32 = 0;
    if negotiate.len > 0 {
        let f, e = parse_negotiate(negotiate);
        if e != OK { return e; }
        nf = f;
    }
    let c, ce = parse_challenge(challenge);
    if ce != OK { return ce; }
    if negotiate.len > a.negotiate.cap || challenge.len > a.challenge.cap { return ERR_LIMIT; }
    a.negotiate.clear();
    a.negotiate.append(negotiate);
    a.challenge.clear();
    a.challenge.append(challenge);
    a.neg_flags = nf;
    a.flags = c.flags;
    a.server_challenge = c.server_challenge;
    a.timestamp = 0;
    let ts, has = av_get(field_bytes(challenge, c.target_info), AV_TIMESTAMP);
    if has { a.timestamp = get64(ts, 0); }
    a.state = ACC_CHALLENGED;
    return OK;
}

fn all_zero(b: const u8[:]) -> bool {
    for c in b { if c != 0 { return false; } }
    return true;
}

// Text of a UTF-16LE field into a fixed buffer; false if it is not
// UTF-16 or does not fit.
fn take_name(dst: u8[..256]&, b: const u8[:]) -> i64 {
    var t: u8[>..] = [];
    if !utf8_of_utf16le(t, b) { return ERR_MALFORMED; }
    if t.len > dst.cap { return ERR_LIMIT; }
    dst.clear();
    dst.append(t);
    return OK;
}

let STRONG_FLAGS: u32 = NEGOTIATE_SIGN | NEGOTIATE_SEAL | NEGOTIATE_KEY_EXCH | NEGOTIATE_128;

// The AUTHENTICATE message checked (see the top of this file). `now` is
// seconds since 1970. F is the NT hash lookup, `{ user, domain, hash =>
// ... }` yielding a bool. On OK the acceptor's user, domain, workstation
// and session are set; on any error the context is spent.
fn accept_authenticate<F>(a: Acceptor&, msg: const u8[:], now: i64) -> i64 {
    if a.state != ACC_CHALLENGED { a.state = ACC_FAILED; return ERR_STATE; }
    a.state = ACC_FAILED;
    let m, me = parse_authenticate(msg);
    if me != OK { return me; }
    let af = m.flags;
    let lm = field_bytes(msg, m.lm);
    let nt = field_bytes(msg, m.nt);
    // Anonymous.
    if m.user.len == 0 && nt.len == 0 && (lm.len == 0 || (lm.len == 1 && lm[0] == 0)) {
        if !a.allow_anonymous { return ERR_ANONYMOUS; }
        a.anonymous = true;
        a.user.clear();
        a.domain.clear();
        a.flags = af;
        a.session = no_session();
        a.state = ACC_DONE;
        return OK;
    }
    // LM and NTLMv1, never.
    if af & NEGOTIATE_LM_KEY != 0 || nt.len == 24 || (nt.len == 0 && lm.len > 0) { return ERR_NTLMV1; }
    if nt.len < 16 + 28 + 4 { return ERR_MALFORMED; }
    // Flags.
    if af & NEGOTIATE_UNICODE == 0 || af & NEGOTIATE_EXTENDED_SESSIONSECURITY == 0 { return ERR_FLAGS; }
    let checked = STRONG_FLAGS | NEGOTIATE_56 | NEGOTIATE_DATAGRAM;
    if af & checked & ~a.flags != 0 { return ERR_FLAGS; }
    if a.neg_flags & STRONG_FLAGS & a.flags & ~af != 0 { return ERR_FLAGS; }
    if a.require_128 && af & (NEGOTIATE_SIGN | NEGOTIATE_SEAL) != 0 && af & NEGOTIATE_128 == 0 { return ERR_FLAGS; }
    // Who.
    var user: u8[..256] = [];
    var domain: u8[..256] = [];
    var ws: u8[..256] = [];
    let ue = take_name(user, field_bytes(msg, m.user));
    if ue != OK { return ue; }
    let de = take_name(domain, field_bytes(msg, m.domain));
    if de != OK { return de; }
    let we = take_name(ws, field_bytes(msg, m.workstation));
    if we != OK { return we; }
    var h: u8[16] = [0; 16];
    let known = F(user[..], domain[..], h[..]);
    // The proof is computed for an unknown user too (a hash of zeros), so
    // the two failures take the same path.
    let key, kok = ntowfv2(h, user, domain);
    if !kok { return ERR_MALFORMED; }
    let blob = nt[16..];
    let proof = nt_proof(key, a.server_challenge, blob);
    let good = same(proof, nt[..16]);
    if !known || !good { return ERR_LOGON; }
    // The blob, now known to be the client's.
    if blob[0] != 1 || blob[1] != 1 { return ERR_MALFORMED; }
    let time = get64(blob, 8);
    let av = blob[28..];
    let ae = av_check(av);
    if ae != OK { return ae; }
    if a.skew >= 0 {
        let ours = filetime(now);
        let d = if time > ours { time - ours } else { ours - time };
        if d > (a.skew as u64) * 10000000 { return ERR_TIMESTAMP; }
    }
    let ts, has_ts = av_get(av, AV_TIMESTAMP);
    if has_ts && a.timestamp != 0 && get64(ts, 0) != a.timestamp { return ERR_TIMESTAMP; }
    // Channel bindings.
    let cb, has_cb = av_get(av, AV_CHANNEL_BINDINGS);
    let sent_cb = has_cb && !all_zero(cb);
    if a.cb_mode == CB_REQUIRED {
        if !a.has_cb || !sent_cb || !same(cb, a.cb_hash) { return ERR_BINDINGS; }
    } else if a.cb_mode == CB_SUPPORTED && a.has_cb && sent_cb && !same(cb, a.cb_hash) {
        return ERR_BINDINGS;
    }
    // The target name.
    if a.spn.len > 0 {
        let tn, has_tn = av_get(av, AV_TARGET_NAME);
        if has_tn && tn.len > 0 {
            var t: u8[>..] = [];
            if !utf8_of_utf16le(t, tn) || !eq_fold_ascii(t, a.spn) { return ERR_TARGET; }
        } else if a.spn_required {
            return ERR_TARGET;
        }
    }
    // The keys.
    let sbk = session_base_key(key, proof);
    var exported: u8[16] = sbk;
    let ek = field_bytes(msg, m.key);
    if af & NEGOTIATE_KEY_EXCH != 0 && ek.len == 16 {
        exported = rc4k(sbk, ek);
    } else if af & NEGOTIATE_KEY_EXCH != 0 && af & (NEGOTIATE_SIGN | NEGOTIATE_SEAL) != 0 {
        return ERR_MALFORMED;
    }
    // The MIC.
    let fl, has_fl = av_get(av, AV_FLAGS);
    let mic_flag = has_fl && get32(fl, 0) & AVF_MIC != 0;
    if mic_flag || a.require_mic {
        if !mic_flag || !m.has_mic { return ERR_MIC; }
        var z: u8[>..] = [];
        z.append(msg);
        for i in 16 { z[MIC_OFFSET + i] = 0; }
        let want = compute_mic(exported, a.negotiate, a.challenge, z);
        if !same(want, msg[MIC_OFFSET..MIC_OFFSET + 16]) { return ERR_MIC; }
    }
    a.user = user;
    a.domain = domain;
    a.workstation = ws;
    a.anonymous = false;
    a.had_mic = mic_flag;
    a.flags = af;
    a.session = new_session(af, exported, false);
    a.state = ACC_DONE;
    return OK;
}

fn accepted(a: const Acceptor&) -> bool { a.state == ACC_DONE }
