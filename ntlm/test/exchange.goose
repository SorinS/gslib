// An initiator and an acceptor in memory: the exchange, signing and
// sealing both ways, and every hostile case: wrong passwords and unknown
// users, a wrong or missing MIC, old and replayed messages, channel
// bindings and target names that differ, NTLMv1 and LM refused,
// downgraded flags both ways, truncated and oversized messages, offsets
// and lengths out of range or overlapping, AV_PAIR lists without
// MsvAvEOL or with a pair twice or of a wrong size, every single byte of
// an AUTHENTICATE message changed, and anonymous logons.
import std;
import os;
import gslib from "../..";
import gslib.ntlm;
import gslib.ntlm.crypto;
import gslib.ntlm.messages;
import gslib.ntlm.session;
import gslib.ntlm.client;
import gslib.ntlm.server;
import tv;

let NOW = tv::NOW;
let SPN = "HTTP/web.example.test";

fn alice() -> ntlm::Credentials {
    let c, e = ntlm::credentials("alice", "EXAMPLE", "correct horse");
    return c;
}

fn server() -> ntlm::Acceptor { ntlm::acceptor("WEB", "EXAMPLE", "web.example.test", "example.test") }

// The NT hash lookup the acceptors use: alice in EXAMPLE (any case).
fn lookup(user: const u8[:], domain: const u8[:], h: u8[:]) -> bool {
    if !ntlm::eq_fold_ascii(user, "alice") { return false; }
    let nth, ok = ntlm::nt_hash("correct horse");
    for i in 16 { h[i] = nth[i]; }
    return true;
}

// The three messages of an exchange; the error of the client's step.
fn messages(cli: ntlm::Initiator&, srv: ntlm::Acceptor&, t1: u8[>..]&, t2: u8[>..]&, t3: u8[>..]&) -> i64 {
    var e = ntlm::negotiate(cli, t1);
    if e != ntlm::OK { return e; }
    e = ntlm::accept_negotiate(srv, t1, NOW, t2);
    if e != ntlm::OK { return e; }
    return ntlm::authenticate(cli, t2, NOW, t3);
}

fn accept(srv: ntlm::Acceptor&, t3: const u8[:], now: i64) -> i64 {
    return ntlm::accept_authenticate(srv, t3, now) { user, domain, h => lookup(user, domain, h) };
}

// A whole exchange; the acceptor's error.
fn run(cli: ntlm::Initiator&, srv: ntlm::Acceptor&) -> i64 {
    var t1: u8[>..] = [];
    var t2: u8[>..] = [];
    var t3: u8[>..] = [];
    let e = messages(cli, srv, t1, t2, t3);
    if e != ntlm::OK { return 100 + e; }
    return accept(srv, t3, NOW);
}

fn good() {
    var cli = ntlm::initiator(alice(), SPN, ntlm::WANT_SEAL);
    var srv = server();
    tv::check_err("exchange", run(cli, srv), ntlm::OK);
    tv::check("both done", ntlm::established(cli) && ntlm::accepted(srv));
    tv::check("user and domain", srv.user[..] == "alice" && srv.domain[..] == "EXAMPLE");
    tv::check("same exported key", cli.session.exported == srv.session.exported);
    tv::check("sealing negotiated", cli.flags & ntlm::NEGOTIATE_SEAL != 0 && srv.flags & ntlm::NEGOTIATE_SEAL != 0);
    tv::check("key exchange", cli.flags & ntlm::NEGOTIATE_KEY_EXCH != 0);
    // Messages both ways, in turn and in runs.
    for i in 5 {
        var w: u8[>..] = [];
        let msg = str("client message ", i);
        tv::check_err("wrap c2s", ntlm::wrap(cli.session, msg, true, w), ntlm::OK);
        tv::check("sealed", find(w, "client message") < 0);
        var p: u8[>..] = [];
        tv::check_err("unwrap c2s", ntlm::unwrap(srv.session, w, p), ntlm::OK);
        tv::check("c2s text", p[..] == msg[..]);
        var w2: u8[>..] = [];
        tv::check_err("wrap s2c", ntlm::wrap(srv.session, "reply", true, w2), ntlm::OK);
        var p2: u8[>..] = [];
        tv::check_err("unwrap s2c", ntlm::unwrap(cli.session, w2, p2), ntlm::OK);
        tv::check("s2c text", p2[..] == "reply");
    }
    var m: u8[>..] = [];
    tv::check_err("get_mic", ntlm::get_mic(cli.session, "data", m), ntlm::OK);
    tv::check_err("verify_mic", ntlm::verify_mic(srv.session, "data", m), ntlm::OK);
    // A replayed signature (out of sequence), a changed message, a token
    // from the wrong direction.
    tv::check_err("replayed MIC", ntlm::verify_mic(srv.session, "data", m), ntlm::ERR_SIGNATURE);
    var w: u8[>..] = [];
    ntlm::wrap(cli.session, "pay 10", true, w);
    w[w.len - 1] ^= 1;
    var p: u8[>..] = [];
    tv::check_err("changed sealed message", ntlm::unwrap(srv.session, w, p), ntlm::ERR_SIGNATURE);
    tv::check("nothing out on failure", p.len == 0);
    // The refused MIC and token left the incoming state as it was: the
    // real message still unwraps.
    w[w.len - 1] ^= 1;
    tv::check_err("good token after refused ones", ntlm::unwrap(srv.session, w, p), ntlm::OK);
    tv::check("its text", p[..] == "pay 10");
    p.clear();
    var own: u8[>..] = [];
    ntlm::wrap(cli.session, "loop", true, own);
    tv::check_err("own token back", ntlm::unwrap(cli.session, own, p), ntlm::ERR_SIGNATURE);
    tv::check_err("short token", ntlm::unwrap(srv.session, "short", p), ntlm::ERR_SIGNATURE);
    var after: u8[>..] = [];
    ntlm::wrap(srv.session, "still in step", true, after);
    tv::check_err("client in step after its own token refused", ntlm::unwrap(cli.session, after, p), ntlm::OK);
    tv::check("sealed session", ntlm::sealed(cli.session) && ntlm::sealed(srv.session));

    // Integrity only: messages signed, not sealed.
    var c2 = ntlm::initiator(alice(), SPN, ntlm::WANT_SIGN);
    var s2 = server();
    tv::check_err("sign-only exchange", run(c2, s2), ntlm::OK);
    var sw: u8[>..] = [];
    var refused: u8[>..] = [];
    tv::check_err("confidentiality asked, not negotiated", ntlm::wrap(c2.session, "secret", true, refused), ntlm::ERR_NO_SESSION);
    tv::check("nothing wrapped", refused.len == 0 && !ntlm::sealed(c2.session));
    ntlm::wrap(c2.session, "in the clear", false, sw);
    tv::check("signed, not sealed", find(sw, "in the clear") == 16);
    var sp: u8[>..] = [];
    tv::check_err("unwrap signed", ntlm::unwrap(s2.session, sw, sp), ntlm::OK);
    // A DOMAIN\user name, and a user name in another case.
    let c3c, c3e = ntlm::credentials("example\\ALICE", "", "correct horse");
    var c3 = ntlm::initiator(c3c, "", 0);
    var s3 = server();
    tv::check_err("DOMAIN\\user, upper case", run(c3, s3), ntlm::OK);
    tv::check("user as sent", s3.user[..] == "ALICE" && s3.domain[..] == "example");
    // Credentials from the NT hash alone.
    let nth, hok = ntlm::nt_hash("correct horse");
    let c4c, c4e = ntlm::credentials_hash("alice", "EXAMPLE", nth);
    var c4 = ntlm::initiator(c4c, SPN, 0);
    var s4 = server();
    tv::check_err("NT hash credentials", run(c4, s4), ntlm::OK);
}

fn logon_failures() {
    let bad, be = ntlm::credentials("alice", "EXAMPLE", "wrong");
    var c1 = ntlm::initiator(bad, SPN, 0);
    var s1 = server();
    tv::check_err("wrong password", run(c1, s1), ntlm::ERR_LOGON);
    tv::check("no user on failure", s1.user.len == 0 && !ntlm::accepted(s1));
    let who, we = ntlm::credentials("mallory", "EXAMPLE", "correct horse");
    var c2 = ntlm::initiator(who, SPN, 0);
    var s2 = server();
    tv::check_err("unknown user", run(c2, s2), ntlm::ERR_LOGON);
    // The domain is part of NTOWFv2: another domain is another key.
    let od, oe = ntlm::credentials("alice", "OTHER", "correct horse");
    var c3 = ntlm::initiator(od, SPN, 0);
    var s3 = server();
    var asked: u8[>..] = [];
    var t1: u8[>..] = [];
    var t2: u8[>..] = [];
    var t3: u8[>..] = [];
    messages(c3, s3, t1, t2, t3);
    let e = ntlm::accept_authenticate(s3, t3, NOW) { user, domain, h => asked.append(domain); lookup(user, domain, h) };
    tv::check_err("another domain", e, ntlm::OK);
    tv::check("domain given to the lookup", asked[..] == "OTHER");
}

fn mic_and_time() {
    // A MIC changed.
    var cli = ntlm::initiator(alice(), SPN, 0);
    var srv = server();
    var t1: u8[>..] = [];
    var t2: u8[>..] = [];
    var t3: u8[>..] = [];
    messages(cli, srv, t1, t2, t3);
    var bad = copy(t3);
    bad[ntlm::MIC_OFFSET + 3] ^= 0x40;
    tv::check_err("wrong MIC", accept(srv, bad, NOW), ntlm::ERR_MIC);
    tv::check_err("context spent after a failure", accept(srv, t3, NOW), ntlm::ERR_STATE);

    // The NEGOTIATE changed in transit (a flag stripped): the MIC covers it.
    var c2 = ntlm::initiator(alice(), SPN, ntlm::WANT_SEAL);
    var s2 = server();
    var n1: u8[>..] = [];
    ntlm::negotiate(c2, n1);
    var n1x = copy(n1);
    n1x[15] &= 0xbf;    // KEY_EXCH (0x40000000) off
    var n2: u8[>..] = [];
    tv::check_err("server takes the stripped NEGOTIATE", ntlm::accept_negotiate(s2, n1x, NOW, n2), ntlm::OK);
    var n3: u8[>..] = [];
    tv::check_err("client answers", ntlm::authenticate(c2, n2, NOW, n3), ntlm::OK);
    tv::check_err("MIC catches the changed NEGOTIATE", accept(s2, n3, NOW), ntlm::ERR_MIC);

    // No MIC, with require_mic; and without (an older client's message).
    var c3 = ntlm::initiator(alice(), SPN, 0);
    var s3 = server();
    s3.require_mic = true;
    var m1: u8[>..] = [];
    ntlm::negotiate(c3, m1);
    var m2: u8[>..] = [];
    ntlm::accept_negotiate(s3, m1, NOW, m2);
    var m3: u8[>..] = [];
    tv::check_err("client without MIC", ntlm::authenticate_with(c3, m2, ntlm::filetime(NOW), "\x01\x02\x03\x04\x05\x06\x07\x08",
                                                                  "0123456789abcdef", false, m3), ntlm::OK);
    tv::check_err("require_mic", accept(s3, m3, NOW), ntlm::ERR_MIC);
    var c4 = ntlm::initiator(alice(), SPN, 0);
    var s4 = server();
    var k1: u8[>..] = [];
    ntlm::negotiate(c4, k1);
    var k2: u8[>..] = [];
    ntlm::accept_negotiate(s4, k1, NOW, k2);
    var k3: u8[>..] = [];
    ntlm::authenticate_with(c4, k2, ntlm::filetime(NOW), "\x01\x02\x03\x04\x05\x06\x07\x08", "0123456789abcdef", false, k3);
    tv::check_err("no MIC, not required", accept(s4, k3, NOW), ntlm::OK);

    // Time: the server's clock 10 minutes on; then a skew of an hour.
    var c5 = ntlm::initiator(alice(), SPN, 0);
    var s5 = server();
    var x1: u8[>..] = [];
    var x2: u8[>..] = [];
    var x3: u8[>..] = [];
    messages(c5, s5, x1, x2, x3);
    tv::check_err("old timestamp", accept(s5, x3, NOW + 600), ntlm::ERR_TIMESTAMP);
    var c6 = ntlm::initiator(alice(), SPN, 0);
    var s6 = server();
    s6.skew = 3600;
    var y1: u8[>..] = [];
    var y2: u8[>..] = [];
    var y3: u8[>..] = [];
    messages(c6, s6, y1, y2, y3);
    tv::check_err("within a wider skew", accept(s6, y3, NOW + 600), ntlm::OK);

    // A replay: the same AUTHENTICATE to another context (another server
    // challenge), and to the finished one.
    var s7 = server();
    var z2: u8[>..] = [];
    ntlm::accept_negotiate(s7, y1, NOW, z2);
    tv::check_err("replayed AUTHENTICATE", accept(s7, y3, NOW), ntlm::ERR_LOGON);
    tv::check_err("finished context", accept(s6, y3, NOW), ntlm::ERR_STATE);

    // A blob whose MsvAvTimestamp is not the one the server sent (the
    // client signs a target info with another time).
    var c8 = ntlm::initiator(alice(), SPN, 0);
    var s8 = server();
    var w1: u8[>..] = [];
    ntlm::negotiate(c8, w1);
    var w2: u8[>..] = [];
    ntlm::accept_negotiate(s8, w1, NOW, w2);
    // Rewrite the challenge's timestamp before the client sees it.
    let ch, ce = ntlm::parse_challenge(w2);
    let ti = ntlm::field_bytes(w2, ch.target_info);
    var p = ch.target_info.off;
    while p + 4 <= w2.len {
        let id = ntlm::get16(w2, p);
        let l = ntlm::get16(w2, p + 2) as i64;
        if id == ntlm::AV_TIMESTAMP { w2[p + 4] ^= 1; break; }
        if id == ntlm::AV_EOL { break; }
        p += 4 + l;
    }
    var w3: u8[>..] = [];
    ntlm::authenticate(c8, w2, NOW, w3);
    tv::check_err("timestamp not the one sent", accept(s8, w3, NOW), ntlm::ERR_TIMESTAMP);
}

fn bindings_and_target() {
    // Matching bindings.
    var c1 = ntlm::initiator(alice(), SPN, 0);
    ntlm::set_channel_bindings(c1, "tls-server-end-point:abc");
    var s1 = server();
    ntlm::set_acceptor_bindings(s1, "tls-server-end-point:abc", ntlm::CB_REQUIRED);
    tv::check_err("bindings match", run(c1, s1), ntlm::OK);
    // Another channel (a relay to another TLS server).
    var c2 = ntlm::initiator(alice(), SPN, 0);
    ntlm::set_channel_bindings(c2, "tls-server-end-point:abd");
    var s2 = server();
    ntlm::set_acceptor_bindings(s2, "tls-server-end-point:abc", ntlm::CB_SUPPORTED);
    tv::check_err("bindings differ", run(c2, s2), ntlm::ERR_BINDINGS);
    // None sent: refused when required, taken when only supported.
    var c3 = ntlm::initiator(alice(), SPN, 0);
    var s3 = server();
    ntlm::set_acceptor_bindings(s3, "tls-server-end-point:abc", ntlm::CB_REQUIRED);
    tv::check_err("bindings required, none sent", run(c3, s3), ntlm::ERR_BINDINGS);
    var c4 = ntlm::initiator(alice(), SPN, 0);
    var s4 = server();
    ntlm::set_acceptor_bindings(s4, "tls-server-end-point:abc", ntlm::CB_SUPPORTED);
    tv::check_err("bindings supported, none sent", run(c4, s4), ntlm::OK);
    // Bindings sent to a server without TLS: not checked.
    var c5 = ntlm::initiator(alice(), SPN, 0);
    ntlm::set_channel_bindings(c5, "tls-server-end-point:abc");
    var s5 = server();
    tv::check_err("bindings to a plain server", run(c5, s5), ntlm::OK);

    // The target name.
    var c6 = ntlm::initiator(alice(), "HTTP/other.example.test", 0);
    var s6 = server();
    ntlm::set_acceptor_spn(s6, SPN, false);
    tv::check_err("another SPN", run(c6, s6), ntlm::ERR_TARGET);
    var c7 = ntlm::initiator(alice(), "http/WEB.example.TEST", 0);
    var s7 = server();
    ntlm::set_acceptor_spn(s7, SPN, true);
    tv::check_err("SPN in another case", run(c7, s7), ntlm::OK);
    var c8 = ntlm::initiator(alice(), "", 0);
    var s8 = server();
    ntlm::set_acceptor_spn(s8, SPN, true);
    tv::check_err("SPN required, none sent", run(c8, s8), ntlm::ERR_TARGET);
    var c9 = ntlm::initiator(alice(), "", 0);
    var s9 = server();
    ntlm::set_acceptor_spn(s9, SPN, false);
    tv::check_err("SPN not required, none sent", run(c9, s9), ntlm::OK);
}

// A server challenged, then an AUTHENTICATE made by hand.
fn challenged(srv: ntlm::Acceptor&, t1: u8[>..]&) -> ntlm::Challenge {
    var cli = ntlm::initiator(alice(), SPN, 0);
    ntlm::negotiate(cli, t1);
    var t2: u8[>..] = [];
    ntlm::accept_negotiate(srv, t1, NOW, t2);
    let c, e = ntlm::parse_challenge(t2);
    return c;
}

fn utf16(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    ntlm::utf16le(out, s);
    return out;
}

fn ntlmv1_refused() {
    let flags = ntlm::NEGOTIATE_UNICODE | ntlm::NEGOTIATE_NTLM | ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY;
    var z24: u8[24] = [0; 24];
    for i in 24 { z24[i] = (i * 7) as! u8; }
    // An NTLMv1 (or NTLM2 session) response: 24 bytes.
    var s1 = server();
    var t1: u8[>..] = [];
    challenged(s1, t1);
    var a1: u8[>..] = [];
    ntlm::authenticate_message(a1, flags, z24, z24, utf16("EXAMPLE"), utf16("alice"), "", "", false);
    tv::check_err("NTLMv1 response", accept(s1, a1, NOW), ntlm::ERR_NTLMV1);
    // LM alone.
    var s2 = server();
    challenged(s2, t1);
    var a2: u8[>..] = [];
    ntlm::authenticate_message(a2, flags, z24, "", utf16("EXAMPLE"), utf16("alice"), "", "", false);
    tv::check_err("LM response alone", accept(s2, a2, NOW), ntlm::ERR_NTLMV1);
    // LM_KEY asked for.
    var s3 = server();
    challenged(s3, t1);
    var big: u8[>..] = [];
    for i in 80 { big.push(i as! u8); }
    var a3: u8[>..] = [];
    ntlm::authenticate_message(a3, flags | ntlm::NEGOTIATE_LM_KEY, z24, big, utf16("EXAMPLE"), utf16("alice"), "", "", false);
    tv::check_err("LM_KEY", accept(s3, a3, NOW), ntlm::ERR_NTLMV1);
    // An NT response too short to be NTLMv2.
    var s4 = server();
    challenged(s4, t1);
    var a4: u8[>..] = [];
    ntlm::authenticate_message(a4, flags, "", big[..40], utf16("EXAMPLE"), utf16("alice"), "", "", false);
    tv::check_err("short NT response", accept(s4, a4, NOW), ntlm::ERR_MALFORMED);
    // The client never makes one: there is no API for it, and its LM
    // response is Z(24) when the server sent a timestamp.
    var cli = ntlm::initiator(alice(), SPN, 0);
    var srv = server();
    var x1: u8[>..] = [];
    var x2: u8[>..] = [];
    var x3: u8[>..] = [];
    messages(cli, srv, x1, x2, x3);
    let m, me = ntlm::parse_authenticate(x3);
    tv::check("LM is Z(24) with a timestamp", me == ntlm::OK && m.lm.len == 24 && ntlm::all_zero(ntlm::field_bytes(x3, m.lm)));
    tv::check("NT response is NTLMv2", m.nt.len > 24);
}

// Sets a 32-bit field of a message.
fn set32(m: u8[>..]&, at: i64, v: u32) { for i in 4 { m[at + i] = (v >> (8 * i)) as! u8; } }

fn downgrades() {
    // The client's view: the CHALLENGE without extended session security,
    // without UNICODE, without 128, without SEAL that was asked for.
    let strip: u32[4] = [ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY, ntlm::NEGOTIATE_UNICODE, ntlm::NEGOTIATE_128, ntlm::NEGOTIATE_SEAL];
    for f in strip {
        var cli = ntlm::initiator(alice(), SPN, ntlm::WANT_SEAL);
        var srv = server();
        var t1: u8[>..] = [];
        ntlm::negotiate(cli, t1);
        var t2: u8[>..] = [];
        ntlm::accept_negotiate(srv, t1, NOW, t2);
        set32(t2, 20, ntlm::get32(t2, 20) & ~f);
        var t3: u8[>..] = [];
        tv::check_err(str("client refuses a CHALLENGE without flag ", f), ntlm::authenticate(cli, t2, NOW, t3), ntlm::ERR_FLAGS);
    }
    // The acceptor's view: AUTHENTICATE flags changed (before the MIC is
    // looked at): UNICODE or ESS gone, SEAL the CHALLENGE did not offer,
    // KEY_EXCH or 128 the NEGOTIATE asked for and the AUTHENTICATE lost.
    let changes: u32[5] = [ntlm::NEGOTIATE_UNICODE, ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY, ntlm::NEGOTIATE_KEY_EXCH,
                           ntlm::NEGOTIATE_128, ntlm::NEGOTIATE_SEAL];
    for f in changes {
        var cli = ntlm::initiator(alice(), SPN, 0);
        var srv = server();
        var t1: u8[>..] = [];
        var t2: u8[>..] = [];
        var t3: u8[>..] = [];
        messages(cli, srv, t1, t2, t3);
        set32(t3, 60, ntlm::get32(t3, 60) ^ f);
        tv::check_err(str("acceptor refuses AUTHENTICATE flags changed by ", f), accept(srv, t3, NOW), ntlm::ERR_FLAGS);
    }
    // 56-bit without 128, with signing: refused (require_128).
    var cli = ntlm::initiator(alice(), SPN, 0);
    var srv = server();
    var t1: u8[>..] = [];
    var t2: u8[>..] = [];
    var t3: u8[>..] = [];
    messages(cli, srv, t1, t2, t3);
    srv.flags |= ntlm::NEGOTIATE_56;
    set32(t3, 60, (ntlm::get32(t3, 60) & ~ntlm::NEGOTIATE_128) | ntlm::NEGOTIATE_56);
    srv.neg_flags &= ~ntlm::NEGOTIATE_128;
    tv::check_err("56-bit refused", accept(srv, t3, NOW), ntlm::ERR_FLAGS);
}

fn malformed() {
    var cli = ntlm::initiator(alice(), SPN, ntlm::WANT_SEAL);
    var srv = server();
    var t1: u8[>..] = [];
    var t2: u8[>..] = [];
    var t3: u8[>..] = [];
    messages(cli, srv, t1, t2, t3);

    // Every prefix of each message: an error, never OK.
    var ok_prefix = 0;
    for n in t1.len {
        let f, e = ntlm::parse_negotiate(t1[..n]);
        if e == ntlm::OK && n < 16 { ok_prefix++; }
    }
    for n in t2.len {
        let c, e = ntlm::parse_challenge(t2[..n]);
        if e == ntlm::OK { ok_prefix++; }
    }
    for n in t3.len {
        var s = server();
        ntlm::adopt_challenge(s, t1, t2);
        if accept(s, t3[..n], NOW) == ntlm::OK { ok_prefix++; }
    }
    tv::check("no truncated message accepted", ok_prefix == 0);
    // The wrong type and signature.
    let x, xe = ntlm::parse_challenge(t1);
    tv::check_err("NEGOTIATE as CHALLENGE", xe, ntlm::ERR_MALFORMED);
    var sig = copy(t2);
    sig[0] = 'X';
    let y, ye = ntlm::parse_challenge(sig);
    tv::check_err("bad signature", ye, ntlm::ERR_MALFORMED);
    // Oversized.
    var huge = copy(t3);
    huge.resize(ntlm::MAX_MESSAGE + 1, 0);
    var s0 = server();
    ntlm::adopt_challenge(s0, t1, t2);
    tv::check_err("oversized AUTHENTICATE", accept(s0, huge, NOW), ntlm::ERR_LIMIT);
    var big_neg: u8[>..] = [];
    big_neg.append(t1);
    big_neg.resize(2000, 0);
    var sb = server();
    var bo: u8[>..] = [];
    tv::check_err("NEGOTIATE larger than kept", ntlm::accept_negotiate(sb, big_neg, NOW, bo), ntlm::ERR_LIMIT);

    // Offsets and lengths: past the end, into the fixed part, overlapping.
    let a, ae = ntlm::parse_authenticate(t3);
    var past = copy(t3);
    set32(past, 20 + 4, (t3.len - 10) as! u32);     // NT response running past the end
    let p1, pe1 = ntlm::parse_authenticate(past);
    tv::check_err("NT field past the end", pe1, ntlm::ERR_MALFORMED);
    var into = copy(t3);
    set32(into, 36 + 4, 40);                          // user name inside the fixed part
    let p2, pe2 = ntlm::parse_authenticate(into);
    tv::check_err("field in the fixed part", pe2, ntlm::ERR_MALFORMED);
    var lap = copy(t3);
    set32(lap, 36 + 4, a.domain.off as! u32);         // user over the domain
    let p3, pe3 = ntlm::parse_authenticate(lap);
    tv::check_err("overlapping fields", pe3, ntlm::ERR_MALFORMED);
    var len = copy(t3);
    len[20] = 0xff;
    len[21] = 0xff;                                   // NT length 65535
    let p4, pe4 = ntlm::parse_authenticate(len);
    tv::check_err("length past the end", pe4, ntlm::ERR_MALFORMED);
    var huge_off = copy(t3);
    set32(huge_off, 36 + 4, 0xffffffff);
    let p5, pe5 = ntlm::parse_authenticate(huge_off);
    tv::check_err("offset 2^32-1", pe5, ntlm::ERR_MALFORMED);
    // The CHALLENGE's target info out of range, for the client.
    var tib = copy(t2);
    set32(tib, 44, (t2.len + 1) as! u32);
    let c5, ce5 = ntlm::parse_challenge(tib);
    tv::check_err("target info past the end", ce5, ntlm::ERR_MALFORMED);

    // Every single byte of the AUTHENTICATE changed: never accepted (the
    // MIC covers the whole message).
    var taken = 0;
    for i in t3.len {
        var s = server();
        ntlm::adopt_challenge(s, t1, t2);
        s.timestamp = srv.timestamp;
        var m = copy(t3);
        m[i] ^= 0x01;
        if accept(s, m, NOW) == ntlm::OK { taken++; print("      byte ", i, " changed was accepted"); }
    }
    tv::check("no changed AUTHENTICATE accepted", taken == 0);
}

fn av_pairs() {
    var ti: u8[>..] = [];
    ntlm::av_put_name(ti, ntlm::AV_NB_DOMAIN_NAME, "EXAMPLE");
    var good = copy(ti);
    ntlm::av_end(good);
    tv::check_err("good list", ntlm::av_check(good), ntlm::OK);
    tv::check_err("missing EOL", ntlm::av_check(ti), ntlm::ERR_AV_PAIRS);
    tv::check_err("empty list", ntlm::av_check(""), ntlm::ERR_AV_PAIRS);
    var cut = copy(good);
    cut.resize(cut.len - 2, 0);
    tv::check_err("EOL cut short", ntlm::av_check(cut), ntlm::ERR_AV_PAIRS);
    var twice = copy(ti);
    twice.append(ti);
    ntlm::av_end(twice);
    tv::check_err("a pair twice", ntlm::av_check(twice), ntlm::ERR_AV_PAIRS);
    var long: u8[>..] = [];
    ntlm::av_put(long, ntlm::AV_NB_COMPUTER_NAME, "AB");
    long[2] = 200;                                    // longer than what follows
    ntlm::av_end(long);
    tv::check_err("pair past the end", ntlm::av_check(long), ntlm::ERR_AV_PAIRS);
    var ts: u8[>..] = [];
    ntlm::av_put(ts, ntlm::AV_TIMESTAMP, "1234");
    ntlm::av_end(ts);
    tv::check_err("timestamp of 4 bytes", ntlm::av_check(ts), ntlm::ERR_AV_PAIRS);
    var cb: u8[>..] = [];
    ntlm::av_put(cb, ntlm::AV_CHANNEL_BINDINGS, "0123456789");
    ntlm::av_end(cb);
    tv::check_err("bindings of 10 bytes", ntlm::av_check(cb), ntlm::ERR_AV_PAIRS);
    var fl: u8[>..] = [];
    ntlm::av_put(fl, ntlm::AV_FLAGS, "12345");
    ntlm::av_end(fl);
    tv::check_err("flags of 5 bytes", ntlm::av_check(fl), ntlm::ERR_AV_PAIRS);
    var sh: u8[>..] = [];
    ntlm::av_put(sh, ntlm::AV_SINGLE_HOST, "short");
    ntlm::av_end(sh);
    tv::check_err("single host too short", ntlm::av_check(sh), ntlm::ERR_AV_PAIRS);
    var odd: u8[>..] = [];
    ntlm::av_put(odd, ntlm::AV_DNS_DOMAIN_NAME, "abc");
    ntlm::av_end(odd);
    tv::check_err("name of odd length", ntlm::av_check(odd), ntlm::ERR_AV_PAIRS);
    var eol: u8[>..] = [];
    ntlm::av_put(eol, ntlm::AV_EOL, "xx");
    tv::check_err("EOL with a value", ntlm::av_check(eol), ntlm::ERR_AV_PAIRS);
    // Many empty unknown pairs (a "loop" of zero-length pairs): bounded.
    var many: u8[>..] = [];
    for i in 300 { ntlm::av_put(many, 0x7f00, ""); }
    ntlm::av_end(many);
    tv::check_err("too many pairs", ntlm::av_check(many), ntlm::ERR_AV_PAIRS);
    var unknown: u8[>..] = [];
    ntlm::av_put(unknown, 0x7f00, "x");
    ntlm::av_put(unknown, 0x7f00, "y");
    ntlm::av_end(unknown);
    tv::check_err("unknown pairs, twice too", ntlm::av_check(unknown), ntlm::OK);

    // A CHALLENGE whose target info has no MsvAvEOL: the client refuses.
    var cli = ntlm::initiator(alice(), SPN, 0);
    var t1: u8[>..] = [];
    ntlm::negotiate(cli, t1);
    var t2: u8[>..] = [];
    ntlm::challenge_message(t2, ntlm::NEGOTIATE_UNICODE | ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY | ntlm::NEGOTIATE_128 |
                            ntlm::NEGOTIATE_TARGET_INFO, "\x01\x02\x03\x04\x05\x06\x07\x08", "", ti);
    var t3: u8[>..] = [];
    tv::check_err("client: target info without EOL", ntlm::authenticate(cli, t2, NOW, t3), ntlm::ERR_AV_PAIRS);
    // A CHALLENGE with no target info at all: NTLMv2 still, with our pairs.
    var c2 = ntlm::initiator(alice(), SPN, 0);
    var u1: u8[>..] = [];
    ntlm::negotiate(c2, u1);
    var u2: u8[>..] = [];
    ntlm::challenge_message(u2, ntlm::NEGOTIATE_UNICODE | ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY | ntlm::NEGOTIATE_128 |
                            ntlm::NEGOTIATE_SIGN | ntlm::NEGOTIATE_KEY_EXCH, "\x01\x02\x03\x04\x05\x06\x07\x08", "", "");
    var u3: u8[>..] = [];
    tv::check_err("client: no target info", ntlm::authenticate(c2, u2, NOW, u3), ntlm::OK);
    var s2 = server();
    tv::check_err("adopt it", ntlm::adopt_challenge(s2, u1, u2), ntlm::OK);
    tv::check_err("and accept", accept(s2, u3, NOW), ntlm::OK);
}

fn anonymous_and_state() {
    var cli = ntlm::initiator(ntlm::anonymous_credentials(), "", 0);
    var srv = server();
    tv::check_err("anonymous refused", run(cli, srv), ntlm::ERR_ANONYMOUS);
    var c2 = ntlm::initiator(ntlm::anonymous_credentials(), "", 0);
    var s2 = server();
    s2.allow_anonymous = true;
    tv::check_err("anonymous allowed", run(c2, s2), ntlm::OK);
    tv::check("anonymous outcome", s2.anonymous && s2.user.len == 0);
    var w: u8[>..] = [];
    tv::check_err("no session for anonymous", ntlm::wrap(s2.session, "x", false, w), ntlm::ERR_NO_SESSION);
    tv::check_err("no MIC for anonymous", ntlm::get_mic(c2.session, "x", w), ntlm::ERR_NO_SESSION);

    var s3 = server();
    tv::check_err("AUTHENTICATE before NEGOTIATE", accept(s3, "NTLMSSP\x00\x03\x00\x00\x00", NOW), ntlm::ERR_STATE);
    var c3 = ntlm::initiator(alice(), SPN, 0);
    var o: u8[>..] = [];
    tv::check_err("CHALLENGE before NEGOTIATE", ntlm::authenticate(c3, "x", NOW, o), ntlm::ERR_STATE);
    var c4 = ntlm::initiator(alice(), SPN, 0);
    ntlm::negotiate(c4, o);
    tv::check_err("NEGOTIATE twice", ntlm::negotiate(c4, o), ntlm::ERR_STATE);
    var s5 = server();
    var t1: u8[>..] = [];
    var c5 = ntlm::initiator(alice(), SPN, 0);
    ntlm::negotiate(c5, t1);
    var t2: u8[>..] = [];
    ntlm::accept_negotiate(s5, t1, NOW, t2);
    tv::check_err("NEGOTIATE again", ntlm::accept_negotiate(s5, t1, NOW, t2), ntlm::ERR_STATE);
    // Names too long for the acceptor: ERR_ARG at its first step, not cut.
    var longname: u8[>..] = [];
    for i in 70 { longname.push('N'); }
    var s7 = ntlm::acceptor(longname, "EXAMPLE", "", "");
    var o7: u8[>..] = [];
    tv::check_err("acceptor name too long", ntlm::accept_negotiate(s7, t1, NOW, o7), ntlm::ERR_ARG);
    // A NEGOTIATE without UNICODE (curl's: OEM) still gets a Unicode challenge.
    var s6 = server();
    var oem: u8[>..] = [];
    ntlm::negotiate_message(oem, ntlm::NEGOTIATE_OEM | ntlm::NEGOTIATE_NTLM | ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY);
    var oc: u8[>..] = [];
    tv::check_err("OEM NEGOTIATE", ntlm::accept_negotiate(s6, oem, NOW, oc), ntlm::OK);
    let ch, ce = ntlm::parse_challenge(oc);
    tv::check("answered in Unicode", ch.flags & ntlm::NEGOTIATE_UNICODE != 0 && ch.flags & ntlm::NEGOTIATE_OEM == 0);
    tv::check("no SIGN not asked for", ch.flags & ntlm::NEGOTIATE_SIGN == 0);
}

fn main() {
    good();
    logon_failures();
    mic_and_time();
    bindings_and_target();
    ntlmv1_refused();
    downgrades();
    malformed();
    av_pairs();
    anonymous_and_state();
    tv::done("exchange");
}
