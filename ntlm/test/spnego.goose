// NTLM inside SPNEGO (krb5.spnego's spnego_ntlm_*): the exchange with
// mechListMIC both ways and sealing after it (the RC4 state reset), a raw
// NTLMSSP token where SPNEGO was expected, an initiator listing Kerberos
// first (NTLM chosen, a round more), no NTLM offered (rejected), a
// mechListMIC changed or stripped, a wrong password.
import std;
import os;
import gslib from "../..";
import gslib.ntlm;
import gslib.ntlm.messages;
import gslib.ntlm.session;
import gslib.ntlm.client;
import gslib.ntlm.server;
import gslib.krb5;
import gslib.krb5.gssapi;
import gslib.krb5.messages;
import gslib.krb5.spnego;
import gslib.encoding.asn1;
import tv;

let NOW = tv::NOW;

fn cred(password: const u8[:]) -> ntlm::Credentials {
    let c, e = ntlm::credentials("bob", "EXAMPLE", password);
    return c;
}

fn acceptor() -> krb5::SpnegoNtlm {
    return krb5::spnego_ntlm_acceptor(ntlm::acceptor("WEB", "EXAMPLE", "web.example.test", "example.test"));
}

fn lookup(user: const u8[:], domain: const u8[:], h: u8[:]) -> bool {
    let nth, ok = ntlm::nt_hash("swordfish");
    for i in 16 { h[i] = nth[i]; }
    return user == "bob";
}

fn step(srv: krb5::SpnegoNtlm&, tok: const u8[:], out: u8[>..]&) -> bool, i64 {
    let done, e = krb5::spnego_ntlm_accept(srv, tok, NOW, out) { user, domain, h => lookup(user, domain, h) };
    return done, e;
}

fn good() {
    var cli = krb5::spnego_ntlm_initiator(cred("swordfish"), "HTTP/web.example.test", ntlm::WANT_SEAL);
    var srv = acceptor();
    var t1: u8[>..] = [];
    tv::check_err("init", krb5::spnego_ntlm_init(cli, t1), ntlm::OK);
    tv::check("NegTokenInit framed", t1.len > 2 && t1[0] == 0x60);
    var t2: u8[>..] = [];
    let d1, e1 = step(srv, t1, t2);
    tv::check("accept 1", !d1 && e1 == ntlm::OK);
    var t3: u8[>..] = [];
    let c1, ce1 = krb5::spnego_ntlm_init_continue(cli, t2, NOW, t3);
    tv::check("continue 1", !c1 && ce1 == ntlm::OK && cli.mic_sent);
    var t4: u8[>..] = [];
    let d2, e2 = step(srv, t3, t4);
    tv::check_err("accept 2", e2, ntlm::OK);
    tv::check("acceptor done, both MICs", d2 && srv.complete && srv.mic_received && srv.mic_sent);
    tv::check("user", srv.acc.user[..] == "bob");
    var t5: u8[>..] = [];
    let c2, ce2 = krb5::spnego_ntlm_init_continue(cli, t4, NOW, t5);
    tv::check_err("continue 2", ce2, ntlm::OK);
    tv::check("initiator done", c2 && cli.complete && t5.len == 0);
    // Sealing after the mechListMICs (RC4 reset, sequence numbers on).
    for i in 3 {
        var w: u8[>..] = [];
        tv::check_err("wrap", ntlm::wrap(krb5::spnego_ntlm_session(cli), "secret", w), ntlm::OK);
        var p: u8[>..] = [];
        tv::check_err("unwrap", ntlm::unwrap(krb5::spnego_ntlm_session(srv), w, p), ntlm::OK);
        tv::check("text", p[..] == "secret");
        var w2: u8[>..] = [];
        ntlm::wrap(krb5::spnego_ntlm_session(srv), "back", w2);
        var p2: u8[>..] = [];
        tv::check_err("unwrap back", ntlm::unwrap(krb5::spnego_ntlm_session(cli), w2, p2), ntlm::OK);
    }
    tv::check("sequence numbers ran on", cli.ini.session.seq_out == 4);
}

fn raw() {
    // A bare NTLMSSP NEGOTIATE where SPNEGO was expected (HTTP Negotiate
    // clients without Kerberos send that).
    var ini = ntlm::initiator(cred("swordfish"), "", 0);
    var srv = acceptor();
    var t1: u8[>..] = [];
    ntlm::negotiate(ini, t1);
    var t2: u8[>..] = [];
    let d1, e1 = step(srv, t1, t2);
    tv::check("raw accept 1", !d1 && e1 == ntlm::OK && srv.raw && ntlm::is_ntlmssp(t2));
    var t3: u8[>..] = [];
    ntlm::authenticate(ini, t2, NOW, t3);
    var t4: u8[>..] = [];
    let d2, e2 = step(srv, t3, t4);
    tv::check("raw accept 2", d2 && e2 == ntlm::OK && t4.len == 0);
}

// NegTokenInit by hand: mechTypes and a mechToken.
fn neg_init(oids: const u8[][:], tok: const u8[:]) -> u8[>..] {
    var list: u8[>..] = [];
    krb5::mech_type_list(list, oids);
    var out: u8[>..] = [];
    krb5::spnego_init_token(out, list, tok, "");
    return out;
}

fn other_mechs() {
    // Kerberos first, with a (fake) optimistic token; NTLM second.
    var oids: u8[][>..] = [];
    oids.push(krb5::KRB5_OID);
    oids.push(krb5::NTLM_OID);
    let t1 = neg_init(oids, "\x60\x00");
    var srv = acceptor();
    var t2: u8[>..] = [];
    let d1, e1 = step(srv, t1, t2);
    tv::check("NTLM second: incomplete", !d1 && e1 == ntlm::OK);
    // The initiator then sends NEGOTIATE in a NegTokenResp; its mechList
    // is the one sent first.
    var cli = krb5::spnego_ntlm_initiator(cred("swordfish"), "", 0);
    var neg: u8[>..] = [];
    ntlm::negotiate(cli.ini, neg);
    cli.started = true;
    var list: u8[>..] = [];
    krb5::mech_type_list(list, oids);
    cli.mech_list.append(list);
    var t3: u8[>..] = [];
    krb5::spnego_resp_token(t3, -1, "", neg, "");
    var t4: u8[>..] = [];
    let d2, e2 = step(srv, t3, t4);
    tv::check("NEGOTIATE in a NegTokenResp", !d2 && e2 == ntlm::OK);
    var t5: u8[>..] = [];
    let c1, ce1 = krb5::spnego_ntlm_init_continue(cli, t4, NOW, t5);
    tv::check_err("initiator answers", ce1, ntlm::OK);
    var t6: u8[>..] = [];
    let d3, e3 = step(srv, t5, t6);
    tv::check("NTLM second: done", d3 && e3 == ntlm::OK);
    var t7: u8[>..] = [];
    let c2, ce2 = krb5::spnego_ntlm_init_continue(cli, t6, NOW, t7);
    tv::check("NTLM second: initiator done", c2 && ce2 == ntlm::OK);

    // No NTLM at all.
    var only: u8[][>..] = [];
    only.push(krb5::KRB5_OID);
    var s2 = acceptor();
    var r: u8[>..] = [];
    let d4, e4 = step(s2, neg_init(only, "\x60\x00"), r);
    tv::check("no NTLM offered: rejected", d4 && e4 == ntlm::ERR_REJECTED);
    var c3 = krb5::spnego_ntlm_initiator(cred("swordfish"), "", 0);
    var x: u8[>..] = [];
    krb5::spnego_ntlm_init(c3, x);
    var y: u8[>..] = [];
    let c4, ce4 = krb5::spnego_ntlm_init_continue(c3, r, NOW, y);
    tv::check("initiator sees the reject", c4 && ce4 == ntlm::ERR_REJECTED);
    var z: u8[>..] = [];
    let d5, e5 = step(s2, "garbage", z);
    tv::check("garbage after", d5 && e5 != ntlm::OK);
}

// An exchange up to the initiator's AUTHENTICATE + mechListMIC token,
// which `change` alters before the acceptor sees it.
fn tampered(password: const u8[:], strip_mic: bool, flip_mic: bool) -> i64 {
    var cli = krb5::spnego_ntlm_initiator(cred(password), "", 0);
    var srv = acceptor();
    var t1: u8[>..] = [];
    krb5::spnego_ntlm_init(cli, t1);
    var t2: u8[>..] = [];
    step(srv, t1, t2);
    var t3: u8[>..] = [];
    let c, ce = krb5::spnego_ntlm_init_continue(cli, t2, NOW, t3);
    if ce != ntlm::OK { return 100 + ce; }
    let t, ok = asn1::parse(t3, true);
    let inner, iok = asn1::explicit(t3, t, true);
    let state, mech, resp, mic, good = krb5::read_neg_resp(t3, inner);
    var m = copy(mic);
    if flip_mic { m[5] ^= 1; }
    var t3x: u8[>..] = [];
    krb5::spnego_resp_token(t3x, -1, "", resp, if strip_mic { "" } else { m[..] });
    var t4: u8[>..] = [];
    let d, e = step(srv, t3x, t4);
    return e;
}

fn hostile() {
    tv::check_err("untouched", tampered("swordfish", false, false), ntlm::OK);
    tv::check_err("mechListMIC changed", tampered("swordfish", false, true), ntlm::ERR_MIC);
    tv::check_err("mechListMIC stripped", tampered("swordfish", true, false), ntlm::ERR_MIC);
    tv::check_err("wrong password", tampered("wrong", false, false), ntlm::ERR_LOGON);
}

fn main() {
    good();
    raw();
    other_mechs();
    hostile();
    tv::done("spnego");
}
