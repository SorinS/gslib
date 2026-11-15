// krb5.spnego: SPNEGO (RFC 4178) over the Kerberos mechanism, both
// sides, and HTTP's Negotiate scheme (RFC 4559).
//
// The initiator offers Kerberos alone (as MIT and curl do) with an
// optimistic token. The acceptor takes Kerberos under either OID (RFC
// 4121's, or Microsoft's 1.2.840.48018.1.2.2, which Windows lists first);
// when the initiator's first choice is something else (NTLM, say) it
// answers accept-incomplete naming Kerberos and waits for its token.
// mechListMIC (§5): checked whenever the peer sends one; sent by the
// acceptor when the initiator sent one, when the mechanism chosen was not
// the initiator's first, or when the initiator asked with request-mic;
// sent by the initiator whenever the acceptor sent one. Microsoft's
// NegTokenInit2 (its negHints) is read; a raw Kerberos token where SPNEGO
// was expected (as some HTTP clients send) is taken too.
//
// NTLM as SPNEGO's mechanism (1.3.6.1.4.1.311.2.2.10, [MS-SPNG]) is the
// spnego_ntlm_* functions at the end, on gslib's ntlm: both sides, a raw
// NTLMSSP token in place of SPNEGO taken too, and mechListMIC signed and
// checked with the NTLM session's keys (the RC4 state reset after each,
// as Windows does). They return ntlm's error codes.

namespace krb5;

import std;
import base64;
import encoding.asn1;
import krb5.crypto;
import krb5.messages;
import krb5.keytab;
import krb5.ccache;
import krb5.service;
import krb5.gssapi;
import krb5.config;
import ntlm;
import ntlm.messages;
import ntlm.session;
import ntlm.client;
import ntlm.server;

let SPNEGO_OID = "1.3.6.1.5.5.2";
let NTLM_OID = "1.3.6.1.4.1.311.2.2.10";

// negState (§4.2.2).
let NEG_ACCEPT_COMPLETED: i64 = 0;
let NEG_ACCEPT_INCOMPLETE: i64 = 1;
let NEG_REJECT: i64 = 2;
let NEG_REQUEST_MIC: i64 = 3;

struct SpnegoContext {
    gss: GssContext,
    started: bool,
    complete: bool,        // SPNEGO's own exchange is done
    raw: bool,             // the peer sent bare Kerberos tokens, not SPNEGO
    ms_oid: bool,          // Kerberos was chosen under Microsoft's OID
    first_choice: bool,    // ...and was the initiator's first
    mic_sent: bool,
    mic_received: bool,
    mech_list: u8[..1024], // the DER of the initiator's mechTypes, which mechListMIC covers
}

fn empty_spnego() -> SpnegoContext {
    return SpnegoContext { gss: empty_gss_context(), started: false, complete: false, raw: false, ms_oid: false,
                           first_choice: true, mic_sent: false, mic_received: false, mech_list: [] };
}

// --- Encoding -----------------------------------------------------------------------

fn put_octets_field(out: u8[>..]&, n: u32, b: const u8[:]) {
    var t: u8[>..] = [];
    asn1::put_octets(t, b);
    put_field(out, n, t);
}

// The initial token: [APPLICATION 0] { SPNEGO OID, [0] NegTokenInit }.
fn spnego_init_token(out: u8[>..]&, mech_list: const u8[:], mech_token: const u8[:], mic: const u8[:]) {
    var s: u8[>..] = [];
    put_field(s, 0, mech_list);
    if mech_token.len > 0 { put_octets_field(s, 2, mech_token); }
    if mic.len > 0 { put_octets_field(s, 3, mic); }
    var seq: u8[>..] = [];
    put_seq(seq, s);
    var choice: u8[>..] = [];
    put_field(choice, 0, seq);
    gss_frame(out, SPNEGO_OID, 0, choice);
}

// [1] NegTokenResp, not framed. `state` < 0 leaves negState out; an empty
// `mech` leaves supportedMech out.
fn spnego_resp_token(out: u8[>..]&, state: i64, mech: const u8[:], response: const u8[:], mic: const u8[:]) {
    var s: u8[>..] = [];
    if state >= 0 {
        var e: u8[>..] = [];
        asn1::put_i64(e, state, asn1::ENUMERATED);
        put_field(s, 0, e);
    }
    if mech.len > 0 {
        var o: u8[>..] = [];
        asn1::put_oid(o, mech);
        put_field(s, 1, o);
    }
    if response.len > 0 { put_octets_field(s, 2, response); }
    if mic.len > 0 { put_octets_field(s, 3, mic); }
    var seq: u8[>..] = [];
    put_seq(seq, s);
    put_field(out, 1, seq);
}

fn mech_type_list(out: u8[>..]&, oids: const u8[][:]) {
    var c: u8[>..] = [];
    for o in oids { asn1::put_oid(c, o); }
    put_seq(out, c);
}

// --- Decoding -----------------------------------------------------------------------

// A NegTokenInit's parts: the mechTypes' DER, its OIDs (text), the
// mechToken and mechListMIC (empty when absent).
fn read_neg_init(buf: const u8[:], t: asn1::Tlv) -> u8[>..], u8[][>..], u8[>..], u8[>..], bool {
    var list: u8[>..] = [];
    var oids: u8[][>..] = [];
    var tok: u8[>..] = [];
    var mic: u8[>..] = [];
    let kids, ok = asn1::children(buf, t, true);
    if !ok || t.tag != asn1::SEQUENCE { return list, oids, tok, mic, false; }
    var good = true;
    for k in kids {
        if k.cls != asn1::CLASS_CONTEXT || !k.constructed { good = false; continue; }
        let inner, iok = asn1::explicit(buf, k, true);
        if !iok { good = false; continue; }
        if k.number == 0 {
            list.append(buf[inner.start..inner.end]);
            let ms, mok = asn1::children(buf, inner, true);
            if !mok || inner.tag != asn1::SEQUENCE { good = false; continue; }
            for m in ms {
                let txt, tok2 = asn1::read_oid(buf, m);
                if !tok2 { good = false; } else { oids.push(copy(txt)); }
            }
        } else if k.number == 2 {
            if inner.tag != asn1::OCTET_STRING { good = false; } else { tok.append(buf[inner.off..inner.end]); }
        } else if k.number == 3 || k.number == 4 {
            // [3] is mechListMIC in RFC 4178 and negHints (a SEQUENCE) in
            // Microsoft's NegTokenInit2, whose mechListMIC is [4].
            if inner.tag == asn1::OCTET_STRING { mic.append(buf[inner.off..inner.end]); }
        }
    }
    return list, oids, tok, mic, good && list.len > 0;
}

// A NegTokenResp's negState (-1 when absent), supportedMech (text, empty
// when absent), responseToken and mechListMIC.
fn read_neg_resp(buf: const u8[:], t: asn1::Tlv) -> i64, u8[>..], u8[>..], u8[>..], bool {
    var mech: u8[>..] = [];
    var tok: u8[>..] = [];
    var mic: u8[>..] = [];
    var state: i64 = -1;
    let kids, ok = asn1::children(buf, t, true);
    if !ok || t.tag != asn1::SEQUENCE { return state, mech, tok, mic, false; }
    var good = true;
    for k in kids {
        if k.cls != asn1::CLASS_CONTEXT || !k.constructed { good = false; continue; }
        let inner, iok = asn1::explicit(buf, k, true);
        if !iok { good = false; continue; }
        if k.number == 0 {
            let v, vok = asn1::read_i64(buf, inner, asn1::ENUMERATED, true);
            if !vok { good = false; } else { state = v; }
        } else if k.number == 1 {
            let txt, tok2 = asn1::read_oid(buf, inner);
            if !tok2 { good = false; } else { mech.append(txt); }
        } else if k.number == 2 {
            if inner.tag != asn1::OCTET_STRING { good = false; } else { tok.append(buf[inner.off..inner.end]); }
        } else if k.number == 3 {
            if inner.tag != asn1::OCTET_STRING { good = false; } else { mic.append(buf[inner.off..inner.end]); }
        }
    }
    return state, mech, tok, mic, good;
}

fn is_krb5_oid(o: const u8[:]) -> bool { o == KRB5_OID || o == MS_KRB5_OID }

// --- The initiator ------------------------------------------------------------------

// The initiator's first token: NegTokenInit offering Kerberos, with the
// Kerberos context token (krb5.gssapi's gss_init) inside.
fn spnego_init(cred: const Credential&, flags: u32, bindings: const u8[:], has_bindings: bool, deleg: const u8[:], now: i64,
               usec: i64, out: u8[>..]&) -> SpnegoContext, i64 {
    var ctx = empty_spnego();
    var tok: u8[>..] = [];
    let g, err = gss_init(cred, flags, bindings, has_bindings, deleg, now, usec, tok);
    if err != OK { return ctx, err; }
    var oids: u8[][>..] = [];
    oids.push(KRB5_OID);
    var list: u8[>..] = [];
    mech_type_list(list, oids);
    spnego_init_token(out, list, tok, "");
    ctx.gss = g;
    ctx.started = true;
    ctx.mech_list.append(list);
    return ctx, OK;
}

// The initiator's next step with the acceptor's NegTokenResp. `out` gets
// a further token to send when SPNEGO needs one (our mechListMIC); done
// tells whether the exchange is over.
fn spnego_init_continue(ctx: SpnegoContext&, token: const u8[:], out: u8[>..]&) -> bool, i64 {
    if !ctx.started || ctx.complete { return true, ERR_CONTEXT; }
    let t, ok = asn1::parse(token, true);
    if !ok || t.tag != asn1::ctx(1, true) { return false, ERR_TOKEN; }
    let inner, iok = asn1::explicit(token, t, true);
    if !iok { return false, ERR_TOKEN; }
    let state, mech, resp, mic, good = read_neg_resp(token, inner);
    if !good { return false, ERR_TOKEN; }
    if state == NEG_REJECT { return true, ERR_MECH; }
    if mech.len > 0 && !is_krb5_oid(mech) { return true, ERR_MECH; }
    if resp.len > 0 && !ctx.gss.established {
        let err = gss_init_continue(ctx.gss, resp);
        if err != OK { return true, err; }
    }
    if !ctx.gss.established { return false, if state == NEG_ACCEPT_INCOMPLETE { OK } else { ERR_CONTEXT }; }
    if mic.len > 0 {
        let err = gss_verify_mic(ctx.gss, ctx.mech_list, mic);
        if err != OK { return true, err; }
        ctx.mic_received = true;
    }
    // The acceptor sent its MIC or asked for ours: we answer with ours.
    if (mic.len > 0 || state == NEG_REQUEST_MIC) && !ctx.mic_sent {
        var m: u8[>..] = [];
        let err = gss_get_mic(ctx.gss, ctx.mech_list, m);
        if err != OK { return true, err; }
        spnego_resp_token(out, -1, "", "", m);
        ctx.mic_sent = true;
    }
    if state == NEG_ACCEPT_COMPLETED || state < 0 { ctx.complete = true; }
    return ctx.complete, OK;
}

// --- The acceptor -------------------------------------------------------------------

// The acceptor's step: the initiator's token (NegTokenInit first, then
// NegTokenResps), a reply in `out` (possibly empty) and, once Kerberos has
// accepted, what it learned. done is true when the context is complete.
fn spnego_accept(ctx: SpnegoContext&, token: const u8[:], kt: const KeytabEntry[:], any_name: bool, rc: ReplayEntry[>..]&,
                 now: i64, usec: i64, skew: i64, bindings: const u8[:], has_bindings: bool, out: u8[>..]&)
    -> bool, GssAccepted, i64 {
    let none = GssAccepted { ap: empty_ap_context(), flags: 0, delegated: [] };
    var mech_token: u8[>..] = [];
    var mic: u8[>..] = [];
    var request_mic = false;
    if !ctx.started {
        // A bare Kerberos token in place of SPNEGO.
        let rid, rat, rerr = gss_unframe(token, KRB5_OID, true);
        if rerr == OK {
            var o: u8[>..] = [];
            var g, acc, err = gss_accept(token, kt, any_name, rc, now, usec, skew, bindings, has_bindings, o);
            ctx.gss = g;
            ctx.started = true;
            ctx.raw = true;
            ctx.complete = err == OK;
            out.append(o);
            return err == OK, acc, err;
        }
        let id, at, err = gss_unframe(token, SPNEGO_OID, false);
        if err != OK { return false, none, err; }
        let t, ok = asn1::read(token, at, token.len, true);
        if !ok || t.tag != asn1::ctx(0, true) { return false, none, ERR_TOKEN; }
        let inner, iok = asn1::explicit(token, t, true);
        if !iok { return false, none, ERR_TOKEN; }
        let list, oids, tok, m, good = read_neg_init(token, inner);
        if !good || list.len > 1024 { return false, none, ERR_TOKEN; }
        ctx.started = true;
        ctx.mech_list.append(list);
        var i = 0;
        var chosen = -1;
        for o in oids {
            if chosen < 0 && is_krb5_oid(o) {
                chosen = i;
                ctx.ms_oid = o == MS_KRB5_OID;
            }
            i++;
        }
        if chosen < 0 {
            spnego_resp_token(out, NEG_REJECT, "", "", "");
            return true, none, ERR_MECH;
        }
        ctx.first_choice = chosen == 0;
        if !ctx.first_choice || tok.len == 0 {
            // The optimistic token is for another mechanism, or there is
            // none: name ours and wait for its token.
            spnego_resp_token(out, NEG_ACCEPT_INCOMPLETE, if ctx.ms_oid { MS_KRB5_OID } else { KRB5_OID }, "", "");
            return false, none, OK;
        }
        mech_token.append(tok);
        mic.append(m);
    } else {
        let t, ok = asn1::parse(token, true);
        if !ok || t.tag != asn1::ctx(1, true) { return false, none, ERR_TOKEN; }
        let inner, iok = asn1::explicit(token, t, true);
        if !iok { return false, none, ERR_TOKEN; }
        let state, mech, resp, m, good = read_neg_resp(token, inner);
        if !good { return false, none, ERR_TOKEN; }
        mech_token.append(resp);
        mic.append(m);
        request_mic = state == NEG_REQUEST_MIC;
    }
    if mech_token.len > 0 {
        if ctx.gss.established { return false, none, ERR_TOKEN; }
        var resp: u8[>..] = [];
        var g, a, err = gss_accept(mech_token, kt, any_name, rc, now, usec, skew, bindings, has_bindings, resp);
        if err != OK {
            spnego_resp_token(out, NEG_REJECT, "", resp, "");
            return true, none, err;
        }
        ctx.gss = g;
        let done, ferr = spnego_finish(ctx, mic, request_mic, true, resp, out);
        return done, a, ferr;
    }
    if !ctx.gss.established { return false, none, ERR_CONTEXT; }
    let done, ferr = spnego_finish(ctx, mic, request_mic, false, "", out);
    return done, none, ferr;
}

// The acceptor's answer once Kerberos has accepted: the initiator's
// mechListMIC checked, ours made when wanted, the NegTokenResp written.
fn spnego_finish(ctx: SpnegoContext&, mic: const u8[:], request_mic: bool, first: bool, resp: const u8[:], out: u8[>..]&) -> bool, i64 {
    if mic.len > 0 {
        let err = gss_verify_mic(ctx.gss, ctx.mech_list, mic);
        if err != OK {
            spnego_resp_token(out, NEG_REJECT, "", "", "");
            return true, err;
        }
        ctx.mic_received = true;
    }
    // Our MIC: when the initiator sent one or asked for it, or Kerberos was
    // not its first choice (§5); then the initiator must answer with its
    // own before we are done, unless it already sent one.
    let want_mic = mic.len > 0 || request_mic || !ctx.first_choice;
    var my_mic: u8[>..] = [];
    if want_mic && !ctx.mic_sent {
        let err = gss_get_mic(ctx.gss, ctx.mech_list, my_mic);
        if err != OK && err != ERR_ETYPE { return true, err; }
        ctx.mic_sent = my_mic.len > 0;
    }
    let need_theirs = ctx.mic_sent && !ctx.mic_received;
    let state = if need_theirs { NEG_ACCEPT_INCOMPLETE } else { NEG_ACCEPT_COMPLETED };
    spnego_resp_token(out, state, if first { if ctx.ms_oid { MS_KRB5_OID } else { KRB5_OID } } else { "" }, resp, my_mic);
    ctx.complete = !need_theirs;
    return ctx.complete, OK;
}

// --- HTTP Negotiate (RFC 4559) --------------------------------------------------------

// "Negotiate <base64 token>", for an Authorization or WWW-Authenticate header.
fn negotiate_header(token: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("Negotiate ");
    base64::encode(out, token);
    return out;
}

// The token of a "Negotiate ..." header value; ok false if it is not one.
fn negotiate_token(value: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let v = trim(value);
    if v.len == 9 && lower(v) == "negotiate" { return out, true; }
    if v.len < 10 || lower(v[..9]) != "negotiate" || (v[9] != ' ' && v[9] != '\t') { return out, false; }
    let b = trim(v[10..]);
    if b.len == 0 { return out, true; }
    if !base64::decode(out, b) { out.clear(); return out, false; }
    return out, true;
}

// --- NTLM as the mechanism ([MS-SPNG]) --------------------------------------------------

// A SPNEGO context whose mechanism is NTLM, either side.
struct SpnegoNtlm {
    initiator:    bool,
    ini:          ntlm::Initiator,
    acc:          ntlm::Acceptor,
    started:      bool,
    complete:     bool,
    raw:          bool,          // bare NTLMSSP tokens, no SPNEGO (the peer sent them so)
    mic_sent:     bool,
    mic_received: bool,
    mech_list:    u8[..1024],    // the DER of the initiator's mechTypes
}

fn spnego_ntlm_initiator(cred: ntlm::Credentials, spn: const u8[:], want: u32) -> SpnegoNtlm {
    return SpnegoNtlm { initiator: true, ini: ntlm::initiator(cred, spn, want), acc: ntlm::Acceptor { .. }, started: false,
                        complete: false, raw: false, mic_sent: false, mic_received: false, mech_list: [] };
}

fn spnego_ntlm_acceptor(a: ntlm::Acceptor) -> SpnegoNtlm {
    var init = ntlm::initiator(ntlm::anonymous_credentials(), "", 0);
    init.state = ntlm::INIT_FAILED;
    return SpnegoNtlm { initiator: false, ini: init, acc: a, started: false, complete: false, raw: false, mic_sent: false,
                        mic_received: false, mech_list: [] };
}

// The session of an established context, for wrap, unwrap and the MICs.
fn spnego_ntlm_session(ctx: SpnegoNtlm&) -> ntlm::Session& { if ctx.initiator { ctx.ini.session } else { ctx.acc.session } }

// The initiator's first token: NegTokenInit offering NTLM alone, the
// NEGOTIATE message in it.
fn spnego_ntlm_init(ctx: SpnegoNtlm&, out: u8[>..]&) -> i64 {
    if !ctx.initiator || ctx.started { return ntlm::ERR_STATE; }
    var neg: u8[>..] = [];
    let e = ntlm::negotiate(ctx.ini, neg);
    if e != ntlm::OK { return e; }
    var oids: u8[][>..] = [];
    oids.push(NTLM_OID);
    var list: u8[>..] = [];
    mech_type_list(list, oids);
    spnego_init_token(out, list, neg, "");
    ctx.mech_list.append(list);
    ctx.started = true;
    return ntlm::OK;
}

// Our mechListMIC over the mechTypes, the outgoing RC4 state reset after it.
fn spnego_ntlm_my_mic(ctx: SpnegoNtlm&, out: u8[>..]&) -> i64 {
    let e = ntlm::get_mic(spnego_ntlm_session(ctx), ctx.mech_list, out);
    if e != ntlm::OK { return e; }
    ntlm::reset_rc4(spnego_ntlm_session(ctx), true);
    ctx.mic_sent = true;
    return ntlm::OK;
}

fn spnego_ntlm_check_mic(ctx: SpnegoNtlm&, mic: const u8[:]) -> i64 {
    let e = ntlm::verify_mic(spnego_ntlm_session(ctx), ctx.mech_list, mic);
    if e != ntlm::OK { return ntlm::ERR_MIC; }
    ntlm::reset_rc4(spnego_ntlm_session(ctx), false);
    ctx.mic_received = true;
    return ntlm::OK;
}

// The initiator's next step with the acceptor's token: the CHALLENGE in
// (the AUTHENTICATE and our mechListMIC out), then the acceptor's
// mechListMIC checked. done: the exchange is over. `now`: seconds since
// 1970.
fn spnego_ntlm_init_continue(ctx: SpnegoNtlm&, token: const u8[:], now: i64, out: u8[>..]&) -> bool, i64 {
    if !ctx.initiator || !ctx.started || ctx.complete { return true, ntlm::ERR_STATE; }
    let t, ok = asn1::parse(token, true);
    if !ok || t.tag != asn1::ctx(1, true) { return true, ntlm::ERR_MALFORMED; }
    let inner, iok = asn1::explicit(token, t, true);
    if !iok { return true, ntlm::ERR_MALFORMED; }
    let state, mech, resp, mic, good = read_neg_resp(token, inner);
    if !good { return true, ntlm::ERR_MALFORMED; }
    if state == NEG_REJECT { return true, ntlm::ERR_REJECTED; }
    if mech.len > 0 && mech[..] != NTLM_OID { return true, ntlm::ERR_REJECTED; }
    if !ntlm::established(ctx.ini) {
        if resp.len == 0 { return true, ntlm::ERR_MALFORMED; }
        var auth: u8[>..] = [];
        let e = ntlm::authenticate(ctx.ini, resp, now, auth);
        if e != ntlm::OK { return true, e; }
        var m: u8[>..] = [];
        let me = spnego_ntlm_my_mic(ctx, m);
        if me != ntlm::OK { return true, me; }
        spnego_resp_token(out, -1, "", auth, m);
        return false, ntlm::OK;
    }
    // The acceptor's verdict, with its mechListMIC.
    if state != NEG_ACCEPT_COMPLETED || resp.len > 0 { return true, ntlm::ERR_MALFORMED; }
    if mic.len == 0 { return true, ntlm::ERR_MIC; }
    let ce = spnego_ntlm_check_mic(ctx, mic);
    if ce != ntlm::OK { return true, ce; }
    ctx.complete = true;
    return true, ntlm::OK;
}

// The acceptor's step: the initiator's token (NegTokenInit first, then
// a NegTokenResp with the AUTHENTICATE and its mechListMIC; or bare
// NTLMSSP tokens), the reply in `out`. F is the NT hash lookup of
// ntlm::accept_authenticate. done is true when the context is complete
// (check the error: OK, or why it failed).
fn spnego_ntlm_accept<F>(ctx: SpnegoNtlm&, token: const u8[:], now: i64, out: u8[>..]&) -> bool, i64 {
    if ctx.initiator || ctx.complete { return true, ntlm::ERR_STATE; }
    if ctx.raw || (!ctx.started && ntlm::is_ntlmssp(token)) {
        ctx.raw = true;
        if !ctx.started {
            ctx.started = true;
            let e = ntlm::accept_negotiate(ctx.acc, token, now, out);
            return e != ntlm::OK, e;
        }
        let e = ntlm::accept_authenticate(ctx.acc, token, now) { user, domain, h => F(user, domain, h) };
        ctx.complete = e == ntlm::OK;
        return true, e;
    }
    var mech_token: u8[>..] = [];
    var mic: u8[>..] = [];
    if !ctx.started {
        let id, at, err = gss_unframe(token, SPNEGO_OID, false);
        if err != OK { return true, ntlm::ERR_MALFORMED; }
        let t, ok = asn1::read(token, at, token.len, true);
        if !ok || t.tag != asn1::ctx(0, true) { return true, ntlm::ERR_MALFORMED; }
        let inner, iok = asn1::explicit(token, t, true);
        if !iok { return true, ntlm::ERR_MALFORMED; }
        let list, oids, tok, m, good = read_neg_init(token, inner);
        if !good || list.len > ctx.mech_list.cap { return true, ntlm::ERR_MALFORMED; }
        ctx.started = true;
        ctx.mech_list.append(list);
        var i = 0;
        var chosen = -1;
        for o in oids {
            if chosen < 0 && o[..] == NTLM_OID { chosen = i; }
            i++;
        }
        if chosen < 0 {
            spnego_resp_token(out, NEG_REJECT, "", "", "");
            return true, ntlm::ERR_REJECTED;
        }
        if chosen != 0 || tok.len == 0 {
            // The optimistic token is another mechanism's: NTLM named,
            // its NEGOTIATE awaited.
            spnego_resp_token(out, NEG_ACCEPT_INCOMPLETE, NTLM_OID, "", "");
            return false, ntlm::OK;
        }
        mech_token.append(tok);
    } else {
        let t, ok = asn1::parse(token, true);
        if !ok || t.tag != asn1::ctx(1, true) { return true, ntlm::ERR_MALFORMED; }
        let inner, iok = asn1::explicit(token, t, true);
        if !iok { return true, ntlm::ERR_MALFORMED; }
        let state, mech, resp, m, good = read_neg_resp(token, inner);
        if !good { return true, ntlm::ERR_MALFORMED; }
        mech_token.append(resp);
        mic.append(m);
    }
    if ctx.acc.state == ntlm::ACC_NEW {
        var ch: u8[>..] = [];
        let e = ntlm::accept_negotiate(ctx.acc, mech_token, now, ch);
        if e != ntlm::OK {
            spnego_resp_token(out, NEG_REJECT, "", "", "");
            return true, e;
        }
        spnego_resp_token(out, NEG_ACCEPT_INCOMPLETE, NTLM_OID, ch, "");
        return false, ntlm::OK;
    }
    let e = ntlm::accept_authenticate(ctx.acc, mech_token, now) { user, domain, h => F(user, domain, h) };
    if e != ntlm::OK {
        spnego_resp_token(out, NEG_REJECT, "", "", "");
        return true, e;
    }
    // mechListMIC: the initiator's checked; required when its AUTHENTICATE
    // carried a MIC (a MIC there and none here is a stripped one).
    if mic.len > 0 {
        let ce = spnego_ntlm_check_mic(ctx, mic);
        if ce != ntlm::OK {
            spnego_resp_token(out, NEG_REJECT, "", "", "");
            return true, ce;
        }
    } else if ctx.acc.had_mic {
        spnego_resp_token(out, NEG_REJECT, "", "", "");
        return true, ntlm::ERR_MIC;
    }
    var my: u8[>..] = [];
    if ctx.mic_received || ctx.acc.had_mic {
        let me = spnego_ntlm_my_mic(ctx, my);
        if me != ntlm::OK { return true, me; }
    }
    spnego_resp_token(out, NEG_ACCEPT_COMPLETED, "", "", my);
    ctx.complete = true;
    return true, ntlm::OK;
}
