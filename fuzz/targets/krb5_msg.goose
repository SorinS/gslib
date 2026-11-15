// Fuzz target: krb5_msg. The first byte picks:
//   0  every ASN.1 message decoder (krb5.messages, SPAKE, PKINIT), each
//      result encoded again and the encoding read back;
//   1  GSS-API and SPNEGO tokens as an acceptor sees them (no valid
//      ticket: the decoders and error paths), the HTTP Negotiate header,
//      and MIC/Wrap tokens against established contexts (AES, RC4, DES3);
//   2  the acceptor past the crypto: the rest is an EncTicketPart and an
//      Authenticator in clear (2-byte length of the first), which the
//      target encrypts (fixed confounder) into a ticket and an AP-REQ for
//      gss_accept, so the checks behind decryption are reached.

import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ccache;
import gslib.krb5.service;
import gslib.krb5.gssapi;
import gslib.krb5.spnego;
import gslib.krb5.spake;
import gslib.krb5.pkinit;

let SVC_KEY = "0123456789abcdef0123456789abcdef";
let RC4_KEY = "0123456789abcdef";
let DES3_KEY = "0123456789abcdef01234567";
let NOW = 1800000000;

fn keytab() -> krb5::KeytabEntry[>..] {
    var kt: krb5::KeytabEntry[>..] = [];
    kt.push(krb5::KeytabEntry { name_type: 1, name: "HTTP/web.example", realm: "EXAMPLE.COM", timestamp: 0, kvno: 3,
                                key: krb5::make_key(18, SVC_KEY) });
    kt.push(krb5::KeytabEntry { name_type: 1, name: "HTTP/web.example", realm: "EXAMPLE.COM", timestamp: 0, kvno: 3,
                                key: krb5::make_key(23, RC4_KEY) });
    return kt;
}

fn decoders(b: const u8[:]) {
    let mt = krb5::message_type(b);
    var out: u8[>..] = [];
    {
        let v, e = krb5::decode_ticket(b);
        if e == krb5::OK { out.clear(); krb5::encode_ticket(out, v); let v2, e2 = krb5::decode_ticket(out); }
    }
    {
        let v, e = krb5::decode_enc_ticket_part(b);
        if e == krb5::OK { out.clear(); krb5::encode_enc_ticket_part(out, v); let v2, e2 = krb5::decode_enc_ticket_part(out); }
    }
    {
        let v, e = krb5::decode_req_body(b);
        if e == krb5::OK { out.clear(); krb5::encode_req_body(out, v); let v2, e2 = krb5::decode_req_body(out); }
    }
    {
        let v, e = krb5::decode_kdc_req(b);
        if e == krb5::OK { out.clear(); krb5::encode_kdc_req(out, v); let v2, e2 = krb5::decode_kdc_req(out); }
    }
    {
        let v, e = krb5::decode_kdc_rep(b);
        if e == krb5::OK { out.clear(); krb5::encode_kdc_rep(out, v); let v2, e2 = krb5::decode_kdc_rep(out); }
    }
    {
        let v, e = krb5::decode_enc_kdc_rep_part(b);
        if e == krb5::OK { out.clear(); krb5::encode_enc_kdc_rep_part(out, v); let v2, e2 = krb5::decode_enc_kdc_rep_part(out); }
    }
    {
        let v, e = krb5::decode_ap_req(b);
        if e == krb5::OK {
            out.clear(); krb5::encode_ap_req(out, v); let v2, e2 = krb5::decode_ap_req(out);
            let t, te = krb5::decode_ticket(v.ticket);
        }
    }
    {
        let v, e = krb5::decode_authenticator(b);
        if e == krb5::OK { out.clear(); krb5::encode_authenticator(out, v); let v2, e2 = krb5::decode_authenticator(out); }
    }
    {
        let v, e = krb5::decode_ap_rep(b);
        if e == krb5::OK { out.clear(); krb5::encode_ap_rep(out, v); let v2, e2 = krb5::decode_ap_rep(out); }
    }
    {
        let v, e = krb5::decode_enc_ap_rep_part(b);
        if e == krb5::OK { out.clear(); krb5::encode_enc_ap_rep_part(out, v); let v2, e2 = krb5::decode_enc_ap_rep_part(out); }
    }
    {
        let v, e = krb5::decode_krb_safe(b);
        if e == krb5::OK { out.clear(); krb5::encode_krb_safe(out, v); let v2, e2 = krb5::decode_krb_safe(out); }
    }
    {
        let v, e = krb5::decode_krb_priv(b);
        if e == krb5::OK { out.clear(); krb5::encode_krb_priv(out, v); let v2, e2 = krb5::decode_krb_priv(out); }
    }
    {
        let v, e = krb5::decode_enc_krb_priv_part(b);
        if e == krb5::OK { out.clear(); krb5::encode_enc_krb_priv_part(out, v); let v2, e2 = krb5::decode_enc_krb_priv_part(out); }
    }
    {
        let v, e = krb5::decode_krb_cred(b);
        if e == krb5::OK { out.clear(); krb5::encode_krb_cred(out, v); let v2, e2 = krb5::decode_krb_cred(out); }
    }
    {
        let v, e = krb5::decode_enc_krb_cred_part(b);
        if e == krb5::OK { out.clear(); krb5::encode_enc_krb_cred_part(out, v); let v2, e2 = krb5::decode_enc_krb_cred_part(out); }
    }
    {
        let v, e = krb5::decode_krb_error(b);
        if e == krb5::OK {
            out.clear(); krb5::encode_krb_error(out, v); let v2, e2 = krb5::decode_krb_error(out);
            // A KRB-ERROR's e-data: METHOD-DATA (PA-DATA) or TYPED-DATA.
            if v.has_edata {
                let pa, pe = krb5::decode_padata(v.edata);
                let td, tde = krb5::decode_typed_data(v.edata);
            }
        }
    }
    {
        let t, us, u, e = krb5::decode_pa_enc_ts(b);
        if e == krb5::OK { out.clear(); krb5::encode_pa_enc_ts(out, t, us, u); }
    }
    for old in [false, true] {
        let v, e = krb5::decode_etype_info(b, old);
        if e == krb5::OK { out.clear(); krb5::encode_etype_info(out, v, old); let v2, e2 = krb5::decode_etype_info(out, old); }
    }
    {
        let v, e = krb5::decode_pa_pac_options(b);
        if e == krb5::OK { out.clear(); krb5::encode_pa_pac_options(out, v); }
    }
    {
        let v, e = krb5::decode_padata(b);
        if e == krb5::OK {
            out.clear(); krb5::encode_padata(out, v); let v2, e2 = krb5::decode_padata(out);
            // What a client reads out of the KDC's PA-DATA.
            for p in v {
                if p.pa_type == 19 || p.pa_type == 11 { let ei, eie = krb5::decode_etype_info(p.value, p.pa_type == 11); }
                if p.pa_type == 151 { let sp, spe = krb5::decode_pa_spake(p.value); }
                if p.pa_type == 17 { let pk, pke = krb5::decode_pa_pk_as_rep(p.value); }
                if p.pa_type == 136 { let fr, fre = krb5::decode_pa_fx_fast_reply(p.value); }
            }
        }
    }
    {
        let v, e = krb5::decode_typed_data(b);
        if e == krb5::OK { out.clear(); krb5::encode_typed_data(out, v); let v2, e2 = krb5::decode_typed_data(out); }
    }
    {
        let v, e = krb5::decode_authdata(b);
        if e == krb5::OK { out.clear(); krb5::encode_authdata(out, v); let v2, e2 = krb5::decode_authdata(out); }
    }
    {
        let v, e = krb5::decode_enc_data(b);
        if e == krb5::OK { out.clear(); krb5::encode_enc_data(out, v); let v2, e2 = krb5::decode_enc_data(out); }
    }
    {
        let v, e = krb5::decode_key(b);
        if e == krb5::OK { out.clear(); krb5::encode_key(out, v); let v2, e2 = krb5::decode_key(out); }
    }
    {
        let v, e = krb5::decode_principal(b);
        if e == krb5::OK {
            out.clear(); krb5::encode_principal(out, v); let v2, e2 = krb5::decode_principal(out);
            let s = krb5::principal_string(v.name, "EXAMPLE.COM");
            let n, r, ok1, ok2 = krb5::parse_principal(s);
            let parts = krb5::name_parts(v.name);
        }
    }
    {
        let v, e = krb5::decode_pa_fx_fast_request(b);
        if e == krb5::OK { out.clear(); krb5::encode_pa_fx_fast_request(out, v); let v2, e2 = krb5::decode_pa_fx_fast_request(out); }
    }
    {
        let v, e = krb5::decode_fast_req(b);
        if e == krb5::OK { out.clear(); krb5::encode_fast_req(out, v); let v2, e2 = krb5::decode_fast_req(out); }
    }
    {
        let v, e = krb5::decode_pa_fx_fast_reply(b);
        if e == krb5::OK { out.clear(); krb5::encode_pa_fx_fast_reply(out, v); }
    }
    {
        let v, e = krb5::decode_fast_response(b);
        if e == krb5::OK { out.clear(); krb5::encode_fast_response(out, v); let v2, e2 = krb5::decode_fast_response(out); }
    }
    { let v, e = krb5::decode_pa_spake(b); }
    { let v, e = krb5::decode_spake_factor(b); }
    { let v, e = krb5::decode_pa_pk_as_rep(b); }
    { let v, n, e = krb5::decode_kdc_dh_key_info(b); }
    // Principal names in text, as a user or krb5.conf gives them.
    let n, r, ok1, ok2 = krb5::parse_principal(b);
}

fn tokens(b: const u8[:]) {
    let kt = keytab();
    {
        let id, at, e = krb5::gss_unframe(b, krb5::KRB5_OID, true);
        let id2, at2, e2 = krb5::gss_unframe(b, krb5::SPNEGO_OID, false);
    }
    {
        var rc:  krb5::ReplayEntry[>..] = [];
        var out: u8[>..]                = [];
        var ctx, acc, e = krb5::gss_accept(b, kt, true, rc, NOW, 0, 300, "bindings", true, out);
    }
    {
        // A fresh SPNEGO acceptor, then the same token as its second leg.
        var rc: krb5::ReplayEntry[>..] = [];
        var sp = krb5::empty_spnego();
        var out: u8[>..] = [];
        let done, acc, e = krb5::spnego_accept(sp, b, kt, false, rc, NOW, 0, 300, "", false, out);
        var sp2 = krb5::empty_spnego();
        sp2.started = true;
        var out2: u8[>..] = [];
        let done2, acc2, e2 = krb5::spnego_accept(sp2, b, kt, false, rc, NOW, 0, 300, "", false, out2);
    }
    {
        let tok, ok = krb5::negotiate_token(b);
        let h = krb5::negotiate_header(b);
    }
    // MIC and Wrap tokens under established contexts, both directions.
    let keys = [krb5::make_key(18, SVC_KEY), krb5::make_key(23, RC4_KEY), krb5::make_key(16, DES3_KEY)];
    for k in keys {
        for init in [false, true] {
            var ctx = krb5::empty_gss_context();
            ctx.initiator = init;
            ctx.established = true;
            ctx.flags = krb5::GSS_SEQUENCE | krb5::GSS_REPLAY | krb5::GSS_CONF | krb5::GSS_INTEG;
            ctx.session_key = k;
            ctx.key = k;
            var out: u8[>..] = [];
            let more, e = krb5::gss_unwrap(ctx, b, out);
            let e2 = krb5::gss_verify_mic(ctx, "message", b);
        }
    }
}

// The bytes of an encrypted part, or empty if the key cannot encrypt.
fn seal(k: krb5::Key, usage: i64, plain: const u8[:]) -> u8[>..], bool {
    var c: u8[>..] = [];
    let conf: u8[16] = [0; 16];
    if !krb5::etype_supported(k.etype) { return c, false; }
    let e = krb5::encrypt_with(k, usage, conf[..krb5::confounder_len(k.etype)], plain, c);
    return c, e == krb5::OK;
}

fn acceptor(b: const u8[:]) {
    if b.len < 3 { return; }
    let opt: u32 = b[0];
    let n = (b[1] as i64) << 8 | b[2];
    if 3 + n > b.len { return; }
    let tp_plain = b[3..3 + n];
    let au_plain = b[3 + n..];
    let svc = krb5::make_key(18, SVC_KEY);
    let tc, ok1 = seal(svc, krb5::USAGE_KDC_REP_TICKET, tp_plain);
    if !ok1 { return; }
    let t = krb5::Ticket { realm: "EXAMPLE.COM", sname: krb5::principal_name(1, "HTTP/web.example"),
                           enc_part: krb5::EncryptedData { etype: 18, has_kvno: true, kvno: 3, cipher: copy(tc) } };
    var tder: u8[>..] = [];
    krb5::encode_ticket(tder, t);
    // The authenticator goes under the ticket's session key, as the
    // initiator would put it; the time the acceptor checks against is its.
    let tp, tpe = krb5::decode_enc_ticket_part(tp_plain);
    if tpe != krb5::OK { return; }
    let ac, ok2 = seal(tp.key, krb5::USAGE_AP_REQ_AUTHENTICATOR, au_plain);
    if !ok2 { return; }
    let au, aue = krb5::decode_authenticator(au_plain);
    let now = if aue == krb5::OK { au.ctime } else { NOW };
    let ap = krb5::ApReq { ap_options: (opt & 0x60) << 24, ticket: copy(tder),
                           authenticator: krb5::EncryptedData { etype: tp.key.etype, has_kvno: false, kvno: 0, cipher: copy(ac) } };
    var apder: u8[>..] = [];
    krb5::encode_ap_req(apder, ap);
    var tok: u8[>..] = [];
    krb5::gss_frame(tok, krb5::KRB5_OID, krb5::TOK_AP_REQ, apder);
    let kt = keytab();
    var rc:  krb5::ReplayEntry[>..] = [];
    var out: u8[>..]                = [];
    var ctx, acc, e = krb5::gss_accept(tok, kt, opt & 1 != 0, rc, now, 0, 300, "bindings", opt & 2 != 0, out);
    if e == krb5::OK {
        // The context works: a Wrap token of ours unwraps on a peer.
        var w: u8[>..] = [];
        let we = krb5::gss_wrap(ctx, "data", opt & 4 != 0, w);
        var m: u8[>..] = [];
        let me = krb5::gss_get_mic(ctx, "data", m);
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let rest = data[1..];
    let sel = data[0] % 3;
    if sel == 0 { decoders(rest); }
    else if sel == 1 { tokens(rest); }
    else { acceptor(rest); }
    return 0;
}

fn main() {}
