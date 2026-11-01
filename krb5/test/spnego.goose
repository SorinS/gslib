// krb5.spnego without a KDC: tickets made here (as in test/gssapi.goose),
// then SPNEGO exchanges: Kerberos first (one round trip), Microsoft's OID
// first, NTLM first (Kerberos chosen, a second round), mechListMIC both
// ways, a raw Kerberos token where SPNEGO was expected, a rejection, and
// the Negotiate header.

import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ccache;
import gslib.krb5.service;
import gslib.krb5.gssapi;
import gslib.krb5.spnego;
import gslib.encoding.asn1;
import tv;

let NOW = 1800000000;

// A ticket for HTTP/web.example@EXAMPLE.COM to alice, valid an hour around
// NOW, and its credential.
fn make_cred(svc_key: krb5::Key, sess_etype: i32, flags: u32, start: i64, end: i64) -> krb5::Credential {
    let sess = krb5::random_key(sess_etype);
    let tp = krb5::EncTicketPart {
        flags: flags, key: sess, crealm: "EXAMPLE.COM", cname: krb5::principal_name(1, "alice"), tr_type: 1, transited: "",
        authtime: start, has_starttime: true, starttime: start, endtime: end, has_renew_till: false, renew_till: 0,
        has_caddr: false, caddr: [], has_authz: true, authz: [krb5::AuthData { ad_type: 1, data: "\x30\x00" }],
    };
    var plain: u8[>..] = [];
    krb5::encode_enc_ticket_part(plain, tp);
    var c: u8[>..] = [];
    tv::check_int("ticket encrypt", krb5::encrypt(svc_key, 2, plain, c), krb5::OK);
    let t = krb5::Ticket { realm: "EXAMPLE.COM", sname: krb5::principal_name(1, "HTTP/web.example"),
                           enc_part: krb5::EncryptedData { etype: svc_key.etype, has_kvno: true, kvno: 3, cipher: copy(c) } };
    var der: u8[>..] = [];
    krb5::encode_ticket(der, t);
    return krb5::Credential {
        client_type: 1, client: "alice", client_realm: "EXAMPLE.COM", server_type: 1, server: "HTTP/web.example",
        server_realm: "EXAMPLE.COM", key: sess, authtime: start, starttime: start, endtime: end, renew_till: 0,
        is_skey: false, flags: flags, addresses: [], authdata: [], ticket: der, second_ticket: "",
    };
}

fn keytab_of(k: krb5::Key) -> krb5::KeytabEntry[>..] {
    var kt: krb5::KeytabEntry[>..] = [];
    kt.push(krb5::KeytabEntry { name_type: 1, name: "HTTP/web.example", realm: "EXAMPLE.COM", timestamp: 0, kvno: 3, key: k });
    return kt;
}


fn basic() {
    let svc = krb5::random_key(18);
    let kt = keytab_of(svc);
    let cred = make_cred(svc, 18, 0, NOW - 600, NOW + 3000);
    var rc: krb5::ReplayEntry[>..] = [];
    var t1: u8[>..] = [];
    var ic, err = krb5::spnego_init(cred, krb5::GSS_MUTUAL, "", false, "", NOW, 0, t1);
    tv::check_int("init", err, krb5::OK);
    var ac = krb5::empty_spnego();
    var t2: u8[>..] = [];
    let done, acc, aerr = krb5::spnego_accept(ac, t1, kt, false, rc, NOW, 0, 300, "", false, t2);
    tv::check("accept done", aerr == krb5::OK && done && acc.ap.client == "alice");
    var t3: u8[>..] = [];
    let idone, ierr = krb5::spnego_init_continue(ic, t2, t3);
    tv::check("init done", ierr == krb5::OK && idone && t3.len == 0);
    // The contexts protect messages.
    var w: u8[>..] = [];
    krb5::gss_wrap(ic.gss, "hello", true, w);
    var u: u8[>..] = [];
    let s, uerr = krb5::gss_unwrap(ac.gss, w, u);
    tv::check("wrap after spnego", uerr == krb5::OK && u == "hello");
    // The Negotiate header round trip.
    let h = krb5::negotiate_header(t1);
    let back, ok = krb5::negotiate_token(h);
    tv::check("negotiate header", ok && back == t1);
    let b2, ok2 = krb5::negotiate_token("NEGOTIATE   ");
    tv::check("empty negotiate", ok2 && b2.len == 0);
    let b3, ok3 = krb5::negotiate_token("Basic abc");
    tv::check("not negotiate", !ok3);
}

// A NegTokenInit as Windows or an NTLM-first client would send it.
fn foreign_init(oids: const u8[][:], krb_token: const u8[:], with_token: bool) -> u8[>..] {
    var list: u8[>..] = [];
    krb5::mech_type_list(list, oids);
    var out: u8[>..] = [];
    krb5::spnego_init_token(out, list, if with_token { krb_token } else { "" }, "");
    return out;
}

fn ms_first() {
    let svc = krb5::random_key(18);
    let kt = keytab_of(svc);
    let cred = make_cred(svc, 18, 0, NOW - 600, NOW + 3000);
    var rc: krb5::ReplayEntry[>..] = [];
    var kt1: u8[>..] = [];
    var g, err = krb5::gss_init(cred, krb5::GSS_MUTUAL, "", false, "", NOW, 0, kt1);
    var oids: u8[][>..] = [];
    oids.push(krb5::MS_KRB5_OID);
    oids.push(krb5::KRB5_OID);
    oids.push(krb5::NTLM_OID);
    let t1 = foreign_init(oids, kt1, true);
    var ac = krb5::empty_spnego();
    var t2: u8[>..] = [];
    let done, acc, aerr = krb5::spnego_accept(ac, t1, kt, false, rc, NOW, 0, 300, "", false, t2);
    tv::check("ms first accepted", aerr == krb5::OK && done && ac.ms_oid);
    // The reply names the MS OID and carries the AP-REP.
    let t, ok = asn1::parse(t2, true);
    let inner, iok = asn1::explicit(t2, t, true);
    let state, mech, resp, mic, good = krb5::read_neg_resp(t2, inner);
    tv::check("ms reply", good && state == 0 && mech == krb5::MS_KRB5_OID && resp.len > 0);
    tv::check_int("ap-rep in it", krb5::gss_init_continue(g, resp), krb5::OK);
}

fn ntlm_first() {
    let svc = krb5::random_key(17);
    let kt = keytab_of(svc);
    let cred = make_cred(svc, 17, 0, NOW - 600, NOW + 3000);
    var rc: krb5::ReplayEntry[>..] = [];
    var oids: u8[][>..] = [];
    oids.push(krb5::NTLM_OID);
    oids.push(krb5::KRB5_OID);
    var list: u8[>..] = [];
    krb5::mech_type_list(list, oids);
    let t1 = foreign_init(oids, "NTLMSSP\x00 negotiate message", true);
    var ac = krb5::empty_spnego();
    var t2: u8[>..] = [];
    let done, acc, aerr = krb5::spnego_accept(ac, t1, kt, false, rc, NOW, 0, 300, "", false, t2);
    tv::check("ntlm first: incomplete", aerr == krb5::OK && !done);
    let t, ok = asn1::parse(t2, true);
    let inner, iok = asn1::explicit(t2, t, true);
    let state, mech, resp, mic, good = krb5::read_neg_resp(t2, inner);
    tv::check("ntlm first: krb5 named", good && state == 1 && mech == krb5::KRB5_OID && resp.len == 0);
    // The initiator now sends its Kerberos token in a NegTokenResp.
    var kt1: u8[>..] = [];
    var g, err = krb5::gss_init(cred, krb5::GSS_MUTUAL, "", false, "", NOW, 0, kt1);
    var t3: u8[>..] = [];
    krb5::spnego_resp_token(t3, -1, "", kt1, "");
    var t4: u8[>..] = [];
    let done2, acc2, aerr2 = krb5::spnego_accept(ac, t3, kt, false, rc, NOW, 0, 300, "", false, t4);
    // Kerberos was not the first choice: the acceptor sends a MIC and
    // waits for the initiator's.
    tv::check("ntlm first: accepted, mic pending", aerr2 == krb5::OK && !done2 && ac.mic_sent);
    let r, rok = asn1::parse(t4, true);
    let rin, riok = asn1::explicit(t4, r, true);
    let st2, mech2, resp2, mic2, good2 = krb5::read_neg_resp(t4, rin);
    tv::check("ntlm first: reply", good2 && st2 == 1 && resp2.len > 0 && mic2.len > 0);
    tv::check_int("ntlm first: ap-rep", krb5::gss_init_continue(g, resp2), krb5::OK);
    tv::check_int("ntlm first: acceptor mic", krb5::gss_verify_mic(g, list, mic2), krb5::OK);
    var m: u8[>..] = [];
    krb5::gss_get_mic(g, list, m);
    var t5: u8[>..] = [];
    krb5::spnego_resp_token(t5, -1, "", "", m);
    var t6: u8[>..] = [];
    let done3, acc3, aerr3 = krb5::spnego_accept(ac, t5, kt, false, rc, NOW, 0, 300, "", false, t6);
    tv::check("ntlm first: complete", aerr3 == krb5::OK && done3);
    // A wrong MIC is refused.
    var ac2 = krb5::empty_spnego();
    var x: u8[>..] = [];
    let d1, a1, e1 = krb5::spnego_accept(ac2, t1, kt, false, rc, NOW, 0, 300, "", false, x);
    var kt2: u8[>..] = [];
    var g2, err2 = krb5::gss_init(cred, krb5::GSS_MUTUAL, "", false, "", NOW, 1, kt2);
    var y: u8[>..] = [];
    krb5::spnego_resp_token(y, -1, "", kt2, "");
    var z: u8[>..] = [];
    let d2, a2, e2 = krb5::spnego_accept(ac2, y, kt, false, rc, NOW, 0, 300, "", false, z);
    var bad: u8[>..] = [];
    krb5::spnego_resp_token(bad, -1, "", "", m);
    var w: u8[>..] = [];
    let d3, a3, e3 = krb5::spnego_accept(ac2, bad, kt, false, rc, NOW, 0, 300, "", false, w);
    tv::check("wrong mic refused", e3 != krb5::OK);
}

// Our initiator against an acceptor that sends a MIC: it answers with its own.
fn initiator_mic() {
    let svc = krb5::random_key(18);
    let kt = keytab_of(svc);
    let cred = make_cred(svc, 18, 0, NOW - 600, NOW + 3000);
    var rc: krb5::ReplayEntry[>..] = [];
    var t1: u8[>..] = [];
    var ic, err = krb5::spnego_init(cred, krb5::GSS_MUTUAL, "", false, "", NOW, 0, t1);
    // An acceptor that wants MICs: answer as one with request-mic.
    var ac = krb5::empty_spnego();
    var t2: u8[>..] = [];
    let done, acc, aerr = krb5::spnego_accept(ac, t1, kt, false, rc, NOW, 0, 300, "", false, t2);
    let t, ok = asn1::parse(t2, true);
    let inner, iok = asn1::explicit(t2, t, true);
    let state, mech, resp, mic, good = krb5::read_neg_resp(t2, inner);
    var m: u8[>..] = [];
    krb5::gss_get_mic(ac.gss, ac.mech_list, m);
    var t2b: u8[>..] = [];
    krb5::spnego_resp_token(t2b, krb5::NEG_ACCEPT_INCOMPLETE, krb5::KRB5_OID, resp, m);
    var t3: u8[>..] = [];
    let idone, ierr = krb5::spnego_init_continue(ic, t2b, t3);
    tv::check("initiator answers a mic", ierr == krb5::OK && t3.len > 0 && ic.mic_received && ic.mic_sent);
    let r, rok = asn1::parse(t3, true);
    let rin, riok = asn1::explicit(t3, r, true);
    let st, mc, rs, imic, good2 = krb5::read_neg_resp(t3, rin);
    tv::check_int("initiator mic verifies", krb5::gss_verify_mic(ac.gss, ac.mech_list, imic), krb5::OK);
}

fn raw_and_reject() {
    let svc = krb5::random_key(18);
    let kt = keytab_of(svc);
    let cred = make_cred(svc, 18, 0, NOW - 600, NOW + 3000);
    var rc: krb5::ReplayEntry[>..] = [];
    var kt1: u8[>..] = [];
    var g, err = krb5::gss_init(cred, krb5::GSS_MUTUAL, "", false, "", NOW, 0, kt1);
    var ac = krb5::empty_spnego();
    var t2: u8[>..] = [];
    let done, acc, aerr = krb5::spnego_accept(ac, kt1, kt, false, rc, NOW, 0, 300, "", false, t2);
    tv::check("raw kerberos accepted", aerr == krb5::OK && done && ac.raw);
    tv::check_int("raw ap-rep", krb5::gss_init_continue(g, t2), krb5::OK);
    var oids: u8[][>..] = [];
    oids.push(krb5::NTLM_OID);
    let t1 = foreign_init(oids, "x", true);
    var ac2 = krb5::empty_spnego();
    var t3: u8[>..] = [];
    let d2, a2, e2 = krb5::spnego_accept(ac2, t1, kt, false, rc, NOW, 0, 300, "", false, t3);
    tv::check("ntlm only rejected", e2 == krb5::ERR_MECH && t3.len > 0);
    var ac3 = krb5::empty_spnego();
    var t4: u8[>..] = [];
    let d3, a3, e3 = krb5::spnego_accept(ac3, "garbage", kt, false, rc, NOW, 0, 300, "", false, t4);
    tv::check("garbage refused", e3 != krb5::OK);
}

fn main() {
    basic();
    ms_first();
    ntlm_first();
    initiator_mic();
    raw_and_reject();
    tv::done("spnego");
}
