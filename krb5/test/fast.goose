// krb5.fast without a KDC: this test plays the KDC's side with the
// message encoders (as MIT's kdc/fast_util.c does it) and checks the
// client's armor, armored requests, replies, errors and encrypted
// challenge, and every way a reply is refused: no FAST response, another
// nonce, no finished part, an altered ticket, an unkeyed checksum, the
// wrong armor key, the challenge keys' directions crossed. For every
// encryption type as the armor's, DES3's block padding included.

import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.ccache;
import gslib.krb5.fast;
import tv;

let NOW = 1800000000;
let ETYPES: i32[8] = [16, 17, 18, 19, 20, 23, 25, 26];

// A TGT for host/fast@F.TEST, its session key of type e, under krbtgt's key.
fn make_tgt(tgs_key: krb5::Key, e: i32) -> krb5::Credential {
    let sess = krb5::random_key(e);
    let tp = krb5::EncTicketPart {
        flags: 0, key: sess, crealm: "F.TEST", cname: krb5::principal_name(3, "host/fast"), tr_type: 1, transited: "",
        authtime: NOW, has_starttime: false, starttime: 0, endtime: NOW + 3600, has_renew_till: false, renew_till: 0,
        has_caddr: false, caddr: [], has_authz: false, authz: [],
    };
    var plain: u8[>..] = [];
    krb5::encode_enc_ticket_part(plain, tp);
    var c: u8[>..] = [];
    tv::check_int("ticket encrypt", krb5::encrypt(tgs_key, krb5::USAGE_KDC_REP_TICKET, plain, c), krb5::OK);
    let t = krb5::Ticket { realm: "F.TEST", sname: krb5::principal_name(2, "krbtgt/F.TEST"),
                           enc_part: krb5::EncryptedData { etype: tgs_key.etype, has_kvno: true, kvno: 1, cipher: copy(c) } };
    var der: u8[>..] = [];
    krb5::encode_ticket(der, t);
    return krb5::Credential {
        client_type: 3, client: "host/fast", client_realm: "F.TEST", server_type: 2, server: "krbtgt/F.TEST",
        server_realm: "F.TEST", key: sess, authtime: NOW, starttime: NOW, endtime: NOW + 3600, renew_till: 0,
        is_skey: false, flags: 0, addresses: [], authdata: [], ticket: der, second_ticket: "",
    };
}

// The KDC's reading of AS armor (MIT's armor_ap_request): the ticket and
// authenticator decrypted, the armor key made from the subkey.
fn kdc_armor_key(tgs_key: krb5::Key, armor: const krb5::KrbFastArmor&) -> krb5::Key, bool {
    let ap, aerr = krb5::decode_ap_req(armor.value);
    if aerr != krb5::OK { return krb5::no_key(), false; }
    let t, terr = krb5::decode_ticket(ap.ticket);
    var tp_der: u8[>..] = [];
    if krb5::decrypt(tgs_key, krb5::USAGE_KDC_REP_TICKET, t.enc_part.cipher, tp_der) != krb5::OK { return krb5::no_key(), false; }
    let tp, tperr = krb5::decode_enc_ticket_part(tp_der);
    var a_der: u8[>..] = [];
    if krb5::decrypt(tp.key, krb5::USAGE_AP_REQ_AUTHENTICATOR, ap.authenticator.cipher, a_der) != krb5::OK {
        return krb5::no_key(), false;
    }
    let a, a2err = krb5::decode_authenticator(a_der);
    if a2err != krb5::OK || !a.has_subkey || a.has_cksum { return krb5::no_key(), false; }
    let k, kerr = krb5::fx_cf2(a.subkey, "subkeyarmor", tp.key, "ticketarmor");
    return k, kerr == krb5::OK;
}

fn sample_body(nonce: u32) -> krb5::KdcReqBody {
    return krb5::KdcReqBody {
        kdc_options: 0x40000010, has_cname: true, cname: krb5::principal_name(1, "grace"), realm: "F.TEST", has_sname: true,
        sname: krb5::principal_name(2, "krbtgt/F.TEST"), has_from: false, from: 0, till: NOW + 3600, has_rtime: false,
        rtime: 0, nonce: nonce, etypes: [18, 17], has_addresses: false, addresses: [], has_enc_authz: false,
        enc_authz: krb5::no_enc_data(), has_tickets: false, tickets: [],
    };
}

// A KrbFastResponse under the armor key as PA-FX-FAST.
fn fast_pa(armor_key: krb5::Key, r: const krb5::KrbFastResponse&) -> krb5::PaData {
    var der: u8[>..] = [];
    krb5::encode_fast_response(der, r);
    var c: u8[>..] = [];
    tv::check_int("fast response encrypt", krb5::encrypt(armor_key, krb5::USAGE_FAST_REP, der, c), krb5::OK);
    var v: u8[>..] = [];
    let d = krb5::EncryptedData { etype: armor_key.etype, has_kvno: false, kvno: 0, cipher: copy(c) };
    krb5::encode_pa_fx_fast_reply(v, d);
    return krb5::PaData { pa_type: krb5::PA_FX_FAST, value: copy(v) };
}

fn finished(armor_key: krb5::Key, ticket: const u8[:], ctype: i32) -> krb5::KrbFastFinished {
    var ck: u8[>..] = [];
    tv::check_int("finished checksum", krb5::checksum(armor_key, ctype, krb5::USAGE_FAST_FINISHED, ticket, ck), krb5::OK);
    return krb5::KrbFastFinished { timestamp: NOW, usec: 5, crealm: "F.TEST", cname: krb5::principal_name(1, "grace"),
                                   ticket_checksum: krb5::Checksum { ctype: if ctype == 0 { krb5::cksum_type_for(armor_key.etype) } else { ctype },
                                                                     sum: copy(ck) } };
}

fn rep_with(pa: const krb5::PaData[:], ticket: const u8[:]) -> krb5::KdcRep {
    return krb5::KdcRep { msg_type: krb5::MSG_AS_REP, has_padata: true, padata: pa, crealm: "F.TEST",
                          cname: krb5::principal_name(1, "mallory"), ticket: ticket,
                          enc_part: krb5::EncryptedData { etype: 18, has_kvno: false, kvno: 0, cipher: "x" } };
}

fn one_type(e: i32) {
    let w = str("etype ", e, ": ");
    let tgs_key = krb5::random_key(18);
    let tgt = make_tgt(tgs_key, e);

    // AS armor, read as the KDC reads it.
    let st, err = krb5::fast_armor_as(tgt, NOW, 7);
    tv::check_int(str(w, "armor"), err, krb5::OK);
    tv::check(str(w, "armor key of the session key's type"), st.has_armor && st.armor_key.etype == e
              && st.armor.armor_type == krb5::FX_FAST_ARMOR_AP_REQUEST);
    let kk, kok = kdc_armor_key(tgs_key, st.armor);
    tv::check(str(w, "KDC's armor key is ours"), kok && kk.etype == e && kk.value[..] == st.armor_key.value[..]);

    // The armored AS-REQ, read as the KDC reads it.
    let nonce: u32 = 0x12345678;
    let body = sample_body(nonce);
    var body_der: u8[>..] = [];
    krb5::encode_req_body(body_der, body);
    var inner: krb5::PaData[>..] = [];
    inner.push(krb5::PaData { pa_type: krb5::PA_FX_COOKIE, value: "cookie" });
    inner.push(krb5::PaData { pa_type: krb5::PA_PAC_REQUEST, value: "\x30\x05\xa0\x03\x01\x01\xff" });
    var none: krb5::PaData[>..] = [];
    var req: u8[>..] = [];
    tv::check_int(str(w, "wrap"), krb5::fast_wrap(st, krb5::MSG_AS_REQ, inner, none, body, body_der, req), krb5::OK);
    let r, rerr = krb5::decode_kdc_req(req);
    tv::check_int(str(w, "outer request"), rerr, krb5::OK);
    var n = 0;
    var fx: u8[>..] = [];
    for p in r.padata { n++; if p.pa_type == krb5::PA_FX_FAST { fx.append(p.value); } }
    tv::check(str(w, "outer padata is PA-FX-FAST alone"), n == 1 && fx.len > 0);
    let ar, arerr = krb5::decode_pa_fx_fast_request(fx);
    tv::check(str(w, "armored request"), arerr == krb5::OK && ar.has_armor && ar.armor.value == st.armor.value);
    tv::check_int(str(w, "request checksum over the body"),
                  krb5::verify_checksum(kk, ar.req_checksum.ctype, krb5::USAGE_FAST_REQ_CHKSUM, body_der, ar.req_checksum.sum),
                  krb5::OK);
    var fr_der: u8[>..] = [];
    tv::check_int(str(w, "inner request decrypts"), krb5::decrypt(kk, krb5::USAGE_FAST_ENC, ar.enc_fast_req.cipher, fr_der),
                  krb5::OK);
    let fr, frerr = krb5::decode_fast_req(krb5::der_unpadded(fr_der));
    var m = 0;
    for p in fr.padata { if (m == 0 && p.pa_type == 133 && p.value == "cookie") || (m == 1 && p.pa_type == 128) { m++; } }
    tv::check(str(w, "inner request: padata and body"), frerr == krb5::OK && m == 2 && fr.req_body.nonce == nonce
              && fr.req_body.cname.name == "grace");

    // Replies.
    let ticket = tgt.ticket;
    let fin = finished(kk, ticket, 0);
    let strengthen = krb5::random_key(18);
    let good = krb5::KrbFastResponse {
        padata: [krb5::PaData { pa_type: krb5::PA_ETYPE_INFO2, value: "info" }], has_strengthen_key: true,
        strengthen_key: strengthen, has_finished: true, finished: copy(fin), nonce: nonce,
    };
    let pa_good = fast_pa(kk, good);
    let pa1: krb5::PaData[] = [copy(pa_good)];
    let rep = rep_with(pa1, ticket);
    let got, gerr = krb5::fast_reply(st, rep, nonce);
    tv::check(str(w, "reply checks"), gerr == krb5::OK && got.finished.cname.name == "grace" && got.has_strengthen_key);
    let rk, rkerr = krb5::fast_reply_key(got, tgt.key);
    let want_rk, werr = krb5::fx_cf2(strengthen, "strengthenkey", tgt.key, "replykey");
    tv::check(str(w, "strengthened reply key"), rkerr == krb5::OK && werr == krb5::OK && rk.etype == 18
              && rk.value[..] == want_rk.value[..]);
    let other, oerr = krb5::fast_reply(st, rep, nonce + 1);
    tv::check_int(str(w, "another nonce refused"), oerr, krb5::ERR_FAST);
    let pa_bare: krb5::PaData[] = [krb5::PaData { pa_type: krb5::PA_ETYPE_INFO2, value: "info" }];
    let bare = rep_with(pa_bare, ticket);
    let b, berr = krb5::fast_reply(st, bare, nonce);
    tv::check_int(str(w, "no PA-FX-FAST refused"), berr, krb5::ERR_FAST);
    var altered: u8[>..] = [];
    altered.append(ticket);
    altered[altered.len - 1] ^= 1;
    let alt = rep_with(pa1, altered);
    let a, aerr = krb5::fast_reply(st, alt, nonce);
    tv::check_int(str(w, "altered ticket refused"), aerr, krb5::ERR_FAST);
    let no_fin = krb5::KrbFastResponse { padata: [], has_strengthen_key: false, strengthen_key: krb5::no_key(),
                                         has_finished: false, finished: krb5::no_fast_finished(), nonce: nonce };
    let pa_nf: krb5::PaData[] = [fast_pa(kk, no_fin)];
    let rep_nf = rep_with(pa_nf, ticket);
    let nf, nferr = krb5::fast_reply(st, rep_nf, nonce);
    tv::check_int(str(w, "no finished part refused"), nferr, krb5::ERR_FAST);
    let unkeyed = krb5::KrbFastResponse { padata: [], has_strengthen_key: false, strengthen_key: krb5::no_key(),
                                          has_finished: true, finished: finished(kk, ticket, krb5::CKSUM_SHA1), nonce: nonce };
    let pa_u: krb5::PaData[] = [fast_pa(kk, unkeyed)];
    let rep_u = rep_with(pa_u, ticket);
    let u, uerr = krb5::fast_reply(st, rep_u, nonce);
    tv::check_int(str(w, "unkeyed ticket checksum refused"), uerr, krb5::ERR_FAST);
    let wrong_key = krb5::random_key(e);
    let pa_w: krb5::PaData[] = [fast_pa(wrong_key, good)];
    let rep_w = rep_with(pa_w, ticket);
    let wr, wrerr = krb5::fast_reply(st, rep_w, nonce);
    tv::check_int(str(w, "another armor key refused"), wrerr, krb5::ERR_FAST);
    let plain_rk, prerr = krb5::fast_reply_key(no_fin, tgt.key);
    tv::check(str(w, "no strengthen key: the reply key as it is"), prerr == krb5::OK && plain_rk.value[..] == tgt.key.value[..]);

    // An armored error: the KRB-ERROR inside, and the padata beside it.
    let inner_err = krb5::KrbError {
        has_ctime: false, ctime: 0, has_cusec: false, cusec: 0, stime: NOW + 30, susec: 0,
        error_code: krb5::KDC_ERR_PREAUTH_REQUIRED, has_crealm: false, crealm: "", has_cname: false, cname: krb5::no_principal(),
        realm: "F.TEST", sname: krb5::principal_name(2, "krbtgt/F.TEST"), has_etext: false, etext: "", has_edata: false, edata: "",
    };
    var ie: u8[>..] = [];
    krb5::encode_krb_error(ie, inner_err);
    let er = krb5::KrbFastResponse {
        padata: [krb5::PaData { pa_type: krb5::PA_FX_COOKIE, value: "c1" },
                 krb5::PaData { pa_type: krb5::PA_ENCRYPTED_CHALLENGE, value: "" },
                 krb5::PaData { pa_type: krb5::PA_FX_ERROR, value: copy(ie) }],
        has_strengthen_key: false, strengthen_key: krb5::no_key(), has_finished: false, finished: krb5::no_fast_finished(), nonce: nonce,
    };
    var edata: u8[>..] = [];
    let pa_er: krb5::PaData[] = [fast_pa(kk, er)];
    krb5::encode_padata(edata, pa_er);
    let outer = krb5::KrbError {
        has_ctime: false, ctime: 0, has_cusec: false, cusec: 0, stime: NOW, susec: 0, error_code: krb5::KRB_ERR_GENERIC,
        has_crealm: false, crealm: "", has_cname: false, cname: krb5::no_principal(), realm: "F.TEST",
        sname: krb5::principal_name(2, "krbtgt/F.TEST"), has_etext: false, etext: "", has_edata: true, edata: copy(edata),
    };
    let ke, hints, keerr = krb5::fast_error(true, st, outer, nonce);
    var hn = 0;
    var cookie = false;
    for h in hints { hn++; if h.pa_type == krb5::PA_FX_COOKIE && h.value == "c1" { cookie = true; } }
    tv::check(str(w, "armored error read"), keerr == krb5::OK && ke.error_code == krb5::KDC_ERR_PREAUTH_REQUIRED
              && ke.stime == NOW + 30 && hn == 2 && cookie);
    let ke2, hints2, keerr2 = krb5::fast_error(true, st, outer, nonce + 1);
    tv::check_int(str(w, "armored error, another nonce"), keerr2, krb5::ERR_FAST);
    let er_nofx = krb5::KrbFastResponse { padata: [krb5::PaData { pa_type: krb5::PA_FX_COOKIE, value: "c1" }],
                                          has_strengthen_key: false, strengthen_key: krb5::no_key(), has_finished: false,
                                          finished: krb5::no_fast_finished(), nonce: nonce };
    var edata2: u8[>..] = [];
    let pa_er2: krb5::PaData[] = [fast_pa(kk, er_nofx)];
    krb5::encode_padata(edata2, pa_er2);
    let outer2 = krb5::KrbError {
        has_ctime: false, ctime: 0, has_cusec: false, cusec: 0, stime: NOW, susec: 0, error_code: krb5::KRB_ERR_GENERIC,
        has_crealm: false, crealm: "", has_cname: false, cname: krb5::no_principal(), realm: "F.TEST",
        sname: krb5::principal_name(2, "krbtgt/F.TEST"), has_etext: false, etext: "", has_edata: true, edata: copy(edata2),
    };
    let ke3, hints3, keerr3 = krb5::fast_error(true, st, outer2, nonce);
    tv::check_int(str(w, "armored error without PA-FX-ERROR"), keerr3, krb5::ERR_FAST);
    let ke4, hints4, keerr4 = krb5::fast_error(true, st, inner_err, nonce);
    tv::check_int(str(w, "unarmored error under armor"), keerr4, krb5::ERR_FAST);

    // Encrypted challenge, both ways, with a long-term key of another type.
    let lt = krb5::random_key(if e == 26 { 17 } else { 26 });
    var ec: u8[>..] = [];
    tv::check_int(str(w, "client challenge"), krb5::enc_challenge(st, lt, NOW, 9, ec), krb5::OK);
    let ecd, ecerr = krb5::decode_enc_data(ec);
    let cck, cckerr = krb5::fx_cf2(kk, "clientchallengearmor", lt, "challengelongterm");
    var ts: u8[>..] = [];
    tv::check(str(w, "KDC reads the client's challenge"), ecerr == krb5::OK && ecd.etype == e
              && krb5::decrypt(cck, krb5::USAGE_ENC_CHALLENGE_CLIENT, ecd.cipher, ts) == krb5::OK);
    let t, has_us, us, tserr = krb5::decode_pa_enc_ts(krb5::der_unpadded(ts));
    tv::check(str(w, "client challenge time"), tserr == krb5::OK && t == NOW && us == 9);
    fn kdc_challenge(kk: krb5::Key, lt: krb5::Key, pepper: const u8[:], usage: i64) -> krb5::PaData {
        let k, err = krb5::fx_cf2(kk, pepper, lt, "challengelongterm");
        var ts: u8[>..] = [];
        krb5::encode_pa_enc_ts(ts, NOW, true, 1);
        var c: u8[>..] = [];
        krb5::encrypt(k, usage, ts, c);
        var v: u8[>..] = [];
        let d = krb5::EncryptedData { etype: k.etype, has_kvno: false, kvno: 0, cipher: copy(c) };
        krb5::encode_enc_data(v, d);
        return krb5::PaData { pa_type: krb5::PA_ENCRYPTED_CHALLENGE, value: copy(v) };
    }
    let ch_good: krb5::PaData[] = [kdc_challenge(kk, lt, "kdcchallengearmor", krb5::USAGE_ENC_CHALLENGE_KDC)];
    let ch_client: krb5::PaData[] = [kdc_challenge(kk, lt, "clientchallengearmor", krb5::USAGE_ENC_CHALLENGE_CLIENT)];
    let ch_other: krb5::PaData[] = [kdc_challenge(kk, krb5::random_key(lt.etype), "kdcchallengearmor", krb5::USAGE_ENC_CHALLENGE_KDC)];
    tv::check_int(str(w, "KDC challenge checks"),
                  krb5::check_kdc_challenge(st, lt, ch_good),
                  krb5::OK);
    tv::check_int(str(w, "client's challenge sent back refused"),
                  krb5::check_kdc_challenge(st, lt, ch_client),
                  krb5::ERR_FAST);
    tv::check_int(str(w, "KDC challenge under another long-term key refused"),
                  krb5::check_kdc_challenge(st, lt, ch_other),
                  krb5::ERR_FAST);
    var no_pa: krb5::PaData[>..] = [];
    tv::check_int(str(w, "no KDC challenge refused"), krb5::check_kdc_challenge(st, lt, no_pa), krb5::ERR_FAST);

    // TGS: implicit armor from the subkey and session key, the outer
    // padata PA-TGS-REQ then PA-FX-FAST, the checksum over the AP-REQ.
    let subkey = krb5::random_key(e);
    let ts2, tserr2 = krb5::fast_armor_tgs(subkey, tgt.key);
    let want_tk, wtkerr = krb5::fx_cf2(subkey, "subkeyarmor", tgt.key, "ticketarmor");
    tv::check(str(w, "TGS implicit armor"), tserr2 == krb5::OK && !ts2.has_armor && ts2.armor_key.value[..] == want_tk.value[..]);
    let ap = "the AP-REQ";
    var outer_pa: krb5::PaData[>..] = [];
    outer_pa.push(krb5::PaData { pa_type: krb5::PA_TGS_REQ, value: ap });
    var treq: u8[>..] = [];
    var no_inner: krb5::PaData[>..] = [];
    tv::check_int(str(w, "TGS wrap"), krb5::fast_wrap(ts2, krb5::MSG_TGS_REQ, no_inner, outer_pa, body, ap, treq), krb5::OK);
    let tr, trerr = krb5::decode_kdc_req(treq);
    var order: i32[>..] = [];
    var tfx: u8[>..] = [];
    for p in tr.padata { order.push(p.pa_type); if p.pa_type == krb5::PA_FX_FAST { tfx.append(p.value); } }
    let want_order: i32[2] = [krb5::PA_TGS_REQ, krb5::PA_FX_FAST];
    tv::check(str(w, "TGS outer padata"), trerr == krb5::OK && tr.msg_type == krb5::MSG_TGS_REQ && order[..] == want_order[..]);
    let tar, tarerr = krb5::decode_pa_fx_fast_request(tfx);
    tv::check(str(w, "TGS armored request: no armor, checksum over the AP-REQ"), tarerr == krb5::OK && !tar.has_armor
              && krb5::verify_checksum(want_tk, tar.req_checksum.ctype, krb5::USAGE_FAST_REQ_CHKSUM, ap, tar.req_checksum.sum)
                 == krb5::OK);
}

fn main() {
    for e in ETYPES { one_type(e); }
    tv::done("fast");
}
