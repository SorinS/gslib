// krb5.fast: FAST (RFC 6113), the client's side. A KDC request travels
// inside an armor: its real padata and body are encrypted under the
// armor key, and the KDC's reply comes back inside it too, its errors
// authenticated and its reply key strengthened.
//
// The armor key. In an AS exchange it comes from a TGT the client already
// has (a host's, say: MIT's kinit -T, Windows' machine account): an
// AP-REQ for that TGT with a fresh subkey, and
// KRB-FX-CF2(subkey, "subkeyarmor", session key, "ticketarmor"). In a TGS
// exchange the TGT the request is made with is the armor (implicit
// armor): the same function of the authenticator's subkey and the TGT's
// session key.
//
// A reply is checked as RFC 6113 §5.4.3 asks: the FAST response decrypts
// under the armor key, carries the request's nonce, and for a ticket
// carries the finished part, whose checksum covers the reply's ticket and
// whose names replace the reply's unprotected ones.

namespace krb5;

import std;
import encoding.asn1;
import krb5.crypto;
import krb5.messages;
import krb5.ccache;

// One armored exchange: the armor key, and the armor to send (none for a
// TGS-REQ's implicit armor).
struct FastState { armor_key: Key, has_armor: bool, armor: KrbFastArmor }

fn no_fast_state() -> FastState {
    FastState { armor_key: Key { etype: 0, value: [] }, has_armor: false,
                armor: KrbFastArmor { armor_type: 0, value: "" } }
}

// Armor for an AS exchange from `tgt`, a TGT for the realm asked
// (krbtgt/REALM@REALM): an AP-REQ with a new subkey of the session key's
// type and no checksum (MIT's KDC refuses armor without a subkey). `now`
// and `usec` are the KDC's time.
fn fast_armor_as(tgt: const Credential&, now: i64, usec: i64) -> FastState, i64 {
    let subkey = random_key(tgt.key.etype);
    if subkey.etype == 0 { return no_fast_state(), ERR_ETYPE; }
    let auth = Authenticator {
        crealm: copy(tgt.client_realm), cname: PrincipalName { name_type: tgt.client_type, name: copy(tgt.client) },
        has_cksum: false, cksum: no_checksum(), cusec: usec, ctime: now, has_subkey: true, subkey: subkey,
        has_seq_number: false, seq_number: 0, has_authz: false, authz: [],
    };
    var auth_der: u8[>..] = [];
    encode_authenticator(auth_der, auth);
    var auth_enc: u8[>..] = [];
    let err = encrypt(tgt.key, USAGE_AP_REQ_AUTHENTICATOR, auth_der, auth_enc);
    if err != OK { return no_fast_state(), err; }
    let ap = ApReq { ap_options: 0, ticket: copy(tgt.ticket),
                     authenticator: EncryptedData { etype: tgt.key.etype, has_kvno: false, kvno: 0, cipher: copy(auth_enc) } };
    var ap_der: u8[>..] = [];
    encode_ap_req(ap_der, ap);
    let key, kerr = fx_cf2(subkey, "subkeyarmor", tgt.key, "ticketarmor");
    if kerr != OK { return no_fast_state(), kerr; }
    return FastState { armor_key: key, has_armor: true,
                       armor: KrbFastArmor { armor_type: FX_FAST_ARMOR_AP_REQUEST, value: copy(ap_der) } }, OK;
}

// Implicit armor for a TGS exchange: from the authenticator's subkey and
// the TGT's session key.
fn fast_armor_tgs(subkey: Key, session_key: Key) -> FastState, i64 {
    let key, err = fx_cf2(subkey, "subkeyarmor", session_key, "ticketarmor");
    if err != OK { return no_fast_state(), err; }
    return FastState { armor_key: key, has_armor: false, armor: KrbFastArmor { armor_type: 0, value: "" } }, OK;
}

// The armored request: `inner` (the request's real padata) and `body`
// inside the armor; outside, `outer` (a TGS-REQ's PA-TGS-REQ) and then
// PA-FX-FAST, and the same body. The request's checksum is over
// `checksummed`: the body's DER for an AS-REQ, the PA-TGS-REQ's AP-REQ
// for a TGS-REQ (RFC 6113 §5.4.2).
fn fast_wrap(st: const FastState&, msg_type: i64, inner: const PaData[:], outer: const PaData[:], body: const KdcReqBody&,
             checksummed: const u8[:], out: u8[>..]&) -> i64 {
    let fr = KrbFastReq { fast_options: 0, padata: inner, req_body: copy(body) };
    var fr_der: u8[>..] = [];
    encode_fast_req(fr_der, fr);
    var enc: u8[>..] = [];
    let eerr = encrypt(st.armor_key, USAGE_FAST_ENC, fr_der, enc);
    if eerr != OK { return eerr; }
    var ck: u8[>..] = [];
    let cerr = checksum(st.armor_key, 0, USAGE_FAST_REQ_CHKSUM, checksummed, ck);
    if cerr != OK { return cerr; }
    let ar = KrbFastArmoredReq {
        has_armor: st.has_armor, armor: KrbFastArmor { armor_type: st.armor.armor_type, value: copy(st.armor.value) },
        req_checksum: Checksum { ctype: cksum_type_for(st.armor_key.etype), sum: copy(ck) },
        enc_fast_req: EncryptedData { etype: st.armor_key.etype, has_kvno: false, kvno: 0, cipher: copy(enc) },
    };
    var pa_der: u8[>..] = [];
    encode_pa_fx_fast_request(pa_der, ar);
    var pa: PaData[>..] = [];
    for p in outer { pa.push(copy(p)); }
    pa.push(PaData { pa_type: PA_FX_FAST, value: copy(pa_der) });
    let r = KdcReq { msg_type: msg_type, has_padata: true, padata: copy(pa), body: copy(body) };
    encode_kdc_req(out, r);
    return OK;
}

fn find_padata(pa: const PaData[:], ty: i32) -> u8[>..], bool {
    var out: u8[>..] = [];
    for p in pa {
        if p.pa_type == ty { out.append(p.value); return out, true; }
    }
    return out, false;
}

// A decrypted SEQUENCE without the zeros DES3 pads it with to its block;
// empty if anything but zeros follows it.
fn der_unpadded(plain: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let t, ok = asn1::read(plain, 0, plain.len, true);
    if !ok { return out; }
    for b in plain[t.end..] { if b != 0 { return out; } }
    out.append(plain[..t.end]);
    return out;
}

// The FAST response in `padata` (a reply's, or an error's e-data): ERR_FAST
// if there is none, it does not decrypt under the armor key, or its
// nonce is not the request's.
fn fast_response(st: const FastState&, padata: const PaData[:], nonce: u32) -> KrbFastResponse, i64 {
    let empty = no_fast_response();
    let v, found = find_padata(padata, PA_FX_FAST);
    if !found { return empty, ERR_FAST; }
    let d, derr = decode_pa_fx_fast_reply(v);
    if derr != OK { return empty, ERR_FAST; }
    var plain: u8[>..] = [];
    if decrypt(st.armor_key, USAGE_FAST_REP, d.cipher, plain) != OK { return empty, ERR_FAST; }
    let r, rerr = decode_fast_response(der_unpadded(plain));
    if rerr != OK || r.nonce != nonce { return empty, ERR_FAST; }
    return r, OK;
}

// The FAST response of an AS-REP or TGS-REP: as fast_response, and its
// finished part there with a checksum (keyed, under the armor key) of the
// reply's ticket.
fn fast_reply(st: const FastState&, rep: const KdcRep&, nonce: u32) -> KrbFastResponse, i64 {
    let r, err = fast_response(st, rep.padata, nonce);
    if err != OK { return r, err; }
    if !r.has_finished { return r, ERR_FAST; }
    let ck = r.finished.ticket_checksum;
    if cksum_etype(ck.ctype) == 0 { return r, ERR_FAST; }
    if verify_checksum(st.armor_key, ck.ctype, USAGE_FAST_FINISHED, rep.ticket, ck.sum) != OK { return r, ERR_FAST; }
    return r, OK;
}

// The reply key, strengthened if the KDC sent a strengthen key:
// KRB-FX-CF2(strengthen key, "strengthenkey", reply key, "replykey").
fn fast_reply_key(r: const KrbFastResponse&, key: Key) -> Key, i64 {
    if !r.has_strengthen_key { return key, OK; }
    return fx_cf2(r.strengthen_key, "strengthenkey", key, "replykey");
}

// The error inside an armored KRB-ERROR: the KRB-ERROR in the FAST
// response's PA-FX-ERROR, and the response's other padata (ETYPE-INFO2,
// PA-FX-COOKIE, the methods the KDC offers). ERR_FAST if the outer
// error's e-data holds no FAST response that checks. Not `armored`: the
// error as it is, with no padata (the caller reads its e-data).
fn fast_error(armored: bool, st: const FastState&, outer: const KrbError&, nonce: u32) -> KrbError, PaData[>..], i64 {
    var hints: PaData[>..] = [];
    if !armored { return copy(outer), hints, OK; }
    let pa, perr = decode_padata(outer.edata);
    if !outer.has_edata || perr != OK { return copy(outer), hints, ERR_FAST; }
    let r, rerr = fast_response(st, pa, nonce);
    if rerr != OK { return copy(outer), hints, ERR_FAST; }
    let v, found = find_padata(r.padata, PA_FX_ERROR);
    if !found { return copy(outer), hints, ERR_FAST; }
    let inner, ierr = decode_krb_error(v);
    if ierr != OK { return copy(outer), hints, ERR_FAST; }
    for p in r.padata { if p.pa_type != PA_FX_ERROR { hints.push(copy(p)); } }
    return inner, hints, OK;
}

// Encrypted challenge (RFC 6113 §5.4.6): PA-ENCRYPTED-CHALLENGE's value,
// the time (PA-ENC-TS-ENC) under
// KRB-FX-CF2(armor key, "clientchallengearmor", reply key, "challengelongterm").
fn enc_challenge(st: const FastState&, key: Key, now: i64, usec: i64, out: u8[>..]&) -> i64 {
    let ck, err = fx_cf2(st.armor_key, "clientchallengearmor", key, "challengelongterm");
    if err != OK { return err; }
    var ts: u8[>..] = [];
    encode_pa_enc_ts(ts, now, true, usec);
    var c: u8[>..] = [];
    let eerr = encrypt(ck, USAGE_ENC_CHALLENGE_CLIENT, ts, c);
    if eerr != OK { return eerr; }
    let d = EncryptedData { etype: ck.etype, has_kvno: false, kvno: 0, cipher: copy(c) };
    encode_enc_data(out, d);
    return OK;
}

// Checks the KDC's encrypted challenge in a reply's padata: its time
// under the KDC challenge key ("kdcchallengearmor"), which only a KDC that
// knows the client's key can make. ERR_FAST if missing or wrong.
fn check_kdc_challenge(st: const FastState&, key: Key, padata: const PaData[:]) -> i64 {
    let v, found = find_padata(padata, PA_ENCRYPTED_CHALLENGE);
    if !found { return ERR_FAST; }
    let d, derr = decode_enc_data(v);
    if derr != OK { return ERR_FAST; }
    let ck, err = fx_cf2(st.armor_key, "kdcchallengearmor", key, "challengelongterm");
    if err != OK { return err; }
    var plain: u8[>..] = [];
    if decrypt(ck, USAGE_ENC_CHALLENGE_KDC, d.cipher, plain) != OK { return ERR_FAST; }
    let t, has_usec, usec, terr = decode_pa_enc_ts(der_unpadded(plain));
    return if terr == OK { OK } else { ERR_FAST };
}

// For an exchange that may be armored: the armor and the reply's FAST
// response when `armored`; else no armor and an empty response.
fn fast_armor_as_if(armored: bool, tgt: const Credential&, now: i64, usec: i64) -> FastState, i64 {
    if armored { return fast_armor_as(tgt, now, usec); }
    return no_fast_state(), OK;
}

fn fast_reply_if(armored: bool, st: const FastState&, rep: const KdcRep&, nonce: u32) -> KrbFastResponse, i64 {
    if armored { return fast_reply(st, rep, nonce); }
    return no_fast_response(), OK;
}

fn no_fast_response() -> KrbFastResponse {
    KrbFastResponse { padata: [], has_strengthen_key: false, strengthen_key: Key { etype: 0, value: [] },
                      has_finished: false, finished: no_fast_finished(), nonce: 0 }
}
