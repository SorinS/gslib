// krb5.gssapi: the Kerberos V5 GSS-API mechanism (RFC 4121, with RFC
// 2743's token framing): context establishment for the initiator and the
// acceptor, with mutual authentication, channel bindings and credential
// delegation (KRB-CRED in the authenticator's checksum); then MIC and
// Wrap tokens, with confidentiality or without, and sequence checks.
//
// The acceptor sends a subkey of its own in the AP-REP (as MIT does), and
// both sides then protect messages with it; without one, with the
// initiator's subkey; without that, with the session key.
//
// Not done: RFC 1964 / RFC 4757 tokens, which MIT and Windows use instead
// of RFC 4121's for DES3 and RC4 session keys; with such keys contexts
// establish, but get_mic and wrap refuse (ERR_ETYPE). DCE-style contexts.

namespace krb5;

import std;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.md5;
import krb5.crypto;
import krb5.messages;
import krb5.keytab;
import krb5.ccache;
import krb5.service;

let KRB5_OID = "1.2.840.113554.1.2.2";
// Microsoft's mistaken Kerberos OID (Windows 2000), which Windows still
// sends first in SPNEGO and sometimes frames its tokens with.
let MS_KRB5_OID = "1.2.840.48018.1.2.2";

// Token identifiers (RFC 4121 §4.1, §4.2.6).
let TOK_AP_REQ: u32 = 0x0100;
let TOK_AP_REP: u32 = 0x0200;
let TOK_ERROR: u32 = 0x0300;
let TOK_MIC: u32 = 0x0404;
let TOK_WRAP: u32 = 0x0504;

// Context flags (RFC 2743, RFC 4121 §4.1.1.1).
let GSS_DELEG: u32 = 1;
let GSS_MUTUAL: u32 = 2;
let GSS_REPLAY: u32 = 4;
let GSS_SEQUENCE: u32 = 8;
let GSS_CONF: u32 = 16;
let GSS_INTEG: u32 = 32;

// Wrap and MIC token flags (§4.2.2).
let TF_SENT_BY_ACCEPTOR: u8 = 1;
let TF_SEALED: u8 = 2;
let TF_ACCEPTOR_SUBKEY: u8 = 4;

struct GssContext {
    initiator: bool,
    established: bool,
    flags: u32,
    session_key: Key,
    key: Key,              // what per-message tokens use
    acceptor_subkey: bool,
    send_seq: u64,
    recv_seq: u64,
    ctime: i64,            // the initiator's authenticator time, for the AP-REP
    cusec: i64,
}

fn empty_gss_context() -> GssContext {
    return GssContext { initiator: false, established: false, flags: 0, session_key: no_key(), key: no_key(),
                        acceptor_subkey: false, send_seq: 0, recv_seq: 0, ctime: 0, cusec: 0 };
}

// --- Framing (RFC 2743 §3.1) ----------------------------------------------------

// [APPLICATION 0] { mech OID, TOK_ID, body }.
fn gss_frame(out: u8[>..]&, oid: const u8[:], tok_id: u32, body: const u8[:]) {
    var c: u8[>..] = [];
    asn1::put_oid(c, oid);
    if tok_id != 0 {
        c.push((tok_id >> 8) as! u8);
        c.push(tok_id as! u8);
    }
    c.append(body);
    asn1::put(out, 0x60, c);
}

// The TOK_ID (when `with_id`) and where the body starts, of a token
// framed with `oid` (or, for Kerberos, Microsoft's OID).
fn gss_unframe(token: const u8[:], oid: const u8[:], with_id: bool) -> u32, i64, i64 {
    let t, ok = asn1::read(token, 0, token.len, true);
    if !ok || t.tag != 0x60 || t.end != token.len { return 0, 0, ERR_TOKEN; }
    let o, ook = asn1::read(token, t.off, t.end, true);
    if !ook { return 0, 0, ERR_TOKEN; }
    let ms = oid == KRB5_OID && asn1::oid_is(token, o, MS_KRB5_OID);
    if !asn1::oid_is(token, o, oid) && !ms { return 0, 0, ERR_MECH; }
    if !with_id { return 0, o.end, OK; }
    if o.end + 2 > t.end { return 0, 0, ERR_TOKEN; }
    let hi: u32 = token[o.end];
    let lo: u32 = token[o.end + 1];
    return hi << 8 | lo, o.end + 2, OK;
}

// --- The authenticator's checksum (§4.1.1) ---------------------------------------------

fn le32(out: u8[>..]&, v: u32) { out.push(v as! u8); out.push((v >> 8) as! u8); out.push((v >> 16) as! u8); out.push((v >> 24) as! u8); }

fn rd_le32(b: const u8[:], at: i64) -> u32 {
    let a: u32 = b[at];
    let c: u32 = b[at + 1];
    let d: u32 = b[at + 2];
    let e: u32 = b[at + 3];
    return a | c << 8 | d << 16 | e << 24;
}

// The MD5 of channel bindings (§4.1.1.2) with no addresses and the
// application data (TLS's "tls-server-end-point:" binding, for one);
// zeros when there are none.
fn bindings_hash(app_data: const u8[:], has: bool) -> u8[16] {
    if !has { return [0; 16]; }
    var b: u8[>..] = [];
    le32(b, 0);
    le32(b, 0);
    le32(b, 0);
    le32(b, 0);
    le32(b, app_data.len as! u32);
    b.append(app_data);
    return bignum::md5(b);
}

fn checksum_8003(bnd: const u8[:], flags: u32, deleg: const u8[:]) -> u8[>..] {
    var c: u8[>..] = [];
    le32(c, 16);
    c.append(bnd);
    le32(c, flags);
    if deleg.len > 0 {
        c.push(1);
        c.push(0);
        c.push((deleg.len & 0xff) as! u8);
        c.push((deleg.len >> 8) as! u8);
        c.append(deleg);
    }
    return c;
}

// --- Delegation (KRB-CRED, RFC 4120 §3.6) -------------------------------------------------

// A KRB-CRED holding a credential, its part encrypted in `key` (usage 14),
// as GSS-API delegation sends a forwarded TGT.
fn make_krb_cred(c: const Credential&, key: Key, out: u8[>..]&) -> i64 {
    var infos: KrbCredInfo[>..] = [];
    infos.push(KrbCredInfo {
        key: c.key, has_prealm: true, prealm: copy(c.client_realm), has_pname: true,
        pname: PrincipalName { name_type: c.client_type, name: copy(c.client) }, has_flags: true, flags: c.flags,
        has_authtime: true, authtime: c.authtime, has_starttime: c.starttime != 0, starttime: c.starttime,
        has_endtime: true, endtime: c.endtime, has_renew_till: c.renew_till != 0, renew_till: c.renew_till,
        has_srealm: true, srealm: copy(c.server_realm), has_sname: true,
        sname: PrincipalName { name_type: c.server_type, name: copy(c.server) }, has_caddr: false, caddr: [],
    });
    let part = EncKrbCredPart { ticket_info: copy(infos), has_nonce: false, nonce: 0, has_timestamp: false, timestamp: 0,
                                has_usec: false, usec: 0, has_s_address: false, s_address: no_address(),
                                has_r_address: false, r_address: no_address() };
    var plain: u8[>..] = [];
    encode_enc_krb_cred_part(plain, part);
    var ct: u8[>..] = [];
    let err = encrypt(key, USAGE_KRB_CRED_ENCPART, plain, ct);
    if err != OK { return err; }
    var tickets: u8[][>..] = [];
    tickets.push(copy(c.ticket));
    let m = KrbCred { tickets: copy(tickets), enc_part: EncryptedData { etype: key.etype, has_kvno: false, kvno: 0, cipher: copy(ct) } };
    encode_krb_cred(out, m);
    return OK;
}

// The credentials of a KRB-CRED, its part decrypted with the first of the
// keys that works (etype 0: the part is in the clear, as some send it).
fn read_krb_cred(b: const u8[:], k1: Key, k2: Key) -> Credential[>..], i64 {
    var out: Credential[>..] = [];
    let m, err = decode_krb_cred(b);
    if err != OK { return out, err; }
    var plain: u8[>..] = [];
    if m.enc_part.etype == 0 {
        plain.append(m.enc_part.cipher);
    } else if decrypt(k1, USAGE_KRB_CRED_ENCPART, m.enc_part.cipher, plain) != OK {
        plain.clear();
        if k2.value.len == 0 || decrypt(k2, USAGE_KRB_CRED_ENCPART, m.enc_part.cipher, plain) != OK { return out, KRB_AP_ERR_BAD_INTEGRITY; }
    }
    let part, perr = decode_enc_krb_cred_part(plain);
    if perr != OK { return out, perr; }
    var i = 0;
    for info in part.ticket_info {
        var k = 0;
        for t in m.tickets {
            if k == i {
                out.push(Credential {
                    client_type: info.pname.name_type, client: copy(info.pname.name), client_realm: copy(info.prealm),
                    server_type: info.sname.name_type, server: copy(info.sname.name), server_realm: copy(info.srealm),
                    key: info.key, authtime: info.authtime, starttime: info.starttime, endtime: info.endtime,
                    renew_till: info.renew_till, is_skey: false, flags: info.flags, addresses: [], authdata: [],
                    ticket: copy(t), second_ticket: "",
                });
            }
            k++;
        }
        i++;
    }
    return out, OK;
}

// --- Establishing a context ----------------------------------------------------------------

// The first token of an initiator, from a service ticket. `flags` are
// GSS_* (mutual, replay, sequence, conf, integ; deleg when `deleg` holds a
// KRB-CRED of a forwarded TGT, from gss_delegation). `bindings` are
// channel bindings' application data (has_bindings false for none).
fn gss_init(cred: const Credential&, flags: u32, bindings: const u8[:], has_bindings: bool, deleg: const u8[:], now: i64,
            usec: i64, token: u8[>..]&) -> GssContext, i64 {
    var ctx = empty_gss_context();
    if !etype_supported(cred.key.etype) { return ctx, ERR_ETYPE; }
    let subkey = random_key(cred.key.etype);
    let seq = random_u32() & 0x3fffffff;
    var f = flags | GSS_INTEG | GSS_CONF;
    if deleg.len == 0 { f = f & ~GSS_DELEG; } else { f = f | GSS_DELEG; }
    let bnd = bindings_hash(bindings, has_bindings);
    let ck = Checksum { ctype: CKSUM_GSSAPI, sum: checksum_8003(bnd, f, deleg) };
    let opts: u32 = if f & GSS_MUTUAL != 0 { flag(AP_OPT_MUTUAL_REQUIRED) } else { 0 };
    var ap: u8[>..] = [];
    let err = make_ap_req(cred, opts, true, ck, true, subkey, true, seq, now, usec, ap);
    if err != OK { return ctx, err; }
    gss_frame(token, KRB5_OID, TOK_AP_REQ, ap);
    ctx = GssContext {
        initiator: true, established: f & GSS_MUTUAL == 0, flags: f, session_key: cred.key, key: subkey,
        acceptor_subkey: false, send_seq: seq, recv_seq: seq, ctime: now, cusec: usec,
    };
    return ctx, OK;
}

// The initiator's second step: the acceptor's AP-REP token (or KRB-ERROR
// token, whose error comes back).
fn gss_init_continue(ctx: GssContext&, token: const u8[:]) -> i64 {
    if !ctx.initiator || ctx.established { return ERR_CONTEXT; }
    let id, at, err = gss_unframe(token, KRB5_OID, true);
    if err != OK { return err; }
    if id == TOK_ERROR {
        let e, kerr = decode_krb_error(token[at..]);
        return if kerr == OK { e.error_code } else { ERR_TOKEN };
    }
    if id != TOK_AP_REP { return ERR_TOKEN; }
    let p, perr = verify_ap_rep(token[at..], ctx.session_key, ctx.ctime, ctx.cusec);
    if perr != OK { return perr; }
    if p.has_subkey {
        ctx.key = p.subkey;
        ctx.acceptor_subkey = true;
    }
    ctx.recv_seq = if p.has_seq_number { p.seq_number } else { ctx.send_seq };
    ctx.established = true;
    return OK;
}

// What an acceptor learns from the initiator's token.
struct GssAccepted { ap: ApContext, flags: u32, delegated: Credential[] }

// The acceptor's step: the initiator's token checked against the
// keytab (see krb5.service), and the AP-REP token to send back when the
// initiator asked for mutual authentication (else out stays empty).
// `bindings` are the acceptor's channel bindings; an initiator that sent
// none is accepted, as MIT does unless told otherwise.
fn gss_accept(token: const u8[:], kt: const KeytabEntry[:], any_name: bool, rc: ReplayEntry[>..]&, now: i64, usec: i64,
              skew: i64, bindings: const u8[:], has_bindings: bool, out: u8[>..]&) -> GssContext, GssAccepted, i64 {
    var ctx = empty_gss_context();
    let none = GssAccepted { ap: empty_ap_context(), flags: 0, delegated: [] };
    let id, at, err = gss_unframe(token, KRB5_OID, true);
    if err != OK { return ctx, none, err; }
    if id != TOK_AP_REQ { return ctx, none, ERR_TOKEN; }
    let ap, aerr = verify_ap_req(token[at..], kt, any_name, rc, now, skew, USAGE_AP_REQ_AUTHENTICATOR);
    if aerr != OK {
        var e: u8[>..] = [];
        make_krb_error(aerr, "", "", now, usec, e);
        gss_frame(out, KRB5_OID, TOK_ERROR, e);
        return ctx, none, aerr;
    }
    if !ap.has_cksum || ap.cksum.ctype != CKSUM_GSSAPI || ap.cksum.sum.len < 24 || rd_le32(ap.cksum.sum, 0) != 16 {
        return ctx, none, KRB_AP_ERR_INAPP_CKSUM;
    }
    let sum = ap.cksum.sum;
    let bnd = sum[4..20];
    if has_bindings {
        let want = bindings_hash(bindings, true);
        let zero: u8[16] = [0; 16];
        if bnd != zero && bnd != want { return ctx, none, KRB_AP_ERR_BADADDR; }
    }
    let f = rd_le32(sum, 20);
    var delegated: Credential[>..] = [];
    if f & GSS_DELEG != 0 && sum.len >= 28 {
        let dlg_opt = sum[24] | (sum[25] as u32) << 8;
        let dlg_len = sum[26] | (sum[27] as i64) << 8;
        if dlg_opt != 1 || 28 + dlg_len > sum.len { return ctx, none, ERR_TOKEN; }
        let cs, cerr = read_krb_cred(sum[28..28 + dlg_len], ap.session_key, if ap.has_subkey { ap.subkey } else { no_key() });
        if cerr != OK { return ctx, none, cerr; }
        for c in cs { delegated.push(copy(c)); }
    }
    let init_key = if ap.has_subkey { ap.subkey } else { ap.session_key };
    let init_seq: u64 = if ap.has_seq_number { ap.seq_number } else { 0 };
    ctx = GssContext {
        initiator: false, established: true, flags: f, session_key: ap.session_key, key: init_key, acceptor_subkey: false,
        send_seq: init_seq, recv_seq: init_seq, ctime: ap.ctime, cusec: ap.cusec,
    };
    if ap.ap_options & flag(AP_OPT_MUTUAL_REQUIRED) != 0 || f & GSS_MUTUAL != 0 {
        let sub = random_key(init_key.etype);
        let seq = random_u32() & 0x3fffffff;
        var rep: u8[>..] = [];
        let rerr = make_ap_rep(ap, true, sub, true, seq, rep);
        if rerr != OK { return ctx, none, rerr; }
        gss_frame(out, KRB5_OID, TOK_AP_REP, rep);
        ctx.key = sub;
        ctx.acceptor_subkey = true;
        ctx.send_seq = seq;
    }
    return ctx, GssAccepted { ap: ap, flags: f, delegated: delegated }, OK;
}

// --- Per-message tokens (§4.2) --------------------------------------------------------------

fn token_flags(ctx: const GssContext&, sealed: bool) -> u8 {
    var f: u8 = 0;
    if !ctx.initiator { f = f | TF_SENT_BY_ACCEPTOR; }
    if sealed { f = f | TF_SEALED; }
    if ctx.acceptor_subkey { f = f | TF_ACCEPTOR_SUBKEY; }
    return f;
}

fn put_seq64(out: u8[>..]&, v: u64) {
    for i in 8 { out.push((v >> ((56 - 8 * i) as! u64)) as! u8); }
}

fn rd_seq64(b: const u8[:], at: i64) -> u64 {
    var v: u64 = 0;
    for i in 8 { v = v << 8 | b[at + i]; }
    return v;
}

fn sign_usage(sender_initiator: bool) -> i64 { if sender_initiator { USAGE_GSSAPI_INITIATOR_SIGN } else { USAGE_GSSAPI_ACCEPTOR_SIGN } }
fn seal_usage(sender_initiator: bool) -> i64 { if sender_initiator { USAGE_GSSAPI_INITIATOR_SEAL } else { USAGE_GSSAPI_ACCEPTOR_SEAL } }

// RFC 4121 tokens need a profile with a "required checksum" of RFC
// 3961's kind; RC4 and DES3 contexts use RFC 4757 / RFC 1964 tokens,
// which we do not have.
fn cfx_key(k: Key) -> bool { k.etype != ETYPE_RC4_HMAC && k.etype != ETYPE_DES3_CBC_SHA1_KD && etype_supported(k.etype) }

// Checks a received token's sequence number: in order, or (without the
// sequence flag) newer than the last; a replay is refused.
fn check_seq(ctx: GssContext&, seq: u64) -> i64 {
    if seq == ctx.recv_seq { ctx.recv_seq++; return OK; }
    if seq < ctx.recv_seq {
        return if ctx.flags & (GSS_REPLAY | GSS_SEQUENCE) != 0 { ERR_SEQUENCE } else { OK };
    }
    if ctx.flags & GSS_SEQUENCE != 0 { return ERR_SEQUENCE; }
    ctx.recv_seq = seq + 1;
    return OK;
}

fn gss_get_mic(ctx: GssContext&, msg: const u8[:], out: u8[>..]&) -> i64 {
    if !ctx.established { return ERR_CONTEXT; }
    if !cfx_key(ctx.key) { return ERR_ETYPE; }
    var h: u8[>..] = [0x04, 0x04, token_flags(ctx, false), 0xff, 0xff, 0xff, 0xff, 0xff];
    put_seq64(h, ctx.send_seq);
    var data: u8[>..] = [];
    data.append(msg);
    data.append(h);
    var ck: u8[>..] = [];
    let err = checksum(ctx.key, 0, sign_usage(ctx.initiator), data, ck);
    if err != OK { return err; }
    ctx.send_seq++;
    out.append(h);
    out.append(ck);
    return OK;
}

// Checks the flags of a received token: from the peer, and naming the
// acceptor subkey exactly when the context uses one.
fn check_token_flags(ctx: const GssContext&, f: u8, sealed_ok: bool) -> bool {
    let from_acceptor = f & TF_SENT_BY_ACCEPTOR != 0;
    if from_acceptor != ctx.initiator { return false; }
    if (f & TF_ACCEPTOR_SUBKEY != 0) != ctx.acceptor_subkey { return false; }
    if !sealed_ok && f & TF_SEALED != 0 { return false; }
    return f & 0xf8 == 0;
}

fn gss_verify_mic(ctx: GssContext&, msg: const u8[:], token: const u8[:]) -> i64 {
    if !ctx.established { return ERR_CONTEXT; }
    if !cfx_key(ctx.key) { return ERR_ETYPE; }
    if token.len < 16 || token[0] != 0x04 || token[1] != 0x04 { return ERR_TOKEN; }
    if !check_token_flags(ctx, token[2], false) { return ERR_TOKEN; }
    for i in 3..8 { if token[i] != 0xff { return ERR_TOKEN; } }
    var data: u8[>..] = [];
    data.append(msg);
    data.append(token[..16]);
    let err = verify_checksum(ctx.key, cksum_type_for(ctx.key.etype), sign_usage(!ctx.initiator), data, token[16..]);
    if err != OK { return err; }
    return check_seq(ctx, rd_seq64(token, 8));
}

// Wraps a message: encrypted when `conf` (and the context allows it),
// else with a checksum. RRC is 0 when we send; any is read.
fn gss_wrap(ctx: GssContext&, msg: const u8[:], conf: bool, out: u8[>..]&) -> i64 {
    if !ctx.established { return ERR_CONTEXT; }
    if !cfx_key(ctx.key) { return ERR_ETYPE; }
    var h: u8[>..] = [0x05, 0x04, token_flags(ctx, conf), 0xff, 0, 0, 0, 0];
    put_seq64(h, ctx.send_seq);
    if conf {
        // No filler: the RFC 3961 profiles here leave no residue.
        var p: u8[>..] = [];
        p.append(msg);
        p.append(h);
        var c: u8[>..] = [];
        let err = encrypt(ctx.key, seal_usage(ctx.initiator), p, c);
        if err != OK { return err; }
        out.append(h);
        out.append(c);
    } else {
        var data: u8[>..] = [];
        data.append(msg);
        data.append(h);
        // The Wrap token's usage even without confidentiality (§2).
        var ck: u8[>..] = [];
        let err = checksum(ctx.key, 0, seal_usage(ctx.initiator), data, ck);
        if err != OK { return err; }
        h[4] = (ck.len >> 8) as! u8;
        h[5] = ck.len as! u8;
        out.append(h);
        out.append(msg);
        out.append(ck);
    }
    ctx.send_seq++;
    return OK;
}

// The message of a Wrap token, appended to out; and whether it was
// encrypted.
fn gss_unwrap(ctx: GssContext&, token: const u8[:], out: u8[>..]&) -> bool, i64 {
    if !ctx.established { return false, ERR_CONTEXT; }
    if !cfx_key(ctx.key) { return false, ERR_ETYPE; }
    if token.len < 16 || token[0] != 0x05 || token[1] != 0x04 || token[3] != 0xff { return false, ERR_TOKEN; }
    let f = token[2];
    if !check_token_flags(ctx, f, true) { return false, ERR_TOKEN; }
    let ec = (token[4] as i64) << 8 | token[5];
    let rrc = (token[6] as i64) << 8 | token[7];
    let seq = rd_seq64(token, 8);
    // Undo the right rotation of everything after the header.
    let body = token[16..];
    var b: u8[>..] = [];
    if body.len > 0 {
        let r = rrc % body.len;
        b.append(body[r..]);
        b.append(body[..r]);
    }
    let sealed = f & TF_SEALED != 0;
    if sealed {
        var p: u8[>..] = [];
        let err = decrypt(ctx.key, seal_usage(!ctx.initiator), b, p);
        if err != OK { return true, err; }
        if p.len < 16 + ec { return true, ERR_TOKEN; }
        // The header inside: the token's, with RRC 0.
        let inner = p[p.len - 16..];
        for i in 16 {
            let want = if i == 6 || i == 7 { 0 } else { token[i] };
            if inner[i] != want { return true, ERR_TOKEN; }
        }
        out.append(p[..p.len - 16 - ec]);
    } else {
        if b.len < ec { return false, ERR_TOKEN; }
        let msg = b[..b.len - ec];
        var data: u8[>..] = [];
        data.append(msg);
        data.append(token[..16]);
        data[data.len - 12] = 0;
        data[data.len - 11] = 0;
        data[data.len - 10] = 0;
        data[data.len - 9] = 0;
        let err = verify_checksum(ctx.key, cksum_type_for(ctx.key.etype), seal_usage(!ctx.initiator), data, b[b.len - ec..]);
        if err != OK { return false, err; }
        out.append(msg);
    }
    return sealed, check_seq(ctx, seq);
}
