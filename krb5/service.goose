// krb5.service: the acceptor's side of the AP exchange (RFC 4120 §3.2):
// an AP-REQ checked against the service's keytab, a replay cache, and the
// AP-REP for mutual authentication; and the client's side of checking
// that AP-REP. The authorization data of the ticket (the PAC, for one)
// comes back for krb5.pac to read.
//
// An AP-REQ is accepted when its ticket decrypts with a key of the
// keytab (the ticket's server name, or any name when the acceptor takes
// any, MIT's GSS_C_NO_NAME), the authenticator decrypts with the ticket's
// session key and names the ticket's client, the ticket is valid now
// within the allowed clock skew, the authenticator's time is within the
// skew, and the authenticator has not been seen before.

namespace krb5;

import std;
import os;
import crypto.bignum;
import crypto.bignum.sha256;
import crypto.bignum.entropy;
import krb5.crypto;
import krb5.messages;
import krb5.keytab;
import krb5.ccache;

// A replay cache (MIT's rcache2 idea): the hash of each authenticator's
// ciphertext and when its entry may go. Kept by the caller, one per
// service; entries go once older than twice the skew.
struct ReplayEntry { expires: i64, hash: u8[32] }

fn replay_check(rc: ReplayEntry[>..]&, cipher: const u8[:], now: i64, skew: i64) -> bool {
    let h = bignum::sha256(cipher);
    // Drop what has expired, keeping the order.
    var keep = 0;
    for i in rc.len {
        if rc[i].expires > now {
            rc[keep] = rc[i];
            keep++;
        }
    }
    rc.resize(keep, ReplayEntry { expires: 0, hash: [0; 32] });
    for e in rc { if e.hash == h { return false; } }
    rc.push(ReplayEntry { expires: now + 2 * skew, hash: h });
    return true;
}

// What an accepted AP-REQ tells the service.
struct ApContext {
    client: u8[],          // escaped, as krb5.messages keeps names
    client_realm: u8[],
    client_type: i32,
    server: u8[],
    server_realm: u8[],
    session_key: Key,
    has_subkey: bool,
    subkey: Key,
    has_seq_number: bool,
    seq_number: u32,
    ap_options: u32,
    ticket_flags: u32,
    authtime: i64,
    endtime: i64,
    ctime: i64,
    cusec: i64,
    has_cksum: bool,
    cksum: Checksum,       // the authenticator's, which GSS-API reads
    authz: AuthData[],     // the ticket's authorization data
    kvno: u32,
    service_key: Key,      // the keytab key the ticket decrypted with (for the PAC's signature)
}

fn empty_ap_context() -> ApContext {
    return ApContext {
        client: "", client_realm: "", client_type: 0, server: "", server_realm: "", session_key: no_key(),
        has_subkey: false, subkey: no_key(), has_seq_number: false, seq_number: 0, ap_options: 0, ticket_flags: 0,
        authtime: 0, endtime: 0, ctime: 0, cusec: 0, has_cksum: false, cksum: no_checksum(), authz: [], kvno: 0, service_key: no_key(),
    };
}

// The key for a ticket from the keytab: for the ticket's server name, or
// with `any_name` for any entry of the realm with the type and version.
// When there is none, why: KRB_AP_ERR_NOT_US (no such name),
// KRB_AP_ERR_NOKEY (not of the ticket's type), KRB_AP_ERR_BADKEYVER (not
// of its key version).
fn ticket_key(kt: const KeytabEntry[:], t: const Ticket&, any_name: bool) -> Key, u32, i64 {
    let kvno: u32 = if t.enc_part.has_kvno { t.enc_part.kvno } else { 0 };
    var named = false;
    var typed = false;
    for pass in 2 {
        if pass == 1 && !any_name { break; }
        for e in kt {
            if e.realm != t.realm { continue; }
            if pass == 0 && e.name != t.sname.name { continue; }
            named = true;
            if e.key.etype != t.enc_part.etype { continue; }
            typed = true;
            if kvno != 0 && e.kvno != kvno { continue; }
            if pass == 0 {
                // The highest version when the ticket names none.
                let k, kv, err = keytab_key(kt, t.sname.name, t.realm, t.enc_part.etype, kvno);
                return k, kv, err;
            }
            // Any name: a wrong key fails to decrypt, as it should.
            return e.key, e.kvno, OK;
        }
    }
    let why = if !named { KRB_AP_ERR_NOT_US } else if !typed { KRB_AP_ERR_NOKEY } else { KRB_AP_ERR_BADKEYVER };
    return no_key(), 0, why;
}

// Checks an AP-REQ for a service with keys in `kt` at time `now`
// (seconds since 1970), with `usage` the authenticator's key usage (11,
// or 7 inside a TGS-REQ). The context, or an error that a KRB-ERROR
// would carry.
fn verify_ap_req(apreq: const u8[:], kt: const KeytabEntry[:], any_name: bool, rc: ReplayEntry[>..]&, now: i64, skew: i64,
                 usage: i64) -> ApContext, i64 {
    let ap, err = decode_ap_req(apreq);
    if err != OK { return empty_ap_context(), if message_type(apreq) == MSG_AP_REQ { err } else { KRB_AP_ERR_MSG_TYPE }; }
    if ap.ap_options & flag(AP_OPT_USE_SESSION_KEY) != 0 {
        // User-to-user tickets are encrypted in a TGT's session key.
        return empty_ap_context(), KRB_AP_ERR_METHOD;
    }
    let t, terr = decode_ticket(ap.ticket);
    if terr != OK { return empty_ap_context(), terr; }
    let key, kvno, kerr = ticket_key(kt, t, any_name);
    if kerr != OK { return empty_ap_context(), kerr; }
    var tp_plain: u8[>..] = [];
    let derr = decrypt(key, USAGE_KDC_REP_TICKET, t.enc_part.cipher, tp_plain);
    if derr != OK { return empty_ap_context(), KRB_AP_ERR_BAD_INTEGRITY; }
    let tp, tperr = decode_enc_ticket_part(tp_plain);
    if tperr != OK { return empty_ap_context(), tperr; }
    if ap.authenticator.etype != tp.key.etype { return empty_ap_context(), KRB_AP_ERR_BAD_INTEGRITY; }
    var a_plain: u8[>..] = [];
    let aerr = decrypt(tp.key, usage, ap.authenticator.cipher, a_plain);
    if aerr != OK { return empty_ap_context(), KRB_AP_ERR_BAD_INTEGRITY; }
    let a, auerr = decode_authenticator(a_plain);
    if auerr != OK { return empty_ap_context(), auerr; }
    if a.cname.name != tp.cname.name || a.crealm != tp.crealm { return empty_ap_context(), KRB_AP_ERR_BADMATCH; }
    // Times (§3.2.3): the authenticator within the skew, the ticket valid.
    if a.ctime < now - skew || a.ctime > now + skew { return empty_ap_context(), KRB_AP_ERR_SKEW; }
    let start = if tp.has_starttime { tp.starttime } else { tp.authtime };
    if start - skew > now || tp.flags & flag(TKT_INVALID) != 0 { return empty_ap_context(), KRB_AP_ERR_TKT_NYV; }
    if now - skew > tp.endtime { return empty_ap_context(), KRB_AP_ERR_TKT_EXPIRED; }
    if !replay_check(rc, ap.authenticator.cipher, now, skew) { return empty_ap_context(), KRB_AP_ERR_REPEAT; }
    return ApContext {
        client: copy(tp.cname.name), client_realm: copy(tp.crealm), client_type: tp.cname.name_type,
        server: copy(t.sname.name), server_realm: copy(t.realm), session_key: tp.key, has_subkey: a.has_subkey,
        subkey: a.subkey, has_seq_number: a.has_seq_number, seq_number: a.seq_number, ap_options: ap.ap_options,
        ticket_flags: tp.flags, authtime: tp.authtime, endtime: tp.endtime, ctime: a.ctime, cusec: a.cusec,
        has_cksum: a.has_cksum, cksum: copy(a.cksum), authz: copy(tp.authz), kvno: kvno, service_key: key,
    }, OK;
}

// The AP-REP answering an accepted AP-REQ (§3.2.4): its time, and a
// subkey and sequence number of the service's when given.
fn make_ap_rep(ctx: const ApContext&, has_subkey: bool, subkey: Key, has_seq: bool, seq: u32, out: u8[>..]&) -> i64 {
    let part = EncApRepPart { ctime: ctx.ctime, cusec: ctx.cusec, has_subkey: has_subkey, subkey: subkey,
                              has_seq_number: has_seq, seq_number: seq };
    var plain: u8[>..] = [];
    encode_enc_ap_rep_part(plain, part);
    var c: u8[>..] = [];
    let err = encrypt(ctx.session_key, USAGE_AP_REP_ENCPART, plain, c);
    if err != OK { return err; }
    let rep = ApRep { enc_part: EncryptedData { etype: ctx.session_key.etype, has_kvno: false, kvno: 0, cipher: copy(c) } };
    encode_ap_rep(out, rep);
    return OK;
}

// The client's check of an AP-REP: it decrypts with the session key and
// carries the authenticator's time (§3.2.5).
fn verify_ap_rep(aprep: const u8[:], session_key: Key, ctime: i64, cusec: i64) -> EncApRepPart, i64 {
    let none = EncApRepPart { ctime: 0, cusec: 0, has_subkey: false, subkey: no_key(), has_seq_number: false, seq_number: 0 };
    let r, err = decode_ap_rep(aprep);
    if err != OK { return none, if message_type(aprep) == MSG_AP_REP { err } else { KRB_AP_ERR_MSG_TYPE }; }
    var plain: u8[>..] = [];
    let derr = decrypt(session_key, USAGE_AP_REP_ENCPART, r.enc_part.cipher, plain);
    if derr != OK { return none, KRB_AP_ERR_MUT_FAIL; }
    let p, perr = decode_enc_ap_rep_part(plain);
    if perr != OK { return none, perr; }
    if p.ctime != ctime || p.cusec != cusec { return none, KRB_AP_ERR_MUT_FAIL; }
    return p, OK;
}

// An AP-REQ from a service ticket: the authenticator (with a checksum,
// subkey and sequence number when given) encrypted in the session key
// (usage 11). Returns the authenticator's time, which the AP-REP repeats.
fn make_ap_req(cred: const Credential&, ap_options: u32, has_cksum: bool, cksum: const Checksum&, has_subkey: bool, subkey: Key,
               has_seq: bool, seq: u32, now: i64, usec: i64, out: u8[>..]&) -> i64 {
    let auth = Authenticator {
        crealm: copy(cred.client_realm), cname: PrincipalName { name_type: cred.client_type, name: copy(cred.client) },
        has_cksum: has_cksum, cksum: copy(cksum), cusec: usec, ctime: now, has_subkey: has_subkey, subkey: subkey,
        has_seq_number: has_seq, seq_number: seq, has_authz: false, authz: [],
    };
    var plain: u8[>..] = [];
    encode_authenticator(plain, auth);
    var c: u8[>..] = [];
    let err = encrypt(cred.key, USAGE_AP_REQ_AUTHENTICATOR, plain, c);
    if err != OK { return err; }
    let ap = ApReq { ap_options: ap_options, ticket: copy(cred.ticket),
                     authenticator: EncryptedData { etype: cred.key.etype, has_kvno: false, kvno: 0, cipher: copy(c) } };
    encode_ap_req(out, ap);
    return OK;
}

// A KRB-ERROR for an AP exchange that failed (§3.2.3): the service's
// time and name, and the error.
fn make_krb_error(code: i64, server: const u8[:], realm: const u8[:], now: i64, usec: i64, out: u8[>..]&) {
    let e = KrbError {
        has_ctime: false, ctime: 0, has_cusec: false, cusec: 0, stime: now, susec: usec, error_code: code,
        has_crealm: false, crealm: "", has_cname: false, cname: no_principal(), realm: realm,
        sname: PrincipalName { name_type: NT_PRINCIPAL, name: server }, has_etext: false, etext: "", has_edata: false, edata: "",
    };
    encode_krb_error(out, e);
}

fn random_u32() -> u32 {
    var b: u8[4] = [0; 4];
    bignum::random_bytes(b);
    let b0: u32 = b[0];
    let b1: u32 = b[1];
    let b2: u32 = b[2];
    let b3: u32 = b[3];
    return b0 << 24 | b1 << 16 | b2 << 8 | b3;
}
