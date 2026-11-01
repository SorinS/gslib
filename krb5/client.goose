// krb5.client: the AS and TGS exchanges (RFC 4120 §3.1, §3.3): a TGT from
// a password or a keytab, with encrypted-timestamp pre-authentication as
// the KDC's ETYPE-INFO2 asks; service tickets; cross-realm tickets along
// [capaths] or the realm hierarchy; referrals (RFC 6806) when the
// service's realm is not known; clock skew corrected from the KDC's time
// (MIT's kdc_timesync); renewal. The *_cached functions keep tickets in a
// credential cache, as kinit and kvno do.
//
// Not done: FAST armoring (RFC 6113) and the pre-authentication that
// needs it (encrypted challenge), PKINIT, SPAKE, S4U2Self/S4U2Proxy and
// user-to-user.

namespace krb5;

import std;
import os;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.entropy;
import krb5.crypto;
import krb5.messages;
import krb5.config;
import krb5.net;
import krb5.keytab;
import krb5.ccache;

// The settings of a request, from krb5.conf's [libdefaults] (MIT's
// defaults), and the clock offset learned from the KDC.
struct Settings {
    lifetime: i64,
    renew_lifetime: i64,
    forwardable: bool,
    proxiable: bool,
    canonicalize: bool,
    request_pac: bool,
    clockskew: i64,
    time_offset: i64,
    kdc_timesync: bool,
}

fn settings(cfg: const Config&) -> Settings {
    return Settings {
        lifetime: conf_duration(cfg, "libdefaults/ticket_lifetime", 86400),
        renew_lifetime: conf_duration(cfg, "libdefaults/renew_lifetime", 0),
        forwardable: conf_bool(cfg, "libdefaults/forwardable", false),
        proxiable: conf_bool(cfg, "libdefaults/proxiable", false),
        canonicalize: conf_bool(cfg, "libdefaults/canonicalize", false),
        request_pac: true,
        clockskew: conf_duration(cfg, "libdefaults/clockskew", 300),
        time_offset: 0,
        kdc_timesync: conf_bool(cfg, "libdefaults/kdc_timesync", true),
    };
}

fn now_ns() -> i64 { time_ns() }

// Our time corrected by the offset: seconds and microseconds.
fn kdc_now(s: const Settings&) -> i64, i64 {
    let ns = now_ns();
    return ns / 1000000000 + s.time_offset, ns / 1000 % 1000000;
}

// A nonce of 31 bits: some KDCs read nonces as signed.
fn new_nonce() -> u32 {
    var b: u8[4] = [0; 4];
    bignum::random_bytes(b);
    let b0: u32 = b[0];
    let b1: u32 = b[1];
    let b2: u32 = b[2];
    let b3: u32 = b[3];
    return (b0 << 24 | b1 << 16 | b2 << 8 | b3) & 0x7fffffff;
}

// The secret an AS exchange proves: a password, or a keytab's keys.
struct Secret { has_password: bool, password: u8[], keytab: KeytabEntry[] }

fn secret_password(pw: const u8[:]) -> Secret { Secret { has_password: true, password: pw, keytab: [] } }

fn secret_keytab(entries: const KeytabEntry[:]) -> Secret {
    var es: KeytabEntry[>..] = [];
    for e in entries { es.push(copy(e)); }
    return Secret { has_password: false, password: "", keytab: es };
}

// The client's long-term key for an encryption type and salt.
fn secret_key(sec: const Secret&, name: const u8[:], realm: const u8[:], etype: i32, salt: const u8[:], params: const u8[:]) -> Key, i64 {
    if sec.has_password { return string_to_key(etype, sec.password, salt, params); }
    let k, kv, err = keytab_key(sec.keytab, name, realm, etype, 0);
    return k, err;
}

fn default_salt_of(name: const u8[:], realm: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    s.append(realm);
    for p in name_parts(name) { s.append(p); }
    return s;
}

// The encryption types to ask for: the configured ones, and for a keytab
// only those it has keys of (MIT's kinit -k does the same).
fn as_etypes(cfg: const Config&, sec: const Secret&, name: const u8[:], realm: const u8[:]) -> i32[>..] {
    let want = conf_etypes(cfg, "default_tkt_enctypes");
    if sec.has_password { return want; }
    return keytab_etypes(sec.keytab, name, realm, want);
}

fn krbtgt(realm: const u8[:], of: const u8[:]) -> PrincipalName { PrincipalName { name_type: NT_SRV_INST, name: name_join("krbtgt", realm) } }

fn kdc_options(s: const Settings&) -> u32 {
    var o: u32 = 0;
    if s.forwardable { o = o | flag(KDC_OPT_FORWARDABLE); }
    if s.proxiable { o = o | flag(KDC_OPT_PROXIABLE); }
    if s.renew_lifetime > 0 { o = o | flag(KDC_OPT_RENEWABLE); }
    if s.canonicalize { o = o | flag(KDC_OPT_CANONICALIZE); }
    return o;
}

// The credential an AS-REP or TGS-REP gives.
fn credential_of(rep: const KdcRep&, part: const EncKdcRepPart&) -> Credential {
    return Credential {
        client_type: rep.cname.name_type, client: copy(rep.cname.name), client_realm: copy(rep.crealm),
        server_type: part.sname.name_type, server: copy(part.sname.name), server_realm: copy(part.srealm),
        key: part.key, authtime: part.authtime, starttime: if part.has_starttime { part.starttime } else { part.authtime },
        endtime: part.endtime, renew_till: if part.has_renew_till { part.renew_till } else { 0 }, is_skey: false,
        flags: part.flags, addresses: copy(part.caddr), authdata: [], ticket: copy(rep.ticket), second_ticket: "",
    };
}

// --- The AS exchange --------------------------------------------------------------

// What a pre-authentication round learned: the key to answer with.
struct PreauthKey { have: bool, key: Key, has_kvno: bool, kvno: u32 }

// The ETYPE-INFO2 (or ETYPE-INFO, or PW-SALT) of padata: the first entry
// whose type we asked for, its salt and parameters; ok false if none.
fn pick_etype_info(pa: const PaData[:], etypes: const i32[:], name: const u8[:], realm: const u8[:]) -> i32, u8[>..], u8[>..], bool {
    var salt: u8[>..] = [];
    var params: u8[>..] = [];
    for p in pa {
        if p.pa_type != PA_ETYPE_INFO2 && p.pa_type != PA_ETYPE_INFO { continue; }
        let infos, err = decode_etype_info(p.value, p.pa_type == PA_ETYPE_INFO);
        if err != OK { continue; }
        for i in infos {
            var wanted = false;
            for e in etypes { if e == i.etype { wanted = true; } }
            if !wanted || !etype_supported(i.etype) { continue; }
            if i.has_salt { salt.append(i.salt); } else { salt.append(default_salt_of(name, realm)); }
            if i.has_s2kparams { params.append(i.s2kparams); }
            return i.etype, salt, params, true;
        }
    }
    // PA-PW-SALT alone: the salt for whatever type the reply uses.
    for p in pa {
        if p.pa_type == PA_PW_SALT { salt.append(p.value); return 0, salt, params, true; }
    }
    return 0, salt, params, false;
}

fn encode_as_req(cfg: const Config&, s: const Settings&, cname: const PrincipalName&, realm: const u8[:],
                 sname: const PrincipalName&, nonce: u32, etypes: const i32[:], pk: const PreauthKey&, out: u8[>..]&) -> i64 {
    let now, usec = kdc_now(s);
    var pa: PaData[>..] = [];
    if pk.have {
        var ts: u8[>..] = [];
        encode_pa_enc_ts(ts, now, true, usec);
        var c: u8[>..] = [];
        let err = encrypt(pk.key, USAGE_AS_REQ_PA_ENC_TIMESTAMP, ts, c);
        if err != OK { return err; }
        var ed: u8[>..] = [];
        let d = EncryptedData { etype: pk.key.etype, has_kvno: false, kvno: 0, cipher: copy(c) };
        encode_enc_data(ed, d);
        pa.push(PaData { pa_type: PA_ENC_TIMESTAMP, value: copy(ed) });
    }
    if s.request_pac {
        var pr: u8[>..] = [];
        encode_pa_pac_request(pr, true);
        pa.push(PaData { pa_type: PA_PAC_REQUEST, value: copy(pr) });
    }
    // Ask for the request's checksum in the reply (RFC 6806 §11), which
    // lets a canonicalized reply be trusted.
    pa.push(PaData { pa_type: PA_REQ_ENC_PA_REP, value: "" });
    let renewable = s.renew_lifetime > 0;
    let body = KdcReqBody {
        kdc_options: kdc_options(s), has_cname: true, cname: copy(cname), realm: realm, has_sname: true, sname: copy(sname),
        has_from: false, from: 0, till: now + s.lifetime, has_rtime: renewable, rtime: now + s.renew_lifetime,
        nonce: nonce, etypes: etypes, has_addresses: false, addresses: [], has_enc_authz: false, enc_authz: no_enc_data(),
        has_tickets: false, tickets: [],
    };
    let r = KdcReq { msg_type: MSG_AS_REQ, has_padata: true, padata: copy(pa), body: copy(body) };
    encode_kdc_req(out, r);
    return OK;
}

// Checks the PA-REQ-ENC-PA-REP of an AS-REP's encrypted part: OK if it
// is there and is the checksum of our request; ERR_INTEGRITY if it is
// there and is not; ERR_NAME_MISMATCH if it is not there.
fn check_req_checksum(part: const EncKdcRepPart&, key: Key, req: const u8[:]) -> i64 {
    if part.flags & flag(TKT_ENC_PA_REP) == 0 || !part.has_enc_padata { return ERR_NAME_MISMATCH; }
    for p in part.enc_padata {
        if p.pa_type != PA_REQ_ENC_PA_REP { continue; }
        var bad = false;
        let t, ok = asn1::parse(p.value, true);
        if !ok { return ERR_INTEGRITY; }
        let ck = checksum_at(p.value, t, bad);
        if bad { return ERR_INTEGRITY; }
        return if verify_checksum(key, ck.ctype, 56, req, ck.sum) == OK { OK } else { ERR_INTEGRITY };
    }
    return ERR_NAME_MISMATCH;
}

// The error code of a reply that is a KRB-ERROR, with the error itself;
// 0 if the reply is not one.
fn reply_error(reply: const u8[:]) -> i64, KrbError {
    let e, err = decode_krb_error(reply);
    if message_type(reply) != MSG_KRB_ERROR || err != OK { return 0, e; }
    return if e.error_code == 0 { KRB_ERR_GENERIC } else { e.error_code }, e;
}

// An AS exchange for `sname` (a TGT's krbtgt/REALM, or a service: kpasswd's
// kadmin/changepw), with the realm's KDCs. The client name's type is
// NT_ENTERPRISE when it holds an escaped '@' (user\@domain), and then
// the KDC may send us to another realm (RFC 6806 §7).
fn as_exchange(cfg: const Config&, s: Settings&, cname: const PrincipalName&, realm0: const u8[:], sname0: const PrincipalName&,
               sec: const Secret&) -> Credential, i64 {
    var realm: u8[>..] = [];
    realm.append(realm0);
    var sname_name: u8[>..] = [];
    sname_name.append(sname0.name);
    var pk = PreauthKey { have: false, key: no_key(), has_kvno: false, kvno: 0 };
    var skew_fixed = false;
    var referrals = 0;
    var salt: u8[>..] = [];
    var params: u8[>..] = [];
    var known_etype: i32 = 0;
    let enterprise = cname.name_type == NT_ENTERPRISE;
    if enterprise { s.canonicalize = true; }
    for attempt in 8 {
        let etypes = as_etypes(cfg, sec, cname.name, realm);
        if etypes.len == 0 { return empty_credential(), ERR_ETYPE; }
        let sname = if sname0.name_type == NT_SRV_INST && name_part(sname_name, 0) == "krbtgt" {
            krbtgt(realm, realm)
        } else {
            PrincipalName { name_type: sname0.name_type, name: copy(sname_name) }
        };
        let nonce = new_nonce();
        var req: u8[>..] = [];
        let eerr = encode_as_req(cfg, s, cname, realm, sname, nonce, etypes, pk, req);
        if eerr != OK { return empty_credential(), eerr; }
        var reply: u8[>..] = [];
        let nerr = send_to_kdc(cfg, realm, req, reply);
        if nerr != OK { return empty_credential(), nerr; }
        let code, kerr = reply_error(reply);
        if code != 0 {
            if code == KDC_ERR_PREAUTH_REQUIRED && !pk.have {
                let pa, perr = decode_padata(kerr.edata);
                if perr != OK { return empty_credential(), ERR_PREAUTH; }
                let e, sl, pr, ok = pick_etype_info(pa, etypes, cname.name, realm);
                if !ok || e == 0 { return empty_credential(), ERR_PREAUTH; }
                let k, err = secret_key(sec, cname.name, realm, e, sl, pr);
                if err != OK { return empty_credential(), err; }
                pk = PreauthKey { have: true, key: k, has_kvno: false, kvno: 0 };
                known_etype = e;
                salt.clear();
                salt.append(sl);
                params.clear();
                params.append(pr);
                continue;
            }
            if code == KRB_AP_ERR_SKEW && !skew_fixed && s.kdc_timesync {
                let now, us = kdc_now(s);
                s.time_offset += kerr.stime - now;
                skew_fixed = true;
                continue;
            }
            if code == KDC_ERR_WRONG_REALM && enterprise && kerr.has_crealm && referrals < 4 && kerr.crealm != realm {
                realm.clear();
                realm.append(kerr.crealm);
                pk = PreauthKey { have: false, key: no_key(), has_kvno: false, kvno: 0 };
                referrals++;
                continue;
            }
            return empty_credential(), code;
        }
        if message_type(reply) != MSG_AS_REP { return empty_credential(), ERR_UNEXPECTED; }
        let rep, derr = decode_kdc_rep(reply);
        if derr != OK { return empty_credential(), derr; }
        // The reply key: the one we pre-authenticated with if the reply
        // uses its type, else one made from the reply's salt.
        var key = pk.key;
        if !pk.have || pk.key.etype != rep.enc_part.etype {
            let one: i32[1] = [rep.enc_part.etype];
            let e, sl, pr, ok = pick_etype_info(rep.padata, one, cname.name, realm);
            let use_salt = if ok { copy(sl) } else { default_salt_of(cname.name, realm) };
            let k, err = secret_key(sec, cname.name, realm, rep.enc_part.etype, use_salt, if ok { pr } else { params });
            if err != OK { return empty_credential(), err; }
            key = k;
        }
        var plain: u8[>..] = [];
        let cerr = decrypt(key, USAGE_AS_REP_ENCPART, rep.enc_part.cipher, plain);
        if cerr != OK { return empty_credential(), if cerr == ERR_INTEGRITY { KDC_ERR_PREAUTH_FAILED } else { cerr }; }
        let part, perr = decode_enc_kdc_rep_part(plain);
        if perr != OK { return empty_credential(), perr; }
        if part.nonce != nonce { return empty_credential(), ERR_NONCE; }
        // Names: as asked, unless the KDC canonicalized them and proved it
        // saw our request (RFC 6806 §11).
        let same = rep.cname.name == cname.name && rep.crealm == realm && part.sname.name == sname.name && part.srealm == realm;
        if !same {
            if !s.canonicalize { return empty_credential(), ERR_NAME_MISMATCH; }
            let ck = check_req_checksum(part, key, req);
            if ck != OK { return empty_credential(), ck; }
        } else if part.flags & flag(TKT_ENC_PA_REP) != 0 {
            let ck = check_req_checksum(part, key, req);
            if ck == ERR_INTEGRITY { return empty_credential(), ck; }
        }
        return credential_of(rep, part), OK;
    }
    return empty_credential(), ERR_PREAUTH;
}

// "user@REALM" (or "user", in the default realm) as a client name and
// realm. A name with an escaped '@' is an enterprise name.
fn client_name(cfg: const Config&, text: const u8[:]) -> PrincipalName, u8[>..], i64 {
    let n, r, has, ok = parse_principal(text);
    var realm: u8[>..] = [];
    if !ok { return no_principal(), realm, ERR_NAME; }
    if has { realm.append(r); }
    else {
        let d, dok = default_realm(cfg);
        if !dok { return no_principal(), realm, ERR_CONFIG; }
        realm.append(d);
    }
    var esc_at = false;
    for i in n.len { if n[i] == '@' { esc_at = true; } }
    return PrincipalName { name_type: if esc_at { NT_ENTERPRISE } else { NT_PRINCIPAL }, name: n }, realm, OK;
}

// A TGT for `principal` with a password.
fn get_tgt_password(cfg: const Config&, principal: const u8[:], password: const u8[:]) -> Credential, i64 {
    let cn, realm, err = client_name(cfg, principal);
    if err != OK { return empty_credential(), err; }
    var s = settings(cfg);
    let sn = krbtgt(realm, realm);
    let sec = secret_password(password);
    return as_exchange(cfg, s, cn, realm, sn, sec);
}

// A TGT for `principal` with its keys from a keytab.
fn get_tgt_keytab(cfg: const Config&, principal: const u8[:], kt: const KeytabEntry[:]) -> Credential, i64 {
    let cn, realm, err = client_name(cfg, principal);
    if err != OK { return empty_credential(), err; }
    var s = settings(cfg);
    let sn = krbtgt(realm, realm);
    let sec = secret_keytab(kt);
    return as_exchange(cfg, s, cn, realm, sn, sec);
}

// --- The TGS exchange ----------------------------------------------------------------

// One TGS exchange with the KDC that `tgt` is for (krbtgt/R@...: realm R),
// for `sname` in `srealm`; extra KDC options (renew, validate) or'd in.
fn tgs_exchange(cfg: const Config&, s: Settings&, tgt: const Credential&, sname: const PrincipalName&, srealm: const u8[:],
                extra: u32) -> Credential, i64 {
    let kdc_realm = name_part(tgt.server, 1);
    var skew_fixed = false;
    for attempt in 2 {
        let now, usec = kdc_now(s);
        let nonce = new_nonce();
        var opts = extra;
        if s.forwardable && tgt.flags & flag(TKT_FORWARDABLE) != 0 { opts = opts | flag(KDC_OPT_FORWARDABLE); }
        if s.proxiable && tgt.flags & flag(TKT_PROXIABLE) != 0 { opts = opts | flag(KDC_OPT_PROXIABLE); }
        // Referrals need canonicalize (RFC 6806 §8); MIT always sets it.
        opts = opts | flag(KDC_OPT_CANONICALIZE);
        let renewable = tgt.flags & flag(TKT_RENEWABLE) != 0 && tgt.renew_till > 0;
        if renewable { opts = opts | flag(KDC_OPT_RENEWABLE); }
        let body = KdcReqBody {
            kdc_options: opts, has_cname: false, cname: no_principal(), realm: srealm, has_sname: true, sname: copy(sname),
            has_from: false, from: 0, till: tgt.endtime, has_rtime: renewable, rtime: tgt.renew_till, nonce: nonce,
            etypes: conf_etypes(cfg, "default_tgs_enctypes"), has_addresses: false, addresses: [], has_enc_authz: false,
            enc_authz: no_enc_data(), has_tickets: false, tickets: [],
        };
        var body_der: u8[>..] = [];
        encode_req_body(body_der, body);
        var ck: u8[>..] = [];
        let cerr = checksum(tgt.key, 0, USAGE_TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CKSUM, body_der, ck);
        if cerr != OK { return empty_credential(), cerr; }
        let auth = Authenticator {
            crealm: copy(tgt.client_realm), cname: PrincipalName { name_type: tgt.client_type, name: copy(tgt.client) },
            has_cksum: true, cksum: Checksum { ctype: cksum_type_for(tgt.key.etype), sum: copy(ck) }, cusec: usec, ctime: now,
            has_subkey: false, subkey: no_key(), has_seq_number: false, seq_number: 0, has_authz: false, authz: [],
        };
        var auth_der: u8[>..] = [];
        encode_authenticator(auth_der, auth);
        var auth_enc: u8[>..] = [];
        let aerr = encrypt(tgt.key, USAGE_TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR, auth_der, auth_enc);
        if aerr != OK { return empty_credential(), aerr; }
        var ap: u8[>..] = [];
        let apr = ApReq { ap_options: 0, ticket: copy(tgt.ticket),
                          authenticator: EncryptedData { etype: tgt.key.etype, has_kvno: false, kvno: 0, cipher: copy(auth_enc) } };
        encode_ap_req(ap, apr);
        var pa: PaData[>..] = [];
        pa.push(PaData { pa_type: PA_TGS_REQ, value: copy(ap) });
        var req: u8[>..] = [];
        let r = KdcReq { msg_type: MSG_TGS_REQ, has_padata: true, padata: copy(pa), body: copy(body) };
        encode_kdc_req(req, r);
        var reply: u8[>..] = [];
        let nerr = send_to_kdc(cfg, kdc_realm, req, reply);
        if nerr != OK { return empty_credential(), nerr; }
        let code, kerr = reply_error(reply);
        if code != 0 {
            if code == KRB_AP_ERR_SKEW && !skew_fixed && s.kdc_timesync {
                s.time_offset += kerr.stime - now;
                skew_fixed = true;
                continue;
            }
            return empty_credential(), code;
        }
        if message_type(reply) != MSG_TGS_REP { return empty_credential(), ERR_UNEXPECTED; }
        let rep, derr = decode_kdc_rep(reply);
        if derr != OK { return empty_credential(), derr; }
        var plain: u8[>..] = [];
        let xerr = decrypt(tgt.key, USAGE_TGS_REP_ENCPART_SESSION_KEY, rep.enc_part.cipher, plain);
        if xerr != OK { return empty_credential(), xerr; }
        let part, perr = decode_enc_kdc_rep_part(plain);
        if perr != OK { return empty_credential(), perr; }
        if part.nonce != nonce { return empty_credential(), ERR_NONCE; }
        if rep.cname.name != tgt.client || rep.crealm != tgt.client_realm { return empty_credential(), ERR_NAME_MISMATCH; }
        return credential_of(rep, part), OK;
    }
    return empty_credential(), KRB_AP_ERR_SKEW;
}

fn is_tgt_name(name: const u8[:]) -> bool { name_count(name) == 2 && name_part(name, 0) == "krbtgt" }

// A service ticket for `sname` in `srealm` (empty: unknown, and the
// KDCs are asked to refer us, RFC 6806), from a TGT. Returns every
// credential got, cross-realm TGTs first and the service's last.
fn get_service_ticket(cfg: const Config&, tgt: const Credential&, sname: const PrincipalName&, srealm: const u8[:])
    -> Credential[>..], i64 {
    var got: Credential[>..] = [];
    var s = settings(cfg);
    var visited: u8[][>..] = [];
    for hop in 12 {
        let cur = if got.len == 0 { copy(tgt) } else { last_credential(got) };
        let kdc_realm = name_part(cur.server, 1);
        visited.push(copy(kdc_realm));
        let here = srealm.len == 0 || srealm == kdc_realm;
        if here {
            let c, err = tgs_exchange(cfg, s, cur, sname, kdc_realm, 0);
            if err != OK { return got, err; }
            // A referral: a TGT for another realm, where the service is.
            if is_tgt_name(c.server) && !is_tgt_name(sname.name) && name_part(c.server, 1) != kdc_realm {
                if seen_realm(visited, name_part(c.server, 1)) { return got, ERR_REFERRALS; }
                got.push(copy(c));
                continue;
            }
            // A different name for the service only through canonicalization.
            if !is_tgt_name(sname.name) && c.server != sname.name && !s.canonicalize { return got, ERR_NAME_MISMATCH; }
            got.push(copy(c));
            return got, OK;
        }
        // Not this realm's: a TGT toward srealm. The KDC may hand back one
        // for a realm nearer than the one asked for (RFC 4120 §3.3.1).
        let toward = krbtgt(srealm, kdc_realm);
        let c, err = tgs_exchange(cfg, s, cur, toward, kdc_realm, 0);
        if err == OK && is_tgt_name(c.server) && name_part(c.server, 1) != kdc_realm {
            if seen_realm(visited, name_part(c.server, 1)) { return got, ERR_REFERRALS; }
            got.push(copy(c));
            continue;
        }
        if err != OK && err != KDC_ERR_S_PRINCIPAL_UNKNOWN { return got, err; }
        // No direct trust: the next realm on the path, from capaths or the
        // hierarchy.
        let path, has = capath(cfg, tgt.client_realm, srealm);
        let hpath = hierarchical_path(kdc_realm, srealm);
        var next: u8[>..] = [];
        for r in (if has { copy(path) } else { copy(hpath) }) {
            if !seen_realm(visited, r) && next.len == 0 { next.append(r); }
        }
        if next.len == 0 { return got, if err == OK { ERR_UNEXPECTED } else { err }; }
        let step = krbtgt(next, kdc_realm);
        let c2, err2 = tgs_exchange(cfg, s, cur, step, kdc_realm, 0);
        if err2 != OK { return got, err2; }
        if !is_tgt_name(c2.server) || name_part(c2.server, 1) == kdc_realm { return got, ERR_UNEXPECTED; }
        got.push(copy(c2));
    }
    return got, ERR_REFERRALS;
}

fn seen_realm(visited: const u8[][:], r: const u8[:]) -> bool {
    for v in visited { if v == r { return true; } }
    return false;
}

// The last of a list of credentials (which can only be walked).
fn last_credential(list: const Credential[:]) -> Credential {
    var i = 0;
    for c in list {
        if i == list.len - 1 { return copy(c); }
        i++;
    }
    return empty_credential();
}

// "service/host@REALM", "service/host" (the realm from [domain_realm], or
// by referral when it has none) or GSS-API's "service@host" as a name and
// realm (empty: ask by referral).
fn service_name(cfg: const Config&, text: const u8[:], gss_form: bool) -> PrincipalName, u8[>..], i64 {
    var realm: u8[>..] = [];
    if gss_form {
        // service@host: a host-based service name (RFC 2743 §4.1).
        var at = -1;
        for i in text.len { if text[i] == '@' { at = i; } }
        var name: u8[>..] = [];
        if at <= 0 || at == text.len - 1 {
            name.append(text);
            if at == text.len - 1 { name.resize(at); }
            return PrincipalName { name_type: NT_SRV_HST, name: name }, realm, if at < 0 { ERR_NAME } else { OK };
        }
        let host = lower(text[at + 1..]);
        name.append(name_join(text[..at], host));
        realm.append(realm_for_host(cfg, host));
        return PrincipalName { name_type: NT_SRV_HST, name: name }, realm, OK;
    }
    let n, r, has, ok = parse_principal(text);
    if !ok { return no_principal(), realm, ERR_NAME; }
    if has { realm.append(r); }
    else if name_count(n) >= 2 { realm.append(realm_for_host(cfg, name_part(n, 1))); }
    else {
        let d, dok = default_realm(cfg);
        if dok { realm.append(d); }
    }
    return PrincipalName { name_type: NT_PRINCIPAL, name: n }, realm, OK;
}

// Renews a renewable ticket (KDC option renew): the new credential.
fn renew(cfg: const Config&, c: const Credential&) -> Credential, i64 {
    var s = settings(cfg);
    let sn = PrincipalName { name_type: c.server_type, name: copy(c.server) };
    return tgs_exchange(cfg, s, c, sn, c.server_realm, flag(KDC_OPT_RENEW));
}

// --- With a credential cache --------------------------------------------------------

// kinit: a TGT with a password, stored as a new cache.
fn kinit_password(cfg: const Config&, cache_name: const u8[:], principal: const u8[:], password: const u8[:]) -> Credential, i64 {
    let c, err = get_tgt_password(cfg, principal, password);
    if err != OK { return c, err; }
    let base = ccache_new(c.client_type, c.client, c.client_realm);
    let cc = ccache_add(base, c);
    let serr = ccache_save(cache_name, cc);
    return c, serr;
}

// kinit -k: a TGT with a keytab's key, stored as a new cache.
fn kinit_keytab(cfg: const Config&, cache_name: const u8[:], principal: const u8[:], kt: const KeytabEntry[:]) -> Credential, i64 {
    let c, err = get_tgt_keytab(cfg, principal, kt);
    if err != OK { return c, err; }
    let base = ccache_new(c.client_type, c.client, c.client_realm);
    let cc = ccache_add(base, c);
    let serr = ccache_save(cache_name, cc);
    return c, serr;
}

// kvno: a service ticket from the cache, or from the KDCs with the
// cache's TGT (the tickets got kept in the cache).
fn get_service_ticket_cached(cfg: const Config&, cache_name: const u8[:], service: const u8[:], gss_form: bool) -> Credential, i64 {
    let cc, err = ccache_load(cache_name);
    if err != OK { return empty_credential(), ERR_NO_CREDS; }
    let sn, srealm, nerr = service_name(cfg, service, gss_form);
    if nerr != OK { return empty_credential(), nerr; }
    var s = settings(cfg);
    let now, us = kdc_now(s);
    if srealm.len > 0 {
        let have, ok = ccache_find(cc, sn.name, srealm, now);
        if ok { return have, OK; }
    }
    let tgt, ok = ccache_find(cc, name_join("krbtgt", cc.realm), cc.realm, now);
    if !ok { return empty_credential(), ERR_NO_CREDS; }
    let got, gerr = get_service_ticket(cfg, tgt, sn, srealm);
    if gerr != OK { return empty_credential(), gerr; }
    let next = ccache_add_all(cc, got);
    let serr = ccache_save(cache_name, next);
    return last_credential(got), serr;
}

// A forwarded TGT (KDC option forwarded) from a forwardable one, for
// delegating to a service (GSS-API's deleg flag).
fn forward_tgt(cfg: const Config&, tgt: const Credential&) -> Credential, i64 {
    if tgt.flags & flag(TKT_FORWARDABLE) == 0 { return empty_credential(), KDC_ERR_BADOPTION; }
    var s = settings(cfg);
    s.forwardable = true;
    let sn = PrincipalName { name_type: tgt.server_type, name: copy(tgt.server) };
    return tgs_exchange(cfg, s, tgt, sn, tgt.server_realm, flag(KDC_OPT_FORWARDED));
}
