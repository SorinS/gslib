// krb5.client: the AS and TGS exchanges (RFC 4120 §3.1, §3.3): a TGT from
// a password or a keytab, with encrypted-timestamp pre-authentication as
// the KDC's ETYPE-INFO2 asks; service tickets; cross-realm tickets along
// [capaths] or the realm hierarchy; referrals (RFC 6806) when the
// service's realm is not known; clock skew corrected from the KDC's time
// (MIT's kdc_timesync); renewal. The *_cached functions keep tickets in a
// credential cache, as kinit and kvno do.
//
// FAST (RFC 6113, krb5.fast): an AS exchange armored with a TGT the
// caller has (get_tgt_*_fast, kinit_*_fast: MIT's kinit -T), encrypted
// challenge in it when the KDC offers it; every TGS exchange armored by
// its own TGT, as MIT's are, a KDC that does not do FAST answered in the
// clear.
//
// Not done: PKINIT, SPAKE, FAST's hide-client-names option, explicit
// armor in a TGS exchange (Windows' compound identity),
// S4U2Self/S4U2Proxy and user-to-user.

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
import krb5.fast;

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
    if sec.has_password { return conf_etypes(cfg, "default_tkt_enctypes"); }
    let want = conf_etypes(cfg, "default_tkt_enctypes");
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

// The padata of an AS-REQ: the pre-authentication (encrypted challenge
// inside FAST when the KDC offers it, else the encrypted timestamp), the
// FAST cookie, the PAC request, and the ask for the request's checksum.
fn as_padata(s: const Settings&, st: const FastState&, armored: bool, challenge: bool, pk: const PreauthKey&,
             cookie: const u8[:], has_cookie: bool, now: i64, usec: i64, out: PaData[>..]&) -> i64 {
    if pk.have {
        if armored && challenge {
            var v: u8[>..] = [];
            let err = enc_challenge(st, pk.key, now, usec, v);
            if err != OK { return err; }
            out.push(PaData { pa_type: PA_ENCRYPTED_CHALLENGE, value: copy(v) });
        } else {
            var ts: u8[>..] = [];
            encode_pa_enc_ts(ts, now, true, usec);
            var c: u8[>..] = [];
            let err = encrypt(pk.key, USAGE_AS_REQ_PA_ENC_TIMESTAMP, ts, c);
            if err != OK { return err; }
            var ed: u8[>..] = [];
            let d = EncryptedData { etype: pk.key.etype, has_kvno: false, kvno: 0, cipher: copy(c) };
            encode_enc_data(ed, d);
            out.push(PaData { pa_type: PA_ENC_TIMESTAMP, value: copy(ed) });
        }
    }
    if has_cookie { out.push(PaData { pa_type: PA_FX_COOKIE, value: cookie }); }
    if s.request_pac {
        var pr: u8[>..] = [];
        encode_pa_pac_request(pr, true);
        out.push(PaData { pa_type: PA_PAC_REQUEST, value: copy(pr) });
    }
    // Ask for the request's checksum in the reply (RFC 6806 §11), which
    // lets a canonicalized reply be trusted.
    out.push(PaData { pa_type: PA_REQ_ENC_PA_REP, value: "" });
    return OK;
}

fn as_req_body(s: const Settings&, cname: const PrincipalName&, realm: const u8[:], sname: const PrincipalName&, nonce: u32,
               etypes: const i32[:], now: i64) -> KdcReqBody {
    let renewable = s.renew_lifetime > 0;
    return KdcReqBody {
        kdc_options: kdc_options(s), has_cname: true, cname: copy(cname), realm: realm, has_sname: true, sname: copy(sname),
        has_from: false, from: 0, till: now + s.lifetime, has_rtime: renewable, rtime: now + s.renew_lifetime,
        nonce: nonce, etypes: etypes, has_addresses: false, addresses: [], has_enc_authz: false, enc_authz: no_enc_data(),
        has_tickets: false, tickets: [],
    };
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
        return if verify_checksum(key, ck.ctype, USAGE_AS_REQ, req, ck.sum) == OK { OK } else { ERR_INTEGRITY };
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
//
// With `armored`, every request is armored with FAST, the armor made
// from `armor`, a TGT for the realm (krbtgt/REALM@REALM): there is no
// first try without it, and a reply that is not armored is refused
// (ERR_FAST), so nothing in the clear can turn FAST off. Only the
// armored KDC's errors are acted on; an unarmored error ends the
// exchange with its code. Also returns whether the KDC said it does FAST
// (PA-FX-FAST in the reply's encrypted padata), as MIT's fast_avail.
fn as_exchange(cfg: const Config&, s: Settings&, cname: const PrincipalName&, realm0: const u8[:], sname0: const PrincipalName&,
               sec: const Secret&, armor: const Credential&, armored: bool) -> Credential, bool, i64 {
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
    var challenge = false;
    var cookie: u8[>..] = [];
    var has_cookie = false;
    let enterprise = cname.name_type == NT_ENTERPRISE;
    if enterprise { s.canonicalize = true; }
    for attempt in 8 {
        let etypes = as_etypes(cfg, sec, cname.name, realm);
        if etypes.len == 0 { return empty_credential(), false, ERR_ETYPE; }
        let sname = if sname0.name_type == NT_SRV_INST && name_part(sname_name, 0) == "krbtgt" {
            krbtgt(realm, realm)
        } else {
            PrincipalName { name_type: sname0.name_type, name: copy(sname_name) }
        };
        let nonce = new_nonce();
        let now, usec = kdc_now(s);
        // The armor: a TGT for this realm (not another one a referral
        // sends us to).
        if armored && !(is_tgt_name(armor.server) && name_part(armor.server, 1) == realm && armor.server_realm == realm) {
            return empty_credential(), false, ERR_FAST;
        }
        let st, aerr = fast_armor_as_if(armored, armor, now, usec);
        if aerr != OK { return empty_credential(), false, aerr; }
        var pa: PaData[>..] = [];
        let perr0 = as_padata(s, st, armored, challenge, pk, cookie, has_cookie, now, usec, pa);
        if perr0 != OK { return empty_credential(), false, perr0; }
        let body = as_req_body(s, cname, realm, sname, nonce, etypes, now);
        var req: u8[>..] = [];
        if armored {
            var body_der: u8[>..] = [];
            encode_req_body(body_der, body);
            var none: PaData[>..] = [];
            let werr = fast_wrap(st, MSG_AS_REQ, pa, none, body, body_der, req);
            if werr != OK { return empty_credential(), false, werr; }
        } else {
            let r = KdcReq { msg_type: MSG_AS_REQ, has_padata: true, padata: copy(pa), body: copy(body) };
            encode_kdc_req(req, r);
        }
        var reply: u8[>..] = [];
        let nerr = send_to_kdc(cfg, realm, req, reply);
        if nerr != OK { return empty_credential(), false, nerr; }
        let code0, kerr0 = reply_error(reply);
        if code0 != 0 {
            // Armored, the error that counts is the one inside the armor,
            // with its padata; unarmored, the error itself and its e-data.
            let inner, fhints, ferr = fast_error(armored, st, kerr0, nonce);
            if ferr != OK {
                // The KDC could not read our armor, so its error is in the
                // clear. Skew alone is acted on (MIT does too): the armor's
                // authenticator is checked against the KDC's clock, and
                // the next request is armored all the same.
                if code0 == KRB_AP_ERR_SKEW && !skew_fixed && s.kdc_timesync {
                    s.time_offset += kerr0.stime - now;
                    skew_fixed = true;
                    continue;
                }
                return empty_credential(), false, code0;
            }
            let kerr = if armored { copy(inner) } else { copy(kerr0) };
            let code = if kerr.error_code == 0 { KRB_ERR_GENERIC } else { kerr.error_code };
            let ehints, eherr = decode_padata(kerr0.edata);
            let hints = if armored { copy(fhints) } else { copy(ehints) };
            let ck, cfound = find_padata(hints, PA_FX_COOKIE);
            if armored && cfound {
                cookie.clear();
                cookie.append(ck);
                has_cookie = true;
            }
            if code == KDC_ERR_PREAUTH_REQUIRED && !pk.have {
                if !armored && eherr != OK { return empty_credential(), false, ERR_PREAUTH; }
                let e, sl, pr, ok = pick_etype_info(hints, etypes, cname.name, realm);
                if !ok || e == 0 { return empty_credential(), false, ERR_PREAUTH; }
                let k, err = secret_key(sec, cname.name, realm, e, sl, pr);
                if err != OK { return empty_credential(), false, err; }
                pk = PreauthKey { have: true, key: k, has_kvno: false, kvno: 0 };
                known_etype = e;
                salt.clear();
                salt.append(sl);
                params.clear();
                params.append(pr);
                let cv, offered = find_padata(hints, PA_ENCRYPTED_CHALLENGE);
                challenge = armored && offered;
                // MIT's disable_encrypted_timestamp: never the timestamp,
                // which anyone who sees it can guess the password from.
                if !challenge && conf_bool(cfg, str("realms/", realm, "/disable_encrypted_timestamp"), false) {
                    return empty_credential(), false, ERR_PREAUTH;
                }
                continue;
            }
            if code == KRB_AP_ERR_SKEW && !skew_fixed && s.kdc_timesync {
                s.time_offset += kerr.stime - now;
                skew_fixed = true;
                continue;
            }
            if code == KDC_ERR_WRONG_REALM && enterprise && kerr.has_crealm && referrals < 4 && kerr.crealm != realm {
                realm.clear();
                realm.append(kerr.crealm);
                pk = PreauthKey { have: false, key: no_key(), has_kvno: false, kvno: 0 };
                has_cookie = false;
                referrals++;
                continue;
            }
            return empty_credential(), false, code;
        }
        if message_type(reply) != MSG_AS_REP { return empty_credential(), false, ERR_UNEXPECTED; }
        let rep0, derr = decode_kdc_rep(reply);
        if derr != OK { return empty_credential(), false, derr; }
        // Armored: the FAST response checked, and its padata and names
        // (the finished part's) are the reply's.
        let fr, frerr = fast_reply_if(armored, st, rep0, nonce);
        if frerr != OK { return empty_credential(), false, frerr; }
        let rep = if armored {
            KdcRep { msg_type: rep0.msg_type, has_padata: true, padata: copy(fr.padata), crealm: copy(fr.finished.crealm),
                     cname: copy(fr.finished.cname), ticket: copy(rep0.ticket), enc_part: copy(rep0.enc_part) }
        } else { copy(rep0) };
        // Only a type we asked for (as MIT checks): a KDC, or someone in
        // the middle, cannot push us onto a weaker one.
        var asked = false;
        for e in etypes { if e == rep.enc_part.etype { asked = true; } }
        if !asked { return empty_credential(), false, KDC_ERR_ETYPE_NOSUPP; }
        // The KDC's answer to our encrypted challenge proves it knows our
        // key (RFC 6113 §5.4.6).
        if armored && challenge && pk.have {
            let cerr = check_kdc_challenge(st, pk.key, rep.padata);
            if cerr != OK { return empty_credential(), false, cerr; }
        }
        // The reply key: the one we pre-authenticated with if the reply
        // uses its type, else one made from the reply's salt; then
        // strengthened by FAST's strengthen key.
        var key = pk.key;
        if !pk.have || pk.key.etype != rep.enc_part.etype {
            let one: i32[1] = [rep.enc_part.etype];
            let e, sl, pr, ok = pick_etype_info(rep.padata, one, cname.name, realm);
            let use_salt = if ok { copy(sl) } else { default_salt_of(cname.name, realm) };
            let k, err = secret_key(sec, cname.name, realm, rep.enc_part.etype, use_salt, if ok { pr } else { params });
            if err != OK { return empty_credential(), false, err; }
            key = k;
        }
        let reply_key, rkerr = fast_reply_key(fr, key);
        if rkerr != OK { return empty_credential(), false, rkerr; }
        var plain: u8[>..] = [];
        let cerr = decrypt(reply_key, USAGE_AS_REP_ENCPART, rep.enc_part.cipher, plain);
        if cerr != OK { return empty_credential(), false, if cerr == ERR_INTEGRITY { KDC_ERR_PREAUTH_FAILED } else { cerr }; }
        let part, perr = decode_enc_kdc_rep_part(plain);
        if perr != OK { return empty_credential(), false, perr; }
        if part.nonce != nonce { return empty_credential(), false, ERR_NONCE; }
        var key_asked = false;
        for e in etypes { if e == part.key.etype { key_asked = true; } }
        if !key_asked { return empty_credential(), false, KDC_ERR_ETYPE_NOSUPP; }
        // Names: as asked, unless the KDC canonicalized them and proved it
        // saw our request (RFC 6806 §11).
        let same = rep.cname.name == cname.name && rep.crealm == realm && part.sname.name == sname.name && part.srealm == realm;
        if !same {
            if !s.canonicalize { return empty_credential(), false, ERR_NAME_MISMATCH; }
            let ck = check_req_checksum(part, reply_key, req);
            if ck != OK { return empty_credential(), false, ck; }
        } else if part.flags & flag(TKT_ENC_PA_REP) != 0 {
            let ck = check_req_checksum(part, reply_key, req);
            if ck == ERR_INTEGRITY { return empty_credential(), false, ck; }
        }
        var fast_avail = false;
        if part.flags & flag(TKT_ENC_PA_REP) != 0 && part.has_enc_padata && check_req_checksum(part, reply_key, req) == OK {
            let fv, ff = find_padata(part.enc_padata, PA_FX_FAST);
            fast_avail = ff;
        }
        return credential_of(rep, part), fast_avail, OK;
    }
    return empty_credential(), false, ERR_PREAUTH;
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
    let sec = secret_password(password);
    let none = empty_credential();
    let c, fast, err = get_tgt(cfg, principal, sec, none, false);
    return c, err;
}

// A TGT for `principal` with its keys from a keytab.
fn get_tgt_keytab(cfg: const Config&, principal: const u8[:], kt: const KeytabEntry[:]) -> Credential, i64 {
    let sec = secret_keytab(kt);
    let none = empty_credential();
    let c, fast, err = get_tgt(cfg, principal, sec, none, false);
    return c, err;
}

// The same, armored with FAST (RFC 6113): `armor` is a TGT for the
// client's realm, a host's say (as MIT's kinit -T takes it from a cache:
// armor_tgt).
fn get_tgt_password_fast(cfg: const Config&, principal: const u8[:], password: const u8[:], armor: const Credential&)
    -> Credential, i64 {
    let sec = secret_password(password);
    let c, fast, err = get_tgt(cfg, principal, sec, armor, true);
    return c, err;
}

fn get_tgt_keytab_fast(cfg: const Config&, principal: const u8[:], kt: const KeytabEntry[:], armor: const Credential&)
    -> Credential, i64 {
    let sec = secret_keytab(kt);
    let c, fast, err = get_tgt(cfg, principal, sec, armor, true);
    return c, err;
}

fn get_tgt(cfg: const Config&, principal: const u8[:], sec: const Secret&, armor: const Credential&, armored: bool)
    -> Credential, bool, i64 {
    let cn, realm, err = client_name(cfg, principal);
    if err != OK { return empty_credential(), false, err; }
    var s = settings(cfg);
    let sn = krbtgt(realm, realm);
    return as_exchange(cfg, s, cn, realm, sn, sec, armor, armored);
}

// The TGT for `realm` (krbtgt/REALM@REALM) in a cache, to armor with:
// one not expired by the cache's clock (its offset from the KDC's).
fn armor_tgt(cache_name: const u8[:], realm: const u8[:]) -> Credential, i64 {
    let cc, err = ccache_load(cache_name);
    if err != OK { return empty_credential(), ERR_NO_CREDS; }
    let now = now_ns() / 1000000000 + (if cc.has_time_offset { cc.time_offset } else { 0 });
    let c, ok = ccache_find(cc, name_join("krbtgt", realm), realm, now);
    return c, if ok { OK } else { ERR_NO_CREDS };
}

// --- The TGS exchange ----------------------------------------------------------------

// One TGS exchange with the KDC that `tgt` is for (krbtgt/R@...: realm R),
// for `sname` in `srealm`; extra KDC options (renew, validate) or'd in.
//
// The authenticator carries a new subkey, and the request is armored with
// FAST by the TGT itself (implicit armor, RFC 6113 §5.4.1.1), as MIT's
// client always does. A KDC that does not do FAST answers in the clear,
// which is taken as MIT takes it: the reply is still under the subkey. An
// armored reply must check (ERR_FAST otherwise), and then its finished
// names are the reply's and its strengthen key strengthens the reply key.
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
        let subkey = random_key(tgt.key.etype);
        if subkey.etype == 0 { return empty_credential(), ERR_ETYPE; }
        let st, sterr = fast_armor_tgs(subkey, tgt.key);
        if sterr != OK { return empty_credential(), sterr; }
        let auth = Authenticator {
            crealm: copy(tgt.client_realm), cname: PrincipalName { name_type: tgt.client_type, name: copy(tgt.client) },
            has_cksum: true, cksum: Checksum { ctype: cksum_type_for(tgt.key.etype), sum: copy(ck) }, cusec: usec, ctime: now,
            has_subkey: true, subkey: subkey, has_seq_number: false, seq_number: 0, has_authz: false, authz: [],
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
        var outer: PaData[>..] = [];
        outer.push(PaData { pa_type: PA_TGS_REQ, value: copy(ap) });
        var inner: PaData[>..] = [];
        var req: u8[>..] = [];
        let werr = fast_wrap(st, MSG_TGS_REQ, inner, outer, body, ap, req);
        if werr != OK { return empty_credential(), werr; }
        var reply: u8[>..] = [];
        let nerr = send_to_kdc(cfg, kdc_realm, req, reply);
        if nerr != OK { return empty_credential(), nerr; }
        let code0, kerr0 = reply_error(reply);
        if code0 != 0 {
            // The error inside the armor if there is one (MIT's KDC armors
            // its errors to an armored request); else the error as it is.
            let inner_err, hints, ferr = fast_error(true, st, kerr0, nonce);
            let kerr = if ferr == OK { copy(inner_err) } else { copy(kerr0) };
            let code = if ferr != OK { code0 } else if kerr.error_code == 0 { KRB_ERR_GENERIC } else { kerr.error_code };
            if code == KRB_AP_ERR_SKEW && !skew_fixed && s.kdc_timesync {
                s.time_offset += kerr.stime - now;
                skew_fixed = true;
                continue;
            }
            return empty_credential(), code;
        }
        if message_type(reply) != MSG_TGS_REP { return empty_credential(), ERR_UNEXPECTED; }
        let rep0, derr = decode_kdc_rep(reply);
        if derr != OK { return empty_credential(), derr; }
        let fv, armored = find_padata(rep0.padata, PA_FX_FAST);
        let fr, frerr = fast_reply_if(armored, st, rep0, nonce);
        if frerr != OK { return empty_credential(), frerr; }
        let rep = if armored {
            KdcRep { msg_type: rep0.msg_type, has_padata: true, padata: copy(fr.padata), crealm: copy(fr.finished.crealm),
                     cname: copy(fr.finished.cname), ticket: copy(rep0.ticket), enc_part: copy(rep0.enc_part) }
        } else { copy(rep0) };
        // Under the subkey (usage 9), or under the session key (8) as
        // Heimdal before 1.3 does it.
        let k9, k9err = fast_reply_key(fr, subkey);
        if k9err != OK { return empty_credential(), k9err; }
        var plain: u8[>..] = [];
        var xerr = decrypt(k9, USAGE_TGS_REP_ENCPART_SUBKEY, rep.enc_part.cipher, plain);
        if xerr != OK {
            let k8, k8err = fast_reply_key(fr, tgt.key);
            if k8err != OK { return empty_credential(), k8err; }
            plain.clear();
            xerr = decrypt(k8, USAGE_TGS_REP_ENCPART_SESSION_KEY, rep.enc_part.cipher, plain);
        }
        if xerr != OK { return empty_credential(), xerr; }
        let part, perr = decode_enc_kdc_rep_part(plain);
        if perr != OK { return empty_credential(), perr; }
        if part.nonce != nonce { return empty_credential(), ERR_NONCE; }
        // The session key of a type we asked for, as MIT checks.
        var key_asked = false;
        for e in body.etypes { if e == part.key.etype { key_asked = true; } }
        if !key_asked { return empty_credential(), KDC_ERR_ETYPE_NOSUPP; }
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

// kinit: a TGT with a password, stored as a new cache. When the KDC says
// it does FAST, the cache says so too (MIT's fast_avail entry), and MIT's
// kinit -T can armor with it.
fn kinit_password(cfg: const Config&, cache_name: const u8[:], principal: const u8[:], password: const u8[:]) -> Credential, i64 {
    let sec = secret_password(password);
    let none = empty_credential();
    let c, fast, err = get_tgt(cfg, principal, sec, none, false);
    return kinit_save(cache_name, c, fast, err);
}

// kinit -k: a TGT with a keytab's key, stored as a new cache.
fn kinit_keytab(cfg: const Config&, cache_name: const u8[:], principal: const u8[:], kt: const KeytabEntry[:]) -> Credential, i64 {
    let sec = secret_keytab(kt);
    let none = empty_credential();
    let c, fast, err = get_tgt(cfg, principal, sec, none, false);
    return kinit_save(cache_name, c, fast, err);
}

// kinit -T: the same, armored with the TGT for the client's realm in
// `armor_cache`.
fn kinit_password_fast(cfg: const Config&, cache_name: const u8[:], principal: const u8[:], password: const u8[:],
                       armor_cache: const u8[:]) -> Credential, i64 {
    let armor, aerr = armor_for(cfg, principal, armor_cache);
    if aerr != OK { return empty_credential(), aerr; }
    let sec = secret_password(password);
    let c, fast, err = get_tgt(cfg, principal, sec, armor, true);
    return kinit_save(cache_name, c, fast, err);
}

fn kinit_keytab_fast(cfg: const Config&, cache_name: const u8[:], principal: const u8[:], kt: const KeytabEntry[:],
                     armor_cache: const u8[:]) -> Credential, i64 {
    let armor, aerr = armor_for(cfg, principal, armor_cache);
    if aerr != OK { return empty_credential(), aerr; }
    let sec = secret_keytab(kt);
    let c, fast, err = get_tgt(cfg, principal, sec, armor, true);
    return kinit_save(cache_name, c, fast, err);
}

fn armor_for(cfg: const Config&, principal: const u8[:], armor_cache: const u8[:]) -> Credential, i64 {
    let cn, realm, err = client_name(cfg, principal);
    if err != OK { return empty_credential(), err; }
    return armor_tgt(armor_cache, realm);
}

fn kinit_save(cache_name: const u8[:], c: const Credential&, fast: bool, err: i64) -> Credential, i64 {
    if err != OK { return copy(c), err; }
    let base = ccache_new(c.client_type, c.client, c.client_realm);
    let with_tgt = ccache_add(base, c);
    let cc = if fast { ccache_with_config(with_tgt, "fast_avail", principal_string(c.server, c.server_realm), "yes") }
             else { copy(with_tgt) };
    let serr = ccache_save(cache_name, cc);
    return copy(c), serr;
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
