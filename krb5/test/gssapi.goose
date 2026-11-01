// krb5.gssapi and krb5.service without a KDC: a service ticket made here
// with a known service key, then contexts established both ways, with and
// without mutual authentication, MIC and Wrap tokens (sealed and not, any
// RRC), tampering, replays and reordering, channel bindings, delegation,
// and the acceptor's checks of tickets and authenticators.

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

fn exchange(what: const u8[:], e: i32, mutual: bool) {
    let svc = krb5::random_key(18);
    let kt = keytab_of(svc);
    let cred = make_cred(svc, e, 0, NOW - 600, NOW + 3000);
    var rc: krb5::ReplayEntry[>..] = [];
    var t1: u8[>..] = [];
    var ictx, err = krb5::gss_init(cred, if mutual { krb5::GSS_MUTUAL | krb5::GSS_SEQUENCE } else { krb5::GSS_SEQUENCE },
                                   "", false, "", NOW, 123, t1);
    tv::check_int(str(what, " init"), err, krb5::OK);
    var t2: u8[>..] = [];
    var actx, acc, aerr = krb5::gss_accept(t1, kt, false, rc, NOW, 0, 300, "", false, t2);
    tv::check_int(str(what, " accept"), aerr, krb5::OK);
    tv::check_eq(str(what, " client"), acc.ap.client, "alice");
    tv::check(str(what, " mutual token"), (t2.len > 0) == mutual);
    if mutual { tv::check_int(str(what, " continue"), krb5::gss_init_continue(ictx, t2), krb5::OK); }
    tv::check(str(what, " established"), ictx.established && actx.established);
    tv::check(str(what, " same key"), ictx.key.value == actx.key.value && ictx.acceptor_subkey == actx.acceptor_subkey);
    let legacy = !krb5::cfx_key(ictx.key);
    for round in 3 {
        for conf in [true, false] {
            var w: u8[>..] = [];
            let msg = str("message ", round, " to the acceptor");
            tv::check_int(str(what, " wrap"), krb5::gss_wrap(ictx, msg, conf, w), krb5::OK);
            var u: u8[>..] = [];
            let sealed, uerr = krb5::gss_unwrap(actx, w, u);
            tv::check(str(what, " unwrap ", conf), uerr == krb5::OK && sealed == conf && u == msg);
            var w2: u8[>..] = [];
            tv::check_int(str(what, " wrap back"), krb5::gss_wrap(actx, "reply", conf, w2), krb5::OK);
            var u2: u8[>..] = [];
            let s2, uerr2 = krb5::gss_unwrap(ictx, w2, u2);
            tv::check(str(what, " unwrap back ", conf), uerr2 == krb5::OK && u2 == "reply");
            // Its own token is not the peer's.
            var u3: u8[>..] = [];
            let s3, uerr3 = krb5::gss_unwrap(actx, w2, u3);
            tv::check(str(what, " reflected refused"), uerr3 != krb5::OK);
        }
        var mic: u8[>..] = [];
        tv::check_int(str(what, " mic"), krb5::gss_get_mic(actx, "signed", mic), krb5::OK);
        tv::check_int(str(what, " verify mic"), krb5::gss_verify_mic(ictx, "signed", mic), krb5::OK);
        tv::check(str(what, " replayed mic"), krb5::gss_verify_mic(ictx, "signed", mic) == krb5::ERR_SEQUENCE);
        var mic2: u8[>..] = [];
        tv::check_int(str(what, " mic 2"), krb5::gss_get_mic(actx, "signed", mic2), krb5::OK);
        tv::check(str(what, " wrong message"), krb5::gss_verify_mic(ictx, "signeD", mic2) == krb5::KRB_AP_ERR_MODIFIED);
        // A later token after a lost one is out of sequence.
        var mic3: u8[>..] = [];
        krb5::gss_get_mic(actx, "x", mic3);
        var mic4: u8[>..] = [];
        krb5::gss_get_mic(actx, "y", mic4);
        tv::check(str(what, " gap"), krb5::gss_verify_mic(ictx, "y", mic4) == krb5::ERR_SEQUENCE);
        // Resynchronize: the acceptor's tokens from now on.
        ictx.recv_seq = actx.send_seq;
    }
    if legacy { return; }
    // Rotated tokens (RRC) read the same.
    var w: u8[>..] = [];
    krb5::gss_wrap(ictx, "rotated payload", true, w);
    var r: u8[>..] = [];
    r.append(w[..16]);
    let body = w[16..];
    let rrc = 28;
    for i in body.len { r.push(body[(i + body.len - rrc % body.len) % body.len]); }
    r[6] = 0;
    r[7] = rrc as! u8;
    var u: u8[>..] = [];
    let sealed, uerr = krb5::gss_unwrap(actx, r, u);
    tv::check(str(what, " rrc 28"), uerr == krb5::OK && u == "rotated payload");
    // Tampering anywhere fails.
    var w2: u8[>..] = [];
    krb5::gss_wrap(ictx, "tamper with me", true, w2);
    for at in [2, 9, 16, 20, w2.len - 1] {
        var t: u8[>..] = [];
        t.append(w2);
        t[at] = t[at] ^ 1;
        var o: u8[>..] = [];
        let s, terr = krb5::gss_unwrap(actx, t, o);
        tv::check(str(what, " tampered at ", at), terr != krb5::OK);
    }
}

fn acceptor_checks() {
    let svc = krb5::random_key(17);
    let kt = keytab_of(svc);
    fn try_accept(what: const u8[:], cred: const krb5::Credential&, keys: const krb5::KeytabEntry[:], now: i64, want: i64) {
        var rc: krb5::ReplayEntry[>..] = [];
        var t1: u8[>..] = [];
        var ictx, err = krb5::gss_init(cred, krb5::GSS_MUTUAL, "", false, "", now, 0, t1);
        var t2: u8[>..] = [];
        var actx, acc, aerr = krb5::gss_accept(t1, keys, false, rc, now, 0, 300, "", false, t2);
        tv::check_int(what, aerr, want);
    }
    let good = make_cred(svc, 17, 0, NOW - 600, NOW + 3000);
    try_accept("expired", good, kt, NOW + 4000, krb5::KRB_AP_ERR_TKT_EXPIRED);
    try_accept("not yet valid", good, kt, NOW - 1000, krb5::KRB_AP_ERR_TKT_NYV);
    let invalid = make_cred(svc, 17, krb5::flag(krb5::TKT_INVALID), NOW - 600, NOW + 3000);
    try_accept("invalid flag", invalid, kt, NOW, krb5::KRB_AP_ERR_TKT_NYV);
    let other = keytab_of(krb5::random_key(17));
    try_accept("wrong key", good, other, NOW, krb5::KRB_AP_ERR_BAD_INTEGRITY);
    var none: krb5::KeytabEntry[>..] = [];
    try_accept("no key", good, none, NOW, krb5::KRB_AP_ERR_NOT_US);
    var old: krb5::KeytabEntry[>..] = [];
    old.push(krb5::KeytabEntry { name_type: 1, name: "HTTP/web.example", realm: "EXAMPLE.COM", timestamp: 0, kvno: 2, key: svc });
    try_accept("old kvno", good, old, NOW, krb5::KRB_AP_ERR_BADKEYVER);
    var rc4only: krb5::KeytabEntry[>..] = [];
    rc4only.push(krb5::KeytabEntry { name_type: 1, name: "HTTP/web.example", realm: "EXAMPLE.COM", timestamp: 0, kvno: 3,
                                     key: krb5::random_key(23) });
    try_accept("other type", good, rc4only, NOW, krb5::KRB_AP_ERR_NOKEY);
    // Skew: the authenticator's time far from ours.
    var rc: krb5::ReplayEntry[>..] = [];
    var t1: u8[>..] = [];
    var ictx, err = krb5::gss_init(good, 0, "", false, "", NOW + 1000, 0, t1);
    var t2: u8[>..] = [];
    var actx, acc, aerr = krb5::gss_accept(t1, kt, false, rc, NOW, 0, 300, "", false, t2);
    tv::check_int("skew", aerr, krb5::KRB_AP_ERR_SKEW);
    tv::check("skew answered with an error token", t2.len > 0);
    let id, at, uerr = krb5::gss_unframe(t2, krb5::KRB5_OID, true);
    tv::check("error token", uerr == krb5::OK && id == krb5::TOK_ERROR);
    // Replay: the same token twice.
    var rc2: krb5::ReplayEntry[>..] = [];
    var t3: u8[>..] = [];
    var ictx2, err2 = krb5::gss_init(good, 0, "", false, "", NOW, 0, t3);
    var o1: u8[>..] = [];
    var a1, acc1, e1 = krb5::gss_accept(t3, kt, false, rc2, NOW, 0, 300, "", false, o1);
    var o2: u8[>..] = [];
    var a2, acc2, e2 = krb5::gss_accept(t3, kt, false, rc2, NOW + 1, 0, 300, "", false, o2);
    tv::check("first accepted", e1 == krb5::OK);
    tv::check_int("replay", e2, krb5::KRB_AP_ERR_REPEAT);
    // Channel bindings: matching, missing (accepted), different (refused).
    fn cb(what: const u8[:], ib: const u8[:], ihas: bool, ab: const u8[:], want: i64) {
        var rc3: krb5::ReplayEntry[>..] = [];
        var t: u8[>..] = [];
        var ic, ie = krb5::gss_init(good, 0, ib, ihas, "", NOW, 0, t);
        var o: u8[>..] = [];
        var ac, aa, ae = krb5::gss_accept(t, kt, false, rc3, NOW, 0, 300, ab, true, o);
        tv::check_int(what, ae, want);
    }
    cb("bindings match", "tls-server-end-point:abc", true, "tls-server-end-point:abc", krb5::OK);
    cb("bindings absent", "", false, "tls-server-end-point:abc", krb5::OK);
    cb("bindings differ", "tls-server-end-point:abd", true, "tls-server-end-point:abc", krb5::KRB_AP_ERR_BADADDR);
    // Any name: a keytab entry of another name with the right key.
    var renamed: krb5::KeytabEntry[>..] = [];
    renamed.push(krb5::KeytabEntry { name_type: 1, name: "host/other", realm: "EXAMPLE.COM", timestamp: 0, kvno: 3, key: svc });
    var rc4: krb5::ReplayEntry[>..] = [];
    var t4: u8[>..] = [];
    var ic4, ie4 = krb5::gss_init(good, 0, "", false, "", NOW, 0, t4);
    var o4: u8[>..] = [];
    var ac4, aa4, ae4 = krb5::gss_accept(t4, renamed, false, rc4, NOW, 0, 300, "", false, o4);
    tv::check_int("other name refused", ae4, krb5::KRB_AP_ERR_NOT_US);
    var o5: u8[>..] = [];
    var ac5, aa5, ae5 = krb5::gss_accept(t4, renamed, true, rc4, NOW, 0, 300, "", false, o5);
    tv::check_int("any name accepted", ae5, krb5::OK);
}

fn delegation() {
    let svc = krb5::random_key(18);
    let kt = keytab_of(svc);
    let cred = make_cred(svc, 18, 0, NOW - 600, NOW + 3000);
    let tgt_key = krb5::random_key(18);
    let tgt = make_cred(tgt_key, 18, krb5::flag(krb5::TKT_FORWARDED), NOW - 600, NOW + 3000);
    var kc: u8[>..] = [];
    tv::check_int("krb-cred", krb5::make_krb_cred(tgt, cred.key, kc), krb5::OK);
    var rc: krb5::ReplayEntry[>..] = [];
    var t1: u8[>..] = [];
    var ictx, err = krb5::gss_init(cred, krb5::GSS_MUTUAL | krb5::GSS_DELEG, "", false, kc, NOW, 0, t1);
    var t2: u8[>..] = [];
    var actx, acc, aerr = krb5::gss_accept(t1, kt, false, rc, NOW, 0, 300, "", false, t2);
    tv::check_int("deleg accept", aerr, krb5::OK);
    tv::check("deleg flag", acc.flags & krb5::GSS_DELEG != 0);
    var n = 0;
    for c in acc.delegated {
        n++;
        tv::check("delegated credential", c.client == "alice" && c.key.value == tgt.key.value && c.ticket == tgt.ticket);
    }
    tv::check_int("delegated count", n, 1);
}

fn main() {
    exchange("aes256 mutual", 18, true);
    exchange("aes128 mutual", 17, true);
    exchange("sha2-256 mutual", 20, true);
    exchange("sha2-128 mutual", 19, true);
    exchange("aes256 one-way", 18, false);
    exchange("rc4 mutual", 23, true);
    acceptor_checks();
    delegation();
    tv::done("gssapi");
}
