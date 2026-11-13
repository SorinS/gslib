// gss_context: a client and a service authenticating each other with
// Kerberos, in memory. The service has a keytab (made from its password);
// a ticket for it is made here with that key, as the KDC would make it.
// First the bare exchange: the client's AP-REQ checked by the service with
// its keytab, a replay of it refused, and the service's AP-REP checked by
// the client. Then GSS-API (RFC 4121): a context with mutual
// authentication, messages wrapped (sealed or only signed) and unwrapped
// both ways, a MIC, and a replayed or altered token refused.
//
//   goose examples/krb5/gss_context.goose
import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ccache;
import gslib.krb5.service;
import gslib.krb5.gssapi;

let NOW: i64 = 1800000000;
let SERVICE = "HTTP/web.example.com";

fn fail(what: const u8[:], err: i64) {
    print("gss_context: ", what, ": ", krb5::error_text(err));
    exit(1);
}

// What the KDC would give alice for the service: a ticket encrypted in the
// service's key (version kvno), and the session key inside it.
fn service_ticket(svc_key: krb5::Key, kvno: u32) -> krb5::Credential {
    let session = krb5::random_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96);
    let part = krb5::EncTicketPart {
        flags:          0, key: session, crealm: "EXAMPLE.COM", cname: krb5::principal_name(krb5::NT_PRINCIPAL, "alice"),
        tr_type:        1, transited: "", authtime: NOW - 60, has_starttime: true, starttime: NOW - 60, endtime: NOW + 36000,
        has_renew_till: false, renew_till: 0, has_caddr: false, caddr: [], has_authz: false, authz: [],
    };
    var plain: u8[>..] = [];
    krb5::encode_enc_ticket_part(plain, part);
    var c: u8[>..] = [];
    krb5::encrypt(svc_key, krb5::USAGE_KDC_REP_TICKET, plain, c);
    let t = krb5::Ticket { realm: "EXAMPLE.COM", sname: krb5::principal_name(krb5::NT_SRV_HST, SERVICE),
                           enc_part: krb5::EncryptedData { etype: svc_key.etype, has_kvno: true, kvno: kvno, cipher: copy(c) } };
    var der: u8[>..] = [];
    krb5::encode_ticket(der, t);
    return krb5::Credential {
        client_type: krb5::NT_PRINCIPAL, client: "alice", client_realm: "EXAMPLE.COM", server_type: krb5::NT_SRV_HST,
        server:      SERVICE, server_realm: "EXAMPLE.COM", key: session, authtime: NOW - 60, starttime: NOW - 60,
        endtime:     NOW + 36000, renew_till: 0, is_skey: false, flags: 0, addresses: [], authdata: [], ticket: der, second_ticket: "",
    };
}

fn main() {
    let etypes: i32[1] = [krb5::ETYPE_AES256_CTS_HMAC_SHA1_96];
    let kt, kerr = krb5::keytab_entries_from_password(krb5::NT_SRV_HST, SERVICE, "EXAMPLE.COM", "service password", 3, etypes, 0);
    if kerr != krb5::OK { fail("keytab", kerr); }
    let svc_key, kvno, ferr = krb5::keytab_key(kt, SERVICE, "EXAMPLE.COM", krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 0);
    let cred = service_ticket(svc_key, kvno);
    var rc: krb5::ReplayEntry[>..] = [];      // the service's replay cache

    // The bare AP exchange, as a protocol other than GSS-API would use it.
    var apreq: u8[>..] = [];
    let opts = krb5::flag(krb5::AP_OPT_MUTUAL_REQUIRED);
    let no_cksum = krb5::no_checksum();
    let me = krb5::make_ap_req(cred, opts, false, no_cksum, false, krb5::no_key(), false, 0, NOW, 500, apreq);
    if me != krb5::OK { fail("AP-REQ", me); }
    let ap, ve = krb5::verify_ap_req(apreq, kt, false, rc, NOW, 300, krb5::USAGE_AP_REQ_AUTHENTICATOR);
    if ve != krb5::OK { fail("verify AP-REQ", ve); }
    print("AP-REQ ", apreq.len, " bytes: ", krb5::principal_string(ap.client, ap.client_realm), " for ",
          krb5::principal_string(ap.server, ap.server_realm), ", ticket kvno ", ap.kvno, ", session key ",
          krb5::etype_name(ap.session_key.etype));
    let again, re = krb5::verify_ap_req(apreq, kt, false, rc, NOW + 1, 300, krb5::USAGE_AP_REQ_AUTHENTICATOR);
    guard re == krb5::KRB_AP_ERR_REPEAT else { fail("a replay was not refused", re); }
    print("the same AP-REQ again: ", krb5::error_text(re));
    var aprep: u8[>..] = [];
    let mr = krb5::make_ap_rep(ap, false, krb5::no_key(), false, 0, aprep);
    let part, pe = krb5::verify_ap_rep(aprep, cred.key, NOW, 500);
    guard mr == krb5::OK && pe == krb5::OK else { fail("AP-REP", pe); }
    print("AP-REP ", aprep.len, " bytes: the service proved it has the key");

    // GSS-API: the initiator's token, the acceptor's reply, and the
    // initiator's check of it (mutual authentication).
    var t1: u8[>..] = [];
    var ictx, ie = krb5::gss_init(cred, krb5::GSS_MUTUAL | krb5::GSS_SEQUENCE, "", false, "", NOW, 0, t1);
    if ie != krb5::OK { fail("gss_init", ie); }
    var t2: u8[>..] = [];
    var actx, acc, ae = krb5::gss_accept(t1, kt, false, rc, NOW, 0, 300, "", false, t2);
    if ae != krb5::OK { fail("gss_accept", ae); }
    let ce = krb5::gss_init_continue(ictx, t2);
    guard ce == krb5::OK && ictx.established && actx.established else { fail("gss_init_continue", ce); }
    print("GSS context: ", t1.len, "-byte token, ", t2.len, "-byte reply; the service sees ",
          krb5::principal_string(acc.ap.client, acc.ap.client_realm));

    // Messages both ways: sealed (encrypted and integrity-protected) or
    // only signed.
    for sealed in [true, false] {
        var w: u8[>..] = [];
        krb5::gss_wrap(ictx, "GET /orders HTTP/1.1", sealed, w);
        var u: u8[>..] = [];
        let was_sealed, ue = krb5::gss_unwrap(actx, w, u);
        guard ue == krb5::OK && was_sealed == sealed && u == "GET /orders HTTP/1.1" else { fail("unwrap", ue); }
        var w2: u8[>..] = [];
        krb5::gss_wrap(actx, "200 OK", sealed, w2);
        var u2: u8[>..] = [];
        let s2, ue2 = krb5::gss_unwrap(ictx, w2, u2);
        guard ue2 == krb5::OK && u2 == "200 OK" else { fail("unwrap reply", ue2); }
        print(if sealed { "sealed" } else { "signed" }, " Wrap tokens: ", w.len, " and ", w2.len, " bytes, unwrapped both ways");
    }

    // A MIC: a signature over data sent separately. Each token counts in
    // sequence, so a replay is refused; so is an altered message.
    var mic: u8[>..] = [];
    krb5::gss_get_mic(ictx, "audit record 1", mic);
    let v1 = krb5::gss_verify_mic(actx, "audit record 1", mic);
    let v2 = krb5::gss_verify_mic(actx, "audit record 1", mic);
    var mic2: u8[>..] = [];
    krb5::gss_get_mic(ictx, "audit record 2", mic2);
    let v3 = krb5::gss_verify_mic(actx, "audit record 3", mic2);
    guard v1 == krb5::OK && v2 == krb5::ERR_SEQUENCE && v3 == krb5::KRB_AP_ERR_MODIFIED else { fail("MIC", v1); }
    print("MIC ", mic.len, " bytes; replayed: ", krb5::error_text(v2), "; altered: ", krb5::error_text(v3));
}
