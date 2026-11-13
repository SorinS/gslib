// http_negotiate: SPNEGO (RFC 4178) as HTTP Negotiate (RFC 4559) carries
// it, client and server in memory. The client puts its SPNEGO token in an
// "Authorization: Negotiate ..." header; the server reads the header,
// accepts the token with its keytab, and answers with a
// "WWW-Authenticate: Negotiate ..." header carrying its reply, which the
// client checks (mutual authentication). The ticket is made here with the
// service's key, as the KDC would make it; see service_ticket.goose for
// getting a real one.
//
//   goose examples/krb5/http_negotiate.goose
import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ccache;
import gslib.krb5.service;
import gslib.krb5.gssapi;
import gslib.krb5.spnego;

let NOW: i64 = 1800000000;
let SERVICE = "HTTP/web.example.com";

fn fail(what: const u8[:], err: i64) {
    print("http_negotiate: ", what, ": ", krb5::error_text(err));
    exit(1);
}

// What the KDC would give alice for the service (as in gss_context.goose).
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
    // The server's keytab, and the client's ticket for it.
    let etypes: i32[1] = [krb5::ETYPE_AES256_CTS_HMAC_SHA1_96];
    let kt, kerr = krb5::keytab_entries_from_password(krb5::NT_SRV_HST, SERVICE, "EXAMPLE.COM", "service password", 1, etypes, 0);
    if kerr != krb5::OK { fail("keytab", kerr); }
    let svc_key, kvno, ferr = krb5::keytab_key(kt, SERVICE, "EXAMPLE.COM", krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 0);
    let cred = service_ticket(svc_key, kvno);

    // Client: GET / with the Negotiate header.
    var token: u8[>..] = [];
    var client, ie = krb5::spnego_init(cred, krb5::GSS_MUTUAL, "", false, "", NOW, 0, token);
    if ie != krb5::OK { fail("spnego_init", ie); }
    let authorization = krb5::negotiate_header(token);
    print("> Authorization: ", authorization[..min(60, authorization.len)], "... (", authorization.len, " bytes)");

    // Server: the header's token, accepted with the keytab.
    let received, okh = krb5::negotiate_token(authorization);
    guard okh && received == token else { print("http_negotiate: not a Negotiate header"); exit(1); }
    var server = krb5::empty_spnego();
    var rc:    krb5::ReplayEntry[>..] = [];
    var reply: u8[>..]                = [];
    let done, acc, ae = krb5::spnego_accept(server, received, kt, false, rc, NOW, 0, 300, "", false, reply);
    guard ae == krb5::OK && done else { fail("spnego_accept", ae); }
    let user = krb5::principal_string(acc.ap.client, acc.ap.client_realm);
    let www = krb5::negotiate_header(reply);
    print("< 200 OK for ", user, "; WWW-Authenticate: ", www[..min(40, www.len)], "... (", www.len, " bytes)");

    // Client: the server's reply proves it is the service.
    let back, okb = krb5::negotiate_token(www);
    var more: u8[>..] = [];
    let cdone, ce = krb5::spnego_init_continue(client, back, more);
    guard okb && ce == krb5::OK && cdone && more.len == 0 else { fail("spnego_init_continue", ce); }
    print("client: the server is ", krb5::principal_string(acc.ap.server, acc.ap.server_realm), " (mutual authentication)");

    // The context can protect messages after the exchange.
    var w: u8[>..] = [];
    krb5::gss_wrap(server.gss, "session cookie", true, w);
    var u: u8[>..] = [];
    let sealed, ue = krb5::gss_unwrap(client.gss, w, u);
    guard ue == krb5::OK && u == "session cookie" else { fail("unwrap", ue); }

    // Headers that are not Negotiate, and a token from no ticket we know.
    let x, okx = krb5::negotiate_token("Basic YWxpY2U6c2VjcmV0");
    guard !okx else { print("http_negotiate: Basic taken for Negotiate"); exit(1); }
    let other_kt, oe = krb5::keytab_entries_from_password(krb5::NT_SRV_HST, SERVICE, "EXAMPLE.COM", "another password", 1, etypes, 0);
    var s2 = krb5::empty_spnego();
    var rc2: krb5::ReplayEntry[>..] = [];
    var r2:  u8[>..]                = [];
    let d2, a2, e2 = krb5::spnego_accept(s2, received, other_kt, false, rc2, NOW, 0, 300, "", false, r2);
    guard e2 != krb5::OK else { print("http_negotiate: a token for another key was accepted"); exit(1); }
    print("a server with another key: ", krb5::error_text(e2), " (a 401, with a ", r2.len, "-byte reply token)");
}
