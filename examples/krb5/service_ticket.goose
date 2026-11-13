// service_ticket: what a client does after kinit to call a Kerberos-
// protected web service. Gets a ticket for HTTP@web.example.com from the
// KDC with the TGT in the cache (across realms if it must; the ticket is
// added to the cache, and taken from it next time), and makes the
// "Authorization: Negotiate ..." header to send. Needs a KDC and a cache
// that kinit.goose (or MIT's kinit) filled.
//
//   goose examples/krb5/service_ticket.goose -- KRB5_CONF CCACHE HTTP@web.example.com
import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.config;
import gslib.krb5.ccache;
import gslib.krb5.client;
import gslib.krb5.gssapi;
import gslib.krb5.spnego;

fn fail(what: const u8[:], err: i64) {
    print("service_ticket: ", what, ": ", krb5::error_text(err));
    exit(1);
}

fn main() {
    let a = args();
    guard a.len == 4 else { print("usage: service_ticket KRB5_CONF CCACHE SERVICE@HOST"); exit(2); }
    let cfg, cerr = krb5::config_load(a[1]);
    if cerr != krb5::OK { fail(a[1], cerr); }

    // "HTTP@web.example.com" is GSS-API's form (gss_form true): the host's
    // realm comes from [domain_realm]. "HTTP/web.example.com@EXAMPLE.COM"
    // is Kerberos' own (gss_form false).
    let cred, err = krb5::get_service_ticket_cached(cfg, str("FILE:", a[2]), a[3], true);
    if err != krb5::OK { fail(a[3], err); }
    let t, terr = krb5::decode_ticket(cred.ticket);
    if terr != krb5::OK { fail("ticket", terr); }
    print("ticket for ", krb5::principal_string(cred.server, cred.server_realm), " to ",
          krb5::principal_string(cred.client, cred.client_realm), ": ", krb5::etype_name(t.enc_part.etype), " kvno ",
          t.enc_part.kvno, ", session key ", krb5::etype_name(cred.key.etype), ", valid until ", cred.endtime);

    // The SPNEGO token for HTTP, asking the server to prove itself
    // (its reply, in WWW-Authenticate, goes to spnego_init_continue).
    let now = time_ns() / 1000000000;
    var token: u8[>..] = [];
    var ctx, ierr = krb5::spnego_init(cred, krb5::GSS_MUTUAL, "", false, "", now, 0, token);
    if ierr != krb5::OK { fail("spnego_init", ierr); }
    print("Authorization: ", krb5::negotiate_header(token));
}
