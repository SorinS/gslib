// mail.sasl against the RFCs' examples: SCRAM-SHA-1 (RFC 5802 §5),
// SCRAM-SHA-256 (RFC 7677 §3), CRAM-MD5 (RFC 2195 §2), PLAIN (RFC 4616),
// and the server's mistakes a client must catch; NTLM against gslib's
// ntlm acceptor in memory.
import std;
import gslib from "../..";
import gslib.mail;
import gslib.mail.sasl;
import gslib.ntlm;
import gslib.ntlm.server;
import gslib.ntlm.http;
import gslib.encoding.asn1;

let ALICE_PEM = embed_file("smime/alice.pem");
let BOB_PEM = embed_file("smime/bob.pem");

var failures = 0;

fn check(what: const u8[:], ok: bool) {
    if !ok { print("FAIL ", what); failures++; }
}

// A whole SCRAM exchange: what the client sends first and second, and
// whether it accepts the server's final message.
fn scram(mech: i64, nonce: const u8[:], first: const u8[:], server_first: const u8[:], final: const u8[:],
         server_final: const u8[:]) {
    let name = mail::auth_name(mech);
    var s = mail::sasl_new(mech, "user", "pencil");
    mail::sasl_set_nonce(s, nonce);
    var out: u8[>..] = [];
    let has = mail::sasl_initial(s, out);
    check(str(name, " has an initial response"), has);
    check(str(name, " client-first"), out == first);
    let e1 = mail::sasl_step(s, server_first, out);
    check(str(name, " step 1"), e1 == mail::OK);
    check(str(name, " client-final"), out == final);
    check(str(name, " not done before the server's signature"), !mail::sasl_done(s));
    let e2 = mail::sasl_step(s, server_final, out);
    check(str(name, " step 2"), e2 == mail::OK);
    check(str(name, " done"), mail::sasl_done(s));
}

// AUTH NTLM: the NEGOTIATE as the initial response, the AUTHENTICATE for
// the CHALLENGE; a second challenge is refused.
fn ntlm_exchange(password: const u8[:]) -> bool {
    var s = mail::sasl_new(mail::AUTH_NTLM, "EXAMPLE\\carol", password);
    var t1: u8[>..] = [];
    if !mail::sasl_initial(s, t1) { return false; }
    var srv = ntlm::acceptor("MAIL", "EXAMPLE", "", "");
    var t2: u8[>..] = [];
    let now = time_ns() / 1000000000;
    if ntlm::accept_negotiate(srv, t1, now, t2) != ntlm::OK { return false; }
    var t3: u8[>..] = [];
    if mail::sasl_step(s, t2, t3) != mail::OK || !mail::sasl_done(s) { return false; }
    var again: u8[>..] = [];
    check("ntlm: one challenge only", mail::sasl_step(s, t2, again) == mail::ERR_AUTH);
    let e = ntlm::accept_authenticate(srv, t3, now) { user, domain, h =>
        let nt, ok = ntlm::nt_hash("pencil");
        for i in 16 { h[i] = nt[i]; }
        user == "carol" && domain == "EXAMPLE"
    };
    return e == ntlm::OK;
}

fn der_of(pem: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(pem, "CERTIFICATE");
    for d in ders { if out.len == 0 { out.append(d); } }
    return out;
}

// NTLM's target: the SPN service/host and the TLS server certificate's
// tls-server-end-point, checked by an acceptor that requires both.
fn ntlm_target(host: const u8[:], client_cert: const u8[:], server_cert: const u8[:]) -> bool {
    var s = mail::sasl_new(mail::AUTH_NTLM, "EXAMPLE\\carol", "pencil");
    mail::sasl_target(s, "SMTPSVC", host, client_cert);
    if s.bad { return false; }
    var t1: u8[>..] = [];
    if !mail::sasl_initial(s, t1) { return false; }
    var srv = ntlm::acceptor("MAIL", "EXAMPLE", "", "");
    if ntlm::set_acceptor_spn(srv, "SMTPSVC/mail.example.com", true) != ntlm::OK { return false; }
    let cb, okc = ntlm::tls_server_end_point(server_cert);
    if !okc { return false; }
    ntlm::set_acceptor_bindings(srv, cb, ntlm::CB_REQUIRED);
    var t2: u8[>..] = [];
    let now = time_ns() / 1000000000;
    if ntlm::accept_negotiate(srv, t1, now, t2) != ntlm::OK { return false; }
    var t3: u8[>..] = [];
    if mail::sasl_step(s, t2, t3) != mail::OK { return false; }
    let e = ntlm::accept_authenticate(srv, t3, now) { user, domain, h =>
        let nt, ok = ntlm::nt_hash("pencil");
        for i in 16 { h[i] = nt[i]; }
        user == "carol" && domain == "EXAMPLE"
    };
    return e == ntlm::OK;
}

fn main() {
    // Too long a user or secret: refused, never cut.
    var long_secret: u8[>..] = [];
    for i in 8193 { long_secret.push('p'); }
    check("fits: limits", mail::sasl_fits("u", "p") && !mail::sasl_fits("u", long_secret));
    var ls = mail::sasl_new(mail::AUTH_PLAIN, "user", long_secret);
    var lo: u8[>..] = [];
    check("fits: initial refused", !mail::sasl_initial(ls, lo) && lo.len == 0);
    check("fits: step refused", mail::sasl_step(ls, "", lo) == mail::ERR_AUTH && lo.len == 0);
    var long_user: u8[>..] = [];
    for i in 513 { long_user.push('u'); }
    var lu = mail::sasl_new(mail::AUTH_LOGIN, long_user, "p");
    check("fits: user refused", mail::sasl_step(lu, "Username:", lo) == mail::ERR_AUTH);
    // NTLM bound to the service and the TLS channel.
    let alice = der_of(ALICE_PEM);
    let bob = der_of(BOB_PEM);
    check("ntlm target: certs", alice.len > 0 && bob.len > 0);
    check("ntlm target: SPN and channel", ntlm_target("mail.example.com", alice, alice));
    check("ntlm target: another host", !ntlm_target("relay.example.net", alice, alice));
    check("ntlm target: another certificate", !ntlm_target("mail.example.com", bob, alice));
    check("ntlm target: no channel binding", !ntlm_target("mail.example.com", "", alice));
    check("ntlm: name", mail::auth_name(mail::AUTH_NTLM) == "NTLM" && !mail::auth_plaintext(mail::AUTH_NTLM));
    check("ntlm: not chosen unasked", mail::auth_choose("NTLM") == mail::AUTH_AUTO);
    check("ntlm: exchange", ntlm_exchange("pencil"));
    check("ntlm: wrong password", !ntlm_exchange("crayon"));
    var bad = mail::sasl_new(mail::AUTH_NTLM, "carol", "pencil");
    var o: u8[>..] = [];
    mail::sasl_initial(bad, o);
    check("ntlm: a challenge that is not one", mail::sasl_step(bad, "garbage", o) == mail::ERR_AUTH && o.len == 0);
    scram(mail::AUTH_SCRAM_SHA1, "fyko+d2lbbFgONRv9qkxdawL", "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
          "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
          "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
          "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");
    scram(mail::AUTH_SCRAM_SHA256, "rOprNGfwEbeRWgbNEkqO", "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
          "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
          "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
          "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");

    // SCRAM: a server nonce that does not extend ours, a wrong signature,
    // an error, a silly iteration count.
    var out: u8[>..] = [];
    var s = mail::sasl_new(mail::AUTH_SCRAM_SHA256, "user", "pencil");
    mail::sasl_set_nonce(s, "abc");
    mail::sasl_initial(s, out);
    check("scram: foreign nonce", mail::sasl_step(s, "r=xyzdef,s=QSXCR+Q6sek8bf92,i=4096", out) == mail::ERR_AUTH);
    s = mail::sasl_new(mail::AUTH_SCRAM_SHA256, "user", "pencil");
    mail::sasl_set_nonce(s, "abc");
    mail::sasl_initial(s, out);
    check("scram: zero iterations", mail::sasl_step(s, "r=abcdef,s=QSXCR+Q6sek8bf92,i=0", out) == mail::ERR_AUTH);
    s = mail::sasl_new(mail::AUTH_SCRAM_SHA256, "user", "pencil");
    mail::sasl_set_nonce(s, "abc");
    mail::sasl_initial(s, out);
    check("scram: e= in server-first", mail::sasl_step(s, "e=unknown-user", out) == mail::ERR_AUTH);
    s = mail::sasl_new(mail::AUTH_SCRAM_SHA256, "user", "pencil");
    mail::sasl_set_nonce(s, "abc");
    mail::sasl_initial(s, out);
    check("scram: step 1", mail::sasl_step(s, "r=abcdef,s=QSXCR+Q6sek8bf92,i=4096", out) == mail::OK);
    check("scram: wrong server signature", mail::sasl_step(s, "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", out) == mail::ERR_AUTH);
    check("scram: not done after a bad signature", !mail::sasl_done(s));

    // A user name with '=' and ',' in it is escaped.
    s = mail::sasl_new(mail::AUTH_SCRAM_SHA1, "a=b,c", "x");
    mail::sasl_set_nonce(s, "n0");
    mail::sasl_initial(s, out);
    check("scram: saslname escaping", out == "n,,n=a=3Db=2Cc,r=n0");

    // CRAM-MD5, RFC 2195's example.
    s = mail::sasl_new(mail::AUTH_CRAM_MD5, "tim", "tanstaaftanstaaf");
    check("cram-md5: no initial response", !mail::sasl_initial(s, out));
    check("cram-md5: step", mail::sasl_step(s, "<1896.697170952@postoffice.reston.mci.net>", out) == mail::OK);
    check("cram-md5: response", out == "tim b913a602c7eda7a495b4e6e7334d3890");

    // PLAIN: authzid empty, NULs between.
    s = mail::sasl_new(mail::AUTH_PLAIN, "tim", "tanstaaftanstaaf");
    check("plain: initial response", mail::sasl_initial(s, out));
    check("plain: bytes", out == "\x00tim\x00tanstaaftanstaaf");

    // LOGIN: user, then password, whatever the prompts say.
    s = mail::sasl_new(mail::AUTH_LOGIN, "tim", "secret");
    check("login: no initial response", !mail::sasl_initial(s, out));
    mail::sasl_step(s, "Benutzername:", out);
    check("login: user", out == "tim");
    mail::sasl_step(s, "Passwort:", out);
    check("login: password", out == "secret");
    check("login: a third prompt", mail::sasl_step(s, "?", out) == mail::ERR_AUTH);

    // XOAUTH2.
    s = mail::sasl_new(mail::AUTH_XOAUTH2, "someone@example.com", "ya29.token");
    mail::sasl_initial(s, out);
    check("xoauth2: initial response", out == "user=someone@example.com\x01auth=Bearer ya29.token\x01\x01");

    // Choosing from what the server offers.
    check("choose: scram-256 first", mail::auth_choose("PLAIN LOGIN SCRAM-SHA-1 SCRAM-SHA-256") == mail::AUTH_SCRAM_SHA256);
    check("choose: cram before plain", mail::auth_choose("login plain cram-md5") == mail::AUTH_CRAM_MD5);
    check("choose: plain", mail::auth_choose("XOAUTH2 PLAIN") == mail::AUTH_PLAIN);
    check("choose: nothing", mail::auth_choose("GSSAPI NTLM") == mail::AUTH_AUTO);
    check("offered: not a prefix", !mail::auth_offered("SCRAM-SHA-256-PLUS", mail::AUTH_SCRAM_SHA256));

    if failures > 0 { print(failures, " failures"); exit(1); }
    print("sasl: ok");
}
