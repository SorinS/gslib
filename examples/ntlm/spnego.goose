// spnego: NTLM as SPNEGO's mechanism (krb5.spnego's spnego_ntlm_*), the
// way HTTP Negotiate and SASL GSS-SPNEGO carry it when there is no
// Kerberos: a NegTokenInit offering NTLM with the NEGOTIATE inside, the
// CHALLENGE back, the AUTHENTICATE with the initiator's mechListMIC, and
// the acceptor's verdict with its own mechListMIC. Both MICs are signed
// with the NTLM session's keys, which then seal messages. Each token is
// shown as the "Negotiate ..." header that would carry it.
//
//   goose examples/ntlm/spnego.goose

import std;
import gslib from "../..";
import gslib.ntlm;
import gslib.ntlm.messages;
import gslib.ntlm.session;
import gslib.ntlm.client;
import gslib.ntlm.server;
import gslib.ntlm.http;
import gslib.krb5;
import gslib.krb5.gssapi;
import gslib.krb5.messages;
import gslib.krb5.spnego;

let NOW: i64 = 1767225600;

fn lookup(user: const u8[:], domain: const u8[:], hash: u8[:]) -> bool {
    let h, ok = ntlm::nt_hash("an example password");
    for i in 16 { hash[i] = h[i]; }
    return user == "bob";
}

fn show(dir: const u8[:], tok: const u8[:]) {
    let h = ntlm::http_header(ntlm::SCHEME_NEGOTIATE, tok);
    print(dir, " ", h[..min(h.len, 48)], "... (", tok.len, " bytes)");
}

fn main() {
    let cred, ce = ntlm::credentials("bob", "EXAMPLE", "an example password");
    var cli = krb5::spnego_ntlm_initiator(cred, "HTTP/web.example.test", ntlm::WANT_SEAL);
    var srv = krb5::spnego_ntlm_acceptor(ntlm::acceptor("WEB", "EXAMPLE", "web.example.test", "example.test"));

    var tok: u8[>..] = [];
    var e = krb5::spnego_ntlm_init(cli, tok);
    var from_client = true;
    var rounds = 0;
    while e == ntlm::OK && tok.len > 0 && rounds < 6 {
        rounds++;
        show(if from_client { ">" } else { "<" }, tok);
        var reply: u8[>..] = [];
        if from_client {
            let done, ae = krb5::spnego_ntlm_accept(srv, tok, NOW, reply) { user, domain, hash => lookup(user, domain, hash) };
            e = ae;
        } else {
            let done, ie = krb5::spnego_ntlm_init_continue(cli, tok, NOW, reply);
            e = ie;
        }
        tok.clear();
        tok.append(reply);
        from_client = !from_client;
    }
    if e != ntlm::OK || !cli.complete || !srv.complete {
        print("spnego: ", ntlm::error_text(e));
        exit(1);
    }
    print("acceptor: ", srv.acc.domain, "\\", srv.acc.user, ", mechListMIC both ways: ", srv.mic_received && cli.mic_received);

    var w: u8[>..] = [];
    ntlm::wrap(krb5::spnego_ntlm_session(cli), "sealed after SPNEGO", w);
    var p: u8[>..] = [];
    e = ntlm::unwrap(krb5::spnego_ntlm_session(srv), w, p);
    print("acceptor unwrapped: ", p, " (", ntlm::error_text(e), ")");
    if e != ntlm::OK { exit(1); }
}
