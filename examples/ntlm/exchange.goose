// exchange: an NTLMv2 logon from end to end in one program, no network.
// A client with alice's password and a server that knows her NT hash
// trade the three NTLMSSP messages (NEGOTIATE, CHALLENGE, AUTHENTICATE)
// with channel bindings and a target name; the server checks the
// response, the MIC and the bindings, then both seal messages to each
// other. Then the same AUTHENTICATE is refused as a replay, a wrong
// password is refused, and an NTLMv1-sized response is refused outright.
//
//   goose examples/ntlm/exchange.goose

import std;
import gslib from "../..";
import gslib.ntlm;
import gslib.ntlm.crypto;
import gslib.ntlm.messages;
import gslib.ntlm.session;
import gslib.ntlm.client;
import gslib.ntlm.server;

// 2026-01-01T00:00:00Z: both clocks.
let NOW: i64 = 1767225600;
let SPN = "HTTP/web.example.test";
// What a TLS server's certificate gives (http.goose's tls_server_end_point).
let BINDINGS = "tls-server-end-point:0123456789abcdef0123456789abcdef";

fn die(what: const u8[:], e: i64) {
    print("exchange: ", what, ": ", ntlm::error_text(e));
    exit(1);
}

// The server's user database: NT hashes, never passwords.
fn lookup(user: const u8[:], domain: const u8[:], hash: u8[:]) -> bool {
    if !ntlm::eq_fold_ascii(user, "alice") || !ntlm::eq_fold_ascii(domain, "EXAMPLE") { return false; }
    let h, ok = ntlm::nt_hash("an example password");
    for i in 16 { hash[i] = h[i]; }
    return true;
}

fn new_server() -> ntlm::Acceptor {
    var srv = ntlm::acceptor("WEB", "EXAMPLE", "web.example.test", "example.test");
    ntlm::set_acceptor_bindings(srv, BINDINGS, ntlm::CB_REQUIRED);
    ntlm::set_acceptor_spn(srv, SPN, true);
    srv.require_mic = true;
    return srv;
}

fn main() {
    let cred, ce = ntlm::credentials("EXAMPLE\\alice", "", "an example password");
    if ce != ntlm::OK { die("credentials", ce); }
    var cli = ntlm::initiator(cred, SPN, ntlm::WANT_SEAL);
    ntlm::set_channel_bindings(cli, BINDINGS);
    var srv = new_server();

    var negotiate: u8[>..] = [];
    var e = ntlm::negotiate(cli, negotiate);
    if e != ntlm::OK { die("negotiate", e); }
    print("> NEGOTIATE ", negotiate.len, " bytes");
    var challenge: u8[>..] = [];
    e = ntlm::accept_negotiate(srv, negotiate, NOW, challenge);
    if e != ntlm::OK { die("accept_negotiate", e); }
    print("< CHALLENGE ", challenge.len, " bytes");
    var authenticate: u8[>..] = [];
    e = ntlm::authenticate(cli, challenge, NOW, authenticate);
    if e != ntlm::OK { die("authenticate", e); }
    print("> AUTHENTICATE ", authenticate.len, " bytes (NTLMv2, MIC, channel bindings, target name)");
    e = ntlm::accept_authenticate(srv, authenticate, NOW) { user, domain, hash => lookup(user, domain, hash) };
    if e != ntlm::OK { die("accept_authenticate", e); }
    print("server: ", srv.domain, "\\", srv.user, " logged on");

    // Sealed messages both ways.
    var w: u8[>..] = [];
    ntlm::wrap(cli.session, "GET /payroll", w);
    var p: u8[>..] = [];
    e = ntlm::unwrap(srv.session, w, p);
    if e != ntlm::OK { die("unwrap", e); }
    print("server unwrapped: ", p);
    var w2: u8[>..] = [];
    ntlm::wrap(srv.session, "200 OK", w2);
    var p2: u8[>..] = [];
    e = ntlm::unwrap(cli.session, w2, p2);
    if e != ntlm::OK { die("unwrap", e); }
    print("client unwrapped: ", p2);

    // The AUTHENTICATE again, to a new context: its server challenge is
    // another, so the proof does not hold.
    var srv2 = new_server();
    var c2: u8[>..] = [];
    ntlm::accept_negotiate(srv2, negotiate, NOW, c2);
    let replay = ntlm::accept_authenticate(srv2, authenticate, NOW) { user, domain, hash => lookup(user, domain, hash) };
    print("replayed AUTHENTICATE: ", ntlm::error_text(replay));

    // A wrong password.
    let bad, be = ntlm::credentials("alice", "EXAMPLE", "a guess");
    var cli3 = ntlm::initiator(bad, SPN, 0);
    ntlm::set_channel_bindings(cli3, BINDINGS);
    var srv3 = new_server();
    var n3: u8[>..] = [];
    ntlm::negotiate(cli3, n3);
    var ch3: u8[>..] = [];
    ntlm::accept_negotiate(srv3, n3, NOW, ch3);
    var a3: u8[>..] = [];
    ntlm::authenticate(cli3, ch3, NOW, a3);
    let wrong = ntlm::accept_authenticate(srv3, a3, NOW) { user, domain, hash => lookup(user, domain, hash) };
    print("wrong password: ", ntlm::error_text(wrong));

    // An NTLMv1 response (24 bytes): refused before any hash is looked up.
    var srv4 = new_server();
    var ch4: u8[>..] = [];
    ntlm::accept_negotiate(srv4, negotiate, NOW, ch4);
    var v1: u8[>..] = [];
    var name16: u8[>..] = [];
    ntlm::utf16le(name16, "alice");
    var z: u8[24] = [7; 24];
    ntlm::authenticate_message(v1, ntlm::NEGOTIATE_UNICODE | ntlm::NEGOTIATE_NTLM, z, z, "", name16, "", "", false);
    let v1e = ntlm::accept_authenticate(srv4, v1, NOW) { user, domain, hash => lookup(user, domain, hash) };
    print("NTLMv1 response: ", ntlm::error_text(v1e));
    if replay == ntlm::OK || wrong == ntlm::OK || v1e != ntlm::ERR_NTLMV1 { exit(1); }
}
