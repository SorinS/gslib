// The server's handle, fed requests as a NAS makes them: PAP, CHAP and
// MS-CHAPv2 right and wrong, accounting, Status-Server, whole EAP
// conversations (PEAP, TTLS, EAP-TLS) carried in Access-Challenges with
// their State and checked against the MS-MPPE keys; and what it drops: a
// wrong secret, no Message-Authenticator, an unknown State, CoA.
import std;
import gslib from "../..";
import gslib.radius;
import gslib.radius.mschap;
import gslib.radius.eap;
import gslib.radius.server;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn field(tag: const u8[:], kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("vectors/certs.txt"), '\n') {
        let w = words(line);
        if w.len < 2 || w[0] != tag { continue; }
        if tag == "root" || tag == "clientca" { return unhex(w[idx - 1]); }
        if w[1] == kind { return unhex(w[idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

let NOW: i64 = 1800000000;
let SECRET: const u8[:] = "testing123";

fn eap_cfg() -> radius::EapConfig {
    var t, ok = tls::server_config(field("server", "rsa", 2), field("server", "rsa", 3));
    assert(ok);
    t.now = NOW;
    t.client_auth = tls::VERIFY_CLIENT_CERT_IF_GIVEN;
    let ca = field("clientca", "", 2);
    assert(x509::pool_add(t.client_cas, ca));
    let methods: u8[3] = [radius::EAP_PEAP, radius::EAP_TTLS, radius::EAP_TLS];
    return radius::eap_config(methods, t);
}

// A request through handle: the answer checked as the client would.
fn ask(srv: radius::Server&, cfg: const radius::EapConfig&, req: radius::Packet&) -> radius::Packet, i64 {
    let wire = radius::sign_request(req, SECRET);
    var reply: u8[>..] = [];
    let got, e = radius::handle(srv, cfg, wire, reply) { user =>
        var pw: u8[>..] = [];
        if user == "alice" { pw.append("alice-pw"); }
        pw
    };
    if e != radius::OK { return got, e; }
    let resp, er = radius::check_response(reply, req, SECRET, radius::random_authenticator(req.code));
    return resp, er;
}

fn simple(srv: radius::Server&, cfg: const radius::EapConfig&) {
    let pws: const u8[:][2] = ["alice-pw", "wrong"];
    for pw in pws {
        let want = if pw == "alice-pw" { radius::ACCESS_ACCEPT } else { radius::ACCESS_REJECT };
        var p = radius::request(radius::ACCESS_REQUEST);
        radius::add(p, radius::USER_NAME, "alice");
        radius::add_password(p, pw, SECRET);
        let r1, e1 = ask(srv, cfg, p);
        check(str("PAP ", pw), e1 == radius::OK && r1.code == want);
        var c = radius::request(radius::ACCESS_REQUEST);
        radius::add(c, radius::USER_NAME, "alice");
        radius::add_chap(c, pw);
        let r2, e2 = ask(srv, cfg, c);
        check(str("CHAP ", pw), e2 == radius::OK && r2.code == want);
        var m = radius::request(radius::ACCESS_REQUEST);
        let ms, okm = radius::add_mschap2(m, "alice", pw);
        let r3, e3 = ask(srv, cfg, m);
        check(str("MS-CHAPv2 ", pw), e3 == radius::OK && r3.code == want);
        if want == radius::ACCESS_ACCEPT {
            check("MS-CHAP2-Success", radius::mschap2_success_ok(r3, ms, "alice"));
            let keys, okk = radius::mppe_keys(r3, SECRET, m.auth);
            check("MS-CHAPv2's MPPE keys", okk && keys.len == 32);
        }
    }
    var u = radius::request(radius::ACCESS_REQUEST);
    radius::add(u, radius::USER_NAME, "mallory");
    radius::add_password(u, "", SECRET);
    let r4, e4 = ask(srv, cfg, u);
    check("unknown user", e4 == radius::OK && r4.code == radius::ACCESS_REJECT);

    var a = radius::request(radius::ACCOUNTING_REQUEST);
    radius::add_u32(a, radius::ACCT_STATUS_TYPE, radius::ACCT_START);
    radius::add(a, radius::ACCT_SESSION_ID, "1");
    let r5, e5 = ask(srv, cfg, a);
    check("accounting", e5 == radius::OK && r5.code == radius::ACCOUNTING_RESPONSE);
    var st = radius::request(radius::STATUS_SERVER);
    let r6, e6 = ask(srv, cfg, st);
    check("Status-Server", e6 == radius::OK && r6.code == radius::ACCESS_ACCEPT);
}

fn dropped(srv: radius::Server&, cfg: const radius::EapConfig&) {
    var p = radius::request(radius::ACCESS_REQUEST);
    radius::add(p, radius::USER_NAME, "alice");
    radius::add_password(p, "alice-pw", "other-secret");
    let wire = radius::sign_request(p, "other-secret");
    var reply: u8[>..] = [];
    let g1, e1 = radius::handle(srv, cfg, wire, reply) { user => "alice-pw" };
    check("another secret: dropped", e1 == radius::ERR_MESSAGE_AUTH && reply.len == 0);
    // No Message-Authenticator.
    var q = radius::request(radius::ACCESS_REQUEST);
    radius::add(q, radius::USER_NAME, "alice");
    radius::add_password(q, "alice-pw", SECRET);
    let g2, e2 = radius::handle(srv, cfg, radius::encode(q), reply) { user => "alice-pw" };
    check("no Message-Authenticator: dropped", e2 == radius::ERR_MESSAGE_AUTH && reply.len == 0);
    // An EAP message that is not an Identity, without a State.
    var r = radius::request(radius::ACCESS_REQUEST);
    radius::set_eap(r, radius::eap_packet(radius::EAP_RESPONSE, 3, radius::EAP_PEAP, "\x00"));
    let g3, e3 = radius::handle(srv, cfg, radius::sign_request(r, SECRET), reply) { user => "alice-pw" };
    check("EAP without a conversation: dropped", e3 == radius::ERR_EAP && reply.len == 0);
    var coa = radius::request(radius::COA_REQUEST);
    radius::add(coa, radius::USER_NAME, "alice");
    let g4, e4 = radius::handle(srv, cfg, radius::sign_request(coa, SECRET), reply) { user => "alice-pw" };
    check("CoA: not for a server", e4 != radius::OK && reply.len == 0);
}

// A whole EAP conversation through handle, as radius::authenticate_eap
// runs it over the network.
fn eap(srv: radius::Server&, cfg: const radius::EapConfig&, pc: const radius::PeerConfig&) -> i64 {
    var p = radius::peer(pc);
    var eapm: u8[>..] = [];
    let start = radius::eap_packet(radius::EAP_REQUEST, 0, radius::EAP_IDENTITY, "");
    radius::peer_step(p, pc, start, eapm);
    var state: u8[>..] = [];
    for round in 100 {
        var req = radius::request(radius::ACCESS_REQUEST);
        radius::add(req, radius::USER_NAME, "anonymous");
        radius::set_eap(req, eapm);
        if state.len > 0 { radius::add(req, radius::STATE, state); }
        let resp, e = ask(srv, cfg, req);
        if e != radius::OK { return e; }
        let msg = radius::eap_message(resp);
        if resp.code == radius::ACCESS_CHALLENGE {
            let st, has = radius::get(resp, radius::STATE);
            state.clear();
            state.append(st);
            eapm.clear();
            if radius::peer_step(p, pc, msg, eapm) != radius::EAP_SEND { return radius::ERR_EAP; }
            continue;
        }
        var none: u8[>..] = [];
        let r = radius::peer_step(p, pc, msg, none);
        if resp.code != radius::ACCESS_ACCEPT { return radius::ERR_REJECTED; }
        if r != radius::EAP_DONE_OK { return radius::ERR_EAP; }
        let keys, okk = radius::mppe_keys(resp, SECRET, req.auth);
        if !okk || keys[..] != radius::peer_msk(p)[..] { return radius::ERR_EAP; }
        return radius::OK;
    }
    return radius::ERR_EAP;
}

fn peer_cfg(method: u8, inner: u8, pw: const u8[:], v: u16) -> radius::PeerConfig {
    var pc = radius::peer_config("alice", pw, method);
    pc.inner = inner;
    pc.tls = tls::client_config("example.com", field("root", "", 2));
    pc.tls.now = NOW;
    pc.tls.max_version = v;
    return pc;
}

fn eap_all(srv: radius::Server&, cfg: const radius::EapConfig&) {
    for v in [tls::VERSION_TLS13, tls::VERSION_TLS12] {
        let vn = if v == tls::VERSION_TLS13 { "TLS 1.3" } else { "TLS 1.2" };
        let peap = peer_cfg(radius::EAP_PEAP, 0, "alice-pw", v);
        let r_peap = eap(srv, cfg, peap);
        check(str("PEAP through handle, ", vn), r_peap == radius::OK);
        let ttls = peer_cfg(radius::EAP_TTLS, radius::INNER_MSCHAPV2, "alice-pw", v);
        let r_ttls = eap(srv, cfg, ttls);
        check(str("TTLS/MS-CHAPv2 through handle, ", vn), r_ttls == radius::OK);
        let pap = peer_cfg(radius::EAP_TTLS, radius::INNER_PAP, "alice-pw", v);
        let r_pap = eap(srv, cfg, pap);
        check(str("TTLS/PAP through handle, ", vn), r_pap == radius::OK);
        var tlsc = peer_cfg(radius::EAP_TLS, 0, "", v);
        tls::set_client_certificate(tlsc.tls, field("client", "p256", 2), field("client", "p256", 3));
        let r_tls = eap(srv, cfg, tlsc);
        check(str("EAP-TLS through handle, ", vn), r_tls == radius::OK);
        let bad = peer_cfg(radius::EAP_PEAP, 0, "wrong", v);
        let r_bad = eap(srv, cfg, bad);
        check(str("PEAP, wrong password, ", vn), r_bad == radius::ERR_REJECTED);
    }
    check("no conversations left over", radius::sessions(srv) == 0);
}

// CoA and Disconnect at a NAS: the request as the client makes it,
// checked and answered; an ACK, a NAK with its Error-Cause, a wrong secret.
fn dynamic() {
    for code in [radius::DISCONNECT_REQUEST, radius::COA_REQUEST] {
        for ack in [true, false] {
            var req = radius::request(code);
            radius::add(req, radius::USER_NAME, "alice");
            radius::add(req, radius::ACCT_SESSION_ID, "s-9");
            if code == radius::COA_REQUEST { radius::ensure_message_auth(req); }
            let wire = radius::sign_request(req, SECRET);
            var reply: u8[>..] = [];
            let got, e = radius::handle_dynamic(SECRET, wire, reply) { r, resp =>
                if !ack { radius::add_u32(resp, radius::ERROR_CAUSE, radius::CAUSE_SESSION_NOT_FOUND); }
                ack && radius::get_text(r, radius::ACCT_SESSION_ID) == "s-9"
            };
            let resp, er = radius::check_response(reply, req, SECRET, false);
            let want = if ack { code + 1 } else { code + 2 };
            check(str(radius::code_name(code), if ack { " ACK" } else { " NAK" }), e == radius::OK && er == radius::OK && resp.code == want);
            if !ack {
                let cause, okc = radius::get_u32(resp, radius::ERROR_CAUSE);
                check("Error-Cause", okc && cause == radius::CAUSE_SESSION_NOT_FOUND);
            }
            var reply2: u8[>..] = [];
            let g2, e2 = radius::handle_dynamic("other", wire, reply2) { r, resp => true };
            check(str(radius::code_name(code), " under another secret"), e2 != radius::OK && reply2.len == 0);
        }
    }
}

fn main() {
    dynamic();
    var srv = radius::server(SECRET);
    let cfg = eap_cfg();
    simple(srv, cfg);
    dropped(srv, cfg);
    eap_all(srv, cfg);
    print("server: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
