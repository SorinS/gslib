// radius.server: a RADIUS server's work on each request, as FreeRADIUS
// does it for the common cases: the request checked against the secret
// (a Message-Authenticator required with EAP, for Status-Server, and
// always when require_ma is set), then answered: PAP, CHAP and MS-CHAPv2
// against the password a block finds (MS-CHAP2-Success and the MPPE keys
// with an Access-Accept), EAP through radius.eap's server with each
// conversation kept by its State (the MSK as MS-MPPE keys in the
// Access-Accept), Accounting-Request with an Accounting-Response,
// Status-Server with an Access-Accept. The answer is signed with the
// Message-Authenticator first. Over UDP or RadSec alike: handle takes
// the request's bytes and gives the answer's.
//
//   var srv = radius::server("testing123");
//   let fd = net::listen_udp("127.0.0.1", 1812);
//   loop {
//       let n, from = net::recv_from(fd, buf, 0);
//       var reply: u8[>..] = [];
//       let req, e = radius::handle(srv, cfg, buf[..n], reply) { user => password_of(user) };
//       if reply.len > 0 { net::send_to(fd, reply, from); }
//   }

namespace radius;

import std;
import crypto.bignum;
import crypto.bignum.ct;
import entropy;
import crypto.tls;
import crypto.tls.handshake;

// One EAP conversation and the State that names it.
struct EapEntry { state: u8[16], started: i64, s: EapSession }

struct Server {
    secret: u8[..256],
    require_ma: bool,        // Message-Authenticator required in every Access-Request: true
    max_sessions: i64,       // EAP conversations kept at once (the oldest dropped): 64
    session_ttl: i64,        // seconds an EAP conversation may take: 60
    sessions: EapEntry[>..],
}

fn server(secret: const u8[:]) -> Server {
    var s = Server { secret: [], require_ma: true, max_sessions: 64, session_ttl: 60, sessions: [] };
    s.secret.append(secret[..::min(secret.len, 256)]);
    return s;
}

// How many EAP conversations are under way.
fn sessions(s: const Server&) -> i64 { s.sessions.len }

fn find_session(srv: const Server&, state: const u8[:]) -> i64 {
    if state.len != 16 { return -1; }
    for i in srv.sessions.len { if srv.sessions[i].state[..] == state { return i; } }
    return -1;
}

fn drop_session(srv: Server&, i: i64) { let gone = remove_at(srv.sessions, i); }

// Drops the conversations that took too long, and the oldest beyond
// max_sessions.
fn expire_sessions(srv: Server&, now: i64) {
    var i = 0;
    while i < srv.sessions.len {
        if now - srv.sessions[i].started > srv.session_ttl { let gone = remove_at(srv.sessions, i); } else { i++; }
    }
    while srv.sessions.len >= srv.max_sessions && srv.sessions.len > 0 { let gone = remove_at(srv.sessions, 0); }
}

// One request's bytes in, the answer's out (nothing for a request that
// does not check, which a server drops silently, RFC 2865 §3), and the
// request as it was parsed with the error that dropped it, if any. The
// block finds a user's password (empty for none):
//
//   radius::handle(srv, cfg, data, reply) { user => password_of(user) }
fn handle<F>(srv: Server&, cfg: const EapConfig&, data: const u8[:], reply: u8[>..]&) -> Packet, i64 {
    let req, e = check_request(data, srv.secret, srv.require_ma);
    if e != OK { return req, e; }
    var resp = response(req, ACCESS_REJECT);
    if req.code == STATUS_SERVER {
        resp.code = ACCESS_ACCEPT;
    } else if req.code == ACCOUNTING_REQUEST {
        resp.code = ACCOUNTING_RESPONSE;
    } else if req.code == ACCESS_REQUEST {
        if count(req, EAP_MESSAGE) > 0 {
            let r = handle_eap(srv, cfg, req, resp, F);
            if r != OK { return req, r; }
        } else {
            let user = get_text(req, USER_NAME);
            let pw = F(user);
            var ok = false;
            if pw.len > 0 && count(req, USER_PASSWORD) > 0 {
                let got, okp = password(req, srv.secret);
                ok = okp && got.len == pw.len && bignum::ct_eq_bytes(got, pw) == 1;
            } else if pw.len > 0 && count(req, CHAP_PASSWORD) > 0 {
                ok = chap_ok(req, pw);
            } else if pw.len > 0 {
                let h, okh = nt_password_hash(pw);
                if okh && check_mschap2(req, ms_user(user), h) {
                    ok = add_mschap2_success(resp, req, ms_user(user), h, srv.secret, true);
                }
            }
            if ok { resp.code = ACCESS_ACCEPT; }
        }
    } else {
        // CoA and Disconnect go to a NAS, not here.
        return req, ERR_MALFORMED;
    }
    reply.append(sign_response(resp, req, srv.secret));
    return req, OK;
}

// An Access-Request carrying EAP: the conversation its State names, or a
// new one for an EAP-Response/Identity; the answer an Access-Challenge
// with the next EAP request and a State, or the end.
fn handle_eap<F>(srv: Server&, cfg: const EapConfig&, req: const Packet&, resp: Packet&) -> i64 {
    let now = time_ns() / 1000000000;
    expire_sessions(srv, now);
    let msg = eap_message(req);
    let state, has = get(req, STATE);
    var i = if has { find_session(srv, state) } else { -1 };
    if i < 0 {
        // Only an Identity response starts one.
        let code, id, n, t, ok = eap_header(msg);
        if !ok || code != EAP_RESPONSE || t != EAP_IDENTITY { return ERR_EAP; }
        var e = EapEntry { state: [0; 16], started: now, s: eap_session(cfg) };
        entropy::random_bytes(e.state);
        srv.sessions.push(e);
        i = srv.sessions.len - 1;
    }
    var out: u8[>..] = [];
    let st = server_step(srv.sessions[i].s, cfg, msg, out, F);
    if !set_eap(resp, out) { drop_session(srv, i); return ERR_LIMIT; }
    if st == EAP_SEND {
        resp.code = ACCESS_CHALLENGE;
        let okst = add(resp, STATE, srv.sessions[i].state);
        return OK;
    }
    if st == EAP_DONE_OK {
        resp.code = ACCESS_ACCEPT;
        // The name the conversation authenticated, not the outer identity
        // a tunnel's peer gave unchecked (a NAS bills and authorizes by it).
        let who = authenticated_identity(srv.sessions[i].s);
        if who.len > 0 { let oku = add(resp, USER_NAME, who); }
        let msk = session_msk(srv.sessions[i].s);
        if msk.len > 0 && !add_mppe_keys(resp, msk, srv.secret, req.auth) {
            drop_session(srv, i);
            return ERR_LIMIT;
        }
    }
    drop_session(srv, i);
    return OK;
}

// A NAS's side of dynamic authorization (RFC 5176): a CoA-Request or
// Disconnect-Request checked against the secret (its Message-
// Authenticator too when there is one), and answered as the block
// decides: true for an ACK, false for a NAK (the block may put an
// Error-Cause in the answer):
//
//   radius::handle_dynamic(secret, data, reply) { req, resp => end_session(req) }
fn handle_dynamic<F>(secret: const u8[:], data: const u8[:], reply: u8[>..]&) -> Packet, i64 {
    let req, e = check_request(data, secret, false);
    if e != OK { return req, e; }
    if req.code != COA_REQUEST && req.code != DISCONNECT_REQUEST { return req, ERR_MALFORMED; }
    var resp = response(req, req.code + 1);
    if !F(req, &resp) { resp.code = req.code + 2; }
    reply.append(sign_response(resp, req, secret));
    return req, OK;
}
