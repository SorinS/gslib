// radius.client: a RADIUS client, as a NAS is one: over UDP with
// retransmission (RFC 2865, RFC 5080 §2.2.1: the same identifier and
// bytes each time), or over RadSec, RADIUS over TLS (RFC 6614, port 2083,
// the secret "radsec", a client certificate as the server asks); requests
// numbered and signed, answers checked (the Message-Authenticator required
// in every answer to an Access-Request, as BlastRADIUS asks, unless
// require_ma is cleared for an old server); and what a NAS asks: PAP,
// CHAP, MS-CHAPv2, a whole EAP conversation through radius.eap's peer
// (the State carried, the MS-MPPE keys checked against the peer's MSK),
// accounting, Status-Server, CoA and Disconnect.
//
//   var c, e = radius::dial("127.0.0.1", 1812, "testing123");
//   let resp, er = radius::authenticate_pap(c, "alice", "alice-pw");
//   if er == radius::OK { print(radius::get_text(resp, radius::REPLY_MESSAGE)); }

namespace radius;

import std;
import net;
import crypto.tls;
import crypto.tls.handshake;
import crypto.x509;
import entropy;

struct Client {
    fd: i64, radsec: bool,
    secret: u8[..256],
    timeout_ms: i32,       // per try (UDP), or for the whole answer (RadSec): 3000
    retries: i64,          // UDP: tries after the first: 2
    require_ma: bool,      // Message-Authenticator required in answers to Access-Request: true
    next_id: u8,
    rbuf: u8[..8192],      // RadSec: what came out of TLS and is not yet a packet
    conn: tls::Conn,
    cc: tls::ClientConfig,
}

fn new_client(fd: i64, secret: const u8[:], cc: const tls::ClientConfig&) -> Client {
    var idb: u8[1] = [0];
    entropy::random_bytes(idb);
    var c = Client {
        fd: fd, radsec: false, secret: [], timeout_ms: 3000, retries: 2, require_ma: true, next_id: idb[0],
        rbuf: [], conn: tls::client(cc), cc: copy(cc),
    };
    c.secret.append(secret[..::min(secret.len, 256)]);
    return c;
}

// A client for host:port over UDP with a shared secret: ERR_NETWORK if
// the host does not resolve.
fn dial(host: const u8[:], port: i64, secret: const u8[:]) -> Client, i64 {
    let fd = net::dial_udp(host, port);
    let cc = tls::client_config("", "");
    var c = new_client(fd, secret, cc);
    return c, if fd < 0 { ERR_NETWORK } else { OK };
}

// A client over RadSec: TCP to host:port, the TLS handshake done with cc
// (the server's name and CA, and a client certificate). ERR_NETWORK or
// ERR_TLS when it fails.
fn dial_radsec(host: const u8[:], port: i64, cc: const tls::ClientConfig&) -> Client, i64 {
    let fd = net::dial(host, port as! i32, 5000);
    var c = new_client(fd, "radsec", cc);
    c.radsec = true;
    if fd < 0 { return c, ERR_NETWORK; }
    var out: u8[>..] = [];
    tls::client_start(c.conn, c.cc, out);
    var buf: u8[16384] = [0; 16384];
    while !tls::connected(c.conn) {
        if out.len > 0 && net::write(fd, out, c.timeout_ms) < 0 { return c, ERR_NETWORK; }
        out.clear();
        let n = net::read(fd, buf, c.timeout_ms);
        if n <= 0 { return c, ERR_NETWORK; }
        var app: u8[>..] = [];
        if tls::feed(c.conn, c.cc, buf[..n], out, app) < 0 {
            let w = net::write(fd, out, c.timeout_ms);
            return c, ERR_TLS;
        }
        c.rbuf.append(app);
    }
    if out.len > 0 && net::write(fd, out, c.timeout_ms) < 0 { return c, ERR_NETWORK; }
    return c, OK;
}

fn close(c: Client&) {
    if c.radsec && tls::connected(c.conn) {
        var out: u8[>..] = [];
        tls::close(c.conn, out);
        let w = net::write(c.fd, out, 1000);
    }
    net::close(c.fd);
    c.fd = -1;
}

// RadSec: the next packet off the TLS stream.
fn radsec_read(c: Client&) -> u8[>..], i64 {
    var pkt: u8[>..] = [];
    var buf: u8[16384] = [0; 16384];
    loop {
        let need = packet_length(c.rbuf);
        if need < 0 { return pkt, ERR_MALFORMED; }
        if need > 0 && c.rbuf.len >= need {
            pkt.append(c.rbuf[..need]);
            var rest: u8[>..] = [];
            rest.append(c.rbuf[need..]);
            c.rbuf.clear();
            c.rbuf.append(rest);
            return pkt, OK;
        }
        let n = net::read(c.fd, buf, c.timeout_ms);
        if n == net::ERR_TIMEOUT { return pkt, ERR_TIMEOUT; }
        if n <= 0 { return pkt, ERR_NETWORK; }
        var out: u8[>..] = [];
        var app: u8[>..] = [];
        let fr = tls::feed(c.conn, c.cc, buf[..n], out, app);
        if out.len > 0 { let w = net::write(c.fd, out, c.timeout_ms); }
        if fr < 0 { return pkt, ERR_TLS; }
        if c.rbuf.len + app.len > c.rbuf.cap { return pkt, ERR_LIMIT; }
        c.rbuf.append(app);
    }
    return pkt, ERR_NETWORK;
}

// Sends a request and waits for its answer: the request gets the next
// identifier and is signed (it keeps them, and its authenticator, which
// hidden attributes in the answer are under); the answer is checked.
// Over UDP the same bytes go again after each timeout, retries times;
// answers to other requests, or that do not check, are dropped meanwhile.
fn exchange(c: Client&, req: Packet&) -> Packet, i64 {
    req.id = c.next_id;
    c.next_id = c.next_id + 1;
    let wire = sign_request(req, c.secret);
    let need_ma = c.require_ma && random_authenticator(req.code);
    if c.radsec {
        var rec: u8[>..] = [];
        if !tls::send(c.conn, wire, rec) || net::write(c.fd, rec, c.timeout_ms) < 0 {
            var none = Packet { code: 0, id: 0, auth: [0; 16], attrs: [] };
            return none, ERR_NETWORK;
        }
        loop {
            let data, e = radsec_read(c);
            if e != OK { var none = Packet { code: 0, id: 0, auth: [0; 16], attrs: [] }; return none, e; }
            let resp, er = check_response(data, req, c.secret, need_ma);
            if er != ERR_ID { return resp, er; }
        }
    }
    var buf: u8[4096] = [0; 4096];
    var last = ERR_TIMEOUT;
    for attempt in c.retries + 1 {
        if net::send(c.fd, wire) < 0 { last = ERR_NETWORK; continue; }
        let deadline = time_ns() / 1000000 + c.timeout_ms;
        loop {
            let left = deadline - time_ns() / 1000000;
            if left <= 0 { break; }
            let n = net::recv(c.fd, buf, left as! i32);
            if n == net::ERR_TIMEOUT { break; }
            if n < 0 { last = ERR_NETWORK; break; }
            let resp, er = check_response(buf[..n], req, c.secret, need_ma);
            if er == OK { return resp, OK; }
            // A stray or forged answer: keep waiting for the real one.
            last = er;
        }
    }
    var none = Packet { code: 0, id: 0, auth: [0; 16], attrs: [] };
    return none, if last == ERR_ID { ERR_TIMEOUT } else { last };
}

// The error of an answer to an Access-Request: OK for Access-Accept,
// ERR_REJECTED for Access-Reject, ERR_EAP for anything else.
fn access_result(resp: const Packet&, e: i64) -> i64 {
    if e != OK { return e; }
    if resp.code == ACCESS_ACCEPT { return OK; }
    if resp.code == ACCESS_REJECT { return ERR_REJECTED; }
    return ERR_EAP;
}

// Copies a template's attributes (NAS-IP-Address, NAS-Identifier, ...)
// into a request.
fn add_all(p: Packet&, base: const Packet&) -> bool {
    if p.attrs.len + base.attrs.len > p.attrs.cap { return false; }
    p.attrs.append(base.attrs);
    return true;
}

// PAP: User-Name and the hidden User-Password; the answer, OK when
// accepted. base's attributes go along.
fn authenticate_pap(c: Client&, user: const u8[:], pw: const u8[:], base: const Packet&) -> Packet, i64 {
    var req = request(ACCESS_REQUEST);
    if !add(req, USER_NAME, user) || !add_password(req, pw, c.secret) || !add_all(req, base) {
        return req, ERR_ARG;
    }
    let resp, e = exchange(c, req);
    return resp, access_result(resp, e);
}

fn authenticate_pap(c: Client&, user: const u8[:], pw: const u8[:]) -> Packet, i64 {
    let none = request(ACCOUNTING_REQUEST);
    let resp, e = authenticate_pap(c, user, pw, none);
    return resp, e;
}

// CHAP over the Request Authenticator.
fn authenticate_chap(c: Client&, user: const u8[:], pw: const u8[:]) -> Packet, i64 {
    var req = request(ACCESS_REQUEST);
    if !add(req, USER_NAME, user) || !add_chap(req, pw) { return req, ERR_ARG; }
    let resp, e = exchange(c, req);
    return resp, access_result(resp, e);
}

// MS-CHAPv2: accepted, and the server's MS-CHAP2-Success right (it knew
// the password); ERR_AUTHENTICATOR when it is not.
fn authenticate_mschapv2(c: Client&, user: const u8[:], pw: const u8[:]) -> Packet, i64 {
    var req = request(ACCESS_REQUEST);
    let m, ok = add_mschap2(req, user, pw);
    if !ok { return req, ERR_ARG; }
    let resp, e = exchange(c, req);
    let r = access_result(resp, e);
    if r == OK && !mschap2_success_ok(resp, m, user) { return resp, ERR_AUTHENTICATOR; }
    return resp, r;
}

// A whole EAP conversation with the peer p: its Identity first, then each
// Access-Challenge's EAP-Message to the peer and its answer back, with the
// State. OK when the server accepts and the peer takes the EAP-Success;
// for a method with keys, the MS-MPPE keys in the Access-Accept must be
// the peer's MSK (ERR_EAP otherwise). base's attributes go in every
// request.
fn authenticate_eap(c: Client&, p: Peer&, pc: const PeerConfig&, base: const Packet&) -> Packet, i64 {
    var eap: u8[>..] = [];
    let start = eap_packet(EAP_REQUEST, 0, EAP_IDENTITY, "");
    if peer_step(p, pc, start, eap) != EAP_SEND { return request(ACCESS_REQUEST), ERR_EAP; }
    let user = if pc.outer_identity.len > 0 && (pc.method == EAP_PEAP || pc.method == EAP_TTLS) {
        pc.outer_identity[..]
    } else { pc.identity[..] };
    var state: u8[>..] = [];
    for round in 100 {
        var req = request(ACCESS_REQUEST);
        if !add(req, USER_NAME, user) || !add_all(req, base) || !set_eap(req, eap) ||
           (state.len > 0 && !add(req, STATE, state)) {
            return req, ERR_LIMIT;
        }
        let resp, e = exchange(c, req);
        if e != OK { return resp, e; }
        let msg = eap_message(resp);
        if resp.code == ACCESS_CHALLENGE {
            let st, has = get(resp, STATE);
            state.clear();
            if has { state.append(st); }
            eap.clear();
            let r = peer_step(p, pc, msg, eap);
            if r != EAP_SEND { return resp, if p.error != OK { p.error } else { ERR_EAP }; }
            continue;
        }
        var none: u8[>..] = [];
        let r = if msg.len > 0 { peer_step(p, pc, msg, none) } else { EAP_DONE_FAIL };
        // The peer's own reason first: a server it did not trust is ERR_TLS.
        if resp.code == ACCESS_REJECT { return resp, if p.error != OK && p.error != ERR_REJECTED { p.error } else { ERR_REJECTED }; }
        if resp.code != ACCESS_ACCEPT || r != EAP_DONE_OK { return resp, ERR_EAP; }
        let msk = peer_msk(p);
        if msk.len > 0 {
            let keys, okk = mppe_keys(resp, c.secret, req.auth);
            if !okk || keys[..] != msk[..] { return resp, ERR_EAP; }
        }
        return resp, OK;
    }
    return request(ACCESS_REQUEST), ERR_EAP;
}

fn authenticate_eap(c: Client&, p: Peer&, pc: const PeerConfig&) -> Packet, i64 {
    let none = request(ACCOUNTING_REQUEST);
    let resp, e = authenticate_eap(c, p, pc, none);
    return resp, e;
}

// Accounting (RFC 2866): an Accounting-Request with Acct-Status-Type,
// Acct-Session-Id, User-Name and base's attributes; OK on an
// Accounting-Response.
fn account(c: Client&, status: u32, session_id: const u8[:], user: const u8[:], base: const Packet&) -> Packet, i64 {
    var req = request(ACCOUNTING_REQUEST);
    if !add_u32(req, ACCT_STATUS_TYPE, status) || !add(req, ACCT_SESSION_ID, session_id) ||
       (user.len > 0 && !add(req, USER_NAME, user)) || !add_all(req, base) {
        return req, ERR_ARG;
    }
    let resp, e = exchange(c, req);
    if e != OK { return resp, e; }
    return resp, if resp.code == ACCOUNTING_RESPONSE { OK } else { ERR_MALFORMED };
}

// Status-Server (RFC 5997): whether the server answers.
fn status(c: Client&) -> Packet, i64 {
    var req = request(STATUS_SERVER);
    let resp, e = exchange(c, req);
    if e != OK { return resp, e; }
    return resp, if resp.code == ACCESS_ACCEPT || resp.code == ACCOUNTING_RESPONSE { OK } else { ERR_MALFORMED };
}

// Dynamic authorization (RFC 5176), sent to a NAS (port 3799): a
// Disconnect-Request or a CoA-Request with the attributes that name the
// session (User-Name, Acct-Session-Id, ...) and, for CoA, what changes.
// OK on an ACK, ERR_REJECTED on a NAK (its Error-Cause says why).
fn disconnect(c: Client&, attrs: const Packet&) -> Packet, i64 {
    var req = request(DISCONNECT_REQUEST);
    if !add_all(req, attrs) { return req, ERR_LIMIT; }
    let resp, e = exchange(c, req);
    if e != OK { return resp, e; }
    if resp.code == DISCONNECT_ACK { return resp, OK; }
    return resp, if resp.code == DISCONNECT_NAK { ERR_REJECTED } else { ERR_MALFORMED };
}

fn change_of_authorization(c: Client&, attrs: const Packet&) -> Packet, i64 {
    var req = request(COA_REQUEST);
    if !add_all(req, attrs) || !ensure_message_auth(req) { return req, ERR_LIMIT; }
    let resp, e = exchange(c, req);
    if e != OK { return resp, e; }
    if resp.code == COA_ACK { return resp, OK; }
    return resp, if resp.code == COA_NAK { ERR_REJECTED } else { ERR_MALFORMED };
}
