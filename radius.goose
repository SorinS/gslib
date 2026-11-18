// radius: RADIUS for the Goose language, both sides, as FreeRADIUS and
// Go's layeh.com/radius speak it: packets and attributes (RFC 2865, 2866,
// 2869, 3162, 5176), vendor-specific attributes and Microsoft's (RFC
// 2548), the authenticators and Message-Authenticator (RFC 3579), always
// first in what it signs (the BlastRADIUS mitigation, CVE-2024-3596),
// User-Password hiding, CHAP, Tunnel-Password and MS-MPPE keys'
// salt-encryption, EAP-Message carried in pieces; a client over UDP with
// retransmission and over RadSec, RADIUS over TLS (RFC 6614); a server's
// pieces; EAP (RFC 3748) peer and server for MD5-Challenge, MS-CHAPv2,
// EAP-TLS (RFC 5216, and over TLS 1.3, RFC 9190), PEAPv0 and EAP-TTLS
// (RFC 5281) with PAP or MS-CHAPv2 inside, their keys (RFC 9427 for TLS
// 1.3); and MS-CHAPv2 itself (RFC 2759, 3079).
//
//   radius              this module: codes, attribute numbers, packets,
//                       their authenticators and hidden attributes
//   radius.mschap       MS-CHAPv2: the NT response, the authenticator
//                       response, MPPE keys; its RADIUS attributes
//   radius.eap          EAP packets and the methods, peer and server
//   radius.client       a client: UDP and RadSec, PAP, CHAP, MS-CHAPv2,
//                       EAP, accounting, Status-Server
//   radius.server       a server: requests checked, answers signed, EAP
//                       conversations kept by their State
//
// All are in the namespace radius. A packet holds its attributes in their
// wire form, in order; a value goes in and out as bytes, with helpers for
// the numbers, the addresses and the vendor-specific ones.
//
//   var req = radius::request(radius::ACCESS_REQUEST);
//   radius::add(req, radius::USER_NAME, "alice");
//   radius::add_password(req, "secret-pw", "testing123");
//   var c, e = radius::dial("radius.example.com", 1812, "testing123");
//   let resp, er = radius::exchange(c, req);      // ACCESS_ACCEPT, ...

namespace radius;

import std;
import crypto.bignum;
import crypto.bignum.md5;
import crypto.bignum.hmac;
import crypto.bignum.ct;
import entropy;

// --- Errors ---------------------------------------------------------------------

let OK:               i64 = 0;
let ERR_ARG:          i64 = 1;    // an argument that cannot be used (too long, empty)
let ERR_MALFORMED:    i64 = 2;    // not a RADIUS packet: lengths that do not add up
let ERR_AUTHENTICATOR: i64 = 3;   // the Request or Response Authenticator is wrong (or the secret)
let ERR_MESSAGE_AUTH: i64 = 4;    // Message-Authenticator wrong, or missing where it is needed
let ERR_ID:           i64 = 5;    // a response to another request
let ERR_TIMEOUT:      i64 = 6;    // no answer after the retries
let ERR_NETWORK:      i64 = 7;    // the socket or the TLS connection failed
let ERR_LIMIT:        i64 = 8;    // more than fits in a packet (4096 bytes)
let ERR_REJECTED:     i64 = 9;    // the server said no (Access-Reject, a NAK)
let ERR_EAP:          i64 = 10;   // the EAP conversation failed or broke its rules
let ERR_TLS:          i64 = 11;   // the TLS of RadSec or of an EAP method failed

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "bad argument"; }
    if e == ERR_MALFORMED { return "malformed packet"; }
    if e == ERR_AUTHENTICATOR { return "wrong authenticator (or shared secret)"; }
    if e == ERR_MESSAGE_AUTH { return "Message-Authenticator wrong or missing"; }
    if e == ERR_ID { return "response to another request"; }
    if e == ERR_TIMEOUT { return "no response"; }
    if e == ERR_NETWORK { return "network error"; }
    if e == ERR_LIMIT { return "too large"; }
    if e == ERR_REJECTED { return "rejected"; }
    if e == ERR_EAP { return "EAP failed"; }
    if e == ERR_TLS { return "TLS failed"; }
    return "unknown error";
}

// --- Codes (RFC 2865 §3, 2866, 5176, 5997, 7930) ----------------------------------

let ACCESS_REQUEST:      u8 = 1;
let ACCESS_ACCEPT:       u8 = 2;
let ACCESS_REJECT:       u8 = 3;
let ACCOUNTING_REQUEST:  u8 = 4;
let ACCOUNTING_RESPONSE: u8 = 5;
let ACCESS_CHALLENGE:    u8 = 11;
let STATUS_SERVER:       u8 = 12;
let STATUS_CLIENT:       u8 = 13;
let DISCONNECT_REQUEST:  u8 = 40;
let DISCONNECT_ACK:      u8 = 41;
let DISCONNECT_NAK:      u8 = 42;
let COA_REQUEST:         u8 = 43;
let COA_ACK:             u8 = 44;
let COA_NAK:             u8 = 45;
let PROTOCOL_ERROR:      u8 = 52;

fn code_name(c: u8) -> const u8[:] {
    if c == ACCESS_REQUEST { return "Access-Request"; }
    if c == ACCESS_ACCEPT { return "Access-Accept"; }
    if c == ACCESS_REJECT { return "Access-Reject"; }
    if c == ACCOUNTING_REQUEST { return "Accounting-Request"; }
    if c == ACCOUNTING_RESPONSE { return "Accounting-Response"; }
    if c == ACCESS_CHALLENGE { return "Access-Challenge"; }
    if c == STATUS_SERVER { return "Status-Server"; }
    if c == STATUS_CLIENT { return "Status-Client"; }
    if c == DISCONNECT_REQUEST { return "Disconnect-Request"; }
    if c == DISCONNECT_ACK { return "Disconnect-ACK"; }
    if c == DISCONNECT_NAK { return "Disconnect-NAK"; }
    if c == COA_REQUEST { return "CoA-Request"; }
    if c == COA_ACK { return "CoA-ACK"; }
    if c == COA_NAK { return "CoA-NAK"; }
    if c == PROTOCOL_ERROR { return "Protocol-Error"; }
    return "unknown";
}

// Whether a code is a request (its authenticator made by the sender alone).
fn is_request(c: u8) -> bool {
    c == ACCESS_REQUEST || c == ACCOUNTING_REQUEST || c == STATUS_SERVER || c == STATUS_CLIENT ||
        c == DISCONNECT_REQUEST || c == COA_REQUEST
}

// The requests whose authenticator is random (the others' is an MD5 over
// the packet and the secret).
fn random_authenticator(c: u8) -> bool { c == ACCESS_REQUEST || c == STATUS_SERVER }

// --- Attributes (RFC 2865 §5, 2866 §5, 2868, 2869, 3162, 5176, 6911) ----------------

let USER_NAME:              u8 = 1;
let USER_PASSWORD:          u8 = 2;
let CHAP_PASSWORD:          u8 = 3;
let NAS_IP_ADDRESS:         u8 = 4;
let NAS_PORT:               u8 = 5;
let SERVICE_TYPE:           u8 = 6;
let FRAMED_PROTOCOL:        u8 = 7;
let FRAMED_IP_ADDRESS:      u8 = 8;
let FRAMED_IP_NETMASK:      u8 = 9;
let FILTER_ID:              u8 = 11;
let FRAMED_MTU:             u8 = 12;
let REPLY_MESSAGE:          u8 = 18;
let STATE:                  u8 = 24;
let CLASS:                  u8 = 25;
let VENDOR_SPECIFIC:        u8 = 26;
let SESSION_TIMEOUT:        u8 = 27;
let IDLE_TIMEOUT:           u8 = 28;
let TERMINATION_ACTION:     u8 = 29;
let CALLED_STATION_ID:      u8 = 30;
let CALLING_STATION_ID:     u8 = 31;
let NAS_IDENTIFIER:         u8 = 32;
let PROXY_STATE:            u8 = 33;
let ACCT_STATUS_TYPE:       u8 = 40;
let ACCT_DELAY_TIME:        u8 = 41;
let ACCT_INPUT_OCTETS:      u8 = 42;
let ACCT_OUTPUT_OCTETS:     u8 = 43;
let ACCT_SESSION_ID:        u8 = 44;
let ACCT_AUTHENTIC:         u8 = 45;
let ACCT_SESSION_TIME:      u8 = 46;
let ACCT_INPUT_PACKETS:     u8 = 47;
let ACCT_OUTPUT_PACKETS:    u8 = 48;
let ACCT_TERMINATE_CAUSE:   u8 = 49;
let ACCT_MULTI_SESSION_ID:  u8 = 50;
let EVENT_TIMESTAMP:        u8 = 55;
let CHAP_CHALLENGE:         u8 = 60;
let NAS_PORT_TYPE:          u8 = 61;
let PORT_LIMIT:             u8 = 62;
let TUNNEL_TYPE:            u8 = 64;
let TUNNEL_MEDIUM_TYPE:     u8 = 65;
let TUNNEL_PASSWORD:        u8 = 69;
let CONNECT_INFO:           u8 = 77;
let EAP_MESSAGE:            u8 = 79;
let MESSAGE_AUTHENTICATOR:  u8 = 80;
let TUNNEL_PRIVATE_GROUP_ID: u8 = 81;
let ACCT_INTERIM_INTERVAL:  u8 = 85;
let NAS_PORT_ID:            u8 = 87;
let FRAMED_POOL:            u8 = 88;
let CHARGEABLE_USER_IDENTITY: u8 = 89;
let NAS_IPV6_ADDRESS:       u8 = 95;
let FRAMED_INTERFACE_ID:    u8 = 96;
let FRAMED_IPV6_PREFIX:     u8 = 97;
let ERROR_CAUSE:            u8 = 101;
let EAP_KEY_NAME:           u8 = 102;
let FRAMED_IPV6_ADDRESS:    u8 = 168;

// Service-Type values.
let SERVICE_LOGIN:          u32 = 1;
let SERVICE_FRAMED:         u32 = 2;
let SERVICE_AUTHORIZE_ONLY: u32 = 17;

// Acct-Status-Type values (RFC 2866 §5.1).
let ACCT_START:          u32 = 1;
let ACCT_STOP:           u32 = 2;
let ACCT_INTERIM_UPDATE: u32 = 3;
let ACCT_ON:             u32 = 7;
let ACCT_OFF:            u32 = 8;

// NAS-Port-Type values.
let PORT_VIRTUAL:     u32 = 5;
let PORT_ETHERNET:    u32 = 15;
let PORT_WIRELESS:    u32 = 19;

// Tunnel-Type and Tunnel-Medium-Type values (RFC 3580: a VLAN).
let TUNNEL_VLAN:      u32 = 13;
let MEDIUM_IEEE_802:  u32 = 6;

// Error-Cause values (RFC 5176 §3.5).
let CAUSE_UNSUPPORTED_ATTRIBUTE: u32 = 401;
let CAUSE_MISSING_ATTRIBUTE:     u32 = 402;
let CAUSE_SESSION_NOT_FOUND:     u32 = 503;
let CAUSE_ADMINISTRATIVELY_PROHIBITED: u32 = 501;

// Vendors, and Microsoft's attributes (RFC 2548).
let VENDOR_MICROSOFT:        u32 = 311;
let MS_CHAP_RESPONSE:        u8 = 1;
let MS_CHAP_ERROR:           u8 = 2;
let MS_MPPE_ENCRYPTION_POLICY: u8 = 7;
let MS_MPPE_ENCRYPTION_TYPES: u8 = 8;
let MS_CHAP_CHALLENGE:       u8 = 11;
let MS_MPPE_SEND_KEY:        u8 = 16;
let MS_MPPE_RECV_KEY:        u8 = 17;
let MS_CHAP2_RESPONSE:       u8 = 25;
let MS_CHAP2_SUCCESS:        u8 = 26;

// --- Packets ------------------------------------------------------------------------

let MAX_PACKET: i64 = 4096;       // RFC 2865 §3
let HEADER: i64 = 20;

// A packet: its code, identifier and authenticator, and its attributes in
// wire form (type, length, value), in order.
struct Packet {
    code: u8, id: u8, auth: u8[16],
    attrs: u8[..4076],
}

// A packet of `code`, identifier 0 (exchange numbers requests), no
// attributes. An Access-Request's and a Status-Server's authenticator is
// random, made here, since User-Password and CHAP depend on it.
fn request(code: u8) -> Packet {
    var p = Packet { code: code, id: 0, auth: [0; 16], attrs: [] };
    if random_authenticator(code) { entropy::random_bytes(p.auth); }
    return p;
}

// The answer to req with `code`: its identifier, and the Proxy-State
// attributes copied in order (RFC 2865 §5.33).
fn response(req: const Packet&, code: u8) -> Packet {
    var p = Packet { code: code, id: req.id, auth: req.auth, attrs: [] };
    var i = 0;
    while i + 2 <= req.attrs.len {
        let l = req.attrs[i + 1] as i64;
        if req.attrs[i] == PROXY_STATE { p.attrs.append(req.attrs[i..i + l]); }
        i += l;
    }
    return p;
}

// Appends an attribute; false when the value is empty or longer than 253
// bytes, or the packet is full.
fn add(p: Packet&, t: u8, v: const u8[:]) -> bool {
    if v.len == 0 || v.len > 253 || p.attrs.len + 2 + v.len > p.attrs.cap { return false; }
    p.attrs.push(t);
    p.attrs.push((v.len + 2) as! u8);
    p.attrs.append(v);
    return true;
}

fn be32(v: u32) -> u8[4] { [(v >> 24) as! u8, (v >> 16) as! u8, (v >> 8) as! u8, v as! u8] }

fn add_u32(p: Packet&, t: u8, v: u32) -> bool { add(p, t, be32(v)) }

// An IPv4 address attribute from its four bytes.
fn add_ipv4(p: Packet&, t: u8, a: const u8[:]) -> bool { a.len == 4 && add(p, t, a) }

// A vendor-specific attribute (RFC 2865 §5.26): the vendor's number, then
// its own type, length and value.
fn add_vsa(p: Packet&, vendor: u32, vt: u8, v: const u8[:]) -> bool {
    if v.len == 0 || v.len > 247 { return false; }
    var b: u8[>..] = [];
    b.append(be32(vendor));
    b.push(vt);
    b.push((v.len + 2) as! u8);
    b.append(v);
    return add(p, VENDOR_SPECIFIC, b);
}

// Removes every attribute of type t.
fn remove(p: Packet&, t: u8) {
    var out: u8[>..] = [];
    var i = 0;
    while i + 2 <= p.attrs.len {
        let l = p.attrs[i + 1] as i64;
        if p.attrs[i] != t { out.append(p.attrs[i..i + l]); }
        i += l;
    }
    p.attrs.clear();
    p.attrs.append(out);
}

// How many attributes of type t.
fn count(p: const Packet&, t: u8) -> i64 {
    var n = 0;
    var i = 0;
    while i + 2 <= p.attrs.len {
        if p.attrs[i] == t { n++; }
        i += p.attrs[i + 1];
    }
    return n;
}

// The first attribute of type t, and true; false if there is none.
fn get(p: const Packet&, t: u8) -> u8[>..], bool {
    var out: u8[>..] = [];
    var i = 0;
    while i + 2 <= p.attrs.len {
        let l = p.attrs[i + 1] as i64;
        if p.attrs[i] == t { out.append(p.attrs[i + 2..i + l]); return out, true; }
        i += l;
    }
    return out, false;
}

// The values of every attribute of type t, joined in order (EAP-Message
// is one message in pieces); empty for none.
fn get_all(p: const Packet&, t: u8) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 2 <= p.attrs.len {
        let l = p.attrs[i + 1] as i64;
        if p.attrs[i] == t { out.append(p.attrs[i + 2..i + l]); }
        i += l;
    }
    return out;
}

fn get_u32(p: const Packet&, t: u8) -> u32, bool {
    let v, ok = get(p, t);
    if !ok || v.len != 4 { return 0, false; }
    return (v[0] as u32) << 24 | (v[1] as u32) << 16 | (v[2] as u32) << 8 | v[3], true;
}

// A text attribute (User-Name, Reply-Message, ...), empty for none.
fn get_text(p: const Packet&, t: u8) -> u8[>..] {
    let v, ok = get(p, t);
    return v;
}

// The first vendor-specific attribute of the vendor's type vt.
fn vsa(p: const Packet&, vendor: u32, vt: u8) -> u8[>..], bool {
    var out: u8[>..] = [];
    var i = 0;
    while i + 2 <= p.attrs.len {
        let l = p.attrs[i + 1] as i64;
        if p.attrs[i] == VENDOR_SPECIFIC && l >= 8 {
            let v = p.attrs[i + 2..i + l];
            let ven = (v[0] as u32) << 24 | (v[1] as u32) << 16 | (v[2] as u32) << 8 | v[3];
            // One sub-attribute or several, each type, length, value.
            var j = 4;
            while ven == vendor && j + 2 <= v.len {
                let sl = v[j + 1] as i64;
                if sl < 2 || j + sl > v.len { break; }
                if v[j] == vt { out.append(v[j + 2..j + sl]); return out, true; }
                j += sl;
            }
        }
        i += l;
    }
    return out, false;
}

// The n-th attribute (from 0): its type and value; false past the last.
fn attr_at(p: const Packet&, n: i64) -> u8, u8[>..], bool {
    var out: u8[>..] = [];
    var i = 0;
    var k = 0;
    while i + 2 <= p.attrs.len {
        let l = p.attrs[i + 1] as i64;
        if k == n { out.append(p.attrs[i + 2..i + l]); return p.attrs[i], out, true; }
        k++;
        i += l;
    }
    return 0, out, false;
}

fn attr_count(p: const Packet&) -> i64 {
    var n = 0;
    var i = 0;
    while i + 2 <= p.attrs.len { n++; i += p.attrs[i + 1]; }
    return n;
}

// An EAP message as EAP-Message attributes of at most 253 bytes each
// (RFC 3579 §3.1), the old ones replaced; false if it does not fit.
fn set_eap(p: Packet&, msg: const u8[:]) -> bool {
    remove(p, EAP_MESSAGE);
    var i = 0;
    while i < msg.len {
        let n = ::min(253, msg.len - i);
        if !add(p, EAP_MESSAGE, msg[i..i + n]) { return false; }
        i += n;
    }
    return msg.len > 0;
}

fn eap_message(p: const Packet&) -> u8[>..] { get_all(p, EAP_MESSAGE) }

// The packet's wire form, its authenticator as it is.
fn encode(p: const Packet&) -> u8[>..] {
    var out: u8[>..] = [];
    let n = HEADER + p.attrs.len;
    out.push(p.code);
    out.push(p.id);
    out.push((n >> 8) as! u8);
    out.push(n as! u8);
    out.append(p.auth);
    out.append(p.attrs);
    return out;
}

// A packet from its wire form: the length field within the datagram (the
// bytes past it are padding and dropped, RFC 2865 §3), attributes that
// fill it exactly, none shorter than 2 bytes. Nothing about the secret is
// checked: check_request and check_response do that.
fn parse(data: const u8[:]) -> Packet, i64 {
    var p = Packet { code: 0, id: 0, auth: [0; 16], attrs: [] };
    if data.len < HEADER { return p, ERR_MALFORMED; }
    let n = (data[2] as i64) << 8 | data[3];
    if n < HEADER || n > data.len || n > MAX_PACKET { return p, ERR_MALFORMED; }
    var i = HEADER;
    while i < n {
        if i + 2 > n { return p, ERR_MALFORMED; }
        let l = data[i + 1] as i64;
        if l < 2 || i + l > n { return p, ERR_MALFORMED; }
        i += l;
    }
    p.code = data[0];
    p.id = data[1];
    for k in 16 { p.auth[k] = data[4 + k]; }
    p.attrs.append(data[HEADER..n]);
    return p, OK;
}

// The length a stream (RadSec) must have read for the packet that starts
// it: 0 until its header has come, else its length (-1 if impossible).
fn packet_length(head: const u8[:]) -> i64 {
    if head.len < 4 { return 0; }
    let n = (head[2] as i64) << 8 | head[3];
    return if n < HEADER || n > MAX_PACKET { -1 } else { n };
}

// --- Authenticators -------------------------------------------------------------------

fn md5_of(a: const u8[:], b: const u8[:]) -> u8[16] {
    var s = bignum::md5_init();
    bignum::md5_update(s, a);
    bignum::md5_update(s, b);
    return bignum::md5_final(s);
}

// Where the Message-Authenticator's value is in the attributes (-1: none).
fn message_auth_pos(p: const Packet&) -> i64 {
    var i = 0;
    while i + 2 <= p.attrs.len {
        let l = p.attrs[i + 1] as i64;
        if p.attrs[i] == MESSAGE_AUTHENTICATOR && l == 18 { return i + 2; }
        i += l;
    }
    return -1;
}

// Puts a zero Message-Authenticator first, unless there is one already
// (where it is is then left as it is).
fn ensure_message_auth(p: Packet&) -> bool {
    if message_auth_pos(p) >= 0 { return true; }
    if p.attrs.len + 18 > p.attrs.cap { return false; }
    var rest: u8[>..] = [];
    rest.append(p.attrs);
    p.attrs.clear();
    p.attrs.push(MESSAGE_AUTHENTICATOR);
    p.attrs.push(18);
    for i in 16 { p.attrs.push(0); }
    p.attrs.append(rest);
    return true;
}

// HMAC-MD5 over the packet with `auth` in the authenticator's place and
// the Message-Authenticator's value zero (RFC 3579 §3.2).
fn message_auth(p: const Packet&, auth: const u8[:], secret: const u8[:]) -> u8[16] {
    var q = Packet { code: p.code, id: p.id, auth: [0; 16], attrs: [] };
    for i in 16 { q.auth[i] = auth[i]; }
    q.attrs.append(p.attrs);
    let pos = message_auth_pos(q);
    if pos >= 0 { for i in 16 { q.attrs[pos + i] = 0; } }
    let h = bignum::hmac(128, secret, encode(q));
    var out: u8[16] = [0; 16];
    for i in 16 { out[i] = h[i]; }
    return out;
}

fn set_message_auth(p: Packet&, auth: const u8[:], secret: const u8[:]) {
    let pos = message_auth_pos(p);
    if pos < 0 { return; }
    let m = message_auth(p, auth, secret);
    for i in 16 { p.attrs[pos + i] = m[i]; }
}

fn message_auth_ok(p: const Packet&, auth: const u8[:], secret: const u8[:]) -> bool {
    let pos = message_auth_pos(p);
    if pos < 0 { return false; }
    let m = message_auth(p, auth, secret);
    return bignum::ct_eq_bytes(m, p.attrs[pos..pos + 16]) == 1;
}

// MD5(code, id, length, auth, attributes, secret): the Response
// Authenticator over the request's, or an Accounting-, CoA- or
// Disconnect-Request's over zeros.
fn packet_md5(p: const Packet&, auth: const u8[:], secret: const u8[:]) -> u8[16] {
    var q = Packet { code: p.code, id: p.id, auth: [0; 16], attrs: [] };
    for i in 16 { q.auth[i] = auth[i]; }
    q.attrs.append(p.attrs);
    return md5_of(encode(q), secret);
}

// A request ready to send: an Access-Request and a Status-Server get a
// Message-Authenticator first (always, as BlastRADIUS asks); the others'
// authenticator is the MD5 over the packet (with a Message-Authenticator,
// if one was added, made over a zero authenticator first, RFC 5176 §3.3).
fn sign_request(p: Packet&, secret: const u8[:]) -> u8[>..] {
    let zero: u8[16] = [0; 16];
    if random_authenticator(p.code) {
        let okm = ensure_message_auth(p);
        set_message_auth(p, p.auth, secret);
    } else {
        set_message_auth(p, zero, secret);
        p.auth = packet_md5(p, zero, secret);
    }
    return encode(p);
}

// A response ready to send: a Message-Authenticator first (over the
// request's authenticator) for every answer to an Access-Request or a
// Status-Server, then the Response Authenticator over the finished packet.
fn sign_response(p: Packet&, req: const Packet&, secret: const u8[:]) -> u8[>..] {
    if random_authenticator(req.code) || p.code == ACCESS_CHALLENGE {
        let okm = ensure_message_auth(p);
    }
    set_message_auth(p, req.auth, secret);
    p.auth = packet_md5(p, req.auth, secret);
    return encode(p);
}

// A response checked against the request it answers: the identifier, the
// Response Authenticator, the Message-Authenticator when there is one,
// and that there is one when it carries EAP or require_ma is set (an
// Access-Request's answers, as BlastRADIUS asks).
fn check_response(data: const u8[:], req: const Packet&, secret: const u8[:], require_ma: bool) -> Packet, i64 {
    var p, e = parse(data);
    if e != OK { return p, e; }
    if p.id != req.id { return p, ERR_ID; }
    let want = packet_md5(p, req.auth, secret);
    if bignum::ct_eq_bytes(want, p.auth) != 1 { return p, ERR_AUTHENTICATOR; }
    let has = message_auth_pos(p) >= 0;
    if !has && (require_ma || count(p, EAP_MESSAGE) > 0) { return p, ERR_MESSAGE_AUTH; }
    if has && !message_auth_ok(p, req.auth, secret) { return p, ERR_MESSAGE_AUTH; }
    return p, OK;
}

// A request checked as a server gets it: an Access-Request's and a
// Status-Server's Message-Authenticator (needed with EAP, for a
// Status-Server, and with require_ma), the others' authenticator.
fn check_request(data: const u8[:], secret: const u8[:], require_ma: bool) -> Packet, i64 {
    var p, e = parse(data);
    if e != OK { return p, e; }
    if !is_request(p.code) { return p, ERR_MALFORMED; }
    let has = message_auth_pos(p) >= 0;
    let zero: u8[16] = [0; 16];
    if random_authenticator(p.code) {
        let need = require_ma || p.code == STATUS_SERVER || count(p, EAP_MESSAGE) > 0;
        if !has && need { return p, ERR_MESSAGE_AUTH; }
        if has && !message_auth_ok(p, p.auth, secret) { return p, ERR_MESSAGE_AUTH; }
    } else {
        let want = packet_md5(p, zero, secret);
        if bignum::ct_eq_bytes(want, p.auth) != 1 { return p, ERR_AUTHENTICATOR; }
        if has && !message_auth_ok(p, zero, secret) { return p, ERR_MESSAGE_AUTH; }
    }
    return p, OK;
}

// --- Hidden attributes ------------------------------------------------------------------

// User-Password hidden (RFC 2865 §5.2): padded with zeros to a multiple
// of 16, each block XORed with MD5(secret + the previous one), the first's
// the Request Authenticator. At most 128 bytes.
fn hide_password(pw: const u8[:], secret: const u8[:], auth: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if pw.len > 128 { return out, false; }
    var padded: u8[>..] = [];
    padded.append(pw);
    while padded.len == 0 || padded.len % 16 != 0 { padded.push(0); }
    var prev: u8[>..] = [];
    prev.append(auth);
    var i = 0;
    while i < padded.len {
        let b = md5_of(secret, prev);
        prev.clear();
        for k in 16 { prev.push(padded[i + k] ^ b[k]); }
        out.append(prev);
        i += 16;
    }
    return out, true;
}

// The password back, its padding zeros dropped.
fn unhide_password(v: const u8[:], secret: const u8[:], auth: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if v.len == 0 || v.len % 16 != 0 || v.len > 128 { return out, false; }
    var prev: u8[>..] = [];
    prev.append(auth);
    var i = 0;
    while i < v.len {
        let b = md5_of(secret, prev);
        for k in 16 { out.push(v[i + k] ^ b[k]); }
        prev.clear();
        prev.append(v[i..i + 16]);
        i += 16;
    }
    while out.len > 0 && out[out.len - 1] == 0 { out.pop(); }
    return out, true;
}

// User-Password, hidden with the packet's authenticator.
fn add_password(p: Packet&, pw: const u8[:], secret: const u8[:]) -> bool {
    let v, ok = hide_password(pw, secret, p.auth);
    return ok && add(p, USER_PASSWORD, v);
}

fn password(p: const Packet&, secret: const u8[:]) -> u8[>..], bool {
    let v, ok = get(p, USER_PASSWORD);
    if !ok { var none: u8[>..] = []; return none, false; }
    return unhide_password(v, secret, p.auth);
}

// CHAP (RFC 2865 §5.3): CHAP-Password is an identifier and MD5(identifier
// + password + challenge); the challenge is the Request Authenticator,
// as RFC 2865 lets it be, unless the packet has a CHAP-Challenge.
fn add_chap(p: Packet&, pw: const u8[:]) -> bool {
    var idb: u8[1] = [0];
    entropy::random_bytes(idb);
    var m = bignum::md5_init();
    bignum::md5_update(m, idb);
    bignum::md5_update(m, pw);
    let ch, has = get(p, CHAP_CHALLENGE);
    if has { bignum::md5_update(m, ch); } else { bignum::md5_update(m, p.auth); }
    let h = bignum::md5_final(m);
    var v: u8[>..] = [];
    v.push(idb[0]);
    v.append(h);
    return add(p, CHAP_PASSWORD, v);
}

// Whether a request's CHAP-Password is the password's.
fn chap_ok(p: const Packet&, pw: const u8[:]) -> bool {
    let v, ok = get(p, CHAP_PASSWORD);
    if !ok || v.len != 17 { return false; }
    var m = bignum::md5_init();
    bignum::md5_update(m, v[..1]);
    bignum::md5_update(m, pw);
    let ch, has = get(p, CHAP_CHALLENGE);
    if has { bignum::md5_update(m, ch); } else { bignum::md5_update(m, p.auth); }
    let h = bignum::md5_final(m);
    return bignum::ct_eq_bytes(h, v[1..]) == 1;
}

// Salt-encryption (RFC 2868 §3.5, RFC 2548 §2.4.2): a two-byte salt, its
// high bit set, then the length byte and the value padded to 16-byte
// blocks, each XORed with MD5(secret + previous), the first's MD5(secret
// + Request Authenticator + salt). For Tunnel-Password (after its tag)
// and MS-MPPE-Send-Key and -Recv-Key in an answer to req.
fn salt_encrypt(value: const u8[:], secret: const u8[:], req_auth: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if value.len > 239 { return out, false; }
    var salt: u8[2] = [0; 2];
    entropy::random_bytes(salt);
    salt[0] |= 0x80;
    var plain: u8[>..] = [];
    plain.push(value.len as! u8);
    plain.append(value);
    while plain.len % 16 != 0 { plain.push(0); }
    out.append(salt);
    var prev: u8[>..] = [];
    prev.append(req_auth);
    prev.append(salt);
    var i = 0;
    while i < plain.len {
        let b = md5_of(secret, prev);
        prev.clear();
        for k in 16 { prev.push(plain[i + k] ^ b[k]); }
        out.append(prev);
        i += 16;
    }
    return out, true;
}

fn salt_decrypt(v: const u8[:], secret: const u8[:], req_auth: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if v.len < 18 || (v.len - 2) % 16 != 0 || v[0] & 0x80 == 0 { return out, false; }
    var plain: u8[>..] = [];
    var prev: u8[>..] = [];
    prev.append(req_auth);
    prev.append(v[..2]);
    var i = 2;
    while i < v.len {
        let b = md5_of(secret, prev);
        for k in 16 { plain.push(v[i + k] ^ b[k]); }
        prev.clear();
        prev.append(v[i..i + 16]);
        i += 16;
    }
    let n = plain[0] as i64;
    if n + 1 > plain.len { return out, false; }
    out.append(plain[1..1 + n]);
    return out, true;
}

// Tunnel-Password (RFC 2868 §3.5) with its tag (0: none).
fn add_tunnel_password(p: Packet&, tag: u8, pw: const u8[:], secret: const u8[:], req_auth: const u8[:]) -> bool {
    let v, ok = salt_encrypt(pw, secret, req_auth);
    if !ok { return false; }
    var b: u8[>..] = [];
    b.push(tag);
    b.append(v);
    return add(p, TUNNEL_PASSWORD, b);
}

fn tunnel_password(p: const Packet&, secret: const u8[:], req_auth: const u8[:]) -> u8[>..], u8, bool {
    let v, ok = get(p, TUNNEL_PASSWORD);
    if !ok || v.len < 1 { var none: u8[>..] = []; return none, 0, false; }
    let pw, okd = salt_decrypt(v[1..], secret, req_auth);
    return pw, v[0], okd;
}

// MS-MPPE-Recv-Key and MS-MPPE-Send-Key, from the server's side as
// RFC 2548 names them: an EAP method's keys are recv = MSK[0..32],
// send = MSK[32..64] (RFC 5216 §2.3); EAP-MS-CHAPv2's 32-byte MSK gives
// 16 bytes each.
fn add_mppe_keys(p: Packet&, msk: const u8[:], secret: const u8[:], req_auth: const u8[:]) -> bool {
    if msk.len != 32 && msk.len < 64 { return false; }
    let half = if msk.len == 32 { 16 } else { 32 };
    let r, okr = salt_encrypt(msk[..half], secret, req_auth);
    let s, oks = salt_encrypt(msk[half..2 * half], secret, req_auth);
    return okr && oks && add_vsa(p, VENDOR_MICROSOFT, MS_MPPE_RECV_KEY, r) &&
        add_vsa(p, VENDOR_MICROSOFT, MS_MPPE_SEND_KEY, s);
}

// The two keys of an Access-Accept back, as one: recv then send, an EAP
// method's MSK (its first 64 bytes).
fn mppe_keys(p: const Packet&, secret: const u8[:], req_auth: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let r, okr = vsa(p, VENDOR_MICROSOFT, MS_MPPE_RECV_KEY);
    let s, oks = vsa(p, VENDOR_MICROSOFT, MS_MPPE_SEND_KEY);
    if !okr || !oks { return out, false; }
    let rk, okrk = salt_decrypt(r, secret, req_auth);
    let sk, oksk = salt_decrypt(s, secret, req_auth);
    if !okrk || !oksk { return out, false; }
    out.append(rk);
    out.append(sk);
    return out, true;
}
