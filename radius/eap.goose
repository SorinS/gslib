// radius.eap: EAP (RFC 3748), a peer (the supplicant) and a server (the
// authenticator's back end), with the methods FreeRADIUS and wpa_supplicant
// speak: MD5-Challenge, MS-CHAPv2 (draft-kamath-pppext-eap-mschapv2),
// EAP-TLS (RFC 5216; over TLS 1.3, RFC 9190), PEAPv0 with EAP-MS-CHAPv2
// inside and its Result TLV, and EAP-TTLS (RFC 5281) with PAP or
// MS-CHAPv2 inside. Each side is a step function: an EAP packet in, the
// next one out, and in the end success or failure; the keys (MSK, EMSK)
// once a TLS method succeeds: from TLS 1.2's PRF with "client EAP
// encryption" (EAP-TLS, PEAP) or "ttls keying material", from TLS 1.3's
// exporter with EXPORTER_EAP_TLS_Key_Material and the method's type (RFC
// 9190, RFC 9427).
//
// TLS messages go in EAP-TLS fragments of PeerConfig.fragment or
// EapConfig.fragment bytes (1000 by default), the other side's fragments
// acknowledged; nothing else of RADIUS is here, so EAPOL could carry the
// same steps.
//
//   var cfg = radius::peer_config("alice", "alice-pw", radius::EAP_PEAP);
//   cfg.tls = tls::client_config("radius.example.com", ca_der);
//   var p = radius::peer(cfg);
//   var out: u8[>..] = [];
//   let st = radius::peer_step(p, cfg, request, out);   // EAP_SEND, EAP_SUCCESS, EAP_FAILURE

namespace radius;

import std;
import crypto.bignum;
import crypto.bignum.md5;
import crypto.bignum.ct;
import entropy;
import crypto.tls;
import crypto.tls.handshake;
import crypto.x509;

// --- Packets ---------------------------------------------------------------------

let EAP_REQUEST:  u8 = 1;
let EAP_RESPONSE: u8 = 2;
let EAP_SUCCESS:  u8 = 3;
let EAP_FAILURE:  u8 = 4;

let EAP_IDENTITY:     u8 = 1;
let EAP_NOTIFICATION: u8 = 2;
let EAP_NAK:          u8 = 3;
let EAP_MD5:          u8 = 4;
let EAP_TLS:          u8 = 13;
let EAP_TTLS:         u8 = 21;
let EAP_PEAP:         u8 = 25;
let EAP_MSCHAPV2:     u8 = 26;
let EAP_TLV:          u8 = 33;

// The inner methods of TTLS.
let INNER_PAP:      u8 = 1;
let INNER_MSCHAPV2: u8 = 2;

// What a step did.
let EAP_SEND:    i64 = 0;   // `out` has the next packet
let EAP_DONE_OK: i64 = 1;   // succeeded (the server's `out` has EAP-Success)
let EAP_DONE_FAIL: i64 = 2; // failed (the server's `out` has EAP-Failure); `error` says why

fn eap_type_name(t: u8) -> const u8[:] {
    if t == EAP_IDENTITY { return "Identity"; }
    if t == EAP_NOTIFICATION { return "Notification"; }
    if t == EAP_NAK { return "Nak"; }
    if t == EAP_MD5 { return "MD5-Challenge"; }
    if t == EAP_TLS { return "TLS"; }
    if t == EAP_TTLS { return "TTLS"; }
    if t == EAP_PEAP { return "PEAP"; }
    if t == EAP_MSCHAPV2 { return "MSCHAPV2"; }
    if t == EAP_TLV { return "TLV"; }
    return "unknown";
}

// An EAP packet: code, identifier, then the type and its data (none for
// Success and Failure).
fn eap_packet(code: u8, id: u8, t: u8, data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let n = if code == EAP_SUCCESS || code == EAP_FAILURE { 4 } else { 5 + data.len };
    out.push(code);
    out.push(id);
    out.push((n >> 8) as! u8);
    out.push(n as! u8);
    if n > 4 { out.push(t); out.append(data); }
    return out;
}

// The header of an EAP packet: its code, identifier and length, the type
// (0 for none); false when it is not one (the length field past the
// bytes, a Request or Response without a type).
fn eap_header(m: const u8[:]) -> u8, u8, i64, u8, bool {
    if m.len < 4 { return 0, 0, 0, 0, false; }
    let n = (m[2] as i64) << 8 | m[3];
    if n < 4 || n > m.len { return 0, 0, 0, 0, false; }
    if m[0] == EAP_REQUEST || m[0] == EAP_RESPONSE {
        if n < 5 { return 0, 0, 0, 0, false; }
        return m[0], m[1], n, m[4], true;
    }
    return m[0], m[1], n, 0, m[0] == EAP_SUCCESS || m[0] == EAP_FAILURE;
}

// --- EAP-TLS framing (RFC 5216 §3) -----------------------------------------------

let TLS_FLAG_L: u8 = 0x80;    // the total length follows
let TLS_FLAG_M: u8 = 0x40;    // more fragments come
let TLS_FLAG_S: u8 = 0x20;    // start
let MAX_TLS_MESSAGE: i64 = 65536;

// One side's TLS in EAP: the connection, a message being reassembled from
// fragments, and the TLS bytes still to send in fragments.
struct TlsLayer {
    conn: tls::Conn,
    started: bool,
    in_total: i64,
    inbuf: u8[..65536],
    outpos: i64,
    outbuf: u8[..65536],
}

fn tls_layer(c: tls::Conn) -> TlsLayer {
    TlsLayer { conn: c, started: false, in_total: -1, inbuf: [], outpos: 0, outbuf: [] }
}

// Whether there is TLS left to send.
fn layer_pending(l: const TlsLayer&) -> bool { l.outpos < l.outbuf.len }

// The next fragment's type data: flags (with the version), the total
// length on the first of several, then up to frag bytes.
fn layer_next(l: TlsLayer&, version: u8, frag: i64) -> u8[>..] {
    var d: u8[>..] = [];
    let total = l.outbuf.len;
    let n = ::min(frag, total - l.outpos);
    var flags = version;
    if total > frag && l.outpos == 0 { flags |= TLS_FLAG_L; }
    if l.outpos + n < total { flags |= TLS_FLAG_M; }
    d.push(flags);
    if flags & TLS_FLAG_L != 0 {
        d.push((total >> 24) as! u8);
        d.push((total >> 16) as! u8);
        d.push((total >> 8) as! u8);
        d.push(total as! u8);
    }
    d.append(l.outbuf[l.outpos..l.outpos + n]);
    l.outpos += n;
    if l.outpos >= l.outbuf.len { l.outbuf.clear(); l.outpos = 0; }
    return d;
}

// Appends TLS bytes to send.
fn layer_queue(l: TlsLayer&, b: const u8[:]) -> bool {
    if l.outpos > 0 && l.outpos >= l.outbuf.len { l.outbuf.clear(); l.outpos = 0; }
    if l.outbuf.len + b.len > l.outbuf.cap { return false; }
    l.outbuf.append(b);
    return true;
}

let LAYER_ACK: i64 = 0;        // an empty message: the other side acknowledges ours
let LAYER_MORE: i64 = 1;       // a fragment, more to come: acknowledge it
let LAYER_MESSAGE: i64 = 2;    // a whole message is in inbuf
let LAYER_BAD: i64 = -1;

// Takes one fragment's type data (flags onwards).
fn layer_take(l: TlsLayer&, d: const u8[:]) -> i64 {
    if d.len < 1 { return LAYER_BAD; }
    let flags = d[0];
    var pos = 1;
    if flags & TLS_FLAG_L != 0 {
        if d.len < 5 { return LAYER_BAD; }
        let total = (d[1] as i64) << 24 | (d[2] as i64) << 16 | (d[3] as i64) << 8 | d[4];
        if total > MAX_TLS_MESSAGE || total < 0 { return LAYER_BAD; }
        if l.in_total < 0 { l.in_total = total; }
        pos = 5;
    }
    if pos == d.len && flags & TLS_FLAG_M == 0 && l.inbuf.len == 0 { return LAYER_ACK; }
    if l.inbuf.len + d.len - pos > l.inbuf.cap { return LAYER_BAD; }
    l.inbuf.append(d[pos..]);
    if l.in_total >= 0 && l.inbuf.len > l.in_total { return LAYER_BAD; }
    if flags & TLS_FLAG_M != 0 { return LAYER_MORE; }
    if l.in_total >= 0 && l.inbuf.len != l.in_total { return LAYER_BAD; }
    return LAYER_MESSAGE;
}

fn layer_reset_in(l: TlsLayer&) { l.inbuf.clear(); l.in_total = -1; }

// The keys of a TLS method: MSK and EMSK, 64 bytes each.
fn tls_method_keys(c: const tls::Conn&, method: u8) -> u8[>..] {
    if tls::version(c) == tls::VERSION_TLS13 {
        let ctx: u8[1] = [method];
        return tls::export_keys(c, "EXPORTER_EAP_TLS_Key_Material", ctx, true, 128);
    }
    let label = if method == EAP_TTLS { "ttls keying material" } else { "client EAP encryption" };
    return tls::export_keys(c, label, "", false, 128);
}

// TTLS's implicit challenge (RFC 5281 §11.2.4): 17 bytes, the MS-CHAP
// challenge and its identifier.
fn ttls_challenge(c: const tls::Conn&) -> u8[>..] { tls::export_keys(c, "ttls challenge", "", false, 17) }

// --- Diameter AVPs, TTLS's inner messages (RFC 5281 §10) -----------------------------

let AVP_FLAG_V: u8 = 0x80;
let AVP_FLAG_M: u8 = 0x40;

fn put_avp(out: u8[>..]&, code: u32, vendor: u32, data: const u8[:]) {
    let hl = if vendor != 0 { 12 } else { 8 };
    let n = hl + data.len;
    out.append(be32(code));
    let vflag: u8 = if vendor != 0 { AVP_FLAG_V } else { 0 };
    out.push(AVP_FLAG_M | vflag);
    out.push((n >> 16) as! u8);
    out.push((n >> 8) as! u8);
    out.push(n as! u8);
    if vendor != 0 { out.append(be32(vendor)); }
    out.append(data);
    while out.len % 4 != 0 { out.push(0); }
}

fn get32(b: const u8[:], i: i64) -> u32 {
    (b[i] as u32) << 24 | (b[i + 1] as u32) << 16 | (b[i + 2] as u32) << 8 | b[i + 3]
}

// The AVP with code and vendor in a list, and true; false for none or a
// list that does not parse.
fn find_avp(b: const u8[:], code: u32, vendor: u32) -> u8[>..], bool {
    var out: u8[>..] = [];
    var i = 0;
    while i + 8 <= b.len {
        let c = get32(b, i);
        let flags = b[i + 4];
        let n = (b[i + 5] as i64) << 16 | (b[i + 6] as i64) << 8 | b[i + 7];
        let hl = if flags & AVP_FLAG_V != 0 { 12 } else { 8 };
        if n < hl || i + n > b.len { return out, false; }
        let v = if flags & AVP_FLAG_V != 0 { get32(b, i + 8) } else { 0 };
        if c == code && v == vendor { out.append(b[i + hl..i + n]); return out, true; }
        i += (n + 3) / 4 * 4;
    }
    return out, false;
}

// --- MS-CHAPv2 in EAP (draft-kamath-pppext-eap-mschapv2) ------------------------------

let MS_OP_CHALLENGE: u8 = 1;
let MS_OP_RESPONSE:  u8 = 2;
let MS_OP_SUCCESS:   u8 = 3;
let MS_OP_FAILURE:   u8 = 4;

// The name MS-CHAPv2 hashes: a user's without a "DOMAIN\" in front.
fn ms_user(name: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var start = 0;
    for i in name.len { if name[i] == '\\' { start = i + 1; } }
    out.append(name[start..]);
    return out;
}

fn ms_data(op: u8, msid: u8, body: const u8[:]) -> u8[>..] {
    var d: u8[>..] = [];
    let n = 4 + body.len;
    d.push(op);
    d.push(msid);
    d.push((n >> 8) as! u8);
    d.push(n as! u8);
    d.append(body);
    return d;
}

// --- The peer ------------------------------------------------------------------------

// What a peer needs: its identity (and the outer, anonymous one a tunnel
// method shows in the clear; the identity when empty), its password, the
// method it wants and the inner method of TTLS, EAP-TLS fragment size,
// and its TLS (the server's name and CA; a client certificate for EAP-TLS).
struct PeerConfig {
    identity: u8[..253], outer_identity: u8[..253], password: u8[..256],
    method: u8, inner: u8, fragment: i64,
    tls: tls::ClientConfig,
}

fn peer_config(identity: const u8[:], password: const u8[:], method: u8) -> PeerConfig {
    var c = PeerConfig {
        identity: [], outer_identity: [], password: [], method: method, inner: INNER_MSCHAPV2, fragment: 1000,
        tls: tls::client_config("", ""),
    };
    c.identity.append(identity[..::min(identity.len, 253)]);
    c.password.append(password[..::min(password.len, 256)]);
    return c;
}

struct Peer {
    method: u8,               // the method under way (0 before)
    error: i64,
    method_ok: bool,          // the method did what success needs (and checked the server)
    inner_ok: bool,           // the tunnel's inner method succeeded (PEAP, TTLS MS-CHAPv2)
    avps_sent: bool,          // TTLS: the inner credentials went
    commitment: bool,         // EAP-TLS 1.3: the server's 0x00 came
    last_id: i64,
    ms_auth_ch: u8[16], ms_peer_ch: u8[16], ms_nt: u8[24], ms_hash: u8[16], ms_ident: u8,
    ms_answered: bool,         // our MS-CHAPv2 Response went: only then can a Success be checked
    ms_keys: u8[..32],        // MS-CHAPv2's MSK
    keys: u8[..128],          // MSK then EMSK (EAP-MS-CHAPv2: a 32-byte MSK)
    last_out: u8[..2048],
    layer: TlsLayer,
}

fn peer(cfg: const PeerConfig&) -> Peer {
    Peer {
        method: 0, error: OK, method_ok: false, inner_ok: false, avps_sent: false, commitment: false, last_id: -1,
        ms_auth_ch: [0; 16], ms_peer_ch: [0; 16], ms_nt: [0; 24], ms_hash: [0; 16], ms_ident: 0, ms_answered: false,
        ms_keys: [], keys: [], last_out: [], layer: tls_layer(tls::client(cfg.tls)),
    }
}

// The keys once a method with keys succeeded: the MSK (64 bytes for the
// TLS methods, 32 for EAP-MS-CHAPv2; RADIUS carries it to the NAS as
// MS-MPPE-Recv-Key and -Send-Key) and the EMSK (the TLS methods').
fn peer_msk(p: const Peer&) -> u8[>..] { var o: u8[>..] = []; o.append(p.keys[..::min(p.keys.len, 64)]); return o; }
fn peer_emsk(p: const Peer&) -> u8[>..] { var o: u8[>..] = []; if p.keys.len >= 128 { o.append(p.keys[64..128]); } return o; }

fn peer_fail(p: Peer&, e: i64) -> i64 { p.error = e; return EAP_DONE_FAIL; }

fn peer_send(p: Peer&, id: u8, t: u8, data: const u8[:], out: u8[>..]&) -> i64 {
    let m = eap_packet(EAP_RESPONSE, id, t, data);
    out.append(m);
    p.last_id = id;
    p.last_out.clear();
    if m.len <= p.last_out.cap { p.last_out.append(m); }
    return EAP_SEND;
}

// One EAP packet from the server; the answer appended to out. EAP_SEND,
// or EAP_DONE_OK on an EAP-Success the method allows (a TLS method's
// handshake done and its server checked, the inner method's success
// seen), EAP_DONE_FAIL on EAP-Failure or a broken conversation.
fn peer_step(p: Peer&, cfg: const PeerConfig&, input: const u8[:], out: u8[>..]&) -> i64 {
    let code, id, n, t, ok = eap_header(input);
    if !ok { return peer_fail(p, ERR_MALFORMED); }
    if code == EAP_SUCCESS {
        if p.method == 0 || !p.method_ok || p.error != OK { return peer_fail(p, if p.error != OK { p.error } else { ERR_EAP }); }
        return EAP_DONE_OK;
    }
    if code == EAP_FAILURE { return peer_fail(p, if p.error != OK { p.error } else { ERR_REJECTED }); }
    if code != EAP_REQUEST { return peer_fail(p, ERR_MALFORMED); }
    // The same request again: the same answer.
    if id == p.last_id && p.last_out.len > 0 { out.append(p.last_out); return EAP_SEND; }
    let data = input[5..n];
    if t == EAP_IDENTITY {
        let tunnel = cfg.method == EAP_PEAP || cfg.method == EAP_TTLS;
        let who = if tunnel && cfg.outer_identity.len > 0 { cfg.outer_identity[..] } else { cfg.identity[..] };
        return peer_send(p, id, EAP_IDENTITY, who, out);
    }
    if t == EAP_NOTIFICATION { return peer_send(p, id, EAP_NOTIFICATION, "", out); }
    if t != cfg.method {
        // Another method proposed: a Nak naming ours, before one is under way.
        if p.method != 0 || t == EAP_NAK { return peer_fail(p, ERR_EAP); }
        let want: u8[1] = [cfg.method];
        return peer_send(p, id, EAP_NAK, want, out);
    }
    p.method = t;
    if t == EAP_MD5 {
        if data.len < 1 || data.len < 1 + data[0] as i64 { return peer_fail(p, ERR_MALFORMED); }
        var m = bignum::md5_init();
        let idb: u8[1] = [id];
        bignum::md5_update(m, idb);
        bignum::md5_update(m, cfg.password);
        bignum::md5_update(m, data[1..1 + data[0] as i64]);
        let h = bignum::md5_final(m);
        var r: u8[>..] = [];
        r.push(16);
        r.append(h);
        // MD5-Challenge cannot check the server: success is taken on its word.
        p.method_ok = true;
        return peer_send(p, id, EAP_MD5, r, out);
    }
    if t == EAP_MSCHAPV2 {
        var r: u8[>..] = [];
        let st = peer_mschapv2(p, cfg, data, r);
        if st != EAP_SEND { return st; }
        p.method_ok = p.inner_ok;
        if p.inner_ok && p.keys.len == 0 { p.keys.append(p.ms_keys); }
        return peer_send(p, id, EAP_MSCHAPV2, r, out);
    }
    if t == EAP_TLS || t == EAP_PEAP || t == EAP_TTLS { return peer_tls(p, cfg, id, t, data, out); }
    return peer_fail(p, ERR_EAP);
}

// MS-CHAPv2's peer: a Challenge answered, a Success checked (the server
// knew the password) and acknowledged, a Failure acknowledged. The type
// data in, the type data out.
fn peer_mschapv2(p: Peer&, cfg: const PeerConfig&, data: const u8[:], r: u8[>..]&) -> i64 {
    if data.len < 1 { return peer_fail(p, ERR_MALFORMED); }
    let op = data[0];
    if op == MS_OP_CHALLENGE {
        if data.len < 5 + 16 || data[4] != 16 { return peer_fail(p, ERR_MALFORMED); }
        let h, okh = nt_password_hash(cfg.password);
        if !okh { return peer_fail(p, ERR_ARG); }
        p.ms_hash = h;
        for i in 16 { p.ms_auth_ch[i] = data[5 + i]; }
        entropy::random_bytes(p.ms_peer_ch);
        p.ms_ident = data[1];
        let user = ms_user(cfg.identity);
        p.ms_nt = nt_response(p.ms_auth_ch, p.ms_peer_ch, user, h);
        var body: u8[>..] = [];
        body.push(49);
        body.append(p.ms_peer_ch);
        for i in 8 { body.push(0); }
        body.append(p.ms_nt);
        body.push(0);
        body.append(cfg.identity);
        r.append(ms_data(MS_OP_RESPONSE, data[1], body));
        p.ms_answered = true;
        return EAP_SEND;
    }
    if op == MS_OP_SUCCESS {
        if data.len < 4 { return peer_fail(p, ERR_MALFORMED); }
        // A Success before any Challenge would be checked against zeros,
        // which anyone can compute from the user name: the authenticator
        // would not be authenticated.
        if !p.ms_answered || data[1] != p.ms_ident { return peer_fail(p, ERR_AUTHENTICATOR); }
        let user = ms_user(cfg.identity);
        if !authenticator_response_ok(data[4..], p.ms_hash, p.ms_nt, p.ms_peer_ch, p.ms_auth_ch, user) {
            return peer_fail(p, ERR_AUTHENTICATOR);
        }
        p.inner_ok = true;
        // EAP-MS-CHAPv2's MSK ([MS-CHAP] §3.1.5.1): the master receive
        // and send keys, the server's names for them.
        let mk = master_key(p.ms_hash, p.ms_nt);
        p.ms_keys.clear();
        p.ms_keys.append(start_key(mk, true, false));
        p.ms_keys.append(start_key(mk, false, false));
        r.push(MS_OP_SUCCESS);
        return EAP_SEND;
    }
    if op == MS_OP_FAILURE {
        p.error = ERR_REJECTED;
        r.push(MS_OP_FAILURE);
        return EAP_SEND;
    }
    return peer_fail(p, ERR_MALFORMED);
}

// The TLS methods' peer: start, fragments either way, the handshake, then
// the method's own part: EAP-TLS's end, PEAP's and TTLS's inner methods.
fn peer_tls(p: Peer&, cfg: const PeerConfig&, id: u8, t: u8, data: const u8[:], out: u8[>..]&) -> i64 {
    if data.len < 1 { return peer_fail(p, ERR_MALFORMED); }
    let version: u8 = 0;
    var l = &p.layer;
    if data[0] & TLS_FLAG_S != 0 {
        if l.started { return peer_fail(p, ERR_EAP); }
        l.started = true;
        var hello: u8[>..] = [];
        tls::client_start(l.conn, cfg.tls, hello);
        if !layer_queue(l, hello) { return peer_fail(p, ERR_LIMIT); }
        return peer_send(p, id, t, layer_next(l, version, cfg.fragment), out);
    }
    if !l.started { return peer_fail(p, ERR_EAP); }
    let r = layer_take(l, data);
    if r == LAYER_BAD { return peer_fail(p, ERR_MALFORMED); }
    if r == LAYER_MORE {
        let ack: u8[1] = [version];
        return peer_send(p, id, t, ack, out);
    }
    if r == LAYER_MESSAGE {
        var to_send: u8[>..] = [];
        var app: u8[>..] = [];
        let fr = tls::feed(l.conn, cfg.tls, l.inbuf, to_send, app);
        layer_reset_in(l);
        let okq = layer_queue(l, to_send);
        if fr < 0 {
            // Ours or the server's alert: ours goes to the server, the
            // server's is acknowledged (RFC 5216 §2.1.3), so that it ends
            // with EAP-Failure; Success is refused from now on.
            p.error = ERR_TLS;
            if layer_pending(l) { return peer_send(p, id, t, layer_next(l, version, cfg.fragment), out); }
            let ack: u8[1] = [version];
            return peer_send(p, id, t, ack, out);
        }
        if tls::connected(l.conn) && p.keys.len == 0 { p.keys.append(tls_method_keys(l.conn, t)); }
        let st = peer_inner(p, cfg, t, app);
        if st != EAP_SEND { return st; }
    }
    if layer_pending(l) { return peer_send(p, id, t, layer_next(l, version, cfg.fragment), out); }
    let ack: u8[1] = [version];
    return peer_send(p, id, t, ack, out);
}

// What the method does with the tunnel once TLS is up: app is what the
// server sent inside it.
fn peer_inner(p: Peer&, cfg: const PeerConfig&, t: u8, app: const u8[:]) -> i64 {
    var l = &p.layer;
    if !tls::connected(l.conn) { return EAP_SEND; }
    if t == EAP_TLS {
        // TLS 1.2: the server's Finished ends it. TLS 1.3: its one byte of
        // 0x00 does (RFC 9190 §2.5).
        if tls::version(l.conn) == tls::VERSION_TLS12 { p.method_ok = true; }
        else if app.len == 1 && app[0] == 0 { p.commitment = true; p.method_ok = true; }
        else if app.len > 0 { return peer_fail(p, ERR_EAP); }
        return EAP_SEND;
    }
    if t == EAP_TTLS { return peer_ttls(p, cfg, app); }
    return peer_peap(p, cfg, app);
}

fn tunnel_send(p: Peer&, b: const u8[:]) -> bool {
    var rec: u8[>..] = [];
    return tls::send(p.layer.conn, b, rec) && layer_queue(p.layer, rec);
}

fn peer_ttls(p: Peer&, cfg: const PeerConfig&, app: const u8[:]) -> i64 {
    if !p.avps_sent {
        p.avps_sent = true;
        var avps: u8[>..] = [];
        put_avp(avps, USER_NAME, 0, cfg.identity);
        if cfg.inner == INNER_PAP {
            var pw: u8[>..] = [];
            pw.append(cfg.password);
            while pw.len == 0 || pw.len % 16 != 0 { pw.push(0); }
            put_avp(avps, USER_PASSWORD, 0, pw);
            // PAP proves nothing of the server beyond its certificate.
            p.method_ok = true;
        } else {
            let ch = ttls_challenge(p.layer.conn);
            let h, okh = nt_password_hash(cfg.password);
            if ch.len != 17 || !okh { return peer_fail(p, ERR_TLS); }
            p.ms_hash = h;
            for i in 16 { p.ms_auth_ch[i] = ch[i]; }
            p.ms_ident = ch[16];
            entropy::random_bytes(p.ms_peer_ch);
            p.ms_nt = nt_response(p.ms_auth_ch, p.ms_peer_ch, ms_user(cfg.identity), h);
            var resp: u8[>..] = [];
            resp.push(p.ms_ident);
            resp.push(0);
            resp.append(p.ms_peer_ch);
            for i in 8 { resp.push(0); }
            resp.append(p.ms_nt);
            put_avp(avps, MS_CHAP_CHALLENGE, VENDOR_MICROSOFT, p.ms_auth_ch);
            put_avp(avps, MS_CHAP2_RESPONSE, VENDOR_MICROSOFT, resp);
        }
        if !tunnel_send(p, avps) { return peer_fail(p, ERR_TLS); }
        return EAP_SEND;
    }
    if app.len == 0 { return EAP_SEND; }
    if app.len == 1 && app[0] == 0 { return EAP_SEND; }     // TLS 1.3's commitment, as wpa_supplicant takes it
    if cfg.inner == INNER_MSCHAPV2 {
        let s, oks = find_avp(app, MS_CHAP2_SUCCESS, VENDOR_MICROSOFT);
        if oks {
            if s.len < 43 || s[0] != p.ms_ident ||
               !authenticator_response_ok(s[1..], p.ms_hash, p.ms_nt, p.ms_peer_ch, p.ms_auth_ch, ms_user(cfg.identity)) {
                return peer_fail(p, ERR_AUTHENTICATOR);
            }
            p.inner_ok = true;
            p.method_ok = true;
            return EAP_SEND;
        }
        let e, oke = find_avp(app, MS_CHAP_ERROR, VENDOR_MICROSOFT);
        if oke { return peer_fail(p, ERR_REJECTED); }
    }
    return EAP_SEND;
}

// PEAPv0's inner EAP: the header left off, but for EAP-TLV's (and the
// full Identity request FreeRADIUS sends); answers likewise.
fn peer_peap(p: Peer&, cfg: const PeerConfig&, app: const u8[:]) -> i64 {
    if app.len == 0 { return EAP_SEND; }
    var full = false;
    if app.len >= 5 && app[0] == EAP_REQUEST {
        let n = (app[2] as i64) << 8 | app[3];
        full = (app.len == 5 && n == 5 && app[4] == EAP_IDENTITY) || (app[4] == EAP_TLV && n == app.len);
    }
    let t = if full { app[4] } else { app[0] };
    let data = if full { app[5..] } else { app[1..] };
    var resp: u8[>..] = [];
    if t == EAP_IDENTITY {
        resp.push(EAP_IDENTITY);
        resp.append(cfg.identity);
    } else if t == EAP_MSCHAPV2 {
        var r: u8[>..] = [];
        let st = peer_mschapv2(p, cfg, data, r);
        if st != EAP_SEND { return st; }
        resp.push(EAP_MSCHAPV2);
        resp.append(r);
    } else if t == EAP_TLV && full {
        // The Result TLV (0x0003, mandatory): answered with ours, success
        // only when the inner method succeeded.
        var status: u16 = 0;
        var i = 0;
        while i + 4 <= data.len {
            let tt = ((data[i] as u16) << 8 | data[i + 1]) & 0x3fff;
            let tl = (data[i + 2] as i64) << 8 | data[i + 3];
            if i + 4 + tl > data.len { return peer_fail(p, ERR_MALFORMED); }
            if tt == 3 && tl == 2 { status = (data[i + 4] as u16) << 8 | data[i + 5]; }
            i += 4 + tl;
        }
        if status == 0 { return peer_fail(p, ERR_MALFORMED); }
        let mine: u16 = if status == 1 && p.inner_ok { 1 } else { 2 };
        let tlv: u8[6] = [0x80, 0x03, 0, 2, 0, mine as! u8];
        let pkt = eap_packet(EAP_RESPONSE, app[1], EAP_TLV, tlv);
        if !tunnel_send(p, pkt) { return peer_fail(p, ERR_TLS); }
        p.method_ok = mine == 1;
        return EAP_SEND;
    } else {
        // An inner method not ours: a Nak, inside.
        resp.push(EAP_NAK);
        resp.push(EAP_MSCHAPV2);
    }
    if !tunnel_send(p, resp) { return peer_fail(p, ERR_TLS); }
    return EAP_SEND;
}

// --- The server ------------------------------------------------------------------------

// What a server offers: its methods in order of preference (a peer's Nak
// may pick another of them), its TLS (the certificate; for EAP-TLS,
// client certificates required and checked against client_cas), its name
// in MS-CHAPv2 challenges, the EAP-TLS fragment size.
struct EapConfig {
    methods: u8[..8], name: u8[..64], fragment: i64,
    tls: tls::ServerConfig,
}

fn eap_config(methods: const u8[:], t: const tls::ServerConfig&) -> EapConfig {
    var c = EapConfig { methods: [], name: [], fragment: 1000, tls: copy(t) };
    c.methods.append(methods[..::min(methods.len, 8)]);
    c.name.append("gslib");
    // No session tickets: nothing in an EAP conversation would resume.
    c.tls.tickets = 0;
    return c;
}

// One conversation, as the server sees it.
struct EapSession {
    id: u8, method: u8, step: i64, error: i64,
    identity: u8[..253], inner_identity: u8[..253],
    challenge: u8[16], ms_ok: bool, inner_ok: bool, ttls_ms: bool,
    answered: bool,            // the method has had a response: a Nak is too late
    ms_keys: u8[..32],
    keys: u8[..128],
    layer: TlsLayer,
}

let SS_IDENTITY: i64 = 0;      // waiting for the Identity response
let SS_METHOD: i64 = 1;        // the method under way
let SS_INNER: i64 = 2;         // the tunnel up, its inner method under way
let SS_RESULT: i64 = 3;        // PEAP: the Result TLV sent; TTLS, EAP-TLS: the last message sent
let SS_DONE: i64 = 4;

// The name a successful conversation authenticated: the inner identity
// in PEAP and TTLS (the outer one is unchecked, often "anonymous"), the
// identity the password was checked for in EAP-MD5 and MS-CHAPv2, and
// none in EAP-TLS, which authenticates a certificate, not the name the
// peer gave.
fn authenticated_identity(s: const EapSession&) -> const u8[:] {
    if s.method == EAP_PEAP || s.method == EAP_TTLS { return s.inner_identity[..]; }
    if s.method == EAP_MD5 || s.method == EAP_MSCHAPV2 { return s.identity[..]; }
    return "";
}

fn eap_session(cfg: const EapConfig&) -> EapSession {
    var idb: u8[1] = [0];
    entropy::random_bytes(idb);
    EapSession {
        id: idb[0], method: 0, step: SS_IDENTITY, error: OK, identity: [], inner_identity: [],
        challenge: [0; 16], ms_ok: false, inner_ok: false, ttls_ms: false, answered: false, ms_keys: [], keys: [],
        layer: tls_layer(tls::server(cfg.tls)),
    }
}

// The request that starts a conversation where the NAS has not sent the
// peer's identity: EAP-Request/Identity.
fn server_start(s: EapSession&, out: u8[>..]&) {
    out.append(eap_packet(EAP_REQUEST, s.id, EAP_IDENTITY, ""));
}

fn session_msk(s: const EapSession&) -> u8[>..] { var o: u8[>..] = []; o.append(s.keys[..::min(s.keys.len, 64)]); return o; }
fn session_emsk(s: const EapSession&) -> u8[>..] { var o: u8[>..] = []; if s.keys.len >= 128 { o.append(s.keys[64..128]); } return o; }

fn server_request(s: EapSession&, t: u8, data: const u8[:], out: u8[>..]&) -> i64 {
    s.id = s.id + 1;
    out.append(eap_packet(EAP_REQUEST, s.id, t, data));
    return EAP_SEND;
}

fn server_done(s: EapSession&, ok: bool, e: i64, out: u8[>..]&) -> i64 {
    s.step = SS_DONE;
    if !ok { s.error = e; }
    out.append(eap_packet(if ok { EAP_SUCCESS } else { EAP_FAILURE }, s.id, 0, ""));
    return if ok { EAP_DONE_OK } else { EAP_DONE_FAIL };
}

fn offers(cfg: const EapConfig&, t: u8) -> bool {
    for m in cfg.methods { if m == t { return true; } }
    return false;
}

// The first request of a method.
fn server_method_start(s: EapSession&, cfg: const EapConfig&, t: u8, out: u8[>..]&) -> i64 {
    s.method = t;
    s.step = SS_METHOD;
    entropy::random_bytes(s.challenge);
    if t == EAP_MD5 {
        var d: u8[>..] = [];
        d.push(16);
        d.append(s.challenge);
        d.append(cfg.name);
        return server_request(s, EAP_MD5, d, out);
    }
    if t == EAP_MSCHAPV2 {
        var body: u8[>..] = [];
        body.push(16);
        body.append(s.challenge);
        body.append(cfg.name);
        return server_request(s, EAP_MSCHAPV2, ms_data(MS_OP_CHALLENGE, s.id + 1, body), out);
    }
    s.layer.started = true;
    let st: u8[1] = [TLS_FLAG_S];
    return server_request(s, t, st, out);
}

// One EAP packet from the peer (through the NAS); the next one for it
// appended to out: EAP_SEND, or EAP_DONE_OK / EAP_DONE_FAIL with
// EAP-Success or EAP-Failure in out. The block finds a user's password
// (empty for an unknown user), for every method but EAP-TLS:
//
//   radius::server_step(s, cfg, msg, out) { user => password_of(user) }
fn server_step<F>(s: EapSession&, cfg: const EapConfig&, input: const u8[:], out: u8[>..]&) -> i64 {
    let code, id, n, t, ok = eap_header(input);
    if !ok || code != EAP_RESPONSE { return server_done(s, false, ERR_MALFORMED, out); }
    if s.step == SS_DONE { return server_done(s, false, ERR_EAP, out); }
    if s.step != SS_IDENTITY && id != s.id { return server_done(s, false, ERR_ID, out); }
    let data = input[5..n];
    if s.step == SS_IDENTITY {
        if t != EAP_IDENTITY { return server_done(s, false, ERR_EAP, out); }
        s.id = id;
        s.identity.append(data[..::min(data.len, 253)]);
        if cfg.methods.len == 0 { return server_done(s, false, ERR_EAP, out); }
        return server_method_start(s, cfg, cfg.methods[0], out);
    }
    if t == EAP_NAK {
        // Before the method's first answer only: another one it asks for.
        // After it, a TLS connection may be up, and a method switched to
        // would take it over (PEAP's handshake ending as EAP-TLS's).
        if s.answered || s.layer.inbuf.len > 0 || s.ms_ok { return server_done(s, false, ERR_EAP, out); }
        for want in data {
            if want != s.method && offers(cfg, want) { return server_method_start(s, cfg, want, out); }
        }
        return server_done(s, false, ERR_EAP, out);
    }
    if t != s.method { return server_done(s, false, ERR_EAP, out); }
    s.answered = true;
    if t == EAP_MD5 {
        let pw = F(s.identity);
        if data.len != 17 || data[0] != 16 || pw.len == 0 { return server_done(s, false, ERR_REJECTED, out); }
        var m = bignum::md5_init();
        let idb: u8[1] = [s.id];
        bignum::md5_update(m, idb);
        bignum::md5_update(m, pw);
        bignum::md5_update(m, s.challenge);
        let h = bignum::md5_final(m);
        return server_done(s, bignum::ct_eq_bytes(h, data[1..17]) == 1, ERR_REJECTED, out);
    }
    if t == EAP_MSCHAPV2 {
        var r: u8[>..] = [];
        let st = server_mschapv2(s, cfg, data, s.identity, r, F);
        if st == EAP_DONE_OK { s.keys.append(s.ms_keys); }
        if st == EAP_DONE_OK || st == EAP_DONE_FAIL { return server_done(s, st == EAP_DONE_OK, ERR_REJECTED, out); }
        return server_request(s, EAP_MSCHAPV2, r, out);
    }
    return server_tls(s, cfg, t, data, out, F);
}

// MS-CHAPv2's server: a Response checked, the Success or Failure request;
// then the peer's acknowledgment of it ends the method. Type data in, type
// data out (EAP_SEND), or the end.
fn server_mschapv2<F>(s: EapSession&, cfg: const EapConfig&, data: const u8[:], user: const u8[:], r: u8[>..]&) -> i64 {
    if data.len < 1 { return EAP_DONE_FAIL; }
    let op = data[0];
    if op == MS_OP_RESPONSE && !s.ms_ok {
        if data.len < 5 + 49 || data[4] != 49 { return EAP_DONE_FAIL; }
        let pw = F(user);
        let h, okh = nt_password_hash(pw);
        let resp = data[5..54];
        let name = ms_user(user);
        let want = nt_response(s.challenge, resp[..16], name, h);
        if pw.len == 0 || !okh || bignum::ct_eq_bytes(want, resp[24..48]) != 1 {
            s.error = ERR_REJECTED;
            r.append(ms_data(MS_OP_FAILURE, data[1], "E=691 R=0 V=3 M=Authentication failed"));
            s.step = SS_RESULT;
            return EAP_SEND;
        }
        s.ms_ok = true;
        let mk = master_key(h, resp[24..48]);
        s.ms_keys.clear();
        s.ms_keys.append(start_key(mk, false, true));
        s.ms_keys.append(start_key(mk, true, true));
        let a = authenticator_response(h, resp[24..48], resp[..16], s.challenge, name);
        var msg: u8[>..] = [];
        msg.append(a);
        msg.append(" M=OK");
        r.append(ms_data(MS_OP_SUCCESS, data[1], msg));
        return EAP_SEND;
    }
    if op == MS_OP_SUCCESS && s.ms_ok { return EAP_DONE_OK; }
    return EAP_DONE_FAIL;
}

fn server_tunnel_send(s: EapSession&, b: const u8[:]) -> bool {
    var rec: u8[>..] = [];
    return tls::send(s.layer.conn, b, rec) && layer_queue(s.layer, rec);
}

fn server_tls<F>(s: EapSession&, cfg: const EapConfig&, t: u8, data: const u8[:], out: u8[>..]&) -> i64 {
    let version: u8 = 0;
    var l = &s.layer;
    let r = layer_take(l, data);
    if r == LAYER_BAD { return server_done(s, false, ERR_MALFORMED, out); }
    if r == LAYER_MORE {
        let ack: u8[1] = [version];
        return server_request(s, t, ack, out);
    }
    var app: u8[>..] = [];
    if r == LAYER_MESSAGE {
        var to_send: u8[>..] = [];
        let fr = tls::feed(l.conn, cfg.tls, l.inbuf, to_send, app);
        layer_reset_in(l);
        let okq = layer_queue(l, to_send);
        if fr < 0 {
            if layer_pending(l) && s.step != SS_DONE { return server_request(s, t, layer_next(l, version, cfg.fragment), out); }
            return server_done(s, false, ERR_TLS, out);
        }
    } else if !layer_pending(l) && tls::connected(l.conn) && s.step == SS_METHOD {
        // The peer acknowledged the last of the handshake.
        if t == EAP_TLS && tls::version(l.conn) == tls::VERSION_TLS12 { s.step = SS_RESULT; }
    }
    if layer_pending(l) { return server_request(s, t, layer_next(l, version, cfg.fragment), out); }
    if !tls::connected(l.conn) {
        // A failed peer sends an alert and no more: give up rather than wait.
        if r == LAYER_ACK { return server_done(s, false, ERR_TLS, out); }
        let ack: u8[1] = [version];
        return server_request(s, t, ack, out);
    }
    if s.keys.len == 0 { s.keys.append(tls_method_keys(l.conn, t)); }
    let st = server_inner(s, cfg, t, r, app, F);
    if st == EAP_DONE_OK || st == EAP_DONE_FAIL { return server_done(s, st == EAP_DONE_OK, ERR_REJECTED, out); }
    if layer_pending(l) { return server_request(s, t, layer_next(l, version, cfg.fragment), out); }
    let ack: u8[1] = [version];
    return server_request(s, t, ack, out);
}

// The method's part once TLS is up; r says what the peer's message was.
fn server_inner<F>(s: EapSession&, cfg: const EapConfig&, t: u8, r: i64, app: const u8[:]) -> i64 {
    var l = &s.layer;
    if t == EAP_TLS {
        // EAP-TLS authenticates the peer by its certificate alone: a
        // handshake without one, or with one not verified, fails, whatever
        // the TLS configuration (shared with PEAP and TTLS, it may ask for
        // a certificate only if given).
        if tls::peer_certificates(l.conn).len == 0 || !tls::peer_verified(l.conn) { return EAP_DONE_FAIL; }
        // TLS 1.2: the peer acknowledged our Finished. TLS 1.3: the
        // commitment message goes once, then its acknowledgment ends it.
        if tls::version(l.conn) == tls::VERSION_TLS12 { return if r == LAYER_ACK { EAP_DONE_OK } else { EAP_SEND }; }
        if s.step == SS_METHOD {
            s.step = SS_RESULT;
            let zero: u8[1] = [0];
            if !server_tunnel_send(s, zero) { return EAP_DONE_FAIL; }
            return EAP_SEND;
        }
        return if r == LAYER_ACK { EAP_DONE_OK } else { EAP_DONE_FAIL };
    }
    if t == EAP_TTLS { return server_ttls(s, cfg, r, app, F); }
    return server_peap(s, cfg, r, app, F);
}

fn server_ttls<F>(s: EapSession&, cfg: const EapConfig&, r: i64, app: const u8[:]) -> i64 {
    if s.step == SS_RESULT { return if r == LAYER_ACK && app.len == 0 { EAP_DONE_OK } else { EAP_DONE_FAIL }; }
    if app.len == 0 { s.step = SS_INNER; return EAP_SEND; }
    let user, oku = find_avp(app, USER_NAME, 0);
    if !oku { return EAP_DONE_FAIL; }
    s.inner_identity.append(user[..::min(user.len, 253)]);
    let pw = F(user);
    if pw.len == 0 { return EAP_DONE_FAIL; }
    let pap, okp = find_avp(app, USER_PASSWORD, 0);
    if okp {
        var got: u8[>..] = [];
        got.append(pap);
        while got.len > 0 && got[got.len - 1] == 0 { got.pop(); }
        return if got.len == pw.len && bignum::ct_eq_bytes(got, pw) == 1 { EAP_DONE_OK } else { EAP_DONE_FAIL };
    }
    let ch, okc = find_avp(app, MS_CHAP_CHALLENGE, VENDOR_MICROSOFT);
    let resp, okr = find_avp(app, MS_CHAP2_RESPONSE, VENDOR_MICROSOFT);
    if !okc || !okr || ch.len != 16 || resp.len != 50 { return EAP_DONE_FAIL; }
    // The challenge must be the one both sides derive (RFC 5281 §11.2.4).
    let want_ch = ttls_challenge(s.layer.conn);
    if want_ch.len != 17 || ch[..] != want_ch[..16] || resp[0] != want_ch[16] { return EAP_DONE_FAIL; }
    let h, okh = nt_password_hash(pw);
    let name = ms_user(user);
    let want = nt_response(ch, resp[2..18], name, h);
    if !okh || bignum::ct_eq_bytes(want, resp[26..50]) != 1 { return EAP_DONE_FAIL; }
    let a = authenticator_response(h, resp[26..50], resp[2..18], ch, name);
    var v: u8[>..] = [];
    v.push(resp[0]);
    v.append(a);
    var avps: u8[>..] = [];
    put_avp(avps, MS_CHAP2_SUCCESS, VENDOR_MICROSOFT, v);
    s.step = SS_RESULT;
    if !server_tunnel_send(s, avps) { return EAP_DONE_FAIL; }
    return EAP_SEND;
}

// PEAPv0's server: the inner Identity request (header left off), then
// EAP-MS-CHAPv2 inside, then the Result TLV (with its header), whose
// answer ends it.
fn server_peap<F>(s: EapSession&, cfg: const EapConfig&, r: i64, app: const u8[:]) -> i64 {
    if s.step == SS_METHOD {
        if app.len > 0 { return EAP_DONE_FAIL; }
        s.step = SS_INNER;
        let ident: u8[1] = [EAP_IDENTITY];
        if !server_tunnel_send(s, ident) { return EAP_DONE_FAIL; }
        return EAP_SEND;
    }
    if app.len == 0 { return EAP_DONE_FAIL; }
    if s.step == SS_RESULT {
        // The Result TLV's answer: success only if both said so.
        if app.len < 11 || app[0] != EAP_RESPONSE || app[4] != EAP_TLV { return EAP_DONE_FAIL; }
        let status = (app[9] as u16) << 8 | app[10];
        let tt = ((app[5] as u16) << 8 | app[6]) & 0x3fff;
        return if tt == 3 && status == 1 && s.inner_ok { EAP_DONE_OK } else { EAP_DONE_FAIL };
    }
    // Inner answers, header left off: the type first.
    let t = app[0];
    let data = app[1..];
    if t == EAP_IDENTITY && s.inner_identity.len == 0 {
        s.inner_identity.append(data[..::min(data.len, 253)]);
        entropy::random_bytes(s.challenge);
        var body: u8[>..] = [];
        body.push(16);
        body.append(s.challenge);
        body.append(cfg.name);
        var req: u8[>..] = [];
        req.push(EAP_MSCHAPV2);
        req.append(ms_data(MS_OP_CHALLENGE, s.id + 1, body));
        if !server_tunnel_send(s, req) { return EAP_DONE_FAIL; }
        return EAP_SEND;
    }
    if t == EAP_MSCHAPV2 && s.inner_identity.len > 0 {
        var rr: u8[>..] = [];
        let st = server_mschapv2(s, cfg, data, s.inner_identity, rr, F);
        if st == EAP_SEND {
            var req: u8[>..] = [];
            req.push(EAP_MSCHAPV2);
            req.append(rr);
            if !server_tunnel_send(s, req) { return EAP_DONE_FAIL; }
            return EAP_SEND;
        }
        // The method's end, either way, is told with the Result TLV.
        s.inner_ok = st == EAP_DONE_OK;
        s.step = SS_RESULT;
        let status: u8 = if s.inner_ok { 1 } else { 2 };
        let tlv: u8[6] = [0x80, 0x03, 0, 2, 0, status];
        let pkt = eap_packet(EAP_REQUEST, s.id + 1, EAP_TLV, tlv);
        if !server_tunnel_send(s, pkt) { return EAP_DONE_FAIL; }
        return EAP_SEND;
    }
    return EAP_DONE_FAIL;
}
