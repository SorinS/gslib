// quic.conn: a QUIC connection, sans-IO (RFC 9000, 9001, 9002). It takes
// the datagrams that arrive and the time (recv), gives the datagrams to
// send (poll), and says when it next wants to be woken (next_timeout,
// then on_timeout); a driver carries the datagrams over UDP. The TLS
// handshake runs inside, in tls's QUIC mode, its messages carried in
// CRYPTO frames at three encryption levels, each with its packet number
// space. Streams are opened, written and read through the connection.
//
// What it does: Initial, Handshake and 1-RTT packets, coalesced, the
// client's Initial datagrams padded to 1200 bytes; the server's
// amplification limit until the client's address is validated; key
// discarding; Retry and Version Negotiation (as a client); key updates
// (both ways); ACKs, loss detection, PTO probes and congestion control
// (quic.recovery); stream and connection flow control; RESET_STREAM and
// STOP_SENDING; PATH_CHALLENGE answered; idle timeout; closing and
// draining; stateless resets recognised. What it does not: 0-RTT,
// connection migration (disable_active_migration is sent), path MTU
// discovery (datagrams stay at 1200 bytes), a server's Retry.
//
// Times are microseconds.

namespace quic;

import std;
import entropy;
import quic;
import quic.packet;
import quic.frame;
import quic.params;
import quic.recovery;
import quic.stream;
import crypto.bignum;
import crypto.tls;
import crypto.tls.handshake;
import crypto.x509;

let CID_LEN: i64 = 8;
let DATAGRAM: i64 = 1200;
let MAX_STREAMS_HERE: i64 = 32;          // streams held at once, both sides'
let CONN_WINDOW: i64 = 16 * 65536;       // connection receive window

let STATE_HANDSHAKE: i64 = 0;
let STATE_CONNECTED: i64 = 1;
let STATE_CLOSING: i64 = 2;
let STATE_DRAINING: i64 = 3;
let STATE_CLOSED: i64 = 4;

// A handshake not done in 10 s is dropped: a connection whose peer only
// keeps it alive (Initial keys are public) holds a server's slot.
let HANDSHAKE_TIMEOUT: i64 = 10000000;

// What a sent packet carried that may need sending again.
let REC_CRYPTO: i64 = 1;
let REC_STREAM: i64 = 2;
let REC_HANDSHAKE_DONE: i64 = 3;
let REC_MAX_DATA: i64 = 4;
let REC_MAX_STREAM_DATA: i64 = 5;
let REC_MAX_STREAMS: i64 = 6;
let REC_RESET: i64 = 7;
let REC_STOP: i64 = 8;
let REC_ACK: i64 = 9;
let REC_RETIRE: i64 = 10;

// At most this many of the peer's connection IDs retired by one
// NEW_CONNECTION_ID, or waiting to be sent again: a Retire Prior To far
// ahead of what was issued is CONNECTION_ID_LIMIT_ERROR (§5.1.2), not
// that many RETIRE_CONNECTION_ID frames.
let MAX_RETIRE: i64 = 16;

struct Rec { kind: i64, id: i64, off: i64, len: i64, fin: bool }

let MAX_RECS: i64 = 2048;

// One packet number space: the next number to send, what was received
// (ranges, highest first), whether an ACK is owed.
struct Space {
    next_pn: i64,
    largest_recv: i64,
    largest_recv_time: i64,
    recv: i64[64],             // (smallest, largest) pairs, highest first
    n_recv: i64,
    floor: i64,                // below it, ranges dropped: taken as received (§12.3)
    ack_needed: bool,
    eliciting_unacked: i64,    // ack-eliciting packets received since the last ACK sent
    ack_deadline: i64,
}

fn space() -> Space {
    Space { next_pn: 0, largest_recv: -1, largest_recv_time: 0, recv: [0; 64], n_recv: 0, floor: 0, ack_needed: false,
            eliciting_unacked: 0, ack_deadline: 0 }
}

struct Stream {
    used: bool,
    id: i64,
    send: SendBuf,
    recv: RecvBuf,
    max_send: i64,             // the peer's limit on what we send (absolute offset)
    max_recv: i64,             // the limit we gave the peer
    read: i64,                 // bytes the application has read
    reset_recv: bool, reset_code: u64,       // the peer reset it
    reset_send: bool, reset_sent_code: u64,  // we reset it
    reset_pending: bool,       // a RESET_STREAM to send
    stop_send: bool, stop_code: u64,         // we asked the peer to stop (STOP_SENDING to send)
    stopped: bool,             // the peer asked us to stop
    max_update: bool,          // a MAX_STREAM_DATA to send
    accepted: bool,            // the application has taken it (accept_stream)
    new_sent: i64,             // the highest offset sent, for connection flow control
}

fn new_stream(id: i64, max_send: i64, max_recv: i64) -> Stream {
    Stream { used: true, id: id, send: send_buf(), recv: recv_buf(), max_send: max_send, max_recv: max_recv, read: 0,
             reset_recv: false, reset_code: 0, reset_send: false, reset_sent_code: 0, reset_pending: false, stop_send: false, stop_code: 0,
             stopped: false, max_update: false, accepted: false, new_sent: 0 }
}

struct Conn {
    is_server: bool,
    state: i64,
    tls: tls::Conn,
    // Connection IDs: ours, the peer's we send to, the client's first
    // Destination (the Initial keys' and original_destination_connection_id's),
    // the Retry's, the peer's first Source.
    scid: u8[..20], dcid: u8[..20], odcid: u8[..20], retry_scid: u8[..20], peer_scid: u8[..20],
    got_peer_scid: bool, retried: bool, token: u8[..512],
    peer_reset_token: u8[16], has_reset_token: bool,
    // Keys per level: Initial, Handshake, 1-RTT (with the next generation
    // and the previous one's read keys for packets reordered across an update).
    rkeys: Keys[3], wkeys: Keys[3], has_rkeys: bool[3], has_wkeys: bool[3],
    discarded: bool[3],
    next_rkeys: Keys, next_wkeys: Keys, prev_rkeys: Keys, has_prev: bool,
    key_phase: bool,
    key_update_pn: i64,                      // the first packet number sent in the current phase (-1: none yet)
    spaces: Space[3],
    rec: Recovery,
    recs: Rec[2048], rec_head: i64,
    crypto_send: SendBuf[3], crypto_recv: RecvBuf[3],
    // Transport parameters: ours (encoded for TLS) and the peer's.
    local: Params, peer: Params, has_peer_params: bool,
    // Flow control: what we may send in all (the peer's MAX_DATA) and have
    // sent of new data; what the peer may send and has, and has been read.
    max_data_send: i64, data_sent: i64,
    max_data_recv: i64, data_recv: i64, data_read: i64, max_data_update: bool,
    max_streams_bidi_send: i64, max_streams_uni_send: i64,   // the peer's limits on streams we open
    max_streams_bidi_recv: i64, max_streams_uni_recv: i64,   // ours on the peer's
    streams_bidi_opened: i64, streams_uni_opened: i64,       // by us
    peer_bidi_opened: i64, peer_uni_opened: i64,             // by the peer (counts)
    max_streams_update: bool,
    handshake_done_pending: bool,
    confirmed: bool,                         // the handshake is confirmed (§4.1.2)
    validated: bool,                         // the server has validated the client's address
    bytes_recv: i64, bytes_sent: i64,        // before validation, for the 3x limit
    path_response: u8[8], path_response_pending: bool,
    retire_pending: i64, retire_seq: u64,
    retire_lost: u64[..16],                  // RETIRE_CONNECTION_IDs lost, to send again
    probes: i64, probe_space: i64,
    // Closing: the error we send or got, its reason, whether ours was an
    // application's, when the closing or draining period ends.
    error: u64, error_frame: u64, app_error: bool, reason: u8[..256], peer_closed: bool,
    close_pending: bool, close_until: i64,
    close_triggers: i64,                     // packets received while closing; answered at 1, 2, 4, 8...
    idle_timeout: i64, last_activity: i64,
    started: i64,                            // when the connection was made, for HANDSHAKE_TIMEOUT
    newest: bool,                            // the last recv opened a packet numbered above all before
    now: i64,
    streams: Stream[..32],
}

// --- Setting up --------------------------------------------------------------

fn new_conn(is_server: bool) -> Conn {
    let none = tls::client_config("", "");
    let ik = initial_keys("", true);
    var c = Conn {
        is_server: is_server, state: STATE_HANDSHAKE, tls: tls::client(none),
        scid: [], dcid: [], odcid: [], retry_scid: [], peer_scid: [], got_peer_scid: false, retried: false, token: [],
        peer_reset_token: [0; 16], has_reset_token: false,
        rkeys: [ik; 3], wkeys: [ik; 3], has_rkeys: [false; 3], has_wkeys: [false; 3],
        discarded: [false; 3],
        next_rkeys: ik, next_wkeys: ik, prev_rkeys: ik, has_prev: false,
        key_phase: false, key_update_pn: -1,
        spaces: [space(); 3], rec: recovery(), recs: [Rec { kind: 0, id: 0, off: 0, len: 0, fin: false }; 2048], rec_head: 0,
        crypto_send: [send_buf(); 3], crypto_recv: [recv_buf(); 3],
        local: default_params(), peer: default_params(), has_peer_params: false,
        max_data_send: 0, data_sent: 0, max_data_recv: CONN_WINDOW, data_recv: 0, data_read: 0, max_data_update: false,
        max_streams_bidi_send: 0, max_streams_uni_send: 0, max_streams_bidi_recv: 16, max_streams_uni_recv: 8,
        streams_bidi_opened: 0, streams_uni_opened: 0, peer_bidi_opened: 0, peer_uni_opened: 0, max_streams_update: false,
        handshake_done_pending: false, confirmed: false, validated: !is_server, bytes_recv: 0, bytes_sent: 0,
        path_response: [0; 8], path_response_pending: false, retire_pending: 0, retire_seq: 0, retire_lost: [],
        probes: 0, probe_space: -1,
        error: 0, error_frame: 0, app_error: false, reason: [], peer_closed: false, close_pending: false, close_until: 0, close_triggers: 0,
        idle_timeout: 30000000, last_activity: 0, started: 0, newest: false, now: 0, streams: [],
    };
    var cid: u8[8] = [0; 8];
    entropy::random_bytes(cid);
    c.scid.append(cid);
    // Ours: a 30 s idle timeout, a megabyte of connection window, a
    // stream's buffer per stream, 16 bidirectional streams and 8
    // unidirectional ones (HTTP/3 needs 3), no migration.
    c.local.max_idle_timeout = 30000;
    c.local.initial_max_data = CONN_WINDOW as! u64;
    c.local.initial_max_stream_data_bidi_local = STREAM_BUF as! u64;
    c.local.initial_max_stream_data_bidi_remote = STREAM_BUF as! u64;
    c.local.initial_max_stream_data_uni = STREAM_BUF as! u64;
    c.local.initial_max_streams_bidi = 16;
    c.local.initial_max_streams_uni = 8;
    c.local.disable_active_migration = true;
    c.local.has_initial_scid = true;
    c.local.initial_scid.append(c.scid);
    return c;
}

fn encoded_params(c: const Conn&) -> u8[>..] {
    var out: u8[>..] = [];
    put_params(out, c.local, c.is_server);
    return out;
}

// A client connection to the server cfg names (cfg.alpn must hold a
// protocol, "h3" for HTTP/3); its first datagram comes from poll.
fn client(cfg: const tls::ClientConfig&, now: i64) -> Conn {
    var c = new_conn(false);
    c.now = now;
    c.last_activity = now;
    c.started = now;
    var d: u8[8] = [0; 8];
    entropy::random_bytes(d);
    c.dcid.append(d);
    c.odcid.append(d);
    set_initial_keys(c);
    c.tls = tls::quic_client(cfg, encoded_params(c));
    var out: u8[>..] = [];
    tls::quic_start(c.tls, cfg, out);
    if tls::failed(c.tls) { fail_tls(c); return c; }
    take_tls_output(c, out);
    return c;
}

// A server connection for a client's first Initial packet (the datagram
// it came in): accept tells whether to make one (see server_accepts).
fn server(cfg: const tls::ServerConfig&, first: const u8[:], now: i64) -> Conn {
    var c = new_conn(true);
    c.now = now;
    c.last_activity = now;
    c.started = now;
    let h, ok = read_header(first, 0, CID_LEN);
    c.odcid.append(first[h.dcid_at..h.dcid_at + h.dcid_len]);
    c.dcid.append(first[h.scid_at..h.scid_at + h.scid_len]);
    c.peer_scid.append(c.dcid);
    c.got_peer_scid = true;
    c.local.has_original_dcid = true;
    c.local.original_dcid.append(c.odcid);
    var tok: u8[16] = [0; 16];
    entropy::random_bytes(tok);
    c.local.has_reset_token = true;
    c.local.reset_token = tok;
    set_initial_keys(c);
    c.tls = tls::quic_server(cfg, encoded_params(c));
    return c;
}

// Whether a datagram is a client's Initial a server should make a
// connection for: a long header of version 1, an Initial, at least 1200
// bytes, a Destination Connection ID of at least 8 bytes. A datagram of
// another version gets a Version Negotiation packet (version_negotiation).
fn server_accepts(d: const u8[:]) -> bool {
    let h, ok = read_header(d, 0, CID_LEN);
    return ok && h.long && h.version == VERSION_1 && h.ptype == PT_INITIAL && d.len >= 1200 && h.dcid_len >= 8;
}

// A Version Negotiation packet answering datagram d (a long header of an
// unknown version), offering version 1; empty when d should get none.
fn version_negotiation(d: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let h, ok = read_header(d, 0, CID_LEN);
    if !ok || !h.long || h.version == VERSION_1 || h.version == 0 || d.len < 1200 { return out; }
    var r: u8[1] = [0];
    entropy::random_bytes(r);
    out.push(0x80 | (r[0] & 0x7f));
    put_u32be(out, 0);
    out.push(h.scid_len as! u8);
    out.append(d[h.scid_at..h.scid_at + h.scid_len]);
    out.push(h.dcid_len as! u8);
    out.append(d[h.dcid_at..h.dcid_at + h.dcid_len]);
    put_u32be(out, VERSION_1);
    return out;
}

fn set_initial_keys(c: Conn&) {
    c.wkeys[0] = initial_keys(c.odcid, !c.is_server);
    c.rkeys[0] = initial_keys(c.odcid, c.is_server);
    c.has_wkeys[0] = true;
    c.has_rkeys[0] = true;
}

// --- State the application reads ---------------------------------------------------

fn established(c: const Conn&) -> bool { c.state == STATE_CONNECTED }
fn closed(c: const Conn&) -> bool { c.state == STATE_CLOSED }
fn closing(c: const Conn&) -> bool { c.state == STATE_CLOSING || c.state == STATE_DRAINING || c.state == STATE_CLOSED }
fn alpn(c: const Conn&) -> u8[>..] { tls::alpn(c.tls) }

// The error that closed the connection: its code, whether an
// application's, and the reason given.
fn close_error(c: const Conn&) -> u64, bool, const u8[:] { return c.error, c.app_error, c.reason[..]; }

// --- Records of what packets carried ---------------------------------------------------

fn add_rec(c: Conn&, kind: i64, id: i64, off: i64, len: i64, fin: bool) {
    c.recs[c.rec_head % MAX_RECS] = Rec { kind: kind, id: id, off: off, len: len, fin: fin };
    c.rec_head++;
}

fn level_space(level: u8) -> i64 {
    if level == tls::QUIC_INITIAL { return SPACE_INITIAL; }
    if level == tls::QUIC_HANDSHAKE { return SPACE_HANDSHAKE; }
    return SPACE_APP;
}

fn find_stream(c: const Conn&, id: i64) -> i64 {
    for k in c.streams.len { if c.streams[k].used && c.streams[k].id == id { return k; } }
    return -1;
}

// A sent packet acknowledged or lost: what it carried, settled.
fn settle(c: Conn&, s: const Sent&, acked: bool) {
    for j in s.rec_n {
        if c.rec_head - (s.rec_at + j) > MAX_RECS { continue; }     // overwritten: long gone
        let r = c.recs[(s.rec_at + j) % MAX_RECS];
        if r.kind == REC_CRYPTO {
            if c.discarded[r.id] { continue; }
            if acked { sb_acked(c.crypto_send[r.id], r.off, r.len, false); }
            else { sb_lost(c.crypto_send[r.id], r.off, r.len, false); }
        } else if r.kind == REC_STREAM {
            let k = find_stream(c, r.id);
            if k < 0 || c.streams[k].reset_send { continue; }
            if acked { sb_acked(c.streams[k].send, r.off, r.len, r.fin); }
            else { sb_lost(c.streams[k].send, r.off, r.len, r.fin); }
        } else if !acked {
            // Control frames: the current value is sent again.
            if r.kind == REC_HANDSHAKE_DONE { c.handshake_done_pending = true; }
            if r.kind == REC_MAX_DATA { c.max_data_update = true; }
            if r.kind == REC_MAX_STREAMS { c.max_streams_update = true; }
            let k = find_stream(c, r.id);
            if k >= 0 && r.kind == REC_MAX_STREAM_DATA { c.streams[k].max_update = true; }
            if k >= 0 && r.kind == REC_RESET { c.streams[k].reset_pending = true; }
            if k >= 0 && r.kind == REC_STOP { c.streams[k].stop_send = true; }
            if r.kind == REC_RETIRE && c.retire_lost.len < MAX_RETIRE { c.retire_lost.push(r.id as! u64); }
        }
    }
}

// --- Closing ---------------------------------------------------------------

fn pto(c: const Conn&) -> i64 { pto_base(c.rec) + c.rec.max_ack_delay }

// Closes the connection with a transport error (app false) or an
// application's (app true): a CONNECTION_CLOSE goes out, then the
// connection waits three PTOs, answering what still arrives (§10.2.1).
fn close_with(c: Conn&, code: u64, frame_type: u64, app: bool, reason: const u8[:]) {
    if closing(c) { return; }
    c.error = code;
    c.error_frame = frame_type;
    c.app_error = app;
    c.reason.clear();
    c.reason.append(reason[..::min(reason.len, 255)]);
    c.state = STATE_CLOSING;
    c.close_pending = true;
    c.close_until = c.now + 3 * pto(c);
}

fn close(c: Conn&, code: u64, reason: const u8[:]) { close_with(c, code, 0, true, reason); }

fn fail(c: Conn&, code: u64, frame_type: u64, reason: const u8[:]) { close_with(c, code, frame_type, false, reason); }

fn fail_tls(c: Conn&) {
    let a: u64 = c.tls.alert;
    fail(c, CRYPTO_ERROR + a, 0x06, "TLS");
}

fn drain(c: Conn&) {
    if c.state == STATE_CLOSED || c.state == STATE_DRAINING { return; }
    c.state = STATE_DRAINING;
    c.close_pending = false;
    c.close_until = c.now + 3 * pto(c);
}

// --- TLS --------------------------------------------------------------------

// TLS's chunks into the CRYPTO streams of their levels.
fn take_tls_output(c: Conn&, out: const u8[:]) {
    var at = 0;
    loop {
        let level, off, n, next, ok = tls::quic_next_chunk(out, at);
        if !ok { break; }
        let sp = level_space(level);
        let took = sb_write(c.crypto_send[sp], out[off..off + n]);
        if took != n { fail(c, CRYPTO_BUFFER_EXCEEDED, 0x06, "handshake too large"); return; }
        at = next;
    }
}

// New TLS secrets become keys; the handshake's end is acted on.
fn take_tls_keys(c: Conn&) {
    let s = tls::quic_suite(c.tls);
    if !c.has_wkeys[1] && !c.discarded[1] && tls::quic_write_level(c.tls) >= tls::QUIC_HANDSHAKE {
        c.wkeys[1] = keys_from_secret(s, tls::quic_secret(c.tls, tls::QUIC_HANDSHAKE, true));
        c.has_wkeys[1] = true;
    }
    if !c.has_rkeys[1] && !c.discarded[1] && tls::quic_read_level(c.tls) >= tls::QUIC_HANDSHAKE {
        c.rkeys[1] = keys_from_secret(s, tls::quic_secret(c.tls, tls::QUIC_HANDSHAKE, false));
        c.has_rkeys[1] = true;
    }
    if !c.has_wkeys[2] && tls::quic_write_level(c.tls) >= tls::QUIC_APPLICATION {
        c.wkeys[2] = keys_from_secret(s, tls::quic_secret(c.tls, tls::QUIC_APPLICATION, true));
        c.next_wkeys = next_keys(c.wkeys[2]);
        c.has_wkeys[2] = true;
    }
    if !c.has_rkeys[2] && tls::quic_read_level(c.tls) >= tls::QUIC_APPLICATION {
        c.rkeys[2] = keys_from_secret(s, tls::quic_secret(c.tls, tls::QUIC_APPLICATION, false));
        c.next_rkeys = next_keys(c.rkeys[2]);
        c.has_rkeys[2] = true;
    }
    if c.state == STATE_HANDSHAKE && tls::connected(c.tls) { handshake_complete(c); }
}

fn same(a: const u8[:], b: const u8[:]) -> bool { a == b }

// The handshake is done: the peer's transport parameters checked and
// taken (§7.3), the server's HANDSHAKE_DONE queued.
fn handshake_complete(c: Conn&) {
    let raw, has = tls::quic_peer_params(c.tls);
    let p, e = read_params(raw, !c.is_server);
    if !has || e != 0 { fail(c, TRANSPORT_PARAMETER_ERROR, 0, "transport parameters"); return; }
    if !p.has_initial_scid || !same(p.initial_scid, c.peer_scid) { fail(c, TRANSPORT_PARAMETER_ERROR, 0, "initial_source_connection_id"); return; }
    if !c.is_server {
        if !p.has_original_dcid || !same(p.original_dcid, c.odcid) { fail(c, TRANSPORT_PARAMETER_ERROR, 0, "original_destination_connection_id"); return; }
        if p.has_retry_scid != c.retried || (c.retried && !same(p.retry_scid, c.retry_scid)) {
            fail(c, TRANSPORT_PARAMETER_ERROR, 0, "retry_source_connection_id");
            return;
        }
        if p.has_reset_token { c.peer_reset_token = p.reset_token; c.has_reset_token = true; }
    }
    c.peer = p;
    c.has_peer_params = true;
    c.max_data_send = p.initial_max_data as! i64;
    c.max_streams_bidi_send = p.initial_max_streams_bidi as! i64;
    c.max_streams_uni_send = p.initial_max_streams_uni as! i64;
    c.rec.max_ack_delay = (p.max_ack_delay as! i64) * 1000;
    // The idle timeout: the smaller of the two that are set (§10.1).
    let peer_idle = (::min(p.max_idle_timeout, 1 << 40) as! i64) * 1000;      // ms, 2^62 at most: capped
    if peer_idle > 0 && peer_idle < c.idle_timeout { c.idle_timeout = peer_idle; }
    c.state = STATE_CONNECTED;
    if c.is_server {
        c.handshake_done_pending = true;
        c.confirmed = true;
        discard_keys(c, 1);
    }
}

fn discard_keys(c: Conn&, sp: i64) {
    if c.discarded[sp] { return; }
    c.discarded[sp] = true;
    c.has_wkeys[sp] = false;
    c.has_rkeys[sp] = false;
    c.spaces[sp].ack_needed = false;
    discard_space(c.rec, sp);
}

// --- Streams ------------------------------------------------------------------

fn is_local(c: const Conn&, id: i64) -> bool { (id & 1 == 1) == c.is_server }
fn is_uni(id: i64) -> bool { id & 2 == 2 }

// The limits a stream starts with (§18.2): what we may send on it, and
// what we let the peer send.
fn stream_limits(c: const Conn&, id: i64) -> i64, i64 {
    let local = is_local(c, id);
    var send: i64 = 0;
    var recv: i64 = 0;
    if is_uni(id) {
        if local { send = c.peer.initial_max_stream_data_uni as! i64; }
        else { recv = c.local.initial_max_stream_data_uni as! i64; }
    } else if local {
        send = c.peer.initial_max_stream_data_bidi_remote as! i64;
        recv = c.local.initial_max_stream_data_bidi_local as! i64;
    } else {
        send = c.peer.initial_max_stream_data_bidi_local as! i64;
        recv = c.local.initial_max_stream_data_bidi_remote as! i64;
    }
    return send, recv;
}

fn add_stream(c: Conn&, id: i64) -> i64 {
    if c.streams.len >= MAX_STREAMS_HERE {
        // Reuse a slot whose stream is over both ways.
        for k in c.streams.len {
            if !c.streams[k].used {
                let ms, mr = stream_limits(c, id);
                c.streams[k] = new_stream(id, ms, mr);
                return k;
            }
        }
        return -1;
    }
    let ms, mr = stream_limits(c, id);
    c.streams.push(new_stream(id, ms, mr));
    return c.streams.len - 1;
}

// Opens a stream of ours: bidirectional or unidirectional. Its id, or -1
// while the peer's limit on streams (or this side's table) is reached.
fn open_stream(c: Conn&, bidi: bool) -> i64 {
    if c.state != STATE_CONNECTED { return -1; }
    let n = if bidi { c.streams_bidi_opened } else { c.streams_uni_opened };
    let limit = if bidi { c.max_streams_bidi_send } else { c.max_streams_uni_send };
    if n >= limit { return -1; }
    let id = n * 4 + (if bidi { 0 } else { 2 }) + (if c.is_server { 1 } else { 0 });
    if add_stream(c, id) < 0 { return -1; }
    if bidi { c.streams_bidi_opened++; } else { c.streams_uni_opened++; }
    let k = find_stream(c, id);
    c.streams[k].accepted = true;
    return id;
}

// A stream the peer opened that the application has not taken yet, or -1.
fn accept_stream(c: Conn&) -> i64 {
    var best: i64 = -1;
    var at: i64 = -1;
    for k in c.streams.len {
        if c.streams[k].used && !c.streams[k].accepted && (best < 0 || c.streams[k].id < best) { best = c.streams[k].id; at = k; }
    }
    if at >= 0 { c.streams[at].accepted = true; }
    return best;
}

// Writes on a stream: the bytes taken (fewer when its buffer is full),
// -1 for no such stream or one we cannot send on. fin ends the stream once
// all of data is taken.
fn stream_write(c: Conn&, id: i64, data: const u8[:], fin: bool) -> i64 {
    let k = find_stream(c, id);
    if k < 0 || (is_uni(id) && !is_local(c, id)) || c.streams[k].reset_send || closing(c) { return -1; }
    let n = sb_write(c.streams[k].send, data);
    if fin && n == data.len { sb_finish(c.streams[k].send); }
    return n;
}

// Reads what a stream has in order into out (at most max bytes): how
// many, or -1 for no such stream. Credit goes back to the peer as it is read.
fn stream_read(c: Conn&, id: i64, out: u8[>..]&, max: i64) -> i64 {
    let k = find_stream(c, id);
    if k < 0 { return -1; }
    let n = rb_read(c.streams[k].recv, out, max);
    c.streams[k].read += n;
    c.data_read += n;
    // More window once half of it is used (§4.2).
    if !rb_fin_known(c.streams[k].recv) && c.streams[k].max_recv - c.streams[k].read < STREAM_BUF / 2 {
        c.streams[k].max_recv = c.streams[k].read + STREAM_BUF;
        c.streams[k].max_update = true;
    }
    if c.max_data_recv - c.data_read < CONN_WINDOW / 2 {
        c.max_data_recv = c.data_read + CONN_WINDOW;
        c.max_data_update = true;
    }
    forget_if_done(c, k);
    return n;
}

// Whether the stream's peer side is over: all read up to its end, or reset.
fn stream_finished(c: const Conn&, id: i64) -> bool {
    let k = find_stream(c, id);
    if k < 0 { return true; }
    return rb_finished(c.streams[k].recv) || c.streams[k].reset_recv;
}

fn stream_readable(c: const Conn&, id: i64) -> i64 {
    let k = find_stream(c, id);
    if k < 0 { return 0; }
    return rb_readable(c.streams[k].recv);
}

// The error code the peer reset a stream with, and whether it did.
fn stream_reset_by_peer(c: const Conn&, id: i64) -> u64, bool {
    let k = find_stream(c, id);
    if k < 0 { return 0, false; }
    return c.streams[k].reset_code, c.streams[k].reset_recv;
}

// Abandons sending on a stream (RESET_STREAM) and/or reading (STOP_SENDING).
fn reset_stream(c: Conn&, id: i64, code: u64) {
    let k = find_stream(c, id);
    if k < 0 || c.streams[k].reset_send { return; }
    c.streams[k].reset_send = true;
    c.streams[k].reset_sent_code = code;
    c.streams[k].reset_pending = true;
}

fn stop_sending(c: Conn&, id: i64, code: u64) {
    let k = find_stream(c, id);
    if k < 0 { return; }
    c.streams[k].stop_send = true;
    c.streams[k].stop_code = code;
}

// A stream done both ways leaves the table; the peer may then open
// another (MAX_STREAMS).
fn forget_if_done(c: Conn&, k: i64) {
    let s = c.streams[k];
    let id = s.id;
    let recv_done = (is_uni(id) && is_local(c, id)) || rb_finished(s.recv) || s.reset_recv;
    let send_done = (is_uni(id) && !is_local(c, id)) || sb_all_acked(s.send) || (s.reset_send && !s.reset_pending);
    if !recv_done || !send_done || !s.accepted { return; }
    c.streams[k].used = false;
    if !is_local(c, id) {
        if is_uni(id) { c.max_streams_uni_recv++; } else { c.max_streams_bidi_recv++; }
        c.max_streams_update = true;
    }
}

// --- Receiving -----------------------------------------------------------------

fn space_level(sp: i64) -> u8 {
    if sp == SPACE_INITIAL { return tls::QUIC_INITIAL; }
    if sp == SPACE_HANDSHAKE { return tls::QUIC_HANDSHAKE; }
    return tls::QUIC_APPLICATION;
}

fn space_ptype(sp: i64) -> u8 {
    if sp == SPACE_INITIAL { return PT_INITIAL; }
    if sp == SPACE_HANDSHAKE { return PT_HANDSHAKE; }
    return PT_ONE_RTT;
}

// Whether pn was received already in the space; below the floor, where
// the history no longer reaches, every number is taken as received, so
// that an old packet replayed is dropped.
fn seen_pn(s: const Space&, pn: i64) -> bool {
    if pn < s.floor { return true; }
    var i = 0;
    while i + 1 < 2 * s.n_recv {
        if pn >= s.recv[i] && pn <= s.recv[i + 1] { return true; }
        i += 2;
    }
    return false;
}

// Adds pn to the received ranges, highest first, merging neighbours; at
// most 32 ranges: when full, the lowest is dropped and the floor raised
// above it, and a pn below every range is not kept at all.
fn note_pn(s: Space&, pn: i64) {
    var n = s.n_recv;
    // Find where it goes: ranges are (lo, hi), highest first.
    var i = 0;
    while i < n && s.recv[2 * i] > pn + 1 { i++; }
    if i < n && pn >= s.recv[2 * i] - 1 && pn <= s.recv[2 * i + 1] + 1 {
        if pn < s.recv[2 * i] { s.recv[2 * i] = pn; }
        if pn > s.recv[2 * i + 1] { s.recv[2 * i + 1] = pn; }
        // Merge with the next lower range when they now touch.
        if i + 1 < n && s.recv[2 * (i + 1) + 1] + 1 >= s.recv[2 * i] {
            s.recv[2 * i] = s.recv[2 * (i + 1)];
            var j = i + 1;
            while j + 1 < n { s.recv[2 * j] = s.recv[2 * (j + 1)]; s.recv[2 * j + 1] = s.recv[2 * (j + 1) + 1]; j++; }
            n--;
        }
        // And with the higher one.
        if i > 0 && s.recv[2 * i + 1] + 1 >= s.recv[2 * (i - 1)] {
            s.recv[2 * (i - 1)] = s.recv[2 * i];
            var j = i;
            while j + 1 < n { s.recv[2 * j] = s.recv[2 * (j + 1)]; s.recv[2 * j + 1] = s.recv[2 * (j + 1) + 1]; j++; }
            n--;
        }
        s.n_recv = n;
        return;
    }
    if n == 32 {
        if i == 32 { s.floor = ::max(s.floor, pn + 1); return; }
        s.floor = s.recv[2 * 31 + 1] + 1;        // the lowest range goes
        n = 31;
    }
    var j = n;
    while j > i { s.recv[2 * j] = s.recv[2 * (j - 1)]; s.recv[2 * j + 1] = s.recv[2 * (j - 1) + 1]; j--; }
    s.recv[2 * i] = pn;
    s.recv[2 * i + 1] = pn;
    s.n_recv = n + 1;
}

// A datagram received at now: each packet in it opened and its frames
// handled. cfg is TLS's configuration, the client's or the server's.
fn recv(c: Conn&, cfg, d: const u8[:], now: i64) {
    c.now = now;
    c.newest = false;
    if c.state == STATE_CLOSED || c.state == STATE_DRAINING { return; }
    if !c.validated { c.bytes_recv += d.len; }
    var at = 0;
    while at < d.len {
        let h, ok = read_header(d, at, CID_LEN);
        if !ok { return; }
        let next = if h.long { h.end } else { d.len };
        if h.long && h.version == 0 { version_negotiation_received(c, d, h); return; }
        if h.long && h.version != VERSION_1 { return; }
        let dcid = d[h.dcid_at..h.dcid_at + h.dcid_len];
        let to_us = dcid == c.scid[..] || (c.is_server && h.long && dcid == c.odcid[..]);
        if !to_us { at = next; continue; }
        if h.long && h.ptype == PT_RETRY { retry_received(c, d, h); return; }
        if h.long && h.ptype == PT_ZERO_RTT { at = next; continue; }
        let sp = if !h.long { SPACE_APP } else if h.ptype == PT_INITIAL { SPACE_INITIAL } else { SPACE_HANDSHAKE };
        if !c.has_rkeys[sp] { at = next; continue; }
        var pkt: u8[>..] = [];
        pkt.append(d[at..next]);
        let pn_at = h.pn_at - at;
        let largest = c.spaces[sp].largest_recv;
        var pn: i64 = 0;
        var hdr_end: i64 = 0;
        var opened = false;
        var copy1: u8[>..] = [];
        copy1.append(pkt);
        pn, hdr_end, opened = open(c.rkeys[sp], copy1, pn_at, copy1.len, largest);
        if opened {
            pkt = copy(copy1);
            // A packet with the other key phase under the current keys
            // cannot open; the phase bit must agree with the keys used.
            if !h.long && ((pkt[0] & 0x04) != 0) != c.key_phase { opened = false; }
        }
        if !opened && !h.long {
            // A key update by the peer (§6.2), or a packet from before one.
            var copy2: u8[>..] = [];
            copy2.append(d[at..next]);
            let pn2, he2, ok2 = open(c.next_rkeys, copy2, pn_at, copy2.len, largest);
            if ok2 && ((copy2[0] & 0x04) != 0) != c.key_phase {
                rotate_keys(c);
                pkt = copy(copy2);
                pn = pn2;
                hdr_end = he2;
                opened = true;
            } else if c.has_prev {
                var copy3: u8[>..] = [];
                copy3.append(d[at..next]);
                let pn3, he3, ok3 = open(c.prev_rkeys, copy3, pn_at, copy3.len, largest);
                if ok3 { pkt = copy(copy3); pn = pn3; hdr_end = he3; opened = true; }
            }
        }
        if !opened {
            // A stateless reset ends in the peer's token (§10.3.1).
            if !h.long && c.has_reset_token && d.len >= 21 && bignum::ct_eq_bytes(d[d.len - 16..], c.peer_reset_token) == 1 {
                c.error = NO_ERROR;
                c.reason.clear();
                c.reason.append("stateless reset");
                c.state = STATE_CLOSED;
                return;
            }
            at = next;
            continue;
        }
        // The reserved bits must be zero once unprotected (§17.2, §17.3).
        let reserved = if h.long { pkt[0] & 0x0c } else { pkt[0] & 0x18 };
        if reserved != 0 { fail(c, PROTOCOL_VIOLATION, 0, "reserved bits"); return; }
        if seen_pn(c.spaces[sp], pn) { at = next; continue; }
        c.last_activity = now;
        if c.is_server && sp == SPACE_HANDSHAKE {
            // A Handshake packet proves the client's address; the Initial
            // keys go (§4.9.1, §8.1).
            c.validated = true;
            c.rec.peer_completed_address_validation = true;
            discard_keys(c, SPACE_INITIAL);
        }
        if !c.is_server && h.long && !c.got_peer_scid {
            // The server's Source Connection ID becomes ours to send to.
            c.dcid.clear();
            c.dcid.append(d[h.scid_at..h.scid_at + h.scid_len]);
            c.peer_scid.clear();
            c.peer_scid.append(c.dcid);
            c.got_peer_scid = true;
        }
        if !c.is_server && sp == SPACE_HANDSHAKE { c.rec.peer_completed_address_validation = true; }
        let payload = pkt[hdr_end..pkt.len - 16];
        if payload.len == 0 { fail(c, PROTOCOL_VIOLATION, 0, "an empty packet"); return; }
        let eliciting = handle_frames(c, cfg, sp, payload);
        if closing(c) && c.state != STATE_CLOSING { return; }
        if c.state == STATE_CLOSING && !c.peer_closed {
            // CONNECTION_CLOSE again, but less and less often (§10.2.1): a
            // peer that keeps sending is not answered packet for packet.
            c.close_triggers++;
            if (c.close_triggers & (c.close_triggers - 1)) == 0 { c.close_pending = true; }
            return;
        }
        // The handshake may have ended in this packet, its keys gone with
        // it: then there is nothing to acknowledge in that space any more.
        if c.discarded[sp] { at = next; continue; }
        note_pn(c.spaces[sp], pn);
        if pn > c.spaces[sp].largest_recv {
            c.spaces[sp].largest_recv = pn;
            c.spaces[sp].largest_recv_time = now;
            c.newest = true;
        }
        if eliciting {
            c.spaces[sp].ack_needed = true;
            c.spaces[sp].eliciting_unacked++;
            if c.spaces[sp].ack_deadline == 0 { c.spaces[sp].ack_deadline = now + (if sp == SPACE_APP { c.local.max_ack_delay as! i64 * 1000 } else { 0 }); }
        }
        at = next;
    }
}

fn version_negotiation_received(c: Conn&, d: const u8[:], h: const Header&) {
    // Only a client, before anything else from the server; one that lists
    // version 1 is ignored (§6.2).
    if c.is_server || c.got_peer_scid { return; }
    var p = h.token_at;
    while p + 4 <= d.len {
        if u32be(d, p) == VERSION_1 { return; }
        p += 4;
    }
    c.error = CONNECTION_REFUSED;
    c.reason.clear();
    c.reason.append("no version in common");
    c.state = STATE_CLOSED;
}

fn retry_received(c: Conn&, d: const u8[:], h: const Header&) {
    if c.is_server || c.retried || c.got_peer_scid || h.token_len <= 16 { return; }
    if h.token_len - 16 > c.token.cap { return; }        // a token longer than any we keep: ignored
    // A Retry naming the client's own Destination Connection ID as its
    // Source is not from the server (§17.2.5.2).
    if d[h.scid_at..h.scid_at + h.scid_len] == c.dcid[..] { return; }
    let tag = retry_tag(c.odcid, d[..d.len - 16]);
    if tag[..] != d[d.len - 16..] { return; }
    c.retried = true;
    c.token.clear();
    c.token.append(d[h.token_at..d.len - 16]);
    c.dcid.clear();
    c.dcid.append(d[h.scid_at..h.scid_at + h.scid_len]);
    c.retry_scid.clear();
    c.retry_scid.append(c.dcid);
    // New Initial keys from the new Destination Connection ID; the
    // ClientHello goes again (§17.2.5.2).
    c.wkeys[0] = initial_keys(c.dcid, true);
    c.rkeys[0] = initial_keys(c.dcid, false);
    discard_space(c.rec, SPACE_INITIAL);
    let cs = c.crypto_send[0];
    sb_lost(c.crypto_send[0], cs.base, cs.sent_upto - cs.base, false);
}

// The frames of a packet in space sp: whether any was ack-eliciting.
fn handle_frames(c: Conn&, cfg, sp: i64, b: const u8[:]) -> bool {
    var at = 0;
    var eliciting = false;
    let pt = space_ptype(sp);
    while at < b.len && !closing(c) {
        let f, next, err = read_frame(b, at);
        if err != 0 { fail(c, err, 0, "a frame"); return eliciting; }
        if !frame_allowed(f.ftype, pt) { fail(c, PROTOCOL_VIOLATION, f.ftype, "a frame not allowed here"); return eliciting; }
        if ack_eliciting(f.ftype) { eliciting = true; }
        handle_frame(c, cfg, sp, b, f);
        at = next;
    }
    return eliciting;
}

fn handle_frame(c: Conn&, cfg, sp: i64, b: const u8[:], f: const Frame&) {
    let t = f.ftype;
    if t == FT_PADDING || t == FT_PING { return; }
    if t == FT_ACK || t == FT_ACK + 1 { ack_frame(c, sp, b, f); return; }
    if t == FT_CRYPTO { crypto_frame(c, cfg, sp, b[f.data_at..f.data_at + f.length], f.offset as! i64); return; }
    if is_stream_type(t) { stream_frame(c, f.stream_id as! i64, f.offset as! i64, b[f.data_at..f.data_at + f.length], f.fin); return; }
    if t == FT_HANDSHAKE_DONE {
        if c.is_server { fail(c, PROTOCOL_VIOLATION, t, "HANDSHAKE_DONE to a server"); return; }
        c.confirmed = true;
        discard_keys(c, SPACE_HANDSHAKE);
        return;
    }
    if t == FT_CONNECTION_CLOSE || t == FT_APPLICATION_CLOSE {
        c.error = f.error_code;
        c.app_error = t == FT_APPLICATION_CLOSE;
        c.reason.clear();
        c.reason.append(b[f.data_at..f.data_at + ::min(f.length, 255)]);
        c.peer_closed = true;
        drain(c);
        return;
    }
    if t == FT_MAX_DATA { if f.max as! i64 > c.max_data_send { c.max_data_send = f.max as! i64; } return; }
    if t == FT_MAX_STREAMS_BIDI { if f.max as! i64 > c.max_streams_bidi_send { c.max_streams_bidi_send = f.max as! i64; } return; }
    if t == FT_MAX_STREAMS_UNI { if f.max as! i64 > c.max_streams_uni_send { c.max_streams_uni_send = f.max as! i64; } return; }
    if t == FT_MAX_STREAM_DATA {
        let id = f.stream_id as! i64;
        if is_uni(id) && !is_local(c, id) { fail(c, STREAM_STATE_ERROR, t, "MAX_STREAM_DATA on a receive-only stream"); return; }
        let k = peer_stream(c, id, t);
        if k >= 0 && f.max as! i64 > c.streams[k].max_send { c.streams[k].max_send = f.max as! i64; }
        return;
    }
    if t == FT_RESET_STREAM {
        let id = f.stream_id as! i64;
        if is_uni(id) && is_local(c, id) { fail(c, STREAM_STATE_ERROR, t, "RESET_STREAM on a send-only stream"); return; }
        let k = peer_stream(c, id, t);
        if k < 0 { return; }
        let fs = f.final_size as! i64;
        let known = rb_final_size(c.streams[k].recv);
        if (known >= 0 && known != fs) || fs < rb_highest(c.streams[k].recv) { fail(c, FINAL_SIZE_ERROR, t, "final size"); return; }
        c.data_recv += fs - rb_highest(c.streams[k].recv);
        if c.data_recv > c.max_data_recv { fail(c, FLOW_CONTROL_ERROR, t, "connection window"); return; }
        c.streams[k].reset_recv = true;
        c.streams[k].reset_code = f.error_code;
        forget_if_done(c, k);
        return;
    }
    if t == FT_STOP_SENDING {
        let id = f.stream_id as! i64;
        if is_uni(id) && !is_local(c, id) { fail(c, STREAM_STATE_ERROR, t, "STOP_SENDING on a receive-only stream"); return; }
        let k = peer_stream(c, id, t);
        if k < 0 { return; }
        c.streams[k].stopped = true;
        reset_stream(c, id, f.error_code);
        return;
    }
    if t == FT_NEW_TOKEN {
        if c.is_server { fail(c, PROTOCOL_VIOLATION, t, "NEW_TOKEN to a server"); }
        return;
    }
    if t == FT_NEW_CONNECTION_ID {
        if c.dcid.len == 0 { fail(c, PROTOCOL_VIOLATION, t, "NEW_CONNECTION_ID with a zero-length ID"); return; }
        // The ID is not used (no migration), but one that retires the
        // current one is moved to, and the old one retired.
        if f.retire_prior_to > c.retire_seq && f.retire_prior_to - c.retire_seq > MAX_RETIRE as! u64 {
            fail(c, CONNECTION_ID_LIMIT_ERROR, t, "NEW_CONNECTION_ID retires too many connection IDs");
            return;
        }
        if f.retire_prior_to > c.retire_seq && f.seq >= f.retire_prior_to {
            c.dcid.clear();
            c.dcid.append(b[f.cid_at..f.cid_at + f.cid_len]);
            c.peer_reset_token = [0; 16];
            for i in 16 { c.peer_reset_token[i] = b[f.token_at + i]; }
            c.has_reset_token = true;
            c.retire_pending = (f.retire_prior_to - c.retire_seq) as! i64;
        }
        return;
    }
    if t == FT_RETIRE_CONNECTION_ID {
        if f.seq > 0 { fail(c, PROTOCOL_VIOLATION, t, "RETIRE_CONNECTION_ID of an ID never issued"); }
        return;
    }
    if t == FT_PATH_CHALLENGE {
        for i in 8 { c.path_response[i] = b[f.data_at + i]; }
        c.path_response_pending = true;
        return;
    }
    // PATH_RESPONSE, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED:
    // nothing to do.
}

fn ack_frame(c: Conn&, sp: i64, b: const u8[:], f: const Frame&) {
    var pairs: u64[>..] = [];
    ack_ranges(b, f, pairs);
    var ranges: i64[>..] = [];
    var i = 0;
    while i + 1 < pairs.len {
        ranges.push(pairs[i + 1] as! i64);
        ranges.push(pairs[i] as! i64);
        i += 2;
    }
    // The delay saturates: a peer's 2^62 shifted would wrap negative.
    let delay = if sp == SPACE_APP { (::min(f.ack_delay, 1 << 40) << c.peer.ack_delay_exponent) as! i64 } else { 0 };
    var done: Sent[>..] = [];
    var acks: bool[>..] = [];
    let ok = on_ack_received(c.rec, sp, ranges, delay, c.now, c.confirmed, c.spaces[sp].next_pn) { s, acked =>
        done.push(s);
        acks.push(acked);
    };
    if !ok { fail(c, PROTOCOL_VIOLATION, f.ftype, "an ACK of a packet never sent"); return; }
    for j in done.len { settle(c, done[j], acks[j]); }
    for k in c.streams.len { if c.streams[k].used { forget_if_done(c, k); } }
}

fn crypto_frame(c: Conn&, cfg, sp: i64, data: const u8[:], off: i64) {
    if c.discarded[sp] { return; }
    let e = rb_insert(c.crypto_recv[sp], off, data, false);
    if e != 0 { fail(c, CRYPTO_BUFFER_EXCEEDED, FT_CRYPTO, "handshake data"); return; }
    if rb_readable(c.crypto_recv[sp]) == 0 { return; }
    var buf: u8[>..] = [];
    let n = rb_read(c.crypto_recv[sp], buf, STREAM_BUF);
    var out: u8[>..] = [];
    let r = tls::feed_crypto(c.tls, cfg, space_level(sp), buf, out);
    take_tls_output(c, out);
    if r != 0 { fail_tls(c); return; }
    take_tls_keys(c);
}

// The table index of the stream a frame names, making the peer's streams
// up to it (§3.2); -1 for one already over (the frame is then ignored).
// A stream of ours not opened yet, or a peer's past our limit, fails the
// connection.
fn peer_stream(c: Conn&, id: i64, frame_type: u64) -> i64 {
    let k = find_stream(c, id);
    if k >= 0 { return k; }
    let n = id / 4;
    if is_local(c, id) {
        let opened = if is_uni(id) { c.streams_uni_opened } else { c.streams_bidi_opened };
        if n >= opened { fail(c, STREAM_STATE_ERROR, frame_type, "a stream not opened"); }
        return -1;
    }
    let limit = if is_uni(id) { c.max_streams_uni_recv } else { c.max_streams_bidi_recv };
    if n >= limit { fail(c, STREAM_LIMIT_ERROR, frame_type, "too many streams"); return -1; }
    let seen = if is_uni(id) { c.peer_uni_opened } else { c.peer_bidi_opened };
    if n < seen { return -1; }                      // opened before and over
    var j = seen;
    var at: i64 = -1;
    while j <= n {
        let sid = j * 4 + (id & 3);
        let slot = add_stream(c, sid);
        if slot < 0 { fail(c, STREAM_LIMIT_ERROR, frame_type, "too many streams held"); return -1; }
        if sid == id { at = slot; }
        j++;
    }
    if is_uni(id) { c.peer_uni_opened = n + 1; } else { c.peer_bidi_opened = n + 1; }
    return at;
}

fn stream_frame(c: Conn&, id: i64, off: i64, data: const u8[:], fin: bool) {
    if is_uni(id) && is_local(c, id) { fail(c, STREAM_STATE_ERROR, 0x08, "STREAM on a send-only stream"); return; }
    let k = peer_stream(c, id, 0x08);
    if k < 0 { return; }
    // The window we advertised for the stream, not only the buffer's (§4.1).
    if off + data.len > c.streams[k].max_recv { fail(c, FLOW_CONTROL_ERROR, 0x08, "stream window"); return; }
    let before = rb_highest(c.streams[k].recv);
    let e = rb_insert(c.streams[k].recv, off, data, fin);
    if e != 0 { fail(c, e, 0x08, "stream data"); return; }
    c.data_recv += rb_highest(c.streams[k].recv) - before;
    if c.data_recv > c.max_data_recv { fail(c, FLOW_CONTROL_ERROR, 0x08, "connection window"); }
}

// --- Sending ---------------------------------------------------------------------

// The ACK frame for a space, its received ranges as (largest, smallest).
fn put_space_ack(c: Conn&, sp: i64, out: u8[>..]&) {
    let s = c.spaces[sp];
    var pairs: u64[>..] = [];
    for i in s.n_recv {
        pairs.push(s.recv[2 * i + 1] as! u64);
        pairs.push(s.recv[2 * i] as! u64);
    }
    var delay: u64 = 0;
    if sp == SPACE_APP && c.now > s.largest_recv_time {
        delay = ((c.now - s.largest_recv_time) as! u64) >> c.local.ack_delay_exponent;
    }
    put_ack(out, pairs, delay, false, 0, 0, 0);
    c.spaces[sp].ack_needed = false;
    c.spaces[sp].eliciting_unacked = 0;
    c.spaces[sp].ack_deadline = 0;
}

// Whether an ACK is due in a space now.
fn ack_due(c: const Conn&, sp: i64) -> bool {
    let s = c.spaces[sp];
    if !s.ack_needed { return false; }
    if sp != SPACE_APP { return true; }
    return s.eliciting_unacked >= 2 || c.now >= s.ack_deadline;
}

// The frames of one packet in space sp, at most room bytes; the records
// of what it carries start at rec_at. Whether it is ack-eliciting.
fn build_payload(c: Conn&, sp: i64, room: i64, out: u8[>..]&, force_ack: bool) -> bool {
    var eliciting = false;
    if c.spaces[sp].n_recv > 0 && (ack_due(c, sp) || force_ack || c.spaces[sp].ack_needed) { put_space_ack(c, sp, out); }
    // CRYPTO data, lost first.
    loop {
        let left = room - out.len - 24;
        if left <= 0 { break; }
        let off, len, fin, ok = sb_next(c.crypto_send[sp], left, 0x3fffffffffffffff);
        if !ok || len == 0 { break; }
        put_crypto(out, off as! u64, sb_bytes(c.crypto_send[sp], off, len));
        sb_sent(c.crypto_send[sp], off, len, false);
        add_rec(c, REC_CRYPTO, sp, off, len, false);
        eliciting = true;
    }
    if sp == SPACE_APP && c.has_wkeys[2] && (c.state == STATE_CONNECTED || c.is_server) {
        if c.handshake_done_pending && c.is_server && c.state == STATE_CONNECTED {
            put_handshake_done(out);
            add_rec(c, REC_HANDSHAKE_DONE, 0, 0, 0, false);
            c.handshake_done_pending = false;
            eliciting = true;
        }
        if c.max_data_update {
            put_max_data(out, c.max_data_recv as! u64);
            add_rec(c, REC_MAX_DATA, 0, 0, 0, false);
            c.max_data_update = false;
            eliciting = true;
        }
        if c.max_streams_update {
            put_max_streams(out, true, c.max_streams_bidi_recv as! u64);
            put_max_streams(out, false, c.max_streams_uni_recv as! u64);
            add_rec(c, REC_MAX_STREAMS, 0, 0, 0, false);
            c.max_streams_update = false;
            eliciting = true;
        }
        if c.path_response_pending {
            put_path_response(out, c.path_response);
            c.path_response_pending = false;
            eliciting = true;
        }
        while c.retire_lost.len > 0 && out.len + 16 <= room {
            let seq = c.retire_lost.pop();
            put_retire_connection_id(out, seq);
            add_rec(c, REC_RETIRE, seq as! i64, 0, 0, false);
            eliciting = true;
        }
        while c.retire_pending > 0 && out.len + 16 <= room {
            put_retire_connection_id(out, c.retire_seq);
            add_rec(c, REC_RETIRE, c.retire_seq as! i64, 0, 0, false);
            c.retire_seq++;
            c.retire_pending--;
            eliciting = true;
        }
        for k in c.streams.len {
            if !c.streams[k].used || out.len + 64 > room { continue; }
            let id = c.streams[k].id;
            if c.streams[k].reset_pending {
                put_reset_stream(out, id as! u64, c.streams[k].reset_sent_code, sb_end(c.streams[k].send) as! u64);
                add_rec(c, REC_RESET, id, 0, 0, false);
                c.streams[k].reset_pending = false;
                eliciting = true;
            }
            if c.streams[k].stop_send {
                put_stop_sending(out, id as! u64, c.streams[k].stop_code);
                add_rec(c, REC_STOP, id, 0, 0, false);
                c.streams[k].stop_send = false;
                eliciting = true;
            }
            if c.streams[k].max_update {
                put_max_stream_data(out, id as! u64, c.streams[k].max_recv as! u64);
                add_rec(c, REC_MAX_STREAM_DATA, id, 0, 0, false);
                c.streams[k].max_update = false;
                eliciting = true;
            }
        }
        // Stream data, within the congestion window and both limits.
        for k in c.streams.len {
            if !c.streams[k].used || c.streams[k].reset_send { continue; }
            loop {
                let left = room - out.len - 32;
                if left <= 16 || !cwnd_allows(c.rec, out.len + 64) { break; }
                let conn_room = c.max_data_send - c.data_sent;
                let limit = ::min(c.streams[k].max_send, c.streams[k].new_sent + ::max(conn_room, 0));
                let off, len, fin, ok = sb_next(c.streams[k].send, left, limit);
                if !ok { break; }
                let id = c.streams[k].id;
                put_stream(out, id as! u64, off as! u64, sb_bytes(c.streams[k].send, off, len), fin, true);
                sb_sent(c.streams[k].send, off, len, fin);
                add_rec(c, REC_STREAM, id, off, len, fin);
                if off + len > c.streams[k].new_sent {
                    c.data_sent += off + len - c.streams[k].new_sent;
                    c.streams[k].new_sent = off + len;
                }
                eliciting = true;
            }
        }
    }
    return eliciting;
}

// The header of a packet in space sp with packet number pn: the bytes,
// and where its packet number starts.
fn put_header(c: const Conn&, sp: i64, pn_len: i64, pn: i64, payload_len: i64, out: u8[>..]&) -> i64 {
    if sp == SPACE_APP {
        out.push(0x40 | (if c.key_phase { 0x04 } else { 0 }) | (pn_len - 1) as! u8);
        out.append(c.dcid);
    } else {
        let ty: u8 = if sp == SPACE_INITIAL { PT_INITIAL } else { PT_HANDSHAKE };
        out.push(0xc0 | (ty << 4) | (pn_len - 1) as! u8);
        put_u32be(out, VERSION_1);
        out.push(c.dcid.len as! u8);
        out.append(c.dcid);
        out.push(c.scid.len as! u8);
        out.append(c.scid);
        if sp == SPACE_INITIAL {
            put_varint(out, c.token.len as! u64);
            out.append(c.token);
        }
        put_varint_n(out, (pn_len + payload_len + 16) as! u64, 2);
    }
    let pn_at = out.len;
    for i in pn_len { out.push((pn >> (8 * (pn_len - 1 - i))) as! u8); }
    return pn_at;
}

// The next datagram to send at now, or an empty one when there is
// nothing to send (call again until then).
fn poll(c: Conn&, now: i64) -> u8[>..] {
    c.now = now;
    var dg: u8[>..] = [];
    if c.state == STATE_CLOSED || c.state == STATE_DRAINING { return dg; }
    if c.state == STATE_CLOSING {
        if c.close_pending {
            close_datagram(c, dg);
            c.close_pending = false;
            // Within the 3x limit too, before the address is validated.
            if !c.validated {
                if c.bytes_sent + dg.len > 3 * c.bytes_recv { dg.clear(); }
                c.bytes_sent += dg.len;
            }
        }
        return dg;
    }
    // Every packet sent is tracked until acknowledged or lost; with the
    // table full, nothing goes but a probe (an ACK frees slots).
    if !can_track(c.rec) && c.probes == 0 { return dg; }
    // The server's limit before the client's address is validated (§8.1).
    var budget = DATAGRAM;
    if !c.validated { budget = ::min(budget, 3 * c.bytes_recv - c.bytes_sent); }
    if budget < 64 { return dg; }
    var payloads: u8[>..] = [];        // each space's payload, back to back
    var lens: i64[3] = [0; 3];
    var elic: bool[3] = [false; 3];
    var recs_at: i64[3] = [0; 3];
    var recs_n: i64[3] = [0; 3];
    var used: i64 = 0;
    for sp in 3 {
        if !c.has_wkeys[sp] || c.discarded[sp] { continue; }
        // A server's Initial is padded to 1200 bytes when ack-eliciting
        // (§14.1): before validation, not sent while the 3x limit has less
        // than that left, rather than sent past it.
        if sp == SPACE_INITIAL && c.is_server && !c.validated && budget < DATAGRAM { continue; }
        let overhead = 1 + 4 + 2 + c.dcid.len + c.scid.len + 2 + c.token.len + 4 + 16 + 4;
        let room = budget - used - overhead;
        if room < 32 { continue; }
        var p: u8[>..] = [];
        recs_at[sp] = c.rec_head;
        let probe = c.probes > 0 && c.probe_space == sp;
        var e = build_payload(c, sp, room, p, probe);
        if probe && !e { put_ping(p); e = true; }
        if probe { c.probes--; }
        recs_n[sp] = c.rec_head - recs_at[sp];
        if p.len == 0 { continue; }
        // Room for the header protection sample (§5.4.2).
        while p.len < 4 { p.push(0); }
        payloads.append(p);
        lens[sp] = p.len;
        elic[sp] = e;
        used += p.len + overhead;
    }
    if payloads.len == 0 { return dg; }
    // A client's datagram with an Initial, and a server's with an
    // ack-eliciting Initial, are padded to 1200 bytes (§14.1): the last
    // packet in it takes the padding.
    let pad_it = lens[0] > 0 && (!c.is_server || elic[0]);
    var at = 0;
    var last: i64 = -1;
    for sp in 3 { if lens[sp] > 0 { last = sp; } }
    for sp in 3 {
        if lens[sp] == 0 { continue; }
        var p: u8[>..] = [];
        p.append(payloads[at..at + lens[sp]]);
        at += lens[sp];
        let pn = c.spaces[sp].next_pn;
        c.spaces[sp].next_pn++;
        let pn_len = pn_length(pn, c.rec.largest_acked[sp]);
        if sp == last && pad_it {
            // What the datagram will be without padding: what is already
            // in it, this header and payload, the tag.
            var probe_hdr: u8[>..] = [];
            let pa = put_header(c, sp, pn_len, pn, p.len, probe_hdr);
            let total = dg.len + probe_hdr.len + p.len + 16;
            if total < DATAGRAM { put_padding(p, DATAGRAM - total); }
        }
        var pkt: u8[>..] = [];
        let pn_at = put_header(c, sp, pn_len, pn, p.len, pkt);
        pkt.append(p);
        seal(c.wkeys[sp], pkt, pn_at, pn_len, pn);
        if sp == SPACE_APP && c.key_update_pn < 0 { c.key_update_pn = pn; }
        on_packet_sent(c.rec, sp, pn, now, pkt.len, elic[sp], elic[sp] || pad_it, recs_at[sp], recs_n[sp]);
        dg.append(pkt);
    }
    if !c.validated { c.bytes_sent += dg.len; }
    // A client that sends a Handshake packet is done with Initial (§4.9.1).
    if !c.is_server && lens[1] > 0 { discard_keys(c, SPACE_INITIAL); }
    return dg;
}

// CONNECTION_CLOSE at each level that has keys (§10.2.3): an
// application's error is APPLICATION_ERROR before 1-RTT.
fn close_datagram(c: Conn&, dg: u8[>..]&) {
    for sp in 3 {
        if !c.has_wkeys[sp] || c.discarded[sp] { continue; }
        var p: u8[>..] = [];
        if c.app_error && sp == SPACE_APP { put_application_close(p, c.error, c.reason); }
        else if c.app_error { put_connection_close(p, APPLICATION_ERROR, 0, ""); }
        else { put_connection_close(p, c.error, c.error_frame, c.reason); }
        while p.len < 4 { p.push(0); }
        let pn = c.spaces[sp].next_pn;
        c.spaces[sp].next_pn++;
        let pn_len = pn_length(pn, c.rec.largest_acked[sp]);
        if !c.is_server && sp == SPACE_INITIAL && dg.len == 0 {
            var probe_hdr: u8[>..] = [];
            let pa = put_header(c, sp, pn_len, pn, p.len, probe_hdr);
            let total = probe_hdr.len + p.len + 16;
            if total < DATAGRAM { put_padding(p, DATAGRAM - total); }
        }
        var pkt: u8[>..] = [];
        let pn_at = put_header(c, sp, pn_len, pn, p.len, pkt);
        pkt.append(p);
        seal(c.wkeys[sp], pkt, pn_at, pn_len, pn);
        dg.append(pkt);
    }
}

// --- Timers --------------------------------------------------------------------

// When the connection next wants on_timeout called (0: no timer).
fn next_timeout(c: const Conn&) -> i64 {
    if c.state == STATE_CLOSED { return 0; }
    if c.state == STATE_CLOSING || c.state == STATE_DRAINING { return c.close_until; }
    var t = c.last_activity + c.idle_timeout;
    if c.is_server && c.state == STATE_HANDSHAKE { t = ::min(t, c.started + HANDSHAKE_TIMEOUT); }
    let lt, ls, is_pto = loss_timer(c.rec, c.confirmed, c.has_wkeys[1], !c.is_server, c.discarded);
    if lt != 0 && lt < t { t = lt; }
    for sp in 3 {
        if c.discarded[sp] || !c.spaces[sp].ack_needed { continue; }
        if c.spaces[sp].ack_deadline != 0 && c.spaces[sp].ack_deadline < t { t = c.spaces[sp].ack_deadline; }
    }
    return t;
}

fn on_timeout(c: Conn&, now: i64) {
    c.now = now;
    if c.state == STATE_CLOSING || c.state == STATE_DRAINING {
        if now >= c.close_until { c.state = STATE_CLOSED; }
        return;
    }
    if c.state == STATE_CLOSED { return; }
    if c.is_server && c.state == STATE_HANDSHAKE && now >= c.started + HANDSHAKE_TIMEOUT {
        c.error = NO_ERROR;
        c.reason.clear();
        c.reason.append("handshake timeout");
        c.state = STATE_CLOSED;
        return;
    }
    if now >= c.last_activity + c.idle_timeout {
        // Silently closed (§10.1).
        c.error = NO_ERROR;
        c.reason.clear();
        c.reason.append("idle timeout");
        c.state = STATE_CLOSED;
        return;
    }
    let lt, ls, is_pto = loss_timer(c.rec, c.confirmed, c.has_wkeys[1], !c.is_server, c.discarded);
    if lt == 0 || now < lt { return; }
    var done: Sent[>..] = [];
    var acks: bool[>..] = [];
    let sp = on_loss_timeout(c.rec, now, c.confirmed, c.has_wkeys[1], !c.is_server, c.discarded) { s, acked =>
        done.push(s);
        acks.push(acked);
    };
    for j in done.len { settle(c, done[j], acks[j]); }
    if sp >= 0 {
        // A PTO: two probes, with the handshake data not yet acknowledged
        // sent again (§6.2.4).
        c.probes = 2;
        c.probe_space = sp;
        if sp != SPACE_APP {
            let cs = c.crypto_send[sp];
            if cs.sent_upto > cs.base { sb_lost(c.crypto_send[sp], cs.base, cs.sent_upto - cs.base, false); }
        }
    }
}

// --- Key updates (RFC 9001 §6) -------------------------------------------------------

// Both directions move to the next generation of 1-RTT keys; the read
// keys of the previous one stay for packets reordered across the change.
fn rotate_keys(c: Conn&) {
    c.prev_rkeys = c.rkeys[2];
    c.has_prev = true;
    c.rkeys[2] = c.next_rkeys;
    c.next_rkeys = next_keys(c.rkeys[2]);
    c.wkeys[2] = c.next_wkeys;
    c.next_wkeys = next_keys(c.wkeys[2]);
    c.key_phase = !c.key_phase;
    c.key_update_pn = -1;
}

// Starts a key update: false before the handshake is confirmed, or while
// the last one is not yet acknowledged (a packet of the current phase must
// be acknowledged first, §6.1).
fn update_keys(c: Conn&) -> bool {
    if !c.confirmed || c.state != STATE_CONNECTED || !c.has_wkeys[2] { return false; }
    if c.key_update_pn < 0 || c.rec.largest_acked[SPACE_APP] < c.key_update_pn { return false; }
    rotate_keys(c);
    return true;
}
