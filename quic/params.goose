// quic.params: transport parameters (RFC 9000 §18), what each endpoint
// tells the other in TLS's quic_transport_parameters extension: flow
// control limits, timeouts, connection ID limits, and the connection IDs
// that tie the handshake to the packets that carried it. Each is an id,
// a length and a value, an integer parameter's value one varint filling
// its length. read_params refuses, as TRANSPORT_PARAMETER_ERROR, a
// parameter twice, a value out of its range, a length that does not fit
// its value, and from a client the parameters only a server sends; ids it
// does not know (GREASE among them, 31 * N + 27) it skips.

namespace quic;

import std;
import quic;
import quic.packet;
import quic.frame;

let TP_ORIGINAL_DESTINATION_CONNECTION_ID: u64   = 0x00;
let TP_MAX_IDLE_TIMEOUT: u64                     = 0x01;
let TP_STATELESS_RESET_TOKEN: u64                = 0x02;
let TP_MAX_UDP_PAYLOAD_SIZE: u64                 = 0x03;
let TP_INITIAL_MAX_DATA: u64                     = 0x04;
let TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64   = 0x05;
let TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64  = 0x06;
let TP_INITIAL_MAX_STREAM_DATA_UNI: u64          = 0x07;
let TP_INITIAL_MAX_STREAMS_BIDI: u64             = 0x08;
let TP_INITIAL_MAX_STREAMS_UNI: u64              = 0x09;
let TP_ACK_DELAY_EXPONENT: u64                   = 0x0a;
let TP_MAX_ACK_DELAY: u64                        = 0x0b;
let TP_DISABLE_ACTIVE_MIGRATION: u64             = 0x0c;
let TP_PREFERRED_ADDRESS: u64                    = 0x0d;
let TP_ACTIVE_CONNECTION_ID_LIMIT: u64           = 0x0e;
let TP_INITIAL_SOURCE_CONNECTION_ID: u64         = 0x0f;
let TP_RETRY_SOURCE_CONNECTION_ID: u64           = 0x10;

// The parameters, with the RFC's defaults for those not sent. The
// connection IDs and the token have has_ flags: whether they came matters
// (§7.3), and an empty connection ID is one.
struct Params {
    has_original_dcid: bool = false,
    original_dcid: u8[..20] = [],
    max_idle_timeout: u64 = 0,                  // milliseconds; 0: none
    has_reset_token: bool = false,
    reset_token: u8[16] = [0; 16],
    max_udp_payload_size: u64 = 65527,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = 3,
    max_ack_delay: u64 = 25,                    // milliseconds
    disable_active_migration: bool = false,
    has_preferred_address: bool = false,
    pa_ipv4: u8[4] = [0; 4],
    pa_ipv4_port: u16 = 0,
    pa_ipv6: u8[16] = [0; 16],
    pa_ipv6_port: u16 = 0,
    pa_cid: u8[..20] = [],
    pa_reset_token: u8[16] = [0; 16],
    active_connection_id_limit: u64 = 2,
    has_initial_scid: bool = false,
    initial_scid: u8[..20] = [],
    has_retry_scid: bool = false,
    retry_scid: u8[..20] = [],
}

fn default_params() -> Params { Params { .. } }

// --- Writing -------------------------------------------------------------------------

fn put_param_int(out: u8[>..]&, id: u64, v: u64) {
    put_varint(out, id);
    put_varint(out, varint_len(v) as! u64);
    put_varint(out, v);
}

fn put_param_bytes(out: u8[>..]&, id: u64, v: const u8[:]) {
    put_varint(out, id);
    put_varint(out, v.len as! u64);
    out.append(v);
}

// The parameters' encoding, as the extension carries it: each that is
// not its default, and the connection IDs and token that are set; the
// ones only a server sends only when is_server.
fn put_params(out: u8[>..]&, p: const Params&, is_server: bool) {
    let d = default_params();
    if is_server && p.has_original_dcid { put_param_bytes(out, TP_ORIGINAL_DESTINATION_CONNECTION_ID, p.original_dcid); }
    if p.max_idle_timeout != d.max_idle_timeout { put_param_int(out, TP_MAX_IDLE_TIMEOUT, p.max_idle_timeout); }
    if is_server && p.has_reset_token { put_param_bytes(out, TP_STATELESS_RESET_TOKEN, p.reset_token); }
    if p.max_udp_payload_size != d.max_udp_payload_size { put_param_int(out, TP_MAX_UDP_PAYLOAD_SIZE, p.max_udp_payload_size); }
    if p.initial_max_data != 0 { put_param_int(out, TP_INITIAL_MAX_DATA, p.initial_max_data); }
    if p.initial_max_stream_data_bidi_local != 0 { put_param_int(out, TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, p.initial_max_stream_data_bidi_local); }
    if p.initial_max_stream_data_bidi_remote != 0 { put_param_int(out, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, p.initial_max_stream_data_bidi_remote); }
    if p.initial_max_stream_data_uni != 0 { put_param_int(out, TP_INITIAL_MAX_STREAM_DATA_UNI, p.initial_max_stream_data_uni); }
    if p.initial_max_streams_bidi != 0 { put_param_int(out, TP_INITIAL_MAX_STREAMS_BIDI, p.initial_max_streams_bidi); }
    if p.initial_max_streams_uni != 0 { put_param_int(out, TP_INITIAL_MAX_STREAMS_UNI, p.initial_max_streams_uni); }
    if p.ack_delay_exponent != d.ack_delay_exponent { put_param_int(out, TP_ACK_DELAY_EXPONENT, p.ack_delay_exponent); }
    if p.max_ack_delay != d.max_ack_delay { put_param_int(out, TP_MAX_ACK_DELAY, p.max_ack_delay); }
    if p.disable_active_migration { put_varint(out, TP_DISABLE_ACTIVE_MIGRATION); put_varint(out, 0); }
    if is_server && p.has_preferred_address {
        var v: u8[>..] = [];
        v.append(p.pa_ipv4);
        v.push((p.pa_ipv4_port >> 8) as! u8);
        v.push(p.pa_ipv4_port as! u8);
        v.append(p.pa_ipv6);
        v.push((p.pa_ipv6_port >> 8) as! u8);
        v.push(p.pa_ipv6_port as! u8);
        v.push(p.pa_cid.len as! u8);
        v.append(p.pa_cid);
        v.append(p.pa_reset_token);
        put_param_bytes(out, TP_PREFERRED_ADDRESS, v);
    }
    if p.active_connection_id_limit != d.active_connection_id_limit {
        put_param_int(out, TP_ACTIVE_CONNECTION_ID_LIMIT, p.active_connection_id_limit);
    }
    if p.has_initial_scid { put_param_bytes(out, TP_INITIAL_SOURCE_CONNECTION_ID, p.initial_scid); }
    if is_server && p.has_retry_scid { put_param_bytes(out, TP_RETRY_SOURCE_CONNECTION_ID, p.retry_scid); }
}

// --- Reading -------------------------------------------------------------------------

// A connection ID parameter: at most 20 bytes.
fn take_cid(dst: u8[..20]&, b: const u8[:], at: i64, n: i64) -> bool {
    if n > MAX_CID { return false; }
    dst.clear();
    dst.append(b[at..at + n]);
    return true;
}

// The parameters the peer sent (b, the extension's content); from_server
// when they are a server's. The parameters and 0, or what was wrong with
// them (TRANSPORT_PARAMETER_ERROR).
fn read_params(b: const u8[:], from_server: bool) -> Params, u64 {
    var p = default_params();
    var seen: u32 = 0;
    var r = reader(b);
    while r.pos < r.end {
        let id = rd_varint(r, b);
        let n64 = rd_varint(r, b);
        if r.bad || n64 > (r.end - r.pos) as! u64 { return p, TRANSPORT_PARAMETER_ERROR; }
        let n = n64 as! i64;
        let at = rd_bytes(r, n);
        if id > TP_RETRY_SOURCE_CONNECTION_ID { continue; }      // not one of these: skipped
        let bit: u32 = 1 << id as! u32;
        if seen & bit != 0 { return p, TRANSPORT_PARAMETER_ERROR; }
        seen = seen | bit;
        // A client sends none of the server's own.
        if !from_server && (id == TP_ORIGINAL_DESTINATION_CONNECTION_ID || id == TP_STATELESS_RESET_TOKEN ||
                            id == TP_PREFERRED_ADDRESS || id == TP_RETRY_SOURCE_CONNECTION_ID) {
            return p, TRANSPORT_PARAMETER_ERROR;
        }
        var ok = true;
        if id == TP_ORIGINAL_DESTINATION_CONNECTION_ID {
            ok = take_cid(p.original_dcid, b, at, n);
            p.has_original_dcid = true;
        } else if id == TP_INITIAL_SOURCE_CONNECTION_ID {
            ok = take_cid(p.initial_scid, b, at, n);
            p.has_initial_scid = true;
        } else if id == TP_RETRY_SOURCE_CONNECTION_ID {
            ok = take_cid(p.retry_scid, b, at, n);
            p.has_retry_scid = true;
        } else if id == TP_STATELESS_RESET_TOKEN {
            ok = n == 16;
            if ok { for i in 16 { p.reset_token[i] = b[at + i]; } }
            p.has_reset_token = true;
        } else if id == TP_DISABLE_ACTIVE_MIGRATION {
            ok = n == 0;
            p.disable_active_migration = true;
        } else if id == TP_PREFERRED_ADDRESS {
            // IPv4 address and port, IPv6 address and port, a connection ID
            // (not empty) and its stateless reset token.
            ok = n >= 4 + 2 + 16 + 2 + 1 + 1 + 16;
            if ok {
                let cl = b[at + 24] as i64;
                ok = cl >= 1 && cl <= MAX_CID && n == 25 + cl + 16;
                if ok {
                    for i in 4 { p.pa_ipv4[i] = b[at + i]; }
                    p.pa_ipv4_port = (b[at + 4] as u16) << 8 | b[at + 5];
                    for i in 16 { p.pa_ipv6[i] = b[at + 6 + i]; }
                    p.pa_ipv6_port = (b[at + 22] as u16) << 8 | b[at + 23];
                    p.pa_cid.append(b[at + 25..at + 25 + cl]);
                    for i in 16 { p.pa_reset_token[i] = b[at + 25 + cl + i]; }
                    p.has_preferred_address = true;
                }
            }
        } else {
            // An integer: one varint that fills the length.
            let v, next, vok = read_varint(b[..at + n], at);
            ok = vok && next == at + n;
            if id == TP_MAX_IDLE_TIMEOUT { p.max_idle_timeout = v; }
            else if id == TP_MAX_UDP_PAYLOAD_SIZE { p.max_udp_payload_size = v; ok = ok && v >= 1200; }
            else if id == TP_INITIAL_MAX_DATA { p.initial_max_data = v; }
            else if id == TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL { p.initial_max_stream_data_bidi_local = v; }
            else if id == TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE { p.initial_max_stream_data_bidi_remote = v; }
            else if id == TP_INITIAL_MAX_STREAM_DATA_UNI { p.initial_max_stream_data_uni = v; }
            else if id == TP_INITIAL_MAX_STREAMS_BIDI { p.initial_max_streams_bidi = v; ok = ok && v <= MAX_STREAMS_LIMIT; }
            else if id == TP_INITIAL_MAX_STREAMS_UNI { p.initial_max_streams_uni = v; ok = ok && v <= MAX_STREAMS_LIMIT; }
            else if id == TP_ACK_DELAY_EXPONENT { p.ack_delay_exponent = v; ok = ok && v <= 20; }
            else if id == TP_MAX_ACK_DELAY { p.max_ack_delay = v; ok = ok && v < 16384; }
            else if id == TP_ACTIVE_CONNECTION_ID_LIMIT { p.active_connection_id_limit = v; ok = ok && v >= 2; }
        }
        if !ok { return p, TRANSPORT_PARAMETER_ERROR; }
    }
    if r.bad { return p, TRANSPORT_PARAMETER_ERROR; }
    return p, NO_ERROR;
}
