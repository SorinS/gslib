// krb5.net: talking to a realm's KDCs (RFC 4120 §7.2). A request no
// longer than udp_preference_limit (1465 bytes by default, as MIT's) goes
// over UDP first; a longer one, a KDC marked tcp/, or a
// KRB_ERR_RESPONSE_TOO_BIG answer goes over TCP, where each message has a
// 4-byte big-endian length before it (§7.2.2). Each KDC of the realm is
// tried in turn, in two rounds, as MIT does; the first answer wins.
// `udp_preference_limit = 1` makes every request TCP.

namespace krb5;

import std;
import krb5.config;
import krb5.messages;
import krb5.sys;

let MAX_TCP_REPLY: i64 = 1 << 24;

struct NetOpts { udp_limit: i64, timeout_ms: i64, max_rounds: i64 }

fn net_opts(cfg: const Config&) -> NetOpts {
    return NetOpts {
        udp_limit: conf_int(cfg, "libdefaults/udp_preference_limit", 1465),
        // MIT waits 1 s for a KDC, then moves on; kdc_timeout is ours too.
        timeout_ms: conf_duration(cfg, "libdefaults/kdc_timeout", 1) * 1000,
        max_rounds: conf_int(cfg, "libdefaults/max_retries", 2),
    };
}

// One exchange over TCP: the reply, or an error.
fn tcp_exchange(host: const u8[:], port: i64, req: const u8[:], out: u8[>..]&, timeout_ms: i64) -> i64 {
    let fd = httpnet_connect(host, port as! i32, timeout_ms as! i32);
    if fd < 0 { return ERR_KDC_UNREACHABLE; }
    var msg: u8[>..] = [];
    let n = req.len;
    msg.push((n >> 24) as! u8);
    msg.push((n >> 16) as! u8);
    msg.push((n >> 8) as! u8);
    msg.push(n as! u8);
    msg.append(req);
    if httpnet_write(fd, msg, timeout_ms as! i32) != msg.len { httpnet_close(fd); return ERR_KDC_UNREACHABLE; }
    var head: u8[4] = [0; 4];
    var got = 0;
    while got < 4 {
        let r = httpnet_read(fd, head[got..], timeout_ms as! i32);
        if r <= 0 { httpnet_close(fd); return ERR_KDC_UNREACHABLE; }
        got += r;
    }
    let h0: i64 = head[0];
    let h1: i64 = head[1];
    let h2: i64 = head[2];
    let h3: i64 = head[3];
    let len = h0 << 24 | h1 << 16 | h2 << 8 | h3;
    // The high bit is reserved (§7.2.2); a KDC that sets it is not one we know.
    if len <= 0 || len > MAX_TCP_REPLY { httpnet_close(fd); return ERR_MALFORMED; }
    let base = out.len;
    out.resize(base + len, 0);
    var have = 0;
    while have < len {
        let r = httpnet_read(fd, out[base + have..base + len], timeout_ms as! i32);
        if r <= 0 { httpnet_close(fd); out.resize(base, 0); return ERR_KDC_UNREACHABLE; }
        have += r;
    }
    httpnet_close(fd);
    return OK;
}

fn udp_exchange(host: const u8[:], port: i64, req: const u8[:], out: u8[>..]&, timeout_ms: i64) -> i64 {
    var buf: u8[>..] = [];
    buf.resize(65536, 0);
    let n = krb5sys_udp_exchange(host, port as! i32, req, buf, timeout_ms as! i32);
    if n <= 0 { return ERR_KDC_UNREACHABLE; }
    out.append(buf[..n]);
    return OK;
}

// Whether a reply is KRB-ERROR KRB_ERR_RESPONSE_TOO_BIG.
fn too_big(reply: const u8[:]) -> bool {
    if message_type(reply) != MSG_KRB_ERROR { return false; }
    let e, err = decode_krb_error(reply);
    return err == OK && e.error_code == KRB_ERR_RESPONSE_TOO_BIG;
}

// Sends a request to the realm's KDCs and puts the first reply in out.
// ERR_NO_KDC when the realm has none configured, ERR_KDC_UNREACHABLE
// when none answers.
fn send_to_kdc(cfg: const Config&, realm: const u8[:], req: const u8[:], out: u8[>..]&) -> i64 {
    let o = net_opts(cfg);
    let kdcs = realm_kdcs(cfg, realm);
    var any = false;
    for k in kdcs { any = true; }
    if !any { return ERR_NO_KDC; }
    let tcp_first = req.len > o.udp_limit;
    for round in (if o.max_rounds < 1 { 1 } else { o.max_rounds }) {
        // Each round waits longer, as MIT's backoff does.
        let t = o.timeout_ms * (round + 1);
        for k in kdcs {
            out.clear();
            let use_udp = !k.tcp_only && (k.udp_only || !tcp_first);
            if use_udp {
                if udp_exchange(k.host, k.port, req, out, t) == OK {
                    if !too_big(out) { return OK; }
                    out.clear();
                    if k.udp_only { continue; }
                } else if k.udp_only {
                    continue;
                }
            }
            if k.udp_only { continue; }
            if tcp_exchange(k.host, k.port, req, out, t) == OK { return OK; }
        }
    }
    out.clear();
    return ERR_KDC_UNREACHABLE;
}
