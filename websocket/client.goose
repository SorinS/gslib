// websocket.client: dial, gorilla's Dialer.Dial: a ws:// or wss:// URL,
// through an HTTP proxy's CONNECT when one is set, TLS for wss with the
// Dialer's roots (or a configuration of the caller's, with a client
// certificate), the opening handshake, and a Conn ready for messages.
//
//   var c = websocket::Conn { .. };
//   var d = websocket::dialer();
//   d.compression = true;
//   let e = websocket::dial(c, "ws://127.0.0.1:9001/", d);
//   // e: OK, or ERR_URL, ERR_NETWORK, ERR_TLS, ERR_PROXY, ERR_TIMEOUT,
//   // ERR_HANDSHAKE (c.status, c.why, c.head say what the server answered)

namespace websocket;

import std;
import base64;
import net;
import net.http;
import net.http.h1;
import net.http.url;
import crypto.tls;
import crypto.tls.handshake;
import entropy;
import websocket;
import websocket.deflate;
import websocket.handshake;
import websocket.conn;

fn connect_fd(host: const u8[:], port: i64, timeout_ms: i32) -> i64 {
    let fd = net::dial(host, port as! i32, timeout_ms);
    return fd;
}

// Reads until inbuf holds a whole response head: its length, or an error.
fn read_head(c: Conn&, timeout_ms: i32) -> http::Head, i64 {
    let lim = http::default_limits();
    loop {
        let h, n = http::parse_response(c.inbuf[c.inpos..], lim);
        if n > 0 { return h, n; }
        if n < 0 { return h, ERR_HANDSHAKE; }
        let e = fill(c, timeout_ms);
        if e != OK { return h, if e == ERR_CLOSED { ERR_HANDSHAKE } else { e }; }
    }
    return http::new_head(http::KIND_RESPONSE), ERR_HANDSHAKE;
}

// A tunnel through an HTTP proxy to host:port (RFC 9110 §9.3.6).
fn proxy_connect(c: Conn&, d: const Dialer&, authority: const u8[:]) -> i64 {
    let pu, pe = http::url_parse(d.proxy);
    if pe != http::URL_OK || http::url_scheme(pu) != "http" { return ERR_PROXY; }
    let ph, hok = http::url_ascii_host(pu);
    let pport = http::url_port(pu);
    if !hok || pport <= 0 { return ERR_PROXY; }
    c.fd = connect_fd(ph, pport, d.timeout_ms);
    if c.fd < 0 { return ERR_NETWORK; }
    c.wire.clear();
    c.wire.append("CONNECT ");
    c.wire.append(authority);
    c.wire.append(" HTTP/1.1\r\nHost: ");
    c.wire.append(authority);
    c.wire.append("\r\n");
    if pu.has_user {
        var up: u8[>..] = [];
        up.append(http::url_username(pu));
        up.push(':');
        up.append(http::url_password(pu));
        c.wire.append("Proxy-Authorization: Basic ");
        base64::encode(c.wire, up);
        c.wire.append("\r\n");
    }
    c.wire.append("\r\n");
    let fe = flush(c);
    if fe != OK { return fe; }
    let h, n = read_head(c, d.timeout_ms);
    if n < 0 { return if n == ERR_HANDSHAKE { ERR_PROXY } else { n }; }
    c.status = h.status;
    if h.status < 200 || h.status > 299 { return ERR_PROXY; }
    c.inpos += n;
    return OK;
}

fn tls_handshake(c: Conn&, timeout_ms: i32) -> i64 {
    c.on_tls = true;
    c.tc.clear();
    c.tc.push(tls::client(c.ccfg));
    c.rec.clear();
    tls::client_start(c.tc[0], c.ccfg, c.rec);
    while !tls::connected(c.tc[0]) {
        if c.rec.len > 0 && net::write(c.fd, c.rec, timeout_ms) < 0 { return ERR_NETWORK; }
        c.rec.clear();
        c.raw.resize(65536, 0);
        let n = net::read(c.fd, c.raw, timeout_ms);
        if n == 0 { return ERR_TLS; }
        if n < 0 { return net_error(n); }
        var data: u8[>..] = [];
        data.append(c.raw[..n]);
        if tls::feed(c.tc[0], c.ccfg, data, c.rec, c.inbuf) < 0 {
            let w = net::write(c.fd, c.rec, 1000);
            return ERR_TLS;
        }
    }
    if c.rec.len > 0 && net::write(c.fd, c.rec, timeout_ms) < 0 { return ERR_NETWORK; }
    return OK;
}

// The handshake on a connected socket (TLS done if wss).
fn client_handshake(c: Conn&, host_field: const u8[:], target: const u8[:], d: const Dialer&) -> i64 {
    var rnd: u8[16] = [0; 16];
    entropy::random_bytes(rnd);
    let key = new_key(rnd);
    c.wire.clear();
    put_request(c.wire, host_field, target, key, d);
    let fe = flush(c);
    if fe != OK { return fe; }
    let h, n = read_head(c, d.timeout_ms);
    if n < 0 { return n; }
    let m = c.inbuf[c.inpos..c.inpos + n];
    c.status = h.status;
    c.head.clear();
    c.head.append(m);
    let a = check_response(c.head, h, key, d);
    if a.err != OK {
        c.why.clear();
        c.why.append(a.why);
        return a.err;
    }
    c.subprotocol.clear();
    c.subprotocol.append(a.subprotocol);
    var early: u8[>..] = [];
    early.append(c.inbuf[c.inpos + n..]);
    start(c, true, a.pmd, early);
    return OK;
}

fn dial_core(c: Conn&, url: const u8[:], d: const Dialer&, own_tls: bool) -> i64 {
    close_now(c);
    c.fd = -1;
    c.on_tls = false;
    c.is_client = true;
    c.status = 0;
    c.why.clear();
    c.head.clear();
    c.inbuf.clear();
    c.inpos = 0;
    c.st = new_state();
    let u, ue = http::url_parse(url);
    if ue != http::URL_OK || !u.has_authority || u.has_fragment { return ERR_URL; }
    let scheme = http::url_scheme(u);
    if scheme != "ws" && scheme != "wss" { return ERR_URL; }
    let secure = scheme == "wss";
    let host, hok = http::url_ascii_host(u);
    if !hok || host.len == 0 { return ERR_URL; }
    var port: i64 = if secure { 443 } else { 80 };
    if http::url_port_text(u).len > 0 {
        port = http::url_port(u);
        if port <= 0 { return ERR_URL; }
    }
    var host_field: u8[>..] = [];
    if !http::host_port_field(u, host_field) { return ERR_URL; }
    var target: u8[>..] = [];
    http::request_target(u, target);
    // host:port for CONNECT
    var authority: u8[>..] = [];
    if u.ipv6 { authority.push('['); authority.append(host); authority.push(']'); } else { authority.append(host); }
    authority.push(':');
    format_int(authority, port, 10, 0, ' ');
    var e = OK;
    if d.proxy.len > 0 {
        e = proxy_connect(c, d, authority);
    } else {
        c.fd = connect_fd(host, port, d.timeout_ms);
        if c.fd < 0 { e = ERR_NETWORK; }
    }
    if e == OK && secure {
        if !own_tls {
            c.ccfg = tls::client_config(if d.server_name.len > 0 { d.server_name[..] } else { host[..] }, d.roots);
            c.ccfg.verify = !d.insecure;
        } else if c.ccfg.server_name.len == 0 {
            c.ccfg.server_name.append(if d.server_name.len > 0 { d.server_name[..] } else { host[..] });
        }
        // HTTP/1.1 by ALPN when the server speaks ALPN (RFC 8441 is HTTP/2's).
        c.ccfg.alpn.clear();
        tls::add_alpn(c.ccfg.alpn, "http/1.1");
        e = tls_handshake(c, d.timeout_ms);
    }
    if e == OK { e = client_handshake(c, host_field, target, d); }
    if e != OK && c.fd >= 0 {
        net::close(c.fd);
        c.fd = -1;
    }
    return e;
}

// Dials a ws:// or wss:// URL with the Dialer's settings.
fn dial(c: Conn&, url: const u8[:], d: const Dialer&) -> i64 { dial_core(c, url, d, false) }

// The same over TLS with a configuration of the caller's (a client
// certificate, pinned roots, versions): cc's server name, or the URL's
// host when it has none, is checked.
fn dial_tls(c: Conn&, url: const u8[:], d: const Dialer&, cc: const tls::ClientConfig&) -> i64 {
    c.ccfg = copy(cc);
    return dial_core(c, url, d, true);
}
