// mail.link: the connection under the SMTP and POP3 clients: a socket
// (gslib's net), TLS from the first byte (SMTPS on 465, POP3S on 995) or
// from a STARTTLS/STLS on, and lines in and out.
//
// The functions are generic over the client: any root struct with these
// fields, which smtp::Client and pop3::Client both have:
//
//   fd: i64                    the socket, -1 when closed
//   secure: bool               TLS is on
//   tc: tls::Conn              the TLS connection
//   tlscfg: tls::ClientConfig  how it checks the server (server_name is set here)
//   inbuf: u8[>..]             what came and is not taken yet (decrypted)
//   inpos: i64                 where in inbuf the next line starts
//   wire: u8[>..]              scratch: bytes for the socket
//   raw: u8[>..]               scratch: bytes from the socket
//   timeout_ms: i64            each read and write's, and the connect's
//
// Replies are read a line at a time, CRLF or a bare LF ending it; a line
// longer than its limit is an error, not a line cut in two.

namespace mail;

import std;
import mail;
import net;
import crypto.tls;
import crypto.tls.handshake;

// A socket error as one of mail's.
fn net_error(e: i64) -> i64 {
    match e {
        net::ERR_ARG => ERR_ARG,
        net::ERR_RESOLVE => ERR_RESOLVE,
        net::ERR_CONNECT => ERR_CONNECT,
        net::ERR_TIMEOUT => ERR_TIMEOUT,
        _ => ERR_IO,
    }
}

fn link_timeout(l) -> i32 { if l.timeout_ms > 0 && l.timeout_ms < 2147483647 { l.timeout_ms as! i32 } else { 0 } }

// Connects to host:port, with TLS at once when tls is set.
fn link_open(l, host: const u8[:], port: i64, tls: bool) -> i64 {
    if l.fd >= 0 { return ERR_STATE; }
    if host.len == 0 || port <= 0 || port > 65535 { return ERR_ARG; }
    l.inbuf.clear();
    l.inpos = 0;
    l.secure = false;
    let fd = net::dial(host, port as! i32, link_timeout(l));
    if fd < 0 { return net_error(fd); }
    l.fd = fd;
    if tls { return link_tls(l, host); }
    return OK;
}

// Writes the scratch wire bytes and empties them.
fn link_flush(l) -> i64 {
    if l.wire.len == 0 { return OK; }
    let n = net::write(l.fd, l.wire, link_timeout(l));
    l.wire.clear();
    return if n < 0 { net_error(n) } else { OK };
}

// The TLS handshake on the open socket, the server checked as server_name
// (the host name connected to, unless tlscfg names another). Nothing may
// be waiting unread: bytes the server sent before TLS, after the reply to
// STARTTLS, would otherwise be taken as if they came under it (the
// STARTTLS injection of CVE-2011-0411).
fn link_tls(l, server_name: const u8[:]) -> i64 {
    if l.fd < 0 { return ERR_STATE; }
    if l.inpos < l.inbuf.len { return ERR_PROTOCOL; }
    l.inbuf.clear();
    l.inpos = 0;
    if l.tlscfg.server_name.len == 0 { l.tlscfg.server_name.append(server_name); }
    l.tc = tls::client(l.tlscfg);
    l.wire.clear();
    tls::client_start(l.tc, l.tlscfg, l.wire);
    l.raw.resize(16384, 0);
    while !tls::connected(l.tc) {
        let e = link_flush(l);
        if e != OK { return e; }
        if tls::failed(l.tc) || tls::closed(l.tc) { return ERR_TLS; }
        let n = net::read(l.fd, l.raw, link_timeout(l));
        if n == 0 { return ERR_IO; }
        if n < 0 { return net_error(n); }
        if tls::client_feed(l.tc, l.tlscfg, l.raw[..n], l.wire, l.inbuf) != 0 { link_flush(l); return ERR_TLS; }
    }
    l.secure = true;
    return link_flush(l);
}

// Sends data, under TLS when it is on.
fn link_write(l, data: const u8[:]) -> i64 {
    if l.fd < 0 { return ERR_STATE; }
    l.wire.clear();
    if l.secure {
        if !tls::send(l.tc, data, l.wire) { return ERR_TLS; }
    } else {
        l.wire.append(data);
    }
    return link_flush(l);
}

// Reads what comes next into inbuf: OK when something came, ERR_IO at the
// end of the stream (TLS's close_notify too), ERR_TIMEOUT.
fn link_fill(l) -> i64 {
    if l.fd < 0 { return ERR_STATE; }
    // What was taken goes first, so inbuf holds only what is still to read.
    if l.inpos > 0 {
        let rest = l.inbuf.len - l.inpos;
        for i in rest { l.inbuf[i] = l.inbuf[l.inpos + i]; }
        l.inbuf.resize(rest, 0);
        l.inpos = 0;
    }
    l.raw.resize(16384, 0);
    loop {
        let n = net::read(l.fd, l.raw, link_timeout(l));
        if n == 0 { return ERR_IO; }
        if n < 0 { return net_error(n); }
        if !l.secure { l.inbuf.append(l.raw[..n]); return OK; }
        let before = l.inbuf.len;
        l.wire.clear();
        let e = tls::client_feed(l.tc, l.tlscfg, l.raw[..n], l.wire, l.inbuf);
        link_flush(l);
        if e != 0 { return ERR_TLS; }
        if l.inbuf.len > before { return OK; }
        if tls::closed(l.tc) { return ERR_IO; }
    }
    return ERR_IO;
}

// The next line, without its CRLF (or LF), into line: at most max bytes.
fn link_read_line(l, line: u8[>..]&, max: i64) -> i64 {
    line.clear();
    loop {
        var i = l.inpos;
        while i < l.inbuf.len && l.inbuf[i] != '\n' { i++; }
        if i < l.inbuf.len {
            var end = i;
            if end > l.inpos && l.inbuf[end - 1] == '\r' { end--; }
            if end - l.inpos > max { return ERR_PROTOCOL; }
            line.append(l.inbuf[l.inpos..end]);
            l.inpos = i + 1;
            return OK;
        }
        if l.inbuf.len - l.inpos > max + 1 { return ERR_PROTOCOL; }
        let e = link_fill(l);
        if e != OK { return e; }
    }
    return ERR_IO;
}

// Ends the connection: TLS's close_notify when it is on, then the socket.
fn link_close(l) {
    if l.fd < 0 { return; }
    if l.secure && tls::connected(l.tc) {
        l.wire.clear();
        tls::close(l.tc, l.wire);
        link_flush(l);
    }
    net::close(l.fd);
    l.fd = -1;
    l.secure = false;
    l.inbuf.clear();
    l.inpos = 0;
}

// Whether s has CR or LF in it: a command argument must not.
fn has_crlf(s: const u8[:]) -> bool {
    for c in s { if c == '\r' || c == '\n' { return true; } }
    return false;
}
