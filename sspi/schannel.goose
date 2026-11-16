// sspi.schannel: a TLS client with Windows' own TLS (Schannel), over
// net's sockets, as Go's alexbrainman/sspi/schannel: the system decides
// the protocol versions and cipher suites (its policy, TLS 1.3 where the
// system has it), checks the server's chain against its roots and the
// name against server_name, and can check revocation. For a server with
// a certificate the system does not trust (a test server), verify false
// leaves the checking to the caller, with peer_certificate and x509.
//
//   import gslib.sspi;
//   import gslib.sspi.schannel;
//
//   var c, st = sspi::tls_dial("example.com", 443, sspi::tls_config("example.com"));
//   if st != sspi::OK { ... sspi::error_text(st) ... }
//   sspi::tls_write(c, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
//   var buf: u8[>..] = [];
//   buf.resize(16384, 0);
//   let n = sspi::tls_read(c, buf);     // > 0 bytes, 0 at the end, < 0 an error
//   sspi::tls_close(c);
//
// Errors are net's (net::ERR_*, -1 to -5) for the socket and SSPI's
// (SEC_E_*, CERT_E_*) for TLS; error_text says either.

namespace sspi;

import std;
import net;

struct TlsConfig {
    server_name: u8[..256],  // the name sent (SNI) and checked against the certificate
    min_version: i64,        // 0x0301 to 0x0304; 0 for the system's policy
    max_version: i64,
    verify:      bool,       // the chain and the name checked by the system (SCH_CRED_AUTO_CRED_VALIDATION)
    revocation:  bool,       // and the chain's revocation (SCH_CRED_REVOCATION_CHECK_CHAIN)
    flags:       i64,        // more SCH_CRED_* flags
    timeout_ms:  i64,        // for each read and write; 0 for none
}

fn tls_config(server_name: const u8[:]) -> TlsConfig {
    var c = TlsConfig {
        server_name: [], min_version: 0, max_version: 0, verify: true, revocation: false,
        flags:       0, timeout_ms: 30000,
    };
    c.server_name.append(server_name[..min(server_name.len, 256)]);
    return c;
}

struct TlsConn {
    fd:         i64,
    cred:       i64,
    ctx:        i64,
    timeout_ms: i64,
    closed:     bool,
}

fn tls_flags() -> i64 {
    return ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
           ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM;
}

fn timeout_of(ms: i64) -> i32 { min(max(ms, 0), 2000000000) as! i32 }

fn conn_free(c: TlsConn&) {
    if c.ctx > 0 { gsspi_delete_context(c.ctx); c.ctx = 0; }
    if c.cred > 0 { gsspi_free_credentials(c.cred); c.cred = 0; }
}

// TLS over a connected socket (net::dial's): the connection and OK once
// the handshake is done, or a status (the socket is left open).
fn tls_client(fd: i64, cfg: const TlsConfig&) -> TlsConn, i64 {
    var c = TlsConn { fd: fd, cred: 0, ctx: 0, timeout_ms: cfg.timeout_ms, closed: false };
    var flags = cfg.flags | (if cfg.verify { SCH_CRED_AUTO_CRED_VALIDATION } else { SCH_CRED_MANUAL_CRED_VALIDATION });
    flags |= SCH_CRED_NO_DEFAULT_CREDS;
    if cfg.revocation { flags |= SCH_CRED_REVOCATION_CHECK_CHAIN; }
    let cred = acquire_schannel(flags, cfg.min_version, cfg.max_version);
    if cred < 0 { return c, cred; }
    c.cred = cred;
    let ctx = context(cred);
    if ctx < 0 { conn_free(c); return c, ctx; }
    c.ctx = ctx;
    let req = tls_flags() | (if cfg.verify { 0 } else { ISC_REQ_MANUAL_CRED_VALIDATION });
    let to = timeout_of(c.timeout_ms);
    var out: u8[>..] = [];
    var buf: u8[>..] = [];
    buf.resize(16384 + 512, 0);
    var st = step(ctx, cfg.server_name, req, "", out);
    while true {
        if out.len > 0 {
            let w = net::write(fd, out, to);
            if w < 0 { conn_free(c); return c, w; }
        }
        if st == OK { break; }
        if st != SEC_I_CONTINUE_NEEDED && st != SEC_E_INCOMPLETE_MESSAGE { conn_free(c); return c, st; }
        if st == SEC_E_INCOMPLETE_MESSAGE || gsspi_pending_input(ctx) == 0 {
            let n = net::read(fd, buf, to);
            if n == 0 { conn_free(c); return c, SEC_E_INCOMPLETE_MESSAGE; }
            if n < 0 { conn_free(c); return c, n; }
            st = step(ctx, cfg.server_name, req, buf[..n], out);
        } else {
            st = step(ctx, cfg.server_name, req, "", out);
        }
    }
    return c, OK;
}

// net::dial, then tls_client: the connection and OK, or a status (and
// nothing left open).
fn tls_dial(host: const u8[:], port: i64, cfg: const TlsConfig&) -> TlsConn, i64 {
    let fd = net::dial(host, port as! i32, timeout_of(cfg.timeout_ms));
    if fd < 0 { return TlsConn { fd: -1, cred: 0, ctx: 0, timeout_ms: 0, closed: true }, fd; }
    var c, st = tls_client(fd, cfg);
    if st != OK { net::close(fd); c.fd = -1; c.closed = true; }
    return c, st;
}

// Up to buf.len bytes of plaintext: how many (> 0), 0 at the end of the
// stream (the server's close_notify, or the socket's end), or a status.
fn tls_read(c: TlsConn&, buf: u8[:]) -> i64 {
    if c.ctx <= 0 { return SEC_E_INVALID_HANDLE; }
    var raw: u8[>..] = [];
    while true {
        let n = gsspi_decrypt(c.ctx, buf);
        let sent = tls_flush(c);
        if sent < 0 { return sent; }
        if n > 0 { return n; }
        if n == END { return 0; }
        if n < 0 { return n; }
        if raw.len == 0 { raw.resize(16384 + 512, 0); }
        let r = net::read(c.fd, raw, timeout_of(c.timeout_ms));
        if r == 0 { return 0; }
        if r < 0 { return r; }
        let f = gsspi_feed(c.ctx, raw[..r]);
        if f < 0 { return f; }
    }
    return 0;
}

// Sends what the context made after the handshake (TLS 1.3's KeyUpdate):
// 0, or a status.
fn tls_flush(c: TlsConn&) -> i64 {
    var pend: u8[>..] = [];
    pend.resize(4096, 0);
    let n = gsspi_take_output(c.ctx, pend);
    if n <= 0 { return n; }
    let w = net::write(c.fd, pend[..n], timeout_of(c.timeout_ms));
    return if w < 0 { w } else { 0 };
}

// All of data, as records: data.len, or a status.
fn tls_write(c: TlsConn&, data: const u8[:]) -> i64 {
    if c.ctx <= 0 || c.closed { return SEC_E_INVALID_HANDLE; }
    let max = gsspi_max_message(c.ctx);
    if max <= 0 { return SEC_E_INVALID_HANDLE; }
    var rec: u8[>..] = [];
    rec.resize(max + 1024, 0);
    var at = 0;
    while at < data.len || data.len == 0 {
        let end = min(data.len, at + max);
        let n = gsspi_encrypt(c.ctx, data[at..end], rec);
        if n < 0 { return n; }
        let w = net::write(c.fd, rec[..n], timeout_of(c.timeout_ms));
        if w < 0 { return w; }
        at = end;
        if data.len == 0 { break; }
    }
    return data.len;
}

// Sends close_notify, closes the socket, frees the context.
fn tls_close(c: TlsConn&) {
    if c.ctx > 0 && !c.closed && c.fd >= 0 {
        var out: u8[>..] = [];
        out.resize(1024, 0);
        let n = gsspi_shutdown(c.ctx, out);
        if n > 0 { net::write(c.fd, out[..n], timeout_of(min(c.timeout_ms, 2000))); }
    }
    c.closed = true;
    if c.fd >= 0 { net::close(c.fd); c.fd = -1; }
    conn_free(c);
}

// The server's certificate (DER), for x509::parse; empty if none.
fn tls_peer_certificate(c: const TlsConn&) -> u8[>..] {
    var buf: u8[>..] = [];
    buf.resize(65536, 0);
    let n = gsspi_peer_certificate(c.ctx, buf);
    if n < 0 { buf.clear(); } else { buf.resize(n, 0); }
    return buf;
}

// The version negotiated: 0x0303 (TLS 1.2), 0x0304 (TLS 1.3), ...; < 0 if
// it cannot say.
fn tls_version(c: const TlsConn&) -> i64 {
    var none: u8[0] = [];
    return gsspi_connection(c.ctx, 0, none);
}

// The cipher suite, IANA's number (0x1302: TLS_AES_256_GCM_SHA384).
fn tls_cipher_suite(c: const TlsConn&) -> i64 {
    var none: u8[0] = [];
    return gsspi_connection(c.ctx, 1, none);
}

// Its name as Windows gives it ("TLS_AES_256_GCM_SHA384").
fn tls_cipher_suite_name(c: const TlsConn&) -> u8[>..] {
    var buf: u8[>..] = [];
    buf.resize(256, 0);
    let n = gsspi_connection(c.ctx, 3, buf);
    if n < 0 { buf.clear(); } else { buf.resize(n, 0); }
    return buf;
}

fn tls_error_text(st: i64) -> u8[>..] {
    var out: u8[>..] = [];
    if st == net::ERR_ARG { out.append("net: bad host or port"); }
    else if st == net::ERR_RESOLVE { out.append("net: the name does not resolve"); }
    else if st == net::ERR_CONNECT { out.append("net: cannot connect"); }
    else if st == net::ERR_TIMEOUT { out.append("net: timed out"); }
    else if st == net::ERR_IO { out.append("net: connection reset or failed"); }
    else { out.append(error_text(st)); }
    return out;
}
