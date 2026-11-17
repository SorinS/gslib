// tpm2.transport: how commands reach a TPM.
//
//   tcp:HOST:PORT     raw command and response bytes over TCP: swtpm's data
//                     channel (`swtpm socket --server type=tcp,port=PORT`), or
//                     a TPM emulator with TPM_PORT
//   mssim:HOST:PORT   the Microsoft simulator's protocol, as tpm2-tss's
//                     mssim TCTI speaks it: TPM_SEND_COMMAND (8), the
//                     locality and the command's size before each command,
//                     a u32 0 after each response, on PORT; the platform
//                     channel on PORT+1 gets TPM_SIGNAL_POWER_ON (1) and
//                     TPM_SIGNAL_NV_ON (11) when opened, so the TPM then
//                     needs Startup; TPM_SESSION_END (20) on both at close
//   device:PATH       a TPM character device, Linux's /dev/tpmrm0 (the
//                     kernel's resource manager) or /dev/tpm0, through sys:
//                     one write of the command, one read of the response.
//                     Where there is none, ERR_TRANSPORT
//   tbs:              Windows' TPM Base Services: not done (Tbsi_Context_Create
//                     and Tbsip_Submit_Command, from tbs.dll); ERR_UNSUPPORTED
//
// A Tpm is a fixed-size handle: the transport, its sockets or file, the
// last response code (rc) and what the transport said (io).

namespace tpm2;

import std;
import net;
import sys;
import tpm2;

let TRANSPORT_TCP:    i64 = 1;
let TRANSPORT_MSSIM:  i64 = 2;
let TRANSPORT_DEVICE: i64 = 3;

let MSSIM_SIGNAL_POWER_ON: u32 = 1;
let MSSIM_SEND_COMMAND:    u32 = 8;
let MSSIM_SIGNAL_NV_ON:    u32 = 11;
let MSSIM_SESSION_END:     u32 = 20;

struct Tpm {
    kind:       i64 = 0,
    fd:         i64 = -1,  // the data channel, or the device
    pfd:        i64 = -1,  // mssim's platform channel
    timeout_ms: i32 = 30000,
    locality:   u8  = 0,
    rc:         u32 = 0,   // the last command's response code
    io:         i64 = 0,   // the last transport error (net::ERR_* or the device's -errno)
}

fn parse_host_port(s: const u8[:]) -> const u8[:], i32, bool {
    let colon = rfind(s, ":");
    if colon <= 0 { return s, 0, false; }
    let port, ok = parse_int(s[colon + 1..]);
    if !ok || port <= 0 || port > 65535 { return s, 0, false; }
    var host = s[..colon];
    if host.len >= 2 && host[0] == '[' && host[host.len - 1] == ']' { host = host[1..host.len - 1]; }
    return host, port as i32, true;
}

fn read_full(t: Tpm&, fd: i64, buf: u8[:]) -> bool {
    var got = 0;
    while got < buf.len {
        let n = net::read(fd, buf[got..], t.timeout_ms);
        if n <= 0 { t.io = if n == 0 { net::ERR_IO } else { n }; return false; }
        got += n;
    }
    return true;
}

fn write_u32(t: Tpm&, fd: i64, v: u32) -> bool {
    var b: u8[>..] = [];
    put_u32(b, v);
    let n = net::write(fd, b, t.timeout_ms);
    if n < 0 { t.io = n; return false; }
    return true;
}

fn read_u32(t: Tpm&, fd: i64) -> u32, bool {
    var b: u8[4] = [0; 4];
    if !read_full(t, fd, b) { return 0, false; }
    return be32(b, 0), true;
}

// Opens a TPM by its spec (tcp:H:P, mssim:H:P, device:PATH). OK, or
// ERR_ARG for a spec it cannot read, ERR_TRANSPORT (t.io says why) or
// ERR_UNSUPPORTED (tbs:).
fn open(spec: const u8[:], timeout_ms: i32 = 30000) -> Tpm, i64 {
    var t = Tpm { timeout_ms: timeout_ms, .. };
    if starts_with(spec, "tcp:") || starts_with(spec, "mssim:") {
        let mssim = starts_with(spec, "mssim:");
        let host, port, ok = parse_host_port(spec[(if mssim { 6 } else { 4 })..]);
        if !ok { return t, ERR_ARG; }
        let fd = net::dial(host, port, timeout_ms);
        if fd < 0 { t.io = fd; return t, ERR_TRANSPORT; }
        t.fd = fd;
        t.kind = TRANSPORT_TCP;
        if mssim {
            t.kind = TRANSPORT_MSSIM;
            let pfd = net::dial(host, port + 1, timeout_ms);
            if pfd < 0 { t.io = pfd; net::close(fd); t.fd = -1; return t, ERR_TRANSPORT; }
            t.pfd = pfd;
            if !platform_signal(t, MSSIM_SIGNAL_POWER_ON) || !platform_signal(t, MSSIM_SIGNAL_NV_ON) {
                close(t);
                return t, ERR_TRANSPORT;
            }
        }
        return t, OK;
    }
    if starts_with(spec, "device:") {
        let fd = sys::open(spec[7..], sys::O_RDWR, 0);
        if fd < 0 { t.io = fd; return t, ERR_TRANSPORT; }
        t.fd = fd;
        t.kind = TRANSPORT_DEVICE;
        return t, OK;
    }
    if starts_with(spec, "tbs:") { return t, ERR_UNSUPPORTED; }
    return t, ERR_ARG;
}

// The kernel takes one command per write and gives its response to the
// next read: the response's length, or sys's error (a short write is EIO).
fn device_transmit(fd: i64, cmd: const u8[:], out: u8[:]) -> i64 {
    let w = sys::write(fd, cmd);
    if w < 0 { return w; }
    if w != cmd.len { return -5; }
    return sys::read(fd, out);
}

// An mssim platform signal: false unless the simulator acknowledges it with 0.
fn platform_signal(t: Tpm&, sig: u32) -> bool {
    if t.kind != TRANSPORT_MSSIM { return false; }
    if !write_u32(t, t.pfd, sig) { return false; }
    let ack, ok = read_u32(t, t.pfd);
    return ok && ack == 0;
}

fn close(t: Tpm&) {
    if t.kind == TRANSPORT_MSSIM {
        write_u32(t, t.fd, MSSIM_SESSION_END);
        write_u32(t, t.pfd, MSSIM_SESSION_END);
    }
    if t.kind == TRANSPORT_DEVICE { sys::close(t.fd); }
    else {
        net::close(t.fd);
        net::close(t.pfd);
    }
    t.fd = -1;
    t.pfd = -1;
    t.kind = 0;
}

// One command's bytes to the TPM and its response's bytes back, the header
// checked: a tag of ST_NO_SESSIONS or ST_SESSIONS, a size of at least 10 and
// at most MAX_RESPONSE that is the bytes that came. OK, ERR_TRANSPORT or
// ERR_MALFORMED.
fn transmit(t: Tpm&, cmd: const u8[:]) -> u8[>..], i64 {
    var rsp: u8[>..] = [];
    if t.kind == 0 { return rsp, ERR_TRANSPORT; }
    if t.kind == TRANSPORT_DEVICE {
        rsp.resize(MAX_RESPONSE + 1, 0);
        let n = device_transmit(t.fd, cmd, rsp);
        if n < 0 { t.io = n; rsp.clear(); return rsp, ERR_TRANSPORT; }
        rsp.resize(n);
        if n < 10 || n > MAX_RESPONSE || be32(rsp, 2) != n { return rsp, ERR_MALFORMED; }
        let tag = be16(rsp, 0);
        if tag != ST_NO_SESSIONS && tag != ST_SESSIONS { return rsp, ERR_MALFORMED; }
        return rsp, OK;
    }
    var framed: u8[>..] = [];
    if t.kind == TRANSPORT_MSSIM {
        put_u32(framed, MSSIM_SEND_COMMAND);
        put_u8(framed, t.locality);
        put_u32(framed, cmd.len as u32);
    }
    framed.append(cmd);
    let w = net::write(t.fd, framed, t.timeout_ms);
    if w < 0 { t.io = w; return rsp, ERR_TRANSPORT; }
    var size: i64 = 0;
    if t.kind == TRANSPORT_MSSIM {
        let s, ok = read_u32(t, t.fd);
        if !ok { return rsp, ERR_TRANSPORT; }
        size = s;
        if size < 10 || size > MAX_RESPONSE { return rsp, ERR_MALFORMED; }
    }
    var hdr: u8[10] = [0; 10];
    if !read_full(t, t.fd, hdr) { return rsp, ERR_TRANSPORT; }
    let tag = be16(hdr, 0);
    let n = be32(hdr, 2) as i64;
    if tag != ST_NO_SESSIONS && tag != ST_SESSIONS { return rsp, ERR_MALFORMED; }
    if n < 10 || n > MAX_RESPONSE { return rsp, ERR_MALFORMED; }
    if t.kind == TRANSPORT_MSSIM && n != size { return rsp, ERR_MALFORMED; }
    rsp.append(hdr);
    rsp.resize(n, 0);
    if !read_full(t, t.fd, rsp[10..]) { return rsp, ERR_TRANSPORT; }
    if t.kind == TRANSPORT_MSSIM {
        let ack, ok = read_u32(t, t.fd);
        if !ok { return rsp, ERR_TRANSPORT; }
    }
    return rsp, OK;
}

// The transport's last error as text.
fn io_text(t: const Tpm&) -> const u8[:] {
    if t.kind == TRANSPORT_DEVICE || t.io < -5 { return "device error"; }
    if t.io == net::ERR_ARG { return "bad host or port"; }
    if t.io == net::ERR_RESOLVE { return "host does not resolve"; }
    if t.io == net::ERR_CONNECT { return "connection refused"; }
    if t.io == net::ERR_TIMEOUT { return "timed out"; }
    if t.io == net::ERR_IO { return "connection closed or reset"; }
    return "";
}

// What went wrong, for a message: the error, the TPM's response code
// for ERR_TPM, the transport's for ERR_TRANSPORT.
fn describe(t: const Tpm&, e: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(error_text(e));
    if e == ERR_TPM { out.append(": "); out.append(rc_text(t.rc)); }
    if e == ERR_TRANSPORT && io_text(t).len > 0 { out.append(": "); out.append(io_text(t)); }
    return out;
}
