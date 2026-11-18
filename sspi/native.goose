// sspi.native: SSPI itself, Windows' secur32.dll (and crypt32.dll for a
// certificate it hands out), bound by extern blocks with no C, as Go's
// alexbrainman/sspi binds them with syscall and no cgo.
//
// SSPI takes pointers inside its structures (a SecBufferDesc's buffers, a
// SecBuffer's bytes, a credential's strings), and some may be null, so
// every structure SSPI reads or writes is laid out by hand in memory
// allocated from kernel32 (LocalAlloc), written with RtlMoveMemory and
// read back with it or ffi::bytes; a pointer is a u64. The layouts are
// Win64's, checked against MSVC's offsetof.
//
// Credentials and contexts are ids, slots of two tables of such blocks. A
// context's block holds its SSPI handle, then its state (Ctx), and points
// to the bytes it keeps: those given and not yet used (a TLS record split
// over two reads, the extra bytes after a handshake message), plaintext
// not yet taken, TLS bytes to send. So the callers in sspi.goose and
// sspi.schannel only move bytes between a socket and these functions.
//
// The tables are this thread's, so an id is used on the thread that made
// it (or one spawned after); the blocks themselves are the process's.
//
// Results are SSPI's status codes, int32 widened: 0 is SEC_E_OK, SEC_I_*
// are positive, SEC_E_* negative. Ids, lengths and counts are >= 0.

namespace sspi;

import std;
import os;
import ffi;

extern "kernel32" {
    fn LocalAlloc(flags: u32, n: u64) -> u64;
    fn LocalFree(p: u64) -> u64;
    fn mem_move(dst: u64, src: u64, n: u64) = "RtlMoveMemory";
    fn mem_put(dst: u64, src: const u8&, n: u64) = "RtlMoveMemory";
    fn mem_get(dst: u8&, src: u64, n: u64) = "RtlMoveMemory";
    fn mem_put64(dst: u64, src: const u64&, n: u64) = "RtlMoveMemory";
    fn mem_get64(dst: u64&, src: u64, n: u64) = "RtlMoveMemory";
    fn mem_put32(dst: u64, src: const u32&, n: u64) = "RtlMoveMemory";
    fn mem_get32(dst: u32&, src: u64, n: u64) = "RtlMoveMemory";
    fn ctx_read(dst: Ctx&, src: u64, n: u64) = "RtlMoveMemory";
    fn ctx_write(dst: u64, src: const Ctx&, n: u64) = "RtlMoveMemory";
    fn mem_zero(dst: u64, n: u64) = "RtlZeroMemory";
    fn lstrlenW(s: u64) -> i32;
}

extern "secur32" {
    fn EnumerateSecurityPackagesW(count: u32&, info: u64&) -> i32;
    fn QuerySecurityPackageInfoW(name: const u8&, info: u64&) -> i32;
    fn AcquireCredentialsHandleW(principal: u64, package: const u8&, use_: u32, logon_id: u64, auth_data: u64,
                                 get_key: u64, get_key_arg: u64, cred: u64, expiry: i64&) -> i32;
    fn FreeCredentialsHandle(cred: u64) -> i32;
    fn InitializeSecurityContextW(cred: u64, ctx: u64, target: u64, req: u32, reserved1: u32, rep: u32,
                                  input: u64, reserved2: u32, new_ctx: u64, output: u64, attrs: u32&,
                                  expiry: i64&) -> i32;
    fn AcceptSecurityContext(cred: u64, ctx: u64, input: u64, req: u32, rep: u32, new_ctx: u64, output: u64,
                             attrs: u32&, expiry: i64&) -> i32;
    fn CompleteAuthToken(ctx: u64, token: u64) -> i32;
    fn DeleteSecurityContext(ctx: u64) -> i32;
    fn ApplyControlToken(ctx: u64, input: u64) -> i32;
    fn QueryContextAttributesW(ctx: u64, attr: u32, buf: u64) -> i32;
    fn FreeContextBuffer(p: u64) -> i32;
    fn EncryptMessage(ctx: u64, qop: u32, msg: u64, seq: u32) -> i32;
    fn MakeSignature(ctx: u64, qop: u32, msg: u64, seq: u32) -> i32;
    fn DecryptMessage(ctx: u64, msg: u64, seq: u32, qop: u64) -> i32;
    fn VerifySignature(ctx: u64, msg: u64, seq: u32, qop: u32&) -> i32;
}

extern "crypt32" {
    fn CertFreeCertificateContext(cert: u64) -> i32;
}

// --- Constants (sspi.h, schannel.h) -----------------------------------------------

let LMEM_ZEROINIT:        u32 = 0x40;
let NATIVE_DREP:          u32 = 0x10;
let ISC_ALLOCATE:         i64 = 0x100;    // ISC_REQ_ALLOCATE_MEMORY, ASC_REQ_ALLOCATE_MEMORY
let B_EMPTY:              i64 = 0;
let B_DATA:               i64 = 1;
let B_TOKEN:              i64 = 2;
let B_EXTRA:              i64 = 5;
let B_TRAILER:            i64 = 6;
let B_HEADER:             i64 = 7;
let B_PADDING:            i64 = 9;
let B_STREAM:             i64 = 10;
let B_ALERT:              i64 = 17;
let ATTR_SIZES:           u32 = 0;
let ATTR_NAMES:           u32 = 1;
let ATTR_STREAM:          u32 = 4;
let ATTR_PACKAGE:         u32 = 10;
let ATTR_NEGOTIATION:     u32 = 12;
let ATTR_REMOTE_CERT:     u32 = 0x53;
let ATTR_CONN_INFO:       u32 = 0x5a;
let ATTR_CIPHER_INFO:     u32 = 0x64;
let SCH_CLIENT_PROTOCOLS: i64 = 0x20 | 0x80 | 0x200 | 0x800 | 0x2000;   // SSL3, TLS 1.0 to 1.3, client
let SCHANNEL_SHUTDOWN:    i64 = 1;
// A step after the handshake: stream, confidentiality, sequence and replay detection.
let POST_FLAGS: i64 = 0x100 | 0x8000 | 0x10 | 0x8 | 0x4;

let MAX_CREDS: i64 = 256;
let MAX_CTXS:  i64 = 1024;

// --- Memory SSPI sees -------------------------------------------------------------

fn at(p: u64, off: i64) -> u64 { p + (off as! u64) }

fn falloc(n: i64) -> u64 { LocalAlloc(LMEM_ZEROINIT, max(n, 1) as! u64) }

fn ffree(p: u64) { if p != 0 { LocalFree(p); } }

fn fwipe(p: u64, n: i64) { if p != 0 && n > 0 { mem_zero(p, n as! u64); } }

fn get64(p: u64) -> u64 {
    var v: u64 = 0;
    mem_get64(v, p, 8);
    return v;
}

fn get32(p: u64) -> i64 {
    var v: u32 = 0;
    mem_get32(v, p, 4);
    return v;
}

fn put64(p: u64, v: u64) {
    let x = v;
    mem_put64(p, x, 8);
}

fn put32(p: u64, v: i64) {
    let x = ((v as! u64) & 0xffffffff) as! u32;
    mem_put32(p, x, 4);
}

fn fput(p: u64, data: const u8[:]) { if data.len > 0 { mem_put(p, data[0], data.len as! u64); } }

// n bytes at p into out from at.
fn fget(out: u8[:], to: i64, p: u64, n: i64) { if n > 0 { mem_get(out[to], p, n as! u64); } }

// A SecBuffer at p, and a SecBufferDesc of count of them.
fn put_buf(p: u64, cb: i64, kind: i64, pv: u64) {
    put32(p, cb);
    put32(at(p, 4), kind);
    put64(at(p, 8), pv);
}

fn put_desc(p: u64, count: i64, bufs: u64) {
    put32(p, 0);
    put32(at(p, 4), count);
    put64(at(p, 8), bufs);
}

fn buf_cb(p: u64) -> i64 { get32(p) }
fn buf_kind(p: u64) -> i64 { get32(at(p, 4)) }
fn buf_pv(p: u64) -> u64 { get64(at(p, 8)) }

// --- Strings ----------------------------------------------------------------------

// s as UTF-16LE with its NUL, for SSPI; false if s is not UTF-8, holds a
// NUL or is too long.
fn widen(s: const u8[:]) -> u8[>..], bool {
    var w: u8[>..] = [];
    if s.len > 1 << 20 { return w, false; }
    var back: u8[>..] = [];
    var nul = false;
    each_utf8(s) {
        let cp = it;
        if cp == 0 { nul = true; }
        push_utf8(back, cp);
        if cp >= 0x10000 {
            let v = cp - 0x10000;
            let hi = 0xD800 + (v >> 10);
            let lo = 0xDC00 + (v & 0x3FF);
            w.push((hi & 0xff) as! u8);
            w.push((hi >> 8) as! u8);
            w.push((lo & 0xff) as! u8);
            w.push((lo >> 8) as! u8);
        } else {
            w.push((cp & 0xff) as! u8);
            w.push((cp >> 8) as! u8);
        }
    };
    // Malformed UTF-8 comes back from the decoder as U+FFFD, which does
    // not encode as the bytes it replaced.
    if nul || back != s { w.clear(); return w, false; }
    w.push(0);
    w.push(0);
    return w, true;
}

fn wipe(b: u8[>..]&) { for i in 0..b.len { b[i] = 0; } }

// The NUL-terminated UTF-16 string at p as UTF-8 (an unpaired surrogate
// as U+FFFD, as WideCharToMultiByte has it); "" for null.
fn narrow(p: u64) -> u8[>..] {
    var out: u8[>..] = [];
    if p == 0 { return out; }
    let n: i64 = lstrlenW(p);
    let w = ffi::bytes(p, n * 2);
    var i = 0;
    while i + 1 < w.len {
        var cp: i64 = w[i] | ((w[i + 1] as i64) << 8);
        i += 2;
        if cp >= 0xD800 && cp < 0xDC00 && i + 1 < w.len {
            let lo: i64 = w[i] | ((w[i + 1] as i64) << 8);
            if lo >= 0xDC00 && lo < 0xE000 {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            }
        }
        if cp >= 0xD800 && cp < 0xE000 { cp = 0xFFFD; }
        push_utf8(out, cp);
    }
    return out;
}

// narrow's text into out: its length, or SEC_E_BUFFER_TOO_SMALL.
fn narrow_into(p: u64, out: u8[:]) -> i64 {
    let s = narrow(p);
    if s.len > out.len { return SEC_E_BUFFER_TOO_SMALL; }
    for i in 0..s.len { out[i] = s[i]; }
    return s.len;
}

// --- The platform -----------------------------------------------------------------

// 1 Windows, 2 elsewhere, 0 not asked yet. Windows always has OS=Windows_NT
// in its environment; Goose has no compile-time test of the platform yet.
var PLATFORM: i64 = 0;

fn windows_here() -> bool {
    if PLATFORM == 0 {
        var v: u8[>..] = [];
        PLATFORM = if ::env("OS", v) && v == "Windows_NT" { 1 } else { 2 };
    }
    return PLATFORM == 1;
}

fn gsspi_platform() -> i32 { if windows_here() { 1 } else { 0 } }

// --- The tables -------------------------------------------------------------------

// A credential's block: its handle (16 bytes), then 1 if it is Schannel's.
var CREDS: u64[MAX_CREDS];

// A context's block: its handle (16 bytes), the new handle a first step
// makes (16), then a Ctx.
var CTXS: u64[MAX_CTXS];

struct Ctx {
    cred:       i64,
    schannel:   i64,
    server:     i64,
    has_handle: i64,
    done:       i64,
    closed:     i64,
    renego:     i64,         // a post-handshake message under way
    tls13:      i64,
    attrs:      i64,
    last:       i64,
    out_len:    i64,         // the last token made
    in_ptr:     u64,         // bytes given, not yet used
    in_len:     i64,
    in_cap:     i64,
    plain_ptr:  u64,         // decrypted, not yet taken
    plain_len:  i64,
    plain_off:  i64,
    pend_ptr:   u64,         // TLS bytes to send (TLS 1.3's KeyUpdate)
    pend_len:   i64,
    have_ss:    i64,         // SecPkgContext_StreamSizes
    ss_header:  i64,
    ss_trailer: i64,
    ss_max:     i64,
    have_sz:    i64,         // SecPkgContext_Sizes
    sz_max_sig: i64,
    sz_block:   i64,
    sz_trailer: i64,
}

let CTX_AT: i64 = 32;

// A Ctx's bytes, as RtlMoveMemory moves them.
fn ctx_size() -> i64 {
    let one: Ctx[1] = [default<Ctx>()];
    return bytes_of(one).len;
}

let CTX_SIZE: i64 = ctx_size();

fn ctx_load(b: u64) -> Ctx {
    var c = default<Ctx>();
    ctx_read(c, at(b, CTX_AT), CTX_SIZE as! u64);
    return c;
}

fn ctx_store(b: u64, c: const Ctx&) { ctx_write(at(b, CTX_AT), c, CTX_SIZE as! u64); }

fn cred_block(id: i64) -> u64 { if id < 1 || id > MAX_CREDS { 0 } else { CREDS[id - 1] } }

fn ctx_block(id: i64) -> u64 { if id < 1 || id > MAX_CTXS { 0 } else { CTXS[id - 1] } }

fn cred_slot() -> i64 {
    for i in 0..MAX_CREDS { if CREDS[i] == 0 { return i + 1; } }
    return SEC_E_INSUFFICIENT_MEMORY;
}

fn in_append(c: Ctx&, data: const u8[:]) -> bool {
    if c.in_len + data.len > c.in_cap {
        var cap = if c.in_cap > 0 { c.in_cap } else { 16384 };
        while cap < c.in_len + data.len { cap *= 2; }
        let q = falloc(cap);
        if q == 0 { return false; }
        if c.in_len > 0 { mem_move(q, c.in_ptr, c.in_len as! u64); }
        fwipe(c.in_ptr, c.in_cap);
        ffree(c.in_ptr);
        c.in_ptr = q;
        c.in_cap = cap;
    }
    fput(at(c.in_ptr, c.in_len), data);
    c.in_len += data.len;
    return true;
}

// Keeps the last n bytes of the input (SECBUFFER_EXTRA's), drops the rest.
fn in_keep_tail(c: Ctx&, n: i64) {
    let k = min(n, c.in_len);
    if k > 0 { mem_move(c.in_ptr, at(c.in_ptr, c.in_len - k), k as! u64); }
    c.in_len = k;
}

// --- Packages ---------------------------------------------------------------------

// A SecPkgInfoW at p as a line: "name\tcapabilities\tversion\trpcid\t
// max_token\tcomment\n".
fn pkg_line(out: u8[>..]&, p: u64) {
    out.append(narrow(get64(at(p, 16))));
    let version = get32(at(p, 4)) & 0xffff;
    let rpcid = (get32(at(p, 4)) >> 16) & 0xffff;
    out.append(str("\t", get32(p), "\t", version, "\t", rpcid, "\t", get32(at(p, 8)), "\t"));
    for c in narrow(get64(at(p, 24))) { out.push(if c == '\t' || c == '\n' || c == '\r' { ' ' } else { c }); }
    out.push('\n');
}

// Every security package, one line each (pkg_line's). The bytes it takes
// (out may be too small: then call again with that many), or a status < 0.
fn gsspi_packages(out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    var n:    u32 = 0;
    var list: u64 = 0;
    let st = EnumerateSecurityPackagesW(n, list);
    if st != 0 { return st; }
    var text: u8[>..] = [];
    for i in 0..(n as i64) { pkg_line(text, at(list, i * 32)); }
    FreeContextBuffer(list);
    if text.len <= out.len { for i in 0..text.len { out[i] = text[i]; } }
    return text.len;
}

// One package, as a line of gsspi_packages: its length, or a status < 0
// (SEC_E_SECPKG_NOT_FOUND when there is none of that name).
fn gsspi_package_info(name: const u8[:], out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let w, ok = widen(name);
    if !ok || name.len == 0 { return SEC_E_INVALID_PARAMETER; }
    var p: u64 = 0;
    let st = QuerySecurityPackageInfoW(w[0], p);
    if st != 0 { return st; }
    var line: u8[>..] = [];
    pkg_line(line, p);
    FreeContextBuffer(p);
    if line.len > out.len { return SEC_E_BUFFER_TOO_SMALL; }
    for i in 0..line.len { out[i] = line[i]; }
    return line.len;
}

// --- Credentials ------------------------------------------------------------------

// A wide string in memory SSPI sees: its address (0 if s is empty and
// allowed to be); n is its length in characters.
fn fwide(w: const u8[:]) -> u64 {
    let p = falloc(w.len);
    if p != 0 { fput(p, w); }
    return p;
}

// Credentials for a package (Negotiate, NTLM, Kerberos, ...): use is 1
// inbound (a server's), 2 outbound (a client's), 3 both. With user empty,
// the logged-on user's; else that user's, with domain and password. The
// credentials' id, or a status < 0.
fn gsspi_acquire(package: const u8[:], use_: i32, user: const u8[:], domain: const u8[:], password: const u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    if use_ < 1 || use_ > 3 { return SEC_E_INVALID_PARAMETER; }
    var pkg, ok1 = widen(package);
    var u, ok2 = widen(user);
    var d, ok3 = widen(domain);
    var pw, ok4 = widen(password);
    var rc: i64 = SEC_E_INVALID_PARAMETER;
    if ok1 && ok2 && ok3 && ok4 && package.len > 0 {
        rc = cred_slot();
        if rc > 0 {
            let b = falloc(32);
            // SEC_WINNT_AUTH_IDENTITY_W: user, its length, domain, its
            // length, password, its length, flags (UNICODE).
            let id = falloc(48);
            let fu = fwide(u);
            let fd = fwide(d);
            let fp = fwide(pw);
            put64(id, fu);
            put32(at(id, 8), (u.len - 2) / 2);
            put64(at(id, 16), fd);
            put32(at(id, 24), (d.len - 2) / 2);
            put64(at(id, 32), fp);
            put32(at(id, 40), (pw.len - 2) / 2);
            put32(at(id, 44), 2);
            var expiry: i64 = 0;
            let st = AcquireCredentialsHandleW(0, pkg[0], use_ as! u32, 0, if user.len > 0 { id } else { 0 },
                                               0, 0, b, expiry);
            fwipe(fp, pw.len);
            ffree(fu);
            ffree(fd);
            ffree(fp);
            ffree(id);
            if st != 0 { ffree(b); rc = st; }
            else { CREDS[rc - 1] = b; }
        }
    }
    wipe(pw);
    return rc;
}

// Schannel's client credentials. flags are SCH_CRED_* (manual
// validation, no revocation checks, ...); min_version and max_version are
// TLS's (0x0301 to 0x0304), 0 for the system's default. SCH_CREDENTIALS,
// which TLS 1.3 needs, and SCHANNEL_CRED where the system predates it.
// The credentials' id, or a status < 0.
fn gsspi_acquire_schannel(flags: i32, min_version: i32, max_version: i32) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let versions: i64[5] = [0x0300, 0x0301, 0x0302, 0x0303, 0x0304];
    let bits:     i64[5] = [0x20, 0x80, 0x200, 0x800, 0x2000];
    let lo:       i64    = if min_version != 0 { min_version } else { 0x0301 };
    let hi:       i64    = if max_version != 0 { max_version } else { 0x0304 };
    if lo > hi { return SEC_E_INVALID_PARAMETER; }
    var enabled: i64 = 0;
    for i in 0..5 { if versions[i] >= lo && versions[i] <= hi { enabled |= bits[i]; } }
    if enabled == 0 { return SEC_E_INVALID_PARAMETER; }
    let id = cred_slot();
    if id < 0 { return id; }
    let b = falloc(32);
    let pkg, ok = widen(SCHANNEL);
    let limited = min_version != 0 || max_version != 0;
    // TLS_PARAMETERS at 128: the protocols disabled at 16.
    // SCH_CREDENTIALS at 0: version 5, flags at 52, one TLS_PARAMETERS at 56 and 64.
    let sc = falloc(256);
    put32(at(sc, 128 + 16), if limited { SCH_CLIENT_PROTOCOLS & ~enabled } else { 0 });
    put32(sc, 5);
    put32(at(sc, 52), flags);
    put32(at(sc, 56), 1);
    put64(at(sc, 64), at(sc, 128));
    var expiry: i64 = 0;
    var st = AcquireCredentialsHandleW(0, pkg[0], 2, 0, sc, 0, 0, b, expiry);
    if st != 0 {
        // Older than Windows 10 1809: SCHANNEL_CRED, version 4, without
        // TLS 1.3: the protocols enabled at 56, flags at 72.
        fwipe(sc, 256);
        put32(sc, 4);
        put32(at(sc, 56), if limited { enabled & ~0x2000 } else { 0 });
        put32(at(sc, 72), flags);
        st = AcquireCredentialsHandleW(0, pkg[0], 2, 0, sc, 0, 0, b, expiry);
    }
    ffree(sc);
    if st != 0 { ffree(b); return st; }
    put32(at(b, 16), 1);
    CREDS[id - 1] = b;
    return id;
}

fn gsspi_free_credentials(id: i64) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = cred_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    let st = FreeCredentialsHandle(b);
    fwipe(b, 32);
    ffree(b);
    CREDS[id - 1] = 0;
    return st;
}

// --- Contexts ---------------------------------------------------------------------

// A new context on credentials, client (server 0) or server (1): its id,
// or a status < 0. The SSPI context itself comes with the first step.
fn gsspi_context(cred: i64, server: i32) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let cb = cred_block(cred);
    if cb == 0 { return SEC_E_INVALID_HANDLE; }
    for i in 0..MAX_CTXS {
        if CTXS[i] == 0 {
            let b = falloc(CTX_AT + CTX_SIZE);
            if b == 0 { return SEC_E_INSUFFICIENT_MEMORY; }
            var c = default<Ctx>();
            c.cred = cred;
            c.schannel = get32(at(cb, 16));
            c.server = if server != 0 { 1 } else { 0 };
            ctx_store(b, c);
            CTXS[i] = b;
            return i + 1;
        }
    }
    return SEC_E_INSUFFICIENT_MEMORY;
}

fn gsspi_delete_context(id: i64) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    let c = ctx_load(b);
    var st: i64 = 0;
    if c.has_handle != 0 { st = DeleteSecurityContext(b); }
    fwipe(c.in_ptr, c.in_cap);
    ffree(c.in_ptr);
    fwipe(c.plain_ptr, c.plain_len);
    ffree(c.plain_ptr);
    ffree(c.pend_ptr);
    fwipe(b, CTX_AT + CTX_SIZE);
    ffree(b);
    CTXS[id - 1] = 0;
    return st;
}

// Bytes from the peer for the context's next step (a token, or TLS
// records): how many it now holds, or a status < 0.
fn gsspi_feed(id: i64, data: const u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    var c = ctx_load(b);
    if !in_append(c, data) { return SEC_E_INSUFFICIENT_MEMORY; }
    ctx_store(b, c);
    return c.in_len;
}

// How many bytes the context holds from the peer and has not used.
fn gsspi_pending_input(id: i64) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    return ctx_load(b).in_len;
}

fn ensure_sizes(b: u64, c: Ctx&) -> bool {
    if c.have_sz == 0 {
        let q = falloc(16);
        if QueryContextAttributesW(b, ATTR_SIZES, q) == 0 {
            c.have_sz = 1;
            c.sz_max_sig = get32(at(q, 4));
            c.sz_block = get32(at(q, 8));
            c.sz_trailer = get32(at(q, 12));
        }
        ffree(q);
    }
    return c.have_sz != 0;
}

fn after_done(b: u64, c: Ctx&) {
    c.done = 1;
    if c.schannel != 0 {
        let q = falloc(64);
        if QueryContextAttributesW(b, ATTR_STREAM, q) == 0 {
            c.have_ss = 1;
            c.ss_header = get32(q);
            c.ss_trailer = get32(at(q, 4));
            c.ss_max = get32(at(q, 8));
        }
        fwipe(q, 64);
        c.tls13 = if QueryContextAttributesW(b, ATTR_CONN_INFO, q) == 0 && (get32(q) & (0x1000 | 0x2000)) != 0 { 1 } else { 0 };
        ffree(q);
    } else {
        ensure_sizes(b, c);
    }
}

// The tokens SSPI made into out from to (and freed): the new length, or
// SEC_E_BUFFER_TOO_SMALL.
fn take_tokens(bufs: u64, count: i64, out: u8[:], to: i64) -> i64 {
    var n = to;
    for i in 0..count {
        let p = at(bufs, i * 16);
        let pv = buf_pv(p);
        let cb = buf_cb(p);
        if pv != 0 && cb > 0 {
            if n >= 0 {
                if n + cb > out.len { n = SEC_E_BUFFER_TOO_SMALL; }
                else { fget(out, n, pv, cb); n += cb; }
            }
            FreeContextBuffer(pv);
        }
    }
    return n;
}

let S_CONTINUE_NEEDED:   i64 = 0x00090312;
let S_COMPLETE_NEEDED:   i64 = 0x00090313;
let S_COMPLETE_CONTINUE: i64 = 0x00090314;

// One step of the handshake: InitializeSecurityContext (a client) or
// AcceptSecurityContext (a server), on what gsspi_feed gave it. The token
// to send goes into out (gsspi_out_len says how long; it is also sent
// when the step fails, as a TLS alert). SEC_E_OK when the context is
// established, SEC_I_CONTINUE_NEEDED when the peer has more to say,
// SEC_E_INCOMPLETE_MESSAGE when more of its bytes are needed, else an
// error. target is the server's name (a client's), flags ISC_REQ_* or
// ASC_REQ_*.
fn gsspi_step(id: i64, target: const u8[:], flags: i32, out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    var c = ctx_load(b);
    let cb = cred_block(c.cred);
    if cb == 0 { return SEC_E_INVALID_HANDLE; }
    c.out_len = 0;
    var t: u64 = 0;
    if target.len > 0 {
        let w, ok = widen(target);
        if !ok { ctx_store(b, c); return SEC_E_INVALID_PARAMETER; }
        t = fwide(w);
    }
    // The input SecBufferDesc at 0 and its buffers at 16; the output's at
    // 64 and 80.
    let s = falloc(160);
    let have_in = c.in_len > 0;
    put_desc(s, if c.schannel != 0 { 2 } else { 1 }, at(s, 16));
    put_buf(at(s, 16), c.in_len, B_TOKEN, c.in_ptr);
    put_buf(at(s, 32), 0, B_EMPTY, 0);
    let outs = if c.schannel != 0 { 2 } else { 1 };
    put_desc(at(s, 64), outs, at(s, 80));
    put_buf(at(s, 80), 0, B_TOKEN, 0);
    put_buf(at(s, 96), 0, B_ALERT, 0);
    put_buf(at(s, 112), 0, B_EMPTY, 0);
    var attrs:  u32 = 0;
    var expiry: i64 = 0;
    let ctxp: u64 = if c.has_handle != 0 { b } else { 0 };
    let newp: u64 = if c.has_handle != 0 { b } else { at(b, 16) };
    let req = (flags | ISC_ALLOCATE) as! u32;
    var st: i64 = 0;
    if c.server != 0 {
        st = AcceptSecurityContext(cb, ctxp, if have_in { s } else { 0 }, req, NATIVE_DREP, newp, at(s, 64),
                                   attrs, expiry);
    } else {
        st = InitializeSecurityContextW(cb, ctxp, t, req, 0, if c.schannel != 0 { 0 } else { NATIVE_DREP },
                                        if have_in { s } else { 0 }, 0, newp, at(s, 64), attrs, expiry);
    }
    ffree(t);
    if c.has_handle == 0 && (st == 0 || st == S_CONTINUE_NEEDED || st == S_COMPLETE_NEEDED ||
                             st == S_COMPLETE_CONTINUE) {
        mem_move(b, at(b, 16), 16);
        c.has_handle = 1;
    }
    if st == S_COMPLETE_NEEDED || st == S_COMPLETE_CONTINUE {
        let cs = CompleteAuthToken(b, at(s, 64));
        st = if cs != 0 { cs } else if st == S_COMPLETE_NEEDED { 0 } else { S_CONTINUE_NEEDED };
    }
    c.attrs = attrs;
    c.last = st;
    let n = take_tokens(at(s, 80), outs, out, 0);
    let extra = if buf_kind(at(s, 32)) == B_EXTRA { buf_cb(at(s, 32)) } else { 0 };
    ffree(s);
    if n < 0 { ctx_store(b, c); return n; }
    c.out_len = n;
    if st == SEC_E_INCOMPLETE_MESSAGE { ctx_store(b, c); return st; }   // keep the input, wait for more
    if c.schannel != 0 && have_in && extra > 0 { in_keep_tail(c, extra); }
    else { c.in_len = 0; }
    if st == 0 { after_done(b, c); }
    ctx_store(b, c);
    return st;
}

// The length of the token the last step made.
fn gsspi_out_len(id: i64) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    return if b == 0 { SEC_E_INVALID_HANDLE } else { ctx_load(b).out_len };
}

// The ISC_RET_* or ASC_RET_* flags the last step gave the context.
fn gsspi_context_flags(id: i64) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    return if b == 0 { SEC_E_INVALID_HANDLE } else { ctx_load(b).attrs };
}

// A made context's block, or 0.
fn handle_block(id: i64) -> u64 {
    let b = ctx_block(id);
    return if b == 0 || ctx_load(b).has_handle == 0 { 0 } else { b };
}

// The package that was negotiated (NTLM or Kerberos under Negotiate; the
// package itself otherwise), into out: its length, or a status < 0.
fn gsspi_context_package(id: i64, out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = handle_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    let q = falloc(16);
    var rc: i64 = 0;
    if QueryContextAttributesW(b, ATTR_NEGOTIATION, q) == 0 && get64(q) != 0 {
        // SecPkgContext_NegotiationInfoW: the SecPkgInfoW, whose name is at 16.
        let info = get64(q);
        rc = narrow_into(get64(at(info, 16)), out);
        FreeContextBuffer(info);
    } else {
        let st = QueryContextAttributesW(b, ATTR_PACKAGE, q);
        let p = get64(q);
        if st != 0 { rc = st; }
        else {
            rc = narrow_into(if p != 0 { get64(at(p, 16)) } else { 0 }, out);
            if p != 0 { FreeContextBuffer(p); }
        }
    }
    ffree(q);
    return rc;
}

// The name the context authenticated: a server's client ("DOMAIN\user"),
// a client's own. Its length, or a status < 0.
fn gsspi_context_user(id: i64, out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = handle_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    let q = falloc(8);
    let st = QueryContextAttributesW(b, ATTR_NAMES, q);
    let name = get64(q);
    ffree(q);
    if st != 0 { return st; }
    let rc = narrow_into(name, out);
    if name != 0 { FreeContextBuffer(name); }
    return rc;
}

// Schannel: the server's certificate (DER) into out: its length, or a
// status < 0.
fn gsspi_peer_certificate(id: i64, out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = handle_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    let q = falloc(8);
    let st = QueryContextAttributesW(b, ATTR_REMOTE_CERT, q);
    let cert = get64(q);
    ffree(q);
    if st != 0 { return st; }
    if cert == 0 { return SEC_E_INTERNAL_ERROR; }
    // CERT_CONTEXT: the encoding at 0, the DER's address at 8, its length at 16.
    let size = get32(at(cert, 16));
    var rc = size;
    if size > out.len { rc = SEC_E_BUFFER_TOO_SMALL; }
    else { fget(out, 0, get64(at(cert, 8)), size); }
    CertFreeCertificateContext(cert);
    return rc;
}

// Schannel: what was negotiated. which: 0 the protocol (TLS's version,
// 0x0303 or 0x0304), 1 the cipher suite (IANA's number), 2 the cipher's
// strength in bits. The suite's name goes into out with which 3 (its
// length). A status < 0 if it cannot say.
fn gsspi_connection(id: i64, which: i32, out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = handle_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    if which == 0 || which == 2 {
        // SecPkgContext_ConnectionInfo: the protocol at 0, the cipher's strength at 8.
        let q = falloc(32);
        let st = QueryContextAttributesW(b, ATTR_CONN_INFO, q);
        let p = get32(q);
        let strength = get32(at(q, 8));
        ffree(q);
        if st != 0 { return st; }
        if which == 2 { return strength; }
        if p & (0x1000 | 0x2000) != 0 { return 0x0304; }
        if p & (0x400 | 0x800) != 0 { return 0x0303; }
        if p & (0x100 | 0x200) != 0 { return 0x0302; }
        if p & (0x40 | 0x80) != 0 { return 0x0301; }
        if p & (0x10 | 0x20) != 0 { return 0x0300; }
        return 0;
    }
    // SecPkgContext_CipherInfo, version 1: the suite at 8, its name at 16.
    let q = falloc(1024);
    put32(q, 1);
    let st = QueryContextAttributesW(b, ATTR_CIPHER_INFO, q);
    var rc: i64 = SEC_E_INVALID_PARAMETER;
    if st != 0 { rc = st; }
    else if which == 1 { rc = get32(at(q, 8)); }
    else if which == 3 { rc = narrow_into(at(q, 16), out); }
    ffree(q);
    return rc;
}

// --- TLS records (Schannel) ------------------------------------------------------

// The largest plaintext one record takes, once the handshake is done.
fn gsspi_max_message(id: i64) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    let c = ctx_load(b);
    return if c.have_ss != 0 { c.ss_max } else { SEC_E_INVALID_HANDLE };
}

// data (at most gsspi_max_message bytes) as one TLS record into out: the
// record's length, or a status < 0.
fn gsspi_encrypt(id: i64, data: const u8[:], out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    let c = ctx_load(b);
    if c.have_ss == 0 || c.closed != 0 { return SEC_E_INVALID_HANDLE; }
    if data.len > c.ss_max { return SEC_E_INVALID_PARAMETER; }
    let need = c.ss_header + data.len + c.ss_trailer;
    if need > out.len { return SEC_E_BUFFER_TOO_SMALL; }
    let rec = falloc(need);
    fput(at(rec, c.ss_header), data);
    let s = falloc(80);
    put_desc(s, 4, at(s, 16));
    put_buf(at(s, 16), c.ss_header, B_HEADER, rec);
    put_buf(at(s, 32), data.len, B_DATA, at(rec, c.ss_header));
    put_buf(at(s, 48), c.ss_trailer, B_TRAILER, at(rec, c.ss_header + data.len));
    put_buf(at(s, 64), 0, B_EMPTY, 0);
    let st = EncryptMessage(b, 0, s, 0);
    var n: i64 = st;
    if st == 0 {
        n = buf_cb(at(s, 16)) + buf_cb(at(s, 32)) + buf_cb(at(s, 48));
        fget(out, 0, rec, n);
    }
    fwipe(rec, need);
    ffree(rec);
    ffree(s);
    return n;
}

let S_CONTEXT_EXPIRED: i64 = 0x00090317;
let S_RENEGOTIATE:     i64 = 0x00090321;

// Grows the bytes to send by n at p.
fn pend_append(c: Ctx&, p: u64, n: i64) -> bool {
    let q = falloc(c.pend_len + n);
    if q == 0 { return false; }
    if c.pend_len > 0 { mem_move(q, c.pend_ptr, c.pend_len as! u64); }
    mem_move(at(q, c.pend_len), p, n as! u64);
    ffree(c.pend_ptr);
    c.pend_ptr = q;
    c.pend_len += n;
    return true;
}

// TLS 1.3's messages after the handshake (NewSessionTicket, KeyUpdate)
// come out of DecryptMessage as SEC_I_RENEGOTIATE, with the records from
// that message on in an EXTRA buffer; InitializeSecurityContext takes
// them, and what it makes (a KeyUpdate of ours) is sent before the next
// record. A TLS 1.2 server's HelloRequest comes the same way and would
// make a ClientHello: that renegotiation is refused.
// SEC_E_INCOMPLETE_MESSAGE while the message is not all there.
fn post_handshake(b: u64, c: Ctx&) -> i64 {
    let cb = cred_block(c.cred);
    if cb == 0 { return SEC_E_INVALID_HANDLE; }
    let s = falloc(128);
    put_desc(s, 2, at(s, 16));
    put_buf(at(s, 16), c.in_len, B_TOKEN, c.in_ptr);
    put_buf(at(s, 32), 0, B_EMPTY, 0);
    put_desc(at(s, 64), 2, at(s, 80));
    put_buf(at(s, 80), 0, B_TOKEN, 0);
    put_buf(at(s, 96), 0, B_ALERT, 0);
    var attrs:  u32 = 0;
    var expiry: i64 = 0;
    let st: i64 = InitializeSecurityContextW(cb, b, 0, POST_FLAGS as! u32, 0, 0, s, 0, b, at(s, 64), attrs, expiry);
    var rc = st;
    for i in 0..2 {
        let p = at(s, 80 + i * 16);
        let pv = buf_pv(p);
        if pv == 0 { continue; }
        let n = buf_cb(p);
        if n > 0 && rc == 0 {
            if c.tls13 == 0 { rc = RENEGOTIATE; }
            else if !pend_append(c, pv, n) { rc = SEC_E_INSUFFICIENT_MEMORY; }
        }
        FreeContextBuffer(pv);
    }
    let extra = if buf_kind(at(s, 32)) == B_EXTRA { buf_cb(at(s, 32)) } else { 0 };
    ffree(s);
    if st == SEC_E_INCOMPLETE_MESSAGE { return st; }
    if st == S_CONTINUE_NEEDED { return RENEGOTIATE; }
    if extra > 0 { in_keep_tail(c, extra); } else { c.in_len = 0; }
    return rc;
}

// One DecryptMessage over the input: its status; the plaintext kept.
fn decrypt_once(b: u64, c: Ctx&) -> i64 {
    let s = falloc(80);
    put_desc(s, 4, at(s, 16));
    put_buf(at(s, 16), c.in_len, B_DATA, c.in_ptr);
    put_buf(at(s, 32), 0, B_EMPTY, 0);
    put_buf(at(s, 48), 0, B_EMPTY, 0);
    put_buf(at(s, 64), 0, B_EMPTY, 0);
    let st: i64 = DecryptMessage(b, s, 0, 0);
    if st != 0 && st != S_CONTEXT_EXPIRED && st != S_RENEGOTIATE { ffree(s); return st; }
    var data:  u64 = 0;
    var extra: u64 = 0;
    for i in 0..4 {
        let p = at(s, 16 + i * 16);
        let kind = buf_kind(p);
        if kind == B_DATA && data == 0 { data = p; }
        else if kind == B_EXTRA && extra == 0 { extra = p; }
    }
    // At close_notify (SEC_I_CONTEXT_EXPIRED) the DATA buffer is the alert
    // record itself, not plaintext. The plaintext lies in the input, so it
    // is copied before the input moves.
    if st == 0 && data != 0 && buf_cb(data) > 0 {
        let n = buf_cb(data);
        let q = falloc(n);
        if q == 0 { ffree(s); return SEC_E_INSUFFICIENT_MEMORY; }
        mem_move(q, buf_pv(data), n as! u64);
        fwipe(c.plain_ptr, c.plain_len);
        ffree(c.plain_ptr);
        c.plain_ptr = q;
        c.plain_len = n;
        c.plain_off = 0;
    }
    if extra != 0 && buf_cb(extra) > 0 { in_keep_tail(c, buf_cb(extra)); } else { c.in_len = 0; }
    ffree(s);
    return st;
}

// Plaintext from the records gsspi_feed gave it, into out: how many bytes
// (> 0), 0 when it needs more of the peer's bytes, END (-100) at the
// peer's close_notify, RENEGOTIATE (-101) when the peer asked to
// renegotiate (refused), or a status < 0. After each call, bytes to send
// may wait in gsspi_take_output.
fn gsspi_decrypt(id: i64, out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    var c = ctx_load(b);
    if c.have_ss == 0 { return SEC_E_INVALID_HANDLE; }
    var rc: i64 = 0;
    loop {
        if c.plain_off < c.plain_len {
            let n = min(c.plain_len - c.plain_off, out.len);
            fget(out, 0, at(c.plain_ptr, c.plain_off), n);
            c.plain_off += n;
            if c.plain_off == c.plain_len {
                fwipe(c.plain_ptr, c.plain_len);
                c.plain_off = 0;
                c.plain_len = 0;
            }
            rc = n;
            break;
        }
        if c.closed != 0 { rc = END; break; }
        if c.in_len == 0 { rc = 0; break; }
        if c.renego != 0 {
            let ps = post_handshake(b, c);
            if ps == SEC_E_INCOMPLETE_MESSAGE { rc = 0; break; }
            if ps != 0 { rc = ps; break; }
            c.renego = 0;
            continue;
        }
        let st = decrypt_once(b, c);
        if st == SEC_E_INCOMPLETE_MESSAGE { rc = 0; break; }
        if st != 0 && st != S_CONTEXT_EXPIRED && st != S_RENEGOTIATE { rc = st; break; }
        if st == S_RENEGOTIATE {
            if c.tls13 == 0 { rc = RENEGOTIATE; break; }
            c.renego = 1;
            if c.in_len == 0 { rc = 0; break; }
        }
        if st == S_CONTEXT_EXPIRED { c.closed = 1; }
    }
    ctx_store(b, c);
    return rc;
}

// TLS bytes the context made to send (TLS 1.3's KeyUpdate in answer to
// the server's), into out: how many, 0 when none; then they are gone.
fn gsspi_take_output(id: i64, out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    var c = ctx_load(b);
    if c.pend_len > out.len { return SEC_E_BUFFER_TOO_SMALL; }
    let n = c.pend_len;
    fget(out, 0, c.pend_ptr, n);
    c.pend_len = 0;
    ctx_store(b, c);
    return n;
}

// The close_notify alert to send, into out: its length, or a status < 0.
fn gsspi_shutdown(id: i64, out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = handle_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    var c = ctx_load(b);
    let cb = cred_block(c.cred);
    if cb == 0 { return SEC_E_INVALID_HANDLE; }
    // The control token at 0 (SCHANNEL_SHUTDOWN, a DWORD at 64), the output at 32.
    let s = falloc(96);
    put32(at(s, 64), SCHANNEL_SHUTDOWN);
    put_desc(s, 1, at(s, 16));
    put_buf(at(s, 16), 4, B_TOKEN, at(s, 64));
    var st: i64 = ApplyControlToken(b, s);
    if st != 0 { ffree(s); return st; }
    put_desc(at(s, 32), 1, at(s, 48));
    put_buf(at(s, 48), 0, B_TOKEN, 0);
    var attrs:  u32 = 0;
    var expiry: i64 = 0;
    st = InitializeSecurityContextW(cb, b, 0, POST_FLAGS as! u32, 0, 0, 0, 0, b, at(s, 32), attrs, expiry);
    let n = take_tokens(at(s, 48), 1, out, 0);
    ffree(s);
    c.closed = 1;
    ctx_store(b, c);
    if st != 0 && st != S_CONTEXT_EXPIRED { return st; }
    return n;
}

// --- Messages (Negotiate, NTLM, Kerberos) ----------------------------------------

// The signature of msg (MakeSignature) into out: its length, or a status
// < 0.
fn gsspi_sign(id: i64, msg: const u8[:], out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    var c = ctx_load(b);
    if c.done == 0 || !ensure_sizes(b, c) { return SEC_E_INVALID_HANDLE; }
    ctx_store(b, c);
    if out.len < c.sz_max_sig { return SEC_E_BUFFER_TOO_SMALL; }
    let m = falloc(msg.len + c.sz_max_sig);
    fput(m, msg);
    let s = falloc(48);
    put_desc(s, 2, at(s, 16));
    put_buf(at(s, 16), msg.len, B_DATA, m);
    put_buf(at(s, 32), c.sz_max_sig, B_TOKEN, at(m, msg.len));
    let st: i64 = MakeSignature(b, 0, s, 0);
    var n = st;
    if st == 0 {
        n = buf_cb(at(s, 32));
        fget(out, 0, at(m, msg.len), n);
    }
    ffree(m);
    ffree(s);
    return n;
}

// Checks sig over msg (VerifySignature): SEC_E_OK or SEC_E_MESSAGE_ALTERED,
// SEC_E_OUT_OF_SEQUENCE, ...
fn gsspi_verify(id: i64, msg: const u8[:], sig: const u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 || ctx_load(b).done == 0 { return SEC_E_INVALID_HANDLE; }
    let m = falloc(msg.len + sig.len);
    fput(m, msg);
    fput(at(m, msg.len), sig);
    let s = falloc(48);
    put_desc(s, 2, at(s, 16));
    put_buf(at(s, 16), msg.len, B_DATA, m);
    put_buf(at(s, 32), sig.len, B_TOKEN, at(m, msg.len));
    var qop: u32 = 0;
    let st: i64 = VerifySignature(b, s, 0, qop);
    ffree(m);
    ffree(s);
    return st;
}

// msg sealed (EncryptMessage) into out as the security token, then the
// ciphertext, then any padding: GSS-API's wrap token as NTLM and Kerberos
// lay it out ([MS-NLMP] 3.4.6: signature, then the sealed message). Its
// length, or a status < 0.
fn gsspi_seal(id: i64, msg: const u8[:], out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    var c = ctx_load(b);
    if c.done == 0 || !ensure_sizes(b, c) { return SEC_E_INVALID_HANDLE; }
    ctx_store(b, c);
    let need = c.sz_trailer + msg.len + c.sz_block;
    if need > out.len { return SEC_E_BUFFER_TOO_SMALL; }
    // The token, the data and the padding, each where SSPI may write its
    // largest.
    let m = falloc(need);
    let tok = m;
    let data = at(m, c.sz_trailer);
    let padding = at(m, c.sz_trailer + msg.len);
    fput(data, msg);
    let s = falloc(64);
    put_desc(s, 3, at(s, 16));
    put_buf(at(s, 16), c.sz_trailer, B_TOKEN, tok);
    put_buf(at(s, 32), msg.len, B_DATA, data);
    put_buf(at(s, 48), c.sz_block, B_PADDING, padding);
    let st: i64 = EncryptMessage(b, 0, s, 0);
    var n = st;
    if st == 0 {
        n = 0;
        for i in 0..3 {
            let p = at(s, 16 + i * 16);
            let cb = buf_cb(p);
            fget(out, n, buf_pv(p), cb);
            n += cb;
        }
    }
    fwipe(m, need);
    ffree(m);
    ffree(s);
    return n;
}

// A sealed message (gsspi_seal's layout) back to the plaintext, into out:
// its length, or a status < 0. SSPI finds the token's end (a STREAM
// buffer); a package that cannot is given the first max-trailer bytes as
// the token.
fn gsspi_unseal(id: i64, msg: const u8[:], out: u8[:]) -> i64 {
    if !windows_here() { return SEC_E_UNSUPPORTED_FUNCTION; }
    let b = ctx_block(id);
    if b == 0 { return SEC_E_INVALID_HANDLE; }
    var c = ctx_load(b);
    if c.done == 0 || !ensure_sizes(b, c) { return SEC_E_INVALID_HANDLE; }
    ctx_store(b, c);
    let m = falloc(msg.len);
    fput(m, msg);
    let s = falloc(48);
    put_desc(s, 2, at(s, 16));
    put_buf(at(s, 16), msg.len, B_STREAM, m);
    put_buf(at(s, 32), 0, B_DATA, 0);
    var st: i64 = DecryptMessage(b, s, 0, 0);
    if st != 0 && c.sz_trailer <= msg.len {
        // No STREAM support: the token, then the data.
        fput(m, msg);
        put_buf(at(s, 16), c.sz_trailer, B_TOKEN, m);
        put_buf(at(s, 32), msg.len - c.sz_trailer, B_DATA, at(m, c.sz_trailer));
        st = DecryptMessage(b, s, 0, 0);
    }
    var n = st;
    if st == 0 {
        n = buf_cb(at(s, 32));
        if n > out.len { n = SEC_E_BUFFER_TOO_SMALL; }
        else { fget(out, 0, buf_pv(at(s, 32)), n); }
    }
    fwipe(m, msg.len);
    ffree(m);
    ffree(s);
    return n;
}
