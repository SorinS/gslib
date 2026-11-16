// sspi: Windows' Security Support Provider Interface, after Go's
// github.com/alexbrainman/sspi: the security packages Windows has
// (Negotiate, NTLM, Kerberos, Schannel's TLS), credentials (the logged-on
// user's, or a name and password), security contexts built a token at a
// time, and the messages a context signs and seals. Two modules on top:
//
//   - sspi.schannel: a TLS client over net's sockets with Windows' own
//     TLS (as alexbrainman/sspi/schannel): the system's roots, its
//     revocation checks and its protocol policy;
//   - sspi.negotiate: "Authorization: Negotiate" for an HTTP client from
//     the Windows login (Kerberos in a domain, NTLM otherwise).
//
//   import gslib.sspi;       // from a program; `import sspi;` inside gslib
//
//   let cred = sspi::acquire(sspi::NEGOTIATE, sspi::CRED_OUTBOUND);
//   let ctx = sspi::context(cred);
//   var token: u8[>..] = [];
//   var st = sspi::step(ctx, "HTTP/web.example.com", sspi::ISC_REQ_CONNECTION, "", token);
//   // send token; while st == sspi::SEC_I_CONTINUE_NEEDED, step again with the reply
//   sspi::delete_context(ctx);
//   sspi::free_credentials(cred);
//
// Results are SSPI's status codes: OK (SEC_E_OK, 0), SEC_I_* (> 0, a
// step that goes on) or SEC_E_* (< 0, an error); error_text says each.
// Credentials and contexts are ids (> 0), their handles kept by the C
// half (sspi/src/sspi.c), which loads secur32 and crypt32 when first
// used. A context is used from one thread at a time.
//
// Windows only: elsewhere every call returns SEC_E_UNSUPPORTED_FUNCTION,
// so a program that uses it builds and runs everywhere and asks
// available() first.

namespace sspi;

import std;

extern fn gsspi_platform() -> i32;
extern fn gsspi_packages(out: u8[:]) -> i64;
extern fn gsspi_package_info(name: const u8[:], out: u8[:]) -> i64;
extern fn gsspi_acquire(package: const u8[:], use_: i32, user: const u8[:], domain: const u8[:], password: const u8[:]) -> i64;
extern fn gsspi_acquire_schannel(flags: i32, min_version: i32, max_version: i32) -> i64;
extern fn gsspi_free_credentials(id: i64) -> i32;
extern fn gsspi_context(cred: i64, server: i32) -> i64;
extern fn gsspi_delete_context(id: i64) -> i32;
extern fn gsspi_feed(id: i64, data: const u8[:]) -> i64;
extern fn gsspi_pending_input(id: i64) -> i64;
extern fn gsspi_step(id: i64, target: const u8[:], flags: i32, out: u8[:]) -> i64;
extern fn gsspi_out_len(id: i64) -> i64;
extern fn gsspi_context_flags(id: i64) -> i64;
extern fn gsspi_context_package(id: i64, out: u8[:]) -> i64;
extern fn gsspi_context_user(id: i64, out: u8[:]) -> i64;
extern fn gsspi_peer_certificate(id: i64, out: u8[:]) -> i64;
extern fn gsspi_connection(id: i64, which: i32, out: u8[:]) -> i64;
extern fn gsspi_max_message(id: i64) -> i64;
extern fn gsspi_encrypt(id: i64, data: const u8[:], out: u8[:]) -> i64;
extern fn gsspi_decrypt(id: i64, out: u8[:]) -> i64;
extern fn gsspi_shutdown(id: i64, out: u8[:]) -> i64;
extern fn gsspi_take_output(id: i64, out: u8[:]) -> i64;
extern fn gsspi_sign(id: i64, msg: const u8[:], out: u8[:]) -> i64;
extern fn gsspi_verify(id: i64, msg: const u8[:], sig: const u8[:]) -> i64;
extern fn gsspi_seal(id: i64, msg: const u8[:], out: u8[:]) -> i64;
extern fn gsspi_unseal(id: i64, msg: const u8[:], out: u8[:]) -> i64;

// --- Packages and constants -----------------------------------------------------

// The packages' names.
let NEGOTIATE: const u8[:] = "Negotiate";
let NTLM:      const u8[:] = "NTLM";
let KERBEROS:  const u8[:] = "Kerberos";
let SCHANNEL:  const u8[:] = "Microsoft Unified Security Protocol Provider";

// What credentials are for (SECPKG_CRED_*).
let CRED_INBOUND:  i64 = 1;        // a server's: accepting contexts
let CRED_OUTBOUND: i64 = 2;        // a client's: initiating them
let CRED_BOTH:     i64 = 3;

// A step's request flags: ISC_REQ_* for a client.
let ISC_REQ_DELEGATE:               i64 = 0x00000001;
let ISC_REQ_MUTUAL_AUTH:            i64 = 0x00000002;
let ISC_REQ_REPLAY_DETECT:          i64 = 0x00000004;
let ISC_REQ_SEQUENCE_DETECT:        i64 = 0x00000008;
let ISC_REQ_CONFIDENTIALITY:        i64 = 0x00000010;
let ISC_REQ_USE_SESSION_KEY:        i64 = 0x00000020;
let ISC_REQ_USE_SUPPLIED_CREDS:     i64 = 0x00000080;
let ISC_REQ_CONNECTION:             i64 = 0x00000800;
let ISC_REQ_EXTENDED_ERROR:         i64 = 0x00004000;
let ISC_REQ_STREAM:                 i64 = 0x00008000;
let ISC_REQ_INTEGRITY:              i64 = 0x00010000;
let ISC_REQ_IDENTIFY:               i64 = 0x00020000;
let ISC_REQ_MANUAL_CRED_VALIDATION: i64 = 0x00080000;
let ISC_REQ_USE_HTTP_STYLE:         i64 = 0x01000000;

// ASC_REQ_* for a server.
let ASC_REQ_DELEGATE:        i64 = 0x00000001;
let ASC_REQ_MUTUAL_AUTH:     i64 = 0x00000002;
let ASC_REQ_REPLAY_DETECT:   i64 = 0x00000004;
let ASC_REQ_SEQUENCE_DETECT: i64 = 0x00000008;
let ASC_REQ_CONFIDENTIALITY: i64 = 0x00000010;
let ASC_REQ_CONNECTION:      i64 = 0x00000800;
let ASC_REQ_INTEGRITY:       i64 = 0x00020000;

// Schannel's credential flags (SCH_CRED_*), for acquire_schannel.
let SCH_CRED_NO_SERVERNAME_CHECK:        i64 = 0x00000004;
let SCH_CRED_MANUAL_CRED_VALIDATION:     i64 = 0x00000008;   // no chain or name check: the caller checks the certificate
let SCH_CRED_NO_DEFAULT_CREDS:           i64 = 0x00000010;   // no client certificate picked for the caller
let SCH_CRED_AUTO_CRED_VALIDATION:       i64 = 0x00000020;   // the chain and the name checked (the default)
let SCH_CRED_REVOCATION_CHECK_CHAIN:     i64 = 0x00000200;
let SCH_CRED_IGNORE_NO_REVOCATION_CHECK: i64 = 0x00000800;
let SCH_CRED_IGNORE_REVOCATION_OFFLINE:  i64 = 0x00001000;
let SCH_USE_STRONG_CRYPTO:               i64 = 0x00400000;

// Status codes. OK and SEC_I_* are successes; SEC_E_* (and CERT_E_*,
// which Schannel's validation gives) are errors, all < 0: the int32
// HRESULTs, widened.
let OK:                          i64 = 0;
let SEC_I_CONTINUE_NEEDED:       i64 = 0x00090312;   // send the token, step again with the reply
let SEC_I_COMPLETE_NEEDED:       i64 = 0x00090313;   // (completed by step: never returned)
let SEC_I_COMPLETE_AND_CONTINUE: i64 = 0x00090314;   // (likewise)
let SEC_I_CONTEXT_EXPIRED:       i64 = 0x00090317;
let SEC_I_RENEGOTIATE:           i64 = 0x00090321;

let SEC_E_INSUFFICIENT_MEMORY:         i64 = -2146893056;   // 0x80090300
let SEC_E_INVALID_HANDLE:              i64 = -2146893055;   // 0x80090301: no such credentials or context
let SEC_E_UNSUPPORTED_FUNCTION:        i64 = -2146893054;   // 0x80090302: not Windows, or not this package
let SEC_E_TARGET_UNKNOWN:              i64 = -2146893053;   // 0x80090303
let SEC_E_INTERNAL_ERROR:              i64 = -2146893052;   // 0x80090304
let SEC_E_SECPKG_NOT_FOUND:            i64 = -2146893051;   // 0x80090305
let SEC_E_INVALID_TOKEN:               i64 = -2146893048;   // 0x80090308
let SEC_E_LOGON_DENIED:                i64 = -2146893044;   // 0x8009030C
let SEC_E_UNKNOWN_CREDENTIALS:         i64 = -2146893043;   // 0x8009030D
let SEC_E_NO_CREDENTIALS:              i64 = -2146893042;   // 0x8009030E
let SEC_E_MESSAGE_ALTERED:             i64 = -2146893041;   // 0x8009030F
let SEC_E_OUT_OF_SEQUENCE:             i64 = -2146893040;   // 0x80090310
let SEC_E_NO_AUTHENTICATING_AUTHORITY: i64 = -2146893039;   // 0x80090311
let SEC_E_CONTEXT_EXPIRED:             i64 = -2146893033;   // 0x80090317
let SEC_E_INCOMPLETE_MESSAGE:          i64 = -2146893032;   // 0x80090318: more of the peer's bytes needed
let SEC_E_BUFFER_TOO_SMALL:            i64 = -2146893023;   // 0x80090321
let SEC_E_WRONG_PRINCIPAL:             i64 = -2146893022;   // 0x80090322
let SEC_E_TIME_SKEW:                   i64 = -2146893020;   // 0x80090324
let SEC_E_UNTRUSTED_ROOT:              i64 = -2146893019;   // 0x80090325
let SEC_E_ILLEGAL_MESSAGE:             i64 = -2146893018;   // 0x80090326
let SEC_E_CERT_UNKNOWN:                i64 = -2146893017;   // 0x80090327
let SEC_E_CERT_EXPIRED:                i64 = -2146893016;   // 0x80090328
let SEC_E_ENCRYPT_FAILURE:             i64 = -2146893015;   // 0x80090329
let SEC_E_DECRYPT_FAILURE:             i64 = -2146893008;   // 0x80090330
let SEC_E_ALGORITHM_MISMATCH:          i64 = -2146893007;   // 0x80090331
let SEC_E_INVALID_PARAMETER:           i64 = -2146892963;   // 0x8009035D
let CERT_E_EXPIRED:                    i64 = -2146762495;   // 0x800B0101
let CERT_E_UNTRUSTEDROOT:              i64 = -2146762487;   // 0x800B0109
let CERT_E_CN_NO_MATCH:                i64 = -2146762481;   // 0x800B010F

// Not SSPI's: a TLS stream's end (the peer's close_notify) and a peer's
// renegotiation, which is refused. Neither collides with net::ERR_*.
let END:         i64 = -100;
let RENEGOTIATE: i64 = -101;

// Whether SSPI is here: Windows.
fn available() -> bool { gsspi_platform() == 1 }

fn failed(st: i64) -> bool { st < 0 }

// ASCII letters compared without case.
fn fold_eq(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in 0..a.len {
        var x = a[i];
        var y = b[i];
        if x >= 'A' && x <= 'Z' { x += 32; }
        if y >= 'A' && y <= 'Z' { y += 32; }
        if x != y { return false; }
    }
    return true;
}

fn hex32(v: i64) -> u8[>..] {
    var out: u8[>..] = "0x";
    let u = (v as! u64) & 0xffffffff;
    var i = 28;
    while i >= 0 {
        let d = ((u >> (i as! u64)) & 15) as! u8;
        out.push(if d < 10 { '0' + d } else { 'A' + d - 10 });
        i -= 4;
    }
    return out;
}

// What a status means, with its code: "SEC_E_LOGON_DENIED (0x8009030C):
// the logon was denied".
fn error_text(st: i64) -> u8[>..] {
    let t = if st == OK { "SEC_E_OK: done" }
    else if st == SEC_I_CONTINUE_NEEDED { "SEC_I_CONTINUE_NEEDED: the peer has more to say" }
    else if st == SEC_I_CONTEXT_EXPIRED { "SEC_I_CONTEXT_EXPIRED: the peer closed the context" }
    else if st == SEC_I_RENEGOTIATE { "SEC_I_RENEGOTIATE: the peer asked to renegotiate" }
    else if st == END { "the peer closed the TLS stream" }
    else if st == RENEGOTIATE { "the peer asked to renegotiate, which is refused" }
    else if st == SEC_E_INSUFFICIENT_MEMORY { "SEC_E_INSUFFICIENT_MEMORY: out of memory, or of credential and context slots" }
    else if st == SEC_E_INVALID_HANDLE { "SEC_E_INVALID_HANDLE: no such credentials or context" }
    else if st == SEC_E_UNSUPPORTED_FUNCTION { "SEC_E_UNSUPPORTED_FUNCTION: not supported (SSPI is Windows')" }
    else if st == SEC_E_TARGET_UNKNOWN { "SEC_E_TARGET_UNKNOWN: the target is unknown" }
    else if st == SEC_E_INTERNAL_ERROR { "SEC_E_INTERNAL_ERROR: the security package failed" }
    else if st == SEC_E_SECPKG_NOT_FOUND { "SEC_E_SECPKG_NOT_FOUND: no such security package" }
    else if st == SEC_E_INVALID_TOKEN { "SEC_E_INVALID_TOKEN: the peer's token is not valid" }
    else if st == SEC_E_LOGON_DENIED { "SEC_E_LOGON_DENIED: the logon was denied" }
    else if st == SEC_E_UNKNOWN_CREDENTIALS { "SEC_E_UNKNOWN_CREDENTIALS: the package does not take these credentials" }
    else if st == SEC_E_NO_CREDENTIALS { "SEC_E_NO_CREDENTIALS: no credentials for the package" }
    else if st == SEC_E_MESSAGE_ALTERED { "SEC_E_MESSAGE_ALTERED: the message was altered" }
    else if st == SEC_E_OUT_OF_SEQUENCE { "SEC_E_OUT_OF_SEQUENCE: a message out of sequence" }
    else if st == SEC_E_NO_AUTHENTICATING_AUTHORITY { "SEC_E_NO_AUTHENTICATING_AUTHORITY: no authority (a domain controller) could be reached" }
    else if st == SEC_E_CONTEXT_EXPIRED { "SEC_E_CONTEXT_EXPIRED: the context has expired" }
    else if st == SEC_E_INCOMPLETE_MESSAGE { "SEC_E_INCOMPLETE_MESSAGE: more of the peer's bytes are needed" }
    else if st == SEC_E_BUFFER_TOO_SMALL { "SEC_E_BUFFER_TOO_SMALL: a buffer is too small" }
    else if st == SEC_E_WRONG_PRINCIPAL { "SEC_E_WRONG_PRINCIPAL: the target is not the principal expected" }
    else if st == SEC_E_TIME_SKEW { "SEC_E_TIME_SKEW: the clocks differ too much" }
    else if st == SEC_E_UNTRUSTED_ROOT { "SEC_E_UNTRUSTED_ROOT: the certificate chain is not trusted" }
    else if st == SEC_E_ILLEGAL_MESSAGE { "SEC_E_ILLEGAL_MESSAGE: the peer's message is malformed (or an alert)" }
    else if st == SEC_E_CERT_UNKNOWN { "SEC_E_CERT_UNKNOWN: a certificate problem" }
    else if st == SEC_E_CERT_EXPIRED { "SEC_E_CERT_EXPIRED: the certificate has expired" }
    else if st == SEC_E_ENCRYPT_FAILURE { "SEC_E_ENCRYPT_FAILURE: encryption failed" }
    else if st == SEC_E_DECRYPT_FAILURE { "SEC_E_DECRYPT_FAILURE: decryption failed" }
    else if st == SEC_E_ALGORITHM_MISMATCH { "SEC_E_ALGORITHM_MISMATCH: no protocol version or cipher in common" }
    else if st == SEC_E_INVALID_PARAMETER { "SEC_E_INVALID_PARAMETER: a bad argument" }
    else if st == CERT_E_EXPIRED { "CERT_E_EXPIRED: the certificate has expired" }
    else if st == CERT_E_UNTRUSTEDROOT { "CERT_E_UNTRUSTEDROOT: the root is not trusted" }
    else if st == CERT_E_CN_NO_MATCH { "CERT_E_CN_NO_MATCH: the certificate is not for that name" }
    else if st > 0 { "a status that goes on" }
    else { "an error" };
    var out: u8[>..] = [];
    if st == END || st == RENEGOTIATE { out.append(t); return out; }
    var colon = 0;
    while colon < t.len && t[colon] != ':' { colon++; }
    out.append(t[..colon]);
    out.append(" (");
    out.append(hex32(st));
    out.append(")");
    out.append(t[colon..]);
    return out;
}

struct Package {
    name:         u8[..128],
    comment:      u8[..512],
    capabilities: i64,          // SECPKG_FLAG_*
    version:      i64,
    rpcid:        i64,          // RPC_C_AUTHN_*: 9 Negotiate, 10 NTLM, 16 Kerberos, 14 Schannel
    max_token:    i64,          // the largest token a step makes
}

fn field_num(f: const u8[:]) -> i64 {
    var v = 0;
    for b in f { if b >= '0' && b <= '9' { v = v * 10 + (b - '0'); } }
    return v;
}

fn parse_package(line: const u8[:]) -> Package {
    var p = Package { name: [], comment: [], capabilities: 0, version: 0, rpcid: 0, max_token: 0 };
    var f = 0;
    var start = 0;
    for i in 0..line.len + 1 {
        if i == line.len || line[i] == '\t' {
            let v = line[start..i];
            if f == 0 { p.name.append(v[..min(v.len, 128)]); }
            else if f == 1 { p.capabilities = field_num(v); }
            else if f == 2 { p.version = field_num(v); }
            else if f == 3 { p.rpcid = field_num(v); }
            else if f == 4 { p.max_token = field_num(v); }
            else if f == 5 { p.comment.append(line[start..min(line.len, start + 512)]); break; }
            f++;
            start = i + 1;
        }
    }
    return p;
}

// Every security package the system has: the list and OK, or a status.
fn packages() -> Package[>..], i64 {
    var list: Package[>..] = [];
    var buf:  u8[>..]      = [];
    buf.resize(16384, 0);
    var n = gsspi_packages(buf);
    if n > buf.len {
        buf.resize(n, 0);
        n = gsspi_packages(buf);
    }
    if n < 0 { return list, n; }
    var start = 0;
    for i in 0..n {
        if buf[i] == '\n' {
            list.push(parse_package(buf[start..i]));
            start = i + 1;
        }
    }
    return list, OK;
}

// One package by name: it and OK, or SEC_E_SECPKG_NOT_FOUND.
fn package_info(name: const u8[:]) -> Package, i64 {
    var buf: u8[>..] = [];
    buf.resize(4096, 0);
    let n = gsspi_package_info(name, buf);
    if n < 0 { return parse_package(""), n; }
    let line = if n > 0 && buf[n - 1] == '\n' { buf[..n - 1] } else { buf[..n] };
    return parse_package(line), OK;
}

// --- Credentials ----------------------------------------------------------------

// The logged-on user's credentials for a package: their id (> 0), or a
// status < 0. use: CRED_OUTBOUND (a client), CRED_INBOUND (a server).
fn acquire(package: const u8[:], use_: i64) -> i64 {
    return gsspi_acquire(package, use_ as! i32, "", "", "");
}

// A user's credentials, by name and password, as SEC_WINNT_AUTH_IDENTITY
// gives them (Negotiate, NTLM, Kerberos): their id, or a status < 0.
// Nothing is checked until a context is made with them.
fn acquire_as(package: const u8[:], use_: i64, user: const u8[:], domain: const u8[:], password: const u8[:]) -> i64 {
    if user.len == 0 { return SEC_E_INVALID_PARAMETER; }
    return gsspi_acquire(package, use_ as! i32, user, domain, password);
}

// Schannel's client credentials: flags SCH_CRED_*, versions TLS's
// (0x0301 to 0x0304; 0 for the system's policy).
fn acquire_schannel(flags: i64, min_version: i64 = 0, max_version: i64 = 0) -> i64 {
    return gsspi_acquire_schannel(flags as! i32, min_version as! i32, max_version as! i32);
}

fn free_credentials(cred: i64) -> i64 { gsspi_free_credentials(cred) }

// --- Contexts -------------------------------------------------------------------

// A context on credentials, a client's (server false) or a server's: its
// id, or a status < 0.
fn context(cred: i64, server: bool = false) -> i64 {
    return gsspi_context(cred, if server { 1 } else { 0 });
}

fn delete_context(ctx: i64) -> i64 { gsspi_delete_context(ctx) }

// The largest token step makes.
let MAX_TOKEN: i64 = 131072;

// One step of making a context: InitializeSecurityContext for a client,
// AcceptSecurityContext for a server, with input the peer's last token
// ("" for a client's first step). out gets the token to send (empty if
// none; it is sent when the step fails too, as a TLS alert). OK: the
// context is made; SEC_I_CONTINUE_NEEDED: send out and step again with
// the reply; SEC_E_INCOMPLETE_MESSAGE (Schannel): more of the peer's
// bytes are needed; else an error. target is the server's name for a
// client (an SPN such as HTTP/web.example.com for Negotiate and
// Kerberos, the host for Schannel), flags ISC_REQ_* or ASC_REQ_*.
fn step(ctx: i64, target: const u8[:], flags: i64, input: const u8[:], out: u8[>..]&) -> i64 {
    out.clear();
    if input.len > 0 {
        let f = gsspi_feed(ctx, input);
        if f < 0 { return f; }
    }
    out.resize(MAX_TOKEN, 0);
    let st = gsspi_step(ctx, target, flags as! i32, out);
    let n = gsspi_out_len(ctx);
    out.resize(if n > 0 { n } else { 0 }, 0);
    return st;
}

// The ISC_RET_* or ASC_RET_* flags the context was given.
fn context_flags(ctx: i64) -> i64 { gsspi_context_flags(ctx) }

// The package the context uses: NTLM or Kerberos under Negotiate, else
// the package itself; "" when it cannot say.
fn context_package(ctx: i64) -> u8[>..] {
    var buf: u8[>..] = [];
    buf.resize(256, 0);
    let n = gsspi_context_package(ctx, buf);
    if n < 0 { buf.clear(); } else { buf.resize(n, 0); }
    return buf;
}

// The user the context is for: a server's client ("DOMAIN\user"), a
// client's own; "" when it cannot say.
fn context_user(ctx: i64) -> u8[>..] {
    var buf: u8[>..] = [];
    buf.resize(1024, 0);
    let n = gsspi_context_user(ctx, buf);
    if n < 0 { buf.clear(); } else { buf.resize(n, 0); }
    return buf;
}

// --- Messages -------------------------------------------------------------------

// msg's signature (MakeSignature) into sig: OK, or a status.
fn sign(ctx: i64, msg: const u8[:], sig: u8[>..]&) -> i64 {
    sig.resize(1024, 0);
    let n = gsspi_sign(ctx, msg, sig);
    if n < 0 { sig.clear(); return n; }
    sig.resize(n, 0);
    return OK;
}

// Checks sig over msg: OK, or SEC_E_MESSAGE_ALTERED, SEC_E_OUT_OF_SEQUENCE, ...
fn verify(ctx: i64, msg: const u8[:], sig: const u8[:]) -> i64 { gsspi_verify(ctx, msg, sig) }

// msg sealed (EncryptMessage) into out: the token, the ciphertext and any
// padding, as GSS-API's wrap lays them out for NTLM and Kerberos. OK, or
// a status.
fn seal(ctx: i64, msg: const u8[:], out: u8[>..]&) -> i64 {
    out.resize(msg.len + 1024, 0);
    let n = gsspi_seal(ctx, msg, out);
    if n < 0 { out.clear(); return n; }
    out.resize(n, 0);
    return OK;
}

// A sealed message back to its plaintext, into out: OK, or a status.
fn unseal(ctx: i64, msg: const u8[:], out: u8[>..]&) -> i64 {
    out.resize(msg.len + 16, 0);
    let n = gsspi_unseal(ctx, msg, out);
    if n < 0 { out.clear(); return n; }
    out.resize(n, 0);
    return OK;
}
