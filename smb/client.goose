// smb.client: an SMB2/3 connection, one request at a time ([MS-SMB2] §3.2).
//
//   dial            TCP, then NEGOTIATE: the dialects between the
//                   options' least and greatest, 3.1.1's contexts, the
//                   server's choice checked against what was offered
//   login_ntlm      SESSION_SETUP with SPNEGO over NTLMv2 (gslib's ntlm),
//   login_kerberos  or over Kerberos with a service ticket (gslib's krb5),
//   login_anonymous or anonymous NTLM; then the session's keys, and the
//                   final response's signature checked
//   tree_connect    a share; 3.0 and 3.0.2's FSCTL_VALIDATE_NEGOTIATE_INFO
//                   on the first one
//   open, read, write, flush, close, query, set_times, truncate, list,
//   stat, statfs, mkdir, unlink, rmdir, rename, read_file, write_file,
//   echo, tree_disconnect, logoff, hangup
//
// Every request after the session is set up is signed when either side
// requires signing (options() requires it), or encrypted when the session
// or the share is (or the options require encryption); a response is
// checked the same way: one that should have been signed or encrypted and
// was not is refused, as is one whose signature or tag is wrong. Credits
// are kept: each request is charged what its size takes (several credits
// for a large READ or WRITE when the server has LARGE_MTU) and asks for
// more, and a large transfer is cut into what the server's maximums and
// the credits in hand allow. Interim responses (STATUS_PENDING) are
// waited past; oplock and lease breaks are not asked for.

namespace smb;

import std;
import net;
import entropy;
import ntlm;
import krb5;
import krb5.ccache;
import krb5.gssapi;
import krb5.spnego;
import smb.crypto;
import smb.messages;

struct Options {
    min_dialect:        u16,         // SMB202
    max_dialect:        u16,         // SMB311
    require_signing:    bool,        // true: every message after the session setup signed (or encrypted)
    require_encryption: bool,        // false: encrypt only when the server asks (for the session or a share)
    ciphers:            u16[..4],    // 3.1.1's offer, preferred first: AES-128-GCM, AES-128-CCM, AES-256-GCM, AES-256-CCM
    signing:            u16[..3],    // 3.1.1's offer: AES-128-GMAC, AES-128-CMAC
    validate_negotiate: bool,        // true: 3.0 and 3.0.2's FSCTL_VALIDATE_NEGOTIATE_INFO
    timeout_ms:         i32,         // 30000: for each response
    max_io:             i64,         // 1 MiB: the largest READ or WRITE asked for
}

fn options() -> Options {
    var o = Options { min_dialect: SMB202, max_dialect: SMB311, require_signing: true, require_encryption: false, ciphers: [],
                      signing: [], validate_negotiate: true, timeout_ms: 30000, max_io: 1 << 20 };
    o.ciphers.push(AES128_GCM);
    o.ciphers.push(AES128_CCM);
    o.ciphers.push(AES256_GCM);
    o.ciphers.push(AES256_CCM);
    o.signing.push(AES_GMAC);
    o.signing.push(AES_CMAC);
    return o;
}

struct Conn {
    fd:              i64,
    opts:            Options,
    server:          u8[..256],      // the name dialed, for the SPN and the NETNAME context
    // NEGOTIATE
    offered:         u16[..8],
    security_mode:   u16,            // ours
    capabilities:    u32,            // ours
    client_guid:     u8[16],
    dialect:         u16,
    server_security: u16,
    server_caps:     u32,
    server_guid:     u8[16],
    max_read:        u32,
    max_write:       u32,
    max_transact:    u32,
    multi_credit:    bool,
    cipher:          u16,            // 0: no encryption possible
    signing_alg:     u16,
    preauth:         u8[64],         // the connection's hash (3.1.1)
    sess_preauth:    u8[64],         // the session's, while it is set up
    // credits and message ids
    credits:         i64,
    next_id:         u64,
    // the session
    session_id:      u64,
    session_flags:   u16,
    have_keys:       bool,
    keys:            Keys,
    signing:         bool,           // requests signed, responses checked
    encrypt:         bool,           // the whole session encrypted
    nonce_count:     u64,
    nonce_salt:      u8[4],
    validated:       bool,
    // the last response
    status:          u32,
    last_tree:       u32,
}

// A share connected to.
struct Tree {
    id:          u32,
    share_type:  u8,
    share_flags: u32,
    encrypt:     bool,               // the share requires encryption
    access:      u32,                // its MaximalAccess for us
}

// An open file or directory.
struct File {
    tree_id: u32,
    encrypt: bool,
    id:      u8[16],
    action:  u32,                    // FILE_OPENED, FILE_CREATED, ...
    info:    FileInfo,               // as the CREATE response had it
}

fn no_conn(opts: const Options&) -> Conn {
    return Conn {
        fd: -1, opts: copy(opts), server: [], offered: [], security_mode: 0, capabilities: 0, client_guid: [0; 16], dialect: 0,
        server_security: 0, server_caps: 0, server_guid: [0; 16], max_read: 65536, max_write: 65536, max_transact: 65536,
        multi_credit: false, cipher: 0, signing_alg: HMAC_SHA256, preauth: [0; 64], sess_preauth: [0; 64], credits: 1,
        next_id: 0, session_id: 0, session_flags: 0, have_keys: false, keys: no_keys(), signing: false, encrypt: false,
        nonce_count: 0, nonce_salt: [0; 4], validated: false, status: 0, last_tree: 0,
    };
}

fn now_secs() -> i64 { time_ns() / 1000000000 }

// --- Messages on the wire ----------------------------------------------------------------------------

// The 64-byte header of a request to fill in: the rest (credits, ids,
// signature) is exchange's.
fn start(out: u8[>..]&, command: u16, tree_id: u32) {
    var h = header(command);
    h.tree_id = tree_id;
    put_header(out, h);
}

fn read_exact(c: Conn&, buf: u8[:]) -> i64 {
    var got = 0;
    while got < buf.len {
        let n = net::read(c.fd, buf[got..], c.opts.timeout_ms);
        if n == net::ERR_TIMEOUT { return ERR_TIMEOUT; }
        if n <= 0 { return ERR_NETWORK; }
        got += n;
    }
    return OK;
}

// One message from the server (a transformed one as it came).
fn receive(c: Conn&, out: u8[>..]&) -> i64 {
    var hdr: u8[4] = [0; 4];
    let e = read_exact(c, hdr);
    if e != OK { return e; }
    let n, ok = transport_len(hdr);
    if !ok || n < HEADER_LEN { return ERR_MALFORMED; }
    out.clear();
    out.resize(n, 0);
    return read_exact(c, out);
}

fn send(c: Conn&, m: const u8[:]) -> i64 {
    var wire: u8[>..] = [];
    put_transport(wire, m.len);
    wire.append(m);
    if net::write(c.fd, wire, c.opts.timeout_ms) < 0 { return ERR_NETWORK; }
    return OK;
}

// The next encryption nonce: a counter, then a random salt chosen with
// the keys; never the same twice under one key.
fn next_nonce(c: Conn&) -> u8[16] {
    var n: u8[16] = [0; 16];
    c.nonce_count++;
    for i in 8 { n[i] = (c.nonce_count >> (8 * i)) as! u8; }
    for i in 4 { n[8 + i] = c.nonce_salt[i]; }
    return n;
}

// Credits a request of `len` payload bytes is charged (§3.2.4.1.5).
fn charge_for(c: const Conn&, len: i64) -> i64 {
    if !c.multi_credit || len <= 65536 { return 1; }
    return 1 + (len - 1) / 65536;
}

// Sends request m (its header from start) and gets its response into
// resp: the credits charged and asked for, the message id, the session,
// then signed or encrypted as the session and share want (or as
// force_sign says); the response decrypted and checked, interim responses
// waited past, credits granted counted. The response's status is in
// c.status; it is OK whatever the status was (callers check it).
fn exchange(c: Conn&, m: u8[>..]&, charge: i64, encrypt: bool, force_sign: bool, resp: u8[>..]&) -> i64 {
    if c.fd < 0 { return ERR_STATE; }
    if c.credits < charge { return ERR_CREDITS; }
    let cmd = get16(m, 12);
    let mid = c.next_id;
    c.next_id += charge as u64;
    c.credits -= charge;
    // CreditCharge is 0 on 2.0.2, which charges one credit a request.
    set16(m, 6, if c.dialect == SMB202 { 0 } else { charge as! u16 });
    var want = charge;
    if c.credits < 256 { want += 64; }
    set16(m, 14, want as! u16);
    for i in 8 { m[24 + i] = (mid >> (8 * i)) as! u8; }
    for i in 8 { m[40 + i] = (c.session_id >> (8 * i)) as! u8; }
    let enc = encrypt && c.have_keys;
    if enc {
        let nonce = next_nonce(c);
        let tm = encrypt_message(c.cipher, c.keys.enc[..c.keys.enc_len], nonce, c.session_id, m);
        let e = send(c, tm);
        if e != OK { return e; }
    } else {
        if c.have_keys && (c.signing || force_sign) && cmd != NEGOTIATE && cmd != SESSION_SETUP {
            sign(c.signing_alg, c.keys.signing, m);
        }
        let e = send(c, m);
        if e != OK { return e; }
    }
    var raw: u8[>..] = [];
    while true {
        let e = receive(c, raw);
        if e != OK { return e; }
        var was_encrypted = false;
        resp.clear();
        if is_transform(raw) {
            if !c.have_keys || transform_session(raw) != c.session_id { return ERR_DECRYPT; }
            let plain, ok = decrypt_message(c.cipher, c.keys.dec[..c.keys.enc_len], raw);
            if !ok { return ERR_DECRYPT; }
            resp.append(plain);
            was_encrypted = true;
        } else {
            resp.append(raw);
        }
        let h, hok = parse_header(resp);
        if !hok || h.flags & FLAGS_SERVER_TO_REDIR == 0 { return ERR_MALFORMED; }
        if h.message_id == UNSOLICITED_ID { continue; }   // a break we did not ask for
        if h.message_id != mid || h.command != cmd { return ERR_MALFORMED; }
        c.credits += h.credits;
        if (enc || c.encrypt) && cmd != NEGOTIATE && cmd != SESSION_SETUP && !was_encrypted { return ERR_DECRYPT; }
        if !was_encrypted && c.have_keys && cmd != NEGOTIATE && cmd != SESSION_SETUP {
            let signed = h.flags & FLAGS_SIGNED != 0;
            let interim = h.status == STATUS_PENDING && h.flags & FLAGS_ASYNC_COMMAND != 0;
            if signed && !verify(c.signing_alg, c.keys.signing, resp) { return ERR_SIGNATURE; }
            if !signed && !interim && (c.signing || force_sign) { return ERR_SIGNATURE; }
        }
        if h.status == STATUS_PENDING && h.flags & FLAGS_ASYNC_COMMAND != 0 { continue; }
        c.status = h.status;
        c.last_tree = h.tree_id;
        if c.credits < 1 { return ERR_CREDITS; }
        return OK;
    }
    return ERR_NETWORK;
}

// The request's status as an error: OK, or ERR_STATUS.
fn status_err(c: const Conn&) -> i64 { if c.status == STATUS_SUCCESS { OK } else { ERR_STATUS } }

// --- NEGOTIATE ---------------------------------------------------------------------------------------

// A connection to host:port with NEGOTIATE done. On an error the
// connection is closed (and c.status may say why).
fn dial(host: const u8[:], port: i64, opts: const Options&) -> Conn, i64 {
    var c = no_conn(opts);
    if host.len > c.server.cap || port < 1 || port > 65535 { return c, ERR_ARG; }
    c.server.append(host);
    c.fd = net::dial(host, port as! i32, opts.timeout_ms);
    if c.fd < 0 {
        let e = if c.fd == net::ERR_TIMEOUT { ERR_TIMEOUT } else { ERR_NETWORK };
        c.fd = -1;
        return c, e;
    }
    let e = negotiate(c);
    if e != OK { hangup(c); }
    return c, e;
}

fn negotiate(c: Conn&) -> i64 {
    let all: u16[5] = [SMB202, SMB21, SMB30, SMB302, SMB311];
    c.offered.clear();
    for d in all { if d >= c.opts.min_dialect && d <= c.opts.max_dialect { c.offered.push(d); } }
    if c.offered.len == 0 { return ERR_ARG; }
    let top = c.offered[c.offered.len - 1];
    entropy::random_bytes(c.client_guid);
    entropy::random_bytes(c.nonce_salt);
    c.security_mode = SIGNING_ENABLED;
    if c.opts.require_signing { c.security_mode |= SIGNING_REQUIRED; }
    c.capabilities = 0;
    if top >= SMB21 { c.capabilities |= CAP_LARGE_MTU; }
    if top >= SMB30 { c.capabilities |= CAP_ENCRYPTION; }

    var r = NegotiateRequest { dialects: [], security_mode: c.security_mode, capabilities: c.capabilities, guid: c.client_guid,
                               salt: [0; 32], ciphers: [], signing: [], netname: [] };
    for d in c.offered { r.dialects.push(d); }
    entropy::random_bytes(r.salt);
    for x in c.opts.ciphers { r.ciphers.push(x); }
    for x in c.opts.signing { r.signing.push(x); }
    if c.server.len <= r.netname.cap { r.netname.append(c.server); }
    var m: u8[>..] = [];
    start(m, NEGOTIATE, 0);
    if !negotiate_request(m, r) { return ERR_ARG; }
    var resp: u8[>..] = [];
    let e = exchange(c, m, 1, false, false, resp);
    if e != OK { return e; }
    if c.status != STATUS_SUCCESS { return ERR_STATUS; }
    let n, ok = parse_negotiate_response(resp);
    if !ok { return if n.dialect == SMB311 { ERR_DIALECT } else { ERR_MALFORMED }; }
    var known = false;
    for d in c.offered { if d == n.dialect { known = true; } }
    if !known { return ERR_DIALECT; }
    c.dialect = n.dialect;
    c.server_security = n.security_mode;
    c.server_caps = n.capabilities;
    c.server_guid = n.guid;
    c.max_read = n.max_read;
    c.max_write = n.max_write;
    c.max_transact = n.max_transact;
    c.multi_credit = c.dialect >= SMB21 && n.capabilities & CAP_LARGE_MTU != 0;
    if c.dialect == SMB311 {
        // The server's choices must be among ours.
        if n.cipher != 0 {
            var ok_c = false;
            for x in c.opts.ciphers { if x == n.cipher { ok_c = true; } }
            if !ok_c { return ERR_DIALECT; }
        }
        c.cipher = n.cipher;
        c.signing_alg = AES_CMAC;
        if n.has_signing {
            var ok_s = false;
            for x in c.opts.signing { if x == n.signing { ok_s = true; } }
            if !ok_s || (n.signing != AES_CMAC && n.signing != AES_GMAC) { return ERR_DIALECT; }
            c.signing_alg = n.signing;
        }
        preauth_update(c.preauth, m);
        preauth_update(c.preauth, resp);
    } else if c.dialect >= SMB30 {
        c.signing_alg = AES_CMAC;
        var ccm = false;
        for x in c.opts.ciphers { if x == AES128_CCM { ccm = true; } }
        c.cipher = if n.capabilities & CAP_ENCRYPTION != 0 && ccm { AES128_CCM } else { 0 };
    } else {
        c.signing_alg = HMAC_SHA256;
        c.cipher = 0;
    }
    if c.opts.require_encryption && c.cipher == 0 { return ERR_UNSUPPORTED; }
    return OK;
}

// --- SESSION_SETUP -------------------------------------------------------------------------------------

// One round of SESSION_SETUP with a security token: the response's
// token in `token`. MORE_PROCESSING_REQUIRED and SUCCESS are OK (check
// c.status); any other status is ERR_AUTH.
fn session_round(c: Conn&, blob: const u8[:], token: u8[>..]&, final: u8[>..]&) -> i64 {
    var m: u8[>..] = [];
    start(m, SESSION_SETUP, 0);
    var mode: u8 = SIGNING_ENABLED as! u8;
    if c.opts.require_signing { mode |= SIGNING_REQUIRED as! u8; }
    session_setup_request(m, mode, 0, 0, blob);
    var resp: u8[>..] = [];
    let e = exchange(c, m, 1, false, false, resp);
    if e != OK { return e; }
    // The request as it went: exchange filled in its header.
    if c.dialect == SMB311 { preauth_update(c.sess_preauth, m); }
    let h, _ = parse_header(resp);
    if c.status != STATUS_SUCCESS && c.status != STATUS_MORE_PROCESSING_REQUIRED { return ERR_AUTH; }
    let flags, span, ok = parse_session_setup_response(resp);
    if !ok { return ERR_MALFORMED; }
    if c.session_id == 0 { c.session_id = h.session_id; }
    if h.session_id != c.session_id { return ERR_MALFORMED; }
    token.clear();
    token.append(span_bytes(resp, span));
    if c.status == STATUS_MORE_PROCESSING_REQUIRED {
        if c.dialect == SMB311 { preauth_update(c.sess_preauth, resp); }
    } else {
        c.session_flags = flags;
        final.clear();
        final.append(resp);
    }
    return OK;
}

fn begin_session(c: Conn&) -> i64 {
    if c.fd < 0 || c.dialect == 0 { return ERR_STATE; }
    if c.session_id != 0 { return ERR_STATE; }
    c.sess_preauth = c.preauth;
    c.have_keys = false;
    c.signing = false;
    c.encrypt = false;
    c.validated = false;
    return OK;
}

// The session's keys from the authentication's key, and the final
// response's signature checked with them: 3.x servers always sign it,
// 2.x ones when signing is required. Guest and anonymous sessions have no
// keys, so they are refused when signing or encryption is required.
fn finish_session(c: Conn&, gss_key: const u8[:], final: const u8[:]) -> i64 {
    // A login with a credential that the server calls a guest or null
    // session: the flags are in the final response, whose signature could
    // not be checked without keys, so a man in the middle could set them
    // and strip signing and encryption from a real login. Refused, as
    // Windows refuses a guest fallback.
    let flagged = c.session_flags & (SESSION_FLAG_IS_GUEST | SESSION_FLAG_IS_NULL) != 0;
    if flagged && gss_key.len > 0 { return ERR_AUTH; }
    let anonymous = flagged || gss_key.len == 0;
    let server_requires = c.server_security & SIGNING_REQUIRED != 0;
    if anonymous {
        if c.opts.require_signing || c.opts.require_encryption || server_requires || c.session_flags & SESSION_FLAG_ENCRYPT_DATA != 0 {
            return ERR_UNSUPPORTED;
        }
        return OK;
    }
    c.keys = derive_keys(c.dialect, gss_key, c.sess_preauth, c.cipher);
    c.signing = c.opts.require_signing || server_requires;
    let signed = get32(final, 16) & FLAGS_SIGNED != 0;
    if signed && !verify(c.signing_alg, c.keys.signing, final) { return ERR_SIGNATURE; }
    if !signed && (c.dialect >= SMB30 || c.signing) { return ERR_SIGNATURE; }
    c.encrypt = c.opts.require_encryption || c.session_flags & SESSION_FLAG_ENCRYPT_DATA != 0;
    if c.encrypt && c.cipher == 0 { return ERR_UNSUPPORTED; }
    c.have_keys = true;
    return OK;
}

// SESSION_SETUP with NTLMv2 inside SPNEGO, the SPN cifs/<server>. The
// server's mechListMIC, when its last token has one, is checked.
fn login_ntlm(c: Conn&, user: const u8[:], domain: const u8[:], password: const u8[:]) -> i64 {
    let cred, ce = ntlm::credentials(user, domain, password);
    if ce != ntlm::OK { return ERR_ARG; }
    return login_ntlm_cred(c, cred);
}

// Anonymous NTLM: a null session (no keys, so not with signing or
// encryption required).
fn login_anonymous(c: Conn&) -> i64 { return login_ntlm_cred(c, ntlm::anonymous_credentials()); }

fn login_ntlm_cred(c: Conn&, cred: ntlm::Credentials) -> i64 {
    let b = begin_session(c);
    if b != OK { return b; }
    var spn: u8[>..] = [];
    spn.append("cifs/");
    spn.append(c.server);
    var ctx = krb5::spnego_ntlm_initiator(cred, spn, ntlm::WANT_SIGN);
    var tok: u8[>..] = [];
    if krb5::spnego_ntlm_init(ctx, tok) != ntlm::OK { return ERR_AUTH; }
    var back: u8[>..] = [];
    var final: u8[>..] = [];
    var rounds = 0;
    while true {
        rounds++;
        if rounds > 4 { return ERR_AUTH; }
        let e = session_round(c, tok, back, final);
        if e != OK { return fail_session(c, e); }
        if c.status == STATUS_SUCCESS { break; }
        tok.clear();
        let done, ne = krb5::spnego_ntlm_init_continue(ctx, back, now_secs(), tok);
        if ne != ntlm::OK || done { return fail_session(c, ERR_AUTH); }
    }
    if back.len > 0 && !ctx.complete && ntlm::established(ctx.ini) {
        var more: u8[>..] = [];
        let done, ne = krb5::spnego_ntlm_init_continue(ctx, back, now_secs(), more);
        if ne != ntlm::OK || !done { return fail_session(c, ERR_AUTH); }
    }
    if !ntlm::established(ctx.ini) { return fail_session(c, ERR_AUTH); }
    var key: u8[>..] = [];
    let sess = krb5::spnego_ntlm_session(ctx);
    if sess.keys { key.append(sess.exported); }
    let fe = finish_session(c, key, final);
    if fe != OK { return fail_session(c, fe); }
    return OK;
}

// SESSION_SETUP with Kerberos inside SPNEGO: `ticket` is a service ticket
// for cifs/<server> (krb5::get_service_ticket and the like). Mutual
// authentication: the server's AP-REP is checked, and the session key is
// the subkey (the acceptor's when it sent one).
fn login_kerberos(c: Conn&, ticket: const krb5::Credential&) -> i64 {
    let b = begin_session(c);
    if b != OK { return b; }
    let now = time_ns();
    var tok: u8[>..] = [];
    var ctx, ie = krb5::spnego_init(ticket, krb5::GSS_MUTUAL | krb5::GSS_INTEG | krb5::GSS_CONF, "", false, "",
                                    now / 1000000000, (now / 1000) % 1000000, tok);
    if ie != krb5::OK { return ERR_AUTH; }
    var back: u8[>..] = [];
    var final: u8[>..] = [];
    var rounds = 0;
    while true {
        rounds++;
        if rounds > 4 { return fail_session(c, ERR_AUTH); }
        let e = session_round(c, tok, back, final);
        if e != OK { return fail_session(c, e); }
        tok.clear();
        if back.len > 0 && !ctx.complete {
            let done, ke = krb5::spnego_init_continue(ctx, back, tok);
            if ke != krb5::OK { return fail_session(c, ERR_AUTH); }
        }
        if c.status == STATUS_SUCCESS { break; }
        if tok.len == 0 { return fail_session(c, ERR_AUTH); }
    }
    if !ctx.gss.established { return fail_session(c, ERR_AUTH); }
    let fe = finish_session(c, ctx.gss.key.value, final);
    if fe != OK { return fail_session(c, fe); }
    return OK;
}

fn fail_session(c: Conn&, e: i64) -> i64 {
    c.have_keys = false;
    c.keys = no_keys();
    c.signing = false;
    c.encrypt = false;
    c.session_id = 0;
    return e;
}

// Ends the session (the connection stays, for another login).
fn logoff(c: Conn&) -> i64 {
    if c.session_id == 0 { return ERR_STATE; }
    var m: u8[>..] = [];
    start(m, LOGOFF, 0);
    empty_request(m);
    var resp: u8[>..] = [];
    let e = exchange(c, m, 1, c.encrypt, false, resp);
    let s = c.status;
    fail_session(c, OK);
    c.status = s;
    if e != OK { return e; }
    return status_err(c);
}

// Closes the connection.
fn hangup(c: Conn&) {
    net::close(c.fd);
    c.fd = -1;
    fail_session(c, OK);
}

// ECHO: whether the server is there.
fn echo(c: Conn&) -> i64 {
    var m: u8[>..] = [];
    start(m, ECHO, 0);
    empty_request(m);
    var resp: u8[>..] = [];
    let e = exchange(c, m, 1, c.encrypt, false, resp);
    if e != OK { return e; }
    return status_err(c);
}

// --- Trees ----------------------------------------------------------------------------------------------

// A share, "\\server\share". The first on 3.0 and 3.0.2 is followed by
// FSCTL_VALIDATE_NEGOTIATE_INFO, signed, whose answer must repeat what
// NEGOTIATE said (a downgrade by someone between is caught there).
fn tree_connect(c: Conn&, unc: const u8[:]) -> Tree, i64 {
    var t = Tree { id: 0, share_type: 0, share_flags: 0, encrypt: false, access: 0 };
    if c.session_id == 0 { return t, ERR_STATE; }
    let server, share, ok = split_unc(unc);
    if !ok { return t, ERR_ARG; }
    var m: u8[>..] = [];
    start(m, TREE_CONNECT, 0);
    if !tree_connect_request(m, unc) { return t, ERR_ARG; }
    var resp: u8[>..] = [];
    let e = exchange(c, m, 1, c.encrypt, false, resp);
    if e != OK { return t, e; }
    if c.status != STATUS_SUCCESS { return t, ERR_STATUS; }
    let info, iok = parse_tree_connect_response(resp);
    if !iok { return t, ERR_MALFORMED; }
    t.id = c.last_tree;
    t.share_type = info.share_type;
    t.share_flags = info.share_flags;
    t.access = info.maximal_access;
    t.encrypt = info.share_flags & SHAREFLAG_ENCRYPT_DATA != 0;
    if (t.encrypt || c.encrypt) && (c.cipher == 0 || !c.have_keys) {
        tree_disconnect(c, t);
        return t, ERR_UNSUPPORTED;
    }
    if (c.dialect == SMB30 || c.dialect == SMB302) && c.opts.validate_negotiate && c.have_keys && !c.validated {
        let ve = validate_negotiate(c, t);
        if ve != OK { return t, ve; }
    }
    return t, OK;
}

// FSCTL_VALIDATE_NEGOTIATE_INFO (§3.2.5.14.12): what we offered, and what
// the server answers must be what it said in NEGOTIATE.
fn validate_negotiate(c: Conn&, t: const Tree&) -> i64 {
    var input: u8[>..] = [];
    put32(input, c.capabilities);
    input.append(c.client_guid);
    put16(input, c.security_mode);
    put16(input, c.offered.len as! u16);
    for d in c.offered { put16(input, d); }
    var m: u8[>..] = [];
    start(m, IOCTL, t.id);
    let fid = no_file_id();
    ioctl_request(m, FSCTL_VALIDATE_NEGOTIATE_INFO, fid, input, 24);
    var resp: u8[>..] = [];
    let e = exchange(c, m, 1, c.encrypt || t.encrypt, true, resp);
    if e != OK { return e; }
    if c.status != STATUS_SUCCESS { return ERR_DIALECT; }
    let ctl, out, ok = parse_ioctl_response(resp);
    if !ok || ctl != FSCTL_VALIDATE_NEGOTIATE_INFO || out.len < 24 { return ERR_DIALECT; }
    let b = span_bytes(resp, out);
    if get32(b, 0) != c.server_caps || b[4..20] != c.server_guid[..] || get16(b, 20) != c.server_security ||
       get16(b, 22) != c.dialect {
        return ERR_DIALECT;
    }
    c.validated = true;
    return OK;
}

fn tree_disconnect(c: Conn&, t: const Tree&) -> i64 {
    var m: u8[>..] = [];
    start(m, TREE_DISCONNECT, t.id);
    empty_request(m);
    var resp: u8[>..] = [];
    let e = exchange(c, m, 1, c.encrypt || t.encrypt, false, resp);
    if e != OK { return e; }
    return status_err(c);
}

// --- Files -------------------------------------------------------------------------------------------------

// CREATE: path within the share ('/' or '\\'), the access wanted, the
// disposition (FILE_OPEN, FILE_CREATE, FILE_OVERWRITE_IF, ...) and
// options (FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, ...).
fn open(c: Conn&, t: const Tree&, path: const u8[:], access: u32, disposition: u32, options: u32) -> File, i64 {
    var f = File { tree_id: t.id, encrypt: t.encrypt, id: [0; 16], action: 0, info: no_info() };
    let p, ok = share_path(path);
    if !ok { return f, ERR_ARG; }
    var m: u8[>..] = [];
    start(m, CREATE, t.id);
    let attrs = if options & FILE_DIRECTORY_FILE != 0 { ATTR_DIRECTORY } else { ATTR_NORMAL };
    if !create_request(m, p, access, attrs, FILE_SHARE_ALL, disposition, options) { return f, ERR_ARG; }
    var resp: u8[>..] = [];
    let e = exchange(c, m, 1, c.encrypt || t.encrypt, false, resp);
    if e != OK { return f, e; }
    if c.status != STATUS_SUCCESS { return f, ERR_STATUS; }
    let action, info, id, cok = parse_create_response(resp);
    if !cok { return f, ERR_MALFORMED; }
    f.action = action;
    f.info = info;
    f.id = id;
    return f, OK;
}

fn file_request(c: Conn&, f: const File&, m: u8[>..]&, charge: i64, resp: u8[>..]&) -> i64 {
    let e = exchange(c, m, charge, c.encrypt || f.encrypt, false, resp);
    if e != OK { return e; }
    return status_err(c);
}

fn close(c: Conn&, f: const File&) -> i64 {
    var m: u8[>..] = [];
    start(m, CLOSE, f.tree_id);
    close_request(m, f.id, 0);
    var resp: u8[>..] = [];
    return file_request(c, f, m, 1, resp);
}

fn flush(c: Conn&, f: const File&) -> i64 {
    var m: u8[>..] = [];
    start(m, FLUSH, f.tree_id);
    flush_request(m, f.id);
    var resp: u8[>..] = [];
    return file_request(c, f, m, 1, resp);
}

// The most a READ or WRITE can carry now: the server's maximum, the
// options', and the credits in hand.
fn io_size(c: const Conn&, server_max: u32) -> i64 {
    var n: i64 = server_max;
    n = ::min(n, c.opts.max_io);
    if c.multi_credit { n = ::min(n, ::max(c.credits, 1) * 65536); } else { n = ::min(n, 65536); }
    return ::max(n, 1);
}

// Up to n bytes from offset; fewer at the end of the file (none past it).
fn read(c: Conn&, f: const File&, offset: u64, n: i64) -> u8[>..], i64 {
    var out: u8[>..] = [];
    var at = offset;
    while out.len < n {
        let want = ::min(n - out.len, io_size(c, c.max_read));
        var m: u8[>..] = [];
        start(m, READ, f.tree_id);
        read_request(m, f.id, at, want as! u32, 0);
        var resp: u8[>..] = [];
        let e = exchange(c, m, charge_for(c, want), c.encrypt || f.encrypt, false, resp);
        if e != OK { return out, e; }
        if c.status == STATUS_END_OF_FILE { break; }
        if c.status != STATUS_SUCCESS { return out, ERR_STATUS; }
        let span, ok = parse_read_response(resp);
        if !ok || span.len > want { return out, ERR_MALFORMED; }
        if span.len == 0 { break; }
        out.append(span_bytes(resp, span));
        at += span.len as u64;
    }
    return out, OK;
}

// All of data at offset.
fn write(c: Conn&, f: const File&, offset: u64, data: const u8[:]) -> i64 {
    var done = 0;
    while done < data.len {
        let n = ::min(data.len - done, io_size(c, c.max_write));
        var m: u8[>..] = [];
        start(m, WRITE, f.tree_id);
        write_request(m, f.id, offset + done as u64, data[done..done + n]);
        var resp: u8[>..] = [];
        let e = file_request(c, f, m, charge_for(c, n), resp);
        if e != OK { return e; }
        let count, ok = parse_write_response(resp);
        if !ok || count > n || count == 0 { return ERR_MALFORMED; }
        done += count;
    }
    return OK;
}

// QUERY_INFO's FileNetworkOpenInformation: times, sizes, attributes now.
fn query(c: Conn&, f: const File&) -> FileInfo, i64 {
    var m: u8[>..] = [];
    start(m, QUERY_INFO, f.tree_id);
    query_info_request(m, f.id, INFO_FILE, FILE_NETWORK_OPEN_INFORMATION, 56, 0);
    var resp: u8[>..] = [];
    let e = file_request(c, f, m, 1, resp);
    if e != OK { return no_info(), e; }
    let span, ok = parse_output_response(resp);
    if !ok { return no_info(), ERR_MALFORMED; }
    let info, iok = parse_network_open(span_bytes(resp, span));
    if !iok { return info, ERR_MALFORMED; }
    return info, OK;
}

fn set_info(c: Conn&, f: const File&, class: u8, buf: const u8[:]) -> i64 {
    var m: u8[>..] = [];
    start(m, SET_INFO, f.tree_id);
    set_info_request(m, f.id, INFO_FILE, class, buf);
    var resp: u8[>..] = [];
    return file_request(c, f, m, 1, resp);
}

// FileBasicInformation: times as FILETIMEs (0: leave), attributes (0: leave).
fn set_times(c: Conn&, f: const File&, created: u64, accessed: u64, written: u64, changed: u64, attributes: u32) -> i64 {
    var b: u8[>..] = [];
    basic_info(b, created, accessed, written, changed, attributes);
    return set_info(c, f, FILE_BASIC_INFORMATION, b);
}

// FileEndOfFileInformation: the file cut or extended to size.
fn truncate(c: Conn&, f: const File&, size: u64) -> i64 {
    var b: u8[>..] = [];
    put64(b, size);
    return set_info(c, f, FILE_END_OF_FILE_INFORMATION, b);
}

// FileDispositionInformation: deleted when the last handle closes.
fn delete_on_close(c: Conn&, f: const File&) -> i64 {
    let b: u8[1] = [1];
    return set_info(c, f, FILE_DISPOSITION_INFORMATION, b);
}

// The space of the share.
fn statfs(c: Conn&, t: const Tree&) -> FsSize, i64 {
    var none = FsSize { total_units: 0, caller_free_units: 0, free_units: 0, sectors_per_unit: 0, bytes_per_sector: 0 };
    var f, e = open(c, t, "", FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN, FILE_DIRECTORY_FILE);
    if e != OK { return none, e; }
    var m: u8[>..] = [];
    start(m, QUERY_INFO, f.tree_id);
    query_info_request(m, f.id, INFO_FILESYSTEM, FILE_FS_FULL_SIZE_INFORMATION, 32, 0);
    var resp: u8[>..] = [];
    let qe = file_request(c, f, m, 1, resp);
    let s = c.status;
    close(c, f);
    c.status = s;
    if qe != OK { return none, qe; }
    let span, ok = parse_output_response(resp);
    if !ok { return none, ERR_MALFORMED; }
    let fs, fok = parse_fs_full_size(span_bytes(resp, span));
    if !fok { return none, ERR_MALFORMED; }
    return fs, OK;
}

// --- Directories and paths ------------------------------------------------------------------------------

// The entries of a directory matching pattern ("*": all, "." and ".."
// left out).
fn list(c: Conn&, t: const Tree&, dir: const u8[:], pattern: const u8[:]) -> DirEntry[>..], i64 {
    var out: DirEntry[>..] = [];
    var f, e = open(c, t, dir, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN, FILE_DIRECTORY_FILE);
    if e != OK { return out, e; }
    var flags = RESTART_SCANS;
    var err = OK;
    while true {
        var m: u8[>..] = [];
        start(m, QUERY_DIRECTORY, f.tree_id);
        let room = io_size(c, c.max_transact);
        if !query_directory_request(m, f.id, FILE_DIRECTORY_INFORMATION, flags, pattern, ::min(room, 65536) as! u32) {
            err = ERR_ARG;
            break;
        }
        flags = 0;
        var resp: u8[>..] = [];
        let qe = exchange(c, m, 1, c.encrypt || f.encrypt, false, resp);
        if qe != OK { err = qe; break; }
        if c.status == STATUS_NO_MORE_FILES { break; }
        if c.status != STATUS_SUCCESS { err = ERR_STATUS; break; }
        let span, ok = parse_output_response(resp);
        var batch: DirEntry[>..] = [];
        if !ok || !parse_directory(span_bytes(resp, span), batch) { err = ERR_MALFORMED; break; }
        for x in batch {
            if x.name[..] != "." && x.name[..] != ".." { out.push(x); }
        }
    }
    let s = c.status;
    close(c, f);
    c.status = s;
    return out, err;
}

// What CREATE tells of a path, without reading it.
fn stat(c: Conn&, t: const Tree&, path: const u8[:]) -> FileInfo, i64 {
    var f, e = open(c, t, path, FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN, 0);
    if e != OK { return no_info(), e; }
    let info = f.info;
    let ce = close(c, f);
    return info, ce;
}

fn mkdir(c: Conn&, t: const Tree&, path: const u8[:]) -> i64 {
    var f, e = open(c, t, path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_CREATE, FILE_DIRECTORY_FILE);
    if e != OK { return e; }
    return close(c, f);
}

fn remove_with(c: Conn&, t: const Tree&, path: const u8[:], options: u32) -> i64 {
    var f, e = open(c, t, path, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN, options);
    if e != OK { return e; }
    let de = delete_on_close(c, f);
    let s = c.status;
    let ce = close(c, f);
    if de != OK { c.status = s; return de; }
    return ce;
}

// Deletes a file (not a directory).
fn unlink(c: Conn&, t: const Tree&, path: const u8[:]) -> i64 { remove_with(c, t, path, FILE_NON_DIRECTORY_FILE) }

// Deletes an empty directory.
fn rmdir(c: Conn&, t: const Tree&, path: const u8[:]) -> i64 { remove_with(c, t, path, FILE_DIRECTORY_FILE) }

// Renames (moves) within the share; replace: over an existing file.
fn rename(c: Conn&, t: const Tree&, from: const u8[:], to: const u8[:], replace: bool) -> i64 {
    let dest, ok = share_path(to);
    if !ok || dest.len == 0 { return ERR_ARG; }
    var f, e = open(c, t, from, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN, 0);
    if e != OK { return e; }
    var b: u8[>..] = [];
    if !rename_info(b, dest, replace) {
        close(c, f);
        return ERR_ARG;
    }
    let re = set_info(c, f, FILE_RENAME_INFORMATION, b);
    let s = c.status;
    let ce = close(c, f);
    if re != OK { c.status = s; return re; }
    return ce;
}

// A whole file.
fn read_file(c: Conn&, t: const Tree&, path: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    var f, e = open(c, t, path, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    if e != OK { return none, e; }
    var data, re = read(c, f, 0, f.info.size as! i64);
    let s = c.status;
    let ce = close(c, f);
    if re != OK { c.status = s; return data, re; }
    return data, ce;
}

// A file made (or replaced) with data.
fn write_file(c: Conn&, t: const Tree&, path: const u8[:], data: const u8[:]) -> i64 {
    var f, e = open(c, t, path, FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE);
    if e != OK { return e; }
    let we = write(c, f, 0, data);
    let s = c.status;
    let ce = close(c, f);
    if we != OK { c.status = s; return we; }
    return ce;
}
