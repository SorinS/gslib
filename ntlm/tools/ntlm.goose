// goose-ntlm: NTLM (NTLMv2 only) on gslib's ntlm, from the command line.
//
//   goose-ntlm hash                       the NT hash (hex) of a password read from stdin
//   goose-ntlm compute CRED --server-challenge HEX --client-challenge HEX [--time FILETIME]
//                      [--target-info HEX] [--session-key HEX]
//                                         NTOWFv2, NTProofStr, the NTLMv2 and LMv2 responses,
//                                         the session base key (and the encrypted session key)
//   goose-ntlm decode [MESSAGE]           an NTLMSSP message (base64, hex, or an "NTLM ..." or
//                                         "Negotiate ..." header value; stdin if none), field by field
//   goose-ntlm initiate CRED [--spn SPN] [--cb-data TEXT | --cb-hex HEX] [--seal] [--spnego]
//   goose-ntlm accept --users FILE [ACCEPT OPTIONS] [--spnego]
//                                         one side of an exchange over stdin and stdout (below)
//   goose-ntlm serve --users FILE [ACCEPT OPTIONS] [--listen ADDR] --port N [--count N]
//                                         an HTTP server whose every path needs NTLM or Negotiate
//   goose-ntlm get CRED [--insecure] URL  GET with NTLM (http.fetch's AUTH_NTLM); the body to stdout
//
// CRED: --user USER (DOMAIN\USER allowed) [--domain DOMAIN] [--workstation NAME] and the
// secret from --password-env VAR (an environment variable), --password-file FILE, or
// --nt-hash-file FILE (32 hex digits; not for get); or --anonymous. Passwords are never
// taken on the command line.
//
// ACCEPT OPTIONS: --spn SPN [--spn-required] (MsvAvTargetName checked), --cb-data TEXT or
// --cb-hex HEX, --cb supported|required (channel bindings: the application data,
// "tls-server-end-point:" and a hash), --require-mic, --allow-anonymous, --skew SECONDS,
// --computer NAME --domain-name NAME (the server's names; WEB and EXAMPLE by default).
// --users FILE: lines "DOMAIN:USER:PASSWORD" (pyspnego's NTLM_USER_FILE format; an empty
// DOMAIN matches any), # comments.
//
// The exchange over stdin and stdout: each side prints "token BASE64" for every token to
// send and reads "token BASE64" lines for those it gets; "done USER" (the acceptor:
// "done DOMAIN\USER") when the context is established, "error TEXT" (exit 1) when it
// fails. Then, line by line: "wrap B64" -> "wrapped B64", "unwrap B64" -> "plain B64",
// "mic B64" -> "mic B64", "verify DATA_B64 MIC_B64" -> "ok"; "quit" or the end of input.
// With --spnego the tokens are SPNEGO (krb5.spnego) with NTLM as the mechanism.
//
// serve answers a request without credentials with 401 and "WWW-Authenticate: NTLM" and
// "WWW-Authenticate: Negotiate"; each connection is authenticated once (raw NTLMSSP under
// either scheme, or SPNEGO under Negotiate), then its requests get "hello DOMAIN\USER".
// It logs to stderr; nothing secret is printed.
//
// Exit status: 0 on success, 1 on failure, 2 on a usage error.

import std;
import os;
import base64;
import gslib from "../..";
import gslib.ntlm;
import gslib.ntlm.crypto;
import gslib.ntlm.messages;
import gslib.ntlm.session;
import gslib.ntlm.client;
import gslib.ntlm.server;
import gslib.ntlm.http;
import gslib.krb5;
import gslib.krb5.gssapi;
import gslib.krb5.messages;
import gslib.krb5.spnego;
import gslib.net;
import gslib.net.http;
import gslib.net.http.conn1;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.net.http.url;

root struct Options {
    user:            u8[>..] = [],
    domain:          u8[>..] = [],
    workstation:     u8[>..] = [],
    password_env:    u8[>..] = [],
    password_file:   u8[>..] = [],
    hash_file:       u8[>..] = [],
    anonymous:       bool    = false,
    spn:             u8[>..] = [],
    spn_required:    bool    = false,
    cb_data:         u8[>..] = [],
    has_cb:          bool    = false,
    cb_mode:         i64     = ntlm::CB_SUPPORTED,
    seal:            bool    = false,
    spnego:          bool    = false,
    users:           u8[>..] = [],
    require_mic:     bool    = false,
    allow_anonymous: bool    = false,
    skew:            i64     = 300,
    computer:        u8[>..] = [],
    domain_name:     u8[>..] = [],
    listen:          u8[>..] = [],
    port:            i64     = -1,
    count:           i64     = 0,
    insecure:        bool    = false,
    url:             u8[>..] = [],
    server_challenge: u8[>..] = [],
    client_challenge: u8[>..] = [],
    time:            u64     = 0,
    target_info:     u8[>..] = [],
    session_key:     u8[>..] = [],
    message:         u8[>..] = [],
}

fn usage() -> i32 {
    write_stderr("usage: goose-ntlm hash | compute | decode | initiate | accept | serve | get (see the source's header)\n");
    return 2;
}

fn say(s: const u8[:]) {
    write_stderr(s);
    write_stderr("\n");
}

fn fail(s: const u8[:]) -> i32 {
    say(str("goose-ntlm: ", s));
    return 1;
}

fn out_line(s: const u8[:]) {
    write_stdout(s);
    write_stdout("\n");
    flush_stdout();
}

fn now_secs() -> i64 { time_ns() / 1000000000 }

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let d = "0123456789abcdef";
    for c in b { out.push(d[c >> 4]); out.push(d[c & 15]); }
    return out;
}

fn unhex(s: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if s.len % 2 != 0 { return out, false; }
    var i = 0;
    while i < s.len {
        var v = 0;
        for k in 2 {
            let c = s[i + k];
            var d = -1;
            if c >= '0' && c <= '9' { d = c - '0'; }
            else if c >= 'a' && c <= 'f' { d = c - 'a' + 10; }
            else if c >= 'A' && c <= 'F' { d = c - 'A' + 10; }
            if d < 0 { out.clear(); return out, false; }
            v = v * 16 + d;
        }
        out.push(v as! u8);
        i += 2;
    }
    return out, true;
}

fn b64(data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    base64::encode(out, data);
    return out;
}

fn first_line(path: const u8[:]) -> u8[>..], bool {
    var data: u8[>..] = [];
    var out: u8[>..] = [];
    if !read_file(path, data) { return out, false; }
    var e = 0;
    while e < data.len && data[e] != '\n' && data[e] != '\r' { e++; }
    out.append(data[..e]);
    return out, true;
}

// --- Credentials and users ------------------------------------------------------------------

fn password_of(o: const Options&) -> u8[>..], bool {
    var pw: u8[>..] = [];
    if o.password_env.len > 0 {
        if !env(o.password_env, pw) { return pw, false; }
        return pw, true;
    }
    if o.password_file.len > 0 {
        let l, ok = first_line(o.password_file);
        pw.append(l);
        return pw, ok;
    }
    return pw, false;
}

fn load_cred(o: const Options&) -> ntlm::Credentials, bool {
    if o.anonymous { return ntlm::anonymous_credentials(), true; }
    if o.user.len == 0 { return ntlm::anonymous_credentials(), false; }
    var c = ntlm::anonymous_credentials();
    if o.hash_file.len > 0 {
        let line, ok = first_line(o.hash_file);
        let h, hok = ntlm::parse_nt_hash(trim(line));
        if !ok || !hok { return c, false; }
        var user: u8[>..] = [];
        var domain: u8[>..] = [];
        user.append(o.user);
        domain.append(o.domain);
        let bs = position(o.user, '\\');
        if o.domain.len == 0 && bs >= 0 {
            user.clear();
            user.append(o.user[bs + 1..]);
            domain.append(o.user[..bs]);
        }
        let cr, e = ntlm::credentials_hash(user, domain, h);
        if e != ntlm::OK { return c, false; }
        c = cr;
    } else {
        let pw, ok = password_of(o);
        if !ok { return c, false; }
        let cr, e = ntlm::credentials(o.user, o.domain, pw);
        if e != ntlm::OK { return c, false; }
        c = cr;
    }
    if o.workstation.len > 0 && ntlm::set_workstation(c, o.workstation) != ntlm::OK { return c, false; }
    return c, true;
}

struct User { domain: u8[..256], user: u8[..256], hash: u8[16] }

// The users file: "DOMAIN:USER:PASSWORD" lines (the password is the rest
// of the line, colons and all).
fn load_users(path: const u8[:], users: User[>..]&) -> bool {
    var data: u8[>..] = [];
    if !read_file(path, data) { return false; }
    var good = true;
    each_split(data, '\n') {
        var line = it;
        if line.len > 0 && line[line.len - 1] == '\r' { line = line[..line.len - 1]; }
        if line.len > 0 && line[0] != '#' {
            let c1 = position(line, ':');
            let rest = if c1 >= 0 { line[c1 + 1..] } else { line[..0] };
            let c2 = position(rest, ':');
            if c1 < 0 || c2 < 0 || c1 > 256 || c2 > 256 { good = false; }
            else {
                let h, ok = ntlm::nt_hash(rest[c2 + 1..]);
                if !ok { good = false; }
                else {
                    var u = User { domain: [], user: [], hash: h };
                    u.domain.append(line[..c1]);
                    u.user.append(rest[..c2]);
                    users.push(u);
                }
            }
        }
    };
    return good;
}

fn lookup(users: const User[:], user: const u8[:], domain: const u8[:], h: u8[:]) -> bool {
    for u in users {
        if ntlm::eq_fold_ascii(u.user, user) && (u.domain.len == 0 || ntlm::eq_fold_ascii(u.domain, domain)) {
            for i in 16 { h[i] = u.hash[i]; }
            return true;
        }
    }
    return false;
}

fn make_acceptor(o: const Options&) -> ntlm::Acceptor {
    var a = ntlm::acceptor(if o.computer.len > 0 { o.computer[..] } else { "WEB" },
                           if o.domain_name.len > 0 { o.domain_name[..] } else { "EXAMPLE" }, "web.example.test", "example.test");
    a.require_mic = o.require_mic;
    a.allow_anonymous = o.allow_anonymous;
    a.skew = o.skew;
    if o.has_cb { ntlm::set_acceptor_bindings(a, o.cb_data, o.cb_mode); } else { a.cb_mode = o.cb_mode; }
    if o.spn.len > 0 { ntlm::set_acceptor_spn(a, o.spn, o.spn_required); }
    return a;
}

// --- hash, compute, decode -----------------------------------------------------------------

fn run_hash() -> i32 {
    var pw: u8[>..] = [];
    read_line(pw);
    let h, ok = ntlm::nt_hash(pw);
    if !ok { return fail("the password is not UTF-8"); }
    out_line(hex(h));
    return 0;
}

fn run_compute(o: const Options&) -> i32 {
    let cred, ok = load_cred(o);
    if !ok || o.anonymous { return fail("credentials: --user and a password or NT hash"); }
    let sc, sok = unhex(o.server_challenge);
    let cc, cok = unhex(o.client_challenge);
    let ti, tok = unhex(o.target_info);
    if !sok || !cok || !tok || sc.len != 8 || cc.len != 8 { return fail("--server-challenge and --client-challenge: 16 hex digits"); }
    let key, kok = ntlm::ntowfv2(cred.nt_hash, cred.user, cred.domain);
    var blob: u8[>..] = [];
    ntlm::client_blob(blob, o.time, cc, ti);
    let proof = ntlm::nt_proof(key, sc, blob);
    var nt: u8[>..] = [];
    nt.append(proof);
    nt.append(blob);
    let sbk = ntlm::session_base_key(key, proof);
    out_line(str("ntowfv2 ", hex(key)));
    out_line(str("ntproofstr ", hex(proof)));
    out_line(str("nt_response ", hex(nt)));
    out_line(str("lmv2_response ", hex(ntlm::lmv2_response(key, sc, cc))));
    out_line(str("session_base_key ", hex(sbk)));
    if o.session_key.len > 0 {
        let rk, rok = unhex(o.session_key);
        if !rok || rk.len != 16 { return fail("--session-key: 32 hex digits"); }
        out_line(str("encrypted_session_key ", hex(ntlm::rc4k(sbk, rk))));
    }
    return 0;
}

let FLAG_NAMES: const u8[:] = "UNICODE,OEM,REQUEST_TARGET,r10,SIGN,SEAL,DATAGRAM,LM_KEY,r9,NTLM,r8,ANONYMOUS,OEM_DOMAIN_SUPPLIED,OEM_WORKSTATION_SUPPLIED,r7,ALWAYS_SIGN,TARGET_TYPE_DOMAIN,TARGET_TYPE_SERVER,r6,EXTENDED_SESSIONSECURITY,IDENTIFY,r5,REQUEST_NON_NT_SESSION_KEY,TARGET_INFO,r4,VERSION,r3,r2,r1,128,KEY_EXCH,56";

fn flag_text(f: u32) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    each_split(FLAG_NAMES, ',') {
        if f & ((1 as u32) << i) != 0 {
            if out.len > 0 { out.push('|'); }
            out.append(it);
        }
        i++;
    };
    return out;
}

fn text16(b: const u8[:]) -> u8[>..] {
    var t: u8[>..] = [];
    if !ntlm::utf8_of_utf16le(t, b) { t.clear(); t.append("(not UTF-16: "); t.append(hex(b)); t.push(')'); }
    return t;
}

fn print_av(ti: const u8[:]) {
    let e = ntlm::av_check(ti);
    if e != ntlm::OK { out_line(str("  target info: ", ntlm::error_text(e), " ", hex(ti))); return; }
    var p = 0;
    while p + 4 <= ti.len {
        let id = ntlm::get16(ti, p);
        let l = ntlm::get16(ti, p + 2) as i64;
        let v = ti[p + 4..p + 4 + l];
        if id == ntlm::AV_EOL { out_line("  MsvAvEOL"); break; }
        if id >= 1 && id <= 5 { out_line(str("  AV ", id, " (name) ", text16(v))); }
        else if id == ntlm::AV_TARGET_NAME { out_line(str("  MsvAvTargetName ", text16(v))); }
        else if id == ntlm::AV_FLAGS { out_line(str("  MsvAvFlags ", ntlm::get32(v, 0))); }
        else if id == ntlm::AV_TIMESTAMP { out_line(str("  MsvAvTimestamp ", ntlm::get64(v, 0), " (unix ", ntlm::filetime_unix(ntlm::get64(v, 0)), ")")); }
        else if id == ntlm::AV_CHANNEL_BINDINGS { out_line(str("  MsvAvChannelBindings ", hex(v))); }
        else if id == ntlm::AV_SINGLE_HOST { out_line(str("  MsvAvSingleHost ", hex(v))); }
        else { out_line(str("  AV ", id, " ", hex(v))); }
        p += 4 + l;
    }
}

fn run_decode(o: const Options&) -> i32 {
    var text: u8[>..] = [];
    if o.message.len > 0 { text.append(o.message); } else { read_stdin(text); }
    let t = trim(text);
    var msg: u8[>..] = [];
    let scheme, tok, hok = ntlm::http_token(t);
    if hok { msg.append(tok); }
    else {
        let h, ok = unhex(t);
        if ok { msg.append(h); }
        else if !base64::decode(msg, t) { return fail("not base64, hex, or an NTLM header"); }
    }
    if !ntlm::is_ntlmssp(msg) { return fail("not an NTLMSSP message (SPNEGO is not decoded)"); }
    let kind = ntlm::get32(msg, 8);
    if kind == ntlm::MSG_NEGOTIATE {
        let f, e = ntlm::parse_negotiate(msg);
        if e != ntlm::OK { return fail(ntlm::error_text(e)); }
        out_line("NEGOTIATE");
        out_line(str("  flags ", f, " ", flag_text(f)));
    } else if kind == ntlm::MSG_CHALLENGE {
        let c, e = ntlm::parse_challenge(msg);
        if e != ntlm::OK { return fail(ntlm::error_text(e)); }
        out_line("CHALLENGE");
        out_line(str("  flags ", c.flags, " ", flag_text(c.flags)));
        out_line(str("  server challenge ", hex(c.server_challenge)));
        out_line(str("  target name ", text16(ntlm::field_bytes(msg, c.target_name))));
        if c.has_version { out_line(str("  version ", hex(c.version))); }
        print_av(ntlm::field_bytes(msg, c.target_info));
    } else if kind == ntlm::MSG_AUTHENTICATE {
        let a, e = ntlm::parse_authenticate(msg);
        if e != ntlm::OK { return fail(ntlm::error_text(e)); }
        out_line("AUTHENTICATE");
        out_line(str("  flags ", a.flags, " ", flag_text(a.flags)));
        out_line(str("  domain ", text16(ntlm::field_bytes(msg, a.domain))));
        out_line(str("  user ", text16(ntlm::field_bytes(msg, a.user))));
        out_line(str("  workstation ", text16(ntlm::field_bytes(msg, a.workstation))));
        out_line(str("  LM response ", a.lm.len, " bytes"));
        out_line(str("  NT response ", a.nt.len, " bytes", if a.nt.len == 24 { " (NTLMv1)" } else if a.nt.len == 0 { "" } else { " (NTLMv2)" }));
        out_line(str("  encrypted session key ", a.key.len, " bytes"));
        out_line(str("  MIC ", if a.has_mic { "present" } else { "absent" }));
        if a.has_version { out_line(str("  version ", hex(a.version))); }
        let nt = ntlm::field_bytes(msg, a.nt);
        if nt.len >= 16 + 28 + 4 {
            let blob = nt[16..];
            out_line(str("  blob time ", ntlm::get64(blob, 8), " (unix ", ntlm::filetime_unix(ntlm::get64(blob, 8)), ")"));
            out_line(str("  client challenge ", hex(blob[16..24])));
            print_av(blob[28..]);
        }
    } else {
        return fail("unknown message type");
    }
    return 0;
}

// --- The exchange over stdin and stdout ------------------------------------------------------

// The next "token B64" line's token; false at the end of input or for
// another line.
fn read_token() -> u8[>..], bool {
    var line: u8[>..] = [];
    var out: u8[>..] = [];
    if !read_line(line) { return out, false; }
    let l = trim(line);
    if l.len < 6 || l[..6] != "token " { return out, false; }
    if !base64::decode(out, trim(l[6..])) { out.clear(); return out, false; }
    return out, true;
}

fn emit_token(t: const u8[:]) { if t.len > 0 { out_line(str("token ", b64(t))); } }

fn decode_arg(s: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let ok = base64::decode(out, trim(s));
    return out, ok;
}

fn session_loop(s: ntlm::Session&) -> i32 {
    var line: u8[>..] = [];
    while true {
        line.clear();
        if !read_line(line) { return 0; }
        let l = trim(line);
        let sp = position(l, ' ');
        let cmd = if sp >= 0 { l[..sp] } else { l };
        let arg = if sp >= 0 { l[sp + 1..] } else { l[..0] };
        if cmd == "quit" { return 0; }
        if cmd == "wrap" || cmd == "unwrap" || cmd == "mic" {
            let d, ok = decode_arg(arg);
            if !ok { out_line("error bad base64"); continue; }
            var o: u8[>..] = [];
            let e = if cmd == "wrap" { ntlm::wrap(s, d, ntlm::sealed(s), o) } else if cmd == "unwrap" { ntlm::unwrap(s, d, o) } else { ntlm::get_mic(s, d, o) };
            if e != ntlm::OK { out_line(str("error ", ntlm::error_text(e))); continue; }
            out_line(str(if cmd == "wrap" { "wrapped " } else if cmd == "unwrap" { "plain " } else { "mic " }, b64(o)));
        } else if cmd == "verify" {
            let sp2 = position(arg, ' ');
            if sp2 < 0 { out_line("error usage"); continue; }
            let d, ok1 = decode_arg(arg[..sp2]);
            let m, ok2 = decode_arg(arg[sp2 + 1..]);
            if !ok1 || !ok2 { out_line("error bad base64"); continue; }
            let e = ntlm::verify_mic(s, d, m);
            if e == ntlm::OK { out_line("ok"); } else { out_line(str("error ", ntlm::error_text(e))); }
        } else {
            out_line("error unknown command");
        }
    }
    return 0;
}

fn run_initiate(o: const Options&) -> i32 {
    let cred, ok = load_cred(o);
    if !ok { return fail("credentials: --user and --password-env, --password-file or --nt-hash-file, or --anonymous"); }
    let want = if o.seal { ntlm::WANT_SEAL } else { ntlm::WANT_SIGN };
    if o.spnego {
        var ctx = krb5::spnego_ntlm_initiator(cred, o.spn, want);
        if o.has_cb { ntlm::set_channel_bindings(ctx.ini, o.cb_data); }
        var t1: u8[>..] = [];
        let e = krb5::spnego_ntlm_init(ctx, t1);
        if e != ntlm::OK { out_line(str("error ", ntlm::error_text(e))); return 1; }
        emit_token(t1);
        while true {
            let tok, tok_ok = read_token();
            if !tok_ok { out_line("error no token"); return 1; }
            var out: u8[>..] = [];
            let done, ce = krb5::spnego_ntlm_init_continue(ctx, tok, now_secs(), out);
            emit_token(out);
            if ce != ntlm::OK { out_line(str("error ", ntlm::error_text(ce))); return 1; }
            if done { break; }
        }
        out_line(str("done ", cred.user));
        return session_loop(ctx.ini.session);
    }
    var ini = ntlm::initiator(cred, o.spn, want);
    if o.has_cb { ntlm::set_channel_bindings(ini, o.cb_data); }
    var t1: u8[>..] = [];
    let e = ntlm::negotiate(ini, t1);
    if e != ntlm::OK { out_line(str("error ", ntlm::error_text(e))); return 1; }
    emit_token(t1);
    let t2, t2ok = read_token();
    if !t2ok { out_line("error no token"); return 1; }
    var t3: u8[>..] = [];
    let ae = ntlm::authenticate(ini, t2, now_secs(), t3);
    if ae != ntlm::OK { out_line(str("error ", ntlm::error_text(ae))); return 1; }
    emit_token(t3);
    out_line(str("done ", cred.user));
    return session_loop(ini.session);
}

fn run_accept(o: const Options&) -> i32 {
    var users: User[>..] = [];
    if o.users.len == 0 || !load_users(o.users, users) { return fail("--users FILE: lines DOMAIN:USER:PASSWORD"); }
    var ctx = krb5::spnego_ntlm_acceptor(make_acceptor(o));
    while true {
        let tok, tok_ok = read_token();
        if !tok_ok { out_line("error no token"); return 1; }
        var out: u8[>..] = [];
        var done = false;
        var e = ntlm::OK;
        if o.spnego {
            let d, ae = krb5::spnego_ntlm_accept(ctx, tok, now_secs(), out) { user, domain, h => lookup(users, user, domain, h) };
            done = d;
            e = ae;
        } else if ctx.acc.state == ntlm::ACC_NEW {
            e = ntlm::accept_negotiate(ctx.acc, tok, now_secs(), out);
            done = e != ntlm::OK;
        } else {
            e = ntlm::accept_authenticate(ctx.acc, tok, now_secs()) { user, domain, h => lookup(users, user, domain, h) };
            done = true;
        }
        emit_token(out);
        if e != ntlm::OK { out_line(str("error ", ntlm::error_text(e))); return 1; }
        if done { break; }
    }
    out_line(str("done ", ctx.acc.domain, "\\", ctx.acc.user));
    return session_loop(ctx.acc.session);
}

// --- serve -----------------------------------------------------------------------------------

fn listen_on(o: const Options&) -> i64 {
    let addr = if o.listen.len > 0 { o.listen[..] } else { "127.0.0.1" };
    let fd = net::listen(addr, o.port);
    if fd >= 0 { say(str("serving on ", addr, " port ", net::local_port(fd))); }
    return fd;
}

// One connection: its requests until it closes; authenticated once.
// Returns how many requests were answered as authenticated.
fn serve_conn(c: i64, o: const Options&, users: const User[:]) -> i64 {
    var hc = http::server_conn(http::server_options());
    var raw: u8[16384] = [0; 16384];
    var buf: u8[>..] = [];
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var out: u8[>..] = [];
    var auth: u8[>..] = [];
    var path: u8[>..] = [];
    var ctx = krb5::spnego_ntlm_acceptor(make_acceptor(o));
    var authed = false;
    var who: u8[>..] = [];
    var served = 0;
    while true {
        while true {
            let ev, h = http::server_read(hc, buf, body, trailer, out);
            if ev.kind == http::EV_REQUEST {
                auth.clear();
                let s, has = http::get(buf, h, "authorization");
                if has { auth.append(buf[s.pos..s.end]); }
                path.clear();
                path.append(buf[h.target.pos..h.target.end]);
                if ev.continue_expected { http::server_continue(hc, out); }
            }
            if ev.kind == http::EV_ERROR || ev.kind == http::EV_CLOSED {
                if out.len > 0 { net::write(c, out, 10000); }
                return served;
            }
            var rest: u8[>..] = [];
            rest.append(buf[ev.used..]);
            buf.clear();
            buf.append(rest);
            if (ev.kind == http::EV_REQUEST || ev.kind == http::EV_END) && http::request_complete(hc) {
                var status = 401;
                var fields: u8[>..] = [];
                var reply: u8[>..] = [];
                let scheme, tok, tok_ok = ntlm::http_token(auth);
                if authed {
                    status = 200;
                } else if auth.len == 0 || !tok_ok || tok.len == 0 {
                    fields.append("WWW-Authenticate: NTLM\r\nWWW-Authenticate: Negotiate\r\n");
                    reply.append("authentication required\n");
                    say(str("GET ", path, ": challenge"));
                } else {
                    // A NEGOTIATE (raw) or a NegTokenInit starts over.
                    let fresh = (ntlm::is_ntlmssp(tok) && ntlm::get32(tok, 8) == ntlm::MSG_NEGOTIATE) || tok[0] == 0x60;
                    if fresh { ctx = krb5::spnego_ntlm_acceptor(make_acceptor(o)); }
                    var t: u8[>..] = [];
                    let done, e = krb5::spnego_ntlm_accept(ctx, tok, now_secs(), t) { user, domain, hh => lookup(users, user, domain, hh) };
                    if e == ntlm::OK && !done {
                        fields.append(str("WWW-Authenticate: ", ntlm::http_header(scheme, t), "\r\n"));
                        reply.append("continue\n");
                    } else if e == ntlm::OK {
                        authed = true;
                        status = 200;
                        who.clear();
                        if ctx.acc.anonymous { who.append("(anonymous)"); } else { format(who, ctx.acc.domain, "\\", ctx.acc.user); }
                        if t.len > 0 { fields.append(str("WWW-Authenticate: ", ntlm::http_header(scheme, t), "\r\n")); }
                        say(str("authenticated ", who, " (", ntlm::scheme_name(scheme), if ctx.raw { ", NTLMSSP" } else { ", SPNEGO" },
                                if ctx.acc.had_mic { ", MIC" } else { "" }, ")"));
                    } else {
                        fields.append("WWW-Authenticate: NTLM\r\nWWW-Authenticate: Negotiate\r\n");
                        reply.append(str("refused: ", ntlm::error_text(e), "\n"));
                        say(str("refused: ", ntlm::error_text(e)));
                        ctx = krb5::spnego_ntlm_acceptor(make_acceptor(o));
                    }
                }
                if status == 200 {
                    reply.append(str("hello ", who, "\n"));
                    served++;
                }
                fields.append("Content-Type: text/plain\r\n");
                http::server_respond(hc, status, fields, reply.len, out);
                http::server_body(hc, reply, out);
                http::server_end(hc, "", out);
                body.clear();
                net::write(c, out, 10000);
                out.clear();
                if http::closing(hc) { return served; }
                continue;
            }
            if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT { break; }
        }
        if out.len > 0 { net::write(c, out, 10000); out.clear(); }
        let n = net::read(c, raw, 30000);
        if n <= 0 { return served; }
        buf.append(raw[..n]);
    }
    return served;
}

fn run_serve(o: const Options&) -> i32 {
    var users: User[>..] = [];
    if o.users.len == 0 || !load_users(o.users, users) { return fail("--users FILE: lines DOMAIN:USER:PASSWORD"); }
    if o.port < 0 { return usage(); }
    let fd = listen_on(o);
    if fd < 0 { return fail("cannot listen"); }
    var total = 0;
    loop {
        let c = net::accept(fd, 1000);
        if c < 0 { continue; }
        total += serve_conn(c, o, users);
        net::close(c);
        if o.count > 0 && total >= o.count { break; }
    }
    return 0;
}

// --- get -------------------------------------------------------------------------------------

fn run_get(o: const Options&) -> i32 {
    if o.url.len == 0 { return usage(); }
    if o.user.len == 0 || o.hash_file.len > 0 { return fail("get: --user and --password-env or --password-file"); }
    let pw, ok = password_of(o);
    if !ok { return fail("no password (--password-env VAR or --password-file FILE)"); }
    var c = http::Client { .. };
    c.opt.auth = http::AUTH_NTLM;
    c.opt.http2 = false;
    c.opt.insecure = o.insecure;
    var user: u8[>..] = [];
    if o.domain.len > 0 { format(user, o.domain, "\\"); }
    user.append(o.user);
    http::set_credentials(c, user, pw);
    var r = http::get(c, o.url);
    if r.err != 0 { return fail(http::client_error_text(r.err)); }
    say(str("HTTP ", r.status));
    write_stdout(http::response_body(r));
    flush_stdout();
    return if r.status >= 200 && r.status < 300 { 0 } else { 1 };
}

fn run() -> i32 {
    let a = args();
    if a.len < 2 { return usage(); }
    let command = a[1];
    var o = Options { .. };
    var i = 2;
    while i < a.len {
        let s = a[i];
        if s == "--anonymous" { o.anonymous = true; }
        else if s == "--seal" { o.seal = true; }
        else if s == "--spnego" { o.spnego = true; }
        else if s == "--spn-required" { o.spn_required = true; }
        else if s == "--require-mic" { o.require_mic = true; }
        else if s == "--allow-anonymous" { o.allow_anonymous = true; }
        else if s == "--insecure" || s == "-k" { o.insecure = true; }
        else if command == "get" && s.len > 0 && s[0] != '-' { o.url.append(s); }
        else if command == "decode" && s.len > 0 && s[0] != '-' { o.message.append(s); }
        else {
            i++;
            if i >= a.len { return usage(); }
            let v = a[i];
            if s == "--user" { o.user.append(v); }
            else if s == "--domain" { o.domain.append(v); }
            else if s == "--workstation" { o.workstation.append(v); }
            else if s == "--password-env" { o.password_env.append(v); }
            else if s == "--password-file" { o.password_file.append(v); }
            else if s == "--nt-hash-file" { o.hash_file.append(v); }
            else if s == "--spn" { o.spn.append(v); }
            else if s == "--cb-data" { o.cb_data.append(v); o.has_cb = true; }
            else if s == "--cb-hex" {
                let b, ok = unhex(v);
                if !ok { return usage(); }
                o.cb_data.append(b);
                o.has_cb = true;
            }
            else if s == "--cb" {
                if v == "supported" { o.cb_mode = ntlm::CB_SUPPORTED; }
                else if v == "required" { o.cb_mode = ntlm::CB_REQUIRED; }
                else if v == "none" { o.cb_mode = ntlm::CB_NONE; }
                else { return usage(); }
            }
            else if s == "--users" { o.users.append(v); }
            else if s == "--skew" { let n, ok = parse_int(v); if !ok { return usage(); } o.skew = n; }
            else if s == "--computer" { o.computer.append(v); }
            else if s == "--domain-name" { o.domain_name.append(v); }
            else if s == "--listen" { o.listen.append(v); }
            else if s == "--port" { let n, ok = parse_int(v); if !ok || n < 0 || n > 65535 { return usage(); } o.port = n; }
            else if s == "--count" { let n, ok = parse_int(v); if !ok || n < 0 { return usage(); } o.count = n; }
            else if s == "--server-challenge" { o.server_challenge.append(v); }
            else if s == "--client-challenge" { o.client_challenge.append(v); }
            else if s == "--time" { let n, ok = parse_int(v); if !ok || n < 0 { return usage(); } o.time = n as u64; }
            else if s == "--target-info" { o.target_info.append(v); }
            else if s == "--session-key" { o.session_key.append(v); }
            else { return usage(); }
        }
        i++;
    }
    if command == "hash" { return run_hash(); }
    if command == "compute" { return run_compute(o); }
    if command == "decode" { return run_decode(o); }
    if command == "initiate" { return run_initiate(o); }
    if command == "accept" { return run_accept(o); }
    if command == "serve" { return run_serve(o); }
    if command == "get" { return run_get(o); }
    return usage();
}

fn main() { exit(run()); }
