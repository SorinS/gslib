// gss: GSS-API and SPNEGO on the krb5 package over TCP, for trying them and
// for scripts/interop.py, which runs them against MIT's gss-client,
// gss-server (in its inetd mode) and curl --negotiate. The client and
// server speak MIT's gss-sample protocol (a flags byte, a 4-byte length,
// the token); the HTTP ones speak Negotiate (RFC 4559). Servers listen on
// 127.0.0.1 only.
//
//   gss client HOST PORT SERVICE@HOST MESSAGE [-spnego] [-nomutual] [-deleg] [-seq] [-noconf] [-nomic]
//   gss server PORT [-once] [-keytab FILE] [-any]
//   gss http-server PORT [-once] [-keytab FILE]
//   gss http-client HOST PORT PATH SERVICE@HOST [-deleg]
//   gss ldap HOST PORT [-service ldap@NAME] [-layer conf|integ|none] [-sid SID]... [-groups ACCOUNT]
//
// ldap binds with SASL GSSAPI (RFC 4752), then prints the bound identity
// (Who am I?), the domain's naming context, each SID's entry, and an
// account's tokenGroups resolved to names.
//
// The client's credentials come from $KRB5CCNAME and $KRB5_CONFIG; the
// server's keytab from -keytab, else $KRB5_KTNAME, else /etc/krb5.keytab.
// A server given port 0 prints "port N" first.

import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.config;
import gslib.krb5.keytab;
import gslib.krb5.ccache;
import gslib.krb5.client;
import gslib.krb5.service;
import gslib.krb5.gssapi;
import gslib.krb5.spnego;
import gslib.krb5.pac;
import gslib.krb5.ndr;
import gslib.krb5.ldap;
import gslib.krb5.claims;
import gslib.net.ldap;
import gslib.net.ldap.conn;

extern fn gssnet_listen(port: i32) -> i32;
extern fn gssnet_port(s: i32) -> i32;
extern fn gssnet_accept(s: i32) -> i32;
extern fn gssnet_connect(host: const u8[:], port: i32) -> i32;
extern fn gssnet_read_full(s: i32, buf: u8[:]) -> i32;
extern fn gssnet_read(s: i32, buf: u8[:]) -> i64;
extern fn gssnet_write(s: i32, data: const u8[:]) -> i32;
extern fn gssnet_close(s: i32);

// gss-sample's token flags.
let TOKEN_NOOP: u8 = 1;
let TOKEN_CONTEXT: u8 = 2;
let TOKEN_DATA: u8 = 4;
let TOKEN_MIC: u8 = 8;
let TOKEN_CONTEXT_NEXT: u8 = 16;
let TOKEN_WRAPPED: u8 = 32;
let TOKEN_ENCRYPTED: u8 = 64;
let TOKEN_SEND_MIC: u8 = 128;

fn die(what: const u8[:]) {
    write_stderr(str("gss: ", what, "\n"));
    exit(1);
}

fn die_err(what: const u8[:], err: i64) { die(str(what, ": ", krb5::error_text(err))); }

fn now_secs() -> i64, i64 {
    let ns = time_ns();
    return ns / 1000000000, ns / 1000 % 1000000;
}

fn send_token(s: i32, flags: u8, tok: const u8[:]) -> bool {
    var b: u8[>..] = [flags];
    let n = tok.len;
    b.push((n >> 24) as! u8);
    b.push((n >> 16) as! u8);
    b.push((n >> 8) as! u8);
    b.push(n as! u8);
    b.append(tok);
    return gssnet_write(s, b) == 0;
}

fn recv_token(s: i32, tok: u8[>..]&) -> u8, bool {
    var h: u8[5] = [0; 5];
    if gssnet_read_full(s, h) != 1 { return 0, false; }
    let n: i64 = (h[1] as i64) << 24 | (h[2] as i64) << 16 | (h[3] as i64) << 8 | h[4];
    if n < 0 || n > 1 << 24 { return 0, false; }
    tok.clear();
    tok.resize(n, 0);
    if n > 0 && gssnet_read_full(s, tok) != 1 { return 0, false; }
    return h[0], true;
}

fn load_keytab(path_arg: const u8[:]) -> krb5::KeytabEntry[>..] {
    var path: u8[>..] = [];
    if path_arg.len > 0 { path.append(path_arg); }
    else if env("KRB5_KTNAME", path) && path.len > 0 {
        if path.starts_with("FILE:") {
            var p: u8[>..] = [];
            p.append(path[5..]);
            path.clear();
            path.append(p);
        }
    }
    else { path.clear(); path.append("/etc/krb5.keytab"); }
    let kt, err = krb5::keytab_load(path);
    if err != krb5::OK { die_err(path, err); }
    return kt;
}

// --- The client (initiator) -------------------------------------------------------

fn client(a: u8[:][>..]&) {
    if a.len < 6 { die("usage: gss client HOST PORT SERVICE@HOST MESSAGE [options]"); }
    var use_spnego = false;
    var mutual = true;
    var deleg = false;
    var seq = false;
    var conf = true;
    var mic = true;
    for i in 6..a.len {
        let o = a[i];
        if o == "-spnego" { use_spnego = true; }
        else if o == "-nomutual" { mutual = false; }
        else if o == "-deleg" { deleg = true; }
        else if o == "-seq" { seq = true; }
        else if o == "-noconf" { conf = false; }
        else if o == "-nomic" { mic = false; }
        else { die(str("unknown option ", o)); }
    }
    let port, pok = parse_int(a[3]);
    if !pok { die("bad port"); }
    let cfg, cerr = krb5::default_config();
    if cerr != krb5::OK { die_err("krb5.conf", cerr); }
    let ccname = krb5::default_ccache_name();
    let cred, err = krb5::get_service_ticket_cached(cfg, ccname, a[4], true);
    if err != krb5::OK { die_err("service ticket", err); }
    var kc: u8[>..] = [];
    if deleg {
        let cc, lerr = krb5::ccache_load(ccname);
        if lerr != krb5::OK { die_err(ccname, lerr); }
        let tgt, tok = krb5::ccache_find(cc, krb5::name_join("krbtgt", cc.realm), cc.realm, 0);
        if !tok { die("no TGT to delegate"); }
        let fwd, ferr = krb5::forward_tgt(cfg, tgt);
        if ferr != krb5::OK { die_err("forwarded TGT", ferr); }
        let merr = krb5::make_krb_cred(fwd, cred.key, kc);
        if merr != krb5::OK { die_err("KRB-CRED", merr); }
    }
    let s = gssnet_connect(a[2], port as! i32);
    if s < 0 { die("cannot connect"); }
    var flags: u32 = krb5::GSS_REPLAY;
    if mutual { flags = flags | krb5::GSS_MUTUAL; }
    if seq { flags = flags | krb5::GSS_SEQUENCE; }
    let now, usec = now_secs();
    send_token(s, TOKEN_NOOP | TOKEN_CONTEXT_NEXT, "");
    var tok: u8[>..] = [];
    var g = krb5::empty_gss_context();
    var sp = krb5::empty_spnego();
    if use_spnego {
        var c, ierr = krb5::spnego_init(cred, flags, "", false, kc, now, usec, tok);
        if ierr != krb5::OK { die_err("spnego init", ierr); }
        sp = c;
    } else {
        var c, ierr = krb5::gss_init(cred, flags, "", false, kc, now, usec, tok);
        if ierr != krb5::OK { die_err("gss init", ierr); }
        g = c;
    }
    send_token(s, TOKEN_CONTEXT, tok);
    var established = if use_spnego { false } else { g.established };
    while !established {
        var inb: u8[>..] = [];
        let fl, ok = recv_token(s, inb);
        if !ok { die("connection closed during context establishment"); }
        if use_spnego {
            var out: u8[>..] = [];
            let done, serr = krb5::spnego_init_continue(sp, inb, out);
            if serr != krb5::OK { die_err("spnego", serr); }
            if out.len > 0 { send_token(s, TOKEN_CONTEXT, out); }
            established = done;
        } else {
            let gerr = krb5::gss_init_continue(g, inb);
            if gerr != krb5::OK { die_err("gss", gerr); }
            established = g.established;
        }
    }
    if use_spnego { g = sp.gss; }
    print("context established with ", a[4]);
    var w: u8[>..] = [];
    let werr = krb5::gss_wrap(g, a[5], conf, w);
    if werr != krb5::OK { die_err("wrap", werr); }
    var f: u8 = TOKEN_DATA | TOKEN_WRAPPED;
    if conf { f = f | TOKEN_ENCRYPTED; }
    if mic { f = f | TOKEN_SEND_MIC; }
    send_token(s, f, w);
    var reply: u8[>..] = [];
    let rf, rok = recv_token(s, reply);
    if !rok { die("no reply"); }
    if mic {
        if rf & TOKEN_MIC == 0 { die("expected a MIC token"); }
        let verr = krb5::gss_verify_mic(g, a[5], reply);
        if verr != krb5::OK { die_err("verify mic", verr); }
        print("Signature verified.");
    }
    send_token(s, TOKEN_NOOP, "");
    gssnet_close(s);
}

// --- The server (acceptor) ------------------------------------------------------------

fn serve_one(c: i32, kt: const krb5::KeytabEntry[:], any: bool, rc: krb5::ReplayEntry[>..]&) {
    var tok: u8[>..] = [];
    let f0, ok0 = recv_token(c, tok);
    if !ok0 || f0 & TOKEN_NOOP == 0 || f0 & TOKEN_CONTEXT_NEXT == 0 { print("error: expected NOOP|CONTEXT_NEXT"); return; }
    var sp = krb5::empty_spnego();
    var done = false;
    while !done {
        let f, ok = recv_token(c, tok);
        if !ok || f & TOKEN_CONTEXT == 0 { print("error: expected a context token"); return; }
        let now, usec = now_secs();
        var out: u8[>..] = [];
        let d, acc, err = krb5::spnego_accept(sp, tok, kt, any, rc, now, usec, 300, "", false, out);
        if out.len > 0 { send_token(c, TOKEN_CONTEXT, out); }
        if err != krb5::OK { print("error: ", krb5::error_text(err)); return; }
        if acc.ap.client.len > 0 {
            var n = 0;
            for x in acc.delegated { n++; }
            print("accepted: ", krb5::principal_string(acc.ap.client, acc.ap.client_realm), " flags=", acc.flags,
                  " delegated=", n, " spnego=", !sp.raw);
            for x in acc.delegated { print("delegated: ", krb5::principal_string(x.server, x.server_realm)); }
            print_pac(acc.ap);
        }
        done = d;
    }
    loop {
        let f, ok = recv_token(c, tok);
        if !ok { return; }
        if f & TOKEN_NOOP != 0 { print("done"); return; }
        var msg: u8[>..] = [];
        if f & TOKEN_WRAPPED != 0 {
            let sealed, err = krb5::gss_unwrap(sp.gss, tok, msg);
            if err != krb5::OK { print("error: unwrap: ", krb5::error_text(err)); return; }
            print("message: ", msg, " sealed=", sealed);
        } else {
            msg.append(tok);
        }
        if f & TOKEN_SEND_MIC != 0 {
            var m: u8[>..] = [];
            let err = krb5::gss_get_mic(sp.gss, msg, m);
            if err != krb5::OK { print("error: mic: ", krb5::error_text(err)); return; }
            send_token(c, TOKEN_MIC, m);
        } else {
            send_token(c, TOKEN_NOOP, "");
        }
    }
}

// The PAC of an accepted ticket, checked with the service key: what it
// says, or why it fails.
fn print_pac(ap: const krb5::ApContext&) {
    let p, found, err = krb5::pac_verify(ap, ap.service_key);
    if !found { print("pac: none"); return; }
    if err != krb5::OK { print("pac: ", krb5::error_text(err)); return; }
    var types: u8[>..] = [];
    for b in p.buffers { types.append(str(" ", b.ul_type)); }
    print("pac: verified client=", p.client_info.name, " upn=", p.upn_dns_info.upn, " buffers", types);
    if p.has_logon_info {
        for s in krb5::logon_sids(p.logon_info) { print("pac sid: ", s); }
    }
    let raw, ok = krb5::pac_from_authz(ap.authz);
    let claims, cerr = krb5::pac_claims(raw, p, krb5::PAC_CLIENT_CLAIMS_INFO);
    if cerr != krb5::OK { print("pac claims: ", krb5::error_text(cerr)); }
    for a in claims {
        for c in a.claims {
            var v: u8[>..] = [];
            for s in c.strings { v.append(str(" ", s)); }
            for x in c.ints { v.append(str(" ", x)); }
            print("pac claim: ", c.id, v);
        }
    }
}

fn listen_on(port_text: const u8[:]) -> i32 {
    let port, ok = parse_int(port_text);
    if !ok { die("bad port"); }
    let l = gssnet_listen(port as! i32);
    if l < 0 { die("cannot listen"); }
    if port == 0 { print("port ", gssnet_port(l)); }
    flush_stdout();
    return l;
}

fn server(a: u8[:][>..]&) {
    if a.len < 3 { die("usage: gss server PORT [-once] [-keytab FILE] [-any]"); }
    var once = false;
    var any = false;
    var ktpath: u8[>..] = [];
    var i = 3;
    while i < a.len {
        if a[i] == "-once" { once = true; }
        else if a[i] == "-any" { any = true; }
        else if a[i] == "-keytab" && i + 1 < a.len { i++; ktpath.append(a[i]); }
        else { die(str("unknown option ", a[i])); }
        i++;
    }
    let kt = load_keytab(ktpath);
    let l = listen_on(a[2]);
    var rc: krb5::ReplayEntry[>..] = [];
    loop {
        let c = gssnet_accept(l);
        if c < 0 { continue; }
        serve_one(c, kt, any, rc);
        flush_stdout();
        gssnet_close(c);
        if once { break; }
    }
}

// --- HTTP Negotiate -------------------------------------------------------------------

// The request or response head (up to the blank line), and what came after.
fn read_head(c: i32, head: u8[>..]&, rest: u8[>..]&) -> bool {
    var buf: u8[>..] = [];
    var chunk: u8[4096] = [0; 4096];
    loop {
        for i in buf.len {
            if i + 3 < buf.len && buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n' {
                head.append(buf[..i + 2]);
                rest.append(buf[i + 4..]);
                return true;
            }
        }
        if buf.len > 65536 { return false; }
        let n = gssnet_read(c, chunk);
        if n <= 0 { return false; }
        buf.append(chunk[..n]);
    }
}

// The value of a header (the first), lower-case name given.
fn header(head: const u8[:], name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var start = 0;
    for i in head.len {
        if head[i] != '\n' { continue; }
        let line = krb5::trim(head[start..i]);
        start = i + 1;
        var colon = -1;
        for j in line.len { if line[j] == ':' && colon < 0 { colon = j; } }
        if colon > 0 && krb5::lower(line[..colon]) == name {
            out.append(krb5::trim(line[colon + 1..]));
            return out, true;
        }
    }
    return out, false;
}

fn respond(c: i32, status: const u8[:], extra: const u8[:], body: const u8[:]) {
    var r: u8[>..] = [];
    r.append("HTTP/1.1 ");
    r.append(status);
    r.append("\r\n");
    r.append(extra);
    r.append("Content-Type: text/plain\r\nConnection: close\r\nContent-Length: ");
    format_int(r, body.len, 10, 0, ' ');
    r.append("\r\n\r\n");
    r.append(body);
    gssnet_write(c, r);
}

fn http_server(a: u8[:][>..]&) {
    if a.len < 3 { die("usage: gss http-server PORT [-once] [-keytab FILE]"); }
    var once = false;
    var ktpath: u8[>..] = [];
    var i = 3;
    while i < a.len {
        if a[i] == "-once" { once = true; }
        else if a[i] == "-keytab" && i + 1 < a.len { i++; ktpath.append(a[i]); }
        else { die(str("unknown option ", a[i])); }
        i++;
    }
    let kt = load_keytab(ktpath);
    let l = listen_on(a[2]);
    var rc: krb5::ReplayEntry[>..] = [];
    var served = 0;
    loop {
        let c = gssnet_accept(l);
        if c < 0 { continue; }
        var head: u8[>..] = [];
        var rest: u8[>..] = [];
        if read_head(c, head, rest) {
            let auth, has = header(head, "authorization");
            let tok, ok = krb5::negotiate_token(auth);
            if !has || !ok || tok.len == 0 {
                respond(c, "401 Unauthorized", "WWW-Authenticate: Negotiate\r\n", "authentication required\n");
                print("challenge");
            } else {
                var sp = krb5::empty_spnego();
                var out: u8[>..] = [];
                let now, usec = now_secs();
                let done, acc, err = krb5::spnego_accept(sp, tok, kt, true, rc, now, usec, 300, "", false, out);
                var extra: u8[>..] = [];
                if out.len > 0 {
                    extra.append("WWW-Authenticate: ");
                    extra.append(krb5::negotiate_header(out));
                    extra.append("\r\n");
                }
                if err == krb5::OK && done {
                    let who = krb5::principal_string(acc.ap.client, acc.ap.client_realm);
                    var n = 0;
                    for x in acc.delegated { n++; }
                    respond(c, "200 OK", extra, str("hello ", who, "\n"));
                    print("authenticated: ", who, " spnego=", !sp.raw, " delegated=", n);
                    print_pac(acc.ap);
                    served++;
                } else {
                    respond(c, "401 Unauthorized", extra, str("refused: ", krb5::error_text(err), "\n"));
                    print("refused: ", krb5::error_text(err));
                }
            }
        }
        flush_stdout();
        gssnet_close(c);
        if once && served > 0 { break; }
    }
}

fn http_client(a: u8[:][>..]&) {
    if a.len < 6 { die("usage: gss http-client HOST PORT PATH SERVICE@HOST [-deleg]"); }
    let deleg = a.len > 6 && a[6] == "-deleg";
    let port, pok = parse_int(a[3]);
    if !pok { die("bad port"); }
    let cfg, cerr = krb5::default_config();
    if cerr != krb5::OK { die_err("krb5.conf", cerr); }
    let ccname = krb5::default_ccache_name();
    let cred, err = krb5::get_service_ticket_cached(cfg, ccname, a[5], true);
    if err != krb5::OK { die_err("service ticket", err); }
    var kc: u8[>..] = [];
    if deleg {
        let cc, lerr = krb5::ccache_load(ccname);
        let tgt, tok = krb5::ccache_find(cc, krb5::name_join("krbtgt", cc.realm), cc.realm, 0);
        if !tok { die("no TGT to delegate"); }
        let fwd, ferr = krb5::forward_tgt(cfg, tgt);
        if ferr != krb5::OK { die_err("forwarded TGT", ferr); }
        krb5::make_krb_cred(fwd, cred.key, kc);
    }
    let now, usec = now_secs();
    var tok: u8[>..] = [];
    var sp, ierr = krb5::spnego_init(cred, krb5::GSS_MUTUAL | krb5::GSS_SEQUENCE, "", false, kc, now, usec, tok);
    if ierr != krb5::OK { die_err("spnego", ierr); }
    let s = gssnet_connect(a[2], port as! i32);
    if s < 0 { die("cannot connect"); }
    var req: u8[>..] = [];
    req.append("GET ");
    req.append(a[4]);
    req.append(" HTTP/1.1\r\nHost: ");
    req.append(a[2]);
    req.append("\r\nAuthorization: ");
    req.append(krb5::negotiate_header(tok));
    req.append("\r\nConnection: close\r\n\r\n");
    gssnet_write(s, req);
    var head: u8[>..] = [];
    var body: u8[>..] = [];
    if !read_head(s, head, body) { die("no response"); }
    var chunk: u8[4096] = [0; 4096];
    loop {
        let n = gssnet_read(s, chunk);
        if n <= 0 { break; }
        body.append(chunk[..n]);
    }
    gssnet_close(s);
    var line_end = 0;
    while line_end < head.len && head[line_end] != '\r' { line_end++; }
    print(head[..line_end]);
    let www, has = header(head, "www-authenticate");
    if has {
        let rt, ok = krb5::negotiate_token(www);
        if ok && rt.len > 0 {
            var out: u8[>..] = [];
            let done, serr = krb5::spnego_init_continue(sp, rt, out);
            if serr != krb5::OK { die_err("mutual authentication", serr); }
            print("mutual authentication: ", if sp.gss.established { "ok" } else { "incomplete" });
        }
    }
    write_stdout(body);
}

// --- LDAP (SASL GSSAPI) ---------------------------------------------------------------

struct LdapIo { s: i32, pending: u8[>..] }

fn ldap_send(io: LdapIo&, sasl: krb5::SaslGssapi&, req: const u8[:]) {
    var wire: u8[>..] = [];
    let err = krb5::sasl_out(sasl, req, wire);
    if err != krb5::OK { die_err("wrap", err); }
    if gssnet_write(io.s, wire) != 0 { die("write failed"); }
}

// Reads until the response to `id` that ends it (a search's done, or the
// one response), collecting every message for it in msgs.
fn ldap_wait(io: LdapIo&, sasl: krb5::SaslGssapi&, c: ldap::Conn&, id: i64, msgs: u8[>..]&) {
    var chunk: u8[16384] = [0; 16384];
    loop {
        var pos = 0;
        loop {
            let m, ok = ldap::next_message(msgs, pos);
            if !ok { break; }
            if m.id == id && m.op != ldap::OP_SEARCH_ENTRY && m.op != 0x73 { return; }
        }
        let n = gssnet_read(io.s, chunk);
        if n <= 0 { die("connection closed"); }
        io.pending.append(chunk[..n]);
        var plain: u8[>..] = [];
        let err = krb5::sasl_in(sasl, io.pending, plain);
        if err != krb5::OK { die_err("unwrap", err); }
        let ferr = ldap::feed(c, plain, msgs);
        if ferr != 0 { die(str("ldap: ", ldap::conn_error(c))); }
    }
}

fn ldap_cmd(a: u8[:][>..]&) {
    if a.len < 4 { die("usage: gss ldap HOST PORT [-service ldap@NAME] [-layer conf|integ|none] [-sid SID]... [-groups ACCOUNT]"); }
    var service: u8[>..] = [];
    service.append("ldap@");
    service.append(a[2]);
    var want: u8 = krb5::SASL_LAYER_CONFIDENTIALITY | krb5::SASL_LAYER_INTEGRITY;
    var sids: u8[][>..] = [];
    var groups_of: u8[>..] = [];
    var i = 4;
    while i < a.len {
        if a[i] == "-service" && i + 1 < a.len { i++; service.clear(); service.append(a[i]); }
        else if a[i] == "-layer" && i + 1 < a.len {
            i++;
            want = if a[i] == "conf" { krb5::SASL_LAYER_CONFIDENTIALITY } else if a[i] == "integ" { krb5::SASL_LAYER_INTEGRITY } else { krb5::SASL_LAYER_NONE };
        }
        else if a[i] == "-sid" && i + 1 < a.len { i++; var t: u8[>..] = []; t.append(a[i]); sids.push(copy(t)); }
        else if a[i] == "-groups" && i + 1 < a.len { i++; groups_of.append(a[i]); }
        else { die(str("unknown option ", a[i])); }
        i++;
    }
    let port, pok = parse_int(a[3]);
    if !pok { die("bad port"); }
    let cfg, cerr = krb5::default_config();
    if cerr != krb5::OK { die_err("krb5.conf", cerr); }
    let cred, err = krb5::get_service_ticket_cached(cfg, krb5::default_ccache_name(), service, true);
    if err != krb5::OK { die_err("service ticket", err); }
    let s = gssnet_connect(a[2], port as! i32);
    if s < 0 { die("cannot connect"); }
    var io = LdapIo { s: s, pending: [] };
    var c = ldap::client();
    var out: u8[>..] = [];
    let now, usec = now_secs();
    var sasl, serr = krb5::sasl_gssapi_start(c, cred, want, "", now, usec, out);
    if serr != krb5::OK { die_err("sasl start", serr); }
    loop {
        gssnet_write(s, out);
        out.clear();
        var msgs: u8[>..] = [];
        ldap_wait(io, sasl, c, sasl.bind_id, msgs);
        var pos = 0;
        let m, ok = ldap::next_message(msgs, pos);
        let done, berr = krb5::sasl_gssapi_step(sasl, c, msgs, m, out);
        if berr != krb5::OK { die(str("bind: ", if berr > 2000 { ldap::result_name(berr - 2000) } else { krb5::error_text(berr) })); }
        if done { break; }
    }
    print("bound: layer ", if sasl.layer == 4 { "confidentiality" } else if sasl.layer == 2 { "integrity" } else { "none" });
    var req: u8[>..] = [];
    let wid = ldap::who_am_i(c, req);
    ldap_send(io, sasl, req);
    var wm: u8[>..] = [];
    ldap_wait(io, sasl, c, wid, wm);
    var wpos = 0;
    let w, wok = ldap::next_message(wm, wpos);
    let who, hok = ldap::response_value(wm, w);
    print("whoami: ", who);
    req.clear();
    let rid = krb5::rootdse_request(c, req);
    ldap_send(io, sasl, req);
    var rm: u8[>..] = [];
    ldap_wait(io, sasl, c, rid, rm);
    var base: u8[>..] = [];
    var rpos = 0;
    loop {
        let m, ok = ldap::next_message(rm, rpos);
        if !ok { break; }
        if m.op == ldap::OP_SEARCH_ENTRY { base.append(ldap::get_value(rm, m, "defaultNamingContext")); }
    }
    print("naming context: ", base);
    for sid in sids { print_sid(io, sasl, c, base, sid); }
    if groups_of.len > 0 {
        req.clear();
        var f: u8[>..] = [];
        f.append("(sAMAccountName=");
        f.append(ldap::escape_filter(groups_of));
        f.append(")");
        let qid = ldap::search(c, base, ldap::SCOPE_SUB, f, "distinguishedName", req);
        ldap_send(io, sasl, req);
        var qm: u8[>..] = [];
        ldap_wait(io, sasl, c, qid, qm);
        var dn: u8[>..] = [];
        var qpos = 0;
        loop {
            let m, ok = ldap::next_message(qm, qpos);
            if !ok { break; }
            if m.op == ldap::OP_SEARCH_ENTRY && dn.len == 0 { dn.append(ldap::entry_dn(qm, m)); }
        }
        if dn.len == 0 { die(str("no account ", groups_of)); }
        print("account: ", dn);
        req.clear();
        let tid = krb5::token_groups_request(c, dn, req);
        ldap_send(io, sasl, req);
        var tm: u8[>..] = [];
        ldap_wait(io, sasl, c, tid, tm);
        var tpos = 0;
        var group_sids: u8[][>..] = [];
        loop {
            let m, ok = ldap::next_message(tm, tpos);
            if !ok { break; }
            if m.op == ldap::OP_SEARCH_ENTRY { for g in krb5::entry_sids(tm, m, "tokenGroups") { group_sids.push(copy(g)); } }
        }
        for g in group_sids { print_sid(io, sasl, c, base, g); }
    }
    req.clear();
    ldap::unbind(c, req);
    ldap_send(io, sasl, req);
    gssnet_close(s);
}

fn print_sid(io: LdapIo&, sasl: krb5::SaslGssapi&, c: ldap::Conn&, base: const u8[:], sid: const u8[:]) {
    var req: u8[>..] = [];
    let id = krb5::sid_lookup_request(c, base, sid, req);
    if id < 0 { print("sid ", sid, ": not a SID"); return; }
    ldap_send(io, sasl, req);
    var m: u8[>..] = [];
    ldap_wait(io, sasl, c, id, m);
    var pos = 0;
    var found = false;
    loop {
        let e, ok = ldap::next_message(m, pos);
        if !ok { break; }
        if e.op == ldap::OP_SEARCH_ENTRY {
            print("sid ", sid, ": ", ldap::entry_dn(m, e), " (", ldap::get_value(m, e, "sAMAccountName"), ")");
            found = true;
        }
    }
    if !found { print("sid ", sid, ": no entry (a well-known or foreign SID)"); }
}

fn main() {
    let a = args();
    if a.len < 2 { die("usage: gss client|server|http-server|http-client ..."); }
    if a[1] == "client" { client(a); return; }
    if a[1] == "server" { server(a); return; }
    if a[1] == "http-server" { http_server(a); return; }
    if a[1] == "http-client" { http_client(a); return; }
    if a[1] == "ldap" { ldap_cmd(a); return; }
    die(str("unknown command ", a[1]));
}
