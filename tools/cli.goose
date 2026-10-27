// What the goose-ldap* tools share, as OpenLDAP's client tools have it:
// the common options, connecting to an LDAP URL (ldap://, ldaps://,
// ldapi://) with StartTLS (-Z, -ZZ) through tlsgoose, binding (-x
// simple, -Y EXTERNAL, PLAIN or DIGEST-MD5), the request controls of -M
// and -e, sending and receiving, and errors written as ldap_err2string
// writes them. TLS takes OpenLDAP's environment: LDAPTLS_CACERT (a PEM
// file of roots; the system's otherwise), LDAPTLS_REQCERT (never or
// allow: no check), LDAPTLS_CERT and LDAPTLS_KEY (a client certificate).
// LDAPURI and LDAPBINDDN stand in for -H and -D.
namespace cli;

import std;
import os;
import base64;
import ldap;
import ldap.conn;
import ldap.url;
import ldap.filter;
import asn1;
import x509;
import tls;
import tls.handshake;
import bignum;
import bignum.entropy;
import .sysnet;

// OpenLDAP's ldap_err2string.
fn err2string(code: i64) -> const u8[:] {
    if code == 0 { return "Success"; }
    if code == 1 { return "Operations error"; }
    if code == 2 { return "Protocol error"; }
    if code == 3 { return "Time limit exceeded"; }
    if code == 4 { return "Size limit exceeded"; }
    if code == 5 { return "Compare False"; }
    if code == 6 { return "Compare True"; }
    if code == 7 { return "Authentication method not supported"; }
    if code == 8 { return "Strong(er) authentication required"; }
    if code == 9 { return "Partial results and referral received"; }
    if code == 10 { return "Referral"; }
    if code == 11 { return "Administrative limit exceeded"; }
    if code == 12 { return "Critical extension is unavailable"; }
    if code == 13 { return "Confidentiality required"; }
    if code == 14 { return "SASL bind in progress"; }
    if code == 16 { return "No such attribute"; }
    if code == 17 { return "Undefined attribute type"; }
    if code == 18 { return "Inappropriate matching"; }
    if code == 19 { return "Constraint violation"; }
    if code == 20 { return "Type or value exists"; }
    if code == 21 { return "Invalid syntax"; }
    if code == 32 { return "No such object"; }
    if code == 33 { return "Alias problem"; }
    if code == 34 { return "Invalid DN syntax"; }
    if code == 35 { return "Entry is a leaf"; }
    if code == 36 { return "Alias dereferencing problem"; }
    if code == 47 { return "Proxy Authorization Failure (X)"; }
    if code == 48 { return "Inappropriate authentication"; }
    if code == 49 { return "Invalid credentials"; }
    if code == 50 { return "Insufficient access"; }
    if code == 51 { return "Server is busy"; }
    if code == 52 { return "Server is unavailable"; }
    if code == 53 { return "Server is unwilling to perform"; }
    if code == 54 { return "Loop detected"; }
    if code == 64 { return "Naming violation"; }
    if code == 65 { return "Object class violation"; }
    if code == 66 { return "Operation not allowed on non-leaf"; }
    if code == 67 { return "Operation not allowed on RDN"; }
    if code == 68 { return "Already exists"; }
    if code == 69 { return "Cannot modify object class"; }
    if code == 70 { return "Results too large"; }
    if code == 71 { return "Operation affects multiple DSAs"; }
    if code == 76 { return "Virtual List View error"; }
    if code == 80 { return "Other (e.g., implementation specific) error"; }
    if code == 118 { return "Cancelled"; }
    if code == 119 { return "No Operation to Cancel"; }
    if code == 120 { return "Too Late to Cancel"; }
    if code == 121 { return "Cannot Cancel"; }
    if code == 122 { return "Assertion Failed"; }
    if code == 123 { return "Proxied Authorization Denied"; }
    if code == 4096 { return "Content Sync Refresh Required"; }
    // The client's own failures, as libldap's negative codes read.
    let api = api_code(code);
    if api == -1 { return "Can't contact LDAP server"; }
    if api == -2 { return "Local error"; }
    if api == -3 { return "Encoding error"; }
    if api == -4 { return "Decoding error"; }
    if api == -5 { return "Timed out"; }
    if api == -6 { return "Unknown authentication method"; }
    if api == -7 { return "Bad search filter"; }
    if api == -9 { return "Bad parameter to an ldap routine"; }
    return "Unknown (extension) error";
}

// The client's own failures as libldap numbers them (negative); result
// codes as they are.
fn api_code(code: i64) -> i64 {
    if code == ldap::ERROR_NETWORK || code == ldap::RESULT_SERVER_DOWN { return -1; }
    if code == ldap::RESULT_LOCAL_ERROR { return -2; }
    if code == ldap::RESULT_ENCODING_ERROR { return -3; }
    if code == ldap::RESULT_DECODING_ERROR || code == ldap::ERROR_UNEXPECTED_RESPONSE || code == ldap::ERROR_UNEXPECTED_MESSAGE { return -4; }
    if code == ldap::RESULT_TIMEOUT { return -5; }
    if code == ldap::RESULT_AUTH_UNKNOWN { return -6; }
    if code == ldap::ERROR_FILTER_COMPILE || code == ldap::RESULT_FILTER_ERROR { return -7; }
    if code == ldap::RESULT_PARAM_ERROR || code == ldap::ERROR_EMPTY_PASSWORD { return -9; }
    return code;
}

// The exit status for a failure, as OpenLDAP's tools exit: the result
// code, libldap's negative ones as a byte (-1 is 255).
fn status(code: i64) -> i32 { (api_code(code) & 0xff) as! i32 }

struct Opts {
    prog: u8[..64],
    uri: u8[..4096], binddn: u8[..4096],
    password: u8[..1024], has_password: bool, ask_password: bool,
    simple: bool, mech: u8[..64], authcid: u8[..1024], authzid: u8[..1024],
    starttls: i64,                        // 1 for -Z (go on without), 2 for -ZZ
    manage_dsa_it: i64,                   // 1 for -M, 2 for -MM (critical)
    verbose: bool, quiet: bool, dry_run: bool, continuous: bool,
    wrap: i64, timeout_ms: i64,
    ext: u8[..8192],                      // -e values, a line each
}

fn opts(prog: const u8[:]) -> Opts {
    var o = Opts { prog: [], uri: [], binddn: [], password: [], has_password: false, ask_password: false, simple: false,
                   mech: [], authcid: [], authzid: [], starttls: 0, manage_dsa_it: 0, verbose: false, quiet: false, dry_run: false,
                   continuous: false, wrap: ldap::LDIF_WRAP, timeout_ms: 30000, ext: [] };
    o.prog.append(prog);
    var v: u8[>..] = [];
    if env("LDAPURI", v) { o.uri.append(v[..if v.len > 4096 { 4096 } else { v.len }]); }
    v.clear();
    if env("LDAPBINDDN", v) { o.binddn.append(v[..if v.len > 4096 { 4096 } else { v.len }]); }
    return o;
}

fn fail(o: const Opts&, s: const u8[:]) -> i32 {
    sysnet::eprint(str(o.prog, ": ", s, "\n"));
    return 1;
}

fn set(dst: u8[..4096]&, v: const u8[:]) -> bool {
    if v.len > dst.cap { return false; }
    dst.clear();
    dst.append(v);
    return true;
}

fn set_small(dst: u8[..1024]&, v: const u8[:]) -> bool {
    if v.len > dst.cap { return false; }
    dst.clear();
    dst.append(v);
    return true;
}

// The common option at a[i] (and its value at a[i + 1]): 1 when it was
// one and i moved past it, 0 when it is the tool's own, -1 when it is
// bad.
fn common_flag(o: Opts&, a: u8[:][:], i: i64&) -> i64 {
    let w = a[i];
    if w == "-x" { o.simple = true; i = i + 1; return 1; }
    if w == "-W" { o.ask_password = true; i = i + 1; return 1; }
    if w == "-Z" { o.starttls = 1; i = i + 1; return 1; }
    if w == "-ZZ" { o.starttls = 2; i = i + 1; return 1; }
    if w == "-M" { o.manage_dsa_it = 1; i = i + 1; return 1; }
    if w == "-MM" { o.manage_dsa_it = 2; i = i + 1; return 1; }
    if w == "-v" { o.verbose = true; i = i + 1; return 1; }
    if w == "-n" { o.dry_run = true; i = i + 1; return 1; }
    if w == "-c" { o.continuous = true; i = i + 1; return 1; }
    if w == "-Q" { o.quiet = true; i = i + 1; return 1; }
    if w == "-N" { i = i + 1; return 1; }
    let takes = w == "-H" || w == "-D" || w == "-w" || w == "-y" || w == "-Y" || w == "-U" || w == "-X" || w == "-e" ||
                w == "-o" || w == "-P" || w == "-h" || w == "-p" || w == "-R" || w == "-O" || w == "-d";
    if !takes { return 0; }
    if i + 1 >= a.len { return -1; }
    let v = a[i + 1];
    i = i + 2;
    if w == "-H" { return if set(o.uri, v) { 1 } else { -1 }; }
    if w == "-D" { return if set(o.binddn, v) { 1 } else { -1 }; }
    if w == "-w" { o.has_password = true; return if set_small(o.password, v) { 1 } else { -1 }; }
    if w == "-y" {
        var t: u8[>..] = [];
        if !read_file(v, t) { return -1; }
        // The whole file, as OpenLDAP reads it: a final newline is part of it.
        o.has_password = true;
        return if set_small(o.password, t) { 1 } else { -1 };
    }
    if w == "-Y" {
        if v.len > 64 { return -1; }
        o.mech.clear();
        for c in v { o.mech.push(if c >= 'a' && c <= 'z' { c - 32 } else { c }); }
        return 1;
    }
    if w == "-U" { return if set_small(o.authcid, v) { 1 } else { -1 }; }
    if w == "-X" { return if set_small(o.authzid, v) { 1 } else { -1 }; }
    if w == "-e" {
        if o.ext.len + v.len + 1 > o.ext.cap { return -1; }
        o.ext.append(v);
        o.ext.push('\n');
        return 1;
    }
    if w == "-o" {
        if v == "ldif_wrap=no" || v == "ldif-wrap=no" { o.wrap = 0; return 1; }
        if starts_with(v, "ldif_wrap=") || starts_with(v, "ldif-wrap=") {
            let n, ok = parse_int(v[10..], 10);
            if !ok || n < 0 { return -1; }
            o.wrap = n;
            return 1;
        }
        if starts_with(v, "nettimeout=") {
            let n, ok = parse_int(v[11..], 10);
            if !ok || n < 1 { return -1; }
            o.timeout_ms = n * 1000;
            return 1;
        }
        return -1;
    }
    if w == "-P" { return if v == "3" { 1 } else { -1 }; }
    if w == "-h" {
        o.uri.clear();
        o.uri.append(str("ldap://", v));
        return 1;
    }
    if w == "-p" {
        if o.uri.len == 0 { o.uri.append("ldap://localhost"); }
        o.uri.append(str(":", v));
        return 1;
    }
    // -R realm, -O security properties, -d debug level: taken, unused.
    return 1;
}

// The usage lines every tool adds.
let COMMON_USAGE: const u8[:] = "Common options:\n  -H URI      LDAP URI (ldap://, ldaps://, ldapi://; $LDAPURI)\n  -x          simple authentication\n  -D binddn   bind DN ($LDAPBINDDN)\n  -w passwd   bind password\n  -W          prompt for the bind password\n  -y file     read the bind password from file\n  -Y mech     SASL mechanism: EXTERNAL, PLAIN, DIGEST-MD5\n  -U authcid  SASL authentication identity\n  -X authzid  SASL authorization identity\n  -Z[Z]       StartTLS (-ZZ: it must succeed)\n  -M[M]       ManageDsaIT control (-MM: critical)\n  -e [!]ext   request control: assert=<filter>, authzid=<id>, manageDSAit, ppolicy, subtreeDelete\n  -o opt      ldif_wrap=<n>|no, nettimeout=<seconds>\n  -n          show what would be done\n  -Q          quiet SASL\n  -v          verbose\n";

// The request controls of -M and -e.
fn controls(o: const Opts&, out: u8[>..]&) -> bool {
    if o.manage_dsa_it > 0 { ldap::put_manage_dsa_it(out, o.manage_dsa_it == 2); }
    for e in split(o.ext, '\n') {
        if e.len == 0 { continue; }
        var critical = false;
        var x: const u8[:] = e;
        if x[0] == '!' { critical = true; x = x[1..]; }
        let eq = position(x, '=');
        let name = if eq >= 0 { x[..eq] } else { x };
        let value = if eq >= 0 { x[eq + 1..] } else { x[x.len..] };
        if name == "assert" {
            let f, ok = ldap::compile(value);
            if !ok { return false; }
            ldap::put_assertion(out, f, critical);
        } else if name == "authzid" {
            if !critical { sysnet::eprint("authzid: must be marked critical\n"); return false; }
            ldap::put_proxied_authz(out, value);
        } else if name == "manageDSAit" {
            ldap::put_manage_dsa_it(out, critical);
        } else if name == "ppolicy" {
            ldap::put_control(out, ldap::CONTROL_BEHERA_PASSWORD_POLICY, critical, "", false);
        } else if name == "subtreeDelete" {
            ldap::put_control(out, ldap::CONTROL_SUBTREE_DELETE, critical, "", false);
        } else {
            return false;
        }
    }
    return true;
}

// --- The transport ------------------------------------------------------------------

// The socket, and TLS over it once it is on.
struct Link { fd: i32, tls_on: bool, host: u8[..1024], t: tls::Conn }

fn link() -> Link {
    var cfg = tls::client_config("", "");
    return Link { fd: -1, tls_on: false, host: [], t: tls::client(cfg) };
}

// The serverSaslCreds of a response, copied out of msgs.
fn sasl_challenge(msgs: const u8[:], m: const ldap::Message&) -> u8[>..] {
    var out: u8[>..] = [];
    let ch, ok = ldap::server_sasl_creds(msgs, m);
    out.append(ch);
    return out;
}

// The TLS configuration for a host, from OpenLDAP's environment.
fn tls_config(o: const Opts&, host: const u8[:], cfg: tls::ClientConfig&) -> bool {
    var v: u8[>..] = [];
    if env("LDAPTLS_CACERT", v) {
        var pool = x509::new_pool();
        if x509::pool_add_file(pool, v) <= 0 { let x = fail(o, str("cannot read certificates from ", v)); return false; }
        cfg = tls::client_config_pool(host, pool);
    } else {
        cfg = tls::client_config(host, "");
    }
    v.clear();
    if env("LDAPTLS_REQCERT", v) && (v == "never" || v == "allow") { cfg.verify = false; }
    var cert_file: u8[>..] = [];
    var key_file: u8[>..] = [];
    if env("LDAPTLS_CERT", cert_file) && env("LDAPTLS_KEY", key_file) {
        var ct: u8[>..] = [];
        var kt: u8[>..] = [];
        if !read_file(cert_file, ct) || !read_file(key_file, kt) { let x = fail(o, "cannot read LDAPTLS_CERT or LDAPTLS_KEY"); return false; }
        let certs, okc = asn1::pem_decode(ct, "CERTIFICATE");
        let keys, okk = asn1::pem_decode(kt, "");
        var chain: u8[>..] = [];
        for c in certs { chain.append(c); }
        var key: u8[>..] = [];
        for k in keys { if key.len == 0 { key.append(k); } }
        if !okc || !okk || chain.len == 0 || key.len == 0 || !tls::set_client_certificate(cfg, chain, key) {
            let x = fail(o, "bad LDAPTLS_CERT or LDAPTLS_KEY");
            return false;
        }
    }
    return true;
}

fn write_all(l: const Link&, data: const u8[:]) -> bool { data.len == 0 || sysnet::net_write(l.fd, data) == data.len }

// Sends LDAP bytes, in TLS records once TLS is on.
fn transmit(l: Link&, data: const u8[:]) -> bool {
    if !l.tls_on { return write_all(l, data); }
    var out: u8[>..] = [];
    if !tls::send(l.t, data, out) { return false; }
    return write_all(l, out);
}

// Reads what arrives and feeds it to c, msgs getting whole messages: 0,
// or why the connection ended.
fn receive(o: const Opts&, l: Link&, cfg: const tls::ClientConfig&, c: ldap::Conn&, msgs: u8[>..]&) -> i64 {
    var buf: u8[65536] = [0; 65536];
    let n = sysnet::net_read(l.fd, buf, o.timeout_ms as! i32);
    if n == -2 { return ldap::RESULT_TIMEOUT; }
    if n <= 0 {
        let e = ldap::eof(c);
        return if e != 0 { e } else { ldap::ERROR_NETWORK };
    }
    if !l.tls_on { return ldap::feed(c, buf[..n], msgs); }
    var out: u8[>..] = [];
    var app: u8[>..] = [];
    let r = tls::client_feed(l.t, cfg, buf[..n], out, app);
    if !write_all(l, out) { return ldap::ERROR_NETWORK; }
    let code = ldap::feed(c, app, msgs);
    if code != 0 { return code; }
    if r != 0 {
        let e = ldap::eof(c);
        return if e != 0 { e } else { ldap::ERROR_NETWORK };
    }
    return 0;
}

// Sends out and waits until request id is answered; msgs holds what came.
fn wait(o: const Opts&, l: Link&, cfg: const tls::ClientConfig&, c: ldap::Conn&, id: i64, out: u8[>..]&, msgs: u8[>..]&) -> i64 {
    if !transmit(l, out) { return ldap::ERROR_NETWORK; }
    out.clear();
    while ldap::outstanding(c, id) {
        let code = receive(o, l, cfg, c, msgs);
        if code != 0 { return code; }
    }
    return 0;
}

// The final response to id among msgs.
fn response(msgs: const u8[:], id: i64) -> ldap::Message, bool {
    var pos = 0;
    var found = false;
    var last, x = ldap::parse_message(msgs, 0, 0);
    loop {
        let m, ok = ldap::next_message(msgs, pos);
        if !ok { break; }
        if m.id == id && m.op != ldap::OP_SEARCH_ENTRY && m.op != ldap::OP_SEARCH_REFERENCE && m.op != ldap::OP_INTERMEDIATE {
            last = m;
            found = true;
        }
    }
    return last, found;
}

// The TLS handshake on the link.
fn handshake(o: const Opts&, l: Link&, cfg: const tls::ClientConfig&) -> bool {
    l.t = tls::client(cfg);
    var out: u8[>..] = [];
    var app: u8[>..] = [];
    tls::client_start(l.t, cfg, out);
    var buf: u8[65536] = [0; 65536];
    loop {
        if !write_all(l, out) { break; }
        out.clear();
        if tls::connected(l.t) { l.tls_on = true; return true; }
        let n = sysnet::net_read(l.fd, buf, o.timeout_ms as! i32);
        if n <= 0 { break; }
        if tls::client_feed(l.t, cfg, buf[..n], out, app) != 0 {
            let x = write_all(l, out);
            break;
        }
    }
    var why: u8[>..] = [];
    format(why, "TLS: handshake failed (alert ", l.t.alert);
    if l.t.error != 0 { format(why, ", ", x509::error_text(l.t.error)); }
    why.push(')');
    let x = fail(o, why);
    return false;
}

// Connects as o says: the URL, TLS for ldaps://, StartTLS for -Z and
// -ZZ. 0, or the code to exit with.
fn connect(o: const Opts&, l: Link&, cfg: tls::ClientConfig&, c: ldap::Conn&) -> i64 {
    sysnet::net_init();
    let text = if o.uri.len > 0 { o.uri[..] } else { "ldap://localhost" };
    // Only the first of several URIs separated by spaces or commas.
    var end = 0;
    while end < text.len && text[end] != ' ' && text[end] != ',' { end++; }
    let u, ok = ldap::parse_url(text[..end]);
    if !ok { let x = fail(o, str("bad URI ", text[..end])); return ldap::RESULT_PARAM_ERROR; }
    let host = if u.host.len > 0 { u.host[..] } else if u.scheme == "ldapi" { "" } else { "localhost" };
    l.host.clear();
    l.host.append(host);
    if u.scheme == "ldapi" {
        if host.len == 0 { let x = fail(o, "ldapi:// needs the socket's path"); return ldap::RESULT_PARAM_ERROR; }
        l.fd = sysnet::net_connect_unix(host);
    } else {
        l.fd = sysnet::net_connect(host, u.port as! i32);
    }
    if l.fd < 0 {
        var s: u8[>..] = [];
        format(s, "Could not connect to URI=", u.scheme, "://");
        if u.scheme == "ldapi" { s.append(text[u.scheme.len + 3..end]); }
        else { format(s, host, ":", u.port); }
        s.append("/??base: Can't contact LDAP server (-1)\n");
        sysnet::eprint(s);
        return 1;
    }
    if !tls_config(o, host, cfg) { return 255; }
    if u.scheme == "ldaps" {
        if !handshake(o, l, cfg) { return 255; }
    } else if o.starttls > 0 {
        var out: u8[>..] = [];
        var msgs: u8[>..] = [];
        let id = ldap::start_tls(c, out);
        let code = wait(o, l, cfg, c, id, out, msgs);
        if code != 0 { report(o, "ldap_start_tls", code, "", ""); return status(code); }
        if !c.tls_ready {
            let m, okm = response(msgs, id);
            let rc = ldap::result_code(msgs, m);
            if o.starttls == 2 {
                report(o, "ldap_start_tls", rc, ldap::result_message(msgs, m), "");
                return status(rc);
            }
            sysnet::eprint(str("ldap_start_tls: ", err2string(rc), " (", rc, ")\n"));
        } else if !handshake(o, l, cfg) {
            return 255;
        }
    }
    return 0;
}

// A failure as OpenLDAP's tools write it (tool_perror): "ldap_<op>:
// <text> (<code>)", then the matched DN and the server's message.
fn report(o: const Opts&, op: const u8[:], code: i64, message: const u8[:], matched: const u8[:]) {
    var s: u8[>..] = [];
    format(s, op, ": ", err2string(code), " (", api_code(code), ")\n");
    if matched.len > 0 { format(s, "\tmatched DN: ", matched, "\n"); }
    if message.len > 0 { format(s, "\tadditional info: ", message, "\n"); }
    sysnet::eprint(s);
}

// A result as ldapcompare, ldapmodrdn and ldappasswd print it, on
// standard output: "<label>: <text> (<code>)", the server's message, the
// matched DN, the referrals.
fn print_result(label: const u8[:], msgs: const u8[:], m: const ldap::Message&) {
    let rc = ldap::result_code(msgs, m);
    var s: u8[>..] = [];
    format(s, label, ": ", err2string(rc), " (", rc, ")\n");
    let text = ldap::result_message(msgs, m);
    if text.len > 0 { format(s, "Additional info: ", text, "\n"); }
    let matched = ldap::matched_dn(msgs, m);
    if matched.len > 0 { format(s, "Matched DN: ", matched, "\n"); }
    for r in ldap::referrals(msgs, m) { format(s, "Referral: ", r, "\n"); }
    write_stdout(s);
}

fn report_response(o: const Opts&, op: const u8[:], msgs: const u8[:], m: const ldap::Message&) {
    report(o, op, ldap::result_code(msgs, m), ldap::result_message(msgs, m), ldap::matched_dn(msgs, m));
    let refs = ldap::referrals(msgs, m);
    if refs.len > 0 {
        var s: u8[>..] = [];
        s.append("\treferrals:\n");
        for r in refs { format(s, "\t\t", r, "\n"); }
        sysnet::eprint(s);
    }
}

fn hex_text(b: const u8[:]) -> u8[>..] {
    var o: u8[>..] = [];
    for x in b { format_uint(o, x, 16, 2, '0'); }
    return o;
}

// Binds as o says: -x (or -D, -w) simple, -Y SASL, else none. 0, or the
// code to exit with.
fn bind(o: Opts&, l: Link&, cfg: const tls::ClientConfig&, c: ldap::Conn&) -> i64 {
    var out: u8[>..] = [];
    var msgs: u8[>..] = [];
    let sasl = o.mech.len > 0;
    if !sasl && !o.simple && o.binddn.len == 0 && !o.has_password && !o.ask_password { return 0; }
    if o.ask_password && !o.has_password {
        let pw, ok = sysnet::secret("Enter LDAP Password: ");
        if !ok { let x = fail(o, "cannot read the password"); return ldap::RESULT_LOCAL_ERROR; }
        o.password.clear();
        o.password.append(pw);
        o.has_password = true;
    }
    if !sasl {
        let id = if o.password.len > 0 { ldap::bind(c, o.binddn, o.password, out) } else { ldap::unauthenticated_bind(c, o.binddn, out) };
        let code = wait(o, l, cfg, c, id, out, msgs);
        if code != 0 { report(o, "ldap_bind", code, "", ""); return status(code); }
        let m, okm = response(msgs, id);
        let rc = ldap::result_code(msgs, m);
        if rc != 0 { report(o, "ldap_bind", rc, ldap::result_message(msgs, m), ""); return status(rc); }
        return 0;
    }
    var id: i64 = 0;
    if o.mech == "EXTERNAL" {
        id = ldap::external_bind(c, out, o.authzid);
    } else if o.mech == "PLAIN" {
        id = ldap::plain_bind(c, o.authcid, o.password, out, o.authzid);
    } else if o.mech == "DIGEST-MD5" {
        id = ldap::sasl_bind(c, "DIGEST-MD5", "", false, out);
    } else {
        sysnet::eprint("ldap_sasl_interactive_bind: Unknown authentication method (-6)\n\tadditional info: SASL(-4): no mechanism available: No worthy mechs found\n");
        return status(ldap::RESULT_AUTH_UNKNOWN);
    }
    if !o.quiet { sysnet::eprint(str("SASL/", o.mech, " authentication started\n")); }
    loop {
        var code = wait(o, l, cfg, c, id, out, msgs);
        if code != 0 { report(o, "ldap_sasl_bind", code, "", ""); return status(code); }
        let m, okm = response(msgs, id);
        let rc = ldap::result_code(msgs, m);
        if rc == ldap::RESULT_SASL_BIND_IN_PROGRESS && o.mech == "DIGEST-MD5" {
            let challenge = sasl_challenge(msgs, m);
            if find(challenge, "rspauth=") >= 0 {
                // The server's proof; the exchange ends with an empty response.
                msgs.clear();
                id = ldap::sasl_bind(c, "DIGEST-MD5", "", false, out);
                continue;
            }
            var nonce_bytes: u8[16] = [0; 16];
            bignum::random_bytes(nonce_bytes);
            let resp, okr = ldap::digest_md5_response(challenge, l.host, o.authcid, o.password, hex_text(nonce_bytes));
            if !okr { let x = fail(o, "DIGEST-MD5: bad challenge"); return ldap::RESULT_DECODING_ERROR; }
            msgs.clear();
            id = ldap::sasl_bind(c, "DIGEST-MD5", resp, true, out);
            continue;
        }
        if rc != 0 { report(o, "ldap_sasl_interactive_bind", rc, ldap::result_message(msgs, m), ""); return status(rc); }
        return 0;
    }
}

// Unbinds and closes.
fn close(l: Link&, c: ldap::Conn&) {
    var out: u8[>..] = [];
    ldap::unbind(c, out);
    let x = transmit(l, out);
    if l.tls_on {
        var cl: u8[>..] = [];
        tls::close(l.t, cl);
        let y = write_all(l, cl);
    }
    sysnet::net_close(l.fd);
    l.fd = -1;
}

// Connects and binds: 0, or the code to exit with.
fn open(o: Opts&, l: Link&, cfg: tls::ClientConfig&, c: ldap::Conn&) -> i64 {
    let code = connect(o, l, cfg, c);
    if code != 0 { return code; }
    return bind(o, l, cfg, c);
}

// A one-request operation: sends it, waits, reports a failure (as
// tool_perror, or with label as print_result); the result code, or the
// client's own failure's.
fn run(o: const Opts&, l: Link&, cfg: const tls::ClientConfig&, c: ldap::Conn&, op: const u8[:], id: i64, out: u8[>..]&,
       msgs: u8[>..]&, label: const u8[:] = "") -> i64 {
    if id < 0 { report(o, op, c.error, c.message, ""); return c.error; }
    let code = wait(o, l, cfg, c, id, out, msgs);
    if code != 0 { report(o, op, code, "", ""); return code; }
    let m, ok = response(msgs, id);
    let rc = ldap::result_code(msgs, m);
    if rc != 0 && rc != ldap::RESULT_COMPARE_TRUE && rc != ldap::RESULT_COMPARE_FALSE {
        if label.len > 0 { print_result(label, msgs, m); } else { report_response(o, op, msgs, m); }
    }
    return rc;
}
