// goose-acme: certificates from an ACME server (RFC 8555), on gslib's acme:
//
//   goose-acme --server URL --account-key FILE [options] run -d NAME [-d NAME ...]
//   goose-acme --server URL --account-key FILE [options] register
//   goose-acme --server URL --account-key FILE [options] revoke --cert FILE [--reason N]
//   goose-acme --server URL --account-key FILE [options] rollover --new-account-key FILE
//   goose-acme --server URL --account-key FILE [options] deactivate
//
// The account key is a JWK file, made (P-256, mode 0600) when it is not
// there. `run` registers the account if it has none, orders a certificate
// for the names, proves each by one of
//
//   --http PORT                 serving http-01 itself on PORT (80 for a real CA)
//   --webroot DIR               writing http-01's files under DIR/.well-known/acme-challenge/
//   --dns SERVER[:PORT]         dns-01 by dynamic update (RFC 2136) to that server,
//     [--tsig NAME:SECRET[:ALG]]  signed with a TSIG key (base64 secret, hmac-sha256 by default),
//     [--dns-zone ZONE]           in that zone (else the zone of the SOA the server gives),
//     [--dns-wait SECONDS]        waiting that long for secondaries before asking for validation
//
// and writes the chain (PEM, leaf first) to --cert-out and a new key
// (PKCS #8 PEM, 0600) to --key-out, or keeps --key FILE's. Other options:
//
//   --ca-file FILE        trust these PEM certificates for the server, not the system's
//   --email ADDRESS       the account's contact; --agree-tos agrees to the terms
//   --eab-kid ID --eab-hmac KEY   bind to the CA's account (KEY base64url, as CAs hand it out)
//   --key-type T          ec256 (the default), ec384, rsa2048, rsa3072 or rsa4096
//   --profile NAME        one of the server's certificate profiles
//
// Nothing secret is printed. Exit status 0 on success, 1 on failure, 2 on
// a usage error.
import std;
import os;
import gslib from "../..";
import gslib.acme;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.net;
import gslib.net.http;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.pool;
import gslib.encoding.asn1;
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.update;
import gslib.dns.client;
import gslib.dns.server;
import gslib.krb5.sys;

struct Options {
    server:          u8[..512]  = [],
    account_key:     u8[..512]  = [],
    ca_file:         u8[..512]  = [],
    email:           u8[..256]  = [],
    agree:           bool       = false,
    eab_kid:         u8[..256]  = [],
    eab_hmac:        u8[..512]  = [],
    names:           u8[..4096] = [],   // one a line
    http_port:       i32        = -1,
    webroot:         u8[..512]  = [],
    dns_server:      u8[..256]  = [],
    tsig:            u8[..512]  = [],
    dns_zone:        u8[..256]  = [],
    dns_wait:        i64        = 0,
    cert_out:        u8[..512]  = [],
    key_out:         u8[..512]  = [],
    key_in:          u8[..512]  = [],
    key_type:        u8[..16]   = [],
    profile:         u8[..64]   = [],
    cert:            u8[..512]  = [],
    reason:          i64        = acme::REASON_NONE,
    new_account_key: u8[..512]  = [],
}

fn usage() -> i32 {
    write_stderr("usage: goose-acme --server URL --account-key FILE [options] run -d NAME ... | register | revoke --cert FILE | rollover --new-account-key FILE | deactivate\n");
    return 2;
}

fn fail(s: const u8[:]) -> i32 {
    write_stderr(str("goose-acme: ", s, "\n"));
    return 1;
}

fn say(s: const u8[:]) { write_stderr(str(s, "\n")); }

// What went wrong with a request: the error, and the server's problem.
fn why(a: const acme::Client&, e: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(acme::error_text(e));
    if e == acme::ERR_HTTP { out.append(": "); out.append(http::client_error_text(a.http_err)); }
    if e == acme::ERR_PROBLEM && a.problem.status > 0 { out.append(": HTTP "); format(out, a.problem.status); }
    if (e == acme::ERR_PROBLEM || e == acme::ERR_INVALID) && (a.problem.kind.len > 0 || a.problem.detail.len > 0) {
        out.append(": ");
        out.append(a.problem.kind);
        if a.problem.detail.len > 0 { out.append(" ("); out.append(a.problem.detail); out.push(')'); }
    }
    return out;
}

fn write_private(path: const u8[:], data: const u8[:]) -> bool { krb5::krb5sys_write_private(path, data) == 0 }

// The account key from its file, or a new P-256 key written there.
fn account_key(path: const u8[:]) -> jwk::Key, bool {
    var text: u8[>..] = [];
    if read_file(path, text) {
        let k, err = jwk::parse(text);
        return k, err == jwx::OK && k.private;
    }
    let k = jwk::generate_ec(jwa::CRV_P256);
    if !write_private(path, jwk::marshal(k, true)) { return k, false; }
    say(str("made a new account key in ", path));
    return k, true;
}

fn cert_key(o: const Options&) -> x509::PrivateKey, bool {
    if o.key_in.len > 0 {
        var text: u8[>..] = [];
        if !read_file(o.key_in, text) { return x509::empty_key(), false; }
        let k, ok = x509::parse_private_key_pem(text);
        return k, ok;
    }
    let t = o.key_type[..];
    if t.len == 0 || t == "ec256" { return x509::generate_key(x509::KEY_EC_P256), true; }
    if t == "ec384" { return x509::generate_key(x509::KEY_EC_P384), true; }
    if t == "rsa2048" { return x509::generate_key(x509::KEY_RSA, 2048), true; }
    if t == "rsa3072" { return x509::generate_key(x509::KEY_RSA, 3072), true; }
    if t == "rsa4096" { return x509::generate_key(x509::KEY_RSA, 4096), true; }
    return x509::empty_key(), false;
}

// The CSR for the names: the first as the CN when it fits, all in the SAN.
fn make_csr(names: const u8[:], k: const x509::PrivateKey&) -> u8[>..], bool {
    var san:   u8[..4096] = [];
    var first: u8[>..]    = [];
    for n in split(names, '\n') {
        if n.len == 0 { continue; }
        if first.len == 0 { first.append(n); }
        if san.len + n.len + 4 > 4096 { var none: u8[>..] = []; return none, false; }
        x509::add_dns(san, n);
    }
    var cn: u8[>..] = [];
    if first.len <= 64 && position(first, ',') < 0 && position(first, '+') < 0 { cn.append("CN="); cn.append(first); }
    let subject, ok = x509::name_der(cn);
    if !ok { var none: u8[>..] = []; return none, false; }
    let csr, err = x509::create_csr(subject, san, k);
    return csr, err == x509::OK;
}

// --- http-01, served ------------------------------------------------------------

fn token_char(c: u8) -> bool { (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' }

// The response to one request: the key authorization for any token under
// /.well-known/acme-challenge/ (it is the token and the account key's
// thumbprint, nothing secret), 404 for anything else.
fn http01_response(req: const u8[:], thumb: const u8[:]) -> u8[>..] {
    let prefix = "GET /.well-known/acme-challenge/";
    var out: u8[>..] = [];
    var from = 0;
    var to = 0;
    if req.len > prefix.len && req[..prefix.len] == prefix {
        let sp = position(req[prefix.len..], ' ');
        if sp > 0 { from = prefix.len; to = prefix.len + sp; }
    }
    let token = req[from..to];
    var ok = token.len > 0;
    for c in token { if !token_char(c) { ok = false; } }
    if !ok {
        out.append("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return out;
    }
    let body = str(token, ".", thumb);
    out.append("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ");
    format(out, body.len);
    out.append("\r\nConnection: close\r\n\r\n");
    out.append(body);
    return out;
}

// Serves http-01 on the listening socket until the program ends.
thread_fn http01_server(fd: i64, thumb: u8[..64]) {
    var buf: u8[4096] = [0; 4096];
    loop {
        let c = dns::dnsnet_accept(fd, 1000);
        if c < 0 { continue; }
        var req: u8[>..] = [];
        while find(req, "\r\n\r\n") < 0 && req.len < 8192 {
            let n = net::read(c, buf, 5000);
            if n <= 0 { break; }
            req.append(buf[..n]);
        }
        net::write(c, http01_response(req, thumb), 5000);
        net::close(c);
    }
}

// --- dns-01, by dynamic update ------------------------------------------------------

fn dns_client(o: const Options&) -> dns::Client, bool {
    var c = dns::Client { .. };
    c.net = dns::NET_TCP;
    if o.tsig.len == 0 { return c, true; }
    let name, rest, ok = split_once(o.tsig, ':');
    if !ok || name.len == 0 { return c, false; }
    let secret, alg, has_alg = split_once(rest, ':');
    let sec = if has_alg { secret } else { rest };
    if sec.len == 0 || sec.len > 128 || name.len > 254 { return c, false; }
    c.tsig_name.append(name);
    if !dns::is_fqdn(name) { c.tsig_name.push('.'); }
    c.tsig_secret.append(sec);
    if has_alg {
        c.tsig_alg.clear();
        c.tsig_alg.append(alg);
        if !dns::is_fqdn(alg) { c.tsig_alg.push('.'); }
    }
    return c, true;
}

// The zone the record goes in: --dns-zone, or the owner of the SOA the
// server answers with for the record's name.
fn dns_zone(o: const Options&, owner: const u8[:]) -> u8[>..], bool {
    var zone: u8[>..] = [];
    if o.dns_zone.len > 0 {
        zone.append(o.dns_zone);
        if !dns::is_fqdn(zone) { zone.push('.'); }
        return zone, true;
    }
    var r = dns::Msg { .. };
    if dns::query(o.dns_server, owner, dns::TYPE_SOA, r) != dns::OK { return zone, false; }
    dns::each_rr(r.answer) { rr => if rr.rtype == dns::TYPE_SOA && zone.len == 0 { zone.append(dns::name_text(rr, r.answer)); } };
    dns::each_rr(r.ns) { rr => if rr.rtype == dns::TYPE_SOA && zone.len == 0 { zone.append(dns::name_text(rr, r.ns)); } };
    return zone, zone.len > 0;
}

// Adds (or removes) the TXT record `value` at the challenge's name.
fn dns_update(o: const Options&, domain: const u8[:], value: const u8[:], add: bool) -> bool {
    let c, ok = dns_client(o);
    if !ok { return false; }
    let owner = str(acme::dns01_name(domain), ".");
    let zone, zok = dns_zone(o, owner);
    if !zok { say(str("no zone found for ", owner)); return false; }
    var u = dns::Msg { .. };
    if dns::set_update(u, zone) != dns::OK { return false; }
    var rr: u8[>..] = [];
    if dns::new_rr(rr, str(owner, " 60 IN TXT \"", value, "\"")) != dns::OK { return false; }
    if add { dns::insert(u, rr); } else { dns::remove(u, rr); }
    var r = dns::Msg { .. };
    let err = dns::exchange(c, u, o.dns_server, r);
    if err != dns::OK || r.hdr.rcode != dns::RCODE_SUCCESS {
        say(str("the update of ", owner, " in ", zone, " failed: ", if err != dns::OK { dns::error_text(err) } else { dns::rcode_name(r.hdr.rcode) }));
        return false;
    }
    return true;
}

// --- Commands ------------------------------------------------------------------------

fn run_order(a: acme::Client&, hc: http::Client&, o: const Options&) -> i32 {
    if o.dns_server.len == 0 && o.http_port < 0 && o.webroot.len == 0 { return fail("run needs --http, --webroot or --dns"); }
    var kind: u8[..8] = [];
    kind.append(if o.dns_server.len > 0 { "dns-01" } else { "http-01" });
    let k, kok = cert_key(o);
    if !kok { return fail("cannot read or make the certificate's key"); }
    let csr, cok = make_csr(o.names, k);
    if !cok { return fail("cannot make the certificate request"); }
    if o.http_port >= 0 {
        let fd = dns::dnsnet_listen("", o.http_port, 1);
        if fd < 0 { return fail(str("cannot listen on port ", o.http_port)); }
        var thumb: u8[..64] = [];
        thumb.append(jwk::thumbprint_b64(a.key));
        thread_spawn(http01_server, fd, thumb);
    }
    var published: u8[>..] = [];       // what to take down afterwards: "name value" or a path, one a line
    var chain, err = acme::obtain(a, hc, o.names, csr, kind, o.profile) { z, ch, value =>
        say(str("proving ", z.id_value, " by ", kind));
        var done = true;
        if kind == "dns-01" {
            done = dns_update(o, z.id_value, value, true);
            if done {
                published.append(str(z.id_value, " ", value, "\n"));
                if o.dns_wait > 0 { sleep_ms(o.dns_wait * 1000); }
            }
        } else if o.webroot.len > 0 {
            let dir = str(o.webroot, "/.well-known/acme-challenge");
            make_dir(o.webroot);
            make_dir(str(o.webroot, "/.well-known"));
            make_dir(dir);
            let path = str(dir, "/", ch.token);
            done = write_file(path, value);
            if done { published.append(str(path, "\n")); }
        }
        done
    };
    for line in split(published, '\n') {
        if line.len == 0 { continue; }
        if kind == "dns-01" {
            let name, value, ok = split_once(line, ' ');
            dns_update(o, name, value, false);
        } else {
            delete_file(line);
        }
    }
    if err != acme::OK { return fail(why(a, err)); }
    var first: u8[>..] = [];
    for n in split(o.names, '\n') { if n.len > 0 && first.len == 0 { first.append(if n.len > 2 && n[..2] == "*." { n[2..] } else { n }); } }
    let cert_out = if o.cert_out.len > 0 { str(o.cert_out) } else { str(first, ".crt") };
    if !write_file(cert_out, chain) { return fail(str("cannot write ", cert_out)); }
    say(str("wrote the certificate chain to ", cert_out));
    if o.key_in.len == 0 {
        let key_out = if o.key_out.len > 0 { str(o.key_out) } else { str(first, ".key") };
        var pem: u8[>..] = [];
        asn1::pem_encode(pem, "PRIVATE KEY", x509::marshal_pkcs8(k));
        if !write_private(key_out, pem) { return fail(str("cannot write ", key_out)); }
        say(str("wrote its key to ", key_out));
    }
    return 0;
}

fn register(a: acme::Client&, hc: http::Client&, o: const Options&) -> i64 {
    let found = acme::find_account(a, hc);
    if found == acme::OK { return acme::OK; }
    if !(found == acme::ERR_PROBLEM && acme::is_problem(a, "accountDoesNotExist")) { return found; }
    var contacts: u8[>..] = [];
    if o.email.len > 0 { contacts.append("mailto:"); contacts.append(o.email); }
    var mac: u8[>..] = [];
    if o.eab_kid.len > 0 {
        let m, ok = jwx::b64_decode(o.eab_hmac);
        if !ok || m.len == 0 { return acme::ERR_ARG; }
        mac.append(m);
    }
    let err = acme::new_account(a, hc, contacts, o.agree, o.eab_kid, mac);
    if err == acme::OK { say(str("registered ", a.account)); }
    return err;
}

fn run() -> i32 {
    let a = args();
    var o = Options { .. };
    var command: u8[..16] = [];
    var i = 1;
    while i < a.len {
        let s = a[i];
        let has_value = i + 1 < a.len;
        if s == "--agree-tos" { o.agree = true; }
        else if s == "run" || s == "register" || s == "revoke" || s == "rollover" || s == "deactivate" {
            command.clear();
            command.append(s);
        }
        else if !has_value { return usage(); }
        else {
            i++;
            let v = a[i];
            if v.len > 4000 { return usage(); }
            if s == "--server" && v.len <= 512 { o.server.append(v); }
            else if s == "--account-key" && v.len <= 512 { o.account_key.append(v); }
            else if s == "--ca-file" && v.len <= 512 { o.ca_file.append(v); }
            else if s == "--email" && v.len <= 256 { o.email.append(v); }
            else if s == "--eab-kid" && v.len <= 256 { o.eab_kid.append(v); }
            else if s == "--eab-hmac" && v.len <= 512 { o.eab_hmac.append(v); }
            else if s == "-d" && o.names.len + v.len + 1 <= 4096 { o.names.append(v); o.names.push('\n'); }
            else if s == "--http" { let p, ok = parse_int(v); if !ok || p < 0 || p > 65535 { return usage(); } o.http_port = p as! i32; }
            else if s == "--webroot" && v.len <= 512 { o.webroot.append(v); }
            else if s == "--dns" && v.len <= 256 { o.dns_server.append(v); }
            else if s == "--tsig" && v.len <= 512 { o.tsig.append(v); }
            else if s == "--dns-zone" && v.len <= 256 { o.dns_zone.append(v); }
            else if s == "--dns-wait" { let w, ok = parse_int(v); if !ok || w < 0 { return usage(); } o.dns_wait = w; }
            else if s == "--cert-out" && v.len <= 512 { o.cert_out.append(v); }
            else if s == "--key-out" && v.len <= 512 { o.key_out.append(v); }
            else if s == "--key" && v.len <= 512 { o.key_in.append(v); }
            else if s == "--key-type" && v.len <= 16 { o.key_type.append(v); }
            else if s == "--profile" && v.len <= 64 { o.profile.append(v); }
            else if s == "--cert" && v.len <= 512 { o.cert.append(v); }
            else if s == "--reason" { let r, ok = parse_int(v); if !ok || r < 0 || r > 10 { return usage(); } o.reason = r; }
            else if s == "--new-account-key" && v.len <= 512 { o.new_account_key.append(v); }
            else { return usage(); }
        }
        i++;
    }
    if command.len == 0 || o.server.len == 0 || o.account_key.len == 0 { return usage(); }

    var hc = http::Client { .. };
    if o.ca_file.len > 0 {
        var text: u8[>..] = [];
        if !read_file(o.ca_file, text) { return fail(str("cannot read ", o.ca_file)); }
        var pool = x509::new_pool();
        if x509::pool_append_pem(pool, text) <= 0 { return fail(str("no certificates in ", o.ca_file)); }
        hc.tlscfg = tls::client_config_pool("", pool);
    }
    var c = acme::Client { .. };
    let key, kok = account_key(o.account_key);
    if !kok { return fail(str("cannot read or write the account key ", o.account_key)); }
    if acme::set_key(c, key) != acme::OK { return fail("the account key cannot sign"); }
    let oerr = acme::open(c, hc, o.server);
    if oerr != acme::OK { return fail(str("cannot read the directory: ", why(c, oerr))); }

    let rerr = register(c, hc, o);
    if rerr != acme::OK { return fail(str("no account: ", why(c, rerr))); }

    if command == "register" {
        print(c.account);
        return 0;
    }
    if command == "run" {
        if o.names.len == 0 { return usage(); }
        return run_order(c, hc, o);
    }
    if command == "revoke" {
        if o.cert.len == 0 { return usage(); }
        var text: u8[>..] = [];
        if !read_file(o.cert, text) { return fail(str("cannot read ", o.cert)); }
        let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
        if !ok || ders.len == 0 { return fail(str("no certificate in ", o.cert)); }
        var err = acme::OK;
        for der in ders { err = acme::revoke(c, hc, der, o.reason); break; }
        if err != acme::OK { return fail(why(c, err)); }
        say("revoked");
        return 0;
    }
    if command == "rollover" {
        if o.new_account_key.len == 0 { return usage(); }
        let nk, nok = account_key(o.new_account_key);
        if !nok { return fail(str("cannot read or write ", o.new_account_key)); }
        let err = acme::key_change(c, hc, nk);
        if err != acme::OK { return fail(why(c, err)); }
        say(str("the account now uses the key in ", o.new_account_key));
        return 0;
    }
    if command == "deactivate" {
        let err = acme::deactivate_account(c, hc);
        if err != acme::OK { return fail(why(c, err)); }
        say("deactivated");
        return 0;
    }
    return usage();
}

fn main() { exit(run()); }
