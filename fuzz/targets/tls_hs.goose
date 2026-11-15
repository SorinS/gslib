// Fuzz target: tls_hs. TLS handshakes in memory, the peer's bytes from the
// input. The configurations are fixed (P-256 server certificate and root
// from crypto/tls/test/vectors, fixed DRBG seeds, clock and ticket key), so
// a run is deterministic and a recorded peer flight replays exactly. The
// first byte picks the path (data[0] % 5) and variants (data[0] / 5):
//   0: a server fed the input as records (server_feed): ClientHello
//      (TLS 1.3 and 1.2, ECH, PSK, HRR), then whatever follows; TLS 1.2's
//      ClientKeyExchange is in the clear. Variants: client certificates
//      requested, TLS 1.2 only, tickets off.
//   1: a client after client_start fed the input as records (client_feed):
//      ServerHello/HelloRetryRequest, and TLS 1.2's Certificate,
//      ServerKeyExchange, CertificateRequest, ServerHelloDone in the
//      clear. Variants: verify off, TLS 1.2 only, ALPN offered.
//   2: TLS 1.3 client handshake messages past ServerHello, straight to
//      client_message (the input split into messages by their headers),
//      starting in the state the variant picks (EncryptedExtensions,
//      CertificateRequest, Certificate, CertificateVerify, Finished,
//      post-handshake NewSessionTicket/KeyUpdate). No ClientHello was sent
//      (no client_start), so the transcript is empty: these states are
//      forced, and a crash here must be shown through paths 0/1 to count.
//   3: TLS 1.3 server messages past ClientHello, straight to
//      server_message: the client's Certificate and CertificateVerify
//      (client auth required and verified), post-handshake messages.
//   4: the standalone parsers: parse_hello, the ECH config list
//      (pick_ech_config, ech_server_config, ech_info), ech_inner_ok and
//      ech_decode_inner against a fixed outer ClientHello, record_length.

import std;
import gslib from "../..";
import gslib.crypto.tls;
import gslib.crypto.bignum;
import gslib.encoding.asn1;
import gslib.crypto.x509;
import gslib.crypto.tls.handshake;
import gslib.crypto.tls.record;
import gslib.crypto.tls.ech;
import gslib.crypto.x509.pool;

let NOW: i64 = 1800000000;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// A field of crypto/tls/test/vectors/hs_certs.txt, as its test reads them.
fn field(kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("../../crypto/tls/test/vectors/hs_certs.txt"), '\n') {
        let w = words(line);
        if w.len < 3 { continue; }
        if w[0] == kind && (kind == "root" || kind == "clientca") { return unhex(w[idx - 1]); }
        if (w[0] == "server" || w[0] == "client") && w[1] == kind { return unhex(w[idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

fn server_cfg(variant: u8) -> tls::ServerConfig {
    var sc, ok = tls::server_config(field("p256", 2), field("p256", 3));
    sc.seed = 2;
    sc.now = NOW;
    for i in 32 { sc.ticket_key[i] = i as! u8; }
    if variant & 1 != 0 {
        sc.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
        let _ = x509::pool_add(sc.client_cas, field("clientca", 2));
        let _ = x509::pool_add(sc.client_cas, field("root", 2));
    }
    if variant & 2 != 0 { sc.max_version = tls::VERSION_TLS12; }
    if variant & 4 != 0 { sc.tickets = 0; }
    return sc;
}

fn client_cfg(variant: u8) -> tls::ClientConfig {
    var cc = tls::client_config("example.com", field("root", 2));
    cc.now = NOW;
    cc.seed = 1;
    if variant & 1 != 0 { cc.verify = false; }
    if variant & 2 != 0 { cc.max_version = tls::VERSION_TLS12; }
    if variant & 4 != 0 { tls::add_alpn(cc.alpn, "h2"); tls::add_alpn(cc.alpn, "http/1.1"); }
    return cc;
}

// The configurations of each variant, made once.
var SC0:  tls::ServerConfig = server_cfg(0);
var SC1:  tls::ServerConfig = server_cfg(1);
var SC2:  tls::ServerConfig = server_cfg(2);
var SC3:  tls::ServerConfig = server_cfg(3);
var SC4:  tls::ServerConfig = server_cfg(4);
var SC5:  tls::ServerConfig = server_cfg(5);
var SC6:  tls::ServerConfig = server_cfg(6);
var SC7:  tls::ServerConfig = server_cfg(7);
var CC0:  tls::ClientConfig = client_cfg(0);
var CC1:  tls::ClientConfig = client_cfg(1);
var CC2:  tls::ClientConfig = client_cfg(2);
var CC3:  tls::ClientConfig = client_cfg(3);
var CC4:  tls::ClientConfig = client_cfg(4);
var CC5:  tls::ClientConfig = client_cfg(5);
var CC6:  tls::ClientConfig = client_cfg(6);
var CC7:  tls::ClientConfig = client_cfg(7);
var CCC0: tls::ClientConfig = client_cfg_cert(0);
var CCC4: tls::ClientConfig = client_cfg_cert(4);

fn scfg(v: u8) -> const tls::ServerConfig& {
    if v % 8 == 0 { return SC0; }
    if v % 8 == 1 { return SC1; }
    if v % 8 == 2 { return SC2; }
    if v % 8 == 3 { return SC3; }
    if v % 8 == 4 { return SC4; }
    if v % 8 == 5 { return SC5; }
    if v % 8 == 6 { return SC6; }
    return SC7;
}

fn ccfg(v: u8) -> const tls::ClientConfig& {
    if v % 8 == 0 { return CC0; }
    if v % 8 == 1 { return CC1; }
    if v % 8 == 2 { return CC2; }
    if v % 8 == 3 { return CC3; }
    if v % 8 == 4 { return CC4; }
    if v % 8 == 5 { return CC5; }
    if v % 8 == 6 { return CC6; }
    return CC7;
}

fn client_cfg_cert(variant: u8) -> tls::ClientConfig {
    var cc = client_cfg(variant);
    let _ = tls::set_client_certificate(cc, field("p256", 2), field("p256", 3));
    return cc;
}

fn server_records(input: const u8[:], variant: u8) {
    let sc = scfg(variant);
    var s = tls::server(sc);
    var out: u8[>..] = [];
    var app: u8[>..] = [];
    let r = tls::server_feed(s, sc, input, out, app);
    if tls::connected(s) {
        var o2: u8[>..] = [];
        let _ = tls::send(s, "reply", o2);
        let _ = tls::key_update(s, true, o2);
        tls::close(s, o2);
    }
}

fn client_records(input: const u8[:], variant: u8) {
    let cc = ccfg(variant);
    var c = tls::client(cc);
    var out: u8[>..] = [];
    var app: u8[>..] = [];
    tls::client_start(c, cc, out);
    out.clear();
    let r = tls::client_feed(c, cc, input, out, app);
    if tls::connected(c) {
        let _ = tls::peer_certificates(c);
        let s, has = tls::session(c);
    }
}

// The input as handshake messages, each to F until one fails.
fn each_message<F>(input: const u8[:]) {
    var off = 0;
    var n = 0;
    while off < input.len && n < 16 {
        let l = tls::handshake_length(input[off..]);
        if l == 0 { return; }
        if F(input[off..off + l]) != 0 { return; }
        off += l;
        n++;
    }
}

fn client_messages(input: const u8[:], variant: u8) {
    let states = [tls::ST_WAIT_EE, tls::ST_WAIT_CERT_CR, tls::ST_WAIT_CERT, tls::ST_WAIT_CV, tls::ST_WAIT_FINISHED,
                  tls::ST_CONNECTED];
    let cert = variant & 8 != 0;
    let alpn = variant & 4 != 0;
    var c = tls::client(CC0);
    var out: u8[>..] = [];
    c.version = tls::VERSION_TLS13;
    c.state = states[(variant % 6) as i64];
    if cert && alpn { each_message(input) { m => tls::client_message(c, CCC4, m, out) }; }
    else if cert { each_message(input) { m => tls::client_message(c, CCC0, m, out) }; }
    else if alpn { each_message(input) { m => tls::client_message(c, CC4, m, out) }; }
    else { each_message(input) { m => tls::client_message(c, CC0, m, out) }; }
}

fn server_messages(input: const u8[:], variant: u8) {
    let states = [tls::ST_WAIT_CLIENT_CERT, tls::ST_WAIT_CLIENT_CV, tls::ST_WAIT_CLIENT_FINISHED, tls::ST_CONNECTED];
    let sc = SC1;
    var s = tls::server(sc);
    s.version = tls::VERSION_TLS13;
    s.state = states[(variant % 4) as i64];
    var out: u8[>..] = [];
    each_message(input) { m => tls::server_message(s, sc, m, out) };
}

var OUTER: u8[>..] = [];

fn parsers(input: const u8[:]) {
    if input.len >= 4 && input[0] == 1 {
        let h, ok = tls::parse_hello(input);
        let _ = tls::hello_digest(input);
    }
    let cfg, cok = tls::pick_ech_config(input);
    let id, kem, sok = tls::ech_server_config(input);
    if input.len >= 4 {
        let _ = tls::ech_info(input);
    }
    if input.len >= 4 && input[0] == 1 {
        let _ = tls::ech_inner_ok(input);
        let inner, iok = tls::ech_decode_inner(OUTER, input[4..]);
        if iok { let h2, ok2 = tls::parse_hello(inner); }
    }
    let _ = tls::record_length(input, false);
    let _ = tls::record_length(input, true);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let input = data[1..];
    let sel = data[0] % 5;
    let variant = data[0] / 5;
    if sel == 0 { server_records(input, variant); }
    else if sel == 1 { client_records(input, variant); }
    else if sel == 2 { client_messages(input, variant); }
    else if sel == 3 { server_messages(input, variant); }
    else { parsers(input); }
    return 0;
}

fn main() {
    // A ClientHello of the client, as the outer one for ech_decode_inner.
    var c = tls::client(CC0);
    var out: u8[>..] = [];
    tls::client_start(c, CC0, out);
    if out.len > 5 { OUTER.append(out[5..]); }
}
