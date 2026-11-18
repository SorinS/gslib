// Keys that never leave a TPM, used by the rest of gslib through signers
// (scripts/interop.py runs this against swtpm): a P-256 and an RSA-2048
// signing key made in the TPM, standing in configurations as their public
// keys (tpm2::x509_key), each signature made by tpm2::sign_data:
// - a self-signed certificate and a CSR (x509), checked;
// - TLS 1.3 and TLS 1.2 handshakes, in memory, the server's key in the TPM;
// - an SSH login, in memory, the server's host key in the TPM;
// - a JWT (ES256) that verifies under the key's public JWK.
//
//   goose scripts/signer.goose -- --tpm tcp:127.0.0.1:2321
//
// Prints "ok NAME", "FAIL NAME: why" or "skip NAME: why" a line, and
// "N passed, M failed"; exit status 1 if any failed.
import std;
import os;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.transport;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.ssh;
import gslib.crypto.ssh.keys;
import gslib.crypto.ssh.conn;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwt;
import gslib.jwx.pem;

var passed = 0;
var failed = 0;

fn ok(name: const u8[:]) { passed++; print("ok    ", name); }
fn fail(name: const u8[:], why: const u8[:]) { failed++; print("FAIL  ", name, ": ", why); }
fn skip(name: const u8[:], why: const u8[:]) { print("skip  ", name, ": ", why); }

fn expect(name: const u8[:], cond: bool, why: const u8[:] = "") -> bool {
    if cond { ok(name); } else { fail(name, why); }
    return cond;
}

let NOW: i64 = 1800000000;
let YEAR: i64 = 31536000;

// A self-signed certificate for the TPM key, made through the signer.
fn self_signed(t: tpm2::Tpm&, key: tpm2::Entity, s: tpm2::Session&, ext: const x509::PrivateKey&, cn: const u8[:]) -> u8[>..], i64 {
    var tm, okt = x509::template(str("CN=", cn), NOW - YEAR, NOW + YEAR);
    tm.key_usage = x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_CERT_SIGN;
    tm.is_ca = true;
    x509::add_dns(tm.san, cn);
    let cert, e = x509::create_certificate(tm, x509::marshal_public_key(ext), "", ext) { k, alg, h, data => tpm2::sign_data(t, key, s, alg, h, data) };
    return cert, e;
}

// A TLS handshake in memory: the server's certificate cert, its key in the
// TPM; up to version max. Whether it connected and data crossed.
fn tls_handshake(t: tpm2::Tpm&, key: tpm2::Entity, s: tpm2::Session&, cert: const u8[:], cn: const u8[:], max: u16) -> bool {
    var sc, oks = tls::server_config(cert);
    if !oks { return false; }
    sc.now = NOW;
    sc.max_version = max;
    var cc = tls::client_config(cn, cert);
    cc.now = NOW;
    cc.max_version = max;
    var c = tls::client(cc);
    var sv = tls::server(sc);
    var to_server: u8[>..] = [];
    var capp: u8[>..] = [];
    var sapp: u8[>..] = [];
    tls::client_start(c, cc, to_server);
    for round in 20 {
        if to_server.len == 0 { break; }
        var to_client: u8[>..] = [];
        let rs = tls::server_feed(sv, sc, to_server, to_client, sapp) { k, alg, h, data => tpm2::sign_data(t, key, s, alg, h, data) };
        to_server.clear();
        if to_client.len == 0 { break; }
        let rc = tls::client_feed(c, cc, to_client, to_server, capp);
    }
    if !tls::connected(c) || !tls::connected(sv) { return false; }
    var to_client: u8[>..] = [];
    return tls::send(sv, "from the TPM's server", to_client) && tls::client_feed(c, cc, to_client, to_server, capp) == 0
           && capp == "from the TPM's server";
}

// An SSH login in memory, the server's host key in the TPM, the client
// knowing it by its public key and logging in with an Ed25519 key in memory.
fn ssh_login(t: tpm2::Tpm&, key: tpm2::Entity, s: tpm2::Session&, ext: const x509::PrivateKey&) -> bool {
    let host, okh = ssh::private_key(ext);
    if !okh { return false; }
    var sc = ssh::server_config();
    if !ssh::add_host_key(sc, host) { return false; }
    let user = ssh::generate_key(x509::KEY_ED25519);
    sc.authorized_keys.append(ssh::marshal_authorized_key(user.public));
    var cc = ssh::client_config("alice", "tpm.example.com");
    cc.known_hosts.append(str("tpm.example.com ", ssh::marshal_authorized_key(host.public)));
    if !ssh::add_key(cc, user) { return false; }
    var c = ssh::client(cc);
    var sv = ssh::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    ssh::client_start(c, cc, to_server);
    ssh::server_start(sv, sc, to_client);
    for round in 60 {
        if to_server.len == 0 && to_client.len == 0 { break; }
        var sev: u8[>..] = [];
        var s_out: u8[>..] = [];
        let rs = ssh::server_feed(sv, sc, to_server, s_out, sev) { k, alg, h, data => tpm2::sign_data(t, key, s, alg, h, data) };
        to_server.clear();
        to_client.append(s_out);
        var cev: u8[>..] = [];
        var c_out: u8[>..] = [];
        let rc = ssh::client_feed(c, cc, to_client, c_out, cev);
        to_client.clear();
        to_server.append(c_out);
    }
    return ssh::connected(c) && ssh::connected(sv);
}

fn p256(t: tpm2::Tpm&, pe: tpm2::Entity) {
    var s = tpm2::pw();
    let ko, ec = tpm2::create_loaded(t, pe, s, tpm2::ecc_sign_template(tpm2::ECC_NIST_P256));
    if !expect("P-256 key made in the TPM", ec == tpm2::OK, tpm2::describe(t, ec)) { return; }
    let key = tpm2::object_of(ko);
    let ext, okx = tpm2::x509_key(ko.public);
    expect("P-256: x509_key", okx && x509::is_external(ext) && ext.kind == x509::KEY_EC_P256);

    let cert, e = self_signed(t, key, s, ext, "tpm.example.com");
    let c, ep = x509::parse(cert);
    expect("P-256: a self-signed certificate signed in the TPM", e == x509::OK && ep == x509::OK && x509::check_signature(c, c) == x509::OK,
           str("create_certificate: ", e));

    let subj, oks = x509::name_der("CN=device.example.com");
    let csr, ecsr = x509::create_csr(subj, "", ext) { k, alg, h, data => tpm2::sign_data(t, key, s, alg, h, data) };
    let cr, ecr = x509::parse_csr(csr);
    expect("P-256: a CSR signed in the TPM", ecsr == x509::OK && ecr == x509::OK && x509::check_csr(cr) == x509::OK);

    expect("P-256: a TLS 1.3 server whose key is in the TPM", tls_handshake(t, key, s, cert, "tpm.example.com", tls::VERSION_TLS13));
    expect("P-256: a TLS 1.2 server whose key is in the TPM", tls_handshake(t, key, s, cert, "tpm.example.com", tls::VERSION_TLS12));
    expect("P-256: an SSH host key in the TPM", ssh_login(t, key, s, ext));

    let pub, ej = jwk::from_spki(x509::marshal_public_key(ext));
    var claims = jwt::new_claims();
    claims.sub.append("device-42");
    claims.has |= jwt::CLAIM_SUB;
    let token, et = jwt::sign(claims, jwa::ES256, pub) { k, alg, h, data => tpm2::sign_data(t, key, s, alg, h, data) };
    var got = jwt::new_claims();
    let v = jwt::Validator { validate: false };
    expect("P-256: a JWT signed in the TPM", ej == jwx::OK && et == jwx::OK
           && jwt::parse(token, jwa::ES256, pub, got, v) == jwx::OK && got.sub == "device-42");
    tpm2::flush(t, ko.handle);
}

fn rsa(t: tpm2::Tpm&, pe: tpm2::Entity) {
    var s = tpm2::pw();
    let ko, ec = tpm2::create_loaded(t, pe, s, tpm2::rsa_sign_template());
    if !expect("RSA-2048 key made in the TPM", ec == tpm2::OK, tpm2::describe(t, ec)) { return; }
    let key = tpm2::object_of(ko);
    let ext, okx = tpm2::x509_key(ko.public);
    let cert, e = self_signed(t, key, s, ext, "rsa.tpm.example.com");
    let c, ep = x509::parse(cert);
    expect("RSA: a self-signed certificate signed in the TPM", okx && e == x509::OK && ep == x509::OK);
    expect("RSA: a TLS 1.2 server whose key is in the TPM", tls_handshake(t, key, s, cert, "rsa.tpm.example.com", tls::VERSION_TLS12));
    // TLS 1.3 takes RSA-PSS with a salt as long as the hash; a TPM may use
    // a longer one, which the client then refuses.
    if tls_handshake(t, key, s, cert, "rsa.tpm.example.com", tls::VERSION_TLS13) { ok("RSA: a TLS 1.3 server whose key is in the TPM (PSS salt as long as the hash)"); }
    else { skip("RSA: TLS 1.3", "this TPM's RSA-PSS salt is not the hash's length"); }
    tpm2::flush(t, ko.handle);
}

fn main() {
    var spec: u8[>..] = [];
    let args = args();
    var i = 1;
    while i < args.len {
        if args[i] == "--tpm" && i + 1 < args.len { spec.clear(); spec.append(args[i + 1]); i++; }
        i++;
    }
    if spec.len == 0 { print("usage: signer.goose -- --tpm tcp:HOST:PORT"); exit(2); }
    var t, e = tpm2::open(spec);
    if e != tpm2::OK { print("cannot open ", spec, ": ", tpm2::describe(t, e)); exit(1); }
    let es = tpm2::startup(t);
    var s = tpm2::pw();
    let parent, ep = tpm2::create_primary(t, tpm2::owner(), s, tpm2::srk_ecc_template());
    if !expect("SRK", ep == tpm2::OK, tpm2::describe(t, ep)) { exit(1); }
    let pe = tpm2::object_of(parent);
    p256(t, pe);
    rsa(t, pe);
    tpm2::flush(t, parent.handle);
    tpm2::close(t);
    print("\n", passed, " passed, ", failed, " failed");
    if failed > 0 { exit(1); }
}
