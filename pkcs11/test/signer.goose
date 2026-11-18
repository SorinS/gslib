// Keys that never leave a PKCS#11 token (SoftHSM2), used by the rest of
// gslib through signers: P-256, RSA-2048 and Ed25519 key pairs made on the
// token, standing in configurations as their public keys (p11::x509_key),
// each signature made by p11::sign_data: a self-signed certificate (x509),
// a TLS 1.3 server and, for RSA, a TLS 1.2 one (PKCS #1) in memory, an SSH
// host key, and a JWT; each checked by the side that does not hold the key.
import std;
import gslib from "../..";
import gslib.pkcs11;
import gslib.pkcs11.p11;
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
import gslib.jwx.jwt;
import gslib.jwx.pem;
import tv;
import hsm;

let NOW: i64 = 1800000000;
let YEAR: i64 = 31536000;

// A key pair made on the token: EC (params) or RSA (params empty), or
// Ed25519.
fn pair(c: pkcs11::Ctx, sh: u64, kind: const u8[:], label: const u8[:]) -> p11::KeyPair, u64 {
    var pubt: u8[>..] = [];
    var privt: u8[>..] = [];
    pkcs11::attr(pubt, pkcs11::CKA_VERIFY, true);
    pkcs11::attr(pubt, pkcs11::CKA_LABEL, label);
    pkcs11::attr(privt, pkcs11::CKA_SIGN, true);
    pkcs11::attr(privt, pkcs11::CKA_PRIVATE, true);
    pkcs11::attr(privt, pkcs11::CKA_SENSITIVE, true);
    pkcs11::attr(privt, pkcs11::CKA_LABEL, label);
    var gen = pkcs11::CKM_EC_KEY_PAIR_GEN;
    if kind == "rsa" {
        gen = pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN;
        pkcs11::attr(pubt, pkcs11::CKA_MODULUS_BITS, 2048);
        pkcs11::attr(pubt, pkcs11::CKA_PUBLIC_EXPONENT, "\x01\x00\x01");
    } else if kind == "ed25519" {
        gen = pkcs11::CKM_EC_EDWARDS_KEY_PAIR_GEN;
        pkcs11::attr(pubt, pkcs11::CKA_EC_PARAMS, pkcs11::EC_PARAMS_ED25519[..]);
    } else {
        pkcs11::attr(pubt, pkcs11::CKA_EC_PARAMS, pkcs11::EC_PARAMS_P256[..]);
    }
    let pub, priv, rv = pkcs11::generate_key_pair(c, sh, pkcs11::mechanism(gen), pubt, privt);
    let o = p11::Object { ctx: c, session: sh, handle: 0 };
    return p11::KeyPair { public: p11::PublicKey { object: p11::Object { ctx: c, session: sh, handle: pub } },
                          private: p11::PrivateKey { object: p11::Object { ctx: c, session: sh, handle: priv } } }, rv;
}

// A TLS handshake in memory, the server's key on the token, up to max.
fn tls_handshake(key: p11::PrivateKey, cert: const u8[:], max: u16) -> bool {
    var sc, oks = tls::server_config(cert);
    sc.now = NOW;
    sc.max_version = max;
    var cc = tls::client_config("hsm.example.com", cert);
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
        let rs = tls::server_feed(sv, sc, to_server, to_client, sapp) { k, alg, h, data => p11::sign_data(key, alg, h, data) };
        to_server.clear();
        if to_client.len == 0 { break; }
        let rc = tls::client_feed(c, cc, to_client, to_server, capp);
    }
    return oks && tls::connected(c) && tls::connected(sv);
}

// An SSH login in memory, the server's host key on the token.
fn ssh_login(key: p11::PrivateKey, ext: const x509::PrivateKey&) -> bool {
    let host, okh = ssh::private_key(ext);
    var sc = ssh::server_config();
    if !okh || !ssh::add_host_key(sc, host) { return false; }
    let user = ssh::generate_key(x509::KEY_ED25519);
    sc.authorized_keys.append(ssh::marshal_authorized_key(user.public));
    var cc = ssh::client_config("alice", "hsm.example.com");
    cc.known_hosts.append(str("hsm.example.com ", ssh::marshal_authorized_key(host.public)));
    let a = ssh::add_key(cc, user);
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
        let rs = ssh::server_feed(sv, sc, to_server, s_out, sev) { k, alg, h, data => p11::sign_data(key, alg, h, data) };
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

fn one(c: pkcs11::Ctx, sh: u64, kind: const u8[:]) {
    let kp, rv = pair(c, sh, kind, str("signer ", kind));
    hsm::ok(str(kind, ": key pair on the token"), rv);
    if rv != pkcs11::CKR_OK { return; }
    let key = kp.private;
    let ext, okx = p11::x509_key(kp.public);
    tv::check(str(kind, ": x509_key"), okx && x509::is_external(ext));

    var tm, okt = x509::template("CN=hsm.example.com", NOW - YEAR, NOW + YEAR);
    tm.is_ca = true;
    tm.key_usage = x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_CERT_SIGN;
    x509::add_dns(tm.san, "hsm.example.com");
    let cert, e = x509::create_certificate(tm, x509::marshal_public_key(ext), "", ext) { k, alg, h, data => p11::sign_data(key, alg, h, data) };
    let ct, ep = x509::parse(cert);
    tv::check(str(kind, ": a self-signed certificate signed on the token"), e == x509::OK && ep == x509::OK && x509::check_signature(ct, ct) == x509::OK);

    let t13 = tls_handshake(key, cert, tls::VERSION_TLS13);
    tv::check(str(kind, ": a TLS 1.3 server whose key is on the token"), t13);
    if kind == "rsa" || kind == "p256" {
        let t12 = tls_handshake(key, cert, tls::VERSION_TLS12);
        tv::check(str(kind, ": a TLS 1.2 server whose key is on the token"), t12);
    }
    let sl = ssh_login(key, ext);
    tv::check(str(kind, ": an SSH host key on the token"), sl);

    let pub, ej = jwk::from_spki(x509::marshal_public_key(ext));
    let alg = if kind == "rsa" { jwa::RS256 } else if kind == "ed25519" { jwa::EDDSA } else { jwa::ES256 };
    var claims = jwt::new_claims();
    claims.sub.append("hsm");
    claims.has |= jwt::CLAIM_SUB;
    let token, et = jwt::sign(claims, alg, pub) { k, a, h, data => p11::sign_data(key, a, h, data) };
    var got = jwt::new_claims();
    let v = jwt::Validator { validate: false };
    tv::check(str(kind, ": a JWT signed on the token"), ej == jwx::OK && et == jwx::OK
              && jwt::parse(token, alg, pub, got, v) == jwx::OK && got.sub == "hsm");
}

fn main() {
    let c = hsm::open();
    let sh = hsm::session(c);
    one(c, sh, "p256");
    one(c, sh, "rsa");
    one(c, sh, "ed25519");
    tv::done("signer");
}
