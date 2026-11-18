// tls_server: an HTTPS server whose private key never leaves the TPM. A
// P-256 signing key is made in the TPM under its storage root key; its
// public key stands for it in the TLS configuration (tpm2::x509_key), a
// self-signed certificate for it is signed in the TPM, and so is every
// handshake: the signer passed to tls::server_feed is tpm2::sign_data.
// It answers each connection with one line, until stopped.
//
//   goose examples/tpm2/tls_server.goose -- TPM [PORT]
//   curl -k https://127.0.0.1:8443/
//
// TPM is as tpm2::open takes it: /dev/tpmrm0, tbs: on Windows, or
// tcp:127.0.0.1:2321 for swtpm. PORT defaults to 8443.

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
import gslib.net;

fn die(what: const u8[:]) { print("tls_server: ", what); exit(1); }

fn main() {
    let a = args();
    if a.len < 2 { die("usage: tls_server.goose -- TPM [PORT]"); }
    var port: i64 = 8443;
    if a.len > 2 { let p, okp = parse_int(a[2], 10); if okp { port = p; } }
    var t, e = tpm2::open(a[1]);
    if e != tpm2::OK { die(str("cannot open the TPM: ", tpm2::describe(t, e))); }
    let es = tpm2::startup(t);
    var s = tpm2::pw();

    // The key, made in the TPM: only its public part comes out.
    let srk, er = tpm2::create_primary(t, tpm2::owner(), s, tpm2::srk_ecc_template());
    if er != tpm2::OK { die(str("CreatePrimary: ", tpm2::describe(t, er))); }
    let ko, ek = tpm2::create_loaded(t, tpm2::object_of(srk), s, tpm2::ecc_sign_template(tpm2::ECC_NIST_P256));
    if ek != tpm2::OK { die(str("CreateLoaded: ", tpm2::describe(t, ek))); }
    let key = tpm2::object_of(ko);
    let pub, okx = tpm2::x509_key(ko.public);

    // A self-signed certificate, signed in the TPM.
    let now = time_ns() / 1000000000;
    var tm, okt = x509::template("CN=localhost", now - 60, now + 30 * 86400);
    x509::add_dns(tm.san, "localhost");
    x509::add_ip(tm.san, "127.0.0.1");
    tm.key_usage = x509::KU_DIGITAL_SIGNATURE;
    let cert, ec = x509::create_certificate(tm, x509::marshal_public_key(pub), "", pub) { k, alg, h, data =>
        tpm2::sign_data(t, key, s, alg, h, data)
    };
    if !okx || !okt || ec != x509::OK { die("cannot make the certificate"); }
    var sc, oks = tls::server_config(cert);
    if !oks { die("server_config"); }

    let lfd = net::listen("127.0.0.1", port);
    if lfd < 0 { die("cannot listen"); }
    print("listening on https://127.0.0.1:", port, "/ with a key in the TPM");
    loop {
        let fd = net::accept(lfd, 0);
        if fd < 0 { continue; }
        var conn = tls::server(sc);
        var buf: u8[16384] = [0; 16384];
        var app: u8[>..] = [];
        var answered = false;
        loop {
            let n = net::read(fd, buf, 10000);
            if n <= 0 { break; }
            var out: u8[>..] = [];
            let r = tls::server_feed(conn, sc, buf[..n], out, app) { k, alg, h, data => tpm2::sign_data(t, key, s, alg, h, data) };
            if out.len > 0 && net::write(fd, out, 10000) < 0 { break; }
            if r < 0 { break; }
            if tls::connected(conn) && !answered && find(app, "\r\n\r\n") >= 0 {
                let body = "hello from a key in the TPM\n";
                var resp: u8[>..] = [];
                let ok = tls::send(conn, str("HTTP/1.1 200 OK\r\nContent-Length: ", body.len, "\r\nConnection: close\r\n\r\n", body), resp);
                tls::close(conn, resp);
                let w = net::write(fd, resp, 10000);
                answered = true;
                break;
            }
        }
        net::close(fd);
    }
}
