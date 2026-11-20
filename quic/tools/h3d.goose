// goose-h3d: an HTTP/3 server over QUIC, for trying the package against
// real clients: GET of a path under --root gives the file (an index.html
// for a directory), POST echoes what was sent, and without --root every
// GET is answered with a short text naming the path.
//
//   goose-h3d --cert chain.pem --key key.pem [--listen 127.0.0.1] [--port 4433] [--root DIR]
//
// One line a request goes to stderr. It listens on 127.0.0.1 unless told
// otherwise.

import std;
import os;
import gslib from "../..";
import gslib.net;
import gslib.encoding.asn1;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.quic;
import gslib.quic.conn;
import gslib.quic.transport;
import gslib.quic.qpack;
import gslib.quic.http3;

fn die(msg: const u8[:]) {
    write_stderr("goose-h3d: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(2);
}

fn pem_der(path: const u8[:], labels: const u8[:][:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { die("cannot read a PEM file"); }
    var out: u8[>..] = [];
    for label in labels {
        let ders, ok = asn1::pem_decode(text, label);
        for d in ders { out.append(d); }
        if out.len > 0 { return out; }
    }
    die("no PEM block of the expected kind");
    return out;
}

fn main() {
    let a = args();
    var cert: u8[>..] = [];
    var key: u8[>..] = [];
    var listen: u8[>..] = [];
    listen.append("127.0.0.1");
    var port: i64 = 4433;
    var root: u8[>..] = [];
    var i = 1;
    while i + 1 < a.len {
        if a[i] == "--cert" { cert.append(a[i + 1]); }
        else if a[i] == "--key" { key.append(a[i + 1]); }
        else if a[i] == "--listen" { listen.clear(); listen.append(a[i + 1]); }
        else if a[i] == "--port" { let p, ok = parse_int(a[i + 1]); port = p; }
        else if a[i] == "--root" { root.append(a[i + 1]); }
        else { die("usage: goose-h3d --cert chain.pem --key key.pem [--listen 127.0.0.1] [--port 4433] [--root DIR]"); }
        i += 2;
    }
    if cert.len == 0 || key.len == 0 { die("--cert and --key are needed"); }
    let chain_labels: const u8[:][1] = ["CERTIFICATE"];
    let key_labels: const u8[:][3] = ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"];
    let chain = pem_der(cert, chain_labels);
    let kd = pem_der(key, key_labels);
    var cfg, ok = tls::server_config(chain, kd);
    if !ok { die("the key does not load"); }
    tls::add_alpn(cfg.alpn, "h3");
    var srv, e = quic::listen(listen, port);
    if e != 0 { die("cannot listen"); }
    var hs: quic::H3[16] = [quic::h3(true); 16];
    // Bodies still being written: which connection and stream, how far.
    var q_conn: i64[4] = [-1; 4];
    var q_id: i64[4] = [0; 4];
    var q_off: i64[4] = [0; 4];
    var q_body: u8[..1048576][4] = [[]; 4];
    write_stderr("goose-h3d: listening\n");
    loop {
        quic::serve_step(srv, cfg, 100);
        for j in 4 {
            let k = q_conn[j];
            if k < 0 { continue; }
            if !srv.live[k] { q_conn[j] = -1; continue; }
            let left = q_body[j].len - q_off[j];
            let n = quic::stream_write(srv.conns[k], q_id[j], q_body[j][q_off[j]..], true);
            if n < 0 { q_conn[j] = -1; continue; }
            q_off[j] += n;
            if q_off[j] == q_body[j].len { q_conn[j] = -1; }
        }
        loop {
            let k = quic::accept(srv);
            if k < 0 { break; }
            hs[k] = quic::h3(true);
        }
        for k in srv.conns.len {
            if !srv.live[k] { continue; }
            quic::h3_poll(srv.conns[k], hs[k]);
            loop {
                let id = quic::h3_next_request(hs[k]);
                if id < 0 { break; }
                let method = quic::h3_field(hs[k], id, ":method");
                let path = quic::h3_field(hs[k], id, ":path");
                var rh: u8[>..] = [];
                var body: u8[>..] = [];
                var status: i64 = 200;
                if method == "POST" {
                    body = quic::h3_body(hs[k], id);
                    quic::qpack_record(rh, "content-type", "application/octet-stream");
                } else if root.len > 0 {
                    var f: u8[>..] = [];
                    f.append(root);
                    f.append(path);
                    if f[f.len - 1] == '/' { f.append("index.html"); }
                    if find(path, "..") >= 0 || !read_file(f, body) { status = 404; body.clear(); body.append("not found\n"); }
                } else {
                    body.append("hello from goose-h3d: ");
                    body.append(path);
                    body.push('\n');
                    quic::qpack_record(rh, "content-type", "text/plain");
                }
                var cl: u8[>..] = [];
                format(cl, body.len);
                quic::qpack_record(rh, "content-length", cl);
                var slot: i64 = -1;
                for j in 4 { if slot < 0 && q_conn[j] < 0 { slot = j; } }
                if body.len > 32768 && slot >= 0 && body.len <= 1048576 {
                    // Long: the head now, the body as the stream takes it.
                    let sent = quic::h3_respond_head(srv.conns[k], hs[k], id, status, rh, body.len);
                    q_conn[slot] = k;
                    q_id[slot] = id;
                    q_off[slot] = 0;
                    q_body[slot].clear();
                    q_body[slot].append(body);
                } else {
                    let sent = quic::h3_respond(srv.conns[k], hs[k], id, status, rh, body);
                }
                var l: u8[>..] = [];
                l.append("goose-h3d: ");
                l.append(method);
                l.push(' ');
                l.append(path);
                l.push(' ');
                format(l, status);
                l.push('\n');
                write_stderr(l);
            }
        }
    }
}
