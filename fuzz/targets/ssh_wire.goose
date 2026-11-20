// Fuzz target: ssh_wire. The first byte picks:
//   0  a public key blob and a signature blob (2-byte length of the
//      first): parse_public_key, fingerprints, the authorized_keys form
//      read back, and verify under each algorithm the key type takes;
//   1  text: each line as an authorized_keys line, and the whole as a
//      known_hosts file checked for a fixed key and host (two ports);
//   2  the server's byte stream from the start: version line, then binary
//      packets (in clear until NEWKEYS) through server_feed;
//   3  the same for the client (client_feed);
//   4  server messages, without the packet layer: the second byte picks the
//      starting state (key exchange, service, authentication, connected),
//      then [2-byte length][payload]... go to handle_message, with an
//      application answering the events (accept channels and requests);
//   5  the same for the client (with a key and a password to log in);
//   6  one packet opened under each cipher and MAC with fixed keys.
// The library draws randomness on its own (KEXINIT cookies, ephemeral
// keys, check words); nothing here depends on it.

import std;
import gslib from "../..";
import gslib.crypto.ssh;
import gslib.crypto.ssh.keys;
import gslib.crypto.ssh.cipher;
import gslib.crypto.ssh.kex;
import gslib.crypto.ssh.conn;
import gslib.crypto.x509;

let ED_KEY = embed_file("../../crypto/ssh/test/vectors/key_ed25519");
let ED_PUB = embed_file("../../crypto/ssh/test/vectors/key_ed25519.pub");
let EC_PUB = embed_file("../../crypto/ssh/test/vectors/key_ecdsa256.pub");
let RSA_PUB = embed_file("../../crypto/ssh/test/vectors/key_rsa2048.pub");

fn ed_key() -> ssh::PrivateKey {
    let k, e = ssh::parse_private_key(ED_KEY);
    assert(e == ssh::KEY_OK);
    return k;
}

fn be16(b: const u8[:], at: i64) -> i64 { (b[at] as i64) << 8 | b[at + 1] }

fn blob_and_sig(b: const u8[:]) {
    if b.len < 2 { return; }
    let n = be16(b, 0);
    if 2 + n > b.len { return; }
    let blob = b[2..2 + n];
    let sig = b[2 + n..];
    let k, ok = ssh::parse_public_key(blob);
    if !ok {
        // The signature against the fixed keys instead.
        for line in [ED_PUB, EC_PUB, RSA_PUB] {
            let pk, opts, comment, okp = ssh::parse_authorized_key(line);
            if !okp { continue; }
            for alg in ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"] {
                let v = ssh::verify(pk, alg, "data", sig);
            }
        }
        return;
    }
    let f1 = ssh::fingerprint_sha256(k);
    let f2 = ssh::fingerprint_md5(k);
    let line = ssh::marshal_authorized_key(k, "comment");
    let k2, opts, comment, ok2 = ssh::parse_authorized_key(line);
    for alg in ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-256",
                "rsa-sha2-512", "ssh-rsa"] {
        if ssh::sig_fits(k.kind, alg) { let v = ssh::verify(k, alg, "data", sig); }
    }
}

fn lines(b: const u8[:]) {
    var i = 0;
    while i < b.len {
        var j = i;
        while j < b.len && b[j] != '\n' { j++; }
        let k, opts, comment, ok = ssh::parse_authorized_key(b[i..j]);
        if ok { let f = ssh::fingerprint_sha256(k); }
        i = j + 1;
    }
    if b.len > 65536 { return; }
    let pk, opts, comment, okp = ssh::parse_authorized_key(ED_PUB);
    for port in [22, 2222] {
        var cfg = ssh::client_config("alice", "Host.Example.com", port);
        cfg.known_hosts.append(b);
        let s = ssh::known_host_status(cfg, pk);
        let kk = ssh::known_kind(cfg, pk.kind);
        let e = ssh::check_host_key(cfg, pk);
        let l = ssh::known_hosts_line(cfg, pk, false);
    }
}

fn server_cfg() -> ssh::ServerConfig {
    var cfg = ssh::server_config();
    let k = ed_key();
    let ok = ssh::add_host_key(cfg, k);
    cfg.authorized_keys.append(ED_PUB);
    cfg.authorized_keys.append(EC_PUB);
    cfg.passwords.append("alice:secret\nbob:hunter2\n");
    cfg.banner.append("hello\n");
    cfg.max_auth_tries = 4;
    return cfg;
}

fn client_cfg() -> ssh::ClientConfig {
    var cfg = ssh::client_config("alice", "host.example.com");
    let k = ed_key();
    let ok = ssh::add_key(cfg, k);
    ssh::set_password(cfg, "secret");
    cfg.host_key_check = ssh::HOST_KEY_ASK;
    return cfg;
}

// The application's side: what a server or client program does with events.
fn server_app(c: ssh::Conn&, events: const u8[:], out: u8[>..]&) {
    var pos = 0;
    var n = 0;
    loop {
        let e, ok = ssh::next_event(events, pos);
        if !ok || n > 256 { break; }
        n++;
        if e.kind == ssh::EV_CHANNEL_OPEN {
            if e.channel % 2 == 0 { let x = ssh::channel_accept(c, e.channel, out); }
            else { let x = ssh::channel_reject(c, e.channel, 1, "no", out); }
        } else if e.kind == ssh::EV_REQUEST && e.value != 0 {
            let x = ssh::channel_reply(c, e.channel, true, out);
        } else if e.kind == ssh::EV_GLOBAL_REQUEST && e.value != 0 {
            let x = ssh::global_reply(c, false, "", out);
        } else if e.kind == ssh::EV_DATA || e.kind == ssh::EV_EXTENDED_DATA {
            let d = ssh::bytes(events, e.data);
            let w = ssh::channel_send(c, e.channel, d, out);
        } else if e.kind == ssh::EV_EOF {
            let x = ssh::exit_status(c, e.channel, 0, out);
            ssh::channel_close(c, e.channel, out);
        }
    }
}

fn client_app(c: ssh::Conn&, cfg: const ssh::ClientConfig&, events: const u8[:], out: u8[>..]&) {
    var pos = 0;
    var n = 0;
    loop {
        let e, ok = ssh::next_event(events, pos);
        if !ok || n > 256 { break; }
        n++;
        if e.kind == ssh::EV_PASSWORD_NEEDED {
            let x = ssh::client_password(c, cfg, "secret", out);
        } else if e.kind == ssh::EV_HOST_KEY_UNKNOWN {
            let x = ssh::host_key_accept(c, cfg, out, out);
        } else if e.kind == ssh::EV_CHANNEL_OPENED {
            let x = ssh::exec(c, e.channel, "ls", out);
        } else if e.kind == ssh::EV_REQUEST && e.value != 0 {
            let x = ssh::channel_reply(c, e.channel, false, out);
        } else if e.kind == ssh::EV_CHANNEL_OPEN {
            let x = ssh::channel_reject(c, e.channel, 1, "no", out);
        } else if e.kind == ssh::EV_DATA {
            ssh::channel_consumed(c, e.channel, ssh::bytes(events, e.data).len, out);
        }
    }
}

fn feed_server(b: const u8[:]) {
    let cfg = SCFG;
    var c = ssh::server(cfg);
    var out: u8[>..] = [];
    ssh::server_start(c, cfg, out);
    var events: u8[>..] = [];
    let r = ssh::server_feed(c, cfg, b, out, events);
    server_app(c, events, out);
}

fn feed_client(b: const u8[:]) {
    let cfg = CCFG;
    var c = ssh::client(cfg);
    var out: u8[>..] = [];
    ssh::client_start(c, cfg, out);
    var events: u8[>..] = [];
    let r = ssh::client_feed(c, cfg, b, out, events);
    client_app(c, cfg, events, out);
}

// A connection put in a state as if the key exchange (and authentication)
// had happened.
fn set_state(c: ssh::Conn&, st: i64) {
    c.peer_version.append("SSH-2.0-Fuzz");
    if st == 0 { c.state = ssh::ST_KEX; return; }
    c.state = if st == 1 { ssh::ST_SERVICE } else if st == 2 { ssh::ST_AUTH } else { ssh::ST_CONNECTED };
    c.kex_count = 1;
    c.session_id.append("0123456789abcdef0123456789abcdef");
    c.host_key_alg.append("ssh-ed25519");
    if st >= 3 { c.user.clear(); c.user.append("alice"); }
}

fn messages(b: const u8[:], server: bool) {
    if b.len < 1 { return; }
    let st: i64 = b[0] % 4;
    var at = 1;
    var out:    u8[>..] = [];
    var events: u8[>..] = [];
    if server {
        let cfg = SCFG;
        var c = ssh::server(cfg);
        if st == 0 { ssh::server_start(c, cfg, out); }
        set_state(c, st);
        while at + 2 <= b.len && !ssh::closed(c) {
            let n = be16(b, at);
            at += 2;
            if at + n > b.len { break; }
            out.clear();
            events.clear();
            let r = ssh::handle_message(c, cfg, b[at..at + n], out, events, x509::sign_data);
            server_app(c, events, out);
            at += n;
        }
    } else {
        let cfg = CCFG;
        var c = ssh::client(cfg);
        if st == 0 { ssh::client_start(c, cfg, out); }
        set_state(c, st);
        if st == 3 {
            // A session we asked for, and a forwarding.
            let ch = ssh::open_session(c, out);
            let f = ssh::tcpip_forward(c, "localhost", 0, out);
        }
        while at + 2 <= b.len && !ssh::closed(c) {
            let n = be16(b, at);
            at += 2;
            if at + n > b.len { break; }
            out.clear();
            events.clear();
            let r = ssh::handle_message(c, cfg, b[at..at + n], out, events, x509::sign_data);
            client_app(c, cfg, events, out);
            at += n;
        }
    }
}

fn packets(b: const u8[:]) {
    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let iv = "0123456789abcdef";
    let suites: const u8[:][2][7] = [
        ["chacha20-poly1305@openssh.com", ""], ["aes128-gcm@openssh.com", ""], ["aes256-gcm@openssh.com", ""],
        ["aes128-ctr", "hmac-sha2-256"], ["aes256-ctr", "hmac-sha2-512-etm@openssh.com"], ["aes192-ctr", "hmac-sha1"],
        ["aes128-ctr", "hmac-sha2-256-etm@openssh.com"],
    ];
    for s in suites {
        let kl, ivl, ok = ssh::cipher_sizes(s[0]);
        var mkl = 0;
        if s[1].len > 0 { let h, l, etm, okm = ssh::mac_sizes(s[1]); mkl = l; }
        var c = ssh::packet_cipher(s[0], s[1], key[..kl], iv[..ivl], key[..mkl]);
        let n = ssh::packet_length(c, b);
        if n > 0 && n <= b.len { let p, okp = ssh::open_packet(c, b[..n]); }
    }
    var none = ssh::no_cipher();
    let n = ssh::packet_length(none, b);
    if n > 0 && n <= b.len { let p, okp = ssh::open_packet(none, b[..n]); }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let rest = data[1..];
    let sel = data[0] % 7;
    if sel == 0 { blob_and_sig(rest); }
    else if sel == 1 { lines(rest); }
    else if sel == 2 { feed_server(rest); }
    else if sel == 3 { feed_client(rest); }
    else if sel == 4 { messages(rest, true); }
    else if sel == 5 { messages(rest, false); }
    else { packets(rest); }
    return 0;
}

// The configurations (and the key parse behind them) once, not per input.
var SCFG = ssh::server_config();
var CCFG = ssh::client_config("alice", "host.example.com");

fn main() {
    SCFG = server_cfg();
    CCFG = client_cfg();
}
