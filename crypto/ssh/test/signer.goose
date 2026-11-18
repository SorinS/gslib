// Keys held elsewhere in ssh.conn, in memory: a server whose host key and a
// client whose user key are only public keys (ssh::private_key of an
// x509::external_key), signing through signers passed to feed, as a TPM's
// or a PKCS#11 token's would. Each key type as a host key and as a user
// key, the signers counted; one signer telling two keys apart; and what
// fails: ssh-rsa's SHA-1, a signer that answers nothing, and no signer.
import std;
import gslib from "../../..";
import gslib.crypto.ssh;
import gslib.crypto.bignum;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.ssh.keys;
import gslib.crypto.ssh.conn;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn key(text: const u8[:]) -> ssh::PrivateKey {
    let k, e = ssh::parse_private_key(text);
    assert(e == ssh::KEY_OK);
    return k;
}

// The same key held elsewhere: its public key alone.
fn held_elsewhere(k: const ssh::PrivateKey&) -> ssh::PrivateKey {
    let x, okx = x509::external_key(x509::marshal_public_key(k.key));
    let p, okp = ssh::private_key(x);
    assert(okx && okp && x509::is_external(p.key));
    return p;
}

// What happened: both sides logged in, and how often each signer was asked.
struct Outcome { ok: bool, host_calls: i64, user_calls: i64, msg: u8[..256] }

// A handshake and login between a server whose host key is `host` held
// elsewhere and a client whose user key is `user` held elsewhere, the
// client asking for host key algorithm `host_alg` ("" for any). mode 0:
// signers that sign; 1: the server's answers nothing; 2: no signers.
fn run(host: const ssh::PrivateKey&, user: const ssh::PrivateKey&, host_alg: const u8[:], mode: i64) -> Outcome {
    var sc = ssh::server_config();
    let hk = held_elsewhere(host);
    check("add_host_key: a key held elsewhere", ssh::add_host_key(sc, hk));
    sc.authorized_keys.append(ssh::marshal_authorized_key(user.public));
    var cc = ssh::client_config("alice", "example.com");
    cc.known_hosts.append(str("example.com ", ssh::marshal_authorized_key(host.public)));
    if host_alg.len > 0 { cc.host_key_algs.clear(); cc.host_key_algs.append(host_alg); }
    let uk = held_elsewhere(user);
    check("add_key: a key held elsewhere", ssh::add_key(cc, uk));

    var host_calls = 0;
    var user_calls = 0;
    fn host_signer(k: const x509::PrivateKey&, alg: i64, h: i64, data: const u8[:]) -> u8[>..] {
        host_calls++;
        if mode == 1 || !x509::is_external(k) { return []; }
        return x509::sign_data(host.key, alg, h, data);
    }
    fn user_signer(k: const x509::PrivateKey&, alg: i64, h: i64, data: const u8[:]) -> u8[>..] {
        user_calls++;
        return x509::sign_data(user.key, alg, h, data);
    }

    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    ssh::client_start(c, cc, to_server);
    ssh::server_start(s, sc, to_client);
    for round in 60 {
        if to_server.len == 0 && to_client.len == 0 { break; }
        var sev: u8[>..] = [];
        var s_out: u8[>..] = [];
        let rs = if mode == 2 { ssh::server_feed(s, sc, to_server, s_out, sev) }
                 else { ssh::server_feed(s, sc, to_server, s_out, sev, host_signer) };
        to_server.clear();
        to_client.append(s_out);
        var cev: u8[>..] = [];
        var c_out: u8[>..] = [];
        let rc = if mode == 2 { ssh::client_feed(c, cc, to_client, c_out, cev) }
                 else { ssh::client_feed(c, cc, to_client, c_out, cev, user_signer) };
        to_client.clear();
        to_server.append(c_out);
    }
    var o = Outcome { ok: ssh::connected(c) && ssh::connected(s),
                      host_calls: host_calls, user_calls: user_calls, msg: [] };
    o.msg.append(if c.message.len > 0 { c.message[..] } else { s.message[..] });
    return o;
}

fn main() {
    let ed = key(embed_file("vectors/key_ed25519"));
    let p256 = key(embed_file("vectors/key_ecdsa256"));
    let p384 = key(embed_file("vectors/key_ecdsa384"));
    let p521 = key(embed_file("vectors/key_ecdsa521"));
    let rsa = key(embed_file("vectors/key_rsa2048"));

    // Each kind as the host key and as the user key, through the signers.
    let o1 = run(ed, p256, "", 0);
    check("ed25519 host, p256 user: logged in, each signer asked once", o1.ok && o1.host_calls == 1 && o1.user_calls == 1);
    if !o1.ok { print("   ", o1.msg); }
    let o2 = run(p384, ed, "", 0);
    check("p384 host, ed25519 user", o2.ok && o2.host_calls == 1 && o2.user_calls == 1);
    let o3 = run(p521, rsa, "", 0);
    check("p521 host, rsa user (rsa-sha2)", o3.ok && o3.host_calls == 1 && o3.user_calls >= 1);
    let o4 = run(rsa, p521, "rsa-sha2-256", 0);
    check("rsa host by rsa-sha2-256", o4.ok && o4.host_calls == 1);
    let o5 = run(rsa, p256, "rsa-sha2-512", 0);
    check("rsa host by rsa-sha2-512", o5.ok && o5.host_calls == 1);

    // ssh-rsa signs with SHA-1, which no signer is asked for.
    let o6 = run(rsa, p256, "ssh-rsa", 0);
    check("ssh-rsa: not signed through a signer", !o6.ok && o6.host_calls == 0);
    // A signer that answers nothing, and no signer at all: no login.
    let o7 = run(p256, ed, "", 1);
    check("a host key signer that fails: no connection", !o7.ok && o7.host_calls == 1);
    let o8 = run(p256, ed, "", 2);
    check("no signer: no connection", !o8.ok);

    // A key held elsewhere keeps its public key.
    let he = held_elsewhere(p256);
    check("the public key held elsewhere is the key's", ssh::marshal_authorized_key(he.public) == ssh::marshal_authorized_key(p256.public));
    let hr = held_elsewhere(rsa);
    check("an RSA public key held elsewhere", ssh::marshal_authorized_key(hr.public) == ssh::marshal_authorized_key(rsa.public));

    print("signer: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
