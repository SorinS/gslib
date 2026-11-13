// login: a first login as `ssh` does it, in memory. The client does not
// know the server yet (HOST_KEY_ASK): the connection waits on
// EV_HOST_KEY_UNKNOWN while the application shows the fingerprint and
// accepts it, then keeps a hashed known_hosts line. The server takes
// passwords (a bcrypt hash in its "user:password" lines) and shows a
// banner; the client has no password set, so it gets EV_PASSWORD_NEEDED
// and answers with client_password. The second login checks the host key
// against the saved line; a wrong password is refused.
//
//   goose examples/ssh/login.goose

import std;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.ssh;
import gslib.crypto.ssh.keys;
import gslib.crypto.ssh.conn;
import gslib.crypto.x509;

// One login, typing `password` when asked. Whether it got in, the
// known_hosts line for a host key the user accepted (empty if none was
// asked about), and the banner.
fn login(cc: const ssh::ClientConfig&, sc: const ssh::ServerConfig&, password: const u8[:]) -> bool, u8[>..], u8[>..] {
    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var accepted:  u8[>..] = [];
    var banner:    u8[>..] = [];
    ssh::client_start(c, cc, to_server);
    ssh::server_start(s, sc, to_client);
    for round in 100 {
        if to_server.len == 0 && to_client.len == 0 { break; }
        var sev: u8[>..] = [];                               // the server's events: nothing to do here
        let rs = ssh::server_feed(s, sc, to_server, to_client, sev);
        to_server.clear();
        var cev: u8[>..] = [];
        let rc = ssh::client_feed(c, cc, to_client, to_server, cev);
        to_client.clear();
        var pos = 0;
        loop {
            let e, ok = ssh::next_event(cev, pos);
            if !ok { break; }
            if e.kind == ssh::EV_HOST_KEY_UNKNOWN {
                print("The authenticity of host 'example.com' can't be established.");
                print("ED25519 key fingerprint is ", ssh::fingerprint_sha256(c.host_key), ". Accepting.");
                var more: u8[>..] = [];                       // only EV_HOST_KEY can come here
                let r = ssh::host_key_accept(c, cc, to_server, more);
                accepted = ssh::known_hosts_line(cc, c.host_key, true);   // hashed, as HashKnownHosts
            }
            if e.kind == ssh::EV_BANNER { banner.append(ssh::bytes(cev, e.data)); }
            if e.kind == ssh::EV_PASSWORD_NEEDED {
                print("alice@example.com's password: (typed)");
                let sent = ssh::client_password(c, cc, password, to_server);
            }
        }
    }
    if !ssh::connected(c) { print("refused: ", c.message); }
    return ssh::connected(c) && ssh::connected(s), accepted, banner;
}

fn run() {
    let host_key = ssh::generate_key(x509::KEY_ED25519);
    var sc = ssh::server_config();
    let a = ssh::add_host_key(sc, host_key);
    let hash, okh = bignum::bcrypt_hash("s3cret", 4);                // a low cost, for the example
    guard okh else { print("login: bcrypt failed"); exit(1); }
    sc.passwords.append(str("alice:", hash, "\n"));
    sc.banner.append("Authorized users only.\n");

    // First contact: the host key is asked about, the password too.
    var cc = ssh::client_config("alice", "example.com");
    cc.host_key_check = ssh::HOST_KEY_ASK;
    let ok1, line, banner = login(cc, sc, "s3cret");
    guard ok1 && line.len > 0 && banner == "Authorized users only.\n" else { print("login: the first login failed"); exit(1); }
    print("logged in; saved to known_hosts: ", line[..line.len - 1]);

    // Next time the saved line is checked, nothing is asked about the host.
    var cc2 = ssh::client_config("alice", "example.com");
    cc2.known_hosts.append(line);
    let ok2, line2, banner2 = login(cc2, sc, "s3cret");
    guard ok2 && line2.len == 0 else { print("login: the second login failed"); exit(1); }
    print("logged in again, host key known");

    // A wrong password, given up front.
    var cc3 = ssh::client_config("alice", "example.com");
    cc3.known_hosts.append(line);
    ssh::set_password(cc3, "guess");
    let ok3, line3, banner3 = login(cc3, sc, "guess");
    guard !ok3 else { print("login: a wrong password got in"); exit(1); }
    print("a wrong password: refused");
}

fn main() {
    run();
}
