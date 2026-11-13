// exec: an SSH client and server in one process, as `ssh host command`
// does it. The package does no I/O: each side is fed the bytes the other
// sent and hands back bytes to send and a stream of events. The client
// logs in with an Ed25519 key that is in the server's authorized_keys,
// checks the server's host key against a known_hosts line, opens a
// session and runs a command; the server's application answers with
// output, a line on stderr and an exit status.
//
//   goose examples/ssh/exec.goose

import std;
import gslib from "../..";
import gslib.crypto.ssh;
import gslib.crypto.ssh.keys;
import gslib.crypto.ssh.conn;
import gslib.crypto.x509;

// What the client saw.
struct Seen { opened: bool, out: u8[..4096], err: u8[..4096], exit: i64, closed: bool }

// The server's application: a session channel is accepted; "exec" runs a
// pretend command: its output, a line on stderr, exit status 0, then EOF
// and close. Other requests are refused.
fn server_app(s: ssh::Conn&, events: const u8[:], out: u8[>..]&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(events, pos);
        if !ok { break; }
        if e.kind == ssh::EV_AUTHENTICATED { print("server: ", ssh::bytes(events, e.data), " logged in"); }
        if e.kind == ssh::EV_CHANNEL_OPEN {
            var r = e.data;
            let kind = ssh::get_string(r, events);
            if ssh::bytes(events, kind) == "session" { let a = ssh::channel_accept(s, e.channel, out); }
            else { let a = ssh::channel_reject(s, e.channel, ssh::OPEN_UNKNOWN_CHANNEL_TYPE, "sessions only", out); }
        }
        if e.kind == ssh::EV_REQUEST {
            var r = e.data;
            let kind = ssh::get_string(r, events);
            if ssh::bytes(events, kind) == "exec" {
                let cmd = ssh::get_string(r, events);
                let a = ssh::channel_reply(s, e.channel, true, out);
                let n1 = ssh::channel_send(s, e.channel, str("Linux example.com, you ran: ", ssh::bytes(events, cmd), "\n"), out);
                let n2 = ssh::channel_send_stderr(s, e.channel, "a warning on stderr\n", out);
                let x = ssh::exit_status(s, e.channel, 0, out);
                ssh::channel_eof(s, e.channel, out);
                ssh::channel_close(s, e.channel, out);
            } else if e.value == 1 {
                let a = ssh::channel_reply(s, e.channel, false, out);
            }
        }
    }
}

fn client_events(events: const u8[:], w: Seen&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(events, pos);
        if !ok { break; }
        if e.kind == ssh::EV_CHANNEL_OPENED { w.opened = true; }
        if e.kind == ssh::EV_DATA { w.out.append(ssh::bytes(events, e.data)); }
        if e.kind == ssh::EV_EXTENDED_DATA { w.err.append(ssh::bytes(events, e.data)); }
        if e.kind == ssh::EV_EXIT_STATUS { w.exit = e.value; }
        if e.kind == ssh::EV_CLOSE { w.closed = true; }
    }
}

// Moves bytes both ways until neither side has more to say.
fn pump(c: ssh::Conn&, cc: const ssh::ClientConfig&, s: ssh::Conn&, sc: const ssh::ServerConfig&,
        to_server: u8[>..]&, to_client: u8[>..]&, w: Seen&) {
    for round in 100 {
        if to_server.len == 0 && to_client.len == 0 { break; }
        var sev:   u8[>..] = [];
        var s_out: u8[>..] = [];
        let rs = ssh::server_feed(s, sc, to_server, s_out, sev);
        to_server.clear();
        server_app(s, sev, s_out);
        to_client.append(s_out);
        var cev:   u8[>..] = [];
        var c_out: u8[>..] = [];
        let rc = ssh::client_feed(c, cc, to_client, c_out, cev);
        to_client.clear();
        client_events(cev, w);
        to_server.append(c_out);
    }
}

fn run() {
    let host_key = ssh::generate_key(x509::KEY_ED25519);
    let user_key = ssh::generate_key(x509::KEY_ED25519);

    var sc = ssh::server_config();
    let a1 = ssh::add_host_key(sc, host_key);
    sc.authorized_keys.append(ssh::marshal_authorized_key(user_key.public, "alice@example.com"));

    var cc = ssh::client_config("alice", "example.com");          // port 22
    let a2 = ssh::add_key(cc, user_key);
    cc.known_hosts.append(str("example.com ", ssh::marshal_authorized_key(host_key.public)));

    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var w = Seen { opened: false, out: [], err: [], exit: -1, closed: false };
    ssh::client_start(c, cc, to_server);                          // both send their version lines
    ssh::server_start(s, sc, to_client);
    pump(c, cc, s, sc, to_server, to_client, w);
    guard ssh::connected(c) && ssh::connected(s) else { print("exec: failed: ", c.message, s.message); exit(1); }
    print("client: connected with ", c.kex_name, ", ", c.cipher_c2s, ", host key ", c.host_key_alg);

    let ch = ssh::open_session(c, to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    guard w.opened && ssh::exec(c, ch, "uname -a", to_server) else { print("exec: no session"); exit(1); }
    pump(c, cc, s, sc, to_server, to_client, w);
    guard w.closed && w.exit == 0 && w.out.starts_with("Linux") && w.err == "a warning on stderr\n" else { print("exec: the command's output was lost"); exit(1); }
    print("stdout: ", w.out[..w.out.len - 1]);
    print("stderr: ", w.err[..w.err.len - 1]);
    print("exit status ", w.exit);

    ssh::disconnect(c, to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    guard ssh::closed(s) else { print("exec: the server did not see the disconnect"); exit(1); }
    print("disconnected");
}

fn main() {
    run();
}
