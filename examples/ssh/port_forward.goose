// port_forward: port forwarding, in memory, the program playing both
// applications. Local forwarding (ssh -L): the client opens a
// direct-tcpip channel to intranet.example.com:80 and the server, which
// would connect there, answers in its place. Remote forwarding (ssh -R):
// the client asks the server to listen on a port it picks (port 0); the
// server names it in its reply and, when a connection comes in, opens a
// forwarded-tcpip channel back to the client.
//
//   goose examples/ssh/port_forward.goose

import std;
import gslib from "../..";
import gslib.crypto.ssh;
import gslib.crypto.ssh.keys;
import gslib.crypto.ssh.conn;
import gslib.crypto.x509;

// What the two applications saw.
struct Seen { target: u8[..256], client_got: u8[..4096], forwarded_port: i64, forwarded_opens: i64 }

// The server: a direct-tcpip channel is taken, its data answered as the
// web server behind it would, then closed; tcpip-forward on port 0 gets
// port 8080.
fn server_app(s: ssh::Conn&, ev: const u8[:], out: u8[>..]&, w: Seen&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(ev, pos);
        if !ok { break; }
        var r = e.data;
        if e.kind == ssh::EV_CHANNEL_OPEN {
            let kind = ssh::bytes(ev, ssh::get_string(r, ev));
            let host = ssh::bytes(ev, ssh::get_string(r, ev));
            let port = ssh::get_u32(r, ev);
            if kind == "direct-tcpip" {
                w.target.append(str(host, ":", port));
                let a = ssh::channel_accept(s, e.channel, out);
            } else {
                let a = ssh::channel_reject(s, e.channel, ssh::OPEN_ADMINISTRATIVELY_PROHIBITED, "no", out);
            }
        } else if e.kind == ssh::EV_DATA {
            let n = ssh::channel_send(s, e.channel, "HTTP/1.0 200 OK\r\n\r\nintranet page", out);
            ssh::channel_eof(s, e.channel, out);
            ssh::channel_close(s, e.channel, out);
        } else if e.kind == ssh::EV_GLOBAL_REQUEST {
            let name = ssh::bytes(ev, ssh::get_string(r, ev));
            if name == "tcpip-forward" {
                var reply: u8[>..] = [];
                ssh::put_u32(reply, 8080);                   // the port it listens on
                let a = ssh::global_reply(s, true, reply, out);
            } else if e.value == 1 {
                let a = ssh::global_reply(s, false, "", out);
            }
        }
    }
}

// The client: data is kept; forwarded-tcpip channels are taken (it would
// connect each to its local target).
fn client_app(c: ssh::Conn&, ev: const u8[:], out: u8[>..]&, w: Seen&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(ev, pos);
        if !ok { break; }
        var r = e.data;
        if e.kind == ssh::EV_DATA { w.client_got.append(ssh::bytes(ev, e.data)); }
        if e.kind == ssh::EV_GLOBAL_REPLY && e.value == 1 { w.forwarded_port = ssh::get_u32(r, ev); }
        if e.kind == ssh::EV_CHANNEL_OPEN {
            let kind = ssh::bytes(ev, ssh::get_string(r, ev));
            if kind == "forwarded-tcpip" { w.forwarded_opens++; let a = ssh::channel_accept(c, e.channel, out); }
        }
    }
}

fn pump(c: ssh::Conn&, cc: const ssh::ClientConfig&, s: ssh::Conn&, sc: const ssh::ServerConfig&,
        to_server: u8[>..]&, to_client: u8[>..]&, w: Seen&) {
    for round in 100 {
        if to_server.len == 0 && to_client.len == 0 { break; }
        var sev: u8[>..] = [];
        let rs = ssh::server_feed(s, sc, to_server, to_client, sev);
        to_server.clear();
        server_app(s, sev, to_client, w);
        var cev: u8[>..] = [];
        let rc = ssh::client_feed(c, cc, to_client, to_server, cev);
        to_client.clear();
        client_app(c, cev, to_server, w);
    }
}

fn run() {
    let host_key = ssh::generate_key(x509::KEY_ED25519);
    let user_key = ssh::generate_key(x509::KEY_ED25519);
    var sc = ssh::server_config();
    let a1 = ssh::add_host_key(sc, host_key);
    sc.authorized_keys.append(ssh::marshal_authorized_key(user_key.public));
    var cc = ssh::client_config("alice", "example.com");
    let a2 = ssh::add_key(cc, user_key);
    cc.known_hosts.append(str("example.com ", ssh::marshal_authorized_key(host_key.public)));

    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var w = Seen { target: [], client_got: [], forwarded_port: -1, forwarded_opens: 0 };
    ssh::client_start(c, cc, to_server);
    ssh::server_start(s, sc, to_client);
    pump(c, cc, s, sc, to_server, to_client, w);
    guard ssh::connected(c) else { print("port_forward: login failed: ", c.message); exit(1); }

    // -L 8000:intranet.example.com:80, a connection to local port 8000
    // having come from 127.0.0.1:50000.
    let ch = ssh::open_direct_tcpip(c, "intranet.example.com", 80, "127.0.0.1", 50000, to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    let n = ssh::channel_send(c, ch, "GET / HTTP/1.0\r\n\r\n", to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    guard w.target == "intranet.example.com:80" && w.client_got.ends_with("intranet page") else { print("port_forward: -L failed"); exit(1); }
    print("-L: the server connected to ", w.target, "; the client got ", w.client_got.len, " bytes back");

    // -R 0:localhost:3000: the server picks the port.
    guard ssh::tcpip_forward(c, "127.0.0.1", 0, to_server) else { print("port_forward: -R not sent"); exit(1); }
    pump(c, cc, s, sc, to_server, to_client, w);
    guard w.forwarded_port == 8080 else { print("port_forward: no port in the reply"); exit(1); }
    // Someone connects to the server's port 8080: a channel to the client.
    let fch = ssh::open_forwarded_tcpip(s, "127.0.0.1", 8080, "192.0.2.7", 41000, to_client);
    pump(c, cc, s, sc, to_server, to_client, w);
    guard w.forwarded_opens == 1 else { print("port_forward: the forwarded channel did not reach the client"); exit(1); }
    print("-R: the server listens on port ", w.forwarded_port, " and forwarded a connection back");
}

fn main() {
    run();
}
