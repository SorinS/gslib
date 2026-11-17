// udp: datagrams both ways. A server bound to a port the system picks
// answers each datagram to whoever sent it (recv_from, send_to); a
// client's socket is connected to the server, so the system drops
// datagrams from anyone else (dial_udp, send, recv).
//
//   goose examples/net/udp.goose

import std;
import gslib from "../..";
import gslib.net;
import gslib.net.ip;

fn main() {
    let srv = net::listen_udp("127.0.0.1", 0);
    let port = net::local_port(srv);
    let c = net::dial_udp("127.0.0.1", port);
    if srv < 0 || c < 0 { print("udp: no sockets"); exit(1); }
    var buf: u8[1500] = [0; 1500];
    for word in ["one", "two", "three"] {
        net::send(c, word);
        let n, from = net::recv_from(srv, buf, 2000);
        print("server: ", buf[..n], " from ", from);
        var up: u8[>..] = [];
        for ch in buf[..n] { up.push(if ch >= 'a' && ch <= 'z' { ch - 32 } else { ch }); }
        net::send_to(srv, up, from);
        let r = net::recv(c, buf, 2000);
        print("client: ", buf[..r]);
    }
    let r = net::recv(c, buf, 100);
    print("nothing more: ", r == net::ERR_TIMEOUT);
    net::close(c);
    net::close(srv);
}
