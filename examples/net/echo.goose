// echo: a TCP echo server and its clients in one program, without
// threads: the listening socket and every connection waited on together
// with net::poll. Each client sends a line and reads it back; the server
// answers whatever arrives and closes a connection at its end.
//
//   goose examples/net/echo.goose [--clients N]

import std;
import os;
import gslib from "../..";
import gslib.net;
import gslib.net.ip;

fn fail(what: const u8[:]) {
    print("echo: ", what);
    exit(1);
}

fn main() {
    let argv = args();
    var clients = 3;
    if argv.len == 3 && argv[1] == "--clients" {
        let v, ok = parse_int(argv[2]);
        if !ok || v < 1 || v > 100 { fail("--clients is 1 to 100"); }
        clients = v;
    }
    let l = net::listen("127.0.0.1", 0);
    if l < 0 { fail("cannot listen"); }
    let at, e = net::local_addr(l);
    print("listening on ", at);

    // The clients connect and write first; the server is not reading yet,
    // and the system holds what they sent.
    var conns: i64[>..] = [];
    for i in clients {
        let c = net::dial("127.0.0.1", at.port as! i32, 2000);
        if c < 0 { fail("cannot connect"); }
        net::write(c, str("hello ", i, "\n"), 2000);
        net::shutdown(c, net::SHUT_WRITE);
        conns.push(c);
    }

    // The server: one poll over the listener and what it accepted.
    var fds: i64[>..] = [l];
    var served = 0;
    var buf: u8[4096] = [0; 4096];
    while served < clients {
        var want: u8[>..] = [];
        var ready: u8[>..] = [];
        for f in fds { want.push(net::WANT_READ); ready.push(0); }
        if net::poll(fds, want, ready, 5000) <= 0 { fail("nothing happened for 5 s"); }
        for i in fds.len {
            if ready[i] == 0 || fds[i] < 0 { continue; }
            if fds[i] == l {
                let s = net::accept(l, 0);
                let peer, pe = net::peer_addr(s);
                print("server: a connection from ", peer);
                fds.push(s);
                continue;
            }
            let n = net::read(fds[i], buf, 1000);
            if n > 0 {
                net::write(fds[i], buf[..n], 1000);
            } else {
                net::close(fds[i]);
                fds[i] = -1;
                served++;
            }
        }
    }

    for c in conns {
        let n = net::read(c, buf, 2000);
        if n <= 0 { fail("no echo"); }
        write_stdout(str("client got: ", buf[..n]));
        net::close(c);
    }
    net::close(l);
}
