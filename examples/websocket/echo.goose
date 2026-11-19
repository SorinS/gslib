// echo: a WebSocket server and its client in one program, over loopback:
// the server (on a thread of its own) echoes what comes, the client
// sends a few messages, compressed by permessage-deflate, one of them in
// parts, pings, and closes.
//
//   goose examples/websocket/echo.goose

import std;
import gslib from "../..";
import gslib.net;
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.handshake;
import gslib.websocket.conn;
import gslib.websocket.client;
import gslib.websocket.server;

// One connection: echo until the client closes.
thread_fn serve(lfd: i64) {
    let fd = net::accept(lfd, 10000);
    var c = websocket::Conn { .. };
    var u = websocket::upgrader();
    u.compression = true;
    u.subprotocols.append("echo.v1");
    if websocket::accept(c, fd, u, 10000) != websocket::OK {
        print("server: handshake refused, ", c.status);
        net::close(fd);
        return;
    }
    var msg: u8[>..] = [];
    loop {
        let kind, e = websocket::read_message(c, msg);
        if e != websocket::OK { break; }
        websocket::write_message(c, kind, msg);
    }
    print("server: the client closed with ", c.close_code, " ", c.close_reason[..]);
}

fn main() {
    let lfd = net::listen("127.0.0.1", 0);
    let port = net::local_port(lfd);
    let id = thread_spawn(serve, lfd);

    var url: u8[>..] = [];
    url.append("ws://127.0.0.1:");
    format(url, port);
    url.append("/echo");
    var d = websocket::dialer();
    d.compression = true;
    d.subprotocols.append("echo.v1");
    var c = websocket::Conn { .. };
    let e = websocket::dial(c, url, d);
    if e != websocket::OK {
        print("client: ", websocket::error_text(e));
        exit(1);
    }
    print("client: connected, subprotocol ", c.subprotocol[..], ", permessage-deflate ", c.pmd.on);

    var msg: u8[>..] = [];
    websocket::write_message(c, websocket::TEXT, "hello, world");
    let k1, e1 = websocket::read_message(c, msg);
    print("client: got ", msg[..]);

    // A message in parts, as it is made.
    websocket::begin_message(c, websocket::TEXT);
    for i in 3 {
        var part: u8[>..] = [];
        part.append("part ");
        format(part, i + 1);
        part.append("; ");
        websocket::write_part(c, part);
    }
    websocket::end_message(c);
    let k2, e2 = websocket::read_message(c, msg);
    print("client: got ", msg[..]);

    // A ping: its pong is handed over when control_events is on.
    c.opt.control_events = true;
    websocket::ping(c, "are you there?");
    let k3, e3 = websocket::read_message(c, msg);
    print("client: pong ", c.control[..], " ", k3 == websocket::PONG);

    var big: u8[>..] = [];
    for i in 100000 { big.push('a' + (i % 7) as! u8); }
    websocket::write_message(c, websocket::BINARY, big);
    let k4, e4 = websocket::read_message(c, msg);
    print("client: got ", msg.len, " bytes back, the same: ", msg[..] == big[..]);

    print("client: close, ", websocket::error_text(websocket::close(c, websocket::CLOSE_NORMAL, "done")));
    var why: u8[>..] = [];
    thread_wait(id, why);
}
