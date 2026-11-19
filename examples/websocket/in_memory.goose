// in_memory: the WebSocket protocol without sockets. An HTTP/1.1 server
// connection (net.http.conn1) reads a client's upgrade request among
// ordinary requests and hands it to websocket::upgrade; both Conns then
// trade frames through bytes this program carries (feed, take_output), as
// a program with its own event loop, or a transport other than TCP, does.
//
//   goose examples/websocket/in_memory.goose

import std;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.h1;
import gslib.net.http.conn1;
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.handshake;
import gslib.websocket.conn;
import gslib.websocket.server;

fn main() {
    // The client's side of the handshake: its request, with an ordinary
    // GET before it on the same connection.
    var d = websocket::dialer();
    d.compression = true;
    let key = websocket::new_key("sixteen bytes!!!");
    var wire: u8[>..] = [];
    wire.append("GET /health HTTP/1.1\r\nHost: app.example\r\n\r\n");
    websocket::put_request(wire, "app.example", "/live", key, d);

    // The server reads requests with net.http, answering the first and
    // upgrading the second.
    var hc = http::server_conn(http::server_options());
    var srv = websocket::Conn { .. };
    var u = websocket::upgrader();
    u.compression = true;
    var to_client: u8[>..] = [];
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var upgraded = false;
    while !upgraded {
        let ev, h = http::server_read(hc, wire, body, trailer, to_client);
        if ev.kind == http::EV_REQUEST {
            let target = wire[h.target.pos..h.target.end];
            if http::has_token(wire, h, "upgrade", "websocket") {
                print("server: ", target, " upgraded: ",
                      websocket::error_text(websocket::upgrade(srv, -1, wire, h, wire[ev.used..], u)));
                websocket::take_output(srv, to_client);
                upgraded = true;
            } else {
                print("server: ", target, " answered over HTTP");
                http::server_respond(hc, 200, "Content-Type: text/plain\r\n", 3, to_client);
                http::server_body(hc, "ok\n", to_client);
                http::server_end(hc, "", to_client);
            }
        }
        var rest: u8[>..] = [];
        rest.append(wire[ev.used..]);
        wire.clear();
        wire.append(rest);
        if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_ERROR { break; }
    }

    // The client reads the 200, then the 101, and checks it.
    let lim = http::default_limits();
    let h1, n1 = http::parse_response(to_client, lim);
    print("client: ", h1.status, " for /health");
    let p = n1 + 3;                                       // and its body, "ok\n"
    let h2, n2 = http::parse_response(to_client[p..], lim);
    let a = websocket::check_response(to_client[p..], h2, key, d);
    print("client: ", h2.status, ", ", websocket::error_text(a.err), ", permessage-deflate ", a.pmd.on);
    var cl = websocket::Conn { .. };
    websocket::start(cl, true, a.pmd, to_client[p + n2..]);

    // Messages both ways.
    var bytes: u8[>..] = [];
    var msg: u8[>..] = [];
    websocket::write_message(cl, websocket::TEXT, "subscribe: prices");
    websocket::take_output(cl, bytes);
    websocket::feed(srv, bytes);
    let k1, e1 = websocket::read_message(srv, msg);
    print("server: got ", msg[..]);
    for i in 3 {
        var update: u8[>..] = [];
        update.append("price update ");
        format(update, i + 1);
        websocket::write_message(srv, websocket::TEXT, update);
    }
    bytes.clear();
    websocket::take_output(srv, bytes);
    print("server: sent ", bytes.len, " bytes of frames, compressed");
    websocket::feed(cl, bytes);
    loop {
        let k, e = websocket::read_message(cl, msg);
        if e == websocket::ERR_NEED_MORE { break; }
        print("client: got ", msg[..]);
    }

    // The closing handshake.
    websocket::close(cl, websocket::CLOSE_GOING_AWAY, "page closed");
    bytes.clear();
    websocket::take_output(cl, bytes);
    websocket::feed(srv, bytes);
    let k2, e2 = websocket::read_message(srv, msg);
    print("server: ", websocket::error_text(e2), " ", srv.close_code, " ", srv.close_reason[..], ", closed: ", websocket::closed(srv));
    bytes.clear();
    websocket::take_output(srv, bytes);
    websocket::feed(cl, bytes);
    let k3, e3 = websocket::read_message(cl, msg);
    print("client: ", websocket::error_text(e3), " ", cl.close_code, ", closed: ", websocket::closed(cl));
}
