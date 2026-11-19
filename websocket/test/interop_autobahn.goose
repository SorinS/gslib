// The client side of Autobahn|Testsuite: against its fuzzingserver, every
// case run as a client that echoes what it is sent, then the report
// updated (scripts/autobahn.py runs it; run_tests.py does not).
//
//   goose run test/interop_autobahn.goose ws://127.0.0.1:9002 goose [--stream] [--no-compression]

import std;
import os;
import gslib from "../..";
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.handshake;
import gslib.websocket.conn;
import gslib.websocket.client;

fn echo(c: websocket::Conn&, stream: bool) {
    var msg: u8[>..] = [];
    loop {
        if !stream {
            let kind, e = websocket::read_message(c, msg);
            if e != websocket::OK { return; }
            if websocket::write_message(c, kind, msg) != websocket::OK { return; }
            continue;
        }
        let kind, e = websocket::next_message(c);
        if e != websocket::OK { return; }
        if websocket::begin_message(c, kind) != websocket::OK { return; }
        loop {
            msg.clear();
            let n, end, re = websocket::read_part(c, msg);
            if re != websocket::OK { return; }
            if websocket::write_part(c, msg) != websocket::OK { return; }
            if end { break; }
        }
        if websocket::end_message(c) != websocket::OK { return; }
    }
}

fn main() {
    let a = args();
    if a.len < 3 { print("usage: interop_autobahn URL AGENT [--stream] [--no-compression]"); exit(2); }
    let base = a[1];
    let agent = a[2];
    var stream = false;
    var d = websocket::dialer();
    d.compression = true;
    for k in 3..a.len {
        if a[k] == "--stream" { stream = true; }
        if a[k] == "--no-compression" { d.compression = false; }
    }
    var url: u8[>..] = [];
    url.append(base);
    url.append("/getCaseCount");
    var c = websocket::Conn { .. };
    if websocket::dial(c, url, d) != websocket::OK { print("FAIL getCaseCount"); exit(1); }
    var msg: u8[>..] = [];
    let kind, e = websocket::read_message(c, msg);
    let n, ok = parse_int(msg);
    if e != websocket::OK || !ok { print("FAIL case count"); exit(1); }
    websocket::close(c, websocket::CLOSE_NORMAL, "");
    for i in 1..n + 1 {
        url.clear();
        url.append(base);
        url.append("/runCase?case=");
        format(url, i);
        url.append("&agent=");
        url.append(agent);
        var cc = websocket::Conn { .. };
        let de = websocket::dial(cc, url, d);
        if de == websocket::OK {
            echo(cc, stream);
            if !websocket::closed(cc) { websocket::close(cc, websocket::CLOSE_NORMAL, ""); }
        }
    }
    url.clear();
    url.append(base);
    url.append("/updateReports?agent=");
    url.append(agent);
    var r = websocket::Conn { .. };
    if websocket::dial(r, url, d) == websocket::OK {
        let k2, e2 = websocket::read_message(r, msg);
        websocket::close(r, websocket::CLOSE_NORMAL, "");
    }
    print("ran ", n, " cases");
}
