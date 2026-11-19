// goose-wscat: a WebSocket client, after the npm wscat: each line of
// stdin goes as a text message (or each -x MSG, in order), and every
// message that comes back is printed, "< " before it.
//
//   goose-wscat [-x MSG]... [--binary] [--wait MS] [--compression]
//               [--protocol P,...] [--origin O] [-H 'Name: value']...
//               [--cacert ca.pem] [-k] [--proxy http://host:port] [--show-ping]
//               [--close CODE] URL
//
// After each message it waits --wait milliseconds (500) for answers;
// at the end of input it closes with CODE (1000) and prints the
// server's close. With -k the server's certificate is not checked.
// The exit status is 0 when the connection ended with a closing
// handshake, 1 when it failed, 2 for bad arguments.

import std;
import os;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.handshake;
import gslib.websocket.conn;
import gslib.websocket.client;

fn die(msg: const u8[:]) {
    write_stderr("goose-wscat: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(2);
}

fn show(prefix: const u8[:], kind: u8, msg: const u8[:]) {
    var l: u8[>..] = [];
    l.append(prefix);
    if kind == websocket::BINARY {
        l.append("[binary ");
        format(l, msg.len);
        l.append(" bytes] ");
        let n = min(msg.len, 32);
        for i in n { format_uint(l, msg[i], 16, 2, '0'); }
        if msg.len > n { l.append("..."); }
    } else if kind == websocket::PING || kind == websocket::PONG {
        l.append(if kind == websocket::PING { "[ping] " } else { "[pong] " });
        l.append(msg);
    } else {
        l.append(msg);
    }
    l.push('\n');
    write_stdout(l);
}

// Prints what comes within wait_ms: false when the connection ended.
fn drain(c: websocket::Conn&, wait_ms: i32) -> bool {
    c.opt.read_timeout_ms = wait_ms;
    var msg: u8[>..] = [];
    loop {
        let kind, e = websocket::read_message(c, msg);
        if e == websocket::ERR_TIMEOUT { return true; }
        if e != websocket::OK { return false; }
        if kind == websocket::PING || kind == websocket::PONG { show("< ", kind, c.control); }
        else { show("< ", kind, msg); }
    }
    return true;
}

fn main() {
    let a = args();
    var d = websocket::dialer();
    var url: u8[>..] = [];
    var msgs: u8[][>..] = [];
    var kind = websocket::TEXT;
    var wait_ms: i32 = 500;
    var close_code: i64 = 1000;
    var show_ping = false;
    var i = 1;
    while i < a.len {
        let o = a[i];
        if o == "--binary" { kind = websocket::BINARY; i++; continue; }
        if o == "--compression" || o == "-C" { d.compression = true; i++; continue; }
        if o == "-k" || o == "--insecure" { d.insecure = true; i++; continue; }
        if o == "--show-ping" { show_ping = true; i++; continue; }
        if o.len > 0 && o[0] != '-' {
            if url.len > 0 { die("one URL"); }
            url.append(o);
            i++;
            continue;
        }
        if i + 1 >= a.len { die("each option takes a value"); }
        let v = a[i + 1];
        if o == "-x" || o == "--execute" { msgs.push(v); }
        else if o == "--wait" {
            let n, ok = parse_int(v);
            if !ok || n < 0 || n > 3600000 { die("bad --wait"); }
            wait_ms = n as! i32;
        }
        else if o == "--close" {
            let n, ok = parse_int(v);
            if !ok || !websocket::valid_close_code(n) { die("bad --close"); }
            close_code = n;
        }
        else if o == "--protocol" { d.subprotocols.append(v); }
        else if o == "--origin" { d.origin.append(v); }
        else if o == "-H" || o == "--header" {
            let c = find(v, ":");
            if c <= 0 { die("a header is 'Name: value'"); }
            d.fields.append(v);
            d.fields.append("\r\n");
        }
        else if o == "--proxy" { d.proxy.append(v); }
        else if o == "--cacert" {
            var text: u8[>..] = [];
            if !read_file(v, text) { die("cannot read --cacert"); }
            let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
            for der in ders { d.roots.append(der); }
            if d.roots.len == 0 { die("no certificate in --cacert"); }
        }
        else { die("usage: goose-wscat [-x MSG]... [--binary] [--wait MS] [--compression] [--protocol P,...] [--origin O] [-H 'N: v']... [--cacert ca.pem] [-k] [--proxy URL] [--show-ping] [--close CODE] URL"); }
        i += 2;
    }
    if url.len == 0 { die("no URL"); }
    var c = websocket::Conn { .. };
    c.opt.control_events = show_ping;
    let e = websocket::dial(c, url, d);
    if e != websocket::OK {
        var l: u8[>..] = [];
        l.append("goose-wscat: ");
        l.append(websocket::error_text(e));
        if c.status != 0 {
            l.append(" (HTTP ");
            format(l, c.status);
            l.append(")");
        }
        if c.why.len > 0 {
            l.append(": ");
            l.append(c.why);
        }
        l.push('\n');
        write_stderr(l);
        exit(1);
    }
    var info: u8[>..] = [];
    info.append("connected");
    if c.subprotocol.len > 0 { info.append(" (subprotocol "); info.append(c.subprotocol); info.append(")"); }
    if c.pmd.on { info.append(" (permessage-deflate)"); }
    info.push('\n');
    write_stderr(info);
    var alive = true;
    if msgs.len > 0 {
        for m in msgs {
            if websocket::write_message(c, kind, m) != websocket::OK { alive = false; break; }
            if !drain(c, wait_ms) { alive = false; break; }
        }
    } else {
        var line: u8[>..] = [];
        while alive && read_line(line) {
            if websocket::write_message(c, kind, line) != websocket::OK { alive = false; break; }
            line.clear();
            alive = drain(c, wait_ms);
        }
    }
    var r = websocket::OK;
    if alive { r = websocket::close(c, close_code, ""); }
    var l: u8[>..] = [];
    l.append("closed: ");
    format(l, c.close_code);
    if c.close_reason.len > 0 { l.push(' '); l.append(c.close_reason); }
    l.push('\n');
    write_stderr(l);
    exit(if r == websocket::OK && c.st.got_close { 0 } else { 1 });
}
