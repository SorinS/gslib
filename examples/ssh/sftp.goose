// sftp: SFTP over an in-memory SSH connection. The client opens a session
// channel and asks for the "sftp" subsystem; SFTP packets then travel as
// channel data. The server here keeps its files in memory: it answers
// INIT, OPEN, WRITE, READ, CLOSE, STAT, OPENDIR and READDIR. The client
// uploads a file, lists the directory as `ls -l` does, reads the file back,
// and gets "No such file" for one that is not there.
//
//   goose examples/ssh/sftp.goose

import std;
import os;
import gslib from "../..";
import gslib.crypto.ssh;
import gslib.crypto.ssh.keys;
import gslib.crypto.ssh.conn;
import gslib.crypto.ssh.sftp;
import gslib.crypto.x509;

struct File { path: u8[..256], data: u8[..16384], mtime: u32 }

// The server's files, and the SFTP bytes received and not yet handled.
struct Server { files: File[..8], inbuf: u8[..300000], listed: bool }

fn find(srv: const Server&, path: const u8[:]) -> i64 {
    for i in srv.files.len { if srv.files[i].path == path { return i; } }
    return -1;
}

fn attrs_of(f: const File&) -> ssh::Attrs {
    var a = ssh::perm_attrs(ssh::S_IFREG | 0x1a4);   // rw-r--r--
    a.flags |= ssh::ATTR_SIZE | ssh::ATTR_ACMODTIME;
    a.size = f.data.len as! u64;
    a.atime = f.mtime;
    a.mtime = f.mtime;
    return a;
}

// One request in, its reply out. A file's handle is its index.
fn serve(srv: Server&, m: const u8[:], out: u8[>..]&) {
    let msg, ok = ssh::sftp_parse(m);
    if !ok { return; }
    var r = msg.body;
    if msg.kind == ssh::FXP_INIT { ssh::sftp_end(out, ssh::sftp_version(out)); return; }
    if msg.kind == ssh::FXP_OPENDIR { ssh::sftp_handle(out, msg.id, "dir"); srv.listed = false; return; }
    if msg.kind == ssh::FXP_READDIR {
        if srv.listed { ssh::sftp_status(out, msg.id, ssh::FX_EOF); return; }
        let mark = ssh::sftp_name_begin(out, msg.id);
        for f in srv.files {
            var long: u8[>..] = [];
            ssh::sftp_longname(long, f.path[1..], attrs_of(f), 1, "alice", "staff", time_ns() / 1000000000);
            ssh::sftp_name_add(out, f.path[1..], long, attrs_of(f));
        }
        ssh::sftp_name_end(out, mark, srv.files.len as! u32);
        srv.listed = true;
        return;
    }
    let name = ssh::bytes(m, ssh::get_string(r, m));           // a path or a handle
    let i = if msg.kind == ssh::FXP_OPEN || msg.kind == ssh::FXP_STAT { find(srv, name) }
            else { let n, okn = parse_int(name); if okn { n } else { -1 } };
    if msg.kind == ssh::FXP_OPEN {
        let flags = ssh::get_u32(r, m);
        if i >= 0 { ssh::sftp_handle(out, msg.id, str(i)); return; }
        if (flags & ssh::FXF_CREAT) == 0 || srv.files.len == srv.files.cap { ssh::sftp_status(out, msg.id, ssh::FX_NO_SUCH_FILE); return; }
        srv.files.push(File { path: [], data: [], mtime: (time_ns() / 1000000000) as! u32 });
        srv.files[srv.files.len - 1].path.append(name);
        ssh::sftp_handle(out, msg.id, str(srv.files.len - 1));
    } else if i < 0 || i >= srv.files.len {
        ssh::sftp_status(out, msg.id, if msg.kind == ssh::FXP_STAT { ssh::FX_NO_SUCH_FILE } else { ssh::FX_FAILURE });
    } else if msg.kind == ssh::FXP_WRITE {
        let off = ssh::get_u64(r, m) as! i64;
        let data = ssh::bytes(m, ssh::get_string(r, m));
        var f = srv.files[i].data;
        if off + data.len > f.cap { ssh::sftp_status(out, msg.id, ssh::FX_FAILURE); return; }
        if f.len < off + data.len { f.resize(off + data.len, 0); }
        for k in data.len { f[off + k] = data[k]; }
        srv.files[i].data = f;
        ssh::sftp_status(out, msg.id, ssh::FX_OK);
    } else if msg.kind == ssh::FXP_READ {
        let off = ssh::get_u64(r, m) as! i64;
        let len = ssh::get_u32(r, m) as! i64;
        let f = srv.files[i].data;
        if off >= f.len { ssh::sftp_status(out, msg.id, ssh::FX_EOF); return; }
        ssh::sftp_data(out, msg.id, f[off..min(f.len, off + len)]);
    } else if msg.kind == ssh::FXP_STAT {
        ssh::sftp_attrs(out, msg.id, attrs_of(srv.files[i]));
    } else if msg.kind == ssh::FXP_CLOSE {
        ssh::sftp_status(out, msg.id, ssh::FX_OK);
    } else {
        ssh::sftp_status(out, msg.id, ssh::FX_OP_UNSUPPORTED);
    }
}

// The SSH side of the server: a session, the sftp subsystem, its data.
fn server_app(s: ssh::Conn&, srv: Server&, ev: const u8[:], out: u8[>..]&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(ev, pos);
        if !ok { break; }
        var r = e.data;
        if e.kind == ssh::EV_CHANNEL_OPEN { let a = ssh::channel_accept(s, e.channel, out); }
        if e.kind == ssh::EV_REQUEST {
            let kind = ssh::bytes(ev, ssh::get_string(r, ev));
            let name = ssh::bytes(ev, ssh::get_string(r, ev));
            let a = ssh::channel_reply(s, e.channel, kind == "subsystem" && name == "sftp", out);
        }
        if e.kind == ssh::EV_DATA {
            srv.inbuf.append(ssh::bytes(ev, e.data));
            loop {                                              // every whole packet that has come
                let n = ssh::sftp_packet_len(srv.inbuf);
                if n <= 0 { break; }
                var reply: u8[>..] = [];
                serve(srv, srv.inbuf[..n], reply);
                let sent = ssh::channel_send(s, e.channel, reply, out);
                var rest: u8[>..] = [];
                rest.append(srv.inbuf[n..]);
                srv.inbuf.clear();
                srv.inbuf.append(rest);
            }
        }
    }
}

fn pump(c: ssh::Conn&, cc: const ssh::ClientConfig&, s: ssh::Conn&, sc: const ssh::ServerConfig&, srv: Server&,
        to_server: u8[>..]&, to_client: u8[>..]&, cin: u8[>..]&) {
    for round in 100 {
        if to_server.len == 0 && to_client.len == 0 { break; }
        var sev: u8[>..] = [];
        let rs = ssh::server_feed(s, sc, to_server, to_client, sev);
        to_server.clear();
        server_app(s, srv, sev, to_client);
        var cev: u8[>..] = [];
        let rc = ssh::client_feed(c, cc, to_client, to_server, cev);
        to_client.clear();
        var pos = 0;
        loop {
            let e, ok = ssh::next_event(cev, pos);
            if !ok { break; }
            if e.kind == ssh::EV_DATA { cin.append(ssh::bytes(cev, e.data)); }
        }
    }
}

// Sends one SFTP request and returns the reply packet.
fn call(c: ssh::Conn&, cc: const ssh::ClientConfig&, s: ssh::Conn&, sc: const ssh::ServerConfig&, srv: Server&,
        ch: i64, req: const u8[:], cin: u8[>..]&) -> u8[>..], ssh::SftpMsg {
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    let sent = ssh::channel_send(c, ch, req, to_server);
    pump(c, cc, s, sc, srv, to_server, to_client, cin);
    let n = ssh::sftp_packet_len(cin);
    guard n > 0 else { print("sftp: no reply"); exit(1); }
    var m: u8[>..] = [];
    m.append(cin[..n]);
    var rest: u8[>..] = [];
    rest.append(cin[n..]);
    cin.clear();
    cin.append(rest);
    let msg, ok = ssh::sftp_parse(m);
    guard ok else { print("sftp: a bad reply"); exit(1); }
    return m, msg;
}

fn run() {
    let host_key = ssh::generate_key(x509::KEY_ED25519);
    var sc = ssh::server_config();
    let a = ssh::add_host_key(sc, host_key);
    sc.passwords.append("alice:pw\n");
    var cc = ssh::client_config("alice", "example.com");
    cc.known_hosts.append(str("example.com ", ssh::marshal_authorized_key(host_key.public)));
    ssh::set_password(cc, "pw");

    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var srv = Server { files: [], inbuf: [], listed: false };
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var cin:       u8[>..] = [];
    ssh::client_start(c, cc, to_server);                       // both send their version lines
    ssh::server_start(s, sc, to_client);
    pump(c, cc, s, sc, srv, to_server, to_client, cin);
    guard ssh::connected(c) else { print("sftp: login failed: ", c.message); exit(1); }
    let ch = ssh::open_session(c, to_server);
    pump(c, cc, s, sc, srv, to_server, to_client, cin);
    guard ssh::subsystem(c, ch, "sftp", to_server) else { print("sftp: no session"); exit(1); }
    pump(c, cc, s, sc, srv, to_server, to_client, cin);

    var req: u8[>..] = [];
    ssh::sftp_init(req);
    let v, vm = call(c, cc, s, sc, srv, ch, req, cin);
    guard vm.kind == ssh::FXP_VERSION && vm.id == 3 else { print("sftp: no VERSION"); exit(1); }
    print("sftp version ", vm.id);

    // Upload: OPEN (create), WRITE, CLOSE.
    let content = "hello over sftp\n";
    req.clear();
    ssh::sftp_open(req, 1, "/hello.txt", ssh::FXF_WRITE | ssh::FXF_CREAT | ssh::FXF_TRUNC, ssh::perm_attrs(0x1a4));
    let h, hm = call(c, cc, s, sc, srv, ch, req, cin);
    guard hm.kind == ssh::FXP_HANDLE else { print("sftp: OPEN failed"); exit(1); }
    var hr = hm.body;
    var handle: u8[>..] = [];
    handle.append(ssh::bytes(h, ssh::get_string(hr, h)));
    req.clear();
    ssh::sftp_write(req, 2, handle, 0, content);
    let w, wm = call(c, cc, s, sc, srv, ch, req, cin);
    let wcode, wtext = ssh::sftp_get_status(w, wm);
    req.clear();
    ssh::sftp_handle_req(req, ssh::FXP_CLOSE, 3, handle);
    let x, xm = call(c, cc, s, sc, srv, ch, req, cin);
    guard wcode == ssh::FX_OK else { print("sftp: WRITE failed"); exit(1); }
    print("put /hello.txt: ", content.len, " bytes");

    // ls -l: OPENDIR, then READDIR until EOF.
    req.clear();
    ssh::sftp_path_req(req, ssh::FXP_OPENDIR, 4, "/");
    let d, dm = call(c, cc, s, sc, srv, ch, req, cin);
    var dr = dm.body;
    let dh = ssh::bytes(d, ssh::get_string(dr, d));
    loop {
        req.clear();
        ssh::sftp_handle_req(req, ssh::FXP_READDIR, 5, dh);
        let n, nm = call(c, cc, s, sc, srv, ch, req, cin);
        if nm.kind != ssh::FXP_NAME { break; }                 // STATUS EOF: no more
        var nr = nm.body;
        let count = ssh::get_u32(nr, n);
        for k in count {
            let fname = ssh::get_string(nr, n);
            let long = ssh::get_string(nr, n);
            let at = ssh::get_attrs(nr, n);
            print(ssh::bytes(n, long));
        }
    }

    // Download: READ until EOF.
    req.clear();
    ssh::sftp_open(req, 6, "/hello.txt", ssh::FXF_READ, ssh::no_attrs());
    let h2, h2m = call(c, cc, s, sc, srv, ch, req, cin);
    var h2r = h2m.body;
    let rh = ssh::bytes(h2, ssh::get_string(h2r, h2));
    var back: u8[>..] = [];
    loop {
        req.clear();
        ssh::sftp_read(req, 7, rh, back.len as! u64, 8);        // 8 bytes at a time, to show the loop
        let dd, ddm = call(c, cc, s, sc, srv, ch, req, cin);
        if ddm.kind != ssh::FXP_DATA { break; }
        var ddr = ddm.body;
        back.append(ssh::bytes(dd, ssh::get_string(ddr, dd)));
    }
    guard back == content else { print("sftp: the file came back changed"); exit(1); }
    print("get /hello.txt: ", back.len, " bytes, the same");

    // A file that is not there.
    req.clear();
    ssh::sftp_path_req(req, ssh::FXP_STAT, 8, "/missing.txt");
    let st, stm = call(c, cc, s, sc, srv, ch, req, cin);
    let code, text = ssh::sftp_get_status(st, stm);
    guard code == ssh::FX_NO_SUCH_FILE else { print("sftp: a missing file was found"); exit(1); }
    print("stat /missing.txt: ", ssh::bytes(st, text));
}

fn main() {
    run();
}
