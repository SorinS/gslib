// client: a share on an SMB server, with NTLMv2: the dialect and the
// protection negotiated, a directory listed, a file written, read back and
// compared, renamed and deleted.
//
//   goose examples/smb/client.goose -- SERVER SHARE USER PASSWORD [PORT]
//
// USER may be DOMAIN\user. Signing is required (the default options); add
// encryption with o.require_encryption.

import std;
import gslib from "../..";
import gslib.smb;
import gslib.smb.messages;
import gslib.smb.client;

fn die(c: const smb::Conn&, what: const u8[:], e: i64) {
    let status: u8[>..] = if e == smb::ERR_STATUS { str(" ", smb::status_name(c.status)) } else { "" };
    print(what, ": ", smb::error_text(e), status);
    exit(1);
}

fn main() {
    let a = args();
    guard a.len >= 5 else { print("usage: client.goose -- SERVER SHARE USER PASSWORD [PORT]"); exit(2); }
    var port: i64 = 445;
    if a.len > 5 { let p, ok = parse_int(a[5], 10); port = p; }
    var domain: u8[>..] = [];
    var user: u8[>..] = [];
    for ch in a[3] { if ch == '\\' { domain.append(user); user.clear(); } else { user.push(ch); } }

    let o = smb::options();
    var c, e = smb::dial(a[1], port, o);
    if e != smb::OK { die(c, "connect", e); }
    e = smb::login_ntlm(c, user, domain, a[4]);
    if e != smb::OK { die(c, "login", e); }
    print("dialect ", smb::dialect_name(c.dialect), ", signing ", smb::signing_name(c.signing_alg),
          ", cipher ", smb::cipher_name(c.cipher));

    let unc = str("\\\\", a[1], "\\", a[2]);
    var t, te = smb::tree_connect(c, unc);
    if te != smb::OK { die(c, "tree connect", te); }

    let entries, le = smb::list(c, t, "", "*");
    if le != smb::OK { die(c, "list", le); }
    for x in entries { print(if smb::is_dir(x.info) { "  dir  " } else { "  file " }, x.info.size, "  ", x.name); }

    var data: u8[>..] = [];
    for i in 200000 { data.push((i * 7) as! u8); }
    e = smb::write_file(c, t, "gslib-example.bin", data);
    if e != smb::OK { die(c, "write", e); }
    let back, re = smb::read_file(c, t, "gslib-example.bin");
    if re != smb::OK { die(c, "read", re); }
    print("wrote and read back ", back.len, " bytes: ", if back == data { "the same" } else { "DIFFERENT" });
    e = smb::rename(c, t, "gslib-example.bin", "gslib-example.old", true);
    if e != smb::OK { die(c, "rename", e); }
    let info, se = smb::stat(c, t, "gslib-example.old");
    if se != smb::OK { die(c, "stat", se); }
    print("renamed: ", info.size, " bytes, modified at ", smb::unix_time(info.written));
    e = smb::unlink(c, t, "gslib-example.old");
    if e != smb::OK { die(c, "delete", e); }

    smb::tree_disconnect(c, t);
    smb::logoff(c);
    smb::hangup(c);
}
