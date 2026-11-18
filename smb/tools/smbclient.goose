// smbclient: files on an SMB2/3 share, from gslib's client.
//
//   smbclient [options] //SERVER/SHARE COMMAND [ARGS] [\; COMMAND [ARGS]]...
//
// Commands (paths within the share, '/' or '\'):
//   ls [DIR]              the entries: size, modified (UTC), name ("/" after a directory)
//   get REMOTE [LOCAL]    a file to LOCAL (default: its last part; "-": stdout)
//   put LOCAL [REMOTE]    a file from LOCAL, made or replaced
//   cat REMOTE            a file to stdout
//   mkdir DIR   rmdir DIR   rm FILE   mv FROM TO   stat PATH
//   truncate FILE SIZE    touch FILE (made empty, or its times now)
//   df                    the share's space
//   info                  what was negotiated: dialect, signing, encryption
//   echo                  an ECHO round trip
// Several commands go in one connection, each after a ";" argument.
//
//   --port N              445
//   -U USER, --user USER  alice, DOMAIN\alice or alice@REALM (Kerberos)
//   --password PW         else $SMB_PASSWORD
//   --domain D            NTLM's domain ("")
//   --anonymous           an anonymous (null) session
//   --kerberos            Kerberos: a TGT from the password (KRB5_CONFIG's
//                         KDC), else the ticket cache; the SPN cifs/HOST
//   --spn-host HOST       the HOST of the SPN (default: SERVER)
//   --dialect D           only this one: 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
//   --min-dialect D --max-dialect D
//   --cipher C[,C..]      3.1.1's ciphers offered: aes-128-gcm, aes-128-ccm,
//                         aes-256-gcm, aes-256-ccm (3.0's is AES-128-CCM)
//   --signing A[,A..]     3.1.1's signing offered: aes-gmac, aes-cmac
//   --encrypt             require encryption for the whole session
//   --no-sign             do not require signing (sign when the server does)
//   --no-validate         skip 3.0's FSCTL_VALIDATE_NEGOTIATE_INFO
//   --max-io N            the largest READ or WRITE (1048576)
//
// It exits 0 when every command succeeded, 1 when one failed (the NT
// status printed), 2 for a usage or connection error.

import std;
import os;
import gslib from "../..";
import gslib.smb;
import gslib.smb.messages;
import gslib.smb.client;
import gslib.krb5;
import gslib.krb5.ccache;
import gslib.krb5.client;
import gslib.krb5.config;

fn die(what: const u8[:]) { write_stderr(str("smbclient: ", what, "\n")); exit(2); }

fn fail(c: const smb::Conn&, what: const u8[:], e: i64) -> bool {
    if e == smb::ERR_STATUS {
        write_stderr(str("smbclient: ", what, ": ", smb::status_name(c.status), "\n"));
    } else if c.status != smb::STATUS_SUCCESS && c.status != smb::STATUS_MORE_PROCESSING_REQUIRED {
        write_stderr(str("smbclient: ", what, ": ", smb::error_text(e), " (", smb::status_name(c.status), ")\n"));
    } else {
        write_stderr(str("smbclient: ", what, ": ", smb::error_text(e), "\n"));
    }
    return false;
}

fn split_list(s: const u8[:]) -> u8[][>..] {
    var out: u8[][>..] = [];
    for p in split(s, ',') { if p.len > 0 { out.push(p); } }
    return out;
}

fn lpad(s: const u8[:], n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    for i in ::max(0, n - s.len) { out.push(' '); }
    out.append(s);
    return out;
}

// A FILETIME as "2006-01-02 15:04:05" (UTC).
fn when(ft: u64) -> u8[>..] {
    let t = smb::unix_time(ft);
    var days = t / 86400;
    let secs = t % 86400;
    // Civil from days (Howard Hinnant's algorithm).
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    var y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 { y++; }
    var out: u8[>..] = [];
    out.append(str(y, "-", if m < 10 { "0" } else { "" }, m, "-", if d < 10 { "0" } else { "" }, d, " "));
    let hh = secs / 3600;
    let mm = secs / 60 % 60;
    let ss = secs % 60;
    out.append(str(if hh < 10 { "0" } else { "" }, hh, ":", if mm < 10 { "0" } else { "" }, mm, ":", if ss < 10 { "0" } else { "" }, ss));
    return out;
}

fn last_part(p: const u8[:]) -> const u8[:] {
    var i = p.len;
    while i > 0 && p[i - 1] != '/' && p[i - 1] != '\\' { i--; }
    return p[i..];
}

// One command: a[idx[0]] and its arguments a[idx[1]], ...
fn run(c: smb::Conn&, t: const smb::Tree&, a, idx: const i64[:]) -> bool {
    var cmd: u8[:][>..] = [];
    for k in idx { cmd.push(a[k]); }
    let name = cmd[0];
    let n = cmd.len;
    if name == "ls" {
        let dir = if n > 1 { cmd[1] } else { "" };
        let entries, e = smb::list(c, t, dir, "*");
        if e != smb::OK { return fail(c, "ls", e); }
        for x in entries {
            print(lpad(str(x.info.size), 12), "  ", when(x.info.written), "  ", x.name, if smb::is_dir(x.info) { "/" } else { "" });
        }
        return true;
    }
    if name == "get" || name == "cat" {
        if n < 2 { die(str("usage: ", name, " REMOTE")); }
        let data, e = smb::read_file(c, t, cmd[1]);
        if e != smb::OK { return fail(c, name, e); }
        let local = if name == "cat" { "-" } else if n > 2 { cmd[2] } else { last_part(cmd[1]) };
        if local == "-" {
            write_stdout(data);
        } else if !write_file(local, data) {
            die(str("cannot write ", local));
        } else {
            print("got ", cmd[1], ": ", data.len, " bytes");
        }
        return true;
    }
    if name == "put" {
        if n < 2 { die("usage: put LOCAL [REMOTE]"); }
        var data: u8[>..] = [];
        if !read_file(cmd[1], data) { die(str("cannot read ", cmd[1])); }
        let remote = if n > 2 { cmd[2] } else { last_part(cmd[1]) };
        let e = smb::write_file(c, t, remote, data);
        if e != smb::OK { return fail(c, "put", e); }
        print("put ", remote, ": ", data.len, " bytes");
        return true;
    }
    if name == "mkdir" || name == "rmdir" || name == "rm" {
        if n < 2 { die(str("usage: ", name, " PATH")); }
        let e = if name == "mkdir" { smb::mkdir(c, t, cmd[1]) } else if name == "rmdir" { smb::rmdir(c, t, cmd[1]) }
                else { smb::unlink(c, t, cmd[1]) };
        if e != smb::OK { return fail(c, name, e); }
        return true;
    }
    if name == "mv" {
        if n < 3 { die("usage: mv FROM TO"); }
        let e = smb::rename(c, t, cmd[1], cmd[2], false);
        if e != smb::OK { return fail(c, "mv", e); }
        return true;
    }
    if name == "stat" {
        if n < 2 { die("usage: stat PATH"); }
        let i, e = smb::stat(c, t, cmd[1]);
        if e != smb::OK { return fail(c, "stat", e); }
        var attrs: u8[>..] = [];
        format_uint(attrs, i.attributes, 16, 8, '0');
        print("size ", i.size, if smb::is_dir(i) { " directory" } else { " file" }, " attributes 0x", attrs);
        print("created ", when(i.created), " modified ", when(i.written));
        return true;
    }
    if name == "truncate" {
        if n < 3 { die("usage: truncate FILE SIZE"); }
        let size, ok = parse_int(cmd[2], 10);
        if !ok || size < 0 { die("bad size"); }
        var f, e = smb::open(c, t, cmd[1], smb::FILE_WRITE_DATA | smb::FILE_READ_ATTRIBUTES | smb::SYNCHRONIZE, smb::FILE_OPEN_IF,
                             smb::FILE_NON_DIRECTORY_FILE);
        if e != smb::OK { return fail(c, "truncate", e); }
        let te = smb::truncate(c, f, size as u64);
        let q, qe = smb::query(c, f);
        smb::close(c, f);
        if te != smb::OK { return fail(c, "truncate", te); }
        if qe != smb::OK { return fail(c, "truncate", qe); }
        print("size ", q.size);
        return true;
    }
    if name == "touch" {
        if n < 2 { die("usage: touch FILE"); }
        var f, e = smb::open(c, t, cmd[1], smb::FILE_WRITE_ATTRIBUTES | smb::FILE_READ_ATTRIBUTES | smb::SYNCHRONIZE,
                             smb::FILE_OPEN_IF, smb::FILE_NON_DIRECTORY_FILE);
        if e != smb::OK { return fail(c, "touch", e); }
        let now = smb::filetime_of(time_ns() / 1000000000);
        let se = smb::set_times(c, f, 0, now, now, now, 0);
        smb::close(c, f);
        if se != smb::OK { return fail(c, "touch", se); }
        return true;
    }
    if name == "df" {
        let s, e = smb::statfs(c, t);
        if e != smb::OK { return fail(c, "df", e); }
        let unit = (s.sectors_per_unit as u64) * (s.bytes_per_sector as u64);
        print("total ", s.total_units * unit, " free ", s.caller_free_units * unit, " bytes");
        return true;
    }
    if name == "info" {
        print("dialect ", smb::dialect_name(c.dialect));
        print("signing ", if c.signing { smb::signing_name(c.signing_alg) } else { "off" });
        print("encryption ", if c.encrypt || t.encrypt { smb::cipher_name(c.cipher) } else { "off" },
              if t.encrypt && !c.encrypt { " (the share's)" } else { "" });
        print("cipher ", smb::cipher_name(c.cipher));
        if c.dialect == smb::SMB30 || c.dialect == smb::SMB302 { print("validated ", if c.validated { "yes" } else { "no" }); }
        print("session ", if c.session_flags & smb::SESSION_FLAG_IS_GUEST != 0 { "guest" }
                         else if !c.have_keys { "anonymous" } else { "user" });
        return true;
    }
    if name == "echo" {
        let e = smb::echo(c);
        if e != smb::OK { return fail(c, "echo", e); }
        print("echo ok");
        return true;
    }
    die(str("unknown command ", name));
    return false;
}

fn kerberos_ticket(user: const u8[:], pw: const u8[:], host: const u8[:]) -> krb5::Credential {
    let cfg, cerr = krb5::default_config();
    if cerr != krb5::OK { die(str("Kerberos configuration: ", krb5::error_text(cerr))); }
    var spn: u8[>..] = [];
    spn.append("cifs/");
    spn.append(host);
    if pw.len == 0 {
        let cred, e = krb5::get_service_ticket_cached(cfg, krb5::default_ccache_name(), spn, false);
        if e != krb5::OK { die(str("Kerberos: ", krb5::error_text(e))); }
        return cred;
    }
    let tgt, te = krb5::get_tgt_password(cfg, user, pw);
    if te != krb5::OK { die(str("Kerberos: ", krb5::error_text(te))); }
    let sname, realm, se = krb5::service_name(cfg, spn, false);
    if se != krb5::OK { die(str("Kerberos: ", krb5::error_text(se))); }
    let creds, ge = krb5::get_service_ticket(cfg, tgt, sname, realm);
    if ge != krb5::OK || creds.len == 0 { die(str("Kerberos: ", krb5::error_text(ge))); }
    var k = 0;
    for x in creds {
        k++;
        if k == creds.len { return copy(x); }
    }
    die("Kerberos: no ticket");
    return krb5::Credential { .. };
}

fn main() {
    let a = args();
    var o = smb::options();
    var port: i64 = 445;
    var user: u8[>..] = [];
    user.append("alice");
    var domain: u8[>..] = [];
    var pw: u8[>..] = [];
    var have_pw = env("SMB_PASSWORD", pw);
    var anonymous = false;
    var kerberos = false;
    var spn_host: u8[>..] = [];
    var pos: i64[>..] = [];
    var i = 1;
    while i < a.len {
        let s = a[i];
        let more = i + 1 < a.len;
        if s == "--port" && more { let v, ok = parse_int(a[i + 1], 10); port = v; i += 2; }
        else if (s == "-U" || s == "--user") && more { user.clear(); user.append(a[i + 1]); i += 2; }
        else if s == "--password" && more { pw.clear(); pw.append(a[i + 1]); have_pw = true; i += 2; }
        else if s == "--domain" && more { domain.clear(); domain.append(a[i + 1]); i += 2; }
        else if s == "--anonymous" { anonymous = true; i++; }
        else if s == "--kerberos" { kerberos = true; i++; }
        else if s == "--spn-host" && more { spn_host.append(a[i + 1]); i += 2; }
        else if (s == "--dialect" || s == "--min-dialect" || s == "--max-dialect") && more {
            let d, ok = smb::parse_dialect(a[i + 1]);
            if !ok { die(str("unknown dialect ", a[i + 1])); }
            if s != "--max-dialect" { o.min_dialect = d; }
            if s != "--min-dialect" { o.max_dialect = d; }
            i += 2;
        }
        else if s == "--cipher" && more {
            o.ciphers.clear();
            for x in split_list(a[i + 1]) {
                let ci, ok = smb::parse_cipher(x);
                if !ok || o.ciphers.len == o.ciphers.cap { die(str("unknown cipher ", x)); }
                o.ciphers.push(ci);
            }
            i += 2;
        }
        else if s == "--signing" && more {
            o.signing.clear();
            for x in split_list(a[i + 1]) {
                let sa, ok = smb::parse_signing(x);
                if !ok || o.signing.len == o.signing.cap { die(str("unknown signing algorithm ", x)); }
                o.signing.push(sa);
            }
            i += 2;
        }
        else if s == "--encrypt" { o.require_encryption = true; i++; }
        else if s == "--no-sign" { o.require_signing = false; i++; }
        else if s == "--no-validate" { o.validate_negotiate = false; i++; }
        else if s == "--max-io" && more { let v, ok = parse_int(a[i + 1], 10); o.max_io = v; i += 2; }
        else { pos.push(i); i++; }
    }
    guard pos.len >= 2 else { die("usage: smbclient [options] //SERVER/SHARE COMMAND [ARGS] [; COMMAND ...]"); }
    let unc = a[pos[0]];
    let server, share, uok = smb::split_unc(unc);
    if !uok { die(str("not //SERVER/SHARE: ", unc)); }
    var unc_bs: u8[>..] = [];
    unc_bs.append("\\\\");
    unc_bs.append(server);
    unc_bs.push('\\');
    unc_bs.append(share);
    // DOMAIN\user for NTLM.
    var uname: u8[>..] = [];
    for k in user.len {
        if user[k] == '\\' { domain.clear(); domain.append(user[..k]); uname.clear(); }
        else { uname.push(user[k]); }
    }

    var c, e = smb::dial(server, port, o);
    if e != smb::OK {
        write_stderr(str("smbclient: cannot connect: ", smb::error_text(e), "\n"));
        exit(2);
    }
    var le = smb::OK;
    if anonymous {
        le = smb::login_anonymous(c);
    } else if kerberos {
        let host = if spn_host.len > 0 { spn_host[..] } else { server };
        let ticket = kerberos_ticket(user, pw, host);
        le = smb::login_kerberos(c, ticket);
    } else {
        if !have_pw { die("no password: --password or $SMB_PASSWORD"); }
        le = smb::login_ntlm(c, uname, domain, pw);
    }
    if le != smb::OK {
        fail(c, "login", le);
        smb::hangup(c);
        exit(2);
    }
    var t, te = smb::tree_connect(c, unc_bs);
    if te != smb::OK {
        fail(c, "tree connect", te);
        smb::hangup(c);
        exit(2);
    }
    var ok = true;
    var k = 1;
    while k < pos.len {
        var cmd: i64[>..] = [];
        while k < pos.len && a[pos[k]] != ";" {
            cmd.push(pos[k]);
            k++;
        }
        k++;
        if cmd.len > 0 && !run(c, t, a, cmd) { ok = false; break; }
    }
    smb::tree_disconnect(c, t);
    smb::logoff(c);
    smb::hangup(c);
    exit(if ok { 0 } else { 1 });
}
