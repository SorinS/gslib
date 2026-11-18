// kerberos: an SMB session with Kerberos: a TGT from a password, a
// service ticket for cifs/HOST, SESSION_SETUP with it (the server's
// AP-REP checked), then the session encrypted with AES-256-GCM, whose key
// comes from the whole 256-bit Kerberos session key.
//
//   KRB5_CONFIG=krb5.conf goose examples/smb/kerberos.goose -- HOST SHARE alice@REALM PASSWORD [PORT]
//
// krb5.conf names the realm's KDC; HOST is the server's name in its SPN.

import std;
import gslib from "../..";
import gslib.smb;
import gslib.smb.messages;
import gslib.smb.client;
import gslib.krb5;
import gslib.krb5.ccache;
import gslib.krb5.client;
import gslib.krb5.config;

fn main() {
    let a = args();
    guard a.len >= 5 else { print("usage: kerberos.goose -- HOST SHARE PRINCIPAL PASSWORD [PORT]"); exit(2); }
    var port: i64 = 445;
    if a.len > 5 { let p, ok = parse_int(a[5], 10); port = p; }

    let cfg, ce = krb5::default_config();
    if ce != krb5::OK { print("krb5.conf: ", krb5::error_text(ce)); exit(1); }
    let tgt, te = krb5::get_tgt_password(cfg, a[3], a[4]);
    if te != krb5::OK { print("TGT: ", krb5::error_text(te)); exit(1); }
    let sname, realm, se = krb5::service_name(cfg, str("cifs/", a[1]), false);
    if se != krb5::OK { print("SPN: ", krb5::error_text(se)); exit(1); }
    let creds, ge = krb5::get_service_ticket(cfg, tgt, sname, realm);
    if ge != krb5::OK { print("ticket: ", krb5::error_text(ge)); exit(1); }

    var o = smb::options();
    o.require_encryption = true;
    o.ciphers.clear();
    o.ciphers.push(smb::AES256_GCM);
    o.min_dialect = smb::SMB311;
    var c, e = smb::dial(a[1], port, o);
    if e != smb::OK { print("connect: ", smb::error_text(e)); exit(1); }
    var n = 0;
    for t in creds {
        n++;
        if n == creds.len { e = smb::login_kerberos(c, t); }
    }
    if e != smb::OK { print("login: ", smb::error_text(e)); exit(1); }
    print("Kerberos session, ", smb::dialect_name(c.dialect), ", ", smb::cipher_name(c.cipher));
    var t, te2 = smb::tree_connect(c, str("\\\\", a[1], "\\", a[2]));
    if te2 != smb::OK { print("tree connect: ", smb::status_name(c.status)); exit(1); }
    let fs, fe = smb::statfs(c, t);
    if fe == smb::OK { print("free: ", fs.caller_free_units * fs.sectors_per_unit * fs.bytes_per_sector, " bytes"); }
    smb::tree_disconnect(c, t);
    smb::logoff(c);
    smb::hangup(c);
}
