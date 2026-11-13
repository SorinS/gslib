// ccache: credential caches, in MIT's FILE format (what kinit writes and
// klist reads). Makes a TGT and a service ticket for alice@EXAMPLE.COM as
// a KDC would (with keys made here, no KDC needed), puts them in a cache
// with a configuration entry, writes it readable by its owner only, reads
// it back, lists it as klist does, and finds the ticket for a service,
// which is not found once it has expired.
//
//   goose examples/krb5/ccache.goose
import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ccache;

let NOW: i64 = 1800000000;

fn temp_path(suffix: const u8[:]) -> u8[>..] {
    var dir: u8[>..] = [];
    if !env("TMPDIR", dir) || dir.len == 0 { dir.append("/tmp"); }
    if dir[dir.len - 1] != '/' { dir.push('/'); }
    return str(dir, "goose-example-", time_ns(), suffix);
}

// A ticket for `server` to alice, encrypted in the server's key, and the
// credential the client keeps for it: the ticket and its session key.
fn issue(server: const u8[:], server_key: krb5::Key, flags: u32, start: i64, end: i64) -> krb5::Credential {
    let session = krb5::random_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96);
    let part = krb5::EncTicketPart {
        flags:          flags, key: session, crealm: "EXAMPLE.COM", cname: krb5::principal_name(krb5::NT_PRINCIPAL, "alice"),
        tr_type:        1, transited: "", authtime: start, has_starttime: true, starttime: start, endtime: end,
        has_renew_till: false, renew_till: 0, has_caddr: false, caddr: [], has_authz: false, authz: [],
    };
    var plain: u8[>..] = [];
    krb5::encode_enc_ticket_part(plain, part);
    var c: u8[>..] = [];
    krb5::encrypt(server_key, krb5::USAGE_KDC_REP_TICKET, plain, c);
    let t = krb5::Ticket { realm: "EXAMPLE.COM", sname: krb5::principal_name(krb5::NT_SRV_INST, server),
                           enc_part: krb5::EncryptedData { etype: server_key.etype, has_kvno: true, kvno: 1, cipher: copy(c) } };
    var der: u8[>..] = [];
    krb5::encode_ticket(der, t);
    return krb5::Credential {
        client_type: krb5::NT_PRINCIPAL, client: "alice", client_realm: "EXAMPLE.COM", server_type: krb5::NT_SRV_INST,
        server:      server, server_realm: "EXAMPLE.COM", key: session, authtime: start, starttime: start, endtime: end,
        renew_till:  0, is_skey: false, flags: flags, addresses: [], authdata: [], ticket: der, second_ticket: "",
    };
}

fn time_text(t: i64) -> u8[>..] {
    var b: u8[>..] = [];
    krb5::put_ktime(b, t);     // DER GeneralizedTime: a tag, a length, YYYYMMDDHHMMSSZ
    var out: u8[>..] = [];
    out.append(b[2..]);
    return out;
}

fn main() {
    let tgt_name = krb5::name_join("krbtgt", "EXAMPLE.COM");
    let initial = krb5::flag(krb5::TKT_INITIAL) | krb5::flag(krb5::TKT_FORWARDABLE) | krb5::flag(krb5::TKT_PRE_AUTHENT);
    let tgt = issue(tgt_name, krb5::random_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96), initial, NOW, NOW + 36000);
    let http = issue("HTTP/web.example.com", krb5::random_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96),
                     krb5::flag(krb5::TKT_FORWARDABLE), NOW + 60, NOW + 36000);

    // A cache for alice: the TGT, the service ticket, and MIT's
    // configuration entry saying the KDC does FAST.
    // (A cache is a frozen value: each step makes a new one.)
    let empty = krb5::ccache_new(krb5::NT_PRINCIPAL, "alice", "EXAMPLE.COM");
    let with_tgt = krb5::ccache_add(empty, tgt);
    let with_http = krb5::ccache_add(with_tgt, http);
    let cc = krb5::ccache_with_config(with_http, "fast_avail", krb5::principal_string(tgt_name, "EXAMPLE.COM"), "yes");

    let path = temp_path(".ccache");
    let name = str("FILE:", path);
    let serr = krb5::ccache_save(name, cc);
    guard serr == krb5::OK else { print("ccache: ", path, ": ", krb5::error_text(serr)); exit(1); }
    let back, lerr = krb5::ccache_load(name);
    delete_file(path);
    guard lerr == krb5::OK else { print("ccache: ", path, ": ", krb5::error_text(lerr)); exit(1); }

    // klist.
    print("Ticket cache: ", name, " (removed)");
    print("Default principal: ", krb5::principal_string(back.principal, back.realm));
    print("Valid starting   Expires          Service principal");
    var n = 0;
    for c in back.creds {
        if krb5::is_config_cred(c) { continue; }
        print(time_text(c.starttime), "  ", time_text(c.endtime), "  ", krb5::principal_string(c.server, c.server_realm),
              "  ", krb5::etype_name(c.key.etype));
        n++;
    }
    let fast, okf = krb5::ccache_config(back, "fast_avail", krb5::principal_string(tgt_name, "EXAMPLE.COM"));
    guard n == 2 && okf && fast == "yes" else { print("ccache: the cache did not read back"); exit(1); }
    print("config fast_avail = ", fast);

    // A program with the cache finds its ticket for the service, with the
    // session key and the ticket's bytes to make an AP-REQ from.
    let found, ok = krb5::ccache_find(back, "HTTP/web.example.com", "EXAMPLE.COM", NOW + 120);
    guard ok && found.key.value == http.key.value && found.ticket == http.ticket else { print("ccache: no HTTP ticket"); exit(1); }
    let t, terr = krb5::decode_ticket(found.ticket);
    guard terr == krb5::OK && t.sname.name == "HTTP/web.example.com" else { print("ccache: the ticket does not decode"); exit(1); }
    print("found ", krb5::principal_string(found.server, found.server_realm), ": ticket of ", found.ticket.len,
          " bytes, encrypted in ", krb5::etype_name(t.enc_part.etype), " kvno ", t.enc_part.kvno);
    let late, ok2 = krb5::ccache_find(back, "HTTP/web.example.com", "EXAMPLE.COM", NOW + 40000);
    guard !ok2 else { print("ccache: an expired ticket was found"); exit(1); }
    print("ten hours later: no ticket (expired)");
}
