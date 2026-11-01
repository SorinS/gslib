// krb5.ldap without a directory: the SASL GSSAPI bind played through
// with this test as the server (our acceptor answering, offering layers,
// checking the client's choice), each layer; then LDAP traffic under the
// integrity and confidentiality layers both ways; a refused bind; SIDs to
// bytes and filters.

import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ccache;
import gslib.krb5.service;
import gslib.krb5.gssapi;
import gslib.krb5.ndr;
import gslib.krb5.ldap;
import gslib.net.ldap;
import gslib.net.ldap.conn;
import gslib.encoding.asn1;
import tv;

let NOW = 1800000000;

// A ticket for HTTP/web.example@EXAMPLE.COM to alice, valid an hour around
// NOW, and its credential.
fn make_cred(svc_key: krb5::Key, sess_etype: i32, flags: u32, start: i64, end: i64) -> krb5::Credential {
    let sess = krb5::random_key(sess_etype);
    let tp = krb5::EncTicketPart {
        flags: flags, key: sess, crealm: "EXAMPLE.COM", cname: krb5::principal_name(1, "alice"), tr_type: 1, transited: "",
        authtime: start, has_starttime: true, starttime: start, endtime: end, has_renew_till: false, renew_till: 0,
        has_caddr: false, caddr: [], has_authz: true, authz: [krb5::AuthData { ad_type: 1, data: "\x30\x00" }],
    };
    var plain: u8[>..] = [];
    krb5::encode_enc_ticket_part(plain, tp);
    var c: u8[>..] = [];
    tv::check_int("ticket encrypt", krb5::encrypt(svc_key, 2, plain, c), krb5::OK);
    let t = krb5::Ticket { realm: "EXAMPLE.COM", sname: krb5::principal_name(1, "HTTP/web.example"),
                           enc_part: krb5::EncryptedData { etype: svc_key.etype, has_kvno: true, kvno: 3, cipher: copy(c) } };
    var der: u8[>..] = [];
    krb5::encode_ticket(der, t);
    return krb5::Credential {
        client_type: 1, client: "alice", client_realm: "EXAMPLE.COM", server_type: 1, server: "HTTP/web.example",
        server_realm: "EXAMPLE.COM", key: sess, authtime: start, starttime: start, endtime: end, renew_till: 0,
        is_skey: false, flags: flags, addresses: [], authdata: [], ticket: der, second_ticket: "",
    };
}

fn keytab_of(k: krb5::Key) -> krb5::KeytabEntry[>..] {
    var kt: krb5::KeytabEntry[>..] = [];
    kt.push(krb5::KeytabEntry { name_type: 1, name: "HTTP/web.example", realm: "EXAMPLE.COM", timestamp: 0, kvno: 3, key: k });
    return kt;
}


// The SASL credentials of a BindRequest the client wrote, and its id.
fn bind_creds(b: const u8[:]) -> i64, u8[>..], bool {
    var creds: u8[>..] = [];
    let t, ok = asn1::parse(b, true);
    let kids, kok = asn1::children(b, t, true);
    if !ok || !kok || kids.len < 2 { return 0, creds, false; }
    let id, iok = asn1::read_i64(b, kids[0], asn1::INTEGER, true);
    let req = kids[1];
    let parts, pok = asn1::children(b, req, true);
    if req.tag != 0x60 || !pok || parts.len < 3 { return id, creds, false; }
    let sasl = parts[2];
    if sasl.tag != 0xa3 { return id, creds, false; }
    let sp, sok = asn1::children(b, sasl, true);
    if !sok || sp.len < 1 { return id, creds, false; }
    if sp.len == 2 { creds.append(b[sp[1].off..sp[1].end]); }
    return id, creds, true;
}

fn bind_response(id: i64, code: i64, creds: const u8[:], has: bool) -> u8[>..] {
    var body: u8[>..] = [];
    asn1::put_i64(body, code, asn1::ENUMERATED);
    asn1::put_octets(body, "");
    asn1::put_octets(body, "");
    if has { asn1::put(body, 0x87, creds); }
    var msg: u8[>..] = [];
    asn1::put_i64(msg, id);
    asn1::put(msg, 0x61, body);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, msg);
    return out;
}

fn search_done(id: i64) -> u8[>..] {
    var body: u8[>..] = [];
    asn1::put_i64(body, 0, asn1::ENUMERATED);
    asn1::put_octets(body, "");
    asn1::put_octets(body, "");
    var msg: u8[>..] = [];
    asn1::put_i64(msg, id);
    asn1::put(msg, 0x65, body);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, msg);
    return out;
}

// Feeds a server message to the client and steps the bind with it.
fn step(s: krb5::SaslGssapi&, c: ldap::Conn&, reply: const u8[:], out: u8[>..]&) -> bool, i64 {
    var msgs: u8[>..] = [];
    let ferr = ldap::feed(c, reply, msgs);
    tv::check_int("feed", ferr, 0);
    var pos = 0;
    let m, ok = ldap::next_message(msgs, pos);
    tv::check("a message", ok);
    return krb5::sasl_gssapi_step(s, c, msgs, m, out);
}

fn bind(what: const u8[:], want: u8, offer: u8) {
    let svc = krb5::random_key(18);
    let kt = keytab_of(svc);
    let cred = make_cred(svc, 18, 0, NOW - 600, NOW + 3000);
    var rc: krb5::ReplayEntry[>..] = [];
    var c = ldap::client();
    var out: u8[>..] = [];
    var s, err = krb5::sasl_gssapi_start(c, cred, want, "u:alice", NOW, 0, out);
    tv::check_int(str(what, " start"), err, krb5::OK);
    // Server: the token, our AP-REP back.
    let id1, tok, ok1 = bind_creds(out);
    tv::check(str(what, " bind request"), ok1 && tok.len > 0);
    var rep: u8[>..] = [];
    var actx, acc, aerr = krb5::gss_accept(tok, kt, false, rc, NOW, 0, 300, "", false, rep);
    tv::check_int(str(what, " accept"), aerr, krb5::OK);
    out.clear();
    let d1, e1 = step(s, c, bind_response(id1, 14, rep, true), out);
    tv::check(str(what, " step 1"), !d1 && e1 == krb5::OK);
    // Server: the empty response; our offer, wrapped.
    let id2, empty, ok2 = bind_creds(out);
    tv::check(str(what, " empty response"), ok2 && empty.len == 0);
    var w: u8[>..] = [];
    let offer_msg: u8[4] = [offer, 0x00, 0x40, 0x00];
    krb5::gss_wrap(actx, offer_msg, false, w);
    out.clear();
    let d2, e2 = step(s, c, bind_response(id2, 14, w, true), out);
    if offer & want == 0 {
        tv::check_int(str(what, " no common layer"), e2, krb5::ERR_MECH);
        return;
    }
    tv::check(str(what, " step 2"), !d2 && e2 == krb5::OK);
    // Server: the client's choice.
    let id3, choice, ok3 = bind_creds(out);
    var plain: u8[>..] = [];
    let sealed, uerr = krb5::gss_unwrap(actx, choice, plain);
    tv::check(str(what, " choice"), uerr == krb5::OK && plain.len == 4 + 7 && plain[4..] == "u:alice");
    let chosen = plain[0];
    tv::check(str(what, " one layer chosen"), chosen == 1 || chosen == 2 || chosen == 4);
    out.clear();
    let d3, e3 = step(s, c, bind_response(id3, 0, "", false), out);
    tv::check(str(what, " done"), d3 && e3 == krb5::OK && s.layer == chosen);
    // Traffic: a search out, its result back, under the layer.
    var sreq: u8[>..] = [];
    let sid = krb5::rootdse_request(c, sreq);
    var wire: u8[>..] = [];
    tv::check_int(str(what, " sasl_out"), krb5::sasl_out(s, sreq, wire), krb5::OK);
    var server = krb5::SaslGssapi { ctx: actx, state: krb5::SASL_DONE, want: 7, layer: chosen, max_out: 0xffffff, bind_id: 0,
                                    authzid: [] };
    var got: u8[>..] = [];
    var pending: u8[>..] = [];
    pending.append(wire);
    let serr = krb5::sasl_in(server, pending, got);
    tv::check_int(str(what, " server unwraps"), serr, krb5::OK);
    tv::check(str(what, " request intact"), got == sreq && (chosen == 1 || wire != sreq));
    var back: u8[>..] = [];
    krb5::sasl_out(server, search_done(sid), back);
    // Delivered in two pieces: the first frame incomplete.
    var cpending: u8[>..] = [];
    var cplain: u8[>..] = [];
    cpending.append(back[..back.len / 2]);
    krb5::sasl_in(s, cpending, cplain);
    tv::check(str(what, " half a frame waits"), cplain.len == 0 || chosen == 1);
    cpending.append(back[back.len / 2..]);
    let cerr = krb5::sasl_in(s, cpending, cplain);
    tv::check_int(str(what, " client unwraps"), cerr, krb5::OK);
    var msgs: u8[>..] = [];
    let ferr = ldap::feed(c, cplain, msgs);
    tv::check_int(str(what, " feed result"), ferr, 0);
    var pos = 0;
    let m, mok = ldap::next_message(msgs, pos);
    tv::check(str(what, " search done"), mok && m.id == sid && ldap::result_code(msgs, m) == 0);
}

fn refused() {
    let svc = krb5::random_key(17);
    let cred = make_cred(svc, 17, 0, NOW - 600, NOW + 3000);
    var c = ldap::client();
    var out: u8[>..] = [];
    var s, err = krb5::sasl_gssapi_start(c, cred, 7, "", NOW, 0, out);
    let id, tok, ok = bind_creds(out);
    out.clear();
    let d, e = step(s, c, bind_response(id, 49, "", false), out);
    tv::check_int("invalid credentials", e, 2049);
    // Success before the layers were agreed is refused.
    var c2 = ldap::client();
    var out2: u8[>..] = [];
    var s2, err2 = krb5::sasl_gssapi_start(c2, cred, 7, "", NOW, 0, out2);
    let id2, tok2, ok2 = bind_creds(out2);
    out2.clear();
    let d2, e2 = step(s2, c2, bind_response(id2, 0, "", false), out2);
    tv::check_int("early success refused", e2, krb5::ERR_CONTEXT);
}

fn sids() {
    for text in ["S-1-5-21-3167651404-3865080224-2280184895-1105", "S-1-5-32-544", "S-1-1-0", "S-1-0x010203040506-7"] {
        let b, ok = krb5::sid_to_bytes(text);
        let back, ok2 = krb5::sid_from_bytes(b);
        tv::check_eq(str("sid round trip ", text), back, text);
    }
    for bad in ["", "S-", "S-1", "X-1-5", "S-1-5-", "S-1-5-x", "S-256-5-1", "S-1-5-4294967296"] {
        let b, ok = krb5::sid_to_bytes(bad);
        tv::check(str("bad sid ", bad), !ok);
    }
    let f, ok = krb5::sid_filter("S-1-5-32-544");
    tv::check_eq("sid filter", f, "(objectSid=\\01\\02\\00\\00\\00\\00\\00\\05\\20\\00\\00\\00\\20\\02\\00\\00)");
    var c = ldap::client();
    var out: u8[>..] = [];
    tv::check("sid search compiles", krb5::sid_lookup_request(c, "DC=x,DC=test", "S-1-5-21-1-2-3-500", out) > 0);
}

fn main() {
    bind("confidentiality", 7, 7);
    bind("integrity", 2, 7);
    bind("integrity offered only", 7, 2);
    bind("no layer", 1, 1);
    bind("no common layer", 4, 2);
    refused();
    sids();
    tv::done("ldap");
}
