// Fuzz target: radius. The first byte picks a path (data[0] % 4), the rest
// is the input:
//   0: the packet parser and what reads a packet: every attribute, the
//      vendor-specific ones, EAP-Message joined, User-Password,
//      Tunnel-Password and the MS-MPPE keys decrypted, MS-CHAP2-Success
//      checked, and the input checked as a request and as an answer.
//   1: EAP's own parsers: the header, EAP-TLS fragments reassembled (the
//      input cut into fragments by a length byte before each), TTLS's
//      Diameter AVPs.
//   2: a server's handle given the input as a request, re-signed with the
//      secret first (when data[0] / 4 is odd) so that the checks after the
//      Message-Authenticator are reached: PAP, CHAP, MS-CHAPv2, accounting,
//      and EAP-MD5 and EAP-MS-CHAPv2 conversations (no TLS method is
//      offered, so no handshake runs).
//   3: a peer (EAP-MD5, or EAP-MS-CHAPv2 when data[0] / 4 is odd) given the
//      input as EAP requests, each with a length byte before it.
// The TLS methods' handshakes are tls's own target's.

import std;
import gslib from "../..";
import gslib.radius;
import gslib.radius.mschap;
import gslib.radius.eap;
import gslib.radius.server;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

let SECRET: const u8[:] = "testing123";
let AUTH: const u8[:] = "0123456789abcdef";

var SRV = radius::server(SECRET);
var CFG_CHAIN: u8[>..] = [];
var CFG_KEY: u8[>..] = [];

fn read_packet(m: const u8[:]) {
    let p, e = radius::parse(m);
    if e != radius::OK { return; }
    let n = radius::attr_count(p);
    for i in n {
        let t, v, ok = radius::attr_at(p, i);
        if !ok { break; }
    }
    let eap = radius::eap_message(p);
    let code, id, len, t, okh = radius::eap_header(eap);
    let pw, okp = radius::password(p, SECRET);
    let tp, tag, okt = radius::tunnel_password(p, SECRET, AUTH);
    let keys, okk = radius::mppe_keys(p, SECRET, AUTH);
    let s, oks = radius::vsa(p, radius::VENDOR_MICROSOFT, radius::MS_CHAP2_SUCCESS);
    let m2 = radius::Mschap2 { auth_ch: [0; 16], peer_ch: [0; 16], nt_resp: [0; 24], hash: [0; 16], ident: 0 };
    let okm = radius::mschap2_success_ok(p, m2, "alice");
    let okc = radius::chap_ok(p, "alice-pw");
    let r1, e1 = radius::check_request(m, SECRET, false);
    var req = radius::request(radius::ACCESS_REQUEST);
    req.id = p.id;
    let r2, e2 = radius::check_response(m, req, SECRET, true);
}

fn eap_parsers(m: const u8[:]) {
    let code, id, len, t, ok = radius::eap_header(m);
    let cc = tls::client_config("", "");
    var l = radius::tls_layer(tls::client(cc));
    var i = 0;
    while i < m.len {
        let n = m[i] as i64;
        let end = ::min(m.len, i + 1 + n);
        let r = radius::layer_take(l, m[i + 1..end]);
        if r == radius::LAYER_BAD { break; }
        if r == radius::LAYER_MESSAGE { radius::layer_reset_in(l); }
        i = end;
    }
    let v, okv = radius::find_avp(m, radius::MS_CHAP2_SUCCESS, radius::VENDOR_MICROSOFT);
    let u, oku = radius::find_avp(m, radius::USER_NAME, 0);
}

fn handle(m: const u8[:], resign: bool) {
    let t, okt = tls::server_config(CFG_CHAIN, CFG_KEY);
    let methods: u8[2] = [radius::EAP_MD5, radius::EAP_MSCHAPV2];
    let cfg = radius::eap_config(methods, t);
    var data: u8[>..] = [];
    data.append(m);
    if resign {
        var p, e = radius::parse(m);
        if e == radius::OK {
            data.clear();
            data.append(radius::sign_request(p, SECRET));
        }
    }
    var reply: u8[>..] = [];
    let req, e = radius::handle(SRV, cfg, data, reply) { user =>
        var pw: u8[>..] = [];
        if user == "alice" { pw.append("alice-pw"); }
        pw
    };
    if reply.len > 0 { read_packet(reply); }
}

fn peer(m: const u8[:], mschap: bool) {
    var pc = radius::peer_config("alice", "alice-pw", if mschap { radius::EAP_MSCHAPV2 } else { radius::EAP_MD5 });
    var p = radius::peer(pc);
    var i = 0;
    while i < m.len {
        let n = m[i] as i64;
        let end = ::min(m.len, i + 1 + n);
        var out: u8[>..] = [];
        let st = radius::peer_step(p, pc, m[i + 1..end], out);
        if st != radius::EAP_SEND { break; }
        i = end;
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let m = data[1..];
    let sel = data[0] % 4;
    let odd = (data[0] / 4) & 1 != 0;
    if sel == 0 { read_packet(m); }
    else if sel == 1 { eap_parsers(m); }
    else if sel == 2 { handle(m, odd); }
    else { peer(m, odd); }
    return 0;
}

fn main() {
    // A certificate for the EAP configuration; no TLS method is offered.
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template("CN=radius.example.com", 1700000000, 2000000000);
    let cert, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    assert(ok && e == x509::OK);
    CFG_CHAIN.append(cert);
    CFG_KEY.append(x509::marshal_pkcs8(k));
}
