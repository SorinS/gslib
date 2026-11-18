// EAP in memory, a peer against a server, for every method: MD5-Challenge,
// MS-CHAPv2, EAP-TLS, PEAP and TTLS (PAP, MS-CHAPv2), over TLS 1.2 and
// 1.3, with small fragments too; both sides agree on the MSK; wrong
// passwords, an unknown user, a peer without a certificate for EAP-TLS, a
// server the peer does not trust, and a Nak to another method.
import std;
import gslib from "../..";
import gslib.radius;
import gslib.radius.mschap;
import gslib.radius.eap;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// Field idx of the line `tag kind ...` (root and clientca lines have no kind).
fn field(tag: const u8[:], kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("vectors/certs.txt"), '\n') {
        let w = words(line);
        if w.len < 2 || w[0] != tag { continue; }
        if tag == "root" || tag == "clientca" { return unhex(w[idx - 1]); }
        if w[1] == kind { return unhex(w[idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

let NOW: i64 = 1800000000;

struct Result { peer: i64, server: i64, peer_msk: u8[..64], server_msk: u8[..64], rounds: i64, identity: u8[..253] }

// A whole conversation: the server starts with Identity; each packet goes
// across until one side is done.
fn run(pc: const radius::PeerConfig&, sc: const radius::EapConfig&, password: const u8[:]) -> Result {
    var p = radius::peer(pc);
    var s = radius::eap_session(sc);
    var res = Result { peer: -1, server: -1, peer_msk: [], server_msk: [], rounds: 0, identity: [] };
    var to_peer: u8[>..] = [];
    radius::server_start(s, to_peer);
    for round in 200 {
        res.rounds = round;
        var to_server: u8[>..] = [];
        let ps = radius::peer_step(p, pc, to_peer, to_server);
        if ps != radius::EAP_SEND { res.peer = ps; break; }
        to_peer.clear();
        let ss = radius::server_step(s, sc, to_server, to_peer) { user =>
            var pw: u8[>..] = [];
            if user == "alice" { pw.append(password); }
            pw
        };
        if ss != radius::EAP_SEND {
            res.server = ss;
            // The peer sees the Success or Failure.
            var none: u8[>..] = [];
            res.peer = radius::peer_step(p, pc, to_peer, none);
            break;
        }
    }
    res.peer_msk.append(radius::peer_msk(p));
    res.server_msk.append(radius::session_msk(s));
    res.identity.append(s.inner_identity);
    return res;
}

fn peer_cfg(method: u8, inner: u8, version: u16, frag: i64) -> radius::PeerConfig {
    var pc = radius::peer_config("alice", "alice-pw", method);
    pc.inner = inner;
    pc.fragment = frag;
    pc.outer_identity.append("anonymous");
    pc.tls = tls::client_config("example.com", field("root", "", 2));
    pc.tls.now = NOW;
    pc.tls.max_version = version;
    return pc;
}

fn server_cfg(methods: const u8[:], frag: i64) -> radius::EapConfig {
    var t, ok = tls::server_config(field("server", "rsa", 2), field("server", "rsa", 3));
    assert(ok);
    t.now = NOW;
    var sc = radius::eap_config(methods, t);
    sc.fragment = frag;
    return sc;
}

fn go(method: u8, inner: u8, v: u16, frag: i64, methods: const u8[:], password: const u8[:]) -> Result {
    let pc = peer_cfg(method, inner, v, frag);
    let sc = server_cfg(methods, frag);
    return run(pc, sc, password);
}

fn version_name(v: u16) -> const u8[:] { if v == tls::VERSION_TLS13 { "TLS 1.3" } else { "TLS 1.2" } }

fn ok_run(what: const u8[:], r: Result, keys: bool) {
    check(str(what, ": both sides succeed"), r.peer == radius::EAP_DONE_OK && r.server == radius::EAP_DONE_OK);
    if keys { check(str(what, ": the same MSK"), r.peer_msk.len == 64 && r.peer_msk == r.server_msk); }
}

fn simple_methods() {
    let md5: u8[1] = [radius::EAP_MD5];
    let r_md5 = go(radius::EAP_MD5, 0, tls::VERSION_TLS13, 1000, md5, "alice-pw");

    ok_run("MD5", r_md5, false);
    let bad = go(radius::EAP_MD5, 0, tls::VERSION_TLS13, 1000, md5, "other");
    check("MD5, wrong password: failure both sides", bad.server == radius::EAP_DONE_FAIL && bad.peer == radius::EAP_DONE_FAIL);
    let ms: u8[1] = [radius::EAP_MSCHAPV2];
    let r_ms = go(radius::EAP_MSCHAPV2, 0, tls::VERSION_TLS13, 1000, ms, "alice-pw");

    ok_run("MS-CHAPv2", r_ms, false);
    check("MS-CHAPv2: the same 32-byte MSK", r_ms.peer_msk.len == 32 && r_ms.peer_msk == r_ms.server_msk);
    let bad2 = go(radius::EAP_MSCHAPV2, 0, tls::VERSION_TLS13, 1000, ms, "other");
    check("MS-CHAPv2, wrong password", bad2.server == radius::EAP_DONE_FAIL && bad2.peer == radius::EAP_DONE_FAIL);
    // The server proposes MD5 first; the peer's Nak picks MS-CHAPv2.
    let both: u8[2] = [radius::EAP_MD5, radius::EAP_MSCHAPV2];
    let r_nak = go(radius::EAP_MSCHAPV2, 0, tls::VERSION_TLS13, 1000, both, "alice-pw");

    ok_run("Nak to MS-CHAPv2", r_nak, false);
    // A Nak to a method the server does not offer.
    let only: u8[1] = [radius::EAP_MD5];
    let nak = go(radius::EAP_PEAP, 0, tls::VERSION_TLS13, 1000, only, "alice-pw");
    check("Nak to a method not offered", nak.server == radius::EAP_DONE_FAIL);
}

fn tls_methods() {
    for v in [tls::VERSION_TLS13, tls::VERSION_TLS12] {
        for frag in [1000, 300] {
            let what = str(version_name(v), ", fragments of ", frag);
            let peap: u8[1] = [radius::EAP_PEAP];
            let rp = go(radius::EAP_PEAP, 0, v, frag, peap, "alice-pw");
            ok_run(str("PEAP ", what), rp, true);
            check(str("PEAP ", what, ": the inner identity"), rp.identity == "alice");
            let ttls: u8[1] = [radius::EAP_TTLS];
            let r_pap = go(radius::EAP_TTLS, radius::INNER_PAP, v, frag, ttls, "alice-pw");

            ok_run(str("TTLS/PAP ", what), r_pap, true);
            let r_ttls_ms = go(radius::EAP_TTLS, radius::INNER_MSCHAPV2, v, frag, ttls, "alice-pw");

            ok_run(str("TTLS/MS-CHAPv2 ", what), r_ttls_ms, true);

            // EAP-TLS: a client certificate, required and checked.
            var pc = peer_cfg(radius::EAP_TLS, 0, v, frag);
            check("client certificate", tls::set_client_certificate(pc.tls, field("client", "p256", 2), field("client", "p256", 3)));
            let et: u8[1] = [radius::EAP_TLS];
            var sc = server_cfg(et, frag);
            sc.tls.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
            check("client CA", x509::pool_add(sc.tls.client_cas, field("clientca", "", 2)));
            let r_tls = run(pc, sc, "");
            ok_run(str("EAP-TLS ", what), r_tls, true);
            // Without a certificate the server refuses it.
            let pc2 = peer_cfg(radius::EAP_TLS, 0, v, frag);
            let nocert = run(pc2, sc, "");
            check(str("EAP-TLS without a certificate ", what), nocert.server == radius::EAP_DONE_FAIL && nocert.peer == radius::EAP_DONE_FAIL);
        }
        let what = version_name(v);
        // Wrong passwords inside the tunnels.
        let peap: u8[1] = [radius::EAP_PEAP];
        let bp = go(radius::EAP_PEAP, 0, v, 1000, peap, "other");
        check(str("PEAP, wrong password, ", what), bp.server == radius::EAP_DONE_FAIL && bp.peer == radius::EAP_DONE_FAIL);
        let ttls: u8[1] = [radius::EAP_TTLS];
        let bt = go(radius::EAP_TTLS, radius::INNER_PAP, v, 1000, ttls, "other");
        check(str("TTLS/PAP, wrong password, ", what), bt.server == radius::EAP_DONE_FAIL && bt.peer == radius::EAP_DONE_FAIL);
        let bm = go(radius::EAP_TTLS, radius::INNER_MSCHAPV2, v, 1000, ttls, "other");
        check(str("TTLS/MS-CHAPv2, wrong password, ", what), bm.server == radius::EAP_DONE_FAIL && bm.peer == radius::EAP_DONE_FAIL);
        // A server the peer does not trust: its own CA is another.
        var pc = peer_cfg(radius::EAP_PEAP, 0, v, 1000);
        pc.tls = tls::client_config("example.com", field("clientca", "", 2));
        pc.tls.now = NOW;
        pc.tls.max_version = v;
        let sc = server_cfg(peap, 1000);
        let untrusted = run(pc, sc, "alice-pw");
        check(str("PEAP, untrusted server, ", what), untrusted.peer == radius::EAP_DONE_FAIL && untrusted.server != radius::EAP_DONE_OK);
    }
}

fn hostile() {
    // A Success before any method: the peer refuses it.
    var pc = peer_cfg(radius::EAP_PEAP, 0, tls::VERSION_TLS13, 1000);
    var p = radius::peer(pc);
    var out: u8[>..] = [];
    let succ = radius::eap_packet(radius::EAP_SUCCESS, 1, 0, "");
    check("early Success refused", radius::peer_step(p, pc, succ, out) == radius::EAP_DONE_FAIL);
    // Truncated and inconsistent packets.
    var p2 = radius::peer(pc);
    let trunc: u8[3] = [1, 1, 0];
    check("truncated", radius::peer_step(p2, pc, trunc, out) == radius::EAP_DONE_FAIL);
    let longer: u8[6] = [1, 1, 0, 9, 1, 0];
    var p3 = radius::peer(pc);
    check("length past the bytes", radius::peer_step(p3, pc, longer, out) == radius::EAP_DONE_FAIL);
    // EAP-TLS fragments longer than their stated total.
    var l = radius::tls_layer(tls::client(pc.tls));
    let frag: u8[9] = [0xc0, 0, 0, 0, 2, 1, 2, 3, 4];
    check("fragment past its total", radius::layer_take(l, frag) == radius::LAYER_BAD);
}

fn main() {
    simple_methods();
    tls_methods();
    hostile();
    print("eap: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
