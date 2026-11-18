// eap_in_memory: 802.1X's authentication from end to end in one program,
// no network: a supplicant (radius::peer) and a RADIUS server (radius::
// handle, with its EAP server) trade packets as a NAS would carry them,
// EAP inside RADIUS Access-Requests and Access-Challenges with their
// State. First PEAP with MS-CHAPv2 inside, then EAP-TLS with a client
// certificate, each over TLS 1.3; both end with the Access-Accept's
// MS-MPPE keys equal to the supplicant's MSK, the key 802.1X's port
// encryption starts from. Certificates are made here, a CA and two leaves.
//
//   goose examples/radius/eap_in_memory.goose

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

fn die(what: const u8[:]) { print("eap_in_memory: ", what); exit(1); }

// A certificate for `name` signed by the CA (self-signed when ca_key is
// the key itself), with the extended key usage TLS wants.
fn issue(name: const u8[:], k: const x509::PrivateKey&, ca_cert: const u8[:], ca_key: const x509::PrivateKey&,
         is_ca: bool, server: bool) -> u8[>..] {
    let now = time_ns() / 1000000000;
    var t, ok = x509::template(str("CN=", name), now - 60, now + 86400);
    t.is_ca = is_ca;
    if is_ca { t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN; }
    else {
        t.key_usage = x509::KU_DIGITAL_SIGNATURE;
        t.ext_key_usage = if server { x509::EKU_SERVER_AUTH } else { x509::EKU_CLIENT_AUTH };
        if server { x509::add_dns(t.san, name); }
    }
    let c, e = x509::create_certificate(t, x509::marshal_public_key(k), ca_cert, ca_key);
    if !ok || e != x509::OK { die(str("certificate for ", name)); }
    return c;
}

// One conversation through the server, as a NAS carries it; the
// Access-Accept's MS-MPPE keys against the supplicant's MSK.
fn authenticate(srv: radius::Server&, cfg: const radius::EapConfig&, pc: const radius::PeerConfig&) {
    var p = radius::peer(pc);
    var eap: u8[>..] = [];
    let start = radius::eap_packet(radius::EAP_REQUEST, 0, radius::EAP_IDENTITY, "");
    radius::peer_step(p, pc, start, eap);
    var state: u8[>..] = [];
    var rounds = 0;
    loop {
        rounds++;
        var req = radius::request(radius::ACCESS_REQUEST);
        radius::add(req, radius::USER_NAME, "anonymous");
        radius::set_eap(req, eap);
        if state.len > 0 { radius::add(req, radius::STATE, state); }
        let wire = radius::sign_request(req, SECRET);
        var reply: u8[>..] = [];
        let got, e = radius::handle(srv, cfg, wire, reply) { user =>
            var pw: u8[>..] = [];
            if user == "alice" { pw.append("alice-pw"); }
            pw
        };
        let resp, er = radius::check_response(reply, req, SECRET, true);
        if e != radius::OK || er != radius::OK { die("the server's answer"); }
        let msg = radius::eap_message(resp);
        if resp.code == radius::ACCESS_CHALLENGE {
            let st, has = radius::get(resp, radius::STATE);
            state.clear();
            state.append(st);
            eap.clear();
            if radius::peer_step(p, pc, msg, eap) != radius::EAP_SEND { die("the supplicant gave up"); }
            continue;
        }
        var none: u8[>..] = [];
        let r = radius::peer_step(p, pc, msg, none);
        let keys, okk = radius::mppe_keys(resp, SECRET, req.auth);
        let msk = radius::peer_msk(p);
        print(radius::eap_type_name(pc.method), ": ", radius::code_name(resp.code), " after ", rounds,
              " round trips, TLS 1.", if tls::version(p.layer.conn) == tls::VERSION_TLS13 { 3 } else { 2 },
              ", MS-MPPE keys ", if okk && keys[..] == msk[..] { "= the supplicant's MSK" } else { "WRONG" });
        if resp.code != radius::ACCESS_ACCEPT || r != radius::EAP_DONE_OK { exit(1); }
        return;
    }
}

fn main() {
    let ca_key = x509::generate_key(x509::KEY_EC_P256);
    let none: u8[0] = [];
    let ca = issue("Example RADIUS CA", ca_key, none, ca_key, true, false);
    let srv_key = x509::generate_key(x509::KEY_EC_P256);
    let srv_cert = issue("radius.example.com", srv_key, ca, ca_key, false, true);
    let cli_key = x509::generate_key(x509::KEY_EC_P256);
    let cli_cert = issue("alice", cli_key, ca, ca_key, false, false);

    // The server: PEAP, TTLS and EAP-TLS, client certificates from the CA.
    var chain: u8[>..] = [];
    chain.append(srv_cert);
    chain.append(ca);
    var t, okt = tls::server_config(chain, x509::marshal_pkcs8(srv_key));
    if !okt { die("server_config"); }
    t.client_auth = tls::VERIFY_CLIENT_CERT_IF_GIVEN;
    if !x509::pool_add(t.client_cas, ca) { die("the CA"); }
    let methods: u8[3] = [radius::EAP_PEAP, radius::EAP_TTLS, radius::EAP_TLS];
    let cfg = radius::eap_config(methods, t);
    var srv = radius::server(SECRET);

    // PEAP: the outer identity anonymous, alice's inside the tunnel.
    var peap = radius::peer_config("alice", "alice-pw", radius::EAP_PEAP);
    peap.outer_identity.append("anonymous");
    peap.tls = tls::client_config("radius.example.com", ca);
    authenticate(srv, cfg, peap);

    // EAP-TLS: alice's certificate is the credential. The server proposes
    // PEAP first; the supplicant's Nak asks for EAP-TLS instead.
    var etls = radius::peer_config("alice", "", radius::EAP_TLS);
    etls.tls = tls::client_config("radius.example.com", ca);
    if !tls::set_client_certificate(etls.tls, cli_cert, x509::marshal_pkcs8(cli_key)) { die("client certificate"); }
    authenticate(srv, cfg, etls);
}
