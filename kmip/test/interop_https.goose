// kmip's client over HTTPS (kmip.https) against goose-kmipd --http:
// test/scenario.goose's checks, the messages in TTLV, XML or JSON.
// scripts/interop.py runs it.
//
//   goose interop_https.goose -- HOST PORT CERTS ENCODING VERSION RUN
//
// CERTS as for interop_client.goose; ENCODING is ttlv, xml or json.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.https;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.encoding.asn1;
import scenario;

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    var out: u8[>..] = [];
    if !read_file(path, text) { return out; }
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    return out;
}

fn main() {
    let a = args();
    guard a.len >= 7 else { print("usage: interop_https HOST PORT CERTS ENCODING VERSION RUN"); exit(2); }
    let port, pok = parse_int(a[2], 10);
    let dir = a[3];
    let enc = if a[4] == "xml" { kmip::MSG_XML } else if a[4] == "json" { kmip::MSG_JSON } else { kmip::MSG_TTLV };
    scenario::verbose = true;
    var cc = kmip::tls_config("kmip.example.com", pem_der(str(dir, "/ca.pem"), "CERTIFICATE"));
    let certok = tls::set_client_certificate(cc, pem_der(str(dir, "/client.pem"), "CERTIFICATE"),
                                             pem_der(str(dir, "/client.key"), "PRIVATE KEY"));
    scenario::check("client certificate", certok);
    var c, e = kmip::https_dial(a[1], port, "/kmip", enc, cc);
    if scenario::check_e(c, "dial", e) {
        scenario::run(c, a[5], a[6]);
        kmip::close(c);
    }
    print(scenario::checks, " checks, ", scenario::failures, " failures");
    if scenario::failures > 0 { exit(1); }
}
