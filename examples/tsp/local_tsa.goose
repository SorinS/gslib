// local_tsa: a time-stamping authority and its client in one program. A
// root CA and a TSA certificate (P-256; the TSA's with the critical
// extended key usage id-kp-timeStamping that RFC 3161 §2.3 asks for), a
// TSA set up with a policy and an accuracy, a request for some data with a
// nonce, the TSA's reply, and the reply checked as a client would: the
// signature, the signingCertificateV2 attribute, the TSA's certificate and
// its path to the root at the time stamped, the imprint and the nonce.
// No network.
//
//   goose examples/tsp/local_tsa.goose

import std;
import os;
import gslib from "../..";
import gslib.tsp;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.pool;
import gslib.encoding.asn1;

let YEAR: i64 = 365 * 86400;

fn main() {
    let now = time_ns() / 1000000000;

    // The root, and the TSA's certificate with its critical EKU.
    let root_key = x509::generate_key(x509::KEY_EC_P256);
    var rt, okr = x509::template("CN=Example Time-Stamping Root,O=Example", now - 60, now + 10 * YEAR);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    assert(okr && er == x509::OK);

    let tsa_key = x509::generate_key(x509::KEY_EC_P256);
    var tt, okt = x509::template("CN=Example TSA,O=Example", now - 60, now + YEAR);
    tt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    var usage: u8[>..] = [];
    asn1::put_oid(usage, tsp::OID_KP_TIME_STAMPING);
    var eku: u8[>..] = [];
    asn1::put(eku, asn1::SEQUENCE, usage);
    x509::put_ext(tt.extra, "2.5.29.37", true, eku);
    let tsa_cert, et = x509::create_certificate(tt, x509::marshal_public_key(tsa_key), root, root_key);
    assert(okt && et == x509::OK);

    // The TSA.
    var t = tsp::Tsa { .. };
    assert(tsp::tsa_init(t, tsa_cert, tsa_key, root, "1.3.6.1.4.1.99999.1") == tsp::OK);
    t.acc_seconds = 1;
    t.precision = 3;
    t.tsa_name = true;

    // A request, its reply, and the reply checked.
    let req, e = tsp::new_request(tsp::SHA256, "the document to time-stamp");
    assert(e == tsp::OK);
    let query, qe = tsp::request_der(req);
    print("request: ", query.len, " bytes, nonce 0x", tsp_hex(req.nonce));
    let reply, status = tsp::respond(t, query, tsp::now_ns());
    print("reply: ", reply.len, " bytes, ", tsp::status_name(status));

    let r, pe = tsp::parse_response(reply);
    assert(pe == tsp::OK);
    var roots = x509::new_pool();
    assert(x509::pool_add(roots, root));
    let o = tsp::VerifyOptions { now: now, .. };
    let info, ve, why = tsp::verify_reply(r, req, roots, "", o);
    if ve != tsp::OK {
        print("not verified: ", tsp::error_text(ve), " ", x509::error_text(why));
        exit(1);
    }
    write_stdout(tsp::info_text(info));
    print("verified");
}

fn tsp_hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    tsp::hex(out, b);
    return out;
}
