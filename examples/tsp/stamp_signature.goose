// stamp_signature: a CMS signature that outlives its certificate, as RFC
// 3161 Appendix A has it. Some content is signed (CMS SignedData), the
// signature value is time-stamped by a TSA (here one in the program), and
// the token goes into the SignerInfo's unsigned attributes as
// id-aa-signatureTimeStampToken. Afterwards the signature still verifies
// (unsigned attributes are outside it), and the token proves the
// signature existed at its time. No network.
//
//   goose examples/tsp/stamp_signature.goose

import std;
import os;
import gslib from "../..";
import gslib.tsp;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.cms;
import gslib.crypto.x509.pool;
import gslib.encoding.asn1;

let YEAR: i64 = 365 * 86400;

fn issue(key: const x509::PrivateKey&, name: const u8[:], tsa: bool, root: const u8[:],
         root_key: const x509::PrivateKey&, now: i64) -> u8[>..] {
    var t, ok = x509::template(name, now - 60, now + YEAR);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    if tsa {
        var usage: u8[>..] = [];
        asn1::put_oid(usage, tsp::OID_KP_TIME_STAMPING);
        var eku: u8[>..] = [];
        asn1::put(eku, asn1::SEQUENCE, usage);
        x509::put_ext(t.extra, "2.5.29.37", true, eku);
    }
    let c, e = x509::create_certificate(t, x509::marshal_public_key(key), root, root_key);
    assert(ok && e == x509::OK);
    return c;
}

fn main() {
    let now = time_ns() / 1000000000;
    let root_key = x509::generate_key(x509::KEY_EC_P256);
    var rt, okr = x509::template("CN=Example Root,O=Example", now - 60, now + 10 * YEAR);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    assert(okr && er == x509::OK);
    var roots = x509::new_pool();
    assert(x509::pool_add(roots, root));

    // The signature.
    let signer_key = x509::generate_key(x509::KEY_EC_P256);
    let signer_der = issue(signer_key, "CN=Example Signer,O=Example", false, root, root_key, now);
    let signer, ep = x509::parse(signer_der);
    let so = x509::CmsSignOptions { .. };
    let cms, oks = x509::cms_sign_with(x509::OID_CMS_DATA, "a contract", signer_key, signer, "", x509::SIG_ECDSA, 256, so);
    assert(oks);
    print("signed: ", cms.len, " bytes");

    // Its time-stamp, from a TSA.
    let tsa_key = x509::generate_key(x509::KEY_EC_P256);
    let tsa_cert = issue(tsa_key, "CN=Example TSA,O=Example", true, root, root_key, now);
    var t = tsp::Tsa { .. };
    assert(tsp::tsa_init(t, tsa_cert, tsa_key, root, "1.3.6.1.4.1.99999.1") == tsp::OK);
    let req, e = tsp::signature_request(cms, tsp::SHA256);
    let query, qe = tsp::request_der(req);
    let reply, status = tsp::respond(t, query, tsp::now_ns());
    let r, pe = tsp::parse_response(reply);
    assert(e == tsp::OK && pe == tsp::OK && status == tsp::GRANTED);

    // Into the signature, and checked.
    let stamped, ae = tsp::add_signature_token(cms, r.token);
    assert(ae == tsp::OK);
    print("time-stamped: ", stamped.len, " bytes");
    let sd, sde = x509::cms_parse_signed(stamped);
    let c, ce = x509::cms_verify(sd);
    print("signature: ", x509::error_text(ce));
    let o = tsp::VerifyOptions { .. };
    let info, ve, why = tsp::verify_signature_token(stamped, roots, "", o);
    print("time-stamp: ", tsp::error_text(ve), ", at ", info.gen_time, " (seconds since 1970)");
    assert(ce == x509::OK && ve == tsp::OK);
}
