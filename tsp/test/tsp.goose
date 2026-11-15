// tsp without a network: requests made and read, GeneralizedTime with
// fractions, replies and their status, failInfo and text (a granted reply
// without a token, a refusal with one, a line end in a status string, all
// refused); a TSA made here (P-256 root and TSA certificate) answering
// requests and its tokens checked: nonce, imprint, policy, certReq both
// ways, accuracy and ordering, the TSA's name, serial numbers, the chain
// at the time stamped; refusals for SHA-1, a policy and an extension not
// taken, and what does not parse; certificates that are not a TSA's (EKU
// not critical, or more than timeStamping) and tokens whose
// signingCertificate does not name the signer, or is missing; ESSCertID
// (v1, SHA-1) and ESSCertIDv2 with an explicit hash; a CMS signature
// time-stamped (RFC 3161 Appendix A); and openssl's own query and replies
// (test/vectors), ESSCertIDv2 and v1, with and without the certificate.
import std;
import os;
import gslib from "../..";
import gslib.tsp;
import gslib.crypto.bignum;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.cms;
import gslib.crypto.x509.pool;
import gslib.encoding.asn1;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

let YEAR:    i64         = 365 * 86400;
let POLICY:  const u8[:] = "1.3.6.1.4.1.99999.1";
let POLICY2: const u8[:] = "1.3.6.1.4.1.99999.2";

fn now() -> i64 { time_ns() / 1000000000 }

// An extendedKeyUsage extension of the OIDs given, critical or not.
fn eku_ext(oids: const u8[:][:], critical: bool) -> u8[>..] {
    var body: u8[>..] = [];
    for o in oids { asn1::put_oid(body, o); }
    var v: u8[>..] = [];
    asn1::put(v, asn1::SEQUENCE, body);
    var out: u8[>..] = [];
    x509::put_ext(out, "2.5.29.37", critical, v);
    return out;
}

fn make_root(key: const x509::PrivateKey&, name: const u8[:]) -> u8[>..] {
    var t, ok = x509::template(name, now() - YEAR, now() + 10 * YEAR);
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let c, e = x509::create_certificate(t, x509::marshal_public_key(key), "", key);
    assert(ok && e == x509::OK);
    return c;
}

fn make_leaf(key: const x509::PrivateKey&, name: const u8[:], ext: const u8[:], ca: const u8[:],
             ca_key: const x509::PrivateKey&, nb: i64, na: i64) -> u8[>..] {
    var t, ok = x509::template(name, nb, na);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.extra.append(ext);
    let c, e = x509::create_certificate(t, x509::marshal_public_key(key), ca, ca_key);
    assert(ok && e == x509::OK);
    return c;
}

fn file(path: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    assert(read_file(path, out));
    return out;
}

fn pem_certs(text: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    for d in ders { out.append(d); }
    return out;
}

// --- Requests -----------------------------------------------------------------------

fn requests() {
    let r, e = tsp::new_request(tsp::SHA256, "hello");
    check("new request", e == tsp::OK && r.hash == 256 && r.imprint[..] == bignum::hash_bits(256, "hello")[..]
          && r.nonce.len == 8 && r.cert_req);
    let der, de = tsp::request_der(r);
    check("request DER", de == tsp::OK);
    let back, be = tsp::parse_request(der);
    check("request read back", be == tsp::OK && back.hash == 256 && back.imprint[..] == r.imprint[..]
          && back.nonce[..] == r.nonce[..] && back.cert_req && back.policy.len == 0 && !back.extensions);
    let r2, e2 = tsp::new_request(tsp::SHA256, "hello");
    check("nonces differ", e2 == tsp::OK && r2.nonce[..] != r.nonce[..]);

    let s1, es1 = tsp::new_request(tsp::SHA1, "x");
    check("SHA-1 refused", es1 == tsp::ERR_UNSUPPORTED);
    let s1b, es1b = tsp::new_request(tsp::SHA1, "x", true, true);
    check("SHA-1 when allowed", es1b == tsp::OK && s1b.imprint.len == 20);
    let bad, ebad = tsp::request_for_digest(tsp::SHA384, bignum::hash_bits(256, "x"));
    check("a digest of the wrong length", ebad == tsp::ERR_ARG);

    var p, ep = tsp::request_for_digest(tsp::SHA512, bignum::hash_bits(512, "x"), false);
    p.policy.append(POLICY);
    p.nonce.clear();
    let pd, epd = tsp::request_der(p);
    let pb, epb = tsp::parse_request(pd);
    check("policy, no nonce, no certReq", epd == tsp::OK && epb == tsp::OK && pb.policy[..] == POLICY && pb.nonce.len == 0
          && !pb.cert_req && pb.hash == 512);
    var q = copy(p);
    q.policy.clear();
    q.policy.append("not an oid");
    let qd, eqd = tsp::request_der(q);
    check("a policy that is not an OID", eqd == tsp::ERR_ARG);

    // By hand: version 2, certReq FALSE written out, an extension, an
    // unknown hash, a nonce too long to keep.
    var imp: u8[>..] = [];
    tsp::put_imprint(imp, tsp::SHA256, bignum::hash_bits(256, "x"));
    for which in 5 {
        var body: u8[>..] = [];
        asn1::put_i64(body, if which == 0 { 2 } else { 1 });
        if which == 3 {
            var alg: u8[>..] = [];
            asn1::put_oid(alg, "1.2.3.4");
            var a2: u8[>..] = [];
            asn1::put(a2, asn1::SEQUENCE, alg);
            asn1::put_octets(a2, bignum::hash_bits(256, "x"));
            asn1::put(body, asn1::SEQUENCE, a2);
        } else {
            body.append(imp);
        }
        if which == 1 { asn1::put_bool(body, false); }
        if which == 2 { asn1::put(body, asn1::ctx(0, true), "\x30\x00"); }
        if which == 4 { var n: u8[>..] = []; n.resize(33, 0x11); asn1::put(body, asn1::INTEGER, n); }
        var d: u8[>..] = [];
        asn1::put(d, asn1::SEQUENCE, body);
        let x, ex = tsp::parse_request(d);
        if which == 0 { check("version 2", ex == tsp::ERR_MALFORMED); }
        if which == 1 { check("certReq FALSE written out", ex == tsp::ERR_MALFORMED); }
        if which == 2 { check("extensions noted", ex == tsp::OK && x.extensions); }
        if which == 3 { check("an unknown hash", ex == tsp::OK && x.hash == 0); }
        if which == 4 { check("a nonce too long", ex == tsp::ERR_MALFORMED); }
    }
    let g, eg = tsp::parse_request("\x30\x03\x02\x01\x01");
    check("no imprint", eg == tsp::ERR_MALFORMED);
}

// --- Times -----------------------------------------------------------------------------

fn times() {
    // 2026-11-15 05:43:43.072 UTC
    let ns: i64 = 1794721423 * 1000000000 + 72000000;
    var out: u8[>..] = [];
    tsp::put_gen_time(out, ns, 3);
    check("genTime, 3 digits", out[2..] == "20261115054343.072Z");
    out.clear();
    tsp::put_gen_time(out, ns, 6);
    check("genTime, trailing zeros dropped", out[2..] == "20261115054343.072Z");
    out.clear();
    tsp::put_gen_time(out, ns, 0);
    check("genTime, whole seconds", out[2..] == "20261115054343Z");
    out.clear();
    tsp::put_gen_time(out, 1794721423 * 1000000000, 3);
    check("genTime, no fraction to write", out[2..] == "20261115054343Z");

    for text in ["20261115054343.072Z", "20261115054343Z", "20261115054343.0720Z", "20261115054343.Z",
                 "20261115054343,5Z", "2026111505434Z", "20261115054343.5"] {
        var d: u8[>..] = [];
        asn1::put(d, asn1::GENERALIZED_TIME, text);
        let t, ok = asn1::parse(d);
        var frac: u8[..32] = [];
        let secs, okt = tsp::read_gen_time(d, t, frac);
        let good = text == "20261115054343.072Z" || text == "20261115054343Z";
        check(str("genTime ", text), okt == good && (!good || secs == 1794721423));
        if text == "20261115054343.072Z" { check("fraction", frac[..] == "072" && tsp::frac_ns(frac) == 72000000); }
    }
}

// --- Replies ----------------------------------------------------------------------------

fn replies() {
    let masks = [tsp::FAIL_BAD_ALG, tsp::FAIL_BAD_REQUEST, tsp::FAIL_BAD_DATA_FORMAT, tsp::FAIL_TIME_NOT_AVAILABLE,
                 tsp::FAIL_UNACCEPTED_POLICY, tsp::FAIL_UNACCEPTED_EXTENSION, tsp::FAIL_ADD_INFO_NOT_AVAILABLE,
                 tsp::FAIL_SYSTEM_FAILURE];
    for m in masks {
        let d = tsp::error_response(tsp::REJECTION, "no", m);
        let r, e = tsp::parse_response(d);
        check(str("failInfo ", tsp::fail_info_text(m)), e == tsp::OK && r.status == tsp::REJECTION && r.fail_info == m
              && r.status_text[..] == "no" && r.token.len == 0);
    }
    check("failInfo names", tsp::fail_info_text(tsp::FAIL_BAD_ALG | tsp::FAIL_SYSTEM_FAILURE) == "badAlg systemFailure");
    let w = tsp::error_response(tsp::WAITING, "", 0);
    let rw, ew = tsp::parse_response(w);
    check("waiting, no text, no failInfo", ew == tsp::OK && rw.status == tsp::WAITING && rw.fail_info == 0
          && rw.status_text.len == 0);
    // Granted without a token.
    let g = tsp::error_response(tsp::GRANTED, "", 0);
    let rg, eg = tsp::parse_response(g);
    check("granted without a token", eg == tsp::ERR_MALFORMED);
    // A refusal with a token.
    var si: u8[>..] = [];
    asn1::put_i64(si, tsp::REJECTION);
    var body: u8[>..] = [];
    asn1::put(body, asn1::SEQUENCE, si);
    asn1::put(body, asn1::SEQUENCE, "\x06\x01\x2a");
    var rt: u8[>..] = [];
    asn1::put(rt, asn1::SEQUENCE, body);
    let rr, er = tsp::parse_response(rt);
    check("a refusal with a token", er == tsp::ERR_MALFORMED);
    // Status strings: a line end, and too long to keep, refused rather than cut.
    let nl = tsp::error_response(tsp::REJECTION, "one\ntwo", 0);
    let rn, en = tsp::parse_response(nl);
    check("a line end in a status string", en == tsp::ERR_MALFORMED);
    var long: u8[>..] = [];
    long.resize(3000, 'a');
    let lr = tsp::error_response(tsp::REJECTION, long, 0);
    let rl, el = tsp::parse_response(lr);
    check("a status string too long", el == tsp::ERR_MALFORMED);
    let st, est = tsp::parse_response("\x30\x05\x30\x03\x02\x01\x09");
    check("a status past 5", est == tsp::ERR_MALFORMED);
}

// --- A TSA of our own -------------------------------------------------------------------

fn tsa_and_tokens() {
    let plain = tsp::VerifyOptions { .. };
    let root_key = x509::generate_key(x509::KEY_EC_P256);
    let root = make_root(root_key, "CN=Goose Test TSA Root,O=Example");
    let tsa_key = x509::generate_key(x509::KEY_EC_P256);
    let ts_only = [tsp::OID_KP_TIME_STAMPING];
    let tsa_cert = make_leaf(tsa_key, "CN=Goose Test TSA,O=Example", eku_ext(ts_only, true), root, root_key,
                             now() - YEAR, now() + YEAR);
    var roots = x509::new_pool();
    check("root pooled", x509::pool_add(roots, root));

    var t = tsp::Tsa { .. };
    check("TSA set up", tsp::tsa_init(t, tsa_cert, tsa_key, root, POLICY) == tsp::OK);
    check("another policy", tsp::tsa_add_policy(t, POLICY2) == tsp::OK);
    check("a policy that is not one", tsp::tsa_add_policy(t, "1..2") == tsp::ERR_ARG);
    check("not its key", tsp::tsa_init(t, tsa_cert, root_key, root, POLICY) == tsp::ERR_ARG);
    check("set up again", tsp::tsa_init(t, tsa_cert, tsa_key, root, POLICY) == tsp::OK);
    t.acc_seconds = 1;
    t.acc_millis = 500;
    t.ordering = true;
    t.tsa_name = true;
    t.precision = 3;
    let o = tsp::VerifyOptions { now: now(), .. };

    let req, e = tsp::new_request(tsp::SHA256, "some data");
    let qd, eq = tsp::request_der(req);
    let reply, status = tsp::respond(t, qd, time_ns());
    check("granted", status == tsp::GRANTED);
    let r, pe = tsp::parse_response(reply);
    check("reply read", pe == tsp::OK && r.status == tsp::GRANTED && r.token.len > 0);
    let info, ve, why = tsp::verify_reply(r, req, roots, "", o);
    check(str("reply verified (", tsp::error_text(ve), " ", x509::error_text(why), ")"), ve == tsp::OK);
    check("what it says", info.version == 1 && info.policy[..] == POLICY && info.hash == 256
          && info.nonce[..] == req.nonce[..] && info.ordering && info.has_accuracy && info.acc_seconds == 1
          && info.acc_millis == 500 && info.acc_micros == -1 && info.tsa.len > 0 && info.serial.len == 16
          && info.gen_time >= now() - 5 && info.gen_time <= now());
    let txt = tsp::info_text(info);
    check("as text", find(txt, "TSA: CN=Goose Test TSA,O=Example") >= 0 && find(txt, "Ordering: yes") >= 0);
    let tv, tve, twhy = tsp::verify_token(r.token, tsp::SHA256, bignum::hash_bits(256, "some data"), roots, "", o);
    check("token verified alone", tve == tsp::OK);
    let tv2, tve2, twhy2 = tsp::verify_token(r.token, tsp::SHA256, bignum::hash_bits(256, "other data"), roots, "", o);
    check("other data", tve2 == tsp::ERR_IMPRINT);
    let tv3, tve3, twhy3 = tsp::verify_token(r.token, tsp::SHA384, bignum::hash_bits(384, "some data"), roots, "", o);
    check("another hash", tve3 == tsp::ERR_IMPRINT);

    // Two replies, two serial numbers; counted ones.
    let reply2, s2 = tsp::respond(t, qd, time_ns());
    let r2, pe2 = tsp::parse_response(reply2);
    let sd2, info2, ie2 = tsp::parse_token(r2.token);
    check("serial numbers differ", ie2 == tsp::OK && info2.serial[..] != info.serial[..]);
    t.next_serial = 255;
    for i in 2 {
        let rc, sc = tsp::respond(t, qd, time_ns());
        let rcp, ec = tsp::parse_response(rc);
        let sdc, ic, iec = tsp::parse_token(rcp.token);
        check("counted serials", iec == tsp::OK && ic.serial[..] == (if i == 0 { "\x00\xff" } else { "\x01\x00" }));
    }

    // Another request's nonce, the policy asked for, the wrong one.
    var other = copy(req);
    other.nonce.clear();
    other.nonce.append("\x01\x02");
    let i3, e3, w3 = tsp::verify_reply(r, other, roots, "", o);
    check("nonce", e3 == tsp::ERR_NONCE);
    var preq = copy(req);
    preq.policy.append(POLICY2);
    let pqd, epq = tsp::request_der(preq);
    let preply, ps = tsp::respond(t, pqd, time_ns());
    let pr, ppe = tsp::parse_response(preply);
    let pinfo, pve, pwhy = tsp::verify_reply(pr, preq, roots, "", o);
    check("the policy asked for", pve == tsp::OK && pinfo.policy[..] == POLICY2);
    var wantp = tsp::VerifyOptions { .. };
    wantp.policy.append(POLICY);
    let pinfo2, pve2, pwhy2 = tsp::verify_reply(pr, preq, roots, "", wantp);
    check("not the policy wanted", pve2 == tsp::ERR_POLICY);
    var badp = copy(req);
    badp.policy.append("1.2.3.4.5");
    let bpd, ebp = tsp::request_der(badp);
    let bpr, bps = tsp::respond(t, bpd, time_ns());
    let bp, ebpp = tsp::parse_response(bpr);
    check("a policy not taken", bps == tsp::REJECTION && bp.fail_info == tsp::FAIL_UNACCEPTED_POLICY);
    let bi, bve, bw = tsp::verify_reply(bp, badp, roots, "", o);
    check("a refusal does not verify", bve == tsp::ERR_REJECTED);

    // SHA-1, an extension, garbage.
    let s1, es1 = tsp::new_request(tsp::SHA1, "x", true, true);
    let s1d, es1d = tsp::request_der(s1);
    let s1r, s1s = tsp::respond(t, s1d, time_ns());
    let s1p, es1p = tsp::parse_response(s1r);
    check("SHA-1 refused by the TSA", s1s == tsp::REJECTION && s1p.fail_info == tsp::FAIL_BAD_ALG);
    t.allow_sha1 = true;
    let s1r2, s1s2 = tsp::respond(t, s1d, time_ns());
    let s1p2, es1p2 = tsp::parse_response(s1r2);
    let s1i, s1e, s1w = tsp::verify_reply(s1p2, s1, roots, "", o);
    check("SHA-1 imprint refused by the client", s1s2 == tsp::GRANTED && s1e == tsp::ERR_UNSUPPORTED);
    var o1 = tsp::VerifyOptions { allow_sha1: true, .. };
    let s1i2, s1e2, s1w2 = tsp::verify_reply(s1p2, s1, roots, "", o1);
    check("SHA-1 imprint when allowed", s1e2 == tsp::OK);
    t.allow_sha1 = false;
    var ext: u8[>..] = [];
    ext.append(qd[2..]);
    asn1::put(ext, asn1::ctx(0, true), "\x30\x00");
    var extd: u8[>..] = [];
    asn1::put(extd, asn1::SEQUENCE, ext);
    let xr, xs = tsp::respond(t, extd, time_ns());
    let xp, exp = tsp::parse_response(xr);
    check("an extension refused", xs == tsp::REJECTION && xp.fail_info == tsp::FAIL_UNACCEPTED_EXTENSION);
    let gr, gs = tsp::respond(t, "garbage", time_ns());
    let gp, egp = tsp::parse_response(gr);
    check("garbage refused", gs == tsp::REJECTION && gp.fail_info == tsp::FAIL_BAD_DATA_FORMAT);

    // certReq false: no certificates in the token; the TSA's from the caller.
    let nreq, en = tsp::new_request(tsp::SHA384, "some data", false);
    let nqd, enq = tsp::request_der(nreq);
    let nrep, ns = tsp::respond(t, nqd, time_ns());
    let nr, enr = tsp::parse_response(nrep);
    let nsd, ninfo, nie = tsp::parse_token(nr.token);
    check("no certificates sent", nie == tsp::OK && x509::cms_certs(nsd).len == 0);
    let n1, ne1, nw1 = tsp::verify_reply(nr, nreq, roots, "", o);
    check("the TSA's certificate needed", ne1 == tsp::ERR_SIGNER);
    let n2, ne2, nw2 = tsp::verify_reply(nr, nreq, roots, tsa_cert, o);
    check("the TSA's certificate given", ne2 == tsp::OK);
    // A request with certReq answered without the certificate.
    var creq = copy(nreq);
    creq.cert_req = true;
    let n3, ne3, nw3 = tsp::verify_reply(nr, creq, roots, tsa_cert, o);
    check("certReq not honoured", ne3 == tsp::ERR_CERT_REQ);

    // Other roots; a time the TSA's certificate was not valid at; the clock.
    let other_key = x509::generate_key(x509::KEY_EC_P256);
    let other_root = make_root(other_key, "CN=Goose Test TSA Root,O=Example");
    var oroots = x509::new_pool();
    check("other root pooled", x509::pool_add(oroots, other_root));
    let c1, ce1, cw1 = tsp::verify_reply(r, req, oroots, "", o);
    check("other roots", ce1 == tsp::ERR_CHAIN && cw1 == x509::ERR_BAD_SIGNATURE);
    let old, olds = tsp::respond(t, qd, (now() - 2 * YEAR) * 1000000000);
    let oldr, eold = tsp::parse_response(old);
    let c2, ce2, cw2 = tsp::verify_reply(oldr, req, roots, "", plain);
    check("before the TSA's certificate", ce2 == tsp::ERR_CHAIN && cw2 == x509::ERR_NOT_YET_VALID);
    let late, lates = tsp::respond(t, qd, (now() - 3600) * 1000000000);
    let later, elate = tsp::parse_response(late);
    let c3, ce3, cw3 = tsp::verify_reply(later, req, roots, "", o);
    check("an hour from the clock", ce3 == tsp::ERR_TIME);
    let c4, ce4, cw4 = tsp::verify_reply(later, req, roots, "", plain);
    check("without the clock", ce4 == tsp::OK);

    // A TSA name that is not the certificate's.
    let rc, rce = x509::parse(root);
    let tst = tsp::tst_info_der(t, req, POLICY, rc, time_ns());
    let tc, tce = x509::parse(tsa_cert);
    var so = x509::CmsSignOptions { .. };
    so.extra_attrs.append(tsp::signing_cert_v2_attr(tc));
    let tok, okt = x509::cms_sign_with(tsp::OID_TST_INFO, tst, tsa_key, tc, "", x509::SIG_ECDSA, 256, so);
    let ni, nne, nnw = tsp::verify_token(tok, tsp::SHA256, req.imprint, roots, "", plain);
    check("another TSA's name", okt && nne == tsp::ERR_TSA_NAME);

    certs_not_a_tsas(root, root_key, roots, tsa_key, tsa_cert);
    signature_stamps(t, roots, root, root_key);
}

// Certificates that are not a TSA's, and signingCertificate attributes
// that do not name the signer.
fn certs_not_a_tsas(root: const u8[:], root_key: const x509::PrivateKey&, roots: const x509::CertPool&,
                    tsa_key: const x509::PrivateKey&, tsa_cert: const u8[:]) {
    let plain = tsp::VerifyOptions { .. };
    let ts_only = [tsp::OID_KP_TIME_STAMPING];
    let ts_and_server = [tsp::OID_KP_TIME_STAMPING, "1.3.6.1.5.5.7.3.1"];
    let noncrit = make_leaf(tsa_key, "CN=Not Critical,O=Example", eku_ext(ts_only, false), root, root_key,
                            now() - YEAR, now() + YEAR);
    let two = make_leaf(tsa_key, "CN=Two Usages,O=Example", eku_ext(ts_and_server, true), root, root_key,
                        now() - YEAR, now() + YEAR);
    let none = make_leaf(tsa_key, "CN=No Usage,O=Example", "", root, root_key, now() - YEAR, now() + YEAR);
    var t = tsp::Tsa { .. };
    check("EKU not critical: no TSA", tsp::tsa_init(t, noncrit, tsa_key, root, POLICY) == tsp::ERR_TSA_CERT);
    check("EKU of two usages: no TSA", tsp::tsa_init(t, two, tsa_key, root, POLICY) == tsp::ERR_TSA_CERT);
    check("no EKU: no TSA", tsp::tsa_init(t, none, tsa_key, root, POLICY) == tsp::ERR_TSA_CERT);
    check("TSA", tsp::tsa_init(t, tsa_cert, tsa_key, root, POLICY) == tsp::OK);

    let req, e = tsp::new_request(tsp::SHA256, "data");
    let tc, tce = x509::parse(tsa_cert);
    let tst = tsp::tst_info_der(t, req, POLICY, tc, time_ns());
    // Signed by certificates that are not a TSA's, each named properly.
    for which in 3 {
        let der = if which == 0 { noncrit[..] } else if which == 1 { two[..] } else { none[..] };
        let c, ce = x509::parse(der);
        var so = x509::CmsSignOptions { .. };
        so.extra_attrs.append(tsp::signing_cert_v2_attr(c));
        let tok, okt = x509::cms_sign_with(tsp::OID_TST_INFO, tst, tsa_key, c, "", x509::SIG_ECDSA, 256, so);
        let i, ve, w = tsp::verify_token(tok, tsp::SHA256, req.imprint, roots, "", plain);
        check(str("signed by a certificate not a TSA's ", which), okt && ve == tsp::ERR_TSA_CERT);
    }
    // signingCertificate: missing; naming another certificate; v1 (SHA-1);
    // v2 with SHA-512 written out; v2 naming the right hash but another
    // serial; v2 by SHA-1, only with allow_sha1.
    for which in 6 {
        var so = x509::CmsSignOptions { .. };
        let cd = tc.der[..];
        if which == 1 {
            let nc, nce = x509::parse(noncrit);
            so.extra_attrs.append(tsp::signing_cert_v2_attr(nc));
        } else if which >= 2 {
            var id: u8[>..] = [];
            if which == 3 { tsp::put_hash_alg(id, 512); }
            if which == 5 { tsp::put_hash_alg(id, tsp::SHA1); }
            asn1::put_octets(id, bignum::hash_bits(if which == 2 || which == 5 { 160 } else if which == 3 { 512 } else { 256 }, cd));
            var gn: u8[>..] = [];
            asn1::put(gn, asn1::ctx(4, true), cd[tc.issuer.start..tc.issuer.end]);
            var is: u8[>..] = [];
            asn1::put(is, asn1::SEQUENCE, gn);
            if which == 4 { asn1::put_i64(is, 12345); } else { is.append(cd[tc.serial.start..tc.serial.end]); }
            asn1::put(id, asn1::SEQUENCE, is);
            var ids: u8[>..] = [];
            asn1::put(ids, asn1::SEQUENCE, id);
            var certs: u8[>..] = [];
            asn1::put(certs, asn1::SEQUENCE, ids);
            var sc: u8[>..] = [];
            asn1::put(sc, asn1::SEQUENCE, certs);
            x509::cms_attr(so.extra_attrs, if which == 2 { tsp::OID_SIGNING_CERT } else { tsp::OID_SIGNING_CERT_V2 }, sc);
        }
        let tok, okt = x509::cms_sign_with(tsp::OID_TST_INFO, tst, tsa_key, tc, "", x509::SIG_ECDSA, 256, so);
        let i, ve, w = tsp::verify_token(tok, tsp::SHA256, req.imprint, roots, "", plain);
        let want = if which == 2 || which == 3 { tsp::OK } else { tsp::ERR_SIGNER };
        check(str("signingCertificate case ", which, ": ", tsp::error_text(ve)), okt && ve == want);
        if which == 5 {
            var sha1 = tsp::VerifyOptions { .. };
            sha1.allow_sha1 = true;
            let i5, ve5, w5 = tsp::verify_token(tok, tsp::SHA256, req.imprint, roots, "", sha1);
            check("ESSCertIDv2 by SHA-1 with allow_sha1", ve5 == tsp::OK);
        }
    }
}

// RFC 3161 Appendix A: a CMS signature time-stamped.
fn signature_stamps(t: tsp::Tsa&, roots: const x509::CertPool&, root: const u8[:], root_key: const x509::PrivateKey&) {
    let plain = tsp::VerifyOptions { .. };
    let sk = x509::generate_key(x509::KEY_EC_P256);
    let signer = make_leaf(sk, "CN=Signer,O=Example", "", root, root_key, now() - YEAR, now() + YEAR);
    let sc, sce = x509::parse(signer);
    let o = x509::CmsSignOptions { .. };
    let cms, oks = x509::cms_sign_with(x509::OID_CMS_DATA, "signed content", sk, sc, "", x509::SIG_ECDSA, 256, o);
    check("CMS signed", oks);
    let sd0, e0 = x509::cms_parse_signed(cms);
    let tk0, te0 = tsp::signature_token(sd0);
    check("no token yet", te0 == tsp::ERR_NO_TOKEN);
    let vi0, ve0, vw0 = tsp::verify_signature_token(cms, roots, "", plain);
    check("no token to verify", ve0 == tsp::ERR_NO_TOKEN);

    let req, e = tsp::signature_request(cms, tsp::SHA256);
    let qd, eq = tsp::request_der(req);
    let reply, st = tsp::respond(t, qd, time_ns());
    let r, pe = tsp::parse_response(reply);
    let i1, ve1, w1 = tsp::verify_reply(r, req, roots, "", plain);
    check("signature's time-stamp granted", e == tsp::OK && ve1 == tsp::OK);
    let stamped, ae = tsp::add_signature_token(cms, r.token);
    check("token added", ae == tsp::OK);
    let sd, pe2 = x509::cms_parse_signed(stamped);
    let c, cve = x509::cms_verify(sd);
    check("the signature still verifies", pe2 == x509::OK && cve == x509::OK);
    let vi, ve, vw = tsp::verify_signature_token(stamped, roots, "", plain);
    check(str("signature time-stamp verified (", tsp::error_text(ve), ")"), ve == tsp::OK);

    // Another signature's token does not fit this one.
    let cms2, oks2 = x509::cms_sign_with(x509::OID_CMS_DATA, "other content", sk, sc, "", x509::SIG_ECDSA, 256, o);
    let wrong, we = tsp::add_signature_token(cms2, r.token);
    let wi, wve, ww = tsp::verify_signature_token(wrong, roots, "", plain);
    check("another signature's token", we == tsp::OK && wve == tsp::ERR_IMPRINT);
    // A second token beside the first: both kept, the signature still good.
    let twice, te2 = tsp::add_signature_token(stamped, r.token);
    let sd2, pe3 = x509::cms_parse_signed(twice);
    let c2, cve2 = x509::cms_verify(sd2);
    let p, okp = asn1::children(sd2.der, sd2.signer);
    let un, oku = asn1::children(sd2.der, p[p.len - 1]);
    check("two unsigned attributes", te2 == tsp::OK && cve2 == x509::OK && oku && un.len == 2);
    let bad, be = tsp::add_signature_token(cms, "not DER");
    check("not a token", be == tsp::ERR_ARG);
}

// --- openssl's (test/vectors: openssl ts -query and -reply) ------------------------------

fn openssl_vectors() {
    let plain = tsp::VerifyOptions { .. };
    let data = file("vectors/data.txt");
    var roots = x509::new_pool();
    check("openssl root", x509::pool_append_pem(roots, file("vectors/openssl_ca.pem")) == 1);
    let tsa = pem_certs(file("vectors/openssl_tsa.pem"));

    let req, e = tsp::parse_request(file("vectors/req.tsq"));
    check("openssl's query", e == tsp::OK && req.hash == 256 && req.cert_req && req.nonce.len >= 8
          && req.imprint[..] == bignum::hash_bits(256, data)[..]);
    for name in ["vectors/resp.tsr", "vectors/resp_v1.tsr"] {
        let r, pe = tsp::parse_response(file(name));
        let info, ve, why = tsp::verify_reply(r, req, roots, "", plain);
        check(str("openssl's reply ", name, " (", tsp::error_text(ve), " ", x509::error_text(why), ")"),
              pe == tsp::OK && ve == tsp::OK);
        check(str("openssl's TSTInfo ", name), info.policy[..] == POLICY && info.ordering && info.acc_seconds == 1
              && info.acc_millis == 500 && info.acc_micros == 100 && info.tsa.len > 0 && info.nonce[..] == req.nonce[..]);
    }
    let nreq, ne = tsp::parse_request(file("vectors/req_nocert.tsq"));
    check("openssl's query without nonce or certReq", ne == tsp::OK && nreq.hash == 384 && !nreq.cert_req && nreq.nonce.len == 0);
    let nr, npe = tsp::parse_response(file("vectors/resp_nocert.tsr"));
    let ni, nve, nwhy = tsp::verify_reply(nr, nreq, roots, "", plain);
    check("openssl's reply without the certificate", nve == tsp::ERR_SIGNER);
    let ni2, nve2, nwhy2 = tsp::verify_reply(nr, nreq, roots, tsa, plain);
    check("openssl's reply, the certificate given", nve2 == tsp::OK);
    let ni3, nve3, nwhy3 = tsp::verify_token(nr.token, tsp::SHA384, bignum::hash_bits(384, data), roots, tsa,
                                             plain);
    check("openssl's token against the data", nve3 == tsp::OK);
}

fn main() {
    requests();
    times();
    replies();
    tsa_and_tokens();
    openssl_vectors();
    print("tsp: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
