// Certify, Re-certify, Validate, Create Split Key and Join Split Key
// against the in-memory server, through kmip.local, in KMIP 1.0 (the
// certificate operations), 1.2, 1.4 and 2.0: certificates for a public key
// the server holds, for PKCS #10 requests and through a private key's
// link; the attributes and links the server sets, Re-certify's names,
// links and dates; chains validated against the server's CA and the
// client's own; keys split by each method and joined from the threshold's
// parts and no fewer; OASIS's TC-SJ-3 parts registered and joined; and
// the ID Placeholder carrying a batch from Create Key Pair to Certify to
// Get.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.client_pki;
import gslib.kmip.local;
import gslib.kmip.server;
import gslib.kmip.server_pki;
import gslib.kmip.split;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

let EMPTY = kmip::attrs();

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn vname(v: kmip::Version) -> u8[>..] {
    var s: u8[>..] = [];
    format_int(s, v.major, 10, 0, ' ');
    s.push('.');
    format_int(s, v.minor, 10, 0, ' ');
    return s;
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// A CA: its certificate and its key in PKCS #8.
fn make_ca(name: const u8[:]) -> u8[>..], u8[>..] {
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template(name, 1000000000, 4000000000);
    t.basic_constraints = true;
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN | x509::KU_DIGITAL_SIGNATURE;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    assert(e == x509::OK);
    return der, x509::marshal_pkcs8(k);
}

fn ca_server(c: kmip::Local&, cert: const u8[:], key: const u8[:]) {
    c.srv.ca_cert.clear();
    c.srv.ca_cert.append(cert);
    c.srv.ca_key.clear();
    c.srv.ca_key.append(key);
}

fn key_pair(c: kmip::Local&, name: const u8[:]) -> u8[>..], u8[>..] {
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
    kmip::attr_curve(common, kmip::CURVE_P_256);
    var priv = kmip::attrs();
    kmip::attr_usage(priv, kmip::USAGE_SIGN);
    kmip::attr_name(priv, name);
    var pub = kmip::attrs();
    kmip::attr_usage(pub, kmip::USAGE_VERIFY);
    let pv, pu, e = kmip::create_key_pair(c, common, priv, pub);
    assert(e == kmip::OK);
    return pv, pu;
}

fn all_attrs(c: kmip::Local&, uid: const u8[:]) -> kmip::Attrs {
    let none: u32[0] = [];
    let a, e = kmip::get_attributes(c, uid, none);
    return a;
}

fn links(a: const kmip::Attrs&, link_type: u32) -> u8[>..] { kmip::link_of(a, link_type) }

fn certificates(c: kmip::Local&, v: kmip::Version, ca: const u8[:], ca_key: const u8[:]) {
    let tag = str(vname(v), ": ");
    ca_server(c, ca, ca_key);
    let pv, pu = key_pair(c, str("key ", vname(v)));

    // For a public key the server holds.
    var a = kmip::attrs();
    kmip::attr_name(a, "the certificate");
    let cu, e1 = kmip::certify(c, pu, "", a);
    check(str(tag, "certify a public key"), e1 == kmip::OK);
    if e1 != kmip::OK { print("  ", kmip::describe(c, e1)); return; }
    let co, eg = kmip::get(c, cu, 0);
    check(str(tag, "get the certificate"), eg == kmip::OK && co.obj_type == kmip::OBJ_CERTIFICATE);
    let cert, pe = x509::parse(co.material);
    let cac, ce = x509::parse(ca);
    check(str(tag, "issued by the CA"), pe == x509::OK && cert.der[cert.issuer.start..cert.issuer.end] == cac.der[cac.subject.start..cac.subject.end]);
    let po, ep = kmip::get(c, pu, 0);
    check(str(tag, "for the public key"), ep == kmip::OK && cert.der[cert.spki.start..cert.spki.end] == po.material[..]);
    check(str(tag, "subject from its Name"), x509::name_text(cert.der, cert.subject) == "CN=the certificate");
    let ca1 = all_attrs(c, cu);
    let ct, ctok = kmip::get_enum(ca1, kmip::TAG_CERTIFICATE_TYPE);
    check(str(tag, "Certificate Type"), ctok && ct == kmip::CERT_X_509);
    if kmip::version_lt(v, kmip::V1_1) {
        check(str(tag, "1.0's Certificate Identifier"), kmip::has_attr(ca1, kmip::TAG_CERTIFICATE_IDENTIFIER) &&
              kmip::has_attr(ca1, kmip::TAG_CERTIFICATE_SUBJECT) && kmip::has_attr(ca1, kmip::TAG_CERTIFICATE_ISSUER));
    } else {
        let cl, clok = kmip::get_int(ca1, kmip::TAG_CERTIFICATE_LENGTH);
        check(str(tag, "Certificate Length"), clok && cl == co.material.len);
        check(str(tag, "X.509 Certificate Identifier, Subject, Issuer"), kmip::has_attr(ca1, kmip::TAG_X_509_CERTIFICATE_IDENTIFIER) &&
              kmip::has_attr(ca1, kmip::TAG_X_509_CERTIFICATE_SUBJECT) && kmip::has_attr(ca1, kmip::TAG_X_509_CERTIFICATE_ISSUER));
    }
    if !kmip::version_lt(v, kmip::V1_2) {
        let sg, sgok = kmip::get_enum(ca1, kmip::TAG_DIGITAL_SIGNATURE_ALGORITHM);
        check(str(tag, "Digital Signature Algorithm"), sgok && sg == kmip::SIG_ECDSA_WITH_SHA256);
    }
    check(str(tag, "the certificate links to its key"), links(ca1, kmip::LINK_PUBLIC_KEY) == pu[..]);
    let pa = all_attrs(c, pu);
    check(str(tag, "the key links to its certificate"), links(pa, kmip::LINK_CERTIFICATE) == cu[..]);

    // From a request, for a key the server has never seen.
    let k = x509::generate_key(x509::KEY_EC_P256);
    let subj, sok = x509::name_der("CN=from a request,O=gslib");
    let csr, ecsr = x509::create_csr(subj, "", k);
    let ru, e2 = kmip::certify(c, "", csr, EMPTY);
    check(str(tag, "certify a request"), e2 == kmip::OK);
    let ro, er = kmip::get(c, ru, 0);
    let rc, rpe = x509::parse(ro.material);
    check(str(tag, "the request's subject and key"), rpe == x509::OK && rc.der[rc.subject.start..rc.subject.end] == subj[..] &&
          rc.der[rc.spki.start..rc.spki.end] == x509::marshal_public_key(k)[..]);
    let e3u, e3 = kmip::certify(c, pu, csr, EMPTY);
    check(str(tag, "a request for another key than the one named"), e3 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_CSR, c.version));
    var bad: u8[>..] = [];
    bad.append(csr);
    bad[bad.len - 3] = bad[bad.len - 3] ^ 1;
    let e4u, e4 = kmip::certify(c, "", bad, EMPTY);
    check(str(tag, "a request whose signature fails"), e4 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_CSR, c.version));
    // Through the private key's Link.
    let vu, e5 = kmip::certify(c, pv, "", EMPTY);
    let vo, ev = kmip::get(c, vu, 0);
    let vc, vpe = x509::parse(vo.material);
    check(str(tag, "certify through the private key"), e5 == kmip::OK && vpe == x509::OK && vc.der[vc.spki.start..vc.spki.end] == po.material[..]);
    check(str(tag, "its subject from the private key's Name"), x509::name_text(vc.der, vc.subject) == str("CN=key ", vname(v)));
    let k2u, ek2 = kmip::create(c, kmip::OBJ_SECRET_DATA, EMPTY);
    let e6u, e6 = kmip::certify(c, k2u, "", EMPTY);
    check(str(tag, "not a public key"), e6 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_OBJECT_TYPE, c.version));

    // Re-certify with an Offset: the names move, the links follow.
    let nu, e7 = kmip::recertify(c, cu, "", 3600, EMPTY);
    check(str(tag, "re-certify"), e7 == kmip::OK);
    let oa = all_attrs(c, cu);
    let na = all_attrs(c, nu);
    check(str(tag, "the old one points at its replacement"), links(oa, kmip::LINK_REPLACEMENT_OBJECT) == nu[..]);
    check(str(tag, "the new one at what it replaced"), links(na, kmip::LINK_REPLACED_OBJECT) == cu[..]);
    check(str(tag, "the name moved"), kmip::get_name(na, 0) == "the certificate" && kmip::get_name(oa, 0).len == 0);
    let pa2 = all_attrs(c, pu);
    check(str(tag, "the key's Link goes to the new one"), links(pa2, kmip::LINK_CERTIFICATE) == nu[..]);
    let ad, adok = kmip::get_datetime(na, kmip::TAG_ACTIVATION_DATE);
    let id, idok = kmip::get_datetime(na, kmip::TAG_INITIAL_DATE);
    check(str(tag, "activated an Offset after it was made"), adok && idok && ad - id == 3600);
    let st, stok = kmip::get_enum(na, kmip::TAG_STATE);
    check(str(tag, "so still Pre-Active"), stok && st == kmip::STATE_PRE_ACTIVE);
    let no, eno = kmip::get(c, nu, 0);
    let nc, npe = x509::parse(no.material);
    check(str(tag, "the same key and subject"), npe == x509::OK && nc.der[nc.spki.start..nc.spki.end] == cert.der[cert.spki.start..cert.spki.end] &&
          nc.der[nc.subject.start..nc.subject.end] == cert.der[cert.subject.start..cert.subject.end]);
    // Without one, the old one's dates; it was active, so the new one is.
    check(str(tag, "activate the request's certificate"), kmip::activate(c, ru) == kmip::OK);
    let n2u, e8 = kmip::recertify(c, ru, csr, -1, EMPTY);
    let n2a = all_attrs(c, n2u);
    let st2, st2ok = kmip::get_enum(n2a, kmip::TAG_STATE);
    check(str(tag, "re-certified with the request, its dates copied, Active"), e8 == kmip::OK && st2ok && st2 == kmip::STATE_ACTIVE);
    let n3u, e9 = kmip::recertify(c, pu, "", -1, EMPTY);
    check(str(tag, "re-certify takes a certificate"), e9 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_OBJECT_TYPE, c.version));

    // Validate.
    let none: u8[..256][0] = [];
    var one: u8[..256][>..] = [];
    var u1: u8[..256] = [];
    u1.append(cu);
    one.push(u1);
    let v1, ev1 = kmip::validate(c, "", one, 0);
    check(str(tag, "validate by identifier, against the server's CA"), ev1 == kmip::OK && v1 == kmip::VALIDITY_VALID);
    var chain: u8[>..] = [];
    chain.append(ca);
    chain.append(ro.material);
    let v2, ev2 = kmip::validate(c, chain, none, 0);
    check(str(tag, "validate a chain given, the CA first"), ev2 == kmip::OK && v2 == kmip::VALIDITY_VALID);
    let v3, ev3 = kmip::validate(c, ro.material, none, 4100000000);
    check(str(tag, "invalid when it has expired"), ev3 == kmip::OK && v3 == kmip::VALIDITY_INVALID);
    let other, other_key = make_ca("CN=another CA");
    var c2 = kmip::local("carol");
    c2.version = v;
    ca_server(c2, other, other_key);
    let v4, ev4 = kmip::validate(c2, ro.material, none, 0);
    check(str(tag, "unknown to a server of another CA"), ev4 == kmip::OK && v4 == kmip::VALIDITY_UNKNOWN);
    let cao = kmip::certificate(ca);
    let regu, ereg = kmip::register(c2, cao, EMPTY);
    let v5, ev5 = kmip::validate(c2, ro.material, none, 0);
    check(str(tag, "valid once the client registers its CA"), ereg == kmip::OK && ev5 == kmip::OK && v5 == kmip::VALIDITY_VALID);
    var tampered: u8[>..] = [];
    tampered.append(ro.material);
    tampered[tampered.len - 5] = tampered[tampered.len - 5] ^ 1;
    let v6, ev6 = kmip::validate(c, tampered, none, 0);
    check(str(tag, "invalid with a bad signature"), ev6 == kmip::OK && v6 == kmip::VALIDITY_INVALID);

    // A server without a CA issues nothing.
    var c3 = kmip::local("dave");
    c3.version = v;
    let p3, q3 = key_pair(c3, "x");
    let e10u, e10 = kmip::certify(c3, q3, "", EMPTY);
    check(str(tag, "no CA: Feature Not Supported"), e10 == kmip::ERR_FAILED && c3.last_reason == kmip::REASON_FEATURE_NOT_SUPPORTED);
}

// The ID Placeholder: Create Key Pair, then Certify and Get naming nothing.
fn placeholder(c: kmip::Local&, v: kmip::Version) {
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
    kmip::attr_curve(common, kmip::CURVE_P_256);
    kmip::attr_usage(common, kmip::USAGE_SIGN | kmip::USAGE_VERIFY);
    // Each key's Name its own: two objects may not share one.
    var private = kmip::attrs();
    kmip::attr_name(private, "batched");
    var out: u8[>..] = [];
    let cred = kmip::no_credential();
    let m = kmip::begin_request(out, v, 3, cred);
    let i1, p1 = kmip::begin_item(out, kmip::OP_CREATE_KEY_PAIR, "");
    kmip::put_template(out, common, v, kmip::TAG_COMMON_TEMPLATE_ATTRIBUTE, kmip::TAG_COMMON_ATTRIBUTES);
    kmip::put_template(out, private, v, kmip::TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE, kmip::TAG_PRIVATE_KEY_ATTRIBUTES);
    kmip::end_item(out, i1, p1);
    let i2, p2 = kmip::begin_item(out, kmip::OP_CERTIFY, "");
    kmip::end_item(out, i2, p2);
    let i3, p3 = kmip::begin_item(out, kmip::OP_GET, "");
    kmip::end_item(out, i3, p3);
    kmip::end(out, m);
    var resp: u8[>..] = [];
    kmip::handle(c.srv, c.owner, out, resp);
    var doc: kmip::Node[>..] = [];
    let root, e = kmip::decode(resp, kmip::Options { .. }, doc);
    let r, pe = kmip::parse_response(resp, doc, root);
    var ok = e == kmip::OK && pe == kmip::OK && r.items.len == 3;
    if ok { for it in r.items { if it.status != kmip::STATUS_SUCCESS { ok = false; } } }
    if ok {
        let t, tok = kmip::child_enum(resp, doc, r.items[2].payload, kmip::TAG_OBJECT_TYPE);
        ok = tok && t == kmip::OBJ_CERTIFICATE;
    }
    check(str(vname(v), ": Create Key Pair, Certify, Get by the ID Placeholder"), ok);
}

fn aes_key(c: kmip::Local&, bits: i32) -> u8[>..] {
    var a = kmip::attrs();
    kmip::attr_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, bits);
    kmip::attr_usage(a, kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    let u, e = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    assert(e == kmip::OK);
    return u;
}

fn pick(uids: const u8[..256][:], which: const i64[:]) -> u8[..256][>..] {
    var out: u8[..256][>..] = [];
    for w in which {
        var n = 0;
        for u in uids { if n == w { out.push(u); } n++; }
    }
    return out;
}

fn split_keys(c: kmip::Local&, v: kmip::Version) {
    let tag = str(vname(v), ": ");
    let ku = aes_key(c, 128);
    let ko, ek = kmip::get(c, ku, 0);
    let parts, e1 = kmip::create_split_key(c, ku, 5, 3, kmip::SPLIT_POLYNOMIAL_SHARING_GF_2_8, "", EMPTY);
    check(str(tag, "split in GF(2^8), 3 of 5"), e1 == kmip::OK && parts.len == 5);
    if e1 != kmip::OK { print("  ", kmip::describe(c, e1)); }
    if parts.len != 5 { return; }
    let p2 = pick(parts, [1]);
    let so, es = kmip::get(c, p2[0], 0);
    check(str(tag, "a part is a Split Key"), es == kmip::OK && so.obj_type == kmip::OBJ_SPLIT_KEY && so.parts == 5 &&
          so.part_id == 2 && so.threshold == 3 && so.split_method == kmip::SPLIT_POLYNOMIAL_SHARING_GF_2_8 &&
          so.alg == kmip::ALG_AES && so.length == 128 && so.material.len == 16 && so.material[..] != ko.material[..]);
    let three = pick(parts, [0, 2, 4]);
    let ju, e2 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, three, 0, EMPTY);
    let jo, ej = kmip::get(c, ju, 0);
    check(str(tag, "parts 1, 3, 5 joined"), e2 == kmip::OK && ej == kmip::OK && jo.material[..] == ko.material[..] && jo.alg == kmip::ALG_AES);
    let other3 = pick(parts, [4, 1, 3]);
    let ju2, e3 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, other3, 0, EMPTY);
    let jo2, ej2 = kmip::get(c, ju2, 0);
    check(str(tag, "parts 5, 2, 4 joined"), e3 == kmip::OK && jo2.material[..] == ko.material[..]);
    let two = pick(parts, [0, 1]);
    let ju3, e4 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, two, 0, EMPTY);
    check(str(tag, "two parts: Cryptographic Failure"), e4 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_CRYPTOGRAPHIC_FAILURE, c.version));
    let twice = pick(parts, [0, 1, 1]);
    let ju4, e5 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, twice, 0, EMPTY);
    check(str(tag, "a part twice"), e5 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_FIELD, c.version));
    // Into secret data.
    let ju5, e6 = kmip::join_split_key(c, kmip::OBJ_SECRET_DATA, three, kmip::SECRET_PASSWORD, EMPTY);
    let so5, es5 = kmip::get(c, ju5, 0);
    check(str(tag, "joined into secret data"), e6 == kmip::OK && so5.obj_type == kmip::OBJ_SECRET_DATA &&
          so5.sub_type == kmip::SECRET_PASSWORD && so5.material[..] == ko.material[..]);

    // XOR: every part needed.
    let xp, e7 = kmip::create_split_key(c, ku, 4, 4, kmip::SPLIT_XOR, "", EMPTY);
    let xj, e8 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, xp, 0, EMPTY);
    let xo, ex = kmip::get(c, xj, 0);
    check(str(tag, "XOR, 4 of 4"), e7 == kmip::OK && e8 == kmip::OK && xo.material[..] == ko.material[..]);
    let xbad, e9 = kmip::create_split_key(c, ku, 4, 2, kmip::SPLIT_XOR, "", EMPTY);
    check(str(tag, "XOR with a threshold below the parts refused"), e9 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_FIELD, c.version));
    let mixed = pick(parts, [0, 2]);
    var mix: u8[..256][>..] = [];
    for u in mixed { mix.push(u); }
    for u in pick(xp, [0]) { mix.push(u); }
    let mj, e10 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, mix, 0, EMPTY);
    check(str(tag, "parts of two splits refused"), e10 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_FIELD, c.version));

    // GF(2^16), and the prime field (2^130 - 5).
    let gp, e11 = kmip::create_split_key(c, ku, 3, 2, kmip::SPLIT_POLYNOMIAL_SHARING_GF_2_16, "", EMPTY);
    let gj, e12 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, pick(gp, [2, 0]), 0, EMPTY);
    let go, eg = kmip::get(c, gj, 0);
    check(str(tag, "GF(2^16), 2 of 3"), e11 == kmip::OK && e12 == kmip::OK && go.material[..] == ko.material[..]);
    let prime = unhex("03fffffffffffffffffffffffffffffffb");
    let pp, e13 = kmip::create_split_key(c, ku, 4, 2, kmip::SPLIT_POLYNOMIAL_SHARING_PRIME_FIELD, prime, EMPTY);
    let ppo, epp = kmip::get(c, pick(pp, [3])[0], 0);
    check(str(tag, "prime field parts at the prime's width"), e13 == kmip::OK && epp == kmip::OK && ppo.material.len == 17 && ppo.prime[..] == prime[..]);
    let pj, e14 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, pick(pp, [3, 1]), 0, EMPTY);
    let pjo, epj = kmip::get(c, pj, 0);
    check(str(tag, "prime field, 2 of 4"), e14 == kmip::OK && pjo.material[..] == ko.material[..]);
    let np, e15 = kmip::create_split_key(c, ku, 4, 2, kmip::SPLIT_POLYNOMIAL_SHARING_PRIME_FIELD, unhex("03fffffffffffffffffffffffffffffffd"), EMPTY);
    check(str(tag, "a Prime Field Size that is not prime refused"), e15 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_FIELD, c.version));

    // A new key, split straight away.
    var na = kmip::attrs();
    kmip::attr_enum(na, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(na, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
    let fresh, e16 = kmip::create_split_key(c, "", 3, 2, kmip::SPLIT_POLYNOMIAL_SHARING_GF_2_8, "", na);
    let fj, e17 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, pick(fresh, [0, 1]), 0, EMPTY);
    let fo, ef = kmip::get(c, fj, 0);
    check(str(tag, "a new AES-256 key split and joined"), e16 == kmip::OK && fresh.len == 3 && e17 == kmip::OK &&
          fo.material.len == 32 && fo.alg == kmip::ALG_AES && fo.length == 256);
    let notkey, e18 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, pick(parts, [0]), 0, EMPTY);
    var mk: u8[..256][>..] = [];
    var ku_fixed: u8[..256] = [];
    ku_fixed.append(ku);
    mk.push(ku_fixed);
    let nk, e19 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, mk, 0, EMPTY);
    check(str(tag, "joining a key that is no Split Key refused"), e19 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_OBJECT_TYPE, c.version));

    // OASIS TC-SJ-3: four registered parts of a 2-of-4 split in GF(2^8).
    let shares = unhex("66C46A7754F94DE420C7B1A7FFF5EC56CF93D1E2A7E593CD5B8D6247F4E5D49CA855B891F61AD9217240D8EC061E37DA803DBAD55CDD329FAD19D99AE2C5A415");
    var reg: u8[..256][>..] = [];
    var x = 0;
    var all_ok = true;
    for k in 4 {
        let sh = shares[k * 16..k * 16 + 16];
        var o = kmip::new_object(kmip::OBJ_SPLIT_KEY);
        o.key_format = kmip::FMT_RAW;
        o.alg = kmip::ALG_AES;
        o.length = 128;
        o.parts = 4;
        o.part_id = (x + 1) as! i32;
        o.threshold = 2;
        o.split_method = kmip::SPLIT_POLYNOMIAL_SHARING_GF_2_8;
        o.material.append(sh);
        let u, e = kmip::register(c, o, EMPTY);
        if e != kmip::OK { all_ok = false; }
        var fixed: u8[..256] = [];
        fixed.append(u);
        reg.push(fixed);
        x++;
    }
    check(str(tag, "TC-SJ-3's parts registered"), all_ok);
    let rj, e20 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, pick(reg, [1, 3]), 0, EMPTY);
    let rjo, erj = kmip::get(c, rj, 0);
    check(str(tag, "TC-SJ-3's parts 2 and 4 joined"), e20 == kmip::OK && rjo.material[..] == unhex("0102030405060708090a0b0c0d0e0f10")[..]);
}

fn main() {
    let ca, ca_key = make_ca("CN=gslib test CA,O=gslib");
    let versions: kmip::Version[4] = [kmip::V1_0, kmip::V1_2, kmip::V1_4, kmip::V2_0];
    for v in versions {
        var c = kmip::local("alice");
        c.version = v;
        certificates(c, v, ca, ca_key);
        placeholder(c, v);
        if kmip::version_lt(v, kmip::V1_2) {
            let p, e = kmip::create_split_key(c, "", 2, 2, kmip::SPLIT_XOR, "", EMPTY);
            check("1.0: no Create Split Key", e == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_OPERATION_NOT_SUPPORTED, c.version));
        } else {
            split_keys(c, v);
        }
    }
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
