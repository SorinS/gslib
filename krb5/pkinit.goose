// krb5.pkinit: PKINIT (RFC 4556), the client's side: a TGT from an X.509
// certificate and its key instead of a password, or anonymously (RFC
// 8062), the reply key agreed by Diffie-Hellman.
//
// The exchange. The KDC lists PA-PK-AS-REQ in its PREAUTH_REQUIRED error,
// with a freshness token (RFC 8070) when it has one. The client sends an
// AuthPack in a CMS SignedData signed by its key, its certificate (and
// those up to its CA) beside it: a PKAuthenticator (time, a nonce, the
// SHA-1 of the KDC-REQ-BODY, the freshness token), its Diffie-Hellman
// public value with the group's parameters, the signature algorithms it
// takes and the KDFs (RFC 8636). The KDC answers with a PA-PK-AS-REP: its
// public value and our nonce in a SignedData signed by the KDC's key, and
// the KDF it picked. The reply key is that KDF over the shared secret
// (with the client's and the KDC's names, the request and the reply in
// it), or RFC 4556's octetstring2key when the KDC names none.
//
// The groups: MODP 2048 and 4096 (RFC 3526 groups 14 and 16, as MIT
// names them by size), P-256, P-384 and P-521 (RFC 5349; the secret is
// the shared point's x-coordinate). MIT's pkinit_dh_min_bits picks the
// group to start with; a KDC that refuses it (DH_KEY_PARAMETERS_NOT_
// ACCEPTED) lists those it takes, and the client takes the first of them
// that is no weaker. The KDC's value is checked: a MODP value in [2, p-2]
// and in the subgroup of order q; an EC point on the curve.
//
// The KDC's certificate must chain to an anchor (pkinit_anchors, with
// the SignedData's other certificates and pkinit_pool as intermediates)
// and name the KDC: an id-pkinit-san of krbtgt/REALM@REALM, or (with
// pkinit_kdc_hostname) a dNSName of that host and then the EKU that
// pkinit_eku_checking asks for (id-pkinit-KPKdc by default; kpServerAuth;
// none), as MIT checks it. Its signature is SHA-256, -384 or -512.
//
// Not done: RSA key transport (encKeyPack; MIT 1.22's KDC refuses it),
// reused DH keys (clientDHNonce), smart cards (PKCS #11).

namespace krb5;

import std;
import os;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.hmac;
import crypto.bignum.ffdh;
import crypto.bignum.ec;
import crypto.x509;
import crypto.x509.keys;
import crypto.x509.cms;
import crypto.x509.verify;
import crypto.x509.pkcs12;
import krb5.crypto;
import krb5.messages;
import krb5.config;
import krb5.fast;

let OID_PKINIT_AUTH_DATA: const u8[:] = "1.3.6.1.5.2.3.1";
let OID_PKINIT_DH_KEY_DATA: const u8[:] = "1.3.6.1.5.2.3.2";
let OID_PKINIT_KP_CLIENT_AUTH: const u8[:] = "1.3.6.1.5.2.3.4";
let OID_PKINIT_KP_KDC: const u8[:] = "1.3.6.1.5.2.3.5";
let OID_PKINIT_SAN: const u8[:] = "1.3.6.1.5.2.2";
let OID_KP_SERVER_AUTH: const u8[:] = "1.3.6.1.5.5.7.3.1";
let OID_DH_PUBLIC_NUMBER: const u8[:] = "1.2.840.10046.2.1";
let OID_EC_PUBLIC_KEY: const u8[:] = "1.2.840.10045.2.1";

// The KDFs of RFC 8636, by the hash each uses (160 for SHA-1), and 0 for
// RFC 4556's octetstring2key.
let PKINIT_KDF_OLD: i64 = 0;

fn pkinit_kdf_oid(h: i64) -> const u8[:] {
    if h == 160 { "1.3.6.1.5.2.3.6.1" } else if h == 256 { "1.3.6.1.5.2.3.6.2" }
    else if h == 512 { "1.3.6.1.5.2.3.6.3" } else { "1.3.6.1.5.2.3.6.4" }
}

// The KDF an OID names, or -1.
fn pkinit_kdf_of(der: const u8[:], t: asn1::Tlv) -> i64 {
    let hs: i64[4] = [160, 256, 512, 384];
    for h in hs { if asn1::oid_is(der, t, pkinit_kdf_oid(h)) { return h; } }
    return -1;
}

// The KDFs offered, in preference order: SHA-256 first (RFC 8636 §6
// requires it), then SHA-512, SHA-384, SHA-1.
fn pkinit_default_kdfs() -> i64[>..] {
    var k: i64[>..] = [];
    k.push(256);
    k.push(512);
    k.push(384);
    k.push(160);
    return k;
}

// --- Groups -------------------------------------------------------------------

// By MIT's order of strength: 2048, P-256, 4096, P-384, P-521.
let PKINIT_MODP2048: i64 = 1;
let PKINIT_P256: i64 = 2;
let PKINIT_MODP4096: i64 = 3;
let PKINIT_P384: i64 = 4;
let PKINIT_P521: i64 = 5;

fn pkinit_is_ec(g: i64) -> bool { g == PKINIT_P256 || g == PKINIT_P384 || g == PKINIT_P521 }

// pkinit_dh_min_bits as MIT reads it: 1024 is taken as 2048 (no 1024-bit
// group here); anything unknown is 2048, MIT's default.
fn pkinit_group_named(s: const u8[:]) -> i64 {
    if s == "P-256" || s == "p-256" { return PKINIT_P256; }
    if s == "4096" { return PKINIT_MODP4096; }
    if s == "P-384" || s == "p-384" { return PKINIT_P384; }
    if s == "P-521" || s == "p-521" { return PKINIT_P521; }
    return PKINIT_MODP2048;
}

fn pkinit_curve(g: i64) -> bignum::Curve {
    if g == PKINIT_P256 { return bignum::p256(); }
    if g == PKINIT_P384 { return bignum::p384(); }
    return bignum::p521();
}

fn pkinit_curve_oid(g: i64) -> const u8[:] {
    if g == PKINIT_P256 { "1.2.840.10045.3.1.7" } else if g == PKINIT_P384 { "1.3.132.0.34" } else { "1.3.132.0.35" }
}

fn pkinit_prime(g: i64) -> u8[>..] { bignum::ffdh_prime(if g == PKINIT_MODP2048 { 14 } else { 16 }) }

// (p - 1) / 2 of a prime p (odd, big-endian).
fn pkinit_half(p: const u8[:]) -> u8[>..] {
    var q: u8[>..] = [];
    q.resize(p.len, 0);
    var carry: u8 = 0;
    for i in p.len {
        q[i] = (p[i] >> 1) | carry;
        carry = (p[i] & 1) << 7;
    }
    return q;
}

// A Diffie-Hellman key pair of ours: the group, the private value, and
// the SubjectPublicKeyInfo that carries the public one.
struct PkinitDh { group: i64, private: u8[], spki: u8[] }

fn pkinit_dh_none() -> PkinitDh { PkinitDh { group: 0, private: "", spki: "" } }

fn pkinit_dh_new(g: i64) -> PkinitDh {
    var alg: u8[>..] = [];
    var bits: u8[>..] = [];
    var priv: u8[>..] = [];
    if pkinit_is_ec(g) {
        let c = pkinit_curve(g);
        let sk, pk = bignum::ec_keypair(c);
        priv.append(sk);
        asn1::put_oid(alg, OID_EC_PUBLIC_KEY);
        asn1::put_oid(alg, pkinit_curve_oid(g));
        bits.append(pk);
    } else {
        // RFC 3279's DomainParameters: p, g, q (q is required).
        let p = pkinit_prime(g);
        // Secret exponents of twice the group's strength (RFC 7919 §5.2).
        let x, y = bignum::ffdh_keygen(p, if g == PKINIT_MODP2048 { 32 } else { 64 });
        priv.append(x);
        var params: u8[>..] = [];
        asn1::put_uint(params, p);
        let two: u8[1] = [2];
        asn1::put_uint(params, two);
        asn1::put_uint(params, pkinit_half(p));
        asn1::put_oid(alg, OID_DH_PUBLIC_NUMBER);
        asn1::put(alg, asn1::SEQUENCE, params);
        asn1::put_uint(bits, y);
    }
    var algid: u8[>..] = [];
    asn1::put(algid, asn1::SEQUENCE, alg);
    asn1::put_bits(algid, bits);
    var spki: u8[>..] = [];
    asn1::put(spki, asn1::SEQUENCE, algid);
    return PkinitDh { group: g, private: priv, spki: spki };
}

// The shared secret with the KDC's public value (the content of
// KDCDHKeyInfo's subjectPublicKey: a DER INTEGER for MODP, a point for
// EC): MODP's padded to the prime's length, EC's the x-coordinate. False
// for a value out of range or out of the subgroup, or not on the curve.
fn pkinit_dh_shared(dh: const PkinitDh&, kdc_value: const u8[:]) -> u8[>..], bool {
    var none: u8[>..] = [];
    if pkinit_is_ec(dh.group) {
        let c = pkinit_curve(dh.group);
        let z, ok = bignum::ecdh_shared(c, dh.private, kdc_value);
        return z, ok;
    }
    let t, okt = asn1::parse(kdc_value);
    if !okt || t.tag != asn1::INTEGER { return none, false; }
    let y, oky = asn1::read_uint(kdc_value, t);
    let p = pkinit_prime(dh.group);
    if !oky || y.len > p.len { return none, false; }
    var yp: u8[>..] = [];
    yp.resize(p.len - y.len, 0);
    yp.append(y);
    if !bignum::ffdh_value_ok(yp, p) { return none, false; }
    // In the subgroup of order q: y^q = 1 (SP 800-56A's full check).
    let one = bignum::ffdh_modexp(yp, pkinit_half(p), p);
    for i in one.len { if one[i] != (if i == one.len - 1 { 1 } else { 0 }) { return none, false; } }
    let z, ok = bignum::ffdh_shared(dh.private, yp, p);
    return z, ok;
}

// The group a TD-DH-PARAMETERS AlgorithmIdentifier names, or 0.
fn pkinit_group_of(der: const u8[:], t: asn1::Tlv) -> i64 {
    let p, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !ok || p.len != 2 { return 0; }
    if asn1::oid_is(der, p[0], OID_EC_PUBLIC_KEY) {
        let gs: i64[3] = [PKINIT_P256, PKINIT_P384, PKINIT_P521];
        for g in gs { if asn1::oid_is(der, p[1], pkinit_curve_oid(g)) { return g; } }
        return 0;
    }
    if !asn1::oid_is(der, p[0], OID_DH_PUBLIC_NUMBER) { return 0; }
    let dp, okd = asn1::children_of(der, p[1], asn1::SEQUENCE);
    if !okd || dp.len < 2 { return 0; }
    let prime, okp = asn1::read_uint(der, dp[0]);
    let gen, okg = asn1::read_uint(der, dp[1]);
    if !okp || !okg || gen != "\x02" { return 0; }
    let gs: i64[2] = [PKINIT_MODP2048, PKINIT_MODP4096];
    for g in gs { if prime == pkinit_prime(g) { return g; } }
    return 0;
}

// The first group of a TD-DH-PARAMETERS list (the KDC's preference) that
// is at least `min`, or 0.
fn pkinit_pick_group(td: const u8[:], min: i64) -> i64 {
    let t, ok = asn1::parse(td);
    if !ok { return 0; }
    let items, oki = asn1::children_of(td, t, asn1::SEQUENCE);
    if !oki { return 0; }
    for it in items {
        let g = pkinit_group_of(td, it);
        if g >= min && g != 0 { return g; }
    }
    return 0;
}

// --- Key derivation -------------------------------------------------------------

// RFC 4556 §3.2.3.1: random-to-key of the first seed-length bytes of
// SHA-1(0 || x) || SHA-1(1 || x) || ...
fn pkinit_octetstring2key(etype: i32, x: const u8[:]) -> Key {
    let n = seed_len(etype);
    var out: u8[>..] = [];
    var counter: u8 = 0;
    while out.len < n {
        let c: u8[1] = [counter];
        out.append(bignum::hash2(160, c, x));
        counter += 1;
    }
    return random_to_key(etype, out[..n]);
}

// KRB5PrincipalName (RFC 4556 §3.2.2), DER.
fn pkinit_principal_der(name: const PrincipalName&, realm: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    put_kstring_f(body, 0, realm);
    put_principal_f(body, 1, name);
    var out: u8[>..] = [];
    put_seq(out, body);
    return out;
}

// RFC 8636 §6's OtherInfo for a KDF by hash h.
fn pkinit_other_info(h: i64, client: const PrincipalName&, crealm: const u8[:], server: const PrincipalName&,
                     srealm: const u8[:], etype: i32, as_req: const u8[:], pk_as_rep: const u8[:]) -> u8[>..] {
    var alg: u8[>..] = [];
    asn1::put_oid(alg, pkinit_kdf_oid(h));
    var body: u8[>..] = [];
    asn1::put(body, asn1::SEQUENCE, alg);
    put_octets_f(body, 0, pkinit_principal_der(client, crealm));
    put_octets_f(body, 1, pkinit_principal_der(server, srealm));
    var supp: u8[>..] = [];
    put_int_f(supp, 0, etype);
    put_octets_f(supp, 1, as_req);
    put_octets_f(supp, 2, pk_as_rep);
    var suppseq: u8[>..] = [];
    put_seq(suppseq, supp);
    put_octets_f(body, 2, suppseq);
    var out: u8[>..] = [];
    put_seq(out, body);
    return out;
}

// RFC 8636's KDF (SP 800-56A's one-step, hash h): the key-generation seed
// of etype from H(counter || Z || OtherInfo), counter from 1, through
// random-to-key.
fn pkinit_kdf(h: i64, etype: i32, z: const u8[:], other_info: const u8[:]) -> Key {
    let n = seed_len(etype);
    var out: u8[>..] = [];
    var counter: u32 = 1;
    while out.len < n {
        var pre: u8[>..] = [];
        pre.push((counter >> 24) as! u8);
        pre.push((counter >> 16) as! u8);
        pre.push((counter >> 8) as! u8);
        pre.push(counter as! u8);
        pre.append(z);
        out.append(bignum::hash2(h, pre, other_info));
        counter += 1;
    }
    return random_to_key(etype, out[..n]);
}

// --- Messages ---------------------------------------------------------------------

// The AuthPack (RFC 4556 §3.2.1, RFC 8636 §6, RFC 8070 §4): body_der is
// the KDC-REQ-BODY its checksum covers; `freshness` the KDC's token, if
// any; `kdfs` the KDFs to offer (none: the field left out).
fn encode_auth_pack(now: i64, usec: i64, nonce: u32, body_der: const u8[:], freshness: const u8[:], has_freshness: bool,
                    dh: const PkinitDh&, kdfs: const i64[:]) -> u8[>..] {
    var pa: u8[>..] = [];
    put_int_f(pa, 0, usec);
    put_ktime_f(pa, 1, now);
    put_int_f(pa, 2, nonce);
    put_octets_f(pa, 3, bignum::hash_bits(160, body_der));
    if has_freshness { put_octets_f(pa, 4, freshness); }
    var pas: u8[>..] = [];
    put_seq(pas, pa);
    var ap: u8[>..] = [];
    put_field(ap, 0, pas);
    put_field(ap, 1, dh.spki);
    // The signature algorithms we take from the KDC, best first.
    var cms: u8[>..] = [];
    let hs: i64[3] = [512, 384, 256];
    for h in hs { cms.append(x509::sig_alg_id(x509::SIG_ECDSA, h)); }
    for h in hs { cms.append(x509::sig_alg_id(x509::SIG_RSA_PKCS1, h)); }
    var cmss: u8[>..] = [];
    put_seq(cmss, cms);
    put_field(ap, 2, cmss);
    if kdfs.len > 0 {
        var ks: u8[>..] = [];
        for h in kdfs {
            var oid: u8[>..] = [];
            asn1::put_oid(oid, pkinit_kdf_oid(h));
            var id: u8[>..] = [];
            put_field(id, 0, oid);
            put_seq(ks, id);
        }
        var kss: u8[>..] = [];
        put_seq(kss, ks);
        put_field(ap, 4, kss);
    }
    var out: u8[>..] = [];
    put_seq(out, ap);
    return out;
}

// PA-PK-AS-REQ: the signed AuthPack (a ContentInfo), [0] IMPLICIT.
fn encode_pa_pk_as_req(signed_auth_pack: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    asn1::put(body, asn1::ctx(0, false), signed_auth_pack);
    var out: u8[>..] = [];
    put_seq(out, body);
    return out;
}

// A PA-PK-AS-REP with DHRepInfo: the dhSignedData (a ContentInfo), and
// the KDF the KDC picked (-1: none named).
struct PkAsRep { signed_data: u8[], kdf: i64 }

fn decode_pa_pk_as_rep(v: const u8[:]) -> PkAsRep, i64 {
    let t, ok = asn1::parse(v);
    if !ok { return PkAsRep { signed_data: "", kdf: -1 }, ERR_MALFORMED; }
    // encKeyPack: RSA key transport, which we do not do.
    if t.tag == asn1::ctx(1, false) { return PkAsRep { signed_data: "", kdf: -1 }, KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED; }
    if t.tag != asn1::ctx(0, true) { return PkAsRep { signed_data: "", kdf: -1 }, ERR_MALFORMED; }
    let rep, okr = asn1::explicit(v, t);
    let kids, okk = asn1::children_of(v, rep, asn1::SEQUENCE);
    if !okr || !okk || kids.len < 1 || kids[0].tag != asn1::ctx(0, false) { return PkAsRep { signed_data: "", kdf: -1 }, ERR_MALFORMED; }
    var kdf: i64 = -1;
    var bad = false;
    var last: u32 = 0;
    for k in kids {
        if k.number < last || k.cls != asn1::CLASS_CONTEXT { bad = true; }
        last = k.number + 1;
        // A serverDHNonce goes with reused keys, which we did not offer.
        if k.number == 1 { bad = true; }
        if k.number == 2 {
            // kdf [2] KDFAlgorithmId ::= SEQUENCE { kdf-id [0] OID }.
            let id, oki = asn1::explicit(v, k);
            let f, okf = asn1::children_of(v, id, asn1::SEQUENCE);
            if !oki || !okf || f.len < 1 || f[0].tag != asn1::ctx(0, true) { bad = true; continue; }
            let oid, oko = asn1::explicit(v, f[0]);
            if !oko || oid.tag != asn1::OID { bad = true; continue; }
            kdf = pkinit_kdf_of(v, oid);
            // A KDF we do not know: -3, refused by the caller.
            if kdf == -1 { kdf = -3; }
        }
    }
    if bad { return PkAsRep { signed_data: "", kdf: -1 }, ERR_MALFORMED; }
    return PkAsRep { signed_data: v[kids[0].off..kids[0].end], kdf: kdf }, OK;
}

// KDCDHKeyInfo: the KDC's public value (subjectPublicKey's bits) and
// the nonce; a dhKeyExpiration (reused keys) is refused.
fn decode_kdc_dh_key_info(v: const u8[:]) -> u8[>..], u32, i64 {
    var none: u8[>..] = [];
    let t, ok = asn1::parse(v);
    if !ok || t.tag != asn1::SEQUENCE { return none, 0, ERR_MALFORMED; }
    var fs = fields_at(v, t);
    require(fs, 3);
    if has(fs, 2) { fs.bad = true; }
    if fs.bad { return none, 0, ERR_MALFORMED; }
    let bs = fs.t[0];
    if bs.tag != asn1::BIT_STRING { return none, 0, ERR_MALFORMED; }
    let bits, unused, okbits = asn1::read_bits(v, bs);
    if !okbits || unused != 0 { return none, 0, ERR_MALFORMED; }
    let nonce = f_uint32(v, fs, 1);
    if fs.bad { return none, 0, ERR_MALFORMED; }
    return bits, nonce, OK;
}

// TYPED-DATA (RFC 4120 §5.9.1): SEQUENCE OF { data-type [0] Int32,
// data-value [1] OCTET STRING OPTIONAL }. The value of the first of a
// type, and whether one was there.
fn find_typed_data(edata: const u8[:], ty: i64) -> u8[>..], bool {
    var none: u8[>..] = [];
    let t, ok = asn1::parse(edata);
    if !ok { return none, false; }
    let items, oki = asn1::children_of(edata, t, asn1::SEQUENCE);
    if !oki { return none, false; }
    for it in items {
        if it.tag != asn1::SEQUENCE { continue; }
        let fs = fields_at(edata, it);
        if fs.bad || !has(fs, 0) { continue; }
        var bad = false;
        let dt = int32_at(edata, fs.t[0], bad);
        if bad || dt != ty { continue; }
        if !has(fs, 1) { return none, true; }
        let v = octets_at(edata, fs.t[1], bad);
        if bad { continue; }
        return v, true;
    }
    return none, false;
}

// --- The KDC's certificate --------------------------------------------------------

// The extension of a certificate with this OID: its value's content
// (the OCTET STRING's), and whether it has one.
fn pkinit_extension(c: const x509::Cert&, oid: const u8[:]) -> asn1::Tlv, bool {
    let d = c.der[..];
    let tf, ok = asn1::children_of(d, c.tbs, asn1::SEQUENCE);
    if !ok { return x509::no_tlv(), false; }
    for f in tf {
        if f.tag != asn1::ctx(3, true) { continue; }
        let exts, oke = asn1::explicit(d, f);
        let list, okl = asn1::children_of(d, exts, asn1::SEQUENCE);
        if !oke || !okl { return x509::no_tlv(), false; }
        for e in list {
            let p, okp = asn1::children_of(d, e, asn1::SEQUENCE);
            if !okp || p.len < 2 || !asn1::oid_is(d, p[0], oid) { continue; }
            let v = p[p.len - 1];
            if v.tag != asn1::OCTET_STRING { return x509::no_tlv(), false; }
            let inner, oki = asn1::read(d, v.off, v.end);
            return inner, oki;
        }
    }
    return x509::no_tlv(), false;
}

// Whether the certificate's extended key usage lists this OID.
fn pkinit_has_eku(c: const x509::Cert&, oid: const u8[:]) -> bool {
    let t, ok = pkinit_extension(c, "2.5.29.37");
    if !ok { return false; }
    let d = c.der[..];
    let list, okl = asn1::children_of(d, t, asn1::SEQUENCE);
    if !okl { return false; }
    for o in list { if asn1::oid_is(d, o, oid) { return true; } }
    return false;
}

// Whether the certificate's SAN holds an id-pkinit-san naming `name` in
// `realm` (the name type not compared, as MIT does not).
fn pkinit_san_names(c: const x509::Cert&, name: const u8[:], realm: const u8[:]) -> bool {
    if !c.has_san { return false; }
    let d = c.der[..];
    let gns, ok = asn1::children_of(d, c.san, asn1::SEQUENCE);
    if !ok { return false; }
    for gn in gns {
        // otherName [0] IMPLICIT SEQUENCE { type-id, [0] EXPLICIT value }.
        if gn.tag != asn1::ctx(0, true) { continue; }
        let p, okp = asn1::children(d, gn);
        if !okp || p.len != 2 || !asn1::oid_is(d, p[0], OID_PKINIT_SAN) || p[1].tag != asn1::ctx(0, true) { continue; }
        let kpn, okk = asn1::explicit(d, p[1]);
        if !okk || kpn.tag != asn1::SEQUENCE { continue; }
        var fs = fields_at(d, kpn);
        require(fs, 3);
        if fs.bad { continue; }
        let r = f_kstring(d, fs, 0);
        let pn = f_principal(d, fs, 1);
        if !fs.bad && r == realm && pn.name == name { return true; }
    }
    return false;
}

// How the client checks the KDC's EKU when it is named by host name
// (pkinit_eku_checking).
let PKINIT_EKU_KDC: i64 = 0;
let PKINIT_EKU_SERVER_AUTH: i64 = 1;
let PKINIT_EKU_NONE: i64 = 2;

// The trust a client puts in KDC certificates: anchors and pool (DER laid
// end to end), the KDC host names taken (pkinit_kdc_hostname, '\n'
// between them) and the EKU checking.
struct PkinitTrust { anchors: u8[], pool: u8[], kdc_hostnames: u8[], eku: i64 }

// Checks a KDC's SignedData: its signer chains to an anchor at time
// `now`, is the KDC of `realm`, and signed the content; the content type
// is id-pkinit-DHKeyData. Returns the content.
fn pkinit_check_kdc(sd_der: const u8[:], trust: const PkinitTrust&, realm: const u8[:], now: i64) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let sd, ep = x509::cms_parse_signed(sd_der);
    if ep != x509::OK { return out, ERR_MALFORMED; }
    let d = sd.der[..];
    if !asn1::oid_is(d, sd.content_type, OID_PKINIT_DH_KEY_DATA) { return out, ERR_MALFORMED; }
    let signer, ev = x509::cms_verify(sd);
    if ev == x509::ERR_UNSUPPORTED_ALGORITHM { return out, KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED; }
    if ev != x509::OK { return out, KDC_ERR_INVALID_SIG; }
    var inters: u8[>..] = [];
    inters.append(x509::cms_certs(sd));
    inters.append(trust.pool);
    var opts = x509::options();
    opts.key_usages = x509::EKU_ANY;
    let ce = x509::verify_chain_with(signer.der, inters, trust.anchors, "", now, "", opts);
    if ce != x509::OK { return out, KDC_ERR_KDC_NOT_TRUSTED; }
    // The KDC's name: its id-pkinit-san, which needs no EKU (MIT: the CA
    // certified it as the KDC), or a host name we were told to take, with
    // the EKU.
    if !pkinit_san_names(signer, name_join("krbtgt", realm), realm) {
        var by_host = false;
        for hn in split(trust.kdc_hostnames, '\n') {
            if hn.len == 0 { continue; }
            for dn in x509::dns_names(signer) { if x509::eq_nocase(dn, hn) { by_host = true; } }
        }
        if !by_host { return out, KDC_ERR_KDC_NAME_MISMATCH; }
        let eku_ok = if trust.eku == PKINIT_EKU_NONE { true }
                     else if trust.eku == PKINIT_EKU_SERVER_AUTH { pkinit_has_eku(signer, OID_KP_SERVER_AUTH) }
                     else { pkinit_has_eku(signer, OID_PKINIT_KP_KDC) };
        if !eku_ok { return out, KDC_ERR_INCONSISTENT_KEY_PURPOSE; }
    }
    out.append(x509::cms_content(sd));
    return out, OK;
}

// --- The client's identity --------------------------------------------------------

// A certificate and its key: the certificate (DER), those up to its CA
// (DER laid end to end; sent with it) and the key.
struct PkIdentity { cert: u8[], chain: u8[], key: x509::PrivateKey }

fn no_pk_identity() -> PkIdentity { PkIdentity { cert: "", chain: "", key: x509::empty_key() } }

// The certificates of a file: PEM (every CERTIFICATE block) or DER.
fn pkinit_certs_of(text: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let blocks, ok = asn1::pem_decode(text, "CERTIFICATE");
    if ok && blocks.len > 0 {
        for b in blocks { out.append(b); }
        return out;
    }
    let t, okt = asn1::parse(text);
    if okt && t.tag == asn1::SEQUENCE { out.append(text); }
    return out;
}

// pkinit_anchors and pkinit_pool values: FILE:path (a bundle) or
// DIR:path (every file in it), each value's certificates appended.
fn pkinit_load_certs(values: const u8[][:], out: u8[>..]&) -> i64 {
    for v in values {
        if v.starts_with("FILE:") {
            var text: u8[>..] = [];
            if !read_file(v[5..], text) { return ERR_FILE; }
            out.append(pkinit_certs_of(text));
        } else if v.starts_with("DIR:") {
            var names: u8[>..] = [];
            if !list_dir(v[4..], names) { return ERR_FILE; }
            for n in split(names, '\n') {
                if n.len == 0 { continue; }
                var text: u8[>..] = [];
                var full: u8[>..] = [];
                full.append(v[4..]);
                full.push('/');
                full.append(n);
                if read_file(full, text) { out.append(pkinit_certs_of(text)); }
            }
        } else {
            return ERR_CONFIG;
        }
    }
    return OK;
}

// An identity from MIT's X509_user_identity syntax: FILE:cert[,key]
// (PEM; the key in the certificate's file when not named; more
// certificates after the first are its chain) or PKCS12:file (with its
// password).
fn pkinit_load_identity(spec: const u8[:], p12_password: const u8[:]) -> PkIdentity, i64 {
    if spec.starts_with("PKCS12:") {
        var der: u8[>..] = [];
        if !read_file(spec[7..], der) { return no_pk_identity(), ERR_FILE; }
        let key, certs, e = x509::pkcs12_decode(der, p12_password);
        if e != x509::OK { return no_pk_identity(), ERR_IDENTITY; }
        let k, okk = x509::parse_private_key(key);
        if !okk { return no_pk_identity(), ERR_IDENTITY; }
        return pkinit_identity_of(certs, k);
    }
    if !spec.starts_with("FILE:") { return no_pk_identity(), ERR_CONFIG; }
    var cert_path: u8[>..] = [];
    var key_path: u8[>..] = [];
    var comma = -1;
    for i in spec.len { if spec[i] == ',' && comma < 0 { comma = i; } }
    if comma < 0 { cert_path.append(spec[5..]); key_path.append(spec[5..]); }
    else { cert_path.append(spec[5..comma]); key_path.append(spec[comma + 1..]); }
    var text: u8[>..] = [];
    if !read_file(cert_path, text) { return no_pk_identity(), ERR_FILE; }
    var ktext: u8[>..] = [];
    if !read_file(key_path, ktext) { return no_pk_identity(), ERR_FILE; }
    let k, okk = x509::parse_private_key_pem(ktext);
    if !okk { return no_pk_identity(), ERR_IDENTITY; }
    return pkinit_identity_of(pkinit_certs_of(text), k);
}

// Certificates laid end to end and a key: the one whose public key is
// the key's is the identity's, the others its chain.
fn pkinit_identity_of(certs: const u8[:], key: const x509::PrivateKey&) -> PkIdentity, i64 {
    let mine = x509::public_key_bytes(key);
    var cert: u8[>..] = [];
    var chain: u8[>..] = [];
    var at = 0;
    while at < certs.len {
        let t, ok = asn1::read(certs, at, certs.len);
        if !ok { return no_pk_identity(), ERR_IDENTITY; }
        let c, e = x509::parse(certs[t.start..t.end]);
        if e != x509::OK { return no_pk_identity(), ERR_IDENTITY; }
        let cd = c.der[..];
        let kb, okb = x509::key_bytes(cd, c.key);
        if cert.len == 0 && okb && kb == mine { cert.append(cd); }
        else { chain.append(cd); }
        at = t.end;
    }
    if cert.len == 0 { return no_pk_identity(), ERR_IDENTITY; }
    return PkIdentity { cert: cert, chain: chain, key: key }, OK;
}

// The signature an identity's key makes: PKCS #1 v1.5 with SHA-256 for
// RSA, ECDSA with the curve's hash.
fn pkinit_sig_alg(key: const x509::PrivateKey&) -> i64, i64 {
    if key.kind == x509::KEY_RSA { return x509::SIG_RSA_PKCS1, 256; }
    let a, h = x509::default_sig(key.kind);
    return a, h;
}

// --- One request --------------------------------------------------------------------

// The PA-PK-AS-REQ of a request: the AuthPack signed by the identity's
// key (unsigned when anonymous). Returns the padata value.
fn pkinit_request(id: const PkIdentity&, anonymous: bool, now: i64, usec: i64, nonce: u32, body_der: const u8[:],
                  freshness: const u8[:], has_freshness: bool, dh: const PkinitDh&, kdfs: const i64[:]) -> u8[>..], i64 {
    let ap = encode_auth_pack(now, usec, nonce, body_der, freshness, has_freshness, dh, kdfs);
    if anonymous { return encode_pa_pk_as_req(x509::cms_unsigned(OID_PKINIT_AUTH_DATA, ap)), OK; }
    let cert, e = x509::parse(id.cert);
    var none: u8[>..] = [];
    if e != x509::OK { return none, ERR_IDENTITY; }
    let alg, h = pkinit_sig_alg(id.key);
    let signed, ok = x509::cms_sign(OID_PKINIT_AUTH_DATA, ap, id.key, cert, id.chain, alg, h);
    if !ok { return none, ERR_IDENTITY; }
    return encode_pa_pk_as_req(signed), OK;
}

// The reply key from the KDC's PA-PK-AS-REP: checks the KDC's signed
// key info (its certificate, its signature, our nonce), finds the shared
// secret, and derives the key of `etype` by the KDF the KDC named (one
// of those we offered) or, when it named none, by octetstring2key.
// `as_req` is the request as sent; client and server its names.
fn pkinit_reply_key(rep_value: const u8[:], trust: const PkinitTrust&, dh: const PkinitDh&, nonce: u32, kdfs: const i64[:],
                    etype: i32, client: const PrincipalName&, crealm: const u8[:], server: const PrincipalName&,
                    srealm: const u8[:], as_req: const u8[:], now: i64) -> Key, i64 {
    let r, err = decode_pa_pk_as_rep(rep_value);
    if err != OK { return no_key(), err; }
    let info, cerr = pkinit_check_kdc(r.signed_data, trust, srealm, now);
    if cerr != OK { return no_key(), cerr; }
    let kdc_value, kn, ierr = decode_kdc_dh_key_info(info);
    if ierr != OK { return no_key(), ierr; }
    if kn != nonce { return no_key(), ERR_NONCE; }
    let z, okz = pkinit_dh_shared(dh, kdc_value);
    if !okz { return no_key(), KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED; }
    if r.kdf == -1 { return pkinit_octetstring2key(etype, z), OK; }
    var offered = false;
    for k in kdfs { if k == r.kdf { offered = true; } }
    if !offered { return no_key(), KDC_ERR_NO_ACCEPTABLE_KDF; }
    let oi = pkinit_other_info(r.kdf, client, crealm, server, srealm, etype, as_req, rep_value);
    return pkinit_kdf(r.kdf, etype, z, oi), OK;
}

// --- Configuration (krb5.conf, as MIT reads it) ------------------------------------

// A realm's value of a PKINIT option ([realms] first, then [libdefaults]).
fn pkinit_conf_all(cfg: const Config&, realm: const u8[:], name: const u8[:]) -> u8[][>..] {
    let r = conf_all(cfg, str("realms/", realm, "/", name));
    if r.len > 0 { return r; }
    return conf_all(cfg, str("libdefaults/", name));
}

fn pkinit_conf(cfg: const Config&, realm: const u8[:], name: const u8[:], dflt: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for v in pkinit_conf_all(cfg, realm, name) { if out.len == 0 { out.append(v); } }
    if out.len == 0 { out.append(dflt); }
    return out;
}

// The trust of a realm's KDC certificates: pkinit_anchors, pkinit_pool,
// pkinit_kdc_hostname, pkinit_eku_checking.
fn pkinit_trust(cfg: const Config&, realm: const u8[:]) -> PkinitTrust, i64 {
    var anchors: u8[>..] = [];
    var pool: u8[>..] = [];
    let ea = pkinit_load_certs(pkinit_conf_all(cfg, realm, "pkinit_anchors"), anchors);
    let ep = pkinit_load_certs(pkinit_conf_all(cfg, realm, "pkinit_pool"), pool);
    var hosts: u8[>..] = [];
    for h in pkinit_conf_all(cfg, realm, "pkinit_kdc_hostname") { hosts.append(h); hosts.push('\n'); }
    let eku_name = pkinit_conf(cfg, realm, "pkinit_eku_checking", "kpKDC");
    let eku = if eku_name == "kpServerAuth" { PKINIT_EKU_SERVER_AUTH } else if eku_name == "none" { PKINIT_EKU_NONE }
              else { PKINIT_EKU_KDC };
    let err = if ea != OK { ea } else if ep != OK { ep } else if anchors.len == 0 { KDC_ERR_KDC_NOT_TRUSTED } else { OK };
    return PkinitTrust { anchors: copy(anchors), pool: copy(pool), kdc_hostnames: copy(hosts), eku: eku }, err;
}

// The group to start with: pkinit_dh_min_bits (2048 by default).
fn pkinit_conf_group(cfg: const Config&, realm: const u8[:]) -> i64 {
    return pkinit_group_named(pkinit_conf(cfg, realm, "pkinit_dh_min_bits", "2048"));
}

// The KDFs to offer: pkinit_kdfs (ours, not MIT's: hash names among
// sha1 sha256 sha384 sha512, or "none" to offer none and have RFC 4556's
// octetstring2key), all four by default.
fn pkinit_conf_kdfs(cfg: const Config&, realm: const u8[:]) -> i64[>..] {
    let v = pkinit_conf(cfg, realm, "pkinit_kdfs", "");
    if v.len == 0 { return pkinit_default_kdfs(); }
    var out: i64[>..] = [];
    for w in words(v) {
        if w == "sha1" { out.push(160); }
        else if w == "sha256" { out.push(256); }
        else if w == "sha384" { out.push(384); }
        else if w == "sha512" { out.push(512); }
    }
    return out;
}

// RFC 8062 §7's check of PA-PKINIT-KX (`kx`, the padata's value): the
// KDC's contribution key, encrypted in the reply key, combined with the
// reply key by KRB-FX-CF2(contribution, "PKINIT", reply key,
// "KEYEXCHANGE") must be the ticket's session key.
fn pkinit_check_kx(kx: const u8[:], reply_key: Key, session_key: Key) -> i64 {
    let ed, err = decode_enc_data(kx);
    if err != OK { return err; }
    var plain: u8[>..] = [];
    let derr = decrypt(reply_key, USAGE_PA_PKINIT_KX, ed.cipher, plain);
    if derr != OK { return derr; }
    let body = der_unpadded(plain);
    let t, ok = asn1::parse(body, true);
    if !ok { return ERR_MALFORMED; }
    var bad = false;
    let contribution = key_at(body, t, bad);
    if bad { return ERR_MALFORMED; }
    let k, cerr = fx_cf2(contribution, "PKINIT", reply_key, "KEYEXCHANGE");
    if cerr != OK { return cerr; }
    return if k.etype == session_key.etype && k.value == session_key.value { OK } else { ERR_INTEGRITY };
}
