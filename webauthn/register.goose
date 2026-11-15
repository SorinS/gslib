// webauthn.register: verifying a registration (§7.1) and its
// attestation statement by format (§8): none; packed, self-attested or
// with an attestation certificate (its subject and the FIDO AAGUID
// extension checked); fido-u2f (a P-256 certificate over the U2F
// registration data); tpm (TPMS_ATTEST and TPMT_PUBLIC parsed, the
// certified name the hash of pubArea, pubArea's key the credential's, the
// AIK certificate's empty subject, its TCG SAN with a registered
// manufacturer, its AIK extended key usage); android-key (the key
// description extension: the challenge, no allApplications, a generated
// key for signing); apple (the nonce extension). The certificates of a
// statement are the credential record's trust path, checked against the
// RP's roots with crypto/x509.

namespace webauthn;

import std;
import json;
import webauthn;
import encoding.cbor;
import encoding.cbor.cose;
import encoding.asn1;
import crypto.x509;
import crypto.x509.verify;
import crypto.x509.pool;
import crypto.bignum;
import crypto.bignum.sha256;
import crypto.bignum.hmac;
import crypto.bignum.ct;
import jwx;

// --- Registration ------------------------------------------------------------------------

// Verifies a registration response (§7.1) against the challenge sent, and
// fills c, the credential record to store, with OK. `roots` are the
// attestation roots the RP trusts (DER certificates, concatenated: from
// MDS, or the vendors' own); a statement whose certificates chain to one
// of them at p.now leaves c.trusted set. Without roots, or when they do
// not chain, the attestation is still checked but not trusted, which is
// an error only when p.require_trusted. Why a check failed is in
// c.message.
fn verify_registration(p: const Policy&, challenge: const u8[:], response_json: const u8[:], roots: const u8[:],
                       c: Credential&) -> i64 {
    if p.rp_id.len == 0 || p.origins.len == 0 || challenge.len == 0 { note(c.message, "no RP ID, origins or challenge"); return ERR_ARG; }
    // Certificates are valid at a time: without one, no chain would be.
    if roots.len > 0 && p.now <= 0 { note(c.message, "roots given without the time (Policy.now)"); return ERR_ARG; }
    var r = Response { .. };
    let e1 = parse_response(r, response_json, true, p.lenient_base64, p.max_response, c.message);
    if e1 != OK { return e1; }
    let e2 = check_client_data(p, r.client_data, "webauthn.create", challenge, c.message);
    if e2 != OK { return e2; }
    let cdh = sha256_of(r.client_data);
    // The attestation object: {fmt, attStmt, authData}.
    let ao = r.attestation_object[..];
    var doc: cbor::Node[>..] = [];
    let root, ec = cbor::decode(ao, cbor::Options { max_bytes: p.max_response, .. }, doc);
    if ec != cbor::OK || !cbor::is_map(doc, root) { note(c.message, str("attestationObject: ", cbor::error_text(ec))); return ERR_MALFORMED; }
    let fmt_name, okf = cbor::as_text(ao, doc, cbor::map_get_text(ao, doc, root, "fmt"));
    let stmt = cbor::map_get_text(ao, doc, root, "attStmt");
    let ad_bytes, oka = cbor::as_bytes(ao, doc, cbor::map_get_text(ao, doc, root, "authData"));
    if !okf || !cbor::is_map(doc, stmt) || !oka { note(c.message, "attestationObject lacks fmt, attStmt or authData"); return ERR_MALFORMED; }
    var ad = AuthData { .. };
    let e3 = parse_auth_data(ad_bytes, ad, c.message);
    if e3 != OK { return e3; }
    let e4 = check_flags(p, ad, c.message);
    if e4 != OK { return e4; }
    if ad.flags & FLAG_AT == 0 { note(c.message, "AT not set in a registration"); return ERR_FLAGS; }
    if ad.cred_id[..] != r.id[..] { note(c.message, "the credential ID is not the response's"); return ERR_CREDENTIAL_ID; }
    // The credential public key and its algorithm.
    let key, ek = cose::decode(ad_bytes[ad.key_at..ad.key_end], p.min_rsa_bits);
    if ek != cose::OK {
        note(c.message, str("credential public key: ", cose::error_text(ek)));
        return if ek == cose::ERR_UNKNOWN_ALG { ERR_ALGORITHM } else { ERR_KEY };
    }
    if key.alg == 0 { note(c.message, "credential public key without alg"); return ERR_ALGORITHM; }
    var asked = false;
    if p.algs.len == 0 { for a in DEFAULT_ALGS { if a == key.alg { asked = true; } } }
    else { for a in p.algs { if a == key.alg { asked = true; } } }
    if !asked || key.alg == cose::RS1 { note(c.message, str("algorithm not asked for: ", cose::alg_name(key.alg), " (", key.alg, ")")); return ERR_ALGORITHM; }
    if !cose::fits(key, key.alg) { note(c.message, str("the key does not fit its alg ", cose::alg_name(key.alg))); return ERR_KEY; }
    // The attestation statement.
    let fmt = format_of(fmt_name);
    if fmt == 0 { note(c.message, str("unknown attestation format: ", fmt_name)); return ERR_FORMAT; }
    if p.formats & format_bit(fmt) == 0 { note(c.message, str("attestation format not allowed: ", fmt_name)); return ERR_FORMAT; }
    c.x5c.clear();
    let att_type, ea = verify_statement(p, fmt, ao, doc, stmt, ad_bytes, ad, key, cdh, c);
    if ea != OK { return ea; }
    c.trusted = false;
    if c.x5c.len > 0 && roots.len > 0 {
        let et = check_trust(c.x5c, roots, p.now, c.message);
        c.trusted = et == OK;
    }
    if p.require_trusted && !c.trusted {
        if c.message.len == 0 { note(c.message, str("attestation ", attestation_type_name(att_type), " is not trusted")); }
        return ERR_TRUST;
    }
    c.message.clear();
    c.id.clear();
    c.id.append(ad.cred_id);
    let pk = ad_bytes[ad.key_at..ad.key_end];
    if pk.len > c.public_key.cap { note(c.message, "credential public key too large to keep"); return ERR_LIMIT; }
    c.public_key.clear();
    c.public_key.append(pk);
    c.alg = key.alg;
    c.sign_count = ad.sign_count;
    c.uv = ad.flags & FLAG_UV != 0;
    c.backup_eligible = ad.flags & FLAG_BE != 0;
    c.backed_up = ad.flags & FLAG_BS != 0;
    c.transports = r.transports;
    for i in 16 { c.aaguid[i] = ad.aaguid[i]; }
    c.fmt = fmt;
    c.attestation_type = att_type;
    c.attachment = r.attachment;
    c.rk = r.rk;
    return OK;
}

// Whether the leaf of x5c (DER certificates, concatenated, the leaf
// first) chains through the others to one of `roots` at `now`, with any
// extended key usage.
fn check_trust(x5c: const u8[:], roots: const u8[:], now: i64, msg: u8[..256]&) -> i64 {
    let t, ok = asn1::read(x5c, 0, x5c.len);
    if !ok { note(msg, "x5c is not DER"); return ERR_MALFORMED; }
    let leaf = x5c[..t.end];
    let inters = x5c[t.end..];
    let ipool, oki = x509::pool_of(inters);
    if !oki { note(msg, "an x5c certificate does not parse"); return ERR_MALFORMED; }
    var rpool = x509::new_pool();
    let okr = x509::pool_add_concatenated(rpool, roots);
    var opts = x509::options();
    opts.key_usages = x509::EKU_ANY;
    let e = x509::verify_pools(leaf, ipool, rpool, "", now, "", opts);
    if e != x509::OK { note(msg, str("attestation chain: ", x509::error_text(e))); return ERR_TRUST; }
    return OK;
}

// --- Attestation statements ----------------------------------------------------------------

// The extension of a certificate by OID: its extnValue (the OCTET STRING,
// whose content is the extension's DER), whether it is critical, and
// whether there is one.
fn cert_extension(c: const x509::Cert&, oid: const u8[:]) -> asn1::Tlv, bool, bool {
    let d = c.der[..];
    let none = x509::no_tlv();
    let f, ok = asn1::children_of(d, c.tbs, asn1::SEQUENCE);
    if !ok { return none, false, false; }
    for t in f {
        if t.tag != asn1::ctx(3, true) { continue; }
        let wrap, okw = asn1::explicit(d, t);
        let exts, oke = asn1::children_of(d, wrap, asn1::SEQUENCE);
        if !okw || !oke { return none, false, false; }
        for e in exts {
            let parts, okp = asn1::children_of(d, e, asn1::SEQUENCE);
            if !okp || parts.len < 2 || !asn1::oid_is(d, parts[0], oid) { continue; }
            let critical = parts.len == 3;
            return parts[parts.len - 1], critical, true;
        }
    }
    return none, false, false;
}

// The certificates of a statement's x5c (an array of DER certificates,
// the attestation certificate first) into c.x5c; the first one parsed.
fn take_x5c(ao: const u8[:], doc: const cbor::Node[:], arr: i64, c: Credential&) -> x509::Cert, i64 {
    if !cbor::is_array(doc, arr) || cbor::length(doc, arr) == 0 || cbor::length(doc, arr) > 10 {
        note(c.message, "x5c is not an array of 1 to 10 certificates");
        return x509::empty_cert(), ERR_ATTESTATION;
    }
    var bad = false;
    cbor::each(doc, arr) { i =>
        let der, ok = cbor::as_bytes(ao, doc, i);
        if !ok { bad = true; }
        else {
            let cert, e = x509::parse(der);
            if e != x509::OK { bad = true; }
            c.x5c.append(der);
        }
    };
    if bad { note(c.message, "an x5c certificate does not parse"); return x509::empty_cert(), ERR_ATTESTATION; }
    let first, okf = cbor::as_bytes(ao, doc, cbor::element(doc, arr, 0));
    let leaf, e = x509::parse(first);
    return leaf, OK;
}

// Verifies sig over msg by alg with a certificate's key.
fn verify_by_cert(cert: const x509::Cert&, alg: i64, msg: const u8[:], sig: const u8[:], allow_sha1: bool,
                  msg_out: u8[..256]&) -> i64 {
    let k, e = cose::from_cert(cert);
    if e != cose::OK { note(msg_out, str("attestation certificate key: ", cose::error_text(e))); return ERR_ATTESTATION; }
    let ev = cose::verify(k, alg, msg, sig, false, allow_sha1);
    if ev == cose::OK { return OK; }
    note(msg_out, str("attestation signature: ", cose::error_text(ev), " (", cose::alg_name(alg), ")"));
    return if ev == cose::ERR_SIGNATURE { ERR_ATTESTATION } else { ERR_ALGORITHM };
}

let OID_FIDO_AAGUID: const u8[:] = "1.3.6.1.4.1.45724.1.1.4";

// The FIDO AAGUID extension, when there: not critical, and the AAGUID of
// the authenticator data (§8.2.1, §8.3.1).
fn check_aaguid_extension(cert: const x509::Cert&, ad: const AuthData&, msg: u8[..256]&) -> i64 {
    let v, critical, found = cert_extension(cert, OID_FIDO_AAGUID);
    if !found { return OK; }
    if critical { note(msg, "the AAGUID extension is critical"); return ERR_ATTESTATION; }
    let d = cert.der[..];
    let inner, ok = asn1::read(d, v.off, v.end);
    if !ok || inner.tag != asn1::OCTET_STRING || inner.end != v.end || inner.end - inner.off != 16
        || d[inner.off..inner.end] != ad.aaguid[..] {
        note(msg, "the certificate's AAGUID is not the authenticator data's");
        return ERR_ATTESTATION;
    }
    return OK;
}

// The one value of a name attribute, when there is exactly one.
fn one_value(vs: const u8[][:]) -> const u8[:], bool {
    if vs.len != 1 { return "", false; }
    for v in vs { return v, v.len > 0; }
    return "", false;
}

// Checks a statement whose format is fmt (§8); the attestation type and
// OK, with the statement's certificates in c.x5c.
fn verify_statement(p: const Policy&, fmt: i64, ao: const u8[:], doc: const cbor::Node[:], stmt: i64,
                    ad_bytes: const u8[:], ad: const AuthData&, key: const cose::Key&, cdh: const u8[:],
                    c: Credential&) -> i64, i64 {
    var signed: u8[>..] = [];
    signed.append(ad_bytes);
    signed.append(cdh);
    if fmt == FMT_NONE {
        if cbor::length(doc, stmt) != 0 { note(c.message, "a none attestation with a statement"); return ATT_NONE, ERR_ATTESTATION; }
        return ATT_NONE, OK;
    }
    if fmt == FMT_PACKED {
        let alg, oka = cbor::as_i64(doc, cbor::map_get_text(ao, doc, stmt, "alg"));
        let sig, oks = cbor::as_bytes(ao, doc, cbor::map_get_text(ao, doc, stmt, "sig"));
        if !oka || !oks { note(c.message, "packed: no alg or sig"); return ATT_NONE, ERR_ATTESTATION; }
        let x5c = cbor::map_get_text(ao, doc, stmt, "x5c");
        if x5c < 0 {
            // Self attestation: the credential's own key, by its own alg.
            if alg != key.alg { note(c.message, "packed self attestation by another alg than the key's"); return ATT_SELF, ERR_ALGORITHM; }
            let ev = cose::verify(key, alg, signed, sig);
            if ev != cose::OK { note(c.message, str("packed self signature: ", cose::error_text(ev))); return ATT_SELF, ERR_ATTESTATION; }
            return ATT_SELF, OK;
        }
        let cert, ex = take_x5c(ao, doc, x5c, c);
        if ex != OK { return ATT_BASIC, ex; }
        let ev = verify_by_cert(cert, alg, signed, sig, false, c.message);
        if ev != OK { return ATT_BASIC, ev; }
        // §8.2.1: version 3; C, O, OU "Authenticator Attestation", CN; not a CA.
        let d = cert.der[..];
        let cs = x509::name_values(d, cert.subject, "2.5.4.6");
        let os = x509::name_values(d, cert.subject, "2.5.4.10");
        let ous = x509::name_values(d, cert.subject, "2.5.4.11");
        let cns = x509::name_values(d, cert.subject, "2.5.4.3");
        let country, okc = one_value(cs);
        let org, oko = one_value(os);
        let ou, okou = one_value(ous);
        let cn, okcn = one_value(cns);
        if cert.version != 3 || !okc || country.len != 2 || !oko || !okcn || !okou || ou != "Authenticator Attestation" {
            note(c.message, "packed: the attestation certificate's subject is not as §8.2.1 asks");
            return ATT_BASIC, ERR_ATTESTATION;
        }
        if cert.is_ca { note(c.message, "packed: the attestation certificate is a CA"); return ATT_BASIC, ERR_ATTESTATION; }
        let ea = check_aaguid_extension(cert, ad, c.message);
        return ATT_BASIC, ea;
    }
    if fmt == FMT_FIDO_U2F {
        let sig, oks = cbor::as_bytes(ao, doc, cbor::map_get_text(ao, doc, stmt, "sig"));
        let x5c = cbor::map_get_text(ao, doc, stmt, "x5c");
        if !oks || cbor::length(doc, x5c) != 1 { note(c.message, "fido-u2f: no sig, or x5c not one certificate"); return ATT_BASIC, ERR_ATTESTATION; }
        let cert, ex = take_x5c(ao, doc, x5c, c);
        if ex != OK { return ATT_BASIC, ex; }
        if cert.key_type != x509::KEY_EC_P256 { note(c.message, "fido-u2f: the certificate's key is not P-256"); return ATT_BASIC, ERR_ATTESTATION; }
        if key.kty != cose::KTY_EC2 || key.crv != cose::CRV_P256 { note(c.message, "fido-u2f: the credential key is not P-256"); return ATT_BASIC, ERR_KEY; }
        var data: u8[>..] = [0];
        data.append(ad.rp_id_hash);
        data.append(cdh);
        data.append(ad.cred_id);
        data.push(4);
        data.append(key.x);
        data.append(key.y);
        let ev = verify_by_cert(cert, cose::ES256, data, sig, false, c.message);
        return ATT_BASIC, ev;
    }
    if fmt == FMT_TPM { return verify_tpm(p, ao, doc, stmt, signed, ad, key, c); }
    if fmt == FMT_ANDROID_KEY { return verify_android_key(p, ao, doc, stmt, signed, ad, key, cdh, c); }
    if fmt == FMT_APPLE {
        let cert, ex = take_x5c(ao, doc, cbor::map_get_text(ao, doc, stmt, "x5c"), c);
        if ex != OK { return ATT_ANONCA, ex; }
        let nonce = bignum::sha256(signed);
        let v, critical, found = cert_extension(cert, "1.2.840.113635.100.8.2");
        let d = cert.der[..];
        let seq, oks = asn1::read(d, v.off, v.end);
        let parts, okp = asn1::children_of(d, seq, asn1::SEQUENCE);
        var good = false;
        if found && oks && okp && seq.end == v.end {
            for t in parts {
                if t.tag == asn1::ctx(1, true) {
                    let o, oko = asn1::explicit(d, t);
                    if oko && o.tag == asn1::OCTET_STRING && d[o.off..o.end] == nonce[..] { good = true; }
                }
            }
        }
        if !good { note(c.message, "apple: the certificate's nonce is not SHA-256(authData || clientDataHash)"); return ATT_ANONCA, ERR_ATTESTATION; }
        let ck, eck = cose::from_cert(cert);
        if eck != cose::OK || !cose::same_key(ck, key) { note(c.message, "apple: the certificate's key is not the credential's"); return ATT_ANONCA, ERR_ATTESTATION; }
        return ATT_ANONCA, OK;
    }
    note(c.message, "attestation format not handled");
    return ATT_NONE, ERR_FORMAT;
}

// --- android-key (§8.4) -----------------------------------------------------------------

// A tagged member [n] of an AuthorizationList, or start == end.
fn auth_list_member(d: const u8[:], list: asn1::Tlv, n: u32) -> asn1::Tlv, bool {
    let items, ok = asn1::children(d, list);
    if !ok { return x509::no_tlv(), false; }
    for t in items {
        if t.cls == asn1::CLASS_CONTEXT && t.number == n {
            let inner, oki = asn1::explicit(d, t);
            return inner, oki;
        }
    }
    return x509::no_tlv(), false;
}

fn verify_android_key(p: const Policy&, ao: const u8[:], doc: const cbor::Node[:], stmt: i64, signed: const u8[:],
                      ad: const AuthData&, key: const cose::Key&, cdh: const u8[:], c: Credential&) -> i64, i64 {
    let alg, oka = cbor::as_i64(doc, cbor::map_get_text(ao, doc, stmt, "alg"));
    let sig, oks = cbor::as_bytes(ao, doc, cbor::map_get_text(ao, doc, stmt, "sig"));
    if !oka || !oks { note(c.message, "android-key: no alg or sig"); return ATT_BASIC, ERR_ATTESTATION; }
    let cert, ex = take_x5c(ao, doc, cbor::map_get_text(ao, doc, stmt, "x5c"), c);
    if ex != OK { return ATT_BASIC, ex; }
    let ev = verify_by_cert(cert, alg, signed, sig, false, c.message);
    if ev != OK { return ATT_BASIC, ev; }
    let ck, eck = cose::from_cert(cert);
    if eck != cose::OK || !cose::same_key(ck, key) { note(c.message, "android-key: the certificate's key is not the credential's"); return ATT_BASIC, ERR_ATTESTATION; }
    // KeyDescription: attestationChallenge (5th), softwareEnforced (7th), teeEnforced (8th).
    let v, critical, found = cert_extension(cert, "1.3.6.1.4.1.11129.2.1.17");
    let d = cert.der[..];
    let kd, okk = asn1::read(d, v.off, v.end);
    let f, okf = asn1::children_of(d, kd, asn1::SEQUENCE);
    if !found || !okk || kd.end != v.end || !okf || f.len < 8 || f[4].tag != asn1::OCTET_STRING
        || f[6].tag != asn1::SEQUENCE || f[7].tag != asn1::SEQUENCE {
        note(c.message, "android-key: no key description extension");
        return ATT_BASIC, ERR_ATTESTATION;
    }
    if d[f[4].off..f[4].end] != cdh { note(c.message, "android-key: attestationChallenge is not the clientDataHash"); return ATT_BASIC, ERR_ATTESTATION; }
    // No allApplications [600] in either list: the key is this RP's.
    for which in [6, 7] {
        let t, has = auth_list_member(d, f[which], 600);
        if has { note(c.message, "android-key: allApplications"); return ATT_BASIC, ERR_ATTESTATION; }
    }
    // origin [702] KM_ORIGIN_GENERATED (0) and purpose [1] holding
    // KM_PURPOSE_SIGN (2): in teeEnforced, or in either list unless the
    // policy wants the TEE's.
    var origin_ok = false;
    var purpose_ok = false;
    for which in [7, 6] {
        if which == 6 && p.android_tee_only { continue; }
        let o, has_o = auth_list_member(d, f[which], 702);
        if has_o {
            let n, okn = asn1::read_i64(d, o);
            if okn && n == 0 { origin_ok = true; }
        }
        let pu, has_p = auth_list_member(d, f[which], 1);
        if has_p {
            let ps, okp = asn1::children_of(d, pu, asn1::SET);
            for x in ps {
                let n, okn = asn1::read_i64(d, x);
                if okn && n == 2 { purpose_ok = true; }
            }
        }
    }
    if !origin_ok || !purpose_ok { note(c.message, "android-key: not a generated signing key"); return ATT_BASIC, ERR_ATTESTATION; }
    return ATT_BASIC, OK;
}

// --- tpm (§8.3) -----------------------------------------------------------------------------

// A cursor over TPM structures (big-endian); `ok` false after a read past
// the end.
struct Tpm { pos: i64 = 0, ok: bool = true }

fn tpm_n(b: const u8[:], t: Tpm&, n: i64) -> u64 {
    if !t.ok || t.pos + n > b.len { t.ok = false; return 0; }
    var v: u64 = 0;
    for i in n { v = (v << 8) | b[t.pos + i]; }
    t.pos += n;
    return v;
}

// A TPM2B: its bytes' start and end.
fn tpm2b(b: const u8[:], t: Tpm&) -> i64, i64 {
    let n = tpm_n(b, t, 2) as i64;
    if !t.ok || t.pos + n > b.len { t.ok = false; return 0, 0; }
    let s = t.pos;
    t.pos += n;
    return s, t.pos;
}

let TPM_ALG_RSA:    u64 = 0x0001;
let TPM_ALG_SHA1:   u64 = 0x0004;
let TPM_ALG_SHA256: u64 = 0x000b;
let TPM_ALG_SHA384: u64 = 0x000c;
let TPM_ALG_SHA512: u64 = 0x000d;
let TPM_ALG_NULL:   u64 = 0x0010;
let TPM_ALG_ECC:    u64 = 0x0023;

fn tpm_hash(alg: u64) -> i64 {
    if alg == TPM_ALG_SHA1 { return 160; }
    if alg == TPM_ALG_SHA256 { return 256; }
    if alg == TPM_ALG_SHA384 { return 384; }
    if alg == TPM_ALG_SHA512 { return 512; }
    return 0;
}

// b without its leading zero bytes.
fn unpadded(b: const u8[:]) -> const u8[:] {
    var i = 0;
    while i < b.len && b[i] == 0 { i++; }
    return b[i..];
}

// TPM vendor IDs (TCG's TPM Vendor ID Registry, table 2, as hex of the
// four bytes TPM_PT_MANUFACTURER holds), and FIDO's conformance tools'.
let TPM_VENDORS: const u8[:][] = ["414D4400", "414E5400", "41524D00", "41544D4C", "4252434D", "4353434F", "464C5953",
    "524F4343", "474F4F47", "48504900", "48504500", "48495349", "49424D00", "49465800", "494E5443", "4C454E00",
    "4D534654", "4E534D20", "4E545A00", "4E534700", "4E544300", "51434F4D", "534D534E", "53454345", "534E5300",
    "534D5343", "53544D20", "54584E00", "57454300", "5345414C", "FFFFF1D0"];

fn tpm_vendor_known(id: const u8[:]) -> bool {
    for v in TPM_VENDORS {
        if v.len != id.len { continue; }
        var same = true;
        for i in v.len {
            var ch = id[i];
            if ch >= 'a' && ch <= 'f' { ch = ch - 32; }
            if ch != v[i] { same = false; }
        }
        if same { return true; }
    }
    return false;
}

// The AIK certificate's subjectAltName: a directoryName with the TPM's
// manufacturer ("id:" and a registered vendor), model and version
// (§8.3.1).
fn check_tpm_san(cert: const x509::Cert&, any_vendor: bool, msg: u8[..256]&) -> i64 {
    if !cert.has_san { note(msg, "tpm: the AIK certificate has no subjectAltName"); return ERR_ATTESTATION; }
    let d = cert.der[..];
    let names, ok = asn1::children_of(d, cert.san, asn1::SEQUENCE);
    var manufacturer: u8[>..] = [];
    var model = false;
    var version = false;
    for n in names {
        if n.tag != asn1::ctx(4, true) { continue; }
        let name, okn = asn1::explicit(d, n);
        if !okn { continue; }
        let ms = x509::name_values(d, name, "2.23.133.2.1");
        for m in ms { manufacturer.clear(); manufacturer.append(m); }
        if x509::name_values(d, name, "2.23.133.2.2").len > 0 { model = true; }
        if x509::name_values(d, name, "2.23.133.2.3").len > 0 { version = true; }
    }
    if !ok || !model || !version || manufacturer.len != 11 || !starts_with(manufacturer, "id:")
        || (!any_vendor && !tpm_vendor_known(manufacturer[3..])) {
        note(msg, "tpm: the AIK certificate's subjectAltName lacks a known manufacturer, a model or a version");
        return ERR_ATTESTATION;
    }
    return OK;
}

fn verify_tpm(p: const Policy&, ao: const u8[:], doc: const cbor::Node[:], stmt: i64, signed: const u8[:],
              ad: const AuthData&, key: const cose::Key&, c: Credential&) -> i64, i64 {
    let ver, okv = cbor::as_text(ao, doc, cbor::map_get_text(ao, doc, stmt, "ver"));
    let alg, oka = cbor::as_i64(doc, cbor::map_get_text(ao, doc, stmt, "alg"));
    let sig, oks = cbor::as_bytes(ao, doc, cbor::map_get_text(ao, doc, stmt, "sig"));
    let ci, okc = cbor::as_bytes(ao, doc, cbor::map_get_text(ao, doc, stmt, "certInfo"));
    let pa, okp = cbor::as_bytes(ao, doc, cbor::map_get_text(ao, doc, stmt, "pubArea"));
    if !okv || ver != "2.0" || !oka || !oks || !okc || !okp { note(c.message, "tpm: not ver 2.0 with alg, sig, certInfo and pubArea"); return ATT_BASIC, ERR_ATTESTATION; }
    if cbor::map_get_text(ao, doc, stmt, "x5c") < 0 { note(c.message, "tpm: no x5c (ECDAA is not supported)"); return ATT_BASIC, ERR_ATTESTATION; }
    if alg == cose::RS1 && !p.allow_rs1 { note(c.message, "tpm: RS1 (SHA-1) not allowed"); return ATT_BASIC, ERR_ALGORITHM; }
    let h = cose::hash_of(alg);
    if h == 0 { note(c.message, str("tpm: an alg without a hash: ", alg)); return ATT_BASIC, ERR_ALGORITHM; }
    // pubArea (TPMT_PUBLIC): its key must be the credential's.
    var t = Tpm { .. };
    let ptype = tpm_n(pa, t, 2);
    let name_alg = tpm_n(pa, t, 2);
    let attrs = tpm_n(pa, t, 4);
    let ap0, ap1 = tpm2b(pa, t);
    let sym = tpm_n(pa, t, 2);
    if sym != TPM_ALG_NULL { let kb = tpm_n(pa, t, 2); let mode = tpm_n(pa, t, 2); }
    let scheme = tpm_n(pa, t, 2);
    if scheme != TPM_ALG_NULL { let sh = tpm_n(pa, t, 2); }
    var same = false;
    if ptype == TPM_ALG_RSA {
        let bits = tpm_n(pa, t, 2);
        let exp = tpm_n(pa, t, 4);
        let n0, n1 = tpm2b(pa, t);
        if t.ok && key.kty == cose::KTY_RSA {
            let e = if exp == 0 { 65537 } else { exp };
            var kv: u64 = 0;
            for x in key.e { kv = (kv << 8) | x; }
            same = unpadded(pa[n0..n1]) == unpadded(key.n) && kv == e && key.e.len <= 8;
        }
    } else if ptype == TPM_ALG_ECC {
        let curve = tpm_n(pa, t, 2);
        let kdf = tpm_n(pa, t, 2);
        if kdf != TPM_ALG_NULL { let kh = tpm_n(pa, t, 2); }
        let x0, x1 = tpm2b(pa, t);
        let y0, y1 = tpm2b(pa, t);
        let crv = if curve == 3 { cose::CRV_P256 } else if curve == 4 { cose::CRV_P384 } else if curve == 5 { cose::CRV_P521 } else { 0 };
        if t.ok && key.kty == cose::KTY_EC2 && crv == key.crv {
            same = unpadded(pa[x0..x1]) == unpadded(key.x) && unpadded(pa[y0..y1]) == unpadded(key.y);
        }
    } else {
        note(c.message, "tpm: pubArea is neither RSA nor ECC");
        return ATT_BASIC, ERR_ATTESTATION;
    }
    if !t.ok || t.pos != pa.len { note(c.message, "tpm: pubArea malformed or with trailing bytes"); return ATT_BASIC, ERR_ATTESTATION; }
    if !same { note(c.message, "tpm: pubArea's key is not the credential's"); return ATT_BASIC, ERR_ATTESTATION; }
    // certInfo (TPMS_ATTEST): a TPM_ST_ATTEST_CERTIFY of pubArea, over the hash of attToBeSigned.
    var u = Tpm { .. };
    let magic = tpm_n(ci, u, 4);
    let atype = tpm_n(ci, u, 2);
    let qs0, qs1 = tpm2b(ci, u);
    let ex0, ex1 = tpm2b(ci, u);
    let clock = tpm_n(ci, u, 8);
    let resets = tpm_n(ci, u, 4);
    let restarts = tpm_n(ci, u, 4);
    let safe = tpm_n(ci, u, 1);
    let fw = tpm_n(ci, u, 8);
    let nm0, nm1 = tpm2b(ci, u);
    let qn0, qn1 = tpm2b(ci, u);
    if !u.ok || u.pos != ci.len { note(c.message, "tpm: certInfo malformed or with trailing bytes"); return ATT_BASIC, ERR_ATTESTATION; }
    if magic != 0xff544347 || atype != 0x8017 { note(c.message, "tpm: certInfo is not a TPM-generated ATTEST_CERTIFY"); return ATT_BASIC, ERR_ATTESTATION; }
    if ci[ex0..ex1] != bignum::hash_bits(h, signed)[..] { note(c.message, "tpm: extraData is not the hash of authData || clientDataHash"); return ATT_BASIC, ERR_ATTESTATION; }
    let nh = tpm_hash(name_alg);
    var name: u8[>..] = [(name_alg >> 8) as! u8, name_alg as! u8];
    if nh == 0 { note(c.message, "tpm: pubArea's nameAlg is not a hash this package does"); return ATT_BASIC, ERR_ATTESTATION; }
    name.append(bignum::hash_bits(nh, pa));
    if ci[nm0..nm1] != name[..] { note(c.message, "tpm: the certified name is not pubArea's"); return ATT_BASIC, ERR_ATTESTATION; }
    // The AIK certificate (§8.3.1) and its signature over certInfo.
    let cert, ex = take_x5c(ao, doc, cbor::map_get_text(ao, doc, stmt, "x5c"), c);
    if ex != OK { return ATT_BASIC, ex; }
    let ev = verify_by_cert(cert, alg, ci, sig, p.allow_rs1, c.message);
    if ev != OK { return ATT_BASIC, ev; }
    let d = cert.der[..];
    let subj, oksub = asn1::children_of(d, cert.subject, asn1::SEQUENCE);
    if cert.version != 3 || !oksub || subj.len != 0 { note(c.message, "tpm: the AIK certificate's subject is not empty"); return ATT_BASIC, ERR_ATTESTATION; }
    let es = check_tpm_san(cert, p.tpm_any_vendor, c.message);
    if es != OK { return ATT_BASIC, es; }
    // Extended key usage tcg-kp-AIKCertificate (2.23.133.8.3).
    let eku, crit, has_eku = cert_extension(cert, "2.5.29.37");
    var aik = false;
    if has_eku {
        let seq, okseq = asn1::read(d, eku.off, eku.end);
        let ks, okk = asn1::children_of(d, seq, asn1::SEQUENCE);
        for k in ks { if asn1::oid_is(d, k, "2.23.133.8.3") { aik = true; } }
    }
    if !aik { note(c.message, "tpm: the AIK certificate lacks the AIK extended key usage"); return ATT_BASIC, ERR_ATTESTATION; }
    if cert.is_ca { note(c.message, "tpm: the AIK certificate is a CA"); return ATT_BASIC, ERR_ATTESTATION; }
    let ea = check_aaguid_extension(cert, ad, c.message);
    return ATT_BASIC, ea;
}
