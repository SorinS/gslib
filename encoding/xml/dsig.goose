// xml.dsig: XML Signature 1.1, the core of it that SAML uses: enveloped
// signatures over same-document references, signed and verified with
// gslib's x509 keys and certificates.
//
// Verification is built against signature wrapping. It verifies one
// Signature element the caller names, with a certificate the caller
// trusts (KeyInfo is never trusted; keyinfo_cert hands it over to be
// checked), and returns the node each Reference resolved to, so that the
// caller reads what was signed rather than learning that "the document is
// signed". A Reference URI is "" (the document) or "#id", an NCName that
// exactly one element of the document has as an ID; anything else (other
// documents, XPointer, a Reference without URI) is refused. Transforms are
// enveloped-signature and one canonicalization after it, nothing else;
// algorithms are a fixed list, SHA-1 only with VerifyOptions.allow_sha1.
// The SignatureValue over SignedInfo is checked before any Reference is
// looked at. verify_enveloped adds what SAML needs: the Signature is a
// child of the element, and its one Reference is that element.
//
// Signature methods: RSA PKCS #1 v1.5 and RSA-PSS (the xmldsig-more
// MGF1 forms, salt as long as the hash) with SHA-256, -384 and -512,
// ECDSA on P-256, P-384 and P-521 with the same, and Ed25519 (RFC 9231);
// RSA-SHA1 and ECDSA-SHA1 verify only, with allow_sha1. Digests: SHA-256,
// -384, -512; SHA-1 with allow_sha1.

namespace xml;

import std;
import base64;
import encoding.xml;
import encoding.xml.c14n;
import crypto.x509;
import crypto.x509.keys;
import crypto.bignum;
import crypto.bignum.ec;
import crypto.bignum.rsa;
import crypto.bignum.hmac;
import crypto.bignum.ct;

let DSIG_NS:     const u8[:] = "http://www.w3.org/2000/09/xmldsig#";
let DSIG11_NS:   const u8[:] = "http://www.w3.org/2009/xmldsig11#";
let EXC_C14N_NS: const u8[:] = "http://www.w3.org/2001/10/xml-exc-c14n#";

let URI_ENVELOPED: const u8[:] = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

let URI_SHA1:   const u8[:] = "http://www.w3.org/2000/09/xmldsig#sha1";
let URI_SHA256: const u8[:] = "http://www.w3.org/2001/04/xmlenc#sha256";
let URI_SHA384: const u8[:] = "http://www.w3.org/2001/04/xmldsig-more#sha384";
let URI_SHA512: const u8[:] = "http://www.w3.org/2001/04/xmlenc#sha512";

let URI_RSA_SHA1:       const u8[:] = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
let URI_RSA_SHA256:     const u8[:] = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
let URI_RSA_SHA384:     const u8[:] = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
let URI_RSA_SHA512:     const u8[:] = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
let URI_RSA_PSS_SHA256: const u8[:] = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
let URI_RSA_PSS_SHA384: const u8[:] = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
let URI_RSA_PSS_SHA512: const u8[:] = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
let URI_ECDSA_SHA1:     const u8[:] = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
let URI_ECDSA_SHA256:   const u8[:] = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
let URI_ECDSA_SHA384:   const u8[:] = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
let URI_ECDSA_SHA512:   const u8[:] = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
let URI_ED25519:        const u8[:] = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519";

// Errors of signing and verifying (beyond xml's).
let ERR_DSIG_MALFORMED: i64 = 20;    // a Signature not as XML Signature lays it out
let ERR_DSIG_ALGORITHM: i64 = 21;    // an algorithm not supported, or not allowed (SHA-1, HMAC)
let ERR_DSIG_REFERENCE: i64 = 22;    // a Reference URI other than "" or "#id"; too many References
let ERR_DSIG_ID:        i64 = 23;    // "#id" names no element, or more than one
let ERR_DSIG_TRANSFORM: i64 = 24;    // a transform not allowed, or in an order not allowed
let ERR_DSIG_DIGEST:    i64 = 25;    // a Reference's digest does not match
let ERR_DSIG_SIGNATURE: i64 = 26;    // the SignatureValue does not verify
let ERR_DSIG_KEY:       i64 = 27;    // the key does not fit the algorithm, or is too small
let ERR_DSIG_WRAPPING:  i64 = 28;    // verify_enveloped: not one Signature, or not over the element
let ERR_DSIG_SIGNING:   i64 = 29;    // signing failed (a fault, a key too small for the hash)

fn dsig_error_name(code: i64) -> const u8[:] {
    if code == ERR_DSIG_MALFORMED { return "malformed signature"; }
    if code == ERR_DSIG_ALGORITHM { return "algorithm not allowed"; }
    if code == ERR_DSIG_REFERENCE { return "reference not allowed"; }
    if code == ERR_DSIG_ID { return "ID not found or not unique"; }
    if code == ERR_DSIG_TRANSFORM { return "transform not allowed"; }
    if code == ERR_DSIG_DIGEST { return "digest mismatch"; }
    if code == ERR_DSIG_SIGNATURE { return "bad signature"; }
    if code == ERR_DSIG_KEY { return "key does not fit"; }
    if code == ERR_DSIG_WRAPPING { return "signature not over the element"; }
    if code == ERR_DSIG_SIGNING { return "signing failed"; }
    return error_name(code);
}

// The most References a signature may have.
let MAX_REFERENCES: i64 = 16;

struct VerifyOptions {
    allow_sha1:     bool = false,  // RSA-SHA1, ECDSA-SHA1 and SHA-1 digests
    max_references: i64  = 4,      // at most MAX_REFERENCES
    min_rsa_bits:   i64  = 2048,
}

fn verify_options() -> VerifyOptions { VerifyOptions { .. } }

// What verification found: OK, or an ERR_DSIG_* code with a message; and
// for each Reference, in order, the node it resolved to (0, the document,
// for URI ""), which is what was signed: its subtree, less the Signature
// when the Signature is inside it.
struct Verified {
    code:      i64       = OK,
    message:   u8[..256] = [],
    refs:      i64[..16] = [],
    signature: i64       = -1,
}

fn verified(v: const Verified&) -> bool { v.code == OK && v.refs.len > 0 }

// Whether n is in what v found signed: in the subtree of one of its
// References, and not in the Signature itself.
fn is_signed(d: const Doc&, v: const Verified&, n: i64) -> bool {
    if !verified(v) || within(d, v.signature, n) { return false; }
    for r in v.refs { if within(d, r, n) { return true; } }
    return false;
}

// --- algorithms ----------------------------------------------------------------------

// The hash (a bignum.hmac id) of a DigestMethod URI; 0 if not allowed.
fn digest_of_uri(uri: const u8[:], allow_sha1: bool) -> i64 {
    if uri == URI_SHA256 { return 256; }
    if uri == URI_SHA384 { return 384; }
    if uri == URI_SHA512 { return 512; }
    if uri == URI_SHA1 && allow_sha1 { return 160; }
    return 0;
}

fn digest_uri(h: i64) -> const u8[:] {
    if h == 384 { return URI_SHA384; }
    if h == 512 { return URI_SHA512; }
    if h == 160 { return URI_SHA1; }
    return URI_SHA256;
}

// The x509 SIG_* algorithm and hash of a SignatureMethod URI; SIG_UNKNOWN
// if not allowed.
fn sig_of_uri(uri: const u8[:], allow_sha1: bool) -> i64, i64 {
    if uri == URI_RSA_SHA256 { return x509::SIG_RSA_PKCS1, 256; }
    if uri == URI_RSA_SHA384 { return x509::SIG_RSA_PKCS1, 384; }
    if uri == URI_RSA_SHA512 { return x509::SIG_RSA_PKCS1, 512; }
    if uri == URI_RSA_PSS_SHA256 { return x509::SIG_RSA_PSS, 256; }
    if uri == URI_RSA_PSS_SHA384 { return x509::SIG_RSA_PSS, 384; }
    if uri == URI_RSA_PSS_SHA512 { return x509::SIG_RSA_PSS, 512; }
    if uri == URI_ECDSA_SHA256 { return x509::SIG_ECDSA, 256; }
    if uri == URI_ECDSA_SHA384 { return x509::SIG_ECDSA, 384; }
    if uri == URI_ECDSA_SHA512 { return x509::SIG_ECDSA, 512; }
    if uri == URI_ED25519 { return x509::SIG_ED25519, 0; }
    if allow_sha1 && uri == URI_RSA_SHA1 { return x509::SIG_RSA_PKCS1, 160; }
    if allow_sha1 && uri == URI_ECDSA_SHA1 { return x509::SIG_ECDSA, 160; }
    return x509::SIG_UNKNOWN, 0;
}

// The SignatureMethod URI of an algorithm and hash ("" for none we sign with).
fn sig_uri(alg: i64, h: i64) -> const u8[:] {
    if alg == x509::SIG_RSA_PKCS1 {
        return if h == 256 { URI_RSA_SHA256 } else if h == 384 { URI_RSA_SHA384 } else if h == 512 { URI_RSA_SHA512 } else { "" };
    }
    if alg == x509::SIG_RSA_PSS {
        return if h == 256 { URI_RSA_PSS_SHA256 } else if h == 384 { URI_RSA_PSS_SHA384 } else if h == 512 { URI_RSA_PSS_SHA512 } else { "" };
    }
    if alg == x509::SIG_ECDSA {
        return if h == 256 { URI_ECDSA_SHA256 } else if h == 384 { URI_ECDSA_SHA384 } else if h == 512 { URI_ECDSA_SHA512 } else { "" };
    }
    if alg == x509::SIG_ED25519 { return URI_ED25519; }
    return "";
}

// --- reading a Signature --------------------------------------------------------------

// A Reference as read: its element, the node its URI resolves to (after
// verification), the hash, the canonicalization (method 0: none, the
// default Canonical XML 1.0), whether enveloped-signature is applied, and
// the digest expected.
struct RefInfo {
    el:        i64,
    uri_el:    i64      = -1,
    hash:      i64      = 0,
    enveloped: bool     = false,
    c14n:      C14n     = C14n { method: 0, .. },
    digest:    u8[..64] = [],
}

fn bad(code: i64, msg: const u8[:]) -> Verified {
    var v = Verified { code: code, .. };
    // A message longer than the field is cut, and says so.
    if msg.len > v.message.cap { format(v.message, msg[..v.message.cap - 3], "..."); } else { format(v.message, msg); }
    return v;
}

// The Algorithm attribute of el, which must have one and no other
// attributes but those listed in `others` (space-separated).
fn algorithm_of(d: const Doc&, el: i64) -> const u8[:], bool {
    let v, ok = attr(d, el, "Algorithm");
    return v, ok;
}

// Whether el has attributes other than the unprefixed ones named in
// `allowed` (space-separated) and namespace declarations.
fn other_attrs(d: const Doc&, el: i64, allowed: const u8[:]) -> bool {
    var other = false;
    each_attr(d, el) { a =>
        if ns_uri(d, a).len > 0 { other = true; }
        else {
            var named = false;
            each_word(allowed) { if it == local_name(d, a) { named = true; } };
            if !named { other = true; }
        }
    };
    return other;
}

// The ds: element children of el, which must be all its element children.
fn ds_children(d: const Doc&, el: i64, out: i64[>..<]&) -> bool {
    if !only_elements(d, el) { return false; }
    var ok = true;
    each_element(d, el) { c => if ns_uri(d, c) != DSIG_NS { ok = false; } out.push(c); };
    return ok;
}

// A CanonicalizationMethod, or a Transform naming one: its C14n, with an
// InclusiveNamespaces PrefixList for the exclusive method. False for
// another algorithm or other content.
fn read_c14n(d: const Doc&, el: i64, uri: const u8[:]) -> C14n, bool {
    var m = C14n { .. };
    let method, comments, known = c14n_of_uri(uri);
    if !known { return m, false; }
    m.method = method;
    m.comments = comments;
    if !only_elements(d, el) { return m, false; }
    var good = true;
    var seen = 0;
    each_element(d, el) { c =>
        if method == EXC_C14N && is(d, c, EXC_C14N_NS, "InclusiveNamespaces") && seen == 0 && first_element(d, c) < 0
           && !other_attrs(d, c, "PrefixList") {
            let pl, has = attr(d, c, "PrefixList");
            if !has || pl.len > m.inclusive.cap || !prefix_list_ok(pl) { good = false; }
            else { format(m.inclusive, pl); }
            seen++;
        } else {
            good = false;
        }
    };
    return m, good;
}

// The parts of a Signature element, strictly: SignedInfo, SignatureValue,
// KeyInfo?, Object*, all in the ds namespace.
struct SigParts { signed_info: i64 = -1, c14n_method: i64 = -1, sig_method: i64 = -1, value: i64 = -1, key_info: i64 = -1 }

fn read_signature(d: const Doc&, sig: i64, refs: RefInfo[>..<]&, o: const VerifyOptions&) -> SigParts, Verified {
    var s = SigParts { .. };
    if !is(d, sig, DSIG_NS, "Signature") { return s, bad(ERR_DSIG_MALFORMED, "not a ds:Signature"); }
    var kids: i64[>..<] = [];
    if !ds_children(d, sig, kids) || other_attrs(d, sig, "Id") {
        return s, bad(ERR_DSIG_MALFORMED, "Signature has content other than ds: elements");
    }
    var i = 0;
    for k in kids {
        let name = local_name(d, k);
        if i == 0 && name == "SignedInfo" { s.signed_info = k; }
        else if i == 1 && name == "SignatureValue" { s.value = k; }
        else if i == 2 && name == "KeyInfo" { s.key_info = k; }
        else if i >= 2 && name == "Object" {}
        else { return s, bad(ERR_DSIG_MALFORMED, str("unexpected ds:", name, " in Signature")); }
        i++;
    }
    if s.signed_info < 0 || s.value < 0 { return s, bad(ERR_DSIG_MALFORMED, "Signature without SignedInfo and SignatureValue"); }
    if other_attrs(d, s.value, "Id") { return s, bad(ERR_DSIG_MALFORMED, "attributes on SignatureValue"); }

    var si: i64[>..<] = [];
    if !ds_children(d, s.signed_info, si) || other_attrs(d, s.signed_info, "Id") {
        return s, bad(ERR_DSIG_MALFORMED, "SignedInfo has content other than ds: elements");
    }
    if si.len < 3 || local_name(d, si[0]) != "CanonicalizationMethod" || local_name(d, si[1]) != "SignatureMethod" {
        return s, bad(ERR_DSIG_MALFORMED, "SignedInfo is not CanonicalizationMethod, SignatureMethod, Reference+");
    }
    s.c14n_method = si[0];
    s.sig_method = si[1];
    if si.len - 2 > o.max_references || si.len - 2 > MAX_REFERENCES {
        return s, bad(ERR_DSIG_REFERENCE, "too many References");
    }
    for j in 2..si.len {
        let r = si[j];
        if local_name(d, r) != "Reference" { return s, bad(ERR_DSIG_MALFORMED, str("unexpected ds:", local_name(d, r), " in SignedInfo")); }
        if other_attrs(d, r, "URI Id Type") { return s, bad(ERR_DSIG_MALFORMED, "unexpected attribute on Reference"); }
        var info = RefInfo { el: r, .. };
        var parts: i64[>..<] = [];
        if !ds_children(d, r, parts) { return s, bad(ERR_DSIG_MALFORMED, "Reference has content other than ds: elements"); }
        var at = 0;
        if parts.len > 0 && local_name(d, parts[0]) == "Transforms" {
            let ts = parts[0];
            var tl: i64[>..<] = [];
            if !ds_children(d, ts, tl) || tl.len == 0 || other_attrs(d, ts, "") {
                return s, bad(ERR_DSIG_MALFORMED, "Transforms is not Transform+");
            }
            if tl.len > 2 { return s, bad(ERR_DSIG_TRANSFORM, "more transforms than enveloped-signature and one canonicalization"); }
            var have_c14n = false;
            for t in tl {
                let alg, has = algorithm_of(d, t);
                if local_name(d, t) != "Transform" || !has || other_attrs(d, t, "Algorithm") {
                    return s, bad(ERR_DSIG_MALFORMED, "malformed Transform");
                }
                if alg == URI_ENVELOPED {
                    if info.enveloped || have_c14n || first_element(d, t) >= 0 || !only_elements(d, t) {
                        return s, bad(ERR_DSIG_TRANSFORM, "enveloped-signature not first, or twice");
                    }
                    info.enveloped = true;
                } else {
                    let m, okm = read_c14n(d, t, alg);
                    if !okm { return s, bad(ERR_DSIG_TRANSFORM, str("transform ", alg, " not allowed")); }
                    if have_c14n { return s, bad(ERR_DSIG_TRANSFORM, "two canonicalizations"); }
                    info.c14n = m;
                    have_c14n = true;
                }
            }
            at = 1;
        }
        if parts.len != at + 2 || local_name(d, parts[at]) != "DigestMethod" || local_name(d, parts[at + 1]) != "DigestValue" {
            return s, bad(ERR_DSIG_MALFORMED, "Reference is not Transforms?, DigestMethod, DigestValue");
        }
        let dm = parts[at];
        let dalg, dhas = algorithm_of(d, dm);
        if !dhas || first_element(d, dm) >= 0 || !only_elements(d, dm) || other_attrs(d, dm, "Algorithm") {
            return s, bad(ERR_DSIG_MALFORMED, "malformed DigestMethod");
        }
        info.hash = digest_of_uri(dalg, o.allow_sha1);
        if info.hash == 0 { return s, bad(ERR_DSIG_ALGORITHM, str("digest ", dalg, " not allowed")); }
        var dv: u8[>..] = [];
        if other_attrs(d, parts[at + 1], "") || !base64_content(d, parts[at + 1], dv) || dv.len != bignum::hash_len(info.hash) {
            return s, bad(ERR_DSIG_MALFORMED, "malformed DigestValue");
        }
        format(info.digest, dv);
        refs.push(info);
    }
    return s, Verified { .. };
}

// The node a Reference URI names: 0 for "", the one element with the ID
// for "#id"; an error for anything else, or an ID not found exactly once.
fn resolve_reference(d: const Doc&, r: i64) -> i64, Verified {
    let uri, has = attr(d, r, "URI");
    if !has { return -1, bad(ERR_DSIG_REFERENCE, "Reference without URI"); }
    if uri.len == 0 { return 0, Verified { .. }; }
    if uri[0] != '#' || !is_ncname(uri[1..]) {
        return -1, bad(ERR_DSIG_REFERENCE, str("Reference URI ", uri, " is not \"\" or #id"));
    }
    let el, count = by_id(d, uri[1..]);
    if count != 1 { return -1, bad(ERR_DSIG_ID, str("ID ", uri[1..], if count == 0 { " not found" } else { " not unique" })); }
    return el, Verified { .. };
}

// The digest of a Reference's node-set: n's subtree without comments,
// less the Signature when enveloped, canonicalized.
fn reference_digest(d: const Doc&, n: i64, info: const RefInfo&, sig: i64) -> u8[>..] {
    var m = C14n { .. };
    m.method = if info.c14n.method == 0 { C14N_10 } else { info.c14n.method };
    m.comments = false;   // same-document references drop comments (§4.4.3.3)
    format(m.inclusive, info.c14n.inclusive[..]);
    m.exclude = if info.enveloped { sig } else { -1 };
    var octets: u8[>..] = [];
    canonicalize(d, n, m, octets);
    return bignum::hash_bits(info.hash, octets);
}

// Verifies sig (raw: r || s for ECDSA, as XML Signature carries it) over
// msg by algorithm alg and hash h with cert's key.
fn verify_value(cert: const x509::Cert&, alg: i64, h: i64, msg: const u8[:], sig: const u8[:], o: const VerifyOptions&) -> i64 {
    if alg == x509::SIG_ED25519 {
        if cert.key_type != x509::KEY_ED25519 { return ERR_DSIG_KEY; }
        return if x509::verify_with(cert, alg, 0, 0, msg, sig) == x509::OK { OK } else { ERR_DSIG_SIGNATURE };
    }
    let digest = bignum::hash_bits(h, msg);
    if alg == x509::SIG_RSA_PKCS1 || alg == x509::SIG_RSA_PSS {
        if cert.key_type != x509::KEY_RSA { return ERR_DSIG_KEY; }
        let pub, okp = x509::rsa_public_key(cert);
        if !okp || bignum::rsa_bits(pub) < o.min_rsa_bits { return ERR_DSIG_KEY; }
        if sig.len != bignum::rsa_size(pub) { return ERR_DSIG_SIGNATURE; }
        return if x509::verify_digest(cert, alg, h, bignum::hash_len(h), digest, sig) == x509::OK { OK } else { ERR_DSIG_SIGNATURE };
    }
    if alg == x509::SIG_ECDSA {
        if cert.key_type != x509::KEY_EC_P256 && cert.key_type != x509::KEY_EC_P384 && cert.key_type != x509::KEY_EC_P521 {
            return ERR_DSIG_KEY;
        }
        let curve = x509::curve_of_key(cert.key_type);
        if sig.len != 2 * curve.len { return ERR_DSIG_SIGNATURE; }
        let der = bignum::ecdsa_sig_to_der(sig);
        return if x509::verify_digest(cert, alg, h, 0, digest, der) == x509::OK { OK } else { ERR_DSIG_SIGNATURE };
    }
    return ERR_DSIG_ALGORITHM;
}

// Verifies the Signature element sig of d with the key of cert, which the
// caller trusts. On success v.refs holds the node of each Reference; act
// only on those (is_signed tells whether a node is in them).
fn verify(d: const Doc&, sig: i64, cert: const x509::Cert&, o: const VerifyOptions&) -> Verified {
    var refs: RefInfo[>..<] = [];
    let s, v = read_signature(d, sig, refs, o);
    if v.code != OK { return v; }
    // SignedInfo, canonicalized by its method, and the signature over it.
    let calg, chas = algorithm_of(d, s.c14n_method);
    if !chas || other_attrs(d, s.c14n_method, "Algorithm") { return bad(ERR_DSIG_MALFORMED, "malformed CanonicalizationMethod"); }
    let cm, okc = read_c14n(d, s.c14n_method, calg);
    if !okc { return bad(ERR_DSIG_ALGORITHM, str("canonicalization ", calg, " not allowed")); }
    let salg, shas = algorithm_of(d, s.sig_method);
    if !shas || first_element(d, s.sig_method) >= 0 || !only_elements(d, s.sig_method) || other_attrs(d, s.sig_method, "Algorithm") {
        return bad(ERR_DSIG_MALFORMED, "malformed SignatureMethod");
    }
    let alg, h = sig_of_uri(salg, o.allow_sha1);
    if alg == x509::SIG_UNKNOWN { return bad(ERR_DSIG_ALGORITHM, str("signature method ", salg, " not allowed")); }
    var sv: u8[>..] = [];
    if !base64_content(d, s.value, sv) { return bad(ERR_DSIG_MALFORMED, "SignatureValue is not base64"); }
    var octets: u8[>..] = [];
    canonicalize(d, s.signed_info, cm, octets);
    let e = verify_value(cert, alg, h, octets, sv, o);
    if e != OK { return bad(e, if e == ERR_DSIG_KEY { "the key does not fit the signature method" } else { "SignatureValue does not verify" }); }
    // Only then the References.
    var out = Verified { signature: sig, .. };
    for &r in refs {
        let n, rv = resolve_reference(d, r.el);
        if rv.code != OK { return rv; }
        let got = reference_digest(d, n, r, sig);
        if got.len != r.digest.len || bignum::ct_eq_bytes(got, r.digest[..]) != 1 {
            return bad(ERR_DSIG_DIGEST, "a Reference's digest does not match");
        }
        out.refs.push(n);
    }
    return out;
}

fn verify(d: const Doc&, sig: i64, cert: const x509::Cert&) -> Verified {
    let o = verify_options();
    return verify(d, sig, cert, o);
}

// Verifies the enveloped signature of el, as SAML signs an assertion or
// a message: el has exactly one ds:Signature child, whose one Reference
// is el itself (by its ID, or URI "" when el is the document element).
fn verify_enveloped(d: const Doc&, el: i64, cert: const x509::Cert&, o: const VerifyOptions&) -> Verified {
    let n = count_children(d, el, DSIG_NS, "Signature");
    if n != 1 { return bad(ERR_DSIG_WRAPPING, if n == 0 { "element not signed" } else { "more than one Signature" }); }
    let sig = child(d, el, DSIG_NS, "Signature");
    let v = verify(d, sig, cert, o);
    if v.code != OK { return v; }
    if v.refs.len != 1 { return bad(ERR_DSIG_WRAPPING, "more than one Reference"); }
    let r = v.refs[0];
    if r != el && !(r == 0 && el == root_element(d)) { return bad(ERR_DSIG_WRAPPING, "the Reference is not the element"); }
    return v;
}

fn verify_enveloped(d: const Doc&, el: i64, cert: const x509::Cert&) -> Verified {
    let o = verify_options();
    return verify_enveloped(d, el, cert, o);
}

// The first X509Certificate of sig's KeyInfo (DER), and whether there is
// one. Not to be trusted as it is: match it against a certificate the
// caller trusts, or verify its chain.
fn keyinfo_cert(d: const Doc&, sig: i64) -> u8[>..], bool {
    var der: u8[>..] = [];
    let ki = child(d, sig, DSIG_NS, "KeyInfo");
    if ki < 0 { return der, false; }
    let xd = child(d, ki, DSIG_NS, "X509Data");
    if xd < 0 { return der, false; }
    let xc = child(d, xd, DSIG_NS, "X509Certificate");
    if xc < 0 || !base64_content(d, xc, der) { der.clear(); return der, false; }
    return der, true;
}

// The ds:Signature elements of the document, in document order.
fn find_signatures(d: const Doc&, out: i64[>..<]&) {
    walk(d, 0) { n, entering =>
        if entering && is(d, n, DSIG_NS, "Signature") { out.push(n); }
        true
    };
}

// --- signing ------------------------------------------------------------------------------

struct SignOptions {
    alg:          i64       = 0,        // x509 SIG_*; 0: the key's default (RSA PKCS #1, ECDSA, Ed25519)
    hash:         i64       = 256,      // of the signature method: 256, 384, 512 (not for Ed25519)
    digest:       i64       = 256,      // of the Reference
    c14n:         i64       = EXC_C14N, // of SignedInfo and of the Reference's transform
    inclusive:    u8[..256] = [],       // an InclusiveNamespaces PrefixList for EXC_C14N
    prefix:       u8[..32]  = "ds",     // of the Signature's elements; empty for the default namespace
    include_cert: bool      = true,     // KeyInfo with the certificate, when one is given
}

fn sign_options() -> SignOptions { SignOptions { .. } }

// A Signature element in the ds namespace with o's prefix.
fn ds_element(d: Doc&, parent: i64, before: i64, local: const u8[:], o: const SignOptions&) -> i64 {
    insert_element(d, parent, before, o.prefix[..], local, DSIG_NS)
}

fn ds_with_algorithm(d: Doc&, parent: i64, local: const u8[:], alg: const u8[:], o: const SignOptions&) -> i64 {
    let e = ds_element(d, parent, -1, local, o);
    set_attr(d, e, "Algorithm", alg);
    return e;
}

fn c14n_element(d: Doc&, parent: i64, local: const u8[:], o: const SignOptions&) -> i64 {
    let e = ds_with_algorithm(d, parent, local, c14n_uri(o.c14n, false), o);
    if o.c14n == EXC_C14N && o.inclusive.len > 0 {
        let inc = insert_element(d, e, -1, "ec", "InclusiveNamespaces", EXC_C14N_NS);
        set_attr(d, inc, "PrefixList", o.inclusive[..]);
    }
    return e;
}

// Signs el with an enveloped signature: a Signature element inserted into
// el before its child `before` (-1: last; SAML puts it after Issuer),
// whose Reference is el by its ID ("#" and the ID), or URI "" when el is
// the document element and has no ID. With cert_der, KeyInfo carries the
// certificate. The signature and OK, or -1 and an error.
fn sign_enveloped(d: Doc&, el: i64, before: i64, key: const x509::PrivateKey&, cert_der: const u8[:],
                  o: const SignOptions&) -> i64, i64 {
    var alg = o.alg;
    var h = o.hash;
    if alg == 0 {
        let da, dh = x509::default_sig(key.kind);
        alg = da;
        if alg == x509::SIG_ED25519 { h = 0; }
    }
    if alg == x509::SIG_ED25519 { h = 0; }
    let uri = sig_uri(alg, h);
    if uri.len == 0 || !x509::sig_fits_key(key.kind, alg, h) { return -1, ERR_DSIG_KEY; }
    if alg == x509::SIG_ECDSA && key.kind != x509::KEY_EC_P256 && key.kind != x509::KEY_EC_P384 && key.kind != x509::KEY_EC_P521 {
        return -1, ERR_DSIG_KEY;
    }
    if o.digest != 256 && o.digest != 384 && o.digest != 512 { return -1, ERR_DSIG_ALGORITHM; }
    if o.c14n != C14N_10 && o.c14n != C14N_11 && o.c14n != EXC_C14N { return -1, ERR_DSIG_ALGORITHM; }
    if !prefix_list_ok(o.inclusive[..]) { return -1, ERR_ARG; }
    var ref_uri: u8[>..] = [];
    let id, has_id = id_of(d, el);
    if has_id {
        let found, count = by_id(d, id);
        if count != 1 || found != el || !is_ncname(id) { return -1, ERR_DSIG_ID; }
        ref_uri.push('#');
        ref_uri.append(id);
    } else if el != root_element(d) {
        return -1, ERR_DSIG_ID;
    }
    let sig = ds_element(d, el, before, "Signature", o);
    if sig < 0 { return -1, ERR_ARG; }
    let si = ds_element(d, sig, -1, "SignedInfo", o);
    c14n_element(d, si, "CanonicalizationMethod", o);
    ds_with_algorithm(d, si, "SignatureMethod", uri, o);
    let r = ds_element(d, si, -1, "Reference", o);
    set_attr(d, r, "URI", ref_uri);
    let ts = ds_element(d, r, -1, "Transforms", o);
    ds_with_algorithm(d, ts, "Transform", URI_ENVELOPED, o);
    c14n_element(d, ts, "Transform", o);
    ds_with_algorithm(d, r, "DigestMethod", digest_uri(o.digest), o);
    let dv = ds_element(d, r, -1, "DigestValue", o);
    let sv = ds_element(d, sig, -1, "SignatureValue", o);
    if o.include_cert && cert_der.len > 0 {
        let ki = ds_element(d, sig, -1, "KeyInfo", o);
        let xd = ds_element(d, ki, -1, "X509Data", o);
        let xc = ds_element(d, xd, -1, "X509Certificate", o);
        var b: u8[>..] = [];
        base64::encode(b, cert_der);
        set_text(d, xc, b);
    }
    // The digest of el (or the document) without the Signature.
    var info = RefInfo { el: r, hash: o.digest, enveloped: true, .. };
    info.c14n.method = o.c14n;
    format(info.c14n.inclusive, o.inclusive[..]);
    let target = if ref_uri.len == 0 { 0 } else { el };
    let digest = reference_digest(d, target, info, sig);
    var db: u8[>..] = [];
    base64::encode(db, digest);
    set_text(d, dv, db);
    // The signature over SignedInfo.
    var m = C14n { method: o.c14n, .. };
    format(m.inclusive, o.inclusive[..]);
    var octets: u8[>..] = [];
    canonicalize(d, si, m, octets);
    var value, ok = x509::sign(key, alg, h, octets);
    if !ok { detach(d, sig); return -1, ERR_DSIG_SIGNING; }
    if alg == x509::SIG_ECDSA {
        let curve = x509::curve_of_key(key.kind);
        let raw, okr = bignum::ecdsa_sig_from_der(curve, value);
        if !okr { detach(d, sig); return -1, ERR_DSIG_SIGNING; }
        value.clear();
        value.append(raw);
    }
    var vb: u8[>..] = [];
    base64::encode(vb, value);
    set_text(d, sv, vb);
    return sig, OK;
}

fn sign_enveloped(d: Doc&, el: i64, before: i64, key: const x509::PrivateKey&, cert_der: const u8[:]) -> i64, i64 {
    let o = sign_options();
    let s, e = sign_enveloped(d, el, before, key, cert_der, o);
    return s, e;
}
