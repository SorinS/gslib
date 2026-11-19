// kmip.server_pki: the server's certificate and split key operations.
//
// Certify and Re-certify issue X.509 certificates from the server's CA
// (Server.ca_cert, Server.ca_key; without one they are refused), for a
// PKCS #10 request (DER or PEM) or for a public key the server holds;
// the certificate is kept with the attributes KMIP has the server set
// (Certificate Type and Length, X.509 Certificate Identifier, Subject and
// Issuer, Digital Signature Algorithm; 1.0's Certificate Identifier,
// Subject and Issuer) and linked to its public key. Validate checks a
// chain against the server's CA and the client's own self-signed CA
// certificates. Create Split Key splits a key the server holds, or one it
// makes, into Split Key objects; Join Split Key makes a key, secret data
// or private key of them again.

namespace kmip;

import std;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.split;
import kmip.server;
import kmip.server_manage;
import kmip.formats;
import crypto.x509;
import crypto.x509.keys;
import crypto.x509.create;
import crypto.x509.verify;
import crypto.x509.pkcs12;
import crypto.bignum.rsa;
import encoding.asn1;

// --- Certificates' attributes ----------------------------------------------------

fn sig_enum(c: const x509::Cert&) -> u32 {
    let h = c.sig_hash;
    if c.sig_alg == x509::SIG_RSA_PKCS1 {
        if h == 1 || h == 160 { return SIG_SHA1_WITH_RSA_ENCRYPTION; }
        if h == 224 { return SIG_SHA224_WITH_RSA_ENCRYPTION; }
        if h == 256 { return SIG_SHA256_WITH_RSA_ENCRYPTION; }
        if h == 384 { return SIG_SHA384_WITH_RSA_ENCRYPTION; }
        if h == 512 { return SIG_SHA512_WITH_RSA_ENCRYPTION; }
    }
    if c.sig_alg == x509::SIG_RSA_PSS { return SIG_RSASSA_PSS; }
    if c.sig_alg == x509::SIG_ECDSA {
        if h == 1 || h == 160 { return SIG_ECDSA_WITH_SHA1; }
        if h == 224 { return SIG_ECDSA_WITH_SHA224; }
        if h == 256 { return SIG_ECDSA_WITH_SHA256; }
        if h == 384 { return SIG_ECDSA_WITH_SHA384; }
        if h == 512 { return SIG_ECDSA_WITH_SHA512; }
    }
    return 0;
}

// Each GeneralName of a GeneralNames, as DER.
fn put_general_names(out: u8[>..]&, der: const u8[:], names: asn1::Tlv, tag: u32) {
    var at = names.off;
    while at < names.end {
        let g, ok = asn1::read(der, at, names.end);
        if !ok { return; }
        put_bytes(out, tag, der[g.start..g.end]);
        at = g.end;
    }
}

// Sets the attributes the server keeps for an X.509 certificate (der) in
// version v: Register, Certify and Re-certify set them. False when der is
// not a certificate.
fn cert_attrs(der: const u8[:], v: Version, a: Attrs&) -> bool {
    let c, e = x509::parse(der);
    if e != x509::OK { return false; }
    let ct = item_of_enum(TAG_CERTIFICATE_TYPE, CERT_X_509);
    set_single(a, ct);
    if version_lt(v, V2_0) {
        // 1.0's, deprecated in 1.1 and gone in 2.0: the names as text.
        var id: u8[>..] = [];
        let s1 = begin(id, TAG_CERTIFICATE_IDENTIFIER);
        put_text(id, TAG_ISSUER, x509::name_text(c.der, c.issuer));
        var serial: u8[>..] = [];
        for b in c.der[c.serial.off..c.serial.end] { format_uint(serial, b, 16, 2, '0'); }
        put_text(id, TAG_SERIAL_NUMBER, serial);
        end(id, s1);
        set_single(a, id);
        var sub: u8[>..] = [];
        let s2 = begin(sub, TAG_CERTIFICATE_SUBJECT);
        put_text(sub, TAG_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME, x509::name_text(c.der, c.subject));
        end(sub, s2);
        set_single(a, sub);
        var iss: u8[>..] = [];
        let s3 = begin(iss, TAG_CERTIFICATE_ISSUER);
        put_text(iss, TAG_CERTIFICATE_ISSUER_DISTINGUISHED_NAME, x509::name_text(c.der, c.issuer));
        end(iss, s3);
        set_single(a, iss);
        if version_lt(v, V1_1) { return true; }
    }
    let len = item_of_int(TAG_CERTIFICATE_LENGTH, der.len as! i32);
    set_single(a, len);
    var id: u8[>..] = [];
    let s1 = begin(id, TAG_X_509_CERTIFICATE_IDENTIFIER);
    put_bytes(id, TAG_ISSUER_DISTINGUISHED_NAME, c.der[c.issuer.start..c.issuer.end]);
    put_bytes(id, TAG_CERTIFICATE_SERIAL_NUMBER, c.der[c.serial.start..c.serial.end]);   // as OASIS's cases: the INTEGER, DER
    end(id, s1);
    set_single(a, id);
    var sub: u8[>..] = [];
    let s2 = begin(sub, TAG_X_509_CERTIFICATE_SUBJECT);
    put_bytes(sub, TAG_SUBJECT_DISTINGUISHED_NAME, c.der[c.subject.start..c.subject.end]);
    if c.has_san { put_general_names(sub, c.der, c.san, TAG_SUBJECT_ALTERNATIVE_NAME); }
    end(sub, s2);
    set_single(a, sub);
    var iss: u8[>..] = [];
    let s3 = begin(iss, TAG_X_509_CERTIFICATE_ISSUER);
    put_bytes(iss, TAG_ISSUER_DISTINGUISHED_NAME, c.der[c.issuer.start..c.issuer.end]);
    end(iss, s3);
    set_single(a, iss);
    let sg = sig_enum(c);
    if sg != 0 && !version_lt(v, V1_2) { let d = item_of_enum(TAG_DIGITAL_SIGNATURE_ALGORITHM, sg); set_single(a, d); }
    let kalg, kbits = cert_key(c);
    if kalg != 0 {
        let ia = item_of_enum(TAG_CRYPTOGRAPHIC_ALGORITHM, kalg);
        set_single(a, ia);
        let il = item_of_int(TAG_CRYPTOGRAPHIC_LENGTH, kbits);
        set_single(a, il);
    }
    for k in NAME_FIELDS.len { let g1 = remove_attr(a, NAME_FIELDS[k].subject, -1); let g2 = remove_attr(a, NAME_FIELDS[k].issuer, -1); }
    if !version_lt(v, V1_4) {
        put_name_fields(a, c.der, c.subject, true);
        put_name_fields(a, c.der, c.issuer, false);
    }
    return true;
}

// The algorithm and length of a certificate's key: RSA and its modulus's
// bits, EC and its curve's; 0 for others.
fn cert_key(c: const x509::Cert&) -> u32, i32 {
    if c.key_type == x509::KEY_RSA {
        // The subjectPublicKey BIT STRING holds RSAPublicKey after its unused-bits byte.
        if c.key.end - c.key.off < 2 { return 0, 0; }
        let ns, ok = der_uints(c.der[c.key.off + 1..c.key.end]);
        if !ok || ns.len != 2 { return 0, 0; }
        let bits = uint_bits(uint_at(c.der[c.key.off + 1..c.key.end], ns[0]));
        if bits == 0 { return 0, 0; }
        return ALG_RSA, bits as! i32;
    }
    if curve_of_kind(c.key_type) != 0 { return ALG_EC, x509::curve_of_key(c.key_type).bits as! i32; }
    return 0, 0;
}

// The bits of a big-endian unsigned integer.
fn uint_bits(n: const u8[:]) -> i64 {
    var i = 0;
    while i < n.len && n[i] == 0 { i++; }
    if i == n.len { return 0; }
    return (n.len - i) * 8 - (clz(n[i]) - 56);
}

// 1.4's attributes of each part of a certificate's subject and issuer
// (Certificate Subject CN, Certificate Issuer C, ...), by the part's OID.
struct NameField { oid: const u8[:], subject: u32, issuer: u32 }

let NAME_FIELDS: NameField[12] = [
    NameField { oid: "2.5.4.3", subject: TAG_CERTIFICATE_SUBJECT_CN, issuer: TAG_CERTIFICATE_ISSUER_CN },
    NameField { oid: "2.5.4.10", subject: TAG_CERTIFICATE_SUBJECT_O, issuer: TAG_CERTIFICATE_ISSUER_O },
    NameField { oid: "2.5.4.11", subject: TAG_CERTIFICATE_SUBJECT_OU, issuer: TAG_CERTIFICATE_ISSUER_OU },
    NameField { oid: "1.2.840.113549.1.9.1", subject: TAG_CERTIFICATE_SUBJECT_EMAIL, issuer: TAG_CERTIFICATE_ISSUER_EMAIL },
    NameField { oid: "2.5.4.6", subject: TAG_CERTIFICATE_SUBJECT_C, issuer: TAG_CERTIFICATE_ISSUER_C },
    NameField { oid: "2.5.4.8", subject: TAG_CERTIFICATE_SUBJECT_ST, issuer: TAG_CERTIFICATE_ISSUER_ST },
    NameField { oid: "2.5.4.7", subject: TAG_CERTIFICATE_SUBJECT_L, issuer: TAG_CERTIFICATE_ISSUER_L },
    NameField { oid: "0.9.2342.19200300.100.1.1", subject: TAG_CERTIFICATE_SUBJECT_UID, issuer: TAG_CERTIFICATE_ISSUER_UID },
    NameField { oid: "2.5.4.5", subject: TAG_CERTIFICATE_SUBJECT_SERIAL_NUMBER, issuer: TAG_CERTIFICATE_ISSUER_SERIAL_NUMBER },
    NameField { oid: "2.5.4.12", subject: TAG_CERTIFICATE_SUBJECT_TITLE, issuer: TAG_CERTIFICATE_ISSUER_TITLE },
    NameField { oid: "0.9.2342.19200300.100.1.25", subject: TAG_CERTIFICATE_SUBJECT_DC, issuer: TAG_CERTIFICATE_ISSUER_DC },
    NameField { oid: "2.5.4.46", subject: TAG_CERTIFICATE_SUBJECT_DN_QUALIFIER, issuer: TAG_CERTIFICATE_ISSUER_DN_QUALIFIER },
];

fn put_name_fields(a: Attrs&, der: const u8[:], name: asn1::Tlv, subject: bool) {
    for f in NAME_FIELDS {
        for v in x509::name_values(der, name, f.oid) { attr_text(a, if subject { f.subject } else { f.issuer }, v); }
    }
}

// One of 1.4's attributes of a part of a certificate's subject or issuer.
fn is_name_field(tag: u32) -> bool {
    return (tag >= TAG_CERTIFICATE_SUBJECT_CN && tag <= TAG_CERTIFICATE_SUBJECT_DN_QUALIFIER) ||
           (tag >= TAG_CERTIFICATE_ISSUER_CN && tag <= TAG_CERTIFICATE_ISSUER_DN_QUALIFIER);
}

// --- Links ----------------------------------------------------------------------

// The object a Link of the type points at, "" for none.
fn link_of(a: const Attrs&, link_type: u32) -> u8[>..] {
    var r: u8[>..] = [];
    each_attr(a) { t, item =>
        if t == TAG_LINK && r.len == 0 {
            var d: Node[>..] = [];
            let root, e = decode(item, Options { .. }, d);
            if e == OK {
                let lt, lok = child_enum(item, d, root, TAG_LINK_TYPE);
                let id, iok = child_text(item, d, root, TAG_LINKED_OBJECT_IDENTIFIER);
                if lok && iok && lt == link_type { r.append(id); }
            }
        }
    };
    return r;
}

// a with its Links of the type to `from` pointed at `to` instead.
fn relinked(a: const Attrs&, link_type: u32, from: const u8[:], to: const u8[:]) -> Attrs {
    var n = attrs();
    each_attr(a) { t, item =>
        var moved = false;
        if t == TAG_LINK {
            var d: Node[>..] = [];
            let root, e = decode(item, Options { .. }, d);
            if e == OK {
                let lt, lok = child_enum(item, d, root, TAG_LINK_TYPE);
                let id, iok = child_text(item, d, root, TAG_LINKED_OBJECT_IDENTIFIER);
                if lok && iok && lt == link_type && id == from { attr_link(n, link_type, to); moved = true; }
            }
        }
        if !moved { n.enc.append(item); }
    };
    return n;
}

fn add_link(s: Server&, owner: const u8[:], uid: const u8[:], link_type: u32, to: const u8[:]) {
    let i = find_object(s, owner, uid);
    if i < 0 { return; }
    var a = attrs_of(s.objects[i]);
    attr_link(a, link_type, to);
    let ok = set_attrs(s.objects[i], a);
}

// --- Issuing --------------------------------------------------------------------

// The PKCS #10 request a payload carries (Certificate Request, 2.0's
// Certificate Request Value), as DER; none is fine.
fn request_csr(buf: const u8[:], doc: const Node[:], p: i64, csr: u8[>..]&) -> Outcome {
    var k = child(doc, p, TAG_CERTIFICATE_REQUEST_VALUE);
    if k < 0 { k = child(doc, p, TAG_CERTIFICATE_REQUEST); }
    if k < 0 { return done(); }
    let b, bok = as_bytes(buf, doc, k);
    if !bok { return fail(REASON_INVALID_FIELD, "the Certificate Request is not a Byte String"); }
    let typ, tok = child_enum(buf, doc, p, TAG_CERTIFICATE_REQUEST_TYPE);
    if !tok { return fail(REASON_INVALID_MESSAGE, "a Certificate Request needs its Certificate Request Type"); }
    if typ == CSR_PKCS_10 { csr.append(b); return done(); }
    if typ == CSR_PEM {
        let ders, ok = asn1::pem_decode(b, "CERTIFICATE REQUEST");
        for d in ders { if csr.len == 0 { csr.append(d); } }
        if csr.len == 0 {
            let ders2, ok2 = asn1::pem_decode(b, "NEW CERTIFICATE REQUEST");
            for d in ders2 { if csr.len == 0 { csr.append(d); } }
        }
        if csr.len == 0 { return fail(REASON_INVALID_CSR, "no CERTIFICATE REQUEST in the PEM"); }
        return done();
    }
    return fail(REASON_FEATURE_NOT_SUPPORTED, "certificate requests here are PKCS #10, in DER or PEM");
}

// The key, subject and alternative names of a request, checked: its
// SubjectPublicKeyInfo, its Name, its GeneralNames' contents.
fn read_csr(csr: const u8[:], spki: u8[>..]&, subject: u8[>..]&, san: u8[>..]&) -> Outcome {
    let r, e = x509::parse_csr(csr);
    if e != x509::OK { return fail(REASON_INVALID_CSR, "the certificate request does not parse"); }
    if x509::check_csr(r) != x509::OK { return fail(REASON_INVALID_CSR, "the certificate request's signature does not verify"); }
    spki.append(r.der[r.spki.start..r.spki.end]);
    subject.append(r.der[r.subject.start..r.subject.end]);
    if r.has_san { san.append(r.der[r.san.off..r.san.end]); }
    return done();
}

// The subject a certificate without a request gets: the attributes'
// X.509 Certificate Subject (its names as DER), 1.x's Certificate Subject
// (as text), else CN= the object's first Name, else CN= its identifier.
fn subject_from(a: const Attrs&, key_attrs: const Attrs&, key_uid: const u8[:], subject: u8[>..]&, san: u8[>..]&) -> bool {
    let x = find_attr(a, TAG_X_509_CERTIFICATE_SUBJECT, 0);
    if x.len > 0 {
        var d: Node[>..] = [];
        let root, e = decode(x, Options { .. }, d);
        if e == OK {
            let dn, dok = child_bytes(x, d, root, TAG_SUBJECT_DISTINGUISHED_NAME);
            if dok { subject.append(dn); }
            var k = child(d, root, TAG_SUBJECT_ALTERNATIVE_NAME);
            while k >= 0 {
                let g, gok = as_bytes(x, d, k);
                if gok { san.append(g); }
                k = next_same(d, k);
            }
            return subject.len > 0 || san.len > 0;
        }
    }
    let c1 = find_attr(a, TAG_CERTIFICATE_SUBJECT, 0);
    if c1.len > 0 {
        var d: Node[>..] = [];
        let root, e = decode(c1, Options { .. }, d);
        if e == OK {
            let dn, dok = child_text(c1, d, root, TAG_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME);
            if dok {
                let n, nok = x509::name_der(dn);
                if nok { subject.append(n); return true; }
            }
        }
    }
    var cn: u8[>..] = [];
    cn.append("CN=");
    var name = get_name(a, 0);
    if name.len == 0 { name = get_name(key_attrs, 0); }
    if name.len > 0 { cn.append(name); } else { cn.append(key_uid); }
    let n, ok = x509::name_der(cn);
    if ok { subject.append(n); }
    return ok;
}

// A certificate from the server's CA for the key, a year from now.
fn issue(s: const Server&, spki: const u8[:], subject: const u8[:], san: const u8[:], cert: u8[>..]&) -> Outcome {
    if s.ca_cert.len == 0 || s.ca_key.len == 0 { return fail(REASON_FEATURE_NOT_SUPPORTED, "this server has no CA to issue certificates with"); }
    let k, kok = x509::parse_private_key(s.ca_key);
    if !kok { return fail(REASON_GENERAL_FAILURE, "the server's CA key is not readable"); }
    let now = now_of(s);
    var t, tok = x509::template("", now - 60, now + 365 * 86400);
    if subject.len > t.subject.cap || san.len > t.san.cap { return fail(REASON_INVALID_FIELD, "the subject or its names are too long"); }
    t.subject.clear();
    t.subject.append(subject);
    t.san.append(san);
    let der, e = x509::create_certificate(t, spki, s.ca_cert, k);
    if e != x509::OK { return fail(REASON_CRYPTOGRAPHIC_FAILURE, "the certificate could not be made for that key"); }
    cert.append(der);
    return done();
}

// The SubjectPublicKeyInfo of a public key object.
fn key_spki(s: const Server&, i: i64, spki: u8[>..]&) -> bool {
    let o, ok = object_of(s.objects[i]);
    if !ok || o.wrapped { return false; }
    let d, dok = spki_of_object(o);
    if !dok { return false; }
    spki.append(d);
    return true;
}

// Certify (1.0): a certificate for a public key, from a request or for a
// public key the server holds (named by its Unique Identifier, the ID
// Placeholder when neither is given, or by its private key's).
fn op_certify(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let a = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    let ct, ctok = get_enum(a, TAG_CERTIFICATE_TYPE);
    if ctok && ct != CERT_X_509 { return fail(REASON_FEATURE_NOT_SUPPORTED, "certificates here are X.509"); }
    var csr: u8[>..] = [];
    let rc = request_csr(buf, doc, p, csr);
    if rc.reason != 0 { return rc; }
    var spki: u8[>..] = [];
    var subject: u8[>..] = [];
    var san: u8[>..] = [];
    if csr.len > 0 {
        let r = read_csr(csr, spki, subject, san);
        if r.reason != 0 { return r; }
    }
    var key_uid: u8[>..] = [];
    var key_attrs = attrs();
    if child(doc, p, TAG_UNIQUE_IDENTIFIER) >= 0 || csr.len == 0 {
        var u: u8[>..] = [];
        u.append(uid_in(s, buf, doc, p));
        var i = find_object(s, owner, u);
        if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
        if s.objects[i].obj_type == OBJ_PRIVATE_KEY {
            let pa = attrs_of(s.objects[i]);
            let pub = link_of(pa, LINK_PUBLIC_KEY);
            key_attrs = copy(pa);                       // its names, for the subject
            u.clear();
            u.append(pub);
            i = find_object(s, owner, u);
            if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "the private key is linked to no public key here"); }
        }
        if s.objects[i].obj_type == OBJ_CERTIFICATE_REQUEST && csr.len == 0 {
            // 2.0: a Certificate Request object the client registered.
            let item = object_item_of(s.objects[i]);
            var d: Node[>..] = [];
            let root, e = decode(item, Options { .. }, d);
            if e != OK { return fail(REASON_INVALID_CSR, "the certificate request object does not read"); }
            let b, bok = child_bytes(item, d, root, TAG_CERTIFICATE_REQUEST_VALUE);
            if !bok { return fail(REASON_INVALID_CSR, "the certificate request object has no value"); }
            csr.append(b);
            let r = read_csr(csr, spki, subject, san);
            if r.reason != 0 { return r; }
        } else if s.objects[i].obj_type == OBJ_PUBLIC_KEY {
            var have: u8[>..] = [];
            if !key_spki(s, i, have) { return fail(REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED, "the public key is not one gslib reads"); }
            if spki.len > 0 && spki[..] != have[..] { return fail(REASON_INVALID_CSR, "the request is for another key"); }
            if spki.len == 0 { spki.append(have); }
            key_uid.append(u);
            if get_name(key_attrs, 0).len == 0 { key_attrs = attrs_of(s.objects[i]); }
        } else {
            return fail(REASON_INVALID_OBJECT_TYPE, "Certify takes a public key or a certificate request");
        }
    }
    if subject.len == 0 && san.len == 0 {
        if !subject_from(a, key_attrs, key_uid, subject, san) { return fail(REASON_INVALID_FIELD, "no subject for the certificate"); }
    }
    var der: u8[>..] = [];
    let ri = issue(s, spki, subject, san, der);
    if ri.reason != 0 { return ri; }
    let ca = without_server_only(a);
    var sa = attrs();
    let cok = cert_attrs(der, v, sa);
    if key_uid.len > 0 { attr_link(sa, LINK_PUBLIC_KEY, key_uid); }
    var uid: u8[>..] = [];
    let co = certificate(der);
    let r = add_object_with(s, owner, co, ca, sa, uid);
    if r.reason != 0 { return r; }
    if key_uid.len > 0 { add_link(s, owner, key_uid, LINK_CERTIFICATE, uid); }
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    return done();
}

// Re-certify (1.0): a new certificate for an existing one's key pair,
// taking over its names; the dates moved by the Offset, or copied.
fn op_recertify(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    var old: u8[>..] = [];
    old.append(uid_in(s, buf, doc, p));
    let i = find_object(s, owner, old);
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    if s.objects[i].obj_type != OBJ_CERTIFICATE { return fail(REASON_INVALID_OBJECT_TYPE, "Re-certify takes a certificate"); }
    let oo, ook = object_of(s.objects[i]);
    let oc, oe = x509::parse(oo.material);
    if !ook || oe != x509::OK { return fail(REASON_INVALID_OBJECT_TYPE, "the certificate is not X.509 gslib reads"); }
    let oa = attrs_of(s.objects[i]);
    let a = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    var csr: u8[>..] = [];
    let rc = request_csr(buf, doc, p, csr);
    if rc.reason != 0 { return rc; }
    var spki: u8[>..] = [];
    var subject: u8[>..] = [];
    var san: u8[>..] = [];
    let old_spki = oc.der[oc.spki.start..oc.spki.end];
    if csr.len > 0 {
        let r = read_csr(csr, spki, subject, san);
        if r.reason != 0 { return r; }
        if spki[..] != old_spki { return fail(REASON_INVALID_CSR, "Re-certify keeps the key pair; the request is for another key"); }
    } else {
        spki.append(old_spki);
        subject.append(oc.der[oc.subject.start..oc.subject.end]);
        if oc.has_san { san.append(oc.der[oc.san.off..oc.san.end]); }
    }
    var der: u8[>..] = [];
    let ri = issue(s, spki, subject, san, der);
    if ri.reason != 0 { return ri; }
    // The new one's attributes: the client's, the old one's names, its
    // public key, the dates, and the certificate's own.
    var na = attrs();
    na.enc.append(a.enc);
    var kept = attrs();
    each_attr(oa) { t, item => if t == TAG_NAME { na.enc.append(item); } else { kept.enc.append(item); } };
    let pub = link_of(oa, LINK_PUBLIC_KEY);
    if pub.len > 0 { attr_link(na, LINK_PUBLIC_KEY, pub); }
    attr_link(na, LINK_REPLACED_OBJECT, old);
    let now = now_of(s);
    let at1, a1 = get_datetime(oa, TAG_ACTIVATION_DATE);
    let dt1, d1 = get_datetime(oa, TAG_DEACTIVATION_DATE);
    let off, offok = as_interval(buf, doc, child(doc, p, TAG_OFFSET));
    var at2: i64 = 0;
    var has_at2 = false;
    if offok {
        at2 = now + off;
        has_at2 = true;
        if d1 && a1 { let dd = item_of_date(TAG_DEACTIVATION_DATE, dt1 + (at2 - at1)); set_single(na, dd); }
    } else {
        if a1 { at2 = at1; has_at2 = true; }
        if d1 { let dd = item_of_date(TAG_DEACTIVATION_DATE, dt1); set_single(na, dd); }
    }
    if has_at2 { let ad = item_of_date(TAG_ACTIVATION_DATE, at2); set_single(na, ad); }
    var sa = attrs();
    let cok = cert_attrs(der, v, sa);
    // The Names it takes over are handed to it, not given by a client.
    let given = without_server_only(na);
    var nc = attrs();
    each_attr(given) { tg, item => if tg == TAG_NAME { sa.enc.append(item); } else { nc.enc.append(item); } };
    var uid: u8[>..] = [];
    let co = certificate(der);
    let r = add_object_with(s, owner, co, nc, sa, uid);
    if r.reason != 0 { return r; }
    if has_at2 && at2 <= now {
        let k = find_object(s, owner, uid);
        if k >= 0 { let ok = set_state(s, s.objects[k], STATE_ACTIVE, 0); }
    }
    // The old one loses its names and points at its replacement; the
    // public key's Link to it now goes to the new one.
    attr_link(kept, LINK_REPLACEMENT_OBJECT, uid);
    let i2 = find_object(s, owner, old);
    if i2 >= 0 { let ok = set_attrs(s.objects[i2], kept); }
    rotate_after_replace(s, owner, old, uid);
    if pub.len > 0 {
        let j = find_object(s, owner, pub);
        if j >= 0 {
            let pa0 = attrs_of(s.objects[j]);
            let pa = relinked(pa0, LINK_CERTIFICATE, old, uid);
            let ok = set_attrs(s.objects[j], pa);
        }
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    return done();
}

// --- Validate -------------------------------------------------------------------

// Validate (1.0): a chain, given as Certificates and as Unique
// Identifiers of the client's, checked at the Validity Date (else now)
// against the server's CA and the client's self-signed CA certificates.
// The leaf is the certificate that issued none of the others; Unknown
// when no trusted root is found, Invalid when the chain fails otherwise.
fn op_validate(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    var chain: u8[][>..] = [];
    var k = child(doc, p, TAG_CERTIFICATE);
    while k >= 0 {
        let t, tok = child_enum(buf, doc, k, TAG_CERTIFICATE_TYPE);
        let der, dok = child_bytes(buf, doc, k, TAG_CERTIFICATE_VALUE);
        if !tok || !dok { return fail(REASON_INVALID_FIELD, "a Certificate without its type or value"); }
        if t != CERT_X_509 { return fail(REASON_FEATURE_NOT_SUPPORTED, "certificates here are X.509"); }
        chain.push(der);
        k = next_same(doc, k);
    }
    k = child(doc, p, TAG_UNIQUE_IDENTIFIER);
    while k >= 0 {
        let u, uok = as_text(buf, doc, k);
        if !uok { return fail(REASON_INVALID_FIELD, "a Unique Identifier not a Text String"); }
        let i = find_object(s, owner, u);
        if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
        if s.objects[i].obj_type != OBJ_CERTIFICATE { return fail(REASON_INVALID_OBJECT_TYPE, "Validate takes certificates"); }
        let o, ok = object_of(s.objects[i]);
        if !ok { return fail(REASON_GENERAL_FAILURE, "the certificate is not readable"); }
        chain.push(copy(o.material));
        k = next_same(doc, k);
    }
    if chain.len == 0 { return fail(REASON_INVALID_MESSAGE, "no certificates to validate"); }
    let when, wok = as_datetime(buf, doc, child(doc, p, TAG_VALIDITY_DATE));
    let at = if wok { when } else { now_of(s) };
    // The leaf: the first one whose subject issued none of the others.
    var leaf = -1;
    var n = 0;
    for der in chain {
        let c, e = x509::parse(der);
        if e != x509::OK {
            put_enum(out, TAG_VALIDITY_INDICATOR, VALIDITY_INVALID);
            return done();
        }
        var issuer_of_other = false;
        var m = 0;
        for other in chain {
            if m != n {
                let c2, e2 = x509::parse(other);
                if e2 == x509::OK && c2.der[c2.issuer.start..c2.issuer.end] == c.der[c.subject.start..c.subject.end] &&
                   other != der { issuer_of_other = true; }
            }
            m++;
        }
        if leaf < 0 && !issuer_of_other { leaf = n; }
        n++;
    }
    if leaf < 0 { leaf = 0; }
    var leaf_der: u8[>..] = [];
    var inters: u8[>..] = [];
    var roots: u8[>..] = [];
    n = 0;
    for der in chain {
        if n == leaf { leaf_der.append(der); } else { inters.append(der); }
        n++;
    }
    roots.append(s.ca_cert);
    for m in s.objects {
        if m.obj_type == OBJ_CERTIFICATE && m.owner[..] == owner {
            let o, ok = object_of(m);
            if ok {
                let c, e = x509::parse(o.material);
                if e == x509::OK && c.is_ca && c.der[c.subject.start..c.subject.end] == c.der[c.issuer.start..c.issuer.end] {
                    roots.append(o.material);
                }
            }
        }
    }
    var opts = x509::options();
    opts.key_usages = x509::EKU_ANY;
    let r = x509::verify_chain_with(leaf_der, inters, roots, "", at, "", opts);
    let vi = if r == x509::OK { VALIDITY_VALID } else if r == x509::ERR_UNKNOWN_ISSUER { VALIDITY_UNKNOWN } else { VALIDITY_INVALID };
    put_enum(out, TAG_VALIDITY_INDICATOR, vi);
    return done();
}

// --- Split keys -----------------------------------------------------------------

// Create Split Key (1.2): a key the server holds (by its Unique
// Identifier), or a new one of the attributes' algorithm and length, split
// into Split Key Parts objects; their identifiers, part 1's first.
fn op_create_split_key(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let t, tok = child_enum(buf, doc, p, TAG_OBJECT_TYPE);
    if !tok { return fail(REASON_INVALID_MESSAGE, "no Object Type"); }
    if t != OBJ_SPLIT_KEY { return fail(REASON_INVALID_OBJECT_TYPE, "Create Split Key makes Split Keys"); }
    let n, nok = child_int(buf, doc, p, TAG_SPLIT_KEY_PARTS);
    let th, thok = child_int(buf, doc, p, TAG_SPLIT_KEY_THRESHOLD);
    let method, mok = child_enum(buf, doc, p, TAG_SPLIT_KEY_METHOD);
    if !nok || !thok || !mok { return fail(REASON_INVALID_MESSAGE, "Split Key Parts, Threshold and Method are needed"); }
    if n < 1 || n > 1024 || th < 1 || th > n { return fail(REASON_INVALID_FIELD, "a threshold from 1 to the parts, up to 1024 parts"); }
    var prime: u8[>..] = [];
    if method == SPLIT_POLYNOMIAL_SHARING_PRIME_FIELD {
        let pr, pok = as_biguint(buf, doc, child(doc, p, TAG_PRIME_FIELD_SIZE));
        if !pok || pr.len > 512 { return fail(REASON_INVALID_FIELD, "the prime field needs a Prime Field Size, up to 4096 bits"); }
        prime.append(pr);
    } else if method != SPLIT_XOR && method != SPLIT_POLYNOMIAL_SHARING_GF_2_8 && method != SPLIT_POLYNOMIAL_SHARING_GF_2_16 {
        return fail(REASON_INVALID_FIELD, "an unknown Split Key Method");
    }
    let a = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    var src = new_object(OBJ_SYMMETRIC_KEY);
    if child(doc, p, TAG_UNIQUE_IDENTIFIER) >= 0 {
        let i = find_object(s, owner, uid_in(s, buf, doc, p));
        if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
        let o, ok = object_of(s.objects[i]);
        if !ok { return fail(REASON_GENERAL_FAILURE, "the object is not readable"); }
        if o.obj_type != OBJ_SYMMETRIC_KEY && o.obj_type != OBJ_PRIVATE_KEY && o.obj_type != OBJ_SECRET_DATA {
            return fail(REASON_INVALID_OBJECT_TYPE, "keys and secret data are split");
        }
        if o.wrapped { return fail(REASON_INVALID_OBJECT_TYPE, "a wrapped key is not split"); }
        src = copy(o);
    } else {
        let alg, aok = get_enum(a, TAG_CRYPTOGRAPHIC_ALGORITHM);
        let bits, lok = get_int(a, TAG_CRYPTOGRAPHIC_LENGTH);
        if !aok || !lok || bits < 8 || bits > 4096 || bits % 8 != 0 {
            return fail(REASON_INVALID_FIELD, "a new key to split needs a Cryptographic Algorithm and a Length of whole bytes");
        }
        src = symmetric_key(alg, new_key_bytes(bits as i64 / 8));
    }
    if src.key_format == FMT_TRANSPARENT_SYMMETRIC_KEY { src.key_format = FMT_RAW; }
    var shares: u8[>..] = [];
    let sok, slen = split_secret(method, src.material, n, th, prime, shares);
    if !sok {
        return fail(REASON_INVALID_FIELD, "the method does not take those (XOR: threshold = parts; GF(2^8): up to 255 parts; GF(2^16): an even length; prime field: a prime above the key)");
    }
    if src.length == 0 { src.length = (src.material.len * 8) as! i32; }
    for x in n as i64 {
        var o = new_object(OBJ_SPLIT_KEY);
        o.key_format = src.key_format;
        o.alg = src.alg;
        o.length = src.length;
        o.parts = n;
        o.part_id = (x + 1) as! i32;
        o.threshold = th;
        o.split_method = method;
        o.prime.append(prime);
        o.material.append(shares[x * slen..(x + 1) * slen]);
        var uid: u8[>..] = [];
        let r = add_object(s, owner, o, a, uid);
        if r.reason != 0 { return r; }
        put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    }
    return done();
}

// Join Split Key (1.2): the Split Keys named, at least their threshold of
// them, joined into a symmetric key, secret data or private key.
fn op_join_split_key(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let t, tok = child_enum(buf, doc, p, TAG_OBJECT_TYPE);
    if !tok { return fail(REASON_INVALID_MESSAGE, "no Object Type"); }
    if t != OBJ_SYMMETRIC_KEY && t != OBJ_SECRET_DATA && t != OBJ_PRIVATE_KEY {
        return fail(REASON_INVALID_OBJECT_TYPE, "split keys are joined into keys and secret data");
    }
    var first = new_object(0);
    var xs: i64[>..] = [];
    var shares: u8[>..] = [];
    var k = child(doc, p, TAG_UNIQUE_IDENTIFIER);
    while k >= 0 {
        let u, uok = as_text(buf, doc, k);
        if !uok { return fail(REASON_INVALID_FIELD, "a Unique Identifier not a Text String"); }
        let i = find_object(s, owner, u);
        if i < 0 { return fail(REASON_OBJECT_NOT_FOUND, "no such object"); }
        if s.objects[i].obj_type != OBJ_SPLIT_KEY { return fail(REASON_INVALID_OBJECT_TYPE, "Join Split Key takes Split Keys"); }
        let o, ok = object_of(s.objects[i]);
        if !ok { return fail(REASON_GENERAL_FAILURE, "the split key is not readable"); }
        if xs.len == 0 {
            first = copy(o);
        } else if o.parts != first.parts || o.threshold != first.threshold || o.split_method != first.split_method ||
                  o.prime[..] != first.prime[..] || o.material.len != first.material.len {
            return fail(REASON_INVALID_FIELD, "the split keys are not parts of one split");
        }
        for x in xs { if x == o.part_id { return fail(REASON_INVALID_FIELD, "a part named twice"); } }
        xs.push(o.part_id);
        shares.append(o.material);
        k = next_same(doc, k);
    }
    if xs.len == 0 { return fail(REASON_INVALID_MESSAGE, "no split keys named"); }
    if xs.len < first.threshold { return fail(REASON_CRYPTOGRAPHIC_FAILURE, "fewer parts than the split key's threshold"); }
    let a = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    var len = first.material.len;
    if first.split_method == SPLIT_POLYNOMIAL_SHARING_PRIME_FIELD {
        let bits, bok = get_int(a, TAG_CRYPTOGRAPHIC_LENGTH);
        len = if first.length > 0 { (first.length as i64 + 7) / 8 } else if bok { (bits as i64 + 7) / 8 } else { first.prime.len - 1 };
    }
    var secret: u8[>..] = [];
    if !join_secret(first.split_method, xs, shares, first.material.len, first.prime, len, secret) {
        return fail(REASON_CRYPTOGRAPHIC_FAILURE, "the parts do not join");
    }
    var o = new_object(t);
    let alg, aok = get_enum(a, TAG_CRYPTOGRAPHIC_ALGORITHM);
    let key_alg = if first.alg != 0 { first.alg } else if aok { alg } else { 0 };
    if t == OBJ_SECRET_DATA {
        let st, stok = child_enum(buf, doc, p, TAG_SECRET_DATA_TYPE);
        o = secret_data(if stok { st } else { SECRET_SEED }, secret);
    } else if t == OBJ_PRIVATE_KEY {
        let fmt = if first.key_format != 0 { first.key_format } else { FMT_PKCS_8 };
        o = private_key(key_alg, first.length, fmt, secret);
    } else {
        o = symmetric_key(key_alg, secret);
        if first.key_format != 0 { o.key_format = first.key_format; }
    }
    var uid: u8[>..] = [];
    let r = add_object(s, owner, o, a, uid);
    if r.reason != 0 { return r; }
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    return done();
}

// --- PKCS #12 ---------------------------------------------------------------------

// The password a private key's PKCS_12 Password Link names: Secret Data
// that is Active (Wrong Key Lifecycle State otherwise, as the test cases
// have it).
fn pkcs12_password(s: const Server&, owner: const u8[:], a: const Attrs&, pw: u8[>..]&) -> Outcome {
    let uid = link_of(a, LINK_PKCS12_PASSWORD);
    if uid.len == 0 { return fail(REASON_INVALID_FIELD, "PKCS #12 needs a PKCS_12 Password Link"); }
    let i = find_object(s, owner, uid);
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such password"); }
    if s.objects[i].state != STATE_ACTIVE { return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "the password is not Active"); }
    let o, ok = object_of(s.objects[i]);
    if !ok || o.obj_type != OBJ_SECRET_DATA || o.wrapped { return fail(REASON_INVALID_OBJECT_TYPE, "the password is not Secret Data"); }
    pw.append(o.material);
    return done();
}

// The algorithm and length of a private key.
fn private_alg(k: const x509::PrivateKey&) -> u32, i32 {
    if k.kind == x509::KEY_RSA { return ALG_RSA, bignum::ct_bit_len(k.rsa.n) as! i32; }
    if curve_of_kind(k.kind) != 0 { return ALG_EC, x509::curve_of_key(k.kind).bits as! i32; }
    return 0, 0;
}

// A private key as PKCS #12: the key, the certificates its PKCS_12
// Certificate Links name one after the other (the key's, then its
// issuer's, ...), under the password of its PKCS_12 Password Link.
fn pkcs12_of(s: const Server&, owner: const u8[:], o: const Object&, a: const Attrs&) -> Object, Outcome {
    var r = new_object(OBJ_PRIVATE_KEY);
    var pw: u8[>..] = [];
    let po = pkcs12_password(s, owner, a, pw);
    if po.reason != 0 { return r, po; }
    let k, kok = private_of(o);
    if !kok { return r, fail(REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED, "the key does not go into PKCS #12"); }
    var certs: u8[>..] = [];
    var next = link_of(a, LINK_PKCS12_CERTIFICATE);
    var n = 0;
    while next.len > 0 && n < 10 {
        let i = find_object(s, owner, next);
        if i < 0 { break; }
        let c, cok = object_of(s.objects[i]);
        if !cok || c.obj_type != OBJ_CERTIFICATE { break; }
        certs.append(c.material);
        let ca = attrs_of(s.objects[i]);
        next = link_of(ca, LINK_PKCS12_CERTIFICATE);
        n++;
    }
    let pfx, e = x509::pkcs12_encode(x509::marshal_pkcs8(k), certs, pw);
    if e != x509::OK { return r, fail(REASON_INVALID_FIELD, "the password does not go into PKCS #12"); }
    r.key_format = FMT_PKCS_12;
    r.material.append(pfx);
    return r, done();
}

// Registers a private key given as PKCS #12, opened with the password of
// its PKCS_12 Password Link: the key, kept as PKCS #8 with the attributes
// given, and each certificate in the file, the key's first and then its
// issuers', each linked to the next by a PKCS_12 Certificate Link (the
// key to its own) and given the key's PKCS_12 Friendly Name. The key's
// identifier into uid.
fn register_pkcs12(s: Server&, owner: const u8[:], v: Version, o: const Object&, a: const Attrs&, uid: u8[>..]&) -> Outcome {
    var pw: u8[>..] = [];
    let po = pkcs12_password(s, owner, a, pw);
    if po.reason != 0 { return po; }
    let p8, certs, e = x509::pkcs12_decode(o.material, pw);
    if e == x509::ERR_BAD_SIGNATURE { return fail(REASON_CRYPTOGRAPHIC_FAILURE, "the PKCS #12 file does not open with the password"); }
    if e != x509::OK || p8.len == 0 { return fail(REASON_INVALID_FIELD, "not a PKCS #12 file of one key"); }
    let k, kok = x509::parse_private_key(p8);
    let alg, bits = private_alg(k);
    if !kok || alg == 0 { return fail(REASON_INVALID_FIELD, "the PKCS #12 file's key is not RSA or EC"); }
    // The certificates in chain order: the key's, then each one's issuer;
    // the rest after.
    var ders: asn1::Tlv[>..] = [];
    var at = 0;
    while at < certs.len {
        let t, ok = asn1::read(certs, at, certs.len);
        if !ok { return fail(REASON_INVALID_FIELD, "a certificate in the PKCS #12 file is not DER"); }
        ders.push(t);
        at = t.end;
    }
    var order: i64[>..] = [];
    let spki = x509::marshal_public_key(k);
    var cur: i64 = -1;
    for j in ders.len {
        let c, ce = x509::parse(certs[ders[j].start..ders[j].end]);
        if ce == x509::OK && c.der[c.spki.start..c.spki.end] == spki[..] { cur = j; }
    }
    while cur >= 0 && order.len < ders.len {
        order.push(cur);
        let c, ce = x509::parse(certs[ders[cur].start..ders[cur].end]);
        var up: i64 = -1;
        for j in ders.len {
            var seen = false;
            for x in order { if x == j { seen = true; } }
            if seen { continue; }
            let d, de = x509::parse(certs[ders[j].start..ders[j].end]);
            if de == x509::OK && d.der[d.subject.start..d.subject.end] == c.der[c.issuer.start..c.issuer.end] { up = j; }
        }
        cur = up;
    }
    for j in ders.len {
        var seen = false;
        for x in order { if x == j { seen = true; } }
        if !seen { order.push(j); }
    }
    let key = private_key(alg, bits, FMT_PKCS_8, p8);
    let none = attrs();
    let r = add_object_with(s, owner, key, a, none, uid);
    if r.reason != 0 { return r; }
    let fname, fok = get_text(a, TAG_PKCS12_FRIENDLY_NAME);
    var prev: u8[>..] = [];
    prev.append(uid);
    for j in order {
        var sa = attrs();
        if !cert_attrs(certs[ders[j].start..ders[j].end], v, sa) { return fail(REASON_INVALID_FIELD, "a certificate in the PKCS #12 file is not read"); }
        var ca = attrs();
        if fok { attr_text(ca, TAG_PKCS12_FRIENDLY_NAME, fname); }
        let c = certificate(certs[ders[j].start..ders[j].end]);
        var cu: u8[>..] = [];
        let rc = add_object_with(s, owner, c, ca, sa, cu);
        if rc.reason != 0 { return rc; }
        link_both(s, prev, LINK_PKCS12_CERTIFICATE, cu, owner);
        prev.clear();
        prev.append(cu);
    }
    return done();
}
