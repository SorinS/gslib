// kmip.client_pki: the client's certificate and split key operations:
// Certify and Re-certify (a PKCS #10 request, or a public key the server
// holds), Validate, Create Split Key and Join Split Key. Like the others
// in kmip.client, they take any client type: Client, or Local.
//
//   let cert_uid, e = kmip::certify(c, public_uid, csr_der, kmip::attrs());
//   let parts, e2 = kmip::create_split_key(c, key_uid, 5, 3, kmip::SPLIT_POLYNOMIAL_SHARING_GF_2_8, "", kmip::attrs());
//   let joined, e3 = kmip::join_split_key(c, kmip::OBJ_SYMMETRIC_KEY, parts[..3], 0, kmip::attrs());

namespace kmip;

import std;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.client;

// A PKCS #10 request (DER), in the tag of the version spoken: 1.x's
// Certificate Request, 2.0's Certificate Request Value.
fn put_csr(out: u8[>..]&, csr: const u8[:], v: Version) {
    if csr.len == 0 { return; }
    put_enum(out, TAG_CERTIFICATE_REQUEST_TYPE, CSR_PKCS_10);
    put_bytes(out, if is_v2(v) { TAG_CERTIFICATE_REQUEST_VALUE } else { TAG_CERTIFICATE_REQUEST }, csr);
}

// Certify: a certificate from the server for the public key uid (or, with
// uid "", for the request's key; the server's ID Placeholder when both
// are empty), from the request csr (DER; "" for none); its Unique
// Identifier.
fn certify<C>(c: C&, uid: const u8[:], csr: const u8[:], a: const Attrs&) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_CERTIFY, resp, doc) { out =>
        put_uid(out, uid);
        put_csr(out, csr, v);
        put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, eu = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, eu;
}

// Re-certify: a new certificate for the key pair of the certificate uid;
// offset (seconds, -1 for none) between its Initial and Activation Dates.
fn recertify<C>(c: C&, uid: const u8[:], csr: const u8[:], offset: i64, a: const Attrs&) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_RECERTIFY, resp, doc) { out =>
        put_uid(out, uid);
        put_csr(out, csr, v);
        if offset >= 0 { put_interval(out, TAG_OFFSET, offset as! u32); }
        put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, eu = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, eu;
}

// Validate: a chain of X.509 certificates, given as DER one after another
// (certs) and as the Unique Identifiers of ones the server holds, at the
// time `at` (seconds; 0 for now): VALIDITY_VALID, _INVALID or _UNKNOWN.
fn validate<C>(c: C&, certs: const u8[:], uids: const u8[..256][:], at: i64) -> u32, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    var bad = false;
    let p, e = call(c, OP_VALIDATE, resp, doc) { out =>
        var off = 0;
        while off < certs.len {
            let n = der_len(certs, off);
            if n <= 0 { bad = true; break; }
            let s = begin(out, TAG_CERTIFICATE);
            put_enum(out, TAG_CERTIFICATE_TYPE, CERT_X_509);
            put_bytes(out, TAG_CERTIFICATE_VALUE, certs[off..off + n]);
            end(out, s);
            off += n;
        }
        for u in uids { put_text(out, TAG_UNIQUE_IDENTIFIER, u); }
        if at != 0 { put_datetime(out, TAG_VALIDITY_DATE, at); }
    };
    if bad { return 0, ERR_MISSING; }
    if e != OK { return 0, e; }
    let vi, ok = child_enum(resp, doc, p, TAG_VALIDITY_INDICATOR);
    return vi, if ok { OK } else { ERR_MISSING };
}

// The length of the DER element at off (header included), 0 when it does
// not fit.
fn der_len(b: const u8[:], off: i64) -> i64 {
    if off + 2 > b.len { return 0; }
    let l0: i64 = b[off + 1];
    if l0 < 0x80 { return if off + 2 + l0 <= b.len { 2 + l0 } else { 0 }; }
    let nb = l0 & 0x7f;
    if nb == 0 || nb > 4 || off + 2 + nb > b.len { return 0; }
    var len: i64 = 0;
    for i in nb { len = (len << 8) | b[off + 2 + i]; }
    let total = 2 + nb + len;
    return if off + total <= b.len { total } else { 0 };
}

// Create Split Key: the key uid (or, with "", a new one of the attributes'
// algorithm and length) split into `parts` Split Keys, any `threshold` of
// them enough, by the method (SPLIT_XOR, SPLIT_POLYNOMIAL_SHARING_GF_2_8,
// ..._GF_2_16, ..._PRIME_FIELD with prime, big-endian); their Unique
// Identifiers, part 1's first.
fn create_split_key<C>(c: C&, uid: const u8[:], parts: i32, threshold: i32, method: u32, prime: const u8[:],
                       a: const Attrs&) -> u8[..256][>..], i64 {
    var uids: u8[..256][>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_CREATE_SPLIT_KEY, resp, doc) { out =>
        put_enum(out, TAG_OBJECT_TYPE, OBJ_SPLIT_KEY);
        put_uid(out, uid);
        put_int(out, TAG_SPLIT_KEY_PARTS, parts);
        put_int(out, TAG_SPLIT_KEY_THRESHOLD, threshold);
        put_enum(out, TAG_SPLIT_KEY_METHOD, method);
        if prime.len > 0 { put_biguint(out, TAG_PRIME_FIELD_SIZE, prime); }
        put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    };
    if e != OK { return uids, e; }
    var k = child(doc, p, TAG_UNIQUE_IDENTIFIER);
    while k >= 0 {
        let t, ok = as_text(resp, doc, k);
        if ok && t.len <= 256 {
            var u: u8[..256] = [];
            u.append(t);
            uids.push(u);
        }
        k = next_same(doc, k);
    }
    return uids, OK;
}

// Join Split Key: the Split Keys uids joined into an object of obj_type
// (OBJ_SYMMETRIC_KEY, OBJ_SECRET_DATA with secret_type, 0 for the
// server's choice, or OBJ_PRIVATE_KEY); its Unique Identifier.
fn join_split_key<C>(c: C&, obj_type: u32, uids: const u8[..256][:], secret_type: u32, a: const Attrs&) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_JOIN_SPLIT_KEY, resp, doc) { out =>
        put_enum(out, TAG_OBJECT_TYPE, obj_type);
        for u in uids { put_text(out, TAG_UNIQUE_IDENTIFIER, u); }
        if secret_type != 0 { put_enum(out, TAG_SECRET_DATA_TYPE, secret_type); }
        put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, eu = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, eu;
}
