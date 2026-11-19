// kmip.formats: a key in the Key Format Type asked for. Private keys go
// between PKCS #1 (RSA), PKCS #8, ECPrivateKey (SEC 1) and the
// Transparent RSA, EC (1.x's ECDSA, ECDH and ECMQV too) and DSA Private
// Key structures; public keys between X.509 SubjectPublicKeyInfo, PKCS #1
// (RSA) and the Transparent public key structures; symmetric keys between
// Raw and Transparent Symmetric Key. A transparent key's material is its
// Key Material Structure, encoded, as objects.goose keeps it.
//
//   let o2, reason = kmip::convert_key(o, kmip::FMT_TRANSPARENT_RSA_PRIVATE_KEY);

namespace kmip;

import std;
import kmip;
import kmip.tables;
import kmip.objects;
import crypto.bignum;
import crypto.x509;
import crypto.x509.keys;
import encoding.asn1;

// KMIP's Recommended Curve for an x509 key kind, and back; 0 and
// KEY_UNKNOWN for none.
fn curve_of_kind(kind: i64) -> u32 {
    if kind == x509::KEY_EC_P256 { return CURVE_P_256; }
    if kind == x509::KEY_EC_P384 { return CURVE_P_384; }
    if kind == x509::KEY_EC_P521 { return CURVE_P_521; }
    if kind == x509::KEY_EC_P224 { return CURVE_P_224; }
    if kind == x509::KEY_EC_BP256 { return CURVE_BRAINPOOLP256R1; }
    if kind == x509::KEY_EC_BP384 { return CURVE_BRAINPOOLP384R1; }
    if kind == x509::KEY_EC_BP512 { return CURVE_BRAINPOOLP512R1; }
    if kind == x509::KEY_EC_SECP256K1 { return CURVE_SECP256K1; }
    return 0;
}

fn kind_of_curve(c: u32) -> i64 {
    if c == CURVE_P_256 { return x509::KEY_EC_P256; }
    if c == CURVE_P_384 { return x509::KEY_EC_P384; }
    if c == CURVE_P_521 { return x509::KEY_EC_P521; }
    if c == CURVE_P_224 { return x509::KEY_EC_P224; }
    if c == CURVE_BRAINPOOLP256R1 { return x509::KEY_EC_BP256; }
    if c == CURVE_BRAINPOOLP384R1 { return x509::KEY_EC_BP384; }
    if c == CURVE_BRAINPOOLP512R1 { return x509::KEY_EC_BP512; }
    if c == CURVE_SECP256K1 { return x509::KEY_EC_SECP256K1; }
    return x509::KEY_UNKNOWN;
}

fn is_transparent_private(f: u32) -> bool {
    f == FMT_TRANSPARENT_RSA_PRIVATE_KEY || f == FMT_TRANSPARENT_DSA_PRIVATE_KEY || f == FMT_TRANSPARENT_DH_PRIVATE_KEY ||
    f == FMT_TRANSPARENT_ECDSA_PRIVATE_KEY || f == FMT_TRANSPARENT_ECDH_PRIVATE_KEY ||
    f == FMT_TRANSPARENT_ECMQV_PRIVATE_KEY || f == FMT_TRANSPARENT_EC_PRIVATE_KEY
}

fn is_transparent_public(f: u32) -> bool {
    f == FMT_TRANSPARENT_RSA_PUBLIC_KEY || f == FMT_TRANSPARENT_DSA_PUBLIC_KEY || f == FMT_TRANSPARENT_DH_PUBLIC_KEY ||
    f == FMT_TRANSPARENT_ECDSA_PUBLIC_KEY || f == FMT_TRANSPARENT_ECDH_PUBLIC_KEY ||
    f == FMT_TRANSPARENT_ECMQV_PUBLIC_KEY || f == FMT_TRANSPARENT_EC_PUBLIC_KEY
}

// Whether a format's Key Material is a Structure.
fn is_transparent(f: u32) -> bool { f == FMT_TRANSPARENT_SYMMETRIC_KEY || is_transparent_private(f) || is_transparent_public(f) }

fn is_ec_transparent(f: u32) -> bool {
    f == FMT_TRANSPARENT_ECDSA_PRIVATE_KEY || f == FMT_TRANSPARENT_ECDH_PRIVATE_KEY || f == FMT_TRANSPARENT_ECMQV_PRIVATE_KEY ||
    f == FMT_TRANSPARENT_EC_PRIVATE_KEY || f == FMT_TRANSPARENT_ECDSA_PUBLIC_KEY || f == FMT_TRANSPARENT_ECDH_PUBLIC_KEY ||
    f == FMT_TRANSPARENT_ECMQV_PUBLIC_KEY || f == FMT_TRANSPARENT_EC_PUBLIC_KEY
}

// The INTEGERs of a DER SEQUENCE; uint_at gives one's magnitude (with a
// leading zero byte when its top bit is set, which put_biguint drops).
fn der_uints(der: const u8[:]) -> asn1::Tlv[>..], bool {
    var out: asn1::Tlv[>..] = [];
    let t, ok = asn1::parse(der);
    if !ok { return out, false; }
    let kids, kok = asn1::children_of(der, t, asn1::SEQUENCE);
    if !kok { return out, false; }
    for k in kids {
        if k.tag != asn1::INTEGER || asn1::content_len(k) == 0 || der[k.off] & 0x80 != 0 { return out, false; }
        out.push(k);
    }
    return out, true;
}

fn uint_at(der: const u8[:], t: asn1::Tlv) -> const u8[:] { der[t.off..t.end] }

// --- Private keys -----------------------------------------------------------------

// The private key an object holds, in any of the formats above.
fn private_of(o: const Object&) -> x509::PrivateKey, bool {
    var k = x509::empty_key();
    let f = o.key_format;
    if f == FMT_PKCS_1 || f == FMT_PKCS_8 || f == FMT_EC_PRIVATE_KEY {
        let p, ok = x509::parse_private_key(o.material);
        return p, ok;
    }
    if !is_transparent_private(f) { return k, false; }
    var doc: Node[>..] = [];
    let r, e = decode(o.material, Options { .. }, doc);
    if e != OK || !is_type(doc, r, STRUCTURE) { return k, false; }
    let buf = o.material[..];
    if f == FMT_TRANSPARENT_RSA_PRIVATE_KEY {
        let n, a = as_biguint(buf, doc, child(doc, r, TAG_MODULUS));
        let ex, b = as_biguint(buf, doc, child(doc, r, TAG_PUBLIC_EXPONENT));
        let d, c = as_biguint(buf, doc, child(doc, r, TAG_PRIVATE_EXPONENT));
        let p, pp = as_biguint(buf, doc, child(doc, r, TAG_P));
        let q, qq = as_biguint(buf, doc, child(doc, r, TAG_Q));
        if !a || !b || !c || !pp || !qq { return k, false; }
        let rk, ok = bignum::rsa_key_from_bytes(n, ex, d, p, q);
        if !ok { return k, false; }
        k.kind = x509::KEY_RSA;
        k.rsa = rk;
        return k, true;
    }
    if f == FMT_TRANSPARENT_DSA_PRIVATE_KEY {
        let p, a = as_biguint(buf, doc, child(doc, r, TAG_P));
        let q, b = as_biguint(buf, doc, child(doc, r, TAG_Q));
        let g, c = as_biguint(buf, doc, child(doc, r, TAG_G));
        let x, d = as_biguint(buf, doc, child(doc, r, TAG_X));
        if !a || !b || !c || !d { return k, false; }
        let ok = x509::dsa_private(k, p, q, g, x);
        return k, ok;
    }
    if is_ec_transparent(f) {
        let c, cok = child_enum(buf, doc, r, TAG_RECOMMENDED_CURVE);
        let d, dok = as_biguint(buf, doc, child(doc, r, TAG_D));
        if !cok || !dok { return k, false; }
        let kind = kind_of_curve(c);
        if kind == x509::KEY_UNKNOWN { return k, false; }
        let size = x509::curve_of_key(kind).len;
        if d.len > size { return k, false; }
        k.kind = kind;
        for z in size - d.len { k.ec_sk.push(0); }
        k.ec_sk.append(d);
        return k, true;
    }
    return k, false;
}

fn put_private(out: u8[>..]&, k: const x509::PrivateKey&, f: u32) -> bool {
    if f == FMT_PKCS_8 { out.append(x509::marshal_pkcs8(k)); return true; }
    if f == FMT_PKCS_1 {
        if k.kind != x509::KEY_RSA { return false; }
        out.append(x509::marshal_pkcs1(k));
        return true;
    }
    if f == FMT_EC_PRIVATE_KEY {
        if !x509::is_ec(k.kind) { return false; }
        out.append(x509::marshal_sec1(k));
        return true;
    }
    if f == FMT_TRANSPARENT_RSA_PRIVATE_KEY {
        if k.kind != x509::KEY_RSA { return false; }
        // RSAPrivateKey: version, n, e, d, p, q, dp, dq, qinv.
        let der = x509::marshal_pkcs1(k);
        let v, ok = der_uints(der);
        if !ok || v.len != 9 { return false; }
        let s = begin(out, TAG_KEY_MATERIAL);
        put_biguint(out, TAG_MODULUS, uint_at(der, v[1]));
        put_biguint(out, TAG_PRIVATE_EXPONENT, uint_at(der, v[3]));
        put_biguint(out, TAG_PUBLIC_EXPONENT, uint_at(der, v[2]));
        put_biguint(out, TAG_P, uint_at(der, v[4]));
        put_biguint(out, TAG_Q, uint_at(der, v[5]));
        put_biguint(out, TAG_PRIME_EXPONENT_P, uint_at(der, v[6]));
        put_biguint(out, TAG_PRIME_EXPONENT_Q, uint_at(der, v[7]));
        put_biguint(out, TAG_CRT_COEFFICIENT, uint_at(der, v[8]));
        end(out, s);
        return true;
    }
    if f == FMT_TRANSPARENT_DSA_PRIVATE_KEY {
        if k.kind != x509::KEY_DSA { return false; }
        let s = begin(out, TAG_KEY_MATERIAL);
        put_biguint(out, TAG_P, k.dsa.p);
        put_biguint(out, TAG_Q, k.dsa.q);
        put_biguint(out, TAG_G, k.dsa.g);
        put_biguint(out, TAG_X, k.dsa.x);
        end(out, s);
        return true;
    }
    if is_ec_transparent(f) && is_transparent_private(f) {
        let c = curve_of_kind(k.kind);
        if c == 0 { return false; }
        let s = begin(out, TAG_KEY_MATERIAL);
        put_enum(out, TAG_RECOMMENDED_CURVE, c);
        put_biguint(out, TAG_D, k.ec_sk);
        end(out, s);
        return true;
    }
    return false;
}

// --- Public keys ------------------------------------------------------------------

fn put_rsa_alg_id(out: u8[>..]&) {
    var body: u8[>..] = [];
    asn1::put_oid(body, "1.2.840.113549.1.1.1");
    asn1::put_null(body);
    asn1::put(out, asn1::SEQUENCE, body);
}

fn spki_from(alg_id: const u8[:], key: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    body.append(alg_id);
    asn1::put_bits(body, key);
    var out: u8[>..] = [];
    asn1::put(out, asn1::SEQUENCE, body);
    return out;
}

// The SubjectPublicKeyInfo of a public key object, in any of the formats
// above.
fn spki_of_object(o: const Object&) -> u8[>..], bool {
    var out: u8[>..] = [];
    let f = o.key_format;
    if f == FMT_X_509 { out.append(o.material); return out, true; }
    var alg: u8[>..] = [];
    if f == FMT_PKCS_1 {
        put_rsa_alg_id(alg);
        return spki_from(alg, o.material), true;
    }
    if !is_transparent_public(f) { return out, false; }
    var doc: Node[>..] = [];
    let r, e = decode(o.material, Options { .. }, doc);
    if e != OK || !is_type(doc, r, STRUCTURE) { return out, false; }
    let buf = o.material[..];
    if f == FMT_TRANSPARENT_RSA_PUBLIC_KEY {
        let n, a = as_biguint(buf, doc, child(doc, r, TAG_MODULUS));
        let ex, b = as_biguint(buf, doc, child(doc, r, TAG_PUBLIC_EXPONENT));
        if !a || !b { return out, false; }
        var body: u8[>..] = [];
        asn1::put_uint(body, n);
        asn1::put_uint(body, ex);
        var key: u8[>..] = [];
        asn1::put(key, asn1::SEQUENCE, body);
        put_rsa_alg_id(alg);
        return spki_from(alg, key), true;
    }
    if f == FMT_TRANSPARENT_DSA_PUBLIC_KEY {
        let p, a = as_biguint(buf, doc, child(doc, r, TAG_P));
        let q, b = as_biguint(buf, doc, child(doc, r, TAG_Q));
        let g, c = as_biguint(buf, doc, child(doc, r, TAG_G));
        let y, d = as_biguint(buf, doc, child(doc, r, TAG_Y));
        if !a || !b || !c || !d { return out, false; }
        var params: u8[>..] = [];
        asn1::put_uint(params, p);
        asn1::put_uint(params, q);
        asn1::put_uint(params, g);
        var body: u8[>..] = [];
        asn1::put_oid(body, "1.2.840.10040.4.1");
        asn1::put(body, asn1::SEQUENCE, params);
        asn1::put(alg, asn1::SEQUENCE, body);
        var key: u8[>..] = [];
        asn1::put_uint(key, y);
        return spki_from(alg, key), true;
    }
    if is_ec_transparent(f) {
        let c, cok = child_enum(buf, doc, r, TAG_RECOMMENDED_CURVE);
        let q, qok = child_bytes(buf, doc, r, TAG_Q_STRING);
        if !cok || !qok { return out, false; }
        let kind = kind_of_curve(c);
        if kind == x509::KEY_UNKNOWN { return out, false; }
        var body: u8[>..] = [];
        asn1::put_oid(body, "1.2.840.10045.2.1");
        asn1::put_oid(body, x509::curve_oid(kind));
        asn1::put(alg, asn1::SEQUENCE, body);
        return spki_from(alg, q), true;
    }
    return out, false;
}

fn put_public(out: u8[>..]&, spki: const u8[:], f: u32) -> bool {
    if f == FMT_X_509 { out.append(spki); return true; }
    let t, ok = asn1::parse(spki);
    if !ok { return false; }
    let kind, key, kok = x509::spki_of(spki, t);
    if !kok { return false; }
    let bits, unused, bok = asn1::read_bits(spki, key);
    if !bok || unused != 0 { return false; }
    if f == FMT_PKCS_1 {
        if kind != x509::KEY_RSA { return false; }
        out.append(bits);
        return true;
    }
    if f == FMT_TRANSPARENT_RSA_PUBLIC_KEY {
        if kind != x509::KEY_RSA { return false; }
        let v, vok = der_uints(bits);
        if !vok || v.len != 2 { return false; }
        let s = begin(out, TAG_KEY_MATERIAL);
        put_biguint(out, TAG_MODULUS, uint_at(bits, v[0]));
        put_biguint(out, TAG_PUBLIC_EXPONENT, uint_at(bits, v[1]));
        end(out, s);
        return true;
    }
    if f == FMT_TRANSPARENT_DSA_PUBLIC_KEY {
        if kind != x509::KEY_DSA { return false; }
        // AlgorithmIdentifier { id-dsa, Dss-Parms { p, q, g } }; the key an INTEGER.
        let p, pok = asn1::children_of(spki, t, asn1::SEQUENCE);
        if !pok { return false; }
        let a, aok = asn1::children_of(spki, p[0], asn1::SEQUENCE);
        if !aok || a.len != 2 { return false; }
        var params: u8[>..] = [];
        params.append(spki[a[1].start..a[1].end]);
        let pqg, gok = der_uints(params);
        let yt, yok = asn1::parse(bits);
        if !gok || pqg.len != 3 || !yok { return false; }
        let y, yvok = asn1::read_uint(bits, yt);
        if !yvok { return false; }
        let s = begin(out, TAG_KEY_MATERIAL);
        put_biguint(out, TAG_P, uint_at(params, pqg[0]));
        put_biguint(out, TAG_Q, uint_at(params, pqg[1]));
        put_biguint(out, TAG_G, uint_at(params, pqg[2]));
        put_biguint(out, TAG_Y, y);
        end(out, s);
        return true;
    }
    if is_ec_transparent(f) && is_transparent_public(f) {
        let c = curve_of_kind(kind);
        if c == 0 { return false; }
        let s = begin(out, TAG_KEY_MATERIAL);
        put_enum(out, TAG_RECOMMENDED_CURVE, c);
        put_bytes(out, TAG_Q_STRING, bits);
        end(out, s);
        return true;
    }
    return false;
}

// --- Conversion -----------------------------------------------------------------

// The object with its key in format `want`, and 0; or a Result Reason
// (Key Format Type Not Supported) when this key does not go into it. A
// wrapped key is not converted.
fn convert_key(o: const Object&, want: u32) -> Object, u32 {
    var r = copy(o);
    if want == o.key_format { return r, 0; }
    if o.wrapped { return r, REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
    r.material.clear();
    r.key_format = want;
    if o.obj_type == OBJ_SYMMETRIC_KEY {
        let raw_like = o.key_format == FMT_RAW || o.key_format == FMT_TRANSPARENT_SYMMETRIC_KEY;
        if raw_like && (want == FMT_RAW || want == FMT_TRANSPARENT_SYMMETRIC_KEY) {
            r.material.append(o.material);
            return r, 0;
        }
        return r, REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED;
    }
    if o.obj_type == OBJ_PRIVATE_KEY {
        let k, ok = private_of(o);
        if !ok || !put_private(r.material, k, want) { return r, REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
        return r, 0;
    }
    if o.obj_type == OBJ_PUBLIC_KEY {
        let spki, ok = spki_of_object(o);
        if !ok || !put_public(r.material, spki, want) { return r, REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
        return r, 0;
    }
    return r, REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED;
}

// A generated key pair as the server keeps it: RSA in PKCS #1 (the
// default KMIP's test cases expect), others in PKCS #8 and X.509.
fn pair_objects(k: const x509::PrivateKey&, alg: u32, length: i32) -> Object, Object {
    if k.kind == x509::KEY_RSA {
        let po = private_key(alg, length, FMT_PKCS_1, x509::marshal_pkcs1(k));
        let x5 = public_key(alg, length, FMT_X_509, x509::marshal_public_key(k));
        let pu, r = convert_key(x5, FMT_PKCS_1);
        return po, pu;
    }
    let po = private_key(alg, length, FMT_PKCS_8, x509::marshal_pkcs8(k));
    let pu = public_key(alg, length, FMT_X_509, x509::marshal_public_key(k));
    return po, pu;
}
