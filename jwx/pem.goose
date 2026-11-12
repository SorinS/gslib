// jwx.pem: JWKs from and to PEM and DER, through crypto/x509: private keys
// (PKCS #8, SEC 1, PKCS #1), public keys (SubjectPublicKeyInfo) and
// certificates, as jwx's jwk.ParseKey(..., WithPEM(true)) and
// jwk.FromRaw read them. RSA, EC (P-256, P-384, P-521) and Ed25519; other
// key types are ERR_UNSUPPORTED. A separate module so that jwk alone does
// not bring in x509.

namespace jwk;

import std;
import jwx;
import jwx.jwa;
import jwx.jwk;
import crypto.x509;
import crypto.x509.keys;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.ec;
import crypto.bignum.ed25519;
import crypto.bignum.sha1;
import crypto.bignum.sha256;

fn crv_of_kind(kind: i64) -> i64 {
    if kind == x509::KEY_EC_P256 { return jwa::CRV_P256; }
    if kind == x509::KEY_EC_P384 { return jwa::CRV_P384; }
    if kind == x509::KEY_EC_P521 { return jwa::CRV_P521; }
    return jwa::CRV_UNKNOWN;
}

fn kind_of_crv(crv: i64) -> i64 {
    if crv == jwa::CRV_P256 { return x509::KEY_EC_P256; }
    if crv == jwa::CRV_P384 { return x509::KEY_EC_P384; }
    return x509::KEY_EC_P521;
}

// The JWK of an x509 private key.
fn from_private(pk: const x509::PrivateKey&) -> Key, i64 {
    var k = empty();
    k.private = true;
    if pk.kind == x509::KEY_RSA {
        k.kty = jwa::KTY_RSA;
        k.rsa = pk.rsa;
        return k, jwx::OK;
    }
    if pk.kind == x509::KEY_ED25519 {
        k.kty = jwa::KTY_OKP;
        k.crv = jwa::CRV_ED25519;
        k.d.append(pk.seed);
        k.x.append(bignum::ed25519_public(pk.seed));
        return k, jwx::OK;
    }
    let crv = crv_of_kind(pk.kind);
    if crv == jwa::CRV_UNKNOWN { return k, jwx::ERR_UNSUPPORTED; }
    k.kty = jwa::KTY_EC;
    k.crv = crv;
    let c = curve(crv);
    let point = bignum::ec_public_key(c, pk.ec_sk);
    let n = jwa::crv_len(crv);
    k.d.append(pk.ec_sk);
    k.x.append(point[1..1 + n]);
    k.y.append(point[1 + n..]);
    return k, jwx::OK;
}

// The JWK of a SubjectPublicKeyInfo at t in der.
fn from_spki_tlv(der: const u8[:], t: asn1::Tlv) -> Key, i64 {
    var k = empty();
    let kind, bits, ok = x509::spki_of(der, t);
    if !ok { return k, jwx::ERR_MALFORMED; }
    let kb, okb = x509::key_bytes(der, bits);
    if !okb { return k, jwx::ERR_MALFORMED; }
    if kind == x509::KEY_RSA {
        let pub, e = x509::rsa_key_of(kb);
        if e != x509::OK { return k, jwx::ERR_KEY; }
        k.kty = jwa::KTY_RSA;
        k.rsa.n.append(pub.n);
        k.rsa.e.append(pub.e);
        return k, jwx::OK;
    }
    if kind == x509::KEY_ED25519 {
        if kb.len != 32 { return k, jwx::ERR_KEY; }
        k.kty = jwa::KTY_OKP;
        k.crv = jwa::CRV_ED25519;
        k.x.append(kb);
        return k, jwx::OK;
    }
    let crv = crv_of_kind(kind);
    if crv == jwa::CRV_UNKNOWN { return k, jwx::ERR_UNSUPPORTED; }
    let n = jwa::crv_len(crv);
    // The uncompressed point only, as JWKs carry both coordinates.
    if kb.len != 1 + 2 * n || kb[0] != 4 { return k, jwx::ERR_UNSUPPORTED; }
    k.kty = jwa::KTY_EC;
    k.crv = crv;
    k.x.append(kb[1..1 + n]);
    k.y.append(kb[1 + n..]);
    let e = validate(k);
    return k, e;
}

// The JWK of a SubjectPublicKeyInfo's DER.
fn from_spki(der: const u8[:]) -> Key, i64 {
    let t, ok = asn1::parse(der);
    if !ok { return empty(), jwx::ERR_MALFORMED; }
    let k, e = from_spki_tlv(der, t);
    return k, e;
}

// The JWK of a certificate's public key, with the certificate's SHA-1 and
// SHA-256 thumbprints as "x5t" and "x5t#S256" (RFC 7517 §4.8, §4.9).
fn from_cert(c: const x509::Cert&) -> Key, i64 {
    var k, e = from_spki_tlv(c.der, c.spki);
    if e != jwx::OK { return k, e; }
    k.x5t.append(bignum::sha1(c.der));
    k.x5t256.append(bignum::sha256(c.der));
    return k, jwx::OK;
}

// The first key in PEM text: a private key ("PRIVATE KEY", "EC PRIVATE
// KEY", "RSA PRIVATE KEY"), a public key ("PUBLIC KEY") or a certificate's
// ("CERTIFICATE").
fn from_pem(text: const u8[:]) -> Key, i64 {
    if find(text, "PRIVATE KEY-----") >= 0 {
        let pk, ok = x509::parse_private_key_pem(text);
        if !ok { return empty(), jwx::ERR_MALFORMED; }
        let k, e = from_private(pk);
        return k, e;
    }
    let pubs, okp = asn1::pem_decode(text, "PUBLIC KEY");
    if okp {
        for der in pubs {
            let k, e = from_spki(der);
            return k, e;
        }
    }
    let certs, okc = asn1::pem_decode(text, "CERTIFICATE");
    if okc {
        for der in certs {
            let c, e = x509::parse(der);
            if e != x509::OK { return empty(), jwx::ERR_MALFORMED; }
            let k, e2 = from_cert(c);
            return k, e2;
        }
    }
    return empty(), jwx::ERR_MALFORMED;
}

// The key as an x509 private key, for marshalling.
fn to_private(k: const Key&) -> x509::PrivateKey, i64 {
    var pk = x509::empty_key();
    if !k.private || k.kty == jwa::KTY_OCT { return pk, jwx::ERR_KEY; }
    if k.kty == jwa::KTY_RSA {
        pk.kind = x509::KEY_RSA;
        pk.rsa = k.rsa;
    } else if k.kty == jwa::KTY_OKP && k.crv == jwa::CRV_ED25519 {
        pk.kind = x509::KEY_ED25519;
        for i in 32 { pk.seed[i] = k.d[i]; }
    } else if k.kty == jwa::KTY_EC {
        pk.kind = kind_of_crv(k.crv);
        pk.ec_sk.append(k.d);
    } else {
        return pk, jwx::ERR_UNSUPPORTED;
    }
    return pk, jwx::OK;
}

// The public key as SubjectPublicKeyInfo DER.
fn marshal_spki(k: const Key&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    var alg: u8[>..] = [];
    var key: u8[>..] = [];
    if k.kty == jwa::KTY_RSA {
        asn1::put_oid(alg, "1.2.840.113549.1.1.1");
        asn1::put_null(alg);
        var body: u8[>..] = [];
        asn1::put_uint(body, uint_bytes(k.rsa.n));
        asn1::put_uint(body, uint_bytes(k.rsa.e));
        asn1::put(key, asn1::SEQUENCE, body);
    } else if k.kty == jwa::KTY_EC {
        asn1::put_oid(alg, "1.2.840.10045.2.1");
        asn1::put_oid(alg, x509::curve_oid(kind_of_crv(k.crv)));
        key.append(ec_point(k));
    } else if k.kty == jwa::KTY_OKP && k.crv == jwa::CRV_ED25519 {
        asn1::put_oid(alg, "1.3.101.112");
        key.append(k.x);
    } else {
        return out, jwx::ERR_UNSUPPORTED;
    }
    var body: u8[>..] = [];
    asn1::put(body, asn1::SEQUENCE, alg);
    asn1::put_bits(body, key);
    asn1::put(out, asn1::SEQUENCE, body);
    return out, jwx::OK;
}

// The key as PEM: a private key as PKCS #8 ("PRIVATE KEY") unless `public`
// or the key is public, then SubjectPublicKeyInfo ("PUBLIC KEY").
fn to_pem(k: const Key&, public: bool = false) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if k.private && !public {
        let pk, e = to_private(k);
        if e != jwx::OK { return out, e; }
        asn1::pem_encode(out, "PRIVATE KEY", x509::marshal_pkcs8(pk));
        return out, jwx::OK;
    }
    let der, e = marshal_spki(k);
    if e != jwx::OK { return out, e; }
    asn1::pem_encode(out, "PUBLIC KEY", der);
    return out, jwx::OK;
}
