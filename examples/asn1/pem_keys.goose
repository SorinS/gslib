// pem_keys: writes an X25519 key pair as the PEM files openssl makes, a
// PKCS #8 private key (RFC 5208, RFC 8410) and a SubjectPublicKeyInfo
// (RFC 5280), then reads the file back: every block, or only those with a
// given label, each block's DER taken apart to find its key.
//
//   PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm AlgorithmIdentifier,
//                                 privateKey OCTET STRING }   -- holding an OCTET STRING
//   SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
//                                       subjectPublicKey BIT STRING }
//   AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER }
//
//   goose examples/asn1/pem_keys.goose

import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.crypto.bignum;
import gslib.crypto.bignum.x25519;

let X25519 = "1.3.101.110";

fn algorithm(out: u8[>..]&) {
    var alg: u8[>..] = [];
    asn1::put_oid(alg, X25519);
    asn1::put(out, asn1::SEQUENCE, alg);
}

// The AlgorithmIdentifier at t names X25519.
fn is_x25519(der: const u8[:], t: asn1::Tlv) -> bool {
    let a, ok = asn1::children_of(der, t, asn1::SEQUENCE);
    return ok && a.len == 1 && asn1::oid_is(der, a[0], X25519);
}

fn main() {
    let sk, pk = bignum::x25519_keypair();

    // Write both keys into one PEM text.
    var inner: u8[>..] = [];
    asn1::put_octets(inner, sk);
    var p8: u8[>..] = [];
    asn1::put_i64(p8, 0);
    algorithm(p8);
    asn1::put_octets(p8, inner);
    var priv: u8[>..] = [];
    asn1::put(priv, asn1::SEQUENCE, p8);

    var spki: u8[>..] = [];
    algorithm(spki);
    asn1::put_bits(spki, pk);
    var pub: u8[>..] = [];
    asn1::put(pub, asn1::SEQUENCE, spki);

    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "PRIVATE KEY", priv);
    asn1::pem_encode(pem, "PUBLIC KEY", pub);
    print(pem[..pem.len - 1]);

    // Every block, whatever its label.
    let all, oka = asn1::pem_decode(pem, "");
    var n = 0;
    for b in all { n++; }
    guard oka && n == 2 else { print("pem_keys: expected two blocks"); exit(1); }

    // The private key: only the PRIVATE KEY blocks.
    let privs, okp = asn1::pem_decode(pem, "PRIVATE KEY");
    guard okp else { print("pem_keys: bad PEM"); exit(1); }
    var got_sk: u8[>..] = [];
    for der in privs {
        let top, ok = asn1::parse(der);
        let f, okf = asn1::children_of(der, top, asn1::SEQUENCE);
        guard ok && okf && f.len == 3 else { print("pem_keys: not a PrivateKeyInfo"); exit(1); }
        let version, okv = asn1::read_i64(der, f[0]);
        let wrapped, okw = asn1::read_octets(der, f[2]);
        guard okv && version == 0 && is_x25519(der, f[1]) && okw else { print("pem_keys: not an X25519 key"); exit(1); }
        let it, oki = asn1::parse(wrapped);              // CurvePrivateKey ::= OCTET STRING
        let key, okk = asn1::read_octets(wrapped, it);
        guard oki && okk && key.len == 32 else { print("pem_keys: bad private key"); exit(1); }
        got_sk.append(key);
    }

    // The public key.
    let pubs, okq = asn1::pem_decode(pem, "PUBLIC KEY");
    guard okq else { print("pem_keys: bad PEM"); exit(1); }
    var got_pk: u8[>..] = [];
    for der in pubs {
        let top, ok = asn1::parse(der);
        let f, okf = asn1::children_of(der, top, asn1::SEQUENCE);
        guard ok && okf && f.len == 2 && is_x25519(der, f[0]) else { print("pem_keys: not an X25519 SPKI"); exit(1); }
        let bits, unused, okb = asn1::read_bits(der, f[1]);
        guard okb && unused == 0 && bits.len == 32 else { print("pem_keys: bad public key"); exit(1); }
        got_pk.append(bits);
    }

    // The two keys read back belong together.
    let derived = bignum::x25519_base(got_sk);
    guard got_sk[..] == sk[..] && got_pk[..] == pk[..] && derived[..] == got_pk[..]
    else { print("pem_keys: the keys did not survive"); exit(1); }

    // A block cut short is refused.
    let cut, okc = asn1::pem_decode(pem[..40], "");
    guard !okc else { print("pem_keys: accepted a broken block"); exit(1); }
    print("read back: the private key's public half matches the public key");
}
