// client: a key from a key manager over KMIP: connect with a client
// certificate, settle the protocol version, find the key named on the
// command line or make it (AES-256), activate it and fetch its bytes,
// then encrypt a line with it there (AES-GCM).
//
//   goose examples/kmip/client.goose -- HOST CA.pem CLIENT.pem CLIENT.key NAME
//
// PyKMIP's server, Thales CipherTrust, Fortanix, HashiCorp Vault's KMIP
// engine or goose-kmipd (kmip/tools/kmipd.goose) answer it.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.encoding.asn1;

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    var out: u8[>..] = [];
    if !read_file(path, text) { print("cannot read ", path); exit(1); }
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    return out;
}

fn need<C>(c: const C&, what: const u8[:], e: i64) {
    if e != kmip::OK { print(what, ": ", kmip::describe(c, e)); exit(1); }
}

fn main() {
    let a = args();
    guard a.len >= 6 else { print("usage: client HOST CA.pem CLIENT.pem CLIENT.key NAME"); exit(2); }
    var cc = kmip::tls_config(a[1], pem_der(a[2], "CERTIFICATE"));
    if !tls::set_client_certificate(cc, pem_der(a[3], "CERTIFICATE"), pem_der(a[4], "PRIVATE KEY")) {
        print("the client certificate and key"); exit(1);
    }
    var c, e = kmip::dial(a[1], 5696, cc);
    need(c, "connect", e);
    let v, ev = kmip::negotiate(c);
    need(c, "discover versions", ev);
    print("KMIP ", v.major, ".", v.minor);

    var by_name = kmip::attrs();
    kmip::attr_name(by_name, a[5]);
    let found, el = kmip::locate(c, by_name, 1);
    need(c, "locate", el);
    var uid: u8[>..] = [];
    if found.len > 0 {
        uid.append(found[0]);
        print("found ", a[5], ": ", uid);
    } else {
        var at = kmip::attrs();
        kmip::attr_enum(at, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
        kmip::attr_int(at, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
        kmip::attr_usage(at, kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
        kmip::attr_name(at, a[5]);
        let u, ec = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, at);
        need(c, "create", ec);
        uid.append(u);
        need(c, "activate", kmip::activate(c, uid));
        print("created ", a[5], ": ", uid);
    }
    let key, eg = kmip::get(c, uid, 0);
    need(c, "get", eg);
    print("the key: ", key.material.len * 8, " bits");
    let gcm = kmip::CryptoParams { alg: kmip::ALG_AES, mode: kmip::MODE_GCM, tag_length: 16 };
    let nonce: u8[12] = [0; 12];
    let s, es = kmip::encrypt(c, uid, gcm, "a line of text", nonce, "");
    if es == kmip::OK { print("encrypted there: ", s.data.len, " bytes and a ", s.tag.len, "-byte tag"); }
    else { print("encrypt: ", kmip::describe(c, es)); }
    kmip::close(c);
}
