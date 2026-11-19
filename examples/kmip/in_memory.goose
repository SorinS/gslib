// in_memory: a key's life in KMIP, in one program, no network: a client
// (kmip.client's operations) and the in-memory key manager (kmip.local)
// trade KMIP 2.0 messages. An AES key is made, named, found again,
// activated, used for AES-GCM, and its bytes fetched to check the
// ciphertext with gslib's own AES-GCM; an RSA key pair signs and checks a
// message; then the key is revoked and destroyed. Every message is real
// TTLV: the first request and response are dumped.
//
//   goose examples/kmip/in_memory.goose

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.local;
import gslib.kmip.messages;
import gslib.crypto.bignum;
import gslib.crypto.bignum.gcm;

fn die<C>(c: const C&, what: const u8[:], e: i64) {
    if e != kmip::OK { print(what, ": ", kmip::describe(c, e)); exit(1); }
}

fn main() {
    var c = kmip::local("alice");
    let v, ev = kmip::negotiate(c);
    die(c, "negotiate", ev);
    print("KMIP ", v.major, ".", v.minor);

    // What a request looks like: Query, written and dumped, then answered.
    var req: u8[>..] = [];
    let m = kmip::begin_request(req, v, 1, c.cred);
    let it, p = kmip::begin_item(req, kmip::OP_QUERY, "");
    kmip::put_enum(req, kmip::TAG_QUERY_FUNCTION, kmip::QUERY_SERVER_INFORMATION);
    kmip::end_item(req, it, p);
    kmip::end(req, m);
    var doc: kmip::Node[>..] = [];
    let r, e = kmip::decode(req, kmip::Options { .. }, doc);
    print(kmip::dump(req, doc, r));
    var resp: u8[>..] = [];
    let ex = kmip::exchange(c, req, resp);
    var rdoc: kmip::Node[>..] = [];
    let rr, re = kmip::decode(resp, kmip::Options { .. }, rdoc);
    print(kmip::dump(resp, rdoc, rr));

    // An AES-256 key with a name.
    var a = kmip::attrs();
    kmip::attr_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
    kmip::attr_usage(a, kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    kmip::attr_name(a, "backup-key");
    let uid, ec = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    die(c, "create", ec);
    var by_name = kmip::attrs();
    kmip::attr_name(by_name, "backup-key");
    let found, el = kmip::locate(c, by_name, 0);
    die(c, "locate", el);
    print("created ", uid, ", located by its name: ", found[0]);
    die(c, "activate", kmip::activate(c, uid));

    // AES-GCM by the key manager, checked with gslib's own.
    let gcm = kmip::CryptoParams { alg: kmip::ALG_AES, mode: kmip::MODE_GCM, tag_length: 16 };
    let nonce: u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let sealed, es = kmip::encrypt(c, uid, gcm, "attack at dawn", nonce, "header");
    die(c, "encrypt", es);
    let key, eg = kmip::get(c, uid, 0);
    die(c, "get", eg);
    var both: u8[>..] = [];
    both.append(sealed.data);
    both.append(sealed.tag);
    let plain, ok = bignum::aes_gcm_open(key.material, nonce, "header", both);
    print("AES-GCM by the server, opened here: ", if ok { plain[..] } else { "(failed)" });

    // An RSA key pair: the key manager signs and checks.
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_RSA);
    kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 2048);
    var pa = kmip::attrs();
    kmip::attr_usage(pa, kmip::USAGE_SIGN);
    var pb = kmip::attrs();
    kmip::attr_usage(pb, kmip::USAGE_VERIFY);
    let priv, pubk, ek = kmip::create_key_pair(c, common, pa, pb);
    die(c, "create key pair", ek);
    die(c, "activate", kmip::activate(c, priv));
    die(c, "activate", kmip::activate(c, pubk));
    let sp = kmip::CryptoParams { sig: kmip::SIG_SHA256_WITH_RSA_ENCRYPTION };
    let sig, esg = kmip::sign(c, priv, sp, "a message");
    die(c, "sign", esg);
    let good, evf = kmip::verify(c, pubk, sp, "a message", sig);
    die(c, "verify", evf);
    print("RSA-2048 signature, ", sig.len, " bytes: ", if good { "valid" } else { "invalid" });

    // The end of the key: revoked, then destroyed.
    die(c, "revoke", kmip::revoke(c, uid, kmip::REVOKE_CESSATION_OF_OPERATION, "rotated", 0));
    die(c, "destroy", kmip::destroy(c, uid));
    let gone, eg2 = kmip::get(c, uid, 0);
    print("after destroy, get: ", kmip::describe(c, eg2));
}
