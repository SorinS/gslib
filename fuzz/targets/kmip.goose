// Fuzz target: kmip. The first byte picks a path (data[0] % 3), the rest
// is the input:
//   0: the TTLV decoder and what reads a decoded message: the dump, a
//      response's and a request's headers and batch items, the attributes
//      (1.x and 2.0 forms) and the managed objects of every Structure.
//   1: the in-memory server's handle given the input as a request, from
//      the owner of an active AES key, an HMAC key, an RSA key pair, an
//      EC P-256 pair, a Triple DES key, a ChaCha20-Poly1305 key and a key
//      that wraps (identifiers 1 to 9), each with every usage, so that the
//      operations on them (wrapping, deriving, in parts...) are reached.
//   2: the attribute list's walking and changing given the input as
//      attributes (each item as 2.0 writes it).

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.server;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;

var SRV = kmip::server();

fn read_message(m: const u8[:]) {
    var doc: kmip::Node[>..] = [];
    let r, e = kmip::decode(m, kmip::Options { .. }, doc);
    if e != kmip::OK { return; }
    let d = kmip::dump(m, doc, r);
    let resp, er = kmip::parse_response(m, doc, r);
    for it in resp.items { let id = kmip::item_id(m, it); let msg = kmip::result_message(m, it); }
    let req, eq = kmip::parse_request(m, doc, r);
    for it in req.items { let id = kmip::request_item_id(m, it); }
    let u = kmip::request_username(m, req);
    for i in doc.len {
        if doc[i].typ != kmip::STRUCTURE { continue; }
        let a = kmip::read_attrs(m, doc, i);
        let n = kmip::attr_count(a);
        let name = kmip::get_name(a, 0);
        let curve, cok = kmip::get_curve(a);
        let t = kmip::reference_tag(m, doc, i);
        let types: u32[6] = [kmip::OBJ_SYMMETRIC_KEY, kmip::OBJ_PRIVATE_KEY, kmip::OBJ_PUBLIC_KEY,
                             kmip::OBJ_CERTIFICATE, kmip::OBJ_SECRET_DATA, kmip::OBJ_OPAQUE_DATA];
        for ty in types {
            let o, ok = kmip::read_object(m, doc, i, ty);
            if ok { var out: u8[>..] = []; let w = kmip::put_object(out, o); }
        }
    }
}

fn handle(m: const u8[:]) {
    var out: u8[>..] = [];
    kmip::handle(SRV, "fuzz", m, out);
    // The answer must be TTLV this package reads.
    var doc: kmip::Node[>..] = [];
    let r, e = kmip::decode(out, kmip::Options { .. }, doc);
    assert(e == kmip::OK);
    let resp, er = kmip::parse_response(out, doc, r);
    assert(er == kmip::OK);
}

fn attrs(m: const u8[:]) {
    var a = kmip::attrs();
    kmip::attr_raw(a, m);
    let n = kmip::attr_count(a);
    let t, tok = kmip::get_text(a, kmip::TAG_NAME);
    let st, sok = kmip::get_enum(a, kmip::TAG_STATE);
    let gone = kmip::remove_attr(a, kmip::TAG_NAME, 0);
    var b = kmip::attrs();
    kmip::attr_name(b, "x");
    kmip::replace_attr(a, b.enc, 1);
    var out: u8[>..] = [];
    kmip::put_template(out, a, kmip::V1_2, kmip::TAG_TEMPLATE_ATTRIBUTE, kmip::TAG_ATTRIBUTES);
    kmip::put_template(out, a, kmip::V2_0, kmip::TAG_TEMPLATE_ATTRIBUTE, kmip::TAG_ATTRIBUTES);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let m = data[1..];
    let sel = data[0] % 3;
    if sel == 0 { read_message(m); }
    else if sel == 1 { handle(m); }
    else { attrs(m); }
    return 0;
}

fn main() {
    // The objects the requests can reach: 1 AES-128 and 2 HMAC-SHA256,
    // active, encrypting and MACing; 3 and 4 an RSA-2048 pair; 5 and 6 a
    // P-256 pair; 7 Triple DES, 8 ChaCha20-Poly1305, 9 a KEK; 10 a
    // password (5's for PKCS #12), 11 a PGP key.
    SRV.version = kmip::V2_1;      // which attributes add_object sets
    let aes: u8[16] = [1; 16];
    let hk: u8[32] = [2; 32];
    var a = kmip::attrs();
    kmip::attr_usage(a, kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT | kmip::USAGE_MAC_GENERATE | kmip::USAGE_MAC_VERIFY |
                        kmip::USAGE_SIGN | kmip::USAGE_VERIFY | kmip::USAGE_WRAP_KEY | kmip::USAGE_UNWRAP_KEY |
                        kmip::USAGE_DERIVE_KEY);
    var uid: u8[>..] = [];
    let o1 = kmip::symmetric_key(kmip::ALG_AES, aes);
    let r1 = kmip::add_object(SRV, "fuzz", o1, a, uid);
    let o2 = kmip::symmetric_key(kmip::ALG_HMAC_SHA256, hk);
    let r2 = kmip::add_object(SRV, "fuzz", o2, a, uid);
    let k = x509::generate_key(x509::KEY_RSA, 2048);
    let o3 = kmip::private_key(kmip::ALG_RSA, 2048, kmip::FMT_PKCS_8, x509::marshal_pkcs8(k));
    let r3 = kmip::add_object(SRV, "fuzz", o3, a, uid);
    let o4 = kmip::public_key(kmip::ALG_RSA, 2048, kmip::FMT_X_509, x509::marshal_public_key(k));
    let r4 = kmip::add_object(SRV, "fuzz", o4, a, uid);
    let ek = x509::generate_key(x509::KEY_EC_P256, 0);
    let o5 = kmip::private_key(kmip::ALG_EC, 256, kmip::FMT_PKCS_8, x509::marshal_pkcs8(ek));
    let r5 = kmip::add_object(SRV, "fuzz", o5, a, uid);
    let o6 = kmip::public_key(kmip::ALG_EC, 256, kmip::FMT_X_509, x509::marshal_public_key(ek));
    let r6 = kmip::add_object(SRV, "fuzz", o6, a, uid);
    let des: u8[24] = [3; 24];
    let o7 = kmip::symmetric_key(kmip::ALG_TRIPLE_DES, des);
    let r7 = kmip::add_object(SRV, "fuzz", o7, a, uid);
    let cc: u8[32] = [4; 32];
    let o8 = kmip::symmetric_key(kmip::ALG_CHACHA20_POLY1305, cc);
    let r8 = kmip::add_object(SRV, "fuzz", o8, a, uid);
    let kek: u8[32] = [5; 32];
    let o9 = kmip::symmetric_key(kmip::ALG_AES, kek);
    let r9 = kmip::add_object(SRV, "fuzz", o9, a, uid);
    // 10 a password, 5's for PKCS #12 (in Object Group "group"); 11 a PGP key.
    let pw = kmip::secret_data(kmip::SECRET_PASSWORD, "password");
    var ga = kmip::attrs();
    kmip::attr_text(ga, kmip::TAG_OBJECT_GROUP, "group");
    let r10 = kmip::add_object(SRV, "fuzz", pw, ga, uid);
    let pgp = kmip::pgp_key(4, kmip::ALG_RSA, 2048, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nx\n-----END PGP PUBLIC KEY BLOCK-----\n");
    let r11 = kmip::add_object(SRV, "fuzz", pgp, a, uid);
    kmip::link_both(SRV, "5", kmip::LINK_PKCS12_PASSWORD, "10", "fuzz");
    for i in SRV.objects.len { let ok = kmip::set_state(SRV, SRV.objects[i], kmip::STATE_ACTIVE, kmip::TAG_ACTIVATION_DATE); }
    // What the input makes stays few: the store takes 64 objects at most.
    SRV.max_objects = 64;
}
