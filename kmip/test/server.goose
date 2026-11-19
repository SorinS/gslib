// The in-memory server's rules, through kmip.local: objects seen by their
// owner alone; the life cycle's refusals; attributes the server keeps,
// single and multi-valued ones, 1.x's Add Attribute and indexes; key
// formats; Locate's limits; AES-CTR, ECDSA and RSA-PSS; operations of a
// later version refused; batches that stop or go on after a failure; and
// requests it cannot read.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.local;
import gslib.kmip.server;
import gslib.crypto.bignum;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.modes;
import gslib.crypto.x509;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn as_owner(c: kmip::Local&, who: const u8[:]) { c.owner.clear(); c.owner.append(who); }

fn aes_attrs(usage: u32) -> kmip::Attrs {
    var a = kmip::attrs();
    kmip::attr_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 128);
    kmip::attr_usage(a, usage);
    return a;
}

// A response's items: their Result Status and Reason, in order.
fn results(resp: const u8[:]) -> u32[>..] {
    var out: u32[>..] = [];
    var doc: kmip::Node[>..] = [];
    let r, e = kmip::decode(resp, kmip::Options { .. }, doc);
    if e != kmip::OK { return out; }
    let m, pe = kmip::parse_response(resp, doc, r);
    if pe != kmip::OK { return out; }
    for it in m.items { out.push(it.status); out.push(it.reason); }
    return out;
}

// A request of two batch items, Get of a missing object then Query, with
// the Batch Error Continuation Option given.
fn two_items(option: u32) -> u8[>..] {
    var out: u8[>..] = [];
    let m = kmip::begin(out, kmip::TAG_REQUEST_MESSAGE);
    let h = kmip::begin(out, kmip::TAG_REQUEST_HEADER);
    kmip::put_version(out, kmip::V1_2);
    kmip::put_enum(out, kmip::TAG_BATCH_ERROR_CONTINUATION_OPTION, option);
    kmip::put_int(out, kmip::TAG_BATCH_COUNT, 2);
    kmip::end(out, h);
    let i1, p1 = kmip::begin_item(out, kmip::OP_GET, "a");
    kmip::put_text(out, kmip::TAG_UNIQUE_IDENTIFIER, "999");
    kmip::end_item(out, i1, p1);
    let i2, p2 = kmip::begin_item(out, kmip::OP_QUERY, "b");
    kmip::put_enum(out, kmip::TAG_QUERY_FUNCTION, kmip::QUERY_OPERATIONS);
    kmip::end_item(out, i2, p2);
    kmip::end(out, m);
    return out;
}

fn main() {
    var c = kmip::local("alice");
    c.version = kmip::V2_0;

    // Whose objects are whose.
    let a = aes_attrs(kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    let uid, e1 = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    check("create", e1 == kmip::OK);
    as_owner(c, "bob");
    let o1, eb = kmip::get(c, uid, 0);
    check("bob cannot get alice's key", eb == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_ITEM_NOT_FOUND, c.version));
    let none = kmip::attrs();
    let lb, elb = kmip::locate(c, none, 0);
    check("bob locates nothing", elb == kmip::OK && lb.len == 0);
    as_owner(c, "alice");
    let la, ela = kmip::locate(c, none, 0);
    check("alice locates hers", ela == kmip::OK && la.len == 1);

    // The life cycle.
    let iv: u8[16] = [0; 16];
    let cbc = kmip::CryptoParams { mode: kmip::MODE_CBC };
    let s0, es0 = kmip::encrypt(c, uid, cbc, "x", iv, "");
    check("a Pre-Active key does not encrypt", es0 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_WRONG_KEY_LIFECYCLE_STATE, c.version));
    check("activate", kmip::activate(c, uid) == kmip::OK);
    check("activate twice refused", kmip::activate(c, uid) == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_WRONG_KEY_LIFECYCLE_STATE, c.version));
    let sig, esg = kmip::mac(c, uid, kmip::CryptoParams { .. }, "x");
    check("no MAC with an AES key that may not", esg == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK, c.version));
    check("revoke for a compromise", kmip::revoke(c, uid, kmip::REVOKE_KEY_COMPROMISE, "", 1000000) == kmip::OK);
    let st, est = kmip::get_attributes(c, uid, [kmip::TAG_STATE, kmip::TAG_COMPROMISE_OCCURRENCE_DATE]);
    let stv, sok = kmip::get_enum(st, kmip::TAG_STATE);
    check("compromised", sok && stv == kmip::STATE_COMPROMISED);
    let cod, cok = kmip::get_datetime(st, kmip::TAG_COMPROMISE_OCCURRENCE_DATE);
    check("compromise occurrence date kept", cok && cod == 1000000);
    check("a compromised key is destroyed", kmip::destroy(c, uid) == kmip::OK);
    let uid2, e2 = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    check("a new object after a destroyed one has a new identifier", e2 == kmip::OK && uid2[..] != uid[..]);
    check("the destroyed one kept, as KMIP keeps them: two objects", kmip::object_count(c.srv) == 2);

    // What Create refuses.
    var bad = aes_attrs(kmip::USAGE_ENCRYPT);
    kmip::attr_enum(bad, kmip::TAG_STATE, kmip::STATE_ACTIVE);
    let u3, e3 = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, bad);
    check("create with a State refused", e3 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_FIELD, c.version));
    var odd = kmip::attrs();
    kmip::attr_enum(odd, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(odd, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 100);
    let u4, e4 = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, odd);
    check("AES-100 refused", e4 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_FIELD, c.version));
    let u5, e5 = kmip::create(c, kmip::OBJ_CERTIFICATE, a);
    check("create a certificate refused", e5 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_OBJECT_TYPE, c.version));

    // Attributes in 1.x: Add, indexes, single values, the server's own.
    c.version = kmip::V1_4;
    var n1 = kmip::attrs();
    kmip::attr_name(n1, "first");
    check("add a Name", kmip::add_attribute(c, uid2, n1) == kmip::OK);
    var n2 = kmip::attrs();
    kmip::attr_name(n2, "second");
    check("add another Name", kmip::add_attribute(c, uid2, n2) == kmip::OK);
    var ci = kmip::attrs();
    kmip::attr_text(ci, kmip::TAG_CONTACT_INFORMATION, "a");
    check("add Contact Information", kmip::add_attribute(c, uid2, ci) == kmip::OK);
    check("add Contact Information twice refused", kmip::add_attribute(c, uid2, ci) == kmip::ERR_FAILED);
    var stx = kmip::attrs();
    kmip::attr_enum(stx, kmip::TAG_STATE, kmip::STATE_ACTIVE);
    check("add a State refused", kmip::add_attribute(c, uid2, stx) == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_READ_ONLY_ATTRIBUTE, c.version));
    let names, en = kmip::get_attributes(c, uid2, [kmip::TAG_NAME]);
    check("two Names", en == kmip::OK && kmip::get_name(names, 0)[..] == "first" && kmip::get_name(names, 1)[..] == "second");
    check("delete a Name", kmip::delete_attribute(c, uid2, kmip::TAG_NAME) == kmip::OK);
    let names2, en2 = kmip::get_attributes(c, uid2, [kmip::TAG_NAME]);
    check("the second Name left", kmip::get_name(names2, 0)[..] == "second" && kmip::get_name(names2, 1).len == 0);
    let list, el = kmip::get_attribute_list(c, uid2);
    var has_state = false;
    for t in list { if t == kmip::TAG_STATE { has_state = true; } }
    check("the attribute list has State", el == kmip::OK && has_state);

    // Key formats.
    let raw, er = kmip::get(c, uid2, kmip::FMT_RAW);
    let tr, et = kmip::get(c, uid2, kmip::FMT_TRANSPARENT_SYMMETRIC_KEY);
    check("Raw and Transparent Symmetric Key the same key", er == kmip::OK && et == kmip::OK &&
          tr.key_format == kmip::FMT_TRANSPARENT_SYMMETRIC_KEY && raw.material[..] == tr.material[..]);
    let p1, ep = kmip::get(c, uid2, kmip::FMT_PKCS_1);
    check("PKCS #1 of an AES key refused", ep == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED, c.version));

    // AES-CTR, checked against gslib's.
    check("activate", kmip::activate(c, uid2) == kmip::OK);
    let ctr = kmip::CryptoParams { mode: kmip::MODE_CTR };
    let ivc: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let sc, esc = kmip::encrypt(c, uid2, ctr, "counter mode text", ivc, "");
    var mine: u8[>..] = [];
    mine.append("counter mode text");
    let k = bignum::aes_init(raw.material);
    bignum::ctr_xor(k, ivc, mine);
    check("AES-CTR as gslib's", esc == kmip::OK && sc.data[..] == mine[..]);
    let ecb = kmip::CryptoParams { mode: kmip::MODE_ECB, padding: kmip::PAD_NONE };
    let se, ese = kmip::encrypt(c, uid2, ecb, "0123456789abcdef", "", "");
    let de, ede = kmip::decrypt(c, uid2, ecb, se.data, "", "", "");
    check("AES-ECB both ways", ese == kmip::OK && ede == kmip::OK && de[..] == "0123456789abcdef");
    let nb, enb = kmip::encrypt(c, uid2, ecb, "short", "", "");
    check("ECB without padding wants whole blocks", enb == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_FIELD, c.version));

    // Locate's limits.
    for j in 4 { let u, eu = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a); }
    let l2, el2 = kmip::locate(c, a, 2);
    check("locate at most 2", el2 == kmip::OK && l2.len == 2);
    let l3, el3 = kmip::locate(c, a, 0);
    check("locate all 5 AES-128 keys", el3 == kmip::OK && l3.len == 5);

    // ECDSA on P-256 and RSA-PSS.
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
    kmip::attr_curve(common, kmip::CURVE_P_256);
    var pa = kmip::attrs();
    kmip::attr_usage(pa, kmip::USAGE_SIGN);
    var pb = kmip::attrs();
    kmip::attr_usage(pb, kmip::USAGE_VERIFY);
    let ecpriv, ecpub, eec = kmip::create_key_pair(c, common, pa, pb);
    check("an EC P-256 key pair", eec == kmip::OK);
    let e_a = kmip::activate(c, ecpriv);
    let e_b = kmip::activate(c, ecpub);
    let ep2 = kmip::CryptoParams { sig: kmip::SIG_ECDSA_WITH_SHA256 };
    let es, ees = kmip::sign(c, ecpriv, ep2, "ec data");
    let ev, eev = kmip::verify(c, ecpub, ep2, "ec data", es);
    check("ECDSA P-256 signs and verifies", ees == kmip::OK && eev == kmip::OK && ev);
    let ev2, eev2 = kmip::verify(c, ecpub, ep2, "ec datA", es);
    check("ECDSA: other data invalid", eev2 == kmip::OK && !ev2);
    let pk, epk = kmip::get(c, ecpriv, 0);
    let parsed, pok = x509::parse_private_key(pk.material);
    check("the private key is PKCS #8 gslib reads", epk == kmip::OK && pk.key_format == kmip::FMT_PKCS_8 && pok && parsed.kind == x509::KEY_EC_P256);
    let links, elk = kmip::get_attributes(c, ecpriv, [kmip::TAG_LINK]);
    check("the private key links to the public key", elk == kmip::OK && kmip::has_attr(links, kmip::TAG_LINK));

    var rc = kmip::attrs();
    kmip::attr_enum(rc, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_RSA);
    kmip::attr_int(rc, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 2048);
    let rpriv, rpub, err2 = kmip::create_key_pair(c, rc, pa, pb);
    let e_c = kmip::activate(c, rpriv);
    let e_d = kmip::activate(c, rpub);
    let pss = kmip::CryptoParams { padding: kmip::PAD_PSS, hash: kmip::HASH_SHA_256 };
    let rs, ers = kmip::sign(c, rpriv, pss, "pss data");
    let rv, erv = kmip::verify(c, rpub, pss, "pss data", rs);
    check("RSA-PSS signs and verifies", err2 == kmip::OK && ers == kmip::OK && erv == kmip::OK && rv && rs.len == 256);
    let wrong, ew = kmip::sign(c, rpriv, ep2, "x");
    check("ECDSA with an RSA key refused", ew == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, c.version));

    // RNG.
    let r0, er0 = kmip::rng_retrieve(c, 0);
    check("RNG of 0 bytes refused", er0 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_FIELD, c.version));
    let r1, er1 = kmip::rng_retrieve(c, 48);
    check("RNG of 48 bytes", er1 == kmip::OK && r1.len == 48);

    // Operations of later versions.
    c.version = kmip::V1_0;
    let r2, er2 = kmip::rng_retrieve(c, 8);
    check("RNG in 1.0 refused", er2 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_OPERATION_NOT_SUPPORTED, c.version));
    c.version = kmip::V1_4;
    var sens = kmip::attrs();
    kmip::attr_bool(sens, kmip::TAG_SENSITIVE, true);
    check("Set Attribute in 1.4 refused", kmip::set_attribute(c, uid2, sens) == kmip::ERR_FAILED &&
          c.last_reason == kmip::reason_for(kmip::REASON_OPERATION_NOT_SUPPORTED, c.version));

    // Batches.
    var srv = kmip::server();
    var resp: u8[>..] = [];
    let req_stop = two_items(kmip::BATCH_STOP);
    kmip::handle(srv, "alice", req_stop, resp);
    let rstop = results(resp);
    check("Stop: one item, failed", rstop.len == 2 && rstop[0] == kmip::STATUS_OPERATION_FAILED && rstop[1] == kmip::REASON_ITEM_NOT_FOUND);
    let req_go = two_items(kmip::BATCH_CONTINUE);
    kmip::handle(srv, "alice", req_go, resp);
    let rgo = results(resp);
    check("Continue: both items, the second done", rgo.len == 4 && rgo[0] == kmip::STATUS_OPERATION_FAILED && rgo[2] == kmip::STATUS_SUCCESS);

    // Requests it cannot read.
    kmip::handle(srv, "alice", "not TTLV at all", resp);
    let rg = results(resp);
    check("garbage: Invalid Message", rg.len == 2 && rg[1] == kmip::REASON_INVALID_MESSAGE);
    let nocred = kmip::no_credential();
    var v3: u8[>..] = [];
    let m = kmip::begin_request(v3, kmip::Version { major: 3, minor: 0 }, 1, nocred);
    let i1, p1b = kmip::begin_item(v3, kmip::OP_QUERY, "");
    kmip::end_item(v3, i1, p1b);
    kmip::end(v3, m);
    kmip::handle(srv, "alice", v3, resp);
    let rv3 = results(resp);
    check("KMIP 3.0: Unsupported Protocol Version", rv3.len == 2 && rv3[1] == kmip::REASON_UNSUPPORTED_PROTOCOL_VERSION);
    var wrong_count: u8[>..] = [];
    let m2 = kmip::begin_request(wrong_count, kmip::V1_2, 2, nocred);
    let i2, p2b = kmip::begin_item(wrong_count, kmip::OP_QUERY, "");
    kmip::end_item(wrong_count, i2, p2b);
    kmip::end(wrong_count, m2);
    kmip::handle(srv, "alice", wrong_count, resp);
    let rwc = results(resp);
    check("a Batch Count that is not the items': Invalid Message", rwc.len == 2 && rwc[1] == kmip::REASON_INVALID_MESSAGE);

    // The credential in the header is read.
    var cred: u8[>..] = [];
    let cr = kmip::password_credential("alice", "pw");
    let m3 = kmip::begin_request(cred, kmip::V1_2, 0, cr);
    kmip::end(cred, m3);
    var doc: kmip::Node[>..] = [];
    let root, ed = kmip::decode(cred, kmip::Options { .. }, doc);
    let req, erq = kmip::parse_request(cred, doc, root);
    check("the request's username and password", erq == kmip::OK && kmip::request_username(cred, req) == "alice" &&
          kmip::request_password(cred, req) == "pw");

    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
