// scenario: every operation of kmip.client against a server, in one
// protocol version, each result checked, and what can be checked here
// (the AES and HMAC of keys fetched with Get) worked out again with
// gslib's own. The in-memory server runs it in test/local.goose; a live
// one (PyKMIP, or goose-kmipd) in test/interop_client.goose. Operations
// the server's Query does not list (PyKMIP has no RNG Retrieve) are left
// out, and those of later versions than the one spoken.

namespace scenario;

import std;
import gslib.kmip;
import gslib.kmip.client;
import gslib.crypto.bignum;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.modes;
import gslib.crypto.bignum.hmac;

var failures = 0;
var checks = 0;
var verbose = false;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL  ", what); } else if verbose { print("ok    ", what); }
}

fn check_e<C>(c: const C&, what: const u8[:], e: i64) -> bool {
    if e != kmip::OK { checks++; failures++; print("FAIL  ", what, ": ", kmip::describe(c, e)); return false; }
    return true;
}

fn has_tag(tags: const u32[:], t: u32) -> bool {
    for x in tags { if x == t { return true; } }
    return false;
}

// DER: a length, and an RSAPublicKey wrapped as a SubjectPublicKeyInfo.
fn der_len(out: u8[>..]&, n: i64) {
    if n < 128 { out.push(n as! u8); }
    else if n < 256 { out.push(0x81); out.push(n as! u8); }
    else { out.push(0x82); out.push((n >> 8) as! u8); out.push(n as! u8); }
}

fn spki_of_pkcs1(pkcs1: const u8[:]) -> u8[>..] {
    let alg: u8[15] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    var bits: u8[>..] = [0x03];
    der_len(bits, pkcs1.len + 1);
    bits.push(0);
    bits.append(pkcs1);
    var out: u8[>..] = [0x30];
    der_len(out, alg.len + bits.len);
    out.append(alg);
    out.append(bits);
    return out;
}

// Runs it all with c, in the version ver ("1.0" to "2.0", or "auto" to
// negotiate); run makes this run's names unique, since a server keeps its
// objects.
fn run<C>(c: C&, ver: const u8[:], run: const u8[:]) {
    // The version.
    if ver == "auto" {
        let v, ev = kmip::negotiate(c);
        check("negotiate", ev == kmip::OK);
        print("      version ", v.major, ".", v.minor);
    } else {
        let mj, ok1 = parse_int(ver[..1], 10);
        let mn, ok2 = parse_int(ver[2..], 10);
        c.version = kmip::Version { major: mj as! i32, minor: mn as! i32 };
        // Discover Versions came with 1.1.
        let vs, ev = kmip::discover_versions(c, kmip::ALL_VERSIONS);
        if kmip::version_lt(c.version, kmip::V1_1) {
            check("discover versions in 1.0: not supported", ev == kmip::ERR_FAILED && c.last_reason == kmip::REASON_OPERATION_NOT_SUPPORTED);
        } else if check_e(c, "discover versions", ev) {
            var has = false;
            for v in vs { if kmip::version_eq(v, c.version) { has = true; } }
            check(str("server speaks ", ver), has);
        }
    }
    let v2 = kmip::is_v2(c.version);

    // Query.
    let fns: u32[2] = [kmip::QUERY_OPERATIONS, kmip::QUERY_OBJECTS];
    let q, eq = kmip::query(c, fns);
    var has_rng = false;
    var has_mac = false;
    if check_e(c, "query", eq) {
        var has_create = false;
        for op in q.operations {
            if op == kmip::OP_CREATE { has_create = true; }
            if op == kmip::OP_RNG_RETRIEVE { has_rng = true; }
            if op == kmip::OP_MAC { has_mac = true; }
        }
        check("query lists Create", has_create);
    }
    let gcm_ok = !kmip::version_lt(c.version, kmip::V1_4);
    // Encrypt, Decrypt, Sign, Signature Verify and MAC came with 1.2.
    let crypto_ok = !kmip::version_lt(c.version, kmip::V1_2);

    // Create an AES key.
    let name = str("gs-aes-", run, "-", ver);
    var at = kmip::attrs();
    kmip::attr_enum(at, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(at, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
    kmip::attr_usage(at, kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    kmip::attr_name(at, name);
    let uid, ec = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, at);
    if !check_e(c, "create AES-256", ec) { print(checks, " checks, ", failures, " failures"); exit(1); }
    check("create gives a Unique Identifier", uid.len > 0);

    // Get it.
    let key, eg = kmip::get(c, uid, 0);
    if check_e(c, "get", eg) {
        check("get: a symmetric key", key.obj_type == kmip::OBJ_SYMMETRIC_KEY);
        check("get: AES, 256 bits, 32 bytes", key.alg == kmip::ALG_AES && key.length == 256 && key.material.len == 32);
    }

    // Its attributes.
    let want: u32[4] = [kmip::TAG_NAME, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::TAG_STATE, kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK];
    let ga, ea = kmip::get_attributes(c, uid, want);
    if check_e(c, "get attributes", ea) {
        check("get attributes: the name", kmip::get_name(ga, 0)[..] == name[..]);
        let alg, aok = kmip::get_enum(ga, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM);
        check("get attributes: AES", aok && alg == kmip::ALG_AES);
        let st, sok = kmip::get_enum(ga, kmip::TAG_STATE);
        check("get attributes: Pre-Active", sok && st == kmip::STATE_PRE_ACTIVE);
        let m, mok = kmip::get_int(ga, kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK);
        check("get attributes: the usage mask", mok && m as! u32 == (kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT));
    }
    let none: u32[0] = [];
    let all, eall = kmip::get_attributes(c, uid, none);
    if check_e(c, "get all attributes", eall) {
        check("get all attributes: several, the length among them", kmip::attr_count(all) >= 4 && kmip::has_attr(all, kmip::TAG_CRYPTOGRAPHIC_LENGTH));
    }
    let list, el = kmip::get_attribute_list(c, uid);
    if check_e(c, "get attribute list", el) {
        check("get attribute list: algorithm, length, name", has_tag(list, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM) &&
              has_tag(list, kmip::TAG_CRYPTOGRAPHIC_LENGTH) && has_tag(list, kmip::TAG_NAME));
    }

    // Locate it by its name.
    var by_name = kmip::attrs();
    kmip::attr_name(by_name, name);
    let found, efound = kmip::locate(c, by_name, 0);
    if check_e(c, "locate by name", efound) {
        check("locate finds the one key", found.len == 1 && found[0][..] == uid[..]);
    }

    // Activate, then encrypt and decrypt with it; check against gslib's AES.
    let eact = kmip::activate(c, uid);
    if check_e(c, "activate", eact) {
        let st, sok = kmip::get_attributes(c, uid, [kmip::TAG_STATE]);
        let s, ok = kmip::get_enum(st, kmip::TAG_STATE);
        check("activate: Active", ok && s == kmip::STATE_ACTIVE);
    }
    let plain = "sixteen byte msg and a few more bytes to pad";
    let iv: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let cbc = kmip::CryptoParams { alg: kmip::ALG_AES, mode: kmip::MODE_CBC, padding: kmip::PAD_PKCS5 };
    let sealed, eenc = kmip::encrypt(c, uid, cbc, plain, iv, "");
    if !crypto_ok { } else if check_e(c, "encrypt AES-CBC", eenc) {
        check("encrypt: whole blocks", sealed.data.len == 48);
        if key.material.len == 32 && sealed.data.len == 48 {
            var mine: u8[>..] = [];
            mine.append(sealed.data);
            let k = bignum::aes_init(key.material);
            bignum::cbc_decrypt(k, iv, mine);
            check("encrypt: gslib's AES-CBC decrypts it", mine[..plain.len] == plain[..]);
        }
        let back, edec = kmip::decrypt(c, uid, cbc, sealed.data, iv, "", "");
        if check_e(c, "decrypt AES-CBC", edec) { check("decrypt: the plaintext again", back[..] == plain[..]); }
    }
    // The server choosing the IV.
    let sealed2, eenc2 = kmip::encrypt(c, uid, kmip::CryptoParams { alg: kmip::ALG_AES, mode: kmip::MODE_CBC, padding: kmip::PAD_PKCS5, random_iv: true }, plain, "", "");
    if !crypto_ok { } else if check_e(c, "encrypt with the server's IV", eenc2) {
        check("encrypt: the server's IV comes back", sealed2.iv.len == 16);
        let back2, edec2 = kmip::decrypt(c, uid, cbc, sealed2.data, sealed2.iv, "", "");
        if check_e(c, "decrypt with that IV", edec2) { check("decrypt: the plaintext again", back2[..] == plain[..]); }
    }
    // AES-GCM.
    let nonce: u8[12] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2];
    let gcm = kmip::CryptoParams { alg: kmip::ALG_AES, mode: kmip::MODE_GCM, tag_length: 16 };
    let sg, eg2 = kmip::encrypt(c, uid, gcm, plain, nonce, "header");
    if !gcm_ok { } else if check_e(c, "encrypt AES-GCM", eg2) {
        check("encrypt AES-GCM: the tag", sg.tag.len == 16 && sg.data.len == plain.len);
        let bg, edg = kmip::decrypt(c, uid, gcm, sg.data, nonce, "header", sg.tag);
        if check_e(c, "decrypt AES-GCM", edg) { check("decrypt AES-GCM: the plaintext again", bg[..] == plain[..]); }
        var bad: u8[>..] = [];
        bad.append(sg.tag);
        bad[0] ^= 1;
        let bb, ebad = kmip::decrypt(c, uid, gcm, sg.data, nonce, "header", bad);
        check("decrypt AES-GCM: a wrong tag refused", ebad == kmip::ERR_FAILED);
    }

    // Register a key of our own and get it back.
    let mine: u8[16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    var ra = kmip::attrs();
    kmip::attr_usage(ra, kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    kmip::attr_name(ra, str("gs-reg-", run, "-", ver));
    let mo = kmip::symmetric_key(kmip::ALG_AES, mine);
    let ruid, er = kmip::register(c, mo, ra);
    if check_e(c, "register an AES-128 key", er) {
        let rk, erk = kmip::get(c, ruid, 0);
        if check_e(c, "get the registered key", erk) { check("get: the same bytes", rk.material[..] == mine[..] && rk.length == 128); }
    }
    // A secret.
    var sa = kmip::attrs();
    kmip::attr_usage(sa, kmip::USAGE_DERIVE_KEY);
    let so0 = kmip::secret_data(kmip::SECRET_PASSWORD, "correct horse");
    let suid, es = kmip::register(c, so0, sa);
    if check_e(c, "register secret data", es) {
        let so, eso = kmip::get(c, suid, 0);
        if check_e(c, "get the secret", eso) {
            check("get: secret data, a password, the same bytes", so.obj_type == kmip::OBJ_SECRET_DATA &&
                  so.sub_type == kmip::SECRET_PASSWORD && so.material[..] == "correct horse");
        }
    }

    // MAC with an HMAC key of our own (Create makes none in PyKMIP);
    // check against gslib's HMAC.
    if has_mac && crypto_ok {
        var ma = kmip::attrs();
        kmip::attr_usage(ma, kmip::USAGE_MAC_GENERATE);
        let hk: u8[32] = [7; 32];
        let ho = kmip::symmetric_key(kmip::ALG_HMAC_SHA256, hk);
        let muid, em = kmip::register(c, ho, ma);
        if check_e(c, "register an HMAC-SHA256 key", em) {
            let ea2 = kmip::activate(c, muid);
            let tag, emac = kmip::mac(c, muid, kmip::CryptoParams { alg: kmip::ALG_HMAC_SHA256 }, "the data");
            if check_e(c, "mac", emac) {
                check("mac: gslib's HMAC-SHA256 the same", tag[..] == bignum::hmac_sha256(hk, "the data")[..]);
            }
        }
    }

    // An RSA key pair: sign, verify.
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_RSA);
    kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 2048);
    var pa = kmip::attrs();
    kmip::attr_usage(pa, kmip::USAGE_SIGN);
    kmip::attr_name(pa, str("gs-rsa-", run, "-", ver));
    var pb = kmip::attrs();
    kmip::attr_usage(pb, kmip::USAGE_VERIFY);
    let priv, pubk, ekp = kmip::create_key_pair(c, common, pa, pb);
    if check_e(c, "create an RSA-2048 key pair", ekp) {
        check("create key pair: two identifiers", priv.len > 0 && pubk.len > 0 && priv[..] != pubk[..]);
        let e1 = kmip::activate(c, priv);
        let e2 = kmip::activate(c, pubk);
        check("activate both", e1 == kmip::OK && e2 == kmip::OK);
        let sp = kmip::CryptoParams { sig: kmip::SIG_SHA256_WITH_RSA_ENCRYPTION, padding: kmip::PAD_PKCS1V15, hash: kmip::HASH_SHA_256, alg: kmip::ALG_RSA };
        if crypto_ok {
        let sig, esig = kmip::sign(c, priv, sp, "signed text");
        check_e(c, "sign", esig);
        check("sign: 256 bytes", sig.len == 256);
        let pk, epk = kmip::get(c, pubk, 0);
        if check_e(c, "get the public key", epk) {
            check("get: an RSA public key", pk.obj_type == kmip::OBJ_PUBLIC_KEY && pk.alg == kmip::ALG_RSA && pk.material.len > 256);
        }
        // The public key verifies the signature; and so does the same key
        // registered again as a SubjectPublicKeyInfo, which checks the
        // bytes Get gave (PyKMIP's are PKCS#1).
        let good, ev = kmip::verify(c, pubk, sp, "signed text", sig);
        if check_e(c, "verify", ev) { check("verify: valid", good); }
        let bad, ev2 = kmip::verify(c, pubk, sp, "signed texT", sig);
        if check_e(c, "verify other data", ev2) { check("verify other data: invalid", !bad); }
        if pk.key_format == kmip::FMT_PKCS_1 {
            let spki = spki_of_pkcs1(pk.material);
            let po = kmip::public_key(kmip::ALG_RSA, 2048, kmip::FMT_X_509, spki);
            var va = kmip::attrs();
            kmip::attr_usage(va, kmip::USAGE_VERIFY);
            let ru, erp = kmip::register(c, po, va);
            if check_e(c, "register the public key as X.509", erp) {
                let e3 = kmip::activate(c, ru);
                let good2, ev3 = kmip::verify(c, ru, sp, "signed text", sig);
                if check_e(c, "verify with it", ev3) { check("verify with it: valid", good2); }
            }
        }
        }
    }

    // Changing attributes.
    if v2 {
        // Set and Modify a single-valued attribute PyKMIP lets clients
        // change (Sensitive), then Delete a Name, as 1.x does below.
        let SE = kmip::TAG_SENSITIVE;
        var na = kmip::attrs();
        kmip::attr_bool(na, SE, false);
        let es1 = kmip::set_attribute(c, ruid, na);
        if check_e(c, "set attribute (Sensitive)", es1) {
            let g, eg3 = kmip::get_attributes(c, ruid, [SE]);
            let gv, gok = kmip::get_bool(g, SE);
            check("set attribute: there", gok && !gv);
            // Sensitive goes one way: false to true (KMIP 2.0 §4.48).
            var na2 = kmip::attrs();
            kmip::attr_bool(na2, SE, true);
            let em2 = kmip::modify_attribute(c, ruid, na2);
            if check_e(c, "modify attribute", em2) {
                let g2, eg4 = kmip::get_attributes(c, ruid, [SE]);
                let gv2, gok2 = kmip::get_bool(g2, SE);
                check("modify attribute: changed", gok2 && gv2);
            }
        }
    }
    {
        // 1.x's Delete Attribute of a Name the key has.
        let ed = kmip::delete_attribute(c, ruid, kmip::TAG_NAME);
        if check_e(c, "delete attribute (Name)", ed) {
            let g3, eg5 = kmip::get_attributes(c, ruid, [kmip::TAG_NAME]);
            check("delete attribute: gone", !kmip::has_attr(g3, kmip::TAG_NAME));
        }
    }

    if has_rng {
        let r, err = kmip::rng_retrieve(c, 32);
        if check_e(c, "rng retrieve", err) { check("rng retrieve: 32 bytes", r.len == 32); }
    }

    // Revoke, destroy; the key is gone.
    let ed1 = kmip::destroy(c, uid);
    check("destroy an Active key refused", ed1 == kmip::ERR_FAILED);
    let erv = kmip::revoke(c, uid, kmip::REVOKE_CESSATION_OF_OPERATION, "done with it", 0);
    if check_e(c, "revoke", erv) {
        let st, sok = kmip::get_attributes(c, uid, [kmip::TAG_STATE]);
        let s, ok = kmip::get_enum(st, kmip::TAG_STATE);
        check("revoke: Deactivated", ok && s == kmip::STATE_DEACTIVATED);
    }
    let ed = kmip::destroy(c, uid);
    if check_e(c, "destroy", ed) {
        let gone, eg6 = kmip::get(c, uid, 0);
        // 2.0 has Object Destroyed for it (gslib's server); servers that
        // forget a destroyed object (PyKMIP's) say Item Not Found.
        let r = c.last_reason;
        let named = r == kmip::REASON_ITEM_NOT_FOUND || (kmip::is_v2(c.version) && r == kmip::REASON_OBJECT_DESTROYED);
        check("get after destroy: Item Not Found or Object Destroyed", eg6 == kmip::ERR_FAILED && named);
    }
    let found2, ef2 = kmip::locate(c, by_name, 0);
    if check_e(c, "locate after destroy", ef2) { check("locate after destroy: none", found2.len == 0); }

}
