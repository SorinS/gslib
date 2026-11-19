// key_lifecycle: a key manager's other half, in one program: wrapped
// keys, derived keys and replacement keys, between a client and the
// in-memory key manager (kmip.local) in KMIP 2.0. A key-encryption key
// is registered; a data key is fetched wrapped under it (NIST Key Wrap)
// and unwrapped here with the client's own copy of the KEK; a key is
// derived from a password with PBKDF2 and from a key with HKDF; a key is
// re-keyed, its name and links moving to the replacement; a large text
// is encrypted in parts; and an RSA key is fetched as a Transparent RSA
// Private Key.
//
//   goose examples/kmip/key_lifecycle.goose

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.client_ops;
import gslib.kmip.local;
import gslib.kmip.wrap;

fn die<C>(c: const C&, what: const u8[:], e: i64) {
    if e != kmip::OK { print(what, ": ", kmip::describe(c, e)); exit(1); }
}

fn hex(b: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    let digits = "0123456789abcdef";
    for x in b { s.push(digits[(x >> 4) as i64]); s.push(digits[(x & 15) as i64]); }
    return s;
}

fn usage(u: u32) -> kmip::Attrs {
    var a = kmip::attrs();
    kmip::attr_usage(a, u);
    return a;
}

fn main() {
    var c = kmip::local("alice");
    c.version = kmip::V2_0;
    let none: u8[0] = [];

    // A KEK the client also holds, and a data key made by the server.
    let kek_bytes: u8[16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let kek_obj = kmip::symmetric_key(kmip::ALG_AES, kek_bytes);
    let kek_use = usage(kmip::USAGE_WRAP_KEY | kmip::USAGE_UNWRAP_KEY);
    let kek, ek = kmip::register(c, kek_obj, kek_use);
    die(c, "register the KEK", ek);
    var a = usage(kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    kmip::attr_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
    kmip::attr_name(a, "data-key");
    kmip::attr_bool(a, kmip::TAG_SENSITIVE, true);
    let dk, ed = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    die(c, "create the data key", ed);
    let plain_try, ep = kmip::get(c, dk, 0);
    print("Get of a Sensitive key in the clear: ", kmip::describe(c, ep));

    // Wrapped under the KEK, unwrapped here.
    var w = kmip::wrapping(kmip::WRAP_ENCRYPT);
    kmip::wrap_encrypt_key(w, kek);
    let wrapped, ew = kmip::get_wrapped(c, dk, w);
    die(c, "get wrapped", ew);
    print("wrapped (", wrapped.material.len, " bytes): ", hex(wrapped.material));
    let mine, r = kmip::unwrap_with(wrapped, kek_obj);
    print("unwrapped here: ", mine.material.len * 8, "-bit AES key, ", if r == 0 { "ok" } else { "failed" });

    // Derived keys.
    let pw_obj = kmip::secret_data(kmip::SECRET_PASSWORD, "correct horse battery staple");
    var pw_use = usage(kmip::USAGE_DERIVE_KEY);
    kmip::attr_datetime(pw_use, kmip::TAG_ACTIVATION_DATE, kmip::now_of(c.srv) - 1);
    let pw, epw = kmip::register(c, pw_obj, pw_use);
    die(c, "register a password", epw);
    var d = kmip::derivation(kmip::DERIVE_PBKDF2);
    d.params = kmip::CryptoParams { hash: kmip::HASH_SHA_256 };
    d.has_params = true;
    d.salt.append("NaCl");
    d.iterations = 100000;
    var da = kmip::attrs();
    kmip::attr_enum(da, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(da, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
    var from: u8[..64][>..] = [];
    var u: u8[..64] = [];
    u.append(pw);
    from.push(u);
    let pk, epk = kmip::derive_key(c, kmip::OBJ_SYMMETRIC_KEY, from, d, da);
    die(c, "PBKDF2", epk);
    let pko, epko = kmip::get(c, pk, 0);
    print("PBKDF2-HMAC-SHA-256, 100000 rounds: ", hex(pko.material));

    // A replacement key: the name moves to it.
    let act = kmip::activate(c, dk);
    let no_attrs = kmip::attrs();
    let nk, en = kmip::rekey(c, dk, 0, no_attrs);
    die(c, "re-key", en);
    let name_tag: u32[1] = [kmip::TAG_NAME];
    let na, ena = kmip::get_attributes(c, nk, name_tag);
    print("re-keyed ", dk, " to ", nk, ", which is now \"", kmip::get_name(na, 0), "\"");

    // Encryption in parts.
    let cbc = kmip::CryptoParams { mode: kmip::MODE_CBC, padding: kmip::PAD_PKCS5 };
    let iv: u8[16] = [7; 16];
    let p1, e1 = kmip::part(c, kmip::OP_ENCRYPT, nk, cbc, "a text sent ", iv, none, false, none);
    die(c, "first part", e1);
    let p2, e2 = kmip::part(c, kmip::OP_ENCRYPT, nk, cbc, "in two parts", none, p1.corr, true, none);
    die(c, "last part", e2);
    print("in parts: ", p1.data.len, " bytes, then ", p2.data.len);

    // An RSA key in KMIP's transparent form.
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_RSA);
    kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 2048);
    let us = usage(kmip::USAGE_SIGN);
    let uv = usage(kmip::USAGE_VERIFY);
    let pv, pb, ekp = kmip::create_key_pair(c, common, us, uv);
    die(c, "create key pair", ekp);
    let t, et = kmip::get(c, pv, kmip::FMT_TRANSPARENT_RSA_PRIVATE_KEY);
    die(c, "get transparent", et);
    var doc: kmip::Node[>..] = [];
    let root, de = kmip::decode(t.material, kmip::Options { .. }, doc);
    print("the private key's Key Material: ", doc[root].count, " Big Integers, ",
          kmip::tag_name(doc[root + 1].tag), " first");
}
