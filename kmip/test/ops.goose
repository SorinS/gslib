// The operations past the basic ones, through kmip.local, with published
// answers where there are some: key formats (PKCS #1, PKCS #8, the
// transparent structures) both ways; wrapped keys (RFC 3394's vector
// registered wrapped and Got unwrapped; Get wrapped with NIST Key Wrap,
// AES Key Wrap with Padding, RSA-OAEP and HMAC, both encodings, unwrapped
// by the client); Sensitive and Extractable; Export and Import; Re-key
// and Re-key Key Pair; Derive Key (the OASIS cases' HASH, HMAC and
// PBKDF2 answers, RFC 6070's PBKDF2, RFC 5869's HKDF, SP 800-108's three
// modes, ECDH both ways); Check, Get Usage Allocation, Obtain Lease,
// Archive and Recover, Adjust Attribute, Interop; MAC Verify, CMAC,
// Hash; RSA-OAEP with SHA-384 and MGF1 over SHA-256; ChaCha20 and
// ChaCha20-Poly1305 (RFC 8439's vectors); Triple DES; operations in parts;
// a batch undone; the ID Placeholder.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.client_ops;
import gslib.kmip.local;
import gslib.kmip.server;
import gslib.kmip.formats;
import gslib.kmip.crypto;
import gslib.kmip.wrap;
import gslib.crypto.bignum;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.cmac;
import gslib.crypto.bignum.modes;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn key_attrs(alg: u32, bits: i32, usage: u32) -> kmip::Attrs {
    var a = kmip::attrs();
    kmip::attr_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, alg);
    kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, bits);
    kmip::attr_usage(a, usage);
    return a;
}

fn usage_only(usage: u32) -> kmip::Attrs {
    var a = kmip::attrs();
    kmip::attr_usage(a, usage);
    return a;
}

// A key registered with its material, Active from an hour ago.
fn register_key(c: kmip::Local&, alg: u32, material: const u8[:], usage: u32) -> u8[>..] {
    var a = usage_only(usage);
    kmip::attr_datetime(a, kmip::TAG_ACTIVATION_DATE, kmip::now_of(c.srv) - 3600);
    let o = kmip::symmetric_key(alg, material);
    let uid, e = kmip::register(c, o, a);
    check("register a key", e == kmip::OK);
    return uid;
}

fn register_secret(c: kmip::Local&, material: const u8[:], usage: u32) -> u8[>..] {
    var a = usage_only(usage);
    kmip::attr_datetime(a, kmip::TAG_ACTIVATION_DATE, kmip::now_of(c.srv) - 3600);
    let o = kmip::secret_data(kmip::SECRET_PASSWORD, material);
    let uid, e = kmip::register(c, o, a);
    check("register a secret", e == kmip::OK);
    return uid;
}

fn material_of(c: kmip::Local&, uid: const u8[:]) -> u8[>..] {
    let o, e = kmip::get(c, uid, 0);
    var m: u8[>..] = [];
    if e == kmip::OK { m.append(o.material); }
    return m;
}

fn one(u: const u8[:]) -> u8[..64][>..] {
    var r: u8[..64][>..] = [];
    var x: u8[..64] = [];
    x.append(u);
    r.push(x);
    return r;
}

fn two(u: const u8[:], w: const u8[:]) -> u8[..64][>..] {
    var r = one(u);
    var x: u8[..64] = [];
    x.append(w);
    r.push(x);
    return r;
}

fn derived(c: kmip::Local&, from: const u8[..64][:], d: const kmip::Derivation&, bits: i32) -> u8[>..] {
    var a = kmip::attrs();
    kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, bits);
    let uid, e = kmip::derive_key(c, kmip::OBJ_SECRET_DATA, from, d, a);
    var m: u8[>..] = [];
    if e != kmip::OK { return m; }
    return material_of(c, uid);
}

// Has the object a Link of the type to the uid?
fn linked(c: kmip::Local&, uid: const u8[:], link_type: u32, to: const u8[:]) -> bool {
    let tags: u32[1] = [kmip::TAG_LINK];
    let a, e = kmip::get_attributes(c, uid, tags);
    if e != kmip::OK { return false; }
    var found = false;
    kmip::each_attr(a) { t, item =>
        var d: kmip::Node[>..] = [];
        let r, de = kmip::decode(item, kmip::Options { .. }, d);
        let lt, lok = kmip::child_enum(item, d, r, kmip::TAG_LINK_TYPE);
        let lu, uok = kmip::child_text(item, d, r, kmip::TAG_LINKED_OBJECT_IDENTIFIER);
        if de == kmip::OK && lok && uok && lt == link_type && lu == to { found = true; }
    };
    return found;
}

fn state_of(c: kmip::Local&, uid: const u8[:]) -> u32 {
    let tags: u32[1] = [kmip::TAG_STATE];
    let a, e = kmip::get_attributes(c, uid, tags);
    let s, ok = kmip::get_enum(a, kmip::TAG_STATE);
    return if e == kmip::OK && ok { s } else { 0 };
}

// The statuses of a response's items.
fn statuses(resp: const u8[:]) -> u32[>..] {
    var out: u32[>..] = [];
    var doc: kmip::Node[>..] = [];
    let r, e = kmip::decode(resp, kmip::Options { .. }, doc);
    if e != kmip::OK { return out; }
    let m, pe = kmip::parse_response(resp, doc, r);
    if pe != kmip::OK { return out; }
    for it in m.items { out.push(it.status); }
    return out;
}

fn formats(c: kmip::Local&) {
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_RSA);
    kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 2048);
    kmip::attr_datetime(common, kmip::TAG_ACTIVATION_DATE, kmip::now_of(c.srv) - 60);
    let ua = usage_only(kmip::USAGE_SIGN | kmip::USAGE_DECRYPT);
    let ub = usage_only(kmip::USAGE_VERIFY | kmip::USAGE_ENCRYPT);
    let pv, pb, e = kmip::create_key_pair(c, common, ua, ub);
    check("RSA pair", e == kmip::OK);
    let p8, e8 = kmip::get(c, pv, kmip::FMT_PKCS_8);
    let p1, e1 = kmip::get(c, pv, kmip::FMT_PKCS_1);
    let tr, et = kmip::get(c, pv, kmip::FMT_TRANSPARENT_RSA_PRIVATE_KEY);
    check("private key as PKCS #8, PKCS #1, Transparent RSA", e8 == kmip::OK && e1 == kmip::OK && et == kmip::OK);
    let back, rb = kmip::convert_key(tr, kmip::FMT_PKCS_8);
    check("Transparent RSA Private Key read back to the same PKCS #8", rb == 0 && back.material[..] == p8.material[..]);
    let ec, eec = kmip::get(c, pv, kmip::FMT_EC_PRIVATE_KEY);
    check("an RSA key is no ECPrivateKey", eec == kmip::ERR_FAILED && c.last_reason == kmip::REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED);
    let x5, ex = kmip::get(c, pb, kmip::FMT_X_509);
    let tp, etp = kmip::get(c, pb, kmip::FMT_TRANSPARENT_RSA_PUBLIC_KEY);
    let b2, rb2 = kmip::convert_key(tp, kmip::FMT_X_509);
    check("public key as Transparent RSA and back", ex == kmip::OK && etp == kmip::OK && rb2 == 0 && b2.material[..] == x5.material[..]);
    // RSA-OAEP with SHA-384 and MGF1 over SHA-256, as the OASIS cases have it.
    let cp = kmip::CryptoParams { padding: kmip::PAD_OAEP, hash: kmip::HASH_SHA_384, mgf: kmip::MGF_MGF1, mgf_hash: kmip::HASH_SHA_256 };
    let none: u8[0] = [];
    let sealed, es = kmip::encrypt(c, pb, cp, "an RSA secret", none, none);
    let opened, eo = kmip::decrypt(c, pv, cp, sealed.data, none, none, none);
    check("RSA-OAEP SHA-384 / MGF1 SHA-256 both ways", es == kmip::OK && eo == kmip::OK && opened[..] == "an RSA secret");
    // EC: SEC 1 and Transparent EC.
    var ecc = kmip::attrs();
    kmip::attr_enum(ecc, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
    kmip::attr_curve(ecc, kmip::CURVE_P_384);
    let us = usage_only(kmip::USAGE_SIGN);
    let uv = usage_only(kmip::USAGE_VERIFY);
    let epv, epb, ee = kmip::create_key_pair(c, ecc, us, uv);
    let s1, es1 = kmip::get(c, epv, kmip::FMT_EC_PRIVATE_KEY);
    let s2, es2 = kmip::get(c, epv, kmip::FMT_TRANSPARENT_EC_PRIVATE_KEY);
    let s3, es3 = kmip::get(c, epb, kmip::FMT_TRANSPARENT_EC_PUBLIC_KEY);
    check("EC keys as SEC 1 and Transparent EC", ee == kmip::OK && es1 == kmip::OK && es2 == kmip::OK && es3 == kmip::OK);
}

fn wrapping(c: kmip::Local&) {
    // RFC 3394 §4.1: the KEK 000102...0f wraps 00112233...ff so.
    let kek_bytes = unhex("000102030405060708090a0b0c0d0e0f");
    let kek = register_key(c, kmip::ALG_AES, kek_bytes, kmip::USAGE_WRAP_KEY | kmip::USAGE_UNWRAP_KEY);
    var w = kmip::wrapping(kmip::WRAP_ENCRYPT);
    kmip::wrap_encrypt_key(w, kek);
    w.encoding = kmip::ENCODING_NO_ENCODING;
    var wrapped = kmip::symmetric_key(kmip::ALG_AES, unhex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"));
    wrapped.wrapped = true;
    put_kwd(wrapped, w);
    wrapped.length = 128;
    let ue = usage_only(kmip::USAGE_ENCRYPT);
    let wu, ew = kmip::register(c, wrapped, ue);
    check("register a wrapped key", ew == kmip::OK);
    let as_reg, ear = kmip::get_as(c, wu, kmip::FMT_RAW, kmip::KEY_WRAP_AS_REGISTERED, w, false);
    check("Get As Registered: wrapped", ear == kmip::OK && as_reg.wrapped && as_reg.material[..] == unhex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")[..]);
    let plain, ep = kmip::get_as(c, wu, kmip::FMT_RAW, kmip::KEY_WRAP_NOT_WRAPPED, w, false);
    check("Get Not Wrapped: RFC 3394's key", ep == kmip::OK && !plain.wrapped && plain.material[..] == unhex("00112233445566778899aabbccddeeff")[..]);
    // The server wraps; the client unwraps with its copy of the KEK.
    let target = register_key(c, kmip::ALG_AES, unhex("00112233445566778899aabbccddeeff0011223344556677"), kmip::USAGE_ENCRYPT);
    let mine = kmip::symmetric_key(kmip::ALG_AES, kek_bytes);
    let g1, e1 = kmip::get_wrapped(c, target, w);
    let u1, r1 = kmip::unwrap_with(g1, mine);
    check("NIST Key Wrap, No Encoding, unwrapped by the client", e1 == kmip::OK && g1.wrapped && r1 == 0 &&
          u1.material[..] == unhex("00112233445566778899aabbccddeeff0011223344556677")[..]);
    var w2 = kmip::wrapping(kmip::WRAP_ENCRYPT);
    kmip::wrap_encrypt_key(w2, kek);
    w2.enc.params = kmip::CryptoParams { mode: kmip::MODE_AES_KEY_WRAP_PADDING };
    w2.enc.has_params = true;
    kmip::wrap_attribute(w2, "Cryptographic Usage Mask");
    let g2, e2 = kmip::get_wrapped(c, target, w2);
    check("parameters a key does not have are refused", e2 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, c.version));
    w2.enc.has_params = false;
    let g3, e3 = kmip::get_wrapped(c, target, w2);
    var got = kmip::attrs();
    let none = kmip::CryptoParams { .. };
    let nothing = kmip::new_object(0);
    let u3, r3 = kmip::unwrap_object(g3, mine, none, false, nothing, none, false, got);
    let m3, mok = kmip::get_int(got, kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK);
    check("TTLV-encoded Key Value with its usage mask", e3 == kmip::OK && r3 == 0 && mok && m3 == kmip::USAGE_ENCRYPT as! i32 &&
          u3.material[..] == unhex("00112233445566778899aabbccddeeff0011223344556677")[..]);
    // MAC/sign only: the Key Value in the clear, an HMAC over it.
    let hk = register_key(c, kmip::ALG_HMAC_SHA256, unhex("0f0e0d0c0b0a09080706050403020100"), kmip::USAGE_MAC_GENERATE | kmip::USAGE_MAC_VERIFY);
    var wm = kmip::wrapping(kmip::WRAP_MAC_SIGN);
    kmip::wrap_mac_key(wm, hk);
    let g4, e4 = kmip::get_wrapped(c, target, wm);
    let hmine = kmip::symmetric_key(kmip::ALG_HMAC_SHA256, unhex("0f0e0d0c0b0a09080706050403020100"));
    let u4, r4 = kmip::unwrap_with(g4, hmine);
    check("MAC/sign: unwrapped with the HMAC key", e4 == kmip::OK && r4 == 0 && u4.material[..] == unhex("00112233445566778899aabbccddeeff0011223344556677")[..]);
    var bad = copy(g4);
    bad.material[bad.material.len - 1] ^= 1;
    let u5, r5 = kmip::unwrap_with(bad, hmine);
    check("MAC/sign: a changed Key Value refused", r5 == kmip::REASON_CRYPTOGRAPHIC_FAILURE);
    // RSA-OAEP with the public key; the client unwraps with the private.
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_RSA);
    kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 2048);
    let uu = usage_only(kmip::USAGE_UNWRAP_KEY);
    let uw = usage_only(kmip::USAGE_WRAP_KEY);
    let pv, pb, ek = kmip::create_key_pair(c, common, uu, uw);
    var wr = kmip::wrapping(kmip::WRAP_ENCRYPT);
    kmip::wrap_encrypt_key(wr, pb);
    let g6, e6 = kmip::get_wrapped(c, target, wr);
    let privo, epo = kmip::get(c, pv, 0);
    let u6, r6 = kmip::unwrap_with(g6, privo);
    check("RSA-OAEP wrapping, unwrapped with the private key", e6 == kmip::OK && epo == kmip::OK && r6 == 0 &&
          u6.material[..] == unhex("00112233445566778899aabbccddeeff0011223344556677")[..]);
    // A key without Wrap Key does not wrap.
    let plain_key = register_key(c, kmip::ALG_AES, kek_bytes, kmip::USAGE_ENCRYPT);
    var wn = kmip::wrapping(kmip::WRAP_ENCRYPT);
    kmip::wrap_encrypt_key(wn, plain_key);
    let g7, e7 = kmip::get_wrapped(c, target, wn);
    check("no Wrap Key usage: refused", e7 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK, c.version));

    // Sensitive and Extractable.
    var sa = key_attrs(kmip::ALG_AES, 128, kmip::USAGE_ENCRYPT);
    kmip::attr_bool(sa, kmip::TAG_SENSITIVE, true);
    let su, es = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, sa);
    let s1, es1 = kmip::get(c, su, 0);
    check("a sensitive key is not given in the clear", es == kmip::OK && es1 == kmip::ERR_FAILED && c.last_reason == kmip::REASON_SENSITIVE);
    let s2, es2 = kmip::get_wrapped(c, su, w);
    check("a sensitive key is given wrapped", es2 == kmip::OK && s2.wrapped);
    var xa = key_attrs(kmip::ALG_AES, 128, kmip::USAGE_ENCRYPT);
    kmip::attr_bool(xa, kmip::TAG_EXTRACTABLE, false);
    let xu, ex = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, xa);
    let x1, ex1 = kmip::get_wrapped(c, xu, w);
    check("an unextractable key is not given at all", ex1 == kmip::ERR_FAILED && c.last_reason == kmip::REASON_NOT_EXTRACTABLE);
    let tags: u32[2] = [kmip::TAG_NEVER_EXTRACTABLE, kmip::TAG_ALWAYS_SENSITIVE];
    let xs, exs = kmip::get_attributes(c, xu, tags);
    let ne, neok = kmip::get_bool(xs, kmip::TAG_NEVER_EXTRACTABLE);
    let al, alok = kmip::get_bool(xs, kmip::TAG_ALWAYS_SENSITIVE);
    check("Never Extractable true, Always Sensitive false", neok && ne && alok && !al);
}

// The Key Wrapping Data w says, on an object registered wrapped.
fn put_kwd(o: kmip::Object&, w: const kmip::Wrapping&) {
    var x = copy(w);
    x.enc.params = kmip::CryptoParams { mode: kmip::MODE_NIST_KEY_WRAP };
    x.enc.has_params = true;
    var kwd: u8[>..] = [];
    kmip::put_wrapping_data(kwd, x);
    o.wrapping.append(kwd);
}

fn export_import(c: kmip::Local&) {
    var a = key_attrs(kmip::ALG_AES, 128, kmip::USAGE_ENCRYPT);
    kmip::attr_name(a, "exported-key");
    let uid, e = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    let w = kmip::wrapping(0);
    let o, xa, ex = kmip::export_object(c, uid, 0, 0, w, false);
    let n = kmip::get_name(xa, 0);
    check("Export: the key and its attributes", ex == kmip::OK && n == "exported-key" && kmip::has_attr(xa, kmip::TAG_STATE));
    let iu, ei = kmip::import_object(c, "imported-1", o, xa, false, 0);
    check("Import under the identifier given", ei == kmip::OK && iu == "imported-1");
    let again, ea = kmip::import_object(c, "imported-1", o, xa, false, 0);
    check("Import over an object refused", ea == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_OBJECT_ALREADY_EXISTS, c.version));
    let rep, er = kmip::import_object(c, "imported-1", o, xa, true, 0);
    check("Import with Replace Existing", er == kmip::OK);
    check("the imported key's material", material_of(c, "imported-1")[..] == o.material[..]);
}

// PGP keys (2.0): kept as they came, given back so, used for nothing.
fn pgp_keys(c: kmip::Local&) {
    let armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot a real key\n-----END PGP PUBLIC KEY BLOCK-----\n";
    let k = kmip::pgp_key(4, kmip::ALG_RSA, 2048, armored);
    let a = key_attrs(kmip::ALG_RSA, 2048, kmip::USAGE_VERIFY);
    let uid, e = kmip::register(c, k, a);
    check("Register a PGP Key", e == kmip::OK);
    let o, eg = kmip::get(c, uid, 0);
    check("Get it back as it came", eg == kmip::OK && o.obj_type == kmip::OBJ_PGP_KEY && o.sub_type == 4 &&
          o.key_format == kmip::FMT_RAW && o.alg == kmip::ALG_RSA && o.length == 2048 && o.material[..] == armored);
    let p1, ep = kmip::get(c, uid, kmip::FMT_PKCS_1);
    check("not in another format", ep == kmip::ERR_FAILED);
    let sg, es = kmip::sign(c, uid, kmip::CryptoParams { .. }, "data");
    check("no cryptography with it", es == kmip::ERR_FAILED);
}

fn rekeying(c: kmip::Local&) {
    var a = key_attrs(kmip::ALG_AES, 256, kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    kmip::attr_name(a, "rotated");
    let old, e = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    let ea = kmip::activate(c, old);
    let none = kmip::attrs();
    let nu, er = kmip::rekey(c, old, 0, none);
    check("Re-key", e == kmip::OK && er == kmip::OK && nu[..] != old[..]);
    check("Re-key: links both ways", linked(c, old, kmip::LINK_REPLACEMENT_OBJECT, nu) && linked(c, nu, kmip::LINK_REPLACED_OBJECT, old));
    let tags: u32[1] = [kmip::TAG_NAME];
    let na, ena = kmip::get_attributes(c, nu, tags);
    let oa, eoa = kmip::get_attributes(c, old, tags);
    let nn = kmip::get_name(na, 0);
    check("Re-key: the name moved", nn == "rotated" && !kmip::has_attr(oa, kmip::TAG_NAME));
    check("Re-key with Offset 0: Active", state_of(c, nu) == kmip::STATE_ACTIVE);
    check("Re-key: a new key", material_of(c, nu).len == 32 && material_of(c, nu)[..] != material_of(c, old)[..]);
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
    kmip::attr_curve(common, kmip::CURVE_P_256);
    var pa = usage_only(kmip::USAGE_SIGN);
    kmip::attr_name(pa, "pair");
    let uv = usage_only(kmip::USAGE_VERIFY);
    let pv, pb, ep = kmip::create_key_pair(c, common, pa, uv);
    let nv, nb, erp = kmip::rekey_key_pair(c, pv, -1, none, none, none);
    check("Re-key Key Pair", ep == kmip::OK && erp == kmip::OK);
    check("Re-key Key Pair: links", linked(c, pv, kmip::LINK_REPLACEMENT_OBJECT, nv) && linked(c, nb, kmip::LINK_REPLACED_OBJECT, pb) &&
          linked(c, nv, kmip::LINK_PUBLIC_KEY, nb));
    let pn, epn = kmip::get_attributes(c, nv, tags);
    let pnn = kmip::get_name(pn, 0);
    check("Re-key Key Pair: the name moved", pnn == "pair");
}

fn deriving(c: kmip::Local&) {
    let base = register_key(c, kmip::ALG_AES, unhex("00112233445566778899aabbccddeeff"), kmip::USAGE_ENCRYPT | kmip::USAGE_DERIVE_KEY);
    // The OASIS test cases' answers (TC-DERIVEKEY-1, 2 and 3).
    var d = kmip::derivation(kmip::DERIVE_HASH);
    d.params = kmip::CryptoParams { hash: kmip::HASH_SHA_256 };
    d.has_params = true;
    check("HASH (TC-DERIVEKEY-1)", derived(c, one(base), d, 128)[..] == unhex("a8faed6abbf35c12a4b26e40f6feb19d")[..]);
    var h = kmip::derivation(kmip::DERIVE_HMAC);
    h.data.append(unhex("0102"));
    check("HMAC (TC-DERIVEKEY-2)", derived(c, one(base), h, 128)[..] == unhex("1e15c1f1da233629f770fb0a04a5020e")[..]);
    let pw = register_secret(c, "password", kmip::USAGE_DERIVE_KEY);
    var p = kmip::derivation(kmip::DERIVE_PBKDF2);
    p.salt.append("salt");
    p.iterations = 1;
    check("PBKDF2 (TC-DERIVEKEY-3, RFC 6070 1)", derived(c, one(pw), p, 128)[..] == unhex("0c60c80f961f0e71f3a9b524af601206")[..]);
    p.iterations = 4096;
    check("PBKDF2 (RFC 6070 3)", derived(c, one(pw), p, 160)[..] == unhex("4b007901b765489abead49d926f721d065a429c1")[..]);
    // RFC 5869 A.1.
    var ikm: u8[>..] = [];
    for k in 22 { ikm.push(0x0b); }
    let hb = register_secret(c, ikm, kmip::USAGE_DERIVE_KEY);
    var hk = kmip::derivation(kmip::DERIVE_HKDF);
    hk.salt.append(unhex("000102030405060708090a0b0c"));
    hk.data.append(unhex("f0f1f2f3f4f5f6f7f8f9"));
    check("HKDF (RFC 5869 A.1)", derived(c, one(hb), hk, 336)[..] ==
          unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")[..]);
    // SP 800-108 with HMAC-SHA-256, as Python's hmac computes them.
    var sc = kmip::derivation(kmip::DERIVE_NIST800_108_C);
    sc.data.append("label");
    sc.data.push(0);
    sc.data.append("context");
    check("SP 800-108 counter", derived(c, one(base), sc, 512)[..] ==
          unhex("3f179a39d08b31fa51202fe2a8632221dfbaaef85ffd9ed7773643b9c193522644cc59d5aadcb46fc2074b8caf3f432338287fde0cae6c898de233dae21d76c1")[..]);
    sc.method = kmip::DERIVE_NIST800_108_F;
    check("SP 800-108 feedback", derived(c, one(base), sc, 512)[..] ==
          unhex("3f179a39d08b31fa51202fe2a8632221dfbaaef85ffd9ed7773643b9c1935226ece8da7ce8b4a389dcfc5f1854760fb20703bedce23c054d84b5dc11b117dfb5")[..]);
    sc.method = kmip::DERIVE_NIST800_108_DPI;
    check("SP 800-108 double pipeline", derived(c, one(base), sc, 512)[..] ==
          unhex("f136c27d4cafd0a68fdf25a9d310eae03695cd976f31b27e2112d323c35bb09193810519ccd3ea38dfa43523573a57028abeb889fcac15624bce985914a7ba08")[..]);
    var big = kmip::derivation(kmip::DERIVE_HASH);
    big.params = kmip::CryptoParams { hash: kmip::HASH_SHA_256 };
    big.has_params = true;
    let toolong = derived(c, one(base), big, 512);
    check("longer than the hash: refused", toolong.len == 0 && c.last_reason == kmip::REASON_INVALID_FIELD);
    let nodrv = register_key(c, kmip::ALG_AES, unhex("00112233445566778899aabbccddeeff"), kmip::USAGE_ENCRYPT);
    let nd = derived(c, one(nodrv), d, 128);
    check("no Derive Key usage: refused", nd.len == 0 && c.last_reason == kmip::reason_for(kmip::REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK, c.version));
    // ECDH, both ways round.
    var ecc = kmip::attrs();
    kmip::attr_enum(ecc, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
    kmip::attr_curve(ecc, kmip::CURVE_P_256);
    kmip::attr_datetime(ecc, kmip::TAG_ACTIVATION_DATE, kmip::now_of(c.srv) - 3600);
    let ud = usage_only(kmip::USAGE_DERIVE_KEY);
    let av, ab, e1 = kmip::create_key_pair(c, ecc, ud, ud);
    let bv, bb, e2 = kmip::create_key_pair(c, ecc, ud, ud);
    let ecdh = kmip::derivation(kmip::DERIVE_ASYMMETRIC_KEY);
    let k1 = derived(c, two(av, bb), ecdh, 256);
    let k2 = derived(c, two(bv, ab), ecdh, 256);
    check("ECDH: both sides derive one key", k1.len == 32 && k1[..] == k2[..]);
    // TC-DERIVEKEY-6: the same on secp256k1.
    var kc = kmip::attrs();
    kmip::attr_enum(kc, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
    kmip::attr_curve(kc, kmip::CURVE_SECP256K1);
    kmip::attr_datetime(kc, kmip::TAG_ACTIVATION_DATE, kmip::now_of(c.srv) - 3600);
    let cv, cb, e3 = kmip::create_key_pair(c, kc, ud, ud);
    let dv, db, e4 = kmip::create_key_pair(c, kc, ud, ud);
    let k3 = derived(c, two(cv, db), ecdh, 256);
    let k4 = derived(c, two(dv, cb), ecdh, 256);
    check("ECDH on secp256k1", e3 == kmip::OK && e4 == kmip::OK && k3.len == 32 && k3[..] == k4[..]);
}

fn usage_and_lifecycle(c: kmip::Local&) {
    var a = key_attrs(kmip::ALG_AES, 128, kmip::USAGE_ENCRYPT);
    var lim: u8[>..] = [];
    let s = kmip::begin(lim, kmip::TAG_USAGE_LIMITS);
    kmip::put_long(lim, kmip::TAG_USAGE_LIMITS_TOTAL, 10);
    kmip::put_long(lim, kmip::TAG_USAGE_LIMITS_COUNT, 10);
    kmip::put_enum(lim, kmip::TAG_USAGE_LIMITS_UNIT, kmip::LIMITS_OBJECT);
    kmip::end(lim, s);
    kmip::attr_raw(a, lim);
    let uid, e = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    check("Check: Encrypt allowed", kmip::check(c, uid, kmip::USAGE_ENCRYPT, -1, -1) == kmip::OK);
    check("Check: Decrypt not", kmip::check(c, uid, kmip::USAGE_DECRYPT, -1, -1) == kmip::ERR_FAILED &&
          c.last_reason == kmip::reason_for(kmip::REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK, c.version));
    check("Check: 10 uses there", kmip::check(c, uid, -1, 10, -1) == kmip::OK);
    check("Get Usage Allocation 4", kmip::get_usage_allocation(c, uid, 4) == kmip::OK);
    check("Get Usage Allocation 7 of 6 left", kmip::get_usage_allocation(c, uid, 7) == kmip::ERR_FAILED && c.last_reason == kmip::REASON_USAGE_LIMIT_EXCEEDED);
    check("Get Usage Allocation 6", kmip::get_usage_allocation(c, uid, 6) == kmip::OK);
    check("Check: none left", kmip::check(c, uid, -1, 1, -1) == kmip::ERR_FAILED);
    let lease, changed, el = kmip::obtain_lease(c, uid);
    check("Obtain Lease: the server's hour", el == kmip::OK && lease == 3600 && changed > 0);
    check("Archive", kmip::archive(c, uid) == kmip::OK);
    let g, eg = kmip::get(c, uid, 0);
    check("an archived key is not got", eg == kmip::ERR_FAILED && c.last_reason == kmip::REASON_OBJECT_ARCHIVED);
    let tags: u32[1] = [kmip::TAG_ARCHIVE_DATE];
    let aa, eaa = kmip::get_attributes(c, uid, tags);
    check("an archived key's attributes are read; its Archive Date", eaa == kmip::OK && kmip::has_attr(aa, kmip::TAG_ARCHIVE_DATE));
    check("Recover", kmip::recover(c, uid) == kmip::OK);
    let g2, eg2 = kmip::get(c, uid, 0);
    check("a recovered key is got", eg2 == kmip::OK);
    var by: u8[>..] = [];
    kmip::put_int(by, kmip::TAG_ADJUSTMENT_VALUE, kmip::USAGE_DECRYPT as! i32);
    check("Adjust Attribute: the usage mask incremented", kmip::adjust_attribute(c, uid, kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK, kmip::ADJUST_INCREMENT, by) == kmip::OK);
    check("Check: Decrypt now allowed", kmip::check(c, uid, kmip::USAGE_DECRYPT, -1, -1) == kmip::OK);
    check("Adjust Attribute: the state refused", kmip::adjust_attribute(c, uid, kmip::TAG_STATE, kmip::ADJUST_INCREMENT, by) == kmip::ERR_FAILED);
    check("Interop Begin and End", kmip::interop(c, kmip::INTEROP_BEGIN, "TC-1") == kmip::OK && kmip::interop(c, kmip::INTEROP_END, "TC-1") == kmip::OK);
    // A key active from a date: Pre-Active until then.
    var fa = key_attrs(kmip::ALG_AES, 128, kmip::USAGE_ENCRYPT);
    kmip::attr_datetime(fa, kmip::TAG_ACTIVATION_DATE, kmip::now_of(c.srv) + 3600);
    let fu, ef = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, fa);
    check("an Activation Date to come: Pre-Active", state_of(c, fu) == kmip::STATE_PRE_ACTIVE);
    c.srv.now = kmip::now_of(c.srv) + 7200;
    check("once it has come: Active", state_of(c, fu) == kmip::STATE_ACTIVE);
    c.srv.now = 0;
}

fn cryptography(c: kmip::Local&) {
    let none: u8[0] = [];
    let hk = register_key(c, kmip::ALG_HMAC_SHA256, unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), kmip::USAGE_MAC_GENERATE | kmip::USAGE_MAC_VERIFY);
    let cp = kmip::CryptoParams { .. };
    let m, em = kmip::mac(c, hk, cp, "Hi There");
    check("HMAC-SHA-256 (RFC 4231 1)", em == kmip::OK && m[..] == unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")[..]);
    let ok1, ev1 = kmip::mac_verify(c, hk, cp, "Hi There", m);
    let ok2, ev2 = kmip::mac_verify(c, hk, cp, "Hi There!", m);
    check("MAC Verify: valid, then invalid", ev1 == kmip::OK && ok1 && ev2 == kmip::OK && !ok2);
    let ak = register_key(c, kmip::ALG_AES, unhex("2b7e151628aed2a6abf7158809cf4f3c"), kmip::USAGE_MAC_GENERATE);
    let cm, ec = kmip::mac(c, ak, kmip::CryptoParams { mode: kmip::MODE_CMAC }, unhex("6bc1bee22e409f96e93d7e117393172a"));
    check("AES-CMAC (SP 800-38B D.1 example 2)", ec == kmip::OK && cm[..] == unhex("070a16b46b4d4144f79bdd9dd04a287c")[..]);
    let d, eh = kmip::hash(c, kmip::HASH_SHA_256, "abc");
    check("Hash SHA-256 of abc", eh == kmip::OK && d[..] == unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")[..]);
    let used, es = kmip::rng_seed(c, "some seed");
    check("RNG Seed: taken, none used", es == kmip::OK && used == 0);
    // ChaCha20 (RFC 8439 2.4.2's first block from a zero key and nonce, as
    // CS-BC-M-CHACHA20-1 has it with an 8-byte nonce).
    let ck = register_key(c, kmip::ALG_CHACHA20, unhex("0000000000000000000000000000000000000000000000000000000000000000"),
                          kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    var zeros: u8[>..] = [];
    zeros.resize(64, 0);
    let s, ech = kmip::encrypt(c, ck, cp, zeros, unhex("0000000000000000"), none);
    check("ChaCha20, an 8-byte nonce", ech == kmip::OK && s.data[..] == unhex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")[..]);
    // ChaCha20-Poly1305 (RFC 8439 2.8.2).
    let pk = register_key(c, kmip::ALG_CHACHA20_POLY1305, unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
                          kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    let msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let aead = kmip::CryptoParams { mode: kmip::MODE_AEAD, tag_length: 16 };
    let sp, ep = kmip::encrypt(c, pk, aead, msg, unhex("070000004041424344454647"), unhex("50515253c0c1c2c3c4c5c6c7"));
    check("ChaCha20-Poly1305: RFC 8439's tag", ep == kmip::OK && sp.tag[..] == unhex("1ae10b594f09e26a7e902ecbd0600691")[..]);
    let op, eop = kmip::decrypt(c, pk, aead, sp.data, unhex("070000004041424344454647"), unhex("50515253c0c1c2c3c4c5c6c7"), sp.tag);
    check("ChaCha20-Poly1305 back", eop == kmip::OK && op[..] == msg);
    // Triple DES, CBC.
    let tk = register_key(c, kmip::ALG_TRIPLE_DES, unhex("0123456789abcdef23456789abcdef01456789abcdef0123"), kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    let t1, et1 = kmip::encrypt(c, tk, kmip::CryptoParams { mode: kmip::MODE_CBC, padding: kmip::PAD_PKCS5 }, "triple DES text", unhex("0001020304050607"), none);
    let t2, et2 = kmip::decrypt(c, tk, kmip::CryptoParams { mode: kmip::MODE_CBC, padding: kmip::PAD_PKCS5 }, t1.data, unhex("0001020304050607"), none, none);
    check("Triple DES CBC both ways", et1 == kmip::OK && et2 == kmip::OK && t2[..] == "triple DES text" && t1.data.len == 16);
}

fn in_parts(c: kmip::Local&) {
    let none: u8[0] = [];
    let k = register_key(c, kmip::ALG_AES, unhex("000102030405060708090a0b0c0d0e0f"), kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    let cbc = kmip::CryptoParams { mode: kmip::MODE_CBC, padding: kmip::PAD_PKCS5 };
    let iv = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let text = "forty bytes of text in three unequal parts";
    let whole, ew = kmip::encrypt(c, k, cbc, text, iv, none);
    let p1, e1 = kmip::part(c, kmip::OP_ENCRYPT, k, cbc, text[..7], iv, none, false, none);
    let p2, e2 = kmip::part(c, kmip::OP_ENCRYPT, k, cbc, text[7..30], none, p1.corr, false, none);
    let p3, e3 = kmip::part(c, kmip::OP_ENCRYPT, k, cbc, text[30..], none, p2.corr, true, none);
    var joined: u8[>..] = [];
    joined.append(p1.data);
    joined.append(p2.data);
    joined.append(p3.data);
    check("CBC in parts: whole blocks as they come", e1 == kmip::OK && e2 == kmip::OK && e3 == kmip::OK && p1.data.len == 0 && p2.data.len == 16);
    check("CBC in parts: as in one", ew == kmip::OK && joined[..] == whole.data[..] && p3.corr.len == 0);
    let q1, f1 = kmip::part(c, kmip::OP_DECRYPT, k, cbc, whole.data[..16], iv, none, false, none);
    let q2, f2 = kmip::part(c, kmip::OP_DECRYPT, k, cbc, whole.data[16..], none, q1.corr, true, none);
    var back: u8[>..] = [];
    back.append(q1.data);
    back.append(q2.data);
    check("CBC decrypted in parts", f1 == kmip::OK && f2 == kmip::OK && back[..] == text);
    // GCM encrypts each part as it comes, the tag at the Final part; it
    // decrypts nothing before the tag is checked. CTR, both ways, as it comes.
    let gcm = kmip::CryptoParams { mode: kmip::MODE_GCM, tag_length: 16 };
    let nonce = unhex("cafebabefacedbaddecaf888");
    let gw, egw = kmip::encrypt(c, k, gcm, text, nonce, none);
    let g1, eg1 = kmip::part(c, kmip::OP_ENCRYPT, k, gcm, text[..7], nonce, none, false, none);
    let g2, eg2 = kmip::part(c, kmip::OP_ENCRYPT, k, gcm, text[7..], none, g1.corr, true, none);
    var gj: u8[>..] = [];
    gj.append(g1.data);
    gj.append(g2.data);
    check("GCM in parts: each part's data as it comes", egw == kmip::OK && eg1 == kmip::OK && eg2 == kmip::OK && g1.data.len == 7 && g1.tag.len == 0);
    check("GCM in parts: as in one, the tag at the end", gj[..] == gw.data[..] && g2.tag[..] == gw.tag[..]);
    let d1, ed1 = kmip::part(c, kmip::OP_DECRYPT, k, gcm, gw.data[..20], nonce, none, false, gw.tag);
    let d2, ed2 = kmip::part(c, kmip::OP_DECRYPT, k, gcm, gw.data[20..], none, d1.corr, true, none);
    check("GCM decrypted in parts: nothing before the tag", ed1 == kmip::OK && ed2 == kmip::OK && d1.data.len == 0 && d2.data[..] == text);
    let ctr = kmip::CryptoParams { mode: kmip::MODE_CTR };
    let cw, ecw = kmip::encrypt(c, k, ctr, text, iv, none);
    let c1, ec1 = kmip::part(c, kmip::OP_DECRYPT, k, ctr, cw.data[..5], iv, none, false, none);
    let c2, ec2 = kmip::part(c, kmip::OP_DECRYPT, k, ctr, cw.data[5..], none, c1.corr, true, none);
    check("CTR decrypted in parts as it comes", ecw == kmip::OK && ec1 == kmip::OK && ec2 == kmip::OK && c1.data[..] == text[..5] && c2.data[..] == text[5..]);
    let h1, g1 = kmip::part(c, kmip::OP_HASH, none, kmip::CryptoParams { hash: kmip::HASH_SHA_256 }, "a", none, none, false, none);
    let h2, g2 = kmip::part(c, kmip::OP_HASH, none, kmip::CryptoParams { hash: kmip::HASH_SHA_256 }, "bc", none, h1.corr, true, none);
    check("Hash in parts", g1 == kmip::OK && g2 == kmip::OK && h2.data[..] == unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")[..]);
    let bogus, eb = kmip::part(c, kmip::OP_HASH, none, kmip::CryptoParams { hash: kmip::HASH_SHA_256 }, "x", none, h1.corr, true, none);
    check("a Correlation Value used up", eb == kmip::ERR_FAILED && c.last_reason == kmip::REASON_INVALID_CORRELATION_VALUE);
    var common = kmip::attrs();
    kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
    kmip::attr_curve(common, kmip::CURVE_P_256);
    kmip::attr_datetime(common, kmip::TAG_ACTIVATION_DATE, kmip::now_of(c.srv) - 60);
    let us = usage_only(kmip::USAGE_SIGN);
    let uv = usage_only(kmip::USAGE_VERIFY);
    let pv, pb, ep = kmip::create_key_pair(c, common, us, uv);
    let es = kmip::CryptoParams { sig: kmip::SIG_ECDSA_WITH_SHA256 };
    let s1, se1 = kmip::part(c, kmip::OP_SIGN, pv, es, "signed in ", none, none, false, none);
    let s2, se2 = kmip::part(c, kmip::OP_SIGN, pv, es, "two parts", none, s1.corr, true, none);
    let good, ev = kmip::verify(c, pb, es, "signed in two parts", s2.data);
    check("Sign in parts, verified whole", se1 == kmip::OK && se2 == kmip::OK && ev == kmip::OK && good);
    let v1, ve1 = kmip::part(c, kmip::OP_SIGNATURE_VERIFY, pb, es, "signed in two ", none, none, false, none);
    let v2, ve2 = kmip::part(c, kmip::OP_SIGNATURE_VERIFY, pb, es, "parts", none, v1.corr, true, s2.data);
    check("Signature Verify in parts", ve1 == kmip::OK && ve2 == kmip::OK && v2.validity == kmip::VALIDITY_VALID);
    let digest = bignum::hash_bits(256, "signed in two parts");
    let ds, eds = kmip::sign_digest(c, pv, es, digest);
    let dv, edv = kmip::verify_digest(c, pb, es, digest, ds);
    check("Sign and Signature Verify on a digest", eds == kmip::OK && edv == kmip::OK && dv);
}

fn batches(c: kmip::Local&) {
    let k = register_key(c, kmip::ALG_AES, unhex("000102030405060708090a0b0c0d0e0f"), kmip::USAGE_ENCRYPT);
    var a = kmip::attrs();
    kmip::attr_usage(a, kmip::USAGE_ENCRYPT);
    let ko = kmip::symmetric_key(kmip::ALG_AES, unhex("000102030405060708090a0b0c0d0e0f"));
    let pre, e = kmip::register(c, ko, a);
    // BL-M-2: Activate, then a Check that fails, with Undo.
    var out: u8[>..] = [];
    let m = kmip::begin(out, kmip::TAG_REQUEST_MESSAGE);
    let h = kmip::begin(out, kmip::TAG_REQUEST_HEADER);
    kmip::put_version(out, kmip::V2_0);
    kmip::put_enum(out, kmip::TAG_BATCH_ERROR_CONTINUATION_OPTION, kmip::BATCH_UNDO);
    kmip::put_int(out, kmip::TAG_BATCH_COUNT, 2);
    kmip::end(out, h);
    let i1, p1 = kmip::begin_item(out, kmip::OP_ACTIVATE, "1");
    kmip::put_text(out, kmip::TAG_UNIQUE_IDENTIFIER, pre);
    kmip::end_item(out, i1, p1);
    let i2, p2 = kmip::begin_item(out, kmip::OP_CHECK, "2");
    kmip::put_text(out, kmip::TAG_UNIQUE_IDENTIFIER, pre);
    kmip::put_int(out, kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK, kmip::USAGE_DECRYPT as! i32);
    kmip::end_item(out, i2, p2);
    kmip::end(out, m);
    var resp: u8[>..] = [];
    let ee = kmip::exchange(c, out, resp);
    let st = statuses(resp);
    check("Undo: the Activate undone, the Check failed", st.len == 2 && st[0] == kmip::STATUS_OPERATION_UNDONE && st[1] == kmip::STATUS_OPERATION_FAILED);
    check("Undo: the key still Pre-Active", state_of(c, pre) == kmip::STATE_PRE_ACTIVE);
    // The ID Placeholder: Create, then Activate and Get with no identifier.
    var out2: u8[>..] = [];
    let cred = kmip::no_credential();
    let m2 = kmip::begin_request(out2, kmip::V2_0, 3, cred);
    let j1, q1 = kmip::begin_item(out2, kmip::OP_CREATE, "");
    kmip::put_enum(out2, kmip::TAG_OBJECT_TYPE, kmip::OBJ_SYMMETRIC_KEY);
    let ka = key_attrs(kmip::ALG_AES, 128, kmip::USAGE_ENCRYPT);
    kmip::put_template(out2, ka, kmip::V2_0, kmip::TAG_TEMPLATE_ATTRIBUTE, kmip::TAG_ATTRIBUTES);
    kmip::end_item(out2, j1, q1);
    let j2, q2 = kmip::begin_item(out2, kmip::OP_ACTIVATE, "");
    kmip::end_item(out2, j2, q2);
    let j3, q3 = kmip::begin_item(out2, kmip::OP_GET, "");
    kmip::end_item(out2, j3, q3);
    kmip::end(out2, m2);
    var resp2: u8[>..] = [];
    let e2 = kmip::exchange(c, out2, resp2);
    let st2 = statuses(resp2);
    check("the ID Placeholder carries Create's key to Activate and Get", st2.len == 3 && st2[0] == 0 && st2[1] == 0 && st2[2] == 0);
}

fn main() {
    var c = kmip::local("alice");
    c.version = kmip::V2_0;
    formats(c);
    wrapping(c);
    export_import(c);
    pgp_keys(c);
    rekeying(c);
    deriving(c);
    usage_and_lifecycle(c);
    cryptography(c);
    in_parts(c);
    batches(c);
    // 1.x forms of the same: Template-Attributes and Attribute names.
    var c1 = kmip::local("alice");
    c1.version = kmip::V1_4;
    wrapping(c1);
    export_import(c1);
    rekeying(c1);
    deriving(c1);
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
