// pkcs11's objects against SoftHSM2: data objects created, found by label
// and class, their attributes read (several at once, one the object does
// not have) and changed, copied with a changed attribute, sized and
// destroyed; a secret key whose value is sensitive, read with its other
// attributes (C_GetAttributeValue's CKR_ATTRIBUTE_SENSITIVE with the rest
// given); searches in batches; and p11's find_object and its errors.
import std;
import gslib from "../..";
import gslib.pkcs11;
import gslib.pkcs11.p11;
import hsm;
import tv;

fn data_object(label: const u8[:], value: const u8[:]) -> u8[>..] {
    var t: u8[>..] = [];
    pkcs11::attr(t, pkcs11::CKA_CLASS, pkcs11::CKO_DATA);
    pkcs11::attr(t, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(t, pkcs11::CKA_LABEL, label);
    pkcs11::attr(t, pkcs11::CKA_APPLICATION, "gslib tests");
    pkcs11::attr(t, pkcs11::CKA_VALUE, value);
    return t;
}

fn main() {
    let c = hsm::open();
    let sh = hsm::session(c);

    let o1, r1 = pkcs11::create_object(c, sh, data_object("first", "hello"));
    hsm::ok("create", r1);
    let o2, r2 = pkcs11::create_object(c, sh, data_object("second", "world"));
    hsm::ok("create another", r2);
    tv::check("distinct handles", o1 != o2 && o1 != 0);

    let types: u64[4] = [pkcs11::CKA_LABEL, pkcs11::CKA_VALUE, pkcs11::CKA_CLASS, pkcs11::CKA_TOKEN];
    let attrs, ra = pkcs11::get_attribute_value(c, sh, o1, types);
    hsm::ok("get attributes", ra);
    let lab, okl = pkcs11::attr_value(attrs, pkcs11::CKA_LABEL);
    let val, okv = pkcs11::attr_value(attrs, pkcs11::CKA_VALUE);
    let cls, okc = pkcs11::attr_value(attrs, pkcs11::CKA_CLASS);
    let tok, okt = pkcs11::attr_value(attrs, pkcs11::CKA_TOKEN);
    tv::check("label", okl && lab == "first");
    tv::check("value", okv && val == "hello");
    tv::check("class", okc && pkcs11::as_ulong(cls) == pkcs11::CKO_DATA);
    tv::check("token object", okt && pkcs11::as_bool(tok));

    // An attribute a data object does not have: the others still come.
    let mixed: u64[2] = [pkcs11::CKA_MODULUS, pkcs11::CKA_LABEL];
    let am, ram = pkcs11::get_attribute_value(c, sh, o1, mixed);
    hsm::check_rv("an attribute the object lacks", ram, pkcs11::CKR_ATTRIBUTE_TYPE_INVALID);
    let mod, okm = pkcs11::attr_value(am, pkcs11::CKA_MODULUS);
    let lab2, okl2 = pkcs11::attr_value(am, pkcs11::CKA_LABEL);
    tv::check("the lacking one unavailable, the label there", !okm && okl2 && lab2 == "first");

    // Changed, then read again.
    var change: u8[>..] = [];
    pkcs11::attr(change, pkcs11::CKA_LABEL, "renamed");
    hsm::ok("set attribute", pkcs11::set_attribute_value(c, sh, o1, change));
    let o1p = p11::Object { ctx: c, session: sh, handle: o1 };
    let newlab, rnl = p11::label(o1p);
    tv::check("renamed", rnl == pkcs11::CKR_OK && newlab == "renamed");

    // Found by label, then by class (in batches of one).
    var ft: u8[>..] = [];
    pkcs11::attr(ft, pkcs11::CKA_LABEL, "second");
    hsm::ok("find init", pkcs11::find_objects_init(c, sh, ft));
    let found, rf = pkcs11::find_objects(c, sh, 10);
    hsm::ok("find", rf);
    hsm::ok("find final", pkcs11::find_objects_final(c, sh));
    tv::check("found by label", found.len == 1 && found[0] == o2);
    var ct: u8[>..] = [];
    pkcs11::attr(ct, pkcs11::CKA_CLASS, pkcs11::CKO_DATA);
    pkcs11::find_objects_init(c, sh, ct);
    var count = 0;
    loop {
        let batch, rb = pkcs11::find_objects(c, sh, 1);
        if rb != pkcs11::CKR_OK || batch.len == 0 { break; }
        count += batch.len;
    }
    pkcs11::find_objects_final(c, sh);
    tv::check_int("found by class, one at a time", count, 2);

    // Copied with a new label; sized; destroyed.
    var cp: u8[>..] = [];
    pkcs11::attr(cp, pkcs11::CKA_LABEL, "copy");
    let o3, rc = pkcs11::copy_object(c, sh, o2, cp);
    hsm::ok("copy", rc);
    let cv, rcv = p11::value(p11::Object { ctx: c, session: sh, handle: o3 });
    tv::check("copy keeps the value", rcv == pkcs11::CKR_OK && cv == "world");
    let size, rsz = pkcs11::get_object_size(c, sh, o3);
    tv::check("object size", rsz == pkcs11::CKR_OK && size > 0);
    hsm::ok("destroy", pkcs11::destroy_object(c, sh, o3));
    let gone, rg = pkcs11::get_attribute_value(c, sh, o3, types);
    hsm::check_rv("destroyed object", rg, pkcs11::CKR_OBJECT_HANDLE_INVALID);

    // A secret key whose value is sensitive.
    var kt: u8[>..] = [];
    pkcs11::attr(kt, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
    pkcs11::attr(kt, pkcs11::CKA_KEY_TYPE, pkcs11::CKK_AES);
    pkcs11::attr(kt, pkcs11::CKA_VALUE_LEN, 16);
    pkcs11::attr(kt, pkcs11::CKA_SENSITIVE, true);
    pkcs11::attr(kt, pkcs11::CKA_LABEL, "sensitive");
    pkcs11::attr(kt, pkcs11::CKA_ID, "\x01\x02");
    let key, rk = pkcs11::generate_key(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_KEY_GEN), kt);
    hsm::ok("generate AES key", rk);
    let kts: u64[3] = [pkcs11::CKA_VALUE, pkcs11::CKA_VALUE_LEN, pkcs11::CKA_ID];
    let ka, rka = pkcs11::get_attribute_value(c, sh, key, kts);
    hsm::check_rv("sensitive value", rka, pkcs11::CKR_ATTRIBUTE_SENSITIVE);
    let kv, okkv = pkcs11::attr_value(ka, pkcs11::CKA_VALUE);
    let kl, okkl = pkcs11::attr_value(ka, pkcs11::CKA_VALUE_LEN);
    let kid, okid = pkcs11::attr_value(ka, pkcs11::CKA_ID);
    tv::check("value withheld, the rest given", !okkv && okkl && pkcs11::as_ulong(kl) == 16 && okid && kid == "\x01\x02");

    // p11: one object, none, too many.
    let s = p11::Session { ctx: c, slot: hsm::slot(c), handle: sh };
    let sk, rsk = p11::find_secret_key(s, "sensitive");
    tv::check("p11 find_secret_key", rsk == pkcs11::CKR_OK && sk.object.handle == key);
    let nk, rnk = p11::find_secret_key(s, "no such key");
    hsm::check_rv("p11 none", rnk, p11::ERR_NO_OBJECT);
    var dt: u8[>..] = [];
    pkcs11::attr(dt, pkcs11::CKA_CLASS, pkcs11::CKO_DATA);
    let many, rmany = p11::find_object(s, dt);
    hsm::check_rv("p11 several", rmany, p11::ERR_MULTIPLE_OBJECTS);
    let alls, ralls = p11::find_objects(s, dt);
    tv::check("p11 find_objects", ralls == pkcs11::CKR_OK && alls.len == 2);
    tv::check_eq("p11 error text", p11::error_text(p11::ERR_NO_OBJECT), "p11: no objects found");
    let made, rmade = p11::create_object(s, data_object("p11", "made by p11"));
    hsm::ok("p11 create", rmade);
    hsm::ok("p11 set", p11::set(made, pkcs11::CKA_LABEL, "p11 renamed"));
    let ml, rml = p11::label(made);
    tv::check("p11 label", rml == pkcs11::CKR_OK && ml == "p11 renamed");
    let cop, rcop = p11::copy_object(made, "");
    hsm::ok("p11 copy", rcop);
    hsm::ok("p11 destroy", p11::destroy(cop));

    pkcs11::logout(c, sh);
    pkcs11::close_session(c, sh);
    pkcs11::finalize(c);
    tv::done("objects");
}
