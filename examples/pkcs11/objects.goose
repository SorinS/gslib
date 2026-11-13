// objects: logs in to a token and works with its objects: lists what is
// there, stores two data objects, finds them again by label and by class
// with templates (in batches, as C_FindObjects returns them), reads
// several attributes at once, renames one, copies it, and destroys what
// it made.
//
//   goose examples/pkcs11/objects.goose -- [MODULE [PIN]]
//
// MODULE and PIN default to $P11_MODULE and $P11_PIN; the token is the
// one labelled $P11_LABEL, else the first initialized one. token_info.goose
// says how to make a throwaway SoftHSM2 token.

import std;
import os;
import gslib from "../..";
import gslib.pkcs11;

fn arg_or_env(i: i64, name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    let a = args();
    if a.len > i { v.append(a[i]); } else { env(name, v); }
    return v;
}

fn check(what: const u8[:], rv: u64) {
    guard rv == pkcs11::CKR_OK else { print("objects: ", what, ": ", pkcs11::error_text(rv)); exit(1); }
}

// The slot of the token to use.
fn token_slot(c: pkcs11::Ctx) -> u64 {
    var want: u8[>..] = [];
    env("P11_LABEL", want);
    let slots, rv = pkcs11::get_slot_list(c, true);
    check("C_GetSlotList", rv);
    for s in slots {
        let t, rt = pkcs11::get_token_info(c, s);
        if rt != pkcs11::CKR_OK || t.flags & pkcs11::CKF_TOKEN_INITIALIZED == 0 { continue; }
        if want.len == 0 || t.label[..] == want[..] { return s; }
    }
    print("objects: no initialized token");
    exit(1);
}

// The handles a template matches, at most 2 per C_FindObjects call.
fn find(c: pkcs11::Ctx, sh: u64, t: const u8[:]) -> u64[>..] {
    var out: u64[>..] = [];
    check("C_FindObjectsInit", pkcs11::find_objects_init(c, sh, t));
    loop {
        let batch, rv = pkcs11::find_objects(c, sh, 2);
        check("C_FindObjects", rv);
        if batch.len == 0 { break; }
        out.append(batch);
    }
    check("C_FindObjectsFinal", pkcs11::find_objects_final(c, sh));
    return out;
}

fn data_object(label: const u8[:], value: const u8[:]) -> u8[>..] {
    var t: u8[>..] = [];
    pkcs11::attr(t, pkcs11::CKA_CLASS, pkcs11::CKO_DATA);
    pkcs11::attr(t, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(t, pkcs11::CKA_PRIVATE, true);
    pkcs11::attr(t, pkcs11::CKA_APPLICATION, "gslib example");
    pkcs11::attr(t, pkcs11::CKA_LABEL, label);
    pkcs11::attr(t, pkcs11::CKA_VALUE, value);
    return t;
}

fn main() {
    let path = arg_or_env(1, "P11_MODULE");
    let pin = arg_or_env(2, "P11_PIN");
    guard path.len > 0 && pin.len > 0 else { print("usage: objects MODULE PIN (or set P11_MODULE, P11_PIN)"); exit(2); }
    var err: u8[>..] = [];
    var c, ok = pkcs11::new(path, err);
    guard ok else { print("objects: ", err); exit(1); }
    check("C_Initialize", pkcs11::initialize(c));
    let sh, rs = pkcs11::open_session(c, token_slot(c), pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION);
    check("C_OpenSession", rs);
    check("C_Login", pkcs11::login(c, sh, pkcs11::CKU_USER, pin));

    // Everything on the token: an empty template matches every object.
    let all = find(c, sh, "");
    print(all.len, " objects on the token");
    let show: u64[2] = [pkcs11::CKA_CLASS, pkcs11::CKA_LABEL];
    for h in all {
        let a, ra = pkcs11::get_attribute_value(c, sh, h, show);
        let cls, okc = pkcs11::attr_value(a, pkcs11::CKA_CLASS);
        let lab, okl = pkcs11::attr_value(a, pkcs11::CKA_LABEL);
        print("  ", h, ": ", if okc { pkcs11::cko_name(pkcs11::as_ulong(cls)) } else { "?" }, " \"", lab, "\"");
    }

    // Two data objects, then found by label and by class.
    let one, r1 = pkcs11::create_object(c, sh, data_object("example: greeting", "hello"));
    check("C_CreateObject", r1);
    let two, r2 = pkcs11::create_object(c, sh, data_object("example: farewell", "goodbye"));
    check("C_CreateObject", r2);
    var by_label: u8[>..] = [];
    pkcs11::attr(by_label, pkcs11::CKA_LABEL, "example: farewell");
    let found = find(c, sh, by_label);
    guard found.len == 1 && found[0] == two else { print("objects: not found by label"); exit(1); }
    var by_class: u8[>..] = [];
    pkcs11::attr(by_class, pkcs11::CKA_CLASS, pkcs11::CKO_DATA);
    pkcs11::attr(by_class, pkcs11::CKA_APPLICATION, "gslib example");
    let mine = find(c, sh, by_class);
    print(mine.len, " data objects of this example");
    guard mine.len == 2 else { print("objects: not found by class"); exit(1); }

    // Several attributes in one call; an object's size.
    let types: u64[3] = [pkcs11::CKA_LABEL, pkcs11::CKA_VALUE, pkcs11::CKA_PRIVATE];
    let attrs, ra = pkcs11::get_attribute_value(c, sh, one, types);
    check("C_GetAttributeValue", ra);
    let lab, okl = pkcs11::attr_value(attrs, pkcs11::CKA_LABEL);
    let val, okv = pkcs11::attr_value(attrs, pkcs11::CKA_VALUE);
    let priv, okp = pkcs11::attr_value(attrs, pkcs11::CKA_PRIVATE);
    print("\"", lab, "\" = \"", val, "\", private: ", pkcs11::as_bool(priv));
    guard okv && val == "hello" else { print("objects: wrong value"); exit(1); }
    let size, rz = pkcs11::get_object_size(c, sh, one);
    // (CK_UNAVAILABLE_INFORMATION, all ones, when the module does not say.)
    if rz == pkcs11::CKR_OK && size != pkcs11::UNAVAILABLE { print("its size on the token: ", size, " bytes"); }

    // Renamed, and copied under another label.
    var rename: u8[>..] = [];
    pkcs11::attr(rename, pkcs11::CKA_LABEL, "example: hello");
    check("C_SetAttributeValue", pkcs11::set_attribute_value(c, sh, one, rename));
    var copy_t: u8[>..] = [];
    pkcs11::attr(copy_t, pkcs11::CKA_LABEL, "example: copy");
    let three, rc = pkcs11::copy_object(c, sh, one, copy_t);
    check("C_CopyObject", rc);
    let cv, rcv = pkcs11::get_attribute_value(c, sh, three, types);
    let copied, okcp = pkcs11::attr_value(cv, pkcs11::CKA_VALUE);
    guard okcp && copied == "hello" else { print("objects: the copy lost its value"); exit(1); }

    // Clean up: the token is as it was.
    for h in [one, two, three] { check("C_DestroyObject", pkcs11::destroy_object(c, sh, h)); }
    guard find(c, sh, by_class).len == 0 else { print("objects: not all destroyed"); exit(1); }
    print("created, found, changed, copied and destroyed 3 objects");
    pkcs11::logout(c, sh);
    pkcs11::close_session(c, sh);
    pkcs11::finalize(c);
    pkcs11::destroy(c);
}
