// p11_keys: the same work through pkcs11.p11, the layer of Module, Slot,
// Session and Object that miekg's p11 is: a signing key pair kept on the
// token under a label, found again by that label and used to sign and
// verify; an AES key found by label to encrypt and decrypt; two EC keys
// agreeing on a secret by ECDH; and a data object read, changed and
// destroyed. What it stores it removes at the end.
//
//   goose examples/pkcs11/p11_keys.goose -- [MODULE [PIN]]
//
// MODULE and PIN default to $P11_MODULE and $P11_PIN; the token is the
// one labelled $P11_LABEL, else the first initialized one. token_info.goose
// says how to make a throwaway SoftHSM2 token.

import std;
import os;
import gslib from "../..";
import gslib.pkcs11;
import gslib.pkcs11.p11;

fn arg_or_env(i: i64, name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    let a = args();
    if a.len > i { v.append(a[i]); } else { env(name, v); }
    return v;
}

fn check(what: const u8[:], rv: u64) {
    guard rv == pkcs11::CKR_OK else { print("p11_keys: ", what, ": ", p11::error_text(rv)); exit(1); }
}

// A P-256 key pair under a label, kept on the token (CKA_TOKEN).
fn ec_pair(s: p11::Session, label: const u8[:], derive: bool) -> p11::KeyPair {
    var pubt: u8[>..] = [];
    pkcs11::attr(pubt, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(pubt, pkcs11::CKA_LABEL, label);
    pkcs11::attr(pubt, pkcs11::CKA_VERIFY, true);
    pkcs11::attr(pubt, pkcs11::CKA_EC_PARAMS, pkcs11::EC_PARAMS_P256);
    var privt: u8[>..] = [];
    pkcs11::attr(privt, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(privt, pkcs11::CKA_LABEL, label);
    pkcs11::attr(privt, pkcs11::CKA_PRIVATE, true);
    pkcs11::attr(privt, pkcs11::CKA_SIGN, true);
    pkcs11::attr(privt, pkcs11::CKA_DERIVE, derive);
    let kp, rv = p11::generate_key_pair(s, pkcs11::mechanism(pkcs11::CKM_EC_KEY_PAIR_GEN), pubt, privt);
    check("generate_key_pair", rv);
    return kp;
}

fn main() {
    let path = arg_or_env(1, "P11_MODULE");
    let pin = arg_or_env(2, "P11_PIN");
    guard path.len > 0 && pin.len > 0 else { print("usage: p11_keys MODULE PIN (or set P11_MODULE, P11_PIN)"); exit(2); }
    var m, rm = p11::open_module(path);
    check("open_module", rm);
    let info, ri = p11::info(m);
    print("module: ", info.manufacturer_id, " ", info.library_description);

    // The token: by label, else the first initialized one.
    var want: u8[>..] = [];
    env("P11_LABEL", want);
    let slots, rs = p11::slots(m);
    check("slots", rs);
    var picked = -1;
    for i in slots.len {
        let t, rt = p11::token_info(slots[i]);
        if picked < 0 && rt == pkcs11::CKR_OK && t.flags & pkcs11::CKF_TOKEN_INITIALIZED != 0
           && (want.len == 0 || t.label[..] == want[..]) { picked = i; }
    }
    guard picked >= 0 else { print("p11_keys: no initialized token"); exit(1); }
    var s, ro = p11::open_write_session(slots[picked]);
    check("open_write_session", ro);
    check("login", p11::login(s, pin));

    // A signing key stored under a label; later (another program, say)
    // found by that label.
    ec_pair(s, "example signing key", false);
    let signer, rf = p11::find_private_key(s, "example signing key");
    check("find_private_key", rf);
    let checker, rf2 = p11::find_public_key(s, "example signing key");
    check("find_public_key", rf2);
    let ecdsa = pkcs11::mechanism(pkcs11::CKM_ECDSA_SHA256);
    let sig, rsg = p11::sign(signer, ecdsa, "release v1.2.3");
    check("sign", rsg);
    check("verify", p11::verify(checker, ecdsa, "release v1.2.3", sig));
    guard p11::verify(checker, ecdsa, "release v1.2.4", sig) == pkcs11::CKR_SIGNATURE_INVALID else {
        print("p11_keys: a signature over another message accepted");
        exit(1);
    }
    print("signed and verified with the key found by its label");

    // A key no one has: ERR_NO_OBJECT, p11's own error.
    let none, rnone = p11::find_private_key(s, "no such key");
    guard rnone == p11::ERR_NO_OBJECT else { print("p11_keys: found a key that is not there"); exit(1); }
    print("a missing key: ", p11::error_text(rnone));

    // A secret key, by label too.
    var kt: u8[>..] = [];
    pkcs11::attr(kt, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(kt, pkcs11::CKA_LABEL, "example data key");
    pkcs11::attr(kt, pkcs11::CKA_VALUE_LEN, 32);
    pkcs11::attr(kt, pkcs11::CKA_ENCRYPT, true);
    pkcs11::attr(kt, pkcs11::CKA_DECRYPT, true);
    p11::generate_key(s, pkcs11::mechanism(pkcs11::CKM_AES_KEY_GEN), kt);
    let dk, rdk = p11::find_secret_key(s, "example data key");
    check("find_secret_key", rdk);
    let nonce, rr = p11::generate_random(s, 12);
    check("generate_random", rr);
    let gcm = pkcs11::mechanism_gcm(pkcs11::CKM_AES_GCM, nonce, "", 128);
    let ct, re = p11::encrypt(dk, gcm, "the vault code is 2468");
    check("encrypt", re);
    let pt, rd = p11::decrypt(dk, gcm, ct);
    check("decrypt", rd);
    guard pt == "the vault code is 2468" else { print("p11_keys: AES round trip failed"); exit(1); }
    print("encrypted and decrypted with the AES key found by its label");

    // ECDH: each side's private key with the other's public point gives
    // the same secret.
    let alice = ec_pair(s, "example alice", true);
    let bob = ec_pair(s, "example bob", true);
    let ap, ra = p11::attribute(alice.public.object, pkcs11::CKA_EC_POINT);
    let bp, rb = p11::attribute(bob.public.object, pkcs11::CKA_EC_POINT);
    check("CKA_EC_POINT", if ra != pkcs11::CKR_OK { ra } else { rb });
    var dt: u8[>..] = [];
    pkcs11::attr(dt, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
    pkcs11::attr(dt, pkcs11::CKA_KEY_TYPE, pkcs11::CKK_GENERIC_SECRET);
    pkcs11::attr(dt, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(dt, pkcs11::CKA_SENSITIVE, false);
    pkcs11::attr(dt, pkcs11::CKA_EXTRACTABLE, true);
    pkcs11::attr(dt, pkcs11::CKA_VALUE_LEN, 32);
    let za, rza = p11::derive_value(alice.private, pkcs11::mechanism_ecdh1(pkcs11::CKM_ECDH1_DERIVE, pkcs11::CKD_NULL, "", pkcs11::ec_point(bp)), dt);
    let zb, rzb = p11::derive_value(bob.private, pkcs11::mechanism_ecdh1(pkcs11::CKM_ECDH1_DERIVE, pkcs11::CKD_NULL, "", pkcs11::ec_point(ap)), dt);
    check("derive", if rza != pkcs11::CKR_OK { rza } else { rzb });
    guard za == zb && za.len == 32 else { print("p11_keys: the ECDH secrets differ"); exit(1); }
    print("ECDH: both sides derived the same ", za.len, "-byte secret");

    // A data object: created, found by a template, renamed, read.
    var t: u8[>..] = [];
    pkcs11::attr(t, pkcs11::CKA_CLASS, pkcs11::CKO_DATA);
    pkcs11::attr(t, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(t, pkcs11::CKA_LABEL, "example config");
    pkcs11::attr(t, pkcs11::CKA_VALUE, "retries=3");
    p11::create_object(s, t);
    var ft: u8[>..] = [];
    pkcs11::attr(ft, pkcs11::CKA_LABEL, "example config");
    let obj, rob = p11::find_object(s, ft);
    check("find_object", rob);
    check("set", p11::set(obj, pkcs11::CKA_LABEL, "example settings"));
    let lab, rl = p11::label(obj);
    let val, rv = p11::value(obj);
    print("data object \"", lab, "\" = \"", val, "\"");
    guard lab == "example settings" && val == "retries=3" else { print("p11_keys: data object"); exit(1); }

    // Everything this example stored, removed.
    var removed = 0;
    for label in ["example signing key", "example data key", "example alice", "example bob", "example settings"] {
        var lt: u8[>..] = [];
        pkcs11::attr(lt, pkcs11::CKA_LABEL, label);
        let objs, rfo = p11::find_objects(s, lt);
        for o in objs { check("destroy", p11::destroy(o)); removed++; }
    }
    print(removed, " objects removed from the token");
    p11::logout(s);
    p11::close(s);
    p11::destroy(m);
}
