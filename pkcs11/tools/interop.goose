// The Goose side of scripts/interop.py: keys made, data signed and
// signatures verified on a token through pkcs11, for OpenSC's pkcs11-tool
// and OpenSSL to check, and to check theirs. The token is $P11_MODULE's
// token labelled $P11_LABEL, logged in with $P11_PIN.
//
//   goose tools/interop.goose -- keys
//   goose tools/interop.goose -- sign LABEL MECH IN OUT
//   goose tools/interop.goose -- verify LABEL MECH IN SIG
//
// MECH is RSA-SHA256, RSA-PSS-SHA256, ECDSA (over a digest), ECDSA-SHA256
// or EDDSA, as pkcs11-tool names them. `keys` makes RSA, P-256 and Ed25519
// key pairs (IDs 10, 11, 12) and an AES key (13). Exit status 0 when it
// went well.
import std;
import os;
import gslib from "../..";
import gslib.pkcs11;
import gslib.pkcs11.p11;

fn getenv(name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    if !env(name, v) { abort(str(name, " is not set")); }
    return v;
}

fn mechanism(name: const u8[:]) -> u8[>..] {
    if name == "RSA-SHA256" { return pkcs11::mechanism(pkcs11::CKM_SHA256_RSA_PKCS); }
    if name == "RSA-PSS-SHA256" {
        return pkcs11::mechanism_pss(pkcs11::CKM_SHA256_RSA_PKCS_PSS, pkcs11::CKM_SHA256, pkcs11::CKG_MGF1_SHA256, 32);
    }
    if name == "ECDSA-SHA256" { return pkcs11::mechanism(pkcs11::CKM_ECDSA_SHA256); }
    if name == "ECDSA" { return pkcs11::mechanism(pkcs11::CKM_ECDSA); }
    if name == "EDDSA" { return pkcs11::mechanism(pkcs11::CKM_EDDSA); }
    abort(str("unknown mechanism ", name));
}

fn check(what: const u8[:], rv: u64) {
    if rv != pkcs11::CKR_OK {
        print(what, ": ", p11::error_text(rv));
        exit(1);
    }
}

// A key pair on the token, labelled and given an ID, as pkcs11-tool's
// --keypairgen makes them.
fn pair(s: p11::Session, gen: u64, label: const u8[:], id: const u8[:], params: const u8[:]) {
    var pubt: u8[>..] = [];
    pkcs11::attr(pubt, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(pubt, pkcs11::CKA_VERIFY, true);
    pkcs11::attr(pubt, pkcs11::CKA_LABEL, label);
    pkcs11::attr(pubt, pkcs11::CKA_ID, id);
    var privt: u8[>..] = [];
    pkcs11::attr(privt, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(privt, pkcs11::CKA_PRIVATE, true);
    pkcs11::attr(privt, pkcs11::CKA_SIGN, true);
    pkcs11::attr(privt, pkcs11::CKA_LABEL, label);
    pkcs11::attr(privt, pkcs11::CKA_ID, id);
    if gen == pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN {
        pkcs11::attr(pubt, pkcs11::CKA_MODULUS_BITS, 2048);
        pkcs11::attr(pubt, pkcs11::CKA_PUBLIC_EXPONENT, "\x01\x00\x01");
    } else {
        pkcs11::attr(pubt, pkcs11::CKA_EC_PARAMS, params);
    }
    let kp, rv = p11::generate_key_pair(s, pkcs11::mechanism(gen), pubt, privt);
    check(str("key pair ", label), rv);
}

fn main() {
    var a: u8[][>..] = [];
    var first = true;
    for x in args() {
        if !first { a.push(str(x)); }
        first = false;
    }
    var words: const u8[:][>..] = [];
    for x in a { words.push(x); }
    if words.len == 0 { abort("usage: keys | sign LABEL MECH IN OUT | verify LABEL MECH IN SIG"); }

    var m, rm = p11::open_module(getenv("P11_MODULE"));
    check("module", rm);
    let slots, rs = p11::slots(m);
    check("slots", rs);
    var slot = slots[0];
    for &x in slots {
        let t, r = p11::token_info(x);
        if t.label[..] == getenv("P11_LABEL")[..] { slot = x; }
    }
    var s, ro = p11::open_write_session(slot);
    check("session", ro);
    check("login", p11::login(s, getenv("P11_PIN")));

    let cmd = words[0];
    if cmd == "keys" {
        pair(s, pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN, "goose-rsa", "\x10", "");
        pair(s, pkcs11::CKM_EC_KEY_PAIR_GEN, "goose-ec", "\x11", pkcs11::EC_PARAMS_P256);
        pair(s, pkcs11::CKM_EC_EDWARDS_KEY_PAIR_GEN, "goose-ed", "\x12", pkcs11::EC_PARAMS_ED25519);
        var st: u8[>..] = [];
        pkcs11::attr(st, pkcs11::CKA_TOKEN, true);
        pkcs11::attr(st, pkcs11::CKA_LABEL, "goose-aes");
        pkcs11::attr(st, pkcs11::CKA_ID, "\x13");
        pkcs11::attr(st, pkcs11::CKA_VALUE_LEN, 32);
        pkcs11::attr(st, pkcs11::CKA_ENCRYPT, true);
        pkcs11::attr(st, pkcs11::CKA_DECRYPT, true);
        let k, rk = p11::generate_key(s, pkcs11::mechanism(pkcs11::CKM_AES_KEY_GEN), st);
        check("AES key", rk);
        print("keys made");

    } else if cmd == "sign" && words.len == 5 {
        let key, rk = p11::find_private_key(s, words[1]);
        check(str("private key ", words[1]), rk);
        var data: u8[>..] = [];
        if !read_file(words[3], data) { abort(str("cannot read ", words[3])); }
        let sig, rsig = p11::sign(key, mechanism(words[2]), data);
        check("sign", rsig);
        if !write_file(words[4], sig) { abort(str("cannot write ", words[4])); }
        print("signed, ", sig.len, " bytes");
    } else if cmd == "verify" && words.len == 5 {
        let key, rk = p11::find_public_key(s, words[1]);
        check(str("public key ", words[1]), rk);
        var data: u8[>..] = [];
        var sig: u8[>..] = [];
        if !read_file(words[3], data) || !read_file(words[4], sig) { abort("cannot read the files"); }
        check("verify", p11::verify(key, mechanism(words[2]), data, sig));
        print("signature is valid");
    } else {
        abort("usage: keys | sign LABEL MECH IN OUT | verify LABEL MECH IN SIG");
    }
    p11::logout(s);
    p11::close(s);
    p11::destroy(m);
}
