// token_info: loads a PKCS#11 module and lists what it has: the library's
// information, each slot and its token (label, model, serial, PIN sizes,
// flags), and the mechanisms the token does with their key sizes, as
// `pkcs11-tool --list-slots --list-mechanisms` would.
//
//   goose examples/pkcs11/token_info.goose -- [MODULE]
//
// MODULE defaults to $P11_MODULE. A throwaway SoftHSM2 token to try it on:
//
//   mkdir -p /tmp/p11/tokens && echo "directories.tokendir = /tmp/p11/tokens" > /tmp/p11/softhsm2.conf
//   export SOFTHSM2_CONF=/tmp/p11/softhsm2.conf
//   softhsm2-util --init-token --free --label example --so-pin 12345678 --pin 1234
//   export P11_MODULE=$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so   # or /usr/lib/softhsm/libsofthsm2.so

import std;
import os;
import gslib from "../..";
import gslib.pkcs11;

fn module_path() -> u8[>..] {
    var p: u8[>..] = [];
    let a = args();
    if a.len > 1 { p.append(a[1]); } else { env("P11_MODULE", p); }
    return p;
}

fn flag(out: u8[>..]&, flags: u64, f: u64, name: const u8[:]) {
    if flags & f != 0 { out.append(" "); out.append(name); }
}

fn main() {
    let path = module_path();
    guard path.len > 0 else { print("usage: token_info MODULE (or set P11_MODULE)"); exit(2); }
    var err: u8[>..] = [];
    var c, ok = pkcs11::new(path, err);
    guard ok else { print("token_info: ", err); exit(1); }
    let rv = pkcs11::initialize(c);
    guard rv == pkcs11::CKR_OK else { print("token_info: ", pkcs11::error_text(rv)); exit(1); }

    let info, ri = pkcs11::get_info(c);
    guard ri == pkcs11::CKR_OK else { print("token_info: ", pkcs11::error_text(ri)); exit(1); }
    print(info.manufacturer_id, " ", info.library_description, " ", info.library_version,
          " (Cryptoki ", info.cryptoki_version, ")");

    // Every slot, and the token in it if there is one.
    let slots, rs = pkcs11::get_slot_list(c, false);
    guard rs == pkcs11::CKR_OK else { print("token_info: ", pkcs11::error_text(rs)); exit(1); }
    var shown = 0;
    for s in slots {
        let si, rsi = pkcs11::get_slot_info(c, s);
        print("slot ", s, ": ", si.slot_description);
        if si.flags & pkcs11::CKF_TOKEN_PRESENT == 0 { print("  no token"); continue; }
        let t, rt = pkcs11::get_token_info(c, s);
        if rt != pkcs11::CKR_OK { print("  ", pkcs11::error_text(rt)); continue; }
        var flags: u8[>..] = [];
        flag(flags, t.flags, pkcs11::CKF_TOKEN_INITIALIZED, "initialized");
        flag(flags, t.flags, pkcs11::CKF_USER_PIN_INITIALIZED, "user-PIN-set");
        flag(flags, t.flags, pkcs11::CKF_LOGIN_REQUIRED, "login-required");
        flag(flags, t.flags, pkcs11::CKF_RNG, "rng");
        flag(flags, t.flags, pkcs11::CKF_WRITE_PROTECTED, "read-only");
        print("  token \"", t.label, "\", ", t.manufacturer_id, " ", t.model, ", serial ", t.serial_number);
        print("  PIN ", t.min_pin_len, "..", t.max_pin_len, " characters; flags:", flags);
        if t.flags & pkcs11::CKF_TOKEN_INITIALIZED == 0 { continue; }

        // The mechanisms, with key sizes for some that generate keys.
        let mechs, rm = pkcs11::get_mechanism_list(c, s);
        guard rm == pkcs11::CKR_OK else { print("token_info: ", pkcs11::error_text(rm)); exit(1); }
        print("  ", mechs.len, " mechanisms, among them:");
        for m in [pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN, pkcs11::CKM_EC_KEY_PAIR_GEN, pkcs11::CKM_AES_KEY_GEN,
                  pkcs11::CKM_AES_GCM, pkcs11::CKM_ECDSA_SHA256, pkcs11::CKM_SHA256_RSA_PKCS_PSS] {
            var has = false;
            for x in mechs { if x == m { has = true; } }
            if !has { continue; }
            let mi, rmi = pkcs11::get_mechanism_info(c, s, m);
            var what: u8[>..] = [];
            flag(what, mi.flags, pkcs11::CKF_GENERATE_KEY_PAIR, "generate-key-pair");
            flag(what, mi.flags, pkcs11::CKF_GENERATE, "generate");
            flag(what, mi.flags, pkcs11::CKF_ENCRYPT, "encrypt");
            flag(what, mi.flags, pkcs11::CKF_SIGN, "sign");
            flag(what, mi.flags, pkcs11::CKF_VERIFY, "verify");
            print("    ", pkcs11::ckm_name(m), ": keys ", mi.min_key_size, "..", mi.max_key_size, ";", what);
        }
        shown++;
    }
    guard shown > 0 else { print("token_info: no initialized token"); exit(1); }
    pkcs11::finalize(c);
    pkcs11::destroy(c);
}
