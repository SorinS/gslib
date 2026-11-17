// Every operation path of pkcs11 dispatched through p11.c's tables at least
// once: signatures and verification in parts (equal to the one-part MAC,
// a changed byte refused), decryption in parts, a CK_ULONG parameter
// (HMAC_GENERAL's length), CCM and EdDSA parameters; and the calls SoftHSM
// may not do (recovery, the dual-function updates, operation state, slot
// events, the legacy function status), which must reach the module, so
// that whatever it answers is a CKR_ and not pkcs11's ERR_ENCODING.
import std;
import gslib from "../..";
import gslib.pkcs11;
import gslib.crypto.bignum;
import gslib.crypto.bignum.hmac;
import gslib.entropy;
import hsm;
import tv;

fn random(n: i64) -> u8[>..] {
    var b: u8[>..] = [];
    b.resize(n, 0);
    entropy::random_bytes(b);
    return b;
}

fn key(c: pkcs11::Ctx, sh: u64, kind: u64, value: const u8[:]) -> u64 {
    var t: u8[>..] = [];
    pkcs11::attr(t, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
    pkcs11::attr(t, pkcs11::CKA_KEY_TYPE, kind);
    pkcs11::attr(t, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(t, pkcs11::CKA_VALUE, value);
    if kind == pkcs11::CKK_AES {
        pkcs11::attr(t, pkcs11::CKA_ENCRYPT, true);
        pkcs11::attr(t, pkcs11::CKA_DECRYPT, true);
    } else {
        pkcs11::attr(t, pkcs11::CKA_SIGN, true);
        pkcs11::attr(t, pkcs11::CKA_VERIFY, true);
    }
    let h, rv = pkcs11::create_object(c, sh, t);
    hsm::ok("key", rv);
    return h;
}

// The call reached the module: its answer is a CKR_, not ERR_ENCODING.
fn reached(what: const u8[:], rv: u64) {
    tv::check(str(what, " reached the module: ", pkcs11::error_text(rv)), rv != pkcs11::ERR_ENCODING
              && rv != pkcs11::ERR_NO_MODULE && rv < 0x100000000);
}

fn main() {
    let c = hsm::open();
    let sh = hsm::session(c);
    let data = random(300);

    // HMAC in parts equals the one-part MAC; verified in parts.
    let hk = random(32);
    let hkey = key(c, sh, pkcs11::CKK_GENERIC_SECRET, hk);
    let want = bignum::hmac(256, hk, data);
    hsm::ok("sign init", pkcs11::sign_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256_HMAC), hkey));
    hsm::ok("sign update", pkcs11::sign_update(c, sh, data[..100]));
    hsm::ok("sign update 2", pkcs11::sign_update(c, sh, data[100..]));
    let mac, rf = pkcs11::sign_final(c, sh);
    tv::check("HMAC in parts is bignum's", rf == pkcs11::CKR_OK && mac == want);
    hsm::ok("verify init", pkcs11::verify_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256_HMAC), hkey));
    hsm::ok("verify update", pkcs11::verify_update(c, sh, data[..7]));
    hsm::ok("verify update 2", pkcs11::verify_update(c, sh, data[7..]));
    hsm::ok("verify final", pkcs11::verify_final(c, sh, mac));
    var bad: u8[>..] = [];
    bad.append(mac);
    bad[31] = bad[31] ^ 1;
    pkcs11::verify_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256_HMAC), hkey);
    pkcs11::verify_update(c, sh, data);
    hsm::check_rv("verify final, changed byte", pkcs11::verify_final(c, sh, bad), pkcs11::CKR_SIGNATURE_INVALID);

    // A CK_ULONG parameter: HMAC_GENERAL cut to 16 bytes, checked where the
    // module does it (SoftHSM does not: CKR_MECHANISM_INVALID).
    let ri = pkcs11::sign_init(c, sh, pkcs11::mechanism_ulong(pkcs11::CKM_SHA256_HMAC_GENERAL, 16), hkey);
    reached("HMAC_GENERAL init", ri);
    if ri == pkcs11::CKR_OK {
        let short, rs = pkcs11::sign(c, sh, data);
        tv::check("HMAC_GENERAL of 16 bytes", rs == pkcs11::CKR_OK && short[..] == want[..16]);
    }

    // CBC decrypted in parts.
    let ak = random(16);
    let akey = key(c, sh, pkcs11::CKK_AES, ak);
    let iv = random(16);
    pkcs11::encrypt_init(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_CBC_PAD, iv), akey);
    let ct, re = pkcs11::encrypt(c, sh, data);
    hsm::ok("decrypt init", pkcs11::decrypt_init(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_CBC_PAD, iv), akey));
    var pt: u8[>..] = [];
    let p1, r1 = pkcs11::decrypt_update(c, sh, ct[..50]);
    pt.append(p1);
    let p2, r2 = pkcs11::decrypt_update(c, sh, ct[50..]);
    pt.append(p2);
    let p3, r3 = pkcs11::decrypt_final(c, sh);
    pt.append(p3);
    tv::check("CBC decrypted in parts", re == pkcs11::CKR_OK && r1 == pkcs11::CKR_OK && r2 == pkcs11::CKR_OK
              && r3 == pkcs11::CKR_OK && pt == data);

    // CCM's and EdDSA's parameters reach the module.
    reached("AES-CCM init", pkcs11::encrypt_init(c, sh,
            pkcs11::mechanism_ccm(pkcs11::CKM_AES_CCM, data.len as u64, random(12), "aad", 16), akey));
    pkcs11::encrypt(c, sh, data);
    reached("EdDSA parameters", pkcs11::sign_init(c, sh, pkcs11::mechanism_eddsa(pkcs11::CKM_EDDSA, false, "ctx"), akey));

    // Recovery, the dual-function updates, operation state, slot events.
    reached("sign recover init", pkcs11::sign_recover_init(c, sh, pkcs11::mechanism(pkcs11::CKM_RSA_X_509), akey));
    let x1, rx1 = pkcs11::sign_recover(c, sh, data);
    reached("sign recover", rx1);
    reached("verify recover init", pkcs11::verify_recover_init(c, sh, pkcs11::mechanism(pkcs11::CKM_RSA_X_509), akey));
    let x2, rx2 = pkcs11::verify_recover(c, sh, data);
    reached("verify recover", rx2);
    let x3, rx3 = pkcs11::digest_encrypt_update(c, sh, data);
    reached("digest encrypt update", rx3);
    let x4, rx4 = pkcs11::decrypt_digest_update(c, sh, data);
    reached("decrypt digest update", rx4);
    let x5, rx5 = pkcs11::sign_encrypt_update(c, sh, data);
    reached("sign encrypt update", rx5);
    let x6, rx6 = pkcs11::decrypt_verify_update(c, sh, data);
    reached("decrypt verify update", rx6);
    pkcs11::digest_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256));
    pkcs11::digest_update(c, sh, data[..10]);
    let state, rst = pkcs11::get_operation_state(c, sh);
    reached("get operation state", rst);
    if rst == pkcs11::CKR_OK { reached("set operation state", pkcs11::set_operation_state(c, sh, state, 0, 0)); }
    reached("digest key", pkcs11::digest_key(c, sh, akey));
    let slot, rw = pkcs11::wait_for_slot_event(c, pkcs11::CKF_DONT_BLOCK);
    reached("wait for slot event", rw);
    reached("get function status", pkcs11::get_function_status(c, sh));
    reached("cancel function", pkcs11::cancel_function(c, sh));

    pkcs11::logout(c, sh);
    pkcs11::close_session(c, sh);
    pkcs11::finalize(c);
    tv::done("operations");
}
