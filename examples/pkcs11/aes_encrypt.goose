// aes_encrypt: encryption with an AES key that stays on the token: AES-GCM
// with a nonce from the token's random generator (and a changed byte
// refused), AES-CBC with padding fed in pieces as a stream would be, and
// a second key wrapped (exported encrypted under the first) and unwrapped
// again, as keys are moved between tokens.
//
//   goose examples/pkcs11/aes_encrypt.goose -- [MODULE [PIN]]
//
// MODULE and PIN default to $P11_MODULE and $P11_PIN; the token is the
// one labelled $P11_LABEL, else the first initialized one. The keys are
// session objects: they go when the session closes. token_info.goose says
// how to make a throwaway SoftHSM2 token.

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
    guard rv == pkcs11::CKR_OK else { print("aes_encrypt: ", what, ": ", pkcs11::error_text(rv)); exit(1); }
}

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
    print("aes_encrypt: no initialized token");
    exit(1);
}

// An AES key of n bytes made by the token: it may encrypt, decrypt, wrap
// and unwrap, and be wrapped (extractable) though never read in clear.
fn aes_key(c: pkcs11::Ctx, sh: u64, n: u64, label: const u8[:]) -> u64 {
    var t: u8[>..] = [];
    pkcs11::attr(t, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(t, pkcs11::CKA_VALUE_LEN, n);
    pkcs11::attr(t, pkcs11::CKA_LABEL, label);
    pkcs11::attr(t, pkcs11::CKA_SENSITIVE, true);
    pkcs11::attr(t, pkcs11::CKA_EXTRACTABLE, true);
    for a in [pkcs11::CKA_ENCRYPT, pkcs11::CKA_DECRYPT, pkcs11::CKA_WRAP, pkcs11::CKA_UNWRAP] { pkcs11::attr(t, a, true); }
    let k, rv = pkcs11::generate_key(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_KEY_GEN), t);
    check("C_GenerateKey", rv);
    return k;
}

fn main() {
    let path = arg_or_env(1, "P11_MODULE");
    let pin = arg_or_env(2, "P11_PIN");
    guard path.len > 0 && pin.len > 0 else { print("usage: aes_encrypt MODULE PIN (or set P11_MODULE, P11_PIN)"); exit(2); }
    var err: u8[>..] = [];
    var c, ok = pkcs11::new(path, err);
    guard ok else { print("aes_encrypt: ", err); exit(1); }
    check("C_Initialize", pkcs11::initialize(c));
    let sh, rs = pkcs11::open_session(c, token_slot(c), pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION);
    check("C_OpenSession", rs);
    check("C_Login", pkcs11::login(c, sh, pkcs11::CKU_USER, pin));
    let key = aes_key(c, sh, 32, "example AES-256");
    let secret = "The meeting is moved to Thursday at 10.";

    // GCM: a fresh 12-byte nonce for each message; the 16-byte tag is
    // appended to the ciphertext.
    let nonce, rn = pkcs11::generate_random(c, sh, 12);
    check("C_GenerateRandom", rn);
    let gcm = pkcs11::mechanism_gcm(pkcs11::CKM_AES_GCM, nonce, "header v1", 128);
    check("C_EncryptInit", pkcs11::encrypt_init(c, sh, gcm, key));
    let sealed, re = pkcs11::encrypt(c, sh, secret);
    check("C_Encrypt", re);
    check("C_DecryptInit", pkcs11::decrypt_init(c, sh, gcm, key));
    let opened, rd = pkcs11::decrypt(c, sh, sealed);
    check("C_Decrypt", rd);
    guard opened == secret else { print("aes_encrypt: GCM round trip failed"); exit(1); }
    var bad: u8[>..] = [];
    bad.append(sealed);
    bad[3] ^= 1;
    pkcs11::decrypt_init(c, sh, gcm, key);
    let nothing, rbad = pkcs11::decrypt(c, sh, bad);
    guard rbad != pkcs11::CKR_OK else { print("aes_encrypt: a changed GCM ciphertext accepted"); exit(1); }
    print("AES-GCM: ", secret.len, " bytes sealed into ", sealed.len, ", opened; a changed byte: ", pkcs11::ckr_name(rbad));

    // CBC with PKCS #7 padding, in pieces: update for each, final for the
    // padded last block.
    let iv, ri = pkcs11::generate_random(c, sh, 16);
    check("C_GenerateRandom", ri);
    let cbc = pkcs11::mechanism(pkcs11::CKM_AES_CBC_PAD, iv);
    check("C_EncryptInit", pkcs11::encrypt_init(c, sh, cbc, key));
    var ct: u8[>..] = [];
    var at = 0;
    while at < secret.len {
        let n = min(7, secret.len - at);
        let part, rp = pkcs11::encrypt_update(c, sh, secret[at..at + n]);
        check("C_EncryptUpdate", rp);
        ct.append(part);
        at += n;
    }
    let last, rl = pkcs11::encrypt_final(c, sh);
    check("C_EncryptFinal", rl);
    ct.append(last);
    pkcs11::decrypt_init(c, sh, cbc, key);
    let pt, rpt = pkcs11::decrypt(c, sh, ct);
    guard rpt == pkcs11::CKR_OK && pt == secret else { print("aes_encrypt: CBC round trip failed"); exit(1); }
    print("AES-CBC-PAD: encrypted in pieces of 7 bytes into ", ct.len, ", decrypted in one");

    // Key wrap: a second key leaves the token only encrypted under the
    // first, and comes back as a new key that decrypts what the old one
    // encrypted.
    let inner = aes_key(c, sh, 16, "example AES-128");
    let wrapped, rw = pkcs11::wrap_key(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_KEY_WRAP), key, inner);
    check("C_WrapKey", rw);
    var ut: u8[>..] = [];
    pkcs11::attr(ut, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
    pkcs11::attr(ut, pkcs11::CKA_KEY_TYPE, pkcs11::CKK_AES);
    pkcs11::attr(ut, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(ut, pkcs11::CKA_DECRYPT, true);
    let back, ru = pkcs11::unwrap_key(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_KEY_WRAP), key, wrapped, ut);
    check("C_UnwrapKey", ru);
    let ecb = pkcs11::mechanism(pkcs11::CKM_AES_ECB);
    pkcs11::encrypt_init(c, sh, ecb, inner);
    let one_block, rb = pkcs11::encrypt(c, sh, "sixteen bytes!!!");
    check("C_Encrypt", rb);
    pkcs11::decrypt_init(c, sh, ecb, back);
    let again, rg = pkcs11::decrypt(c, sh, one_block);
    guard rg == pkcs11::CKR_OK && again == "sixteen bytes!!!" else { print("aes_encrypt: the unwrapped key differs"); exit(1); }
    print("AES Key Wrap: a 16-byte key wrapped into ", wrapped.len, " bytes, unwrapped, and it decrypts");

    pkcs11::logout(c, sh);
    pkcs11::close_session(c, sh);
    pkcs11::finalize(c);
    pkcs11::destroy(c);
}
