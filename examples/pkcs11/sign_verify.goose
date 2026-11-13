// sign_verify: key pairs made on the token, whose private halves never
// leave it: an RSA-2048 pair signing with PKCS #1 v1.5 and PSS, and a P-256
// pair signing with ECDSA. The token verifies each signature (and refuses
// it over another message); then the public keys are read out (the
// modulus, the EC point) and crypto/bignum verifies the same signatures,
// as a peer holding only the public key would.
//
//   goose examples/pkcs11/sign_verify.goose -- [MODULE [PIN]]
//
// MODULE and PIN default to $P11_MODULE and $P11_PIN; the token is the
// one labelled $P11_LABEL, else the first initialized one. The keys are
// session objects (CKA_TOKEN false): they go when the session closes.
// token_info.goose says how to make a throwaway SoftHSM2 token.

import std;
import os;
import gslib from "../..";
import gslib.pkcs11;
import gslib.crypto.bignum;
import gslib.crypto.bignum.rsa;
import gslib.crypto.bignum.ec;

fn arg_or_env(i: i64, name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    let a = args();
    if a.len > i { v.append(a[i]); } else { env(name, v); }
    return v;
}

fn check(what: const u8[:], rv: u64) {
    guard rv == pkcs11::CKR_OK else { print("sign_verify: ", what, ": ", pkcs11::error_text(rv)); exit(1); }
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
    print("sign_verify: no initialized token");
    exit(1);
}

// Signs msg with the private key, has the token verify it, and checks it
// refuses the signature over another message.
fn sign_on_token(c: pkcs11::Ctx, sh: u64, mech: const u8[:], priv: u64, pub: u64, msg: const u8[:]) -> u8[>..] {
    check("C_SignInit", pkcs11::sign_init(c, sh, mech, priv));
    let sig, rs = pkcs11::sign(c, sh, msg);
    check("C_Sign", rs);
    check("C_VerifyInit", pkcs11::verify_init(c, sh, mech, pub));
    check("C_Verify", pkcs11::verify(c, sh, msg, sig));
    pkcs11::verify_init(c, sh, mech, pub);
    guard pkcs11::verify(c, sh, "another message", sig) == pkcs11::CKR_SIGNATURE_INVALID else {
        print("sign_verify: a signature over another message accepted");
        exit(1);
    }
    return sig;
}

fn main() {
    let path = arg_or_env(1, "P11_MODULE");
    let pin = arg_or_env(2, "P11_PIN");
    guard path.len > 0 && pin.len > 0 else { print("usage: sign_verify MODULE PIN (or set P11_MODULE, P11_PIN)"); exit(2); }
    var err: u8[>..] = [];
    var c, ok = pkcs11::new(path, err);
    guard ok else { print("sign_verify: ", err); exit(1); }
    check("C_Initialize", pkcs11::initialize(c));
    let sh, rs = pkcs11::open_session(c, token_slot(c), pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION);
    check("C_OpenSession", rs);
    check("C_Login", pkcs11::login(c, sh, pkcs11::CKU_USER, pin));
    let msg = "pay 100 to example.com";

    // RSA: the public template says the size and exponent, the private one
    // what the key may do.
    var pubt: u8[>..] = [];
    pkcs11::attr(pubt, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(pubt, pkcs11::CKA_VERIFY, true);
    pkcs11::attr(pubt, pkcs11::CKA_MODULUS_BITS, 2048);
    pkcs11::attr(pubt, pkcs11::CKA_PUBLIC_EXPONENT, "\x01\x00\x01");
    var privt: u8[>..] = [];
    pkcs11::attr(privt, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(privt, pkcs11::CKA_PRIVATE, true);
    pkcs11::attr(privt, pkcs11::CKA_SENSITIVE, true);
    pkcs11::attr(privt, pkcs11::CKA_SIGN, true);
    let rpub, rpriv, rk = pkcs11::generate_key_pair(c, sh, pkcs11::mechanism(pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN), pubt, privt);
    check("RSA key pair", rk);
    let sig1 = sign_on_token(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256_RSA_PKCS), rpriv, rpub, msg);
    let pss = pkcs11::mechanism_pss(pkcs11::CKM_SHA256_RSA_PKCS_PSS, pkcs11::CKM_SHA256, pkcs11::CKG_MGF1_SHA256, 32);
    let sig2 = sign_on_token(c, sh, pss, rpriv, rpub, msg);
    print("RSA-2048: PKCS #1 v1.5 and PSS signatures (", sig1.len, " bytes) verified by the token");

    // The public key read out, and the signatures checked by bignum.
    let nt: u64[2] = [pkcs11::CKA_MODULUS, pkcs11::CKA_PUBLIC_EXPONENT];
    let a, ra = pkcs11::get_attribute_value(c, sh, rpub, nt);
    check("C_GetAttributeValue", ra);
    let n, okn = pkcs11::attr_value(a, pkcs11::CKA_MODULUS);
    let e, oke = pkcs11::attr_value(a, pkcs11::CKA_PUBLIC_EXPONENT);
    let bpub, okb = bignum::rsa_public_from(bignum::from_bytes_be(n), bignum::from_bytes_be(e));
    guard okn && oke && okb && bignum::rsa_verify_pkcs1(bpub, msg, sig1, 256) && bignum::rsa_verify_pss(bpub, msg, sig2, 32, 256) else {
        print("sign_verify: bignum does not verify the RSA signatures");
        exit(1);
    }
    print("  and by bignum with the modulus read from the token");

    // ECDSA on P-256: the curve goes in the public template.
    var epub: u8[>..] = [];
    pkcs11::attr(epub, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(epub, pkcs11::CKA_VERIFY, true);
    pkcs11::attr(epub, pkcs11::CKA_EC_PARAMS, pkcs11::EC_PARAMS_P256);
    var epriv: u8[>..] = [];
    pkcs11::attr(epriv, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(epriv, pkcs11::CKA_PRIVATE, true);
    pkcs11::attr(epriv, pkcs11::CKA_SIGN, true);
    let ep, es, re = pkcs11::generate_key_pair(c, sh, pkcs11::mechanism(pkcs11::CKM_EC_KEY_PAIR_GEN), epub, epriv);
    check("EC key pair", re);
    // The signature is r || s, 64 bytes on P-256.
    let esig = sign_on_token(c, sh, pkcs11::mechanism(pkcs11::CKM_ECDSA_SHA256), es, ep, msg);
    let pt: u64[1] = [pkcs11::CKA_EC_POINT];
    let pa, rpa = pkcs11::get_attribute_value(c, sh, ep, pt);
    check("C_GetAttributeValue", rpa);
    let der, okp = pkcs11::attr_value(pa, pkcs11::CKA_EC_POINT);
    let point = pkcs11::ec_point(der);
    let curve = bignum::p256();
    guard okp && bignum::ecdsa_verify(curve, point, msg, esig) else {
        print("sign_verify: bignum does not verify the ECDSA signature");
        exit(1);
    }
    print("P-256: ECDSA signature (", esig.len, " bytes) verified by the token and by bignum");

    pkcs11::logout(c, sh);
    pkcs11::close_session(c, sh);
    pkcs11::finalize(c);
    pkcs11::destroy(c);
}
