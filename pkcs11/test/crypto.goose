// pkcs11's cryptographic operations against SoftHSM2, each checked with
// crypto/bignum, an implementation of its own: AES-CBC with padding, ECB,
// GCM (one part and several), AES Key Wrap of a key on the token and back,
// SHA-256 and SHA-512, HMAC; RSA keys made on the token, their PKCS #1 v1.5
// and PSS signatures verified by bignum and OAEP ciphertexts bignum made
// decrypted by the token; ECDSA on P-256 and P-384 both ways (the token's
// signatures verified by bignum, bignum's by the token); Ed25519; ECDH with
// a bignum key, the token's derived key equal to bignum's; and the same
// through p11's keys.
import std;
import gslib from "../..";
import gslib.pkcs11;
import gslib.pkcs11.p11;
import gslib.crypto.bignum;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.modes;
import gslib.crypto.bignum.gcm;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.sha256;
import gslib.crypto.bignum.sha512;
import gslib.crypto.bignum.rsa;
import gslib.crypto.bignum.ec;
import gslib.crypto.bignum.ed25519;
import gslib.crypto.bignum.keywrap;
import gslib.crypto.bignum.entropy;
import hsm;
import tv;

fn random(n: i64) -> u8[>..] {
    var b: u8[>..] = [];
    b.resize(n, 0);
    bignum::random_bytes(b);
    return b;
}

// A session key (not on the token) of known value: AES or generic secret.
fn secret_key(c: pkcs11::Ctx, sh: u64, kind: u64, value: const u8[:]) -> u64 {
    var t: u8[>..] = [];
    pkcs11::attr(t, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
    pkcs11::attr(t, pkcs11::CKA_KEY_TYPE, kind);
    pkcs11::attr(t, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(t, pkcs11::CKA_VALUE, value);
    for a in [pkcs11::CKA_ENCRYPT, pkcs11::CKA_DECRYPT, pkcs11::CKA_SIGN, pkcs11::CKA_VERIFY, pkcs11::CKA_WRAP,
              pkcs11::CKA_UNWRAP, pkcs11::CKA_EXTRACTABLE] {
        if kind == pkcs11::CKK_GENERIC_SECRET && (a == pkcs11::CKA_ENCRYPT || a == pkcs11::CKA_DECRYPT
                                                  || a == pkcs11::CKA_WRAP || a == pkcs11::CKA_UNWRAP) { continue; }
        pkcs11::attr(t, a, true);
    }
    pkcs11::attr(t, pkcs11::CKA_SENSITIVE, false);
    let h, rv = pkcs11::create_object(c, sh, t);
    hsm::ok("secret key", rv);
    return h;
}

fn has(mechs: const u64[:], m: u64) -> bool {
    for x in mechs { if x == m { return true; } }
    return false;
}

fn symmetric(c: pkcs11::Ctx, sh: u64) {
    let kv = random(32);
    let key = secret_key(c, sh, pkcs11::CKK_AES, kv);
    let msg = "Twenty-seven bytes of text!";

    // CBC with PKCS #7 padding: one part, then several.
    let iv = random(16);
    hsm::ok("CBC_PAD init", pkcs11::encrypt_init(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_CBC_PAD, iv), key));
    let ct, re = pkcs11::encrypt(c, sh, msg);
    var mine: u8[>..] = [];
    mine.append(bignum::pkcs7_pad(msg));
    let k = bignum::aes_init(kv);
    bignum::cbc_encrypt(k, iv, mine);
    tv::check("AES-CBC-PAD is bignum's", re == pkcs11::CKR_OK && ct == mine);
    pkcs11::encrypt_init(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_CBC_PAD, iv), key);
    var parts: u8[>..] = [];
    let p1, r1 = pkcs11::encrypt_update(c, sh, msg[..10]);
    parts.append(p1);
    let p2, r2 = pkcs11::encrypt_update(c, sh, msg[10..]);
    parts.append(p2);
    let p3, r3 = pkcs11::encrypt_final(c, sh);
    parts.append(p3);
    tv::check("CBC in parts the same", r1 == pkcs11::CKR_OK && r2 == pkcs11::CKR_OK && r3 == pkcs11::CKR_OK && parts == ct);
    pkcs11::decrypt_init(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_CBC_PAD, iv), key);
    let pt, rd = pkcs11::decrypt(c, sh, ct);
    tv::check("CBC decrypted", rd == pkcs11::CKR_OK && pt == msg);

    // ECB of one block.
    let one = random(16);
    pkcs11::encrypt_init(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_ECB), key);
    let eb, reb = pkcs11::encrypt(c, sh, one);
    let want_block = bignum::aes_encrypt_block(k, one);
    tv::check("AES-ECB is bignum's", reb == pkcs11::CKR_OK && eb[..] == want_block[..]);

    // GCM.
    let nonce = random(12);
    let aad = "header";
    hsm::ok("GCM init", pkcs11::encrypt_init(c, sh, pkcs11::mechanism_gcm(pkcs11::CKM_AES_GCM, nonce, aad, 128), key));
    let g, rg = pkcs11::encrypt(c, sh, msg);
    tv::check("AES-GCM is bignum's", rg == pkcs11::CKR_OK && g == bignum::aes_gcm_seal(kv, nonce, aad, msg));
    pkcs11::decrypt_init(c, sh, pkcs11::mechanism_gcm(pkcs11::CKM_AES_GCM, nonce, aad, 128), key);
    let gp, rgp = pkcs11::decrypt(c, sh, g);
    tv::check("GCM decrypted", rgp == pkcs11::CKR_OK && gp == msg);
    var bad: u8[>..] = [];
    bad.append(g);
    bad[0] = bad[0] ^ 1;
    pkcs11::decrypt_init(c, sh, pkcs11::mechanism_gcm(pkcs11::CKM_AES_GCM, nonce, aad, 128), key);
    let gx, rgx = pkcs11::decrypt(c, sh, bad);
    tv::check("GCM tampered refused", rgx != pkcs11::CKR_OK);

    // AES Key Wrap of another key, and back.
    let inner_v = random(16);
    let inner = secret_key(c, sh, pkcs11::CKK_AES, inner_v);
    let wrapped, rw = pkcs11::wrap_key(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_KEY_WRAP), key, inner);
    let want_wrapped, okw = bignum::aes_key_wrap(kv, inner_v);
    tv::check("AES Key Wrap is bignum's", rw == pkcs11::CKR_OK && okw && wrapped == want_wrapped);
    var ut: u8[>..] = [];
    pkcs11::attr(ut, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
    pkcs11::attr(ut, pkcs11::CKA_KEY_TYPE, pkcs11::CKK_AES);
    pkcs11::attr(ut, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(ut, pkcs11::CKA_SENSITIVE, false);
    pkcs11::attr(ut, pkcs11::CKA_EXTRACTABLE, true);
    let un, ru = pkcs11::unwrap_key(c, sh, pkcs11::mechanism(pkcs11::CKM_AES_KEY_WRAP), key, wrapped, ut);
    hsm::ok("unwrap", ru);
    let uv, ruv = p11::value(p11::Object { ctx: c, session: sh, handle: un });
    tv::check("unwrapped key is the key", ruv == pkcs11::CKR_OK && uv == inner_v);

    // Digests, one part and several.
    let data = random(1000);
    pkcs11::digest_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256));
    let d, rdg = pkcs11::digest(c, sh, data);
    tv::check("SHA-256 is bignum's", rdg == pkcs11::CKR_OK && d[..] == bignum::sha256(data)[..]);
    pkcs11::digest_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA512));
    pkcs11::digest_update(c, sh, data[..333]);
    pkcs11::digest_update(c, sh, data[333..]);
    let d2, rd2 = pkcs11::digest_final(c, sh);
    tv::check("SHA-512 in parts is bignum's", rd2 == pkcs11::CKR_OK && d2 == bignum::sha512(data));

    // HMAC.
    let hk = random(32);
    let hkey = secret_key(c, sh, pkcs11::CKK_GENERIC_SECRET, hk);
    pkcs11::sign_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256_HMAC), hkey);
    let mac, rmac = pkcs11::sign(c, sh, data);
    tv::check("HMAC-SHA256 is bignum's", rmac == pkcs11::CKR_OK && mac == bignum::hmac(256, hk, data));
    pkcs11::verify_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256_HMAC), hkey);
    hsm::ok("HMAC verified", pkcs11::verify(c, sh, data, mac));
    var badmac: u8[>..] = [];
    badmac.append(mac);
    badmac[5] = badmac[5] ^ 0x80;
    pkcs11::verify_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256_HMAC), hkey);
    hsm::check_rv("bad HMAC", pkcs11::verify(c, sh, data, badmac), pkcs11::CKR_SIGNATURE_INVALID);
}

fn rsa(c: pkcs11::Ctx, sh: u64) {
    var pubt: u8[>..] = [];
    pkcs11::attr(pubt, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(pubt, pkcs11::CKA_VERIFY, true);
    pkcs11::attr(pubt, pkcs11::CKA_ENCRYPT, true);
    pkcs11::attr(pubt, pkcs11::CKA_MODULUS_BITS, 2048);
    pkcs11::attr(pubt, pkcs11::CKA_PUBLIC_EXPONENT, "\x01\x00\x01");
    pkcs11::attr(pubt, pkcs11::CKA_LABEL, "rsa");
    var privt: u8[>..] = [];
    pkcs11::attr(privt, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(privt, pkcs11::CKA_PRIVATE, true);
    pkcs11::attr(privt, pkcs11::CKA_SIGN, true);
    pkcs11::attr(privt, pkcs11::CKA_DECRYPT, true);
    pkcs11::attr(privt, pkcs11::CKA_LABEL, "rsa");
    let pub, priv, rv = pkcs11::generate_key_pair(c, sh, pkcs11::mechanism(pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN), pubt, privt);
    hsm::ok("RSA key pair", rv);
    let ts: u64[2] = [pkcs11::CKA_MODULUS, pkcs11::CKA_PUBLIC_EXPONENT];
    let a, ra = pkcs11::get_attribute_value(c, sh, pub, ts);
    let n, okn = pkcs11::attr_value(a, pkcs11::CKA_MODULUS);
    let e, oke = pkcs11::attr_value(a, pkcs11::CKA_PUBLIC_EXPONENT);
    let bpub, okp = bignum::rsa_public_from(bignum::from_bytes_be(n), bignum::from_bytes_be(e));
    tv::check("RSA public key read", ra == pkcs11::CKR_OK && okn && oke && okp && n.len == 256);

    let msg = "signed by the token";
    pkcs11::sign_init(c, sh, pkcs11::mechanism(pkcs11::CKM_SHA256_RSA_PKCS), priv);
    let sig, rs = pkcs11::sign(c, sh, msg);
    tv::check("RSA PKCS #1 v1.5 verified by bignum", rs == pkcs11::CKR_OK && bignum::rsa_verify_pkcs1(bpub, msg, sig, 256));
    let pss = pkcs11::mechanism_pss(pkcs11::CKM_SHA256_RSA_PKCS_PSS, pkcs11::CKM_SHA256, pkcs11::CKG_MGF1_SHA256, 32);
    pkcs11::sign_init(c, sh, pss, priv);
    let psig, rps = pkcs11::sign(c, sh, msg);
    tv::check("RSA-PSS verified by bignum", rps == pkcs11::CKR_OK && bignum::rsa_verify_pss(bpub, msg, psig, 32, 256));
    pkcs11::verify_init(c, sh, pss, pub);
    hsm::ok("RSA-PSS verified by the token", pkcs11::verify(c, sh, msg, psig));

    // OAEP: bignum encrypts, the token decrypts; and the token's own.
    // SoftHSM does OAEP with SHA-1 and MGF1-SHA1 only (other hashes are
    // CKR_ARGUMENTS_BAD), so SHA-1 it is.
    let secret = "a CEK of 32 bytes, more or less!";
    let oaep = pkcs11::mechanism_oaep(pkcs11::CKM_RSA_PKCS_OAEP, pkcs11::CKM_SHA_1, pkcs11::CKG_MGF1_SHA1);
    let bct = bignum::rsa_encrypt_oaep(bpub, secret, "", bignum::HASH_SHA1);
    hsm::ok("OAEP decrypt init", pkcs11::decrypt_init(c, sh, oaep, priv));
    let dec, rdec = pkcs11::decrypt(c, sh, bct);
    tv::check("RSA-OAEP from bignum decrypted by the token", rdec == pkcs11::CKR_OK && dec == secret);
    pkcs11::encrypt_init(c, sh, oaep, pub);
    let tct, rtct = pkcs11::encrypt(c, sh, secret);
    pkcs11::decrypt_init(c, sh, oaep, priv);
    let tdec, rtdec = pkcs11::decrypt(c, sh, tct);
    tv::check("RSA-OAEP round trip", rtct == pkcs11::CKR_OK && rtdec == pkcs11::CKR_OK && tdec == secret);

    // Through p11, by label.
    let s = p11::Session { ctx: c, slot: hsm::slot(c), handle: sh };
    let pk, rpk = p11::find_private_key(s, "rsa");
    let pubk, rpubk = p11::find_public_key(s, "rsa");
    let ps, rps2 = p11::sign(pk, pkcs11::mechanism(pkcs11::CKM_SHA512_RSA_PKCS), "p11");
    tv::check("p11 RSA sign", rpk == pkcs11::CKR_OK && rps2 == pkcs11::CKR_OK && bignum::rsa_verify_pkcs1(bpub, "p11", ps, 512));
    hsm::ok("p11 RSA verify", p11::verify(pubk, pkcs11::mechanism(pkcs11::CKM_SHA512_RSA_PKCS), "p11", ps));
    let pe, rpe = p11::encrypt(pubk, oaep, "via p11");
    let pd, rpd = p11::decrypt(pk, oaep, pe);
    tv::check("p11 RSA encrypt/decrypt", rpe == pkcs11::CKR_OK && rpd == pkcs11::CKR_OK && pd == "via p11");
}

fn ec_pair(c: pkcs11::Ctx, sh: u64, params: const u8[:], gen: u64, label: const u8[:]) -> u64, u64, u8[>..] {
    var pubt: u8[>..] = [];
    pkcs11::attr(pubt, pkcs11::CKA_EC_PARAMS, params);
    pkcs11::attr(pubt, pkcs11::CKA_VERIFY, true);
    pkcs11::attr(pubt, pkcs11::CKA_LABEL, label);
    var privt: u8[>..] = [];
    pkcs11::attr(privt, pkcs11::CKA_SIGN, true);
    pkcs11::attr(privt, pkcs11::CKA_DERIVE, gen == pkcs11::CKM_EC_KEY_PAIR_GEN);
    pkcs11::attr(privt, pkcs11::CKA_PRIVATE, true);
    pkcs11::attr(privt, pkcs11::CKA_LABEL, label);
    let pub, priv, rv = pkcs11::generate_key_pair(c, sh, pkcs11::mechanism(gen), pubt, privt);
    hsm::ok(str(label, " key pair"), rv);
    let ts: u64[1] = [pkcs11::CKA_EC_POINT];
    let a, ra = pkcs11::get_attribute_value(c, sh, pub, ts);
    let pt, okp = pkcs11::attr_value(a, pkcs11::CKA_EC_POINT);
    var point: u8[>..] = [];
    point.append(pkcs11::ec_point(pt));
    tv::check(str(label, " point read"), ra == pkcs11::CKR_OK && okp && point.len > 0);
    return pub, priv, point;
}

fn ec(c: pkcs11::Ctx, sh: u64, mechs: const u64[:]) {
    let msg = "an EC signature";
    for which in 2 {
        let params = if which == 0 { pkcs11::EC_PARAMS_P256[..] } else { pkcs11::EC_PARAMS_P384[..] };
        let curve = if which == 0 { bignum::p256() } else { bignum::p384() };
        let name = if which == 0 { "P-256" } else { "P-384" };
        let hm = if which == 0 { pkcs11::CKM_ECDSA_SHA256 } else { pkcs11::CKM_ECDSA_SHA384 };
        let pub, priv, point = ec_pair(c, sh, params, pkcs11::CKM_EC_KEY_PAIR_GEN, name);
        tv::check(str(name, " point uncompressed"), point.len == 1 + 2 * curve.len && point[0] == 4);
        // The token signs the message hashed by the mechanism, or (where
        // the token lacks ECDSA_SHA*) the digest bignum made.
        var sig: u8[>..] = [];
        if has(mechs, hm) {
            pkcs11::sign_init(c, sh, pkcs11::mechanism(hm), priv);
            let s, rs = pkcs11::sign(c, sh, msg);
            hsm::ok(str(name, " sign"), rs);
            sig.append(s);
        } else {
            pkcs11::sign_init(c, sh, pkcs11::mechanism(pkcs11::CKM_ECDSA), priv);
            let s, rs = pkcs11::sign(c, sh, bignum::hash_bits(curve.hash, msg));
            hsm::ok(str(name, " sign digest"), rs);
            sig.append(s);
        }
        tv::check(str(name, " ECDSA verified by bignum"), bignum::ecdsa_verify(curve, point, msg, sig));
        // bignum's signature, verified by the token with a public key object.
        let sk, pk = bignum::ec_keypair(curve);
        let bsig = bignum::ecdsa_sign(curve, sk, msg);
        var t: u8[>..] = [];
        pkcs11::attr(t, pkcs11::CKA_CLASS, pkcs11::CKO_PUBLIC_KEY);
        pkcs11::attr(t, pkcs11::CKA_KEY_TYPE, pkcs11::CKK_EC);
        pkcs11::attr(t, pkcs11::CKA_TOKEN, false);
        pkcs11::attr(t, pkcs11::CKA_VERIFY, true);
        pkcs11::attr(t, pkcs11::CKA_EC_PARAMS, params);
        pkcs11::attr(t, pkcs11::CKA_EC_POINT, pkcs11::ec_point_der(pk));
        let bpub, rb = pkcs11::create_object(c, sh, t);
        hsm::ok(str(name, " public key object"), rb);
        pkcs11::verify_init(c, sh, pkcs11::mechanism(pkcs11::CKM_ECDSA), bpub);
        hsm::ok(str(name, " bignum's ECDSA verified by the token"), pkcs11::verify(c, sh, bignum::hash_bits(curve.hash, msg), bsig));

        // ECDH: the token's private key with bignum's public one.
        var dt: u8[>..] = [];
        pkcs11::attr(dt, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
        pkcs11::attr(dt, pkcs11::CKA_KEY_TYPE, pkcs11::CKK_GENERIC_SECRET);
        pkcs11::attr(dt, pkcs11::CKA_TOKEN, false);
        pkcs11::attr(dt, pkcs11::CKA_SENSITIVE, false);
        pkcs11::attr(dt, pkcs11::CKA_EXTRACTABLE, true);
        pkcs11::attr(dt, pkcs11::CKA_VALUE_LEN, curve.len as u64);
        let mech = pkcs11::mechanism_ecdh1(pkcs11::CKM_ECDH1_DERIVE, pkcs11::CKD_NULL, "", pk);
        let z, rz = p11::derive_value(p11::PrivateKey { object: p11::Object { ctx: c, session: sh, handle: priv } }, mech, dt);
        let want, okz = bignum::ecdh_shared(curve, sk, point);
        tv::check(str(name, " ECDH is bignum's"), rz == pkcs11::CKR_OK && okz && z == want);
    }
}

fn eddsa(c: pkcs11::Ctx, sh: u64) {
    let pub, priv, point = ec_pair(c, sh, pkcs11::EC_PARAMS_ED25519, pkcs11::CKM_EC_EDWARDS_KEY_PAIR_GEN, "Ed25519");
    tv::check_int("Ed25519 public key length", point.len, 32);
    let msg = "an Ed25519 signature";
    pkcs11::sign_init(c, sh, pkcs11::mechanism(pkcs11::CKM_EDDSA), priv);
    let sig, rs = pkcs11::sign(c, sh, msg);
    tv::check("Ed25519 verified by bignum", rs == pkcs11::CKR_OK && sig.len == 64 && bignum::ed25519_verify(point, msg, sig));
    pkcs11::verify_init(c, sh, pkcs11::mechanism(pkcs11::CKM_EDDSA), pub);
    hsm::ok("Ed25519 verified by the token", pkcs11::verify(c, sh, msg, sig));
    pkcs11::verify_init(c, sh, pkcs11::mechanism(pkcs11::CKM_EDDSA), pub);
    hsm::check_rv("Ed25519 other message", pkcs11::verify(c, sh, "another", sig), pkcs11::CKR_SIGNATURE_INVALID);
}

fn main() {
    let c = hsm::open();
    let sh = hsm::session(c);
    let mechs, rm = pkcs11::get_mechanism_list(c, hsm::slot(c));
    symmetric(c, sh);
    rsa(c, sh);
    ec(c, sh, mechs);
    eddsa(c, sh);
    pkcs11::logout(c, sh);
    pkcs11::close_session(c, sh);
    pkcs11::finalize(c);
    tv::done("crypto");
}
