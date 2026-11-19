// kmip.crypto: the cryptography KMIP names, on gslib's: hashes by KMIP's
// enumeration, symmetric ciphers by algorithm, mode and padding (AES,
// Triple DES, ChaCha20 and ChaCha20-Poly1305; ECB, CBC, CFB, OFB, CTR, GCM,
// CCM, XTS, NIST Key Wrap and AES Key Wrap with Padding; PKCS #5, ANSI
// X9.23, ISO 10126, zeros or none), RSA encryption (OAEP, its hash and
// MGF1's apart, and PKCS #1 v1.5), and signatures. The server's
// operations, key wrapping and key derivation all go through here, and a
// client can use it to unwrap what a server wrapped.

namespace kmip;

import std;
import entropy;
import kmip;
import kmip.tables;
import kmip.attributes;
import kmip.objects;
import kmip.formats;
import crypto.bignum;
import crypto.bignum.aes;
import crypto.bignum.des;
import crypto.bignum.modes;
import crypto.bignum.gcm;
import crypto.bignum.ccm;
import crypto.bignum.chacha20;
import crypto.bignum.cmac;
import crypto.bignum.hmac;
import crypto.bignum.keywrap;
import crypto.bignum.ec;
import crypto.bignum.ct;
import crypto.bignum.rsa;
import crypto.x509;
import crypto.x509.keys;
import encoding.asn1;

// bignum's hash id for a KMIP Hashing Algorithm; 0 for one gslib has not.
fn hash_id(h: u32) -> i64 {
    if h == HASH_SHA_1 { return bignum::HASH_SHA1; }
    if h == HASH_SHA_224 { return bignum::HASH_SHA224; }
    if h == HASH_SHA_256 { return bignum::HASH_SHA256; }
    if h == HASH_SHA_384 { return bignum::HASH_SHA384; }
    if h == HASH_SHA_512 { return bignum::HASH_SHA512; }
    if h == HASH_SHA_512_224 { return bignum::HASH_SHA512_224; }
    if h == HASH_SHA_512_256 { return bignum::HASH_SHA512_256; }
    if h == HASH_SHA3_224 { return bignum::HASH_SHA3_224; }
    if h == HASH_SHA3_256 { return bignum::HASH_SHA3_256; }
    if h == HASH_SHA3_384 { return bignum::HASH_SHA3_384; }
    if h == HASH_SHA3_512 { return bignum::HASH_SHA3_512; }
    if h == HASH_MD5 { return 128; }
    return 0;
}

// The hash of an HMAC algorithm, bignum's id; 0 when it is not one.
fn hmac_bits(alg: u32) -> i64 {
    if alg == ALG_HMAC_SHA1 { return 160; }
    if alg == ALG_HMAC_SHA224 { return 224; }
    if alg == ALG_HMAC_SHA256 { return 256; }
    if alg == ALG_HMAC_SHA384 { return 384; }
    if alg == ALG_HMAC_SHA512 { return 512; }
    if alg == ALG_HMAC_MD5 { return 128; }
    if alg == ALG_HMAC_SHA3_224 { return bignum::HASH_SHA3_224; }
    if alg == ALG_HMAC_SHA3_256 { return bignum::HASH_SHA3_256; }
    if alg == ALG_HMAC_SHA3_384 { return bignum::HASH_SHA3_384; }
    if alg == ALG_HMAC_SHA3_512 { return bignum::HASH_SHA3_512; }
    return 0;
}

// --- Padding ----------------------------------------------------------------------

fn pad_block(data: const u8[:], bs: i64, method: u32) -> u8[>..], bool {
    var out: u8[>..] = [];
    out.append(data);
    if method == PAD_NONE { return out, data.len % bs == 0; }
    let n = bs - data.len % bs;
    if method == PAD_PKCS5 { for k in n { out.push(n as! u8); } return out, true; }
    if method == PAD_ANSI_X923 { for k in n - 1 { out.push(0); } out.push(n as! u8); return out, true; }
    if method == PAD_ISO_10126 {
        var r: u8[>..] = [];
        r.resize(n - 1, 0);
        entropy::random_bytes(r);
        out.append(r);
        out.push(n as! u8);
        return out, true;
    }
    if method == PAD_ZEROS {
        if data.len % bs != 0 { for k in n { out.push(0); } }
        return out, true;
    }
    return out, false;
}

fn unpad_block(data: const u8[:], bs: i64, method: u32) -> u8[>..], bool {
    var out: u8[>..] = [];
    if data.len % bs != 0 { return out, false; }
    if method == PAD_NONE || method == PAD_ZEROS { out.append(data); return out, true; }
    if data.len == 0 { return out, false; }
    let n = data[data.len - 1] as i64;
    if n < 1 || n > bs { return out, false; }
    if method == PAD_PKCS5 {
        let un, ok = bignum::pkcs7_unpad(data, bs);
        if ok { out.append(un); }
        return out, ok;
    }
    if method == PAD_ANSI_X923 {
        for k in n - 1 { if data[data.len - n + k] != 0 { return out, false; } }
    } else if method != PAD_ISO_10126 {
        return out, false;
    }
    out.append(data[..data.len - n]);
    return out, true;
}

// --- Symmetric ciphers -------------------------------------------------------------

// What a symmetric operation takes and gives: the IV, nonce or counter
// (made when encrypting without one and the mode needs one), the AEAD
// data and tag.
struct Sym {
    iv: u8[..64],
    made_iv: bool,
    aad: u8[>..],
}

fn sym() -> Sym { Sym { iv: [], made_iv: false, aad: [] } }

fn xts_tweak<K>(k1: const K&, k2: const K&, tweak: const u8[:], data: u8[:], decrypt: bool) {
    var tw = bignum::cipher_encrypt(k2, tweak);
    var off = 0;
    var x: u8[16] = [0; 16];
    while off < data.len {
        for i in 16 { x[i] = data[off + i] ^ tw[i]; }
        let e = if decrypt { bignum::cipher_decrypt(k1, x) } else { bignum::cipher_encrypt(k1, x) };
        for i in 16 { data[off + i] = e[i] ^ tw[i]; }
        var carry: u8 = 0;
        for i in 16 {
            let c = tw[i] >> 7;
            tw[i] = (tw[i] << 1) | carry;
            carry = c;
        }
        tw[0] ^= 0x87 & (0 - carry);
        off += 16;
    }
}

// A block cipher in one of the modes that take a key schedule K.
fn block_mode<K>(k: const K&, bs: i64, mode: u32, padding: u32, enc: bool, data: const u8[:], iv: const u8[:],
                 out: u8[>..]&) -> u32 {
    // No padding unless the parameters name one, as the OASIS test cases
    // (CS-BC-M-*) have it.
    let padm = if padding != 0 { padding } else { PAD_NONE };
    if mode == MODE_CBC || mode == MODE_ECB {
        if mode == MODE_CBC && iv.len != bs { return REASON_INVALID_FIELD; }
        if enc {
            let p, ok = pad_block(data, bs, padm);
            if !ok { return if padm == PAD_NONE { REASON_INVALID_FIELD } else { REASON_BAD_CRYPTOGRAPHIC_PARAMETERS }; }
            out.append(p);
            if mode == MODE_CBC { bignum::cbc_encrypt(k, iv, out); }
            else { var at = 0; while at < out.len { let b = bignum::cipher_encrypt(k, out[at..at + bs]); for j in bs { out[at + j] = b[j]; } at += bs; } }
            return 0;
        }
        if data.len % bs != 0 || data.len == 0 { return REASON_INVALID_FIELD; }
        var tmp: u8[>..] = [];
        tmp.append(data);
        if mode == MODE_CBC { bignum::cbc_decrypt(k, iv, tmp); }
        else { var at = 0; while at < tmp.len { let b = bignum::cipher_decrypt(k, tmp[at..at + bs]); for j in bs { tmp[at + j] = b[j]; } at += bs; } }
        let un, ok = unpad_block(tmp, bs, padm);
        if !ok { return REASON_CRYPTOGRAPHIC_FAILURE; }
        out.append(un);
        return 0;
    }
    if iv.len != bs { return REASON_INVALID_FIELD; }
    out.append(data);
    if mode == MODE_CFB { if enc { bignum::cfb_encrypt(k, iv, out); } else { bignum::cfb_decrypt(k, iv, out); } return 0; }
    if mode == MODE_OFB { bignum::ofb_xor(k, iv, out); return 0; }
    if mode == MODE_CTR { bignum::ctr_xor(k, iv, out); return 0; }
    out.clear();
    return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS;
}

// The IV length a mode needs, bytes; 0 for none.
fn iv_len_of(alg: u32, mode: u32, cp: const CryptoParams&) -> i64 {
    if alg == ALG_CHACHA20 { return 12; }
    if alg == ALG_CHACHA20_POLY1305 || mode == MODE_AEAD { return 12; }
    if mode == MODE_ECB || mode == MODE_NIST_KEY_WRAP || mode == MODE_AES_KEY_WRAP_PADDING { return 0; }
    if mode == MODE_GCM || mode == MODE_CCM { return if cp.iv_length > 0 { cp.iv_length as i64 / 8 } else if mode == MODE_GCM { 12 } else { 13 }; }
    return if alg == ALG_TRIPLE_DES { 8 } else { 16 };
}

// Encrypts (enc) or decrypts data with a symmetric key object, by the
// parameters (the mode CBC and padding PKCS #5 when not named; NIST Key
// Wrap for mode 0 of a key whose own parameters say so is the caller's).
// s.iv is used, or made and s.made_iv set; AEAD modes write the tag into
// tag (encrypting) or check the one given (decrypting). 0, or the Result
// Reason.
fn sym_crypt(o: const Object&, cp: const CryptoParams&, enc: bool, data: const u8[:], s: Sym&, tag: u8[>..]&,
             out: u8[>..]&) -> u32 {
    if o.obj_type != OBJ_SYMMETRIC_KEY || o.wrapped { return REASON_INVALID_OBJECT_TYPE; }
    if o.key_format != FMT_RAW && o.key_format != FMT_TRANSPARENT_SYMMETRIC_KEY { return REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
    let alg = o.alg;
    if cp.alg != 0 && cp.alg != alg { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
    let key = o.material[..];
    let mode = if cp.mode != 0 { cp.mode } else if alg == ALG_CHACHA20_POLY1305 { MODE_AEAD } else { MODE_CBC };
    let need = iv_len_of(alg, mode, cp);
    if need > 0 && s.iv.len == 0 {
        if !enc { return REASON_INVALID_MESSAGE; }  // as OASIS's test cases have it, rather than Missing Initialization Vector
        s.iv.resize(need, 0);
        entropy::random_bytes(s.iv);
        s.made_iv = true;
    }
    let tag_len: i64 = if cp.tag_length > 0 { cp.tag_length } else { 16 };
    if alg == ALG_AES {
        if key.len != 16 && key.len != 24 && key.len != 32 && !(mode == MODE_XTS && key.len == 64) { return REASON_INVALID_FIELD; }
        if mode == MODE_NIST_KEY_WRAP || mode == MODE_AES_KEY_WRAP_PADDING {
            let kwp = mode == MODE_AES_KEY_WRAP_PADDING;
            var w: u8[>..] = [];
            var ok = false;
            if enc && kwp { w, ok = bignum::aes_key_wrap_pad(key, data); }
            else if enc { w, ok = bignum::aes_key_wrap(key, data); }
            else if kwp { w, ok = bignum::aes_key_unwrap_pad(key, data); }
            else { w, ok = bignum::aes_key_unwrap(key, data); }
            if !ok { return if enc { REASON_INVALID_FIELD } else { REASON_CRYPTOGRAPHIC_FAILURE }; }
            out.append(w);
            return 0;
        }
        if mode == MODE_GCM {
            if tag_len < 12 || tag_len > 16 { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
            if s.iv.len == 0 { return REASON_INVALID_FIELD; }
            let g = bignum::gcm_init(key);
            out.append(data);
            if enc {
                let t = bignum::gcm_encrypt(g, s.iv, s.aad, out);
                tag.append(t[..tag_len]);
                return 0;
            }
            if tag.len != tag_len { return REASON_INVALID_FIELD; }
            // The tag over the ciphertext, its first tag_len bytes compared
            // in constant time; then the ciphertext through the same CTR.
            let j0 = bignum::gcm_j0(g, s.iv);
            let full = bignum::gcm_tag(g, j0, s.aad, data);
            if bignum::ct_eq_bytes(full[..tag_len], tag) != 1 { out.clear(); return REASON_CRYPTOGRAPHIC_FAILURE; }
            let ignored = bignum::gcm_encrypt(g, s.iv, s.aad, out);
            return 0;
        }
        if mode == MODE_CCM {
            let k = bignum::aes_init(key);
            if !bignum::ccm_fits(s.iv.len, tag_len, data.len, s.aad.len) { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
            out.append(data);
            if enc {
                let t = bignum::ccm_encrypt(k, s.iv, s.aad, out, tag_len);
                tag.append(t[..tag_len]);
                return 0;
            }
            if !bignum::ccm_decrypt(k, s.iv, s.aad, out, tag) { out.clear(); return REASON_CRYPTOGRAPHIC_FAILURE; }
            return 0;
        }
        if mode == MODE_XTS {
            if key.len != 32 && key.len != 64 { return REASON_INVALID_FIELD; }
            if s.iv.len != 16 || data.len % 16 != 0 || data.len == 0 { return REASON_INVALID_FIELD; }
            let half = key.len / 2;
            let k1 = bignum::aes_init(key[..half]);
            let k2 = bignum::aes_init(key[half..]);
            out.append(data);
            xts_tweak(k1, k2, s.iv, out, !enc);
            return 0;
        }
        let k = bignum::aes_init(key);
        return block_mode(k, 16, mode, cp.padding, enc, data, s.iv, out);
    }
    if alg == ALG_TRIPLE_DES {
        if key.len != 24 && key.len != 16 { return REASON_INVALID_FIELD; }
        var k24: u8[>..] = [];
        k24.append(key);
        if key.len == 16 { k24.append(key[..8]); }
        let k = bignum::des3_init(k24);
        return block_mode(k, 8, mode, cp.padding, enc, data, s.iv, out);
    }
    if alg == ALG_CHACHA20 {
        if key.len != 32 { return REASON_INVALID_FIELD; }
        // A 12-byte nonce (RFC 8439), an 8-byte one (the original's, its
        // counter the upper 32 bits zero), or 16 bytes: a little-endian
        // counter then the nonce.
        var nonce: u8[12] = [0; 12];
        var counter: u32 = if cp.has_initial_counter { cp.initial_counter as! u32 } else { 0 };
        if s.iv.len == 12 { for i in 12 { nonce[i] = s.iv[i]; } }
        else if s.iv.len == 8 { for i in 8 { nonce[4 + i] = s.iv[i]; } }
        else if s.iv.len == 16 {
            counter = bignum::le32(s.iv[..4]);
            for i in 12 { nonce[i] = s.iv[4 + i]; }
        } else { return REASON_INVALID_FIELD; }
        if !bignum::chacha20_fits(counter, data.len) { return REASON_INVALID_FIELD; }
        out.append(data);
        bignum::chacha20_xor(key, counter, nonce, out);
        return 0;
    }
    if alg == ALG_CHACHA20_POLY1305 {
        if key.len != 32 || s.iv.len != 12 { return REASON_INVALID_FIELD; }
        if cp.tag_length != 0 && cp.tag_length != 16 { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
        out.append(data);
        if enc {
            let t = bignum::chacha20_poly1305_encrypt(key, s.iv, s.aad, out);
            tag.append(t);
            return 0;
        }
        if !bignum::chacha20_poly1305_decrypt(key, s.iv, s.aad, out, tag) { out.clear(); return REASON_CRYPTOGRAPHIC_FAILURE; }
        return 0;
    }
    return REASON_INVALID_OBJECT_TYPE;
}

// --- MACs -----------------------------------------------------------------------

// A MAC of data with a symmetric key: HMAC for an HMAC key, CMAC for an
// AES or Triple DES key (Block Cipher Mode CMAC). 0, or the Result Reason.
fn sym_mac(o: const Object&, cp: const CryptoParams&, data: const u8[:], out: u8[>..]&) -> u32 {
    if o.obj_type != OBJ_SYMMETRIC_KEY || o.wrapped { return REASON_INVALID_OBJECT_TYPE; }
    let alg = if cp.alg != 0 { cp.alg } else { o.alg };
    let bits = hmac_bits(alg);
    if bits != 0 {
        // An HMAC key, or any key the parameters (or its own) say makes HMACs.
        if hmac_bits(o.alg) != 0 && cp.alg != 0 && cp.alg != o.alg { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
        out.append(bignum::hmac(bits, o.material, data));
        return 0;
    }
    if o.alg == ALG_AES && (cp.mode == MODE_CMAC || cp.mode == 0) {
        if o.material.len != 16 && o.material.len != 24 && o.material.len != 32 { return REASON_INVALID_FIELD; }
        let k = bignum::aes_init(o.material);
        out.append(bignum::cmac(k, data));
        return 0;
    }
    if o.alg == ALG_TRIPLE_DES && (cp.mode == MODE_CMAC || cp.mode == 0) {
        if o.material.len != 24 { return REASON_INVALID_FIELD; }
        let k = bignum::des3_init(o.material);
        out.append(bignum::cmac(k, data));
        return 0;
    }
    return REASON_INVALID_OBJECT_TYPE;
}

// --- RSA encryption -------------------------------------------------------------

// RSA encryption with a public key object (enc) or decryption with a
// private one: OAEP (the default; SHA-1 for its hash and MGF1's, as KMIP
// has them, unless the parameters name others; P Source its label) or
// PKCS #1 v1.5.
fn rsa_crypt(o: const Object&, cp: const CryptoParams&, enc: bool, data: const u8[:], out: u8[>..]&) -> u32 {
    let padm = if cp.padding != 0 { cp.padding } else { PAD_OAEP };
    if padm != PAD_OAEP && padm != PAD_PKCS1V15 { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
    let h = hash_id(if cp.hash != 0 { cp.hash } else { HASH_SHA_1 });
    let mh = hash_id(if cp.mgf_hash != 0 { cp.mgf_hash } else if cp.hash != 0 { cp.hash } else { HASH_SHA_1 });
    if h == 0 || mh == 0 || h == 128 || mh == 128 { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
    if enc {
        if o.obj_type != OBJ_PUBLIC_KEY { return REASON_INVALID_OBJECT_TYPE; }
        let pk, r = rsa_public_of(o);
        if r != 0 { return r; }
        if padm == PAD_OAEP {
            if data.len > bignum::rsa_oaep_max(pk, h) { return REASON_INVALID_FIELD; }
            out.append(bignum::rsa_encrypt_oaep(pk, data, cp.p_source, h, mh));
        } else {
            if data.len > bignum::rsa_size(pk) - 11 { return REASON_INVALID_FIELD; }
            out.append(bignum::rsa_encrypt_pkcs1(pk, data));
        }
        return 0;
    }
    if o.obj_type != OBJ_PRIVATE_KEY || o.wrapped { return REASON_INVALID_OBJECT_TYPE; }
    let k, kok = private_of(o);
    if !kok { return REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
    if k.kind != x509::KEY_RSA { return REASON_INVALID_OBJECT_TYPE; }
    var pt: u8[>..] = [];
    var ok = false;
    if padm == PAD_OAEP { pt, ok = bignum::rsa_decrypt_oaep(k.rsa, data, cp.p_source, h, mh); }
    else { pt, ok = bignum::rsa_decrypt_pkcs1(k.rsa, data); }
    if !ok { return REASON_CRYPTOGRAPHIC_FAILURE; }
    out.append(pt);
    return 0;
}

// The RSA public key of a public key object.
fn rsa_public_of(o: const Object&) -> bignum::RsaPublicKey, u32 {
    var none = bignum::RsaPublicKey { n: [], e: [] };
    let spki, sok = spki_of_object(o);
    if !sok { return none, REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
    let t, tok = asn1::parse(spki);
    let kind, key, kok = x509::spki_of(spki, t);
    if !tok || !kok || kind != x509::KEY_RSA { return none, REASON_INVALID_OBJECT_TYPE; }
    let bits, unused, bok = asn1::read_bits(spki, key);
    let v, vok = der_uints(bits);
    if !bok || !vok || v.len != 2 { return none, REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
    let pk, pok = bignum::rsa_public_from(bignum::from_bytes_be(uint_at(bits, v[0])), bignum::from_bytes_be(uint_at(bits, v[1])));
    if !pok { return none, REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
    return pk, 0;
}

// PKCS #1 v1.5's signature block over bytes as they are, without the
// DigestInfo (PKCS #11's CKM_RSA_PKCS): what a Digested Data that is no
// hash's length is signed as.
fn pkcs1_raw_block(k: i64, data: const u8[:]) -> u8[>..], bool {
    var em: u8[>..] = [];
    if data.len > k - 11 { return em, false; }
    em.push(0);
    em.push(1);
    for j in k - 3 - data.len { em.push(0xff); }
    em.push(0);
    em.append(data);
    return em, true;
}

// --- Signatures -----------------------------------------------------------------

// The x509 signature algorithm and hash the parameters name, for a key of
// the algorithm; alg 0 when they name none it does.
fn sig_of(cp: const CryptoParams&, key_alg: u32) -> i64, i64 {
    if cp.sig == SIG_SHA1_WITH_RSA_ENCRYPTION { return x509::SIG_RSA_PKCS1, 160; }
    if cp.sig == SIG_SHA224_WITH_RSA_ENCRYPTION { return x509::SIG_RSA_PKCS1, 224; }
    if cp.sig == SIG_SHA256_WITH_RSA_ENCRYPTION { return x509::SIG_RSA_PKCS1, 256; }
    if cp.sig == SIG_SHA384_WITH_RSA_ENCRYPTION { return x509::SIG_RSA_PKCS1, 384; }
    if cp.sig == SIG_SHA512_WITH_RSA_ENCRYPTION { return x509::SIG_RSA_PKCS1, 512; }
    if cp.sig == SIG_ECDSA_WITH_SHA1 { return x509::SIG_ECDSA, 160; }
    if cp.sig == SIG_ECDSA_WITH_SHA224 { return x509::SIG_ECDSA, 224; }
    if cp.sig == SIG_ECDSA_WITH_SHA256 { return x509::SIG_ECDSA, 256; }
    if cp.sig == SIG_ECDSA_WITH_SHA384 { return x509::SIG_ECDSA, 384; }
    if cp.sig == SIG_ECDSA_WITH_SHA512 { return x509::SIG_ECDSA, 512; }
    if cp.sig == SIG_SHA3_256_WITH_RSA_ENCRYPTION { return x509::SIG_RSA_PKCS1, bignum::HASH_SHA3_256; }
    if cp.sig == SIG_SHA3_384_WITH_RSA_ENCRYPTION { return x509::SIG_RSA_PKCS1, bignum::HASH_SHA3_384; }
    if cp.sig == SIG_SHA3_512_WITH_RSA_ENCRYPTION { return x509::SIG_RSA_PKCS1, bignum::HASH_SHA3_512; }
    if cp.sig == SIG_DSA_WITH_SHA1 { return x509::SIG_DSA, 160; }
    if cp.sig == SIG_DSA_WITH_SHA224 { return x509::SIG_DSA, 224; }
    if cp.sig == SIG_DSA_WITH_SHA256 { return x509::SIG_DSA, 256; }
    let h = hash_id(cp.hash);
    if cp.sig == SIG_RSASSA_PSS || cp.padding == PAD_PSS { return x509::SIG_RSA_PSS, if h != 0 { h } else { 256 }; }
    if cp.sig != 0 { return 0, 0; }
    if key_alg == ALG_RSA && (cp.padding == PAD_PKCS1V15 || cp.padding == 0) { return x509::SIG_RSA_PKCS1, if h != 0 { h } else { 256 }; }
    if key_alg == ALG_EC || key_alg == ALG_ECDSA { return x509::SIG_ECDSA, if h != 0 { h } else { 256 }; }
    if key_alg == ALG_DSA { return x509::SIG_DSA, if h != 0 { h } else { 256 }; }
    return 0, 0;
}

// A Cert holding only a public key, for x509::verify_with.
fn key_holder(o: const Object&) -> x509::Cert, bool {
    var c = x509::empty_cert();
    let spki, sok = spki_of_object(o);
    if !sok { return c, false; }
    c.der.append(spki);
    let t, ok = asn1::parse(c.der);
    if !ok { return c, false; }
    let kind, key, kok = x509::spki_of(c.der, t);
    if !kok { return c, false; }
    c.spki = t;
    c.key_type = kind;
    c.key = key;
    return c, true;
}

// Signs data (or, prehashed, its digest) with a private key object.
fn sign_with(o: const Object&, cp: const CryptoParams&, data: const u8[:], prehashed: bool, out: u8[>..]&) -> u32 {
    if o.obj_type != OBJ_PRIVATE_KEY || o.wrapped { return REASON_INVALID_OBJECT_TYPE; }
    let k, kok = private_of(o);
    if !kok { return REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
    let alg, h = sig_of(cp, o.alg);
    if alg == 0 || !x509::sig_fits_key(k.kind, alg, h) { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
    if prehashed && data.len != bignum::hash_len(h) {
        // A digest of another length: RSA over it as it is, ECDSA on it.
        if alg == x509::SIG_RSA_PKCS1 {
            let em, eok = pkcs1_raw_block(bignum::rsa_size(k.rsa), data);
            if !eok { return REASON_INVALID_FIELD; }
            let s, sok = bignum::rsa_private_op(k.rsa, em);
            if !sok { return REASON_CRYPTOGRAPHIC_FAILURE; }
            out.append(s);
            return 0;
        }
        if alg == x509::SIG_ECDSA {
            let curve = x509::curve_of_key(k.kind);
            out.append(bignum::ecdsa_sig_to_der(bignum::ecdsa_sign_digest(curve, k.ec_sk, data, h)));
            return 0;
        }
        return REASON_INVALID_FIELD;
    }
    var sig: u8[>..] = [];
    var ok = false;
    if prehashed { sig, ok = x509::sign_digest(k, alg, h, data); } else { sig, ok = x509::sign(k, alg, h, data); }
    if !ok { return REASON_CRYPTOGRAPHIC_FAILURE; }
    out.append(sig);
    return 0;
}

// Checks a signature with a public key object: 0 and whether it is good,
// or a Result Reason.
fn verify_with(o: const Object&, cp: const CryptoParams&, data: const u8[:], sig: const u8[:], prehashed: bool) -> u32, bool {
    if o.obj_type != OBJ_PUBLIC_KEY && o.obj_type != OBJ_CERTIFICATE { return REASON_INVALID_OBJECT_TYPE, false; }
    var c = x509::empty_cert();
    if o.obj_type == OBJ_CERTIFICATE {
        var e = x509::OK;
        c, e = x509::parse(o.material);
        if e != x509::OK { return REASON_INVALID_FIELD, false; }
    } else {
        var cok = false;
        c, cok = key_holder(o);
        if !cok { return REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED, false; }
    }
    let alg, h = sig_of(cp, if o.alg != 0 { o.alg } else if c.key_type == x509::KEY_RSA { ALG_RSA } else { ALG_EC });
    if alg == 0 { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, false; }
    if prehashed && data.len != bignum::hash_len(h) && o.obj_type == OBJ_PUBLIC_KEY {
        if alg == x509::SIG_RSA_PKCS1 {
            if c.key_type != x509::KEY_RSA { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, false; }
            let pk, pr = rsa_public_of(o);
            if pr != 0 { return pr, false; }
            let em, eok = pkcs1_raw_block(bignum::rsa_size(pk), data);
            let m, mok = bignum::rsa_public_op(pk, sig);
            return 0, eok && mok && m.len == em.len && bignum::ct_eq_bytes(m, em) == 1;
        }
        if alg == x509::SIG_ECDSA {
            if !x509::is_ec(c.key_type) { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, false; }
            let curve = x509::curve_of_key(c.key_type);
            let raw, rok = bignum::ecdsa_sig_from_der(curve, sig);
            let pt, unused, ptok = asn1::read_bits(c.der, c.key);
            return 0, rok && ptok && bignum::ecdsa_verify_digest(curve, pt, data, raw);
        }
        return REASON_INVALID_FIELD, false;
    }
    let salt: i64 = if cp.salt_length >= 0 { cp.salt_length } else if alg == x509::SIG_RSA_PSS { bignum::hash_len(h) } else { 0 };
    let r = if prehashed { x509::verify_digest(c, alg, h, salt, data, sig) } else { x509::verify_with(c, alg, h, salt, data, sig) };
    if r == x509::OK || alg != x509::SIG_RSA_PSS || cp.salt_length >= 0 { return 0, r == x509::OK; }
    // No Salt Length given: the longest salt the key takes too (what
    // signers that maximize it, as the OASIS cases' did, use).
    let most = (sig.len - bignum::hash_len(h) - 2);
    let r2 = if prehashed { x509::verify_digest(c, alg, h, most, data, sig) } else { x509::verify_with(c, alg, h, most, data, sig) };
    return 0, r2 == x509::OK;
}
