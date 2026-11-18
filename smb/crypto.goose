// smb.crypto: the cryptography of SMB 2 and 3 ([MS-SMB2] §3.1.4).
//
// Keys: SMB 2.x signs with the session key itself; 3.x derives each key
// with SP 800-108's KDF in counter mode (HMAC-SHA256, a 32-bit counter
// and length) from the session key, with 3.0's labels and contexts or
// 3.1.1's labels and the session's preauth integrity hash (SHA-512 over
// every NEGOTIATE and SESSION_SETUP message up to the last request).
// AES-256 ciphers get 256-bit encryption keys from the full session key.
//
// Signing: HMAC-SHA256 truncated to 16 bytes (2.x), AES-128-CMAC (3.x),
// AES-128-GMAC (3.1.1 when negotiated, its nonce the MessageId and the
// message's direction), over the whole message with the signature field
// zeroed.
//
// Encryption: the TRANSFORM_HEADER (52 bytes) and the message encrypted
// with AES-CCM (an 11-byte nonce) or AES-GCM (12 bytes), the header from
// its Nonce on as the AAD, the tag as its Signature. Each nonce is a
// counter under the key with a random suffix, never repeated.

namespace smb;

import std;
import crypto.bignum;
import crypto.bignum.hmac;
import crypto.bignum.sha512;
import crypto.bignum.aes;
import crypto.bignum.cmac;
import crypto.bignum.gcm;
import crypto.bignum.ccm;
import crypto.bignum.ct;

let TRANSFORM_LEN: i64 = 52;
let TRANSFORM_ENCRYPTED: u16 = 0x0001;

// SP 800-108 counter mode with HMAC-SHA256: L bits (128 or 256) from Ki,
// the label and the context (each passed with its trailing NUL, as SMB's
// are), one block.
fn kdf(ki: const u8[:], label: const u8[:], context: const u8[:], bits: i64) -> u8[>..] {
    var m: u8[>..] = [];
    m.push(0); m.push(0); m.push(0); m.push(1);
    m.append(label);
    m.push(0);
    m.append(context);
    m.push(0); m.push(0);
    m.push(((bits >> 8) & 0xff) as! u8);
    m.push((bits & 0xff) as! u8);
    let h = bignum::hmac_sha256(ki, m);
    var out: u8[>..] = [];
    out.append(h[..bits / 8]);
    return out;
}

// A session's keys. enc and dec are the client's: requests out, responses in.
struct Keys {
    session:     u8[16],         // Session.SessionKey: the first 16 bytes of the GSS key, zero-padded
    signing:     u8[16],
    application: u8[16],
    enc:         u8[32],
    dec:         u8[32],
    enc_len:     i64,            // 16 or 32: the cipher's
}

fn no_keys() -> Keys {
    return Keys { session: [0; 16], signing: [0; 16], application: [0; 16], enc: [0; 32], dec: [0; 32], enc_len: 0 };
}

// The keys of a session on a dialect: gss_key is the full session key of
// the authentication (NTLM's exported session key, Kerberos's subkey),
// preauth the session's hash (3.1.1), cipher the connection's (0: none).
fn derive_keys(dialect: u16, gss_key: const u8[:], preauth: const u8[:], cipher: u16) -> Keys {
    var k = no_keys();
    for i in ::min(16, gss_key.len) { k.session[i] = gss_key[i]; }
    if dialect < SMB30 {
        k.signing = k.session;
        return k;
    }
    let ebits: i64 = if cipher_key_len(cipher) == 32 { 256 } else { 128 };
    // AES-256 keys come from the whole key (§3.2.5.3.1: Session.FullSessionKey).
    let full = if ebits == 256 { gss_key } else { k.session[..] };
    if dialect == SMB311 {
        let s = kdf(k.session, "SMBSigningKey\0", preauth, 128);
        let a = kdf(k.session, "SMBAppKey\0", preauth, 128);
        let e = kdf(full, "SMBC2SCipherKey\0", preauth, ebits);
        let d = kdf(full, "SMBS2CCipherKey\0", preauth, ebits);
        for i in 16 { k.signing[i] = s[i]; k.application[i] = a[i]; }
        for i in e.len { k.enc[i] = e[i]; k.dec[i] = d[i]; }
        k.enc_len = e.len;
    } else {
        let s = kdf(k.session, "SMB2AESCMAC\0", "SmbSign\0", 128);
        let a = kdf(k.session, "SMB2APP\0", "SmbRpc\0", 128);
        let e = kdf(k.session, "SMB2AESCCM\0", "ServerIn \0", 128);
        let d = kdf(k.session, "SMB2AESCCM\0", "ServerOut\0", 128);
        for i in 16 { k.signing[i] = s[i]; k.application[i] = a[i]; k.enc[i] = e[i]; k.dec[i] = d[i]; }
        k.enc_len = 16;
    }
    return k;
}

// --- Preauth integrity (§3.2.5.2, 3.1.1) -------------------------------------------------------------

// hash = SHA-512(hash || message).
fn preauth_update(hash: u8[64]&, msg: const u8[:]) {
    var s = bignum::sha512_init();
    bignum::sha512_update(s, hash);
    bignum::sha512_update(s, msg);
    let h = bignum::sha512_final(s);
    for i in 64 { hash[i] = h[i]; }
}

// --- Signing (§3.1.4.1) --------------------------------------------------------------------------------

// The signature of msg (a whole SMB2 message, its signature field taken
// as zero) under the algorithm and key.
fn signature(alg: u16, key: const u8[:], msg: const u8[:]) -> u8[16] {
    var m: u8[>..] = [];
    m.append(msg);
    for i in 16 { m[48 + i] = 0; }
    var sig: u8[16] = [0; 16];
    if alg == HMAC_SHA256 {
        let h = bignum::hmac_sha256(key, m);
        for i in 16 { sig[i] = h[i]; }
    } else if alg == AES_CMAC {
        let a = bignum::aes_init(key);
        let t = bignum::cmac(a, m);
        for i in 16 { sig[i] = t[i]; }
    } else {
        // GMAC: GCM with the message as AAD and nothing to encrypt; the
        // nonce is the MessageId, then the direction and whether it is a
        // CANCEL (§3.1.4.1).
        var nonce: u8[12] = [0; 12];
        for i in 8 { nonce[i] = m[24 + i]; }
        var role: u8 = 0;
        if get32(m, 16) & FLAGS_SERVER_TO_REDIR != 0 { role |= 1; }
        if get16(m, 12) == CANCEL { role |= 2; }
        nonce[8] = role;
        let g = bignum::gcm_init(key);
        var none: u8[0] = [];
        sig = bignum::gcm_encrypt(g, nonce, m, none);
    }
    return sig;
}

// Signs msg in place: the SIGNED flag set, the signature written.
fn sign(alg: u16, key: const u8[:], msg: u8[:]) {
    set32(msg, 16, get32(msg, 16) | FLAGS_SIGNED);
    let s = signature(alg, key, msg);
    for i in 16 { msg[48 + i] = s[i]; }
}

// Whether msg carries the SIGNED flag and its right signature (compared
// in constant time).
fn verify(alg: u16, key: const u8[:], msg: const u8[:]) -> bool {
    if msg.len < HEADER_LEN || get32(msg, 16) & FLAGS_SIGNED == 0 { return false; }
    let s = signature(alg, key, msg);
    return bignum::ct_eq_bytes(s, msg[48..64]) == 1;
}

// --- Encryption (§3.1.4.3) ------------------------------------------------------------------------------

fn is_transform(m: const u8[:]) -> bool { m.len >= 4 && m[0] == 0xfd && m[1] == 'S' && m[2] == 'M' && m[3] == 'B' }

// The nonce's length for a cipher.
fn nonce_len(cipher: u16) -> i64 { if cipher_is_gcm(cipher) { 12 } else { 11 } }

// The transformed message of plain: the TRANSFORM_HEADER with the Nonce
// field (zero-padded to 16 bytes; the cipher takes its first 11 or 12, but
// all 16 are in the AAD) and session id, then plain encrypted.
fn encrypt_message(cipher: u16, key: const u8[:], nonce: const u8[:], session_id: u64, plain: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.push(0xfd); out.push('S'); out.push('M'); out.push('B');
    for i in 16 { out.push(0); }
    let n = nonce_len(cipher);
    assert(nonce.len >= n && nonce.len <= 16);
    for i in 16 { out.push(if i < nonce.len { nonce[i] } else { 0 }); }
    put32(out, plain.len as! u32);
    put16(out, 0);
    put16(out, TRANSFORM_ENCRYPTED);
    put64(out, session_id);
    var aad: u8[32] = [0; 32];
    for i in 32 { aad[i] = out[20 + i]; }
    let at = out.len;
    out.append(plain);
    var tag: u8[16] = [0; 16];
    if cipher_is_gcm(cipher) {
        let g = bignum::gcm_init(key);
        tag = bignum::gcm_encrypt(g, nonce[..n], aad, out[at..]);
    } else {
        let a = bignum::aes_init(key);
        tag = bignum::ccm_encrypt(a, nonce[..n], aad, out[at..], 16);
    }
    for i in 16 { out[4 + i] = tag[i]; }
    return out;
}

// The session id of a transformed message (0 if it is too short).
fn transform_session(m: const u8[:]) -> u64 { if m.len >= TRANSFORM_LEN { get64(m, 44) } else { 0 } }

// The SMB2 message inside a transformed one, under the cipher and key;
// false when it is not a transform header of an encrypted message, its
// sizes are wrong, or it does not decrypt.
fn decrypt_message(cipher: u16, key: const u8[:], m: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !is_transform(m) || m.len < TRANSFORM_LEN || get16(m, 42) != TRANSFORM_ENCRYPTED { return out, false; }
    if get32(m, 36) != m.len - TRANSFORM_LEN { return out, false; }
    out.append(m[TRANSFORM_LEN..]);
    let n = nonce_len(cipher);
    var ok = false;
    if cipher_is_gcm(cipher) {
        let g = bignum::gcm_init(key);
        ok = bignum::gcm_decrypt(g, m[20..20 + n], m[20..52], out, m[4..20]);
    } else {
        let a = bignum::aes_init(key);
        ok = bignum::ccm_decrypt(a, m[20..20 + n], m[20..52], out, m[4..20]);
    }
    if !ok { out.clear(); }
    return out, ok;
}
