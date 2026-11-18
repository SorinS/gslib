// bignum.ccm: AES-CCM (NIST SP 800-38C, RFC 3610), counter mode with a
// CBC-MAC: the cipher of SMB 3 and of 802.11's CCMP. Nonces of 7 to 13
// bytes, tags of 4 to 16 bytes (even), any AAD under 2^32 bytes.
// Constant time when AES is: only the lengths steer it.

namespace bignum;

import std;
import crypto.bignum.ct;
import crypto.bignum.aes;

// Whether the nonce and tag lengths are CCM's, and a message of n bytes
// fits the counter the nonce leaves (15 - nonce bytes of it).
fn ccm_fits(nonce_len: i64, tag_len: i64, n: i64, aad_len: i64) -> bool {
    if nonce_len < 7 || nonce_len > 13 || tag_len < 4 || tag_len > 16 || tag_len % 2 != 0 { return false; }
    if n < 0 || aad_len < 0 || aad_len > 0xffffffff { return false; }
    let q = 15 - nonce_len;
    if q < 8 && n >= (1 << (8 * q)) { return false; }
    return true;
}

// x = E(x ^ block) over data, the last block zero-padded.
fn ccm_mac_update(k: const Aes&, x: u8[:], data: const u8[:]) {
    var off = 0;
    while off < data.len {
        let n = ::min(16, data.len - off);
        for i in n { x[i] ^= data[off + i]; }
        let e = aes_encrypt_block(k, x);
        for i in 16 { x[i] = e[i]; }
        off += n;
    }
}

// The CBC-MAC T over B0, the encoded AAD and the plaintext.
fn ccm_mac(k: const Aes&, nonce: const u8[:], aad: const u8[:], pt: const u8[:], tag_len: i64) -> u8[16] {
    let q = 15 - nonce.len;
    var b0: u8[16] = [0; 16];
    var flags = ((tag_len - 2) / 2) << 3 | (q - 1);
    if aad.len > 0 { flags |= 0x40; }
    b0[0] = flags as! u8;
    for i in nonce.len { b0[1 + i] = nonce[i]; }
    var len = pt.len;
    var i = 15;
    while i > nonce.len {
        b0[i] = (len & 0xff) as! u8;
        len >>= 8;
        i--;
    }
    var x = aes_encrypt_block(k, b0);
    if aad.len > 0 {
        var head: u8[>..] = [];
        if aad.len < 0xff00 {
            head.push((aad.len >> 8) as! u8);
            head.push((aad.len & 0xff) as! u8);
        } else {
            head.push(0xff);
            head.push(0xfe);
            for j in 4 { head.push(((aad.len >> (24 - 8 * j)) & 0xff) as! u8); }
        }
        head.append(aad);
        ccm_mac_update(k, x, head);
    }
    ccm_mac_update(k, x, pt);
    return x;
}

// Counter block i: flags (q - 1), the nonce, i in the last q bytes.
fn ccm_ctr0(nonce: const u8[:]) -> u8[16] {
    var a: u8[16] = [0; 16];
    a[0] = (14 - nonce.len) as! u8;
    for i in nonce.len { a[1 + i] = nonce[i]; }
    return a;
}

// Encrypts data in place and returns the tag in the first tag_len bytes
// of the block. A nonce must never repeat under one key. Lengths that
// ccm_fits refuses abort.
fn ccm_encrypt(k: const Aes&, nonce: const u8[:], aad: const u8[:], data: u8[:], tag_len: i64) -> u8[16] {
    assert(ccm_fits(nonce.len, tag_len, data.len, aad.len));
    var t = ccm_mac(k, nonce, aad, data, tag_len);
    var cb = ccm_ctr0(nonce);
    let s0 = aes_encrypt_block(k, cb);
    for i in 16 { t[i] ^= s0[i]; }
    for i in tag_len..16 { t[i] = 0; }
    ctr_increment(cb, false);
    aes_ctr_xor(k, cb, data, false);
    return t;
}

// Decrypts data in place and checks the tag (its length is the tag
// length); false, with data zeroed, when it does not match or the lengths
// are not CCM's. The comparison is constant time.
fn ccm_decrypt(k: const Aes&, nonce: const u8[:], aad: const u8[:], data: u8[:], tag: const u8[:]) -> bool {
    if !ccm_fits(nonce.len, tag.len, data.len, aad.len) {
        for &x in data { x = 0; }
        return false;
    }
    var cb = ccm_ctr0(nonce);
    let s0 = aes_encrypt_block(k, cb);
    ctr_increment(cb, false);
    aes_ctr_xor(k, cb, data, false);
    var t = ccm_mac(k, nonce, aad, data, tag.len);
    for i in 16 { t[i] ^= s0[i]; }
    if ct_eq_bytes(t[..tag.len], tag) == 0 {
        for &x in data { x = 0; }
        return false;
    }
    return true;
}

// One-shot forms: ciphertext followed by the tag, and back.
fn aes_ccm_seal(key: const u8[:], nonce: const u8[:], aad: const u8[:], plaintext: const u8[:], tag_len: i64) -> u8[>..] {
    let k = aes_init(key);
    var out: u8[>..] = [];
    out.append(plaintext);
    let t = ccm_encrypt(k, nonce, aad, out, tag_len);
    out.append(t[..tag_len]);
    return out;
}

fn aes_ccm_open(key: const u8[:], nonce: const u8[:], aad: const u8[:], sealed: const u8[:], tag_len: i64) -> u8[>..], bool {
    var out: u8[>..] = [];
    if key.len != 16 && key.len != 24 && key.len != 32 { return out, false; }
    if sealed.len < tag_len || !ccm_fits(nonce.len, tag_len, sealed.len - tag_len, aad.len) { return out, false; }
    let k = aes_init(key);
    let n = sealed.len - tag_len;
    out.append(sealed[..n]);
    let ok = ccm_decrypt(k, nonce, aad, out, sealed[n..]);
    if !ok { out.clear(); }
    return out, ok;
}
