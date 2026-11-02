// bignum.cmac: CMAC (NIST SP 800-38B, RFC 4493) over any block cipher of
// bignum.modes with 8- or 16-byte blocks: AES-CMAC, Camellia-CMAC (RFC
// 6803's checksum), and the 64-bit ciphers. Constant time when the cipher
// is: the subkeys' conditional XOR is a mask, and only the message's
// length picks the last block's padding.

namespace bignum;

import std;
import crypto.bignum.ct;
import crypto.bignum.modes;

// One doubling in GF(2^n) (n = 8 bs): shift left by one, the reduction
// constant (0x87 for 128-bit blocks, 0x1b for 64) XORed in under a mask
// of the bit shifted out.
fn cmac_double(v: u8[:], bs: i64) {
    let top: u32 = v[0] >> 7;
    let rb: u32 = if bs == 16 { 0x87 } else { 0x1b };
    for i in bs - 1 { v[i] = v[i] << 1 | v[i + 1] >> 7; }
    let low = (ct_mask(top) & rb) as! u8;
    v[bs - 1] = v[bs - 1] << 1 ^ low;
}

// The MAC of msg under the cipher key k: one block (16 or 8 bytes).
fn cmac<K>(k: const K&, msg: const u8[:]) -> u8[>..] {
    let bs = cipher_block_len(k);
    assert(bs == 16 || bs == 8);
    var zero: u8[16] = [0; 16];
    let l = cipher_encrypt(k, zero[..bs]);
    var k1: u8[16] = [0; 16];
    for i in bs { k1[i] = l[i]; }
    cmac_double(k1, bs);
    var k2: u8[16] = [0; 16];
    for i in bs { k2[i] = k1[i]; }
    cmac_double(k2, bs);

    // All blocks but the last through CBC; the last, whole or padded with
    // 10*, XORed with K1 or K2.
    var n = (msg.len + bs - 1) / bs;
    let whole = n > 0 && msg.len % bs == 0;
    if n == 0 { n = 1; }
    var x: u8[16] = [0; 16];
    for b in n - 1 {
        for i in bs { x[i] ^= msg[b * bs + i]; }
        let e = cipher_encrypt(k, x[..bs]);
        for i in bs { x[i] = e[i]; }
    }
    let off = (n - 1) * bs;
    var last: u8[16] = [0; 16];
    let rest = msg.len - off;
    for i in rest { last[i] = msg[off + i]; }
    if whole {
        for i in bs { last[i] ^= k1[i]; }
    } else {
        last[rest] = 0x80;
        for i in bs { last[i] ^= k2[i]; }
    }
    for i in bs { x[i] ^= last[i]; }
    let t = cipher_encrypt(k, x[..bs]);
    var out: u8[>..] = [];
    out.append(t[..bs]);
    return out;
}

// Whether tag (1 to a block's bytes, a truncated CMAC being its leading
// bytes) is msg's, compared in constant time.
fn cmac_verify<K>(k: const K&, msg: const u8[:], tag: const u8[:]) -> bool {
    let t = cmac(k, msg);
    if tag.len < 1 || tag.len > t.len { return false; }
    return ct_eq_bytes(t[..tag.len], tag) == 1;
}
