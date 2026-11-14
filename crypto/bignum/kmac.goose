// bignum.kmac: KMAC128 and KMAC256 (NIST SP 800-185 §4), the keyed MAC
// built on cSHAKE: cSHAKE(bytepad(encode_string(K), rate) || X ||
// right_encode(L), "KMAC", S). The output length L is part of the input,
// so a shorter MAC is not a prefix of a longer one. Constant time: Keccak
// is, and only the lengths decide anything.
//
//   let tag = bignum::kmac(256, key, data, 32, "custom");

namespace bignum;

import std;
import crypto.bignum.sha3;

// right_encode (SP 800-185 §2.3.1): x in as few big-endian bytes as it
// takes (at least one), then their count.
fn right_encode(out: u8[>..]&, x: u64) {
    var n = 1;
    while n < 8 && (x >> (8 * n)) != 0 { n++; }
    var i = n;
    while i > 0 {
        i--;
        out.push((x >> (8 * i)) as! u8);
    }
    out.push(n as! u8);
}

// KMAC128 (bits 128) or KMAC256 (bits 256) of data under key, n bytes
// long, with the customization string custom.
fn kmac(bits: i64, key: const u8[:], data: const u8[:], n: i64, custom: const u8[:] = "") -> u8[>..] {
    assert((bits == 128 || bits == 256) && n >= 0);
    var s = cshake_init(bits, "KMAC", custom);
    var pre: u8[>..] = [];
    left_encode(pre, s.rate as! u64);
    left_encode(pre, 8 * key.len as! u64);
    pre.append(key);
    while pre.len % s.rate != 0 { pre.push(0); }
    sha3_update(s, pre);
    sha3_update(s, data);
    var tail: u8[>..] = [];
    right_encode(tail, 8 * n as! u64);
    sha3_update(s, tail);
    var out: u8[>..] = [];
    out.resize(n, 0);
    shake_read(s, out);
    return out;
}
