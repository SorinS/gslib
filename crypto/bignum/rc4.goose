// bignum.rc4: the RC4 stream cipher, for old protocols only: its output
// is biased and it is broken (RFC 7465 bans it from TLS). As in Go, the
// state is indexed by key-dependent values, so it is not constant time.

namespace bignum;

import std;

struct Rc4 { s: u8[256], i: u8, j: u8 }

// A key of 1 to 256 bytes.
fn rc4_init(key: const u8[:]) -> Rc4 {
    assert(key.len >= 1 && key.len <= 256);
    var r = Rc4 { s: [0; 256], i: 0, j: 0 };
    for i in 256 { r.s[i] = i as! u8; }
    var j: u8 = 0;
    for i in 256 {
        j = j + r.s[i] + key[i % key.len];
        let t = r.s[i];
        r.s[i] = r.s[j];
        r.s[j] = t;
    }
    return r;
}

// data ^= the next data.len bytes of keystream.
fn rc4_xor(r: Rc4&, data: u8[:]) {
    for k in data.len {
        r.i = r.i + 1;
        r.j = r.j + r.s[r.i];
        let t = r.s[r.i];
        r.s[r.i] = r.s[r.j];
        r.s[r.j] = t;
        data[k] ^= r.s[(r.s[r.i] + r.s[r.j]) as! u8];
    }
}
