// bignum.entropy: cryptographically secure random bytes from the OS, by
// getentropy(3) (macOS, Linux, the BSDs). std's rng is splitmix64 and is
// not for keys, nor is os's random_seed, which falls back to the clocks.
//
// getentropy comes from the C library, opened at startup (spec §7.10), so
// that `goose run`, which links no C library, has it too; bignum.build
// names Linux's.

namespace bignum;

import std;

extern "c" {
    fn getentropy(p: u8&, n: u64) -> i32;
}

// Fills out with random bytes; aborts if the OS cannot provide them.
fn random_bytes(out: u8[:]) {
    var off = 0;
    while off < out.len {
        let n = ::min(out.len - off, 256);       // getentropy's limit per call
        let rc = getentropy(out[off], n as u64);
        assert(rc == 0);
        off += n;
    }
}
