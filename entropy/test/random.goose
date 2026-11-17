// entropy: the OS's random bytes. Nothing random is printed, only what
// the checks found, so the expected output is the same on every run.

import std;
import gslib from "../..";
import gslib.entropy;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if ok { print("ok   ", what); } else { print("FAIL ", what); failed += 1; }
}

// No 32-byte part of b is all zero (one in 2^256 by chance).
fn every_part_set(b: const u8[:]) -> bool {
    var i = 0;
    while i < b.len {
        let end = ::min(i + 32, b.len);
        var any = false;
        for x in b[i..end] { if x != 0 { any = true; } }
        if !any { return false; }
        i = end;
    }
    return true;
}

fn main() {
    var small: u8[32] = [0; 32];
    entropy::random_bytes(small);
    check(every_part_set(small), "random_bytes fills 32 bytes");

    // More than one getentropy call (256 bytes each), not a multiple of it.
    var big: u8[>..] = [];
    big.resize(1000, 0);
    entropy::random_bytes(big);
    check(every_part_set(big), "random_bytes fills 1000 bytes, every part");

    var again: u8[32] = [0; 32];
    entropy::random_bytes(again);
    check(again[..] != small[..], "two draws differ");

    var t: u8[16] = [0; 16];
    check(entropy::try_random_bytes(t) && every_part_set(t), "try_random_bytes");

    var none: u8[>..] = [];
    entropy::random_bytes(none);
    check(entropy::try_random_bytes(none), "an empty slice");

    // A slice of a larger buffer: only that part is written.
    var mid: u8[64] = [0; 64];
    entropy::random_bytes(mid[16..48]);
    var outside = true;
    for i in 16 { if mid[i] != 0 || mid[48 + i] != 0 { outside = false; } }
    check(outside && every_part_set(mid[16..48]), "a part of a buffer, and nothing beside it");

    // Byte values are spread: each of 256 values appears in 64 KiB.
    var lots: u8[>..] = [];
    lots.resize(65536, 0);
    entropy::random_bytes(lots);
    var seen: i64[256] = [0; 256];
    for x in lots { seen[x]++; }
    var spread = true;
    for c in seen { if c < 128 || c > 384 { spread = false; } }
    check(spread, "64 KiB: every byte value about equally often");

    if failed > 0 { exit(1); }
}
