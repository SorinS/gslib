// X25519 against vectors/x25519.txt, made by scripts/gen_vectors.py from a
// Python transcription of RFC 7748: random scalars, and u-coordinates that
// include non-canonical encodings (>= p, top bit set).
import std;
import bignum from "..";
import bignum.x25519;

fn unhex(s: const u8[:]) -> u8[32] {
    assert(s.len == 64);
    var out: u8[32] = [0; 32];
    for i in 32 {
        let v, ok = parse_int(s[2 * i..2 * i + 2], 16);
        assert(ok);
        out[i] = v as u8;
    }
    return out;
}

fn main() {
    var n = 0;
    var failures = 0;
    for line in split(embed_file("vectors/x25519.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        n++;
        let got = bignum::x25519(unhex(w[0]), unhex(w[1]));
        if got != unhex(w[2]) { failures++; print("FAIL: ", line); }
    }
    print("x25519 vectors: ", n, " checks, ", failures, " failed");
    assert(failures == 0);
}
