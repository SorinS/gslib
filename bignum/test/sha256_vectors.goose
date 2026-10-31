// SHA-256 against vectors/sha256.txt (hashlib): every length from 0 to 129
// bytes, across the padding boundaries, then longer ones; each also fed in
// uneven pieces, and MGF1 against RFC 8017's definition.
import std;
import bignum from "..";
import bignum.sha256;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn main() {
    var n = 0;
    var failures = 0;
    for line in split(embed_file("vectors/sha256.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let m = unhex(w[1]);
        let want = unhex(w[2]);
        n++;
        if bignum::sha256(m) != want { failures++; print("FAIL one-shot: ", line); }
        // The same message in pieces of 1, 2, 3, ... bytes.
        var s = bignum::sha256_init();
        var off = 0;
        var step = 1;
        while off < m.len {
            let end = ::min(m.len, off + step);
            bignum::sha256_update(s, m[off..end]);
            off = end;
            step++;
        }
        n++;
        if bignum::sha256_final(s) != want { failures++; print("FAIL pieces: ", line); }
    }
    // MGF1: block i of the mask is SHA-256(seed || i as 4 big-endian bytes).
    var mask: u8[70] = [0; 70];
    bignum::mgf1_xor(mask, "seed");
    for i in 3 {
        var buf: u8[>..] = [];
        buf.append("seed");
        let c: u8[4] = [0, 0, 0, i as! u8];
        buf.append(c);
        let d = bignum::sha256(buf);
        for k in ::min(32, 70 - 32 * i) {
            n++;
            if mask[32 * i + k] != d[k] { failures++; }
        }
    }
    print("sha256 vectors: ", n, " checks, ", failures, " failed");
    assert(failures == 0);
}
