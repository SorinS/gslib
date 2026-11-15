// X448 against vectors/x448.txt, made by scripts/ed448_vectors.py from a
// Python transcription of RFC 7748 and checked against openssl: random
// scalars (some from openssl genpkey) and u-coordinates that include
// non-canonical encodings (p and above). Then the low-order points, whose
// all-zero secret x448_shared reports, and fresh key pairs.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.x448;

fn unhex(s: const u8[:]) -> u8[56] {
    assert(s.len == 112);
    var out: u8[56] = [0; 56];
    for i in 56 {
        let v, ok = parse_int(s[2 * i..2 * i + 2], 16);
        assert(ok);
        out[i] = v as! u8;
    }
    return out;
}

fn main() {
    var n = 0;
    var failures = 0;
    for line in split(embed_file("vectors/x448.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        n++;
        let got = bignum::x448(unhex(w[1]), unhex(w[2]));
        if got != unhex(w[3]) { failures++; print("FAIL: ", line); }
    }
    // u = 0, 1 and p - 1 (= -1) have order dividing 4 (with p and p + 1,
    // their non-canonical forms): the secret is zero, which must be refused.
    var low: u8[56][>..] = [];
    var u:   u8[56]      = [0; 56];
    low.push(u);
    u[0] = 1;
    low.push(u);
    var pm1: u8[56] = [0xff; 56];
    pm1[0] = 0xfe;
    pm1[28] = 0xfe;
    low.push(pm1);
    var p: u8[56] = [0xff; 56];
    p[28] = 0xfe;
    low.push(p);
    for i in 28 { p[i] = 0; }
    p[28] = 0xff;                                        // p + 1
    low.push(p);
    let sk, pk = bignum::x448_keypair();
    for l in low {
        n++;
        let s, ok = bignum::x448_shared(sk, l);
        let zero: u8[56] = [0; 56];
        if ok || s != zero { failures++; print("FAIL: low-order point accepted"); }
    }
    let sk2, pk2 = bignum::x448_keypair();
    let s1, ok1 = bignum::x448_shared(sk, pk2);
    let s2, ok2 = bignum::x448_shared(sk2, pk);
    n++;
    if !ok1 || !ok2 || s1 != s2 || pk == pk2 { failures++; print("FAIL: fresh key agreement"); }
    print("x448 vectors: ", n, " checks, ", failures, " failed");
    assert(failures == 0);
}
