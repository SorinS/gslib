// vectors/ffdh.txt (scripts/ffdh_vectors.py, Python's pow): the MODP
// groups' primes as RFC 3526's formula gives them; 2^x mod p for exponents
// of 32 to 512 bytes; a shared secret both ways; base^x mod p for random
// bases; then the range check, and keys made here agreeing.
import std;
import bignum from "..";
import bignum.ffdh;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
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
    for line in split(embed_file("vectors/ffdh.txt"), '\n') {
        let w = words(line);
        if w.len < 3 { continue; }
        let g, okg = parse_int(w[1], 10);
        let p = bignum::ffdh_prime(g);
        if w[0] == "prime" {
            check(str("prime ", w[1]), p == unhex(w[2]));
        } else if w[0] == "pub" {
            let two: u8[1] = [2];
            check(str("pub ", w[1]), bignum::ffdh_modexp(two, unhex(w[2]), p) == unhex(w[3]));
        } else if w[0] == "shared" {
            let two: u8[1] = [2];
            let xa = unhex(w[2]);
            let xb = unhex(w[3]);
            let ya = bignum::ffdh_modexp(two, xa, p);
            let yb = bignum::ffdh_modexp(two, xb, p);
            let sa, oka = bignum::ffdh_shared(xa, yb, p);
            let sb, okb = bignum::ffdh_shared(xb, ya, p);
            check(str("shared ", w[1]), oka && okb && sa == unhex(w[4]) && sb == sa);
        } else {
            check(str("pow ", w[1]), bignum::ffdh_modexp(unhex(w[2]), unhex(w[3]), p) == unhex(w[4]));
        }
    }
    // The range check: 0, 1 and p - 1 are refused, 2 and p - 2 taken.
    let p = bignum::ffdh_prime(14);
    var pm1 = copy(p);
    pm1[pm1.len - 1] -= 1;
    var pm2 = copy(p);
    pm2[pm2.len - 1] -= 2;
    let zero: u8[1] = [0];
    let one: u8[1] = [1];
    let two: u8[1] = [2];
    check("range", !bignum::ffdh_value_ok(zero, p) && !bignum::ffdh_value_ok(one, p) && !bignum::ffdh_value_ok(pm1, p) &&
          !bignum::ffdh_value_ok(p, p) && bignum::ffdh_value_ok(two, p) && bignum::ffdh_value_ok(pm2, p));
    let s0, ok0 = bignum::ffdh_shared(two, one, p);
    check("shared refuses 1", !ok0);
    // Keys made here agree.
    let xa, ya = bignum::ffdh_keygen(p, 64);
    let xb, yb = bignum::ffdh_keygen(p, 64);
    let sa, oka = bignum::ffdh_shared(xa, yb, p);
    let sb, okb = bignum::ffdh_shared(xb, ya, p);
    check("keygen", oka && okb && sa == sb && xa.len == 64 && ya.len == 256);
    print("ffdh: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
