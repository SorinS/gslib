// ML-KEM-512, -768 and -1024 against vectors/mlkem.txt, made by openssl:
// the encapsulation and expanded decapsulation keys of a seed must match
// openssl's byte for byte; openssl's ciphertexts must decapsulate to its
// shared secrets, and changed ones to the same implicit rejection keys
// openssl gives. Then encapsulation here, round trips, and malformed keys
// and ciphertexts.
import std;
import bignum from "..";
import bignum.mlkem;

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
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn main() {
    for line in split(embed_file("vectors/mlkem.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let k, okk = parse_int(w[1], 10);
        let seed = unhex(w[2]);
        if w[0] == "mlkem" {
            let ek, dk = bignum::mlkem_keys_from_seed(k, seed);
            check("ek", ek == unhex(w[3]));
            check("dk", dk == unhex(w[4]));
            // Round trips with encapsulation here.
            let ss, ct, ok = bignum::mlkem_encaps(k, ek);
            let ss2, ok2 = bignum::mlkem_decaps(k, seed, ct);
            check("round trip", ok && ok2 && ss == ss2 && ct.len == bignum::mlkem_ct_len(k));
            let ss3, ok3 = bignum::mlkem_decaps_dk(k, dk, ct);
            check("round trip dk", ok3 && ss3 == ss);
            // A coefficient of q or more makes ek malformed.
            var bad = copy(ek);
            bad[0] = 0xff;
            bad[1] = bad[1] | 0x0f;
            let s4, c4, ok4 = bignum::mlkem_encaps(k, bad);
            check("ek modulus check", !ok4 && !bignum::mlkem_ek_ok(k, bad) && bignum::mlkem_ek_ok(k, ek));
            let s5, c5, ok5 = bignum::mlkem_encaps(k, ek[1..]);
            check("ek length", !ok5);
            // A dk whose hash of ek is wrong is refused.
            var bdk = copy(dk);
            bdk[768 * k + 40] ^= 1;
            let s6, ok6 = bignum::mlkem_decaps_dk(k, bdk, ct);
            check("dk hash check", !ok6);
            let s7, ok7 = bignum::mlkem_decaps(k, seed, ct[1..]);
            check("ct length", !ok7);
        } else if w[0] == "encap" || w[0] == "reject" {
            let ss, ok = bignum::mlkem_decaps(k, seed, unhex(w[3]));
            check(w[0], ok && ss == unhex(w[4]));
        }
    }
    // Deterministic encapsulation: the same message, the same output.
    let seed: u8[64] = [7; 64];
    let ek, dk = bignum::mlkem_keys_from_seed(3, seed);
    let m: u8[32] = [9; 32];
    let a1, c1, o1 = bignum::mlkem_encaps_with(3, ek, m);
    let a2, c2, o2 = bignum::mlkem_encaps_with(3, ek, m);
    check("deterministic", o1 && o2 && a1 == a2 && c1 == c2);
    print("mlkem vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
