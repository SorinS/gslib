// BLAKE2b, BLAKE2s, PBKDF2, scrypt and Argon2 against vectors/kdf.txt:
// BLAKE2 from hashlib at lengths around its blocks, keyed and not, at
// every output length, also fed in pieces; PBKDF2 over each hash family
// from hashlib, and RFC 6070's case; scrypt from hashlib with RFC 7914's
// cases; Argon2d, Argon2i and Argon2id from RFC 9106 §5 and openssl, with
// and without a secret and associated data, over 1 to 4 lanes and memory
// that crosses segment and address-block boundaries.
import std;
import bignum from "..";
import bignum.blake2;
import bignum.kdf;
import bignum.argon2;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

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

fn num(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s, 10);
    assert(ok);
    return v;
}

fn main() {
    for line in split(embed_file("vectors/kdf.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "blake2b" || w[0] == "blake2s" {
            let n = num(w[1]);
            let key = unhex(w[2]);
            let m = unhex(w[3]);
            let want = unhex(w[4]);
            if w[0] == "blake2b" {
                check(line, bignum::blake2b(m, n, key) == want);
                var s = bignum::blake2b_init(n, key);
                var off = 0;
                var step = 1;
                while off < m.len {
                    let end = ::min(m.len, off + step);
                    bignum::blake2b_update(s, m[off..end]);
                    off = end;
                    step += 7;
                }
                check(line, bignum::blake2b_final(s) == want);
            } else {
                check(line, bignum::blake2s(m, n, key) == want);
                var s = bignum::blake2s_init(n, key);
                var off = 0;
                var step = 1;
                while off < m.len {
                    let end = ::min(m.len, off + step);
                    bignum::blake2s_update(s, m[off..end]);
                    off = end;
                    step += 5;
                }
                check(line, bignum::blake2s_final(s) == want);
            }
        } else if w[0] == "pbkdf2" {
            let dk = bignum::pbkdf2(num(w[1]), unhex(w[2]), unhex(w[3]), num(w[4]), num(w[5]));
            check(line, dk == unhex(w[6]));
        } else if w[0] == "scrypt" {
            let dk, ok = bignum::scrypt(unhex(w[1]), unhex(w[2]), num(w[3]), num(w[4]), num(w[5]), 64);
            check(line, ok && dk == unhex(w[6]));
        } else if w[0] == "argon2" {
            let tag = bignum::argon2(num(w[1]), unhex(w[2]), unhex(w[3]), unhex(w[4]), unhex(w[5]),
                                     num(w[6]), num(w[7]), num(w[8]), num(w[9]));
            check(line, tag == unhex(w[10]));
        }
    }
    // scrypt refuses bad parameters.
    let a, ok1 = bignum::scrypt("p", "s", 3, 1, 1, 32);
    check("n not a power of 2", !ok1);
    let b, ok2 = bignum::scrypt("p", "s", 1, 1, 1, 32);
    check("n = 1", !ok2);
    let c, ok3 = bignum::scrypt("p", "s", 16, 0, 1, 32);
    check("r = 0", !ok3);
    let d, ok4 = bignum::scrypt("p", "s", 16, 1 << 20, 1 << 10, 32);
    check("r * p too big", !ok4);
    // Go's names give the same tags.
    check("IDKey", bignum::argon2id_key("pw", "somesalt", 1, 64, 2, 32)
                   == bignum::argon2(bignum::ARGON2ID, "pw", "somesalt", "", "", 1, 64, 2, 32));
    print("kdf vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
