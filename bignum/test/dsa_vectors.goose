// vectors/dsa.txt: DSA against openssl for (L, N) = (1024, 160), (2048,
// 224), (2048, 256) and (3072, 256): deterministic signatures (RFC 6979)
// over SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 digests, reproduced
// byte for byte and read from DER; random-nonce ones, verified; and
// changed ones that must fail. Digests longer than q are cut to its
// leftmost N bits. Then keys and signatures made here, generated
// parameters, and refusals.
import std;
import bignum from "..";
import bignum.dsa;

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
    var key = bignum::DsaKey { p: [], q: [], g: [], y: [], x: [] };
    var pub = bignum::DsaKey { p: [], q: [], g: [], y: [], x: [] };
    for line in split(embed_file("vectors/dsa.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "key" {
            let k, ok = bignum::dsa_key_from(unhex(w[1]), unhex(w[2]), unhex(w[3]), unhex(w[4]), unhex(w[5]));
            check("key", ok);
            key = k;
            pub = bignum::dsa_public(k);
            let sig = bignum::dsa_sign(key, "0123456789abcdef0123");
            check("random nonce", bignum::dsa_verify(pub, "0123456789abcdef0123", sig) &&
                  bignum::dsa_sign(key, "0123456789abcdef0123") != sig);
            check("other digest", !bignum::dsa_verify(pub, "0123456789abcdef0124", sig));
        } else if w[0] == "det" {
            let d = unhex(w[2]);
            let raw = unhex(w[3]);
            check(line[..20], bignum::dsa_sign_deterministic(key, d, num(w[1])) == raw);
            check("verify", bignum::dsa_verify(pub, d, raw));
            let fromder, ok = bignum::dsa_sig_from_der(pub, unhex(w[4]));
            check("der", ok && fromder == raw && bignum::dsa_sig_to_der(raw) == unhex(w[4]));
        } else if w[0] == "rnd" {
            let raw, ok = bignum::dsa_sig_from_der(pub, unhex(w[2]));
            check("openssl random nonce", ok && bignum::dsa_verify(pub, unhex(w[1]), raw));
        } else if w[0] == "bad" {
            check("changed", !bignum::dsa_verify(pub, unhex(w[1]), unhex(w[2])));
        }
    }
    // r and s out of range, wrong lengths, and bad keys.
    let d: u8[20] = [3; 20];
    let sig = bignum::dsa_sign(key, d);
    let w = key.q.len;
    var zero_r: u8[>..] = [];
    zero_r.resize(w, 0);
    zero_r.append(sig[w..]);
    check("r = 0", !bignum::dsa_verify(pub, d, zero_r));
    var big_s: u8[>..] = [];
    big_s.append(sig[..w]);
    big_s.append(key.q);
    check("s = q", !bignum::dsa_verify(pub, d, big_s));
    check("short", !bignum::dsa_verify(pub, d, sig[..sig.len - 1]));
    let k1, ok1 = bignum::dsa_key_from(key.p, key.q, key.g, key.y, key.q);
    check("x = q", !ok1);
    let k1z, ok1z = bignum::dsa_key_from(key.p, key.q, key.g, key.y, "\x00\x00");
    check("x = 0", !ok1z);
    var xpad: u8[>..] = [0, 0];
    xpad.append(key.x);
    let k1p, ok1p = bignum::dsa_key_from(key.p, key.q, key.g, key.y, xpad);
    check("x with leading zeros", ok1p && k1p.x == key.x);
    let k1s, ok1s = bignum::dsa_key_from(key.p, key.q, key.g, key.y, "\x05");
    check("x of one byte", ok1s && k1s.x.len == key.q.len && k1s.x[k1s.x.len - 1] == 5 && k1s.x[0] == 0);
    var xlong: u8[>..] = [1];
    xlong.append(key.x);
    let k1l, ok1l = bignum::dsa_key_from(key.p, key.q, key.g, key.y, xlong);
    check("x too long", !ok1l);
    let k2, ok2 = bignum::dsa_key_from(key.p, key.q, "\x01", key.y);
    check("g = 1", !ok2);
    var q192: u8[24] = [0xff; 24];
    let k3, ok3 = bignum::dsa_key_from(key.p, q192, key.g, key.y);
    check("q of 192 bits", !ok3);
    // Fresh parameters and a key on them.
    let p, q, g = bignum::dsa_generate_parameters(1024, 160);
    let nk, okn = bignum::dsa_generate_key(p, q, g);
    check("generated", p.len == 128 && q.len == 20 && okn && (p[0] & 0x80) != 0 && (q[0] & 0x80) != 0);
    let s2 = bignum::dsa_sign(nk, "a digest of twenty b");
    let npub = bignum::dsa_public(nk);
    check("generated key signs", bignum::dsa_verify(npub, "a digest of twenty b", s2));
    // Primality at the small end, where trial division meets Miller-Rabin.
    let primes = bignum::small_primes();
    var prime_ok = true;
    for v in [-7, 0, 1, 4, 9, 15, 25, 1001, 3999, 4001 * 4003, 561, 1105, 2047] {
        if bignum::dsa_probably_prime(bignum::big(v), primes) { prime_ok = false; print("composite called prime: ", v); }
    }
    for v in [2, 3, 5, 7, 97, 101, 251, 257, 1999, 2003, 65537, 4001 * 1000 + 3] {
        if !bignum::dsa_probably_prime(bignum::big(v), primes) { prime_ok = false; print("prime called composite: ", v); }
    }
    check("dsa_probably_prime at the small end", prime_ok);
    print("dsa vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
