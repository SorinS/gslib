// P-256 and P-384 against vectors/ec.txt, P-521 against ec521.txt and P-224 against ec224.txt (a Python transcription of SEC 1
// and RFC 6979, checked against openssl): scalar multiples of the
// generator including 1, 2, n - 2 and n - 1; ECDH; deterministic ECDSA,
// whose signatures must match byte for byte, verify, survive DER and back,
// and fail when anything changes. Then points that are not on the curve,
// or not encoded right, and scalars out of range.
import std;
import bignum from "..";
import bignum.ec;

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

fn shared_ok(c: const bignum::Curve&, sk: const u8[:], peer: const u8[:]) -> bool {
    let s, ok = bignum::ecdh_shared(c, sk, peer);
    return ok;
}

fn der_ok(c: const bignum::Curve&, der: const u8[:]) -> bool {
    let raw, ok = bignum::ecdsa_sig_from_der(c, der);
    return ok;
}

fn bad_points(c: const bignum::Curve&, good: const u8[:], sk: const u8[:]) {
    var off: u8[>..] = [];
    off.append(good);
    off[off.len - 1] ^= 1;                               // y changed: off the curve
    let s1, ok1 = bignum::ecdh_shared(c, sk, off);
    check("off curve", !ok1);
    check("short", !shared_ok(c, sk, good[..good.len - 1]));
    var tag: u8[>..] = [];
    tag.append(good);
    tag[0] = 2;                                          // compressed form: unsupported
    check("prefix", !shared_ok(c, sk, tag));
    // x = p is out of range even though x = 0 might be on the curve.
    var big: u8[>..] = [];
    big.push(4);
    big.append(bignum::to_bytes_be(bignum::big_of(c.p), c.len));
    big.append(good[1 + c.len..]);
    check("x >= p", !shared_ok(c, sk, big));
    var inf: u8[>..] = [];
    inf.resize(good.len, 0);
    inf[0] = 4;
    check("all zero", !shared_ok(c, sk, inf));
    // Private keys 0 and n are refused.
    var z: u8[>..] = [];
    z.resize(c.len, 0);
    check("sk 0", !shared_ok(c, z, good));
    check("sk n", !shared_ok(c, bignum::to_bytes_be(bignum::big_of(c.n), c.len), good));
}

fn main() {
    let c256 = bignum::p256();
    let c384 = bignum::p384();
    let c521 = bignum::p521();
    let c224 = bignum::p224();
    var all: u8[>..] = [];
    all.append(embed_file("vectors/ec.txt"));
    all.append(embed_file("vectors/ec521.txt"));
    all.append(embed_file("vectors/ec224.txt"));
    for line in split(all, '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let c = if w[1] == "p256" { c256 } else if w[1] == "p384" { c384 }
                else if w[1] == "p521" { c521 } else { c224 };
        if w[0] == "mul" {
            let k, ok = bignum::parse(w[2], 16);
            check(line, bignum::ec_public_key(c, bignum::to_bytes_be(k, c.len)) == unhex(w[3]));
        } else if w[0] == "ecdh" {
            let sk = unhex(w[2]);
            let peer = unhex(w[3]);
            let s, ok = bignum::ecdh_shared(c, sk, peer);
            check(line, ok && s == unhex(w[4]));
            bad_points(c, peer, sk);
        } else if w[0] == "ecdsa" {
            let sk = unhex(w[2]);
            let pk = unhex(w[3]);
            let msg = unhex(w[4]);
            let raw = unhex(w[5]);
            let der = unhex(w[6]);
            check(line, bignum::ec_public_key(c, sk) == pk);
            check(line, bignum::ecdsa_sign(c, sk, msg) == raw);
            check(line, bignum::ecdsa_verify(c, pk, msg, raw));
            check("to der", bignum::ecdsa_sig_to_der(raw) == der);
            let back, okd = bignum::ecdsa_sig_from_der(c, der);
            check("from der", okd && back == raw);
            var other = copy(msg);
            other.push(0);
            check("other message", !bignum::ecdsa_verify(c, pk, other, raw));
            var bad = copy(raw);
            bad[c.len + 3] ^= 0x20;
            check("changed s", !bignum::ecdsa_verify(c, pk, msg, bad));
            var swapped: u8[>..] = [];
            swapped.append(raw[c.len..]);
            swapped.append(raw[..c.len]);
            check("r s swapped", !bignum::ecdsa_verify(c, pk, msg, swapped));
            // r = 0 and s = n are out of range.
            var zr = copy(raw);
            for i in c.len { zr[i] = 0; }
            check("r = 0", !bignum::ecdsa_verify(c, pk, msg, zr));
            var sn = copy(raw);
            let nb = bignum::to_bytes_be(bignum::big_of(c.n), c.len);
            for i in c.len { sn[c.len + i] = nb[i]; }
            check("s = n", !bignum::ecdsa_verify(c, pk, msg, sn));
            // DER that is not minimal, or has trailing bytes, is refused.
            var trail = copy(der);
            trail.push(0);
            check("der trailing", !der_ok(c, trail));
            var longer = copy(der);
            longer[1] += 1;
            longer.push(0);
            check("der length", !der_ok(c, longer));
            var padded: u8[>..] = [];
            padded.push(0x30);
            padded.push(der[1] + 1);
            padded.push(2);
            padded.push(der[3] + 1);
            padded.push(0);
            padded.append(der[4..]);
            if der[4] < 0x80 && der[4] != 0 {
                check("der not minimal", !der_ok(c, padded));
            }
        }
    }
    // Round trips with fresh keys.
    for c in [c224, c256, c384, c521] {
        let a, apk = bignum::ec_keypair(c);
        let b, bpk = bignum::ec_keypair(c);
        let s1, ok1 = bignum::ecdh_shared(c, a, bpk);
        let s2, ok2 = bignum::ecdh_shared(c, b, apk);
        check("ecdh agree", ok1 && ok2 && s1 == s2 && s1.len == c.len);
        let sig = bignum::ecdsa_sign(c, a, "hello");
        check("fresh sign", bignum::ecdsa_verify(c, apk, "hello", sig));
        check("fresh other key", !bignum::ecdsa_verify(c, bpk, "hello", sig));
    }
    print("ec vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
