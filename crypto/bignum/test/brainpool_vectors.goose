// brainpoolP256r1, P384r1 and P512r1 against vectors/brainpool.txt
// (scripts/brainpool_vectors.py: a Python transcription of SEC 1 and RFC
// 6979 holding RFC 7027's and RFC 6932's ECDH vectors, checked against
// openssl, the ecdsa package and cryptography): multiples of the generator
// including 1, 2, n - 2 and n - 1, compressed points, ECDH, deterministic
// ECDSA byte for byte, and signatures made by openssl and cryptography.
// Then points that are not on the curve or not encoded right, points of
// one curve given to another, and scalars out of range. Last, the
// general-a addition run on P-256 must give P-256's own results.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.ec;

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

fn decodes(c: const bignum::Curve&, pt: const u8[:]) -> bool {
    let p, ok = bignum::ec_decode(c, pt);
    return ok;
}

fn bad_points(c: const bignum::Curve&, good: const u8[:], sk: const u8[:]) {
    var off: u8[>..] = [];
    off.append(good);
    off[off.len - 1] ^= 1;                               // y changed: off the curve
    check("off curve", !shared_ok(c, sk, off));
    check("short", !shared_ok(c, sk, good[..good.len - 1]));
    var tag: u8[>..] = [];
    tag.append(good);
    tag[0] = 2;
    check("prefix", !shared_ok(c, sk, tag));
    var big: u8[>..] = [];
    big.push(4);
    big.append(bignum::to_bytes_be(bignum::big_of(c.p), c.len));
    big.append(good[1 + c.len..]);
    check("x >= p", !shared_ok(c, sk, big));
    var inf: u8[>..] = [];
    inf.resize(good.len, 0);
    inf[0] = 4;
    check("all zero", !shared_ok(c, sk, inf));
    var z: u8[>..] = [];
    z.resize(c.len, 0);
    check("sk 0", !shared_ok(c, z, good));
    check("sk n", !shared_ok(c, bignum::to_bytes_be(bignum::big_of(c.n), c.len), good));
}

// A point's compressed form decodes back to it, and its negation has the
// other prefix and sums with it to infinity.
fn compressed(c: const bignum::Curve&, u: const u8[:]) {
    let p, ok = bignum::ec_decode(c, u);
    if !ok { check("compressed: decode", false); return; }
    let enc = bignum::ec_encode_compressed(c, p);
    let q, qok = bignum::ec_decode_compressed(c, enc);
    check("compressed decode", qok && bignum::ec_encode(c, q) == u);
    let np = bignum::ec_neg(c, p);
    let n = bignum::ec_encode_compressed(c, np);
    check("compressed neg", n[0] == (enc[0] ^ 1) && n[1..] == enc[1..]);
    let r, rok = bignum::ec_decode_compressed(c, n);
    let sum = bignum::ec_add(c, r, q);
    let ax, ay, finite = bignum::ec_affine(c, sum);
    check("compressed neg decode", rok && !finite);
}

// Compressed encodings that are not points: a prefix not 02 or 03, the
// wrong length, x = p, and x values with no y (about half of them).
fn compressed_bad(c: const bignum::Curve&) {
    let gen = bignum::ec_generator(c);
    let g = bignum::ec_encode_compressed(c, gen);
    for pre in [0, 1, 4, 5, 6, 7] {
        var b: u8[>..] = [];
        b.append(g);
        b[0] = pre as! u8;
        let p, ok = bignum::ec_decode_compressed(c, b);
        check("compressed bad prefix", !ok);
    }
    let p1, ok1 = bignum::ec_decode_compressed(c, g[..g.len - 1]);
    check("compressed short", !ok1);
    var long: u8[>..] = [];
    long.append(g);
    long.push(0);
    let p2, ok2 = bignum::ec_decode_compressed(c, long);
    check("compressed long", !ok2);
    var xp: u8[>..] = [2];
    var pb: u8[>..] = [];
    pb.resize(c.len, 0);
    bignum::be_from_limbs(pb[..], c.p[..]);
    xp.append(pb);
    let p3, ok3 = bignum::ec_decode_compressed(c, xp);
    check("compressed x = p", !ok3);
    var none = 0;
    for x in 1..41 {
        var b: u8[>..] = [];
        b.resize(1 + c.len, 0);
        b[0] = 2;
        b[c.len] = x as! u8;
        let q, ok = bignum::ec_decode_compressed(c, b);
        if !ok { none++; continue; }
        let u = bignum::ec_encode(c, q);
        check("compressed small x on curve", decodes(c, u));
    }
    check("compressed some x have no point", none > 5 && none < 35);
}

fn ecdsa_line(c: const bignum::Curve&, line: const u8[:]) {
    let w = words(line);
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
    var zr = copy(raw);
    for i in c.len { zr[i] = 0; }
    check("r = 0", !bignum::ecdsa_verify(c, pk, msg, zr));
    var sn = copy(raw);
    let nb = bignum::to_bytes_be(bignum::big_of(c.n), c.len);
    for i in c.len { sn[c.len + i] = nb[i]; }
    check("s = n", !bignum::ecdsa_verify(c, pk, msg, sn));
    // -s verifies too (ECDSA's malleability), so its acceptance is right.
    var neg = copy(raw);
    let s = bignum::from_bytes_be(raw[c.len..]);
    let ns = bignum::sub(bignum::big_of(c.n), s);
    let nsb = bignum::to_bytes_be(ns, c.len);
    for i in c.len { neg[c.len + i] = nsb[i]; }
    check("n - s", bignum::ecdsa_verify(c, pk, msg, neg));
}

// The same addition law both ways: a curve with a = -3 put through the
// general formulas must give the specialised ones' results.
fn general_on_nist(c: const bignum::Curve&) {
    var g = c;
    g.a_is_minus3 = false;
    for i in 4 {
        let sk, pk = bignum::ec_keypair(c);
        check("general a: public key", bignum::ec_public_key(g, sk) == pk);
        check("general a: signature", bignum::ecdsa_sign(g, sk, "msg") == bignum::ecdsa_sign(c, sk, "msg"));
        check("general a: verify", bignum::ecdsa_verify(g, pk, "msg", bignum::ecdsa_sign(c, sk, "msg")));
        let b, bpk = bignum::ec_keypair(c);
        let s1, ok1 = bignum::ecdh_shared(g, sk, bpk);
        let s2, ok2 = bignum::ecdh_shared(c, sk, bpk);
        check("general a: ecdh", ok1 && ok2 && s1 == s2);
    }
    // p + p, p + (-p) and p + infinity, by the general formulas.
    let p = bignum::ec_generator(c);
    let d = bignum::ec_add(g, p, p);
    let d2 = bignum::ec_add(c, p, p);
    check("general a: double", bignum::ec_encode(c, d) == bignum::ec_encode(c, d2));
    let np = bignum::ec_neg(c, p);
    let z = bignum::ec_add(g, p, np);
    let zx, zy, zf = bignum::ec_affine(c, z);
    check("general a: p - p", !zf);
    let inf = bignum::ec_infinity(c);
    let i = bignum::ec_add(g, p, inf);
    check("general a: p + inf", bignum::ec_encode(c, i) == bignum::ec_encode(c, p));
}

fn main() {
    let b256 = bignum::bp256();
    let b384 = bignum::bp384();
    let b512 = bignum::bp512();
    for line in split(embed_file("vectors/brainpool.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let c = if w[1] == "bp256" { b256 } else if w[1] == "bp384" { b384 } else { b512 };
        if w[0] == "mul" {
            let k, ok = bignum::parse(w[2], 16);
            check(line, bignum::ec_public_key(c, bignum::to_bytes_be(k, c.len)) == unhex(w[3]));
            compressed(c, unhex(w[3]));
        } else if w[0] == "comp" {
            let p, ok = bignum::ec_decode_compressed(c, unhex(w[2]));
            check(line, ok && bignum::ec_encode(c, p) == unhex(w[3]));
            let q, okq = bignum::ec_decode(c, unhex(w[3]));
            check(line, okq && bignum::ec_encode_compressed(c, q) == unhex(w[2]));
        } else if w[0] == "ecdh" {
            let sk = unhex(w[2]);
            let peer = unhex(w[3]);
            let s, ok = bignum::ecdh_shared(c, sk, peer);
            check(line, ok && s == unhex(w[4]));
            bad_points(c, peer, sk);
        } else if w[0] == "ecdsa" {
            ecdsa_line(c, line);
        } else if w[0] == "verify" {
            let pk = unhex(w[2]);
            let msg = unhex(w[3]);
            let raw, ok = bignum::ecdsa_sig_from_der(c, unhex(w[4]));
            check(line, ok && bignum::ecdsa_verify(c, pk, msg, raw));
            var other = copy(msg);
            other.push(1);
            check("verify: other message", !bignum::ecdsa_verify(c, pk, other, raw));
        }
    }
    for c in [b256, b384, b512] { compressed_bad(c); }
    // Points of one curve are not points of another of the same size.
    let p256 = bignum::p256();
    let g1 = bignum::ec_generator(p256);
    let g2 = bignum::ec_generator(b256);
    let gp = bignum::ec_encode(p256, g1);
    let gb = bignum::ec_encode(b256, g2);
    check("P-256 point on brainpoolP256r1", !decodes(b256, gp));
    check("brainpoolP256r1 point on P-256", !decodes(p256, gb));
    let p384 = bignum::p384();
    let g3 = bignum::ec_generator(p384);
    check("P-384 point on brainpoolP384r1", !decodes(b384, bignum::ec_encode(p384, g3)));
    // Round trips with fresh keys, and a digest from another hash.
    for c in [b256, b384, b512] {
        let a, apk = bignum::ec_keypair(c);
        let b, bpk = bignum::ec_keypair(c);
        let s1, ok1 = bignum::ecdh_shared(c, a, bpk);
        let s2, ok2 = bignum::ecdh_shared(c, b, apk);
        check("ecdh agree", ok1 && ok2 && s1 == s2 && s1.len == c.len);
        let sig = bignum::ecdsa_sign(c, a, "hello");
        check("fresh sign", bignum::ecdsa_verify(c, apk, "hello", sig));
        check("fresh other key", !bignum::ecdsa_verify(c, bpk, "hello", sig));
        let h = bignum::hash_bits(384, "hello");
        let sd = bignum::ecdsa_sign_digest(c, a, h, 384);
        check("sha-384 digest", bignum::ecdsa_verify_digest(c, apk, h, sd));
        let back, okd = bignum::ecdsa_sig_from_der(c, bignum::ecdsa_sig_to_der(sig));
        check("der round trip", okd && back == sig);
    }
    general_on_nist(p256);
    general_on_nist(p384);
    print("brainpool vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
