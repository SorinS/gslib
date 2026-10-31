// bignum.rsa's API: generated keys, the checks made when loading a key,
// the raw operations' input checks, and signatures and ciphertexts that
// must not verify or decrypt under another key.
import std;
import bignum from "..";
import bignum.rsa;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn hex(s: const u8[:]) -> bignum::BigInt {
    let v, ok = bignum::parse(s, 16);
    assert(ok);
    return v;
}

fn main() {
    let key = bignum::rsa_generate(1024);
    let pub = bignum::rsa_public(key);
    check("bits", bignum::rsa_bits(key) == 1024 && bignum::rsa_size(pub) == 128);
    let n = bignum::big_of(key.n);
    let e = bignum::big_of(key.e);
    let d = bignum::big_of(key.d);
    let p = bignum::big_of(key.p);
    let q = bignum::big_of(key.q);
    check("e", bignum::cmp_i64(e, 65537) == 0);
    check("n = pq", bignum::eq(bignum::mul(p, q), n) && bignum::gt(p, q));
    check("primes of 512 bits", bignum::bit_len(p) == 512 && bignum::bit_len(q) == 512);
    let x = bignum::from_u64(123456789);
    check("e d", bignum::eq(bignum::modpow(bignum::modpow(x, e, n), d, n), x));

    // A key loads back from its numbers, and bad numbers are refused.
    let k2, ok2 = bignum::rsa_key_from(n, e, d, p, q);
    check("reload", ok2 && k2.dp == key.dp && k2.qinv == key.qinv);
    let k3, ok3 = bignum::rsa_key_from(n, e, d, p, bignum::add(q, bignum::big(2)));
    check("p q != n", !ok3);
    let k4, ok4 = bignum::rsa_key_from(n, e, bignum::add(d, bignum::big(2)), p, q);
    check("wrong d", !ok4);
    let k5, ok5 = bignum::rsa_key_from(n, bignum::big(65536), d, p, q);
    check("even e", !ok5);
    let p5, okp5 = bignum::rsa_public_from(bignum::sub(bignum::shl(bignum::one(), 511), bignum::one()), e);
    check("too small", !okp5);
    let p6, okp6 = bignum::rsa_public_from(n, n);
    check("e >= n", !okp6);
    let p7, okp7 = bignum::rsa_public_from(n, e);
    check("public from", okp7 && p7.n == pub.n && p7.e == pub.e);

    // A q that is not prime, with d an inverse of e mod lcm(p - 1, q - 1):
    // every other check passes, but the CRT is wrong, so the pairwise
    // test refuses the key (rather than every private operation aborting).
    let cn = hex("81d8e20a55fbf97eb46c7b74781c50cb2e2f94ac6290dc266d9dc4f588d359e138a51779ab3628f339f94f425cd6e42e6e00e6cd050323b77aedf0992598632bea847420767bfc8d9be52ff1399c77a561057021a6fbbe7df0582266fb13365defa32ffec2c245a01bf39d1f08e60c27fd80a7b349ea8ade1b6d1d2d3a91aca7");
    let cd = hex("3d11ab261f509604308940fb032e96152950b984e60aa96fed6821653587e9a2d2885ae51f5026ac565cda19251ef04ca1f20c9aea3b92c5cdac30d766662865a840bfb9c1dc605940446e599623828377af19425ae522a11b4e2cfe35e2f3fe65fe49dd4ce8c16fbaf2b0b6edae181756a46e295b05b3c59888cd7ef2093c61");
    let cp = hex("c40604f710c585d427e7e8d4dffc618bb47766162ece0b4e1e909f185d49a68e093175558f3e6a39781020e6633dd215d95cb4d93b50fba30c2dbf9991fb80f1");
    let cq = hex("a99374a17d61dcc2aac445a83a1f30257fd99a5faf90509fa302415119c751fdd021488c06a3daee8a279c11535dbec176c1cbc8d8b69f42001a72889b9a8717");
    let kc, okc = bignum::rsa_key_from(cn, e, cd, cp, cq);
    check("composite q", !okc);

    // p and q 2^401 apart, under Go's |p - q| > 2^(nbits/2 - 100): Fermat
    // factors n, so the key is refused either way round.
    let fn_ = hex("ee3e97aba4e6c66914ec2c41e43e3f1ca8c70e2b9bd3235f7473c0bff70e6b75bbb3308342e4bdcc54fa4b1814099859578ba1f805478c3a2955cbb42dd9112c206ca9263558d731e52873973a8a1ef668294f0c31bf85641892fe60f3a760afaa4638a989a8e5f28c5ad9a447b9f6a449c0af38f3555527e0d110675e9ea967");
    let fd = hex("5060a8adfd93e843a28ded7e8b811eacce1a5e23034ef003afd7afa3743816b4214fdaa1a64b62e75192220cad11f1a6cebceab7b11c4ae882729227a7423122d1e7bbed2b560d6da17406d0e1e384e9e4fcf6d4980dfac3969656d204b3ea156859f799a823317d06b407c7f274075661d2154a6395667494f395e1c8cbb9c1");
    let fp = hex("f6f675cc81e74ef5e8e25d940ed904759531985d5d9dc9f81818e811892f902bd23f0824128b2f330c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b7a7");
    let fq = hex("f6f675cc81e74ef5e8e25d940eda04759531985d5d9dc9f81818e811892f902bd23f0824128b2f330c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b841");
    let kf1, okf1 = bignum::rsa_key_from(fn_, e, fd, fp, fq);
    let kf2, okf2 = bignum::rsa_key_from(fn_, e, fd, fq, fp);
    check("p q too close", !okf1 && !okf2);

    // Go's bounds on the public key: 1024 bits or more, and 3 <= e < 2^31.
    let p8, okp8 = bignum::rsa_public_from(bignum::sub(bignum::shl(bignum::one(), 1023), bignum::one()), e);
    check("1023 bits", !okp8);
    // And 8192 bits at most, Go's limit for TLS peers' keys.
    let n8192 = bignum::sub(bignum::shl(bignum::one(), 8192), bignum::one());
    let p9, okp9 = bignum::rsa_public_from(n8192, e);
    let n8193 = bignum::add(bignum::shl(bignum::one(), 8192), bignum::one());
    let p10, okp10 = bignum::rsa_public_from(n8193, e);
    check("8192 bits taken, 8193 refused", okp9 && bignum::rsa_bits(p9) == 8192 && !okp10);
    let p9, okp9 = bignum::rsa_public_from(n, bignum::add(bignum::shl(bignum::one(), 31), bignum::one()));
    let p10, okp10 = bignum::rsa_public_from(n, bignum::sub(bignum::shl(bignum::one(), 31), bignum::one()));
    check("e 2^31 + 1", !okp9 && okp10);

    // Encryption (constant time) agrees with the variable-time public
    // operation.
    var em2: u8[>..] = [];
    em2.resize(128, 7);
    em2[0] = 0;
    let c1, okc1 = bignum::rsa_public_op(pub, em2);
    let c2, okc2 = bignum::rsa_public_op_ct(pub, em2);
    check("public op ct", okc1 && okc2 && c1 == c2);
    let c3, okc3 = bignum::rsa_public_op_ct(pub, bignum::to_bytes_be(n, 128));
    check("public op ct: n", !okc3);

    // Raw operations: k bytes below n, and they invert each other.
    var m: u8[>..] = [];
    m.resize(128, 0);
    m[127] = 42;
    let c, okc = bignum::rsa_public_op(pub, m);
    let m2, okm = bignum::rsa_private_op(key, c);
    check("raw round trip", okc && okm && m2 == m);
    let nb = bignum::to_bytes_be(n, 128);
    let r1, okr1 = bignum::rsa_public_op(pub, nb);
    check("public op x = n", !okr1);
    let r2, okr2 = bignum::rsa_private_op(key, nb);
    check("private op x = n", !okr2);
    let r3, okr3 = bignum::rsa_private_op(key, m[1..]);
    check("private op short", !okr3);
    var zero: u8[>..] = [];
    zero.resize(128, 0);
    let r4, okr4 = bignum::rsa_private_op(key, zero);
    check("private op 0", okr4 && r4 == zero);

    // Signatures and ciphertexts are bound to their key.
    let other = bignum::rsa_generate(1024);
    let s1, ok_s1 = bignum::rsa_sign_pkcs1(key, "message");
    let s2, ok_s2 = bignum::rsa_sign_pss(key, "message");
    check("pkcs1", ok_s1 && bignum::rsa_verify_pkcs1(pub, "message", s1));
    check("pss", ok_s2 && bignum::rsa_verify_pss(key, "message", s2));
    // Signing fails, as Go's does, for a key too small for the hash and
    // salt, and for a hash with no DigestInfo.
    let s4, ok_s4 = bignum::rsa_sign_pss(key, "message", -1, 512);
    check("pss sha512 on 1024 bits", !ok_s4 && s4.len == 0);
    let s5, ok_s5 = bignum::rsa_sign_pkcs1(key, "message", bignum::HASH_BLAKE2B_512);
    check("pkcs1 blake2b", !ok_s5 && s5.len == 0);
    check("pkcs1 other key", !bignum::rsa_verify_pkcs1(other, "message", s1));
    check("pss other key", !bignum::rsa_verify_pss(other, "message", s2));
    check("pkcs1 is not pss", !bignum::rsa_verify_pss(pub, "message", s1));
    // Over a digest, as Go's SignPKCS1v15 and SignPSS take one.
    let d256 = bignum::hash_bits(256, "message");
    let d384 = bignum::hash_bits(384, "message");
    let s6, ok_s6 = bignum::rsa_sign_pkcs1_digest(key, d256);
    check("pkcs1 digest", ok_s6 && s6 == s1);
    check("pkcs1 digest verifies", bignum::rsa_verify_pkcs1_digest(pub, d256, s1));
    check("pkcs1 digest other", !bignum::rsa_verify_pkcs1_digest(pub, bignum::hash_bits(256, "messagf"), s1));
    let s7, ok_s7 = bignum::rsa_sign_pkcs1_digest(key, d384, 384);
    check("pkcs1 digest sha384", ok_s7 && bignum::rsa_verify_pkcs1(pub, "message", s7, 384));
    let s8, ok_s8 = bignum::rsa_sign_pkcs1_digest(key, d384);
    check("pkcs1 digest length", !ok_s8 && s8.len == 0);
    check("pkcs1 verify digest length", !bignum::rsa_verify_pkcs1_digest(pub, d384, s1));
    check("pss digest verifies", bignum::rsa_verify_pss_digest(pub, d256, s2));
    check("pss digest other", !bignum::rsa_verify_pss_digest(pub, bignum::hash_bits(256, "messagf"), s2));
    let s9, ok_s9 = bignum::rsa_sign_pss_digest(key, d384, -1, 384);
    check("pss digest sha384", ok_s9 && bignum::rsa_verify_pss(pub, "message", s9, -1, 384));
    let s10, ok_s10 = bignum::rsa_sign_pss_digest(key, d384);
    check("pss digest length", !ok_s10 && s10.len == 0);
    check("pss verify digest length", !bignum::rsa_verify_pss_digest(pub, d384, s2));
    let biggest = bignum::rsa_oaep_max(pub);
    check("oaep max", biggest == 62);
    var long: u8[>..] = [];
    long.resize(biggest, 7);
    let ct = bignum::rsa_encrypt_oaep(pub, long, "label");
    let back, okb = bignum::rsa_decrypt_oaep(key, ct, "label");
    check("oaep longest", okb && back == long);
    let none, okn = bignum::rsa_decrypt_oaep(other, ct, "label");
    check("oaep other key", !okn && none.len == 0);
    // A valid RSA input that is not an OAEP block.
    let s3, oks3 = bignum::rsa_public_op(pub, m);
    let junk, okj = bignum::rsa_decrypt_oaep(key, s3);
    check("oaep junk", oks3 && !okj);

    print("rsa api: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
