// SLH-DSA (FIPS 205), all twelve sets, against vectors/slhdsa.txt
// (openssl: keys from seeds, deterministic signatures under empty, short
// and 255-byte contexts, signatures with given randomness, and changed
// ones openssl refuses) and vectors/slhdsa_acvp.txt (NIST ACVP: keys,
// HashSLH-DSA under each of the twelve pre-hashes, the internal interface,
// hedged signing); see scripts/slhdsa_vectors.py. The "f" sets are signed
// here three times, SHA2-128s and SHAKE-128s once, the other "s" sets only
// verified (signing one takes seconds). Then hedged signing here, and the refusals: another
// context, message, pre-hash or set, a context past 255 bytes, wrong
// lengths.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.slhdsa;
import gslib.crypto.bignum.sha3;
import gslib.crypto.bignum.hmac;

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

// A signature, or the SHA3-256 (64 hex digits) of one to make here.
fn is_digest(s: const u8[:]) -> bool { s.len == 64 }

fn prehash_of(name: const u8[:]) -> i64 {
    if name == "SHA2-224" { return bignum::HASH_SHA224; }
    if name == "SHA2-256" { return bignum::HASH_SHA256; }
    if name == "SHA2-384" { return bignum::HASH_SHA384; }
    if name == "SHA2-512" { return bignum::HASH_SHA512; }
    if name == "SHA2-512/224" { return bignum::HASH_SHA512_224; }
    if name == "SHA2-512/256" { return bignum::HASH_SHA512_256; }
    if name == "SHA3-224" { return bignum::HASH_SHA3_224; }
    if name == "SHA3-256" { return bignum::HASH_SHA3_256; }
    if name == "SHA3-384" { return bignum::HASH_SHA3_384; }
    if name == "SHA3-512" { return bignum::HASH_SHA3_512; }
    if name == "SHAKE-128" { return bignum::SLHDSA_PH_SHAKE128; }
    assert(name == "SHAKE-256");
    return bignum::SLHDSA_PH_SHAKE256;
}

fn openssl_vectors() {
    var set: i64     = 0;
    var sk:  u8[>..] = [];
    var pk:  u8[>..] = [];
    var sig: u8[>..] = [];
    for line in split(embed_file("vectors/slhdsa.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "key" {
            set = num(w[1]);
            let seed = unhex(w[2]);
            pk = unhex(w[3]);
            let s2, p2 = bignum::slhdsa_key_from_seed(set, seed);
            check("public key", p2 == pk);
            sk = copy(s2);
            check("private key", sk.len == bignum::slhdsa_sk_len(set) && sk[..seed.len] == seed && bignum::slhdsa_public_key(set, sk) == pk);
        } else if w[0] == "sig" {
            let ctx = unhex(w[1]);
            let msg = unhex(w[2]);
            if is_digest(w[3]) {
                sig = bignum::slhdsa_sign_deterministic(set, sk, msg, ctx);
                check("deterministic", bignum::sha3(256, sig) == unhex(w[3]));
            } else {
                sig = unhex(w[3]);
            }
            check("verify", bignum::slhdsa_verify(set, pk, msg, sig, ctx));
            var ctx2 = copy(ctx);
            if ctx2.len < 255 { ctx2.push(0x5a); } else { ctx2[0] ^= 1; }
            check("other context", !bignum::slhdsa_verify(set, pk, msg, sig, ctx2));
            var msg2 = copy(msg);
            msg2.push(0);
            check("other message", !bignum::slhdsa_verify(set, pk, msg2, sig, ctx));
        } else if w[0] == "bad" {
            let ctx = unhex(w[1]);
            let msg = unhex(w[2]);
            let off = num(w[3]);
            var bad = copy(sig);
            if off == -1 { bad.resize(bad.len - 1, 0); }
            else if off == -2 { bad.push(0); }
            else { bad[off] ^= num(w[4]) as! u8; }
            check(line[.. ::min(line.len, 40)], !bignum::slhdsa_verify(set, pk, msg, bad, ctx));
        } else if w[0] == "rnd" {
            let ctx = unhex(w[1]);
            let msg = unhex(w[2]);
            let s = bignum::slhdsa_sign_with(set, sk, msg, ctx, unhex(w[3]));
            check("given randomness", bignum::sha3(256, s) == unhex(w[4]) && bignum::slhdsa_verify(set, pk, msg, s, ctx));
        }
    }
}

fn acvp_vectors() {
    for line in split(embed_file("vectors/slhdsa_acvp.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let set = num(w[1]);
        let n = bignum::slhdsa_n(set);
        if w[0] == "akey" {
            let sk, pk = bignum::slhdsa_key_from_seed(set, unhex(w[2]));
            check("ACVP key", sk == unhex(w[3]));
            continue;
        }
        let iface = w[2];
        let sk = unhex(w[4]);
        let pk = bignum::slhdsa_public_key(set, sk);
        let ctx = unhex(w[5]);
        let msg = unhex(w[6]);
        var rnd = unhex(w[7]);
        if rnd.len == 0 { rnd.append(sk[2 * n..3 * n]); }    // deterministic
        let here = is_digest(w[8]);
        var sig: u8[>..] = [];
        if iface == "internal" {
            if here { sig = bignum::slhdsa_sign_internal(set, sk, msg, rnd); } else { sig = unhex(w[8]); }
            check("ACVP internal", (!here || bignum::sha3(256, sig) == unhex(w[8])) && bignum::slhdsa_verify_internal(set, pk, msg, sig));
            check("ACVP internal is not pure", !bignum::slhdsa_verify(set, pk, msg, sig));
        } else if iface == "pure" {
            if here { sig = bignum::slhdsa_sign_with(set, sk, msg, ctx, rnd); } else { sig = unhex(w[8]); }
            check("ACVP pure", (!here || bignum::sha3(256, sig) == unhex(w[8])) && bignum::slhdsa_verify(set, pk, msg, sig, ctx));
        } else {
            let ph = prehash_of(w[3]);
            if here { sig = bignum::slhdsa_hash_sign_with(set, sk, msg, ph, ctx, rnd); } else { sig = unhex(w[8]); }
            check(str("ACVP pre-hash ", w[3]), (!here || bignum::sha3(256, sig) == unhex(w[8])) &&
                  bignum::slhdsa_hash_verify(set, pk, msg, sig, ph, ctx));
            let other = if ph == bignum::HASH_SHA256 { bignum::HASH_SHA512 } else { bignum::HASH_SHA256 };
            check("ACVP other pre-hash", !bignum::slhdsa_hash_verify(set, pk, msg, sig, other, ctx));
            check("ACVP pre-hash is not pure", !bignum::slhdsa_verify(set, pk, msg, sig, ctx));
        }
    }
}

fn main() {
    openssl_vectors();
    acvp_vectors();
    // Sizes and names of every set (FIPS 205 Table 2).
    let pks:  i64[6] = [32, 32, 48, 48, 64, 64];
    let sigs: i64[6] = [7856, 17088, 16224, 35664, 29792, 49856];
    for set in 1..13 {
        let i = (set - 1) % 6;
        check("sizes", bignum::slhdsa_pk_len(set) == pks[i] && bignum::slhdsa_sk_len(set) == 2 * pks[i] &&
              bignum::slhdsa_sig_len(set) == sigs[i] && bignum::slhdsa_seed_len(set) == 3 * pks[i] / 2);
        check("name", bignum::slhdsa_set_of_name(bignum::slhdsa_name(set)) == set);
    }
    check("no such name", bignum::slhdsa_set_of_name("SLH-DSA-SHA2-128") == 0);
    // A key pair from the OS, hedged signing, and refusals, on a fast set.
    let set = bignum::SLHDSA_SHAKE_128F;
    let sk, pk = bignum::slhdsa_keygen(set);
    check("generated key", sk.len == 64 && pk.len == 32 && bignum::slhdsa_check_key(set, sk));
    var badkey = copy(sk);
    badkey[63] ^= 1;
    check("key with a wrong root", !bignum::slhdsa_check_key(set, badkey));
    let a = bignum::slhdsa_sign(set, sk, "", "ctx");
    let b = bignum::slhdsa_sign(set, sk, "", "ctx");
    check("hedged here", a != b && bignum::slhdsa_verify(set, pk, "", a, "ctx") && bignum::slhdsa_verify(set, pk, "", b, "ctx"));
    let h = bignum::slhdsa_hash_sign(set, sk, "m", bignum::HASH_SHA3_256);
    check("hedged pre-hash", bignum::slhdsa_hash_verify(set, pk, "m", h, bignum::HASH_SHA3_256) &&
          !bignum::slhdsa_hash_verify(set, pk, "m", h, bignum::HASH_SHA3_256, "x"));
    check("no such pre-hash", !bignum::slhdsa_hash_verify(set, pk, "m", h, bignum::HASH_SHA1));
    var long_ctx: u8[256] = [7; 256];
    check("context too long", !bignum::slhdsa_verify(set, pk, "", a, long_ctx) &&
          !bignum::slhdsa_hash_verify(set, pk, "m", h, bignum::HASH_SHA3_256, long_ctx));
    check("short signature", !bignum::slhdsa_verify(set, pk, "", a[..a.len - 1], "ctx"));
    check("short key", !bignum::slhdsa_verify(set, pk[..pk.len - 1], "", a, "ctx"));
    check("other set", !bignum::slhdsa_verify(bignum::SLHDSA_SHA2_128F, pk, "", a, "ctx"));
    check("no such set", !bignum::slhdsa_verify(13, pk, "", a, "ctx") && !bignum::slhdsa_verify(0, pk, "", a, "ctx"));
    print("slhdsa vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
