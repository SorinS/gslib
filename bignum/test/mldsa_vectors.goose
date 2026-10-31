// vectors/mldsa.txt: ML-DSA-44, -65 and -87 (FIPS 204) against openssl:
// public keys and expanded private keys from seeds, deterministic
// signatures under empty, short and 255-byte contexts (signed again here
// byte for byte, directly and through external mu), hedged signatures,
// and changed signatures every one of which must fail, malformed hint
// encodings included. Then hedged signing here, and the refusals: another
// context or message, a context past 255 bytes, wrong lengths.
import std;
import bignum from "..";
import bignum.mldsa;
import bignum.sha3;

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
    var set: i64 = 0;
    var seed: u8[>..] = [];
    var pk: u8[>..] = [];
    var hedged_done = false;
    for line in split(embed_file("vectors/mldsa.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "key" {
            set = num(w[1]);
            seed = unhex(w[2]);
            pk = unhex(w[3]);
            check("public key", bignum::mldsa_public_key(set, seed) == pk);
            let sk = bignum::mldsa_expand_key(set, seed);
            check("expanded key", sk.len == bignum::mldsa_sk_len(set) && bignum::sha3(256, sk) == unhex(w[4]));
            hedged_done = false;
        } else if w[0] == "sig" {
            let ctx = unhex(w[1]);
            let msg = unhex(w[2]);
            let sig = unhex(w[3]);
            check("deterministic", bignum::mldsa_sign_deterministic(set, seed, msg, ctx) == sig);
            check("verify", bignum::mldsa_verify(set, pk, msg, sig, ctx));
            var ctx2: u8[>..] = [];
            ctx2.append(ctx);
            if ctx2.len < 255 { ctx2.push(0x5a); } else { ctx2[0] ^= 1; }
            check("other context", !bignum::mldsa_verify(set, pk, msg, sig, ctx2));
            var msg2: u8[>..] = [];
            msg2.append(msg);
            msg2.push(0);
            check("other message", !bignum::mldsa_verify(set, pk, msg2, sig, ctx));
            let mu, ok = bignum::mldsa_mu(pk, msg, ctx);
            check("external mu", ok && bignum::mldsa_sign_mu(set, seed, mu, true) == sig && bignum::mldsa_verify_mu(set, pk, mu, sig));
        } else if w[0] == "hedged" {
            let ctx = unhex(w[1]);
            let msg = unhex(w[2]);
            check("hedged from openssl", bignum::mldsa_verify(set, pk, msg, unhex(w[3]), ctx));
            if !hedged_done {
                let a = bignum::mldsa_sign(set, seed, msg, ctx);
                let b = bignum::mldsa_sign(set, seed, msg, ctx);
                check("hedged here", a != b && bignum::mldsa_verify(set, pk, msg, a, ctx) && bignum::mldsa_verify(set, pk, msg, b, ctx));
                let mu, ok = bignum::mldsa_mu(pk, msg, ctx);
                check("hedged mu", bignum::mldsa_verify(set, pk, msg, bignum::mldsa_sign_mu(set, seed, mu), ctx));
                hedged_done = true;
            }
        } else if w[0] == "bad" {
            check(line[..40], !bignum::mldsa_verify(set, pk, unhex(w[2]), unhex(w[3]), unhex(w[1])));
        }
    }
    // An empty message, a key pair from the OS, the sizes, and refusals.
    let sets: i64[3] = [44, 65, 87];
    let pks: i64[3] = [1312, 1952, 2592];
    let sigs: i64[3] = [2420, 3309, 4627];
    let sks: i64[3] = [2560, 4032, 4896];
    for i in 3 {
        let s = sets[i];
        let sd, p = bignum::mldsa_keygen(s);
        check("sizes", sd.len == 32 && p.len == pks[i] && bignum::mldsa_pk_len(s) == pks[i] &&
              bignum::mldsa_sig_len(s) == sigs[i] && bignum::mldsa_sk_len(s) == sks[i]);
        let sig = bignum::mldsa_sign(s, sd, "");
        check("empty message", sig.len == sigs[i] && bignum::mldsa_verify(s, p, "", sig));
        var long_ctx: u8[256] = [7; 256];
        let mu, ok = bignum::mldsa_mu(p, "m", long_ctx);
        check("context too long", !ok && !bignum::mldsa_verify(s, p, "", sig, long_ctx));
        check("short signature", !bignum::mldsa_verify(s, p, "", sig[..sig.len - 1]));
        check("short key", !bignum::mldsa_verify(s, p[..p.len - 1], "", sig));
        let other = sets[(i + 1) % 3];
        check("other set", !bignum::mldsa_verify(other, p, "", sig));
    }
    print("mldsa vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
