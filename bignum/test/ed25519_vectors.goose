// Ed25519 against vectors/ed25519.txt: RFC 8032's tests 1 to 3, then
// random seeds and messages signed by a transcription of the RFC and by
// openssl. Signatures must match byte for byte and verify; changed
// messages, signatures and keys, S >= L, and non-canonical encodings must
// not.
import std;
import bignum from "..";
import bignum.ed25519;

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

fn main() {
    for line in split(embed_file("vectors/ed25519.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let seed = unhex(w[1]);
        let msg = unhex(w[2]);
        let pk = unhex(w[3]);
        let sig = unhex(w[4]);
        check(line, bignum::ed25519_public(seed) == pk);
        check(line, bignum::ed25519_sign(seed, msg) == sig);
        check(line, bignum::ed25519_verify(pk, msg, sig));
        var other = copy(msg);
        other.push(1);
        check("other message", !bignum::ed25519_verify(pk, other, sig));
        var badr = copy(sig);
        badr[5] ^= 1;
        check("changed R", !bignum::ed25519_verify(pk, msg, badr));
        var bads = copy(sig);
        bads[40] ^= 1;
        check("changed S", !bignum::ed25519_verify(pk, msg, bads));
        var badk = copy(pk);
        badk[0] ^= 2;
        check("changed key", !bignum::ed25519_verify(badk, msg, sig));
        // S + L is the same scalar mod L, but S must be below L.
        let s = bignum::from_bytes_le(sig[32..]);
        let lo, okl = bignum::parse("27742317777372353535851937790883648493");
        let l = bignum::add(bignum::shl(bignum::one(), 252), lo);
        let sl = bignum::add(s, l);
        if bignum::bit_len(sl) <= 256 {
            var malleable = copy(sig);
            let b = bignum::to_bytes_le(sl, 32);
            for i in 32 { malleable[32 + i] = b[i]; }
            check("S >= L", !bignum::ed25519_verify(pk, msg, malleable));
        }
    }
    // y = p (non-canonical) and a y with no x are refused as keys.
    var yp: u8[32] = [0xff; 32];
    yp[0] = 0xed;
    yp[31] = 0x7f;
    let sig: u8[64] = [0; 64];
    check("y = p", !bignum::ed25519_verify(yp, "", sig));
    var nox: u8[32] = [0; 32];
    nox[0] = 2;                                          // y = 2 is not on the curve
    check("not on curve", !bignum::ed25519_verify(nox, "", sig));
    let seed, pk = bignum::ed25519_keypair();
    let s2 = bignum::ed25519_sign(seed, "fresh");
    check("fresh", bignum::ed25519_verify(pk, "fresh", s2));
    print("ed25519 vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
