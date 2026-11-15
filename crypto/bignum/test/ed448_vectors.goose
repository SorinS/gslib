// Ed448 and Ed448ph against vectors/ed448.txt (scripts/ed448_vectors.py):
// all of RFC 8032 §7.4 and §7.5, then random seeds (some from openssl
// genpkey), messages and contexts, signed by a transcription of the RFC and
// by openssl. Keys and signatures must match byte for byte and verify.
// Changed messages, contexts, signatures and keys must not, nor an Ed448
// signature taken as Ed448ph or the reverse, nor S >= L, non-canonical or
// off-curve points, x = 0 with the sign bit set, or wrong lengths.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.ed448;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what[.. ::min(what.len, 100)]); } }
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

fn verify(ph: bool, pk: const u8[:], msg: const u8[:], sig: const u8[:], ctx: const u8[:]) -> bool {
    if ph { return bignum::ed448_verify_ph(pk, bignum::ed448_prehash(msg), sig, ctx); }
    return bignum::ed448_verify(pk, msg, sig, ctx);
}

fn main() {
    let lo, okl = bignum::parse("13818066809895115352007386748515426880336692474882178609894547503885");
    assert(okl);
    let l = bignum::sub(bignum::shl(bignum::one(), 446), lo);
    for line in split(embed_file("vectors/ed448.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let ph = w[1] == "1";
        let seed = unhex(w[2]);
        let msg = unhex(w[3]);
        let ctx = unhex(w[4]);
        let pk = unhex(w[5]);
        let sig = unhex(w[6]);
        check(line, bignum::ed448_public(seed) == pk);
        if ph {
            check(line, bignum::ed448_sign_ph(seed, bignum::ed448_prehash(msg), ctx) == sig);
        } else {
            check(line, bignum::ed448_sign(seed, msg, ctx) == sig);
        }
        check(line, verify(ph, pk, msg, sig, ctx));
        // Ed448 and Ed448ph are told apart by dom4's flag.
        check("other variant", !verify(!ph, pk, msg, sig, ctx));
        var other = copy(msg);
        other.push(1);
        check("other message", !verify(ph, pk, other, sig, ctx));
        var octx = copy(ctx);
        octx.push(0);
        check("other context", !verify(ph, pk, msg, sig, octx));
        if ctx.len > 0 { check("no context", !verify(ph, pk, msg, sig, "")); }
        var badr = copy(sig);
        badr[5] ^= 1;
        check("changed R", !verify(ph, pk, msg, badr, ctx));
        var bads = copy(sig);
        bads[70] ^= 1;
        check("changed S", !verify(ph, pk, msg, bads, ctx));
        var badk = copy(pk);
        badk[0] ^= 2;
        check("changed key", !verify(ph, badk, msg, sig, ctx));
        check("short signature", !verify(ph, pk, msg, sig[..113], ctx));
        check("short key", !verify(ph, pk[..56], msg, sig, ctx));
        // S + L is the same scalar mod L, but S must be below L.
        let s = bignum::from_bytes_le(sig[57..]);
        let sl = bignum::to_bytes_le(bignum::add(s, l), 57);
        var malleable = copy(sig);
        for i in 57 { malleable[57 + i] = sl[i]; }
        check("S >= L", !verify(ph, pk, msg, malleable, ctx));
        var top = copy(sig);
        top[113] = 0x80;
        check("S byte 56", !verify(ph, pk, msg, top, ctx));
    }
    let sig: u8[114] = [0; 114];
    // y = p and y = p + 1 (non-canonical), a set bit among byte 56's low
    // seven, y = 2 (no x), and y = 1 with the sign bit (x = 0, "-0").
    var yp: u8[57] = [0xff; 57];
    yp[28] = 0xfe;
    yp[56] = 0;
    check("y = p", !bignum::ed448_verify(yp, "", sig));
    var yp1: u8[57] = [0xff; 57];
    for i in 28 { yp1[i] = 0; }
    yp1[56] = 0;
    check("y = p + 1", !bignum::ed448_verify(yp1, "", sig));
    let seed, pk = bignum::ed448_keypair();
    var hi = pk;
    hi[56] = hi[56] | 1;
    let s0 = bignum::ed448_sign(seed, "fresh");
    check("fresh", bignum::ed448_verify(pk, "fresh", s0));
    check("byte 56 low bits", !bignum::ed448_verify(hi, "fresh", s0));
    var nox: u8[57] = [0; 57];
    nox[0] = 2;
    check("not on curve", !bignum::ed448_verify(nox, "", sig));
    var negzero: u8[57] = [0; 57];
    negzero[0] = 1;
    negzero[56] = 0x80;
    check("x = 0, sign 1", !bignum::ed448_verify(negzero, "", sig));
    var long_ctx: u8[256] = [7; 256];
    check("context of 256 bytes", !bignum::ed448_verify(pk, "fresh", s0, long_ctx));
    check("context of 255 bytes", bignum::ed448_verify(pk, "fresh", bignum::ed448_sign(seed, "fresh", long_ctx[..255]), long_ctx[..255]));
    let d = bignum::ed448_prehash("fresh");
    check("digest of 63 bytes", !bignum::ed448_verify_ph(pk, d[..63], bignum::ed448_sign_ph(seed, d), ""));
    print("ed448 vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
