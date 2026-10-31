// ChaCha20, Poly1305 and ChaCha20-Poly1305 against vectors/chacha20.txt:
// RFC 8439's AEAD example, then random keys, counters, nonces and lengths
// around the 64-byte block (ChaCha20 and Poly1305 checked against
// openssl), Poly1305 with the largest key and message limbs, and the AEAD
// opened with each part tampered with in turn.
import std;
import bignum from "..";
import bignum.chacha20;

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
    for line in split(embed_file("vectors/chacha20.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "chacha" {
            let key = unhex(w[1]);
            let ctr, ok = parse_int(w[2], 10);
            let nonce = unhex(w[3]);
            var data = unhex(w[4]);
            bignum::chacha20_xor(key, ctr as! u32, nonce, data);
            check(line, data == unhex(w[5]));
        } else if w[0] == "poly1305" {
            let key = unhex(w[1]);
            let msg = unhex(w[2]);
            let want = unhex(w[3]);
            check(line, bignum::poly1305(key, msg) == want);
            // In uneven pieces.
            var st = bignum::poly1305_init(key);
            var off = 0;
            var step = 1;
            while off < msg.len {
                let end = ::min(msg.len, off + step);
                bignum::poly1305_update(st, msg[off..end]);
                off = end;
                step += 5;
            }
            check(line, bignum::poly1305_final(st) == want);
        } else if w[0] == "aead" {
            let key = unhex(w[1]);
            let nonce = unhex(w[2]);
            let aad = unhex(w[3]);
            let pt = unhex(w[4]);
            var want = unhex(w[5]);
            want.append(unhex(w[6]));
            let sealed = bignum::chacha20_poly1305_seal(key, nonce, aad, pt);
            check(line, sealed == want);
            let opened, ok = bignum::chacha20_poly1305_open(key, nonce, aad, sealed);
            check(line, ok && opened == pt);
            var bad = copy(sealed);
            bad[bad.len - 1] ^= 1;
            let o1, ok1 = bignum::chacha20_poly1305_open(key, nonce, aad, bad);
            check("tag", !ok1 && o1.len == 0);
            if pt.len > 0 {
                var badc = copy(sealed);
                badc[0] ^= 1;
                let o2, ok2 = bignum::chacha20_poly1305_open(key, nonce, aad, badc);
                check("ciphertext", !ok2);
                var buf = copy(sealed);
                let n = pt.len;
                check("in place", !bignum::chacha20_poly1305_decrypt(key, nonce, aad, buf[..n], bad[n..]));
                var zeroed = true;
                for x in buf[..n] { if x != 0 { zeroed = false; } }
                check("zeroed", zeroed);
            }
            var bada = copy(aad);
            bada.push(0);
            let o3, ok3 = bignum::chacha20_poly1305_open(key, nonce, bada, sealed);
            check("aad", !ok3);
            var badn = copy(nonce);
            badn[11] ^= 0x80;
            let o4, ok4 = bignum::chacha20_poly1305_open(key, badn, aad, sealed);
            check("nonce", !ok4);
        }
    }
    // A tag of the wrong length fails (and zeroes the data) rather than
    // aborting.
    let k32: u8[32] = [0; 32];
    var d6: u8[>..] = [];
    d6.resize(8, 1);
    check("short tag", !bignum::chacha20_poly1305_decrypt(k32, k32[..12], "", d6, k32[..15]) && d6[0] == 0);
    check("long tag", !bignum::chacha20_poly1305_decrypt(k32, k32[..12], "", d6, k32[..17]));
    // The 32-bit block counter never wraps: from 0xffffffff one block
    // remains, and it is that block's keystream.
    check("fits: last block", bignum::chacha20_fits(0xffffffff, 64));
    check("fits: one byte over", !bignum::chacha20_fits(0xffffffff, 65));
    check("fits: from 0", bignum::chacha20_fits(0, 274877906944) && !bignum::chacha20_fits(0, 274877906945));
    check("fits: from 1", bignum::chacha20_fits(1, bignum::CHACHA20_POLY1305_MAX)
                          && !bignum::chacha20_fits(1, bignum::CHACHA20_POLY1305_MAX + 1));
    check("fits: empty, negative", bignum::chacha20_fits(0xffffffff, 0) && !bignum::chacha20_fits(0, -1));
    var last: u8[64] = [0; 64];
    bignum::chacha20_xor(k32, 0xffffffff, k32[..12], last);
    check("last block", last == bignum::chacha20_block(k32, 0xffffffff, k32[..12]));
    print("chacha20 vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
