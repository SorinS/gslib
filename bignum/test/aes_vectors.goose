// AES against vectors/aes.txt (a FIPS 197 transcription, checked against
// openssl): the S-box and its inverse on all 256 bytes, block encryption
// and decryption at each key size, and CTR mode, including counters that
// carry across words and wrap the whole block.
import std;
import bignum from "..";
import bignum.aes;

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

// The bitsliced S-box on 32 bytes at once: plane j holds bit j of each.
fn sbox32(xs: const u8[:], inverse: bool) -> u8[32] {
    var q: u32[8] = [0; 8];
    for i in 32 {
        let x: u32 = xs[i];
        for j in 8 { q[j] = q[j] | ((x >> j) & 1) << i; }
    }
    if inverse { bignum::aes_inv_sbox(q); } else { bignum::aes_sbox(q); }
    var out: u8[32] = [0; 32];
    for i in 32 {
        for j in 8 { out[i] = out[i] | (((q[j] >> i) & 1) << j) as! u8; }
    }
    return out;
}

fn main() {
    for line in split(embed_file("vectors/aes.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "sbox" {
            let sb = unhex(w[1]);
            var xs: u8[32] = [0; 32];
            for g in 8 {
                for i in 32 { xs[i] = (32 * g + i) as! u8; }
                let fwd = sbox32(xs, false);
                for i in 32 { check("sbox", fwd[i] == sb[32 * g + i]); }
                let back = sbox32(fwd, true);
                for i in 32 { check("inv sbox", back[i] == xs[i]); }
            }
        } else if w[0] == "block" {
            let k = bignum::aes_init(unhex(w[1]));
            let pt = unhex(w[2]);
            let ct = unhex(w[3]);
            check(line, bignum::aes_encrypt_block(k, pt) == ct);
            check(line, bignum::aes_decrypt_block(k, ct) == pt);
        } else if w[0] == "ctr" {
            let k = bignum::aes_init(unhex(w[1]));
            let iv = unhex(w[2]);
            let pt = unhex(w[3]);
            let want = unhex(w[4]);
            var data = copy(pt);
            bignum::aes_ctr(k, iv, data);
            check(line, data == want);
            bignum::aes_ctr(k, iv, data);
            check(line, data == pt);
            // Streamed in whole blocks: the counter carries over between calls.
            var cb: u8[16] = [0; 16];
            for i in 16 { cb[i] = iv[i]; }
            var parts = copy(pt);
            var off = 0;
            var blocks = 1;
            while off < parts.len {
                let end = ::min(parts.len, off + 16 * blocks);
                bignum::aes_ctr_xor(k, cb, parts[off..end], false);
                off = end;
                blocks++;
            }
            check(line, parts == want);
        }
    }
    print("aes vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
