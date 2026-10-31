// AES-GCM against vectors/gcm.txt: the GCM specification's test cases 1 to
// 5, then random keys, nonces of 12 bytes and of other lengths, and AAD and
// plaintext lengths around the block size. Each is sealed, opened, and
// opened again after flipping a bit of the tag, the ciphertext, the AAD or
// the nonce, which must fail and leave nothing behind.
import std;
import bignum from "..";
import bignum.gcm;

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
    for line in split(embed_file("vectors/gcm.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let key = unhex(w[1]);
        let nonce = unhex(w[2]);
        let aad = unhex(w[3]);
        let pt = unhex(w[4]);
        let ct = unhex(w[5]);
        let tag = unhex(w[6]);
        var want = copy(ct);
        want.append(tag);
        let sealed = bignum::aes_gcm_seal(key, nonce, aad, pt);
        check(line, sealed == want);
        let opened, ok = bignum::aes_gcm_open(key, nonce, aad, sealed);
        check(line, ok && opened == pt);

        // The in-place form with a reused context.
        let g = bignum::gcm_init(key);
        var data = copy(pt);
        let t = bignum::gcm_encrypt(g, nonce, aad, data);
        check(line, data == ct && t == tag);
        check(line, bignum::gcm_decrypt(g, nonce, aad, data, t) && data == pt);

        // Tampering anywhere fails, and the plaintext is not released.
        var bad_tag = copy(sealed);
        bad_tag[bad_tag.len - 1] ^= 1;
        let o1, ok1 = bignum::aes_gcm_open(key, nonce, aad, bad_tag);
        check("tag", !ok1 && o1.len == 0);
        if ct.len > 0 {
            var bad_ct = copy(sealed);
            bad_ct[0] ^= 0x80;
            let o2, ok2 = bignum::aes_gcm_open(key, nonce, aad, bad_ct);
            check("ciphertext", !ok2 && o2.len == 0);
            var buf = copy(ct);
            check("in place", !bignum::gcm_decrypt(g, nonce, aad, buf, bad_tag[ct.len..]));
            var zeroed = true;
            for x in buf { if x != 0 { zeroed = false; } }
            check("zeroed", zeroed);
        }
        var bad_aad = copy(aad);
        bad_aad.push(0);
        let o3, ok3 = bignum::aes_gcm_open(key, nonce, bad_aad, sealed);
        check("aad", !ok3);
        var bad_nonce = copy(nonce);
        bad_nonce[0] ^= 1;
        let o4, ok4 = bignum::aes_gcm_open(key, bad_nonce, aad, sealed);
        check("nonce", !ok4);
    }
    let short: u8[15] = [0; 15];
    let o5, ok5 = bignum::aes_gcm_open(short, short[..12], "", short);
    check("short", !ok5);
    // A tag of the wrong length fails (and zeroes the data) rather than
    // aborting.
    let k16: u8[16] = [0; 16];
    let g5 = bignum::gcm_init(k16);
    var d5: u8[>..] = [];
    d5.resize(8, 1);
    check("short tag", !bignum::gcm_decrypt(g5, short[..12], "", d5, short[..15]) && d5[0] == 0);
    check("empty tag", !bignum::gcm_decrypt(g5, short[..12], "", d5, short[..0]));
    // The size limit every entry point checks, at its boundary.
    check("gcm_fits", bignum::gcm_fits(0) && bignum::gcm_fits(bignum::GCM_MAX) && !bignum::gcm_fits(bignum::GCM_MAX + 1)
          && !bignum::gcm_fits(-1) && bignum::GCM_MAX == (4294967296 - 2) * 16);
    print("gcm vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
