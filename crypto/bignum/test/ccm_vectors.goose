// AES-CCM against vectors/ccm.txt: SP 800-38C's examples 1 to 3, RFC
// 3610's packet vector 1, Microsoft's SMB 3.0 encryption vector, then
// random keys of every AES size with every nonce and tag length. Each is
// sealed, opened, and opened again after flipping a bit of the tag, the
// ciphertext, the AAD or the nonce, which must fail and leave nothing
// behind.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.ccm;

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
    var cases = 0;
    for line in split(embed_file("vectors/ccm.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        cases++;
        let key = unhex(w[1]);
        let nonce = unhex(w[2]);
        let aad = unhex(w[3]);
        let pt = unhex(w[4]);
        let ct = unhex(w[5]);
        let tag = unhex(w[6]);
        var want = copy(ct);
        want.append(tag);
        let sealed = bignum::aes_ccm_seal(key, nonce, aad, pt, tag.len);
        check(line, sealed == want);
        let opened, ok = bignum::aes_ccm_open(key, nonce, aad, sealed, tag.len);
        check(line, ok && opened == pt);

        // The in-place form with a reused key.
        let k = bignum::aes_init(key);
        var data = copy(pt);
        let t = bignum::ccm_encrypt(k, nonce, aad, data, tag.len);
        check(line, data == ct && t[..tag.len] == tag[..]);
        check(line, bignum::ccm_decrypt(k, nonce, aad, data, tag) && data == pt);

        // Tampering anywhere fails, and the plaintext is not released.
        var bad_tag = copy(sealed);
        bad_tag[bad_tag.len - 1] ^= 1;
        let o1, ok1 = bignum::aes_ccm_open(key, nonce, aad, bad_tag, tag.len);
        check("tag", !ok1 && o1.len == 0);
        if ct.len > 0 {
            var bad_ct = copy(sealed);
            bad_ct[0] ^= 0x80;
            let o2, ok2 = bignum::aes_ccm_open(key, nonce, aad, bad_ct, tag.len);
            check("ciphertext", !ok2 && o2.len == 0);
            var buf = copy(ct);
            check("in place", !bignum::ccm_decrypt(k, nonce, aad, buf, bad_tag[ct.len..]));
            var zeroed = true;
            for x in buf { if x != 0 { zeroed = false; } }
            check("zeroed", zeroed);
        }
        var bad_aad = copy(aad);
        bad_aad.push(0);
        let o3, ok3 = bignum::aes_ccm_open(key, nonce, bad_aad, sealed, tag.len);
        check("aad", !ok3);
        var bad_nonce = copy(nonce);
        bad_nonce[0] ^= 1;
        let o4, ok4 = bignum::aes_ccm_open(key, bad_nonce, aad, sealed, tag.len);
        check("nonce", !ok4);
        // A shorter tag is not a prefix match: it is refused.
        let o5, ok5 = bignum::aes_ccm_open(key, nonce, aad, sealed[..sealed.len - 2], tag.len - 2);
        check("truncated tag", !ok5 && o5.len == 0);
    }
    // Lengths CCM does not have fail rather than abort.
    let k16: u8[16] = [0; 16];
    let z: u8[32] = [0; 32];
    let o6, ok6 = bignum::aes_ccm_open(k16, z[..6], "", z, 16);
    let o7, ok7 = bignum::aes_ccm_open(k16, z[..14], "", z, 16);
    let o8, ok8 = bignum::aes_ccm_open(k16, z[..11], "", z, 5);
    let o9, ok9 = bignum::aes_ccm_open(z[..15], z[..11], "", z, 16);
    let o10, ok10 = bignum::aes_ccm_open(k16, z[..11], "", z[..8], 16);
    check("bad lengths", !ok6 && !ok7 && !ok8 && !ok9 && !ok10);
    check("fits", bignum::ccm_fits(13, 16, 65535, 0) && !bignum::ccm_fits(13, 16, 65536, 0) && bignum::ccm_fits(12, 16, 65536, 0));
    print(cases, " vectors, ", checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
