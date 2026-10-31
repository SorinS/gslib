// SHA-384, SHA-512, HMAC and HKDF against vectors/hash.txt (hashlib and
// hmac): lengths around SHA-512's 128-byte block and its padding boundary,
// each hash also fed in pieces; HMAC keys shorter and longer than a block;
// HKDF from RFC 5869's first test case and random ones. Then
// vectors/hash2.txt: SHA-1, SHA-224, SHA-512/224, SHA-512/256, SHA-3 and
// SHAKE at lengths around every block and rate, and HMAC over them.
import std;
import bignum from "..";
import bignum.hmac;
import bignum.sha1;
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

// hmac_prefix_ct equals hmac over prefix ‖ data[..len] for every len in
// its window, SHA-1 and SHA-256, around the block and padding boundaries.
fn prefix_ct() {
    var key: u8[32] = [0; 32];
    for i in 32 { key[i] = (7 * i + 1) as! u8; }
    var prefix: u8[13] = [0; 13];
    for i in 13 { prefix[i] = (i + 0x40) as! u8; }
    var all = true;
    var n = 0;
    for bits in [160, 256] {
        for size in [0, 1, 47, 55, 56, 64, 100, 119, 120, 300, 1000] {
            var data: u8[>..] = [];
            for i in size { data.push((i * 31 + size) as! u8); }
            let min_len = ::max(0, size - 70);
            for len in min_len..size + 1 {
                var whole: u8[>..] = [];
                whole.append(prefix);
                whole.append(data[..len]);
                let kl = if bits == 160 { 20 } else { 32 };
                if bignum::hmac_prefix_ct(bits, key[..kl], prefix, data, len, min_len) != bignum::hmac(bits, key[..kl], whole) {
                    all = false;
                    print("FAIL hmac_prefix_ct ", bits, " size ", size, " len ", len);
                }
                n++;
            }
        }
    }
    check("hmac_prefix_ct", all && n > 900);
    // Its public size limit, around 2^30 (the positions it compares are 32
    // bits): checked without making such a buffer.
    let lim = bignum::HMAC_PREFIX_CT_MAX;
    check("hmac_prefix_ct_fits", bignum::hmac_prefix_ct_fits(13, lim - 13) && !bignum::hmac_prefix_ct_fits(13, lim - 12)
          && bignum::hmac_prefix_ct_fits(0, lim) && !bignum::hmac_prefix_ct_fits(lim + 1, 0)
          && !bignum::hmac_prefix_ct_fits(-1, 0) && !bignum::hmac_prefix_ct_fits(0, -1)
          && !bignum::hmac_prefix_ct_fits(lim, lim));
}

fn main() {
    for line in split(embed_file("vectors/hash.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "sha384" || w[0] == "sha512" {
            let m = unhex(w[1]);
            let want = unhex(w[2]);
            let is384 = w[0] == "sha384";
            check(line, (if is384 { bignum::sha384(m) } else { bignum::sha512(m) }) == want);
            var s = if is384 { bignum::sha384_init() } else { bignum::sha512_init() };
            var off = 0;
            var step = 1;
            while off < m.len {
                let end = ::min(m.len, off + step);
                bignum::sha512_update(s, m[off..end]);
                off = end;
                step += 3;
            }
            check(line, bignum::sha512_final(s) == want);
        } else if w[0] == "hmac" {
            check(line, bignum::hmac(num(w[1]), unhex(w[2]), unhex(w[3])) == unhex(w[4]));
        } else if w[0] == "hkdf" {
            let got = bignum::hkdf(num(w[1]), unhex(w[2]), unhex(w[3]), unhex(w[4]), num(w[5]));
            check(line, got == unhex(w[6]));
        }
    }
    for line in split(embed_file("vectors/hash2.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let id = num(w[1]);
        let m = unhex(w[2]);
        if w[0] == "hash" {
            let want = unhex(w[3]);
            check(line, bignum::hash_bits(id, m) == want);
            // In pieces, through each hash's own streaming interface.
            var got: u8[>..] = [];
            if id == 160 {
                var s = bignum::sha1_init();
                var off = 0;
                while off < m.len { let e = ::min(m.len, off + 7); bignum::sha1_update(s, m[off..e]); off = e; }
                got.append(bignum::sha1_final(s));
            } else if id > 3000 && id < 4000 {
                var s = bignum::sha3_init(id - 3000);
                var off = 0;
                while off < m.len { let e = ::min(m.len, off + 13); bignum::sha3_update(s, m[off..e]); off = e; }
                got = bignum::sha3_final(s);
            } else if id == 224 {
                var s = bignum::sha224_init();
                bignum::sha256_update(s, m);
                got.append(bignum::sha224_final(s));
            } else {
                var s = if id == 5224 { bignum::sha512_224_init() } else { bignum::sha512_256_init() };
                var off = 0;
                while off < m.len { let e = ::min(m.len, off + 29); bignum::sha512_update(s, m[off..e]); off = e; }
                got = bignum::sha512_final(s);
            }
            check(line, got == want);
        } else if w[0] == "shake" {
            let n = num(w[3]);
            let want = unhex(w[4]);
            check(line, bignum::shake(id, m, n) == want);
            // Squeezed in uneven reads.
            var s = bignum::shake_init(id);
            bignum::sha3_update(s, m);
            var got: u8[>..] = [];
            var step = 1;
            while got.len < n {
                var part: u8[>..] = [];
                part.resize(::min(step, n - got.len), 0);
                bignum::shake_read(s, part);
                got.append(part);
                step += 11;
            }
            check(line, got == want);
        } else if w[0] == "hmac" {
            check(line, bignum::hmac(id, m, unhex(w[3])) == unhex(w[4]));
        }
    }
    check("hmac_sha256", bignum::hmac_sha256("key", "The quick brown fox jumps over the lazy dog")
          == unhex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));
    prefix_ct();
    print("hash vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
