// vectors/xcrypto.txt, from Go's golang.org/x/crypto (tools/govectors):
// MD4 and RIPEMD-160 at lengths around the block boundaries; Salsa20,
// XSalsa20 and HSalsa20; NaCl secretbox, box and its anonymous form, sign
// and auth, each opened again and refused when changed; bcrypt hashes
// recomputed from their salts; bcrypt_pbkdf (OpenBSD's vectors among
// them); Blowfish, CAST5, Twofish, TEA and XTEA
// blocks both ways and in CBC; AES-XTS sectors. vectors/rc2.txt: RC2-CBC
// at 40, 64 and 128 effective bits, from openssl. Then RFC 2268's RC2
// vectors and RFC 2144's CAST-128 one.
import std;
import bignum from "..";
import bignum.md4;
import bignum.ripemd160;
import bignum.salsa20;
import bignum.nacl;
import bignum.bcrypt;
import bignum.blowfish;
import bignum.cast5;
import bignum.twofish;
import bignum.tea;
import bignum.rc2;
import bignum.aes;
import bignum.modes;

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

fn flip(b: const u8[:], at: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(b);
    out[at] ^= 1;
    return out;
}

// A cipher's block lines: encrypt to ct, decrypt back.
fn block_ok<K>(k: const K&, pt: const u8[:], ct: const u8[:]) -> bool {
    let e = bignum::cipher_encrypt(k, pt);
    let d = bignum::cipher_decrypt(k, ct);
    return e[..] == ct && d[..] == pt;
}

fn cbc_ok<K>(k: const K&, iv: const u8[:], pt: const u8[:], ct: const u8[:]) -> bool {
    var buf: u8[>..] = [];
    buf.append(pt);
    bignum::cbc_encrypt(k, iv, buf);
    let enc = buf == ct;
    bignum::cbc_decrypt(k, iv, buf);
    return enc && buf == pt;
}

fn main() {
    for line in split(embed_file("vectors/xcrypto.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let kind = w[0];
        if kind == "md4" {
            check("md4", bignum::md4(unhex(w[1]))[..] == unhex(w[2]));
            // Streamed in two uneven pieces.
            let m = unhex(w[1]);
            var s = bignum::md4_init();
            bignum::md4_update(s, m[..m.len / 3]);
            bignum::md4_update(s, m[m.len / 3..]);
            check("md4 streamed", bignum::md4_final(s)[..] == unhex(w[2]));
        } else if kind == "ripemd160" {
            let m = unhex(w[1]);
            check("ripemd160", bignum::ripemd160(m)[..] == unhex(w[2]));
            var s = bignum::ripemd160_init();
            bignum::ripemd160_update(s, m[..m.len / 3]);
            bignum::ripemd160_update(s, m[m.len / 3..]);
            check("ripemd160 streamed", bignum::ripemd160_final(s)[..] == unhex(w[2]));
        } else if kind == "salsa20" {
            var buf = unhex(w[3]);
            bignum::salsa20_xor(unhex(w[1]), unhex(w[2]), buf);
            check("salsa20", buf == unhex(w[4]));
        } else if kind == "hsalsa20" {
            check("hsalsa20", bignum::hsalsa20(unhex(w[1]), unhex(w[2]))[..] == unhex(w[3]));
        } else if kind == "secretbox" {
            let key = unhex(w[1]);
            let nonce = unhex(w[2]);
            let sealed = unhex(w[4]);
            check("secretbox seal", bignum::secretbox_seal(unhex(w[3]), nonce, key) == sealed);
            let m, ok = bignum::secretbox_open(sealed, nonce, key);
            check("secretbox open", ok && m == unhex(w[3]));
            let m2, ok2 = bignum::secretbox_open(flip(sealed, sealed.len - 1), nonce, key);
            check("secretbox changed", !ok2);
        } else if kind == "box" {
            let sa = unhex(w[1]);
            let pa = unhex(w[2]);
            let sb = unhex(w[3]);
            let pb = unhex(w[4]);
            let nonce = unhex(w[5]);
            let sealed = unhex(w[7]);
            check("box keys", bignum::x25519_base(sa)[..] == pa && bignum::x25519_base(sb)[..] == pb);
            check("box seal", bignum::box_seal(unhex(w[6]), nonce, pb, sa) == sealed);
            let m, ok = bignum::box_open(sealed, nonce, pa, sb);
            check("box open", ok && m == unhex(w[6]));
            let m2, ok2 = bignum::box_open(sealed, flip(nonce, 0), pa, sb);
            check("box other nonce", !ok2);
        } else if kind == "anon" {
            let sb = unhex(w[1]);
            let pb = unhex(w[2]);
            let sealed = unhex(w[5]);
            check("anonymous seal", bignum::box_seal_anonymous_with(unhex(w[4]), pb, unhex(w[3])) == sealed);
            let m, ok = bignum::box_open_anonymous(sealed, pb, sb);
            check("anonymous open", ok && m == unhex(w[4]));
            let m2, ok2 = bignum::box_open_anonymous(flip(sealed, 3), pb, sb);
            check("anonymous changed", !ok2);
        } else if kind == "sign" {
            let sk = unhex(w[1]);
            let signed = unhex(w[4]);
            check("nacl sign", bignum::nacl_sign(unhex(w[3]), sk) == signed);
            let m, ok = bignum::nacl_sign_open(signed, unhex(w[2]));
            check("nacl sign open", ok && m == unhex(w[3]));
            let m2, ok2 = bignum::nacl_sign_open(flip(signed, signed.len - 1), unhex(w[2]));
            check("nacl sign changed", !ok2);
        } else if kind == "auth" {
            let key = unhex(w[1]);
            let d = unhex(w[3]);
            check("nacl auth", bignum::nacl_auth(unhex(w[2]), key)[..] == d && bignum::nacl_auth_verify(d, unhex(w[2]), key));
            check("nacl auth changed", !bignum::nacl_auth_verify(flip(d, 0), unhex(w[2]), key));
        } else if kind == "bcrypt" {
            let pw = unhex(w[1]);
            let h = w[3];
            check("bcrypt verify", bignum::bcrypt_verify(h, pw) && bignum::bcrypt_cost(h) == num(w[2]));
            // Another password: one more byte, or (at the 72-byte limit,
            // past which bcrypt reads nothing) a changed first byte.
            var pw2: u8[>..] = [];
            pw2.append(pw);
            if pw2.len < 72 { pw2.push('x'); } else { pw2[0] ^= 1; }
            check("bcrypt other password", !bignum::bcrypt_verify(h, pw2));
            let minor, cost, salt, at, ok = bignum::bcrypt_parse(h);
            let again, oka = bignum::bcrypt_hash_with(pw, cost, salt);
            check("bcrypt from its salt", ok && oka && again == h);
        } else if kind == "bcrypt_pbkdf" {
            let want = unhex(w[4]);
            let k, ok = bignum::bcrypt_pbkdf(unhex(w[1]), unhex(w[2]), num(w[3]), want.len);
            check("bcrypt_pbkdf", ok && k == want);
        } else if kind == "blowfish" {
            let c = bignum::blowfish_init(unhex(w[1]));
            check("blowfish", block_ok(c, unhex(w[2]), unhex(w[3])));
        } else if kind == "blowfish-cbc" {
            let c = bignum::blowfish_init(unhex(w[1]));
            check("blowfish cbc", cbc_ok(c, unhex(w[2]), unhex(w[3]), unhex(w[4])));
        } else if kind == "cast5" {
            let c = bignum::cast5_init(unhex(w[1]));
            check("cast5", block_ok(c, unhex(w[2]), unhex(w[3])));
        } else if kind == "cast5-cbc" {
            let c = bignum::cast5_init(unhex(w[1]));
            check("cast5 cbc", cbc_ok(c, unhex(w[2]), unhex(w[3]), unhex(w[4])));
        } else if kind == "twofish" {
            let c = bignum::twofish_init(unhex(w[1]));
            check("twofish", block_ok(c, unhex(w[2]), unhex(w[3])));
        } else if kind == "twofish-cbc" {
            let c = bignum::twofish_init(unhex(w[1]));
            check("twofish cbc", cbc_ok(c, unhex(w[2]), unhex(w[3]), unhex(w[4])));
        } else if kind == "tea" {
            let c = bignum::tea_init(unhex(w[1]), num(w[2]));
            check("tea", block_ok(c, unhex(w[3]), unhex(w[4])));
        } else if kind == "tea-cbc" {
            let c = bignum::tea_init(unhex(w[1]), num(w[2]));
            check("tea cbc", cbc_ok(c, unhex(w[3]), unhex(w[4]), unhex(w[5])));
        } else if kind == "xtea" {
            let c = bignum::xtea_init(unhex(w[1]));
            check("xtea", block_ok(c, unhex(w[2]), unhex(w[3])));
        } else if kind == "xtea-cbc" {
            let c = bignum::xtea_init(unhex(w[1]));
            check("xtea cbc", cbc_ok(c, unhex(w[2]), unhex(w[3]), unhex(w[4])));
        } else if kind == "xts" {
            let key = unhex(w[1]);
            let half = key.len / 2;
            let k1 = bignum::aes_init(key[..half]);
            let k2 = bignum::aes_init(key[half..]);
            let sector, oks = parse_int(w[2], 10);
            var buf = unhex(w[3]);
            bignum::xts_encrypt(k1, k2, sector as! u64, buf);
            check("xts", oks && buf == unhex(w[4]));
            bignum::xts_decrypt(k1, k2, sector as! u64, buf);
            check("xts back", buf == unhex(w[3]));
        }
    }
    for line in split(embed_file("vectors/rc2.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let c = bignum::rc2_init(unhex(w[1]), num(w[2]));
        check("rc2 cbc", cbc_ok(c, unhex(w[3]), unhex(w[4]), unhex(w[5])));
    }
    // RFC 2268 §5, and RFC 2144 Appendix B.1.
    let r1 = bignum::rc2_init(unhex("0000000000000000"), 63);
    check("rfc 2268 1", block_ok(r1, unhex("0000000000000000"), unhex("ebb773f993278eff")));
    let r2 = bignum::rc2_init(unhex("ffffffffffffffff"), 64);
    check("rfc 2268 2", block_ok(r2, unhex("ffffffffffffffff"), unhex("278b27e42e2f0d49")));
    let r3 = bignum::rc2_init(unhex("3000000000000000"), 64);
    check("rfc 2268 3", block_ok(r3, unhex("1000000000000001"), unhex("30649edf9be7d2c2")));
    let c5 = bignum::cast5_init(unhex("0123456712345678234567893456789a"));
    check("rfc 2144", block_ok(c5, unhex("0123456789abcdef"), unhex("238b4fe5847e44b2")));
    // bcrypt's limits.
    let none: u8[16] = [0; 16];
    var long_pw: u8[73] = [0x61; 73];
    let hl, okl = bignum::bcrypt_hash_with(long_pw, 4, none);
    check("bcrypt 73 bytes", !okl);
    let hc, okc = bignum::bcrypt_hash_with("pw", 32, none);
    check("bcrypt cost 32", !okc);
    let hd, okd = bignum::bcrypt_hash_with("pw", 2, none);
    check("bcrypt default cost", okd && bignum::bcrypt_cost(hd) == 10);
    let p0, okp0 = bignum::bcrypt_pbkdf("pw", "salt", 0, 32);
    let p1, okp1 = bignum::bcrypt_pbkdf("", "salt", 1, 32);
    let p2, okp2 = bignum::bcrypt_pbkdf("pw", "", 1, 32);
    let p3, okp3 = bignum::bcrypt_pbkdf("pw", "salt", 1, 1025);
    check("bcrypt_pbkdf limits", !okp0 && !okp1 && !okp2 && !okp3);
    check("bcrypt malformed", !bignum::bcrypt_verify("$2a$04$short", "pw") && bignum::bcrypt_cost("$3a$04$") == -1);
    print("xcrypto vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
