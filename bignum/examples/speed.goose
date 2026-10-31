// Throughput and operation rates of every primitive, one line each:
// "name value unit", MB/s over 16 KiB buffers (as openssl speed -bytes
// 16384) or operations a second. scripts/speed_vs_openssl.py builds this
// natively and sets each line against openssl's figure for the same
// operation. A name given as an argument runs only the lines it prefixes.
//
//   goose build -o speed examples/speed.goose && ./speed [prefix]
import std;
import os;
import bignum from "..";
import bignum.md5;
import bignum.sha1;
import bignum.sha256;
import bignum.sha512;
import bignum.sha3;
import bignum.blake2;
import bignum.hmac;
import bignum.aes;
import bignum.gcm;
import bignum.modes;
import bignum.des;
import bignum.rc4;
import bignum.chacha20;
import bignum.x25519;
import bignum.ed25519;
import bignum.ec;
import bignum.rsa;
import bignum.mlkem;
import bignum.kdf;
import bignum.argon2;

let SECS: f64 = 0.5;
let BUF: i64 = 16384;

var only: u8[>..] = [];

fn wanted(name: const u8[:]) -> bool {
    only.len == 0 || (name.len >= only.len && name[..only.len] == only)
}

// Runs until SECS have passed: n counts the calls, t0 when it started.
struct Timer { t0: f64, n: i64 }

fn timer() -> Timer { Timer { t0: clock(), n: 0 } }

fn more(t: Timer&) -> bool {
    if t.n > 0 && clock() - t.t0 >= SECS { return false; }
    t.n++;
    return true;
}

fn mbps(name: const u8[:], t: const Timer&) {
    let s = clock() - t.t0;
    print(name, " ", ((t.n * BUF) / s / 1000000.0), " MB/s");
}

fn ops(name: const u8[:], t: const Timer&) {
    let s = clock() - t.t0;
    print(name, " ", (t.n / s), " op/s");
}

fn bytes_of(n: i64, seed: i64) -> u8[>..] {
    var out: u8[>..] = [];
    for i in n { out.push(((i * 131 + seed * 17 + 7) % 251) as! u8); }
    return out;
}

fn hashes(buf: u8[:]) {
    if wanted("md5") { var t = timer(); while more(t) { let h = bignum::md5(buf); buf[0] = h[0]; } mbps("md5", t); }
    if wanted("sha1") { var t = timer(); while more(t) { let h = bignum::sha1(buf); buf[0] = h[0]; } mbps("sha1", t); }
    if wanted("sha256") { var t = timer(); while more(t) { let h = bignum::sha256(buf); buf[0] = h[0]; } mbps("sha256", t); }
    if wanted("sha512") { var t = timer(); while more(t) { let h = bignum::sha512(buf); buf[0] = h[0]; } mbps("sha512", t); }
    if wanted("sha3-256") { var t = timer(); while more(t) { let h = bignum::sha3(256, buf); buf[0] = h[0]; } mbps("sha3-256", t); }
    if wanted("blake2b512") { var t = timer(); while more(t) { let h = bignum::blake2b(buf); buf[0] = h[0]; } mbps("blake2b512", t); }
    if wanted("blake2s256") { var t = timer(); while more(t) { let h = bignum::blake2s(buf); buf[0] = h[0]; } mbps("blake2s256", t); }
    let key = bytes_of(32, 1);
    if wanted("hmac-sha256") { var t = timer(); while more(t) { let h = bignum::hmac(256, key, buf); buf[0] = h[0]; } mbps("hmac-sha256", t); }
}

fn ciphers(buf: u8[:]) {
    let k16 = bytes_of(16, 2);
    let k32 = bytes_of(32, 3);
    let iv = bytes_of(16, 4);
    let nonce = bytes_of(12, 5);
    if wanted("aes-128-gcm") {
        let g = bignum::gcm_init(k16);
        var t = timer(); while more(t) { let tag = bignum::gcm_encrypt(g, nonce, "", buf); } mbps("aes-128-gcm", t);
    }
    if wanted("aes-256-gcm") {
        let g = bignum::gcm_init(k32);
        var t = timer(); while more(t) { let tag = bignum::gcm_encrypt(g, nonce, "", buf); } mbps("aes-256-gcm", t);
    }
    if wanted("chacha20-poly1305") {
        var t = timer(); while more(t) { let tag = bignum::chacha20_poly1305_encrypt(k32, nonce, "", buf); } mbps("chacha20-poly1305", t);
    }
    if wanted("chacha20") {
        var t = timer(); while more(t) { bignum::chacha20_xor(k32, 1, nonce, buf); } mbps("chacha20", t);
    }
    let a128 = bignum::aes_init(k16);
    let a256 = bignum::aes_init(k32);
    if wanted("aes-128-ctr") { var t = timer(); while more(t) { bignum::aes_ctr(a128, iv, buf); } mbps("aes-128-ctr", t); }
    if wanted("aes-256-ctr") { var t = timer(); while more(t) { bignum::aes_ctr(a256, iv, buf); } mbps("aes-256-ctr", t); }
    if wanted("aes-128-cbc") { var t = timer(); while more(t) { bignum::cbc_encrypt(a128, iv, buf); } mbps("aes-128-cbc", t); }
    if wanted("aes-256-cbc") { var t = timer(); while more(t) { bignum::cbc_encrypt(a256, iv, buf); } mbps("aes-256-cbc", t); }
    if wanted("aes-128-cfb") { var t = timer(); while more(t) { bignum::cfb_encrypt(a128, iv, buf); } mbps("aes-128-cfb", t); }
    if wanted("aes-128-ofb") { var t = timer(); while more(t) { bignum::ofb_xor(a128, iv, buf); } mbps("aes-128-ofb", t); }
    let d1 = bignum::des_init(bytes_of(8, 6));
    let d3 = bignum::des3_init(bytes_of(24, 7));
    if wanted("des-cbc") { var t = timer(); while more(t) { bignum::cbc_encrypt(d1, iv[..8], buf); } mbps("des-cbc", t); }
    if wanted("des-ede3-cbc") { var t = timer(); while more(t) { bignum::cbc_encrypt(d3, iv[..8], buf); } mbps("des-ede3-cbc", t); }
    if wanted("rc4") {
        var r = bignum::rc4_init(k16);
        var t = timer(); while more(t) { bignum::rc4_xor(r, buf); } mbps("rc4", t);
    }
}

fn curves() {
    let msg = bytes_of(32, 8);
    let sk = bytes_of(32, 9);
    if wanted("x25519") {
        let pk = bignum::x25519_base(bytes_of(32, 10));
        var t = timer(); while more(t) { let s = bignum::x25519(sk, pk); } ops("x25519", t);
    }
    if wanted("ed25519") {
        let pk = bignum::ed25519_public(sk);
        let sig = bignum::ed25519_sign(sk, msg);
        var t = timer(); while more(t) { let s = bignum::ed25519_sign(sk, msg); } ops("ed25519-sign", t);
        t = timer(); while more(t) { assert(bignum::ed25519_verify(pk, msg, sig)); } ops("ed25519-verify", t);
    }
    let names: const u8[:][4] = ["p224", "p256", "p384", "p521"];
    for i in 4 {
        let c = if i == 0 { bignum::p224() } else if i == 1 { bignum::p256() } else if i == 2 { bignum::p384() } else { bignum::p521() };
        var nd: u8[>..] = [];
        nd.append("ecdh-"); nd.append(names[i]);
        var ns: u8[>..] = [];
        ns.append("ecdsa-"); ns.append(names[i]); ns.append("-sign");
        var nv: u8[>..] = [];
        nv.append("ecdsa-"); nv.append(names[i]); nv.append("-verify");
        if !wanted(nd) && !wanted(ns) && !wanted(nv) { continue; }
        var d: u8[>..] = [];
        d.append(bytes_of(c.len, 11));
        d[0] = 1;
        let pk = bignum::ec_public_key(c, d);
        var d2 = bytes_of(c.len, 12);
        d2[0] = 1;
        let peer = bignum::ec_public_key(c, d2);
        if wanted(nd) {
            var t = timer(); while more(t) { let s, ok = bignum::ecdh_shared(c, d, peer); assert(ok); } ops(nd, t);
        }
        let sig = bignum::ecdsa_sign(c, d, msg);
        if wanted(ns) { var t = timer(); while more(t) { let s = bignum::ecdsa_sign(c, d, msg); } ops(ns, t); }
        if wanted(nv) { var t = timer(); while more(t) { assert(bignum::ecdsa_verify(c, pk, msg, sig)); } ops(nv, t); }
    }
}

fn rsa() {
    let msg = bytes_of(32, 13);
    let sizes: i64[3] = [2048, 3072, 4096];
    for bits in sizes {
        var nm: u8[>..] = [];
        nm.append("rsa");
        format_int(nm, bits, 10, 0, 32);
        if !wanted(nm) { continue; }
        let key = bignum::rsa_generate(bits);
        let pub = bignum::rsa_public(key);
        let sig, ok_sig = bignum::rsa_sign_pkcs1(key, msg);
        var t = timer(); while more(t) { let s, ok_s = bignum::rsa_sign_pkcs1(key, msg); }
        var a: u8[>..] = []; a.append(nm); a.append("-sign"); ops(a, t);
        t = timer(); while more(t) { assert(bignum::rsa_verify_pkcs1(pub, msg, sig)); }
        a = []; a.append(nm); a.append("-verify"); ops(a, t);
    }
}

fn kems() {
    let ks: i64[3] = [2, 3, 4];
    for k in ks {
        var nm: u8[>..] = [];
        nm.append("mlkem");
        format_int(nm, 256 * k, 10, 0, 32);
        if !wanted(nm) { continue; }
        let seed = bytes_of(64, 14 + k);
        var t = timer(); while more(t) { let ek, dk = bignum::mlkem_keys_from_seed(k, seed); }
        var a: u8[>..] = []; a.append(nm); a.append("-keygen"); ops(a, t);
        let ek, dk = bignum::mlkem_keys_from_seed(k, seed);
        t = timer(); while more(t) { let ss, c, ok = bignum::mlkem_encaps(k, ek); }
        a = []; a.append(nm); a.append("-encaps"); ops(a, t);
        let ss, c, ok = bignum::mlkem_encaps(k, ek);
        t = timer(); while more(t) { let s2, ok2 = bignum::mlkem_decaps_dk(k, dk, c); }
        a = []; a.append(nm); a.append("-decaps"); ops(a, t);
    }
}

fn kdfs() {
    if wanted("pbkdf2") {
        var t = timer(); while more(t) { let dk = bignum::pbkdf2(256, "password", "saltsaltsaltsalt", 100000, 32); }
        ops("pbkdf2-sha256-100k", t);
    }
    if wanted("scrypt") {
        var t = timer(); while more(t) { let dk, ok = bignum::scrypt("password", "saltsaltsaltsalt", 1 << 15, 8, 1, 32); }
        ops("scrypt-n15-r8", t);
    }
    if wanted("argon2") {
        var t = timer(); while more(t) { let dk = bignum::argon2id_key("password", "saltsaltsaltsalt", 1, 65536, 4, 32); }
        ops("argon2id-t1-64m-p4", t);
    }
}

fn main() {
    let a = args();
    if a.len > 1 { only.append(a[1]); }
    var buf = bytes_of(BUF, 0);
    hashes(buf);
    ciphers(buf);
    curves();
    rsa();
    kems();
    kdfs();
}
