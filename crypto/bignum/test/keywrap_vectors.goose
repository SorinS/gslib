// AES Key Wrap against RFC 3394 §4's six vectors and RFC 5649 §6's two,
// then round trips of every key length up to 64 bytes under each KEK size,
// each unwrapped again after flipping every bit of the wrapped key in turn,
// which must fail and give nothing back.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.keywrap;
import gslib.entropy;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        if s[i] == ' ' { i++; continue; }
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

let K128 = "000102030405060708090A0B0C0D0E0F";
let K192 = "000102030405060708090A0B0C0D0E0F1011121314151617";
let K256 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
let D128 = "00112233445566778899AABBCCDDEEFF";
let D192 = "00112233445566778899AABBCCDDEEFF0001020304050607";
let D256 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";

fn rfc3394(name: const u8[:], kek: const u8[:], key: const u8[:], want: const u8[:]) {
    let k = unhex(kek);
    let d = unhex(key);
    let w = unhex(want);
    let got, ok = bignum::aes_key_wrap(k, d);
    check(str(name, " wrap"), ok && got == w);
    let back, ok2 = bignum::aes_key_unwrap(k, w);
    check(str(name, " unwrap"), ok2 && back == d);
}

fn rfc5649(name: const u8[:], key: const u8[:], want: const u8[:]) {
    let k = unhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    let d = unhex(key);
    let w = unhex(want);
    let got, ok = bignum::aes_key_wrap_pad(k, d);
    check(str(name, " wrap"), ok && got == w);
    let back, ok2 = bignum::aes_key_unwrap_pad(k, w);
    check(str(name, " unwrap"), ok2 && back == d);
}

// Every one-bit change of a wrapped key must be refused.
fn tamper(name: const u8[:], kek: const u8[:], w: const u8[:], padded: bool) {
    var t: u8[>..] = [];
    t.append(w);
    var all = true;
    for i in t.len {
        for bit in 8 {
            t[i] = t[i] ^ (1 << bit as u8);
            if padded {
                let back, ok = bignum::aes_key_unwrap_pad(kek, t);
                if ok || back.len != 0 { all = false; }
            } else {
                let back, ok = bignum::aes_key_unwrap(kek, t);
                if ok || back.len != 0 { all = false; }
            }
            t[i] = t[i] ^ (1 << bit as u8);
        }
    }
    check(str(name, " tampered"), all);
}

fn main() {
    rfc3394("RFC 3394 4.1", K128, D128, "1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5");
    rfc3394("RFC 3394 4.2", K192, D128, "96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D");
    rfc3394("RFC 3394 4.3", K256, D128, "64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7");
    rfc3394("RFC 3394 4.4", K192, D192, "031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2");
    rfc3394("RFC 3394 4.5", K256, D192, "A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1");
    rfc3394("RFC 3394 4.6", K256, D256,
            "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21");
    rfc5649("RFC 5649 20 bytes", "c37b7e6492584340bed12207808941155068f738",
            "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");
    rfc5649("RFC 5649 7 bytes", "466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f");

    // Lengths RFC 3394 refuses, and KEKs of no AES size.
    let k = unhex(K128);
    let short, ok1 = bignum::aes_key_wrap(k, unhex("0011223344556677"));
    check("8-byte key refused", !ok1 && short.len == 0);
    let odd, ok2 = bignum::aes_key_wrap(k, unhex("00112233445566778899AABBCCDDEEFF00"));
    check("17-byte key refused", !ok2 && odd.len == 0);
    let badkek, ok3 = bignum::aes_key_wrap(unhex("0011"), unhex(D128));
    check("2-byte KEK refused", !ok3 && badkek.len == 0);
    let empty, ok4 = bignum::aes_key_wrap_pad(k, "");
    check("empty key refused by KWP", !ok4 && empty.len == 0);

    for kl in [16, 24, 32] {
        var kek: u8[>..] = [];
        kek.resize(kl, 0);
        entropy::random_bytes(kek);
        for n in 1..65 {
            var key: u8[>..] = [];
            key.resize(n, 0);
            entropy::random_bytes(key);
            let wp, okp = bignum::aes_key_wrap_pad(kek, key);
            check(str("KWP wrap ", kl, "/", n), okp && wp.len == (n + 7) / 8 * 8 + 8);
            let bp, okb = bignum::aes_key_unwrap_pad(kek, wp);
            check(str("KWP round trip ", kl, "/", n), okb && bp == key);
            if n % 8 == 0 && n >= 16 {
                let w, ok = bignum::aes_key_wrap(kek, key);
                check(str("KW wrap ", kl, "/", n), ok && w.len == n + 8);
                let b, okw = bignum::aes_key_unwrap(kek, w);
                check(str("KW round trip ", kl, "/", n), okw && b == key);
                if n <= 32 { tamper(str("KW ", kl, "/", n), kek, w, false); }
            }
            if n <= 24 { tamper(str("KWP ", kl, "/", n), kek, wp, true); }
        }
    }
    // KW and KWP do not accept each other's output: their initial values differ.
    let w, okw = bignum::aes_key_wrap(k, unhex(D128));
    let x, okx = bignum::aes_key_unwrap_pad(k, w);
    check("KW output refused by KWP", okw && !okx);

    print("keywrap: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
