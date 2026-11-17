// Randomness for keys: entropy's random_bytes fills a buffer from the OS
// (getentropy, or BCryptGenRandom on Windows), for keys, nonces, salts and
// tokens. std's rng is a
// fast generator for simulations and tests, never for secrets. Also: a
// uniform random number below a bound, by rejection, without bias.
//
//   goose examples/bignum/random_bytes.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.entropy;
import gslib.crypto.bignum.gcm;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

// A URL-safe token: 33 random bytes in base64url, 44 characters.
fn token() -> u8[>..] {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var raw: u8[33] = [0; 33];                 // a multiple of 3: no padding
    entropy::random_bytes(raw);
    var out: u8[>..] = [];
    var i = 0;
    while i < raw.len {
        let v = (raw[i] as u32 << 16) | (raw[i + 1] as u32 << 8) | raw[i + 2];
        for s in [18, 12, 6, 0] { out.push(alphabet[((v >> s as u32) & 63) as i64]); }
        i += 3;
    }
    return out;
}

// A uniform integer in [0, n), n > 0: draw just enough bits, retry above.
fn below(n: const bignum::BigInt&) -> bignum::BigInt {
    let bits = bignum::bit_len(n);
    var buf: u8[>..] = [];
    buf.resize((bits + 7) / 8, 0);
    loop {
        entropy::random_bytes(buf);
        if bits % 8 != 0 { buf[0] &= ((1 << (bits % 8)) - 1) as! u8; }
        let v = bignum::from_bytes_be(buf);
        if bignum::lt(v, n) { return v; }
    }
}

fn main() {
    // Keys and nonces: fixed-size arrays filled in place.
    var key:   u8[32] = [0; 32];
    var nonce: u8[12] = [0; 12];
    entropy::random_bytes(key);
    entropy::random_bytes(nonce);
    print("aes-256 key ", hex(key));
    print("gcm nonce   ", hex(nonce));
    let sealed = bignum::aes_gcm_seal(key, nonce, "", "random key, random nonce");
    let opened, ok = bignum::aes_gcm_open(key, nonce, "", sealed);
    guard ok && opened == "random key, random nonce" else { print("random_bytes: round trip failed"); exit(1); }

    // Two draws never repeat (a repeat of 32 bytes would mean a broken source).
    var again: u8[32] = [0; 32];
    entropy::random_bytes(again);
    guard again[..] != key[..] else { print("random_bytes: two draws were equal"); exit(1); }

    // Any length works; large buffers are filled 256 bytes per OS call.
    var big: u8[>..] = [];
    big.resize(1000, 0);
    entropy::random_bytes(big);
    var zeros = 0;
    for b in big { if b == 0 { zeros++; } }
    print("1000 random bytes, ", zeros, " of them zero (about 4 expected)");

    print("session token ", token());

    // Dice: uniform in [1, 6], counted over 6000 throws.
    let six = bignum::big(6);
    var counts: i64[6] = [0; 6];
    for i in 6000 {
        let r, okr = bignum::to_i64(below(six));
        counts[r]++;
    }
    print("6000 throws of a die: ", counts[0], " ", counts[1], " ", counts[2], " ", counts[3], " ", counts[4], " ",
          counts[5]);
    for c in counts { guard c > 800 && c < 1200 else { print("random_bytes: die is biased"); exit(1); } }
    print("randomness checks passed");
}
