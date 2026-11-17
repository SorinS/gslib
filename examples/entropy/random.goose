// Random bytes for secrets: entropy::random_bytes fills a buffer from the
// OS (getentropy, or BCryptGenRandom on Windows), for keys, nonces, salts
// and tokens. std's rng is a fast generator for simulations and tests,
// never for secrets. Also: a session token, a UUID (version 4), and a
// uniform number below a bound without bias.
//
//   goose examples/entropy/random.goose
import std;
import gslib from "../..";
import gslib.entropy;

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

// A random UUID (RFC 9562 version 4): 122 random bits.
fn uuid4() -> u8[>..] {
    var b: u8[16] = [0; 16];
    entropy::random_bytes(b);
    b[6] = (b[6] & 0x0f) | 0x40;               // version 4
    b[8] = (b[8] & 0x3f) | 0x80;               // the RFC's variant
    let h = hex(b);
    return str(h[0..8], "-", h[8..12], "-", h[12..16], "-", h[16..20], "-", h[20..32]);
}

// A uniform integer in [0, n), 0 < n < 2^32: drawing 4 bytes and taking
// them mod n would favour small values, so draws at or above the largest
// multiple of n are thrown away.
fn below(n: u64) -> u64 {
    let limit = (1 as u64 << 32) / n * n;
    while true {
        var b: u8[4] = [0; 4];
        entropy::random_bytes(b);
        let v = (b[0] as u64 << 24) | (b[1] as u64 << 16) | (b[2] as u64 << 8) | b[3];
        if v < limit { return v % n; }
    }
    return 0;
}

fn main() {
    var key: u8[32] = [0; 32];
    entropy::random_bytes(key);
    print("aes-256 key   ", hex(key));

    // When a program can do without, try_random_bytes reports instead.
    var salt: u8[16] = [0; 16];
    guard entropy::try_random_bytes(salt) else { print("the OS gave no random bytes"); exit(1); }
    print("salt          ", hex(salt));

    print("session token ", token());
    print("uuid          ", uuid4());

    // Dice: uniform in [1, 6], counted over 6000 throws.
    var counts: i64[6] = [0; 6];
    for i in 6000 { counts[below(6)]++; }
    print("6000 throws of a die: ", counts[0], " ", counts[1], " ", counts[2], " ", counts[3], " ", counts[4], " ",
          counts[5]);
    for c in counts { guard c > 800 && c < 1200 else { print("the die is biased"); exit(1); } }
}
