// Secret sharing: the OASIS KMIP test cases' parts (TC-SJ-3-20 in GF(2^8),
// TC-SJ-4-20 in XOR) joined back to their key; parts made with fixed
// coefficients against ones a Python reference made (its GF(2^16) product
// worked out from y^2 = y + m, not the spec's formula used here); the
// GF(2^8) and
// GF(2^16) field laws; and round trips of random secrets through every
// method, joined from each set of parts of the threshold's size, with too
// few parts not giving the secret.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.shamir;
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
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn random(n: i64) -> u8[>..] {
    var r: u8[>..] = [];
    r.resize(n, 0);
    entropy::random_bytes(r);
    return r;
}

let KEY = "0102030405060708090a0b0c0d0e0f10";

fn oasis() {
    // TC-SJ-3-20: four parts of a 2-of-4 split in GF(2^8).
    var parts: u8[>..] = [];
    parts.append(unhex("66C46A7754F94DE420C7B1A7FFF5EC56"));
    parts.append(unhex("CF93D1E2A7E593CD5B8D6247F4E5D49C"));
    parts.append(unhex("A855B891F61AD9217240D8EC061E37DA"));
    parts.append(unhex("803DBAD55CDD329FAD19D99AE2C5A415"));
    let key = unhex(KEY);
    for a in 4 {
        for b in 4 {
            if a < b {
                let xs: i64[2] = [a + 1, b + 1];
                var two: u8[>..] = [];
                two.append(parts[a * 16..a * 16 + 16]);
                two.append(parts[b * 16..b * 16 + 16]);
                var out: u8[>..] = [];
                check("TC-SJ-3-20 joined", bignum::join_gf8(xs, two, 16, out) && out[..] == key[..]);
            }
        }
    }
    let one: i64[1] = [2];
    var single: u8[>..] = [];
    let ok1 = bignum::join_gf8(one, parts[16..32], 16, single);
    check("one part is not the key", ok1 && single[..] != key[..]);
    // TC-SJ-4-20: four XOR parts.
    var xp: u8[>..] = [];
    xp.append(unhex("d4b92c299199298e30dee13b967e6dda"));
    xp.append(unhex("35ea4f615686230c7b11538693674e89"));
    xp.append(unhex("3478ddd2e1f89f2005011d26d9fff37c"));
    xp.append(unhex("d429bd9e23e192aa47c4a497d1e8df3f"));
    var xo: u8[>..] = [];
    check("TC-SJ-4-20 joined", bignum::join_xor(xp, 16, xo) && xo[..] == key[..]);
    var three: u8[>..] = [];
    let ok3 = bignum::join_xor(xp[..48], 16, three);
    check("three XOR parts are not the key", three[..] != key[..]);
}

fn reference() {
    let key = unhex(KEY);
    var rand: u8[>..] = [];
    for i in 32 { rand.push((0xa0 + i) as! u8); }
    let want8 = unhex("1112131415161718191a1b1c1d1e1f00a6a3a8a9babfb4bd9e9b909182878c95b6b3b8b9aaafa4ad8e8b808192979c8574635e4d20370a11dccbf6e5889fa2a9");
    var o8: u8[>..] = [];
    check("GF(2^8) parts", bignum::split_gf8_with(key, 4, 3, rand, o8) && o8[..] == want8[..]);
    var o16: u8[>..] = [];
    check("GF(2^16) parts", bignum::split_gf16_with(key, 300, 3, rand, o16) && o16[..64] == want8[..]);
    check("GF(2^16) part 257", o16[256 * 16..257 * 16] == unhex("c977bf05259b53e10cb27ac0e05e9634")[..]);
    check("GF(2^16) part 300", o16[299 * 16..300 * 16] == unhex("ca7cac1e06b060da4ff9299b8335e54f")[..]);
    check("GF(2^16) product", bignum::gf16_mul(0x1234, 0xabcd) == 0xd223);
    let xs: i64[3] = [300, 2, 257];
    var pick: u8[>..] = [];
    pick.append(o16[299 * 16..300 * 16]);
    pick.append(o16[16..32]);
    pick.append(o16[256 * 16..257 * 16]);
    var back: u8[>..] = [];
    check("GF(2^16) joined past 255", bignum::join_gf16(xs, pick, 16, back) && back[..] == key[..]);
    // 2^130 - 5, the coefficients 17 + 8 bytes each from 1, 2, 3, ...
    let prime = unhex("03fffffffffffffffffffffffffffffffb");
    var rp: u8[>..] = [];
    for i in 50 { rp.push((i + 1) as! u8); }
    var op: u8[>..] = [];
    let want = unhex("032e3134373a3d40652ab035bb40c64bcd02a1a8afb6bdc4cc57e675039220af3dc8025b6875828f9caae03c587490acc8e4fc025b70859aafc4dbfe2c5a88b6e5134169");
    check("prime field parts", bignum::split_prime_with(key, prime, 4, 3, rp, op) && op[..] == want[..]);
    check("2^130 - 5 will do for 16 bytes", bignum::prime_field_ok(prime, 16));
    check("not for 17", !bignum::prime_field_ok(prime, 17));
    check("2^130 - 3 is not prime", !bignum::prime_field_ok(unhex("03fffffffffffffffffffffffffffffffd"), 16));
}

fn field_laws() {
    var ok8 = true;
    for a in 256 {
        let x = a as! u8;
        if a != 0 && bignum::gf8_mul(x, bignum::gf8_inv(x)) != 1 { ok8 = false; }
        if bignum::gf8_mul(x, 1) != x { ok8 = false; }
    }
    check("GF(2^8) inverses", ok8);
    check("GF(2^8): 2 * 0x80 is 0x1D", bignum::gf8_mul(2, 0x80) == 0x1D);
    var ok16 = true;
    var lin = true;
    for i in 2000 {
        let r = random(6);
        let a = (r[0] as u16) << 8 | r[1];
        let b = (r[2] as u16) << 8 | r[3];
        let c = (r[4] as u16) << 8 | r[5];
        if a != 0 && bignum::gf16_mul(a, bignum::gf16_inv(a)) != 1 { ok16 = false; }
        if bignum::gf16_mul(a, b ^ c) != (bignum::gf16_mul(a, b) ^ bignum::gf16_mul(a, c)) { lin = false; }
        if bignum::gf16_mul(bignum::gf16_mul(a, b), c) != bignum::gf16_mul(a, bignum::gf16_mul(b, c)) { lin = false; }
        if bignum::gf16_mul(a, b) != bignum::gf16_mul(b, a) { lin = false; }
    }
    check("GF(2^16) inverses", ok16);
    check("GF(2^16) distributes, associates, commutes", lin);
}

// The parts at the positions in pick, one after another, and their numbers.
fn take(parts: const u8[:], len: i64, pick: const i64[:], out: u8[>..]&, xs: i64[>..]&) {
    out.clear();
    xs.clear();
    for p in pick { out.append(parts[p * len..(p + 1) * len]); xs.push(p + 1); }
}

fn round_trips() {
    let prime = unhex("03fffffffffffffffffffffffffffffffb");
    var ok = true;
    var short_differs = true;
    for round in 40 {
        let r = random(2);
        let n = 2 + (r[0] % 7) as i64;
        let t = 1 + r[1] % n;
        let key = random(16);
        for method in 3 {
            var parts: u8[>..] = [];
            var len: i64 = 16;
            var made = false;
            if method == 0 { made = bignum::split_gf8(key, n, t, parts); }
            else if method == 1 { made = bignum::split_gf16(key, n, t, parts); }
            else { made = bignum::split_prime(key, prime, n, t, parts); len = prime.len; }
            if !made || parts.len != n * len { ok = false; continue; }
            // The first t, the last t, and every other one from the end.
            var pick: i64[>..] = [];
            for i in t { pick.push(i); }
            var pick2: i64[>..] = [];
            for i in t { pick2.push(n - 1 - i); }
            var sel: u8[>..] = [];
            var xs: i64[>..] = [];
            for which in 2 {
                if which == 0 { take(parts, len, pick, sel, xs); } else { take(parts, len, pick2, sel, xs); }
                var back: u8[>..] = [];
                var j = false;
                if method == 0 { j = bignum::join_gf8(xs, sel, 16, back); }
                else if method == 1 { j = bignum::join_gf16(xs, sel, 16, back); }
                else { j = bignum::join_prime(xs, sel, prime, 16, back); }
                if !j || back[..] != key[..] { ok = false; }
            }
            if t >= 2 {
                take(parts, len, pick[..t - 1], sel, xs);
                var back: u8[>..] = [];
                var j = false;
                if method == 0 { j = bignum::join_gf8(xs, sel, 16, back); }
                else if method == 1 { j = bignum::join_gf16(xs, sel, 16, back); }
                else { j = bignum::join_prime(xs, sel, prime, 16, back); }
                if j && back[..] == key[..] { short_differs = false; }
            }
        }
        var xp: u8[>..] = [];
        var xb: u8[>..] = [];
        if !bignum::split_xor(key, n, xp) || !bignum::join_xor(xp, 16, xb) || xb[..] != key[..] { ok = false; }
    }
    check("round trips", ok);
    check("fewer parts than the threshold do not give the secret", short_differs);
    var bad: u8[>..] = [];
    let k = random(16);
    check("a threshold above the parts refused", !bignum::split_gf8(k, 3, 4, bad));
    check("256 parts refused in GF(2^8)", !bignum::split_gf8(k, 256, 2, bad));
    check("an odd length refused in GF(2^16)", !bignum::split_gf16(k[..15], 3, 2, bad));
    let dup: i64[2] = [1, 1];
    var two: u8[>..] = [];
    two.append(k);
    two.append(k);
    check("a part twice refused", !bignum::join_gf8(dup, two, 16, bad));
}

fn main() {
    oasis();
    reference();
    field_laws();
    round_trips();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
