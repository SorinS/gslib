// net.idna: host names outside ASCII in their ASCII form, as Go's
// cookiejar and http proxy rules take them: each label with a byte past
// 0x7f as "xn--" and its Punycode (RFC 3492). No IDNA2008 mapping or
// validation beyond lowering ASCII letters in such labels.
//
//   import gslib.net.idna;    // `import net.idna;` inside gslib
//
//   let a, ok = net::to_ascii_host("bücher.example");   // "xn--bcher-kva.example"

namespace net;

import std;

let PUNY_BASE: i64 = 36;
let PUNY_TMIN: i64 = 1;
let PUNY_TMAX: i64 = 26;
let PUNY_SKEW: i64 = 38;
let PUNY_DAMP: i64 = 700;
let PUNY_INITIAL_BIAS: i64 = 72;
let PUNY_INITIAL_N: i64 = 128;

fn puny_digit(d: i64) -> u8 { if d < 26 { ('a' + d) as! u8 } else { ('0' + d - 26) as! u8 } }

fn puny_adapt(delta0: i64, num_points: i64, first: bool) -> i64 {
    var delta = if first { delta0 / PUNY_DAMP } else { delta0 / 2 };
    delta += delta / num_points;
    var k: i64 = 0;
    while delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2 {
        delta /= PUNY_BASE - PUNY_TMIN;
        k += PUNY_BASE;
    }
    return k + (PUNY_BASE - PUNY_TMIN + 1) * delta / (delta + PUNY_SKEW);
}

// UTF-8 to code points; false for bytes that are not UTF-8.
fn utf8_points(s: const u8[:], out: i64[>..]&) -> bool {
    var i = 0;
    while i < s.len {
        let c = s[i];
        var n = 0;
        var cp: i64 = 0;
        if c < 0x80 { cp = c; n = 1; }
        else if c >= 0xc2 && c < 0xe0 { cp = c & 0x1f; n = 2; }
        else if c >= 0xe0 && c < 0xf0 { cp = c & 0x0f; n = 3; }
        else if c >= 0xf0 && c < 0xf5 { cp = c & 0x07; n = 4; }
        else { return false; }
        if i + n > s.len { return false; }
        for k in 1..n {
            let d = s[i + k];
            if (d & 0xc0) != 0x80 { return false; }
            cp = (cp << 6) | (d & 0x3f);
        }
        if (n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff) {
            return false;
        }
        out.push(cp);
        i += n;
    }
    return true;
}

// One label's Punycode (RFC 3492 §6.3), without the "xn--" prefix.
fn punycode_encode(out: u8[>..]&, label: const u8[:]) -> bool {
    var cps: i64[>..] = [];
    if !utf8_points(label, cps) { return false; }
    var n = PUNY_INITIAL_N;
    var delta: i64 = 0;
    var bias = PUNY_INITIAL_BIAS;
    var b: i64 = 0;
    for cp in cps { if cp < 0x80 { out.push(cp as! u8); b++; } }
    var h = b;
    if b > 0 { out.push('-'); }
    while h < cps.len {
        var m: i64 = 0x7fffffff;
        for cp in cps { if cp >= n && cp < m { m = cp; } }
        delta += (m - n) * (h + 1);
        if delta > 0x7fffffff { return false; }
        n = m;
        for cp in cps {
            if cp < n { delta++; }
            if cp == n {
                var q = delta;
                var k = PUNY_BASE;
                while true {
                    var t = k - bias;
                    if t < PUNY_TMIN { t = PUNY_TMIN; } else if t > PUNY_TMAX { t = PUNY_TMAX; }
                    if q < t { break; }
                    out.push(puny_digit(t + (q - t) % (PUNY_BASE - t)));
                    q = (q - t) / (PUNY_BASE - t);
                    k += PUNY_BASE;
                }
                out.push(puny_digit(q));
                bias = puny_adapt(delta, h + 1, h == b);
                delta = 0;
                h++;
            }
        }
        delta++;
        n++;
    }
    return true;
}

// A host name in ASCII: each label with a byte past 0x7f as "xn--" and its
// Punycode, ASCII letters lowered in such labels only (Go's cookiejar
// toASCII). Names already ASCII come back unchanged.
fn to_ascii_host(h: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var ascii = true;
    for c in h { if c >= 0x80 { ascii = false; } }
    if ascii { out.append(h); return out, true; }
    var ok = true;
    var first = true;
    each_split(h, '.') {
        if !first { out.push('.'); }
        first = false;
        var plain = true;
        for c in it { if c >= 0x80 { plain = false; } }
        if plain {
            out.append(it);
        } else {
            var low: u8[>..] = [];
            for c in it { low.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); }
            out.append("xn--");
            if !punycode_encode(out, low) { ok = false; }
        }
    };
    return out, ok;
}
