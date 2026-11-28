// hex: bytes as hexadecimal text and back, as Go's encoding/hex: two
// digits for each byte, high nibble first (RFC 4648 §8's base16, in either
// case), and a dump in hexdump -C's layout for looking at bytes.
//
//   var text: u8[>..] = [];
//   hex::encode(text, digest);                   // "00ff1a..."
//   hex::encode_ct(text, key);                   // the same text, in constant time
//   print(hex::to_str(digest));
//   var bytes: u8[>..] = [];
//   if !hex::decode(bytes, "DEADbeef") { abort("not hex"); }
//
// encode_ct and decode compute the digits rather than look them up in a
// table, and decode accumulates validity instead of stopping at the first
// bad character, so their loops have no exits or memory accesses that
// depend on the bytes: what a key holds does not choose which memory is
// read or how long it takes. encode is the same from 16 bytes on, and below
// that takes each digit from a 16-byte table, which is faster for a few
// bytes; use encode_ct for secrets. The long loops are `simd fn`s, as std's
// base64 is: the C compiler vectorizes them, and where clang builds for
// x86-64 they run as AVX2 or AVX-512 code on a CPU that has it.

namespace hex;

import std;

// What `value` gives for a byte that is not a hex digit.
let INVALID: u8 = 255;

// The digit of a nibble: '0' + n, and from 10 on 39 more for 'a'-'f' (7
// for 'A'-'F'). 9 - n wraps to 128 or more exactly when n > 9, so its top
// bit, spread to a mask, chooses the gap without a branch.
fn digit(n: u8, gap: u8) -> u8 {
    let over: u8 = 0 - ((9 - n) >> 7);
    return n + '0' + (over & gap);
}

// The value of a hex digit, either case, INVALID for anything else. A
// range test is one wrapping subtraction and compare; `| 0x20` folds
// 'A'-'F' onto 'a'-'f'.
fn value(c: u8) -> u8 {
    var v = INVALID;
    if c - '0' < 10 { v = c - '0'; }
    if (c | 0x20) - 'a' < 6 { v = (c | 0x20) - 'a' + 10; }
    return v;
}

// Inputs shorter than these are appended a digit at a time: for a few
// bytes, sizing out and slicing it cost more than the loop saves. Measured
// on an M1; encode's table loop holds out longer than decode's.
let SHORT_ENCODE = 16;
let SHORT = 8;

// Appends two digits for every byte of src.
simd fn encode_long(out: u8[>..]&, src: const u8[:], gap: u8) {
    let start = out.len;
    out.resize(start + src.len * 2, 0);
    var s = src;
    var d = out[start..];
    // d always has room for the rest of s; testing it as well lets the
    // compiler see that every store is in bounds.
    while s.len >= 1 && d.len >= 2 {
        d[0] = digit(s[0] >> 4, gap);
        d[1] = digit(s[0] & 15, gap);
        s = s[1..];
        d = d[2..];
    }
}

// Appends the lowercase hex of src to out: "00ff1a". Not for secrets
// shorter than 16 bytes, whose digits it looks up: encode_ct is.
fn encode(out: u8[>..]&, src: const u8[:]) {
    if src.len >= SHORT_ENCODE { encode_long(out, src, 39); return; }
    // A local, not a global: the C reads a global's slice afresh each time.
    let d = "0123456789abcdef";
    for c in src { out.push(d[c >> 4]); out.push(d[c & 15]); }
}

// Appends the uppercase hex of src to out: "00FF1A". As encode.
fn encode_upper(out: u8[>..]&, src: const u8[:]) {
    if src.len >= SHORT_ENCODE { encode_long(out, src, 7); return; }
    let d = "0123456789ABCDEF";
    for c in src { out.push(d[c >> 4]); out.push(d[c & 15]); }
}

// encode in constant time for every length: the hex of a key or another
// secret.
fn encode_ct(out: u8[>..]&, src: const u8[:]) {
    if src.len >= SHORT { encode_long(out, src, 39); return; }
    for c in src { out.push(digit(c >> 4, 39)); out.push(digit(c & 15, 39)); }
}

// The lowercase hex of src, returned.
fn to_str(src: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    encode(out, src);
    return out;
}

// Appends the bytes src spells to out, and returns whether src is valid:
// an even number of hex digits, in either case, and nothing else (no
// spaces, colons or "0x"). Invalid input leaves out as it was.
fn decode(out: u8[>..]&, src: const u8[:]) -> bool {
    if src.len % 2 != 0 { return false; }
    if src.len >= 2 * SHORT { return decode_long(out, src); }
    let start = out.len;
    var seen: u8 = 0;
    var i = 0;
    while i + 1 < src.len {
        let a = value(src[i]);
        let b = value(src[i + 1]);
        seen |= a | b;
        out.push(a << 4 | (b & 15));
        i += 2;
    }
    let valid = seen < 16;
    if !valid { out.resize(start); }
    return valid;
}

simd fn decode_long(out: u8[>..]&, src: const u8[:]) -> bool {
    let start = out.len;
    out.resize(start + src.len / 2, 0);
    var s = src;
    var o = out[start..];
    // Digits fit in four bits, so only an INVALID among them ORs to
    // INVALID's high bits.
    var seen: u8 = 0;
    while s.len >= 2 && o.len >= 1 {
        let a = value(s[0]);
        let b = value(s[1]);
        seen |= a | b;
        o[0] = a << 4 | (b & 15);
        s = s[2..];
        o = o[1..];
    }
    let valid = seen < 16;
    if !valid { out.resize(start); }
    return valid;
}

// Appends src as hexdump -C (and Go's hex.Dump) shows it: lines of 16
// bytes, each with its offset in eight digits, the bytes in hex in two
// groups of eight, and the printable ones between bars, '.' for the rest.
//
//   00000000  47 6f 6f 73 65 0a                                 |Goose.|
fn dump(out: u8[>..]&, src: const u8[:]) {
    var off = 0;
    while off < src.len {
        let line = src[off..min(off + 16, src.len)];
        format_uint(out, off as u64, 16, 8, '0');
        out.append("  ");
        for i in 16 {
            if i < line.len {
                out.push(digit(line[i] >> 4, 39));
                out.push(digit(line[i] & 15, 39));
                out.push(' ');
            } else {
                out.append("   ");
            }
            if i == 7 { out.push(' '); }
        }
        out.append(" |");
        for c in line { out.push(if c >= 0x20 && c < 0x7f { c } else { '.' }); }
        out.append("|\n");
        off += 16;
    }
}
