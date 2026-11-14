// tv: what the tests share: counting checks, hex, and the vector files in
// test/vectors (made by gpg 2.5 with test keys; see vectors/README).

namespace tv;

import std;
import os;

var checks = 0;
var failures = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok {
        failures++;
        if failures <= 40 { print("FAIL ", what); }
    }
}

fn check_int(what: const u8[:], got: i64, want: i64) {
    check(what, got == want);
    if got != want && failures <= 40 { print("      got ", got, ", want ", want); }
}

fn check_eq(what: const u8[:], got: const u8[:], want: const u8[:]) {
    check(what, got == want);
    if got != want && failures <= 40 {
        print("      got  ", hex(got));
        print("      want ", hex(want));
    }
}

// Prints the totals; exits 1 if anything failed.
fn done(name: const u8[:]) {
    print(name, ": ", checks - failures, "/", checks, " checks passed");
    if failures > 0 { exit(1); }
}

fn hex(b: const u8[:]) -> u8[>..] {
    let d = "0123456789abcdef";
    var out: u8[>..] = [];
    for x in b { out.push(d[(x >> 4) as i64]); out.push(d[(x & 15) as i64]); }
    return out;
}

fn nib(c: u8) -> u8 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

// Hex (spaces and line breaks ignored) as bytes.
fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var hi:  i64     = -1;
    for c in s {
        if c == ' ' || c == '\n' || c == '\r' { continue; }
        if hi < 0 { hi = nib(c); } else { out.push(((hi as! u8) << 4) | nib(c)); hi = -1; }
    }
    return out;
}

fn read(path: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { abort(str("cannot read ", path)); }
    return text;
}
