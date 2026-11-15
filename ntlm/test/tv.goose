// tv: what ntlm's tests share: counting checks, hex, and the [MS-NLMP]
// §4.2.1 common values (user "User", domain "Domain", password
// "Password", server "Server", workstation "COMPUTER").

namespace tv;

import std;
import os;
import gslib.ntlm;

var checks = 0;
var failures = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok {
        failures++;
        print("FAIL ", what);
    }
}

// That code is what came back.
fn check_err(what: const u8[:], got: i64, want: i64) {
    check(what, got == want);
    if got != want { print("      got ", ntlm::error_text(got), ", want ", ntlm::error_text(want)); }
}

fn check_hex(what: const u8[:], got: const u8[:], want_hex: const u8[:]) {
    let g = hex(got);
    check(what, g[..] == want_hex);
    if g[..] != want_hex { print("      got  ", g, "\n      want ", want_hex); }
}

fn done(name: const u8[:]) {
    print(name, ": ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let d = "0123456789abcdef";
    for c in b { out.push(d[c >> 4]); out.push(d[c & 15]); }
    return out;
}

// Hex with spaces allowed, as the spec prints it.
fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var hi = -1;
    for c in s {
        var v = -1;
        if c >= '0' && c <= '9' { v = c - '0'; }
        else if c >= 'a' && c <= 'f' { v = c - 'a' + 10; }
        else if c >= 'A' && c <= 'F' { v = c - 'A' + 10; }
        if v < 0 { continue; }
        if hi < 0 { hi = v; } else { out.push((hi * 16 + v) as! u8); hi = -1; }
    }
    return out;
}

let USER = "User";
let DOMAIN = "Domain";
let PASSWORD = "Password";
let WORKSTATION = "COMPUTER";

// 2026-01-01T00:00:00Z.
let NOW: i64 = 1767225600;
