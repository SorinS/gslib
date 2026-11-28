// hex: RFC 4648 §10's base16 vectors both ways; every byte value encoded
// in both cases and decoded back; every character's validity against a
// plain reference; odd lengths, bad characters at each position and
// prefixes that are not digits refused, with out left as it was; appending
// to text already there; and dump against hexdump -C's output.
import std;
import gslib from "../../..";
import gslib.encoding.hex;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn enc(b: const u8[:]) -> u8[>..] { var o: u8[>..] = []; hex::encode(o, b); return o; }
fn enc_upper(b: const u8[:]) -> u8[>..] { var o: u8[>..] = []; hex::encode_upper(o, b); return o; }
fn enc_ct(b: const u8[:]) -> u8[>..] { var o: u8[>..] = []; hex::encode_ct(o, b); return o; }

fn dec(s: const u8[:]) -> u8[>..], bool {
    var o: u8[>..] = [];
    let ok = hex::decode(o, s);
    return o, ok;
}

// The value of a hex digit by the obvious branches, -1 otherwise.
fn ref_value(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

fn rfc4648() {
    let plain: const u8[:][7] = ["", "f", "fo", "foo", "foob", "fooba", "foobar"];
    let upper: const u8[:][7] = ["", "66", "666F", "666F6F", "666F6F62", "666F6F6261", "666F6F626172"];
    let lower: const u8[:][7] = ["", "66", "666f", "666f6f", "666f6f62", "666f6f6261", "666f6f626172"];
    for i in 7 {
        check("rfc4648 encode_upper", enc_upper(plain[i]) == upper[i]);
        check("rfc4648 encode", enc(plain[i]) == lower[i]);
        check("rfc4648 to_str", hex::to_str(plain[i]) == lower[i]);
        check("rfc4648 encode_ct", enc_ct(plain[i]) == lower[i]);
        let a, ok1 = dec(upper[i]);
        check("rfc4648 decode upper", ok1 && a == plain[i]);
        let b, ok2 = dec(lower[i]);
        check("rfc4648 decode lower", ok2 && b == plain[i]);
    }
}

fn every_byte() {
    var all: u8[256] = [0; 256];
    for i in 256 { all[i] = i as u8; }
    let lo = enc(all);
    let up = enc_upper(all);
    check("all: length", lo.len == 512 && up.len == 512);
    let digits = "0123456789abcdef";
    let udigits = "0123456789ABCDEF";
    var same = true;
    for i in 256 {
        if lo[2 * i] != digits[i >> 4] || lo[2 * i + 1] != digits[i & 15] { same = false; }
        if up[2 * i] != udigits[i >> 4] || up[2 * i + 1] != udigits[i & 15] { same = false; }
    }
    check("all: digits", same);
    check("all: encode_ct", enc_ct(all) == lo);
    let a, ok1 = dec(lo);
    check("all: decode lower", ok1 && a == all);
    let b, ok2 = dec(up);
    check("all: decode upper", ok2 && b == all);
    // Mixed case within a byte.
    let c, ok3 = dec("aBcDeF");
    check("mixed case", ok3 && c.len == 3 && c[0] == 0xab && c[1] == 0xcd && c[2] == 0xef);
}

// Every length from 0 to 40, across the short inputs' table and the long
// loop: the three encoders agree with a plain reference.
fn every_length() {
    var src: u8[>..] = [];
    var agree = true;
    for n in 41 {
        var want: u8[>..] = [];
        var wantup: u8[>..] = [];
        for c in src {
            want.push("0123456789abcdef"[c >> 4]); want.push("0123456789abcdef"[c & 15]);
            wantup.push("0123456789ABCDEF"[c >> 4]); wantup.push("0123456789ABCDEF"[c & 15]);
        }
        if enc(src) != want || enc_ct(src) != want || enc_upper(src) != wantup { agree = false; }
        let back, ok = dec(want);
        if !ok || back != src { agree = false; }
        src.push((n * 167 + 13) as! u8);
    }
    check("every length", agree);
}

fn every_char() {
    var agree = true;
    for i in 256 {
        let c = i as u8;
        let v = hex::value(c);
        let r = ref_value(c);
        if r < 0 { if v != hex::INVALID { agree = false; } } else if v != r { agree = false; }
        // In each position of a pair, and of a longer text.
        var t: u8[4] = ['4', '1', c, '0'];
        let o1, ok1 = dec(t);
        if ok1 != (r >= 0) { agree = false; }
        if ok1 && (o1.len != 2 || o1[0] != 0x41 || o1[1] != r * 16) { agree = false; }
        t = ['4', '1', '0', c];
        let o2, ok2 = dec(t);
        if ok2 != (r >= 0) { agree = false; }
        if ok2 && o2[1] != r { agree = false; }
    }
    check("every character", agree);
}

fn refused() {
    let bad: const u8[:][10] = ["0", "abc", "0g", "g0", " 00", "00 ", "0x00", "00:11", "de ad", "zz"];
    for s in bad {
        var o: u8[>..] = [];
        o.append("kept");
        let ok = hex::decode(o, s);
        check("refused", !ok && o == "kept");
    }
    // A bad character after many good ones: nothing of it left behind.
    var long: u8[>..] = [];
    for i in 1000 { long.append("a5"); }
    long[1999] = 'G';
    var o: u8[>..] = [];
    o.append("x");
    check("refused late", !hex::decode(o, long) && o == "x");
    long[1999] = '5';
    check("accepted long", hex::decode(o, long) && o.len == 1001 && o[1000] == 0xa5);
}

fn appends() {
    var o: u8[>..] = [];
    o.append("key=");
    hex::encode(o, "\x01\xfe");
    check("encode appends", o == "key=01fe");
    hex::encode_upper(o, "\x0a");
    check("encode_upper appends", o == "key=01fe0A");
    var b: u8[>..] = [];
    b.push(7);
    check("decode appends", hex::decode(b, "0809") && b.len == 3 && b[0] == 7 && b[1] == 8 && b[2] == 9);
    check("decode empty", hex::decode(b, "") && b.len == 3);
    var e: u8[>..] = [];
    hex::encode(e, "");
    check("encode empty", e.len == 0);
}

fn dumps() {
    // hexdump -C of the same bytes, less its last line (the end offset).
    var want: u8[>..] = [];
    want.append("00000000  47 6f 6f 73 65 20 64 65  62 75 67 67 65 72 20 30  |Goose debugger 0|\n");
    want.append("00000010  2e 33 0a 00 01 7f 80 ff  20 74 61 62 09 68 65 72  |.3...... tab.her|\n");
    want.append("00000020  65                                                |e|\n");
    var d: u8[>..] = [];
    hex::dump(d, "Goose debugger 0.3\n\x00\x01\x7f\x80\xff tab\there");
    check("dump", d == want);
    if d != want { print(d); }
    var e: u8[>..] = [];
    hex::dump(e, "");
    check("dump empty", e.len == 0);
    var f: u8[>..] = [];
    hex::dump(f, "0123456789abcdef");
    check("dump one line", f == "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n");
}

fn main() {
    rfc4648();
    every_byte();
    every_length();
    every_char();
    refused();
    appends();
    dumps();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
