// net.ip and net.idna: IP addresses parsed (Go's netip rules), printed
// the canonical way (RFC 5952), classified, with ports and as prefixes;
// host:port split and joined; Punycode (Go's cookiejar vectors).

import std;
import gslib from "../..";
import gslib.net.ip;
import gslib.net.idna;

var failures = 0;

fn check(what: const u8[:], got: const u8[:], want: const u8[:]) {
    if got != want {
        print("FAIL ", what, ": got '", got, "', want '", want, "'");
        failures++;
    }
}

fn check_bool(what: const u8[:], got: bool, want: bool) {
    if got != want { print("FAIL ", what, ": got ", got); failures++; }
}

fn ip(s: const u8[:], want_kind: i64, want_hex: const u8[:]) {
    let a, kind = net::parse_ip(s);
    if kind != want_kind { print("FAIL ip ", s, ": kind ", kind); failures++; return; }
    if kind == 0 { return; }
    var h: u8[>..] = [];
    for c in a { format_uint(h, c, 16, 2, '0'); }
    check(s, h, want_hex);
}

fn ips() {
    ip("1.2.3.4", 4, "00000000000000000000ffff01020304");
    ip("255.255.255.255", 4, "00000000000000000000ffffffffffff");
    ip("01.2.3.4", 0, "");
    ip("1.2.3", 0, "");
    ip("1.2.3.4.5", 0, "");
    ip("256.1.1.1", 0, "");
    ip("1..2.3", 0, "");
    ip("::", 6, "00000000000000000000000000000000");
    ip("::1", 6, "00000000000000000000000000000001");
    ip("1::", 6, "00010000000000000000000000000000");
    ip("1:2:3:4:5:6:7:8", 6, "00010002000300040005000600070008");
    ip("1:2:3:4:5:6:7::", 6, "00010002000300040005000600070000");
    ip("1::8", 6, "00010000000000000000000000000008");
    ip("::ffff:1.2.3.4", 6, "00000000000000000000ffff01020304");
    ip("1:2:3:4:5:6:1.2.3.4", 6, "00010002000300040005000601020304");
    ip("abcd:EF01::", 6, "abcdef01000000000000000000000000");
    ip("1:2:3:4:5:6:7:8:9", 0, "");
    ip("1:2:3:4:5:6:7:8::", 0, "");
    ip("::1:2:3:4:5:6:7:8", 0, "");
    ip("1::2::3", 0, "");
    ip(":::", 0, "");
    ip("12345::", 0, "");
    ip("1:", 0, "");
    ip(":1", 0, "");
    ip("1:2:3:4:5:6:7:1.2.3.4", 0, "");
    ip("::1.2.3", 0, "");
    ip("", 0, "");
    check_bool("zone", net::is_ip("fe80::1%en0"), true);
    check_bool("empty zone", net::is_ip("fe80::1%"), false);
    check_bool("v4 zone", net::is_ip("1.2.3.4%x"), false);
    let l1, k1 = net::parse_ip("127.9.9.9");
    check_bool("127/8 loopback", net::ip_is_loopback(l1, k1), true);
    let l2, k2 = net::parse_ip("::1");
    check_bool("::1 loopback", net::ip_is_loopback(l2, k2), true);
    let l3, k3 = net::parse_ip("::2");
    check_bool("::2 not loopback", net::ip_is_loopback(l3, k3), false);
    let l4, k4 = net::parse_ip("::ffff:127.0.0.1");
    check_bool("mapped loopback", net::ip_is_loopback(l4, k4), true);
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i + 1 < s.len {
        out.push((net::ip_hex(s[i]) * 16 + net::ip_hex(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn punycode() {
    let data = embed_file("vectors/punycode.txt");
    var n = 0;
    each_split(data, '\n') {
        let line = it;
        let sp = position(line, ' ');
        if line.len > 0 && line[0] != '#' && sp > 0 {
            let label = unhex(line[..sp]);
            var want: u8[>..] = [];
            if line[sp + 1..] != "-" { want.append(line[sp + 1..]); }
            var got: u8[>..] = [];
            check_bool("punycode ok", net::punycode_encode(got, label), true);
            check(line, got, want);
            n++;
        }
    };
    print("punycode vectors: ", n);
}


// Parsed, then printed: want "" for text that is not an address.
fn canon(s: const u8[:], want: const u8[:]) {
    let a, ok = net::parse_addr(s);
    if want.len == 0 { check_bool(str("not an address: ", s), ok, false); return; }
    check_bool(str("parse ", s), ok, true);
    check(str("print ", s), net::addr_string(a), want);
    let back, ok2 = net::parse_addr(net::addr_string(a));
    check_bool(str("round trip ", s), ok2 && net::addr_equal(a, back), true);
}

fn printing() {
    canon("1.2.3.4", "1.2.3.4");
    canon("2001:DB8::1", "2001:db8::1");
    canon("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1");    // the first of equal runs
    canon("2001:db8:0:0:0:1:0:0", "2001:db8::1:0:0");      // the longest run
    canon("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"); // one zero group stays
    canon("0:0:0:0:0:0:0:0", "::");
    canon("::1", "::1");
    canon("1::", "1::");
    canon("0001:0db8::0010", "1:db8::10");
    canon("::ffff:10.1.2.3", "::ffff:10.1.2.3");
    canon("fe80::1%eth0", "fe80::1%eth0");
    canon("1.2.3.4%eth0", "");
    canon("fe80::1%", "");
    canon("fe80::1%abcdefghijklmnop", "");
    canon("", "");
    canon("example.com", "");
    let a, ok = net::addr_from_bytes([192, 0, 2, 1]);
    check("from 4 bytes", net::addr_string(a), "192.0.2.1");
    check("v4 bytes", net::addr_bytes(a), [192, 0, 2, 1]);
    let m, okm = net::parse_addr("::ffff:192.0.2.1");
    check_bool("mapped is not the v4 address", net::addr_equal(m, a), false);
    let um = net::unmap(m);
    check_bool("unmapped is", net::addr_equal(um, a), true);
    check_bool("is_4_in_6", net::is_4_in_6(m) && !net::is_4_in_6(a) && net::is_4(a) && net::is_6(m), true);
    let none = net::no_addr();
    check("invalid", net::addr_string(none), "invalid IP");
    let v4 = net::addr_v4(10, 0, 0, 1);
    check("addr_v4", net::addr_string(v4), "10.0.0.1");
}

// Each class asked of an address: loopback, unspecified, private,
// link-local unicast, link-local multicast, multicast, global unicast.
fn kinds(s: const u8[:], want: const u8[:]) {
    let a, ok = net::parse_addr(s);
    var got: u8[>..] = [];
    for b in [net::is_loopback(a), net::is_unspecified(a), net::is_private(a), net::is_link_local_unicast(a),
              net::is_link_local_multicast(a), net::is_multicast(a), net::is_global_unicast(a)] {
        got.push(if b { '1' } else { '0' });
    }
    check(str("classes of ", s), got, want);
}

fn classes() {
    kinds("127.0.0.1", "1000000");
    kinds("127.255.0.9", "1000000");
    kinds("::1", "1000000");
    kinds("::ffff:127.0.0.1", "1000000");
    kinds("0.0.0.0", "0100000");
    kinds("::", "0100000");
    kinds("10.1.2.3", "0010001");
    kinds("172.16.0.1", "0010001");
    kinds("172.32.0.1", "0000001");
    kinds("192.168.1.1", "0010001");
    kinds("fd00::1", "0010001");
    kinds("169.254.1.1", "0001000");
    kinds("fe80::1", "0001000");
    kinds("224.0.0.251", "0000110");
    kinds("ff02::1", "0000110");
    kinds("239.1.1.1", "0000010");
    kinds("ff05::1", "0000010");
    kinds("8.8.8.8", "0000001");
    kinds("2001:db8::1", "0000001");
    kinds("255.255.255.255", "0000000");
}

fn host_ports() {
    let h, p, ok = net::split_host_port("example.com:80");
    check_bool("split ok", ok && h == "example.com" && p == "80", true);
    let h6, p6, ok6 = net::split_host_port("[::1]:443");
    check_bool("split v6", ok6 && h6 == "::1" && p6 == "443", true);
    let h0, p0, ok0 = net::split_host_port(":8080");
    check_bool("split no host", ok0 && h0.len == 0 && p0 == "8080", true);
    for bad in ["example.com", "::1:80", "[::1]80", "[::1", "a[b]:80", "[::1]:8]0", "h:80:90"] {
        let x, y, okb = net::split_host_port(bad);
        check_bool(str("split refuses ", bad), okb, false);
    }
    check("join v6", net::join_host_port("::1", "80"), "[::1]:80");
    check("join name", net::join_host_port("example.com", "80"), "example.com:80");
    let ap, oka = net::parse_addr_port("[fe80::1%eth0]:22");
    check_bool("addr port", oka && ap.port == 22, true);
    check("addr port printed", net::addr_port_string(ap), "[fe80::1%eth0]:22");
    let a4, ok4 = net::parse_addr_port("192.0.2.1:65535");
    check("v4 addr port", net::addr_port_string(a4), "192.0.2.1:65535");
    for bad in ["::1:80", "[1.2.3.4]:80", "1.2.3.4:65536", "1.2.3.4:", "[::1]", "host:80"] {
        let x, okb = net::parse_addr_port(bad);
        check_bool(str("addr port refuses ", bad), okb, false);
    }
}

fn prefixes() {
    let p, ok = net::parse_prefix("10.1.2.3/8");
    check_bool("prefix", ok && p.bits == 8, true);
    check("prefix kept", net::prefix_string(p), "10.1.2.3/8");
    let pm = net::prefix_masked(p);
    check("prefix masked", net::prefix_string(pm), "10.0.0.0/8");
    let a, oka = net::parse_addr("10.200.0.1");
    let b, okb = net::parse_addr("11.0.0.1");
    let m, okm = net::parse_addr("::ffff:10.0.0.1");
    check_bool("contains", net::prefix_contains(p, a), true);
    check_bool("outside", net::prefix_contains(p, b), false);
    check_bool("mapped not in a v4 prefix", net::prefix_contains(p, m), false);
    let q, okq = net::parse_prefix("2001:db8::/32");
    let c, okc = net::parse_addr("2001:db8:ffff::1");
    let d, okd = net::parse_addr("2001:db9::1");
    check_bool("v6 contains", okq && net::prefix_contains(q, c) && !net::prefix_contains(q, d), true);
    let all, okall = net::parse_prefix("0.0.0.0/0");
    check_bool("/0 holds every v4", okall && net::prefix_contains(all, b), true);
    let one, okone = net::parse_prefix("192.0.2.1/32");
    let e, oke = net::parse_addr("192.0.2.1");
    let f, okf = net::parse_addr("192.0.2.2");
    check_bool("/32", okone && net::prefix_contains(one, e) && !net::prefix_contains(one, f), true);
    let w, okw = net::parse_prefix("2001:db8:abcd::1/36");
    let wm = net::prefix_masked(w);
    check("masked v6", net::prefix_string(wm), "2001:db8:a000::/36");
    for bad in ["10.0.0.0/33", "::/129", "10.0.0.0/08", "10.0.0.0/", "10.0.0.0", "/8", "x/8", "fe80::1%eth0/64"] {
        let x, okb = net::parse_prefix(bad);
        check_bool(str("prefix refuses ", bad), okb, false);
    }
}

fn main() {
    ips();
    printing();
    classes();
    host_ports();
    prefixes();
    punycode();
    let a, ok = net::to_ascii_host("Bücher.example");
    check("to_ascii_host", a, "xn--bcher-kva.example");
    let b, okb = net::to_ascii_host("plain.Example");
    check("ascii untouched", b, "plain.Example");
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("ip: all passed");
}
