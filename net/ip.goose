// net.ip: IP addresses, as Go's net/netip has them: parsing IPv4 and IPv6
// (with a zone), printing them the canonical way (RFC 5952), telling
// loopback, private, link-local, multicast and unspecified ones apart,
// an address with a port ("[::1]:443"), host:port splitting and joining,
// and prefixes ("10.0.0.0/8") with whether one holds an address. Pure
// Goose; the sockets that take and give these are net.goose's.
//
//   import gslib.net.ip;      // `import net.ip;` inside gslib
//
//   let a, ok = net::parse_addr("2001:db8::1");
//   print(a, " ", net::is_private(a));        // 2001:db8::1 false
//   let p, okp = net::parse_prefix("10.0.0.0/8");
//   let b, okb = net::parse_addr("10.1.2.3");
//   net::prefix_contains(p, b);               // true
//
// An address keeps 16 bytes, IPv4 as ::ffff:a.b.c.d, and its kind: 4 for
// an IPv4 address, 6 for IPv6 (an IPv4-mapped one too, which prints as
// ::ffff:a.b.c.d and is not equal to the IPv4 address it maps), 0 for
// none. Go's rules: no leading zeros in IPv4 parts, at most four hex
// digits in an IPv6 group, "::" for at least one group.

namespace net;

import std;

struct Addr {
    ip:   u8[16],    // IPv4 as ::ffff:a.b.c.d
    kind: i64,       // 4, 6, or 0 for no address
    zone: u8[..16],  // an IPv6 zone ("eth0", or a scope id's number), "" for none
}

struct AddrPort { addr: Addr, port: i64 }

// A network: the first bits of addr (the rest zero after prefix_masked).
struct Prefix { addr: Addr, bits: i64 }

fn no_addr() -> Addr { Addr { ip: [0; 16], kind: 0, zone: [] } }

fn ip_hex(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

// --- Parsing ---------------------------------------------------------------

// An IPv4 address in dotted decimal, Go's netip way: four parts, no
// leading zeros, each at most 255.
fn parse_ip4(s: const u8[:], out: u8[:]) -> bool {
    var part = 0;
    var digits = 0;
    var v: i64 = 0;
    for i in s.len {
        let c = s[i];
        if c >= '0' && c <= '9' {
            if digits == 1 && v == 0 { return false; }
            v = v * 10 + (c - '0');
            digits++;
            if v > 255 { return false; }
        } else if c == '.' {
            if digits == 0 || part == 3 { return false; }
            out[part] = v as! u8;
            part++;
            digits = 0;
            v = 0;
        } else {
            return false;
        }
    }
    if digits == 0 || part != 3 { return false; }
    out[3] = v as! u8;
    return true;
}

// An IP address: 4 for IPv4, 6 for IPv6 (an IPv4 tail allowed), 0 for
// neither; the 16 bytes (IPv4 as ::ffff:a.b.c.d). No zone.
fn parse_ip(s: const u8[:]) -> u8[16], i64 {
    var ip: u8[16] = [0; 16];
    var v4: u8[4] = [0; 4];
    if parse_ip4(s, v4) {
        ip[10] = 0xff; ip[11] = 0xff;
        for i in 4 { ip[12 + i] = v4[i]; }
        return ip, 4;
    }
    var ellipsis = -1;
    var p = 0;                      // the next byte of s
    if s.len >= 2 && s[0] == ':' && s[1] == ':' {
        ellipsis = 0;
        p = 2;
        if p == s.len { return ip, 6; }
    }
    var i = 0;                      // bytes of ip written
    while i < 16 {
        var off = 0;
        var acc: i64 = 0;
        while p + off < s.len {
            let v = ip_hex(s[p + off]);
            if v < 0 { break; }
            if off > 3 { return ip, 0; }
            acc = acc * 16 + v;
            off++;
        }
        if off == 0 { return ip, 0; }
        if p + off < s.len && s[p + off] == '.' {
            if (ellipsis < 0 && i != 12) || i + 4 > 16 { return ip, 0; }
            if !parse_ip4(s[p..], v4) { return ip, 0; }
            for k in 4 { ip[i + k] = v4[k]; }
            i += 4;
            p = s.len;
            break;
        }
        ip[i] = (acc >> 8) as! u8;
        ip[i + 1] = (acc & 0xff) as! u8;
        i += 2;
        p += off;
        if p == s.len { break; }
        if s[p] != ':' || p + 1 == s.len { return ip, 0; }
        p++;
        if s[p] == ':' {
            if ellipsis >= 0 { return ip, 0; }
            ellipsis = i;
            p++;
            if p == s.len { break; }
        }
    }
    if p != s.len { return ip, 0; }
    if i < 16 {
        if ellipsis < 0 { return ip, 0; }
        let n = 16 - i;
        var k = i - 1;
        while k >= ellipsis { ip[k + n] = ip[k]; k--; }
        for z in ellipsis..ellipsis + n { ip[z] = 0; }
    } else if ellipsis >= 0 {
        return ip, 0;
    }
    return ip, 6;
}

// An IP address with an IPv6 zone allowed ("fe80::1%en0"; the zone not empty).
fn parse_ip_zone(s: const u8[:]) -> u8[16], i64 {
    let z = position(s, '%');
    if z < 0 { return parse_ip(s); }
    let ip, kind = parse_ip(s[..z]);
    if kind != 6 || z + 1 == s.len { return ip, 0; }
    return ip, 6;
}

fn is_ip(s: const u8[:]) -> bool {
    let ip, kind = parse_ip_zone(s);
    return kind != 0;
}

// Whether the bytes and kind parse_ip gave are a loopback address
// (127.0.0.0/8, ::1; an IPv4-mapped 127.x too).
fn ip_is_loopback(ip: const u8[:], kind: i64) -> bool {
    if kind == 0 { return false; }
    if is_v4_bytes(ip) { return ip[12] == 127; }
    if kind != 6 { return false; }
    for i in 15 { if ip[i] != 0 { return false; } }
    return ip[15] == 1;
}

fn is_v4_bytes(ip: const u8[:]) -> bool {
    for i in 10 { if ip[i] != 0 { return false; } }
    return ip[10] == 0xff && ip[11] == 0xff;
}

// An address, IPv6 with a zone ("fe80::1%eth0") allowed (at most 15
// bytes of it); false for anything else.
fn parse_addr(s: const u8[:]) -> Addr, bool {
    var a = no_addr();
    let z = position(s, '%');
    let text = if z < 0 { s } else { s[..z] };
    let ip, kind = parse_ip(text);
    if kind == 0 { return a, false; }
    if z >= 0 && (kind != 6 || z + 1 == s.len || s.len - z - 1 > 15) { return a, false; }
    a.ip = ip;
    a.kind = kind;
    if z >= 0 { a.zone.append(s[z + 1..]); }
    return a, true;
}

// The address of 4 bytes (IPv4) or 16 (IPv6), as on the wire.
fn addr_from_bytes(b: const u8[:]) -> Addr, bool {
    var a = no_addr();
    if b.len == 4 {
        a.ip[10] = 0xff; a.ip[11] = 0xff;
        for i in 4 { a.ip[12 + i] = b[i]; }
        a.kind = 4;
        return a, true;
    }
    if b.len == 16 {
        for i in 16 { a.ip[i] = b[i]; }
        a.kind = 6;
        return a, true;
    }
    return a, false;
}

fn addr_v4(a: u8, b: u8, c: u8, d: u8) -> Addr {
    let bytes: u8[4] = [a, b, c, d];
    let r, ok = addr_from_bytes(bytes);
    return r;
}

// The address as on the wire: 4 bytes for IPv4, else 16; none for no address.
fn addr_bytes(a: const Addr&) -> u8[>..] {
    var out: u8[>..] = [];
    if a.kind == 4 { out.append(a.ip[12..16]); }
    else if a.kind == 6 { out.append(a.ip[..]); }
    return out;
}

// An IPv4-mapped IPv6 address as the IPv4 one; any other as it is.
fn unmap(a: const Addr&) -> Addr {
    var r = copy(a);
    if r.kind == 6 && is_v4_bytes(r.ip[..]) { r.kind = 4; r.zone.clear(); }
    return r;
}

fn addr_equal(a: const Addr&, b: const Addr&) -> bool {
    return a.kind == b.kind && a.ip[..] == b.ip[..] && a.zone[..] == b.zone[..];
}

fn is_valid(a: const Addr&) -> bool { a.kind != 0 }
fn is_4(a: const Addr&) -> bool { a.kind == 4 }
fn is_6(a: const Addr&) -> bool { a.kind == 6 }
fn is_4_in_6(a: const Addr&) -> bool { a.kind == 6 && is_v4_bytes(a.ip[..]) }

// --- What kind of address --------------------------------------------------
// As Go's netip: an IPv4-mapped address is judged as the IPv4 one.

// 127.0.0.0/8, ::1.
fn is_loopback(a: const Addr&) -> bool { ip_is_loopback(a.ip[..], a.kind) }

// 0.0.0.0, ::.
fn is_unspecified(a: const Addr&) -> bool {
    if a.kind == 4 { return (a.ip[12] | a.ip[13] | a.ip[14] | a.ip[15]) == 0; }
    if a.kind != 6 { return false; }
    for b in a.ip { if b != 0 { return false; } }
    return true;
}

// RFC 1918 (10/8, 172.16/12, 192.168/16) and RFC 4193 (fc00::/7).
fn is_private(a: const Addr&) -> bool {
    let u = unmap(a);
    if u.kind == 4 {
        let b0 = u.ip[12];
        let b1 = u.ip[13];
        return b0 == 10 || (b0 == 172 && (b1 & 0xf0) == 16) || (b0 == 192 && b1 == 168);
    }
    return u.kind == 6 && (u.ip[0] & 0xfe) == 0xfc;
}

// 169.254/16, fe80::/10 (unicast); 224.0.0.0/24, ff02::/16 (multicast).
fn is_link_local_unicast(a: const Addr&) -> bool {
    let u = unmap(a);
    if u.kind == 4 { return u.ip[12] == 169 && u.ip[13] == 254; }
    return u.kind == 6 && u.ip[0] == 0xfe && (u.ip[1] & 0xc0) == 0x80;
}

fn is_link_local_multicast(a: const Addr&) -> bool {
    let u = unmap(a);
    if u.kind == 4 { return u.ip[12] == 224 && u.ip[13] == 0 && u.ip[14] == 0; }
    return u.kind == 6 && u.ip[0] == 0xff && (u.ip[1] & 0x0f) == 0x02;
}

// 224.0.0.0/4, ff00::/8.
fn is_multicast(a: const Addr&) -> bool {
    let u = unmap(a);
    if u.kind == 4 { return (u.ip[12] & 0xf0) == 0xe0; }
    return u.kind == 6 && u.ip[0] == 0xff;
}

// Not any of the above, nor the IPv4 broadcast address: what may be
// routed to (private addresses included, as Go has it).
fn is_global_unicast(a: const Addr&) -> bool {
    let u = unmap(a);
    if u.kind == 0 || is_unspecified(u) || is_loopback(u) || is_multicast(u) || is_link_local_unicast(u) { return false; }
    if u.kind == 4 && (u.ip[12] & u.ip[13] & u.ip[14] & u.ip[15]) == 255 { return false; }
    return true;
}

// --- Printing --------------------------------------------------------------

fn put_hex16(out: u8[>..]&, v: i64) {
    let digits = "0123456789abcdef";
    var started = false;
    var shift = 12;
    while shift >= 0 {
        let d = (v >> shift) & 15;
        if d != 0 || started || shift == 0 { out.push(digits[d]); started = true; }
        shift -= 4;
    }
}

fn put_v4(out: u8[>..]&, b: const u8[:]) {
    for i in 4 {
        if i > 0 { out.push('.'); }
        format_int(out, b[i], 10, 0, ' ');
    }
}

// The address the canonical way: dotted IPv4; IPv6 as RFC 5952 has it
// (lower-case hex, no leading zeros, the longest run of two or more zero
// groups as "::", the first of equal runs), an IPv4-mapped one as
// ::ffff:a.b.c.d; "%zone" after. "invalid IP" for no address, as Go.
fn format(out: u8[>..]&, a: const Addr&) {
    if a.kind == 4 { put_v4(out, a.ip[12..16]); return; }
    if a.kind != 6 { out.append("invalid IP"); return; }
    if is_v4_bytes(a.ip[..]) {
        out.append("::ffff:");
        put_v4(out, a.ip[12..16]);
    } else {
        var best = -1;
        var best_len = 1;
        var g = 0;
        while g < 8 {
            if a.ip[2 * g] == 0 && a.ip[2 * g + 1] == 0 {
                var e = g;
                while e < 8 && a.ip[2 * e] == 0 && a.ip[2 * e + 1] == 0 { e++; }
                if e - g > best_len { best = g; best_len = e - g; }
                g = e;
            } else {
                g++;
            }
        }
        g = 0;
        while g < 8 {
            if g == best {
                out.append("::");
                g += best_len;
                continue;
            }
            if g > 0 && g != best + best_len { out.push(':'); }
            put_hex16(out, ((a.ip[2 * g] as i64) << 8) | a.ip[2 * g + 1]);
            g++;
        }
    }
    if a.zone.len > 0 {
        out.push('%');
        out.append(a.zone);
    }
}

fn addr_string(a: const Addr&) -> u8[>..] {
    var out: u8[>..] = [];
    format(out, a);
    return out;
}

// "1.2.3.4:80", "[::1]:80".
fn format(out: u8[>..]&, ap: const AddrPort&) {
    if ap.addr.kind == 6 { out.push('['); }
    format(out, ap.addr);
    if ap.addr.kind == 6 { out.push(']'); }
    out.push(':');
    format_int(out, ap.port, 10, 0, ' ');
}

fn addr_port_string(ap: const AddrPort&) -> u8[>..] {
    var out: u8[>..] = [];
    format(out, ap);
    return out;
}

// "10.0.0.0/8".
fn format(out: u8[>..]&, p: const Prefix&) {
    format(out, p.addr);
    out.push('/');
    format_int(out, p.bits, 10, 0, ' ');
}

fn prefix_string(p: const Prefix&) -> u8[>..] {
    var out: u8[>..] = [];
    format(out, p);
    return out;
}

// --- Hosts and ports -------------------------------------------------------

// Go's SplitHostPort: "host:port", "[host]:port" (the brackets taken
// off; an IPv6 address needs them), ":port"; the host and the port as
// text, false for anything else (no port, brackets that do not close, a
// colon too many). The port is not checked further.
fn split_host_port(s: const u8[:]) -> u8[>..], u8[>..], bool {
    var host: u8[>..] = [];
    var port: u8[>..] = [];
    var colon = -1;
    for i in s.len { if s[i] == ':' { colon = i; } }
    if colon < 0 { return host, port, false; }
    if s.len > 0 && s[0] == '[' {
        let close = position(s, ']');
        if close < 0 || close + 1 != colon { return host, port, false; }
        let h = s[1..close];
        if position(h, '[') >= 0 || position(h, ']') >= 0 { return host, port, false; }
        host.append(h);
    } else {
        let h = s[..colon];
        if position(h, ':') >= 0 || position(h, '[') >= 0 || position(h, ']') >= 0 { return host, port, false; }
        host.append(h);
    }
    let p = s[colon + 1..];
    if position(p, '[') >= 0 || position(p, ']') >= 0 { return host, port, false; }
    port.append(p);
    return host, port, true;
}

// Go's JoinHostPort: brackets around a host with a colon in it.
fn join_host_port(host: const u8[:], port: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let v6 = position(host, ':') >= 0;
    if v6 { out.push('['); }
    out.append(host);
    if v6 { out.push(']'); }
    out.push(':');
    out.append(port);
    return out;
}

fn port_number(s: const u8[:]) -> i64 {
    if s.len == 0 || s.len > 5 { return -1; }
    var v: i64 = 0;
    for c in s {
        if c < '0' || c > '9' { return -1; }
        v = v * 10 + (c - '0');
    }
    return if v > 65535 { -1 } else { v };
}

// An address and a port, as format writes them ("1.2.3.4:80",
// "[::1]:80", "[fe80::1%eth0]:80"); an IPv6 address must have brackets,
// an IPv4 one may not.
fn parse_addr_port(s: const u8[:]) -> AddrPort, bool {
    var ap = AddrPort { addr: no_addr(), port: 0 };
    let h, p, ok = split_host_port(s);
    if !ok { return ap, false; }
    let a, aok = parse_addr(h);
    let port = port_number(p);
    if !aok || port < 0 { return ap, false; }
    if (a.kind == 6) != (s.len > 0 && s[0] == '[') { return ap, false; }
    ap.addr = a;
    ap.port = port;
    return ap, true;
}

// --- Prefixes --------------------------------------------------------------

// A prefix "addr/bits": bits at most 32 for IPv4 and 128 for IPv6, no
// zone, no leading zeros in bits. The address is kept as given; see
// prefix_masked.
fn parse_prefix(s: const u8[:]) -> Prefix, bool {
    var p = Prefix { addr: no_addr(), bits: -1 };
    let slash = position(s, '/');
    if slash < 0 { return p, false; }
    let ip, kind = parse_ip(s[..slash]);
    let digits = s[slash + 1..];
    if kind == 0 || digits.len == 0 || digits.len > 3 || (digits.len > 1 && digits[0] == '0') { return p, false; }
    var bits: i64 = 0;
    for c in digits {
        if c < '0' || c > '9' { return p, false; }
        bits = bits * 10 + (c - '0');
    }
    if bits > (if kind == 4 { 32 } else { 128 }) { return p, false; }
    p.addr.ip = ip;
    p.addr.kind = kind;
    p.bits = bits;
    return p, true;
}

// The prefix with the address's bits past `bits` zeroed: "10.1.2.3/8" is 10.0.0.0/8.
fn prefix_masked(p: const Prefix&) -> Prefix {
    var r = copy(p);
    let total = if p.addr.kind == 4 { p.bits + 96 } else { p.bits };
    for b in total..128 {
        r.addr.ip[b / 8] = r.addr.ip[b / 8] & ~((0x80 >> (b % 8)) as! u8);
    }
    return r;
}

// Whether the prefix holds the address: the same kind (an IPv4 prefix
// does not hold an IPv4-mapped IPv6 address), and the first bits equal.
fn prefix_contains(p: const Prefix&, a: const Addr&) -> bool {
    if p.addr.kind == 0 || p.addr.kind != a.kind || a.zone.len > 0 { return false; }
    let total = if p.addr.kind == 4 { p.bits + 96 } else { p.bits };
    for b in total {
        let m = (0x80 >> (b % 8)) as! u8;
        if (a.ip[b / 8] & m) != (p.addr.ip[b / 8] & m) { return false; }
    }
    return true;
}
