// dns.zone: the presentation form read, as miekg's ZoneParser and NewRR
// read it (RFC 1035 §5, with BIND's extensions): records one per line or
// across parentheses, comments after ';', quoted strings, \X and \DDD
// escapes, "@" for the origin, relative names, an omitted owner (the
// previous one), TTL and class in either order and either omitted, TTLs
// with units (1h30m), RFC 3597's "\# n hex" rdata for any type, and the
// directives $ORIGIN, $TTL, $INCLUDE (when allowed, 7 deep at most) and
// $GENERATE.
//
//   var rrs: u8[>..] = [];
//   let e = dns::new_rr(rrs, "www.example.org. 300 IN A 192.0.2.1");
//
//   var opts = dns::ZoneOptions { .. };
//   opts.origin = dns::name_parse("example.org.", [])...;
//   let r = dns::parse_zone(text, opts, rrs);      // r.err, r.line, r.msg
//
// An omitted TTL is the $TTL in force, else the last TTL given, else the
// default (3600 for new_rr, 0 for a zone, as miekg); an omitted class is IN.

namespace dns;

import std;
import base64;
import os;
import dns;
import dns.rdata;
import dns.msg;

struct ZoneOptions {
    origin: Name = [0],
    default_ttl: i64 = -1,      // -1: none until a TTL is given
    include: bool = false,      // $INCLUDE allowed
    file: u8[..1024] = "",      // the zone's path, for $INCLUDE's relative paths and errors
}

struct ZoneResult { err: i64, line: i64, msg: u8[..160] }

fn zone_ok() -> ZoneResult { ZoneResult { OK, 0, "" } }

fn zone_fail(err: i64, line: i64, msg: const u8[:]) -> ZoneResult {
    var r = ZoneResult { err, line, "" };
    let n = if msg.len > 160 { 160 } else { msg.len };
    r.msg.append(msg[..n]);
    return r;
}

// --- Lexing ------------------------------------------------------------------------

// A token: its bytes at off..end in the text (escapes still in it), whether
// it was in quotes, whether it touches the one before (no blank between).
struct Tok { off: i64, end: i64, quoted: bool, glued: bool }

fn text(t: Tok, src: const u8[:]) -> const u8[:] { src[t.off .. t.end] }

// Reads one entry starting at pos: the tokens of a line, or of several
// joined by parentheses. The position after it, the line count it spanned,
// whether the line started with a blank (owner omitted), and OK or
// ERR_SYNTAX (an unclosed quote or parenthesis).
fn next_entry(src: const u8[:], pos0: i64, toks: Tok[>..]&) -> i64, i64, bool, i64 {
    toks.clear();
    var pos = pos0;
    var lines = 0;
    var depth = 0;
    let blank_start = pos < src.len && (src[pos] == ' ' || src[pos] == '\t');
    var glued = false;
    while pos < src.len {
        let c = src[pos];
        if c == '\n' {
            lines++;
            pos++;
            glued = false;
            if depth == 0 {
                if toks.len > 0 { return pos, lines, blank_start, OK; }
                return pos, lines, blank_start, OK;
            }
            continue;
        }
        if c == ' ' || c == '\t' || c == '\r' { pos++; glued = false; continue; }
        if c == ';' {
            while pos < src.len && src[pos] != '\n' { pos++; }
            glued = false;
            continue;
        }
        if c == '(' { depth++; pos++; glued = false; continue; }
        if c == ')' {
            if depth == 0 { return pos, lines, blank_start, ERR_SYNTAX; }
            depth--;
            pos++;
            glued = false;
            continue;
        }
        if c == '"' {
            let start = pos + 1;
            var i = start;
            while i < src.len && src[i] != '"' {
                if src[i] == '\\' { i++; }
                if i < src.len && src[i] == '\n' { lines++; }
                i++;
            }
            if i >= src.len { return src.len, lines, blank_start, ERR_SYNTAX; }
            toks.push(Tok { start, i, true, glued });
            pos = i + 1;
            glued = true;
            continue;
        }
        let start = pos;
        while pos < src.len {
            let d = src[pos];
            if d == '\\' { pos += 2; continue; }
            if d == ' ' || d == '\t' || d == '\r' || d == '\n' || d == ';' || d == '(' || d == ')' || d == '"' { break; }
            pos++;
        }
        if pos > src.len { pos = src.len; }
        toks.push(Tok { start, pos, false, glued });
        glued = true;
    }
    if depth != 0 { return pos, lines, blank_start, ERR_SYNTAX; }
    return pos, lines, blank_start, OK;
}

// A token's bytes with \X and \DDD undone; false for a \DDD over 255 or a
// dangling backslash.
fn unescape(out: u8[>..]&, s: const u8[:]) -> bool {
    var i = 0;
    while i < s.len {
        if s[i] != '\\' { out.push(s[i]); i++; continue; }
        if i + 1 >= s.len { return false; }
        if is_ddd(s, i + 1) {
            let v = ddd(s, i + 1);
            if v > 255 { return false; }
            out.push(v as! u8);
            i += 4;
        } else {
            out.push(s[i + 1]);
            i += 2;
        }
    }
    return true;
}

// A TTL: a number of seconds, or BIND's units (1w2d3h4m5s), as miekg's
// stringToTTL. -1 if it is not one.
fn ttl_parse(s: const u8[:]) -> i64 {
    if s.len == 0 || !ascii::is_digit(s[0]) { return -1; }
    var total: i64 = 0;
    var cur: i64 = 0;
    for c in s {
        if ascii::is_digit(c) { cur = cur * 10 + (c - '0'); if cur > 0xffffffff { return -1; } continue; }
        let l = lower(c);
        if l == 's' { total += cur; }
        else if l == 'm' { total += cur * 60; }
        else if l == 'h' { total += cur * 3600; }
        else if l == 'd' { total += cur * 86400; }
        else if l == 'w' { total += cur * 604800; }
        else { return -1; }
        cur = 0;
        if total > 0xffffffff { return -1; }
    }
    total += cur;
    return if total > 0xffffffff { -1 } else { total };
}

fn uint_parse(s: const u8[:], max: i64) -> i64 {
    if !all_digits(s) || s.len > 20 { return -1; }
    let n, ok = parse_int(s);
    if !ok || n > max { return -1; }
    return n;
}

// Dotted-quad IPv4, exactly four parts of 0..255.
fn ip4_parse(s: const u8[:]) -> u8[4], bool {
    var out: u8[4] = [0; 4];
    var part = 0;
    var cur = -1;
    var digits = 0;
    for c in s {
        if c == '.' {
            if cur < 0 || part >= 3 { return out, false; }
            out[part] = cur as! u8;
            part++;
            cur = -1;
            digits = 0;
            continue;
        }
        if !ascii::is_digit(c) { return out, false; }
        if digits > 0 && cur == 0 { return out, false; }    // no leading zeros, as Go
        cur = (if cur < 0 { 0 } else { cur }) * 10 + (c - '0');
        digits++;
        if cur > 255 { return out, false; }
    }
    if cur < 0 || part != 3 { return out, false; }
    out[3] = cur as! u8;
    return out, true;
}

// IPv6 text (RFC 4291 §2.2): groups, one "::", a final dotted IPv4.
fn ip6_parse(s: const u8[:]) -> u8[16], bool {
    var out: u8[16] = [0; 16];
    var groups: u16[..8] = [];
    var gap = -1;
    var i = 0;
    if s.len >= 2 && s[0] == ':' && s[1] == ':' { gap = 0; i = 2; }
    else if s.len >= 1 && s[0] == ':' { return out, false; }
    while i < s.len {
        // A dotted IPv4 tail?
        var j = i;
        var dot = false;
        while j < s.len && s[j] != ':' { if s[j] == '.' { dot = true; } j++; }
        if dot {
            if j != s.len || groups.len > 6 { return out, false; }
            let v4, ok = ip4_parse(s[i..j]);
            if !ok { return out, false; }
            groups.push(get16(v4, 0));
            groups.push(get16(v4, 2));
            i = j;
            break;
        }
        if j == i || j - i > 4 || groups.len >= 8 { return out, false; }
        var v: i64 = 0;
        for k in i..j {
            let h = ascii::hex_value(s[k]);
            if h < 0 { return out, false; }
            v = v * 16 + h;
        }
        groups.push(v as! u16);
        i = j;
        if i < s.len {
            i++;        // the ':'
            if i < s.len && s[i] == ':' {
                if gap >= 0 { return out, false; }
                gap = groups.len;
                i++;
            } else if i == s.len {
                return out, false;
            }
        }
    }
    if gap < 0 && groups.len != 8 { return out, false; }
    if gap >= 0 && groups.len > 7 { return out, false; }
    let fill = 8 - groups.len;
    var g = 0;
    for k in groups.len {
        if k == gap { g += fill; }
        set16(out, g * 2, groups[k]);
        g++;
    }
    return out, true;
}

fn hex_decode(out: u8[>..]&, s: const u8[:]) -> bool {
    if s.len % 2 != 0 { return false; }
    var i = 0;
    while i < s.len {
        let h = ascii::hex_value(s[i]);
        let l = ascii::hex_value(s[i + 1]);
        if h < 0 || l < 0 { return false; }
        out.push((h * 16 + l) as! u8);
        i += 2;
    }
    return true;
}

// --- Rdata from text ---------------------------------------------------------------

// The fields of one record's rdata from the tokens toks[first..], onto rd.
// OK, or an error with why in msg.
fn rdata_parse(t: u16, src: const u8[:], toks: const Tok[:], first: i64, origin: const u8[:],
               rd: u8[>..]&, msg: u8[..160]&) -> i64 {
    var i = first;
    let rstart = rd.len;
    // RFC 3597's generic form, for any type.
    if i < toks.len && toks[i].text(src) == "\\#" && !toks[i].quoted {
        if i + 1 >= toks.len { msg.append("bad RFC 3597 rdata"); return ERR_SYNTAX; }
        let n = uint_parse(toks[i + 1].text(src), 65535);
        if n < 0 { msg.append("bad RFC 3597 rdata length"); return ERR_SYNTAX; }
        var hex: u8[>..] = [];
        for k in i + 2 .. toks.len { hex.append(toks[k].text(src)); }
        let start = rd.len;
        if !hex_decode(rd, hex) || rd.len - start != n { msg.append("bad RFC 3597 rdata"); return ERR_SYNTAX; }
        if n > 0 && !rdata_valid(t, rd[start..]) { msg.append("bad rdata"); return ERR_RDATA; }
        return OK;
    }
    let lay, known = layout(t);
    if !known { msg.append("unknown RR type, use RFC 3597 \\# form"); return ERR_TYPE; }
    if t == TYPE_NULL || t == TYPE_OPT || t == TYPE_TSIG || t == TYPE_TKEY || t == TYPE_ANY || t == TYPE_NXNAME {
        if i == toks.len && t != TYPE_NULL { return OK; }
        msg.append("records of this type do not have a presentation format");
        return ERR_SYNTAX;
    }
    // Empty rdata is allowed, as miekg allows it (dynamic update's deletes).
    if i == toks.len { return OK; }
    for fi in lay.f.len {
        let k = lay.f[fi];
        let last = fi == lay.f.len - 1;
        if i >= toks.len {
            // Trailing strings may be absent (ISDN's subaddress, HINFO's OS: no).
            if k == 's' && t == TYPE_ISDN { rd.push(0); break; }       // an empty subaddress, as miekg
            if k == 'm' || k == 'V' { break; }
            if k == '4' && t == TYPE_SOA { put32(rd, 0); continue; }    // miekg takes missing timers as 0
            msg.append("missing rdata field");
            return ERR_SYNTAX;
        }
        let tok = toks[i];
        let s = tok.text(src);
        if k == '1' || k == '2' || k == '4' {
            let max = if k == '1' { 255 } else if k == '2' { 65535 } else { 0xffffffff };
            var n = uint_parse(s, max);
            if n < 0 && t == TYPE_SOA && fi > 2 { n = ttl_parse(s); }     // SOA's timers take TTL units
            if n < 0 { msg.append("bad number: "); msg.append(clip(s)); return ERR_SYNTAX; }
            if k == '1' { rd.push(n as! u8); } else if k == '2' { put16(rd, n as! u16); } else { put32(rd, n as! u32); }
            i++;
        } else if k == 'g' {
            var n = uint_parse(s, 255);
            if n < 0 { n = alg_from_string(s); }
            if n < 0 { msg.append("bad algorithm"); return ERR_SYNTAX; }
            rd.push(n as! u8);
            i++;
        } else if k == 'C' {
            var n = uint_parse(s, 65535);
            if n < 0 { n = cert_from_string(s); }
            if n < 0 { msg.append("bad CERT type"); return ERR_SYNTAX; }
            put16(rd, n as! u16);
            i++;
        } else if k == 'y' {
            let n = type_from_string(s);
            if n < 0 { msg.append("bad type"); return ERR_SYNTAX; }
            put16(rd, n as! u16);
            i++;
        } else if k == 'T' {
            let v, ok = time_parse(s);
            if !ok { msg.append("bad time"); return ERR_SYNTAX; }
            put32(rd, v);
            i++;
        } else if k == 'c' || k == 'n' {
            let nm, e = name_parse(s, origin);
            if e != OK || tok.quoted { msg.append("bad name: "); msg.append(clip(s)); return ERR_NAME; }
            rd.append(nm);
            i++;
        } else if k == 'a' {
            let ip, ok = ip4_parse(s);
            if !ok { msg.append("bad A"); return ERR_SYNTAX; }
            rd.append(ip);
            i++;
        } else if k == 'A' {
            let ip, ok = ip6_parse(s);
            var colon = false;
            for c in s { if c == ':' { colon = true; } }
            if !ok || !colon { msg.append("bad AAAA"); return ERR_SYNTAX; }
            rd.append(ip);
            i++;
        } else if k == 's' || k == 'S' {
            var b: u8[>..] = [];
            if !unescape(b, s) || b.len > 255 { msg.append("bad character-string"); return ERR_SYNTAX; }
            rd.push(b.len as! u8);
            rd.append(b);
            i++;
        } else if k == 't' {
            while i < toks.len {
                var b: u8[>..] = [];
                if !unescape(b, toks[i].text(src)) { msg.append("bad character-string"); return ERR_SYNTAX; }
                // Longer than 255: in pieces of 255, as miekg does.
                var j = 0;
                while true {
                    let e = if j + 255 < b.len { j + 255 } else { b.len };
                    rd.push((e - j) as! u8);
                    rd.append(b[j..e]);
                    j = e;
                    if j >= b.len { break; }
                }
                i++;
            }
        } else if k == 'o' {
            var b: u8[>..] = [];
            if !unescape(b, s) { msg.append("bad string"); return ERR_SYNTAX; }
            rd.append(b);
            i++;
            if i < toks.len { msg.append("too many strings"); return ERR_SYNTAX; }
        } else if k == 'x' || k == 'X' || k == 'Z' || k == 'b' {
            var all: u8[>..] = [];
            while i < toks.len { all.append(toks[i].text(src)); i++; }
            let ok = if k == 'b' { base64::decode(rd, all) } else { hex_decode(rd, all) };
            if !ok { msg.append(if k == 'b' { "bad base64" } else { "bad hex" }); return ERR_SYNTAX; }
        } else if k == 'h' {
            if s == "-" { rd.push(0); }
            else {
                var b: u8[>..] = [];
                if !hex_decode(b, s) || b.len > 255 { msg.append("bad salt"); return ERR_SYNTAX; }
                rd.push(b.len as! u8);
                rd.append(b);
            }
            i++;
        } else if k == 'B' {
            var b: u8[>..] = [];
            if !base32_decode(b, s) || b.len > 255 || b.len == 0 { msg.append("bad base32"); return ERR_SYNTAX; }
            rd.push(b.len as! u8);
            rd.append(b);
            i++;
        } else if k == 'm' {
            var ts: u16[>..] = [];
            while i < toks.len {
                let n = type_from_string(toks[i].text(src));
                if n < 0 { msg.append("bad type in bitmap"); return ERR_SYNTAX; }
                ts.push(n as! u16);
                i++;
            }
            sort(ts);
            bitmap_build(rd, ts);
        } else if k == 'e' || k == 'E' {
            let n = if k == 'e' { 6 } else { 8 };
            if s.len != n * 3 - 1 { msg.append("bad EUI"); return ERR_SYNTAX; }
            for g in n {
                if g > 0 && s[g * 3 - 1] != '-' { msg.append("bad EUI"); return ERR_SYNTAX; }
                if !hex_decode(rd, s[g * 3 .. g * 3 + 2]) { msg.append("bad EUI"); return ERR_SYNTAX; }
            }
            i++;
        } else if k == 'd' || k == 'D' {
            if s.len != 19 || s[4] != ':' || s[9] != ':' || s[14] != ':' { msg.append("bad locator"); return ERR_SYNTAX; }
            for g in 4 { if !hex_decode(rd, s[g * 5 .. g * 5 + 4]) { msg.append("bad locator"); return ERR_SYNTAX; } }
            i++;
        } else if k == 'L' {
            let e = loc_parse(src, toks, i, rd, msg);
            if e != OK { return e; }
            i = toks.len;
        } else if k == 'P' {
            while i < toks.len {
                if !apl_parse(rd, toks[i].text(src)) { msg.append("bad APL prefix"); return ERR_SYNTAX; }
                i++;
            }
        } else if k == 'I' {
            let gt = rd[rstart + 1];
            if gt == 0 { if s != "." { msg.append("bad IPSECKEY gateway"); return ERR_SYNTAX; } }
            else if gt == 1 { let ip, ok = ip4_parse(s); if !ok { msg.append("bad IPSECKEY gateway"); return ERR_SYNTAX; } rd.append(ip); }
            else if gt == 2 { let ip, ok = ip6_parse(s); if !ok { msg.append("bad IPSECKEY gateway"); return ERR_SYNTAX; } rd.append(ip); }
            else if gt == 3 { let nm, e = name_parse(s, origin); if e != OK { msg.append("bad IPSECKEY gateway"); return ERR_SYNTAX; } rd.append(nm); }
            else { msg.append("bad IPSECKEY gateway type"); return ERR_SYNTAX; }
            i++;
            var all: u8[>..] = [];
            while i < toks.len { all.append(toks[i].text(src)); i++; }
            if !base64::decode(rd, all) { msg.append("bad base64"); return ERR_SYNTAX; }
        } else if k == 'G' {
            // The D-bit and the gateway type.
            if i + 1 >= toks.len { msg.append("bad AMTRELAY"); return ERR_SYNTAX; }
            let gt = uint_parse(toks[i + 1].text(src), 127);
            if (s != "0" && s != "1") || gt < 0 { msg.append("bad AMTRELAY"); return ERR_SYNTAX; }
            rd.push((gt | (if s == "1" { 0x80 } else { 0 })) as! u8);
            i += 2;
        } else if k == 'M' {
            let gt = rd[rstart + 1] & 0x7f;
            let g = s;
            if gt == 0 { if g != "." { msg.append("bad AMTRELAY gateway"); return ERR_SYNTAX; } }
            else if gt == 1 { let ip, ok = ip4_parse(g); if !ok { msg.append("bad AMTRELAY gateway"); return ERR_SYNTAX; } rd.append(ip); }
            else if gt == 2 { let ip, ok = ip6_parse(g); if !ok { msg.append("bad AMTRELAY gateway"); return ERR_SYNTAX; } rd.append(ip); }
            else if gt == 3 { let nm, e = name_parse(g, origin); if e != OK { msg.append("bad AMTRELAY gateway"); return ERR_SYNTAX; } rd.append(nm); }
            else { msg.append("bad AMTRELAY gateway type"); return ERR_SYNTAX; }
            i++;
        } else if k == 'H' {
            if i + 2 >= toks.len { msg.append("bad HIP"); return ERR_SYNTAX; }
            let alg = uint_parse(s, 255);
            var hit: u8[>..] = [];
            var key: u8[>..] = [];
            if alg < 0 || !hex_decode(hit, toks[i + 1].text(src)) || hit.len > 255 || !base64::decode(key, toks[i + 2].text(src)) || key.len > 65535 {
                msg.append("bad HIP");
                return ERR_SYNTAX;
            }
            rd.push(hit.len as! u8);
            rd.push(alg as! u8);
            put16(rd, key.len as! u16);
            rd.append(hit);
            rd.append(key);
            i += 3;
            while i < toks.len {
                let nm, e = name_parse(toks[i].text(src), origin);
                if e != OK { msg.append("bad HIP rendezvous server"); return ERR_NAME; }
                rd.append(nm);
                i++;
            }
        } else if k == 'V' {
            let e = svcb_parse(src, toks, i, rd, msg);
            if e != OK { return e; }
            i = toks.len;
        } else {
            msg.append("records of this type do not have a presentation format");
            return ERR_SYNTAX;
        }
        if last && i < toks.len {
            msg.append("garbage after rdata: ");
            msg.append(clip(toks[i].text(src)));
            return ERR_SYNTAX;
        }
    }
    return OK;
}

fn clip(s: const u8[:]) -> const u8[:] { if s.len > 64 { s[..64] } else { s } }

// "<digits>[.<digits>][m]" in centimetres, as LOC's size bytes (miekg's stringToCm).
fn cm_parse(s0: const u8[:]) -> i64 {
    var s = s0;
    if s.len > 0 && (s[s.len - 1] == 'm' || s[s.len - 1] == 'M') { s = s[..s.len - 1]; }
    let ms, cs, has = split_once(s, '.');
    var meters = 0;
    var cm = 0;
    if has {
        if cs.len == 0 || cs.len > 2 || !all_digits(cs) { return -1; }
        cm = uint_parse(cs, 99);
        if cs.len == 1 { cm *= 10; }
    }
    if !has || ms.len > 0 {
        meters = uint_parse(ms, 90000000);
        if meters < 0 || (meters == 90000000 && cm != 0) { return -1; }
    }
    var e = 0;
    var v = 0;
    if meters > 0 { e = 2; v = meters; } else { v = cm; }
    while v >= 10 { e++; v /= 10; }
    return (v << 4) | e;
}

fn loc_parse(src: const u8[:], toks: const Tok[:], first: i64, rd: u8[>..]&, msg: u8[..160]&) -> i64 {
    var i = first;
    var vals: i64[2] = [0, 0];
    for axis in 2 {
        let max = if axis == 0 { 90 } else { 180 };
        if i >= toks.len { msg.append("bad LOC"); return ERR_SYNTAX; }
        let deg = uint_parse(toks[i].text(src), max);
        if deg < 0 { msg.append("bad LOC degrees"); return ERR_SYNTAX; }
        var v = deg * 3600000;
        i++;
        var parts = 0;
        while i < toks.len {
            let s = toks[i].text(src);
            let pos = if axis == 0 { "N" } else { "E" };
            let neg = if axis == 0 { "S" } else { "W" };
            if ascii_eq_fold(s, pos) || ascii_eq_fold(s, neg) {
                if ascii_eq_fold(s, pos) { v = (1 << 31) + v; } else { v = (1 << 31) - v; }
                i++;
                break;
            }
            if parts == 0 {
                let mi = uint_parse(s, 59);
                if mi < 0 { msg.append("bad LOC minutes"); return ERR_SYNTAX; }
                v += mi * 60000;
            } else if parts == 1 {
                let f, ok = parse_flt(s);
                if !ok || f < 0.0 || f >= 60.0 { msg.append("bad LOC seconds"); return ERR_SYNTAX; }
                v += (f * 1000.0) as! i64;
            } else {
                msg.append("bad LOC hemisphere");
                return ERR_SYNTAX;
            }
            parts++;
            i++;
        }
        vals[axis] = v;
    }
    if i >= toks.len { msg.append("bad LOC altitude"); return ERR_SYNTAX; }
    var a = toks[i].text(src);
    if a.len > 0 && (a[a.len - 1] == 'm' || a[a.len - 1] == 'M') { a = a[..a.len - 1]; }
    let alt, ok = parse_flt(a);
    if !ok { msg.append("bad LOC altitude"); return ERR_SYNTAX; }
    i++;
    var sizes: u8[3] = [0x12, 0x16, 0x13];
    var n = 0;
    while i < toks.len && n < 3 {
        let c = cm_parse(toks[i].text(src));
        if c < 0 { msg.append("bad LOC size or precision"); return ERR_SYNTAX; }
        sizes[n] = c as! u8;
        n++;
        i++;
    }
    if i < toks.len { msg.append("bad LOC"); return ERR_SYNTAX; }
    rd.push(0);
    rd.append(sizes);
    put32(rd, vals[0] as! u32);
    put32(rd, vals[1] as! u32);
    put32(rd, (alt * 100.0 + 10000000.0 + 0.5) as! u32);
    return OK;
}

// "[!]afi:address/prefix", the address cut to its last non-zero byte.
fn apl_parse(rd: u8[>..]&, s0: const u8[:]) -> bool {
    var s = s0;
    var negate = false;
    if s.len > 0 && s[0] == '!' { negate = true; s = s[1..]; }
    let fam, rest, ok1 = split_once(s, ':');
    let addr, pfx, ok2 = split_once(rest, '/');
    if !ok1 || !ok2 { return false; }
    var ip: u8[16] = [0; 16];
    var n = 0;
    var max = 0;
    if fam == "1" {
        let v4, ok = ip4_parse(addr);
        if !ok { return false; }
        for j in 4 { ip[j] = v4[j]; }
        n = 4; max = 32;
    } else if fam == "2" {
        let v6, ok = ip6_parse(addr);
        if !ok { return false; }
        ip = v6;
        n = 16; max = 128;
    } else {
        return false;
    }
    let p = uint_parse(pfx, max);
    if p < 0 { return false; }
    // The address must have no bits past the prefix (miekg checks the mask).
    for j in n {
        let bits = p - j * 8;
        if bits <= 0 { if ip[j] != 0 { return false; } }
        else if bits < 8 { if ip[j] & (0xff >> bits) != 0 { return false; } }
    }
    var afd = n;
    while afd > 0 && ip[afd - 1] == 0 { afd--; }
    put16(rd, if n == 4 { 1 } else { 2 });
    rd.push(p as! u8);
    rd.push((afd | (if negate { 0x80 } else { 0 })) as! u8);
    rd.append(ip[..afd]);
    return true;
}

fn svcb_key_from(s: const u8[:]) -> i64 {
    for i in SVCB_KEY_NAMES.len { if s == SVCB_KEY_NAMES[i] { return i; } }
    if s.len > 3 && s[..3] == "key" {
        let n = uint_parse(s[3..], 65534);
        if n >= 0 && !(s.len > 4 && s[3] == '0') { return n; }
    }
    return -1;
}

struct SvcbParam { key: u16, off: i64, end: i64 }

// SVCB's parameters: key=value, key="value" or key alone; sorted by key
// on the wire, each key once.
fn svcb_parse(src: const u8[:], toks: const Tok[:], first: i64, rd: u8[>..]&, msg: u8[..160]&) -> i64 {
    var params: SvcbParam[>..] = [];
    var vals: u8[>..] = [];
    var i = first;
    while i < toks.len {
        let s = toks[i].text(src);
        var key = s;
        var val: u8[>..] = [];
        let k0, v0, has = split_once(s, '=');
        if has {
            key = k0;
            if v0.len == 0 && i + 1 < toks.len && toks[i + 1].glued && toks[i + 1].quoted {
                i++;
                if !unescape(val, toks[i].text(src)) { msg.append("bad SVCB value"); return ERR_SYNTAX; }
            } else {
                var raw = v0;
                if raw.len >= 2 && raw[0] == '"' && raw[raw.len - 1] == '"' { raw = raw[1 .. raw.len - 1]; }
                if !unescape(val, raw) { msg.append("bad SVCB value"); return ERR_SYNTAX; }
            }
        }
        let code = svcb_key_from(key);
        if code < 0 { msg.append("bad SVCB key: "); msg.append(clip(key)); return ERR_SYNTAX; }
        for p in params { if p.key == code { msg.append("duplicate SVCB key"); return ERR_SYNTAX; } }
        let off = vals.len;
        let e = svcb_value_parse(code as! u16, val, vals);
        if e.len > 0 { msg.append(e); return ERR_SYNTAX; }
        params.push(SvcbParam { code as! u16, off, vals.len });
        i++;
    }
    sort(params) { a, b => a.key < b.key };
    for p in params {
        put16(rd, p.key);
        put16(rd, (p.end - p.off) as! u16);
        rd.append(vals[p.off .. p.end]);
    }
    return OK;
}

// One parameter's value onto out; "" or why it is bad.
fn svcb_value_parse(key: u16, v: const u8[:], out: u8[>..]&) -> const u8[:] {
    if key == 0 {
        if v.len == 0 { return "bad SVCB mandatory"; }
        var codes: u16[>..] = [];
        each_split(v, ',') { k =>
            let c = svcb_key_from(k);
            if c < 0 { return "bad SVCB mandatory"; }
            codes.push(c as! u16);
        };
        sort(codes);
        for c in codes { put16(out, c); }
    } else if key == 1 {
        if v.len == 0 { return "bad SVCB alpn"; }
        // Commas separate ids; "\," (after the zone file's own unescaping) is a comma in one.
        var cur: u8[>..] = [];
        var i = 0;
        while i <= v.len {
            if i == v.len || v[i] == ',' {
                if cur.len == 0 || cur.len > 255 { return "bad SVCB alpn"; }
                out.push(cur.len as! u8);
                out.append(cur);
                cur.clear();
                i++;
                continue;
            }
            if v[i] == '\\' && i + 1 < v.len { cur.push(v[i + 1]); i += 2; continue; }
            cur.push(v[i]);
            i++;
        }
    } else if key == 2 || key == 8 {
        if v.len != 0 { return "SVCB key takes no value"; }
    } else if key == 3 {
        let p = uint_parse(v, 65535);
        if p < 0 { return "bad SVCB port"; }
        put16(out, p as! u16);
    } else if key == 4 {
        if v.len == 0 { return "bad SVCB ipv4hint"; }
        each_split(v, ',') { a =>
            let ip, ok = ip4_parse(a);
            if !ok { return "bad SVCB ipv4hint"; }
            out.append(ip);
        };
    } else if key == 5 {
        if !base64::decode(out, v) { return "bad SVCB ech"; }
    } else if key == 6 {
        if v.len == 0 { return "bad SVCB ipv6hint"; }
        each_split(v, ',') { a =>
            let ip, ok = ip6_parse(a);
            var dot = false;
            for c in a { if c == '.' { dot = true; } }
            if !ok || dot { return "bad SVCB ipv6hint"; }
            out.append(ip);
        };
    } else {
        out.append(v);
    }
    return "";
}

// --- Records and zones -------------------------------------------------------------

// The state that carries from one entry to the next.
struct ZoneState {
    origin: Name,
    prev_owner: Name,
    has_prev: bool,
    ttl: i64,               // the TTL for records without one, -1 for none
    ttl_directive: bool,    // ttl came from $TTL
}

// One record from an entry's tokens onto out.
fn entry_rr(src: const u8[:], toks: const Tok[:], blank: bool, st: ZoneState&, out: u8[>..]&, msg: u8[..160]&) -> i64 {
    var i = 0;
    var owner: Name = [];
    if blank {
        if !st.has_prev { msg.append("no previous owner name"); return ERR_NAME; }
        owner = st.prev_owner;
    } else {
        let s = toks[0].text(src);
        let n, e = name_parse(s, st.origin);
        if e != OK || toks[0].quoted { msg.append("bad owner name: "); msg.append(clip(s)); return ERR_NAME; }
        owner = n;
        i = 1;
    }
    var ttl: i64 = -1;
    var class: i64 = -1;
    var t: i64 = -1;
    while i < toks.len && t < 0 {
        let s = toks[i].text(src);
        if ttl < 0 && ascii::is_digit(s[0]) {
            ttl = ttl_parse(s);
            if ttl < 0 { msg.append("bad TTL: "); msg.append(clip(s)); return ERR_TTL; }
        } else if type_from_string(s) >= 0 {
            t = type_from_string(s);        // a type first, as miekg's lexer: "ANY" is one
        } else if class < 0 && class_from_string(s) >= 0 {
            class = class_from_string(s);
        } else {
            msg.append("unknown RR type: "); msg.append(clip(s));
            return ERR_TYPE;
        }
        i++;
    }
    if t < 0 { msg.append("missing RR type"); return ERR_TYPE; }
    if ttl >= 0 {
        if !st.ttl_directive { st.ttl = ttl; }
    } else {
        ttl = if st.ttl >= 0 { st.ttl } else { 0 };
    }
    if class < 0 { class = CLASS_INET; }
    st.prev_owner = owner;
    st.has_prev = true;
    let start = out.len;
    out.append(owner);
    put16(out, t as! u16);
    put16(out, class as! u16);
    put32(out, ttl as! u32);
    put16(out, 0);
    let rs = out.len;
    let e = rdata_parse(t as! u16, src, toks, i, st.origin, out, msg);
    if e != OK { out.resize(start); return e; }
    if out.len - rs > 65535 { out.resize(start); msg.append("rdata too long"); return ERR_BUF; }
    set16(out, rs - 2, (out.len - rs) as! u16);
    return OK;
}

// A file's directory, with its separator, from its path.
fn dir_of(path: const u8[:]) -> const u8[:] {
    var i = path.len - 1;
    while i >= 0 && path[i] != '/' && path[i] != '\\' { i--; }
    return path[.. i + 1];
}

struct Frame {
    start: i64, end: i64, pos: i64, line: i64,
    origin: Name, ttl: i64, ttl_directive: bool,
    file: u8[..1024],
}

let MAX_INCLUDE_DEPTH: i64 = 7;
let MAX_GENERATE: i64 = 65535;

// Reads a zone in text onto out (miekg's ZoneParser): every record, in
// order. Stops at the first error, which r.line and r.msg place.
fn parse_zone(zone: const u8[:], opts: ZoneOptions, out: u8[>..]&) -> ZoneResult {
    var store: u8[>..] = [];
    store.append(zone);
    var frames: Frame[..8] = [];
    frames.push(Frame { 0, zone.len, 0, 1, opts.origin, opts.default_ttl, false, opts.file });
    var st = ZoneState { opts.origin, [0], false, opts.default_ttl, false };
    var toks: Tok[>..] = [];
    var gen: u8[>..] = [];
    var gtoks: Tok[>..] = [];
    var msg: u8[..160] = [];
    while frames.len > 0 {
        let fi = frames.len - 1;
        if frames[fi].pos >= frames[fi].end - frames[fi].start {      // pos is within the frame's text
            frames.pop();
            if frames.len > 0 {
                let p = frames.len - 1;
                st.origin = frames[p].origin;
                st.ttl = frames[p].ttl;
                st.ttl_directive = frames[p].ttl_directive;
            }
            continue;
        }
        let src = store[frames[fi].start .. frames[fi].end];
        let line = frames[fi].line;
        let next, lines, blank, le = next_entry(src, frames[fi].pos, toks);
        frames[fi].pos = next;
        frames[fi].line += lines;
        if le != OK { return zone_fail(le, line, "unbalanced parenthesis or quote"); }
        if toks.len == 0 { continue; }
        let first = toks[0].text(src);
        if !blank && first.len > 1 && first[0] == '$' {
            if ascii_eq_fold(first, "$ORIGIN") {
                if toks.len != 2 { return zone_fail(ERR_SYNTAX, line, "bad $ORIGIN"); }
                let n, e = name_parse(toks[1].text(src), st.origin);
                if e != OK { return zone_fail(ERR_NAME, line, "bad $ORIGIN name"); }
                st.origin = n;
                frames[fi].origin = n;
            } else if ascii_eq_fold(first, "$TTL") {
                if toks.len != 2 { return zone_fail(ERR_SYNTAX, line, "bad $TTL"); }
                let t = ttl_parse(toks[1].text(src));
                if t < 0 { return zone_fail(ERR_TTL, line, "bad $TTL value"); }
                st.ttl = t;
                st.ttl_directive = true;
                frames[fi].ttl = t;
                frames[fi].ttl_directive = true;
            } else if ascii_eq_fold(first, "$INCLUDE") {
                if !opts.include { return zone_fail(ERR_SYNTAX, line, "$INCLUDE directive not allowed"); }
                if frames.len > MAX_INCLUDE_DEPTH { return zone_fail(ERR_LIMIT, line, "too deeply nested $INCLUDE"); }
                if toks.len < 2 || toks.len > 3 { return zone_fail(ERR_SYNTAX, line, "bad $INCLUDE"); }
                var path: u8[..1024] = [];
                let p = toks[1].text(src);
                if p.len > 0 && p[0] != '/' && !(p.len > 1 && p[1] == ':') { path.append(dir_of(frames[fi].file)); }
                if path.len + p.len > 1024 { return zone_fail(ERR_SYNTAX, line, "$INCLUDE path too long"); }
                path.append(p);
                var origin = st.origin;
                if toks.len == 3 {
                    let n, e = name_parse(toks[2].text(src), st.origin);
                    if e != OK { return zone_fail(ERR_NAME, line, "bad $INCLUDE origin"); }
                    origin = n;
                }
                let start = store.len;
                if !read_file(path, store) { return zone_fail(ERR_IO, line, "cannot read $INCLUDE file"); }
                frames.push(Frame { start, store.len, 0, 1, origin, st.ttl, st.ttl_directive, path });
                st.origin = origin;
            } else if ascii_eq_fold(first, "$GENERATE") {
                let e = generate(src, toks, st, out, gen, gtoks, msg);
                if e != OK { return zone_fail(e, line, msg); }
            } else {
                return zone_fail(ERR_SYNTAX, line, "unknown directive");
            }
            continue;
        }
        msg.clear();
        let e = entry_rr(src, toks, blank, st, out, msg);
        if e != OK { return zone_fail(e, line, msg); }
    }
    return zone_ok();
}

// $GENERATE start-stop[/step] lhs [ttl] [class] type rhs, as miekg reads
// it: the rest of the line again for each value, with "$" the value,
// "${offset[,width[,base]]}" it formatted (base d, o, x or X), "$$" and
// "\$" a dollar. As in miekg, the generated records are read on their
// own: an omitted TTL is 3600, not the $TTL in force.
fn generate(src: const u8[:], toks: const Tok[:], st: ZoneState&, out: u8[>..]&, line: u8[>..]&,
            ltoks: Tok[>..]&, msg: u8[..160]&) -> i64 {
    if toks.len < 4 { msg.append("bad $GENERATE"); return ERR_SYNTAX; }
    let range = toks[1].text(src);
    let r0, stepstr, has_step = split_once(range, '/');
    let a, b, ok1 = split_once(r0, '-');
    let start = uint_parse(a, 0x7fffffff);
    let stop = uint_parse(b, 0x7fffffff);
    let step = if has_step { uint_parse(stepstr, 0x7fffffff) } else { 1 };
    if !ok1 || start < 0 || stop < 0 || step <= 0 || stop < start { msg.append("bad range in $GENERATE range"); return ERR_SYNTAX; }
    if (stop - start) / step > MAX_GENERATE { msg.append("bad range in $GENERATE range"); return ERR_LIMIT; }
    let last = toks[toks.len - 1];
    let rest = src[toks[2].off - (if toks[2].quoted { 1 } else { 0 }) .. last.end + (if last.quoted { 1 } else { 0 })];
    var gst = ZoneState { st.origin, [0], false, 3600, false };
    var i = start;
    while i <= stop {
        line.clear();
        let ge = gen_expand(line, rest, i, start, stop);
        if ge.len > 0 { msg.append(ge); return ERR_SYNTAX; }
        line.push('\n');
        let next, lines, blank, le = next_entry(line, 0, ltoks);
        if le != OK { msg.append("bad $GENERATE"); return ERR_SYNTAX; }
        msg.clear();
        let e = entry_rr(line, ltoks, false, gst, out, msg);
        if e != OK { return e; }
        i += step;
    }
    return OK;
}

fn gen_expand(out: u8[>..]&, s: const u8[:], n: i64, start: i64, stop: i64) -> const u8[:] {
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c == '\\' && i + 1 < s.len && s[i + 1] == '$' { out.push('$'); i += 2; continue; }
        if c != '$' { out.push(c); i++; continue; }
        if i + 1 < s.len && s[i + 1] == '$' { out.push('$'); i += 2; continue; }
        if i + 1 < s.len && s[i + 1] == '{' {
            var j = i + 2;
            while j < s.len && s[j] != '}' { j++; }
            if j >= s.len { return "bad modifier in $GENERATE"; }
            let parts = split(s[i + 2 .. j], ',');
            if parts.len > 3 { return "bad modifier in $GENERATE"; }
            let off, ok = parse_int(parts[0]);
            if !ok { return "bad offset in $GENERATE"; }
            let width = if parts.len > 1 { uint_parse(parts[1], 255) } else { 0 };
            if width < 0 { return "bad width in $GENERATE"; }
            let base = if parts.len > 2 { parts[2] } else { "d" };
            if start + off < 0 || stop + off > 0x7fffffff { return "bad offset in $GENERATE"; }
            let v = n + off;
            if base == "d" { format_int(out, v, 10, width, '0'); }
            else if base == "o" { format_int(out, v, 8, width, '0'); }
            else if base == "x" { format_int(out, v, 16, width, '0'); }
            else if base == "X" {
                var tmp: u8[>..] = [];
                format_int(tmp, v, 16, width, '0');
                for ch in tmp { out.push(if ch >= 'a' && ch <= 'f' { ch - 32 } else { ch }); }
            } else { return "bad base in $GENERATE"; }
            i = j + 1;
            continue;
        }
        format(out, n);
        i++;
    }
    return "";
}

// One record from its text onto out (miekg's NewRR): origin the root, a
// default TTL of 3600, $INCLUDE allowed. Text with no record is
// ERR_SYNTAX.
fn new_rr(out: u8[>..]&, s: const u8[:]) -> i64 {
    let r = new_rr_result(out, s);
    return r.err;
}

fn new_rr_result(out: u8[>..]&, s: const u8[:]) -> ZoneResult {
    var opts = ZoneOptions { .. };
    opts.default_ttl = 3600;
    opts.include = true;
    let start = out.len;
    let r = parse_zone(s, opts, out);
    if r.err != OK { return r; }
    if out.len == start { return zone_fail(ERR_SYNTAX, 1, "no record"); }
    // Only the first record counts.
    let rr = rr_at(out, start);
    out.resize(rr.end);
    return r;
}
