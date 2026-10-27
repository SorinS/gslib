// ldap.url: LDAP URLs (RFC 4516), as ldapsearch's -H and go-ldap's
// DialURL take them: ldap://host:port (389), ldaps:// (636), and
// ldapi:// with the socket's path percent-encoded as the host; then
// optionally /dn?attributes?scope?filter?extensions, each
// percent-decoded. A host in brackets is an IPv6 address.

namespace ldap;

import std;
import ldap;

struct Url {
    scheme: u8[..8],                   // "ldap", "ldaps" or "ldapi"
    host: u8[..1024], port: i64,       // ldapi: the socket's path; port 0
    dn: u8[..4096], attrs: u8[..4096], // attrs as given, comma-separated
    scope: i64,                        // -1 when absent
    filter: u8[..4096],
    exts: u8[..4096],
}

// %xx escapes decoded; false on a broken one.
fn percent_decode(s: const u8[:], out: u8[>..]&) -> bool {
    var i = 0;
    while i < s.len {
        if s[i] == '%' {
            if i + 2 >= s.len { return false; }
            let h = hex_value(s[i + 1]);
            let l = hex_value(s[i + 2]);
            if h < 0 || l < 0 { return false; }
            out.push((h * 16 + l) as! u8);
            i += 3;
        } else {
            out.push(s[i]);
            i++;
        }
    }
    return true;
}

fn parse_url(text: const u8[:]) -> Url, bool {
    var u = Url { scheme: [], host: [], port: 0, dn: [], attrs: [], scope: -1, filter: [], exts: [] };
    let sep = find(text, "://");
    if sep <= 0 { return u, false; }
    var scheme: u8[>..] = [];
    for c in text[..sep] { scheme.push(lower(c)); }
    if scheme != "ldap" && scheme != "ldaps" && scheme != "ldapi" { return u, false; }
    u.scheme.append(scheme);
    let rest = text[sep + 3..];
    var slash = position(rest, '/');
    if slash < 0 { slash = rest.len; }
    let hostport = rest[..slash];
    // The host is hostport[h0..h1], the port's digits from p0.
    var h0 = 0;
    var h1 = hostport.len;
    var p0 = hostport.len;
    if hostport.len > 0 && hostport[0] == '[' {
        let close = position(hostport, ']');
        if close < 0 { return u, false; }
        h0 = 1;
        h1 = close;
        if close + 1 < hostport.len {
            if hostport[close + 1] != ':' { return u, false; }
            p0 = close + 2;
        }
    } else if scheme != "ldapi" {
        let colon = position(hostport, ':');
        if colon >= 0 { h1 = colon; p0 = colon + 1; }
    }
    let port_text = hostport[p0..];
    var h: u8[>..] = [];
    if !percent_decode(hostport[h0..h1], h) || h.len > 1024 { return u, false; }
    u.host.append(h);
    if scheme == "ldap" { u.port = 389; }
    if scheme == "ldaps" { u.port = 636; }
    if port_text.len > 0 {
        let p, okp = parse_int(port_text, 10);
        if !okp || p < 1 || p > 65535 { return u, false; }
        u.port = p;
    }
    if slash >= rest.len { return u, true; }
    let parts = split(rest[slash + 1..], '?');
    if parts.len > 5 { return u, false; }
    for i in parts.len {
        var v: u8[>..] = [];
        if !percent_decode(parts[i], v) || v.len > 4096 { return u, false; }
        if i == 0 { u.dn.append(v); }
        else if i == 1 { u.attrs.append(v); }
        else if i == 2 {
            if v.len == 0 { }
            else if v == "base" { u.scope = SCOPE_BASE; }
            else if v == "one" { u.scope = SCOPE_ONE; }
            else if v == "sub" { u.scope = SCOPE_SUB; }
            else if v == "children" { u.scope = SCOPE_CHILDREN; }
            else { return u, false; }
        }
        else if i == 3 { u.filter.append(v); }
        else { u.exts.append(v); }
    }
    return u, true;
}
