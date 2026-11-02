// krb5.config: krb5.conf, in MIT's profile syntax (doc/admin/conf_files/
// krb5_conf.rst): [sections] of `tag = value` relations, `tag = { ... }`
// subsections to any depth, `*` after a section or `}` to make it final,
// comments (#, ;), quoted values, `include FILE` and `includedir DIR`.
// A Config is the relations in order, each a '/'-joined path
// ("realms/EXAMPLE.COM/kdc") and its value; the first of several wins
// for single-valued settings, as with MIT, and files read first come
// first.
//
// The settings the library reads, with MIT's defaults, are below the
// parser: realms' KDCs, domain_realm, capaths, enctype lists, durations
// and booleans.

namespace krb5;

import std;
import os;
import krb5.crypto;

struct ConfEntry { path: u8[], value: u8[] }
struct Config { entries: ConfEntry[] }

fn empty_config() -> Config { Config { entries: [] } }

fn is_space(c: u8) -> bool { c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 11 || c == 12 }

fn trim(s: const u8[:]) -> const u8[:] {
    var a = 0;
    var b = s.len;
    while a < b && is_space(s[a]) { a++; }
    while b > a && is_space(s[b - 1]) { b--; }
    return s[a..b];
}

// A value as the profile library reads it: a quoted string with \n, \t,
// \b and \\ escapes, or the text up to the end of the line.
fn conf_value_text(v: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if v.len == 0 || v[0] != '"' { out.append(v); return out; }
    var i = 1;
    while i < v.len && v[i] != '"' {
        if v[i] == '\\' && i + 1 < v.len {
            let d = v[i + 1];
            out.push(if d == 'n' { '\n' } else if d == 't' { '\t' } else if d == 'b' { 8 } else { d });
            i += 2;
            continue;
        }
        out.push(v[i]);
        i++;
    }
    return out;
}

fn is_include(line: const u8[:]) -> bool {
    line.starts_with("include ") || line.starts_with("include\t") ||
    line.starts_with("includedir ") || line.starts_with("includedir\t")
}

// The text with its include and includedir lines replaced by the files
// they name, one level per pass (nesting is limited to 8). After an
// included file the including file's section is opened again, so that
// relations after the include stay where they were. Includes inside a
// subsection are an error, as in MIT.
fn expand_includes(text0: const u8[:]) -> u8[>..], i64 {
    var text: u8[>..] = [];
    text.append(text0);
    for pass in 9 {
        var out: u8[>..] = [];
        var section: u8[>..] = [];
        var depth = 0;
        var changed = false;
        var start = 0;
        for i in text.len + 1 {
            if i < text.len && text[i] != '\n' { continue; }
            let raw = text[start..i];
            start = i + 1;
            let line = trim(raw);
            if line.len > 0 && line[0] == '[' { section.clear(); section.append(line); }
            if line.ends_with("{") { depth++; }
            if line.len > 0 && line[0] == '}' && depth > 0 { depth--; }
            if !is_include(line) {
                out.append(raw);
                out.push('\n');
                continue;
            }
            if depth > 0 || pass == 8 { return out, ERR_CONFIG; }
            changed = true;
            let dir = line.starts_with("includedir");
            let path = trim(line[if dir { 10 } else { 7 }..]);
            if dir {
                var names: u8[>..] = [];
                if list_dir(path, names) {
                    var s = 0;
                    for j in names.len + 1 {
                        if j < names.len && names[j] != '\n' { continue; }
                        let n = names[s..j];
                        s = j + 1;
                        if n.len == 0 { continue; }
                        // MIT reads names of letters, digits, '-' and '_', or ending in ".conf".
                        var plain = true;
                        for c in n {
                            if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') { plain = false; }
                        }
                        if !plain && !n.ends_with(".conf") { continue; }
                        var full: u8[>..] = [];
                        full.append(path);
                        full.push('/');
                        full.append(n);
                        if read_file(full, out) { out.push('\n'); }
                    }
                }
            } else {
                if !read_file(path, out) { return out, ERR_CONFIG; }
                out.push('\n');
            }
            if section.len > 0 { out.append(section); out.push('\n'); }
        }
        text.clear();
        text.append(out);
        if !changed { break; }
    }
    return text, OK;
}

// Parses text without includes, appending its relations. OK or
// ERR_CONFIG with the line.
fn config_parse_into(text: const u8[:], entries: ConfEntry[>..]&) -> i64, i64 {
    var section: u8[>..] = [];
    var stack: u8[>..] = [];          // the path of open subsections, '/'-joined
    var marks: i64[>..] = [];         // stack's length before each open subsection
    var lineno = 0;
    var start = 0;
    var i = 0;
    while i <= text.len {
        if i < text.len && text[i] != '\n' { i++; continue; }
        lineno++;
        let line = trim(text[start..i]);
        start = i + 1;
        i++;
        if line.len == 0 || line[0] == '#' || line[0] == ';' { continue; }
        if line[0] == '[' {
            if marks.len != 0 { return ERR_CONFIG, lineno; }
            var e = 1;
            while e < line.len && line[e] != ']' { e++; }
            if e >= line.len { return ERR_CONFIG, lineno; }
            section.clear();
            section.append(trim(line[1..e]));
            stack.clear();
            stack.append(section);
            continue;
        }
        if line[0] == '}' {
            if marks.len == 0 { return ERR_CONFIG, lineno; }
            stack.resize(marks[marks.len - 1]);
            marks.resize(marks.len - 1);
            continue;
        }
        if section.len == 0 { return ERR_CONFIG, lineno; }
        var eq = -1;
        for j in line.len { if line[j] == '=' { eq = j; break; } }
        if eq <= 0 { return ERR_CONFIG, lineno; }
        let tag = trim(line[..eq]);
        let val = trim(line[eq + 1..]);
        if tag.len == 0 { return ERR_CONFIG, lineno; }
        if val == "{" {
            marks.push(stack.len);
            stack.push('/');
            stack.append(tag);
            continue;
        }
        var path: u8[>..] = [];
        path.append(stack);
        path.push('/');
        path.append(tag);
        entries.push(ConfEntry { path: copy(path), value: conf_value_text(val) });
    }
    if marks.len != 0 { return ERR_CONFIG, lineno; }
    return OK, 0;
}

fn config_parse(text: const u8[:]) -> Config, i64 {
    var entries: ConfEntry[>..] = [];
    let full, ierr = expand_includes(text);
    if ierr != OK { return Config { entries: entries }, ierr; }
    let err, line = config_parse_into(full, entries);
    return Config { entries: entries }, err;
}

// Reads the files of a ':'-separated list (MIT's KRB5_CONFIG), in order;
// files that are not there are skipped.
fn config_load(paths: const u8[:]) -> Config, i64 {
    var entries: ConfEntry[>..] = [];
    var s = 0;
    for j in paths.len + 1 {
        if j < paths.len && paths[j] != ':' { continue; }
        let p = paths[s..j];
        s = j + 1;
        if p.len == 0 { continue; }
        var t: u8[>..] = [];
        if !read_file(p, t) { continue; }
        let full, ierr = expand_includes(t);
        if ierr != OK { return Config { entries: entries }, ierr; }
        let err, line = config_parse_into(full, entries);
        if err != OK { return Config { entries: entries }, err; }
    }
    return Config { entries: entries }, OK;
}

// $KRB5_CONFIG, else /etc/krb5.conf (C:\ProgramData\MIT\Kerberos5\krb5.ini
// on Windows, where /etc is not).
fn default_config() -> Config, i64 {
    var paths: u8[>..] = [];
    if !env("KRB5_CONFIG", paths) || paths.len == 0 {
        paths.clear();
        paths.append("/etc/krb5.conf");
        if !file_exists(paths) {
            paths.clear();
            paths.append("C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini");
        }
    }
    return config_load(paths);
}

// --- Lookups ------------------------------------------------------------------

// The first value at path ("libdefaults/default_realm").
fn conf_get(cfg: const Config&, path: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    for e in cfg.entries {
        if e.path == path { out.append(e.value); return out, true; }
    }
    return out, false;
}

// Every value at path, in order.
fn conf_all(cfg: const Config&, path: const u8[:]) -> u8[][>..] {
    var out: u8[][>..] = [];
    for e in cfg.entries { if e.path == path { out.push(copy(e.value)); } }
    return out;
}

fn path2(a: const u8[:], b: const u8[:]) -> u8[>..] {
    var p: u8[>..] = [];
    p.append(a);
    p.push('/');
    p.append(b);
    return p;
}

fn path3(a: const u8[:], b: const u8[:], c: const u8[:]) -> u8[>..] {
    var p = path2(a, b);
    p.push('/');
    p.append(c);
    return p;
}

fn lower(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for c in s { out.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); }
    return out;
}

// A boolean as the profile reads them: y, yes, true, t, 1, on; n, no,
// false, nil, 0, off.
fn conf_bool(cfg: const Config&, path: const u8[:], dflt: bool) -> bool {
    let v, ok = conf_get(cfg, path);
    if !ok { return dflt; }
    let l = lower(v);
    if l == "y" || l == "yes" || l == "true" || l == "t" || l == "1" || l == "on" { return true; }
    if l == "n" || l == "no" || l == "false" || l == "nil" || l == "0" || l == "off" { return false; }
    return dflt;
}

fn conf_int(cfg: const Config&, path: const u8[:], dflt: i64) -> i64 {
    let v, ok = conf_get(cfg, path);
    if !ok { return dflt; }
    let n, nok = parse_duration(v);
    return if nok { n } else { dflt };
}

// A duration (MIT's krb5_string_to_deltat): seconds ("36000"),
// "h:m[:s]", or numbers with d, h, m, s in that order ("1d 2h30m").
fn parse_duration(s0: const u8[:]) -> i64, bool {
    let s = trim(s0);
    if s.len == 0 { return 0, false; }
    var colons = 0;
    for c in s { if c == ':' { colons++; } }
    if colons > 0 {
        var parts: i64[3] = [0; 3];
        var k = 0;
        var any = false;
        for c in s {
            if c == ':' { if !any || k >= 2 { return 0, false; } k++; any = false; continue; }
            if c < '0' || c > '9' { return 0, false; }
            parts[k] = parts[k] * 10 + (c - '0');
            any = true;
            if parts[k] > 1 << 40 { return 0, false; }
        }
        if !any { return 0, false; }
        return parts[0] * 3600 + parts[1] * 60 + parts[2], true;
    }
    var total: i64 = 0;
    var cur: i64 = 0;
    var have = false;
    var rank = 5;                     // units must come in order: d h m s
    for c in s {
        if c >= '0' && c <= '9' {
            cur = cur * 10 + (c - '0');
            if cur > 1 << 40 { return 0, false; }
            have = true;
            continue;
        }
        if c == ' ' { continue; }
        if !have { return 0, false; }
        let r = if c == 'd' { 4 } else if c == 'h' { 3 } else if c == 'm' { 2 } else if c == 's' { 1 } else { 0 };
        if r == 0 || r >= rank { return 0, false; }
        rank = r;
        total += cur * (if r == 4 { 86400 } else if r == 3 { 3600 } else if r == 2 { 60 } else { 1 });
        cur = 0;
        have = false;
    }
    if have { total += cur; }
    return total, true;
}

fn conf_duration(cfg: const Config&, path: const u8[:], dflt: i64) -> i64 {
    let v, ok = conf_get(cfg, path);
    if !ok { return dflt; }
    let n, nok = parse_duration(v);
    return if nok { n } else { dflt };
}

// MIT 1.22's default enctype list.
let DEFAULT_ETYPES: i32[8] = [18, 17, 20, 19, 16, 23, 26, 25];

// An enctype list (MIT's): names, numbers and families (aes, aes-sha1,
// aes-sha2, des3, rc4, camellia, DEFAULT), separated by spaces or commas,
// a leading '-' removing; types we do not have are left out.
fn parse_etypes(s: const u8[:]) -> i32[>..] {
    var out: i32[>..] = [];
    var w = 0;
    for j in s.len + 1 {
        if j < s.len && !is_space(s[j]) && s[j] != ',' { continue; }
        let word = s[w..j];
        w = j + 1;
        if word.len == 0 { continue; }
        let remove = word[0] == '-';
        let name = lower(if remove || word[0] == '+' { word[1..] } else { word });
        var add: i32[>..] = [];
        if name == "default" { add.append(DEFAULT_ETYPES); }
        else if name == "aes" { add.push(18); add.push(17); add.push(20); add.push(19); }
        else if name == "aes-sha1" { add.push(18); add.push(17); }
        else if name == "aes-sha2" { add.push(20); add.push(19); }
        else if name == "des3" { add.push(16); }
        else if name == "rc4" { add.push(23); }
        else if name == "camellia" { add.push(26); add.push(25); }
        else {
            let e = etype_by_name(name);
            if e != 0 { add.push(e); }
        }
        for e in add {
            if !etype_supported(e) { continue; }
            var at = -1;
            for k in out.len { if out[k] == e { at = k; } }
            if remove {
                if at >= 0 {
                    var rest: i32[>..] = [];
                    for k in out.len { if k != at { rest.push(out[k]); } }
                    out.clear();
                    out.append(rest);
                }
            } else if at < 0 {
                out.push(e);
            }
        }
    }
    return out;
}

// The enctypes a libdefaults relation lists, or MIT's defaults.
fn conf_etypes(cfg: const Config&, name: const u8[:]) -> i32[>..] {
    // default_tkt_enctypes and default_tgs_enctypes fall back to
    // permitted_enctypes, as in MIT.
    let v, ok = conf_get(cfg, path2("libdefaults", name));
    if ok { return parse_etypes(v); }
    let w, ok2 = conf_get(cfg, "libdefaults/permitted_enctypes");
    if ok2 { return parse_etypes(w); }
    var d: i32[>..] = [];
    d.append(DEFAULT_ETYPES);
    return d;
}

fn default_realm(cfg: const Config&) -> u8[>..], bool {
    let r, ok = conf_get(cfg, "libdefaults/default_realm");
    return r, ok;
}

// A KDC's address: host, port, and whether it must be TCP ("tcp/host"
// in the relation) or UDP ("udp/host").
struct KdcAddr { host: u8[], port: i64, tcp_only: bool, udp_only: bool }

// Splits "host", "host:port", "[v6]:port" or "v6" (more than one colon).
fn split_host_port(s: const u8[:], dflt_port: i64) -> u8[>..], i64, bool {
    var host: u8[>..] = [];
    var port = dflt_port;
    if s.len > 0 && s[0] == '[' {
        var e = 1;
        while e < s.len && s[e] != ']' { e++; }
        if e >= s.len { return host, port, false; }
        host.append(s[1..e]);
        if e + 1 < s.len {
            if s[e + 1] != ':' { return host, port, false; }
            let p, ok = parse_int(s[e + 2..]);
            if !ok || p <= 0 || p > 65535 { return host, port, false; }
            port = p;
        }
        return host, port, host.len > 0;
    }
    var colons = 0;
    var last = -1;
    for j in s.len { if s[j] == ':' { colons++; last = j; } }
    if colons == 1 {
        host.append(s[..last]);
        let p, ok = parse_int(s[last + 1..]);
        if !ok || p <= 0 || p > 65535 { return host, port, false; }
        port = p;
    } else {
        host.append(s);
    }
    return host, port, host.len > 0;
}

// The realm's KDCs from [realms] (kdc relations, in order).
fn realm_kdcs(cfg: const Config&, realm: const u8[:]) -> KdcAddr[>..] {
    var out: KdcAddr[>..] = [];
    for v in conf_all(cfg, path3("realms", realm, "kdc")) {
        var s = trim(v);
        var tcp = false;
        var udp = false;
        if s.starts_with("tcp/") { tcp = true; s = s[4..]; }
        else if s.starts_with("udp/") { udp = true; s = s[4..]; }
        let h, p, ok = split_host_port(s, 88);
        if ok { out.push(KdcAddr { host: copy(h), port: p, tcp_only: tcp, udp_only: udp }); }
    }
    return out;
}

// The realm of a host by [domain_realm]: the host itself, then each of
// its parent domains with a leading '.', longest first. Empty when no
// relation says (MIT then asks the KDC, by referral, or uses the default
// realm).
fn realm_for_host(cfg: const Config&, host0: const u8[:]) -> u8[>..] {
    var host = lower(host0);
    while host.len > 0 && host[host.len - 1] == '.' { host.resize(host.len - 1); }
    let v, ok = conf_get(cfg, path2("domain_realm", host));
    if ok { return v; }
    var j = 0;
    while j < host.len {
        if host[j] == '.' {
            let w, ok2 = conf_get(cfg, path2("domain_realm", host[j..]));
            if ok2 { return w; }
        }
        j++;
    }
    var e: u8[>..] = [];
    return e;
}

// The realms between client and server realms by [capaths] (RFC 4120
// §1.2's transit path): the intermediate realms in order, empty for a
// direct trust. ok is false when capaths says nothing of the pair, and
// the caller falls back to the hierarchy.
fn capath(cfg: const Config&, client_realm: const u8[:], server_realm: const u8[:]) -> u8[][>..], bool {
    var out: u8[][>..] = [];
    let p = path3("capaths", client_realm, server_realm);
    var found = false;
    for e in cfg.entries {
        if e.path != p { continue; }
        found = true;
        if e.value != "." { out.push(copy(e.value)); }
    }
    return out, found;
}

// The parent realm: what follows the first '.', or empty.
fn parent_realm(r: const u8[:]) -> const u8[:] {
    for k in r.len { if r[k] == '.' { return r[k + 1..]; } }
    return r[r.len..];
}

// Whether `s` is `suffix` or ends in "." + suffix.
fn realm_under(s: const u8[:], suffix: const u8[:]) -> bool {
    if s == suffix { return true; }
    return suffix.len < s.len && s.ends_with(suffix) && s[s.len - suffix.len - 1] == '.';
}

// The hierarchical path (RFC 4120 §1.2.1, MIT's default without capaths):
// up from the client realm to the nearest realm both are under, then down
// to the server realm; the realms between the two ends, in order.
// "A.EXAMPLE.COM" to "B.EXAMPLE.COM" goes through "EXAMPLE.COM"; with
// nothing in common the path goes through both top-level realms.
fn hierarchical_path(client_realm: const u8[:], server_realm: const u8[:]) -> u8[][>..] {
    var out: u8[][>..] = [];
    if client_realm == server_realm { return out; }
    var common = client_realm;
    while common.len > 0 && !realm_under(server_realm, common) { common = parent_realm(common); }
    var cur = client_realm;
    while cur.len > 0 && cur != common {
        cur = parent_realm(cur);
        if cur.len > 0 && cur != server_realm && (cur != common || common != client_realm) { out.push(cur); }
        if cur.len == 0 { break; }
    }
    // Down: the server realm's ancestors below `common`, outermost first.
    var downs: u8[][>..] = [];
    var s = parent_realm(server_realm);
    while server_realm != common && s.len > 0 && s != common {
        downs.push(s);
        s = parent_realm(s);
    }
    var n = 0;
    for d in downs { n++; }
    var k = n - 1;
    while k >= 0 {
        var i = 0;
        for d in downs { if i == k { out.push(copy(d)); } i++; }
        k--;
    }
    return out;
}
