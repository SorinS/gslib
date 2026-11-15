// Fuzz target: http_url. URLs (net/http url): the input up to the first
// NUL or newline is a base URL, the rest a reference resolved against it
// (as a Location field is). Each URL's accessors, its request target,
// Host field, Referer and redacted form; its text parsed again must give
// the same text. The query is read as a form, escapes are round-tripped,
// and the host goes through the IP parsers and Punycode.

import std;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.url;

fn probe(u: const http::Url&) {
    let _ = http::url_scheme(u);
    let _ = http::is_abs(u);
    let _ = http::url_check_http(u);
    let _ = http::url_https(u);
    let _ = http::url_port(u);
    let _ = http::url_hostname(u);
    let _ = http::url_username(u);
    let _ = http::url_password(u);
    let _ = http::url_ascii_host(u);
    var t: u8[>..] = [];
    http::request_target(u, t);
    t.clear();
    let _ = http::host_port_field(u, t);
    t.clear();
    if http::url_check_http(u) == 0 { http::absolute_target(u, t); }
    let _ = http::url_referer(u);
    let _ = http::url_redacted(u);
    let h = http::url_host(u);
    let _ = http::parse_ip(h);
    let _ = http::parse_ip_zone(h);
    let ip, kind = http::parse_ip_zone(h);
    let _ = http::ip_is_loopback(ip, kind);
    let _ = http::to_ascii_host(h);
    // The query as a form.
    let q = http::url_query(u);
    each_split(q, '&') {
        let pair = it;
        let eq = position(pair, '=');
        let k = if eq < 0 { pair } else { pair[..eq] };
        var key: u8[>..] = [];
        if http::query_unescape(key, k) { let _ = http::query_value(q, key); }
    };
}

fn escapes(s: const u8[:]) {
    var e: u8[>..] = [];
    http::query_escape(e, s);
    var back: u8[>..] = [];
    if !http::query_unescape(back, e) || back[..] != s { abort("http_url: query_escape round trip"); }
    e.clear();
    back.clear();
    http::path_escape(e, s);
    if !http::path_unescape(back, e) || back[..] != s { abort("http_url: path_escape round trip"); }
    var f: u8[>..] = [];
    http::form_add(f, s, s);
    let v, ok = http::query_value(f, s);
    if !ok || v[..] != s { abort("http_url: form_add then query_value"); }
    back.clear();
    let _ = http::query_unescape(back, s);
    back.clear();
    let _ = http::path_unescape(back, s);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    var cut = data.len;
    for i in data.len { if data[i] == 0 || data[i] == '\n' { cut = i; break; } }
    let a = data[..cut];
    let b = if cut < data.len { data[cut + 1..] } else { data[cut..] };
    let u, e = http::url_parse(a);
    if e == 0 {
        probe(u);
        let u2, e2 = http::url_parse(http::url_text(u));
        if e2 != 0 || http::url_text(u2) != http::url_text(u) { abort("http_url: text does not parse back the same"); }
        let r, er = http::url_resolve(u, b);
        if er == 0 { probe(r); }
    } else {
        let _ = http::url_error_text(e);
    }
    let rb, eb = http::url_parse(b);
    if eb == 0 { probe(rb); }
    if a.len <= 256 { escapes(a); }
    return 0;
}

fn main() {}
