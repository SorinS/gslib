// Fuzz target: http_cookie. Cookies (net/http cookie). Byte 0: its low bit
// picks Set-Cookie lines (the rest split at newlines, each parsed and put
// in a jar for one of a few request URLs, as a client gets them) or a
// curl cookies.txt loaded into a jar; the other bits pick the URL. Then
// the jar is queried (the Cookie field for each URL), saved and loaded
// again. Dates go through parse_cookie_date and format_http_date, hosts
// through the public suffix list (built in, loaded once).

import std;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.url;
import gslib.net.http.cookie;

var psl = http::empty_psl();
let URLS = ["https://www.example.com/a/b?c=d", "http://example.co.uk/", "http://127.0.0.1:8080/x/",
             "https://[::1]/p", "http://localhost/", "https://foo.bar.blogspot.com/dir/page",
             "http://xn--bcher-kva.example/", "https://a.b.c.d.e.example.org:8443/deep/path/"];

let NOW: i64 = 1700000000000;

fn probe_set_cookie(m: const u8[:]) {
    let c, ok = http::parse_set_cookie(m);
    if !ok { return; }
    let _ = m[c.name.pos..c.name.end];
    let _ = m[c.value.pos..c.value.end];
    if c.has_domain {
        let d = m[c.domain.pos..c.domain.end];
        let _ = http::registrable_domain(psl, d);
        let _ = http::public_suffix(psl, d);
        let _ = http::canonical_host(d);
    }
    if c.has_path { let _ = http::default_cookie_path(m[c.path.pos..c.path.end]); }
    if c.has_expires {
        var t: u8[>..] = [];
        http::format_http_date(t, c.expires_ms);
        let back, okb = http::parse_cookie_date(t);
        if !okb || back != (if c.expires_ms >= 0 { c.expires_ms / 1000 } else { -((-c.expires_ms + 999) / 1000) }) * 1000 {
            abort("http_cookie: format_http_date does not parse back");
        }
    }
}

fn query(j: http::Jar&) {
    for us in URLS {
        let u, e = http::url_parse(us);
        var out: u8[>..] = [];
        let _ = http::jar_cookie_header(j, psl, u, NOW + 1000, out);
        var n = 0;
        http::jar_cookies(j, psl, u, NOW + 1000) { name, value => n += name.len + value.len; };
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let sel = data[0] & 1;
    let u, ue = http::url_parse(URLS[(data[0] >> 1) % URLS.len]);
    let rest = data[1..];
    var j = http::new_jar();
    if sel == 0 {
        var now = NOW;
        var lines = 0;
        each_split(rest, '\n') {
            if lines < 64 {
                lines++;
                probe_set_cookie(it);
                let _ = http::parse_cookie_date(it);
                let _ = http::jar_set_cookie(j, psl, u, it, now);
                now += 1001;
            }
        };
    } else {
        let _ = http::jar_load_netscape(j, psl, rest, NOW);
    }
    let _ = http::jar_count(j);
    query(j);
    // Saved and loaded again: as many cookies.
    var saved: u8[>..] = [];
    http::jar_save_netscape(j, saved, NOW, true);
    var j2 = http::new_jar();
    let _ = http::jar_load_netscape(j2, psl, saved, NOW);
    query(j2);
    let _ = http::cookie_host(u);
    return 0;
}

fn main() {
    let _ = http::psl_builtin(psl);
}
