// http.url: what scripts/url_differential.py does not compare with Go:
// request targets, Host fields, Referer and redacted forms, ports,
// queries and forms. IP addresses and Punycode are net's (net/test/ip.goose).

import std;
import gslib from "../../..";
import gslib.net.http;
import gslib.net.http.url;

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

fn parsed(s: const u8[:]) -> http::Url {
    let u, e = http::url_parse(s);
    if e != 0 { print("FAIL parse ", s, ": ", http::url_error_text(e)); failures++; }
    return u;
}

fn target(s: const u8[:], want: const u8[:]) {
    let u = parsed(s);
    var t: u8[>..] = [];
    http::request_target(u, t);
    check(s, t, want);
}

fn absolute(s: const u8[:], want: const u8[:]) {
    let u = parsed(s);
    var t: u8[>..] = [];
    http::absolute_target(u, t);
    check(s, t, want);
}

fn host_field(s: const u8[:], want: const u8[:]) {
    let u = parsed(s);
    var t: u8[>..] = [];
    let ok = http::host_port_field(u, t);
    check_bool(s, ok, true);
    check(s, t, want);
}

fn port_of(s: const u8[:]) -> i64 {
    let u = parsed(s);
    return http::url_port(u);
}

fn check_http(s: const u8[:]) -> i64 {
    let u = parsed(s);
    return http::url_check_http(u);
}

fn targets() {
    target("http://a", "/");
    target("http://a/", "/");
    target("http://a/x/y?q=1&r", "/x/y?q=1&r");
    target("http://a/x?", "/x?");
    target("http://a/%41%2fb", "/%41%2fb");                 // escapes stay as written
    target("http://a/a b?c d", "/a%20b?c%20d");             // RFC 9112 has no space in a target
    target("http://a/\"<>\\^`{|}", "/%22%3C%3E%5C%5E%60%7B%7C%7D");
    target("http://a/[x]?[y]", "/%5Bx%5D?%5By%5D");
    target("http://a/\xc3\xa9?\xc3\xa9", "/%C3%A9?%C3%A9");
    target("http://a/p?x=/?:@!$&'()*+,;=", "/p?x=/?:@!$&'()*+,;=");
    target("http://a/:@!$&'()*+,;=-._~", "/:@!$&'()*+,;=-._~");
    target("http://a/x#frag", "/x");
    absolute("http://u:p@a:8080/x?q#f", "http://a:8080/x?q");
    absolute("https://[::1]/", "https://[::1]/");
    absolute("http://A.example", "http://A.example/");
}

fn hosts() {
    host_field("http://example.com/x", "example.com");
    host_field("http://example.com:80/x", "example.com:80");      // as written, as Go sends it
    host_field("http://example.com:/x", "example.com");
    host_field("http://[::1]:8080/", "[::1]:8080");
    host_field("http://[fe80::1%25en0]:8/", "[fe80::1]:8");       // no zone on the wire (Go's removeZone)
    host_field("http://b\xc3\xbccher.example/", "xn--bcher-kva.example");
    host_field("http://B\xc3\xbcCHER.example/", "xn--bcher-kva.example");
    host_field("http://a%c3%bc.example/", "xn--a-eha.example");
    let u = parsed("http://\xff.example/");
    var t: u8[>..] = [];
    check_bool("not UTF-8", http::host_port_field(u, t), false);
}

fn parts() {
    let u = parsed("HTTPS://us%40er:p%3Ass@Example.COM:8443/a/b?q=1#top");
    check("scheme", http::url_scheme(u), "https");
    check("host", http::url_host(u), "Example.COM");
    check("user", http::url_username(u), "us@er");
    check("password", http::url_password(u), "p:ss");
    check("text", http::url_text(u), "https://us%40er:p%3Ass@Example.COM:8443/a/b?q=1#top");
    check("referer", http::url_referer(u), "https://Example.COM:8443/a/b?q=1");
    check("redacted", http::url_redacted(u), "https://us%40er:xxxxx@Example.COM:8443/a/b?q=1#top");
    check_bool("https", http::url_https(u), true);
    check_bool("port", http::url_port(u) == 8443, true);
    let v6 = parsed("http://u@[::1]:9/x#f");
    check("referer v6", http::url_referer(v6), "http://[::1]:9/x");
    check("hostname v6", http::url_hostname(v6), "::1");
    check_bool("default http", port_of("http://a/") == 80, true);
    check_bool("default https", port_of("https://a/") == 443, true);
    check_bool("port 0", port_of("http://a:0/") == -1, true);
    check_bool("port 65536", port_of("http://a:65536/") == -1, true);
    check_bool("port 65535", port_of("http://a:65535/") == 65535, true);
    check_bool("http ok", check_http("http://a/") == 0, true);
    check_bool("no host", check_http("http:///x") != 0, true);
    check_bool("ftp", check_http("ftp://a/") != 0, true);
    check_bool("relative", check_http("/a") != 0, true);
    check_bool("opaque", check_http("http:a") != 0, true);
    let e1, c1 = http::url_parse("http://a/\x01");
    check_bool("control", c1 == http::URL_ERR_CONTROL, true);
    let e2, c2 = http::url_parse("http://a:x/");
    check_bool("bad port", c2 == http::URL_ERR_PORT, true);
    let e3, c3 = http::url_parse("http://a/%zz");
    check_bool("bad escape", c3 == http::URL_ERR_ESCAPE, true);
}

fn resolution() {
    // RFC 3986 §5.4's normal and abnormal examples; scripts/url_differential.py
    // checks them against Go too.
    let base = parsed("http://a/b/c/d;p?q");
    let cases = [
        "g:h", "g:h", "g", "http://a/b/c/g", "./g", "http://a/b/c/g", "g/", "http://a/b/c/g/", "/g", "http://a/g",
        "//g", "http://g", "?y", "http://a/b/c/d;p?y", "g?y", "http://a/b/c/g?y", "#s", "http://a/b/c/d;p?q#s",
        "g#s", "http://a/b/c/g#s", "g?y#s", "http://a/b/c/g?y#s", ";x", "http://a/b/c/;x", "g;x", "http://a/b/c/g;x",
        "g;x?y#s", "http://a/b/c/g;x?y#s", "", "http://a/b/c/d;p?q", ".", "http://a/b/c/", "./", "http://a/b/c/",
        "..", "http://a/b/", "../", "http://a/b/", "../g", "http://a/b/g", "../..", "http://a/", "../../", "http://a/",
        "../../g", "http://a/g", "../../../g", "http://a/g", "../../../../g", "http://a/g", "/./g", "http://a/g",
        "/../g", "http://a/g", "g.", "http://a/b/c/g.", ".g", "http://a/b/c/.g", "g..", "http://a/b/c/g..",
        "..g", "http://a/b/c/..g", "./../g", "http://a/b/g", "./g/.", "http://a/b/c/g/", "g/./h", "http://a/b/c/g/h",
        "g/../h", "http://a/b/c/h", "g;x=1/./y", "http://a/b/c/g;x=1/y", "g;x=1/../y", "http://a/b/c/y",
        "g?y/./x", "http://a/b/c/g?y/./x", "g?y/../x", "http://a/b/c/g?y/../x", "g#s/./x", "http://a/b/c/g#s/./x",
        "g#s/../x", "http://a/b/c/g#s/../x", "http:g", "http:g",
    ];
    var i = 0;
    while i < cases.len {
        let r, e = http::url_resolve(base, cases[i]);
        check_bool(cases[i], e == 0, true);
        check(cases[i], http::url_text(r), cases[i + 1]);
        i += 2;
    }
    // Go's resolvePath never leaves "//" at a path's start.
    let o = parsed("http:/a");
    let r, e = http::url_resolve(o, "..//x");
    check("no empty first segment", http::url_text(r), "http:/x");
    // A path that starts with "//" without an authority is written with
    // "/." before it, so the text does not read as one.
    let back = parsed("http:/.//x");
    check("dot-slash path", http::url_path(back), "/.//x");
}

fn queries() {
    var q: u8[>..] = [];
    http::form_add(q, "a b", "c&d=e");
    http::form_add(q, "x", "\xc3\xa9/?#+~");
    check("form", q, "a+b=c%26d%3De&x=%C3%A9%2F%3F%23%2B~");
    let v, ok = http::query_value(q, "a b");
    check_bool("value found", ok, true);
    check("value", v, "c&d=e");
    let v2, ok2 = http::query_value(q, "x");
    check("value 2", v2, "\xc3\xa9/?#+~");
    let v3, ok3 = http::query_value("a=1;b=2&b=3&c&c=4", "b");
    check("semicolon pair skipped", v3, "3");
    let v4, ok4 = http::query_value("a=1&c&c=4", "c");
    check_bool("empty value found", ok4, true);
    check("empty value", v4, "");
    let v5, ok5 = http::query_value("a=%zz&a=2", "a");
    check("bad escape skipped", v5, "2");
    let v6, ok6 = http::query_value("a=1", "b");
    check_bool("missing", ok6, false);
    var p: u8[>..] = [];
    http::path_escape(p, "a b/c;d,e?f@g:h");
    check("path escape", p, "a%20b%2Fc%3Bd%2Ce%3Ff@g:h");
    var d: u8[>..] = [];
    check_bool("unescape", http::query_unescape(d, "a+b%20c%2B"), true);
    check("unescaped", d, "a b c+");
    var d2: u8[>..] = [];
    check_bool("bad unescape", http::path_unescape(d2, "a%2"), false);
    check("nothing appended", d2, "");
}

fn main() {
    targets();
    hosts();
    parts();
    resolution();
    queries();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("url: all passed");
}
