// Fuzz target: dns_zone. The first byte picks the parser:
//   0: parse_zone on the text (origin example.org., $INCLUDE off), the
//      records then written as text (fixed clock), checked (list_valid,
//      rdata_valid, canonical form) and packed into a message and read back.
//   1: new_rr on the text (miekg's NewRR), the record likewise.
//   2: resolv.conf (client_config) and name_list over its search domains.
// new_rr allows $INCLUDE (a known finding): text naming it is skipped,
// since it would read files.

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.rdata;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.client;

let NOW: i64 = 1800000000;

var ORIGIN: dns::Name = [];

fn has_include(s: const u8[:]) -> bool {
    let pat = "include";
    var i = 0;
    while i + pat.len <= s.len {
        var ok = true;
        for j in pat.len { if dns::lower(s[i + j]) != pat[j] { ok = false; break; } }
        if ok { return true; }
        i++;
    }
    return false;
}

fn exercise(list: const u8[:]) {
    if !dns::list_valid(list) { return; }
    var out:   u8[>..] = [];
    var canon: u8[>..] = [];
    var n = 0;
    dns::each_rr(list) { rr =>
        dns::rr_header_append(out, list, rr);
        dns::rdata_append(out, rr.rtype, rr.rdata(list), NOW);
        out.push('\n');
        let _ = dns::rdata_valid(rr.rtype, rr.rdata(list));
        canon.clear();
        dns::rdata_canonical(rr.rtype, rr.rdata(list), canon);
        n++;
    };
    // Packed with compression, read back, and the text read again.
    var m = dns::Msg { .. };
    m.compress = true;
    m.hdr.response = true;
    m.answer.append(list);
    var w: u8[>..] = [];
    if dns::pack(m, w) == dns::OK {
        var back = dns::Msg { .. };
        let _ = dns::unpack(w, back);
    }
    if n <= 64 {
        var again: u8[>..] = [];
        var o = dns::ZoneOptions { .. };
        o.origin = ORIGIN;
        let _ = dns::parse_zone(out, o, again);
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let text = data[1..];
    let sel = data[0] % 3;
    if sel == 0 {
        var opts = dns::ZoneOptions { .. };
        opts.origin = ORIGIN;
        var out: u8[>..] = [];
        let r = dns::parse_zone(text, opts, out);
        if r.err == dns::OK { exercise(out); }
    } else if sel == 1 {
        if has_include(text) { return 0; }
        var out: u8[>..] = [];
        let e = dns::new_rr(out, text);
        if e == dns::OK { exercise(out); }
    } else {
        let c = dns::client_config(text);
        for s in c.search {
            let _ = dns::name_list(c, s);
        }
        let _ = dns::name_list(c, "www");
    }
    return 0;
}

fn main() {
    let o, oe = dns::name_parse("example.org.", []);
    ORIGIN.append(o);
}
