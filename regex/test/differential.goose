// regex against the Rust regex crate: 605 cases kept from the differential
// test (regex/scripts/differential.py), random patterns that mix `^ $ \A \z
// \b \B` into alternations, repetitions, groups and scoped flags, on random
// texts over "ab \n_x.A". differential_cases.txt holds them, a pattern and
// a text in hex per line; expected/differential.txt is what the crate
// (regex 1.13.2, regex::bytes, Unicode off) gives for them, printed as
// regex.goose's show() prints: each match's groups as start,end, joined
// by |. find, count and matches are checked against the iteration too.
// With an argument, the cases come from that file instead, and a pattern
// that does not compile prints its error (the differential's runs).
import std;
import os;
import gslib from "../..";
import gslib.regex;

fn unhex(s: u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((ascii::hex_value(s[i]) * 16 + ascii::hex_value(s[i + 1])) as u8);
        i += 2;
    }
    return out;
}

// s with its line breaks and tabs made visible.
fn visible(out: u8[>..]&, s: u8[:]) {
    var a: u8[>..] = [];
    format_replaced(a, s, "\n", "\\n");
    format_replaced(out, a, "\t", "\\t");
}

fn main() {
    var path: u8[>..] = [];
    if arg_count() > 1 { arg(1, path); } else { path.append("differential_cases.txt"); }
    var data: u8[>..] = [];
    assert(read_file(path, data));
    var out: u8[>..] = [];
    var at = 0;
    while at < data.len {
        var end = at;
        while end < data.len && data[end] != '\n' { end++; }
        let line = data[at..end];
        at = end + 1;
        let sp = position(line, ' ');
        let pattern = unhex(line[..sp]);
        let text = unhex(line[sp + 1..]);
        var err: u8[>..] = [];
        let re = regex::compile(pattern, err);
        visible(out, pattern);
        out.append(" on ");
        visible(out, text);
        out.append(" =>");
        if err.len > 0 {
            format(out, " error ", err, "\n");
            continue;
        }
        var n = 0;
        var fs = -1;
        var fe = -1;
        regex::each_captures(re, text) { c =>
            out.push(' ');
            for v, k in c.slots { format(out, if k == 0 { "" } else if k % 2 == 0 { "|" } else { "," }, v); }
            if n == 0 { fs = c.slots[0]; fe = c.slots[1]; }
            n++;
        };
        if n == 0 { out.append(" none"); }
        let s, e = regex::find(re, text);
        if s != fs || e != fe || regex::count(re, text) != n || regex::matches(re, text) != (n > 0) {
            out.append(" (count, matches or find disagree)");
        }
        out.push('\n');
    }
    write_stdout(out);
}
