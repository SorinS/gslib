// regex's literal searches, against a naive search: literal sequences
// (found without the DFAs), with (?i) and with \b at both ends, and a
// repeated set before a literal (Skip.Suffix), on texts whose lengths lie
// around the scans' blocks (16, 64 and 128 bytes), with the needle at the
// start, at the end, at random places and overlapping itself, among filler
// made of the needle's own bytes so that most candidates fail their check.
// Prints only what disagrees, and a count.
import std;
import gslib from "../..";
import gslib.regex;

fn is_word(c: u8) -> bool { ascii::is_alnum(c) || c == '_' }

fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }
fn upper(c: u8) -> u8 { if c >= 'a' && c <= 'z' { c - 32 } else { c } }

// The starts of the non-overlapping, leftmost matches of a literal needle,
// case-insensitive where `fold`, between word boundaries where `bounds`.
fn naive_literal(text: u8[:], needle: u8[:], fold: bool, bounds: bool) -> i64[>..] {
    fn boundary(p: i64) -> bool {
        let before = p > 0 && is_word(text[p - 1]);
        let after = p < text.len && is_word(text[p]);
        return before != after;
    }
    var out: i64[>..] = [];
    var i = 0;
    while i + needle.len <= text.len {
        var ok = true;
        for c, k in needle {
            let t = text[i + k];
            if (if fold { lower(t) != lower(c) } else { t != c }) { ok = false; break; }
        }
        if ok && bounds { ok = boundary(i) && boundary(i + needle.len); }
        if ok {
            out.push(i);
            i += needle.len;
        } else {
            i++;
        }
    }
    return out;
}

// The leftmost-first matches of [a-z]{min,max}L (max -1: none), greedy: at
// each start the most repetitions that L follows.
fn naive_suffix(text: u8[:], min: i64, max: i64, l: u8[:]) -> i64[>..] {
    var out: i64[>..] = [];
    var s = 0;
    while s < text.len {
        var run = 0;
        while s + run < text.len && text[s + run] >= 'a' && text[s + run] <= 'z' && (max < 0 || run < max) { run++; }
        var found = -1;
        var k = run;
        while k >= min {
            if s + k + l.len <= text.len && text[s + k..s + k + l.len] == l { found = k; break; }
            k--;
        }
        if found >= 0 {
            out.push(s);
            out.push(s + found + l.len);
            s = s + found + l.len;
        } else {
            s++;
        }
    }
    return out;
}

var cases = 0;
var failures = 0;
var routes: i64[5] = [0; 5];     // DFA, Rare, Pair, Any, Suffix

fn check(what: u8[:], pattern: u8[:], text: u8[:], want: i64[:]) {
    let re = regex::compile(pattern);
    if re.skip == regex::Skip.Suffix { routes[4]++; }
    else if re.lit.len == 0 { routes[0]++; }
    else { routes[match re.lit.hunt { Rare => 1, Pair => 2, Any => 3 }]++; }
    var got: i64[>..] = [];
    regex::each_match(re, text) { s, e => got.push(s); got.push(e); };
    let s, e = regex::find(re, text);
    let first_ok = if want.len == 0 { s == -1 } else { s == want[0] && e == want[1] };
    if got != want || !first_ok || regex::count(re, text) != want.len / 2 || regex::matches(re, text) != (want.len > 0) {
        failures++;
        if failures <= 10 {
            print("FAIL ", what, " /", pattern, "/ on ", text.len, " bytes: want ", want.len / 2, " matches, got ", got.len / 2);
        }
    }
    cases++;
}

fn main() {
    var r = rng { 11 };
    let lengths = [0, 1, 2, 15, 16, 17, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 257, 300, 1000];
    // alphabets: rare bytes (a probe and scan_rare), common ones (find_pair),
    // a mix, and letters for (?i)
    let alphabets = ["Mzq", "eth", "Mte", "abc"];
    let needle_lens = [1, 2, 3, 8, 16, 65];
    for alphabet in alphabets {
        for n in needle_lens {
            var needle: u8[>..] = [];
            for k in n { needle.push(alphabet[r.rand_int(alphabet.len)]); }
            for len in lengths {
                for mode in 3 {         // plain, (?i), \b..\b
                    // filler of the needle's bytes and spaces, the needle
                    // at the start, the end and random places
                    var text: u8[>..] = [];
                    for k in len {
                        let x = r.rand_int(4);
                        text.push(if x == 0 { ' ' } else { alphabet[r.rand_int(alphabet.len)] });
                        if mode == 1 && r.rand_int(2) == 0 { text[text.len - 1] = upper(text[text.len - 1]); }
                    }
                    if len >= n {
                        text[0..n].copy_from(needle);
                        text[len - n..len].copy_from(needle);
                        for k in 3 {
                            let at = r.rand_int(len - n + 1);
                            text[at..at + n].copy_from(needle);
                        }
                    }
                    var pattern: u8[>..] = [];
                    if mode == 1 { pattern.append("(?i)"); }
                    if mode == 2 { pattern.append("\\b"); }
                    pattern.append(needle);
                    if mode == 2 { pattern.append("\\b"); }
                    var want: i64[>..] = [];
                    for s in naive_literal(text, needle, mode == 1, mode == 2) { want.push(s); want.push(s + n); }
                    check("literal", pattern, text, want);
                }
            }
        }
    }
    // A needle longer than the text, and repeats of a counted set.
    check("longer", "abcdefgh", "abcdefg", []);
    check("counted", "x{3}y", "xxxy xxy xxxxy", [0, 4, 10, 14]);
    // A repeated set before a literal: [a-z]{min,max}L, a set common enough
    // that the prefix test does not take it.
    let suffixes = ["c", "cd", "aac", "xyz", "ing"];
    for l in suffixes {
        for len in lengths {
            var text: u8[>..] = [];
            for k in len {
                let x = r.rand_int(10);
                text.push(if x < 6 { "abcde"[r.rand_int(5)] } else if x < 8 { l[r.rand_int(l.len)] } else { ' ' });
            }
            if len >= l.len + 2 { text[len - l.len..len].copy_from(l); }
            for mm in [[1, -1], [0, -1], [2, 3], [1, 1]] {
                var pattern: u8[>..] = [];
                format(pattern, "[a-z]{", mm[0], ",");
                if mm[1] >= 0 { format(pattern, mm[1]); }
                format(pattern, "}", l);
                if mm[1] == mm[0] { pattern.clear(); format(pattern, "[a-z]{", mm[0], "}", l); }
                check("suffix", pattern, text, naive_suffix(text, mm[0], mm[1], l));
            }
        }
    }
    print(cases, " cases, ", failures, " failures");
    print("by the DFAs ", routes[0], ", literal by a rare byte ", routes[1], ", by a pair ", routes[2],
          ", by a byte ", routes[3], ", suffix ", routes[4]);
}
