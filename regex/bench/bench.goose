// gslib's regex in the regex benchmark (bench.py): for each pattern of the
// patterns file, the compile time, the matches over the corpus counted
// (the best of several runs), and for `caps` patterns the first group's
// spans over every match. It prints the protocol every engine prints:
// "pattern corpus metric value" lines.
//
//   goose build bench.goose -o bench-goose && ./bench-goose patterns.tsv corpus.txt generated
import std;
import os;
import gslib from "../..";
import gslib.regex;

// Seconds for the best of the runs of F: at least three runs and half a
// second, or one run past three seconds, and at most twenty. A run repeats
// F until it has taken 5 ms, for work shorter than the clock can time.
fn best<F>() -> f64 {
    var best = 1.0e9;
    var total = 0.0;
    var runs = 0;
    while runs < 20 && !(runs >= 3 && total >= 0.5) && !(runs >= 1 && total >= 3.0) {
        let t0 = clock();
        var reps = 0;
        var t = 0.0;
        while reps == 0 || t < 0.005 {
            F();
            reps++;
            t = clock() - t0;
        }
        total += t;
        if t / reps < best { best = t / reps; }
        runs++;
    }
    return best;
}

fn main() {
    var patterns_path: u8[>..] = [];
    var corpus_path: u8[>..] = [];
    var corpus: u8[>..] = [];
    arg(1, patterns_path);
    arg(2, corpus_path);
    arg(3, corpus);
    var only: u8[>..] = [];
    if arg_count() > 4 { arg(4, only); }
    var table: u8[>..] = [];
    var text: u8[>..] = [];
    assert(read_file(patterns_path, table));
    assert(read_file(corpus_path, text));
    let mb = text.len / 1.0e6;
    var out: u8[>..] = [];
    var at = 0;
    while at < table.len {
        var end = at;
        while end < table.len && table[end] != '\n' { end++; }
        let line = table[at..end];
        at = end + 1;
        if line.len == 0 || line[0] == '#' { continue; }
        // name, kind, pattern, (the POSIX spelling and flags)
        let t1 = position(line, '\t');
        let name = line[..t1];
        let rest = line[t1 + 1..];
        let t2 = position(rest, '\t');
        let kind = rest[..t2];
        let rest2 = rest[t2 + 1..];
        let t3 = position(rest2, '\t');
        let pattern = if t3 >= 0 { rest2[..t3] } else { rest2 };
        if only.len > 0 && name != only { continue; }

        var compiles = 0;
        let c0 = clock();
        while compiles < 1 || (clock() - c0 < 0.2 && compiles < 1000) {
            let r = regex::compile(pattern);
            compiles++;
        }
        format(out, name, " ", corpus, " compile_us ", (clock() - c0) / compiles * 1.0e6, "\n");

        let re = regex::compile(pattern);
        var n = 0;
        let t = best() { n = regex::count(re, text); };
        format(out, name, " ", corpus, " count ", n, "\n");
        format(out, name, " ", corpus, " count_mbps ", mb / t, "\n");
        if kind == "caps" {
            var sum = 0;
            let tc = best() {
                sum = 0;
                regex::each_captures(re, text) { c => if c.slots[2] >= 0 { sum += c.slots[3] - c.slots[2]; } };
            };
            format(out, name, " ", corpus, " caps_sum ", sum, "\n");
            format(out, name, " ", corpus, " caps_mbps ", mb / tc, "\n");
        }
        write_stdout(out);
        flush_stdout();
        out.clear();
    }
}
