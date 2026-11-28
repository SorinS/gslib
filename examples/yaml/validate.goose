// validate: what a program should refuse in YAML it is given, and how it
// learns where. parse reports a syntax error with yaml.v3's message and
// the true line and column; check finds what yaml.v3's decoder refuses in
// a well-formed document: repeated keys, a tag the value does not fit,
// bad merges, and the alias bomb ("billion laughs").
//
//   goose examples/yaml/validate.goose

import std;
import os;
import gslib from "../..";
import gslib.encoding.yaml;

var failures = 0;

// What parse and then check say of text: "" when it is fine.
fn verdict(text: const u8[:]) -> u8[>..] {
    var doc:     yaml::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let first, err = yaml::parse(text, doc, decoded);
    if err.message.len > 0 { return str(err.message, " [at ", err.line, ":", err.column, "]"); }
    var d = first;
    while d {
        let e = yaml::check(d);
        if e.message.len > 0 { return str(e.message, " [at ", e.line, ":", e.column, "]"); }
        d .= d.next;
    }
    return str("");
}

fn expect(what: const u8[:], text: const u8[:], want: const u8[:]) {
    let v = verdict(text);
    print(what, ": ", if v.len == 0 { "fine" } else { v[..] });
    if v != want { failures++; print("  expected: ", want); }
}

fn main() {
    expect("good", "a: 1\nb: [x, y]\n", "");

    // Syntax errors. yaml.v3 counts a parser error's line from 0, so its
    // message says line 2 for a fault on line 3; Error.line is the real one.
    expect("bad indentation", "a:\n  b: 1\n c: 2\n", "yaml: line 2: did not find expected key [at 3:2]");
    expect("unclosed flow", "ports: [80, 443\nname: x\n", "yaml: line 1: did not find expected ',' or ']' [at 2:5]");
    expect("tab indentation", "a:\n\tb: 1\n", "yaml: line 2: found character that cannot start any token [at 2:1]");
    expect("unknown alias", "a: *nowhere\n", "yaml: unknown anchor 'nowhere' referenced [at 1:4]");

    // Well-formed, but refused when decoded.
    expect("repeated key", "user: a\nuid: 1\nuser: b\n",
           "yaml: unmarshal errors:\n  line 3: mapping key \"user\" already defined at line 1 [at 3:1]");
    expect("tag that does not fit", "port: !!int eighty\n", "yaml: cannot decode !!str `eighty` as a !!int [at 1:7]");
    expect("bad merge", "a:\n  <<: 1\n", "yaml: map merge requires map or sequence of maps as the value [at 2:7]");

    // The billion laughs: nine levels of nine aliases, 9^9 nodes from a
    // few hundred bytes.
    var bomb: u8[>..] = [];
    bomb.append("a: &a [lol,lol,lol,lol,lol,lol,lol,lol,lol]\n");
    let names = "abcdefghi";
    for i in 1..9 {
        format(bomb, names[i..i + 1], ": &", names[i..i + 1], " [");
        for j in 9 {
            if j > 0 { bomb.push(','); }
            bomb.push('*');
            bomb.push(names[i - 1]);
        }
        bomb.append("]\n");
    }
    let t0 = clock();
    let v = verdict(bomb);
    print("alias bomb (", bomb.len, " bytes): ", v, ", in ", ((clock() - t0) * 1000.0) as! i64, " ms");
    if !v.starts_with("yaml: document contains excessive aliasing") { failures++; }

    guard failures == 0 else { print("validate: ", failures, " unexpected"); exit(1); }
}
