// The yaml package on its own, without Go: the tree and its accessors,
// merges, the core schema, the text of every kind of scalar, tags and
// directives, streams of documents, UTF-16, the errors and where they put
// the fault, the decoder's checks, and reading into the caller's types.
import std;
import yaml from "..";

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

// Parses text, which must have no error, and gives the root of its first
// document to F.
fn with_root<F>(text: const u8[:]) {
    var doc: yaml::Node[>..] = [];
    var decoded: u8[>..] = [];
    let first, err = yaml::parse(text, doc, decoded);
    guard err.message.len == 0 else { print("FAIL parse ", text, ": ", err.message); failures++; return; }
    guard first else { print("FAIL no document in ", text); failures++; return; }
    let root = first.first;
    guard root else { print("FAIL empty document in ", text); failures++; return; }
    F(root);
}

// The error parsing text gives: its message, line and column.
fn error_of(text: const u8[:]) -> yaml::Error {
    var doc: yaml::Node[>..] = [];
    var decoded: u8[>..] = [];
    let first, err = yaml::parse(text, doc, decoded);
    return err;
}

fn error_is(text: const u8[:], message: const u8[:], line: i64, column: i64) {
    let e = error_of(text);
    let ok = e.message == message && e.line == line && e.column == column;
    check(text, ok);
    if !ok { print("  got ", e.message, " at ", e.line, ":", e.column); }
}

// The value of scalar text, read as the only node of a document.
fn scalar_value<F>(text: const u8[:]) {
    with_root(text) { n => F(n.value); };
}

fn tree() {
    with_root("""
        name: goose
        size: 3
        ratio: 0.5
        on: true
        none: ~
        list: [a, b, c]
        nested:
          deep: {x: 1}
        """) { root =>
        check("root is a mapping", root.kind == yaml::MAPPING && root.count == 14);
        let name, named = yaml::as_string(yaml::member(root, "name"));
        check("member name", named && name == "goose");
        let size, sized = yaml::as_i64(yaml::member(root, "size"));
        check("member size", sized && size == 3);
        let ratio, rated = yaml::as_f64(yaml::member(root, "ratio"));
        check("member ratio", rated && ratio == 0.5);
        let on, is_bool = yaml::as_bool(yaml::member(root, "on"));
        check("member on", is_bool && on);
        check("null", yaml::is_null(yaml::member(root, "none")) && !yaml::is_null(yaml::member(root, "size")));
        check("missing", yaml::member(root, "nope") == null && yaml::member(null, "x") == null);
        let b, has_b = yaml::as_string(yaml::element(yaml::member(root, "list"), 1));
        check("element", has_b && b == "b" && yaml::element(yaml::member(root, "list"), 3) == null);
        let x, has_x = yaml::as_i64(yaml::member(yaml::member(yaml::member(root, "nested"), "deep"), "x"));
        check("chained", has_x && x == 1);
        var items: u8[>..] = [];
        yaml::each_element(yaml::member(root, "list")) { e => items.append(e.value); };
        check("each_element", items == "abc");
        var keys: u8[>..] = [];
        yaml::each_pair(root) { k, v => keys.append(k.value); keys.push(' '); };
        check("each_pair", keys == "name size ratio on none list nested ");
        let l = yaml::member(root, "list");
        if l { check("flow style and position", (l.style & yaml::FLOW) != 0 && l.line == 6 && l.column == 7); }
    };
}

fn merges() {
    with_root("""
        base: &base {a: 1, b: 2}
        more: &more {b: 3, c: 4}
        one:
          <<: *base
          a: 9
        two:
          <<: [*more, *base]
          d: 5
        """) { root =>
        let one = yaml::member(root, "one");
        let a, has_a = yaml::as_i64(yaml::member(one, "a"));
        check("own key wins over merge", has_a && a == 9);
        let b, has_b = yaml::as_i64(yaml::member(one, "b"));
        check("merged key", has_b && b == 2);
        var pairs: u8[>..] = [];
        yaml::each_pair(yaml::member(root, "two")) { k, v =>
            let t = yaml::target(v);
            if t { format(pairs, k.value, "=", t.value, " "); }
        };
        check("merge order: own, then each mapping in turn, earlier first", pairs == "d=5 b=3 c=4 a=1 ");
        let e = yaml::check(root);
        check("merges check out", e.message.len == 0);
    };
}

fn schema() {
    // The core schema as yaml.v3 resolves plain scalars.
    let tags = [["~", "!!null"], ["null", "!!null"], ["", "!!null"], ["true", "!!bool"], ["False", "!!bool"],
                ["yes", "!!str"], ["12", "!!int"], ["-0x1F", "!!int"], ["0o17", "!!int"], ["017", "!!int"],
                ["0b101", "!!int"], ["1_000", "!!int"], ["1.5", "!!float"], [".inf", "!!float"], ["-.Inf", "!!float"],
                [".NaN", "!!float"], ["1e3", "!!float"], ["08", "!!float"], ["1e999", "!!str"], ["2001-12-14", "!!timestamp"],
                ["2001-02-29", "!!str"], ["<<", "!!str"], ["0x", "!!str"], ["abc", "!!str"]];
    for t in tags {
        check(str("resolve ", t[0]), yaml::resolve_tag(t[0]) == t[1]);
    }
    with_root("[12, -0x10, 0o17, 9223372036854775808, 1.5, .inf, 2001-12-14t21:59:43.10-05:00, !!float 3, \"12\", !!binary aGk=]") { s =>
        var r: u8[>..] = [];
        yaml::each_element(s) { e =>
            match yaml::resolve(e) {
                Int i => { format(r, "i", i.v, " "); },
                Uint u => { format(r, "u", u.v, " "); },
                Float f => { format(r, "f", f.v, " "); },
                Timestamp t => { r.push('t'); yaml::format_time(r, t.t); r.push(' '); },
                Str => { format(r, "s", e.value, " "); },
                Binary => { var b: u8[>..] = []; yaml::binary(e, b); format(r, "b", b, " "); },
                _ => { r.append("? "); },
            }
        };
        check("resolve values", r == "i12 i-16 i15 u9223372036854775808 f1.5 finf t2001-12-14T21:59:43.1-05:00 f3.0 s12 bhi ");
    };
    with_root("!!int x") { n => check("scalar_error", yaml::scalar_error(n) == "yaml: cannot decode !!str `x` as a !!int"); };
}

fn scalars() {
    scalar_value("'it''s'") { v => check("single quotes", v == "it's"); };
    scalar_value("\"\\t\\x41\\u00e9\\U0001F600\\N\\_\\L\\P\\0\\e\"") { v =>
        check("double-quoted escapes", v == "\tA\xc3\xa9\xf0\x9f\x98\x80\xc2\x85\xc2\xa0\xe2\x80\xa8\xe2\x80\xa9\x00\x1b");
    };
    scalar_value("\"a\\\n   b\"") { v => check("escaped line break", v == "ab"); };
    scalar_value("\"a\n  b\n\n  c\"") { v => check("quoted folding", v == "a b\nc"); };
    scalar_value("a\n  b\n\n  c") { v => check("plain folding", v == "a b\nc"); };
    scalar_value("|\n  a\n   b\n\n") { v => check("literal clips", v == "a\n b\n"); };
    scalar_value("|-\n  a\n\n") { v => check("literal strips", v == "a"); };
    scalar_value("|+\n  a\n\n") { v => check("literal keeps", v == "a\n\n"); };
    scalar_value(">\n  a\n  b\n\n  c\n    d\n  e\n") { v => check("folded", v == "a b\nc\n  d\ne\n"); };
    scalar_value("|2\n   a\n  b\n") { v => check("indentation indicator", v == " a\nb\n"); };
    scalar_value("a\r\n  b\r\n") { v => check("CR LF folds", v == "a b"); };
    with_root("- \"x\"\n- 'y'\n- |\n z\n- plain\n") { s =>
        var styles: u8[>..] = [];
        yaml::each_element(s) { e => format(styles, e.style, " "); };
        check("styles", styles == "2 4 8 0 ");
    };
}

fn tags() {
    with_root("""
        %TAG !e! tag:example.com,2000:app/
        ---
        - !e!foo a
        - !<tag:yaml.org,2002:int> 1
        - !!str 2
        - !local x
        - ! 12
        - !my%20tag y
        """) { s =>
        var t: u8[>..] = [];
        yaml::each_element(s) { e => format(t, e.tag, "|"); };
        check("tags", t == "tag:example.com,2000:app/foo|!!int|!!str|!local|!!int|!my tag|");
        let e0 = yaml::element(s, 0);
        let e4 = yaml::element(s, 4);
        if e0 { if e4 { check("tagged style", (e0.style & yaml::TAGGED) != 0 && (e4.style & yaml::TAGGED) == 0); } }
    };
    error_is("!e!x a", "yaml: found undefined tag handle", 1, 1);
    error_is("%TAG !e! a\n%TAG !e! b\n--- x", "yaml: line 1: found duplicate %TAG directive", 2, 1);
    error_is("%YAML 1.2\n--- a", "yaml: found incompatible YAML document", 1, 1);
}

fn anchors() {
    with_root("a: &x [1, 2]\nb: *x\nc: &x 3\nd: *x\n") { m =>
        let b = yaml::member(m, "b");
        check("alias resolves to its collection", b != null && b.kind == yaml::SEQUENCE && b.count == 2);
        let d, has_d = yaml::as_i64(yaml::member(m, "d"));
        check("an anchor redefined", has_d && d == 3);
        let raw = m.first;
        if raw {
            let v = raw.next;
            if v { check("anchor name", v.anchor == "x"); }
        }
    };
    error_is("x: [1, *y]\n", "yaml: unknown anchor 'y' referenced", 1, 8);
    // A plain << is a merge key; resolved on its own, it is text.
    with_root("<<: {a: 1}") { m =>
        let k = m.first;
        if k { check("merge key tag", k.tag == "!!merge"); }
    };
    with_root("a: &r [1, *r]") { m =>
        let e = yaml::check(m);
        check("anchor that contains itself", e.message == "yaml: anchor 'r' value contains itself" && e.line == 1 && e.column == 11);
    };
}

fn streams() {
    var doc: yaml::Node[>..] = [];
    var decoded: u8[>..] = [];
    let first, err = yaml::parse("- a\n- b\n--- x\n...\n--- [\n", doc, decoded);
    var n = 0;
    var d = first;
    while d { n++; d .= d.next; }
    check("documents before an error", n == 2 && err.message == "yaml: line 5: did not find expected node content" && err.line == 6 && err.column == 1);
    if first { check("first document", first.kind == yaml::DOCUMENT && first.line == 1); }
    var doc2: yaml::Node[>..] = [];
    let none, err2 = yaml::parse("# nothing\n", doc2, decoded);
    check("no documents", none == null && err2.message.len == 0);
    var doc3: yaml::Node[>..] = [];
    let three, err3 = yaml::parse("---\n---\n--- a\n", doc3, decoded);
    var k = 0;
    d .= three;
    while d { k++; d .= d.next; }
    check("empty documents", k == 3 && err3.message.len == 0);
    // A document's anchors carry over, as yaml.v3's do.
    with_root("a: &x 1\n---\nb: *x\n") { m => check("first of two", m.kind == yaml::MAPPING); };
}

fn encodings() {
    scalar_value("\xff\xfeh\x00\xe9\x00") { v => check("UTF-16LE", v == "h\xc3\xa9"); };
    scalar_value("\xfe\xff\x00h\x00\xe9") { v => check("UTF-16BE", v == "h\xc3\xa9"); };
    scalar_value("\xef\xbb\xbfx") { v => check("UTF-8 BOM", v == "x"); };
    error_is("\xff\xfeh\x00\x01\x00", "yaml: control characters are not allowed", 1, 2);
    error_is("a: \xff", "yaml: invalid leading UTF-8 octet", 1, 4);
    error_is("a: 1\nb: x\x01\n", "yaml: control characters are not allowed", 2, 5);
}

fn errors() {
    error_is("a: 1\nb: @x\n", "yaml: line 2: found character that cannot start any token", 2, 4);
    error_is("\xc3\xa9: @x\n", "yaml: found character that cannot start any token", 1, 4);
    // yaml.v3 counts a parser error's line from 0: the problem is on line 3.
    error_is("a:\n  b: 1\n c: 2\n", "yaml: line 2: did not find expected key", 3, 2);
    error_is("a: \"\\q\"", "yaml: found unknown escape character", 1, 5);
    error_is("[1, 2\n", "yaml: line 1: did not find expected ',' or ']'", 2, 1);
    error_is("a: 1\nb\n", "yaml: line 2: could not find expected ':'", 3, 1);
    error_is("a\nb: c\n", "yaml: line 2: mapping values are not allowed in this context", 2, 2);
    error_is("a: b: c\n", "yaml: mapping values are not allowed in this context", 1, 5);
    error_is("|0\n a\n", "yaml: found an indentation indicator equal to 0", 1, 2);
    var deep: u8[>..] = [];
    for i in 10001 { deep.push('['); }
    error_is(deep, "yaml: exceeded max depth of 10000", 1, 10001);
}

fn decoder_checks() {
    with_root("a: 1\nb: 2\na: 3\n") { m =>
        let e = yaml::check(m);
        check("repeated key", e.message == "yaml: unmarshal errors:\n  line 3: mapping key \"a\" already defined at line 1" && e.line == 3);
    };
    with_root("a:\n  <<: 1\n") { m =>
        check("bad merge", yaml::check(m).message == "yaml: map merge requires map or sequence of maps as the value");
    };
    // The billion laughs: 9^9 "lol"s from a few hundred bytes.
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
    with_root(bomb) { m => check("alias bomb", yaml::check(m).message == "yaml: document contains excessive aliasing"); };
    with_root("a: &a [1, 2]\nb: [*a, *a, *a]\n") { m => check("a few aliases are fine", yaml::check(m).message.len == 0); };
}

struct Config { name: u8[..16], port: i64, debug: bool, ratio: f64, tags: i64 }

fn reader() {
    with_root("""
        name: server
        port: 8080
        debug: yes
        ratio: 1
        tags: [a, b]
        extra: ignored
        """) { m =>
        var r = yaml::reader();
        var c = Config { name: "", port: 0, debug: false, ratio: 0.0, tags: 0 };
        var scratch: u8[>..] = [];
        yaml::each_member(r, m) { key, v =>
            if key == "name" { format(c.name, yaml::read_string(r, v, scratch)); }
            else if key == "port" { c.port = yaml::read_int(r, v); }
            else if key == "debug" { c.debug = yaml::read_bool(r, v); }
            else if key == "ratio" { c.ratio = yaml::read_float(r, v); }
            else if key == "tags" { yaml::each_item(r, v) { it => c.tags++; }; }
        };
        check("read into a struct", yaml::finish(r) && c.name == "server" && c.port == 8080 && c.debug && c.ratio == 1.0 && c.tags == 2);
    };
    with_root("port: x\ncount: [1]\nok: 3\n") { m =>
        var r = yaml::reader();
        var total = 0;
        yaml::each_member(r, m) { key, v => total += yaml::read_int(r, v); };
        check("read errors, all of them", !yaml::finish(r) && total == 3
              && yaml::message(r) == "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `x` into int64\n  line 2: cannot unmarshal !!seq into int64");
    };
}

fn main() {
    tree();
    merges();
    schema();
    scalars();
    tags();
    anchors();
    streams();
    encodings();
    errors();
    decoder_checks();
    reader();
    print("unit: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
