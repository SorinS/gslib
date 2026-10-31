// The writer on trees built by hand, as yaml.v3's Marshal writes the same
// trees of yaml.Node (the expected texts are its output): the tags it
// leaves out, the quoting it chooses, !!binary for text that is not
// UTF-8, flow and empty collections, complex keys, aliases, block scalars,
// and the trees it refuses. This program never parses, so it also shows
// that writing alone compiles.
import std;
import yaml from "..";

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn written(what: const u8[:], n: yaml::Node&, want: const u8[:]) {
    var out: u8[>..] = [];
    let e = yaml::write(out, n);
    let ok = e.message.len == 0 && out == want;
    check(what, ok);
    if !ok { print("  got ", e.message, " [", out, "]"); }
}

fn refused(what: const u8[:], n: yaml::Node&, message: const u8[:]) {
    var out: u8[>..] = [];
    let e = yaml::write(out, n);
    check(what, e.message == message);
    if e.message != message { print("  got ", e.message, " [", out, "]"); }
}

fn scalar(doc: yaml::Node[>..]&, parent: yaml::Node&, value: const u8[:], tag: const u8[:] = "") {
    yaml::add(parent, doc.push(yaml::node(yaml::SCALAR, value, tag)));
}

fn config() {
    var doc: yaml::Node[>..] = [];
    let d .= doc.push(yaml::node(yaml::DOCUMENT));
    let m .= doc.push(yaml::node(yaml::MAPPING));
    yaml::add(d, m);
    scalar(doc, m, "name");
    scalar(doc, m, "goose");
    scalar(doc, m, "port");
    scalar(doc, m, "8080", "!!str");
    scalar(doc, m, "bytes");
    scalar(doc, m, "\xff\xfe");
    scalar(doc, m, "text");
    scalar(doc, m, "two\nlines");
    scalar(doc, m, "list");
    let s .= doc.push(yaml::node(yaml::SEQUENCE));
    yaml::add(m, s);
    scalar(doc, s, "true");
    scalar(doc, s, "");
    written("config", d, "name: goose\nport: \"8080\"\nbytes: !!binary //4=\ntext: |-\n    two\n    lines\nlist:\n    - true\n    -\n");
}

fn refusals() {
    var doc: yaml::Node[>..] = [];
    let b .= doc.push(yaml::node(yaml::SCALAR, "x"));
    b.anchor = "a b";
    refused("bad anchor", b, "yaml: anchor value must contain alphanumerical characters only");
    let bin .= doc.push(yaml::node(yaml::SCALAR, "\xff", "!!binary"));
    refused("binary that is not base64", bin, "yaml: explicitly tagged !!binary data must be base64-encoded");
    let i .= doc.push(yaml::node(yaml::SCALAR, "\xff", "!!int"));
    refused("bad UTF-8 with a tag", i, "yaml: cannot marshal invalid UTF-8 data as !!int");
}

fn collections() {
    var doc: yaml::Node[>..] = [];
    let f .= doc.push(yaml::node(yaml::SEQUENCE));
    f.style = yaml::FLOW;
    scalar(doc, f, "a");
    let m .= doc.push(yaml::node(yaml::MAPPING));
    yaml::add(f, m);
    scalar(doc, m, "k");
    scalar(doc, m, "v");
    yaml::add(f, doc.push(yaml::node(yaml::SEQUENCE)));
    written("flow", f, "[a, {k: v}, []]\n");
    let e .= doc.push(yaml::node(yaml::MAPPING));
    scalar(doc, e, "a");
    yaml::add(e, doc.push(yaml::node(yaml::MAPPING)));
    scalar(doc, e, "b");
    yaml::add(e, doc.push(yaml::node(yaml::SEQUENCE)));
    written("empty collections", e, "a: {}\nb: []\n");
    let k .= doc.push(yaml::node(yaml::MAPPING));
    let km .= doc.push(yaml::node(yaml::MAPPING));
    yaml::add(k, km);
    scalar(doc, km, "a");
    scalar(doc, km, "b");
    scalar(doc, k, "v");
    let ks .= doc.push(yaml::node(yaml::SEQUENCE));
    yaml::add(k, ks);
    scalar(doc, ks, "1");
    scalar(doc, k, "w");
    written("complex keys", k, "?   a: b\n: v\n?   - 1\n: w\n");
    let a .= doc.push(yaml::node(yaml::SEQUENCE));
    let x .= doc.push(yaml::node(yaml::SCALAR, "x"));
    x.anchor = "a";
    yaml::add(a, x);
    let al .= doc.push(yaml::node(yaml::ALIAS, "a"));
    al.alias .= x;
    yaml::add(a, al);
    written("aliases", a, "- &a x\n- *a\n");
}

fn scalars() {
    var doc: yaml::Node[>..] = [];
    let q .= doc.push(yaml::node(yaml::SEQUENCE));
    scalar(doc, q, "", "!!str");
    scalar(doc, q, "123", "!!str");
    scalar(doc, q, "true", "!!str");
    scalar(doc, q, "~", "!!str");
    scalar(doc, q, " lead");
    scalar(doc, q, "a: b");
    scalar(doc, q, "- x");
    scalar(doc, q, "#c");
    scalar(doc, q, "it's");
    scalar(doc, q, "tab\there");
    scalar(doc, q, "\x1b");
    scalar(doc, q, "\xc3\xa9t\xc3\xa9");
    scalar(doc, q, "trail ");
    written("quoting", q, "- \"\"\n- \"123\"\n- \"true\"\n- \"~\"\n- ' lead'\n- 'a: b'\n- '- x'\n- '#c'\n- it's\n- \"tab\\there\"\n- \"\\e\"\n- \xc3\xa9t\xc3\xa9\n- 'trail '\n");
    let t .= doc.push(yaml::node(yaml::SEQUENCE));
    scalar(doc, t, "x", "!local");
    scalar(doc, t, "y", "tag:example.com,2000:t");
    scalar(doc, t, "1", "!!int");
    scalar(doc, t, "z", "!!int");
    scalar(doc, t, "a b", "!e%");
    written("tags", t, "- !local x\n- !<tag:example.com,2000:t> y\n- 1\n- !!int z\n- !e%25 a b\n");
    let b .= doc.push(yaml::node(yaml::SEQUENCE));
    let f .= doc.push(yaml::node(yaml::SCALAR, "a b\nc\n"));
    f.style = yaml::FOLDED;
    yaml::add(b, f);
    let l .= doc.push(yaml::node(yaml::SCALAR, "x\n\n"));
    l.style = yaml::LITERAL;
    yaml::add(b, l);
    let s .= doc.push(yaml::node(yaml::SCALAR, "q"));
    s.style = yaml::SINGLE_QUOTED;
    yaml::add(b, s);
    written("block scalars", b, "- >\n  a b\n\n  c\n\n- |+\n  x\n\n- 'q'\n");
}

fn main() {
    config();
    refusals();
    collections();
    scalars();
    print("write: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
