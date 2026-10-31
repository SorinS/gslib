// yaml against gopkg.in/yaml.v3 (test/vectors/goyaml.txt, from
// tools/goyaml.sh -corpus test/corpus.txt): every case read here into the
// same dump yaml.v3 gives, byte for byte: each node's kind, line and
// column, tag, style, anchor and value, the value decoded, each document
// checked as yaml.v3's decoder checks it, or the same error.
import std;
import os;
import yaml from "..";

var failures = 0;
var checks = 0;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// A gen line's input: pieces "hex" or "hex*count".
fn expand(spec: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    each_word(spec) {
        let star = find(it, "*");
        var n = 1;
        var h = it;
        if star >= 0 {
            h = it[..star];
            let c, ok = parse_int(it[star + 1..]);
            assert(ok);
            n = c;
        }
        let unit = unhex(h);
        for i in n { out.append(unit); }
    };
    return out;
}

// s quoted as tools/goyaml quotes it: bytes outside printable ASCII, '"'
// and '\' as \xHH.
fn quote(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    for c in s {
        if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
            out.append("\\x");
            format_uint(out, c, 16, 2, '0');
        } else {
            out.push(c);
        }
    }
    out.push('"');
}

fn style_name(out: u8[>..]&, style: u8) {
    var n = 0;
    let names = ["tagged", "double", "single", "literal", "folded", "flow"];
    for name, i in names {
        if (style & ((1 as u8) << i)) != 0 {
            if n > 0 { out.push('|'); }
            out.append(name);
            n++;
        }
    }
    if n == 0 { out.push('-'); }
}

fn kind_name(k: u8) -> const u8[:] {
    if k == yaml::DOCUMENT { return "doc"; }
    if k == yaml::SEQUENCE { return "seq"; }
    if k == yaml::MAPPING { return "map"; }
    if k == yaml::SCALAR { return "scalar"; }
    return "alias";
}

fn resolved(out: u8[>..]&, n: yaml::Node&) {
    let e = yaml::scalar_error(n);
    if e.len > 0 {
        out.append("error ");
        quote(out, e);
        return;
    }
    match yaml::resolve(n) {
        Null => { out.append("null"); },
        Bool b => { format(out, "bool ", b.v); },
        Int i => { format(out, "int ", i.v); },
        Uint u => { format(out, "uint ", u.v); },
        Float f => {
            out.append("float ");
            if f.v != f.v { out.append("nan"); } else { format_uint(out, float_text::bits_of(f.v), 16, 16, '0'); }
        },
        Timestamp t => {
            out.append("timestamp ");
            yaml::format_time(out, t.t);
        },
        Binary => {
            var b: u8[>..] = [];
            yaml::binary(n, b);
            if b == n.value { out.append("str"); } else { out.append("str "); quote(out, b); }
        },
        _ => { out.append("str"); },
    }
}

// A Reader's error as tools/goyaml prints it: one of a TypeError without
// its heading, or the error that stopped the walk.
fn read_error(out: u8[>..]&, r: yaml::Reader&) {
    out.push('!');
    if r.fatal { quote(out, r.errors); } else { quote(out, r.errors[2..]); }
}

// What reading n gives into an int64, a uint64, a float64, a bool and a
// string.
fn typed(out: u8[>..]&, n: yaml::Node&) {
    var r = yaml::reader();
    let i = yaml::read_int(r, n);
    out.append("i=");
    if yaml::finish(r) { format(out, i); } else { read_error(out, r); }
    r = yaml::reader();
    let u = yaml::read_uint(r, n);
    out.append(" u=");
    if yaml::finish(r) { format(out, u); } else { read_error(out, r); }
    r = yaml::reader();
    let f = yaml::read_float(r, n);
    out.append(" f=");
    if yaml::finish(r) {
        if f != f { out.append("nan"); } else { format_uint(out, float_text::bits_of(f), 16, 16, '0'); }
    } else {
        read_error(out, r);
    }
    r = yaml::reader();
    let b = yaml::read_bool(r, n);
    out.append(" b=");
    if yaml::finish(r) { format(out, b); } else { read_error(out, r); }
    var scratch: u8[>..] = [];
    r = yaml::reader();
    let s = yaml::read_string(r, n, scratch);
    out.append(" s=");
    if yaml::finish(r) { quote(out, s); } else { read_error(out, r); }
}

// The dump of node n and the nodes under it, depth levels in.
fn dump_node(out: u8[>..]&, root: yaml::Node&) {
    // The nodes still to write, with their depths, deepest last.
    var todo: (yaml::Node&)[>..<] = [];
    var depths: i64[>..<] = [];
    todo.push(&root);
    depths.push(0);
    while todo.len > 0 {
        let n .= todo[todo.len - 1];
        let depth = depths[depths.len - 1];
        todo.pop();
        depths.pop();
        if n.kind == yaml::DOCUMENT {
            format(out, depth, " doc ", n.line, ":", n.column, "\n");
        } else {
            format(out, depth, " ", kind_name(n.kind), " ", n.line, ":", n.column, " tag=");
            quote(out, n.tag);
            out.append(" style=");
            style_name(out, n.style);
            if n.anchor.len > 0 {
                out.append(" anchor=");
                quote(out, n.anchor);
            }
            if n.kind == yaml::SCALAR {
                out.append(" value=");
                quote(out, n.value);
                out.append(" => ");
                resolved(out, n);
                format(out, "\n", depth, " as ");
                typed(out, n);
            } else if n.kind == yaml::ALIAS {
                out.append(" value=");
                quote(out, n.value);
                let a = n.alias;
                if a { format(out, " -> ", a.line, ":", a.column); }
            }
            out.push('\n');
        }
        // The children, last first, so that the first comes off first.
        let mark = todo.len;
        var c = n.first;
        while c {
            todo.push(&c);
            depths.push(depth + 1);
            c .= c.next;
        }
        reverse(todo[mark..]);
    }
}

// 64-bit FNV-1a.
fn fnv64(s: const u8[:]) -> u64 {
    var h: u64 = 0xcbf29ce484222325;
    for c in s {
        h ^= c;
        h *= 0x100000001b3;
    }
    return h;
}

// A dump as a vector keeps it: the first 100 lines, then for a longer one
// "more", how many lines follow, and the hash of the whole dump.
fn vector_form(d: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var lines = 0;
    var cut = d.len;
    for c, i in d {
        if c == '\n' {
            lines++;
            if lines == 100 { cut = i + 1; }
        }
    }
    if lines <= 100 {
        out.append(d);
        return out;
    }
    out.append(d[..cut]);
    format(out, "more ", lines - 100, " ");
    format_uint(out, fnv64(d), 16, 16, '0');
    out.push('\n');
    return out;
}

// The dump of text's documents, as tools/goyaml writes it.
fn dump(text: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var doc: yaml::Node[>..] = [];
    var decoded: u8[>..] = [];
    let first, err = yaml::parse(text, doc, decoded);
    var ndocs = 0;
    var d = first;
    while d {
        dump_node(out, d);
        let e = yaml::check(d);
        if e.message.len > 0 {
            out.append("decode error ");
            quote(out, e.message);
            out.push('\n');
        } else {
            out.append("decode ok\n");
        }
        var text: u8[>..] = [];
        let w = yaml::write(text, d);
        if w.message.len > 0 {
            out.append("marshal error ");
            quote(out, w.message);
        } else {
            out.append("marshal ");
            quote(out, text);
        }
        out.push('\n');
        ndocs++;
        d .= d.next;
    }
    if ndocs > 1 && err.message.len == 0 {
        if first {
            var text: u8[>..] = [];
            let w = yaml::write_stream(text, first);
            if w.message.len > 0 {
                out.append("stream error ");
                quote(out, w.message);
            } else {
                out.append("stream ");
                quote(out, text);
            }
            out.push('\n');
        }
    }
    if err.message.len > 0 {
        out.append("error ");
        quote(out, err.message);
        out.push('\n');
    }
    return out;
}

fn main() {
    var data: u8[>..] = [];
    guard read_file("vectors/goyaml.txt", data) else { abort("cannot read test/vectors/goyaml.txt"); }
    var name: u8[>..] = [];
    var input: u8[>..] = [];
    var want: u8[>..] = [];
    var cases = 0;
    var in_case = false;
    each_split(data, '\n') {
        if !in_case {
            if starts_with(it, "case ") {
                name.clear();
                name.append(it[5..]);
                in_case = true;
                want.clear();
                input.clear();
            }
        } else if starts_with(it, "input ") && input.len == 0 && want.len == 0 {
            input.append(unhex(it[6..]));
        } else if starts_with(it, "gen ") && input.len == 0 && want.len == 0 {
            input.append(expand(it[4..]));
        } else if it == "end" {
            in_case = false;
            cases++;
            checks++;
            let got = vector_form(dump(input));
            if got != want {
                failures++;
                print("FAIL ", name);
                if failures <= 20 { print("  want:\n", want, "  got:\n", got); }
            }
        } else {
            want.append(it);
            want.push('\n');
        }
    };
    print("vectors: ", cases, " cases, ", failures, " failed");
    if failures > 0 { exit(1); }
}
