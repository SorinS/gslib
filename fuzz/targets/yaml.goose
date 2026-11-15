// Fuzz target: yaml (encoding/yaml). parse, then for each document check
// and the writer (write, then write_stream of them all, each parsed
// again); then every node of the pool read through the accessors: scalars
// resolved and read as each type, sequences by each_element/element/
// each_item, mappings by their own links and, when the stream has no
// merge key, by each_pair, member and each_member.
//
// Known finding (yaml.goose:2934-2979): each_pair (and member and
// each_member, built on it) loops forever on a merge cycle and takes 2^n
// steps for n stacked merges. A stream with any merge key (yaml::is_merge)
// is not walked through them, so the fuzzer is not stuck on it.

import std;
import gslib from "../..";
import gslib.encoding.yaml;

let MAX_DOCS: i64 = 16;

fn read_node(n: yaml::Node&, merges: bool) {
    let _ = yaml::target(n);
    if n.kind == yaml::SCALAR {
        let _ = yaml::is_null(n);
        let _, _ = yaml::as_i64(n);
        let _, _ = yaml::as_f64(n);
        let _, _ = yaml::as_bool(n);
        let _, _ = yaml::as_string(n);
        let _ = yaml::resolve(n);
        let _ = yaml::scalar_error(n);
        let _ = yaml::resolve_tag(n.value);
        var b: u8[>..] = [];
        let _ = yaml::binary(n, b);
        var r = yaml::reader();
        let _ = yaml::read_int(r, n);
        let _ = yaml::read_uint(r, n);
        let _ = yaml::read_float(r, n);
        let _ = yaml::read_bool(r, n);
        var scratch: u8[>..] = [];
        let _ = yaml::read_string(r, n, scratch);
        let _ = yaml::message(r);
    } else if n.kind == yaml::SEQUENCE {
        yaml::each_element(n) { e => let _ = e.kind; };
        let _ = yaml::element(n, 0);
        let _ = yaml::element(n, n.count - 1);
        var r = yaml::reader();
        yaml::each_item(r, n) { e => let _ = e.kind; };
        let _ = yaml::finish(r);
    } else if n.kind == yaml::MAPPING {
        var k = n.first;
        while k {
            let v = k.next;
            guard v else { break; }
            let _ = yaml::is_merge(k);
            k .= v.next;
        }
        if !merges {
            yaml::each_pair(n) { key, v => let _ = key.value; };
            let _ = yaml::member(n, "a");
            var r = yaml::reader();
            yaml::each_member(r, n) { key, v => let _ = yaml::read_int(r, v); };
            let _ = yaml::finish(r);
        }
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    var doc:     yaml::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let first, err = yaml::parse(data, doc, decoded);
    guard first else { return 0; }

    var merges = false;
    for i in doc.len { if yaml::is_merge(doc[i]) { merges = true; } }

    var d: yaml::Node? = first;
    var docs = 0;
    while d {
        if docs >= MAX_DOCS { break; }
        docs++;
        let _ = yaml::check(d);
        var out: u8[>..] = [];
        let we = yaml::write(out, d);
        if we.message.len == 0 {
            var doc2: yaml::Node[>..] = [];
            var dec2: u8[>..]         = [];
            let _, _ = yaml::parse(out[..], doc2, dec2);
        }
        d .= d.next;
    }
    if err.message.len == 0 {
        var out: u8[>..] = [];
        let _ = yaml::write_stream(out, first);
    }
    for i in doc.len { read_node(doc[i], merges); }
    return 0;
}

fn main() {}
