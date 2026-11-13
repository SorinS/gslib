// write_yaml: makes YAML three ways. A tree built by hand with node and
// add, written as yaml.Marshal writes it (4-space indentation, quoting
// where text would read as something else, flow where asked); a document
// read, changed and written back; and a stream of two documents with
// write_stream, as a yaml.Encoder writes them.
//
//   goose examples/yaml/write_yaml.goose

import std;
import gslib from "../..";
import gslib.encoding.yaml;

fn scalar(pool: yaml::Node[>..]&, parent: yaml::Node&, value: const u8[:], tag: const u8[:] = "") {
    yaml::add(parent, pool.push(yaml::node(yaml::SCALAR, value, tag)));
}

fn main() {
    // Build: a mapping with text, a number kept as text, a multi-line
    // value, a block sequence and a flow one.
    var pool: yaml::Node[>..] = [];
    let d .= pool.push(yaml::node(yaml::DOCUMENT));
    let m .= pool.push(yaml::node(yaml::MAPPING));
    yaml::add(d, m);
    scalar(pool, m, "name");
    scalar(pool, m, "inventory");
    scalar(pool, m, "version");
    scalar(pool, m, "1.10", "!!str");             // text, not the float 1.1
    scalar(pool, m, "enabled");
    scalar(pool, m, "true");                      // resolves to a bool: plain
    scalar(pool, m, "motd");
    scalar(pool, m, "Welcome.\nBe nice.");
    scalar(pool, m, "hosts");
    let hosts .= pool.push(yaml::node(yaml::SEQUENCE));
    yaml::add(m, hosts);
    scalar(pool, hosts, "a.example.com");
    scalar(pool, hosts, "b.example.com");
    scalar(pool, m, "ports");
    let ports .= pool.push(yaml::node(yaml::SEQUENCE));
    ports.style = yaml::FLOW;
    yaml::add(m, ports);
    scalar(pool, ports, "80");
    scalar(pool, ports, "443");

    var out: u8[>..] = [];
    let e = yaml::write(out, d);
    guard e.message.len == 0 else { print("write_yaml: ", e.message); exit(1); }
    print(out);
    // A raw string ends without a newline; the writer ends with one.
    let want = """
        name: inventory
        version: "1.10"
        enabled: true
        motd: |-
            Welcome.
            Be nice.
        hosts:
            - a.example.com
            - b.example.com
        ports: [80, 443]
        """;
    guard out == str(want, "\n") else { print("write_yaml: not what yaml.Marshal writes"); exit(1); }

    // Read what was written, change a value, write it again.
    var doc:     yaml::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let first, err = yaml::parse(out, doc, decoded);
    guard first && err.message.len == 0 else { print("write_yaml: cannot read back: ", err.message); exit(1); }
    let motd, okm = yaml::as_string(yaml::member(first.first, "motd"));
    guard okm && motd == "Welcome.\nBe nice." else { print("write_yaml: motd changed"); exit(1); }
    let name = yaml::member(first.first, "name");
    guard name else { exit(1); }
    name.value = "inventory-v2";
    var again: u8[>..] = [];
    yaml::write(again, first);
    guard again.len > 0 && again[..30] == "name: inventory-v2\nversion: \"1" else { print("write_yaml: the edit was lost"); exit(1); }

    // A stream: each document after a ---.
    var docs: yaml::Node[>..] = [];
    var dec2: u8[>..]         = [];
    let s, err2 = yaml::parse("a: 1\n---\n[x, y]\n", docs, dec2);
    guard s && err2.message.len == 0 else { exit(1); }
    var stream: u8[>..] = [];
    yaml::write_stream(stream, s);
    print(stream);
    guard stream == "a: 1\n---\n[x, y]\n" else { print("write_yaml: the stream changed"); exit(1); }
}
