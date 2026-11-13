// read_config: reads a service's configuration with the tree accessors:
// member by key, element by index, each_element and each_pair, the as_
// readers, and a merge key (<<) sharing defaults between two sections.
// Without FILE it reads the configuration below; a lookup that misses
// gives null, so lookups chain and a default can stand in.
//
//   goose examples/yaml/read_config.goose [-- FILE]

import std;
import os;
import gslib from "../..";
import gslib.encoding.yaml;

let SAMPLE = """
    # a service and its two backends
    service:
      name: inventory
      port: 8080
      debug: false
      timeout: 2.5
    defaults: &defaults
      retries: 3
      tls: true
    backends:
      - name: primary
        host: db1.example.com
        <<: *defaults
      - name: replica
        host: db2.example.com
        retries: 5          # its own value wins over the merged one
        <<: *defaults
    allowed: [127.0.0.1, 192.0.2.0/24]
    """;

fn main() {
    let a = args();
    var text: u8[>..] = [];
    if a.len > 1 {
        guard read_file(a[1], text) else { print("read_config: cannot read ", a[1]); exit(1); }
    } else {
        text.append(SAMPLE);
    }

    var doc:     yaml::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let first, err = yaml::parse(text, doc, decoded);
    guard err.message.len == 0 else { print("read_config: ", err.message, " (", err.line, ":", err.column, ")"); exit(1); }
    guard first else { print("read_config: no document"); exit(1); }
    let root = first.first;

    let svc = yaml::member(root, "service");
    let name, okn = yaml::as_string(yaml::member(svc, "name"));
    var port, okp = yaml::as_i64(yaml::member(svc, "port"));
    if !okp { port = 80; }                          // absent or not a number
    let debug, okd = yaml::as_bool(yaml::member(svc, "debug"));
    let timeout, okt = yaml::as_f64(yaml::member(svc, "timeout"));
    print("service ", name, " on port ", port, ", debug ", debug, ", timeout ", timeout, "s");

    // A sequence of mappings, each with the defaults merged in.
    var retries = 0;
    yaml::each_element(yaml::member(root, "backends")) { b =>
        let host, okh = yaml::as_string(yaml::member(b, "host"));
        let r, okr = yaml::as_i64(yaml::member(b, "retries"));
        let tls, okl = yaml::as_bool(yaml::member(b, "tls"));
        print("  backend ", host, ": retries ", r, ", tls ", tls);
        retries += r;
    };

    // Every pair of a mapping, in order, merged pairs after its own.
    var keys: u8[>..] = [];
    yaml::each_pair(yaml::element(yaml::member(root, "backends"), 0)) { k, v => format(keys, k.value, " "); };
    print("  first backend's keys: ", keys);

    let net, okw = yaml::as_string(yaml::element(yaml::member(root, "allowed"), 1));
    let missing = yaml::member(yaml::member(root, "nowhere"), "deeper");
    print("allowed[1] ", net, "; a missing key is null: ", yaml::is_null(missing));

    // The sample's answers, so that a run is also a test.
    if a.len <= 1 {
        guard okn && name == "inventory" && port == 8080 && okd && !debug && okt && timeout == 2.5
              && retries == 8 && keys == "name host retries tls " && net == "192.0.2.0/24" && missing == null
        else { print("read_config: wrong values"); exit(1); }
    }
}
