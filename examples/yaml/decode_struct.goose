// decode_struct: reads YAML into the program's own structs with a Reader,
// as yaml.v3's Unmarshal reads into Go structs: each field converted as
// its type asks (an integer from a float, a bool from yes or off, a string
// from any scalar), unknown keys passed over, and a value that does not
// convert recorded with its line while the walk goes on.
//
//   goose examples/yaml/decode_struct.goose

import std;
import gslib from "../..";
import gslib.encoding.yaml;

// Fixed-capacity text fields: only a struct's last field may grow.
struct User { name: u8[..32], uid: i64, admin: bool, groups: u8[..64] }

struct Config { version: i64, ratio: f64, max_size: u64, users: User[>..] }

let GOOD = """
    version: 2
    ratio: 0.75
    max_size: 18446744073709551615
    comment: not a field, passed over
    users:
      - name: alice
        uid: 1000
        admin: yes
        groups: [wheel, staff]
      - name: bob
        uid: 1001.0
        groups: [staff]
    """;

let BAD = """
    version: two
    ratio: 0.5
    users:
      - name: carol
        uid: [1002]
        admin: maybe
    """;

fn decode(text: const u8[:], c: Config&) -> bool, u8[>..] {
    var doc:     yaml::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let first, err = yaml::parse(text, doc, decoded);
    guard err.message.len == 0 else { return false, copy(err.message); }
    guard first else { return false, str("no document"); }
    var r = yaml::reader();
    var scratch: u8[>..] = [];
    yaml::each_member(r, first.first) { key, v =>
        if key == "version" { c.version = yaml::read_int(r, v); }
        else if key == "ratio" { c.ratio = yaml::read_float(r, v); }
        else if key == "max_size" { c.max_size = yaml::read_uint(r, v); }
        else if key == "users" {
            yaml::each_item(r, v, "[]main.User") { item =>
                var u = User { name: "", uid: 0, admin: false, groups: "" };
                yaml::each_member(r, item, "main.User") { k, f =>
                    if k == "name" { format(u.name, yaml::read_string(r, f, scratch)); }
                    else if k == "uid" { u.uid = yaml::read_int(r, f); }
                    else if k == "admin" { u.admin = yaml::read_bool(r, f); }
                    else if k == "groups" {
                        yaml::each_item(r, f, "[]string") { g => format(u.groups, yaml::read_string(r, g, scratch), " "); };
                    }
                };
                c.users.push(u);
            };
        }
    };
    if !yaml::finish(r) { return false, yaml::message(r); }
    return true, str("");
}

fn main() {
    var c = Config { version: 0, ratio: 0.0, max_size: 0, users: [] };
    let ok, msg = decode(GOOD, c);
    guard ok else { print("decode_struct: ", msg); exit(1); }
    print("version ", c.version, ", ratio ", c.ratio, ", max_size ", c.max_size);
    for u in c.users {
        print("  ", u.name, " uid ", u.uid, ", admin ", u.admin, ", groups ", u.groups);
    }
    guard c.version == 2 && c.ratio == 0.75 && c.max_size == 0xFFFFFFFFFFFFFFFF && c.users.len == 2
          && c.users[0].name == "alice" && c.users[0].admin && c.users[0].groups == "wheel staff "
          && c.users[1].uid == 1001 && !c.users[1].admin
    else { print("decode_struct: wrong values"); exit(1); }

    // Every field that does not convert, each with its line, as yaml.v3
    // reports them; the fields that do convert are still read.
    var d = Config { version: 0, ratio: 0.0, max_size: 0, users: [] };
    let ok2, msg2 = decode(BAD, d);
    print(msg2);
    guard !ok2 && d.ratio == 0.5 && d.users.len == 1 && d.users[0].name == "carol"
          && msg2 == "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `two` into int64\n  line 5: cannot unmarshal !!seq into int64\n  line 6: cannot unmarshal !!str `maybe` into bool"
    else { print("decode_struct: the errors were not reported as expected"); exit(1); }
}
