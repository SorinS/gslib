// core_schema: what a scalar means. resolve gives a scalar's value as
// yaml.v3 decodes it into an interface{}: null, bool, int (Uint above
// i64), float, timestamp, string or binary; quoting or a !!str tag makes
// anything text. resolve_tag names the tag a plain scalar resolves to,
// format_time writes a timestamp as Go's RFC 3339, binary decodes
// !!binary, and scalar_error says why a tag does not fit its text.
//
//   goose examples/yaml/core_schema.goose

import std;
import gslib from "../..";
import gslib.encoding.yaml;

let TEXT = """
    - ~
    - yes
    - true
    - 0x1F
    - 0o17
    - 1_000
    - 18446744073709551615
    - 6.02e23
    - -.inf
    - 2001-12-14t21:59:43.10-05:00
    - "12"
    - !!str 3.0
    - !!binary aGVsbG8sIHdvcmxk
    - |
      two
      lines
    """;

fn main() {
    var doc:     yaml::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let first, err = yaml::parse(TEXT, doc, decoded);
    guard first && err.message.len == 0 else { print("core_schema: ", err.message); exit(1); }

    var summary: u8[>..] = [];
    yaml::each_element(first.first) { e =>
        var what: u8[>..] = [];
        match yaml::resolve(e) {
            Null => { what.append("null"); },
            Bool b => { format(what, "bool ", b.v); },
            Int i => { format(what, "int ", i.v); },
            Uint u => { format(what, "uint ", u.v); },
            Float f => { format(what, "float ", f.v); },
            Timestamp t => { what.append("time "); yaml::format_time(what, t.t); },
            Str => { format(what, "string \"", e.value, "\""); },
            Binary => {
                var b: u8[>..] = [];
                yaml::binary(e, b);
                format(what, "binary ", b.len, " bytes \"", b, "\"");
            },
            Invalid => { what.append("invalid"); },
        }
        print(e.tag, "\t", what);
        format(summary, what, "|");
    };
    let want = str("null|string \"yes\"|bool true|int 31|int 15|int 1000|uint 18446744073709551615|float 6.02e+23|float -inf|",
                   "time 2001-12-14T21:59:43.1-05:00|string \"12\"|string \"3.0\"|binary 12 bytes \"hello, world\"|string \"two\nlines\"|");
    guard summary == want else { print("core_schema: got ", summary); exit(1); }

    // The tag of plain text, without parsing a document.
    for t in ["null", "False", "017", "0b101", "1e3", "08", "2001-12-14", "1e999", "<<"] {
        print("resolve_tag(", t, ") = ", yaml::resolve_tag(t));
    }
    guard yaml::resolve_tag("08") == "!!float" && yaml::resolve_tag("1e999") == "!!str" else { exit(1); }

    // A tag the text does not fit: resolve says Invalid, scalar_error why.
    var doc2: yaml::Node[>..] = [];
    let bad, err2 = yaml::parse("!!int x", doc2, decoded);
    guard bad else { exit(1); }
    let n = bad.first;
    guard n else { exit(1); }
    print(yaml::scalar_error(n));
    guard yaml::scalar_error(n) == "yaml: cannot decode !!str `x` as a !!int" else { exit(1); }
}
