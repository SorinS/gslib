# yaml

YAML 1.2 for the Goose language, read and written as Go's
[gopkg.in/yaml.v3](https://github.com/go-yaml/yaml/tree/v3.0.1) (v3.0.1)
reads and writes it, in the shape of the standard library's `json`: a
parser that builds a document tree in one pool, a reader that walks the
tree into the caller's own types, and a writer that appends to a byte
builder. The parser is libyaml's scanner and parser as yaml.v3 carries
them, and yaml.v3's composer, ported, so that every stream reads as it
reads in yaml.v3, and every stream yaml.v3 refuses is refused with the
same message, and with the line and column of the fault besides. No other
package is needed.

- **The tree**: `parse(text, doc, decoded)` pushes a node for every
  document, collection, scalar and alias onto `doc`, in text order, and
  returns the first document (the others follow it by `next`) and an
  `Error`. A `Node` has its kind (`DOCUMENT`, `SEQUENCE`, `MAPPING`,
  `SCALAR`, `ALIAS`), its style bits (`TAGGED`, `DOUBLE_QUOTED`,
  `SINGLE_QUOTED`, `LITERAL`, `FOLDED`, `FLOW`), its line and column, its
  tag (yaml.v3's: `!!str` for `tag:yaml.org,2002:str`, and for a node
  written without one the tag the core schema resolves it to), its value,
  its anchor, its first child and next sibling (a mapping's children are
  its keys and values in turn), and for an alias the node it names. Tags
  and scalars that had to be put together (folded, unescaped, prefixed)
  are slices of `decoded`; anchors are slices of the text.
- **Block and flow collections, every scalar**: plain, single- and
  double-quoted (every escape, line folding), literal and folded block
  scalars with chomping and indentation indicators; complex keys (`?`);
  comments; streams of documents (`---`, `...`); `%YAML` and `%TAG`;
  anchors and aliases; tags with `!`, `!!`, `%TAG` handles, `%`-escapes
  and `!<verbatim>`; UTF-8 and UTF-16 either way round, with or without a
  byte order mark; CR, LF, CR LF, NEL, LS and PS line breaks.
- **The core schema**: `resolve(n)` is a scalar's value as yaml.v3 decodes
  it into an `interface{}`: `Null`, `Bool`, `Int`, `Uint` (above `i64`),
  `Float` (`.inf`, `.nan`), `Timestamp`, `Str`, `Binary` (`binary(n,
  out)` decodes it), or `Invalid` for a tag the text does not fit
  (`scalar_error(n)` says why); `resolve_tag(text)` is the tag of a plain
  scalar. Integers in decimal, `0x`, `0o`, `0b`, the old octal `017`, with
  signs and `_`; floats as yaml.v3's pattern has them; yaml.v3's four
  timestamp layouts, `format_time` writing one as Go's RFC 3339 does.
- **Accessors**: `member(n, key)` (a mapping's value by key, merges
  included), `element(n, i)`, `each_pair` and `each_element` (blocks over
  a mapping's pairs and a sequence's elements), `target` (past aliases),
  `is_null`, `as_i64`, `as_f64`, `as_bool`, `as_string`. All accept a null
  node, so lookups chain. A merge (`<<`) gives a mapping the pairs of the
  mappings it names after its own, the earlier of two that share a key
  winning, as yaml.v3 decodes it.
- **`check(d)`**: what yaml.v3's decoder refuses in a document it reads
  into an `interface{}`, with its message: a scalar its tag does not fit,
  `!!binary` that is not base64, an alias whose anchor contains it, a
  mapping whose keys repeat (every pair of them, line by line), a merge of
  something other than mappings, a collection as a key, and the alias bomb
  ("billion laughs"), by yaml.v3's own count of nodes decoded inside
  aliases against nodes decoded.
- **`Reader`**: `read_int`, `read_uint`, `read_float`, `read_bool` and
  `read_string` read a node into an `i64`, `u64`, `f64`, `bool` or string
  with the conversions yaml.v3 makes for a field of that type (a float
  into an integer, `yes` and `off` into a bool, any scalar into a string,
  null into the zero value); `each_member` and `each_item` walk a mapping
  and a sequence. A node that does not convert is recorded, as yaml.v3's
  type errors are, and the walk goes on; `finish(r)` says whether there
  were any and `message(r)` gives them as yaml.v3 does ("yaml: unmarshal
  errors:" and a line each).
- **Writing**: `write(out, n)` appends node `n` as yaml.v3's `Marshal(&n)`
  writes it (4-space indentation, flow where the node was flow, a tag left
  out where the node resolves to it anyway, quoting where a string would
  read as something else, text that is not UTF-8 as `!!binary` base64);
  `write_stream` appends a stream of documents as a yaml.v3 `Encoder`
  does. `node(kind, value, tag)` and `add(parent, child)` build a tree to
  write.

```goose
import yaml from "../yamlgoose.git";

var doc: yaml::Node[>..] = [];
var decoded: u8[>..] = [];
let first, err = yaml::parse(text, doc, decoded);
guard first else { abort(err.message); }    // "yaml: line 3: did not find expected key", err.line, err.column
let root = first.first;
let port, ok = yaml::as_i64(yaml::member(root, "port"));
yaml::each_element(yaml::member(root, "hosts")) { h => print(h.value); };
let bad = yaml::check(first);               // repeated keys, alias bombs, bad merges
var out: u8[>..] = [];
yaml::write(out, first);                    // as yaml.Marshal writes it
```

An `Error` has the message as yaml.v3 words it, line number and all, and
the line and column, from 1, of the character, token or node at fault;
the column counts characters, not bytes. yaml.v3 counts a parser error's
line from 0 ("yaml: line 2: did not find expected key" for a fault on
line 3), and gives no line for a reader error or for some scanner errors;
`Error.line` is always the real one. When a stream fails, `parse`
returns the documents before the failure, read whole. yaml.v3's reader
decodes and checks the text 512 bytes at a time, so which of two faults a
stream is refused for depends on where they fall; this one counts the
same way. Nesting is limited to 10000 levels of flow collections and of
block indentation ("exceeded max depth of 10000"), as in yaml.v3. The
parser and composer are loops with stacks of their own; `check` recurses
as yaml.v3's decoder does, which 10000 levels allow (yaml.v3's limit
tests, a megabyte each, are among the vectors).

Where this package and yaml.v3 part:
- comments are passed over as yaml.v3 passes them over, but not kept:
  nodes have no head, line or foot comment, and the writer writes none
  (the vectors' `marshal` lines are of trees with their comments
  cleared);
- `check`'s message for a collection as a key is "yaml: invalid map key",
  without the Go syntax of the key yaml.v3 adds;
- a repeated key is quoted as Go's `%#v` quotes it for ASCII, the usual
  escapes and bytes that are not UTF-8; of the characters Unicode does not
  count as printable, this one escapes the C1 controls, U+00A0, U+00AD,
  U+2028, U+2029 and U+FEFF and keeps the others;
- where a merge has to tell keys apart, timestamps are compared by their
  text (Go compares `time.Time` values, zone and all) and NaNs are equal;
- a float too big for `read_int` or `read_uint` converts as Go converts
  it on arm64 (saturating), which is what the vectors were made on; on
  amd64 Go's conversion differs;
- `.nan` is the platform's NaN, not Go's `math.NaN()` bit pattern
  (`0x7FF8000000000001`);
- a reader fault that yaml.v3 meets while looking ahead for a comment
  stops the stream here; yaml.v3 can go on to report a scanner fault
  further on instead.

Where yaml.v3, and so this package, is not YAML 1.2.2:
- only `%YAML 1.1` is taken: `%YAML 1.2` is "found incompatible YAML
  document", and a reserved directive (`%FOO`) is refused rather than
  ignored;
- anchors are shared by the documents of a stream, a later definition
  replacing an earlier one;
- plain scalars resolve with YAML 1.1's extras: timestamps, the octal
  `017`, `+` signs, `_` in numbers, `0b` binary, and `08` as the float 8;
  a merge key `<<` merges; a non-specific `!` tag on a plain scalar
  resolves it as if it had none; and `y`, `yes`, `on` and the like read
  into a bool field;
- in double quotes, `\/` is refused and `\'` is taken;
- the continuation lines of a quoted scalar need no indentation, and tabs
  follow libyaml's rules: after a simple key's `:` or in a flow collection
  a tab separates, elsewhere at the start of a token it is "found
  character that cannot start any token";
- yaml.v3's test for a byte order mark looks at the start of its buffer
  rather than at the cursor, so that a stream starting with two marks
  loses the first character of every line until its buffer moves; this
  package does the same;
- the decoder's limits (the alias ratio, 10000 levels) are yaml.v3's, not
  the spec's.

Parsing a 6 MB document of 840000 nodes takes 187 ms here (built
natively, on an arm64 Mac) and 323 ms in yaml.v3; writing it back, 76 ms
and 490 ms.

## Tests

```bash
python3 scripts/run_tests.py            # at -O0, -O2 and --debug
python3 scripts/run_tests.py --native   # also built with the C compiler
tools/goyaml.sh -corpus test/corpus.txt -corpus test/corpus-yamlv3.txt -corpus test/corpus-yamlv2.txt > test/vectors/goyaml.txt   # remake the vectors
tools/goyaml.sh -corpus test/corpus.txt -corpus test/corpus-yamlv3.txt -corpus test/corpus-yamlv2.txt -check test/vectors/goyaml.txt
tools/goyaml.sh -mine "$(go env GOMODCACHE)/gopkg.in/yaml.v3@v3.0.1" > test/corpus-yamlv3.txt   # remake the mined corpora
tools/goyaml.sh -mine "$(go env GOMODCACHE)/gopkg.in/yaml.v2@v2.4.0" > test/corpus-yamlv2.txt
tools/goyaml.sh file.yaml               # yaml.v3's dump of a file, by hand
tools/goyaml.sh -version
```

They take the compiler from `$GOOSE`, else `goose` on PATH, else
`../goose.git/build/goose` (run_tests.py also takes `--goose`).
`tools/goyaml` needs Go with gopkg.in/yaml.v3 v3.0.1 in the module cache,
and builds offline (`GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off`); the
tests themselves need no Go. There is no copy of the YAML test suite to
be had offline, so the corpus is hand-written, and yaml.v3's and yaml.v2's
own test inputs.

- `vectors`: against yaml.v3 (`test/vectors/goyaml.txt`, from
  `tools/goyaml`): 1598 streams read here into the same dump yaml.v3
  gives, byte for byte: each node's kind, line and column, tag, style,
  anchor and value, an alias's target; each scalar's value as `Decode`
  gives it into an `interface{}`, and into an `int64`, a `uint64`, a
  `float64`, a `bool` and a `string` (3264 scalars, with yaml.v3's type
  errors); each document checked as yaml.v3's decoder checks it (54
  refused); each document written as `yaml.Marshal` writes it, and each
  stream of more than one as a `yaml.Encoder` writes it; or the same
  error (323 streams refused). The streams: `test/corpus.txt`, 373 written
  for this, every construct and many malformed inputs, yaml.v3's limit
  tests (a megabyte of nesting, of aliases), alias bombs, and faults
  placed around the reader's 512-byte reads; and every string constant in
  yaml.v3's tests (723, `test/corpus-yamlv3.txt`) and yaml.v2's (502),
  inputs, outputs and messages alike. A dump of more than 100 lines is
  kept as its first 100 and a hash of the rest.
- `unit`: without Go (92 checks): the tree and its accessors, merges, the
  core schema, the text of every kind of scalar, tags and directives,
  streams, UTF-16, errors and the line and column they give, the
  decoder's checks (the billion laughs among them), and reading into a
  struct.
- `write`: the writer on trees built by hand (11 checks), against what
  yaml.v3's `Marshal` writes of the same trees: the tags it leaves out,
  the quoting, `!!binary`, flow and empty collections, complex keys,
  aliases, block scalars, and the trees it refuses; it never parses.
