# regex

goose's std `regex` with the assertions it leaves out: `^ $ \A \z \b \B`
and the `m` flag, with the meaning they have in Rust's `regex` crate, whose
syntax and semantics std's module follows. It is std's module
(stdlib/regex.goose) with a patch that is proposed for goose. It keeps
std's namespace and API, so a program switches to it by changing one
import, and back once goose ships the same. It is kept in step with std's
until then. A program imports one or the other, not both: both declare
`regex`, and importing both is a compile error.

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.regex;                     // instead of std's `import regex;`

fn main() {
    let setting = regex::compile("""(?m)^(\w+):[ \t]*(.*)$""");
    regex::each_captures(setting, "host: example.com\nport: 8080\n") { c =>
        print(regex::group(c, 1), " = ", regex::group(c, 2));
    };
    let cat = regex::compile("""\bcat\b""");
    print(regex::count(cat, "cat, cats and concatenate"));    // 1
}
```

The API is std's (docs/stdlib.md in goose.git): `compile`, `find`,
`matches`, `count`, `each_match`, `each_captures`, `format_replaced`,
`group`.

## The assertions

| Syntax | Holds |
|---|---|
| `\A` | at the start of the text |
| `\z` | at the end of the text |
| `^` | as `\A`; under `m`, also right after a `\n` |
| `$` | as `\z`; under `m`, also right before a `\n` (without `m`, not before a final `\n`: `a$` does not match `"a\n"`) |
| `\b` | between a word byte (`[0-9A-Za-z_]`) and a byte that is not one, or an end of the text |
| `\B` | where `\b` does not |

The `m` flag is written as std's `i` and `s` are: `(?m)` to the end of the
group, `(?m:...)` within, `(?-m)` off, and with the others (`(?im)`). The
word bytes are ASCII, as std's classes are. On ASCII text that is what the
crate's Unicode `\b` gives. Assertions see the text beyond a search's start
and end, as the crate's do. So the iterating functions find `^` only at 0
(and at line starts under `m`), and `\b` on `ab cd` at 0, 2, 3 and 5.
`\b{2}` is a repeated `\b`, as in the crate. Not supported: CRLF mode
`(?R)`, `\b{start}`, `\b{end}` and the crate's other word boundaries
(`\<`, `\>`), and what std's module leaves out (class set operations,
nested and Unicode classes, the `x` and `U` flags).

## How

Std's module compiles a pattern to complete DFAs up front, and a search is
one table lookup per byte. That stays so with assertions. Each one looks at
most one byte behind and one ahead, so for a pattern with assertions a DFA
state also records the kind of byte before it (none, `\n`, word, other).
Its pending assertions and match wait for the next byte, or for a column
for the end of the text, to settle them, as the crate's DFAs do. Patterns
anchored with `\A` stop at the first byte after the start. Patterns whose
every match starts at a line start skip to the next newline. The
prefix-byte skip still applies, and the capture backtracker checks
assertions against the whole text. Patterns without assertions build the
same DFAs and take the same loops as std's.

## Tests

```bash
make test-regex          # scripts/run_tests.py: the tests at -O0, -O2 and --debug, and the example
make differential-regex  # scripts/differential.py: random cases against the Rust regex crate (needs cargo)
```

- `test/regex.goose` is goose's own test of std's regex
  (test/stdlib/stdlib_regex.goose), run on this module. It covers the
  syntax, leftmost-first preference, captures, empty matches in iteration,
  the skip loops, the errors, and the assertions at their edges: empty
  text, matches at 0 and at the end, `$` against `(?m)$` before a final
  newline, `\b` beside non-word bytes and at the text's ends, and captures
  that need the backtracker. Its expected lines were checked against the
  crate.
- `test/differential.goose` replays 605 cases kept from the differential
  (`test/differential_cases.txt`), against the crate's output for them.
  With a file argument it runs any cases, which is how the differential
  uses it.
- `scripts/differential.py` makes random patterns that mix the six
  assertions into alternations, greedy and lazy repetitions, groups and
  scoped `(?m:)`, `(?-m:)` and `(?i:)` flags, some under a leading `(?m)`.
  It runs each on three random texts over `"ab \n_x.A"`, short ones and,
  every other pattern, longer ones that get the skip loops chosen. It
  compares every match's groups with the crate's (regex 1.13.2,
  `regex::bytes`, Unicode off; `scripts/oracle`). Patterns too large for
  the module's DFAs, which the crate's lazy DFA runs, are counted apart.
  Developing the patch, 156,000 such cases (about 52,000 patterns) came
  out the same but for 51 of those too-large ones.

Tested on macOS arm64.

## Examples

- `examples/regex/anchors.goose`: whole-text validation with `\A` and `\z`,
  settings read line by line with `(?m)^...$`, a whole word replaced with
  `\b`, and `\B`.
