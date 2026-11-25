// regex: std's regex (goose's stdlib/regex.goose, docs/stdlib.md) with
// anchors and word boundaries added: `^ $ \A \z \b \B` and the `m` flag.
// It has std's namespace and API, so a program switches by changing its
// import (`import regex;` to `import gslib.regex;`), and is kept in step
// with std's until goose ships the same (a patch for it is proposed
// upstream). A program imports one or the other, not both: they share the
// namespace `regex`.
//
//   import gslib.regex;          // from a program; `import regex;` inside gslib
//
//   let re = regex::compile("(?m)^(\\w+):\\s*(.*)$");
//   regex::each_captures(re, text) { c => print(regex::group(c, 1)); };
//
// Regular expressions (docs/stdlib.md), with the syntax and the semantics of
// the Rust `regex` crate: leftmost-first matching (the earliest match wins,
// and among the matches starting there the alternatives and repetitions are
// preferred in pattern order, `*?` and friends being lazy), unanchored
// search, and non-overlapping iteration.
//
// A pattern is parsed into a syntax tree and compiled to a Thompson NFA, the
// program, built in the shapes the crate's compiler builds, on which the
// order of preference depends. From it `compile` builds complete DFAs once,
// up front: a forward one, which finds where the leftmost-first match ends,
// and one over the reversed pattern, which walks back from that end to
// where the match starts. A search is then one table lookup per byte, and
// whenever the forward DFA is back in its start state a skip loop passes
// over the text where no match can start: one that tests two of the
// leading bytes every match has, or one that looks for a rare byte inside
// every match and walks back from it. Capture groups, which a DFA cannot
// see, come from their fixed places in the match where the pattern gives
// them one, and from a backtracker that runs over the match alone where not.
//
// The engine works on bytes: classes, `\d`, `\w`, `\s` and case folding are
// ASCII, which is what the crate's Unicode classes come to on ASCII text.
//
// The assertions are the crate's: `\A` and `\z` hold at the start and the
// end of the text, and so do `^` and `$`, except that under the `m` flag
// `^` holds after a `\n` as well and `$` before one (`$` alone does not hold
// before a final `\n`). `\b` holds between a word byte, `[0-9A-Za-z_]`, and
// a byte that is not one or an end of the text, and `\B` where `\b` does
// not. They look at the text around a search's start too: an iteration's
// second search does not take its start for the start of the text. Each
// looks at most one byte behind and one ahead, so a DFA can carry what it
// needs: in a pattern with assertions, a state also records the kind of
// the byte before it (none, `\n`, a word byte or another), and holds its
// assertions and its match over until the next byte, or the end of the
// text, settles them, as the crate's DFAs do. Patterns without assertions
// are built and searched as before.
//
// Not supported: CRLF mode (?R), the other word boundaries (`\b{start}`,
// `\<` and the like), class set operations, and patterns too large to
// compile: whose programs would need more than MAX_INSTS instructions, or
// whose DFAs more than MAX_STATES states or more than MAX_WORK steps to
// build.
//
// Known differences: the crate factors a prefix that every alternative
// shares out of an alternation, `a*ab|a*c?` becoming `a*(?:ab|c?)`, which
// changes the leftmost-first match where that prefix can repeat (on "aab"
// the crate matches "aa"); here the pattern means what it says, as in Perl
// and RE2. And where the last groups of a pattern lie under a `{0}`, the
// crate leaves them out of a match's groups, where here they are there and
// take no part.

namespace regex;

import std;
import dictionary;

let MAX_STATES = 10000;     // per DFA
let MAX_WORK = 50000000;    // per DFA: its states' threads times its columns
let MAX_INSTS = 10000;      // per program
let MAX_PREFIX = 8;         // leading byte positions the prefix test considers
let MAX_REPEAT = 1000;      // the largest count a {n,m} may give

// --- the syntax tree ---------------------------------------------------------

// An assertion: `\A`, `\z`, `^` and `$` under (?m), `\b`, `\B`.
enum Look { TextStart, TextEnd, LineStart, LineEnd, Boundary, NotBoundary }

// The kinds of byte an assertion tells apart on either side of a position:
// none (the start or the end of the text), a newline, a word byte, another.
let AT_EDGE = 0;
let AT_NEWLINE = 1;
let AT_WORD = 2;
let AT_OTHER = 3;

// The kind of each byte: a table, which costs the searches less than the
// tests would.
let KINDS: u8[256] = kinds();

fn kinds() -> u8[256] {
    var t: u8[256] = [AT_OTHER; 256];
    for b in 256 { if ascii::is_alnum(b as u8) || b == '_' { t[b] = AT_WORD; } }
    t['\n'] = AT_NEWLINE;
    return t;
}

fn kind(b: u8) -> i64 { KINDS[b] }

// The kind of byte before position i of the text, and at it.
fn kind_before(text: u8[:], i: i64) -> i64 { if i == 0 { AT_EDGE } else { kind(text[i - 1]) } }
fn kind_at(text: u8[:], i: i64) -> i64 { if i == text.len { AT_EDGE } else { kind(text[i]) } }

// Whether an assertion holds between bytes of these kinds.
fn holds(look: Look, before: i64, after: i64) -> bool {
    match look {
        TextStart => before == AT_EDGE,
        TextEnd => after == AT_EDGE,
        LineStart => before == AT_EDGE || before == AT_NEWLINE,
        LineEnd => after == AT_EDGE || after == AT_NEWLINE,
        Boundary => (before == AT_WORD) != (after == AT_WORD),
        NotBoundary => (before == AT_WORD) == (after == AT_WORD),
    }
}

// The assertion that holds on the reversed text where `look` holds on the
// text.
fn reversed(look: Look) -> Look {
    match look {
        TextStart => Look.TextEnd,
        TextEnd => Look.TextStart,
        LineStart => Look.LineEnd,
        LineEnd => Look.LineStart,
        Boundary => Look.Boundary,
        NotBoundary => Look.NotBoundary,
    }
}

// A node of the parsed pattern; children are indices into the node pool.
enum Node {
    Empty,
    Look { look: Look },                                    // matches the empty string where it holds
    Bytes { set: i32 },                                     // one byte of the set
    Cat { first: i32, second: i32 },
    Alt { first: i32, second: i32 },                        // first preferred
    Repeat { sub: i32, min: i32, max: i32, greedy: bool },  // max -1: unbounded
    Group { sub: i32, index: i32 },                         // a capture group
}

// --- the program ---------------------------------------------------------------

// An NFA instruction. A program is built back to front, from the match
// instruction at 0, so an instruction's successors are already in place
// when it is added; a loop patches its head afterwards.
enum Inst {
    Byte { set: i32, next: i32 },           // consume one byte of the set
    Split { first: i32, second: i32 },      // fork; the first thread is preferred
    Save { slot: i32, next: i32 },          // record the position in a capture slot
    Match,
    Look { look: Look, next: i32 },         // go on where the assertion holds
}

// A DFA over byte classes. States are numbered with the dead state first,
// then the match states, then, where a skip strategy takes over there, the
// start state, so a single comparison against `special` finds every state
// the search loop must look at. A state number is premultiplied by the
// number of classes: it is the offset of the state's row in `trans`.
//
// The DFA of a pattern with assertions reports a match a byte late: its
// match states are those entered from a position a match ends at. A row
// has a column more, `eoi`, taken at the end of the text, and there is a
// start state for each kind of byte before the start, in `starts`. States
// from which no match can be reached are the dead state, so a search for
// `\Aa` past the start ends at its first byte.
struct Dfa { start: i32, match_end: i32, special: i32, eoi: i32, starts: i32[4], trans: i32[] }

// How a search gets past text where no match can start, whenever the
// forward DFA is in its start state: by the prefix test, by the inner byte,
// to the next line start where every match starts at one, or not at all.
enum Skip { Scan, Prefix, Inner, Line }

// The prefix test: every match is at least `len` bytes long, and its bytes
// at offsets `at1` and `at2` lie in `set1` and `set2`, so a match can only
// start where both hold. at1 <= at2.
struct Prefilter { len: i64, at1: i64, at2: i64, set1: ByteSet, set2: ByteSet }

// Where a capture group lies in every match, if that is fixed: its start
// `start` bytes after the start of the match, or before its end with
// `start_back`, and likewise its end; -1 if not fixed.
struct Place { start: i64, start_back: bool, end: i64, end_back: bool }

struct Regex {
    groups:   i64,          // capture groups, group 0 being the whole match
    nullable: bool,         // whether the empty string matches, assertions aside
    looks:    bool,         // whether the pattern has assertions
    placed:   bool,         // whether every group has a fixed place
    entry:    i32,          // where the program starts an anchored match
    classes:  u8[256],      // byte -> its column in the DFAs
    skip:     Skip,
    filter:   Prefilter,
    // The inner byte: every match has a byte of `inner` right after a part
    // that holds none, so a match can only start where the reverse DFA of
    // that part, `before`, run back from such a byte, matches. For the
    // line skip, the newline.
    inner:  ByteSet,
    fwd:    Dfa,            // unanchored and leftmost-first: finds match ends
    rev:    Dfa,            // the reversed pattern, anchored: finds match starts
    before: Dfa,
    places: Place[],
    prog:   Inst[],
    sets:   (bool[256])[],
}

// --- byte sets -----------------------------------------------------------------

fn add_range(s: bool[256]&, lo: u8, hi: u8) {
    for b in (lo as i64)..(hi as i64) + 1 { s[b] = true; }
}

// Adds the other case of every ASCII letter in the set.
fn fold_case(s: bool[256]&) {
    for b in ('A' as i64)..('Z' as i64) + 1 {
        let lower = b + 32;
        if s[b] || s[lower] { s[b] = true; s[lower] = true; }
    }
}

// The set of \d, \w or \s (named by the escape letter's lower case), or of
// their complements \D, \W and \S, added to s. False for any other letter.
fn add_perl_class(s: bool[256]&, c: u8) -> bool {
    var t: bool[256] = [false; 256];
    let lower = if c >= 'A' && c <= 'Z' { c + 32 } else { c };
    if lower == 'd' {
        add_range(t, '0', '9');
    } else if lower == 'w' {
        add_range(t, 'a', 'z');
        add_range(t, 'A', 'Z');
        add_range(t, '0', '9');
        t['_'] = true;
    } else if lower == 's' {
        add_range(t, '\t', '\r');       // \t \n \v \f \r
        t[' '] = true;
    } else {
        return false;
    }
    let negated = c != lower;
    for b in 256 { if t[b] != negated { s[b] = true; } }
    return true;
}

// The byte a one-character escape stands for: a control character, or an
// ASCII punctuation character taken literally. -1 for anything else.
fn escaped_byte(c: u8) -> i64 {
    if c == 'n' { return '\n'; }
    if c == 't' { return '\t'; }
    if c == 'r' { return '\r'; }
    if c == 'f' { return 0x0c; }
    if c == 'v' { return 0x0b; }
    if c >= 0x21 && c < 0x7f && !ascii::is_alnum(c) { return c; }
    return -1;
}

// --- compiling -------------------------------------------------------------------

// Compiles a pattern. A syntax error, or a pattern too large to compile,
// aborts with a message saying what and where, as unwrapping the crate's
// Regex::new would.
fn compile(pattern: u8[:]) -> Regex {
    var err: u8[>..] = [];
    return build(pattern, err, true);
}

// Compiles a pattern that may be malformed: a syntax error, or a pattern too
// large to compile, appends its message to `err` and gives a regex that
// matches nothing.
fn compile(pattern: u8[:], err: u8[>..]&) -> Regex { build(pattern, err, false) }

// A regex that matches nothing, as compile gives for a malformed pattern:
// its forward DFA starts in the dead state.
fn nothing() -> Regex {
    let dead = Dfa { start: 0, match_end: 1, special: 1, eoi: 0, starts: [0; 4], trans: [0] };
    let none: ByteSet = byte_set([false; 256]);
    return Regex {
        groups: 1, nullable: false, looks: false, placed: false, entry: 0, classes: [0; 256], skip: Skip.Scan,
        filter: Prefilter { len: 0, at1: 0, at2: 0, set1: none, set2: none }, inner: none,
        fwd:    dead, rev: dead, before: dead, places: [], prog: [Inst.Match], sets: [],
    };
}

fn build(pattern: u8[:], err: u8[>..]&, aborts: bool) -> Regex {
    var nodes: Node[>..]        = [];
    var sets:  (bool[256])[>..] = [];
    var pos = 0;
    var fold = false;           // (?i): letters match either case
    var dot_nl = false;         // (?s): `.` matches a newline too
    var lines = false;          // (?m): `^` and `$` hold at line ends too
    var looks = false;          // whether the pattern has an assertion
    var groups = 1;

    // Ends the compile at an error: aborts with the message where `aborts`
    // says so, and otherwise appends it to `err` and returns a regex that
    // matches nothing. The result type lets the parsing functions return it.
    fn stop(message: u8[:]) -> i32 {
        if aborts { abort(message); }
        err.append(message);
        return nothing() from build;
    }
    fn fail_at(what: u8[:], at: i64) -> i32 { stop(str("regex: ", what, " at offset ", at, " in ", pattern)) }
    fn fail(what: u8[:]) -> i32 { fail_at(what, pos) }

    fn add(n: Node) -> i32 {
        nodes.push(n);
        return (nodes.len - 1) as i32;
    }

    fn add_bytes(s: bool[256]) -> i32 {
        sets.push(s);
        return add(Node.Bytes { set: (sets.len - 1) as i32 });
    }

    fn more() -> bool { pos < pattern.len }

    fn assertion(look: Look) -> i32 {
        looks = true;
        return add(Node.Look { look: look });
    }

    fn literal(c: u8) -> i32 {
        var s: bool[256] = [false; 256];
        s[c] = true;
        if fold { fold_case(s); }
        return add_bytes(s);
    }

    // A decimal count of a repetition.
    fn number() -> i32 {
        let start = pos;
        var v = 0;
        while more() && ascii::is_digit(pattern[pos]) {
            v = v * 10 + (pattern[pos] - '0');
            guard v <= MAX_REPEAT else { return fail("repetition count too large"); }
            pos++;
        }
        guard pos > start else { return fail("expected a repetition count"); }
        return v as i32;
    }

    // The byte of an escape whose backslash is behind us, \xNN included.
    // Errors name the backslash.
    fn escape_byte() -> u8 {
        let at = pos - 1;
        guard more() else { return fail_at("trailing backslash", at) as! u8; }
        let c = pattern[pos];
        pos++;
        if c == 'x' {
            guard pos + 2 <= pattern.len && ascii::hex_value(pattern[pos]) >= 0 && ascii::hex_value(pattern[pos + 1]) >= 0 else {
                return fail_at("bad \\x escape", at) as! u8;
            }
            let v = ascii::hex_value(pattern[pos]) * 16 + ascii::hex_value(pattern[pos + 1]);
            pos += 2;
            return v as u8;
        }
        let b = escaped_byte(c);
        guard b >= 0 else { return fail_at("unsupported escape", at) as! u8; }
        return b as u8;
    }

    // A class, its `[` behind us: bytes, ranges and Perl classes, maybe
    // negated. A `]` first, or a `-` first or last, is literal.
    fn class() -> i32 {
        var s: bool[256] = [false; 256];
        var negated = false;
        if more() && pattern[pos] == '^' { negated = true; pos++; }
        var first = true;
        loop {
            guard more() else { return fail("unclosed class"); }
            let c = pattern[pos];
            if c == ']' && !first { pos++; break; }
            first = false;
            guard c != '[' else { return fail("nested classes are not supported"); }
            guard !((c == '&' || c == '-' || c == '~') && pos + 1 < pattern.len && pattern[pos + 1] == c) else {
                return fail("class set operations are not supported");
            }
            pos++;
            var lo = c;
            if c == '\\' {
                if more() && add_perl_class(s, pattern[pos]) { pos++; continue; }
                lo = escape_byte();
            }
            if pos + 1 < pattern.len && pattern[pos] == '-' && pattern[pos + 1] != ']' {
                pos++;
                guard pattern[pos] != '-' else { return fail("class set operations are not supported"); }
                var hi = pattern[pos];
                pos++;
                if hi == '\\' { hi = escape_byte(); }
                guard hi >= lo else { return fail("bad class range"); }
                add_range(s, lo, hi);
            } else {
                s[lo] = true;
            }
        }
        if fold { fold_case(s); }
        if negated { for &x in s { x = !x; } }
        return add_bytes(s);
    }

    // An escape outside a class: an assertion, a Perl class or a byte.
    fn escape() -> i32 {
        var s: bool[256] = [false; 256];
        if more() && add_perl_class(s, pattern[pos]) {
            pos++;
            return add_bytes(s);
        }
        if more() {
            let c = pattern[pos];
            if c == 'A' { pos++; return assertion(Look.TextStart); }
            if c == 'z' { pos++; return assertion(Look.TextEnd); }
            if c == 'b' || c == 'B' {
                // \b{start} and the like are the crate's other word
                // boundaries; \b{2} is a repetition
                guard !(c == 'b' && pos + 2 < pattern.len && pattern[pos + 1] == '{'
                        && (ascii::is_alpha(pattern[pos + 2]) || pattern[pos + 2] == '-')) else {
                    return fail_at("unsupported word boundary", pos - 1);
                }
                pos++;
                return assertion(if c == 'b' { Look.Boundary } else { Look.NotBoundary });
            }
        }
        return literal(escape_byte());
    }

    // A group, its `(` behind us: capturing, non-capturing `(?:...)`, with
    // flags `(?i:...)`, or a bare flag setting `(?i)`, which holds to the end
    // of the group around it.
    recursive fn group() -> i32 {
        let outer_fold = fold;
        let outer_dot = dot_nl;
        let outer_lines = lines;
        var index = -1;
        if more() && pattern[pos] == '?' {
            pos++;
            if more() && (pattern[pos] == '<' || pattern[pos] == 'P') {
                // a named group: the name does not matter here
                while more() && pattern[pos] != '>' { pos++; }
                guard more() else { return fail("unclosed group name"); }
                pos++;
                index = groups;
                groups++;
            } else {
                var on = true;
                loop {
                    guard more() else { return fail("unclosed group"); }
                    let c = pattern[pos];
                    pos++;
                    if c == ')' { return add(Node.Empty); }
                    if c == ':' { break; }
                    if c == '-' { on = false; }
                    else if c == 'i' { fold = on; }
                    else if c == 's' { dot_nl = on; }
                    else if c == 'm' { lines = on; }
                    else { return fail_at("unsupported flag", pos - 1); }
                }
            }
        } else {
            index = groups;
            groups++;
        }
        let body = parse_alt();
        guard more() && pattern[pos] == ')' else { return fail("unclosed group"); }
        pos++;
        fold = outer_fold;
        dot_nl = outer_dot;
        lines = outer_lines;
        if index < 0 { return body; }
        return add(Node.Group { sub: body, index: index as i32 });
    }

    recursive fn parse_atom() -> i32 {
        let c = pattern[pos];
        guard c != '*' && c != '+' && c != '?' && c != '{' else { return fail("nothing to repeat"); }
        pos++;
        if c == '^' { return assertion(if lines { Look.LineStart } else { Look.TextStart }); }
        if c == '$' { return assertion(if lines { Look.LineEnd } else { Look.TextEnd }); }
        if c == '(' { return group(); }
        if c == '[' { return class(); }
        if c == '\\' { return escape(); }
        if c == '.' {
            var s: bool[256] = [true; 256];
            if !dot_nl { s['\n'] = false; }
            return add_bytes(s);
        }
        return literal(c);
    }

    // An atom and the repetition operators after it.
    recursive fn parse_repeat() -> i32 {
        var sub = parse_atom();
        while more() {
            let c = pattern[pos];
            var min: i32 = 0;
            var max: i32 = -1;
            if c == '*' {
                pos++;
            } else if c == '+' {
                min = 1;
                pos++;
            } else if c == '?' {
                max = 1;
                pos++;
            } else if c == '{' {
                pos++;
                min = number();
                max = min;
                if more() && pattern[pos] == ',' {
                    pos++;
                    max = if more() && pattern[pos] == '}' { -1 } else { number() };
                }
                guard more() && pattern[pos] == '}' else { return fail("unclosed repetition"); }
                guard max < 0 || max >= min else { return fail("bad repetition range"); }
                pos++;
            } else {
                break;
            }
            var greedy = true;
            if more() && pattern[pos] == '?' { greedy = false; pos++; }
            sub = add(Node.Repeat { sub: sub, min: min, max: max, greedy: greedy });
        }
        return sub;
    }

    recursive fn parse_cat() -> i32 {
        var seq = -1;
        while more() && pattern[pos] != '|' && pattern[pos] != ')' {
            let item = parse_repeat();
            seq = if seq < 0 { item } else { add(Node.Cat { first: seq as i32, second: item }) };
        }
        if seq < 0 { return add(Node.Empty); }
        return seq as i32;
    }

    recursive fn parse_alt() -> i32 {
        let first = parse_cat();
        if more() && pattern[pos] == '|' {
            pos++;
            let second = parse_alt();
            return add(Node.Alt { first: first, second: second });
        }
        return first;
    }

    fn push(prog: Inst[>..]&, i: Inst) -> i32 {
        if prog.len >= MAX_INSTS { stop(str("regex: the pattern is too large: ", pattern)); }
        prog.push(i);
        return (prog.len - 1) as i32;
    }

    // A repetition's choice between another round of `body` and leaving.
    fn choice(greedy: bool, body: i32, exit: i32) -> Inst {
        if greedy { Inst.Split { first: body, second: exit } } else { Inst.Split { first: exit, second: body } }
    }

    // Whether node n can match the empty string.
    recursive fn nullable(n: i32) -> bool {
        match nodes[n] {
            Empty => true,
            Look => true,
            Bytes => false,
            Cat c => nullable(c.first) && nullable(c.second),
            Alt a => nullable(a.first) || nullable(a.second),
            Group g => nullable(g.sub),
            Repeat r => r.min == 0 || nullable(r.sub),
        }
    }

    // Node n's instructions, continuing at `next`; returns their entry. The
    // reversed program matches the reversed strings and records no groups.
    recursive fn emit(prog: Inst[>..]&, n: i32, next: i32, reverse: bool) -> i32 {
        match nodes[n] {
            Empty => { return next; },
            Look l => { return push(prog, Inst.Look { look: if reverse { reversed(l.look) } else { l.look }, next: next }); },
            Bytes b => { return push(prog, Inst.Byte { set: b.set, next: next }); },
            Cat c => {
                if reverse { return emit(prog, c.second, emit(prog, c.first, next, reverse), reverse); }
                return emit(prog, c.first, emit(prog, c.second, next, reverse), reverse);
            },
            Alt a => {
                let first = emit(prog, a.first, next, reverse);
                let second = emit(prog, a.second, next, reverse);
                return push(prog, Inst.Split { first: first, second: second });
            },
            Group g => {
                if reverse { return emit(prog, g.sub, next, reverse); }
                let close = push(prog, Inst.Save { slot: 2 * g.index + 1, next: next });
                let body = emit(prog, g.sub, close, reverse);
                return push(prog, Inst.Save { slot: 2 * g.index, next: body });
            },
            // The shapes the regex crate's compiler gives repetitions: which
            // thread a leftmost-first match prefers depends on them where the
            // repeated expression can match the empty string.
            Repeat r => {
                var t = next;
                if r.max >= 0 {
                    // x{2,4} is xx(x(x)?)?
                    for k in r.max - r.min {
                        t = push(prog, choice(r.greedy, emit(prog, r.sub, t, reverse), next));
                    }
                    for k in r.min { t = emit(prog, r.sub, t, reverse); }
                    return t;
                }
                // x{n,} is x{n-1} and then x looping back to itself; x* is a
                // loop, or (x+)? where x can match the empty string.
                let head = push(prog, Inst.Match);      // patched below
                let body = emit(prog, r.sub, head, reverse);
                prog[head] = choice(r.greedy, body, next);
                if r.min == 0 {
                    if nullable(r.sub) { return push(prog, choice(r.greedy, body, next)); }
                    return head;
                }
                t = body;
                for k in r.min - 1 { t = emit(prog, r.sub, t, reverse); }
                return t;
            },
        }
    }

    // The length every match of node n has, or -1 if it varies.
    recursive fn fixed_len(n: i32) -> i64 {
        match nodes[n] {
            Empty => 0,
            Look => 0,
            Bytes => 1,
            Cat c => {
                let a = fixed_len(c.first);
                let b = fixed_len(c.second);
                if a < 0 || b < 0 { -1 } else { a + b }
            },
            Alt a => {
                let x = fixed_len(a.first);
                if x == fixed_len(a.second) { x } else { -1 }
            },
            Repeat r => {
                let x = fixed_len(r.sub);
                if r.min == r.max && x >= 0 { x * r.min } else { -1 }
            },
            Group g => fixed_len(g.sub),
        }
    }

    // Adds every byte node n can consume to s.
    recursive fn alphabet(n: i32, s: bool[256]&) {
        match nodes[n] {
            Empty => {},
            Look => {},
            Bytes b => { for c in 256 { if sets[b.set][c] { s[c] = true; } } },
            Cat c => { alphabet(c.first, s); alphabet(c.second, s); },
            Alt a => { alphabet(a.first, s); alphabet(a.second, s); },
            Repeat r => { if r.max != 0 { alphabet(r.sub, s); } },
            Group g => { alphabet(g.sub, s); },
        }
    }

    // Adds the bytes a match of node n can start with to s; true if it can
    // be empty, so that what follows it can start the match as well.
    recursive fn first_bytes(n: i32, s: bool[256]&) -> bool {
        match nodes[n] {
            Empty => true,
            Look => true,
            Bytes b => {
                for c in 256 { if sets[b.set][c] { s[c] = true; } }
                false
            },
            Cat c => if first_bytes(c.first, s) { first_bytes(c.second, s) } else { false },
            Alt a => {
                let x = first_bytes(a.first, s);
                let y = first_bytes(a.second, s);
                x || y
            },
            Repeat r => {
                if r.max == 0 { return true; }
                let empty = first_bytes(r.sub, s);
                empty || r.min == 0
            },
            Group g => first_bytes(g.sub, s),
        }
    }

    // The nodes a concatenation is made of, in order.
    recursive fn flatten(n: i32, out: i32[>..]&) {
        match nodes[n] {
            Cat c => { flatten(c.first, out); flatten(c.second, out); },
            _ => { out.push(n); },
        }
    }

    // Records the place of each group that every match of node n holds at
    // a fixed distance from the match's ends: n spans the match but for
    // `head` bytes at its start and `tail` at its end, each -1 if unknown.
    // Groups under an alternation or a repetition are left out: they need
    // not take part in a match, or take part more than once.
    recursive fn place(n: i32, head: i64, tail: i64, places: Place[>..]&) {
        match nodes[n] {
            Cat c => {
                let a = fixed_len(c.first);
                let b = fixed_len(c.second);
                place(c.first, head, if tail >= 0 && b >= 0 { tail + b } else { -1 }, places);
                place(c.second, if head >= 0 && a >= 0 { head + a } else { -1 }, tail, places);
            },
            Group g => {
                let len = fixed_len(g.sub);
                var p = Place { start: -1, start_back: false, end: -1, end_back: false };
                if head >= 0 {
                    p.start = head;
                } else if tail >= 0 && len >= 0 {
                    p.start = tail + len;
                    p.start_back = true;
                }
                if tail >= 0 {
                    p.end = tail;
                    p.end_back = true;
                } else if head >= 0 && len >= 0 {
                    p.end = head + len;
                }
                places[g.index] = p;
                place(g.sub, head, tail, places);
            },
            _ => {},
        }
    }

    // Whether every match of node n starts at the start of a line: at the
    // start of the text or after a newline.
    recursive fn at_line_start(n: i32) -> bool {
        match nodes[n] {
            Look l => l.look == Look.TextStart || l.look == Look.LineStart,
            Cat c => at_line_start(c.first) || (fixed_len(c.first) == 0 && at_line_start(c.second)),
            Alt a => at_line_start(a.first) && at_line_start(a.second),
            Repeat r => r.min > 0 && at_line_start(r.sub),
            Group g => at_line_start(g.sub),
            _ => false,
        }
    }

    let root = parse_alt();
    if more() { fail("unmatched )"); }

    var prog:  Inst[>..] = [];
    var rprog: Inst[>..] = [];
    let top = add(Node.Group { sub: root, index: 0 });
    let entry = emit(prog, top, push(prog, Inst.Match), false);
    let rentry = emit(rprog, root, push(rprog, Inst.Match), true);

    // The unanchored start: (?s:.)*? ahead of the pattern, lowest priority.
    sets.push([true; 256]);
    let head = push(prog, Inst.Match);
    let any = push(prog, Inst.Byte { set: (sets.len - 1) as i32, next: head });
    prog[head] = Inst.Split { first: entry, second: any };

    // The prefix test, and the inner byte: of the sets of bytes that can
    // start the rest of the pattern after a leading part of its
    // concatenation, the rarest one the leading part cannot consume.
    let prefix = prefix_sets(prog, sets, entry);
    let filter, filter_share = choose_filter(prefix);
    var items: i32[>..] = [];
    flatten(root, items);
    var inner: bool[256] = [false; 256];
    var inner_share = 1.0;
    var inner_at = -1;
    for t in 1..items.len {
        var before: bool[256] = [false; 256];
        for k in t { alphabet(items[k], before); }
        var start: bool[256] = [false; 256];
        var empty = true;
        for k in t..items.len {
            if !first_bytes(items[k], start) { empty = false; break; }
        }
        var share = 0.0;
        var disjoint = !empty;
        for c in 256 {
            if start[c] {
                share += frequency(c as u8) / 100.0;
                if before[c] { disjoint = false; }
            }
        }
        if disjoint && share < inner_share { inner = start; inner_share = share; inner_at = t; }
    }
    // A skip loop pays where it lets through under a tenth of the
    // positions; the inner byte, each of whose hits costs a backward scan,
    // is taken only where it is several times rarer than the prefix test.
    // Where every match starts at a line start, the next newline is the
    // place to look, unless the prefix test is rarer still. The inner byte
    // is not used with assertions, which the part before it could hold.
    var skip = Skip.Scan;
    var bprog: Inst[>..] = [];
    var bentry = push(bprog, Inst.Match);
    if looks && at_line_start(root) && filter_share >= frequency('\n') / 100.0 {
        skip = Skip.Line;
        inner = [false; 256];
        inner['\n'] = true;
    } else if !looks && prefix.len > 0 && inner_at > 0 && inner_share < 0.1 && inner_share * 4.0 < filter_share {
        skip = Skip.Inner;
        var part = items[0];
        for k in 1..inner_at { part = add(Node.Cat { first: part, second: items[k] }); }
        bentry = emit(bprog, part, bentry, true);
    } else if filter_share < 0.1 {
        skip = Skip.Prefix;
    }

    var places: Place[>..] = [];
    places.resize(groups, Place { start: -1, start_back: false, end: -1, end_back: false });
    place(top, 0, 0, places);
    var placed = true;
    for p in places { if p.start < 0 || p.end < 0 { placed = false; } }

    // The bytes the assertions tell apart get byte classes of their own.
    if looks {
        var word: bool[256] = [false; 256];
        add_perl_class(word, 'w');
        var newline: bool[256] = [false; 256];
        newline['\n'] = true;
        sets.push(word);
        sets.push(newline);
    }
    let classes = byte_classes(sets);
    let scans = skip != Skip.Scan;
    var too_big = false;
    let re = Regex {
        groups:   groups,
        nullable: prefix.len == 0,
        looks:    looks,
        placed:   placed,
        entry:    entry,
        classes:  classes,
        skip:     skip,
        filter:   filter,
        inner:    byte_set(inner),
        fwd:      build_dfa(prog, sets, classes, head, true, scans, looks, too_big),
        rev:      build_dfa(rprog, sets, classes, rentry, false, false, looks, too_big),
        before:   build_dfa(bprog, sets, classes, bentry, false, false, looks, too_big),
        places:   copy(places),
        prog:     copy(prog),
        sets:     copy(sets),
    };
    if too_big { stop(str("regex: the pattern's DFA would be too large: ", pattern)); }
    return re;
}

// --- analysis --------------------------------------------------------------------

// The bytes each of a match's leading positions can hold: element j is the
// set of bytes at offset j, for every offset a match always reaches (up to
// MAX_PREFIX of them). Empty when the empty string matches.
fn prefix_sets(prog: Inst[:], sets: (bool[256])[:], entry: i32) -> (bool[256])[>..] {
    var out:   (bool[256])[>..] = [];
    var front: i32[>..]         = []; // the Byte instructions a thread can be at
    var next:  i32[>..]         = [];
    var seen:  i32[>..]         = [];
    seen.resize(prog.len, -1);
    var round: i32       = 0;
    var stack: i32[>..<] = [];

    // Adds the Byte instructions pc leads to without consuming a byte to
    // `next`; true if it can reach a match that way.
    fn reach(pc0: i32) -> bool {
        var matched = false;
        stack.push(pc0);
        while stack.len > 0 {
            let pc = stack.pop();
            if seen[pc] == round { continue; }
            seen[pc] = round;
            match prog[pc] {
                Byte => next.push(pc),
                Look l => stack.push(l.next),       // as if it held: the sets can only grow
                Split sp => { stack.push(sp.second); stack.push(sp.first); },
                Save sv => stack.push(sv.next),
                Match => { matched = true; },
            }
        }
        return matched;
    }

    if reach(entry) { return out; }
    while out.len < MAX_PREFIX {
        front.clear();
        front.append(next);
        next.clear();
        round++;
        var s: bool[256] = [false; 256];
        var matched = false;
        for pc in front {
            match prog[pc] {
                Byte b => {
                    for c in 256 { if sets[b.set][c] { s[c] = true; } }
                    if reach(b.next) { matched = true; }
                },
                _ => {},
            }
        }
        out.push(s);
        if matched { break; }
    }
    return out;
}

// A rough share, in percent, of a byte in typical text, prose, code and
// data alike: the digits rank with the letters, as in the byte-frequency
// table the regex crate picks its prefilter bytes by.
fn frequency(b: u8) -> f64 {
    if b == ' ' { return 15.0; }
    if b >= 'a' && b <= 'z' { return if position("etaoinsrhl", b) >= 0 { 5.0 } else { 1.0 }; }
    if b >= '0' && b <= '9' { return 2.0; }
    if b >= 'A' && b <= 'Z' { return 0.5; }
    if b == '\n' || position(""".,-/:;"'()=_""", b) >= 0 { return 1.0; }
    if b > ' ' && b < 0x7f { return 0.2; }
    return 0.05;
}

// The prefix test for these prefix sets: the pair of positions, or the one
// position, whose bytes are rarest by `frequency`, and the share of
// positions it is expected to let through.
fn choose_filter(prefix: (bool[256])[:]) -> Prefilter, f64 {
    var share: f64[>..] = [];
    for &s in prefix {
        var f = 0.0;
        for b in 256 { if s[b] { f += frequency(b as u8); } }
        share.push(f / 100.0);
    }
    var best = 1.0;
    var at1 = 0;
    var at2 = 0;
    for j in prefix.len {
        for k in j..prefix.len {
            let p = if j == k { share[j] } else { share[j] * share[k] };
            if p < best { best = p; at1 = j; at2 = k; }
        }
    }
    guard prefix.len > 0 else {
        let none = byte_set([false; 256]);
        return Prefilter { len: 0, at1: 0, at2: 0, set1: none, set2: none }, 1.0;
    }
    return Prefilter { len: prefix.len, at1: at1, at2: at2, set1: byte_set(prefix[at1]),
                       set2: byte_set(prefix[at2]) }, best;
}

// The byte classes of a program's sets: two bytes share a class when every
// set treats them alike, so a DFA needs a column per class rather than per
// byte. Classes are numbered in the order of their first byte.
fn byte_classes(sets: (bool[256])[:]) -> u8[256] {
    var classes: u8[256] = [0; 256];
    for &s in sets {
        var split: i32[512] = [-1; 512];    // (class, in s) -> refined class
        var n:     i32      = 0;
        for b in 256 {
            let k = classes[b] as i64 * 2 + (if s[b] { 1 } else { 0 });
            if split[k] < 0 { split[k] = n; n++; }
            classes[b] = split[k] as u8;
        }
    }
    return classes;
}

// --- the DFAs ----------------------------------------------------------------------

// The DFA of a program, by subset construction. A state is the
// priority-ordered list of the Byte instructions its threads wait at, and
// whether a thread has matched. With `leftmost` the list ends at the first
// match, which drops every thread of lower priority, as leftmost-first
// semantics wants; without it every thread runs on, so that the reverse DFA
// sees each place a match can start. `skip_start` makes the start state
// special, for a search that hands it to a skip loop. A DFA that would be too
// large to build sets `too_big` and comes back empty.
//
// With `looks`, the program has assertions, which the next byte settles:
// the list holds every instruction the threads reached, in the order they
// were reached, a state records the kind of byte before it, and `matched`
// says a thread matched where the state was entered from. A transition
// first settles the list at the state's position, knowing the bytes on
// either side, by following the threads again from the list in its order:
// an assertion that holds lets its thread on, a Byte steps over the byte
// into the next state's list, and a Match matches. The list must hold the
// instructions between as well, the order of preference depending on which
// thread reaches an instruction first.
fn build_dfa(prog: Inst[:], sets: (bool[256])[:], classes: u8[256], start_pc: i32,
             leftmost: bool, skip_start: bool, looks: bool, too_big: bool&) -> Dfa {
    var reps: u8[>..] = [];         // the first byte of each class
    for b in 256 { if classes[b] == reps.len { reps.push(b as u8); } }
    let stride = reps.len;
    let columns = if looks { stride + 1 } else { stride };     // and the end of the text

    // The kinds of byte before a position that the program's assertions
    // tell apart: each kind stands for the first kind like it, so states
    // that differ only in kinds alike are one.
    var canon: i64[4] = [0, 1, 2, 3];
    for k in 1..4 {
        for j in k {
            var alike = true;
            for &inst in prog {
                match inst {
                    Look l => { for after in 4 { if holds(l.look, j, after) != holds(l.look, k, after) { alike = false; } } },
                    _ => {},
                }
            }
            if alike { canon[k] = canon[j]; break; }
        }
    }

    var lists:    i32[>..]  = [];   // every state's instructions, back to back
    var bounds:   i64[>..]  = [0];  // state k's are lists[bounds[k]..bounds[k + 1]]
    var matching: bool[>..] = [];
    var kinds:    i64[>..]  = [];   // the kind of byte before each state
    var keys:     u8[>..]   = [];   // the same lists, encoded as dictionary keys
    var index = dictionary<const u8[:], i32> {};
    var trans: i32[>..] = [];       // by state index, `columns` entries per state

    var list: i32[>..] = [];        // the state being made
    var matched = false;
    var before = AT_EDGE;
    var probe: u8[>..]  = [];
    var seen:  i32[>..] = [];
    seen.resize(prog.len, -1);
    var round: i32       = 0;
    var stack: i32[>..<] = [];
    // The settling of a state's list, at its own position, keeps apart
    // from the next state's: one instruction can wait at both.
    var here:       i32[>..] = [];
    here.resize(prog.len, -1);
    var here_round: i32       = 0;
    var pending:    i32[>..<] = [];

    // Adds the threads pc leads to without consuming a byte, in priority
    // order; true if a match cut the list short. With `looks` a thread
    // waits at an assertion or a match for the next byte.
    fn follow(pc0: i32) -> bool {
        stack.push(pc0);
        while stack.len > 0 {
            let pc = stack.pop();
            if seen[pc] == round { continue; }
            seen[pc] = round;
            if looks { list.push(pc); }
            match prog[pc] {
                Byte => if !looks { list.push(pc); },
                Look => {},
                Split sp => { stack.push(sp.second); stack.push(sp.first); },
                Save sv => stack.push(sv.next),
                Match => {
                    if !looks { matched = true; }
                    if leftmost { stack.clear(); return true; }
                },
            }
        }
        return false;
    }

    // Follows the threads from pc0 again, at the position of a state with
    // bytes of kinds `kind_before` and `kind_after` on either side, stepping
    // their Bytes over class c (none at the end); true if a match cut the
    // lists short.
    fn settle(pc0: i32, kind_before: i64, kind_after: i64, c: i64) -> bool {
        pending.push(pc0);
        while pending.len > 0 {
            let pc = pending.pop();
            if here[pc] == here_round { continue; }
            here[pc] = here_round;
            match prog[pc] {
                Byte b => if c < stride && sets[b.set][reps[c]] && follow(b.next) { pending.clear(); return true; },
                Look l => if holds(l.look, kind_before, kind_after) { pending.push(l.next); },
                Split sp => { pending.push(sp.second); pending.push(sp.first); },
                Save sv => pending.push(sv.next),
                Match => {
                    matched = true;
                    if leftmost { pending.clear(); return true; }
                },
            }
        }
        return false;
    }

    // The state for `list`, `matched` and `before`, made if it is new.
    fn intern() -> i32 {
        // Without a thread at an assertion, the list comes to its Bytes and
        // Match, and the kind before does not matter.
        var kept = 0;
        if looks {
            var waits = false;
            for pc in list { match prog[pc] { Look => { waits = true; }, _ => {} } }
            if waits {
                kept = canon[before];
            } else {
                var n = 0;
                for pc in list {
                    match prog[pc] {
                        Byte => { list[n] = pc; n++; },
                        Match => { list[n] = pc; n++; },
                        _ => {},
                    }
                }
                list.resize(n, 0);
            }
        }
        probe.clear();
        for pc in list { format_uleb(probe, pc); }
        probe.push(if matched { 1 } else { 0 });
        probe.push(kept as u8);
        let known = index.get(probe);
        if known { return known; }
        let id = matching.len as i32;
        let k = keys.len;
        keys.append(probe);
        index.insert(keys[k..], id);
        lists.append(list);
        bounds.push(lists.len);
        matching.push(matched);
        kinds.push(kept);
        guard matching.len <= MAX_STATES && lists.len * columns <= MAX_WORK else {
            too_big = true;
            return Dfa { start: 0, match_end: 1, special: 1, eoi: 0, starts: [0; 4], trans: [0] } from build_dfa;
        }
        return id;
    }

    fn begin() {
        list.clear();
        matched = false;
        round++;
    }

    begin();
    intern();                       // 0: the dead state, with no threads
    var starts: i32[>..] = [];      // by the kind of byte before the start
    for b in (if looks { 4 } else { 1 }) {
        begin();
        follow(start_pc);
        before = b;
        starts.push(intern());
    }
    let start = starts[0];
    var k = 0;
    while k < matching.len {
        for c in columns {
            begin();
            if looks {
                here_round++;
                let after = if c == stride { AT_EDGE } else { kind(reps[c]) };
                for at in bounds[k]..bounds[k + 1] {
                    if settle(lists[at], kinds[k], after, c) { break; }
                }
                before = after;
            } else {
                for at in bounds[k]..bounds[k + 1] {
                    match prog[lists[at]] {
                        Byte b => if sets[b.set][reps[c]] && follow(b.next) { break; },
                        _ => {},
                    }
                }
            }
            trans.push(intern());
        }
        k++;
    }

    // With `looks`, the states no match can be reached from are dead: found
    // by walking the transitions back from the match states.
    var live: bool[>..] = [];
    live.resize(matching.len, true);
    if looks {
        for s in matching.len { live[s] = matching[s]; }
        var first: i64[>..] = [];       // state t's predecessors are from[first[t]..first[t + 1]]
        first.resize(matching.len + 1, 0);
        for t in trans { first[t + 1]++; }
        for t in matching.len { first[t + 1] += first[t]; }
        var fill: i64[>..] = copy(first);
        var from: i32[>..] = [];
        from.resize(trans.len, 0);
        for t, at in trans {
            from[fill[t]] = (at / columns) as i32;
            fill[t]++;
        }
        var work: i32[>..<] = [];
        for s in matching.len { if live[s] { work.push(s as i32); } }
        while work.len > 0 {
            let t = work.pop();
            for at in first[t]..first[t + 1] {
                let s = from[at];
                if !live[s] { live[s] = true; work.push(s); }
            }
        }
    }

    // Renumbered: the dead state, the match states, the start states if they
    // are special, then the rest. The states not live are the dead state.
    var placed: bool[>..] = [];
    placed.resize(matching.len, false);
    placed[0] = true;
    var order: i32[>..] = [0];
    for s in 1..matching.len { if matching[s] { order.push(s as i32); placed[s] = true; } }
    let match_end = order.len;
    if skip_start {
        for s in starts { if live[s] && !placed[s] { order.push(s); placed[s] = true; } }
    }
    let special = order.len;
    for s in 1..matching.len { if live[s] && !placed[s] { order.push(s as i32); } }
    var number: i32[>..] = [];
    number.resize(matching.len, 0);
    for old, new in order { number[old] = new as i32; }
    let width = columns as i32;
    var table: i32[>..] = [];
    for old in order {
        for c in columns { table.push(number[trans[old * columns + c]] * width); }
    }
    var numbered: i32[4] = [0; 4];
    for s, b in starts { numbered[b] = number[s] * width; }
    return Dfa {
        start:     number[start] * width,
        match_end: match_end as i32 * width,
        special:   special as i32 * width,
        eoi:       stride as i32,
        starts:    numbered,
        trans:     copy(table),
    };
}

// --- searching ----------------------------------------------------------------------

// The prefix test's next position at or after i where a match can start;
// text.len if there is none.
inline fn skip_prefix(f: Prefilter&, text: u8[:], i: i64) -> i64 {
    let fits = text.len - f.len + 1;    // the positions a match fits at
    assert(i >= 0);
    guard i < fits else { return text.len; }
    // The first position from i on whose bytes at1 and at2 on pass the tests.
    let p = if f.at1 == f.at2 { find_any(text[i + f.at1..fits + f.at1], f.set1) }
            else { find_pair(text[i + f.at1..fits + f.at2], f.set1, f.at2 - f.at1, f.set2) };
    return if p >= 0 { i + p } else { text.len };
}

// The inner byte's next position at or after i where a match can start:
// where the part before an inner byte starts, found by running its reverse
// DFA back from the byte, no further than i or than the inner byte before.
fn skip_inner(re: Regex&, text: u8[:], i: i64) -> i64 {
    assert(i >= 0);
    var lo = i;
    var q = i;
    while q < text.len {
        let k = find_any(text[q..], re.inner);
        if k < 0 { break; }
        q += k;
        let s = scan_back(re, re.before, text, lo, q);
        if s >= 0 { return s; }
        q++;
        lo = q;
    }
    return text.len;
}

// Where the search goes on when the forward DFA is in its start state at
// i, which no match starts before: the first position a match can start at.
fn resume(re: Regex&, text: u8[:], i: i64) -> i64 {
    match re.skip {
        Prefix => skip_prefix(re.filter, text, i),
        Inner => skip_inner(re, text, i),
        Scan => i,
        Line => i,      // find_end_looks takes the line skip itself
    }
}

// The line skip's next position at or after i where a match can start: the
// next line start, or text.len.
fn skip_line(re: Regex&, text: u8[:], i: i64) -> i64 {
    if i == 0 || text[i - 1] == '\n' { return i; }
    let k = find_any(text[i..], re.inner);
    return if k >= 0 { i + k + 1 } else { text.len };
}

// The end of the leftmost-first match that starts at or after `at`, or -1.
fn find_end(re: Regex&, text: u8[:], at: i64) -> i64 {
    if re.looks { return find_end_looks(re, text, at); }
    let trans = re.fwd.trans;
    let start = re.fwd.start;
    let special = re.fwd.special;
    var s = start;
    var last: i64 = -1;
    if re.nullable { last = at; }
    var i = resume(re, text, at);
    while i < text.len {
        s = trans[s + re.classes[text[i]]];
        i++;
        if s < special {
            if s >= re.fwd.match_end {
                // back at the start: no thread is alive but the search's own
                i = resume(re, text, i);
            } else if s == 0 {
                return last;
            } else {
                last = i;
            }
        }
    }
    return last;
}

// find_end for a pattern with assertions, whose DFA reports a match on the
// byte after it, or at the end of the text. After a skip, the start state
// is the one for the byte before where the search goes on. (It takes the
// skips itself, so that find_end stays resume's one caller, which inlines
// it.)
fn find_end_looks(re: Regex&, text: u8[:], at: i64) -> i64 {
    let trans = re.fwd.trans;
    let starts = re.fwd.starts;
    let match_end = re.fwd.match_end;
    let special = re.fwd.special;
    fn resume(i: i64) -> i64 {
        match re.skip {
            Prefix => skip_prefix(re.filter, text, i),
            Line => skip_line(re, text, i),
            _ => i,         // the inner byte is not used with assertions
        }
    }
    var last: i64 = -1;
    var i = resume(at);
    var s = starts[kind_before(text, i)];
    while i < text.len {
        s = trans[s + re.classes[text[i]]];
        if s < special {
            if s == 0 { return last; }
            if s < match_end {
                last = i;
            } else {
                i = resume(i + 1);
                s = starts[kind_before(text, i)];
                continue;
            }
        }
        i++;
    }
    s = trans[s + re.fwd.eoi];
    if s != 0 && s < match_end { last = text.len; }
    return last;
}

// Where the reverse DFA d, run back from `end` no further than `lo`, last
// matches: the leftmost start of a match of its pattern that ends at
// `end`; -1 if there is none.
fn scan_back(re: Regex&, d: Dfa&, text: u8[:], lo: i64, end: i64) -> i64 {
    if re.looks { return scan_back_looks(re, d, text, lo, end); }
    let trans = d.trans;
    let match_end = d.match_end;
    var s = d.start;
    var first: i64 = -1;
    if s < match_end { first = end; }
    assert(lo >= 0 && end <= text.len);
    var i = end;
    while i > lo {
        s = trans[s + re.classes[text[i - 1]]];
        i--;
        if s < match_end {
            if s == 0 { break; }
            first = i;
        }
    }
    return first;
}

// scan_back for a pattern with assertions, whose DFA reports a match a
// byte late: the byte before `lo`, or the start of the text, settles
// whether a match starts at `lo`. The assertions see the text beyond `lo`
// and `end`, as the crate's do beyond a search's bounds.
fn scan_back_looks(re: Regex&, d: Dfa&, text: u8[:], lo: i64, end: i64) -> i64 {
    let trans = d.trans;
    let match_end = d.match_end;
    assert(lo >= 0 && end <= text.len);
    var s = d.starts[kind_at(text, end)];
    var first: i64 = -1;
    var i = end;
    while i > lo {
        s = trans[s + re.classes[text[i - 1]]];
        if s < match_end {
            if s == 0 { return first; }
            first = i;
        }
        i--;
    }
    s = trans[s + (if lo == 0 { d.eoi } else { re.classes[text[lo - 1]] as i32 })];
    if s != 0 && s < match_end { first = lo; }
    return first;
}

// Where the match that ends at `end`, and starts at or after `at`, starts.
fn find_start(re: Regex&, text: u8[:], at: i64, end: i64) -> i64 { scan_back(re, re.rev, text, at, end) }

// The leftmost-first match: where it starts and where it ends; -1, -1 if
// there is none.
fn find(re: Regex&, text: u8[:]) -> i64, i64 {
    let e = find_end(re, text, 0);
    if e < 0 { return -1, -1; }
    return find_start(re, text, 0, e), e;
}

// Whether text holds a match, as the crate's is_match: the reverse DFA,
// which finds where a match starts, is not run.
fn matches(re: Regex&, text: u8[:]) -> bool { find_end(re, text, 0) >= 0 }

// F(start, end) for every match, left to right, as the regex crate's
// find_iter yields them: no two overlap, and no empty match comes where the
// previous match ended.
fn each_match<F>(re: Regex&, text: u8[:]) {
    var at = 0;
    var last_end = -1;
    while at <= text.len {
        var e = find_end(re, text, at);
        if e < 0 { break; }
        var s = find_start(re, text, at, e);
        if s == e && e == last_end {
            if at == text.len { break; }
            e = find_end(re, text, at + 1);
            if e < 0 { break; }
            s = find_start(re, text, at + 1, e);
        }
        F(s, e);
        at = e;
        last_end = e;
    }
}

// The number of matches: what find_iter(text).count() counts. A match that
// cannot be empty is counted from its end alone, as the crate's count()
// does: only a match's start takes the reverse DFA.
fn count(re: Regex&, text: u8[:]) -> i64 {
    var n = 0;
    if re.nullable {
        each_match(re, text) { s, e => n++; };
        return n;
    }
    var at = 0;
    loop {
        let e = find_end(re, text, at);
        if e < 0 { break; }
        n++;
        at = e;
    }
    return n;
}

// --- capture groups --------------------------------------------------------------------

// The capture groups of a match: group k spans slots[2k]..slots[2k + 1] of
// the text, or both are -1 if it took no part in the match. Group 0 is the
// match, and the others are numbered by their opening parentheses.
struct Captures { text: const u8[:], slots: const i64[:] }

// Group k's text; empty if the group took no part in the match.
fn group(c: Captures, k: i64) -> const u8[:] {
    let s = c.slots[2 * k];
    if s < 0 { return c.text[0..0]; }
    return c.text[s..c.slots[2 * k + 1]];
}

// A step of the backtracking search: a thread to explore, or a capture slot
// to restore when the search backs out of the thread that set it.
enum Frame { Explore { pc: i32, at: i64 }, Restore { slot: i32, old: i64 } }

// The capture slots of the leftmost-first match [start, end), by
// backtracking over the program from `start` in priority order: the first
// thread to reach the match instruction is the one the match took. Each
// (instruction, position) pair is explored once at most, which `visited`,
// the caller's scratch, records.
fn backtrack(re: Regex&, text: u8[:], start: i64, end: i64, slots: i64[:], visited: bool[>..]&) {
    let prog = re.prog;
    let sets = re.sets;
    let width = end - start + 1;
    let need = prog.len * width;
    if visited.len < need { visited.resize(need, false); }
    fill(visited[..need], false);
    var stack: Frame[>..<] = [];
    fill(slots, -1);
    stack.push(Frame.Explore { pc: re.entry, at: start });
    while stack.len > 0 {
        match stack.pop() {
            Restore r => { slots[r.slot] = r.old; },
            Explore x => {
                var pc = x.pc;
                var i = x.at;
                loop {
                    let k = pc * width + (i - start);
                    if visited[k] { break; }
                    visited[k] = true;
                    match prog[pc] {
                        Byte b => {
                            guard i < end && sets[b.set][text[i]] else { break; }
                            pc = b.next;
                            i++;
                        },
                        Split sp => {
                            stack.push(Frame.Explore { pc: sp.second, at: i });
                            pc = sp.first;
                        },
                        Save sv => {
                            stack.push(Frame.Restore { slot: sv.slot, old: slots[sv.slot] });
                            slots[sv.slot] = i;
                            pc = sv.next;
                        },
                        Match => { return; },
                        Look l => {
                            guard holds(l.look, kind_before(text, i), kind_at(text, i)) else { break; }
                            pc = l.next;
                        },
                    }
                }
            },
        }
    }
}

// The capture slots of the match [start, end): from the groups' places
// where every group has a fixed one, and by backtracking where not.
fn captures(re: Regex&, text: u8[:], start: i64, end: i64, slots: i64[:], visited: bool[>..]&) {
    guard re.placed else { backtrack(re, text, start, end, slots, visited); return; }
    for &p, k in re.places {
        slots[2 * k] = if p.start_back { end - p.start } else { start + p.start };
        slots[2 * k + 1] = if p.end_back { end - p.end } else { start + p.end };
    }
}

// F(captures) for every match each_match finds, as the crate's
// captures_iter yields them. The slots are reused from match to match.
fn each_captures<F>(re: Regex&, text: u8[:]) {
    var slots: i64[>..] = [];
    slots.resize(2 * re.groups, -1);
    var visited: bool[>..] = [];
    each_match(re, text) { s, e =>
        captures(re, text, s, e, slots, visited);
        F(Captures { text: text, slots: slots });
    };
}

// Appends text to out with every match replaced by F(captures), as the
// crate's replace_all with a closure: the text between matches stays as it
// is.
fn format_replaced<F>(out: u8[>..]&, re: Regex&, text: u8[:]) {
    var last = 0;
    each_captures(re, text) { caps =>
        out.append(text[last..caps.slots[0]]);
        out.append(F(caps));
        last = caps.slots[1];
    };
    out.append(text[last..]);
}
