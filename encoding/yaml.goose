// YAML 1.2 (docs in README.md) as gopkg.in/yaml.v3 reads and writes it: a
// parser that builds a document tree in one pool, the core schema's
// resolution of plain scalars, a check that refuses what yaml.v3's decoder
// refuses (alias bombs, repeated keys, bad merges), a reader that walks the
// tree into the caller's own types, and a writer that appends a tree to a
// byte builder as yaml.v3's Marshal writes it. The parser is libyaml's
// scanner and parser, as yaml.v3 carries them, and yaml.v3's composer, so
// that it reads every stream as yaml.v3 does and refuses every stream it
// refuses, with the same message; since the error says where, it also has
// the line and column. The writer is libyaml's emitter, driven as yaml.v3's
// encoder drives it.

namespace yaml;

import std;
import dictionary;

// --- the document tree ----------------------------------------------------------

// The kinds of node, numbered as yaml.v3's Kind.
let DOCUMENT: u8 = 1;
let SEQUENCE: u8 = 2;
let MAPPING: u8 = 4;
let SCALAR: u8 = 8;
let ALIAS: u8 = 16;

// The bits of a node's style, as yaml.v3's Style: TAGGED when the tag was
// written, and how the node was written. A plain scalar and a block
// collection have none of the others.
let TAGGED: u8 = 1;
let DOUBLE_QUOTED: u8 = 2;
let SINGLE_QUOTED: u8 = 4;
let LITERAL: u8 = 8;
let FOLDED: u8 = 16;
let FLOW: u8 = 32;

// A stream is one grow-only pool of fixed-size nodes in text order, its
// documents linked by `next` from the first. A node is a link to its next
// sibling, a link to its first child (a document's is its root, a
// mapping's are its keys and values in turn), and for an alias the node
// its anchor names; its kind, style and number of children; where it
// starts, line and column from 1; and its tag, value and anchor, which are
// views of the text, or of the caller's buffer for those that had to be
// put together. The tag is yaml.v3's: the short form (!!str for
// tag:yaml.org,2002:str) of the tag written, or for a node without one
// the tag the core schema resolves it to; an alias has none, and its value
// is the name of the anchor. Links are 4-byte self-relative offsets.
struct Node {
    next: Node&<u32>?,
    first: Node&<u32>?,
    alias: Node&<u32>?,
    kind: u8,
    style: u8,
    count: i64,
    line: i64,
    column: i64,
    tag: const u8[:],
    value: const u8[:],
    anchor: const u8[:],
}

// What went wrong, and where: the line and column, from 1, of the
// character, token or node at fault. The message is yaml.v3's, word for
// word, line number and all ("yaml: line 3: did not find expected key");
// empty when nothing went wrong.
struct Error { line: i64 = 0, column: i64 = 0, message: u8[>..] }

// --- positions and characters --------------------------------------------------

// A position as libyaml counts it: characters from the start of the text,
// and line and column from 0.
struct Mark { index: i64 = 0, line: i64 = 0, column: i64 = 0 }

fn is_alpha(c: u8) -> bool {
    (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '-'
}

fn is_digit(c: u8) -> bool { c >= '0' && c <= '9' }

fn is_hex(c: u8) -> bool { (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') }

fn as_hex(c: u8) -> i64 {
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - '0';
}

// The length of the UTF-8 sequence that c starts; 0 if it starts none.
fn width(c: u8) -> i64 {
    if (c & 0x80) == 0 { return 1; }
    if (c & 0xE0) == 0xC0 { return 2; }
    if (c & 0xF0) == 0xE0 { return 3; }
    if (c & 0xF8) == 0xF0 { return 4; }
    return 0;
}

// --- the parser's state ---------------------------------------------------------

// Token kinds, in libyaml's order.
let T_STREAM_START = 1;
let T_STREAM_END = 2;
let T_VERSION_DIRECTIVE = 3;
let T_TAG_DIRECTIVE = 4;
let T_DOCUMENT_START = 5;
let T_DOCUMENT_END = 6;
let T_BLOCK_SEQUENCE_START = 7;
let T_BLOCK_MAPPING_START = 8;
let T_BLOCK_END = 9;
let T_FLOW_SEQUENCE_START = 10;
let T_FLOW_SEQUENCE_END = 11;
let T_FLOW_MAPPING_START = 12;
let T_FLOW_MAPPING_END = 13;
let T_BLOCK_ENTRY = 14;
let T_FLOW_ENTRY = 15;
let T_KEY = 16;
let T_VALUE = 17;
let T_ALIAS = 18;
let T_ANCHOR = 19;
let T_TAG = 20;
let T_SCALAR = 21;

// Scalar styles, as libyaml's.
let S_PLAIN = 1;
let S_SINGLE = 2;
let S_DOUBLE = 3;
let S_LITERAL = 4;
let S_FOLDED = 5;

// Where a token's or event's text is: bytes from..to of the text being
// scanned, or of `decoded` for text that was put together.
struct Span { from: i64 = 0, to: i64 = 0, decoded: bool = false }

// A token: an anchor's or alias's name, a tag's handle and suffix, a
// %TAG directive's handle and prefix, a scalar's text and style, a %YAML
// directive's version.
struct Token {
    kind: i64,
    start: Mark,
    end: Mark,
    value: Span = Span { .. },
    suffix: Span = Span { .. },
    style: i64 = 0,
    major: i64 = 0,
    minor: i64 = 0,
}

// A place where a simple key (one without '?') may start, while the ':'
// that would make it one may still come.
struct SimpleKey { possible: bool, required: bool, token_number: i64, mark: Mark }

struct TagDirective { handle: Span, prefix: Span }

// Event kinds.
let E_STREAM_START = 1;
let E_STREAM_END = 2;
let E_DOCUMENT_START = 3;
let E_DOCUMENT_END = 4;
let E_ALIAS = 5;
let E_SCALAR = 6;
let E_SEQUENCE_START = 7;
let E_SEQUENCE_END = 8;
let E_MAPPING_START = 9;
let E_MAPPING_END = 10;

struct Event {
    kind: i64,
    start: Mark,
    end: Mark,
    anchor: Span = Span { .. },
    tag: Span = Span { .. },
    value: Span = Span { .. },
    implicit: bool = false,
    quoted_implicit: bool = false,
    style: i64 = 0,
    flow: bool = false,
}

// Parser states, in libyaml's order.
let P_STREAM_START = 0;
let P_IMPLICIT_DOCUMENT_START = 1;
let P_DOCUMENT_START = 2;
let P_DOCUMENT_CONTENT = 3;
let P_DOCUMENT_END = 4;
let P_BLOCK_NODE = 5;
let P_BLOCK_NODE_OR_INDENTLESS_SEQUENCE = 6;
let P_FLOW_NODE = 7;
let P_BLOCK_SEQUENCE_FIRST_ENTRY = 8;
let P_BLOCK_SEQUENCE_ENTRY = 9;
let P_INDENTLESS_SEQUENCE_ENTRY = 10;
let P_BLOCK_MAPPING_FIRST_KEY = 11;
let P_BLOCK_MAPPING_KEY = 12;
let P_BLOCK_MAPPING_VALUE = 13;
let P_FLOW_SEQUENCE_FIRST_ENTRY = 14;
let P_FLOW_SEQUENCE_ENTRY = 15;
let P_FLOW_SEQUENCE_ENTRY_MAPPING_KEY = 16;
let P_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE = 17;
let P_FLOW_SEQUENCE_ENTRY_MAPPING_END = 18;
let P_FLOW_MAPPING_FIRST_KEY = 19;
let P_FLOW_MAPPING_KEY = 20;
let P_FLOW_MAPPING_VALUE = 21;
let P_FLOW_MAPPING_EMPTY_VALUE = 22;
let P_END = 23;

// The input encodings.
let ENC_ANY = 0;
let ENC_UTF8 = 1;
let ENC_UTF16LE = 2;
let ENC_UTF16BE = 3;

// yaml.v3's reader decodes the raw text this many bytes at a time, and
// refuses a character that is not allowed when it decodes it, so this one
// does too: which error a stream gets, when it has two, depends on it.
let RAW_CHUNK = 512;

// The deepest nesting of flow collections, and of block indentation, that
// yaml.v3 reads: deeper is "exceeded max depth of 10000".
let MAX_DEPTH = 10000;

// The scanner, parser and composer, all of them: the text, as UTF-8, and
// where they are in it; yaml.v3's reader emulated (how much raw text it has
// read and decoded, and the first byte of its buffer, which its BOM test
// looks at); the scanner's queue of tokens and its stacks of indentation
// and simple keys; the parser's stacks of states and marks and its tag
// directives; and the buffer that tags and scalars that had to be put
// together go to. Errors leave through `return … from compose`.
struct Parser {
    buf: const u8[:],
    pos: i64 = 0,
    mark: Mark,
    raw: const u8[:],
    encoding: i64 = 0,
    raw_win: i64 = 0,
    raw_pos: i64 = 0,
    raw_end: i64 = 0,
    out_pos: i64 = 0,
    eof: bool = false,
    unread: i64 = 0,
    buf_start: i64 = 0,
    stream_start_produced: bool = false,
    stream_end_produced: bool = false,
    token_available: bool = false,
    tokens_head: i64 = 0,
    tokens_parsed: i64 = 0,
    last_kind: i64 = 0,
    flow_level: i64 = 0,
    indent: i64 = 0,
    simple_key_allowed: bool = false,
    newlines: i64 = 0,
    state: i64 = 0,
    first_doc: i64 = -1,
    buf_base: i64 = -1,
    bang: Span = Span { .. },
    bangbang: Span = Span { .. },
    core_prefix: Span = Span { .. },
    tokens: Token[>..<]&,
    indents: i64[>..<]&,
    simple_keys: SimpleKey[>..<]&,
    keys_by_token: dictionary<i64, i64>&,
    states: i64[>..<]&,
    marks: Mark[>..<]&,
    directives: TagDirective[>..<]&,
    decoded: u8[>..]&,
}

// The bytes of span s, for the scanner and parser to look at.
fn view<P>(p: P&, s: Span) -> const u8[:] { if s.decoded { p.decoded[s.from..s.to] } else { p.buf[s.from..s.to] } }

// The span of bytes from..to of the text being scanned, which for UTF-16
// text is in `decoded`.
fn buf_span<P>(p: P&, from: i64, to: i64) -> Span {
    if p.buf_base < 0 { return Span { from: from, to: to }; }
    return Span { from: p.buf_base + from, to: p.buf_base + to, decoded: true };
}

// The span of what was pushed onto `decoded` since `first`.
fn decoded_span<P>(p: P&, first: i64) -> Span { Span { from: first, to: p.decoded.len, decoded: true } }

// The byte at i of the text, or 0 past its end, where libyaml's buffer
// holds the NUL that ends the text.
fn at<P>(p: P&, i: i64) -> u8 { if i < p.buf.len { p.buf[i] } else { 0 } }

fn here<P>(p: P&) -> u8 { at(p, p.pos) }

fn is_blank_at<P>(p: P&, i: i64) -> bool { let c = at(p, i); c == ' ' || c == '\t' }

fn is_break_at<P>(p: P&, i: i64) -> bool {
    let c = at(p, i);
    if c == '\r' || c == '\n' { return true; }
    if c == 0xC2 { return at(p, i + 1) == 0x85; }
    if c == 0xE2 { return at(p, i + 1) == 0x80 && (at(p, i + 2) == 0xA8 || at(p, i + 2) == 0xA9); }
    return false;
}

fn is_z_at<P>(p: P&, i: i64) -> bool { i >= p.buf.len }

fn is_breakz_at<P>(p: P&, i: i64) -> bool { is_z_at(p, i) || is_break_at(p, i) }

fn is_blankz_at<P>(p: P&, i: i64) -> bool { is_blank_at(p, i) || is_breakz_at(p, i) }

fn is_blank_here<P>(p: P&) -> bool { is_blank_at(p, p.pos) }
fn is_break_here<P>(p: P&) -> bool { is_break_at(p, p.pos) }
fn is_breakz_here<P>(p: P&) -> bool { is_breakz_at(p, p.pos) }
fn is_blankz_here<P>(p: P&) -> bool { is_blankz_at(p, p.pos) }

// yaml.v3's test for a byte order mark, which looks at the first bytes of
// its buffer, not at the cursor: where the buffer starts with one, the
// character at the cursor is passed over at the start of every line.
fn is_bom<P>(p: P&) -> bool {
    at(p, p.buf_start) == 0xEF && at(p, p.buf_start + 1) == 0xBB && at(p, p.buf_start + 2) == 0xBF
}

// --- errors ---------------------------------------------------------------------

// The error message as yaml.v3 words it: "yaml: line N: " and the problem,
// N the context's line, else the problem's, counted from 0, but from 1 for
// the scanner's errors; no line where that comes to 0.
fn fail(context_mark: Mark, problem_mark: Mark, problem: const u8[:], scanner: bool) {
    var line = 0;
    if context_mark.line != 0 {
        line = context_mark.line;
        if scanner { line++; }
    } else if problem_mark.line != 0 {
        line = problem_mark.line;
        if scanner { line++; }
    }
    let where = Error { line: problem_mark.line + 1, column: problem_mark.column + 1, message: [] };
    if line != 0 {
        return Error { line: where.line, column: where.column, message: str("yaml: line ", line, ": ", problem) } from compose;
    }
    return Error { line: where.line, column: where.column, message: str("yaml: ", problem) } from compose;
}

fn scanner_error<P>(p: P&, context_mark: Mark, problem: const u8[:]) {
    fail(context_mark, p.mark, problem, true);
}

fn parser_error<P>(p: P&, problem: const u8[:], problem_mark: Mark) {
    fail(Mark { .. }, problem_mark, problem, false);
}

fn parser_error_context<P>(p: P&, context_mark: Mark, problem: const u8[:], problem_mark: Mark) {
    fail(context_mark, problem_mark, problem, false);
}

// An error yaml.v3's composer or decoder finds, at node or event mark m.
fn failf(m: Mark, what: const u8[:]) {
    return Error { line: m.line + 1, column: m.column + 1, message: str("yaml: ", what) } from compose;
}

// --- reading the characters -----------------------------------------------------

// The next read of raw text into yaml.v3's 512-byte raw buffer: what is
// left in it moves to its front and the rest fills from the text. A read
// at the end of the text is the end of input.
fn update_raw<P>(p: P&) {
    if p.raw_pos == p.raw_win && p.raw_end - p.raw_win == RAW_CHUNK { return; }
    if p.eof { return; }
    p.raw_win = p.raw_pos;
    if p.raw_end == p.raw.len {
        p.eof = true;
        return;
    }
    p.raw_end = min(p.raw.len, p.raw_win + RAW_CHUNK);
}

// Makes sure `length` characters past the cursor are decoded, as yaml.v3's
// cache(): when fewer are, its buffer moves to start at the cursor, and it
// decodes all the raw text it has, reading more until it has enough or the
// text ends. A character that is not allowed fails the stream when it is
// decoded.
fn cache<P>(p: P&, length: i64) {
    if p.unread >= length { return; }
    p.buf_start = p.pos;
    var first = true;
    while p.unread < length {
        if !first || p.raw_pos == p.raw_end { update_raw(p); }
        first = false;
        while p.raw_pos != p.raw_end {
            let w, out = decode_char(p);
            if w == 0 { break; }
            p.raw_pos += w;
            p.out_pos += out;
            p.unread++;
        }
        if p.eof {
            p.unread++;
            break;
        }
    }
}

// The raw width of the character at raw_pos and its width as UTF-8, after
// the checks yaml.v3's reader makes; 0, 0 for a character the raw buffer
// holds only part of while there is more text to read.
fn decode_char<P>(p: P&) -> i64, i64 {
    let r = p.raw;
    let i = p.raw_pos;
    let avail = p.raw_end - i;
    var value = 0;
    var w = 0;
    if p.encoding == ENC_UTF8 {
        let octet = r[i];
        w = width(octet);
        guard w > 0 else { reader_error(p, "invalid leading UTF-8 octet"); }
        if w > avail {
            guard !p.eof else { reader_error(p, "incomplete UTF-8 octet sequence"); }
            return 0, 0;
        }
        value = if w == 1 { octet & 0x7F } else if w == 2 { octet & 0x1F } else if w == 3 { octet & 0x0F } else { octet & 0x07 };
        for k in 1..w {
            let o = r[i + k];
            guard (o & 0xC0) == 0x80 else { reader_error(p, "invalid trailing UTF-8 octet"); }
            value = (value << 6) + (o & 0x3F);
        }
        guard w == 1 || (w == 2 && value >= 0x80) || (w == 3 && value >= 0x800) || (w == 4 && value >= 0x10000) else {
            reader_error(p, "invalid length of a UTF-8 sequence");
        }
        guard !((value >= 0xD800 && value <= 0xDFFF) || value > 0x10FFFF) else { reader_error(p, "invalid Unicode character"); }
    } else {
        let low = if p.encoding == ENC_UTF16LE { 0 } else { 1 };
        let high = 1 - low;
        if avail < 2 {
            guard !p.eof else { reader_error(p, "incomplete UTF-16 character"); }
            return 0, 0;
        }
        value = r[i + low] + ((r[i + high] as i64) << 8);
        guard (value & 0xFC00) != 0xDC00 else { reader_error(p, "unexpected low surrogate area"); }
        if (value & 0xFC00) == 0xD800 {
            w = 4;
            if avail < 4 {
                guard !p.eof else { reader_error(p, "incomplete UTF-16 surrogate pair"); }
                return 0, 0;
            }
            let value2 = r[i + low + 2] + ((r[i + high + 2] as i64) << 8);
            guard (value2 & 0xFC00) == 0xDC00 else { reader_error(p, "expected low surrogate area"); }
            value = 0x10000 + ((value & 0x3FF) << 10) + (value2 & 0x3FF);
        } else {
            w = 2;
        }
    }
    guard value == 0x09 || value == 0x0A || value == 0x0D || (value >= 0x20 && value <= 0x7E) || value == 0x85
          || (value >= 0xA0 && value <= 0xD7FF) || (value >= 0xE000 && value <= 0xFFFD) || (value >= 0x10000 && value <= 0x10FFFF) else {
        reader_error(p, "control characters are not allowed");
    }
    let out = if value <= 0x7F { 1 } else if value <= 0x7FF { 2 } else if value <= 0xFFFF { 3 } else { 4 };
    return w, out;
}

// A reader error: yaml.v3 gives no line for one; the error has the line
// and column of the character, in the text decoded so far.
fn reader_error<P>(p: P&, problem: const u8[:]) {
    let m = mark_of(p.buf, p.mark, p.pos, p.out_pos);
    return Error { line: m.line + 1, column: m.column + 1, message: str("yaml: ", problem) } from compose;
}

// The mark of byte `to` of text, counting from mark m at byte `from`.
fn mark_of(text: const u8[:], m: Mark, from: i64, to: i64) -> Mark {
    var r = m;
    var i = from;
    while i < to && i < text.len {
        let c = text[i];
        if c == '\r' && i + 1 < text.len && text[i + 1] == '\n' {
            r.index += 2; r.line++; r.column = 0; i += 2;
        } else if c == '\r' || c == '\n' {
            r.index++; r.line++; r.column = 0; i++;
        } else if c == 0xC2 && i + 1 < text.len && text[i + 1] == 0x85 {
            r.index++; r.line++; r.column = 0; i += 2;
        } else if c == 0xE2 && i + 2 < text.len && text[i + 1] == 0x80 && (text[i + 2] == 0xA8 || text[i + 2] == 0xA9) {
            r.index++; r.line++; r.column = 0; i += 3;
        } else {
            r.index++; r.column++; i += max(1, width(c));
        }
    }
    return r;
}

// --- the scanner ----------------------------------------------------------------

// Past one character that is not a line break.
fn skip<P>(p: P&) {
    if !is_blank_here(p) { p.newlines = 0; }
    p.mark.index++;
    p.mark.column++;
    p.unread--;
    p.pos += max(1, width(here(p)));
}

// Past one line break, CR LF being one.
fn skip_line<P>(p: P&) {
    if here(p) == '\r' && at(p, p.pos + 1) == '\n' {
        p.mark.index += 2;
        p.mark.column = 0;
        p.mark.line++;
        p.unread -= 2;
        p.pos += 2;
        p.newlines++;
    } else if is_break_here(p) {
        p.mark.index++;
        p.mark.column = 0;
        p.mark.line++;
        p.unread--;
        p.pos += width(here(p));
        p.newlines++;
    }
}

// The character at the cursor onto s, and past it.
fn read<P>(p: P&, s: u8[>..]&) {
    if !is_blank_here(p) { p.newlines = 0; }
    let w = max(1, width(here(p)));
    s.append(p.buf[p.pos..p.pos + w]);
    p.pos += w;
    p.mark.index++;
    p.mark.column++;
    p.unread--;
}

// The line break at the cursor onto s, CR, LF, CR LF and NEL as '\n',
// LS and PS as they are, and past it.
fn read_line<P>(p: P&, s: u8[>..]&) {
    let c = here(p);
    if c == '\r' && at(p, p.pos + 1) == '\n' {
        s.push('\n');
        p.pos += 2;
        p.mark.index++;
        p.unread--;
    } else if c == '\r' || c == '\n' {
        s.push('\n');
        p.pos += 1;
    } else if c == 0xC2 && at(p, p.pos + 1) == 0x85 {
        s.push('\n');
        p.pos += 2;
    } else if c == 0xE2 && at(p, p.pos + 1) == 0x80 && (at(p, p.pos + 2) == 0xA8 || at(p, p.pos + 2) == 0xA9) {
        s.append(p.buf[p.pos..p.pos + 3]);
        p.pos += 3;
    } else {
        return;
    }
    p.mark.index++;
    p.mark.column = 0;
    p.mark.line++;
    p.unread--;
    p.newlines++;
}

// The token at the head of the queue, scanning as far ahead as yaml.v3
// does: at least three tokens, and past a simple key that may still turn
// out to be one.
fn peek_token<P>(p: P&) -> Token {
    if !p.token_available { fetch_more_tokens(p); }
    return p.tokens[p.tokens_head];
}

fn skip_token<P>(p: P&) {
    p.token_available = false;
    p.tokens_parsed++;
    p.stream_end_produced = p.tokens[p.tokens_head].kind == T_STREAM_END;
    p.tokens_head++;
    if p.tokens_head == p.tokens.len {
        p.tokens.clear();
        p.tokens_head = 0;
    }
}

// t into the queue, pos tokens after its head, or at its end for -1.
fn insert_token<P>(p: P&, pos: i64, t: Token) {
    if pos < 0 {
        p.tokens.push(t);
        p.last_kind = t.kind;
    } else {
        insert_at(p.tokens, p.tokens_head + pos, t);
    }
}

fn fetch_more_tokens<P>(p: P&) {
    loop {
        if p.tokens_head < p.tokens.len - 2 {
            let k = p.keys_by_token.get(p.tokens_parsed);
            guard k else { break; }
            let i = k;
            if !simple_key_is_valid(p, i) { break; }
        }
        fetch_next_token(p);
    }
    p.token_available = true;
}

fn fetch_next_token<P>(p: P&) {
    cache(p, 1);
    if !p.stream_start_produced {
        fetch_stream_start(p);
        return;
    }
    let scan_mark = p.mark;
    scan_to_next_token(p);
    unroll_indent(p, p.mark.column, scan_mark);
    cache(p, 4);
    if is_z_at(p, p.pos) {
        fetch_stream_end(p);
        return;
    }
    let c = here(p);
    if p.mark.column == 0 && c == '%' {
        fetch_directive(p);
        return;
    }
    if p.mark.column == 0 && c == '-' && at(p, p.pos + 1) == '-' && at(p, p.pos + 2) == '-' && is_blankz_at(p, p.pos + 3) {
        fetch_document_indicator(p, T_DOCUMENT_START);
        return;
    }
    if p.mark.column == 0 && c == '.' && at(p, p.pos + 1) == '.' && at(p, p.pos + 2) == '.' && is_blankz_at(p, p.pos + 3) {
        fetch_document_indicator(p, T_DOCUMENT_END);
        return;
    }
    fetch_token(p, c);
    // yaml.v3 reads a comment on the rest of the line as the token's,
    // after any token but a block entry: that it passes it over here, tabs
    // and all, is what counts.
    if p.last_kind != T_BLOCK_ENTRY { scan_line_comment(p); }
}

fn fetch_token<P>(p: P&, c: u8) {
    if c == '[' { fetch_flow_collection_start(p, T_FLOW_SEQUENCE_START); return; }
    if c == '{' { fetch_flow_collection_start(p, T_FLOW_MAPPING_START); return; }
    if c == ']' { fetch_flow_collection_end(p, T_FLOW_SEQUENCE_END); return; }
    if c == '}' { fetch_flow_collection_end(p, T_FLOW_MAPPING_END); return; }
    if c == ',' { fetch_flow_entry(p); return; }
    let next_blankz = is_blankz_at(p, p.pos + 1);
    if c == '-' && next_blankz { fetch_block_entry(p); return; }
    if c == '?' && (p.flow_level > 0 || next_blankz) { fetch_key(p); return; }
    if c == ':' && (p.flow_level > 0 || next_blankz) { fetch_value(p); return; }
    if c == '*' { fetch_anchor(p, T_ALIAS); return; }
    if c == '&' { fetch_anchor(p, T_ANCHOR); return; }
    if c == '!' { fetch_tag(p); return; }
    if c == '|' && p.flow_level == 0 { fetch_block_scalar(p, true); return; }
    if c == '>' && p.flow_level == 0 { fetch_block_scalar(p, false); return; }
    if c == '\'' { fetch_flow_scalar(p, true); return; }
    if c == '"' { fetch_flow_scalar(p, false); return; }
    let indicator = is_blankz_here(p) || c == '-' || c == '?' || c == ':' || c == ',' || c == '[' || c == ']'
                    || c == '{' || c == '}' || c == '#' || c == '&' || c == '*' || c == '!' || c == '|' || c == '>'
                    || c == '\'' || c == '"' || c == '%' || c == '@' || c == '`';
    if !indicator || (c == '-' && !is_blank_at(p, p.pos + 1))
       || (p.flow_level == 0 && (c == '?' || c == ':') && !next_blankz) {
        fetch_plain_scalar(p);
        return;
    }
    scanner_error(p, p.mark, "found character that cannot start any token");
}

// Whether simple key i can still be one: on the line it started on and
// within 1024 characters of it. A required one that cannot is an error.
fn simple_key_is_valid<P>(p: P&, i: i64) -> bool {
    let k = p.simple_keys[i];
    if !k.possible { return false; }
    if k.mark.line < p.mark.line || k.mark.index + 1024 < p.mark.index {
        if k.required { scanner_error(p, k.mark, "could not find expected ':'"); }
        p.simple_keys[i].possible = false;
        return false;
    }
    return true;
}

fn save_simple_key<P>(p: P&) {
    let required = p.flow_level == 0 && p.indent == p.mark.column;
    if p.simple_key_allowed {
        let k = SimpleKey { possible: true, required: required,
                            token_number: p.tokens_parsed + (p.tokens.len - p.tokens_head), mark: p.mark };
        remove_simple_key(p);
        p.simple_keys[p.simple_keys.len - 1] = k;
        p.keys_by_token.insert(k.token_number, p.simple_keys.len - 1);
    }
}

fn remove_simple_key<P>(p: P&) {
    let i = p.simple_keys.len - 1;
    if p.simple_keys[i].possible {
        if p.simple_keys[i].required { scanner_error(p, p.simple_keys[i].mark, "could not find expected ':'"); }
        p.simple_keys[i].possible = false;
        p.keys_by_token.remove(p.simple_keys[i].token_number);
    }
}

fn increase_flow_level<P>(p: P&) {
    p.simple_keys.push(SimpleKey { possible: false, required: false,
                                   token_number: p.tokens_parsed + (p.tokens.len - p.tokens_head), mark: p.mark });
    p.flow_level++;
    if p.flow_level > MAX_DEPTH {
        scanner_error(p, p.simple_keys[p.simple_keys.len - 1].mark, "exceeded max depth of 10000");
    }
}

fn decrease_flow_level<P>(p: P&) {
    if p.flow_level > 0 {
        p.flow_level--;
        let last = p.simple_keys.len - 1;
        p.keys_by_token.remove(p.simple_keys[last].token_number);
        p.simple_keys.pop();
    }
}

// A deeper block indentation at column: the token that starts the
// collection goes in at number (a token number), or at the end for -1.
fn roll_indent<P>(p: P&, column: i64, number: i64, kind: i64, m: Mark) {
    if p.flow_level > 0 { return; }
    if p.indent < column {
        p.indents.push(p.indent);
        p.indent = column;
        if p.indents.len > MAX_DEPTH {
            scanner_error(p, p.simple_keys[p.simple_keys.len - 1].mark, "exceeded max depth of 10000");
        }
        let at = if number > -1 { number - p.tokens_parsed } else { number };
        insert_token(p, at, Token { kind: kind, start: m, end: m, .. });
    }
}

// The block collections deeper than column end. (yaml.v3 moves the end's
// mark to a comment above it; no node's position depends on it.)
fn unroll_indent<P>(p: P&, column: i64, scan_mark: Mark) {
    if p.flow_level > 0 { return; }
    var block_mark = scan_mark;
    block_mark.index--;
    while p.indent > column {
        insert_token(p, -1, Token { kind: T_BLOCK_END, start: block_mark, end: block_mark, .. });
        p.indent = p.indents[p.indents.len - 1];
        p.indents.pop();
    }
}

fn fetch_stream_start<P>(p: P&) {
    p.indent = -1;
    p.simple_keys.push(SimpleKey { possible: false, required: false, token_number: 0, mark: Mark { .. } });
    p.simple_key_allowed = true;
    p.stream_start_produced = true;
    insert_token(p, -1, Token { kind: T_STREAM_START, start: p.mark, end: p.mark, .. });
}

fn fetch_stream_end<P>(p: P&) {
    if p.mark.column != 0 {
        p.mark.column = 0;
        p.mark.line++;
    }
    unroll_indent(p, -1, p.mark);
    remove_simple_key(p);
    p.simple_key_allowed = false;
    insert_token(p, -1, Token { kind: T_STREAM_END, start: p.mark, end: p.mark, .. });
}

fn fetch_directive<P>(p: P&) {
    unroll_indent(p, -1, p.mark);
    remove_simple_key(p);
    p.simple_key_allowed = false;
    insert_token(p, -1, scan_directive(p));
}

fn fetch_document_indicator<P>(p: P&, kind: i64) {
    unroll_indent(p, -1, p.mark);
    remove_simple_key(p);
    p.simple_key_allowed = false;
    let start = p.mark;
    skip(p);
    skip(p);
    skip(p);
    insert_token(p, -1, Token { kind: kind, start: start, end: p.mark, .. });
}

fn fetch_flow_collection_start<P>(p: P&, kind: i64) {
    save_simple_key(p);
    increase_flow_level(p);
    p.simple_key_allowed = true;
    let start = p.mark;
    skip(p);
    insert_token(p, -1, Token { kind: kind, start: start, end: p.mark, .. });
}

fn fetch_flow_collection_end<P>(p: P&, kind: i64) {
    remove_simple_key(p);
    decrease_flow_level(p);
    p.simple_key_allowed = false;
    let start = p.mark;
    skip(p);
    insert_token(p, -1, Token { kind: kind, start: start, end: p.mark, .. });
}

fn fetch_flow_entry<P>(p: P&) {
    remove_simple_key(p);
    p.simple_key_allowed = true;
    let start = p.mark;
    skip(p);
    insert_token(p, -1, Token { kind: T_FLOW_ENTRY, start: start, end: p.mark, .. });
}

fn fetch_block_entry<P>(p: P&) {
    if p.flow_level == 0 {
        if !p.simple_key_allowed { scanner_error(p, p.mark, "block sequence entries are not allowed in this context"); }
        roll_indent(p, p.mark.column, -1, T_BLOCK_SEQUENCE_START, p.mark);
    }
    remove_simple_key(p);
    p.simple_key_allowed = true;
    let start = p.mark;
    skip(p);
    insert_token(p, -1, Token { kind: T_BLOCK_ENTRY, start: start, end: p.mark, .. });
}

fn fetch_key<P>(p: P&) {
    if p.flow_level == 0 {
        if !p.simple_key_allowed { scanner_error(p, p.mark, "mapping keys are not allowed in this context"); }
        roll_indent(p, p.mark.column, -1, T_BLOCK_MAPPING_START, p.mark);
    }
    remove_simple_key(p);
    p.simple_key_allowed = p.flow_level == 0;
    let start = p.mark;
    skip(p);
    insert_token(p, -1, Token { kind: T_KEY, start: start, end: p.mark, .. });
}

fn fetch_value<P>(p: P&) {
    let i = p.simple_keys.len - 1;
    if simple_key_is_valid(p, i) {
        let k = p.simple_keys[i];
        insert_token(p, k.token_number - p.tokens_parsed, Token { kind: T_KEY, start: k.mark, end: k.mark, .. });
        roll_indent(p, k.mark.column, k.token_number, T_BLOCK_MAPPING_START, k.mark);
        p.simple_keys[i].possible = false;
        p.keys_by_token.remove(k.token_number);
        p.simple_key_allowed = false;
    } else {
        if p.flow_level == 0 {
            if !p.simple_key_allowed { scanner_error(p, p.mark, "mapping values are not allowed in this context"); }
            roll_indent(p, p.mark.column, -1, T_BLOCK_MAPPING_START, p.mark);
        }
        p.simple_key_allowed = p.flow_level == 0;
    }
    let start = p.mark;
    skip(p);
    insert_token(p, -1, Token { kind: T_VALUE, start: start, end: p.mark, .. });
}

fn fetch_anchor<P>(p: P&, kind: i64) {
    save_simple_key(p);
    p.simple_key_allowed = false;
    insert_token(p, -1, scan_anchor(p, kind));
}

fn fetch_tag<P>(p: P&) {
    save_simple_key(p);
    p.simple_key_allowed = false;
    insert_token(p, -1, scan_tag(p));
}

fn fetch_block_scalar<P>(p: P&, literal: bool) {
    remove_simple_key(p);
    p.simple_key_allowed = true;
    insert_token(p, -1, scan_block_scalar(p, literal));
}

fn fetch_flow_scalar<P>(p: P&, single: bool) {
    save_simple_key(p);
    p.simple_key_allowed = false;
    insert_token(p, -1, scan_flow_scalar(p, single));
}

fn fetch_plain_scalar<P>(p: P&) {
    save_simple_key(p);
    p.simple_key_allowed = false;
    insert_token(p, -1, scan_plain_scalar(p));
}

// Past white space, line breaks and comments to the next token. A tab
// counts as white space only in a flow collection or where a simple key
// may not start.
fn scan_to_next_token<P>(p: P&) {
    loop {
        cache(p, 1);
        if p.mark.column == 0 && is_bom(p) { skip(p); }
        cache(p, 1);
        while here(p) == ' ' || ((p.flow_level > 0 || !p.simple_key_allowed) && here(p) == '\t') {
            skip(p);
            cache(p, 1);
        }
        if here(p) == '#' { scan_comments(p); }
        if is_break_here(p) {
            cache(p, 2);
            skip_line(p);
            if p.flow_level == 0 { p.simple_key_allowed = true; }
        } else {
            break;
        }
    }
}

// Past a comment at the cursor and the comment lines after it, as
// yaml.v3's comment scanner goes past them: up to the end of the last
// comment of the run, with only white space, line breaks, and in a flow
// collection a closing bracket, between them, looking at most 512 bytes
// ahead for the next. (yaml.v3 keeps the comments, for its nodes' head,
// line and foot comments; this passes them over.)
fn scan_comments<P>(p: P&) {
    var peek = 0;
    while peek < 512 {
        cache(p, peek + 1);
        let c = at(p, p.pos + peek);
        if c == ' ' || c == '\t' { peek++; continue; }
        let close_flow = p.flow_level > 0 && (c == ']' || c == '}');
        if close_flow || is_breakz_at(p, p.pos + peek) {
            if !is_break_at(p, p.pos + peek) { break; }
            peek++;
            continue;
        }
        if c != '#' { break; }
        consume_comment(p, p.mark.index + peek);
        peek = 1;
    }
}

// Past everything up to character `seen`, and from there to the end of
// its line.
fn consume_comment<P>(p: P&, seen: i64) {
    loop {
        cache(p, 1);
        if is_breakz_here(p) {
            if p.mark.index >= seen { break; }
            cache(p, 2);
            skip_line(p);
        } else {
            skip(p);
        }
    }
}

// Past a comment on the rest of the line, unless a line break has been
// passed since the last token.
fn scan_line_comment<P>(p: P&) {
    if p.newlines > 0 { return; }
    for peek in 512 {
        cache(p, peek + 1);
        if is_blank_at(p, p.pos + peek) { continue; }
        if at(p, p.pos + peek) == '#' { consume_comment(p, p.mark.index + peek); }
        break;
    }
}

// --- directives, anchors and tags -----------------------------------------------

fn scan_directive<P>(p: P&) -> Token {
    let start = p.mark;
    skip(p);
    let name = scan_directive_name(p, start);
    var t = Token { kind: 0, start: start, end: start, .. };
    if name == "YAML" {
        let major, minor = scan_version_directive_value(p, start);
        t = Token { kind: T_VERSION_DIRECTIVE, start: start, end: p.mark, major: major, minor: minor, .. };
    } else if name == "TAG" {
        let handle, prefix = scan_tag_directive_value(p, start);
        t = Token { kind: T_TAG_DIRECTIVE, start: start, end: p.mark, value: handle, suffix: prefix, .. };
    } else {
        scanner_error(p, start, "found unknown directive name");
    }
    cache(p, 1);
    while is_blank_here(p) {
        skip(p);
        cache(p, 1);
    }
    if here(p) == '#' {
        while !is_breakz_here(p) {
            skip(p);
            cache(p, 1);
        }
    }
    if !is_breakz_here(p) { scanner_error(p, start, "did not find expected comment or line break"); }
    if is_break_here(p) {
        cache(p, 2);
        skip_line(p);
    }
    return t;
}

fn scan_directive_name<P>(p: P&, start: Mark) -> const u8[:] {
    cache(p, 1);
    let from = p.pos;
    while is_alpha(here(p)) {
        skip(p);
        cache(p, 1);
    }
    if p.pos == from { scanner_error(p, start, "could not find expected directive name"); }
    if !is_blankz_here(p) { scanner_error(p, start, "found unexpected non-alphabetical character"); }
    return p.buf[from..p.pos];
}

fn scan_version_directive_value<P>(p: P&, start: Mark) -> i64, i64 {
    cache(p, 1);
    while is_blank_here(p) {
        skip(p);
        cache(p, 1);
    }
    let major = scan_version_directive_number(p, start);
    if here(p) != '.' { scanner_error(p, start, "did not find expected digit or '.' character"); }
    skip(p);
    let minor = scan_version_directive_number(p, start);
    return major, minor;
}

fn scan_version_directive_number<P>(p: P&, start: Mark) -> i64 {
    cache(p, 1);
    var value = 0;
    var length = 0;
    while is_digit(here(p)) {
        length++;
        if length > 2 { scanner_error(p, start, "found extremely long version number"); }
        value = value * 10 + (here(p) - '0');
        skip(p);
        cache(p, 1);
    }
    if length == 0 { scanner_error(p, start, "did not find expected version number"); }
    return value;
}

fn scan_tag_directive_value<P>(p: P&, start: Mark) -> Span, Span {
    cache(p, 1);
    while is_blank_here(p) {
        skip(p);
        cache(p, 1);
    }
    let handle = scan_tag_handle(p, true, start);
    cache(p, 1);
    if !is_blank_here(p) { scanner_error(p, start, "did not find expected whitespace"); }
    while is_blank_here(p) {
        skip(p);
        cache(p, 1);
    }
    let prefix = scan_tag_uri(p, true, Span { .. }, start);
    cache(p, 1);
    if !is_blankz_here(p) { scanner_error(p, start, "did not find expected whitespace or line break"); }
    return handle, prefix;
}

fn scan_anchor<P>(p: P&, kind: i64) -> Token {
    let start = p.mark;
    skip(p);
    cache(p, 1);
    let from = p.pos;
    while is_alpha(here(p)) {
        skip(p);
        cache(p, 1);
    }
    let end = p.mark;
    let c = here(p);
    if p.pos == from || !(is_blankz_here(p) || c == '?' || c == ':' || c == ',' || c == ']' || c == '}' || c == '%' || c == '@' || c == '`') {
        scanner_error(p, start, "did not find expected alphabetic or numeric character");
    }
    return Token { kind: kind, start: start, end: end, value: buf_span(p, from, p.pos), .. };
}

fn scan_tag<P>(p: P&) -> Token {
    let start = p.mark;
    cache(p, 2);
    if at(p, p.pos + 1) == '<' {
        skip(p);
        skip(p);
        let verbatim = scan_tag_uri(p, false, Span { .. }, start);
        if here(p) != '>' { scanner_error(p, start, "did not find the expected '>'"); }
        skip(p);
        return tag_token(p, start, Span { .. }, verbatim);
    }
    let handle = scan_tag_handle(p, false, start);
    let h = view(p, handle);
    if h[0] == '!' && h.len > 1 && h[h.len - 1] == '!' {
        return tag_token(p, start, handle, scan_tag_uri(p, false, Span { .. }, start));
    }
    // A handle that is not one is the start of the suffix, after "!".
    let suffix = scan_tag_uri(p, false, handle, start);
    if suffix.to == suffix.from { return tag_token(p, start, Span { .. }, p.bang); }
    return tag_token(p, start, p.bang, suffix);
}

fn tag_token<P>(p: P&, start: Mark, handle: Span, suffix: Span) -> Token {
    cache(p, 1);
    if !is_blankz_here(p) { scanner_error(p, start, "did not find expected whitespace or line break"); }
    return Token { kind: T_TAG, start: start, end: p.mark, value: handle, suffix: suffix, .. };
}

fn scan_tag_handle<P>(p: P&, directive: bool, start: Mark) -> Span {
    cache(p, 1);
    if here(p) != '!' { scanner_error(p, start, "did not find expected '!'"); }
    let from = p.pos;
    skip(p);
    cache(p, 1);
    while is_alpha(here(p)) {
        skip(p);
        cache(p, 1);
    }
    if here(p) == '!' {
        skip(p);
    } else if directive && p.pos - from != 1 {
        scanner_error(p, start, "did not find expected '!'");
    }
    return buf_span(p, from, p.pos);
}

// A tag's URI, decoding %-escapes, after head without its first byte (a
// handle that was the start of the suffix).
fn scan_tag_uri<P>(p: P&, directive: bool, head: Span, start: Mark) -> Span {
    let first = p.decoded.len;
    let head_len = head.to - head.from;
    var has_tag = head_len > 0;
    if head_len > 1 {
        // (A view of the text, which is not `decoded`, or of what is in it
        // already.)
        let h = view(p, Span { from: head.from + 1, to: head.to, decoded: head.decoded });
        for c in h { p.decoded.push(c); }
    }
    cache(p, 1);
    loop {
        let c = here(p);
        guard is_alpha(c) || c == ';' || c == '/' || c == '?' || c == ':' || c == '@' || c == '&' || c == '=' || c == '+'
              || c == '$' || c == ',' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')'
              || c == '[' || c == ']' || c == '%' else { break; }
        if c == '%' { scan_uri_escapes(p, directive, start); } else { read(p, p.decoded); }
        cache(p, 1);
        has_tag = true;
    }
    if !has_tag { scanner_error(p, start, "did not find expected tag URI"); }
    return decoded_span(p, first);
}

fn scan_uri_escapes<P>(p: P&, directive: bool, start: Mark) {
    var w = 1024;
    while w > 0 {
        cache(p, 3);
        if !(here(p) == '%' && is_hex(at(p, p.pos + 1)) && is_hex(at(p, p.pos + 2))) {
            scanner_error(p, start, "did not find URI escaped octet");
        }
        let octet = ((as_hex(at(p, p.pos + 1)) << 4) + as_hex(at(p, p.pos + 2))) as! u8;
        if w == 1024 {
            w = width(octet);
            if w == 0 { scanner_error(p, start, "found an incorrect leading UTF-8 octet"); }
        } else if (octet & 0xC0) != 0x80 {
            scanner_error(p, start, "found an incorrect trailing UTF-8 octet");
        }
        p.decoded.push(octet);
        skip(p);
        skip(p);
        skip(p);
        w--;
    }
}

// --- scalars --------------------------------------------------------------------

// A block scalar, | or >, with its chomping and indentation indicators;
// its text goes to `decoded`.
fn scan_block_scalar<P>(p: P&, literal: bool) -> Token {
    let start = p.mark;
    skip(p);
    cache(p, 1);
    var chomping = 0;
    var increment = 0;
    if here(p) == '+' || here(p) == '-' {
        chomping = if here(p) == '+' { 1 } else { -1 };
        skip(p);
        cache(p, 1);
        if is_digit(here(p)) {
            if here(p) == '0' { scanner_error(p, start, "found an indentation indicator equal to 0"); }
            increment = here(p) - '0';
            skip(p);
        }
    } else if is_digit(here(p)) {
        if here(p) == '0' { scanner_error(p, start, "found an indentation indicator equal to 0"); }
        increment = here(p) - '0';
        skip(p);
        cache(p, 1);
        if here(p) == '+' || here(p) == '-' {
            chomping = if here(p) == '+' { 1 } else { -1 };
            skip(p);
        }
    }
    cache(p, 1);
    while is_blank_here(p) {
        skip(p);
        cache(p, 1);
    }
    if here(p) == '#' {
        scan_line_comment(p);
        while !is_breakz_here(p) {
            skip(p);
            cache(p, 1);
        }
    }
    if !is_breakz_here(p) { scanner_error(p, start, "did not find expected comment or line break"); }
    if is_break_here(p) {
        cache(p, 2);
        skip_line(p);
    }
    var end = p.mark;
    var indent = 0;
    if increment > 0 {
        indent = if p.indent >= 0 { p.indent + increment } else { increment };
    }
    let first = p.decoded.len;
    var leading_break: u8[>..] = [];
    var trailing_breaks: u8[>..] = [];
    indent, end = scan_block_scalar_breaks(p, indent, trailing_breaks, start);
    cache(p, 1);
    var leading_blank = false;
    var trailing_blank = false;
    while p.mark.column == indent && !is_z_at(p, p.pos) {
        trailing_blank = is_blank_here(p);
        if !literal && !leading_blank && !trailing_blank && leading_break.len > 0 && leading_break[0] == '\n' {
            if trailing_breaks.len == 0 { p.decoded.push(' '); }
        } else {
            p.decoded.append(leading_break);
        }
        leading_break.clear();
        p.decoded.append(trailing_breaks);
        trailing_breaks.clear();
        leading_blank = is_blank_here(p);
        while !is_breakz_here(p) {
            read(p, p.decoded);
            cache(p, 1);
        }
        cache(p, 2);
        read_line(p, leading_break);
        indent, end = scan_block_scalar_breaks(p, indent, trailing_breaks, start);
    }
    if chomping != -1 { p.decoded.append(leading_break); }
    if chomping == 1 { p.decoded.append(trailing_breaks); }
    return Token { kind: T_SCALAR, start: start, end: end, value: decoded_span(p, first),
                   style: if literal { S_LITERAL } else { S_FOLDED }, .. };
}

// Past the empty lines and indentation before a block scalar's next line,
// their breaks onto `breaks`; the indentation, worked out from the most
// indented of those lines when there was none, and the mark after the
// last break.
fn scan_block_scalar_breaks<P>(p: P&, indent0: i64, breaks: u8[>..]&, start: Mark) -> i64, Mark {
    var indent = indent0;
    var end = p.mark;
    var max_indent = 0;
    loop {
        cache(p, 1);
        while (indent == 0 || p.mark.column < indent) && here(p) == ' ' {
            skip(p);
            cache(p, 1);
        }
        if p.mark.column > max_indent { max_indent = p.mark.column; }
        if (indent == 0 || p.mark.column < indent) && here(p) == '\t' {
            scanner_error(p, start, "found a tab character where an indentation space is expected");
        }
        if !is_break_here(p) { break; }
        cache(p, 2);
        read_line(p, breaks);
        end = p.mark;
    }
    if indent == 0 {
        indent = max_indent;
        if indent < p.indent + 1 { indent = p.indent + 1; }
        if indent < 1 { indent = 1; }
    }
    return indent, end;
}

// A single- or double-quoted scalar, its escapes decoded and its lines
// folded; its text goes to `decoded`.
fn scan_flow_scalar<P>(p: P&, single: bool) -> Token {
    let start = p.mark;
    skip(p);
    let first = p.decoded.len;
    var leading_break: u8[>..] = [];
    var trailing_breaks: u8[>..] = [];
    var whitespaces: u8[>..] = [];
    loop {
        cache(p, 4);
        if p.mark.column == 0 && ((here(p) == '-' && at(p, p.pos + 1) == '-' && at(p, p.pos + 2) == '-')
                                  || (here(p) == '.' && at(p, p.pos + 1) == '.' && at(p, p.pos + 2) == '.'))
           && is_blankz_at(p, p.pos + 3) {
            scanner_error(p, start, "found unexpected document indicator");
        }
        if is_z_at(p, p.pos) { scanner_error(p, start, "found unexpected end of stream"); }
        var leading_blanks = false;
        while !is_blankz_here(p) {
            let c = here(p);
            if single && c == '\'' && at(p, p.pos + 1) == '\'' {
                p.decoded.push('\'');
                skip(p);
                skip(p);
            } else if single && c == '\'' {
                break;
            } else if !single && c == '"' {
                break;
            } else if !single && c == '\\' && is_break_at(p, p.pos + 1) {
                cache(p, 3);
                skip(p);
                skip_line(p);
                leading_blanks = true;
                break;
            } else if !single && c == '\\' {
                escape(p, start);
            } else {
                read(p, p.decoded);
            }
            cache(p, 2);
        }
        cache(p, 1);
        if single && here(p) == '\'' { break; }
        if !single && here(p) == '"' { break; }
        while is_blank_here(p) || is_break_here(p) {
            if is_blank_here(p) {
                if !leading_blanks { read(p, whitespaces); } else { skip(p); }
            } else {
                cache(p, 2);
                if !leading_blanks {
                    whitespaces.clear();
                    read_line(p, leading_break);
                    leading_blanks = true;
                } else {
                    read_line(p, trailing_breaks);
                }
            }
            cache(p, 1);
        }
        if leading_blanks {
            if leading_break.len > 0 && leading_break[0] == '\n' {
                if trailing_breaks.len == 0 { p.decoded.push(' '); } else { p.decoded.append(trailing_breaks); }
            } else {
                p.decoded.append(leading_break);
                p.decoded.append(trailing_breaks);
            }
            trailing_breaks.clear();
            leading_break.clear();
        } else {
            p.decoded.append(whitespaces);
            whitespaces.clear();
        }
    }
    skip(p);
    return Token { kind: T_SCALAR, start: start, end: p.mark, value: decoded_span(p, first),
                   style: if single { S_SINGLE } else { S_DOUBLE }, .. };
}

// The escape at the cursor in a double-quoted scalar, decoded onto
// `decoded`.
fn escape<P>(p: P&, start: Mark) {
    let e = at(p, p.pos + 1);
    var code_length = 0;
    if e == '0' { p.decoded.push(0); }
    else if e == 'a' { p.decoded.push(7); }
    else if e == 'b' { p.decoded.push(8); }
    else if e == 't' || e == '\t' { p.decoded.push(9); }
    else if e == 'n' { p.decoded.push(10); }
    else if e == 'v' { p.decoded.push(11); }
    else if e == 'f' { p.decoded.push(12); }
    else if e == 'r' { p.decoded.push(13); }
    else if e == 'e' { p.decoded.push(27); }
    else if e == ' ' || e == '"' || e == '\'' || e == '\\' { p.decoded.push(e); }
    else if e == 'N' { p.decoded.append("\xC2\x85"); }
    else if e == '_' { p.decoded.append("\xC2\xA0"); }
    else if e == 'L' { p.decoded.append("\xE2\x80\xA8"); }
    else if e == 'P' { p.decoded.append("\xE2\x80\xA9"); }
    else if e == 'x' { code_length = 2; }
    else if e == 'u' { code_length = 4; }
    else if e == 'U' { code_length = 8; }
    else { scanner_error(p, start, "found unknown escape character"); }
    skip(p);
    skip(p);
    if code_length > 0 {
        var value = 0;
        cache(p, code_length);
        for k in code_length {
            if !is_hex(at(p, p.pos + k)) { scanner_error(p, start, "did not find expected hexdecimal number"); }
            value = (value << 4) + as_hex(at(p, p.pos + k));
        }
        if (value >= 0xD800 && value <= 0xDFFF) || value > 0x10FFFF {
            scanner_error(p, start, "found invalid Unicode character escape code");
        }
        push_utf8(p.decoded, value);
        for k in code_length { skip(p); }
    }
}

// A plain scalar, its lines folded; its text goes to `decoded`. It ends at
// ": ", at " #", at a document marker, in a flow collection at ",?[]{}",
// and in a block at a line less indented than its block.
fn scan_plain_scalar<P>(p: P&) -> Token {
    let first = p.decoded.len;
    var leading_break: u8[>..] = [];
    var trailing_breaks: u8[>..] = [];
    var whitespaces: u8[>..] = [];
    var leading_blanks = false;
    let indent = p.indent + 1;
    let start = p.mark;
    var end = p.mark;
    loop {
        cache(p, 4);
        if p.mark.column == 0 && ((here(p) == '-' && at(p, p.pos + 1) == '-' && at(p, p.pos + 2) == '-')
                                  || (here(p) == '.' && at(p, p.pos + 1) == '.' && at(p, p.pos + 2) == '.'))
           && is_blankz_at(p, p.pos + 3) {
            break;
        }
        if here(p) == '#' { break; }
        while !is_blankz_here(p) {
            let c = here(p);
            if (c == ':' && is_blankz_at(p, p.pos + 1))
               || (p.flow_level > 0 && (c == ',' || c == '?' || c == '[' || c == ']' || c == '{' || c == '}')) {
                break;
            }
            if leading_blanks || whitespaces.len > 0 {
                if leading_blanks {
                    if leading_break[0] == '\n' {
                        if trailing_breaks.len == 0 { p.decoded.push(' '); } else { p.decoded.append(trailing_breaks); }
                    } else {
                        p.decoded.append(leading_break);
                        p.decoded.append(trailing_breaks);
                    }
                    trailing_breaks.clear();
                    leading_break.clear();
                    leading_blanks = false;
                } else {
                    p.decoded.append(whitespaces);
                    whitespaces.clear();
                }
            }
            read(p, p.decoded);
            end = p.mark;
            cache(p, 2);
        }
        if !(is_blank_here(p) || is_break_here(p)) { break; }
        cache(p, 1);
        while is_blank_here(p) || is_break_here(p) {
            if is_blank_here(p) {
                if leading_blanks && p.mark.column < indent && here(p) == '\t' {
                    scanner_error(p, start, "found a tab character that violates indentation");
                }
                if !leading_blanks { read(p, whitespaces); } else { skip(p); }
            } else {
                cache(p, 2);
                if !leading_blanks {
                    whitespaces.clear();
                    read_line(p, leading_break);
                    leading_blanks = true;
                } else {
                    read_line(p, trailing_breaks);
                }
            }
            cache(p, 1);
        }
        if p.flow_level == 0 && p.mark.column < indent { break; }
    }
    if leading_blanks { p.simple_key_allowed = true; }
    return Token { kind: T_SCALAR, start: start, end: end, value: decoded_span(p, first), style: S_PLAIN, .. };
}

// --- events ---------------------------------------------------------------------

// The next event, from the parser's state machine; kind 0 past the end.
fn next_event<P>(p: P&) -> Event {
    if p.stream_end_produced || p.state == P_END { return Event { kind: 0, start: p.mark, end: p.mark, .. }; }
    let s = p.state;
    match s {
        P_STREAM_START => parse_stream_start(p),
        P_IMPLICIT_DOCUMENT_START => parse_document_start(p, true),
        P_DOCUMENT_START => parse_document_start(p, false),
        P_DOCUMENT_CONTENT => parse_document_content(p),
        P_DOCUMENT_END => parse_document_end(p),
        P_BLOCK_NODE => parse_node(p, true, false),
        P_BLOCK_NODE_OR_INDENTLESS_SEQUENCE => parse_node(p, true, true),
        P_FLOW_NODE => parse_node(p, false, false),
        P_BLOCK_SEQUENCE_FIRST_ENTRY => parse_block_sequence_entry(p, true),
        P_BLOCK_SEQUENCE_ENTRY => parse_block_sequence_entry(p, false),
        P_INDENTLESS_SEQUENCE_ENTRY => parse_indentless_sequence_entry(p),
        P_BLOCK_MAPPING_FIRST_KEY => parse_block_mapping_key(p, true),
        P_BLOCK_MAPPING_KEY => parse_block_mapping_key(p, false),
        P_BLOCK_MAPPING_VALUE => parse_block_mapping_value(p),
        P_FLOW_SEQUENCE_FIRST_ENTRY => parse_flow_sequence_entry(p, true),
        P_FLOW_SEQUENCE_ENTRY => parse_flow_sequence_entry(p, false),
        P_FLOW_SEQUENCE_ENTRY_MAPPING_KEY => parse_flow_sequence_entry_mapping_key(p),
        P_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE => parse_flow_sequence_entry_mapping_value(p),
        P_FLOW_SEQUENCE_ENTRY_MAPPING_END => parse_flow_sequence_entry_mapping_end(p),
        P_FLOW_MAPPING_FIRST_KEY => parse_flow_mapping_key(p, true),
        P_FLOW_MAPPING_KEY => parse_flow_mapping_key(p, false),
        P_FLOW_MAPPING_VALUE => parse_flow_mapping_value(p, false),
        _ => parse_flow_mapping_value(p, true),
    }
}

fn pop_state<P>(p: P&) {
    p.state = p.states[p.states.len - 1];
    p.states.pop();
}

fn pop_mark<P>(p: P&) -> Mark {
    let m = p.marks[p.marks.len - 1];
    p.marks.pop();
    return m;
}

fn parse_stream_start<P>(p: P&) -> Event {
    let t = peek_token(p);
    if t.kind != T_STREAM_START { parser_error(p, "did not find expected <stream-start>", t.start); }
    p.state = P_IMPLICIT_DOCUMENT_START;
    skip_token(p);
    return Event { kind: E_STREAM_START, start: t.start, end: t.end, .. };
}

fn parse_document_start<P>(p: P&, implicit: bool) -> Event {
    var t = peek_token(p);
    if !implicit {
        while t.kind == T_DOCUMENT_END {
            skip_token(p);
            t = peek_token(p);
        }
    }
    if implicit && t.kind != T_VERSION_DIRECTIVE && t.kind != T_TAG_DIRECTIVE && t.kind != T_DOCUMENT_START && t.kind != T_STREAM_END {
        process_directives(p);
        p.states.push(P_DOCUMENT_END);
        p.state = P_BLOCK_NODE;
        return Event { kind: E_DOCUMENT_START, start: t.start, end: t.end, implicit: true, .. };
    }
    if t.kind != T_STREAM_END {
        let start = t.start;
        process_directives(p);
        t = peek_token(p);
        if t.kind != T_DOCUMENT_START { parser_error(p, "did not find expected <document start>", t.start); }
        p.states.push(P_DOCUMENT_END);
        p.state = P_DOCUMENT_CONTENT;
        skip_token(p);
        return Event { kind: E_DOCUMENT_START, start: start, end: t.end, .. };
    }
    p.state = P_END;
    skip_token(p);
    return Event { kind: E_STREAM_END, start: t.start, end: t.end, .. };
}

fn parse_document_content<P>(p: P&) -> Event {
    let t = peek_token(p);
    if t.kind == T_VERSION_DIRECTIVE || t.kind == T_TAG_DIRECTIVE || t.kind == T_DOCUMENT_START
       || t.kind == T_DOCUMENT_END || t.kind == T_STREAM_END {
        pop_state(p);
        return empty_scalar(t.start);
    }
    return parse_node(p, true, false);
}

fn parse_document_end<P>(p: P&) -> Event {
    let t = peek_token(p);
    let start = t.start;
    var end = t.start;
    var implicit = true;
    if t.kind == T_DOCUMENT_END {
        end = t.end;
        skip_token(p);
        implicit = false;
    }
    p.directives.clear();
    p.state = P_DOCUMENT_START;
    return Event { kind: E_DOCUMENT_END, start: start, end: end, implicit: implicit, .. };
}

// A node: an alias, or an anchor and a tag in either order, then a scalar,
// the start of a collection, or for an anchor or tag alone an empty
// scalar.
fn parse_node<P>(p: P&, in_block: bool, indentless_sequence: bool) -> Event {
    var t = peek_token(p);
    if t.kind == T_ALIAS {
        pop_state(p);
        skip_token(p);
        return Event { kind: E_ALIAS, start: t.start, end: t.end, anchor: t.value, .. };
    }
    var start = t.start;
    var end = t.start;
    var tag_token = false;
    var tag_handle = Span { .. };
    var tag_suffix = Span { .. };
    var anchor = Span { .. };
    var tag_mark = t.start;
    if t.kind == T_ANCHOR {
        anchor = t.value;
        start = t.start;
        end = t.end;
        skip_token(p);
        t = peek_token(p);
        if t.kind == T_TAG {
            tag_token = true;
            tag_handle = t.value;
            tag_suffix = t.suffix;
            tag_mark = t.start;
            end = t.end;
            skip_token(p);
            t = peek_token(p);
        }
    } else if t.kind == T_TAG {
        tag_token = true;
        tag_handle = t.value;
        tag_suffix = t.suffix;
        start = t.start;
        tag_mark = t.start;
        end = t.end;
        skip_token(p);
        t = peek_token(p);
        if t.kind == T_ANCHOR {
            anchor = t.value;
            end = t.end;
            skip_token(p);
            t = peek_token(p);
        }
    }
    var tag = Span { .. };
    if tag_token {
        if tag_handle.to == tag_handle.from {
            tag = tag_suffix;
        } else {
            for d in p.directives {
                if view(p, d.handle) == view(p, tag_handle) {
                    let first = p.decoded.len;
                    append_span(p, d.prefix);
                    append_span(p, tag_suffix);
                    tag = decoded_span(p, first);
                    break;
                }
            }
            if tag.to == tag.from { parser_error_context(p, start, "found undefined tag handle", tag_mark); }
        }
    }
    let tag_len = tag.to - tag.from;
    let implicit = tag_len == 0;
    if indentless_sequence && t.kind == T_BLOCK_ENTRY {
        p.state = P_INDENTLESS_SEQUENCE_ENTRY;
        return Event { kind: E_SEQUENCE_START, start: start, end: t.end, anchor: anchor, tag: tag, implicit: implicit, .. };
    }
    if t.kind == T_SCALAR {
        var plain_implicit = false;
        var quoted_implicit = false;
        if (tag_len == 0 && t.style == S_PLAIN) || view(p, tag) == "!" {
            plain_implicit = true;
        } else if tag_len == 0 {
            quoted_implicit = true;
        }
        pop_state(p);
        skip_token(p);
        return Event { kind: E_SCALAR, start: start, end: t.end, anchor: anchor, tag: tag, value: t.value,
                       implicit: plain_implicit, quoted_implicit: quoted_implicit, style: t.style, .. };
    }
    if t.kind == T_FLOW_SEQUENCE_START {
        p.state = P_FLOW_SEQUENCE_FIRST_ENTRY;
        return Event { kind: E_SEQUENCE_START, start: start, end: t.end, anchor: anchor, tag: tag, implicit: implicit, flow: true, .. };
    }
    if t.kind == T_FLOW_MAPPING_START {
        p.state = P_FLOW_MAPPING_FIRST_KEY;
        return Event { kind: E_MAPPING_START, start: start, end: t.end, anchor: anchor, tag: tag, implicit: implicit, flow: true, .. };
    }
    if in_block && t.kind == T_BLOCK_SEQUENCE_START {
        p.state = P_BLOCK_SEQUENCE_FIRST_ENTRY;
        return Event { kind: E_SEQUENCE_START, start: start, end: t.end, anchor: anchor, tag: tag, implicit: implicit, .. };
    }
    if in_block && t.kind == T_BLOCK_MAPPING_START {
        p.state = P_BLOCK_MAPPING_FIRST_KEY;
        return Event { kind: E_MAPPING_START, start: start, end: t.end, anchor: anchor, tag: tag, implicit: implicit, .. };
    }
    if anchor.to > anchor.from || tag_len > 0 {
        pop_state(p);
        return Event { kind: E_SCALAR, start: start, end: end, anchor: anchor, tag: tag, implicit: implicit, style: S_PLAIN, .. };
    }
    parser_error_context(p, start, "did not find expected node content", t.start);
    return Event { kind: 0, start: start, end: end, .. };
}

fn parse_block_sequence_entry<P>(p: P&, first: bool) -> Event {
    if first {
        let t = peek_token(p);
        p.marks.push(t.start);
        skip_token(p);
    }
    var t = peek_token(p);
    if t.kind == T_BLOCK_ENTRY {
        let m = t.end;
        skip_token(p);
        t = peek_token(p);
        if t.kind != T_BLOCK_ENTRY && t.kind != T_BLOCK_END {
            p.states.push(P_BLOCK_SEQUENCE_ENTRY);
            return parse_node(p, true, false);
        }
        p.state = P_BLOCK_SEQUENCE_ENTRY;
        return empty_scalar(m);
    }
    if t.kind == T_BLOCK_END {
        pop_state(p);
        pop_mark(p);
        skip_token(p);
        return Event { kind: E_SEQUENCE_END, start: t.start, end: t.end, .. };
    }
    parser_error_context(p, pop_mark(p), "did not find expected '-' indicator", t.start);
    return Event { kind: 0, start: t.start, end: t.end, .. };
}

fn parse_indentless_sequence_entry<P>(p: P&) -> Event {
    var t = peek_token(p);
    if t.kind == T_BLOCK_ENTRY {
        let m = t.end;
        skip_token(p);
        t = peek_token(p);
        if t.kind != T_BLOCK_ENTRY && t.kind != T_KEY && t.kind != T_VALUE && t.kind != T_BLOCK_END {
            p.states.push(P_INDENTLESS_SEQUENCE_ENTRY);
            return parse_node(p, true, false);
        }
        p.state = P_INDENTLESS_SEQUENCE_ENTRY;
        return empty_scalar(m);
    }
    pop_state(p);
    return Event { kind: E_SEQUENCE_END, start: t.start, end: t.start, .. };
}

fn parse_block_mapping_key<P>(p: P&, first: bool) -> Event {
    if first {
        let t = peek_token(p);
        p.marks.push(t.start);
        skip_token(p);
    }
    var t = peek_token(p);
    if t.kind == T_KEY {
        let m = t.end;
        skip_token(p);
        t = peek_token(p);
        if t.kind != T_KEY && t.kind != T_VALUE && t.kind != T_BLOCK_END {
            p.states.push(P_BLOCK_MAPPING_VALUE);
            return parse_node(p, true, true);
        }
        p.state = P_BLOCK_MAPPING_VALUE;
        return empty_scalar(m);
    }
    if t.kind == T_BLOCK_END {
        pop_state(p);
        pop_mark(p);
        skip_token(p);
        return Event { kind: E_MAPPING_END, start: t.start, end: t.end, .. };
    }
    parser_error_context(p, pop_mark(p), "did not find expected key", t.start);
    return Event { kind: 0, start: t.start, end: t.end, .. };
}

fn parse_block_mapping_value<P>(p: P&) -> Event {
    var t = peek_token(p);
    if t.kind == T_VALUE {
        let m = t.end;
        skip_token(p);
        t = peek_token(p);
        if t.kind != T_KEY && t.kind != T_VALUE && t.kind != T_BLOCK_END {
            p.states.push(P_BLOCK_MAPPING_KEY);
            return parse_node(p, true, true);
        }
        p.state = P_BLOCK_MAPPING_KEY;
        return empty_scalar(m);
    }
    p.state = P_BLOCK_MAPPING_KEY;
    return empty_scalar(t.start);
}

fn parse_flow_sequence_entry<P>(p: P&, first: bool) -> Event {
    if first {
        let t = peek_token(p);
        p.marks.push(t.start);
        skip_token(p);
    }
    var t = peek_token(p);
    if t.kind != T_FLOW_SEQUENCE_END {
        if !first {
            if t.kind == T_FLOW_ENTRY {
                skip_token(p);
                t = peek_token(p);
            } else {
                parser_error_context(p, pop_mark(p), "did not find expected ',' or ']'", t.start);
            }
        }
        if t.kind == T_KEY {
            p.state = P_FLOW_SEQUENCE_ENTRY_MAPPING_KEY;
            skip_token(p);
            return Event { kind: E_MAPPING_START, start: t.start, end: t.end, implicit: true, flow: true, .. };
        } else if t.kind != T_FLOW_SEQUENCE_END {
            p.states.push(P_FLOW_SEQUENCE_ENTRY);
            return parse_node(p, false, false);
        }
    }
    pop_state(p);
    pop_mark(p);
    skip_token(p);
    return Event { kind: E_SEQUENCE_END, start: t.start, end: t.end, .. };
}

fn parse_flow_sequence_entry_mapping_key<P>(p: P&) -> Event {
    let t = peek_token(p);
    if t.kind != T_VALUE && t.kind != T_FLOW_ENTRY && t.kind != T_FLOW_SEQUENCE_END {
        p.states.push(P_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE);
        return parse_node(p, false, false);
    }
    let m = t.end;
    skip_token(p);
    p.state = P_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE;
    return empty_scalar(m);
}

fn parse_flow_sequence_entry_mapping_value<P>(p: P&) -> Event {
    let t = peek_token(p);
    if t.kind == T_VALUE {
        skip_token(p);
        let t2 = peek_token(p);
        if t2.kind != T_FLOW_ENTRY && t2.kind != T_FLOW_SEQUENCE_END {
            p.states.push(P_FLOW_SEQUENCE_ENTRY_MAPPING_END);
            return parse_node(p, false, false);
        }
    }
    p.state = P_FLOW_SEQUENCE_ENTRY_MAPPING_END;
    return empty_scalar(t.start);
}

fn parse_flow_sequence_entry_mapping_end<P>(p: P&) -> Event {
    let t = peek_token(p);
    p.state = P_FLOW_SEQUENCE_ENTRY;
    return Event { kind: E_MAPPING_END, start: t.start, end: t.start, .. };
}

fn parse_flow_mapping_key<P>(p: P&, first: bool) -> Event {
    if first {
        let t = peek_token(p);
        p.marks.push(t.start);
        skip_token(p);
    }
    var t = peek_token(p);
    if t.kind != T_FLOW_MAPPING_END {
        if !first {
            if t.kind == T_FLOW_ENTRY {
                skip_token(p);
                t = peek_token(p);
            } else {
                parser_error_context(p, pop_mark(p), "did not find expected ',' or '}'", t.start);
            }
        }
        if t.kind == T_KEY {
            skip_token(p);
            t = peek_token(p);
            if t.kind != T_VALUE && t.kind != T_FLOW_ENTRY && t.kind != T_FLOW_MAPPING_END {
                p.states.push(P_FLOW_MAPPING_VALUE);
                return parse_node(p, false, false);
            }
            p.state = P_FLOW_MAPPING_VALUE;
            return empty_scalar(t.start);
        } else if t.kind != T_FLOW_MAPPING_END {
            p.states.push(P_FLOW_MAPPING_EMPTY_VALUE);
            return parse_node(p, false, false);
        }
    }
    pop_state(p);
    pop_mark(p);
    skip_token(p);
    return Event { kind: E_MAPPING_END, start: t.start, end: t.end, .. };
}

fn parse_flow_mapping_value<P>(p: P&, empty: bool) -> Event {
    var t = peek_token(p);
    if empty {
        p.state = P_FLOW_MAPPING_KEY;
        return empty_scalar(t.start);
    }
    if t.kind == T_VALUE {
        skip_token(p);
        t = peek_token(p);
        if t.kind != T_FLOW_ENTRY && t.kind != T_FLOW_MAPPING_END {
            p.states.push(P_FLOW_MAPPING_KEY);
            return parse_node(p, false, false);
        }
    }
    p.state = P_FLOW_MAPPING_KEY;
    return empty_scalar(t.start);
}

// The bytes of span s onto `decoded`. (From the text, or from what is in
// `decoded` already, a byte at a time, since appending a view of it to
// itself is not allowed.)
fn append_span<P>(p: P&, s: Span) {
    if s.decoded {
        for i in s.from..s.to { p.decoded.push(p.decoded[i]); }
    } else {
        p.decoded.append(p.buf[s.from..s.to]);
    }
}

fn empty_scalar(m: Mark) -> Event {
    return Event { kind: E_SCALAR, start: m, end: m, implicit: true, style: S_PLAIN, .. };
}

// The %YAML and %TAG directives before a document, and the default tag
// handles ! and !!. yaml.v3 takes %YAML 1.1 only.
fn process_directives<P>(p: P&) {
    var t = peek_token(p);
    var version = false;
    while t.kind == T_VERSION_DIRECTIVE || t.kind == T_TAG_DIRECTIVE {
        if t.kind == T_VERSION_DIRECTIVE {
            if version { parser_error(p, "found duplicate %YAML directive", t.start); }
            if t.major != 1 || t.minor != 1 { parser_error(p, "found incompatible YAML document", t.start); }
            version = true;
        } else {
            append_tag_directive(p, t.value, t.suffix, false, t.start);
        }
        skip_token(p);
        t = peek_token(p);
    }
    append_tag_directive(p, p.bang, p.bang, true, t.start);
    append_tag_directive(p, p.bangbang, p.core_prefix, true, t.start);
}

fn append_tag_directive<P>(p: P&, handle: Span, prefix: Span, allow_duplicates: bool, m: Mark) {
    for d in p.directives {
        if view(p, d.handle) == view(p, handle) {
            if allow_duplicates { return; }
            parser_error(p, "found duplicate %TAG directive", m);
        }
    }
    p.directives.push(TagDirective { handle: handle, prefix: prefix });
}

// --- composing the tree ---------------------------------------------------------

// A collection the composer is inside of: its node, its last child so
// far, and how many it has.
struct Open { node: Node?, last: Node?, count: i64 }

// The prefix of the core schema's tags in their long form; !! in the
// short.
let LONG_TAG_PREFIX = "tag:yaml.org,2002:";

// tag in yaml.v3's short form: !!x for tag:yaml.org,2002:x, put together
// on `decoded`; any other tag as it is.
fn short_tag(tag: const u8[:], decoded: u8[>..]&) -> const u8[:] {
    guard starts_with(tag, LONG_TAG_PREFIX) else { return tag; }
    let first = decoded.len;
    decoded.append("!!");
    decoded.append(tag[LONG_TAG_PREFIX.len..]);
    return decoded[first..];
}

// Reads the stream onto doc, as yaml.v3's Decoder reads it a document at a
// time, and links the documents from p.first_doc; the error, if it fails,
// with the documents before it read whole. Anchors are yaml.v3's: one set
// for the stream, a later definition of a name replacing the earlier one
// from there on.
fn compose<P>(p: P&, text: const u8[:], doc: Node[>..]&, decoded: u8[>..]&) -> Error {
    var anchors = dictionary<const u8[:], i64> {};    // a name's node, by its index in doc
    var outer: Open[>..<] = [];
    var event = next_event(p);         // the event at the cursor,
    var have = true;                   // whether it has been read
    var last_doc: Node? = null;

    // The bytes of span s, as the nodes keep them.
    fn bytes(s: Span) -> const u8[:] { if s.decoded { decoded[s.from..s.to] } else { text[s.from..s.to] } }

    fn peek() -> i64 {
        if !have {
            event = next_event(p);
            have = true;
        }
        return event.kind;
    }

    fn expect(kind: i64) {
        peek();
        if event.kind == E_STREAM_END { failf(event.start, "attempted to go past the end of stream; corrupted value?"); }
        have = false;
    }

    // A node for the event at the cursor, with yaml.v3's tag: the short
    // form of the tag written, else the default tag, else for a scalar
    // the one it resolves to.
    fn make(kind: u8, default_tag: const u8[:], value: const u8[:]) -> Node {
        let written = event.tag.to > event.tag.from && bytes(event.tag) != "!";
        let tag = if written { short_tag(bytes(event.tag), decoded) }
                  else if default_tag.len > 0 { default_tag }
                  else if kind == SCALAR { resolve_tag(value) }
                  else { "" };
        return Node { next: null, first: null, alias: null, kind: kind, style: if written { TAGGED } else { 0 }, count: 0,
                      line: event.start.line + 1, column: event.start.column + 1,
                      tag: tag, value: value, anchor: "" };
    }

    expect(E_STREAM_START);
    loop {
        guard peek() == E_DOCUMENT_START else { return Error { message: [] }; }
        let d .= doc.push(Node { next: null, first: null, alias: null, kind: DOCUMENT, style: 0, count: 0,
                                 line: event.start.line + 1, column: event.start.column + 1,
                                 tag: "", value: "", anchor: "" });
        expect(E_DOCUMENT_START);
        var parent: Node? = d;
        var last: Node? = null;
        var count = 0;
        loop {
            let k = peek();
            if k == E_SEQUENCE_END || k == E_MAPPING_END {
                if parent { parent.count = count; }
                expect(k);
                let o = outer[outer.len - 1];
                outer.pop();
                parent .= o.node;
                last .= o.last;
                count = o.count;
                if outer.len == 0 { break; }
                continue;
            }
            var n: Node? = null;
            if k == E_SCALAR {
                var style: u8 = 0;
                if event.style == S_DOUBLE { style = DOUBLE_QUOTED; }
                else if event.style == S_SINGLE { style = SINGLE_QUOTED; }
                else if event.style == S_LITERAL { style = LITERAL; }
                else if event.style == S_FOLDED { style = FOLDED; }
                let value = bytes(event.value);
                let default_tag = if style == 0 { if value == "<<" { "!!merge" } else { "" } } else { "!!str" };
                let m .= doc.push(make(SCALAR, default_tag, value));
                m.style |= style;
                n .= m;
            } else if k == E_ALIAS {
                let name = bytes(event.anchor);
                let m .= doc.push(make(ALIAS, "", name));
                let target = anchors.get(name);
                guard target else { failf(event.start, str("unknown anchor '", name, "' referenced")); }
                m.alias .= doc[target];
                n .= m;
            } else {
                let is_map = k == E_MAPPING_START;
                let m .= doc.push(make(if is_map { MAPPING } else { SEQUENCE }, if is_map { "!!map" } else { "!!seq" }, ""));
                if event.flow { m.style |= FLOW; }
                n .= m;
            }
            guard n else { break; }
            if event.anchor.to > event.anchor.from && k != E_ALIAS {
                let name = bytes(event.anchor);
                n.anchor = name;
                anchors.insert(name, doc.index_of(n));
            }
            if last { last.next .= n; } else if parent { parent.first .= n; }
            last .= n;
            count++;
            expect(k);
            if k == E_SEQUENCE_START || k == E_MAPPING_START {
                outer.push(Open { node: parent, last: last, count: count });
                parent .= n;
                last .= null;
                count = 0;
                continue;
            }
            if outer.len == 0 { break; }
        }
        d.count = 1;
        peek();
        expect(E_DOCUMENT_END);
        if last_doc { last_doc.next .= d; } else { p.first_doc = doc.index_of(d); }
        last_doc .= d;
    }
}

// Parses the YAML stream in text onto doc and returns its first document,
// the others linked from it by `next`, and the error that ended it if one
// did: the stream as gopkg.in/yaml.v3's Decoder reads it, refused with its
// message, and with the line and column of what is at fault. When the
// stream fails, the documents before the failure are returned, read whole;
// nodes of the one that failed are in doc too, linked from none of them.
// Tags and scalars put together from their text (folded, unescaped,
// prefixed) are pushed onto `decoded`; anchor and alias names are views of
// text. Text in UTF-16, with a byte order mark, is converted onto
// `decoded` first.
fn parse(text: const u8[:], doc: Node[>..]&, decoded: u8[>..]&) -> Node?, Error {
    var tokens: Token[>..<] = [];
    var indents: i64[>..<] = [];
    var simple_keys: SimpleKey[>..<] = [];
    var keys_by_token = dictionary<i64, i64> {};
    var states: i64[>..<] = [];
    var marks: Mark[>..<] = [];
    var directives: TagDirective[>..<] = [];
    // yaml.v3's reader starts by reading 512 bytes, and a second time when
    // that gave it fewer than 3, to look for a byte order mark.
    let enc, bom = encoding_of(text);
    let utf8 = enc == ENC_UTF8;
    let base = decoded.len;
    let buf = if utf8 { text } else { utf16_to_utf8(text, bom, enc == ENC_UTF16LE, decoded) };
    let consts = decoded.len;
    decoded.append("!!tag:yaml.org,2002:");
    var p = Parser { buf: buf, pos: if utf8 { bom } else { 0 }, mark: Mark { .. }, raw: text, encoding: enc,
                     raw_pos: bom, raw_end: min(text.len, RAW_CHUNK), out_pos: if utf8 { bom } else { 0 },
                     eof: text.len < 3, buf_base: if utf8 { -1 } else { base },
                     bang: Span { from: consts, to: consts + 1, decoded: true },
                     bangbang: Span { from: consts, to: consts + 2, decoded: true },
                     core_prefix: Span { from: consts + 2, to: consts + 20, decoded: true },
                     tokens: tokens, indents: indents, simple_keys: simple_keys, keys_by_token: keys_by_token,
                     states: states, marks: marks, directives: directives, decoded: decoded, .. };
    let err = compose(p, text, doc, decoded);
    if p.first_doc < 0 { return null, err; }
    return doc[p.first_doc], err;
}

// The encoding of text, from its byte order mark, and the mark's length:
// UTF-16 in either order, or UTF-8 with or without a mark.
fn encoding_of(text: const u8[:]) -> i64, i64 {
    if text.len >= 2 && text[0] == 0xFF && text[1] == 0xFE { return ENC_UTF16LE, 2; }
    if text.len >= 2 && text[0] == 0xFE && text[1] == 0xFF { return ENC_UTF16BE, 2; }
    if text.len >= 3 && text[0] == 0xEF && text[1] == 0xBB && text[2] == 0xBF { return ENC_UTF8, 3; }
    return ENC_UTF8, 0;
}

// The UTF-16 text from byte `from`, as UTF-8 onto out, up to the first
// thing that is not UTF-16; the reader refuses it when it gets there.
fn utf16_to_utf8(text: const u8[:], from: i64, le: bool, out: u8[>..]&) -> const u8[:] {
    let first = out.len;
    let low = if le { 0 } else { 1 };
    let high = 1 - low;
    var i = from;
    while i + 1 < text.len {
        var value = text[i + low] + ((text[i + high] as i64) << 8);
        if (value & 0xFC00) == 0xDC00 { break; }
        var w = 2;
        if (value & 0xFC00) == 0xD800 {
            if i + 3 >= text.len { break; }
            let value2 = text[i + low + 2] + ((text[i + high + 2] as i64) << 8);
            if (value2 & 0xFC00) != 0xDC00 { break; }
            value = 0x10000 + ((value & 0x3FF) << 10) + (value2 & 0x3FF);
            w = 4;
        }
        push_utf8(out, value);
        i += w;
    }
    return out[first..];
}

// --- resolving scalars ----------------------------------------------------------

// A timestamp, as yaml.v3 reads one into a time.Time: the date and time
// written, and the zone's offset east of UTC in seconds (0 when none was
// written, which is UTC).
struct Time { year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64, nanosecond: i64, offset: i64 }

// A scalar's value, as yaml.v3 decodes it into an interface{}: null, a
// bool, an integer (Uint for those above i64's range), a float, a
// timestamp, or text (the node's value; Binary for !!binary, whose bytes
// `binary` decodes). Invalid when the tag written does not fit the text,
// as in `!!int x`, which yaml.v3 refuses: `scalar_error` says why.
enum Scalar {
    Null,
    Bool { v: bool },
    Int { v: i64 },
    Uint { v: u64 },
    Float { v: f64 },
    Timestamp { t: Time },
    Str,
    Binary,
    Invalid,
}

// The tag yaml.v3 resolves a plain scalar without one to.
fn resolve_tag(value: const u8[:]) -> const u8[:] {
    let tag, s = resolve_text("", value);
    return tag;
}

// Whether a scalar is text whatever it says: tagged !!str, or quoted or
// a block scalar with no tag (or the tag !).
fn indicated_string(n: Node&) -> bool {
    n.kind == SCALAR && (n.tag == "!!str"
        || ((n.tag.len == 0 || n.tag == "!") && (n.style & (SINGLE_QUOTED | DOUBLE_QUOTED | LITERAL | FOLDED)) != 0))
}

// The value of scalar n (or of the node alias n names), as yaml.v3's
// Node.Decode gives it into an interface{}.
fn resolve(node: Node&) -> Scalar {
    var n .= node;
    while n.kind == ALIAS {
        let a = n.alias;
        guard a else { return Scalar.Invalid; }
        n .= a;
    }
    guard n.kind == SCALAR else { return Scalar.Invalid; }
    if indicated_string(n) { return Scalar.Str; }
    let tag, s = resolve_text(n.tag, n.value);
    if tag == "!!binary" {
        if !valid_base64(n.value) { return Scalar.Invalid; }
        return Scalar.Binary;
    }
    return s;
}

// Why yaml.v3 refuses to decode scalar n: "yaml: cannot decode !!str `x`
// as a !!int", or bad base64 for !!binary; empty when it does not.
fn scalar_error(n: Node&) -> u8[>..] {
    var out: u8[>..] = [];
    guard n.kind == SCALAR && !indicated_string(n) else { return out; }
    let tag, s = resolve_text(n.tag, n.value);
    if tag == "!!binary" {
        if !valid_base64(n.value) { out.append("yaml: !!binary value contains invalid base64 data"); }
        return out;
    }
    match s {
        Invalid => { format(out, "yaml: cannot decode ", resolve_tag(n.value), " `", n.value, "` as a ", n.tag); },
        _ => {},
    }
    return out;
}

// What yaml.v3's resolve(tag, text) makes of text: the tag it resolves to,
// and the value; Invalid when tag is one of the core schema's that text
// does not resolve to (a float tag takes an integer, as a float).
fn resolve_text(tag: const u8[:], text: const u8[:]) -> const u8[:], Scalar {
    guard tag.len == 0 || tag == "!!str" || tag == "!!bool" || tag == "!!int" || tag == "!!float"
          || tag == "!!null" || tag == "!!timestamp" else {
        return tag, Scalar.Str;
    }
    let rtag, s = resolve_plain(tag, text);
    if tag.len == 0 || tag == rtag || tag == "!!str" { return rtag, s; }
    if tag == "!!float" {
        match s {
            Int i => { return "!!float", Scalar.Float { v: i.v }; },
            _ => {},
        }
    }
    return rtag, Scalar.Invalid;
}

// The first byte's hint, as yaml.v3's resolve table has it: 'S' for a
// sign, 'D' for a digit, 'M' for the first letters of the words it looks
// up, '.' for a dot, 0 for text.
fn hint(c: u8) -> u8 {
    if c == '+' || c == '-' { return 'S'; }
    if c >= '0' && c <= '9' { return 'D'; }
    if c == '.' { return '.'; }
    for m in "yYnNtTfFoO~" { if c == m { return 'M'; } }
    return 0;
}

fn resolve_plain(tag: const u8[:], text: const u8[:]) -> const u8[:], Scalar {
    let h = if text.len == 0 { 'N' } else { hint(text[0]) };
    guard h != 0 && tag != "!!str" else { return "!!str", Scalar.Str; }
    // The words.
    if text.len == 0 || text == "~" || text == "null" || text == "Null" || text == "NULL" { return "!!null", Scalar.Null; }
    if text == "true" || text == "True" || text == "TRUE" { return "!!bool", Scalar.Bool { v: true }; }
    if text == "false" || text == "False" || text == "FALSE" { return "!!bool", Scalar.Bool { v: false }; }
    if text == ".nan" || text == ".NaN" || text == ".NAN" { return "!!float", Scalar.Float { v: 0.0 / 0.0 }; }
    if text == ".inf" || text == ".Inf" || text == ".INF" || text == "+.inf" || text == "+.Inf" || text == "+.INF" {
        return "!!float", Scalar.Float { v: 1.0 / 0.0 };
    }
    if text == "-.inf" || text == "-.Inf" || text == "-.INF" { return "!!float", Scalar.Float { v: -1.0 / 0.0 }; }
    if text == "<<" { return "!!merge", Scalar.Str; }
    if h == '.' {
        let v, ok = parse_dot_float(text);
        if ok { return "!!float", Scalar.Float { v: v }; }
    } else if h == 'D' || h == 'S' {
        if tag.len == 0 || tag == "!!timestamp" {
            let t, ok = parse_timestamp(text);
            if ok { return "!!timestamp", Scalar.Timestamp { t: t }; }
        }
        var plain: u8[>..] = [];
        for c in text { if c != '_' { plain.push(c); } }
        let i, iok = go_parse_int(plain, 0);
        if iok { return "!!int", Scalar.Int { v: i }; }
        let u, uok = go_parse_uint(plain, 0);
        if uok { return "!!int", Scalar.Uint { v: u }; }
        if float_syntax(plain) {
            let v, ok = parse_flt(plain);
            if ok && v - v == 0.0 { return "!!float", Scalar.Float { v: v }; }
        }
        if starts_with(plain, "0b") {
            let b, bok = go_parse_int(plain[2..], 2);
            if bok { return "!!int", Scalar.Int { v: b }; }
            let bu, buok = go_parse_uint(plain[2..], 2);
            if buok { return "!!int", Scalar.Uint { v: bu }; }
        } else if starts_with(plain, "-0b") {
            var neg: u8[>..] = [];
            neg.push('-');
            neg.append(plain[3..]);
            let b, bok = go_parse_int(neg, 2);
            if bok { return "!!int", Scalar.Int { v: b }; }
        }
        if starts_with(plain, "0o") {
            let o, ook = go_parse_int(plain[2..], 8);
            if ook { return "!!int", Scalar.Int { v: o }; }
            let ou, ouok = go_parse_uint(plain[2..], 8);
            if ouok { return "!!int", Scalar.Uint { v: ou }; }
        } else if starts_with(plain, "-0o") {
            var neg: u8[>..] = [];
            neg.push('-');
            neg.append(plain[3..]);
            let o, ook = go_parse_int(neg, 8);
            if ook { return "!!int", Scalar.Int { v: o }; }
        }
    }
    return "!!str", Scalar.Str;
}

// strconv.ParseFloat of text that starts with '.': digits, and an
// exponent, with underscores between digits as Go writes them; false for
// anything else, and for a value too big for an f64.
fn parse_dot_float(text: const u8[:]) -> f64, bool {
    var plain: u8[>..] = [];
    var i = 1;
    var saw: u8 = '!';           // '0' after a digit, '_' after an underscore
    var digits = 0;
    while i < text.len && (is_digit(text[i]) || text[i] == '_') {
        if text[i] == '_' {
            guard saw == '0' else { return 0.0, false; }
            saw = '_';
        } else {
            saw = '0';
            digits++;
        }
        i++;
    }
    guard digits > 0 && saw != '_' else { return 0.0, false; }
    if i < text.len && (text[i] == 'e' || text[i] == 'E') {
        i++;
        saw = '!';
        if i < text.len && (text[i] == '-' || text[i] == '+') { i++; }
        var exp_digits = 0;
        while i < text.len && (is_digit(text[i]) || text[i] == '_') {
            if text[i] == '_' {
                guard saw == '0' else { return 0.0, false; }
                saw = '_';
            } else {
                saw = '0';
                exp_digits++;
            }
            i++;
        }
        guard exp_digits > 0 && saw != '_' else { return 0.0, false; }
    }
    guard i == text.len else { return 0.0, false; }
    for c in text { if c != '_' { plain.push(c); } }
    let v, ok = parse_flt(plain);
    guard ok && v - v == 0.0 else { return 0.0, false; }
    return v, true;
}

// Whether s is a float as yaml.v3's pattern has one:
// [-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?
fn float_syntax(s: const u8[:]) -> bool {
    var i = 0;
    if i < s.len && (s[i] == '-' || s[i] == '+') { i++; }
    if i < s.len && s[i] == '.' {
        i++;
        let from = i;
        while i < s.len && is_digit(s[i]) { i++; }
        if i == from { return false; }
    } else {
        let from = i;
        while i < s.len && is_digit(s[i]) { i++; }
        if i == from { return false; }
        if i < s.len && s[i] == '.' {
            i++;
            while i < s.len && is_digit(s[i]) { i++; }
        }
    }
    if i < s.len && (s[i] == 'e' || s[i] == 'E') {
        i++;
        if i < s.len && (s[i] == '-' || s[i] == '+') { i++; }
        let from = i;
        while i < s.len && is_digit(s[i]) { i++; }
        if i == from { return false; }
    }
    return i == s.len;
}

// strconv.ParseUint(s, base, 64): base 0 reads the prefixes 0b, 0o and 0x
// (in either case, with a digit after them) and a lone leading 0 as
// octal.
fn go_parse_uint(s: const u8[:], base0: i64) -> u64, bool {
    guard s.len > 0 else { return 0, false; }
    var base = base0;
    var i = 0;
    if base == 0 {
        base = 10;
        if s[0] == '0' {
            let c = if s.len >= 3 { s[1] | 0x20 } else { 0 };
            if c == 'b' { base = 2; i = 2; }
            else if c == 'o' { base = 8; i = 2; }
            else if c == 'x' { base = 16; i = 2; }
            else { base = 8; i = 1; }
        }
    }
    var n: u64 = 0;
    let b = base as u64;
    let cutoff: u64 = 0xFFFFFFFFFFFFFFFF / b + 1;
    while i < s.len {
        let c = s[i];
        var d: u64 = 99;
        if c >= '0' && c <= '9' { d = c - '0'; }
        else if (c | 0x20) >= 'a' && (c | 0x20) <= 'z' { d = (c | 0x20) - 'a' + 10; }
        if d >= b { return 0, false; }
        if n >= cutoff { return 0, false; }
        n *= b;
        let n1 = n + d;
        if n1 < n { return 0, false; }
        n = n1;
        i++;
    }
    return n, true;
}

// strconv.ParseInt(s, base, 64): a sign, then as go_parse_uint.
fn go_parse_int(s: const u8[:], base: i64) -> i64, bool {
    guard s.len > 0 else { return 0, false; }
    var neg = false;
    var t = s;
    if s[0] == '+' || s[0] == '-' {
        neg = s[0] == '-';
        t = s[1..];
    }
    let u, ok = go_parse_uint(t, base);
    guard ok else { return 0, false; }
    let cutoff: u64 = 0x8000000000000000;
    if !neg && u >= cutoff { return 0, false; }
    if neg && u > cutoff { return 0, false; }
    let v = if neg { (0 - u) as! i64 } else { u as! i64 };
    return v, true;
}

// yaml.v3's timestamps: text that starts with four digits and '-', read by
// Go's time.Parse with one of the layouts 2006-1-2T15:4:5.999999999Z07:00
// (or with a 't'), 2006-1-2 15:4:5.999999999, and 2006-1-2.
fn parse_timestamp(s: const u8[:]) -> Time, bool {
    var t = Time { year: 0, month: 0, day: 0, hour: 0, minute: 0, second: 0, nanosecond: 0, offset: 0 };
    guard s.len > 4 && is_digit(s[0]) && is_digit(s[1]) && is_digit(s[2]) && is_digit(s[3]) && s[4] == '-' else { return t, false; }
    for layout in 4 {
        let r, ok = time_layout(s, layout);
        if ok { return r, true; }
    }
    return t, false;
}

// time.Parse of s with the layout numbered as parse_timestamp lists them.
fn time_layout(s: const u8[:], layout: i64) -> Time, bool {
    var t = Time { year: 0, month: 1, day: 1, hour: 0, minute: 0, second: 0, nanosecond: 0, offset: 0 };
    let bad = Time { year: 0, month: 0, day: 0, hour: 0, minute: 0, second: 0, nanosecond: 0, offset: 0 };
    var i = 0;
    // A number of one or two digits, as time.Parse's getnum.
    fn num() -> i64, bool {
        guard i < s.len && is_digit(s[i]) else { return 0, false; }
        var v: i64 = s[i] - '0';
        i++;
        if i < s.len && is_digit(s[i]) {
            v = v * 10 + (s[i] - '0');
            i++;
        }
        return v, true;
    }
    fn lit(c: u8) -> bool {
        guard i < s.len && s[i] == c else { return false; }
        i++;
        return true;
    }
    t.year = (s[0] - '0') as i64 * 1000 + (s[1] - '0') as i64 * 100 + (s[2] - '0') as i64 * 10 + (s[3] - '0');
    i = 4;
    guard lit('-') else { return bad, false; }
    let mo, mok = num();
    guard mok && mo >= 1 && mo <= 12 && lit('-') else { return bad, false; }
    let d, dok = num();
    guard dok else { return bad, false; }
    t.month = mo;
    t.day = d;
    if layout < 3 {
        if layout == 2 {
            // A space in a layout matches any run of spaces.
            guard i < s.len && s[i] == ' ' else { return bad, false; }
            while i < s.len && s[i] == ' ' { i++; }
        } else {
            guard lit(if layout == 0 { 'T' } else { 't' }) else { return bad, false; }
        }
        let h, hok = num();
        guard hok && h < 24 && lit(':') else { return bad, false; }
        let mi, miok = num();
        guard miok && mi < 60 && lit(':') else { return bad, false; }
        let se, seok = num();
        guard seok && se < 60 else { return bad, false; }
        t.hour = h;
        t.minute = mi;
        t.second = se;
        // A fraction of a second: any number of digits, the first nine
        // read.
        if i + 1 < s.len && (s[i] == '.' || s[i] == ',') && is_digit(s[i + 1]) {
            i++;
            var digits = 0;
            var ns = 0;
            while i < s.len && is_digit(s[i]) {
                if digits < 9 { ns = ns * 10 + (s[i] - '0'); digits++; }
                i++;
            }
            while digits < 9 { ns *= 10; digits++; }
            t.nanosecond = ns;
        }
        if layout < 2 {
            if i < s.len && s[i] == 'Z' {
                i++;
            } else {
                guard s.len - i >= 6 && s[i + 3] == ':' && (s[i] == '+' || s[i] == '-')
                      && is_digit(s[i + 1]) && is_digit(s[i + 2]) && is_digit(s[i + 4]) && is_digit(s[i + 5]) else { return bad, false; }
                let zh: i64 = (s[i + 1] - '0') * 10 + (s[i + 2] - '0');
                let zm: i64 = (s[i + 4] - '0') * 10 + (s[i + 5] - '0');
                guard zh <= 24 && zm <= 60 else { return bad, false; }
                t.offset = (zh * 60 + zm) * 60;
                if s[i] == '-' { t.offset = -t.offset; }
                i += 6;
            }
        }
    }
    guard i == s.len && t.day >= 1 && t.day <= days_in(t.month, t.year) else { return bad, false; }
    return t, true;
}

fn days_in(month: i64, year: i64) -> i64 {
    if month == 2 { return if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 { 29 } else { 28 }; }
    if month == 4 || month == 6 || month == 9 || month == 11 { return 30; }
    return 31;
}

// t as Go's time.RFC3339Nano writes it: 2001-12-14T21:59:43.1-05:00, or Z
// for UTC.
fn format_time(out: u8[>..]&, t: Time) {
    format_int(out, t.year, 10, 4, '0');
    out.push('-');
    format_int(out, t.month, 10, 2, '0');
    out.push('-');
    format_int(out, t.day, 10, 2, '0');
    out.push('T');
    format_int(out, t.hour, 10, 2, '0');
    out.push(':');
    format_int(out, t.minute, 10, 2, '0');
    out.push(':');
    format_int(out, t.second, 10, 2, '0');
    if t.nanosecond > 0 {
        var digits: u8[..9] = [];
        format_int(digits, t.nanosecond, 10, 9, '0');
        var n = 9;
        while digits[n - 1] == '0' { n--; }
        out.push('.');
        out.append(digits[..n]);
    }
    if t.offset == 0 {
        out.push('Z');
        return;
    }
    let minutes = abs(t.offset) / 60;
    out.push(if t.offset < 0 { '-' } else { '+' });
    format_int(out, minutes / 60, 10, 2, '0');
    out.push(':');
    format_int(out, minutes % 60, 10, 2, '0');
}

// Whether s is base64 as Go's StdEncoding decodes it: padded, with line
// breaks (CR, LF) anywhere ignored.
fn valid_base64(s: const u8[:]) -> bool {
    var n = 0;          // characters that are not line breaks
    var pads = 0;
    for c in s {
        if c == '\r' || c == '\n' { continue; }
        if pads > 0 && c != '=' { return false; }
        if c == '=' {
            pads++;
        } else if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') {
            return false;
        }
        n++;
    }
    return n % 4 == 0 && pads <= 2;
}

// The bytes of !!binary scalar n onto out; false if it is not base64.
fn binary(n: Node&, out: u8[>..]&) -> bool {
    guard valid_base64(n.value) else { return false; }
    var acc: u32 = 0;
    var bits = 0;
    for c in n.value {
        var v: u32 = 0;
        if c >= 'A' && c <= 'Z' { v = c - 'A'; }
        else if c >= 'a' && c <= 'z' { v = c - 'a' + 26; }
        else if c >= '0' && c <= '9' { v = c - '0' + 52; }
        else if c == '+' { v = 62; }
        else if c == '/' { v = 63; }
        else { continue; }
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as! u8);
        }
    }
    return true;
}

// --- checking documents as yaml.v3's decoder does --------------------------------

// A key in one of the sets of keys a merge has seen: the set, and the key's
// decoded value (its kind and bits, or its text); and the next key with
// the same hash. (Keys are compared here, since == on a struct compares
// the slices in it as views, not as text.)
struct MergeKey { set: i64, kind: i64, bits: u64, text: const u8[:], next: i64 = -1 }

fn key_hash(k: MergeKey) -> u64 { hash_combine(hash_combine(hash(k.set), hash(k.kind)), hash_combine(hash(k.bits), hash(k.text))) }

fn same_key(a: MergeKey, b: MergeKey) -> bool { a.set == b.set && a.kind == b.kind && a.bits == b.bits && a.text == b.text }

// Whether key k is in its set, and if not, puts it in.
fn add_key<C>(c: C&, k: MergeKey) -> bool {
    let h = key_hash(k);
    var first = -1;
    let at = c.heads.get(h);
    if at { first = at; }
    var i = first;
    while i >= 0 {
        if same_key(c.entries[i], k) { return true; }
        i = c.entries[i].next;
    }
    var e = k;
    e.next = first;
    c.entries.push(e);
    c.heads.insert(h, c.entries.len - 1);
    return false;
}

// The walk of yaml.v3's decoder over a document, decoding it into an
// interface{}: how many nodes it has decoded, and how many of them inside
// aliases; the aliases it is inside of; the sets of keys merges have seen,
// and the one in force; and the decoding errors, which do not stop it.
struct Check {
    decode_count: i64 = 0,
    alias_count: i64 = 0,
    alias_depth: i64 = 0,
    merged: i64 = -1,
    sets: i64 = 0,
    error_line: i64 = 0,
    error_column: i64 = 0,
    heads: dictionary<u64, i64>&,
    entries: MergeKey[>..<]&,
    expanding: (Node&)[>..<]&,
    errors: u8[>..]&,
}

// What yaml.v3 refuses when it decodes document d (or any node) into an
// interface{}, with its message: a scalar its tag does not fit, bad
// base64, an alias whose anchor contains it, a mapping whose keys repeat,
// a merge (<<) of something other than mappings, a collection as a key,
// and the alias bomb: a document of more than 1000 nodes, more than 100 of
// them inside aliases, whose share of nodes inside aliases is more than
// yaml.v3 allows (0.99 up to 400000 nodes, falling to 0.10 at 4000000).
// The error is empty when there is none.
fn check(d: Node&) -> Error {
    var heads = dictionary<u64, i64> {};
    var entries: MergeKey[>..<] = [];
    var expanding: (Node&)[>..<] = [];
    var errors: u8[>..] = [];
    var c = Check { heads: heads, entries: entries, expanding: expanding, errors: errors, .. };
    unmarshal(c, d);
    if errors.len > 0 {
        return Error { line: c.error_line, column: c.error_column, message: str("yaml: unmarshal errors:\n", errors) };
    }
    return Error { message: [] };
}

fn allowed_alias_ratio(decode_count: i64) -> f64 {
    if decode_count <= 400000 { return 0.99; }
    if decode_count >= 4000000 { return 0.10; }
    return 0.99 - 0.89 * ((decode_count - 400000) / 3600000.0);
}

fn decode_fail(n: Node&, what: const u8[:]) {
    return Error { line: n.line, column: n.column, message: str("yaml: ", what) } from check;
}

// d.unmarshal: counts n, and decodes it; false where yaml.v3's gives no
// value (a mapping with repeated keys).
recursive fn unmarshal<C>(c: C&, n: Node&) -> bool {
    c.decode_count++;
    if c.alias_depth > 0 { c.alias_count++; }
    if c.alias_count > 100 && c.decode_count > 1000
       && (c.alias_count as f64) / c.decode_count > allowed_alias_ratio(c.decode_count) {
        decode_fail(n, "document contains excessive aliasing");
    }
    if n.kind == DOCUMENT {
        guard n.count == 1 else { return false; }
        let r = n.first;
        if r { unmarshal(c, r); }
        return true;
    }
    if n.kind == ALIAS {
        for e in c.expanding {
            if e .== n { decode_fail(n, str("anchor '", n.value, "' value contains itself")); }
        }
        c.expanding.push(&n);
        c.alias_depth++;
        var good = false;
        let a = n.alias;
        if a { good = unmarshal(c, a); }
        c.alias_depth--;
        c.expanding.pop();
        return good;
    }
    if n.kind == SCALAR {
        if scalar_error(n).len > 0 {
            return Error { line: n.line, column: n.column, message: scalar_error(n) } from check;
        }
        return true;
    }
    if n.kind == SEQUENCE {
        var e = n.first;
        while e {
            unmarshal(c, e);
            e .= e.next;
        }
        return true;
    }
    return unmarshal_mapping(c, n);
}

recursive fn unmarshal_mapping<C>(c: C&, n: Node&) -> bool {
    if repeated_keys(c, n) { return false; }
    let merged = c.merged;
    c.merged = -1;
    var merge: Node? = null;
    var k = n.first;
    while k {
        let v = k.next;
        guard v else { break; }
        if is_merge(k) {
            merge .= v;
            k .= v.next;
            continue;
        }
        if unmarshal(c, k) {
            var skip_value = false;
            if merged >= 0 {
                skip_value = add_key(c, merge_key(merged, k));
            }
            if !skip_value {
                if is_collection(k) { decode_fail(k, "invalid map key"); }
                unmarshal(c, v);
            }
        }
        k .= v.next;
    }
    c.merged = merged;
    if merge { unmarshal_merge(c, n, merge); }
    return true;
}

// d.merge: the keys of parent, decoded into a set the first time, then the
// mappings of m, whose keys already in the set are passed over.
recursive fn unmarshal_merge<C>(c: C&, parent: Node&, m: Node&) {
    let merged = c.merged;
    if merged < 0 {
        c.merged = c.sets;
        c.sets++;
        var k = parent.first;
        while k {
            if unmarshal(c, k) { add_key(c, merge_key(c.merged, k)); }
            let v = k.next;
            guard v else { break; }
            k .= v.next;
        }
    }
    if m.kind == MAPPING {
        unmarshal(c, m);
    } else if m.kind == ALIAS {
        let a = m.alias;
        if a { if a.kind != MAPPING { decode_fail(m, "map merge requires map or sequence of maps as the value"); } }
        unmarshal(c, m);
    } else if m.kind == SEQUENCE {
        var e = m.first;
        while e {
            if e.kind == ALIAS {
                let a = e.alias;
                if a { if a.kind != MAPPING { decode_fail(e, "map merge requires map or sequence of maps as the value"); } }
            } else if e.kind != MAPPING {
                decode_fail(e, "map merge requires map or sequence of maps as the value");
            }
            unmarshal(c, e);
            e .= e.next;
        }
    } else {
        decode_fail(m, "map merge requires map or sequence of maps as the value");
    }
    c.merged = merged;
}

// Whether key n is a merge key: a plain << with no tag, or tagged !!merge.
fn is_merge(n: Node&) -> bool {
    n.kind == SCALAR && n.value == "<<" && (n.tag.len == 0 || n.tag == "!" || n.tag == "!!merge")
}

// Whether n, past its aliases, is a collection, which yaml.v3 does not take
// as a key.
fn is_collection(node: Node&) -> bool {
    var n .= node;
    while n.kind == ALIAS {
        let a = n.alias;
        guard a else { return false; }
        n .= a;
    }
    return n.kind == MAPPING || n.kind == SEQUENCE;
}

// Key n as decoded, in key set `set`: its kind and bits, or its text.
fn merge_key(set: i64, node: Node&) -> MergeKey {
    var n .= node;
    while n.kind == ALIAS {
        let a = n.alias;
        guard a else { break; }
        n .= a;
    }
    match resolve(n) {
        Null => { return MergeKey { set: set, kind: 1, bits: 0, text: "" }; },
        Bool b => { return MergeKey { set: set, kind: 2, bits: if b.v { 1 } else { 0 }, text: "" }; },
        Int i => { return MergeKey { set: set, kind: 3, bits: i.v as! u64, text: "" }; },
        Uint u => { return MergeKey { set: set, kind: 4, bits: u.v, text: "" }; },
        Float f => { return MergeKey { set: set, kind: 5, bits: float_text::bits_of(f.v), text: "" }; },
        Timestamp => { return MergeKey { set: set, kind: 6, bits: 0, text: n.value }; },
        _ => { return MergeKey { set: set, kind: 7, bits: 0, text: n.value }; },
    }
}

// Whether mapping n has keys of the same kind and value, which yaml.v3
// reports, each pair of them, line by line.
fn repeated_keys<C>(c: C&, n: Node&) -> bool {
    var seen = dictionary<const u8[:], u8> {};      // a value's kinds of key
    var repeated = false;
    var k = n.first;
    while k {
        let kinds = seen.get(k.value);
        if kinds {
            if (kinds & k.kind) != 0 { repeated = true; }
            kinds |= k.kind;
        } else {
            seen.insert(k.value, k.kind);
        }
        let v = k.next;
        guard v else { break; }
        k .= v.next;
    }
    guard repeated else { return false; }
    var ki = n.first;
    while ki {
        let vi = ki.next;
        guard vi else { break; }
        var kj = vi.next;
        while kj {
            if kj.kind == ki.kind && kj.value == ki.value {
                if c.errors.len == 0 {
                    c.error_line = kj.line;
                    c.error_column = kj.column;
                } else {
                    c.errors.push('\n');
                }
                format(c.errors, "  line ", kj.line, ": mapping key ");
                go_quote(c.errors, kj.value);
                format(c.errors, " already defined at line ", ki.line);
            }
            let vj = kj.next;
            guard vj else { break; }
            kj .= vj.next;
        }
        ki .= vi.next;
    }
    return true;
}

// s as Go's strconv.Quote writes it, for the characters it keeps or
// escapes in text: ASCII, \a \b \f \n \r \t \v, \xHH for other control
// bytes and bytes that are not UTF-8, \u for the C1 controls, U+00A0,
// U+00AD, U+2028, U+2029 and U+FEFF, and other characters as they are.
// (Go's test for printable characters is Unicode's; this one knows the
// usual ones.)
fn go_quote(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c < 0x80 {
            if c == '"' || c == '\\' { out.push('\\'); out.push(c); }
            else if c >= 0x20 && c < 0x7F { out.push(c); }
            else if c == 7 { out.append("\\a"); }
            else if c == 8 { out.append("\\b"); }
            else if c == 12 { out.append("\\f"); }
            else if c == 10 { out.append("\\n"); }
            else if c == 13 { out.append("\\r"); }
            else if c == 9 { out.append("\\t"); }
            else if c == 11 { out.append("\\v"); }
            else { out.append("\\x"); format_uint(out, c, 16, 2, '0'); }
            i++;
            continue;
        }
        let w = width(c);
        var cp = 0;
        var ok = w >= 2 && i + w <= s.len;
        if ok {
            cp = if w == 2 { c & 0x1F } else if w == 3 { c & 0x0F } else { c & 0x07 };
            for k in 1..w {
                if (s[i + k] & 0xC0) != 0x80 { ok = false; }
                cp = (cp << 6) | (s[i + k] & 0x3F);
            }
            ok = ok && !(w == 2 && cp < 0x80) && !(w == 3 && cp < 0x800) && !(w == 4 && cp < 0x10000)
                 && !(cp >= 0xD800 && cp <= 0xDFFF) && cp <= 0x10FFFF;
        }
        if !ok {
            out.append("\\x");
            format_uint(out, c, 16, 2, '0');
            i++;
            continue;
        }
        if (cp >= 0x80 && cp < 0xA0) || cp == 0xA0 || cp == 0xAD || cp == 0x2028 || cp == 0x2029 || cp == 0xFEFF {
            out.append("\\u");
            format_uint(out, cp as u64, 16, 4, '0');
        } else {
            out.append(s[i..i + w]);
        }
        i += w;
    }
    out.push('"');
}

// --- reading the tree -----------------------------------------------------------

// n past its aliases; null for null.
fn target(n: Node?) -> Node? {
    guard n else { return null; }
    var t .= n;
    while t.kind == ALIAS {
        let a = t.alias;
        guard a else { return null; }
        t .= a;
    }
    return t;
}

// F(key, value) for each pair of mapping n (past aliases), as yaml.v3
// decodes a mapping: its own pairs in order, then those of the mappings
// its merge key (<<) names, in order and theirs in turn, each key that
// came already passed over. Keys are compared as text. Nothing for null or
// a node that is not a mapping.
fn each_pair<F>(node: Node?) {
    let n = target(node);
    guard n else { return; }
    guard n.kind == MAPPING else { return; }
    var seen = dictionary<const u8[:], bool> {};
    var todo: (Node&)[>..<] = [];     // the mappings still to walk, the next last
    todo.push(&n);
    var top = true;
    while todo.len > 0 {
        let m .= todo[todo.len - 1];
        todo.pop();
        var merge: Node? = null;
        var k = m.first;
        while k {
            let v = k.next;
            guard v else { break; }
            if is_merge(k) {
                merge .= v;
            } else {
                let key = target(k);
                let text = if key { key.value } else { k.value };
                if top || seen.insert(text, true) {
                    if top { seen.insert(text, true); }
                    F(k, v);
                }
            }
            k .= v.next;
        }
        top = false;
        let g = target(merge);
        if g {
            if g.kind == MAPPING {
                todo.push(&g);
            } else if g.kind == SEQUENCE {
                let mark = todo.len;
                var e = g.first;
                while e {
                    let t = target(e);
                    if t { if t.kind == MAPPING { todo.push(&t); } }
                    e .= e.next;
                }
                reverse(todo[mark..]);
            }
        }
    }
}

// The value of the first pair of mapping n whose key's text is key, in
// each_pair's order (merges after the mapping's own pairs); null if there
// is none, or if n is null or no mapping, so that lookups chain. Aliases
// are followed.
fn member(n: Node?, key: u8[:]) -> Node? {
    each_pair(n) { k, v =>
        let t = target(k);
        if t { if t.kind == SCALAR && t.value == key { return target(v); } }
    };
    return null;
}

// Element i of sequence n, past aliases; null if there is none.
fn element(n: Node?, i: i64) -> Node? {
    let s = target(n);
    guard s else { return null; }
    guard s.kind == SEQUENCE && i >= 0 else { return null; }
    var e = s.first;
    var k = 0;
    while e {
        if k == i { return target(e); }
        k++;
        e .= e.next;
    }
    return null;
}

// F(element) for each element of sequence n (past aliases), in order.
fn each_element<F>(node: Node?) {
    let n = target(node);
    guard n else { return; }
    guard n.kind == SEQUENCE else { return; }
    var e = n.first;
    while e {
        F(e);
        e .= e.next;
    }
}

// Whether n (past aliases) is null: a scalar that resolves to null, or
// null itself.
fn is_null(node: Node?) -> bool {
    let n = target(node);
    guard n else { return true; }
    guard n.kind == SCALAR else { return false; }
    match resolve(n) {
        Null => { return true; },
        _ => { return false; },
    }
}

// An integer's value: an !!int scalar within i64's range; false for
// anything else.
fn as_i64(n: Node?) -> i64, bool {
    let t = target(n);
    guard t else { return 0, false; }
    match resolve(t) {
        Int i => { return i.v, true; },
        _ => { return 0, false; },
    }
}

// A number's value: an !!int or !!float scalar; false for anything else.
fn as_f64(n: Node?) -> f64, bool {
    let t = target(n);
    guard t else { return 0.0, false; }
    match resolve(t) {
        Int i => { return i.v, true; },
        Uint u => { return u.v, true; },
        Float f => { return f.v, true; },
        _ => { return 0.0, false; },
    }
}

fn as_bool(n: Node?) -> bool, bool {
    let t = target(n);
    guard t else { return false, false; }
    match resolve(t) {
        Bool b => { return b.v, true; },
        _ => { return false, false; },
    }
}

// A scalar's text, whatever it resolves to; false for a collection or
// null.
fn as_string(n: Node?) -> const u8[:], bool {
    let t = target(n);
    guard t else { return "", false; }
    guard t.kind == SCALAR else { return "", false; }
    return t.value, true;
}

// --- reading into the caller's types --------------------------------------------

// What a walk that reads the tree into the caller's own types has met, as
// yaml.v3's Unmarshal meets it: `read_int`, `read_string` and the rest read
// a node into an i64, a string and so on with the conversions yaml.v3
// makes for a field of that type (a float into an integer, yes and no into
// a bool, anything into a string, null into the zero value), and record the
// node that does not convert, as yaml.v3 does, without stopping the walk;
// `finish` says whether the walk met none. A scalar its tag does not fit,
// and bad base64, stop it: yaml.v3 fails the whole document for those.
struct Reader { count: i64 = 0, line: i64 = 0, column: i64 = 0, fatal: bool = false, errors: u8[>..] }

fn reader() -> Reader { Reader { errors: [], .. } }

// Whether nothing failed to convert.
fn finish(r: Reader&) -> bool { r.count == 0 }

// The errors as yaml.v3 words them: "yaml: unmarshal errors:" and a line
// for each ("line 3: cannot unmarshal !!str `abc` into int64"), or the
// error that stopped the walk.
fn message(r: Reader&) -> u8[>..] {
    if r.fatal { return copy(r.errors); }
    return str("yaml: unmarshal errors:\n", r.errors);
}

// A node that does not convert to `into`: yaml.v3's d.terror.
fn type_error(r: Reader&, n: Node&, into: const u8[:]) {
    if r.fatal { return; }
    if r.count == 0 {
        r.line = n.line;
        r.column = n.column;
    } else {
        r.errors.push('\n');
    }
    r.count++;
    format(r.errors, "  line ", n.line, ": cannot unmarshal ", n.tag);
    if n.tag != "!!seq" && n.tag != "!!map" {
        r.errors.append(" `");
        if n.value.len > 10 {
            r.errors.append(n.value[..7]);
            r.errors.append("...");
        } else {
            r.errors.append(n.value);
        }
        r.errors.push('`');
    }
    format(r.errors, " into ", into);
}

// The value of n as yaml.v3's d.scalar starts on it, or false when there
// is none to convert: null (or nothing), a collection (a type error), or a
// scalar that stops the walk.
fn read_scalar(r: Reader&, node: Node?, into: const u8[:]) -> Scalar, bool {
    guard !r.fatal else { return Scalar.Null, false; }
    let n = target(node);
    guard n else { return Scalar.Null, false; }
    guard n.kind == SCALAR else {
        type_error(r, n, into);
        return Scalar.Null, false;
    }
    let e = scalar_error(n);
    if e.len > 0 {
        r.fatal = true;
        r.count++;
        r.line = n.line;
        r.column = n.column;
        r.errors.clear();
        r.errors.append(e);
        return Scalar.Null, false;
    }
    let s = resolve(n);
    match s {
        Null => { return s, false; },
        _ => { return s, true; },
    }
}

// f converted to an i64 as Go converts it on arm64: truncated, and
// saturated at the ends of the range.
fn saturate_i64(f: f64) -> i64 {
    if f != f { return 0; }
    if f >= 9223372036854775807.0 { return 9223372036854775807; }
    if f <= -9223372036854775808.0 { return -9223372036854775807 - 1; }
    return f as! i64;
}

fn saturate_u64(f: f64) -> u64 {
    if f != f || f <= 0.0 { return 0; }
    if f >= 18446744073709551615.0 { return 0xFFFFFFFFFFFFFFFF; }
    return f as! u64;
}

// n read as an int64 field: an integer in range, or a float (truncated)
// at most 2^63.
fn read_int(r: Reader&, n: Node?) -> i64 {
    let s, ok = read_scalar(r, n, "int64");
    guard ok else { return 0; }
    match s {
        Int i => { return i.v; },
        Uint u => { if u.v <= 0x7FFFFFFFFFFFFFFF { return u.v as! i64; } },
        Float f => { if f.v <= 9223372036854775807.0 { return saturate_i64(f.v); } },
        _ => {},
    }
    let t = target(n);
    if t { type_error(r, t, "int64"); }
    return 0;
}

// n read as a uint64 field: an integer at least 0, or a float at most
// 2^64.
fn read_uint(r: Reader&, n: Node?) -> u64 {
    let s, ok = read_scalar(r, n, "uint64");
    guard ok else { return 0; }
    match s {
        Int i => { if i.v >= 0 { return i.v as! u64; } },
        Uint u => { return u.v; },
        Float f => { if f.v <= 18446744073709551615.0 { return saturate_u64(f.v); } },
        _ => {},
    }
    let t = target(n);
    if t { type_error(r, t, "uint64"); }
    return 0;
}

// n read as a float64 field: any number.
fn read_float(r: Reader&, n: Node?) -> f64 {
    let s, ok = read_scalar(r, n, "float64");
    guard ok else { return 0.0; }
    match s {
        Int i => { return i.v; },
        Uint u => { return u.v; },
        Float f => { return f.v; },
        _ => {},
    }
    let t = target(n);
    if t { type_error(r, t, "float64"); }
    return 0.0;
}

// n read as a bool field: true or false, or text that YAML 1.1 reads as
// one (y, yes, on, n, no, off, in their cases).
fn read_bool(r: Reader&, n: Node?) -> bool {
    let s, ok = read_scalar(r, n, "bool");
    guard ok else { return false; }
    match s {
        Bool b => { return b.v; },
        Str, Binary, Invalid => {
            let t = target(n);
            if t {
                let v = t.value;
                if v == "y" || v == "Y" || v == "yes" || v == "Yes" || v == "YES" || v == "on" || v == "On" || v == "ON" { return true; }
                if v == "n" || v == "N" || v == "no" || v == "No" || v == "NO" || v == "off" || v == "Off" || v == "OFF" { return false; }
            }
        },
        _ => {},
    }
    let t = target(n);
    if t { type_error(r, t, "bool"); }
    return false;
}

// n read as a string field: a scalar's text, whatever it resolves to, the
// bytes of a !!binary one decoded onto scratch; "" for null.
fn read_string(r: Reader&, n: Node?, scratch: u8[>..]&) -> const u8[:] {
    let s, ok = read_scalar(r, n, "string");
    guard ok else { return ""; }
    let t = target(n);
    guard t else { return ""; }
    match s {
        Binary => {
            let first = scratch.len;
            binary(t, scratch);
            return scratch[first..];
        },
        _ => { return t.value; },
    }
}

// F(key, value) for each pair of mapping n, as each_pair gives them, the
// key's text and the value past its aliases; a node that is not a mapping
// is a type error, `into` its type.
fn each_member<F>(r: Reader&, n: Node?, into: const u8[:] = "map[string]interface {}") {
    let t = target(n);
    guard t else { return; }
    guard t.kind == MAPPING else {
        type_error(r, t, into);
        return;
    }
    each_pair(t) { k, v =>
        let kt = target(k);
        let vt = target(v);
        if kt { if vt { F(kt.value, vt); } }
    };
}

// F(element) for each element of sequence n, past its aliases; a node that
// is not a sequence is a type error, `into` its type.
fn each_item<F>(r: Reader&, n: Node?, into: const u8[:] = "[]interface {}") {
    let t = target(n);
    guard t else { return; }
    guard t.kind == SEQUENCE else {
        type_error(r, t, into);
        return;
    }
    var e = t.first;
    while e {
        let et = target(e);
        if et { F(et); }
        e .= e.next;
    }
}

// --- writing --------------------------------------------------------------------

// A node to write, as yaml.v3's encoder makes it an event for its emitter:
// the anchor, the tag's handle and suffix (empty for a tag left out), the
// value, the style, and whether the tag may be left out of a plain or a
// quoted scalar.
struct OutEvent {
    kind: i64,
    anchor: const u8[:] = "",
    handle: const u8[:] = "",
    suffix: const u8[:] = "",
    value: const u8[:] = "",
    style: i64 = 0,
    flow: bool = false,
    implicit: bool = true,
    quoted_implicit: bool = true,
}

// The emitter's states, in libyaml's order.
let W_STREAM_START = 0;
let W_FIRST_DOCUMENT_START = 1;
let W_DOCUMENT_START = 2;
let W_DOCUMENT_CONTENT = 3;
let W_DOCUMENT_END = 4;
let W_FLOW_SEQUENCE_FIRST_ITEM = 5;
let W_FLOW_SEQUENCE_ITEM = 7;
let W_FLOW_MAPPING_FIRST_KEY = 8;
let W_FLOW_MAPPING_KEY = 10;
let W_FLOW_MAPPING_SIMPLE_VALUE = 11;
let W_FLOW_MAPPING_VALUE = 12;
let W_BLOCK_SEQUENCE_FIRST_ITEM = 13;
let W_BLOCK_SEQUENCE_ITEM = 14;
let W_BLOCK_MAPPING_FIRST_KEY = 15;
let W_BLOCK_MAPPING_KEY = 16;
let W_BLOCK_MAPPING_SIMPLE_VALUE = 17;
let W_BLOCK_MAPPING_VALUE = 18;
let W_END = 19;

// libyaml's emitter, as yaml.v3 sets it up (indentation 4, no width,
// Unicode as it is, '\n' line breaks): the events, where it is in them and
// in its output, its analysis of the event at hand, and its stacks of
// states and indentation. Errors leave through `return … from emit`.
struct Emitter {
    out: u8[>..]&,
    events: OutEvent[>..]&,
    states: i64[>..<]&,
    indents: i64[>..<]&,
    head: i64 = 0,
    state: i64 = 0,
    best_indent: i64 = 4,
    best_width: i64 = 2147483647,
    indent: i64 = -1,
    flow_level: i64 = 0,
    root_context: bool = false,
    sequence_context: bool = false,
    mapping_context: bool = false,
    simple_key_context: bool = false,
    line: i64 = 0,
    column: i64 = 0,
    whitespace: bool = true,
    indention: bool = true,
    open_ended: bool = false,
    space_above: bool = true,
    foot_indent: i64 = -1,
    // the event at hand, analyzed
    anchor: const u8[:] = "",
    has_anchor: bool = false,
    alias: bool = false,
    handle: const u8[:] = "",
    suffix: const u8[:] = "",
    value: const u8[:] = "",
    multiline: bool = false,
    flow_plain_allowed: bool = false,
    block_plain_allowed: bool = false,
    single_quoted_allowed: bool = false,
    block_allowed: bool = false,
    style: i64 = 0,
}

fn emit_error(problem: const u8[:]) {
    return Error { message: str("yaml: ", problem) } from emit;
}

fn put<E>(e: E&, c: u8) {
    e.out.push(c);
    e.column++;
}

fn put_break<E>(e: E&) {
    e.out.push('\n');
    if e.column == 0 { e.space_above = true; }
    e.column = 0;
    e.line++;
    e.indention = true;
}

// The character at s[i] to the output; the index past it.
fn write_char<E>(e: E&, s: const u8[:], i: i64) -> i64 {
    let w = max(1, width(s[i]));
    e.out.append(s[i..i + w]);
    e.column++;
    return i + w;
}

fn write_all<E>(e: E&, s: const u8[:]) {
    var i = 0;
    while i < s.len { i = write_char(e, s, i); }
}

fn write_break<E>(e: E&, s: const u8[:], i: i64) -> i64 {
    if s[i] == '\n' {
        put_break(e);
        return i + 1;
    }
    let next = write_char(e, s, i);
    if e.column == 0 { e.space_above = true; }
    e.column = 0;
    e.line++;
    e.indention = true;
    return next;
}

// The characters libyaml's emitter writes as they are; it escapes the
// rest in double quotes.
fn is_printable(s: const u8[:], i: i64) -> bool {
    let c = s[i];
    let c1 = if i + 1 < s.len { s[i + 1] } else { 0 };
    let c2 = if i + 2 < s.len { s[i + 2] } else { 0 };
    return c == 0x0A || (c >= 0x20 && c <= 0x7E) || (c == 0xC2 && c1 >= 0xA0) || (c > 0xC2 && c < 0xED)
           || (c == 0xED && c1 < 0xA0) || c == 0xEE
           || (c == 0xEF && !(c1 == 0xBB && c2 == 0xBF) && !(c1 == 0xBF && (c2 == 0xBE || c2 == 0xBF)));
}

fn str_is_break(s: const u8[:], i: i64) -> bool {
    guard i < s.len else { return false; }
    let c = s[i];
    if c == '\r' || c == '\n' { return true; }
    if c == 0xC2 { return i + 1 < s.len && s[i + 1] == 0x85; }
    if c == 0xE2 { return i + 2 < s.len && s[i + 1] == 0x80 && (s[i + 2] == 0xA8 || s[i + 2] == 0xA9); }
    return false;
}

fn str_is_space(s: const u8[:], i: i64) -> bool { i < s.len && s[i] == ' ' }

fn str_is_blank(s: const u8[:], i: i64) -> bool { i < s.len && (s[i] == ' ' || s[i] == '\t') }

fn str_is_blankz(s: const u8[:], i: i64) -> bool { i >= s.len || s[i] == 0 || str_is_blank(s, i) || str_is_break(s, i) }

// yaml.v3's emitter's BOM test, which looks at the start of the value, not
// at i: a value that starts with a BOM has all of its characters escaped
// in double quotes.
fn str_is_bom(s: const u8[:]) -> bool { s.len >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF }

// Whether s is valid UTF-8 as Go's utf8.ValidString has it.
fn valid_utf8(s: const u8[:]) -> bool {
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c < 0x80 { i++; continue; }
        let w = width(c);
        guard w >= 2 && i + w <= s.len else { return false; }
        var cp: i64 = if w == 2 { c & 0x1F } else if w == 3 { c & 0x0F } else { c & 0x07 };
        for k in 1..w {
            guard (s[i + k] & 0xC0) == 0x80 else { return false; }
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        guard !(w == 2 && cp < 0x80) && !(w == 3 && cp < 0x800) && !(w == 4 && cp < 0x10000)
              && !(cp >= 0xD800 && cp <= 0xDFFF) && cp <= 0x10FFFF else { return false; }
        i += w;
    }
    return true;
}

// The events yaml.v3's encoder makes of node n for its emitter, onto
// events: a tag left out where the node resolves to it anyway, a !!str
// that would resolve to something else written double-quoted, a value
// with a line break written literal, and text that is not UTF-8 written
// as !!binary base64 (onto scratch).
fn node_events<N>(n: N&, events: OutEvent[>..]&, scratch: u8[>..]&) {
    var todo: (Node&)[>..<] = [];      // the nodes still to do, the next last
    var ends: i64[>..<] = [];          // how many of todo's entries are ends
    todo.push(&n);
    ends.push(0);
    while todo.len > 0 {
        let m .= todo[todo.len - 1];
        let is_end = ends[ends.len - 1];
        todo.pop();
        ends.pop();
        if is_end != 0 {
            events.push(OutEvent { kind: if m.kind == DOCUMENT { E_DOCUMENT_END } else if m.kind == MAPPING { E_MAPPING_END } else { E_SEQUENCE_END }, .. });
            continue;
        }
        var drop_tag = false;
        var force_quoting = false;
        if m.tag.len > 0 && (m.style & TAGGED) == 0 {
            if m.kind == SCALAR {
                if same_tag(m.tag, "!!str") && (m.style & (SINGLE_QUOTED | DOUBLE_QUOTED | LITERAL | FOLDED)) != 0 {
                    drop_tag = true;
                } else {
                    let rtag = resolve_tag(m.value);
                    if same_tag(m.tag, rtag) {
                        drop_tag = true;
                    } else if same_tag(m.tag, "!!str") {
                        drop_tag = true;
                        force_quoting = true;
                    }
                }
            } else if (m.kind == MAPPING && same_tag(m.tag, "!!map")) || (m.kind == SEQUENCE && same_tag(m.tag, "!!seq")) {
                drop_tag = true;
            }
        }
        let tag = if drop_tag { "" } else { m.tag };
        let h, s = tag_parts(tag);
        let implicit = tag.len == 0;
        if m.kind == DOCUMENT || m.kind == SEQUENCE || m.kind == MAPPING {
            if m.kind == DOCUMENT {
                events.push(OutEvent { kind: E_DOCUMENT_START, .. });
            } else {
                events.push(OutEvent { kind: if m.kind == MAPPING { E_MAPPING_START } else { E_SEQUENCE_START },
                                       anchor: m.anchor, handle: h, suffix: s, flow: (m.style & FLOW) != 0,
                                       implicit: implicit, quoted_implicit: implicit, .. });
            }
            todo.push(&m);
            ends.push(1);
            let mark = todo.len;
            var c = m.first;
            while c {
                todo.push(&c);
                ends.push(0);
                c .= c.next;
            }
            reverse(todo[mark..]);
            continue;
        }
        if m.kind == ALIAS {
            events.push(OutEvent { kind: E_ALIAS, anchor: m.value, .. });
            continue;
        }
        let utf8 = valid_utf8(m.value);
        let first = scratch.len;
        if !utf8 {
            if same_tag(m.tag, "!!binary") { emit_error("explicitly tagged !!binary data must be base64-encoded"); }
            if m.tag.len > 0 {
                if starts_with(m.tag, LONG_TAG_PREFIX) {
                    emit_error(str("cannot marshal invalid UTF-8 data as !!", m.tag[LONG_TAG_PREFIX.len..]));
                }
                emit_error(str("cannot marshal invalid UTF-8 data as ", m.tag));
            }
            encode_base64(scratch, m.value);
        }
        let value = if utf8 { m.value } else { scratch[first..] };
        let vh = if utf8 { h } else { "!!" };
        let vs = if utf8 { s } else { "binary" };
        let vimplicit = utf8 && implicit;
        var style = S_PLAIN;
        if (m.style & DOUBLE_QUOTED) != 0 { style = S_DOUBLE; }
        else if (m.style & SINGLE_QUOTED) != 0 { style = S_SINGLE; }
        else if (m.style & LITERAL) != 0 { style = S_LITERAL; }
        else if (m.style & FOLDED) != 0 { style = S_FOLDED; }
        else if find(value, "\n") >= 0 { style = S_LITERAL; }
        else if force_quoting { style = S_DOUBLE; }
        events.push(OutEvent { kind: E_SCALAR, anchor: m.anchor, handle: vh, suffix: vs, value: value, style: style,
                               implicit: vimplicit, quoted_implicit: vimplicit, .. });
    }
}

// Whether tag, in either form, is the core schema's tag short (!!str).
fn same_tag(tag: const u8[:], short: const u8[:]) -> bool {
    if tag == short { return true; }
    return starts_with(short, "!!") && starts_with(tag, LONG_TAG_PREFIX) && tag[LONG_TAG_PREFIX.len..] == short[2..];
}

// The handle and suffix the emitter writes tag with, by the default tag
// directives: !! for tag:yaml.org,2002:, ! for a local tag, and none (a
// verbatim tag) otherwise.
fn tag_parts(tag: const u8[:]) -> const u8[:], const u8[:] {
    if tag.len == 0 { return "", ""; }
    if starts_with(tag, "!!") { return "!!", tag[2..]; }
    if tag[0] == '!' { return "!", tag[1..]; }
    if starts_with(tag, LONG_TAG_PREFIX) { return "!!", tag[LONG_TAG_PREFIX.len..]; }
    return "", tag;
}

// s in base64, as yaml.v3's encodeBase64 writes it: in lines of 70, each
// ending in a line break, when it takes more than one.
fn encode_base64(out: u8[>..]&, s: const u8[:]) {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var enc: u8[>..] = [];
    var i = 0;
    while i + 3 <= s.len {
        let v = ((s[i] as u32) << 16) | ((s[i + 1] as u32) << 8) | s[i + 2];
        enc.push(alphabet[(v >> 18) & 63]);
        enc.push(alphabet[(v >> 12) & 63]);
        enc.push(alphabet[(v >> 6) & 63]);
        enc.push(alphabet[v & 63]);
        i += 3;
    }
    if s.len - i == 1 {
        let v = (s[i] as u32) << 16;
        enc.push(alphabet[(v >> 18) & 63]);
        enc.push(alphabet[(v >> 12) & 63]);
        enc.append("==");
    } else if s.len - i == 2 {
        let v = ((s[i] as u32) << 16) | ((s[i + 1] as u32) << 8);
        enc.push(alphabet[(v >> 18) & 63]);
        enc.push(alphabet[(v >> 12) & 63]);
        enc.push(alphabet[(v >> 6) & 63]);
        enc.push('=');
    }
    let lines = enc.len / 70 + 1;
    var k = 0;
    while k < enc.len {
        let j = min(k + 70, enc.len);
        out.append(enc[k..j]);
        if lines > 1 { out.push('\n'); }
        k = j;
    }
}

// Writes node n as yaml.v3's Marshal(&n) writes it: a document as it is,
// any other node as the root of one. The error is the emitter's, which
// refuses an anchor that is not alphanumeric, an empty tag, and text that
// is not UTF-8 with a tag other than !!binary (text that is not UTF-8
// without a tag it writes as !!binary base64); empty when there is none,
// and then out has the text.
fn write(out: u8[>..]&, n: Node&) -> Error { emit(out, n, false) }

// Writes a stream of documents, n and those linked from it by `next`, as
// yaml.v3's Encoder writes them, a document at a time: the second and later
// after a "---" line.
fn write_stream(out: u8[>..]&, n: Node&) -> Error { emit(out, n, true) }

fn emit(out: u8[>..]&, n: Node&, stream: bool) -> Error {
    var events: OutEvent[>..] = [];
    var scratch: u8[>..] = [];
    var states: i64[>..<] = [];
    var indents: i64[>..<] = [];
    events.push(OutEvent { kind: E_STREAM_START, .. });
    var d .= n;
    loop {
        if d.kind == DOCUMENT {
            node_events(d, events, scratch);
        } else {
            events.push(OutEvent { kind: E_DOCUMENT_START, .. });
            node_events(d, events, scratch);
            events.push(OutEvent { kind: E_DOCUMENT_END, .. });
        }
        guard stream else { break; }
        let next = d.next;
        guard next else { break; }
        d .= next;
    }
    events.push(OutEvent { kind: E_STREAM_END, .. });
    let first = out.len;
    var e = Emitter { out: out, events: events, states: states, indents: indents, .. };
    while e.head < e.events.len {
        let ev = e.events[e.head];
        // yaml.v3's encoder clears open_ended before the end of the stream,
        // so that no "..." ends it.
        if ev.kind == E_STREAM_END { e.open_ended = false; }
        analyze_event(e, ev);
        state_machine(e, ev);
        e.head++;
    }
    return Error { message: [] };
}

fn analyze_event<E>(e: E&, ev: OutEvent) {
    e.has_anchor = false;
    e.anchor = "";
    e.handle = "";
    e.suffix = "";
    e.value = "";
    if ev.kind == E_ALIAS {
        analyze_anchor(e, ev.anchor, true);
    } else if ev.kind == E_SCALAR || ev.kind == E_SEQUENCE_START || ev.kind == E_MAPPING_START {
        if ev.anchor.len > 0 { analyze_anchor(e, ev.anchor, false); }
        let tagged = ev.handle.len > 0 || ev.suffix.len > 0;
        if tagged && !ev.implicit && (ev.kind != E_SCALAR || !ev.quoted_implicit) {
            e.handle = ev.handle;
            e.suffix = ev.suffix;
        }
        if ev.kind == E_SCALAR { analyze_scalar(e, ev.value); }
    }
}

fn analyze_anchor<E>(e: E&, anchor: const u8[:], alias: bool) {
    if anchor.len == 0 { emit_error(if alias { "alias value must not be empty" } else { "anchor value must not be empty" }); }
    var i = 0;
    while i < anchor.len {
        if !is_alpha(anchor[i]) {
            emit_error(if alias { "alias value must contain alphanumerical characters only" } else { "anchor value must contain alphanumerical characters only" });
        }
        i += max(1, width(anchor[i]));
    }
    e.anchor = anchor;
    e.has_anchor = true;
    e.alias = alias;
}

// What styles scalar value may be written in, as libyaml's emitter works
// it out.
fn analyze_scalar<E>(e: E&, value: const u8[:]) {
    e.value = value;
    if value.len == 0 {
        e.multiline = false;
        e.flow_plain_allowed = false;
        e.block_plain_allowed = true;
        e.single_quoted_allowed = true;
        e.block_allowed = false;
        return;
    }
    var block_indicators = false;
    var flow_indicators = false;
    var line_breaks = false;
    var special_characters = false;
    var tab_characters = false;
    var leading_space = false;
    var leading_break = false;
    var trailing_space = false;
    var trailing_break = false;
    var break_space = false;
    var space_break = false;
    var preceded_by_whitespace = true;
    var previous_space = false;
    var previous_break = false;
    if value.len >= 3 && ((value[0] == '-' && value[1] == '-' && value[2] == '-') || (value[0] == '.' && value[1] == '.' && value[2] == '.')) {
        block_indicators = true;
        flow_indicators = true;
    }
    var i = 0;
    while i < value.len {
        let c = value[i];
        let w = max(1, width(c));
        let followed_by_whitespace = i + w >= value.len || str_is_blank(value, i + w);
        if i == 0 {
            if c == '#' || c == ',' || c == '[' || c == ']' || c == '{' || c == '}' || c == '&' || c == '*' || c == '!'
               || c == '|' || c == '>' || c == '\'' || c == '"' || c == '%' || c == '@' || c == '`' {
                flow_indicators = true;
                block_indicators = true;
            } else if c == '?' || c == ':' {
                flow_indicators = true;
                if followed_by_whitespace { block_indicators = true; }
            } else if c == '-' {
                if followed_by_whitespace {
                    flow_indicators = true;
                    block_indicators = true;
                }
            }
        } else {
            if c == ',' || c == '?' || c == '[' || c == ']' || c == '{' || c == '}' {
                flow_indicators = true;
            } else if c == ':' {
                flow_indicators = true;
                if followed_by_whitespace { block_indicators = true; }
            } else if c == '#' {
                if preceded_by_whitespace {
                    flow_indicators = true;
                    block_indicators = true;
                }
            }
        }
        if c == '\t' {
            tab_characters = true;
        } else if !is_printable(value, i) {
            special_characters = true;
        }
        if c == ' ' {
            if i == 0 { leading_space = true; }
            if i + w == value.len { trailing_space = true; }
            if previous_break { break_space = true; }
            previous_space = true;
            previous_break = false;
        } else if str_is_break(value, i) {
            line_breaks = true;
            if i == 0 { leading_break = true; }
            if i + w == value.len { trailing_break = true; }
            if previous_space { space_break = true; }
            previous_space = false;
            previous_break = true;
        } else {
            previous_space = false;
            previous_break = false;
        }
        preceded_by_whitespace = str_is_blankz(value, i);
        i += w;
    }
    e.multiline = line_breaks;
    e.flow_plain_allowed = true;
    e.block_plain_allowed = true;
    e.single_quoted_allowed = true;
    e.block_allowed = true;
    if leading_space || leading_break || trailing_space || trailing_break {
        e.flow_plain_allowed = false;
        e.block_plain_allowed = false;
    }
    if trailing_space { e.block_allowed = false; }
    if break_space {
        e.flow_plain_allowed = false;
        e.block_plain_allowed = false;
        e.single_quoted_allowed = false;
    }
    if space_break || tab_characters || special_characters {
        e.flow_plain_allowed = false;
        e.block_plain_allowed = false;
        e.single_quoted_allowed = false;
    }
    if space_break || special_characters { e.block_allowed = false; }
    if line_breaks {
        e.flow_plain_allowed = false;
        e.block_plain_allowed = false;
    }
    if flow_indicators { e.flow_plain_allowed = false; }
    if block_indicators { e.block_plain_allowed = false; }
}

fn pop_emit_state<E>(e: E&) {
    e.state = e.states[e.states.len - 1];
    e.states.pop();
}

fn pop_indent<E>(e: E&) {
    e.indent = e.indents[e.indents.len - 1];
    e.indents.pop();
}

fn increase_indent<E>(e: E&, flow: bool, indentless: bool) {
    e.indents.push(e.indent);
    if e.indent < 0 {
        e.indent = if flow { e.best_indent } else { 0 };
    } else if !indentless {
        if e.states[e.states.len - 1] == W_BLOCK_SEQUENCE_ITEM {
            e.indent += 2;
        } else {
            e.indent = e.best_indent * ((e.indent + e.best_indent) / e.best_indent);
        }
    }
}

fn state_machine<E>(e: E&, ev: OutEvent) {
    let s = e.state;
    if s == W_STREAM_START { emit_stream_start(e, ev); }
    else if s == W_FIRST_DOCUMENT_START { emit_document_start(e, ev, true); }
    else if s == W_DOCUMENT_START { emit_document_start(e, ev, false); }
    else if s == W_DOCUMENT_CONTENT { emit_document_content(e, ev); }
    else if s == W_DOCUMENT_END { emit_document_end(e, ev); }
    else if s == W_FLOW_SEQUENCE_FIRST_ITEM { emit_flow_sequence_item(e, ev, true); }
    else if s == W_FLOW_SEQUENCE_ITEM { emit_flow_sequence_item(e, ev, false); }
    else if s == W_FLOW_MAPPING_FIRST_KEY { emit_flow_mapping_key(e, ev, true); }
    else if s == W_FLOW_MAPPING_KEY { emit_flow_mapping_key(e, ev, false); }
    else if s == W_FLOW_MAPPING_SIMPLE_VALUE { emit_flow_mapping_value(e, ev, true); }
    else if s == W_FLOW_MAPPING_VALUE { emit_flow_mapping_value(e, ev, false); }
    else if s == W_BLOCK_SEQUENCE_FIRST_ITEM { emit_block_sequence_item(e, ev, true); }
    else if s == W_BLOCK_SEQUENCE_ITEM { emit_block_sequence_item(e, ev, false); }
    else if s == W_BLOCK_MAPPING_FIRST_KEY { emit_block_mapping_key(e, ev, true); }
    else if s == W_BLOCK_MAPPING_KEY { emit_block_mapping_key(e, ev, false); }
    else if s == W_BLOCK_MAPPING_SIMPLE_VALUE { emit_block_mapping_value(e, ev, true); }
    else if s == W_BLOCK_MAPPING_VALUE { emit_block_mapping_value(e, ev, false); }
    else { emit_error("expected nothing after STREAM-END"); }
}

fn emit_stream_start<E>(e: E&, ev: OutEvent) {
    if ev.kind != E_STREAM_START { emit_error("expected STREAM-START"); }
    e.indent = -1;
    e.line = 0;
    e.column = 0;
    e.whitespace = true;
    e.indention = true;
    e.space_above = true;
    e.foot_indent = -1;
    e.state = W_FIRST_DOCUMENT_START;
}

fn emit_document_start<E>(e: E&, ev: OutEvent, first: bool) {
    if ev.kind == E_DOCUMENT_START {
        // yaml.v3's documents are all implicit, with no directives: only
        // the second and later start with "---".
        if !first {
            write_indent(e);
            write_indicator(e, "---", true, false, false);
            write_indent(e);
        }
        e.state = W_DOCUMENT_CONTENT;
        return;
    }
    if ev.kind == E_STREAM_END {
        if e.open_ended {
            write_indicator(e, "...", true, false, false);
            write_indent(e);
        }
        e.state = W_END;
        return;
    }
    emit_error("expected DOCUMENT-START or STREAM-END");
}

fn emit_document_content<E>(e: E&, ev: OutEvent) {
    e.states.push(W_DOCUMENT_END);
    emit_any(e, ev, true, false, false, false);
}

fn emit_document_end<E>(e: E&, ev: OutEvent) {
    if ev.kind != E_DOCUMENT_END { emit_error("expected DOCUMENT-END"); }
    e.foot_indent = -1;
    write_indent(e);
    e.state = W_DOCUMENT_START;
}

fn emit_flow_sequence_item<E>(e: E&, ev: OutEvent, first: bool) {
    if first {
        write_indicator(e, "[", true, true, false);
        increase_indent(e, true, false);
        e.flow_level++;
    }
    if ev.kind == E_SEQUENCE_END {
        e.flow_level--;
        pop_indent(e);
        if e.column == 0 { write_indent(e); }
        write_indicator(e, "]", false, false, false);
        pop_emit_state(e);
        return;
    }
    if !first { write_indicator(e, ",", false, false, false); }
    if e.column == 0 { write_indent(e); }
    if e.column > e.best_width { write_indent(e); }
    e.states.push(W_FLOW_SEQUENCE_ITEM);
    emit_any(e, ev, false, true, false, false);
}

fn emit_flow_mapping_key<E>(e: E&, ev: OutEvent, first: bool) {
    if first {
        write_indicator(e, "{", true, true, false);
        increase_indent(e, true, false);
        e.flow_level++;
    }
    if ev.kind == E_MAPPING_END {
        e.flow_level--;
        pop_indent(e);
        write_indicator(e, "}", false, false, false);
        pop_emit_state(e);
        return;
    }
    if !first { write_indicator(e, ",", false, false, false); }
    if e.column == 0 { write_indent(e); }
    if e.column > e.best_width { write_indent(e); }
    if check_simple_key(e) {
        e.states.push(W_FLOW_MAPPING_SIMPLE_VALUE);
        emit_any(e, ev, false, false, true, true);
        return;
    }
    write_indicator(e, "?", true, false, false);
    e.states.push(W_FLOW_MAPPING_VALUE);
    emit_any(e, ev, false, false, true, false);
}

fn emit_flow_mapping_value<E>(e: E&, ev: OutEvent, simple: bool) {
    if simple {
        write_indicator(e, ":", false, false, false);
    } else {
        if e.column > e.best_width { write_indent(e); }
        write_indicator(e, ":", true, false, false);
    }
    e.states.push(W_FLOW_MAPPING_KEY);
    emit_any(e, ev, false, false, true, false);
}

fn emit_block_sequence_item<E>(e: E&, ev: OutEvent, first: bool) {
    if first { increase_indent(e, false, false); }
    if ev.kind == E_SEQUENCE_END {
        pop_indent(e);
        pop_emit_state(e);
        return;
    }
    write_indent(e);
    write_indicator(e, "-", true, false, true);
    e.states.push(W_BLOCK_SEQUENCE_ITEM);
    emit_any(e, ev, false, true, false, false);
}

fn emit_block_mapping_key<E>(e: E&, ev: OutEvent, first: bool) {
    if first { increase_indent(e, false, false); }
    if ev.kind == E_MAPPING_END {
        pop_indent(e);
        pop_emit_state(e);
        return;
    }
    write_indent(e);
    if check_simple_key(e) {
        e.states.push(W_BLOCK_MAPPING_SIMPLE_VALUE);
        emit_any(e, ev, false, false, true, true);
        return;
    }
    write_indicator(e, "?", true, false, true);
    e.states.push(W_BLOCK_MAPPING_VALUE);
    emit_any(e, ev, false, false, true, false);
}

fn emit_block_mapping_value<E>(e: E&, ev: OutEvent, simple: bool) {
    if simple {
        write_indicator(e, ":", false, false, false);
    } else {
        write_indent(e);
        write_indicator(e, ":", true, false, true);
    }
    e.states.push(W_BLOCK_MAPPING_KEY);
    emit_any(e, ev, false, false, true, false);
}

fn emit_any<E>(e: E&, ev: OutEvent, root: bool, sequence: bool, mapping: bool, simple_key: bool) {
    e.root_context = root;
    e.sequence_context = sequence;
    e.mapping_context = mapping;
    e.simple_key_context = simple_key;
    if ev.kind == E_ALIAS {
        process_anchor(e);
        pop_emit_state(e);
    } else if ev.kind == E_SCALAR {
        select_scalar_style(e, ev);
        process_anchor(e);
        process_tag(e);
        increase_indent(e, true, false);
        process_scalar(e);
        pop_indent(e);
        pop_emit_state(e);
    } else if ev.kind == E_SEQUENCE_START {
        process_anchor(e);
        process_tag(e);
        e.state = if e.flow_level > 0 || ev.flow || check_empty(e, E_SEQUENCE_START, E_SEQUENCE_END) { W_FLOW_SEQUENCE_FIRST_ITEM } else { W_BLOCK_SEQUENCE_FIRST_ITEM };
    } else if ev.kind == E_MAPPING_START {
        process_anchor(e);
        process_tag(e);
        e.state = if e.flow_level > 0 || ev.flow || check_empty(e, E_MAPPING_START, E_MAPPING_END) { W_FLOW_MAPPING_FIRST_KEY } else { W_BLOCK_MAPPING_FIRST_KEY };
    } else {
        emit_error("expected SCALAR, SEQUENCE-START, MAPPING-START, or ALIAS");
    }
}

// Whether the event at hand starts a collection that ends at once.
fn check_empty<E>(e: E&, start: i64, end: i64) -> bool {
    e.head + 1 < e.events.len && e.events[e.head].kind == start && e.events[e.head + 1].kind == end
}

// Whether the event at hand can be a simple key: an alias, a one-line
// scalar, or an empty collection, of at most 128 bytes with its anchor and
// tag.
fn check_simple_key<E>(e: E&) -> bool {
    let k = e.events[e.head].kind;
    var length = 0;
    if k == E_ALIAS {
        length = e.anchor.len;
    } else if k == E_SCALAR {
        if e.multiline { return false; }
        length = e.anchor.len + e.handle.len + e.suffix.len + e.value.len;
    } else if k == E_SEQUENCE_START {
        if !check_empty(e, E_SEQUENCE_START, E_SEQUENCE_END) { return false; }
        length = e.anchor.len + e.handle.len + e.suffix.len;
    } else if k == E_MAPPING_START {
        if !check_empty(e, E_MAPPING_START, E_MAPPING_END) { return false; }
        length = e.anchor.len + e.handle.len + e.suffix.len;
    } else {
        return false;
    }
    return length <= 128;
}

fn select_scalar_style<E>(e: E&, ev: OutEvent) {
    let no_tag = e.handle.len == 0 && e.suffix.len == 0;
    if no_tag && !ev.implicit && !ev.quoted_implicit { emit_error("neither tag nor implicit flags are specified"); }
    var style = if ev.style == 0 { S_PLAIN } else { ev.style };
    if e.simple_key_context && e.multiline { style = S_DOUBLE; }
    if style == S_PLAIN {
        if (e.flow_level > 0 && !e.flow_plain_allowed) || (e.flow_level == 0 && !e.block_plain_allowed) { style = S_SINGLE; }
        if e.value.len == 0 && (e.flow_level > 0 || e.simple_key_context) { style = S_SINGLE; }
        if no_tag && !ev.implicit { style = S_SINGLE; }
    }
    if style == S_SINGLE && !e.single_quoted_allowed { style = S_DOUBLE; }
    if (style == S_LITERAL || style == S_FOLDED) && (!e.block_allowed || e.flow_level > 0 || e.simple_key_context) { style = S_DOUBLE; }
    if no_tag && !ev.quoted_implicit && style != S_PLAIN { e.handle = "!"; }
    e.style = style;
}

fn process_anchor<E>(e: E&) {
    guard e.has_anchor else { return; }
    write_indicator(e, if e.alias { "*" } else { "&" }, true, false, false);
    write_all(e, e.anchor);
    e.whitespace = false;
    e.indention = false;
}

fn process_tag<E>(e: E&) {
    if e.handle.len == 0 && e.suffix.len == 0 { return; }
    if e.handle.len > 0 {
        if !e.whitespace { put(e, ' '); }
        write_all(e, e.handle);
        e.whitespace = false;
        e.indention = false;
        if e.suffix.len > 0 { write_tag_content(e, e.suffix, false); }
    } else {
        write_indicator(e, "!<", true, false, false);
        write_tag_content(e, e.suffix, false);
        write_indicator(e, ">", false, false, false);
    }
}

fn process_scalar<E>(e: E&) {
    let s = e.style;
    if s == S_PLAIN { write_plain_scalar(e, e.value, !e.simple_key_context); }
    else if s == S_SINGLE { write_single_quoted_scalar(e, e.value, !e.simple_key_context); }
    else if s == S_DOUBLE { write_double_quoted_scalar(e, e.value, !e.simple_key_context); }
    else if s == S_LITERAL { write_literal_scalar(e, e.value); }
    else { write_folded_scalar(e, e.value); }
}

fn write_indent<E>(e: E&) {
    let indent = max(e.indent, 0);
    if !e.indention || e.column > indent || (e.column == indent && !e.whitespace) { put_break(e); }
    if e.foot_indent == indent { put_break(e); }
    while e.column < indent { put(e, ' '); }
    e.whitespace = true;
    e.space_above = false;
    e.foot_indent = -1;
}

fn write_indicator<E>(e: E&, indicator: const u8[:], need_whitespace: bool, is_whitespace: bool, is_indention: bool) {
    if need_whitespace && !e.whitespace { put(e, ' '); }
    write_all(e, indicator);
    e.whitespace = is_whitespace;
    e.indention = e.indention && is_indention;
    e.open_ended = false;
}

fn write_tag_content<E>(e: E&, value: const u8[:], need_whitespace: bool) {
    if need_whitespace && !e.whitespace { put(e, ' '); }
    var i = 0;
    while i < value.len {
        let c = value[i];
        if c == ';' || c == '/' || c == '?' || c == ':' || c == '@' || c == '&' || c == '=' || c == '+' || c == '$'
           || c == ',' || c == '_' || c == '.' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')'
           || c == '[' || c == ']' || is_alpha(c) {
            i = write_char(e, value, i);
        } else {
            let w = max(1, width(c));
            for k in w {
                let octet = value[i];
                i++;
                put(e, '%');
                put(e, "0123456789ABCDEF"[octet >> 4]);
                put(e, "0123456789ABCDEF"[octet & 15]);
            }
        }
    }
    e.whitespace = false;
    e.indention = false;
}

fn write_plain_scalar<E>(e: E&, value: const u8[:], allow_breaks: bool) {
    if value.len > 0 && !e.whitespace { put(e, ' '); }
    var spaces = false;
    var breaks = false;
    var i = 0;
    while i < value.len {
        if value[i] == ' ' {
            if allow_breaks && !spaces && e.column > e.best_width && !str_is_space(value, i + 1) {
                write_indent(e);
                i += 1;
            } else {
                i = write_char(e, value, i);
            }
            spaces = true;
        } else if str_is_break(value, i) {
            if !breaks && value[i] == '\n' { put_break(e); }
            i = write_break(e, value, i);
            breaks = true;
        } else {
            if breaks { write_indent(e); }
            i = write_char(e, value, i);
            e.indention = false;
            spaces = false;
            breaks = false;
        }
    }
    if value.len > 0 { e.whitespace = false; }
    e.indention = false;
    if e.root_context { e.open_ended = true; }
}

fn write_single_quoted_scalar<E>(e: E&, value: const u8[:], allow_breaks: bool) {
    write_indicator(e, "'", true, false, false);
    var spaces = false;
    var breaks = false;
    var i = 0;
    while i < value.len {
        if value[i] == ' ' {
            if allow_breaks && !spaces && e.column > e.best_width && i > 0 && i < value.len - 1 && !str_is_space(value, i + 1) {
                write_indent(e);
                i += 1;
            } else {
                i = write_char(e, value, i);
            }
            spaces = true;
        } else if str_is_break(value, i) {
            if !breaks && value[i] == '\n' { put_break(e); }
            i = write_break(e, value, i);
            breaks = true;
        } else {
            if breaks { write_indent(e); }
            if value[i] == '\'' { put(e, '\''); }
            i = write_char(e, value, i);
            e.indention = false;
            spaces = false;
            breaks = false;
        }
    }
    write_indicator(e, "'", false, false, false);
    e.whitespace = false;
    e.indention = false;
}

fn write_double_quoted_scalar<E>(e: E&, value: const u8[:], allow_breaks: bool) {
    var spaces = false;
    write_indicator(e, "\"", true, false, false);
    let bom = str_is_bom(value);
    var i = 0;
    while i < value.len {
        let c = value[i];
        if !is_printable(value, i) || bom || str_is_break(value, i) || c == '"' || c == '\\' {
            var w = max(1, width(c));
            var v: i64 = if w == 1 { c & 0x7F } else if w == 2 { c & 0x1F } else if w == 3 { c & 0x0F } else { c & 0x07 };
            for k in 1..w { v = (v << 6) + (value[i + k] & 0x3F); }
            i += w;
            put(e, '\\');
            if v == 0x00 { put(e, '0'); }
            else if v == 0x07 { put(e, 'a'); }
            else if v == 0x08 { put(e, 'b'); }
            else if v == 0x09 { put(e, 't'); }
            else if v == 0x0A { put(e, 'n'); }
            else if v == 0x0B { put(e, 'v'); }
            else if v == 0x0C { put(e, 'f'); }
            else if v == 0x0D { put(e, 'r'); }
            else if v == 0x1B { put(e, 'e'); }
            else if v == 0x22 { put(e, '"'); }
            else if v == 0x5C { put(e, '\\'); }
            else if v == 0x85 { put(e, 'N'); }
            else if v == 0xA0 { put(e, '_'); }
            else if v == 0x2028 { put(e, 'L'); }
            else if v == 0x2029 { put(e, 'P'); }
            else {
                if v <= 0xFF { put(e, 'x'); w = 2; }
                else if v <= 0xFFFF { put(e, 'u'); w = 4; }
                else { put(e, 'U'); w = 8; }
                var k = (w - 1) * 4;
                while k >= 0 {
                    put(e, "0123456789ABCDEF"[(v >> k) & 15]);
                    k -= 4;
                }
            }
            spaces = false;
        } else if c == ' ' {
            if allow_breaks && !spaces && e.column > e.best_width && i > 0 && i < value.len - 1 {
                write_indent(e);
                if str_is_space(value, i + 1) { put(e, '\\'); }
                i += 1;
            } else {
                i = write_char(e, value, i);
            }
            spaces = true;
        } else {
            i = write_char(e, value, i);
            spaces = false;
        }
    }
    write_indicator(e, "\"", false, false, false);
    e.whitespace = false;
    e.indention = false;
}

fn write_block_scalar_hints<E>(e: E&, value: const u8[:]) {
    if str_is_space(value, 0) || str_is_break(value, 0) {
        var hint: u8[..1] = [];
        hint.push(('0' + e.best_indent) as! u8);
        write_indicator(e, hint, false, false, false);
    }
    e.open_ended = false;
    var chomp: u8 = 0;
    if value.len == 0 {
        chomp = '-';
    } else {
        var i = value.len - 1;
        while (value[i] & 0xC0) == 0x80 { i--; }
        if !str_is_break(value, i) {
            chomp = '-';
        } else if i == 0 {
            chomp = '+';
            e.open_ended = true;
        } else {
            i--;
            while (value[i] & 0xC0) == 0x80 { i--; }
            if str_is_break(value, i) {
                chomp = '+';
                e.open_ended = true;
            }
        }
    }
    if chomp != 0 {
        var hint: u8[..1] = [];
        hint.push(chomp);
        write_indicator(e, hint, false, false, false);
    }
}

fn write_literal_scalar<E>(e: E&, value: const u8[:]) {
    write_indicator(e, "|", true, false, false);
    write_block_scalar_hints(e, value);
    e.whitespace = true;
    var breaks = true;
    var i = 0;
    while i < value.len {
        if str_is_break(value, i) {
            i = write_break(e, value, i);
            breaks = true;
        } else {
            if breaks { write_indent(e); }
            i = write_char(e, value, i);
            e.indention = false;
            breaks = false;
        }
    }
}

fn write_folded_scalar<E>(e: E&, value: const u8[:]) {
    write_indicator(e, ">", true, false, false);
    write_block_scalar_hints(e, value);
    e.whitespace = true;
    var breaks = true;
    var leading_spaces = true;
    var i = 0;
    while i < value.len {
        if str_is_break(value, i) {
            if !breaks && !leading_spaces && value[i] == '\n' {
                // (libyaml looks from the start of the value here.)
                var k = 0;
                while str_is_break(value, k) { k += max(1, width(value[k])); }
                if !str_is_blankz(value, k) { put_break(e); }
            }
            i = write_break(e, value, i);
            breaks = true;
        } else {
            if breaks {
                write_indent(e);
                leading_spaces = str_is_blank(value, i);
            }
            if !breaks && value[i] == ' ' && !str_is_space(value, i + 1) && e.column > e.best_width {
                write_indent(e);
                i += 1;
            } else {
                i = write_char(e, value, i);
            }
            e.indention = false;
            breaks = false;
        }
    }
}

// --- building a tree to write ---------------------------------------------------

// A node of kind DOCUMENT, MAPPING or SEQUENCE, with no children yet, or a
// scalar with value; tag "" lets the writer choose, as yaml.v3's does for
// a node without one: plain where the text reads back as a string, quoted
// where it would read as something else. Push it onto the pool, and link
// it with `add`.
fn node(kind: u8, value: const u8[:] = "", tag: const u8[:] = "") -> Node {
    Node { next: null, first: null, alias: null, kind: kind, style: 0, count: 0, line: 0, column: 0,
           tag: tag, value: value, anchor: "" }
}

// child as the last child of parent, both in the same pool: a document's
// root, a sequence's next element, a mapping's next key or value.
fn add<N>(parent: N&, child: N&) {
    var c = parent.first;
    if c {
        var last .= c;
        loop {
            let n = last.next;
            guard n else { break; }
            last .= n;
        }
        last.next .= child;
    } else {
        parent.first .= child;
    }
    parent.count++;
}
