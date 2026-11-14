// mail.imap: an IMAP client, IMAP4rev2 (RFC 9051) that works with IMAP4rev1
// servers (RFC 3501) too: CAPABILITY, STARTTLS or TLS from the first byte
// (993), LOGIN, AUTHENTICATE with mail.sasl's mechanisms (SASL-IR, RFC
// 4959, when offered), ID (RFC 2971), ENABLE (RFC 5161), SELECT, EXAMINE,
// LIST, LSUB, CREATE, DELETE, RENAME, SUBSCRIBE, STATUS, FETCH, SEARCH
// (ESEARCH's answer too), STORE, COPY, MOVE (RFC 6851), EXPUNGE, UID
// EXPUNGE (RFC 4315), APPEND (LITERAL+ and LITERAL-, RFC 7888), NOOP, IDLE
// (RFC 2177), CLOSE, UNSELECT and LOGOUT.
//
//   var c = imap::Client { .. };
//   var e = imap::dial(c, "imap.example.com", 0, imap::TLS_IMPLICIT);   // 993
//   if e == mail::OK { e = imap::authenticate(c, mail::AUTH_AUTO, "user", "password"); }
//   if e == mail::OK { e = imap::select(c, "INBOX"); }          // c.exists, c.uidvalidity, c.uidnext
//   var msgs: imap::Message[>..] = [];
//   if e == mail::OK { e = imap::fetch(c, "1:*", "(UID FLAGS ENVELOPE BODY.PEEK[HEADER])", msgs); }
//   var head: u8[>..] = [];
//   for m in msgs { imap::fetch_item(c, m, "BODY[HEADER]", head); }
//   imap::logout(c);
//   // on mail::ERR_REPLY, c.text is the server's NO or BAD text, c.code its [code]
//
// Every untagged response a command brings is kept, as it came, in c.data
// until the next command: messages() reads the FETCH responses among them
// (a FETCH's, a STORE's, a NOOP's or an IDLE's), and a Message's items are
// read from there. The mailbox's state (c.exists, c.uidvalidity, c.flags,
// ...) follows the responses whatever command brings them.
//
// The parser takes a response as it came, its literals inline: "{n}" (or
// "~{n}", "{n+}"), CRLF, then n bytes. tree() parses one into a flat array
// of Nodes, with no recursion: atoms, NIL, quoted strings, literals and
// parenthesized lists. A response line is at most MAX_LINE bytes, a
// literal c.max_literal, and all of a command's responses c.max_data:
// anything larger is ERR_PROTOCOL, refused before it is read. The rest of
// that response is then still unread, so close() after ERR_PROTOCOL; a
// FETCH of many large bodies goes in smaller sets to stay under max_data.

namespace imap;

import std;
import base64;
import mail;
import mail.link;
import mail.sasl;
import mail.address;
import mime;
import mime.encodedword;
import crypto.tls;
import crypto.tls.handshake;

// How a connection gets TLS, as smtp's and pop3's.
let TLS_MANDATORY:     i64 = 0;  // STARTTLS, and fail (ERR_NO_TLS) when the server does not offer it
let TLS_OPPORTUNISTIC: i64 = 1;  // STARTTLS when the server offers it
let TLS_NONE:          i64 = 2;
let TLS_IMPLICIT:      i64 = 3;  // TLS from the first byte (993)

let MAX_LINE:    i64 = 1 << 20;  // one line of a response, its literals apart
let MAX_LITERAL: i64 = 1 << 26;  // c.max_literal's default: one literal, 64 MiB
let MAX_DATA:    i64 = 1 << 28;  // c.max_data's default: a command's responses together, 256 MiB
let MAX_DEPTH:   i64 = 64;       // parentheses nested deeper are a malformed response
let MAX_QUOTED:  i64 = 1000;     // a longer argument goes as a literal

root struct Client {
    // mail.link's
    fd:         i64               = -1,
    secure:     bool              = false,
    tc:         tls::Conn         = tls::new_conn(false, 0),
    tlscfg:     tls::ClientConfig = tls::client_config("", ""),
    inbuf:      u8[>..]           = [],
    inpos:      i64               = 0,
    wire:       u8[>..]           = [],
    raw:        u8[>..]           = [],
    timeout_ms: i64               = 30000,
    // IMAP's
    host:          u8[..255] = "",
    caps:          u8[>..]   = [],     // the capabilities, each "NAME\n", upper-case
    text:          u8[>..]   = [],     // the last status response's text, after its [code]
    code:          u8[>..]   = [],     // its response code, inside the brackets ("" if none)
    tag:           u8[..16]  = "",
    tagn:          i64       = 0,
    authenticated: bool      = false,
    utf8:          bool      = false,  // UTF8=ACCEPT or IMAP4rev2 enabled: names and strings in UTF-8
    rev2:          bool      = false,  // IMAP4rev2 enabled
    bye:           bool      = false,  // the server said BYE
    idling:        bool      = false,
    // The selected mailbox (-1: not told)
    selected:      bool    = false,
    readonly:      bool    = false,
    exists:        i64     = 0,
    recent:        i64     = 0,
    uidvalidity:   i64     = -1,
    uidnext:       i64     = -1,
    unseen:        i64     = -1,       // the first unseen message's number (IMAP4rev1)
    highestmodseq: i64     = -1,
    flags:         u8[>..] = [],       // FLAGS: the flags in use, space-separated
    permflags:     u8[>..] = [],       // PERMANENTFLAGS: the flags that can be stored
    // Limits
    max_literal: i64 = MAX_LITERAL,
    max_data:    i64 = MAX_DATA,
    // The untagged responses of the last command, as they came ("* ..."),
    // one after another: each ends where ends says.
    data: u8[>..]  = [],
    ends: i64[>..] = [],
    // scratch
    resp:    u8[>..]  = [],            // the response being read
    line:    u8[>..]  = [],
    cmd:     u8[>..]  = [],            // the command being built
    waits:   i64[>..] = [],            // where in cmd the server's "+" is awaited (synchronizing literals)
    cmd_err: i64      = 0,             // an argument that could not be added
}

// --- The parser ------------------------------------------------------------------

// What a token or Node is.
let K_END:     i64 = 0;
let K_ATOM:    i64 = 1;   // a number too; flags (\Seen), BODY[...]<n>
let K_QUOTED:  i64 = 2;   // pos..end inside the quotes, escapes still in
let K_LITERAL: i64 = 3;   // pos..end the literal's bytes
let K_NIL:     i64 = 4;
let K_LIST:    i64 = 5;   // a token: "("; a Node: pos..end from "(" to ")"
let K_CLOSE:   i64 = 6;
let K_BAD:     i64 = 7;

// One value of a parsed response: its span in the text, its first child
// (a list's) and its next sibling, -1 when none.
struct Node { kind: i64, pos: i64, end: i64, child: i64, next: i64, count: i64 }

fn is_digit(c: u8) -> bool { c >= '0' && c <= '9' }

// The literal that starts at s[i] ("{n}", "{n+}", "~{n}"): its size and
// where its "}" ends; -1 when it is not one, -2 for a size past 18 digits.
fn literal_head(s: const u8[:], i: i64) -> i64, i64 {
    var j = i;
    if j < s.len && s[j] == '~' { j++; }
    if j >= s.len || s[j] != '{' { return -1, i; }
    j++;
    var n: i64 = 0;
    let d0 = j;
    while j < s.len && is_digit(s[j]) {
        if j - d0 >= 18 { return -2, i; }
        n = n * 10 + (s[j] - '0');
        j++;
    }
    if j == d0 { return -1, i; }
    if j < s.len && s[j] == '+' { j++; }
    if j >= s.len || s[j] != '}' { return -1, i; }
    return n, j + 1;
}

// The size of the literal a line ends with, -1 if it ends with none, -2
// for one too large to say.
fn literal_at_end(l: const u8[:]) -> i64 {
    if l.len < 3 || l[l.len - 1] != '}' { return -1; }
    var j = l.len - 2;
    if l[j] == '+' { j--; }
    while j >= 0 && is_digit(l[j]) { j--; }
    if j < 0 || l[j] != '{' { return -1; }
    if j > 0 && l[j - 1] == '~' { j--; }
    let n, end = literal_head(l, j);
    if n >= 0 && end != l.len { return -1; }
    return n;
}

// The token at s[i]: its kind, its span, and where the next one starts.
fn token(s: const u8[:], i0: i64) -> i64, i64, i64, i64 {
    var i = i0;
    while i < s.len && s[i] == ' ' { i++; }
    if i >= s.len { return K_END, i, i, i; }
    let c = s[i];
    if c == '(' { return K_LIST, i, i + 1, i + 1; }
    if c == ')' { return K_CLOSE, i, i + 1, i + 1; }
    if c == '"' {
        var j = i + 1;
        while j < s.len && s[j] != '"' {
            if s[j] == '\r' || s[j] == '\n' { return K_BAD, i, i, i; }
            if s[j] == '\\' { j++; }
            j++;
        }
        if j >= s.len { return K_BAD, i, i, i; }
        return K_QUOTED, i + 1, j, j + 1;
    }
    if c == '{' || c == '~' {
        let n, after = literal_head(s, i);
        if n < 0 { return K_BAD, i, i, i; }
        var p = after;
        if p + 1 < s.len && s[p] == '\r' && s[p + 1] == '\n' { p += 2; }
        else if p < s.len && s[p] == '\n' { p++; }
        else { return K_BAD, i, i, i; }
        if n > s.len - p { return K_BAD, i, i, i; }
        return K_LITERAL, p, p + n, p + n;
    }
    // An atom; what is in brackets is part of it, spaces and parentheses
    // too (BODY[HEADER.FIELDS (FROM TO)]<0>).
    var j = i;
    var depth = 0;
    while j < s.len {
        let ch = s[j];
        if ch == '\r' || ch == '\n' { break; }
        if depth > 0 {
            if ch == '[' { depth++; } else if ch == ']' { depth--; }
            j++;
            continue;
        }
        if ch == ' ' || ch == '(' || ch == ')' || ch == '"' || ch == '{' || ch == ']' { break; }
        if ch == '[' { depth++; }
        j++;
    }
    if j == i || depth > 0 { return K_BAD, i, i, i; }
    if j - i == 3 && mail::eq_fold(s[i..j], "NIL") { return K_NIL, i, j, j; }
    return K_ATOM, i, j, j;
}

// The values of s, parsed into nodes: nodes[0] is a list holding them.
// False for a malformed text: an unclosed quote or parenthesis, a literal
// past the end, parentheses nested past MAX_DEPTH.
fn tree(s: const u8[:], nodes: Node[>..]&) -> bool {
    nodes.clear();
    nodes.push(Node { kind: K_LIST, pos: 0, end: s.len, child: -1, next: -1, count: 0 });
    var open: i64[>..<] = [];
    var last: i64[>..<] = [];
    open.push(0);
    last.push(-1);
    var i = 0;
    loop {
        let kind, pos, end, next = token(s, i);
        if kind == K_END { return open.len == 1; }
        if kind == K_BAD { return false; }
        i = next;
        if kind == K_CLOSE {
            if open.len == 1 { return false; }
            let top = open.pop();
            last.pop();
            nodes[top].end = next;
            continue;
        }
        let idx = nodes.len;
        nodes.push(Node { kind: kind, pos: pos, end: end, child: -1, next: -1, count: 0 });
        let parent = open[open.len - 1];
        let prev = last[last.len - 1];
        if prev < 0 { nodes[parent].child = idx; } else { nodes[prev].next = idx; }
        nodes[parent].count++;
        last[last.len - 1] = idx;
        if kind == K_LIST {
            if open.len > MAX_DEPTH { return false; }
            nodes[idx].pos = pos;
            open.push(idx);
            last.push(-1);
        }
    }
    return false;
}

// The k-th child (from 0) of list node i, -1 if it has none.
fn nth(nodes: const Node[:], i: i64, k: i64) -> i64 {
    if i < 0 || i >= nodes.len || nodes[i].kind != K_LIST { return -1; }
    var j = nodes[i].child;
    var n = 0;
    while j >= 0 && n < k { j = nodes[j].next; n++; }
    return j;
}

fn kind_of(nodes: const Node[:], i: i64) -> i64 { if i < 0 || i >= nodes.len { K_END } else { nodes[i].kind } }

// A node's raw text: a list's with its parentheses, a quoted string's
// inside its quotes (escapes in), a literal's bytes.
fn raw(s: const u8[:], nodes: const Node[:], i: i64) -> const u8[:] {
    if i < 0 || i >= nodes.len { return s[0..0]; }
    return s[nodes[i].pos..nodes[i].end];
}

// A quoted string's contents, its escapes undone, appended to out.
fn unquote(out: u8[>..]&, q: const u8[:]) {
    var i = 0;
    while i < q.len {
        if q[i] == '\\' && i + 1 < q.len { i++; }
        out.push(q[i]);
        i++;
    }
}

// A string node's value (an atom, a quoted string, a literal), appended to
// out; NIL appends nothing. False for a list, or no node.
fn text(s: const u8[:], nodes: const Node[:], i: i64, out: u8[>..]&) -> bool {
    let k = kind_of(nodes, i);
    if k == K_QUOTED { unquote(out, raw(s, nodes, i)); return true; }
    if k == K_ATOM || k == K_LITERAL { out.append(raw(s, nodes, i)); return true; }
    return k == K_NIL;
}

// A number node's value (a non-negative atom of digits).
fn number(s: const u8[:], nodes: const Node[:], i: i64) -> i64, bool {
    if kind_of(nodes, i) != K_ATOM { return 0, false; }
    return parse_number(raw(s, nodes, i));
}

// Digits as a number: none, a sign or more than 18 digits is false.
fn parse_number(d: const u8[:]) -> i64, bool {
    if d.len == 0 || d.len > 18 { return 0, false; }
    var n: i64 = 0;
    for c in d {
        if !is_digit(c) { return 0, false; }
        n = n * 10 + (c - '0');
    }
    return n, true;
}

// A string node's value into a limited array, cut at its capacity.
fn put<T>(dst: T&, s: const u8[:], nodes: const Node[:], i: i64) {
    var t: u8[>..] = [];
    text(s, nodes, i, t);
    put_cap(dst, t);
}

fn put_cap<T>(dst: T&, v: const u8[:]) {
    dst.clear();
    dst.append(v[.. ::min(v.len, dst.cap)]);
}

// The status of a response: its word (OK, NO, BAD, BYE, PREAUTH), its
// response code inside the brackets, and its text. r starts after the tag
// or "* ".
fn status_parts(r: const u8[:]) -> const u8[:], const u8[:], const u8[:] {
    var i = 0;
    while i < r.len && r[i] != ' ' { i++; }
    let word = r[..i];
    if i < r.len { i++; }
    var code = r[i..i];
    if i < r.len && r[i] == '[' {
        var j = i + 1;
        while j < r.len && r[j] != ']' { j++; }
        if j < r.len {
            code = r[i + 1..j];
            i = j + 1;
            if i < r.len && r[i] == ' ' { i++; }
        }
    }
    return word, code, r[i..];
}

// The first word of s and the rest after one space.
fn first_word(s: const u8[:]) -> const u8[:], const u8[:] {
    var i = 0;
    while i < s.len && s[i] != ' ' { i++; }
    return s[..i], if i < s.len { s[i + 1..] } else { s[i..] };
}

// --- Sequence sets ---------------------------------------------------------------

// Whether s is a sequence set: numbers from 1, '*', ranges "a:b", joined by
// commas; or "$" (SEARCHRES).
fn seq_set_ok(s: const u8[:]) -> bool {
    if s == "$" { return true; }
    if s.len == 0 { return false; }
    var i = 0;
    loop {
        // a number or '*', then perhaps ':' and another
        for half in 2 {
            if i < s.len && s[i] == '*' { i++; }
            else {
                let d0 = i;
                while i < s.len && is_digit(s[i]) { i++; }
                let n, ok = parse_number(s[d0..i]);
                if !ok || n == 0 || n > 4294967295 || s[d0] == '0' { return false; }
            }
            if half == 0 {
                if i < s.len && s[i] == ':' { i++; } else { break; }
            }
        }
        if i == s.len { return true; }
        if s[i] != ',' { return false; }
        i++;
    }
    return false;
}

// nums as a sequence set, runs of consecutive numbers as ranges: [1, 2, 3,
// 5, 7, 8] is "1:3,5,7:8". The numbers are taken in the order given.
fn seq_set(out: u8[>..]&, nums: const i64[:]) {
    var i = 0;
    while i < nums.len {
        var j = i;
        while j + 1 < nums.len && nums[j + 1] == nums[j] + 1 { j++; }
        if i > 0 { out.push(','); }
        format(out, nums[i]);
        if j > i { out.push(':'); format(out, nums[j]); }
        i = j + 1;
    }
}

// A sequence set's numbers, appended to out in the order written (a range
// either way round, low to high); '*' is star. False for a set that does
// not parse, or more than max numbers.
fn parse_seq_set(s: const u8[:], star: i64, max: i64, out: i64[>..]&) -> bool {
    if s.len == 0 { return false; }
    var count = 0;
    var i = 0;
    loop {
        var lo: i64 = 0;
        var hi: i64 = 0;
        for half in 2 {
            var v: i64 = 0;
            if i < s.len && s[i] == '*' { v = star; i++; }
            else {
                let d0 = i;
                while i < s.len && is_digit(s[i]) { i++; }
                let n, ok = parse_number(s[d0..i]);
                if !ok || n == 0 || n > 4294967295 { return false; }
                v = n;
            }
            if half == 0 {
                lo = v;
                hi = v;
                if i < s.len && s[i] == ':' { i++; } else { break; }
            } else {
                hi = v;
            }
        }
        if lo > hi { let t = lo; lo = hi; hi = t; }
        if hi - lo + 1 > max - count { return false; }
        count += hi - lo + 1;
        var n = lo;
        while n <= hi { out.push(n); n++; }
        if i == s.len { return true; }
        if s[i] != ',' { return false; }
        i++;
    }
    return false;
}

// --- Modified UTF-7 (RFC 3501 §5.1.3) ------------------------------------------------

fn b64_char(v: i64) -> u8 {
    let a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
    return a[v];
}

fn b64_value(c: u8) -> i64 {
    if c >= 'A' && c <= 'Z' { return c - 'A'; }
    if c >= 'a' && c <= 'z' { return c - 'a' + 26; }
    if c >= '0' && c <= '9' { return c - '0' + 52; }
    if c == '+' { return 62; }
    if c == ',' { return 63; }
    return -1;
}

// A mailbox name in modified UTF-7, decoded to UTF-8 and appended to out.
// False (out as it was) for one that is not: a byte outside printable
// ASCII, a bad base64 run, a lone surrogate, bits left over.
fn utf7_decode(out: u8[>..]&, s: const u8[:]) -> bool {
    let mark = out.len;
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c < 0x20 || c > 0x7e { out.resize(mark); return false; }
        if c != '&' { out.push(c); i++; continue; }
        i++;
        if i < s.len && s[i] == '-' { out.push('&'); i++; continue; }
        var bits: i64 = 0;
        var nbits = 0;
        var high: i64 = 0;          // a high surrogate awaiting its low one
        var units = 0;
        while i < s.len && s[i] != '-' {
            let v = b64_value(s[i]);
            if v < 0 { out.resize(mark); return false; }
            bits = (bits << 6) | v;
            nbits += 6;
            if nbits >= 16 {
                nbits -= 16;
                let u = (bits >> nbits) & 0xFFFF;
                bits &= (1 << nbits) - 1;
                units++;
                if high != 0 {
                    if u < 0xDC00 || u > 0xDFFF { out.resize(mark); return false; }
                    mime::push_rune(out, 0x10000 + ((high - 0xD800) << 10) + (u - 0xDC00));
                    high = 0;
                } else if u >= 0xD800 && u <= 0xDBFF {
                    high = u;
                } else if u >= 0xDC00 && u <= 0xDFFF {
                    out.resize(mark);
                    return false;
                } else {
                    mime::push_rune(out, u);
                }
            }
            i++;
        }
        // Unterminated, empty, a surrogate left open, or bits that are not zero padding.
        if i >= s.len || units == 0 || high != 0 || nbits >= 6 || bits != 0 { out.resize(mark); return false; }
        i++;
    }
    return true;
}

// UTF-8 as modified UTF-7, appended to out: printable ASCII as itself, '&'
// as "&-", the rest as UTF-16 in base64 between '&' and '-'. False (out as
// it was) for bytes that are not UTF-8.
fn utf7_encode(out: u8[>..]&, s: const u8[:]) -> bool {
    let mark = out.len;
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c >= 0x20 && c <= 0x7e {
            out.push(c);
            if c == '&' { out.push('-'); }
            i++;
            continue;
        }
        out.push('&');
        var bits: i64 = 0;
        var nbits = 0;
        while i < s.len && (s[i] < 0x20 || s[i] > 0x7e) {
            let r, size = mime::decode_rune(s, i);
            if r == mime::RUNE_ERROR && size <= 1 && !(i + 2 < s.len && s[i] == 0xEF && s[i + 1] == 0xBF && s[i + 2] == 0xBD) {
                out.resize(mark);
                return false;
            }
            i += size;
            var units: i64[2] = [0, 0];
            var n = 1;
            if r >= 0x10000 {
                units[0] = 0xD800 + ((r - 0x10000) >> 10);
                units[1] = 0xDC00 + ((r - 0x10000) & 0x3FF);
                n = 2;
            } else {
                units[0] = r;
            }
            for k in n {
                bits = (bits << 16) | units[k];
                nbits += 16;
                while nbits >= 6 {
                    nbits -= 6;
                    out.push(b64_char((bits >> nbits) & 63));
                }
                bits &= (1 << nbits) - 1;
            }
        }
        if nbits > 0 { out.push(b64_char((bits << (6 - nbits)) & 63)); }
        out.push('-');
    }
    return true;
}

// --- Arguments ---------------------------------------------------------------------

fn atom_char(c: u8) -> bool {
    c > 0x20 && c < 0x7f && c != '(' && c != ')' && c != '{' && c != '%' && c != '*' && c != '"' &&
        c != '\\' && c != ']'
}

// How astring would send s: an atom, a quoted string, a literal; or not
// at all.
let ARG_ATOM:    i64 = 0;
let ARG_QUOTED:  i64 = 1;
let ARG_LITERAL: i64 = 2;
let ARG_BAD:     i64 = 3;   // CR, LF or NUL: nothing can carry it here

// What form s takes as an argument: an atom when it is one (and not NIL),
// quoted when it is 7-bit (or, with utf8, UTF-8) and short, a literal
// otherwise. CR, LF and NUL are refused: no command argument has them.
fn arg_form(s: const u8[:], utf8: bool) -> i64 {
    var atom = s.len > 0 && !(s.len == 3 && mail::eq_fold(s, "NIL"));
    var seven = true;
    for c in s {
        if c == '\r' || c == '\n' || c == 0 { return ARG_BAD; }
        if !atom_char(c) { atom = false; }
        if c >= 0x80 { seven = false; }
    }
    if atom { return ARG_ATOM; }
    if s.len <= MAX_QUOTED && (seven || utf8) { return ARG_QUOTED; }
    return ARG_LITERAL;
}

// s quoted: '"', with '\' before each '"' and '\', '"'.
fn quote(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    for c in s {
        if c == '"' || c == '\\' { out.push('\\'); }
        out.push(c);
    }
    out.push('"');
}

// s as an argument (astring), appended to out: the form arg_form picks; a
// literal as "{n}" (or "{n+}" when nonsync) and CRLF, then s. Returns the
// form; for a literal, its bytes are the last s.len of out.
fn astring(out: u8[>..]&, s: const u8[:], utf8: bool, nonsync: bool) -> i64 {
    let f = arg_form(s, utf8);
    if f == ARG_ATOM { out.append(s); }
    else if f == ARG_QUOTED { quote(out, s); }
    else if f == ARG_LITERAL {
        format(out, "{", s.len, if nonsync { "+}\r\n" } else { "}\r\n" });
        out.append(s);
    }
    return f;
}

// Whether a literal of n bytes may go without waiting for "+": LITERAL+, or
// LITERAL- (IMAP4rev2 has it) for 4096 bytes at most.
fn nonsync_ok(c: const Client&, n: i64) -> bool {
    if capability(c, "LITERAL+") { return true; }
    return n <= 4096 && (capability(c, "LITERAL-") || capability(c, "IMAP4rev2"));
}

// A new command: its tag and its name.
fn begin(c: Client&, name: const u8[:]) {
    c.tagn++;
    c.tag.clear();
    format(c.tag, "A", c.tagn);
    c.cmd.clear();
    c.waits.clear();
    c.cmd_err = mail::OK;
    c.cmd.append(c.tag);
    c.cmd.push(' ');
    c.cmd.append(name);
}

// Words of the command as they are (sequence sets, item lists, flags):
// CR, LF and NUL are refused.
fn add_raw(c: Client&, s: const u8[:]) {
    for b in s { if b == '\r' || b == '\n' || b == 0 { c.cmd_err = mail::ERR_LINE; return; } }
    c.cmd.push(' ');
    c.cmd.append(s);
}

// A string argument, as astring sends it.
fn add_string(c: Client&, s: const u8[:]) {
    c.cmd.push(' ');
    let nonsync = nonsync_ok(c, s.len);
    let f = astring(c.cmd, s, c.utf8, nonsync);
    if f == ARG_BAD { c.cmd_err = mail::ERR_LINE; }
    else if f == ARG_LITERAL && !nonsync { c.waits.push(c.cmd.len - s.len); }
}

// A mailbox name (UTF-8), in modified UTF-7 unless UTF-8 is enabled.
// INBOX is any case of it.
fn add_mailbox(c: Client&, name: const u8[:]) {
    for b in name { if b == '\r' || b == '\n' || b == 0 { c.cmd_err = mail::ERR_LINE; return; } }
    if c.utf8 { add_string(c, name); return; }
    var enc: u8[>..] = [];
    if !utf7_encode(enc, name) { c.cmd_err = mail::ERR_ARG; return; }
    add_string(c, enc);
}

// --- Responses ---------------------------------------------------------------------

let R_UNTAGGED: i64 = 1;
let R_CONTINUE: i64 = 2;
let R_TAGGED:   i64 = 3;

// Reads n bytes into out, after what is left in inbuf.
fn read_exact(c: Client&, n: i64, out: u8[>..]&) -> i64 {
    var need = n;
    loop {
        let take = ::min(c.inbuf.len - c.inpos, need);
        out.append(c.inbuf[c.inpos..c.inpos + take]);
        c.inpos += take;
        need -= take;
        if need == 0 { return mail::OK; }
        let e = mail::link_fill(c);
        if e != mail::OK { return e; }
    }
    return mail::ERR_IO;
}

// One response into c.resp, its literals inline as they came: a line that
// ends with "{n}" is followed by CRLF, the n bytes and the line that goes
// on after them.
fn read_response(c: Client&) -> i64 {
    c.resp.clear();
    loop {
        let e = mail::link_read_line(c, c.line, MAX_LINE);
        if e != mail::OK { return e; }
        if c.line.len > c.max_data - c.resp.len { return mail::ERR_PROTOCOL; }
        c.resp.append(c.line);
        let n = literal_at_end(c.line);
        if n == -1 { return mail::OK; }
        if n < 0 || n > c.max_literal || n > c.max_data - c.resp.len - 2 { return mail::ERR_PROTOCOL; }
        c.resp.append("\r\n");
        let le = read_exact(c, n, c.resp);
        if le != mail::OK { return le; }
    }
    return mail::ERR_IO;
}

// The capabilities in s ("IMAP4rev1 STARTTLS AUTH=PLAIN"), kept.
fn set_caps(c: Client&, s: const u8[:]) {
    c.caps.clear();
    for w in words(s) {
        for ch in w { c.caps.push(if ch >= 'a' && ch <= 'z' { ch - 32 } else { ch }); }
        c.caps.push('\n');
    }
}

// A list "(a b c)" as "a b c".
fn list_body(s: const u8[:]) -> const u8[:] {
    let t = trim(s);
    if t.len >= 2 && t[0] == '(' && t[t.len - 1] == ')' { return t[1..t.len - 1]; }
    return t;
}

// What a response code tells: the capabilities, the mailbox's numbers and
// flags, whether it is read-only.
fn apply_code(c: Client&, code: const u8[:]) {
    let name, rest = first_word(code);
    if mail::eq_fold(name, "CAPABILITY") { set_caps(c, rest); return; }
    if mail::eq_fold(name, "READ-ONLY") { c.readonly = true; return; }
    if mail::eq_fold(name, "READ-WRITE") { c.readonly = false; return; }
    if mail::eq_fold(name, "PERMANENTFLAGS") {
        c.permflags.clear();
        c.permflags.append(list_body(rest));
        return;
    }
    let n, ok = parse_number(trim(rest));
    if !ok { return; }
    if mail::eq_fold(name, "UIDVALIDITY") { c.uidvalidity = n; }
    else if mail::eq_fold(name, "UIDNEXT") { c.uidnext = n; }
    else if mail::eq_fold(name, "UNSEEN") { c.unseen = n; }
    else if mail::eq_fold(name, "HIGHESTMODSEQ") { c.highestmodseq = n; }
}

// An untagged response: the state it changes, and kept in c.data.
fn untagged(c: Client&) -> i64 {
    let r = c.resp[2..];
    let w1, rest = first_word(r);
    let n, isnum = parse_number(w1);
    if isnum {
        let w2, rest2 = first_word(rest);
        if mail::eq_fold(w2, "EXISTS") { c.exists = n; }
        else if mail::eq_fold(w2, "RECENT") { c.recent = n; }
        else if mail::eq_fold(w2, "EXPUNGE") { if c.exists > 0 { c.exists--; } }
    } else if mail::eq_fold(w1, "CAPABILITY") {
        set_caps(c, rest);
    } else if mail::eq_fold(w1, "FLAGS") {
        c.flags.clear();
        c.flags.append(list_body(rest));
    } else if mail::eq_fold(w1, "ENABLED") {
        for w in words(rest) {
            if mail::eq_fold(w, "UTF8=ACCEPT") || mail::eq_fold(w, "UTF8=ONLY") { c.utf8 = true; }
            if mail::eq_fold(w, "IMAP4rev2") { c.rev2 = true; c.utf8 = true; }
        }
    } else if mail::eq_fold(w1, "OK") || mail::eq_fold(w1, "NO") || mail::eq_fold(w1, "BAD") ||
              mail::eq_fold(w1, "BYE") || mail::eq_fold(w1, "PREAUTH") {
        let word, code, txt = status_parts(r);
        apply_code(c, code);
        if mail::eq_fold(w1, "BYE") {
            c.bye = true;
            c.text.clear();
            c.text.append(txt[.. ::min(txt.len, 2048)]);
        }
        if mail::eq_fold(w1, "PREAUTH") { c.authenticated = true; }
    }
    if c.resp.len > c.max_data - c.data.len { return mail::ERR_PROTOCOL; }
    c.data.append(c.resp);
    c.ends.push(c.data.len);
    return mail::OK;
}

// Reads a response and says what it was: untagged (kept), a continuation
// ("+", its text in c.text) or the command's completion (OK: OK, NO or
// BAD: ERR_REPLY, with c.code and c.text). A connection that ends after
// BYE is ERR_REPLY, BYE's text in c.text.
fn read_one(c: Client&) -> i64, i64 {
    let e = read_response(c);
    if e != mail::OK {
        if c.bye && (e == mail::ERR_IO || e == mail::ERR_TLS) { return 0, mail::ERR_REPLY; }
        return 0, e;
    }
    let r = c.resp[..];
    if r.len >= 2 && r[0] == '*' && r[1] == ' ' { return R_UNTAGGED, untagged(c); }
    if r.len >= 1 && r[0] == '+' && (r.len == 1 || r[1] == ' ') {
        c.text.clear();
        if r.len > 2 { c.text.append(r[2..]); }
        return R_CONTINUE, mail::OK;
    }
    if c.tag.len > 0 && r.len > c.tag.len && r[c.tag.len] == ' ' && r[..c.tag.len] == c.tag[..] {
        let word, code, txt = status_parts(r[c.tag.len + 1..]);
        c.code.clear();
        c.code.append(code[.. ::min(code.len, 4096)]);
        c.text.clear();
        c.text.append(txt[.. ::min(txt.len, 4096)]);
        apply_code(c, code);
        if mail::eq_fold(word, "OK") { return R_TAGGED, mail::OK; }
        if mail::eq_fold(word, "NO") || mail::eq_fold(word, "BAD") { return R_TAGGED, mail::ERR_REPLY; }
    }
    return 0, mail::ERR_PROTOCOL;
}

// Reads up to the command's completion.
fn finish(c: Client&) -> i64 {
    loop {
        let kind, e = read_one(c);
        if kind == R_TAGGED { return e; }
        if e != mail::OK { return e; }
        if kind == R_CONTINUE { return mail::ERR_PROTOCOL; }
    }
    return mail::ERR_IO;
}

// Sends what is in cmd from `from` to `to`.
fn send_part(c: Client&, from: i64, to: i64) -> i64 {
    var b: u8[>..] = [];
    b.append(c.cmd[from..to]);
    return mail::link_write(c, b);
}

// Sends the command built in c.cmd, waiting for "+" before each
// synchronizing literal, and reads its responses: OK, ERR_REPLY when the
// server says NO or BAD (to the command, or to a literal).
fn run(c: Client&) -> i64 {
    if c.cmd_err != mail::OK { return c.cmd_err; }
    if c.fd < 0 { return mail::ERR_STATE; }
    if c.idling { return mail::ERR_STATE; }
    c.data.clear();
    c.ends.clear();
    c.code.clear();
    c.text.clear();
    c.cmd.append("\r\n");
    var from = 0;
    for w in c.waits {
        var e = send_part(c, from, w);
        if e != mail::OK { return e; }
        loop {
            let kind, re = read_one(c);
            if re != mail::OK { return re; }
            if kind == R_CONTINUE { break; }
            if kind == R_TAGGED { return mail::ERR_PROTOCOL; }
        }
        from = w;
    }
    let e = send_part(c, from, c.cmd.len);
    if e != mail::OK { return e; }
    return finish(c);
}

// A command with no arguments.
fn simple(c: Client&, name: const u8[:]) -> i64 {
    begin(c, name);
    return run(c);
}

// The untagged responses kept, each to F(response): "* ...", literals
// inline.
fn each_response<F>(c: const Client&) {
    var from = 0;
    for end in c.ends {
        F(c.data[from..end]);
        from = end;
    }
}

// --- Connecting ----------------------------------------------------------------------

fn reset(c: Client&) {
    c.caps.clear();
    c.authenticated = false;
    c.utf8 = false;
    c.rev2 = false;
    c.bye = false;
    c.idling = false;
    c.tag.clear();
    reset_mailbox(c);
}

fn reset_mailbox(c: Client&) {
    c.selected = false;
    c.readonly = false;
    c.exists = 0;
    c.recent = 0;
    c.uidvalidity = -1;
    c.uidnext = -1;
    c.unseen = -1;
    c.highestmodseq = -1;
    c.flags.clear();
    c.permflags.clear();
}

// Connects, reads the greeting (OK, or PREAUTH: already authenticated;
// BYE is ERR_REPLY), asks CAPABILITY unless the greeting told them, and
// gets TLS as policy asks (CAPABILITY again under it). Port 0 is the
// policy's usual: 993 for TLS_IMPLICIT, 143 otherwise.
fn dial(c: Client&, host: const u8[:], port: i64, policy: i64) -> i64 {
    if host.len > 255 { return mail::ERR_ARG; }
    let p = if port != 0 { port } else if policy == TLS_IMPLICIT { 993 } else { 143 };
    // A server name left from a dial to another host is not this one's.
    if c.tlscfg.server_name[..] == c.host[..] { c.tlscfg.server_name.clear(); }
    c.host.clear();
    c.host.append(host);
    reset(c);
    c.data.clear();
    c.ends.clear();
    var e = mail::link_open(c, host, p, policy == TLS_IMPLICIT);
    if e == mail::OK {
        let kind, ge = read_one(c);
        e = ge;
        if e == mail::OK && kind != R_UNTAGGED { e = mail::ERR_PROTOCOL; }
        if e == mail::OK && c.bye { e = mail::ERR_REPLY; }
        if e == mail::OK {
            let word, rest = first_word(c.resp[2..]);
            if !mail::eq_fold(word, "OK") && !mail::eq_fold(word, "PREAUTH") { e = mail::ERR_PROTOCOL; }
        }
    }
    if e == mail::OK && c.caps.len == 0 { e = capabilities(c); }
    if e == mail::OK && !c.secure && (policy == TLS_MANDATORY || policy == TLS_OPPORTUNISTIC) {
        // PREAUTH leaves no place for STARTTLS (RFC 9051 §6.2.1).
        if capability(c, "STARTTLS") && !c.authenticated { e = starttls(c); }
        else if policy == TLS_MANDATORY { e = mail::ERR_NO_TLS; }
    }
    if e != mail::OK { close(c); }
    return e;
}

// CAPABILITY: the server's capabilities, kept for capability().
fn capabilities(c: Client&) -> i64 {
    c.caps.clear();
    return simple(c, "CAPABILITY");
}

// Whether the server has a capability (compared without case).
fn capability(c: const Client&, name: const u8[:]) -> bool {
    var i = 0;
    while i < c.caps.len {
        var j = i;
        while j < c.caps.len && c.caps[j] != '\n' { j++; }
        if mail::eq_fold(c.caps[i..j], name) { return true; }
        i = j + 1;
    }
    return false;
}

// The SASL mechanisms offered (AUTH=...), space-separated.
fn auth_list(c: const Client&) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < c.caps.len {
        var j = i;
        while j < c.caps.len && c.caps[j] != '\n' { j++; }
        if j - i > 5 && mail::eq_fold(c.caps[i..i + 5], "AUTH=") {
            if out.len > 0 { out.push(' '); }
            out.append(c.caps[i + 5..j]);
        }
        i = j + 1;
    }
    return out;
}

// STARTTLS, the handshake, and CAPABILITY again (what came before TLS is
// forgotten, RFC 9051 §6.2.1).
fn starttls(c: Client&) -> i64 {
    if c.secure { return mail::ERR_STATE; }
    var e = simple(c, "STARTTLS");
    if e != mail::OK { return e; }
    e = mail::link_tls(c, c.host);
    if e != mail::OK { return e; }
    return capabilities(c);
}

// --- Authentication ------------------------------------------------------------------

fn is_local(host: const u8[:]) -> bool { host == "localhost" || host == "127.0.0.1" || host == "::1" }

// After a login: authenticated, and the capabilities again unless the
// completion gave them (they change with authentication).
fn logged_in(c: Client&) -> i64 {
    c.authenticated = true;
    let name, rest = first_word(c.code);
    if mail::eq_fold(name, "CAPABILITY") { return mail::OK; }
    return capabilities(c);
}

// LOGIN. The password goes readable, so without TLS this is refused
// (ERR_AUTH) except to localhost; a server that says LOGINDISABLED,
// ERR_UNSUPPORTED.
fn login(c: Client&, user: const u8[:], password: const u8[:]) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    if !c.secure && !is_local(c.host) { return mail::ERR_AUTH; }
    if capability(c, "LOGINDISABLED") { return mail::ERR_UNSUPPORTED; }
    begin(c, "LOGIN");
    add_string(c, user);
    add_string(c, password);
    let e = run(c);
    if e != mail::OK { return e; }
    return logged_in(c);
}

fn send_line(c: Client&, line: const u8[:]) -> i64 {
    var b: u8[>..] = [];
    b.append(line);
    b.append("\r\n");
    return mail::link_write(c, b);
}

// AUTHENTICATE with a SASL mechanism (AUTH_AUTO: the best the AUTH=
// capabilities list), the initial response on the command line when the
// server has SASL-IR. As pop3::auth: readable mechanisms only over TLS or
// to localhost, a SCRAM server must prove itself, a failed step cancels
// with "*".
fn authenticate(c: Client&, mech: i64, user: const u8[:], secret: const u8[:]) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    var m = mech;
    if m == mail::AUTH_AUTO {
        let list = auth_list(c);
        if list.len == 0 { return mail::ERR_UNSUPPORTED; }
        m = mail::auth_choose(list);
        if m == mail::AUTH_AUTO { return mail::ERR_AUTH; }
    }
    if mail::auth_plaintext(m) && !c.secure && !is_local(c.host) { return mail::ERR_AUTH; }
    var s = mail::sasl_new(m, user, secret);
    var resp: u8[>..] = [];
    var line: u8[>..] = [];
    var pending = mail::sasl_initial(s, resp);
    begin(c, "AUTHENTICATE");
    c.cmd.push(' ');
    c.cmd.append(mail::auth_name(m));
    if pending && capability(c, "SASL-IR") {
        c.cmd.push(' ');
        if resp.len == 0 { c.cmd.push('='); } else { base64::encode(c.cmd, resp); }
        pending = false;
    }
    c.data.clear();
    c.ends.clear();
    var e = send_part(c, 0, c.cmd.len);
    if e == mail::OK { e = send_line(c, ""); }
    if e != mail::OK { return e; }
    loop {
        let kind, re = read_one(c);
        if kind == R_TAGGED {
            if re == mail::OK && !mail::sasl_done(s) { return mail::ERR_AUTH; }
            if re != mail::OK { return re; }
            return logged_in(c);
        }
        if re != mail::OK { return re; }
        if kind != R_CONTINUE { continue; }
        line.clear();
        if pending {
            // The initial response, after the server's empty challenge.
            base64::encode(line, resp);
            pending = false;
        } else {
            var challenge: u8[>..] = [];
            var se = mail::OK;
            if !base64::decode(challenge, c.text) { se = mail::ERR_AUTH; }
            if se == mail::OK { se = mail::sasl_step(s, challenge, resp); }
            if se != mail::OK {
                send_line(c, "*");                // cancels (RFC 9051 §6.2.2)
                finish(c);
                return mail::ERR_AUTH;
            }
            base64::encode(line, resp);
        }
        e = send_line(c, line);
        if e != mail::OK { return e; }
    }
    return mail::ERR_IO;
}

// ENABLE (RFC 5161): capabilities such as "UTF8=ACCEPT" or "IMAP4rev2",
// space-separated. c.utf8 and c.rev2 say what the server enabled.
fn enable(c: Client&, caps: const u8[:]) -> i64 {
    if !capability(c, "ENABLE") && !capability(c, "IMAP4rev2") { return mail::ERR_UNSUPPORTED; }
    begin(c, "ENABLE");
    add_raw(c, caps);
    return run(c);
}

// ID (RFC 2971): tells the server the client's name and version (NIL when
// name is empty); the server's own answer, its raw list or NIL, into out.
fn id(c: Client&, name: const u8[:], version: const u8[:], out: u8[>..]&) -> i64 {
    if !capability(c, "ID") { return mail::ERR_UNSUPPORTED; }
    begin(c, "ID");
    if name.len == 0 { add_raw(c, "NIL"); }
    else {
        if mail::has_crlf(name) || mail::has_crlf(version) || name.len > 1024 || version.len > 1024 { return mail::ERR_LINE; }
        c.cmd.append(" (\"name\" ");
        quote(c.cmd, name);
        if version.len > 0 {
            c.cmd.append(" \"version\" ");
            quote(c.cmd, version);
        }
        c.cmd.push(')');
    }
    let e = run(c);
    if e != mail::OK { return e; }
    each_response(c) { r =>
        let w, rest = first_word(r[2..]);
        if mail::eq_fold(w, "ID") { out.append(rest); }
    };
    return mail::OK;
}

// --- Mailboxes -----------------------------------------------------------------------

// SELECT: the mailbox becomes the selected one, its state in c.exists,
// c.recent, c.uidvalidity, c.uidnext, c.unseen, c.flags, c.permflags and
// c.readonly. A failed SELECT leaves none selected.
fn select(c: Client&, mailbox: const u8[:]) -> i64 { open_mailbox(c, "SELECT", mailbox) }

// EXAMINE: SELECT, read-only.
fn examine(c: Client&, mailbox: const u8[:]) -> i64 { open_mailbox(c, "EXAMINE", mailbox) }

fn open_mailbox(c: Client&, verb: const u8[:], mailbox: const u8[:]) -> i64 {
    begin(c, verb);
    add_mailbox(c, mailbox);
    if c.cmd_err != mail::OK { return c.cmd_err; }
    reset_mailbox(c);
    c.readonly = verb == "EXAMINE";
    let e = run(c);
    c.selected = e == mail::OK;
    return e;
}

// A mailbox LIST told of: its attributes ("\HasNoChildren \Sent", as
// sent), its hierarchy delimiter (0 for none: NIL) and its name, decoded
// to UTF-8 (as sent when it is not modified UTF-7).
struct Mailbox { attrs: u8[..256] = [], delim: u8 = 0, name: u8[..1024] = [] }

// A LIST or LSUB response (after its word) as a Mailbox.
fn parse_list(s: const u8[:], utf8: bool, out: Mailbox&) -> bool {
    var nodes: Node[>..] = [];
    if !tree(s, nodes) { return false; }
    let a = nth(nodes, 0, 0);
    let d = nth(nodes, 0, 1);
    let n = nth(nodes, 0, 2);
    if kind_of(nodes, a) != K_LIST || n < 0 { return false; }
    put_cap(out.attrs, list_body(raw(s, nodes, a)));
    var delim: u8[>..] = [];
    if !text(s, nodes, d, delim) || delim.len > 1 { return false; }
    out.delim = if delim.len == 1 { delim[0] } else { 0 };
    var name: u8[>..] = [];
    if kind_of(nodes, n) == K_LIST || !text(s, nodes, n, name) { return false; }
    if name.len > 1024 { return false; }
    var dec: u8[>..] = [];
    if !utf8 && utf7_decode(dec, name) { put_cap(out.name, dec); } else { put_cap(out.name, name); }
    return true;
}

// LIST reference pattern: the mailboxes that match ('*' any, '%' any but
// the delimiter); reference "" and pattern "*" for all of them.
fn list(c: Client&, reference: const u8[:], pattern: const u8[:], out: Mailbox[>..]&) -> i64 {
    return list_cmd(c, "LIST", reference, pattern, out);
}

// LSUB: LIST's subscribed mailboxes (IMAP4rev1; IMAP4rev2 has LIST
// (SUBSCRIBED) instead, which list's pattern cannot ask).
fn lsub(c: Client&, reference: const u8[:], pattern: const u8[:], out: Mailbox[>..]&) -> i64 {
    return list_cmd(c, "LSUB", reference, pattern, out);
}

fn list_cmd(c: Client&, verb: const u8[:], reference: const u8[:], pattern: const u8[:], out: Mailbox[>..]&) -> i64 {
    out.clear();
    begin(c, verb);
    add_mailbox(c, reference);
    // A pattern is a list-mailbox: '%' and '*' may be bare.
    var bare = pattern.len > 0;
    for ch in pattern { if !(atom_char(ch) || ch == '%' || ch == '*') { bare = false; } }
    if bare { add_raw(c, pattern); } else { add_mailbox(c, pattern); }
    let e = run(c);
    if e != mail::OK { return e; }
    var bad = false;
    each_response(c) { r =>
        let w, rest = first_word(r[2..]);
        if mail::eq_fold(w, verb) {
            var m = Mailbox { .. };
            if parse_list(rest, c.utf8, m) { out.push(m); } else { bad = true; }
        }
    };
    return if bad { mail::ERR_PROTOCOL } else { mail::OK };
}

fn mailbox_cmd(c: Client&, verb: const u8[:], mailbox: const u8[:]) -> i64 {
    begin(c, verb);
    add_mailbox(c, mailbox);
    return run(c);
}

fn create(c: Client&, mailbox: const u8[:]) -> i64 { mailbox_cmd(c, "CREATE", mailbox) }
fn delete(c: Client&, mailbox: const u8[:]) -> i64 { mailbox_cmd(c, "DELETE", mailbox) }
fn subscribe(c: Client&, mailbox: const u8[:]) -> i64 { mailbox_cmd(c, "SUBSCRIBE", mailbox) }
fn unsubscribe(c: Client&, mailbox: const u8[:]) -> i64 { mailbox_cmd(c, "UNSUBSCRIBE", mailbox) }

fn rename(c: Client&, from: const u8[:], to: const u8[:]) -> i64 {
    begin(c, "RENAME");
    add_mailbox(c, from);
    add_mailbox(c, to);
    return run(c);
}

// What STATUS told of a mailbox; -1 for what it did not.
struct Status {
    messages: i64 = -1, recent: i64 = -1, uidnext: i64 = -1, uidvalidity: i64 = -1,
    unseen:   i64 = -1, deleted: i64 = -1, size: i64 = -1, highestmodseq: i64 = -1,
}

// A STATUS response's list, "(MESSAGES 3 UIDNEXT 9)", into out.
fn parse_status(s: const u8[:], out: Status&) -> bool {
    var nodes: Node[>..] = [];
    if !tree(s, nodes) { return false; }
    // name (the mailbox), then the list
    let l = nth(nodes, 0, 1);
    if kind_of(nodes, l) != K_LIST { return false; }
    var i = nodes[l].child;
    while i >= 0 {
        let v = nodes[i].next;
        if v < 0 { return false; }
        let n, ok = number(s, nodes, v);
        if !ok { return false; }
        let k = raw(s, nodes, i);
        if mail::eq_fold(k, "MESSAGES") { out.messages = n; }
        else if mail::eq_fold(k, "RECENT") { out.recent = n; }
        else if mail::eq_fold(k, "UIDNEXT") { out.uidnext = n; }
        else if mail::eq_fold(k, "UIDVALIDITY") { out.uidvalidity = n; }
        else if mail::eq_fold(k, "UNSEEN") { out.unseen = n; }
        else if mail::eq_fold(k, "DELETED") { out.deleted = n; }
        else if mail::eq_fold(k, "SIZE") { out.size = n; }
        else if mail::eq_fold(k, "HIGHESTMODSEQ") { out.highestmodseq = n; }
        i = nodes[v].next;
    }
    return true;
}

// STATUS: a mailbox's MESSAGES, UIDNEXT, UIDVALIDITY and UNSEEN, without
// selecting it.
fn status(c: Client&, mailbox: const u8[:], out: Status&) -> i64 {
    out = Status { .. };
    begin(c, "STATUS");
    add_mailbox(c, mailbox);
    add_raw(c, "(MESSAGES UIDNEXT UIDVALIDITY UNSEEN)");
    let e = run(c);
    if e != mail::OK { return e; }
    var found = false;
    var bad = false;
    each_response(c) { r =>
        let w, rest = first_word(r[2..]);
        if mail::eq_fold(w, "STATUS") {
            if parse_status(rest, out) { found = true; } else { bad = true; }
        }
    };
    return if bad || !found { mail::ERR_PROTOCOL } else { mail::OK };
}

// CLOSE: expunges the \Deleted messages and leaves the mailbox.
fn close_mailbox(c: Client&) -> i64 {
    let e = simple(c, "CLOSE");
    if e == mail::OK { reset_mailbox(c); }
    return e;
}

// UNSELECT (RFC 3691, IMAP4rev2): leaves the mailbox, expunging nothing.
fn unselect(c: Client&) -> i64 {
    if !capability(c, "UNSELECT") && !capability(c, "IMAP4rev2") { return mail::ERR_UNSUPPORTED; }
    let e = simple(c, "UNSELECT");
    if e == mail::OK { reset_mailbox(c); }
    return e;
}

// --- Messages ------------------------------------------------------------------------

// A FETCH response: the message's number, and what came of UID,
// RFC822.SIZE, FLAGS, INTERNALDATE and MODSEQ (uid 0, size and modseq -1,
// flags and date "" when they did not). pos..end is its item list in
// c.data, for fetch_item, envelope and bodystructure, until the next
// command.
struct Message {
    seq:   i64        = 0, uid: i64 = 0, size: i64 = -1, modseq: i64 = -1,
    flags: u8[..1024] = [], internaldate: u8[..64] = [],
    pos:   i64        = 0, end: i64 = 0,
}

// A FETCH response's item list into m.
fn parse_fetch(s: const u8[:], m: Message&) -> bool {
    var nodes: Node[>..] = [];
    if !tree(s, nodes) { return false; }
    let l = nth(nodes, 0, 0);
    if kind_of(nodes, l) != K_LIST || nodes[0].count != 1 { return false; }
    var i = nodes[l].child;
    while i >= 0 {
        let v = nodes[i].next;
        if v < 0 || kind_of(nodes, i) != K_ATOM { return false; }
        let k = raw(s, nodes, i);
        if mail::eq_fold(k, "UID") {
            let n, ok = number(s, nodes, v);
            if !ok { return false; }
            m.uid = n;
        } else if mail::eq_fold(k, "RFC822.SIZE") {
            let n, ok = number(s, nodes, v);
            if !ok { return false; }
            m.size = n;
        } else if mail::eq_fold(k, "FLAGS") {
            if kind_of(nodes, v) != K_LIST { return false; }
            put_cap(m.flags, list_body(raw(s, nodes, v)));
        } else if mail::eq_fold(k, "INTERNALDATE") {
            put(m.internaldate, s, nodes, v);
        } else if mail::eq_fold(k, "MODSEQ") {
            let n, ok = number(s, nodes, nth(nodes, v, 0));
            if ok { m.modseq = n; }
        }
        i = nodes[v].next;
    }
    return true;
}

// The FETCH responses among those kept: what the last FETCH, STORE, NOOP
// or IDLE brought. Several for one message (a server may split them) are
// kept as they came.
fn messages(c: const Client&, out: Message[>..]&) -> i64 {
    out.clear();
    var bad = false;
    var from = 0;
    for end in c.ends {
        let r = c.data[from..end];
        let w1, rest = first_word(r[2..]);
        let n, isnum = parse_number(w1);
        let w2, items = first_word(rest);
        if isnum && mail::eq_fold(w2, "FETCH") {
            var m = Message { seq: n, .. };
            m.pos = end - items.len;
            m.end = end;
            if parse_fetch(items, m) { out.push(m); } else { bad = true; }
        }
        from = end;
    }
    return if bad { mail::ERR_PROTOCOL } else { mail::OK };
}

// The span of item `name`'s value in a FETCH item list: "BODY[]" for the
// answer to BODY.PEEK[] (with or without its "<origin>"), "ENVELOPE",
// "BODYSTRUCTURE". Names are compared without case.
fn find_item(s: const u8[:], nodes: Node[>..]&, name: const u8[:]) -> i64 {
    if !tree(s, nodes) { return -1; }
    let l = nth(nodes, 0, 0);
    if kind_of(nodes, l) != K_LIST { return -1; }
    var i = nodes[l].child;
    while i >= 0 {
        let v = nodes[i].next;
        if v < 0 { return -1; }
        let k = raw(s, nodes, i);
        if mail::eq_fold(k, name) { return v; }
        // BODY[]<0> answers BODY[]<0.100>, and BODY[] too.
        if k.len > name.len && k[name.len] == '<' && mail::eq_fold(k[..name.len], name) { return v; }
        i = nodes[v].next;
    }
    return -1;
}

// An item's value in a FETCH item list (s from "(" on), a string's
// contents (a literal's bytes, a quoted string unescaped) appended to out;
// a list as its raw text. False when the item is not there; NIL appends
// nothing.
fn item(s: const u8[:], name: const u8[:], out: u8[>..]&) -> bool {
    var nodes: Node[>..] = [];
    let v = find_item(s, nodes, name);
    if v < 0 { return false; }
    if kind_of(nodes, v) == K_LIST { out.append(raw(s, nodes, v)); return true; }
    return text(s, nodes, v, out);
}

// A Message's item from the last command's responses: fetch_item(c, m,
// "BODY[HEADER]", out).
fn fetch_item(c: const Client&, m: const Message&, name: const u8[:], out: u8[>..]&) -> bool {
    if m.pos < 0 || m.end > c.data.len || m.pos > m.end { return false; }
    return item(c.data[m.pos..m.end], name, out);
}

// FETCH set items: set a sequence set ("1:*", "4,7"), items a data item
// or a list of them ("(UID FLAGS ENVELOPE BODY.PEEK[])", "FULL"). The
// answers into out; fetch_item and the others read their items.
fn fetch(c: Client&, set: const u8[:], items: const u8[:], out: Message[>..]&) -> i64 {
    return fetch_cmd(c, "FETCH", set, items, out);
}

// UID FETCH: set is of UIDs.
fn uid_fetch(c: Client&, set: const u8[:], items: const u8[:], out: Message[>..]&) -> i64 {
    return fetch_cmd(c, "UID FETCH", set, items, out);
}

fn fetch_cmd(c: Client&, verb: const u8[:], set: const u8[:], items: const u8[:], out: Message[>..]&) -> i64 {
    out.clear();
    if !seq_set_ok(set) || items.len == 0 { return mail::ERR_ARG; }
    begin(c, verb);
    add_raw(c, set);
    add_raw(c, items);
    let e = run(c);
    if e != mail::OK { return e; }
    return messages(c, out);
}

// The numbers of a SEARCH response ("1 4 9"), or of an ESEARCH one's ALL
// ("(TAG "A4") UID ALL 1:3,9"), appended to out.
fn parse_search(word: const u8[:], rest: const u8[:], max: i64, out: i64[>..]&) -> bool {
    if mail::eq_fold(word, "SEARCH") {
        for w in words(rest) {
            if w[0] == '(' { break; }            // CONDSTORE's (MODSEQ n)
            let n, ok = parse_number(w);
            if !ok || out.len >= max { return false; }
            out.push(n);
        }
        return true;
    }
    var nodes: Node[>..] = [];
    if !tree(rest, nodes) { return false; }
    var i = nodes[0].child;
    if kind_of(nodes, i) == K_LIST { i = nodes[i].next; }     // the tag
    while i >= 0 {
        let k = raw(rest, nodes, i);
        if mail::eq_fold(k, "UID") { i = nodes[i].next; continue; }
        let v = nodes[i].next;
        if v < 0 { return false; }
        if mail::eq_fold(k, "ALL") && !parse_seq_set(raw(rest, nodes, v), 0, max - out.len, out) { return false; }
        i = nodes[v].next;
    }
    return true;
}

// SEARCH criteria: the matching messages' numbers into out. criteria is
// IMAP's search syntax ("UNSEEN", "FROM \"bob\" SINCE 1-Jan-2026");
// quote() makes a string for it.
fn search(c: Client&, criteria: const u8[:], out: i64[>..]&) -> i64 { search_cmd(c, "SEARCH", criteria, out) }

// UID SEARCH: their UIDs.
fn uid_search(c: Client&, criteria: const u8[:], out: i64[>..]&) -> i64 { search_cmd(c, "UID SEARCH", criteria, out) }

fn search_cmd(c: Client&, verb: const u8[:], criteria: const u8[:], out: i64[>..]&) -> i64 {
    out.clear();
    if criteria.len == 0 { return mail::ERR_ARG; }
    begin(c, verb);
    add_raw(c, criteria);
    let e = run(c);
    if e != mail::OK { return e; }
    var bad = false;
    let max = c.max_data / 8;
    each_response(c) { r =>
        let w, rest = first_word(r[2..]);
        if mail::eq_fold(w, "SEARCH") || mail::eq_fold(w, "ESEARCH") {
            if !parse_search(w, rest, max, out) { bad = true; }
        }
    };
    return if bad { mail::ERR_PROTOCOL } else { mail::OK };
}

// Whether flags is a flag list's insides: "\Seen \Deleted $Label".
fn flags_ok(flags: const u8[:]) -> bool {
    for w in words(flags) {
        let body = if w[0] == '\\' { w[1..] } else { w };
        if body.len == 0 { return false; }
        for ch in body { if !atom_char(ch) { return false; } }
    }
    return true;
}

// STORE set how (flags): how is FLAGS (replace), +FLAGS (add) or -FLAGS
// (remove), ".SILENT" after it for no FETCH back; flags "\Seen \Deleted".
// The FETCH responses it brings are messages()'.
fn store(c: Client&, set: const u8[:], how: const u8[:], flags: const u8[:]) -> i64 { store_cmd(c, "STORE", set, how, flags) }
fn uid_store(c: Client&, set: const u8[:], how: const u8[:], flags: const u8[:]) -> i64 { store_cmd(c, "UID STORE", set, how, flags) }

fn store_cmd(c: Client&, verb: const u8[:], set: const u8[:], how: const u8[:], flags: const u8[:]) -> i64 {
    var h = how;
    if h.len > 0 && (h[0] == '+' || h[0] == '-') { h = h[1..]; }
    if !mail::eq_fold(h, "FLAGS") && !mail::eq_fold(h, "FLAGS.SILENT") { return mail::ERR_ARG; }
    if !seq_set_ok(set) || !flags_ok(flags) { return mail::ERR_ARG; }
    begin(c, verb);
    add_raw(c, set);
    add_raw(c, how);
    c.cmd.append(" (");
    c.cmd.append(flags);
    c.cmd.push(')');
    return run(c);
}

// COPY set mailbox. With UIDPLUS, c.code is "COPYUID uidvalidity from to".
fn copy(c: Client&, set: const u8[:], mailbox: const u8[:]) -> i64 { copy_cmd(c, "COPY", set, mailbox) }
fn uid_copy(c: Client&, set: const u8[:], mailbox: const u8[:]) -> i64 { copy_cmd(c, "UID COPY", set, mailbox) }

// MOVE (RFC 6851): ERR_UNSUPPORTED from a server without it.
fn move(c: Client&, set: const u8[:], mailbox: const u8[:]) -> i64 { copy_cmd(c, "MOVE", set, mailbox) }
fn uid_move(c: Client&, set: const u8[:], mailbox: const u8[:]) -> i64 { copy_cmd(c, "UID MOVE", set, mailbox) }

fn copy_cmd(c: Client&, verb: const u8[:], set: const u8[:], mailbox: const u8[:]) -> i64 {
    if verb.ends_with("MOVE") && !capability(c, "MOVE") && !capability(c, "IMAP4rev2") { return mail::ERR_UNSUPPORTED; }
    if !seq_set_ok(set) { return mail::ERR_ARG; }
    begin(c, verb);
    add_raw(c, set);
    add_mailbox(c, mailbox);
    return run(c);
}

// EXPUNGE: removes the \Deleted messages; expunged() says which went.
fn expunge(c: Client&) -> i64 { simple(c, "EXPUNGE") }

// UID EXPUNGE set (UIDPLUS, IMAP4rev2): only those of set.
fn uid_expunge(c: Client&, set: const u8[:]) -> i64 {
    if !capability(c, "UIDPLUS") && !capability(c, "IMAP4rev2") { return mail::ERR_UNSUPPORTED; }
    if !seq_set_ok(set) { return mail::ERR_ARG; }
    begin(c, "UID EXPUNGE");
    add_raw(c, set);
    return run(c);
}

// The EXPUNGE responses among those kept, their numbers as they came (each
// counted after the ones before it went).
fn expunged(c: const Client&, out: i64[>..]&) {
    out.clear();
    each_response(c) { r =>
        let w1, rest = first_word(r[2..]);
        let n, isnum = parse_number(w1);
        if isnum && mail::eq_fold(trim(rest), "EXPUNGE") { out.push(n); }
    };
}

// APPEND: msg (CRLF lines) added to mailbox, with flags ("\Seen", or "")
// and an internal date ("14-Nov-2026 10:00:00 +0000", or "" for now). It
// goes as a literal, without waiting for "+" when LITERAL+ allows. With
// UIDPLUS, c.code is "APPENDUID uidvalidity uid".
fn append(c: Client&, mailbox: const u8[:], flags: const u8[:], date: const u8[:], msg: const u8[:]) -> i64 {
    if !flags_ok(flags) || mail::has_crlf(date) || date.len > 64 { return mail::ERR_ARG; }
    begin(c, "APPEND");
    add_mailbox(c, mailbox);
    if flags.len > 0 {
        c.cmd.append(" (");
        c.cmd.append(flags);
        c.cmd.push(')');
    }
    if date.len > 0 {
        c.cmd.push(' ');
        quote(c.cmd, date);
    }
    let nonsync = nonsync_ok(c, msg.len);
    format(c.cmd, " {", msg.len, if nonsync { "+}\r\n" } else { "}\r\n" });
    if !nonsync { c.waits.push(c.cmd.len); }
    c.cmd.append(msg);
    return run(c);
}

// NOOP: what happened meanwhile (new messages: c.exists) comes with it.
fn noop(c: Client&) -> i64 { simple(c, "NOOP") }

// --- IDLE (RFC 2177) ---------------------------------------------------------------

// IDLE: the server sends what happens as it happens, idle_wait reads it,
// idle_done ends it. Nothing else may be sent meanwhile (ERR_STATE).
fn idle_start(c: Client&) -> i64 {
    if !capability(c, "IDLE") && !capability(c, "IMAP4rev2") { return mail::ERR_UNSUPPORTED; }
    begin(c, "IDLE");
    let e = run_until_continue(c);
    if e == mail::OK { c.idling = true; }
    return e;
}

// Sends the command and waits for "+"; a completion instead is the
// server's refusal.
fn run_until_continue(c: Client&) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    if c.cmd_err != mail::OK { return c.cmd_err; }
    if c.idling { return mail::ERR_STATE; }
    c.data.clear();
    c.ends.clear();
    c.cmd.append("\r\n");
    let e = send_part(c, 0, c.cmd.len);
    if e != mail::OK { return e; }
    loop {
        let kind, re = read_one(c);
        if kind == R_TAGGED { return if re == mail::OK { mail::ERR_PROTOCOL } else { re }; }
        if re != mail::OK { return re; }
        if kind == R_CONTINUE { return mail::OK; }
    }
    return mail::ERR_IO;
}

// Waits up to wait_ms for the server, then reads one response: OK and it
// is kept (c.data starts afresh at each wait; c.exists and the others
// follow it), ERR_TIMEOUT when nothing came.
fn idle_wait(c: Client&, wait_ms: i64) -> i64 {
    if !c.idling || c.fd < 0 { return mail::ERR_STATE; }
    c.data.clear();
    c.ends.clear();
    if c.inpos >= c.inbuf.len {
        let saved = c.timeout_ms;
        c.timeout_ms = wait_ms;
        let e = mail::link_fill(c);
        c.timeout_ms = saved;
        if e != mail::OK { return e; }
    }
    let kind, e = read_one(c);
    if kind == R_TAGGED {
        // The server ended IDLE itself.
        c.idling = false;
        return if e == mail::OK { mail::ERR_PROTOCOL } else { e };
    }
    if e != mail::OK { return e; }
    if kind != R_UNTAGGED { return mail::ERR_PROTOCOL; }
    return mail::OK;
}

// DONE: ends IDLE, and reads its completion.
fn idle_done(c: Client&) -> i64 {
    if !c.idling { return mail::ERR_STATE; }
    c.idling = false;
    let e = send_line(c, "DONE");
    if e != mail::OK { return e; }
    return finish(c);
}

// --- Leaving -------------------------------------------------------------------------

// LOGOUT: the server says BYE and closes; the connection closes whatever
// the reply.
fn logout(c: Client&) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    if c.idling { idle_done(c); }
    var e = simple(c, "LOGOUT");
    if e == mail::ERR_REPLY && c.bye && c.code.len == 0 { e = mail::OK; }   // closed after BYE
    close(c);
    return e;
}

// Closes without LOGOUT.
fn close(c: Client&) {
    mail::link_close(c);
    c.idling = false;
    c.selected = false;
}

// --- ENVELOPE and BODYSTRUCTURE ---------------------------------------------------------

// An ENVELOPE (RFC 9051 §7.5.2): the subject decoded from RFC 2047 when it
// can be, the addresses as mail.address has them (a group's members, not
// the group), "" and none for NIL.
root struct Envelope {
    date:        u8[>..]            = [],
    subject:     u8[>..]            = [],
    from:        mail::Address[>..] = [],
    sender:      mail::Address[>..] = [],
    reply_to:    mail::Address[>..] = [],
    to:          mail::Address[>..] = [],
    cc:          mail::Address[>..] = [],
    bcc:         mail::Address[>..] = [],
    in_reply_to: u8[>..]            = [],
    message_id:  u8[>..]            = [],
}

// An nstring decoded from RFC 2047 when it is encoded-words, as it is
// otherwise.
fn decoded(s: const u8[:], nodes: const Node[:], i: i64, out: u8[>..]&) -> bool {
    var t: u8[>..] = [];
    if !text(s, nodes, i, t) { return false; }
    var d: u8[>..] = [];
    if mime::decode_header(d, t) == mime::OK { out.append(d); } else { out.append(t); }
    return true;
}

// An address list, ((name adl mailbox host) ...) or NIL, into out.
fn parse_addresses(s: const u8[:], nodes: const Node[:], i: i64, out: mail::Address[>..]&) -> bool {
    out.clear();
    let k = kind_of(nodes, i);
    if k == K_NIL { return true; }
    if k != K_LIST { return false; }
    var a = nodes[i].child;
    while a >= 0 {
        if kind_of(nodes, a) != K_LIST || nodes[a].count != 4 { return false; }
        var name: u8[>..] = [];
        var mbox: u8[>..] = [];
        var host: u8[>..] = [];
        if !decoded(s, nodes, nth(nodes, a, 0), name) || !text(s, nodes, nth(nodes, a, 2), mbox) ||
           !text(s, nodes, nth(nodes, a, 3), host) { return false; }
        // A group's start (host NIL) and end (mailbox NIL too) are not addresses.
        if kind_of(nodes, nth(nodes, a, 3)) != K_NIL {
            var x = mail::Address { .. };
            put_cap(x.name, name);
            var spec: u8[>..] = [];
            spec.append(mbox);
            if host.len > 0 { spec.push('@'); spec.append(host); }
            put_cap(x.addr, spec);
            out.push(x);
        }
        a = nodes[a].next;
    }
    return true;
}

// An ENVELOPE's value, "(date subject from ...)", into env.
fn parse_envelope(s: const u8[:], env: Envelope&) -> bool {
    env.date.clear();
    env.subject.clear();
    env.in_reply_to.clear();
    env.message_id.clear();
    var nodes: Node[>..] = [];
    if !tree(s, nodes) { return false; }
    let l = nth(nodes, 0, 0);
    if kind_of(nodes, l) != K_LIST || nodes[l].count < 10 { return false; }
    return text(s, nodes, nth(nodes, l, 0), env.date) && decoded(s, nodes, nth(nodes, l, 1), env.subject) &&
           parse_addresses(s, nodes, nth(nodes, l, 2), env.from) &&
           parse_addresses(s, nodes, nth(nodes, l, 3), env.sender) &&
           parse_addresses(s, nodes, nth(nodes, l, 4), env.reply_to) &&
           parse_addresses(s, nodes, nth(nodes, l, 5), env.to) &&
           parse_addresses(s, nodes, nth(nodes, l, 6), env.cc) &&
           parse_addresses(s, nodes, nth(nodes, l, 7), env.bcc) &&
           text(s, nodes, nth(nodes, l, 8), env.in_reply_to) && text(s, nodes, nth(nodes, l, 9), env.message_id);
}

// A Message's ENVELOPE, from the last command's responses.
fn envelope(c: const Client&, m: const Message&, env: Envelope&) -> bool {
    var v: u8[>..] = [];
    if !fetch_item(c, m, "ENVELOPE", v) { return false; }
    return parse_envelope(v, env);
}

// A part of a BODYSTRUCTURE, in the order they come (depth first): its
// section number for BODY[...] ("1", "2.1"; a multipart has the prefix its
// parts number from: "" at the top), how deep it is, its type in lower
// case, and the parameters and fields that say what it is. A value longer
// than its field is cut. size and lines are -1 when not given.
struct Part {
    section:     u8[..64]  = [],
    depth:       i64       = 0,
    multipart:   bool      = false,
    mtype:       u8[..32]  = [],       // the media type: "text", "image", "multipart"
    subtype:     u8[..64]  = [],       // "plain", "mixed"
    charset:     u8[..40]  = [],
    name:        u8[..256] = [],       // the NAME parameter, decoded
    id:          u8[..256] = [],       // Content-ID
    encoding:    u8[..32]  = [],       // "base64", "7bit", in lower case
    size:        i64       = -1,       // in bytes, as encoded
    lines:       i64       = -1,       // text/* and message/rfc822
    disposition: u8[..32]  = [],       // "attachment", "inline", lower case
    filename:    u8[..256] = [],       // the disposition's FILENAME, decoded
    boundary:    u8[..80]  = [],       // a multipart's
}

fn put_lower<T>(dst: T&, s: const u8[:], nodes: const Node[:], i: i64) {
    var t: u8[>..] = [];
    text(s, nodes, i, t);
    for k in t.len { if t[k] >= 'A' && t[k] <= 'Z' { t[k] += 32; } }
    put_cap(dst, t);
}

// The value of parameter `key` in a parameter list ("CHARSET" "UTF-8"
// ...), decoded from RFC 2047 (names often are), into dst.
fn param<T>(dst: T&, s: const u8[:], nodes: const Node[:], l: i64, key: const u8[:]) {
    if kind_of(nodes, l) != K_LIST { return; }
    var i = nodes[l].child;
    while i >= 0 {
        let v = nodes[i].next;
        if v < 0 { return; }
        var k: u8[>..] = [];
        text(s, nodes, i, k);
        if mail::eq_fold(k, key) {
            var t: u8[>..] = [];
            decoded(s, nodes, v, t);
            put_cap(dst, t);
            return;
        }
        i = nodes[v].next;
    }
}

// The disposition ("ATTACHMENT" ("FILENAME" "a.pdf")) or NIL into p.
fn disposition(p: Part&, s: const u8[:], nodes: const Node[:], d: i64) {
    if kind_of(nodes, d) != K_LIST { return; }
    put_lower(p.disposition, s, nodes, nth(nodes, d, 0));
    param(p.filename, s, nodes, nth(nodes, d, 1), "FILENAME");
}

struct Pending { node: i64, section: u8[..64], depth: i64 }

// A section number: prefix, '.', k (just k without a prefix).
fn section_of(prefix: const u8[:], k: i64) -> u8[..64] {
    var s: u8[..64] = [];
    var t: u8[>..]  = [];
    if prefix.len > 0 { t.append(prefix); t.push('.'); }
    format(t, k);
    put_cap(s, t);
    return s;
}

// A BODYSTRUCTURE's value, "(...)", into parts: every part, depth first,
// each with its section number. False when it does not parse.
fn parse_bodystructure(s: const u8[:], parts: Part[>..]&) -> bool {
    parts.clear();
    var nodes: Node[>..] = [];
    if !tree(s, nodes) { return false; }
    let top = nth(nodes, 0, 0);
    if kind_of(nodes, top) != K_LIST { return false; }
    var todo: Pending[>..<] = [];
    let top_multi = kind_of(nodes, nth(nodes, top, 0)) == K_LIST;
    todo.push(Pending { node: top, section: if top_multi { "" } else { "1" }, depth: 0 });
    while todo.len > 0 {
        let p = todo.pop();
        let b = p.node;
        if kind_of(nodes, b) != K_LIST || nodes[b].count < 1 || p.depth > MAX_DEPTH { return false; }
        var part = Part { section: p.section, depth: p.depth, .. };
        if kind_of(nodes, nodes[b].child) == K_LIST {
            // multipart: its parts, then the subtype and the extensions
            part.multipart = true;
            put_cap(part.mtype, "multipart");
            var kids: i64[>..] = [];
            var i = nodes[b].child;
            while kind_of(nodes, i) == K_LIST { kids.push(i); i = nodes[i].next; }
            if i < 0 { return false; }
            put_lower(part.subtype, s, nodes, i);
            let params = nodes[i].next;
            param(part.boundary, s, nodes, params, "BOUNDARY");
            if params >= 0 { disposition(part, s, nodes, nodes[params].next); }
            parts.push(part);
            // pushed last first, so they come out in order
            var k = kids.len;
            while k > 0 {
                k--;
                todo.push(Pending { node: kids[k], section: section_of(p.section, k + 1), depth: p.depth + 1 });
            }
            continue;
        }
        // type subtype params id description encoding size ...
        if nodes[b].count < 7 { return false; }
        put_lower(part.mtype, s, nodes, nth(nodes, b, 0));
        put_lower(part.subtype, s, nodes, nth(nodes, b, 1));
        param(part.charset, s, nodes, nth(nodes, b, 2), "CHARSET");
        param(part.name, s, nodes, nth(nodes, b, 2), "NAME");
        put(part.id, s, nodes, nth(nodes, b, 3));
        put_lower(part.encoding, s, nodes, nth(nodes, b, 5));
        let size, ok = number(s, nodes, nth(nodes, b, 6));
        if !ok { return false; }
        part.size = size;
        var ext = 7;                          // where body-ext-1part starts: md5, disposition
        let message = part.mtype == "message" && (part.subtype == "rfc822" || part.subtype == "global");
        if part.mtype == "text" {
            let lines, okl = number(s, nodes, nth(nodes, b, 7));
            if okl { part.lines = lines; }
            ext = 8;
        } else if message && nodes[b].count >= 10 {
            let lines, okl = number(s, nodes, nth(nodes, b, 9));
            if okl { part.lines = lines; }
            ext = 10;
        }
        disposition(part, s, nodes, nth(nodes, b, ext + 1));
        parts.push(part);
        if message && nodes[b].count >= 10 {
            // The message's own body: a multipart numbers its parts from
            // this part's number, a single part is number.1.
            let inner = nth(nodes, b, 8);
            let multi = kind_of(nodes, nth(nodes, inner, 0)) == K_LIST;
            todo.push(Pending { node: inner, section: if multi { p.section } else { section_of(p.section, 1) },
                                depth: p.depth + 1 });
        }
    }
    return true;
}

// A Message's BODYSTRUCTURE (or BODY), from the last command's responses.
fn bodystructure(c: const Client&, m: const Message&, parts: Part[>..]&) -> bool {
    var v: u8[>..] = [];
    if !fetch_item(c, m, "BODYSTRUCTURE", v) && !fetch_item(c, m, "BODY", v) { return false; }
    return parse_bodystructure(v, parts);
}
