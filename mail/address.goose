// mail.address: email addresses (RFC 5322 §3.4), read and written as Go's
// net/mail reads and writes them.
//
// parse_address reads one: a bare addr-spec ("user@example.com"), a
// name-addr ("Name <user@example.com>"), a quoted display name, RFC 2047
// encoded-words in the display name (decoded), a comment after a bare
// addr-spec taken as the display name, comments elsewhere skipped, and a
// group holding exactly one address. parse_address_list reads a list, the
// members of groups included. Non-ASCII is allowed as RFC 6532 allows it.
// CR, LF and NUL are refused anywhere, so nothing parsed can split a
// header.
//
// write_address writes one back as Go's (*Address).String does: the local
// part quoted if it is not a dot-atom, the display name quoted when it is
// printable ASCII, else as an encoded-word (B when the name holds a
// character RFC 2047 §5(3) forbids there, Q otherwise).

namespace mail;

import std;
import mime;
import mime.encodedword;
import mail;

let ADDR_NAME_MAX: i64 = 256;     // a display name, decoded
let ADDR_SPEC_MAX: i64 = 320;     // an addr-spec: 64 for the local part, 255 for the domain, '@'

// An address: the display name (UTF-8, decoded; "" if none) and the
// addr-spec, local@domain.
struct Address { name: u8[..256] = [], addr: u8[..320] = [] }

// --- The grammar's character classes (net/mail's, over runes) --------------

fn addr_is_vchar(r: i64) -> bool { (r >= '!' && r <= '~') || r >= 0x80 }
fn addr_is_wsp(r: i64) -> bool { r == ' ' || r == '\t' }
fn addr_is_qtext(r: i64) -> bool { r != '\\' && r != '"' && addr_is_vchar(r) }
fn addr_is_dtext(r: i64) -> bool { r != '[' && r != ']' && r != '\\' && addr_is_vchar(r) }

// atext; with dot, '.' too.
fn addr_is_atext(r: i64, dot: bool) -> bool {
    if r == '.' { return dot; }
    if r == '(' || r == ')' || r == '<' || r == '>' || r == '[' || r == ']' || r == ':' || r == ';' ||
       r == '@' || r == '\\' || r == ',' || r == '"' { return false; }
    return addr_is_vchar(r);
}

// CR, LF or NUL anywhere: nothing with one is an address.
fn addr_has_break(s: const u8[:]) -> bool {
    for c in s { if c == '\r' || c == '\n' || c == 0 { return true; } }
    return false;
}

// --- The parser --------------------------------------------------------------

struct AddrParser { s: const u8[:], pos: i64 }

fn p_empty(p: const AddrParser&) -> bool { p.pos >= p.s.len }
fn p_peek(p: const AddrParser&) -> u8 { p.s[p.pos] }

fn p_consume(p: AddrParser&, c: u8) -> bool {
    if p_empty(p) || p_peek(p) != c { return false; }
    p.pos++;
    return true;
}

// Spaces and tabs.
fn p_skip_space(p: AddrParser&) {
    while !p_empty(p) && (p_peek(p) == ' ' || p_peek(p) == '\t') { p.pos++; }
}

// A comment's text after its '(' (nested ones kept, a backslash's escape
// undone); false if it does not close.
fn p_comment(p: AddrParser&, out: u8[>..]&) -> bool {
    var depth = 1;
    while !p_empty(p) && depth > 0 {
        if p_peek(p) == '\\' && p.pos + 1 < p.s.len { p.pos++; }
        else if p_peek(p) == '(' { depth++; }
        else if p_peek(p) == ')' { depth--; }
        if depth > 0 { out.push(p_peek(p)); }
        p.pos++;
    }
    return depth == 0;
}

// CFWS: white space and comments; false on a comment that does not close.
fn p_skip_cfws(p: AddrParser&) -> bool {
    p_skip_space(p);
    var scratch: u8[>..] = [];
    while p_consume(p, '(') {
        scratch.clear();
        if !p_comment(p, scratch) { return false; }
        p_skip_space(p);
    }
    return true;
}

// A quoted-string at '"': its content, the quoted-pairs undone, into out.
fn p_quoted_string(p: AddrParser&, out: u8[>..]&) -> i64 {
    var i = p.pos + 1;
    var escaped = false;
    loop {
        if i >= p.s.len { return ERR_ADDRESS; }              // unclosed
        let r, size = mime::decode_rune(p.s, i);
        if size == 1 && r == mime::RUNE_ERROR { return ERR_ADDRESS; }
        if escaped {
            if !addr_is_vchar(r) && !addr_is_wsp(r) { return ERR_ADDRESS; }
            out.append(p.s[i..i + size]);
            escaped = false;
        } else if addr_is_qtext(r) || addr_is_wsp(r) {
            out.append(p.s[i..i + size]);
        } else if r == '"' {
            break;
        } else if r == '\\' {
            escaped = true;
        } else {
            return ERR_ADDRESS;
        }
        i += size;
    }
    p.pos = i + 1;
    return OK;
}

// An atom (a dot-atom with dot); unless permissive, no leading, trailing
// or doubled dot. The atom, and OK or ERR_ADDRESS.
fn p_atom(p: AddrParser&, dot: bool, permissive: bool) -> const u8[:], i64 {
    let start = p.pos;
    var i = p.pos;
    while i < p.s.len {
        let r, size = mime::decode_rune(p.s, i);
        if size == 1 && r == mime::RUNE_ERROR { return "", ERR_ADDRESS; }
        if !addr_is_atext(r, dot) { break; }
        i += size;
    }
    if i == start { return "", ERR_ADDRESS; }
    let atom = p.s[start..i];
    p.pos = i;
    if !permissive {
        if atom[0] == '.' || atom[atom.len - 1] == '.' { return "", ERR_ADDRESS; }
        for k in atom.len - 1 { if atom[k] == '.' && atom[k + 1] == '.' { return "", ERR_ADDRESS; } }
    }
    return atom, OK;
}

// A domain-literal at '[': "[" dtext "]", an IPv4 address or "IPv6:" and an
// IPv6 one, as Go checks it (net.ParseIP).
fn p_domain_literal(p: AddrParser&, out: u8[>..]&) -> i64 {
    if !p_consume(p, '[') { return ERR_ADDRESS; }
    let start = p.pos;
    loop {
        if p_empty(p) { return ERR_ADDRESS; }
        if p_peek(p) == ']' { break; }
        let r, size = mime::decode_rune(p.s, p.pos);
        if size == 1 && r == mime::RUNE_ERROR { return ERR_ADDRESS; }
        if !addr_is_dtext(r) { return ERR_ADDRESS; }
        p.pos += size;
    }
    let dtext = p.s[start..p.pos];
    p.pos++;
    if dtext.len >= 5 && dtext[..5] == "IPv6:" {
        if addr_ip_kind(dtext[5..]) == 0 { return ERR_ADDRESS; }      // Go: any 16-byte ParseIP
    } else {
        let kind = addr_ip_kind(dtext);
        if kind != 4 && kind != 5 { return ERR_ADDRESS; }        // Go: To4() != nil
    }
    out.push('[');
    out.append(dtext);
    out.push(']');
    return OK;
}

// An addr-spec, local@domain, into out; on failure p and out are as they were.
fn p_addr_spec(p: AddrParser&, out: u8[>..]&) -> i64 {
    let pos0 = p.pos;
    let mark = out.len;
    let rc = p_addr_spec_inner(p, out);
    if rc != OK { p.pos = pos0; out.resize(mark); }
    return rc;
}

fn p_addr_spec_inner(p: AddrParser&, out: u8[>..]&) -> i64 {
    p_skip_space(p);
    if p_empty(p) { return ERR_ADDRESS; }
    if p_peek(p) == '"' {
        let mark = out.len;
        let rc = p_quoted_string(p, out);
        if rc != OK { return rc; }
        if out.len == mark { return ERR_ADDRESS; }            // an empty quoted local part
    } else {
        let atom, rc = p_atom(p, true, false);
        if rc != OK { return rc; }
        out.append(atom);
    }
    if !p_consume(p, '@') { return ERR_ADDRESS; }
    out.push('@');
    p_skip_space(p);
    if p_empty(p) { return ERR_ADDRESS; }
    if p_peek(p) == '[' { return p_domain_literal(p, out); }
    let atom, rc = p_atom(p, true, false);
    if rc != OK { return rc; }
    out.append(atom);
    return OK;
}

// An RFC 2047 encoded-word, decoded into out: whether it was one, and an
// error for one in a charset that cannot be read (Go's decodeRFC2047Word:
// a malformed word is just text).
fn addr_decode_2047(out: u8[>..]&, word: const u8[:]) -> bool, i64 {
    let rc = mime::decode_word(out, word);
    if rc == OK { return true, OK; }
    if rc == mime::ERR_UNHANDLED_CHARSET || rc == mime::ERR_CHARSET { return true, ERR_ADDRESS; }
    return false, OK;
}

// A phrase (the display name): words joined by a space, adjacent
// encoded-words run together, CFWS allowed after the first (obs-phrase).
fn p_phrase(p: AddrParser&, out: u8[>..]&) -> i64 {
    var words = 0;              // words written to out
    var enc:  u8[>..] = [];     // encoded-words decoded since the last plain word
    var word: u8[>..] = [];
    var err = OK;
    loop {
        if words > 0 || enc.len > 0 {
            if !p_skip_cfws(p) { return ERR_ADDRESS; }
        }
        p_skip_space(p);
        if p_empty(p) { break; }
        word.clear();
        var is_encoded = false;
        if p_peek(p) == '"' {
            err = p_quoted_string(p, word);
        } else {
            let atom, rc = p_atom(p, true, true);
            err = rc;
            if rc == OK {
                let mark = enc.len;
                let e, rc2 = addr_decode_2047(enc, atom);
                is_encoded = e;
                err = rc2;
                if !e { word.append(atom); }
                if rc2 != OK { enc.resize(mark); }
            }
        }
        if err != OK { break; }
        if is_encoded { continue; }
        if enc.len > 0 {
            if words > 0 { out.push(' '); }
            out.append(enc);
            enc.clear();
            words++;
        }
        if words > 0 { out.push(' '); }
        out.append(word);
        words++;
    }
    if enc.len > 0 {
        if words > 0 { out.push(' '); }
        out.append(enc);
        words++;
    }
    if err != OK && words == 0 { return ERR_ADDRESS; }
    return OK;
}

// The comment after a bare addr-spec, as its display name: its words,
// encoded-words decoded, joined by a space.
fn p_display_name_comment(p: AddrParser&, out: u8[>..]&) -> i64 {
    if !p_consume(p, '(') { return ERR_ADDRESS; }
    var comment: u8[>..] = [];
    if !p_comment(p, comment) { return ERR_ADDRESS; }
    var first = true;
    var i = 0;
    while i < comment.len {
        while i < comment.len && (comment[i] == ' ' || comment[i] == '\t') { i++; }
        if i == comment.len { break; }
        let start = i;
        while i < comment.len && comment[i] != ' ' && comment[i] != '\t' { i++; }
        if !first { out.push(' '); }
        first = false;
        let mark = out.len;
        let e, rc = addr_decode_2047(out, comment[start..i]);
        if rc != OK { return rc; }
        if !e { out.resize(mark); out.append(comment[start..i]); }
    }
    return OK;
}

// A finished address into a, ERR_ADDRESS if a part is too long for it.
fn addr_fill(a: Address&, name: const u8[:], spec: const u8[:]) -> i64 {
    if name.len > ADDR_NAME_MAX || spec.len > ADDR_SPEC_MAX { return ERR_ADDRESS; }
    a.name.clear();
    a.name.append(name);
    a.addr.clear();
    a.addr.append(spec);
    return OK;
}

let ADDR_IS_GROUP: i64 = -1;         // p_mailbox: a display name and ':' were read

// A mailbox (name-addr or addr-spec) into a. With allow_group, a display
// name followed by ':' gives ADDR_IS_GROUP, the ':' consumed.
fn p_mailbox(p: AddrParser&, a: Address&, allow_group: bool) -> i64 {
    p_skip_space(p);
    if p_empty(p) { return ERR_ADDRESS; }
    var spec: u8[>..] = [];
    var name: u8[>..] = [];
    // An addr-spec is the narrower grammar, so it is tried first.
    if p_addr_spec(p, spec) == OK {
        p_skip_space(p);
        if !p_empty(p) && p_peek(p) == '(' {
            let rc = p_display_name_comment(p, name);
            if rc != OK { return rc; }
        }
        return addr_fill(a, name, spec);
    }
    if p_peek(p) != '<' {
        let rc = p_phrase(p, name);
        if rc != OK { return rc; }
    }
    p_skip_space(p);
    if allow_group && p_consume(p, ':') { return ADDR_IS_GROUP; }
    if !p_consume(p, '<') { return ERR_ADDRESS; }
    let rc = p_addr_spec(p, spec);
    if rc != OK { return rc; }
    if !p_consume(p, '>') { return ERR_ADDRESS; }
    return addr_fill(a, name, spec);
}

// The rest of a group after its ':': mailboxes separated by commas, then
// ';' (an empty group too), appended to out.
fn p_group_list(p: AddrParser&, out: Address[>..]&) -> i64 {
    p_skip_space(p);
    if p_consume(p, ';') {
        if !p_skip_cfws(p) { return ERR_ADDRESS; }
        return OK;
    }
    loop {
        p_skip_space(p);
        var a = Address { .. };
        let rc = p_mailbox(p, a, false);
        if rc != OK { return rc; }
        out.push(a);
        if !p_skip_cfws(p) { return ERR_ADDRESS; }
        if p_consume(p, ';') {
            if !p_skip_cfws(p) { return ERR_ADDRESS; }
            return OK;
        }
        if !p_consume(p, ',') { return ERR_ADDRESS; }
    }
    return OK;
}

// An address: a mailbox, or a group's members, appended to out.
fn p_address(p: AddrParser&, out: Address[>..]&) -> i64 {
    var a = Address { .. };
    let rc = p_mailbox(p, a, true);
    if rc == ADDR_IS_GROUP { return p_group_list(p, out); }
    if rc != OK { return rc; }
    out.push(a);
    return OK;
}

// --- The API -----------------------------------------------------------------

// ParseAddress: one address, with nothing but CFWS after it. A group
// counts only when it holds exactly one address.
fn parse_address(s: const u8[:]) -> Address, i64 {
    if addr_has_break(s) { return Address { .. }, ERR_ADDRESS; }
    var p = AddrParser { s: s, pos: 0 };
    var got: Address[>..] = [];
    let rc = p_address(p, got);
    if rc != OK { return Address { .. }, rc; }
    if !p_skip_cfws(p) || !p_empty(p) || got.len != 1 { return Address { .. }, ERR_ADDRESS; }
    return got[0], OK;
}

// ParseAddressList: the addresses of a comma-separated list (empty entries
// skipped, groups' members included), appended to out; on an error out is
// as it was.
fn parse_address_list(s: const u8[:], out: Address[>..]&) -> i64 {
    if addr_has_break(s) { return ERR_ADDRESS; }
    let mark = out.len;
    var p = AddrParser { s: s, pos: 0 };
    loop {
        p_skip_space(p);
        if p_consume(p, ',') { continue; }
        let rc = p_address(p, out);
        if rc != OK { out.resize(mark); return rc; }
        if !p_skip_cfws(p) { out.resize(mark); return ERR_ADDRESS; }
        if p_empty(p) { break; }
        if p_peek(p) != ',' { out.resize(mark); return ERR_ADDRESS; }
        while p_consume(p, ',') { p_skip_space(p); }
        if p_empty(p) { break; }
    }
    return OK;
}

// An address from its parts: name as it is (UTF-8, no CR or LF) and addr,
// which must be an addr-spec alone.
fn make_address(name: const u8[:], addr: const u8[:]) -> Address, i64 {
    if addr_has_break(name) || addr_has_break(addr) { return Address { .. }, ERR_ADDRESS; }
    var p = AddrParser { s: addr, pos: 0 };
    var spec: u8[>..] = [];
    if p_addr_spec(p, spec) != OK || !p_empty(p) { return Address { .. }, ERR_ADDRESS; }
    var a = Address { .. };
    let rc = addr_fill(a, name, spec);
    return a, rc;
}

// quoteString: a quoted-string; controls dropped, as Go drops them.
fn addr_quote_string(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    var i = 0;
    while i < s.len {
        let r, size = mime::decode_rune(s, i);
        if addr_is_qtext(r) || addr_is_wsp(r) { mime::push_rune(out, r); }
        else if addr_is_vchar(r) { out.push('\\'); mime::push_rune(out, r); }
        i += size;
    }
    out.push('"');
}

// (*Address).String.
fn write_address(out: u8[>..]&, a: const Address&) {
    let addr = a.addr[..];
    var at = -1;
    for i in addr.len { if addr[i] == '@' { at = i; } }
    let local = if at < 0 { addr } else { addr[..at] };
    let domain = if at < 0 { addr[addr.len..] } else { addr[at + 1..] };
    var quote_local = false;
    var i = 0;
    while i < local.len {
        let r, size = mime::decode_rune(local, i);
        if !addr_is_atext(r, false) {
            // A dot is fine between two atext runes.
            if !(r == '.' && i > 0 && local[i - 1] != '.' && i < local.len - 1) { quote_local = true; break; }
        }
        i += size;
    }
    if a.name.len > 0 {
        write_display_name(out, a.name);
        out.push(' ');
    }
    out.push('<');
    if quote_local { addr_quote_string(out, local); } else { out.append(local); }
    out.push('@');
    out.append(domain);
    out.push('>');
}

// The display name: a quoted-string when it is all printable ASCII, else
// an encoded-word.
fn write_display_name(out: u8[>..]&, name: const u8[:]) {
    var printable = true;
    var i = 0;
    while i < name.len {
        let r, size = mime::decode_rune(name, i);
        if (!addr_is_vchar(r) && !addr_is_wsp(r)) || r >= 0x80 { printable = false; break; }
        i += size;
    }
    if printable { addr_quote_string(out, name); return; }
    var special = false;
    for c in name {
        if c == '"' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '(' || c == ')' ||
           c == ',' || c == '.' || c == ':' || c == ';' || c == '<' || c == '>' || c == '@' || c == '[' ||
           c == ']' || c == '^' || c == '`' || c == '{' || c == '|' || c == '}' || c == '~' { special = true; }
    }
    mime::encode_word(out, if special { mime::B_ENCODING } else { mime::Q_ENCODING }, "utf-8", name);
}

fn address_string(a: const Address&) -> u8[>..] {
    var out: u8[>..] = [];
    write_address(out, a);
    return out;
}

// --- IP addresses, for domain-literals ----------------------------------------

// Dotted decimal, four parts, no leading zeros (Go's parser).
fn addr_ip4_ok(s: const u8[:]) -> bool {
    var parts = 0;
    var digits = 0;
    var v = 0;
    for c in s {
        if c >= '0' && c <= '9' {
            if digits == 1 && v == 0 { return false; }
            v = v * 10 + (c - '0');
            digits++;
            if v > 255 { return false; }
        } else if c == '.' {
            if digits == 0 || parts == 3 { return false; }
            parts++;
            digits = 0;
            v = 0;
        } else {
            return false;
        }
    }
    return digits > 0 && parts == 3;
}

fn addr_hex(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

// 4 for IPv4, 5 for an IPv4-mapped IPv6 address (::ffff:a.b.c.d), 6 for
// other IPv6, 0 for neither: what Go's ParseIP accepts, and To4's answer.
fn addr_ip_kind(s: const u8[:]) -> i64 {
    if addr_ip4_ok(s) { return 4; }
    var ip: u8[16] = [0; 16];
    var ellipsis = -1;
    var p = 0;
    if s.len >= 2 && s[0] == ':' && s[1] == ':' {
        ellipsis = 0;
        p = 2;
        if p == s.len { return 6; }
    }
    var i = 0;
    while i < 16 {
        var off = 0;
        var acc = 0;
        while p + off < s.len {
            let v = addr_hex(s[p + off]);
            if v < 0 { break; }
            if off > 3 { return 0; }
            acc = acc * 16 + v;
            off++;
        }
        if off == 0 { return 0; }
        if p + off < s.len && s[p + off] == '.' {
            if (ellipsis < 0 && i != 12) || i + 4 > 16 { return 0; }
            if !addr_ip4_ok(s[p..]) { return 0; }
            for k in 4 { ip[i + k] = 1; }          // not zero: only the prefix decides To4
            i += 4;
            p = s.len;
            break;
        }
        ip[i] = (acc >> 8) as! u8;
        ip[i + 1] = (acc & 0xff) as! u8;
        i += 2;
        p += off;
        if p == s.len { break; }
        if s[p] != ':' || p + 1 == s.len { return 0; }
        p++;
        if s[p] == ':' {
            if ellipsis >= 0 { return 0; }
            ellipsis = i;
            p++;
            if p == s.len { break; }
        }
    }
    if p != s.len { return 0; }
    if i < 16 {
        if ellipsis < 0 { return 0; }
        let n = 16 - i;
        var k = i - 1;
        while k >= ellipsis { ip[k + n] = ip[k]; k--; }
        for z in ellipsis..ellipsis + n { ip[z] = 0; }
    } else if ellipsis >= 0 {
        return 0;
    }
    for k in 10 { if ip[k] != 0 { return 6; } }
    if ip[10] == 0xff && ip[11] == 0xff { return 5; }
    return 6;
}
