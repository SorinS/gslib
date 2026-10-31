// ldap.ldif: LDIF (RFC 2849). Written as OpenLDAP's ldapsearch writes it:
// "name: value", or "name:: base64" for a value LDIF cannot hold as it is
// (one starting with a space, ':' or '<', ending with a space, or with a
// NUL, CR, LF or byte past 0x7e in it, and every userPassword), lines
// folded at a width. Read as ldapmodify reads it: records separated by
// blank lines, folded lines, comments, "version: 1", base64 and URL
// values, control: lines, and change records (add, delete, modify with
// add/delete/replace/increment, modrdn/moddn), and plain entries, added
// (ldapadd, ldapmodify -a) or refused as OpenLDAP 2.7's ldapmodify
// refuses them without -a. A URL
// value ("name:< file:///path") is the caller's to fetch, through the
// block next_record takes: F(url, out) appends the value and says
// whether it could.

namespace ldap;

import std;
import base64;
import net.ldap;
import encoding.asn1;

// OpenLDAP's width (its LDIF_LINE_WIDTH).
let LDIF_WRAP: i64 = 78;

// Whether a value goes in base64 (OpenLDAP's ldif_must_b64_encode, with
// its userPassword).
fn ldif_needs_base64(name: const u8[:], v: const u8[:]) -> bool {
    if equal_fold(name, "userPassword") || equal_fold(name, "2.5.4.35") { return true; }
    if v.len == 0 { return false; }
    if v[0] == ' ' || v[0] == ':' || v[0] == '<' || v[v.len - 1] == ' ' { return true; }
    for c in v { if c == 0 || c == '\r' || c == '\n' || c > 0x7e { return true; } }
    return false;
}

// One logical line, "name: value" or "name:: base64", folded so that no
// line is longer than wrap (0: never), continuation lines starting with a
// space.
fn ldif_line(out: u8[>..]&, name: const u8[:], v: const u8[:], wrap: i64 = LDIF_WRAP) {
    var line: u8[>..] = [];
    line.append(name);
    if ldif_needs_base64(name, v) {
        line.append(":: ");
        base64::encode(line, v);
    } else if v.len == 0 {
        line.push(':');
    } else {
        line.append(": ");
        line.append(v);
    }
    if wrap <= 1 || line.len <= wrap {
        out.append(line);
        out.push('\n');
        return;
    }
    out.append(line[..wrap]);
    var i = wrap;
    while i < line.len {
        let n = if line.len - i < wrap - 1 { line.len - i } else { wrap - 1 };
        out.append("\n ");
        out.append(line[i..i + n]);
        i += n;
    }
    out.push('\n');
}

// A SearchResultEntry as an LDIF record (without the blank line after
// it); with types_only, the attribute names alone.
fn ldif_entry(out: u8[>..]&, buf: const u8[:], m: const Message&, wrap: i64 = LDIF_WRAP, types_only: bool = false) {
    ldif_line(out, "dn", entry_dn(buf, m), wrap);
    for a in attributes(buf, m) {
        let name = attribute_name(buf, a);
        if types_only {
            out.append(name);
            out.append(":\n");
            continue;
        }
        for v in attribute_values(buf, a) { ldif_line(out, name, v, wrap); }
    }
}

// --- Reading ----------------------------------------------------------------------

let CHANGE_ADD: i64 = 0;
let CHANGE_DELETE: i64 = 1;
let CHANGE_MODIFY: i64 = 2;
let CHANGE_MODDN: i64 = 3;

// One record: what it does, the line it starts on (and, after an error,
// the line at fault), the DN, the controls
// (put_control's), a moddn's new RDN, deleteoldrdn and new superior, and
// an add's attributes (put_attribute's) or a modify's changes
// (put_change's), ready for ldap::add and ldap::modify.
struct Record {
    kind: i64, line: i64, error_line: i64,
    dn: u8[..16384],
    controls: u8[..65536],
    new_rdn: u8[..16384], delete_old: bool, new_superior: u8[..16384], has_new_superior: bool,
    body: u8[>..],
}

fn empty_record() -> Record {
    Record { kind: CHANGE_ADD, line: 0, error_line: 0, dn: [], controls: [], new_rdn: [], delete_old: false, new_superior: [],
             has_new_superior: false, body: [] }
}

struct Span { off: i64, end: i64, line: i64 }

fn starts_fold(s: const u8[:], p: const u8[:]) -> bool { s.len >= p.len && equal_fold(s[..p.len], p) }

// The logical lines of the record at pos (folding undone, comments
// gone) into lines, as spans of text; pos moves past it and the blank
// lines after it. The first line's number into line.
fn record_lines(text: const u8[:], pos: i64&, lineno: i64&, joined: u8[>..]&, lines: Span[>..]&) -> i64 {
    // Skip blank lines (and comments) before the record.
    var first = 0;
    loop {
        if pos >= text.len { return 0; }
        var e = pos;
        while e < text.len && text[e] != '\n' { e++; }
        var l = text[pos..e];
        if l.len > 0 && l[l.len - 1] == '\r' { l = l[..l.len - 1]; }
        if l.len == 0 || l[0] == '#' {
            pos = if e < text.len { e + 1 } else { e };
            lineno = lineno + 1;
            // A comment's continuation lines are the comment's.
            if l.len > 0 {
                while pos < text.len && text[pos] == ' ' {
                    var e2 = pos;
                    while e2 < text.len && text[e2] != '\n' { e2++; }
                    pos = if e2 < text.len { e2 + 1 } else { e2 };
                    lineno = lineno + 1;
                }
            }
            continue;
        }
        first = lineno + 1;
        break;
    }
    var comment = false;
    while pos < text.len {
        var e = pos;
        while e < text.len && text[e] != '\n' { e++; }
        var l = text[pos..e];
        if l.len > 0 && l[l.len - 1] == '\r' { l = l[..l.len - 1]; }
        pos = if e < text.len { e + 1 } else { e };
        lineno = lineno + 1;
        if l.len == 0 { break; }
        if l[0] == ' ' {
            if comment { continue; }
            if lines.len == 0 { return -1; }
            joined.append(l[1..]);
            lines[lines.len - 1].end = joined.len;
            continue;
        }
        comment = l[0] == '#';
        if comment { continue; }
        let off = joined.len;
        joined.append(l);
        lines.push(Span { off: off, end: joined.len, line: lineno });
    }
    return first;
}

// A line's name and value: "name: text", "name:: base64" or "name:<
// url" (F fetches it). false, with err, when the line is none of these.
fn line_value<F>(l: const u8[:], name_end: i64&, value: u8[>..]&, err: u8[>..]&) -> bool {
    let colon = position(l, ':');
    if colon <= 0 { err.append("missing ':' after attribute name"); return false; }
    name_end = colon;
    var i = colon + 1;
    if i < l.len && l[i] == ':' {
        i++;
        while i < l.len && l[i] == ' ' { i++; }
        if !base64::decode(value, l[i..]) { err.append("invalid base64 value"); return false; }
        return true;
    }
    if i < l.len && l[i] == '<' {
        i++;
        while i < l.len && l[i] == ' ' { i++; }
        if !F(l[i..], value) { format(err, "cannot read ", l[i..]); return false; }
        return true;
    }
    while i < l.len && l[i] == ' ' { i++; }
    value.append(l[i..]);
    return true;
}

// The next record of text at pos into r: 1, 0 at the end, -1 with err
// saying why (and r.error_line where). default_add: a record without a
// changetype is added (ldapadd, ldapmodify -a); otherwise it is refused
// ("modify operation type is missing").
fn next_record<F>(text: const u8[:], pos: i64&, lineno: i64&, r: Record&, err: u8[>..]&, default_add: bool = false) -> i64 {
    r.kind = CHANGE_ADD;
    r.error_line = 0;
    r.dn.clear();
    r.controls.clear();
    r.new_rdn.clear();
    r.delete_old = false;
    r.new_superior.clear();
    r.has_new_superior = false;
    r.body.clear();
    var joined: u8[>..] = [];
    var lines: Span[>..] = [];
    var li = 0;
    var ne = 0;
    var v: u8[>..] = [];
    var first = 0;
    loop {
        first = record_lines(text, pos, lineno, joined, lines);
        if first < 0 { err.append("continuation line without a line before it"); return -1; }
        if first == 0 { return 0; }
        // "version: 1" on its own, or before the first record's dn.
        if !starts_with(joined[lines[0].off..lines[0].end], "version:") { break; }
        let l = joined[lines[0].off..lines[0].end];
        let okl1 = line_value(l, ne, v, err) { u, o => F(u, o) };
        if !okl1 { return -1; }
        if trim(v) != "1" { err.append("unsupported LDIF version"); return -1; }
        if lines.len > 1 { li = 1; break; }
        joined.clear();
        lines.clear();
        v.clear();
    }
    r.line = first;
    let dl = joined[lines[li].off..lines[li].end];
    v.clear();
    let okl2 = line_value(dl, ne, v, err) { u, o => F(u, o) };
    if !okl2 { return -1; }
    if !equal_fold(dl[..ne], "dn") { err.append("record does not start with dn:"); return -1; }
    if v.len > 16384 { err.append("dn too long"); return -1; }
    r.dn.append(v);
    li++;

    // control: oid [true|false] [value]
    while li < lines.len && starts_fold(joined[lines[li].off..lines[li].end], "control:") {
        let l = joined[lines[li].off..lines[li].end];
        var i = 8;
        while i < l.len && l[i] == ' ' { i++; }
        let o0 = i;
        while i < l.len && l[i] != ' ' && l[i] != ':' { i++; }
        let oid = l[o0..i];
        while i < l.len && l[i] == ' ' { i++; }
        var critical = false;
        if starts_with(l[i..], "true") { critical = true; i += 4; }
        else if starts_with(l[i..], "false") { i += 5; }
        while i < l.len && l[i] == ' ' { i++; }
        var cv: u8[>..] = [];
        var has_value = false;
        if i < l.len {
            var x = 0;
            var tmp: u8[>..] = [];
            tmp.append("v");
            tmp.append(l[i..]);
            let okl3 = line_value(tmp, x, cv, err) { u, o => F(u, o) };
            if !okl3 { return -1; }
            has_value = true;
        }
        if oid.len == 0 { err.append("control: without an OID"); return -1; }
        var cb: u8[>..] = [];
        put_control(cb, oid, critical, cv, has_value);
        if r.controls.len + cb.len > 65536 { err.append("too many controls"); return -1; }
        r.controls.append(cb);
        li++;
    }

    var kind: i64 = -1;
    if li < lines.len {
        let l = joined[lines[li].off..lines[li].end];
        v.clear();
        let okl4 = line_value(l, ne, v, err) { u, o => F(u, o) };
        if !okl4 { return -1; }
        if equal_fold(l[..ne], "changetype") {
            let t = trim(v);
            if t == "add" { kind = CHANGE_ADD; }
            else if t == "delete" { kind = CHANGE_DELETE; }
            else if t == "modify" { kind = CHANGE_MODIFY; }
            else if t == "modrdn" || t == "moddn" { kind = CHANGE_MODDN; }
            else { format(err, "unknown changetype \"", t, "\""); r.error_line = lines[li].line; return -1; }
            li++;
        }
    }
    if kind < 0 {
        if !default_add {
            err.append("modify operation type is missing");
            r.error_line = if li < lines.len { lines[li].line } else { lines[lines.len - 1].line };
            return -1;
        }
        kind = CHANGE_ADD;
    }
    r.kind = kind;

    if kind == CHANGE_DELETE {
        if li != lines.len { err.append("delete record with attributes"); return -1; }
        return 1;
    }
    if kind == CHANGE_MODDN {
        var seen_rdn = false;
        var seen_delete = false;
        while li < lines.len {
            let l = joined[lines[li].off..lines[li].end];
            v.clear();
            let okl5 = line_value(l, ne, v, err) { u, o => F(u, o) };
            if !okl5 { return -1; }
            let name = l[..ne];
            if equal_fold(name, "newrdn") && !seen_rdn { r.new_rdn.append(v); seen_rdn = true; }
            else if equal_fold(name, "deleteoldrdn") && !seen_delete {
                let t = trim(v);
                if t != "0" && t != "1" { err.append("deleteoldrdn is 0 or 1"); return -1; }
                r.delete_old = t == "1";
                seen_delete = true;
            }
            else if (equal_fold(name, "newsuperior") || equal_fold(name, "newparent")) && !r.has_new_superior {
                r.new_superior.append(v);
                r.has_new_superior = true;
            }
            else { format(err, "unexpected ", name, " in modrdn record"); return -1; }
            li++;
        }
        if !seen_rdn { err.append("modrdn record without newrdn"); return -1; }
        return 1;
    }

    // An add's attribute lines, grouped by name in the order they first appear.
    if kind == CHANGE_ADD {
        var names: Span[>..] = [];
        var vals: u8[>..] = [];       // each value, put_value'd, in line order
        var owner: i64[>..] = [];     // the name each value has
        var voff: Span[>..] = [];
        var scratch: u8[>..] = [];
        while li < lines.len {
            let l = joined[lines[li].off..lines[li].end];
            v.clear();
            let okl6 = line_value(l, ne, v, err) { u, o => F(u, o) };
            if !okl6 { return -1; }
            let name = l[..ne];
            if equal_fold(name, "changetype") || equal_fold(name, "control") { format(err, "unexpected ", name); return -1; }
            var k = -1;
            for j in names.len { if equal_fold(scratch[names[j].off..names[j].end], name) { k = j; break; } }
            if k < 0 {
                k = names.len;
                let o = scratch.len;
                scratch.append(name);
                names.push(Span { off: o, end: scratch.len, line: 0 });
            }
            let o = vals.len;
            put_value(vals, v);
            voff.push(Span { off: o, end: vals.len, line: 0 });
            owner.push(k);
            li++;
        }
        if names.len == 0 { err.append("add record without attributes"); return -1; }
        for j in names.len {
            var these: u8[>..] = [];
            for x in voff.len { if owner[x] == j { these.append(vals[voff[x].off..voff[x].end]); } }
            put_attribute(r.body, scratch[names[j].off..names[j].end], these);
        }
        return 1;
    }

    // modify: "op: attr", its values, "-".
    while li < lines.len {
        let l = joined[lines[li].off..lines[li].end];
        v.clear();
        let okl7 = line_value(l, ne, v, err) { u, o => F(u, o) };
        if !okl7 { return -1; }
        let op_name = l[..ne];
        var op: i64 = -1;
        if equal_fold(op_name, "add") { op = MOD_ADD; }
        else if equal_fold(op_name, "delete") { op = MOD_DELETE; }
        else if equal_fold(op_name, "replace") { op = MOD_REPLACE; }
        else if equal_fold(op_name, "increment") { op = MOD_INCREMENT; }
        else { format(err, "unknown modify operation ", op_name); return -1; }
        var attr: u8[>..] = [];
        attr.append(trim(v));
        if attr.len == 0 { err.append("modify operation without an attribute"); return -1; }
        li++;
        var these: u8[>..] = [];
        var count = 0;
        while li < lines.len {
            let l2 = joined[lines[li].off..lines[li].end];
            if l2 == "-" { li++; break; }
            v.clear();
            let okl8 = line_value(l2, ne, v, err) { u, o => F(u, o) };
            if !okl8 { return -1; }
            if !equal_fold(l2[..ne], attr) { format(err, "value of ", l2[..ne], " in a change of ", attr); r.error_line = lines[li].line; return -1; }
            put_value(these, v);
            count++;
            li++;
        }
        if op == MOD_INCREMENT && count != 1 { err.append("increment takes one value"); return -1; }
        put_change(r.body, op, attr, these);
    }
    return 1;
}
