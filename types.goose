// mime.types: media types by file extension, as Go's mime package keeps
// them: TypeByExtension, ExtensionsByType, AddExtensionType.
//
// The table starts as Go's built-in one (types_builtin.goose, generated
// from Go's mime/type.go), then, on macOS, Linux and the BSDs, takes the
// system's: the first FreeDesktop shared-mime-info globs2 file that exists
// (/usr/local/share/mime/globs2, /usr/share/mime/globs2), else every
// mime.types file of /etc/mime.types, /etc/apache2/mime.types,
// /etc/apache/mime.types, /etc/httpd/conf/mime.types. Go reads the
// registry on Windows; this does not (the built-in table only there).
//
// A text/ type without a charset gets "; charset=utf-8", as in Go.
// Lookups are case-sensitive first, then by the extension in lower case.
// The table is loaded on first use (types_init); its strings live for the
// whole program.

namespace mime;

import std;
import dictionary;
import os;
import mime;
import types_builtin;

struct TSpan { pos: i64, end: i64 }
struct ExtOf { typ: TSpan, ext: TSpan }

var types_ready: bool = false;
var types_arena: u8[>..];
var types_by_ext = dictionary<const u8[:], TSpan> {};          // Go's mimeTypes
var types_by_lower = dictionary<const u8[:], TSpan> {};        // Go's mimeTypesLower
var types_exts: ExtOf[>..];                                    // Go's extensions, flattened
var types_ext_seen = dictionary<const u8[:], bool> {};         // "type\0ext" of types_exts

let MIME_GLOBS = ["/usr/local/share/mime/globs2", "/usr/share/mime/globs2"];
let TYPE_FILES = ["/etc/mime.types", "/etc/apache2/mime.types", "/etc/apache/mime.types", "/etc/httpd/conf/mime.types"];

fn tspan_text(s: TSpan) -> const u8[:] { types_arena[s.pos..s.end] }

fn arena_add(s: const u8[:]) -> TSpan {
    let p = types_arena.len;
    types_arena.append(s);
    return TSpan { pos: p, end: types_arena.len };
}

// Sets key's value in d, keeping the key in the arena the first time.
fn types_store(d: dictionary<const u8[:], TSpan>&, key: const u8[:], v: TSpan) {
    let slot = d.get(key);
    if slot { slot = v; return; }
    let ks = arena_add(key);
    d.insert(types_arena[ks.pos..ks.end], v);
}

// Records ext (lower case) as one of the type's extensions, once.
fn types_add_ext(just_type: const u8[:], ext_lower: const u8[:]) {
    var k: u8[>..] = [];
    k.append(just_type);
    k.push(0);
    k.append(ext_lower);
    if types_ext_seen.contains(k) { return; }
    let ks = arena_add(k);
    types_ext_seen.insert(types_arena[ks.pos..ks.end], true);
    let ts = TSpan { pos: ks.pos, end: ks.pos + just_type.len };
    let es = TSpan { pos: ks.pos + just_type.len + 1, end: ks.end };
    types_exts.push(ExtOf { typ: ts, ext: es });
}

// setMimeTypes: the table emptied, then the given entries (extension in
// lower case and type) put in as they are, both case-sensitive and not.
fn types_reset(with_builtin: bool) {
    types_by_ext.clear();
    types_by_lower.clear();
    types_exts.clear();
    types_ext_seen.clear();
    types_ready = true;
    if !with_builtin { return; }
    for kv in BUILTIN_TYPES {
        let vs = arena_add(kv.value);
        types_store(types_by_lower, kv.key, vs);
        types_store(types_by_ext, kv.key, vs);
        let mt = parse_media_type(kv.value);
        types_add_ext(mt.typ, kv.key);
    }
}

// The table as Go's initMime makes it: the built-in one, then the system's.
fn types_init() {
    if types_ready { return; }
    types_reset(true);
    if is_windows() { return; }
    for g in MIME_GLOBS { if load_mime_globs_file(g) { return; } }
    for f in TYPE_FILES { load_mime_file(f); }
}

// setExtensionType: 0 or parse_media_type's error.
fn set_extension_type(extension: const u8[:], mime_type: const u8[:]) -> i64 {
    var mt = parse_media_type(mime_type);
    if mt.err != OK { return mt.err; }
    var value: u8[>..] = [];
    let cs, has_cs = param(mt, "charset");
    if starts_with(mime_type, "text/") && cs.len == 0 {
        var kvs: KV[>..] = [];
        for p in mt.params { if p.name != "charset" { kvs.push(KV { key: p.name, value: p.value }); } }
        kvs.push(KV { key: "charset", value: "utf-8" });
        format_media_type(value, mt.typ, kvs);
    } else {
        value.append(mime_type);
    }
    var lower: u8[>..] = [];
    go_to_lower(lower, extension);
    let vs = arena_add(value);
    types_store(types_by_ext, extension, vs);
    types_store(types_by_lower, lower, vs);
    types_add_ext(mt.typ, lower);
    return OK;
}

// TypeByExtension: the type of the extension (".html"), "" if none.
fn type_by_extension(ext: const u8[:]) -> const u8[:] {
    types_init();
    let v = types_by_ext.get(ext);
    if v { return tspan_text(v); }
    var lower: u8[>..] = [];
    go_to_lower(lower, ext);
    let w = types_by_lower.get(lower);
    if w { return tspan_text(w); }
    return "";
}

// ExtensionsByType: the extensions of the type (its parameters ignored),
// sorted, appended to out; parse_media_type's error if typ is not one.
fn extensions_by_type(out: u8[][>..]&, typ: const u8[:]) -> i64 {
    let mt = parse_media_type(typ);
    if mt.err != OK { return mt.err; }
    types_init();
    var found: const u8[:][>..] = [];
    for e in types_exts { if tspan_text(e.typ) == mt.typ { found.push(tspan_text(e.ext)); } }
    sort(found) { a, b => compare(a, b) < 0 };
    for e in found { out.push(e); }
    return OK;
}

// AddExtensionType: ext must start with '.'.
fn add_extension_type(ext: const u8[:], typ: const u8[:]) -> i64 {
    if ext.len == 0 || ext[0] != '.' { return ERR_EXTENSION_NO_DOT; }
    types_init();
    return set_extension_type(ext, typ);
}

// The message of add_extension_type's error.
fn add_extension_type_error(out: u8[>..]&, ext: const u8[:], code: i64) {
    if code == ERR_EXTENSION_NO_DOT {
        out.append("mime: extension ");
        go_quote(out, ext);
        out.append(" missing leading dot");
    } else {
        out.append(error_text(code));
    }
}

// bufio.Scanner's lines: split at '\n', a '\r' before it dropped, the last
// line kept if it is not empty.
fn each_scan_line<F>(text: const u8[:]) {
    var start = 0;
    while start < text.len {
        var e = start;
        while e < text.len && text[e] != '\n' { e++; }
        var l = text[start..e];
        if l.len > 0 && l[l.len - 1] == '\r' { l = l[..l.len - 1]; }
        F(l);
        start = e + 1;
    }
}

// loadMimeGlobsFile: "weight:type:*.ext" lines in weight order, the first
// line for an extension winning; globs that are not plain extensions are
// skipped. False if the file cannot be read.
fn load_mime_globs_file(path: const u8[:]) -> bool {
    var text: u8[>..] = [];
    if !read_file(path, text) { return false; }
    each_scan_line(text) { line: const u8[:] =>
        let fields = split(line, ':');
        if fields.len >= 3 && fields[0].len >= 1 && fields[2].len >= 3 &&
           fields[0][0] != '#' && fields[2][0] == '*' && fields[2][1] == '.' {
            let extension = fields[2][1..];
            var glob = false;
            for c in extension { if c == '?' || c == '*' || c == '[' { glob = true; } }
            if !glob && !types_by_ext.contains(extension) { set_extension_type(extension, fields[1]); }
        }
    };
    return true;
}

// strings.Fields: the runs between Unicode white space.
fn each_field<F>(s: const u8[:]) {
    var i = 0;
    while i < s.len {
        i = skip_space(s, i);
        if i >= s.len { break; }
        var j = i;
        while j < s.len {
            let r, n = decode_rune(s, j);
            if is_space_rune(r) && !(r == RUNE_ERROR && n == 1) { break; }
            j += n;
        }
        F(s[i..j]);
        i = j;
    }
}

// loadMimeFile: "type ext ext ..." lines, '#' starting a comment.
fn load_mime_file(path: const u8[:]) {
    var text: u8[>..] = [];
    if !read_file(path, text) { return; }
    var fields: const u8[:][>..] = [];
    each_scan_line(text) { line: const u8[:] =>
        fields.clear();
        each_field(line) { fields.push(it); };
        if fields.len > 1 && fields[0][0] != '#' {
            for k in 1..fields.len {
                if fields[k][0] == '#' { break; }
                set_extension_type(str(".", fields[k]), fields[0]);
            }
        }
    };
}
