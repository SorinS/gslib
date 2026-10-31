// mime.types against Go's type_test.go and type_unix_test.go: their
// tables (test/vectors, extracted from $GOROOT/src/mime) and their setups
// ported: Go's test data files (copied by scripts/gen_vectors.py), the
// local tables of TestTypeByExtension_LocalData and TestTypeByExtensionCase,
// TestAddExtensionType_TextMIMEWithParamsDefaultCharset, ExtensionsByType
// over a small table and over Go's built-in one.

import std;
import mime from "..";
import mime.types;
import tv;

fn set_type(ext: const u8[:], typ: const u8[:]) {
    tv::check_int(str("set type ", ext), mime::set_extension_type(ext, typ), 0);
}

fn exts_text(typ: const u8[:]) -> u8[>..] {
    var exts: u8[][>..] = [];
    let rc = mime::extensions_by_type(exts, typ);
    var out: u8[>..] = [];
    format(out, rc);
    for e in exts { out.push('|'); out.append(e); }
    return out;
}

// TestTypeByExtension: initMimeForTests (testdata/test.types, no globs2).
fn type_by_extension() {
    mime::types_reset(true);
    mime::load_mime_file("vectors/go_test.types");
    tv::each_row("vectors/go_types_init.txt") { r: tv::Row& =>
        let ext = r.next();
        let want = r.next();
        tv::check_eq(str("type of ", ext), mime::type_by_extension(ext), want);
    };
}

fn local_data() {
    mime::types_reset(false);
    set_type(".foo", "x/foo");
    set_type(".bar", "x/bar");
    set_type(".Bar", "x/bar; capital=1");
    tv::each_row("vectors/go_types_local_data.txt") { r: tv::Row& =>
        let ext = r.next();
        let want = r.next();
        tv::check_eq(str("local type of ", ext), mime::type_by_extension(ext), want);
    };
}

// TestTypeByExtensionCase.
fn by_case() {
    mime::types_reset(false);
    set_type(".TEST", "test/test; WAS=ALLCAPS");
    set_type(".tesT", "test/test; charset=iso-8859-1");
    tv::check_eq(".tesT", mime::type_by_extension(".tesT"), "test/test; charset=iso-8859-1");
    tv::check_eq(".TEST", mime::type_by_extension(".TEST"), "test/test; WAS=ALLCAPS");
    tv::check_eq(".TesT", mime::type_by_extension(".TesT"), "test/test; charset=iso-8859-1");
}

// TestAddExtensionType_TextMIMEWithParamsDefaultCharset, and the dot.
fn add_extension_type() {
    mime::types_reset(false);
    tv::check_int("add .regtxt", mime::add_extension_type(".regtxt", "text/x-reg; myparam=myvalue"), 0);
    let got = mime::type_by_extension(".regtxt");
    tv::check("charset added", find(got, "charset=utf-8") >= 0);
    tv::check("type kept", starts_with(got, "text/x-reg"));
    tv::check_eq("as Go formats it", got, "text/x-reg; charset=utf-8; myparam=myvalue");
    let rc = mime::add_extension_type("txt", "text/plain");
    tv::check_int("missing dot", rc, mime::ERR_EXTENSION_NO_DOT);
    var m: u8[>..] = [];
    mime::add_extension_type_error(m, "txt", rc);
    tv::check_eq("missing dot message", m, "mime: extension \"txt\" missing leading dot");
    tv::check_int("bad type", mime::add_extension_type(".x", "bogus/"), mime::ERR_NO_TOKEN_AFTER_SLASH);
}

fn extensions_by_type() {
    mime::types_reset(false);
    set_type(".gif", "image/gif");
    set_type(".a", "foo/letter");
    set_type(".b", "foo/letter");
    set_type(".B", "foo/letter");
    set_type(".PNG", "image/png");
    tv::each_row("vectors/go_ext_by_type.txt") { r: tv::Row& =>
        let typ = r.next();
        var want: u8[>..] = [];
        want.push('0');
        if !r.next_is_nil() { let n = r.next_int(); for i in n { want.push('|'); want.append(r.next()); } }
        tv::check_eq(str("extensions of ", typ), exts_text(typ), want);
    };
    mime::types_reset(true);
    tv::each_row("vectors/go_ext_by_type2.txt") { r: tv::Row& =>
        let typ = r.next();
        var want: u8[>..] = [];
        want.push('0');
        let n = r.next_int();
        for i in n { want.push('|'); want.append(r.next()); }
        tv::check_eq(str("built-in extensions of ", typ), exts_text(typ), want);
    };
    var none: u8[][>..] = [];
    tv::check_int("extensions of a bad type", mime::extensions_by_type(none, "/x"), mime::ERR_NO_MEDIA_TYPE);
}

// TestTypeByExtensionUNIX: the built-in table, the globs2 test file, then
// test.types.
fn unix() {
    mime::types_reset(true);
    tv::check("globs2 read", mime::load_mime_globs_file("vectors/go_test.types.globs2"));
    mime::load_mime_file("vectors/go_test.types");
    tv::each_row("vectors/go_types_unix.txt") { r: tv::Row& =>
        let ext = r.next();
        let want = r.next();
        tv::check_eq(str("unix type of ", ext), mime::type_by_extension(ext), want);
    };
    tv::check("missing globs2", !mime::load_mime_globs_file("vectors/no-such-file"));
}

fn main() {
    type_by_extension();
    local_data();
    by_case();
    add_extension_type();
    extensions_by_type();
    unix();
    tv::done("types");
}
