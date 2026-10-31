// mime's media types: ParseMediaType and FormatMediaType against Go's own
// test tables (test/vectors/go_*.txt, from $GOROOT/src/mime/mediatype_test.go
// by scripts/gen_vectors.py), each row checked against what Go returns.

import std;
import mime from "..";
import tv;

fn params_text(out: u8[>..]&, mt: const mime::MediaType&) {
    for p in mt.params { out.append(p.name); out.push('='); out.append(p.value); out.push(';'); }
}

// A flattened map[string]string from the row, as the same text.
fn row_map(out: u8[>..]&, r: tv::Row&) {
    if r.next_is_nil() { return; }
    let n = r.next_int();
    for i in n { out.append(r.next()); out.push('='); out.append(r.next()); out.push(';'); }
}

fn consume() {
    tv::each_row("vectors/go_consume_token.txt") { r: tv::Row& =>
        r.next_int();
        let input = r.next();
        let token = r.next();
        let rest = r.next();
        let e = mime::consume_token(input, 0);
        tv::check_eq(str("consume_token ", input), input[..e], token);
        tv::check_eq(str("consume_token rest ", input), input[e..], rest);
    };
    tv::each_row("vectors/go_consume_value.txt") { r: tv::Row& =>
        r.next_int();
        let input = r.next();
        let value = r.next();
        let rest = r.next();
        var arena: u8[>..] = [];
        let e = mime::consume_value(input, 0, arena);
        let got_rest = if e < 0 { input } else { input[e..] };
        tv::check_eq(str("consume_value ", input), arena, value);
        tv::check_eq(str("consume_value rest ", input), got_rest, rest);
    };
    tv::each_row("vectors/go_consume_media_param.txt") { r: tv::Row& =>
        r.next_int();
        let input = r.next();
        let param = r.next();
        let value = r.next();
        let rest = r.next();
        var arena: u8[>..] = [];
        var e = mime::Ent { key: mime::Span { pos: 0, end: 0 }, val: mime::Span { pos: 0, end: 0 } };
        let after = mime::consume_media_param(input, 0, arena, e);
        if after < 0 {
            tv::check(str("consume_media_param fails ", input), param == "" && value == "" && rest == input);
        } else {
            tv::check_eq(str("consume_media_param name ", input), arena[e.key.pos..e.key.end], param);
            tv::check_eq(str("consume_media_param value ", input), arena[e.val.pos..e.val.end], value);
            tv::check_eq(str("consume_media_param rest ", input), input[after..], rest);
        }
    };
}

// A row whose Go results are: the error's text, the type, the parameters.
fn parse_row(r: tv::Row&, input: const u8[:]) {
    r.to_results();
    let err = r.next();
    let typ = r.next();
    var want: u8[>..] = [];
    row_map(want, r);
    let mt = mime::parse_media_type(input);
    tv::check_eq(str("parse_media_type error ", input), mime::error_text(mt.err), err);
    tv::check_eq(str("parse_media_type type ", input), mt.typ, typ);
    var got: u8[>..] = [];
    params_text(got, mt);
    tv::check_eq(str("parse_media_type params ", input), got, want);
}

fn parse() {
    tv::each_row("vectors/go_parse_media_type.txt") { r: tv::Row& => parse_row(r, r.next()); };
    tv::each_row("vectors/go_bad_media_type.txt") { r: tv::Row& => parse_row(r, r.next()); };
}

fn format_tests() {
    tv::each_row("vectors/go_format_media_type.txt") { r: tv::Row& =>
        let typ = r.next();
        var kvs: mime::KV[>..] = [];
        if !r.next_is_nil() {
            let n = r.next_int();
            for i in n { let k = r.next(); let v = r.next(); kvs.push(mime::KV { key: k, value: v }); }
        }
        let want = r.next();
        r.to_results();
        let go = r.next();
        let got = mime::format_media_type(typ, kvs);
        tv::check_eq(str("format_media_type ", typ), got, go);
        tv::check_eq(str("format_media_type (table) ", typ), got, want);
        // Go's round trip: what it writes parses back to the same parameters.
        if got.len > 0 {
            let mt = mime::parse_media_type(got);
            tv::check(str("format round trip ", got), mt.err == 0);
            for kv in kvs {
                var lk: u8[>..] = [];
                mime::append_lower(lk, kv.key);
                let v, ok = mime::param(mt, lk);
                tv::check_eq(str("format round trip ", got, " ", kv.key), v, kv.value);
            }
        }
    };
}

// What the tables leave out: Unicode around the type, and RFC 2231 edges.
fn extra() {
    let mt1 = mime::parse_media_type("Key/x; a=b");      // KELVIN SIGN lowers to 'k' in Go
    tv::check_eq("kelvin sign", mt1.typ, "key/x");
    let mt2 = mime::parse_media_type(" text/plain　; charset=utf-8");
    tv::check_eq("unicode spaces", mt2.typ, "text/plain");
    tv::check_eq("unicode spaces param", mime::get_or(mt2, "charset"), "utf-8");
    let mt3 = mime::parse_media_type("a; t*=\"US-ASCİİ''x%41\"");   // ToLower(U+0130) is 'i'
    tv::check_eq("2231 charset folded", mime::get_or(mt3, "t"), "xA");
    let mt3b = mime::parse_media_type("a; t*=US-ASCİİ''x%41");      // not a token
    tv::check_int("2231 charset unquoted", mt3b.err, mime::ERR_INVALID_MEDIA_PARAMETER);
    let mt4 = mime::parse_media_type("a; t*0=x; t*1*=%4"); // a bad later piece adds nothing
    tv::check_eq("bad continuation piece", mime::get_or(mt4, "t"), "x");
    let mt5 = mime::parse_media_type("a; *=x; **=utf-8''y");      // "*" is the base "" (Go: no parameters)
    tv::check_int("empty base name", mt5.params.len, 0);
    let mt5b = mime::parse_media_type("a; *=utf-8''y");
    tv::check_eq("empty base name, single", mime::get_or(mt5b, ""), "y");
    let mt6 = mime::parse_media_type("text/html\xff");
    tv::check_int("invalid UTF-8 in the type", mt6.err, mime::ERR_UNEXPECTED_CONTENT);
}

fn main() {
    consume();
    parse();
    format_tests();
    extra();
    tv::done("mediatype");
}
