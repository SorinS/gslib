// Fuzz target: mime_header. MIME's header-level parsers (mime,
// textproto, encodedword, quotedprintable). Byte 0 picks: 0 a MIME
// header (textproto's ReadMIMEHeader: whole, with small limits, and fed
// before its end), the keys canonicalized; 1 RFC 2047 encoded words in a
// header (decoded, with a charset reader too, and encoded back to the
// same text); 2 a media type with RFC 2231 parameters (parsed, formatted,
// parsed back the same); 3 quoted-printable (decoded whole and in pieces,
// the same; encoded and decoded back); 4 the type table's lookups.

import std;
import gslib from "../..";
import gslib.mime;
import gslib.mime.encodedword;
import gslib.mime.quotedprintable;
import gslib.mime.textproto;
import gslib.mime.types;

fn header(s: const u8[:], lim: u8) {
    var h = textproto::new_header();
    var d: u8[>..] = [];
    let c1, e1 = textproto::read_mime_header_at(s, 0, true, textproto::MAX_INT64, textproto::MAX_INT64, h, d);
    if e1 > s.len { abort("mime_header: the header ends past the input"); }
    for f in h.fields {
        var k: u8[>..] = [];
        textproto::canonical_mime_header_key(k, f.key);
        let _ = textproto::get(h, f.key);
        let _ = textproto::count_values(h, f.key);
        if f.key.len <= 200 {
            // Each value an encoded-word header, and a media type when it says so.
            var o: u8[>..] = [];
            let _ = mime::decode_header(o, f.value);
        }
    }
    let _ = textproto::key_count(h);
    var msg: u8[>..] = [];
    textproto::error_message(msg, c1, d);
    // With small limits, and before the input has ended.
    var h2 = textproto::new_header();
    let c2, e2 = textproto::read_mime_header_at(s, 0, true, (lim as i64) * 16, (lim as i64) % 20, h2, d);
    if e2 > s.len { abort("mime_header: the header ends past the input (limits)"); }
    var h3 = textproto::new_header();
    let c3, e3 = textproto::read_mime_header_at(s, 0, false, textproto::MAX_INT64, textproto::MAX_INT64, h3, d);
    if e3 > s.len { abort("mime_header: the header ends past the input (not at eof)"); }
    let _ = textproto::canonical_mime_header_key(s);
}

fn encoded_words(s: const u8[:]) {
    var o: u8[>..] = [];
    let _ = mime::decode_word(o, s);
    o.clear();
    let rc = mime::decode_header(o, s);
    var m: u8[>..] = [];
    mime::header_error(m, s);
    m.clear();
    mime::word_error(m, s);
    o.clear();
    let _ = mime::decode_header_charset(o, s) { cs: const u8[:], content: const u8[:], out: u8[>..]& =>
        if cs == "x-upper" {
            for c in content { out.push(if c >= 'a' && c <= 'z' { c - 32 } else { c }); }
            mime::OK
        } else { mime::ERR_UNHANDLED_CHARSET }
    };
    for enc in [mime::B_ENCODING, mime::Q_ENCODING] {
        let e = mime::encode_word(enc, "UTF-8", s);
        if mime::needs_encoding(s) {
            var back: u8[>..] = [];
            let r = mime::decode_header(back, e);
            if r != 0 || back[..] != s { abort("mime_header: encode_word then decode_header differs"); }
        }
    }
}

fn media_type(s: const u8[:]) {
    let mt = mime::parse_media_type(s);
    if mt.err != 0 { let _ = mime::media_type_error(mt.err); return; }
    let _ = mime::param(mt, "charset");
    let _ = mime::param_count(mt);
    var f: u8[>..] = [];
    if mime::format_media_type(f, mt.typ, mt) {
        let back = mime::parse_media_type(f);
        if back.err != 0 || back.typ != mt.typ || back.params.len > mt.params.len {
            abort("mime_header: format_media_type does not parse back");
        }
        for p in mt.params {
            let v, ok = mime::param(back, p.name);
            if p.name.len > 0 && (!ok || v != p.value) { abort("mime_header: a parameter differs after format and parse"); }
        }
    }
}

fn qp(s: const u8[:], step0: i64) {
    var whole: u8[>..] = [];
    var wm:    u8[>..] = [];
    let _ = quotedprintable::decode_all(whole, s, wm);
    var r = quotedprintable::new_reader();
    var pieces: u8[>..] = [];
    var p = 0;
    var rc: i64 = 0;
    var step = step0;
    while p < s.len && rc == 0 {
        let m = if s.len - p < step { s.len - p } else { step };
        rc = quotedprintable::decode(r, pieces, s[p..p + m]);
        p += m;
        step = step % 9 + 1;
    }
    if rc == 0 { let _ = quotedprintable::finish(r, pieces); }
    var pm: u8[>..] = [];
    quotedprintable::error_message(r, pm);
    if pieces[..] != whole[..] || pm[..] != wm[..] { abort("mime_header: quoted-printable differs fed in pieces"); }
    for binary in [false, true] {
        var enc: u8[>..] = [];
        quotedprintable::encode_all(enc, s, binary);
        var back: u8[>..] = [];
        let r2 = quotedprintable::decode_all(back, enc);
        if binary && (r2 != 0 || back[..] != s) { abort("mime_header: quoted-printable round trip"); }
        var longest = 0;
        each_split(enc, '\n') { if it.len > longest { longest = it.len; } };
        if binary && longest > 77 { abort("mime_header: quoted-printable line too long"); }
    }
}

fn types(s: const u8[:]) {
    let _ = mime::type_by_extension(s);
    var e: u8[][>..] = [];
    let _ = mime::extensions_by_type(e, s);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let sel = data[0] % 5;
    let rest = data[1..];
    if sel == 0 { header(rest, data[0]); }
    else if sel == 1 { encoded_words(rest); }
    else if sel == 2 { media_type(rest); }
    else if sel == 3 { qp(rest, ((data[0] / 5) % 9) + 1); }
    else { types(rest); media_type(rest); }
    return 0;
}

fn main() {
    mime::types_reset(true);
}
