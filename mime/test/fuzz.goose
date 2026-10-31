// Robustness: random and mutated inputs through every parser, which must
// never abort (run under --debug too, so a bounds, overflow or narrowing
// error would abort), and the round trips that must hold for any input:
// FormatMediaType then ParseMediaType, the word encoder then the decoder,
// the quoted-printable writer (binary) then the reader, the multipart
// writer then the reader, and the same results whichever way a body is
// fed. Seeds are Go's own test inputs (test/vectors), mutated.
//
//     goose run fuzz.goose                 the suite's run
//     goose run fuzz.goose -- 50 7         50 times as many inputs, from seed 7

import std;
import gslib from "../..";
import gslib.mime;
import gslib.mime.encodedword;
import gslib.mime.quotedprintable;
import gslib.mime.textproto;
import gslib.mime.multipart;
import gslib.mime.formdata;
import gslib.mime.types;
import tv;

var seed: u64 = 0x2545F4914F6CDD1D;

fn rnd(n: i64) -> i64 {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    return (seed % (n as u64)) as i64;
}

let SPECIAL = "=?_;:\"\\/'*%-\r\n\t \x00\x80\xc3\xa9\xff";

// A mutation of s: bytes flipped, inserted, removed, duplicated; pieces
// from the special bytes the grammars care about.
fn mutate(out: u8[>..]&, s: const u8[:]) {
    out.append(s);
    let k = rnd(4) + 1;
    for i in k {
        let op = rnd(6);
        let at = if out.len == 0 { 0 } else { rnd(out.len + 1) };
        if op == 0 && at < out.len { out[at] = rnd(256) as u8; }
        else if op == 1 { out.push(SPECIAL[rnd(SPECIAL.len)]); }
        else if op == 2 && at < out.len { out[at] = SPECIAL[rnd(SPECIAL.len)]; }
        else if op == 3 && out.len > 0 { out.resize(rnd(out.len + 1)); }
        else if op == 4 && out.len > 0 && out.len < 4096 {
            let a = rnd(out.len);
            let b = a + rnd(out.len - a + 1);
            var piece: u8[>..] = [];
            piece.append(out[a..b]);
            out.append(piece);
        } else { out.push(rnd(256) as u8); }
    }
}

fn random_bytes(out: u8[>..]&, n: i64) {
    for i in n { if rnd(3) == 0 { out.push(SPECIAL[rnd(SPECIAL.len)]); } else { out.push((rnd(95) + 32) as u8); } }
}

struct SeedSpan { pos: i64, end: i64 }
var seed_text: u8[>..];
var seeds: SeedSpan[>..];

fn load_seeds(path: const u8[:]) {
    tv::each_row(path) { r: tv::Row& =>
        for i in r.count() {
            let f = r.field(i);
            if f.len > 0 && f.len < 20000 {
                let p = seed_text.len;
                seed_text.append(f);
                seeds.push(SeedSpan { pos: p, end: seed_text.len });
            }
        }
    };
}

fn input(out: u8[>..]&) {
    if rnd(4) == 0 { random_bytes(out, rnd(80)); return; }
    let sp = seeds[rnd(seeds.len)];
    mutate(out, seed_text[sp.pos..sp.end]);
}

fn media_types(n: i64) {
    for k in n {
        var s: u8[>..] = [];
        input(s);
        let mt = mime::parse_media_type(s);
        if mt.err == 0 {
            // what parses formats, and what formats parses back the same
            var f: u8[>..] = [];
            if mime::format_media_type(f, mt.typ, mt) {
                let back = mime::parse_media_type(f);
                tv::check(str("format round trip of ", s), back.err == 0 && back.typ == mt.typ && back.params.len <= mt.params.len);
                var same = true;
                for p in mt.params { let v, ok = mime::param(back, p.name); if p.name.len > 0 && (!ok || v != p.value) { same = false; } }
                tv::check(str("format round trip values of ", s), same);
            }
        }
    }
}

fn words(n: i64) {
    for k in n {
        var s: u8[>..] = [];
        input(s);
        var o: u8[>..] = [];
        mime::decode_word(o, s);
        o.clear();
        mime::decode_header(o, s);
        var m: u8[>..] = [];
        mime::header_error(m, s);
        for enc in [mime::B_ENCODING, mime::Q_ENCODING] {
            let e = mime::encode_word(enc, "UTF-8", s);
            if mime::needs_encoding(s) {
                var back: u8[>..] = [];
                let rc = mime::decode_header(back, e);
                tv::check(str("word round trip ", enc, " of ", s), rc == 0 && back == s);
                var longest = 0;
                each_split(e, ' ') { longest = max(longest, it.len); };
                tv::check(str("word length ", enc, " of ", s), longest <= 75);
            }
        }
    }
}

fn quoted_printable(n: i64) {
    for k in n {
        var s: u8[>..] = [];
        input(s);
        var whole: u8[>..] = [];
        var wm: u8[>..] = [];
        quotedprintable::decode_all(whole, s, wm);
        // fed in random pieces: the same
        var r = quotedprintable::new_reader();
        var pieces: u8[>..] = [];
        var p = 0;
        var rc = 0;
        while p < s.len && rc == 0 {
            let m = ::min(s.len - p, rnd(9) + 1);
            rc = quotedprintable::decode(r, pieces, s[p..p + m]);
            p += m;
        }
        if rc == 0 { quotedprintable::finish(r, pieces); }
        var pm: u8[>..] = [];
        quotedprintable::error_message(r, pm);
        tv::check(str("qp pieces of ", s), pieces == whole && pm == wm);
        // binary round trip
        var enc: u8[>..] = [];
        quotedprintable::encode_all(enc, s, true);
        var back: u8[>..] = [];
        tv::check(str("qp round trip of ", s), quotedprintable::decode_all(back, enc) == 0 && back == s);
        var longest = 0;
        each_split(enc, '\n') { longest = max(longest, it.len); };
        tv::check(str("qp lines of ", s), longest <= 77);
    }
}

fn headers(n: i64) {
    for k in n {
        var s: u8[>..] = [];
        input(s);
        var h = textproto::new_header();
        var d: u8[>..] = [];
        let c1, e1 = textproto::read_mime_header_at(s, 0, true, 2000 + rnd(2000), rnd(20), h, d);
        let c2, e2 = textproto::read_mime_header_at(s, 0, false, textproto::MAX_INT64, textproto::MAX_INT64, h, d);
        tv::check(str("header end within the input ", s), e1 <= s.len && e2 <= s.len);
    }
}

// Parses body fed in random pieces; the parts' text.
fn parse_text(body: const u8[:], boundary: const u8[:], whole: bool) -> u8[>..] {
    var r = multipart::Reader { .. };
    multipart::init(r, boundary);
    var out: u8[>..] = [];
    var data: u8[>..] = [];
    var fed = 0;
    loop {
        let ev = multipart::next(r, data);
        if ev == multipart::EV_NEED_MORE {
            if fed == body.len { multipart::finish(r); continue; }
            let m = if whole { body.len - fed } else { ::min(body.len - fed, rnd(13) + 1) };
            multipart::feed(r, body[fed..fed + m]);
            fed += m;
            continue;
        }
        if ev == multipart::EV_PART {
            data.clear();
            for f in r.header.fields { format(out, f.key, ":", f.value, ";"); }
            format(out, "[", multipart::form_name(r), "|", multipart::file_name(r), "]");
            continue;
        }
        if ev == multipart::EV_DATA { continue; }
        if ev == multipart::EV_PART_END { format(out, "{", data, "}", r.part_err, ";"); data.clear(); continue; }
        format(out, "end ", ev, " ", r.err);
        return out;
    }
}

fn multipart_bodies(n: i64) {
    for k in n {
        var s: u8[>..] = [];
        input(s);
        let boundary = if rnd(2) == 0 { "MyBoundary" } else { "b" };
        let a = parse_text(s, boundary, true);
        let b = parse_text(s, boundary, false);
        tv::check(str("multipart pieces of ", s), a == b);
        var f = multipart::Form { .. };
        multipart::read_form_bytes(f, s, boundary, rnd(64) - 8);
        multipart::remove_all(f);
    }
    // the writer's output reads back as written
    for k in n / 4 {
        var w = multipart::new_writer();
        var out: u8[>..] = [];
        var vtext: u8[>..] = [];
        var vspans: SeedSpan[>..] = [];
        let parts = rnd(4) + 1;
        for i in parts {
            var v: u8[>..] = [];
            input(v);
            multipart::create_form_field(w, out, str("f", i));
            out.append(v);
            let p = vtext.len;
            vtext.append(v);
            vspans.push(SeedSpan { pos: p, end: vtext.len });
        }
        multipart::close(w, out);
        var f = multipart::Form { .. };
        let rc = multipart::read_form_bytes(f, out, multipart::boundary(w), 1 << 20);
        var ok = rc == 0 && multipart::value_count(f) == parts;
        if ok { for i in parts { let name, v = multipart::value_at(f, i); if v != vtext[vspans[i].pos..vspans[i].end] { ok = false; } } }
        tv::check("writer round trip", ok);
    }
}

fn types(n: i64) {
    mime::types_reset(true);
    for k in n {
        var s: u8[>..] = [];
        input(s);
        mime::type_by_extension(s);
        var e: u8[][>..] = [];
        mime::extensions_by_type(e, s);
        var dotted: u8[>..] = [];
        dotted.push('.');
        dotted.append(s);
        if mime::add_extension_type(dotted, "text/x-fuzz") == 0 {
            tv::check_eq("added type", mime::type_by_extension(dotted), "text/x-fuzz; charset=utf-8");
        }
        multipart::base_name(s);
    }
}

fn main() {
    for name in ["parse_media_type", "bad_media_type", "decode_header", "decode_word", "qp_reader",
                 "multipart_parse", "read_mime_header", "header_malformed", "form_message", "truncated_bodies"] {
        load_seeds(str("vectors/go_", name, ".txt"));
    }
    let a = args();
    var times = 1;
    if a.len > 1 { let t, ok = parse_int(a[1]); if ok && t > 0 { times = t; } }
    if a.len > 2 { let s0, ok = parse_int(a[2]); if ok && s0 != 0 { seed = s0 as u64; } }
    media_types(4000 * times);
    words(2000 * times);
    quoted_printable(2000 * times);
    headers(2000 * times);
    multipart_bodies(1500 * times);
    types(1000 * times);
    tv::done("fuzz");
}
