// websocket.deflate: permessage-deflate (RFC 7692): the
// Sec-WebSocket-Extensions header (RFC 6455 §9.1), a client's offer and the
// check of the server's answer, a server's choice among a client's offers
// and its answer, and the parameters both then keep to.
//
// A message is compressed as raw DEFLATE ending in a sync flush, whose
// last four bytes (00 00 ff ff) are left off (§7.2.1); the reader puts
// them back (§7.2.2). Each side's window and whether it keeps its history
// from one message to the next are negotiated: compress.deflate keeps to a
// window as small as 2^8 (deflate_set_window_bits), and compress.flate's
// 32 KiB window reads whatever the peer sends.

namespace websocket;

import std;
import websocket;

// What was agreed for a connection. Bits are 8 to 15.
struct Pmd {
    on: bool,
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: i64,
    client_max_window_bits: i64,
}

fn no_pmd() -> Pmd {
    Pmd { on: false, server_no_context_takeover: false, client_no_context_takeover: false,
          server_max_window_bits: 15, client_max_window_bits: 15 }
}

// --- The extension header (RFC 6455 §9.1) ----------------------------------------
//
//   Sec-WebSocket-Extensions = extension-list
//   extension-list = 1#extension
//   extension = extension-token *( ";" extension-param )
//   extension-param = token [ "=" (token | quoted-string) ]
//
// A quoted value must itself be a token once unquoted. Several header
// lines are one list joined by commas.

struct ExtParam { name: u8[..64], value: u8[..64], has_value: bool }

struct Extension { name: u8[..64], params: ExtParam[..16] }

fn is_tchar(c: u8) -> bool {
    if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') { return true; }
    return c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
           c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

fn skip_ows(s: const u8[:], i: i64) -> i64 {
    var p = i;
    while p < s.len && (s[p] == ' ' || s[p] == '\t') { p++; }
    return p;
}

fn token_end(s: const u8[:], i: i64) -> i64 {
    var p = i;
    while p < s.len && is_tchar(s[p]) { p++; }
    return p;
}

// Parses a list (the header's lines joined by ", ") into exts; false when
// it is not the grammar's, or holds more than exts or a name can.
fn parse_extensions(s: const u8[:], exts: Extension[..16]&) -> bool {
    exts.clear();
    var i: i64 = 0;
    loop {
        i = skip_ows(s, i);
        if i >= s.len { return true; }
        if s[i] == ',' { i++; continue; }        // empty elements (RFC 9110 §5.6.1)
        let ne = token_end(s, i);
        if ne == i || ne - i > 64 || exts.len == exts.cap { return false; }
        var e = Extension { name: [], params: [] };
        e.name.append(s[i..ne]);
        i = skip_ows(s, ne);
        while i < s.len && s[i] == ';' {
            i = skip_ows(s, i + 1);
            let pe = token_end(s, i);
            if pe == i || pe - i > 64 || e.params.len == e.params.cap { return false; }
            var prm = ExtParam { name: [], value: [], has_value: false };
            prm.name.append(s[i..pe]);
            i = skip_ows(s, pe);
            if i < s.len && s[i] == '=' {
                i = skip_ows(s, i + 1);
                prm.has_value = true;
                if i < s.len && s[i] == '"' {
                    i++;
                    while i < s.len && s[i] != '"' {
                        var c = s[i];
                        if c == '\\' {
                            i++;
                            if i >= s.len { return false; }
                            c = s[i];
                        }
                        if !is_tchar(c) || prm.value.len == prm.value.cap { return false; }
                        prm.value.push(c);
                        i++;
                    }
                    if i >= s.len || prm.value.len == 0 { return false; }
                    i++;
                } else {
                    let ve = token_end(s, i);
                    if ve == i || ve - i > 64 { return false; }
                    prm.value.append(s[i..ve]);
                    i = ve;
                }
                i = skip_ows(s, i);
            }
            e.params.push(prm);
        }
        exts.push(e);
        if i >= s.len { return true; }
        if s[i] != ',' { return false; }
        i++;
    }
    return true;
}

fn eq_fold(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len {
        var x = a[i];
        var y = b[i];
        if x >= 'A' && x <= 'Z' { x += 32; }
        if y >= 'A' && y <= 'Z' { y += 32; }
        if x != y { return false; }
    }
    return true;
}

// A window size's value: 8 to 15 in decimal without leading zeros
// (RFC 7692 §7.1.2.1), or -1.
fn window_bits(v: const u8[:]) -> i64 {
    if v.len == 1 && v[0] >= '8' && v[0] <= '9' { return v[0] - '0'; }
    if v.len == 2 && v[0] == '1' && v[1] >= '0' && v[1] <= '5' { return 10 + (v[1] - '0') as i64; }
    return -1;
}

// --- The client's side ---------------------------------------------------------------

// What a client asks for. client_max_window_bits is offered without a
// value (the server may then name one) unless client_bits < 15.
struct PmdOffer {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: i64,      // 15: not asked
    client_max_window_bits: i64,      // 15: offered without a value
}

fn pmd_offer() -> PmdOffer {
    PmdOffer { server_no_context_takeover: false, client_no_context_takeover: false,
               server_max_window_bits: 15, client_max_window_bits: 15 }
}

fn put_decimal(out: u8[>..]&, v: i64) {
    if v >= 10 { out.push(('0' + v / 10) as! u8); }
    out.push(('0' + v % 10) as! u8);
}

// The offer as the header's value.
fn put_offer(out: u8[>..]&, o: const PmdOffer&) {
    out.append("permessage-deflate");
    if o.server_no_context_takeover { out.append("; server_no_context_takeover"); }
    if o.client_no_context_takeover { out.append("; client_no_context_takeover"); }
    if o.server_max_window_bits < 15 {
        out.append("; server_max_window_bits=");
        put_decimal(out, o.server_max_window_bits);
    }
    out.append("; client_max_window_bits");
    if o.client_max_window_bits < 15 {
        out.append("=");
        put_decimal(out, o.client_max_window_bits);
    }
}

// Checks a server's answer to the offer (its extension list): the
// parameters agreed (on false when it declined), or false when the answer
// must fail the connection: an extension not offered, permessage-deflate
// twice, a parameter not allowed or not offered, a bad value (§7.1).
fn check_answer(list: const u8[:], o: const PmdOffer&) -> Pmd, bool {
    var p = no_pmd();
    var exts: Extension[..16] = [];
    if !parse_extensions(list, exts) { return p, false; }
    for e in exts {
        if e.name[..] != "permessage-deflate" || p.on { return p, false; }
        p.on = true;
        var seen: u8 = 0;
        for prm in e.params {
            var bit: u8 = 0;
            if prm.name[..] == "server_no_context_takeover" {
                bit = 1;
                if prm.has_value { return p, false; }
                p.server_no_context_takeover = true;
            } else if prm.name[..] == "client_no_context_takeover" {
                bit = 2;
                if prm.has_value { return p, false; }
                p.client_no_context_takeover = true;
            } else if prm.name[..] == "server_max_window_bits" {
                bit = 4;
                let b = window_bits(prm.value);
                if !prm.has_value || b < 0 || b > o.server_max_window_bits { return p, false; }
                p.server_max_window_bits = b;
            } else if prm.name[..] == "client_max_window_bits" {
                bit = 8;
                let b = window_bits(prm.value);
                if !prm.has_value || b < 0 || b > o.client_max_window_bits { return p, false; }
                p.client_max_window_bits = b;
            } else {
                return p, false;
            }
            if (seen & bit) != 0 { return p, false; }
            seen |= bit;
        }
        // A server asked not to keep its history must say it will not.
        if o.server_no_context_takeover && !p.server_no_context_takeover { return p, false; }
        if o.server_max_window_bits < 15 && (seen & 4) == 0 { return p, false; }
    }
    if p.on && o.client_no_context_takeover { p.client_no_context_takeover = true; }
    if p.on && o.client_max_window_bits < p.client_max_window_bits { p.client_max_window_bits = o.client_max_window_bits; }
    return p, true;
}

// --- The server's side -----------------------------------------------------------------

// What a server is willing to do beyond what a client asks: keep no
// history itself, have the client keep none, and limit the client's
// window (when the client allows it to).
struct PmdPolicy {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    client_max_window_bits: i64,      // 15: no limit asked
}

fn pmd_policy() -> PmdPolicy {
    PmdPolicy { server_no_context_takeover: false, client_no_context_takeover: false, client_max_window_bits: 15 }
}

// Chooses the first permessage-deflate offer in a client's list it can
// take (§7.1: one with a parameter not defined, a bad value or a
// parameter twice is declined): the parameters, with on false when there
// is none, and false when the list is not the header's grammar.
fn choose_offer(list: const u8[:], pol: const PmdPolicy&) -> Pmd, bool {
    var exts: Extension[..16] = [];
    if !parse_extensions(list, exts) { return no_pmd(), false; }
    for e in exts {
        if !eq_fold(e.name, "permessage-deflate") { continue; }
        var p = no_pmd();
        var ok = true;
        var seen: u8 = 0;
        var client_bits_offered = false;
        for prm in e.params {
            var bit: u8 = 0;
            if prm.name[..] == "server_no_context_takeover" {
                bit = 1;
                if prm.has_value { ok = false; }
                p.server_no_context_takeover = true;
            } else if prm.name[..] == "client_no_context_takeover" {
                bit = 2;
                if prm.has_value { ok = false; }
                p.client_no_context_takeover = true;
            } else if prm.name[..] == "server_max_window_bits" {
                bit = 4;
                let b = window_bits(prm.value);
                if !prm.has_value || b < 0 { ok = false; }
                p.server_max_window_bits = b;
            } else if prm.name[..] == "client_max_window_bits" {
                bit = 8;
                client_bits_offered = true;
                if prm.has_value {
                    let b = window_bits(prm.value);
                    if b < 0 { ok = false; }
                    p.client_max_window_bits = b;
                }
            } else {
                ok = false;
            }
            if (seen & bit) != 0 { ok = false; }
            seen |= bit;
        }
        if !ok { continue; }
        p.on = true;
        if pol.server_no_context_takeover { p.server_no_context_takeover = true; }
        if pol.client_no_context_takeover { p.client_no_context_takeover = true; }
        if client_bits_offered && pol.client_max_window_bits < p.client_max_window_bits {
            p.client_max_window_bits = pol.client_max_window_bits;
        }
        return p, true;
    }
    return no_pmd(), true;
}

// The answer to the offer chosen, as the header's value: every parameter
// that binds either side (the client's window only when it is limited).
fn put_answer(out: u8[>..]&, p: const Pmd&) {
    out.append("permessage-deflate");
    if p.server_no_context_takeover { out.append("; server_no_context_takeover"); }
    if p.client_no_context_takeover { out.append("; client_no_context_takeover"); }
    if p.server_max_window_bits < 15 {
        out.append("; server_max_window_bits=");
        put_decimal(out, p.server_max_window_bits);
    }
    if p.client_max_window_bits < 15 {
        out.append("; client_max_window_bits=");
        put_decimal(out, p.client_max_window_bits);
    }
}
