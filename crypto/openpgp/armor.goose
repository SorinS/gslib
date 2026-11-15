// openpgp.armor: ASCII armor (RFC 9580 §6) and the cleartext signature
// framework's text (§7).
//
//   var text: u8[>..] = [];
//   openpgp::armor(text, openpgp::ARMOR_MESSAGE, binary);
//   var bin: u8[>..] = [];
//   let label, err = openpgp::dearmor(text, bin);   // label "PGP MESSAGE"
//
// Armor is written as gpg writes it: base64 in lines of 64, then the CRC24
// line, which RFC 9580 makes optional; reading takes it or its absence,
// but refuses one that does not match. Armor headers are skipped, except
// that the cleartext framework reads its "Hash:" lines. Line ends may be
// LF or CRLF, and trailing white space on any line is ignored.

namespace openpgp;

import std;
import base64;
import crypto.openpgp;

let ARMOR_MESSAGE:        const u8[:] = "PGP MESSAGE";
let ARMOR_SIGNATURE:      const u8[:] = "PGP SIGNATURE";
let ARMOR_PUBLIC_KEY:     const u8[:] = "PGP PUBLIC KEY BLOCK";
let ARMOR_PRIVATE_KEY:    const u8[:] = "PGP PRIVATE KEY BLOCK";
let ARMOR_SIGNED_MESSAGE: const u8[:] = "PGP SIGNED MESSAGE";

// CRC-24 (RFC 9580 §6.1.1).
fn crc24(data: const u8[:]) -> u32 {
    var crc: u32 = 0xB704CE;
    for b in data {
        crc ^= (b as u32) << 16;
        for i in 8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 { crc ^= 0x1864CFB; }
        }
    }
    return crc & 0xFFFFFF;
}

// data armored under `label`, appended to out with LF line ends. headers
// (each "Name: value" and LF) go between the BEGIN line and the blank line.
fn armor(out: u8[>..]&, label: const u8[:], data: const u8[:], headers: const u8[:] = "") {
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    out.append(headers);
    out.push('\n');
    var b64: u8[>..] = [];
    base64::encode(b64, data);
    var i = 0;
    while i < b64.len {
        let n = ::min(64, b64.len - i);
        out.append(b64[i..i + n]);
        out.push('\n');
        i += n;
    }
    let c = crc24(data);
    let cb: u8[3] = [(c >> 16 & 255) as! u8, (c >> 8 & 255) as! u8, (c & 255) as! u8];
    out.push('=');
    base64::encode(out, cb);
    out.append("\n-----END ");
    out.append(label);
    out.append("-----\n");
}

// The line at text[at..]: its end (CR, LF and trailing spaces and tabs not
// counted) and where the next line starts.
fn line_at(text: const u8[:], at: i64) -> i64, i64 {
    var e = at;
    while e < text.len && text[e] != '\n' { e++; }
    let next = if e < text.len { e + 1 } else { e };
    while e > at && (text[e - 1] == '\r' || text[e - 1] == ' ' || text[e - 1] == '\t') { e--; }
    return e, next;
}

// Where the first line "-----BEGIN <label>-----" starts at or after `from`
// (any label when label is ""), and its label; -1 if there is none.
fn find_begin(text: const u8[:], from: i64, label: const u8[:] = "") -> i64, u8[..64] {
    var at = from;
    var none: u8[..64] = [];
    while at < text.len {
        let e, next = line_at(text, at);
        let line = text[at..e];
        if starts_with(line, "-----BEGIN ") && ends_with(line, "-----") && line.len > 16 && line.len - 16 <= 64 {
            let l = line[11..line.len - 5];
            if label.len == 0 || l == label {
                var got: u8[..64] = [];
                got.append(l);
                return at, got;
            }
        }
        at = next;
    }
    return -1, none;
}

// Whether data looks armored: its first non-blank text is "-----BEGIN ".
fn is_armored(data: const u8[:]) -> bool {
    var i = 0;
    while i < data.len && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n') { i++; }
    return starts_with(data[i..], "-----BEGIN ");
}

// The armored block that starts at text[at] (its BEGIN line): its data
// appended to out, its label, the position after its END line, and an
// error. Headers are skipped; the "Hash:" values are appended to hashes
// (comma-separated as they appear) for the cleartext framework.
fn dearmor_at(text: const u8[:], at: i64, out: u8[>..]&, hashes: u8[>..]&) -> u8[..64], i64, i64 {
    var label: u8[..64] = [];
    let e0, n0 = line_at(text, at);
    let first = text[at..e0];
    if !starts_with(first, "-----BEGIN ") || !ends_with(first, "-----") || first.len <= 16 || first.len - 16 > 64 {
        return label, at, ERR_MALFORMED;
    }
    label.append(first[11..first.len - 5]);
    var p = n0;
    // Headers: "Name: value" lines up to a blank one. A line without a
    // colon there is the data already (some writers leave the blank out).
    loop {
        if p >= text.len { return label, p, ERR_MALFORMED; }
        let e, next = line_at(text, p);
        let line = text[p..e];
        if line.len == 0 { p = next; break; }
        let colon = find(line, ": ");
        if colon <= 0 { break; }
        if line[..colon] == "Hash" {
            if hashes.len > 0 { hashes.push(','); }
            hashes.append(line[colon + 2..]);
        }
        p = next;
    }
    var b64: u8[>..] = [];
    var crc: u8[>..] = [];
    var has_crc = false;
    var ended = false;
    while p < text.len {
        let e, next = line_at(text, p);
        var s = p;
        while s < e && (text[s] == ' ' || text[s] == '\t') { s++; }
        let line = text[s..e];
        p = next;
        if starts_with(line, "-----END ") {
            if !ends_with(line, "-----") || line.len < 14 || line[9..line.len - 5] != label[..] {
                return label, p, ERR_MALFORMED;
            }
            ended = true;
            break;
        }
        if has_crc {
            if line.len > 0 { return label, p, ERR_MALFORMED; }
            continue;
        }
        if line.len == 5 && line[0] == '=' {
            crc.clear();
            if !base64::decode(crc, line[1..]) || crc.len != 3 { return label, p, ERR_MALFORMED; }
            has_crc = true;
            continue;
        }
        b64.append(line);
    }
    if !ended { return label, p, ERR_MALFORMED; }
    let mark = out.len;
    if !base64::decode(out, b64) { out.resize(mark); return label, p, ERR_MALFORMED; }
    if has_crc {
        let c = crc24(out[mark..]);
        if (crc[0] as u32) << 16 | (crc[1] as u32) << 8 | crc[2] != c { out.resize(mark); return label, p, ERR_CHECKSUM; }
    }
    return label, p, OK;
}

// The first armored block of text: its data appended to out, and its label.
fn dearmor(text: const u8[:], out: u8[>..]&) -> u8[..64], i64 {
    let at, l = find_begin(text, 0);
    if at < 0 { return l, ERR_MALFORMED; }
    var hashes: u8[>..] = [];
    let label, next, err = dearmor_at(text, at, out, hashes);
    return label, err;
}

// Binary OpenPGP data from what may be armored (its first block) or
// binary already, appended to out.
fn decode_input(data: const u8[:], out: u8[>..]&) -> i64 {
    if is_armored(data) {
        let label, err = dearmor(data, out);
        return err;
    }
    out.append(data);
    return OK;
}

// --- Text -------------------------------------------------------------------

// Text with its line ends made CRLF (LF, CR LF or a lone CR), appended to
// out, as text-mode signatures hash it. With strip, trailing spaces and
// tabs of each line go too, as the cleartext framework hashes text.
fn canonical_text(out: u8[>..]&, text: const u8[:], strip: bool = false) {
    var i = 0;
    var start = out.len;
    while i < text.len {
        let c = text[i];
        if c == '\r' || c == '\n' {
            if strip {
                while out.len > start && (out[out.len - 1] == ' ' || out[out.len - 1] == '\t') { out.resize(out.len - 1); }
            }
            out.append("\r\n");
            if c == '\r' && i + 1 < text.len && text[i + 1] == '\n' { i++; }
            i++;
            start = out.len;
            continue;
        }
        out.push(c);
        i++;
    }
    if strip {
        while out.len > start && (out[out.len - 1] == ' ' || out[out.len - 1] == '\t') { out.resize(out.len - 1); }
    }
}

// A cleartext signed message (§7): the text as signed (canonical: CRLF
// between lines, trailing white space gone, no line end after the last),
// the hashes its Hash: headers name (none: any hash, as RFC 9580 has
// it), and the signature packets, dearmored.
root struct Cleartext {
    text:   u8[>..]  = [],           // canonical, as hashed
    sigs:   u8[>..]  = [],           // the signature packets
    hashes: i64[>..] = [],
}

fn parse_cleartext(data: const u8[:], ct: Cleartext&) -> i64 {
    let at, l = find_begin(data, 0, ARMOR_SIGNED_MESSAGE);
    if at < 0 { return ERR_MALFORMED; }
    let e0, n0 = line_at(data, at);
    var p = n0;
    // Hash: headers, then a blank line.
    loop {
        if p >= data.len { return ERR_MALFORMED; }
        let e, next = line_at(data, p);
        let line = data[p..e];
        p = next;
        if line.len == 0 { break; }
        if !starts_with(line, "Hash: ") { continue; }
        for name in split(line[6..], ',') {
            var a = 0;
            var b = name.len;
            while a < b && name[a] == ' ' { a++; }
            while b > a && name[b - 1] == ' ' { b--; }
            let h = hash_of_name(name[a..b]);
            if h == 0 { return ERR_UNSUPPORTED; }
            ct.hashes.push(h);
        }
    }
    // The text, up to the signature's BEGIN line.
    var first = true;
    loop {
        if p >= data.len { return ERR_MALFORMED; }
        let e, next = line_at(data, p);
        let line = data[p..e];
        if starts_with(line, "-----BEGIN PGP SIGNATURE-----") { break; }
        var body = line;
        if starts_with(line, "- ") { body = line[2..]; }
        if !first { ct.text.append("\r\n"); }
        ct.text.append(body);
        first = false;
        p = next;
    }
    var hashes: u8[>..] = [];
    let label, next, err = dearmor_at(data, p, ct.sigs, hashes);
    if err != OK { return err; }
    if label[..] != ARMOR_SIGNATURE { return ERR_MALFORMED; }
    return OK;
}

// The text of a cleartext message as it reads (dash escapes undone, LF
// line ends), appended to out: the canonical text with CRLF made LF.
fn cleartext_body(out: u8[>..]&, ct: const Cleartext&) {
    var i = 0;
    while i < ct.text.len {
        if ct.text[i] == '\r' && i + 1 < ct.text.len && ct.text[i + 1] == '\n' { out.push('\n'); i += 2; continue; }
        out.push(ct.text[i]);
        i++;
    }
    out.push('\n');
}

// What a cleartext signature hashes of text, as parse_cleartext reads the
// lines dash_escape writes: lines split at LF only, each without its
// trailing CR, spaces and tabs, joined by CRLF. A CR within a line is
// text, on both sides.
fn cleartext_hashed(out: u8[>..]&, text: const u8[:]) {
    var at = 0;
    loop {
        var nl = at;
        while nl < text.len && text[nl] != '\n' { nl++; }
        let e, next = line_at(text, at);
        out.append(text[at..e]);
        if nl >= text.len { break; }
        out.append("\r\n");
        at = next;
    }
}

// The dash-escaped text of a cleartext message (§7.2), lines LF-ended:
// each line that starts with '-' gets "- " before it, and so does one
// that starts "From " (as gpg escapes it, for mbox).
fn dash_escape(out: u8[>..]&, text: const u8[:]) {
    var at = 0;
    while at < text.len {
        var e = at;
        while e < text.len && text[e] != '\n' { e++; }
        var le = e;
        if le > at && text[le - 1] == '\r' { le--; }
        let line = text[at..le];
        if starts_with(line, "-") || starts_with(line, "From ") { out.append("- "); }
        out.append(line);
        out.push('\n');
        at = e + 1;
    }
}
