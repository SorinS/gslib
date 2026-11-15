// ntlm.messages: the NTLMSSP messages ([MS-NLMP] §2.2.1), written and
// read, and the AV_PAIR lists of target info (§2.2.2.1).
//
// Reading is strict and bounded: the signature and type, the fixed part
// whole, every field's offset and length inside the message and after the
// fixed part, payload fields that do not overlap, at most MAX_MESSAGE
// bytes. An AV_PAIR list must end in MsvAvEOL, hold no pair twice, and
// give MsvAvFlags, MsvAvTimestamp, MsvAvChannelBindings and
// MsvAvSingleHost their sizes. A read message's variable fields are
// Fields: offsets into the caller's bytes, nothing copied.

namespace ntlm;

import std;

// A payload field of a message: where it is in the message.
struct Field { off: i64, len: i64 }

fn no_field() -> Field { Field { off: 0, len: 0 } }

fn field_bytes(m: const u8[:], f: Field) -> const u8[:] { m[f.off..f.off + f.len] }

// The VERSION structure (§2.2.2.10) gslib sends: 10.0, build 0, NTLM
// revision 15.
let OUR_VERSION: u8[8] = [10, 0, 0, 0, 0, 0, 0, 15];

// --- AV_PAIRs --------------------------------------------------------------------------

let MAX_AV_PAIRS: i64 = 256;

// Whether `ti` is a list of AV_PAIRs ending in MsvAvEOL: ERR_AV_PAIRS if
// not. Bytes after the MsvAvEOL are not read (the NTLMv2 blob's Z(4)).
fn av_check(ti: const u8[:]) -> i64 {
    var p = 0;
    var seen: u32 = 0;
    var n = 0;
    while true {
        if p + 4 > ti.len { return ERR_AV_PAIRS; }
        let id = get16(ti, p);
        let l = get16(ti, p + 2) as i64;
        if p + 4 + l > ti.len { return ERR_AV_PAIRS; }
        if id == AV_EOL { return if l == 0 { OK } else { ERR_AV_PAIRS }; }
        n++;
        if n > MAX_AV_PAIRS { return ERR_AV_PAIRS; }
        if id <= AV_CHANNEL_BINDINGS {
            let bit: u32 = 1 << id;
            if seen & bit != 0 { return ERR_AV_PAIRS; }
            seen |= bit;
        }
        if id == AV_FLAGS && l != 4 { return ERR_AV_PAIRS; }
        if id == AV_TIMESTAMP && l != 8 { return ERR_AV_PAIRS; }
        if id == AV_CHANNEL_BINDINGS && l != 16 { return ERR_AV_PAIRS; }
        if id == AV_SINGLE_HOST && l < 48 { return ERR_AV_PAIRS; }
        let is_name = id == AV_NB_COMPUTER_NAME || id == AV_NB_DOMAIN_NAME || id == AV_DNS_COMPUTER_NAME ||
                      id == AV_DNS_DOMAIN_NAME || id == AV_DNS_TREE_NAME || id == AV_TARGET_NAME;
        if is_name && l % 2 != 0 { return ERR_AV_PAIRS; }
        p += 4 + l;
    }
    return ERR_AV_PAIRS;
}

// The value of pair `id` in a list av_check accepted; false if absent.
fn av_get(ti: const u8[:], id: u16) -> const u8[:], bool {
    var p = 0;
    while p + 4 <= ti.len {
        let i = get16(ti, p);
        let l = get16(ti, p + 2) as i64;
        if i == AV_EOL || p + 4 + l > ti.len { break; }
        if i == id { return ti[p + 4..p + 4 + l], true; }
        p += 4 + l;
    }
    return ti[..0], false;
}

fn av_put(out: u8[>..]&, id: u16, value: const u8[:]) {
    put16(out, id);
    put16(out, value.len as! u16);
    out.append(value);
}

// A name pair, its value UTF-8 text written as UTF-16LE; false if it is
// not UTF-8 or too long for a pair.
fn av_put_name(out: u8[>..]&, id: u16, name: const u8[:]) -> bool {
    var u: u8[>..] = [];
    if !utf16le(u, name) || u.len > 0xffff { return false; }
    av_put(out, id, u);
    return true;
}

fn av_end(out: u8[>..]&) { put32(out, 0); }

// Every pair of a checked list but MsvAvEOL and those of `drop` (a bit
// per id), copied.
fn av_copy_without(out: u8[>..]&, ti: const u8[:], drop: u32) {
    var p = 0;
    while p + 4 <= ti.len {
        let i = get16(ti, p);
        let l = get16(ti, p + 2) as i64;
        if i == AV_EOL || p + 4 + l > ti.len { break; }
        let skip = i <= 31 && (drop & ((1 as u32) << i)) != 0;
        if !skip { out.append(ti[p..p + 4 + l]); }
        p += 4 + l;
    }
}

// --- Fields ---------------------------------------------------------------------------------

fn put_field(out: u8[>..]&, at: i64, len: i64, off: i64) {
    // Written into the fixed part already laid out: len, maxlen, offset.
    out[at] = len as! u8;
    out[at + 1] = (len >> 8) as! u8;
    out[at + 2] = len as! u8;
    out[at + 3] = (len >> 8) as! u8;
    out[at + 4] = off as! u8;
    out[at + 5] = (off >> 8) as! u8;
    out[at + 6] = (off >> 16) as! u8;
    out[at + 7] = (off >> 24) as! u8;
}

// Appends a payload field and fills its descriptor at `at`.
fn add_payload(out: u8[>..]&, at: i64, data: const u8[:]) {
    put_field(out, at, data.len, out.len);
    out.append(data);
}

// The field descriptor at `at`; false if its bytes are not inside the
// message past `fixed`. An empty field is taken wherever it points.
fn read_field(m: const u8[:], at: i64, fixed: i64) -> Field, bool {
    let l = get16(m, at) as i64;
    let off = get32(m, at + 4) as i64;
    if l == 0 { return no_field(), true; }
    if off < fixed || off + l > m.len { return no_field(), false; }
    return Field { off: off, len: l }, true;
}

fn overlaps(a: Field, b: Field) -> bool {
    if a.len == 0 || b.len == 0 { return false; }
    return a.off < b.off + b.len && b.off < a.off + a.len;
}

fn header_ok(m: const u8[:], kind: u32, min: i64) -> i64 {
    if m.len > MAX_MESSAGE { return ERR_LIMIT; }
    if m.len < min || m[..8] != SIGNATURE || get32(m, 8) != kind { return ERR_MALFORMED; }
    return OK;
}

// Whether a token is a raw NTLMSSP message (not SPNEGO).
fn is_ntlmssp(token: const u8[:]) -> bool { token.len >= 12 && token[..8] == SIGNATURE }

// --- NEGOTIATE_MESSAGE (§2.2.1.1) --------------------------------------------------------------

// A NEGOTIATE message with no domain or workstation (they are sent in the
// AUTHENTICATE message), and VERSION when the flags have it.
fn negotiate_message(out: u8[>..]&, flags: u32) {
    let fixed = if flags & NEGOTIATE_VERSION != 0 { 40 } else { 32 };
    out.append(SIGNATURE);
    put32(out, MSG_NEGOTIATE);
    put32(out, flags & ~(NEGOTIATE_OEM_DOMAIN_SUPPLIED | NEGOTIATE_OEM_WORKSTATION_SUPPLIED));
    let at = out.len;
    for i in 16 { out.push(0); }
    put_field(out, at, 0, fixed);
    put_field(out, at + 8, 0, fixed);
    if fixed == 40 { out.append(OUR_VERSION); }
}

// A NEGOTIATE message's flags. Its domain and workstation (OEM text,
// informational) are checked to be inside it and not read.
fn parse_negotiate(m: const u8[:]) -> u32, i64 {
    let h = header_ok(m, MSG_NEGOTIATE, 16);
    if h != OK { return 0, h; }
    let flags = get32(m, 12);
    if m.len >= 32 {
        let d, dok = read_field(m, 16, 32);
        let w, wok = read_field(m, 24, 32);
        if !dok || !wok || overlaps(d, w) { return 0, ERR_MALFORMED; }
    }
    return flags, OK;
}

// --- CHALLENGE_MESSAGE (§2.2.1.2) ---------------------------------------------------------------

struct Challenge {
    flags:            u32,
    server_challenge: u8[8],
    has_version:      bool,
    version:          u8[8],
    target_name:      Field,     // UTF-16LE (or OEM without UNICODE)
    target_info:      Field,     // AV_PAIRs, checked
}

// A CHALLENGE message: the target name as UTF-16LE, the target info as
// AV_PAIRs (empty: none), VERSION when the flags have it.
fn challenge_message(out: u8[>..]&, flags: u32, server_challenge: const u8[:], target_name: const u8[:], target_info: const u8[:]) {
    out.append(SIGNATURE);
    put32(out, MSG_CHALLENGE);
    let tn = out.len;
    for i in 8 { out.push(0); }
    put32(out, flags);
    out.append(server_challenge[..8]);
    for i in 8 { out.push(0); }
    let ti = out.len;
    for i in 8 { out.push(0); }
    if flags & NEGOTIATE_VERSION != 0 { out.append(OUR_VERSION); }
    add_payload(out, tn, target_name);
    if target_info.len > 0 { add_payload(out, ti, target_info); } else { put_field(out, ti, 0, out.len); }
}

fn parse_challenge(m: const u8[:]) -> Challenge, i64 {
    var c = Challenge { flags: 0, server_challenge: [0; 8], has_version: false, version: [0; 8],
                        target_name: no_field(), target_info: no_field() };
    let h = header_ok(m, MSG_CHALLENGE, 48);
    if h != OK { return c, h; }
    c.flags = get32(m, 20);
    for i in 8 { c.server_challenge[i] = m[24 + i]; }
    let tn, tok = read_field(m, 12, 48);
    let ti, iok = read_field(m, 40, 48);
    if !tok || !iok || overlaps(tn, ti) { return c, ERR_MALFORMED; }
    var min = m.len;
    if tn.len > 0 { min = ::min(min, tn.off); }
    if ti.len > 0 { min = ::min(min, ti.off); }
    if c.flags & NEGOTIATE_VERSION != 0 && min >= 56 {
        c.has_version = true;
        for i in 8 { c.version[i] = m[48 + i]; }
    }
    c.target_name = tn;
    c.target_info = ti;
    if ti.len > 0 {
        let e = av_check(field_bytes(m, ti));
        if e != OK { return c, e; }
    }
    return c, OK;
}

// --- AUTHENTICATE_MESSAGE (§2.2.1.3) ---------------------------------------------------------

struct Authenticate {
    flags:       u32,
    lm:          Field,
    nt:          Field,
    domain:      Field,
    user:        Field,
    workstation: Field,
    key:         Field,          // EncryptedRandomSessionKey
    has_version: bool,
    version:     u8[8],
    has_mic:     bool,           // the MIC field is there, at 72..88
}

let MIC_OFFSET: i64 = 72;

// An AUTHENTICATE message; the names already UTF-16LE. With `mic` the
// fixed part has VERSION and a zero MIC field (filled by the caller at
// MIC_OFFSET); without, VERSION only when the flags have it. The
// payload goes in Windows' order: domain, user, workstation, LM, NT, key.
fn authenticate_message(out: u8[>..]&, flags: u32, lm: const u8[:], nt: const u8[:], domain: const u8[:], user: const u8[:],
                        workstation: const u8[:], key: const u8[:], mic: bool) {
    out.append(SIGNATURE);
    put32(out, MSG_AUTHENTICATE);
    let at = out.len;
    for i in 48 { out.push(0); }
    put32(out, flags);
    if mic || flags & NEGOTIATE_VERSION != 0 {
        if flags & NEGOTIATE_VERSION != 0 { out.append(OUR_VERSION); } else { for i in 8 { out.push(0); } }
    }
    if mic { for i in 16 { out.push(0); } }
    add_payload(out, at + 16, domain);
    add_payload(out, at + 24, user);
    add_payload(out, at + 32, workstation);
    add_payload(out, at, lm);
    add_payload(out, at + 8, nt);
    add_payload(out, at + 40, key);
}

fn parse_authenticate(m: const u8[:]) -> Authenticate, i64 {
    var a = Authenticate { flags: 0, lm: no_field(), nt: no_field(), domain: no_field(), user: no_field(), workstation: no_field(),
                           key: no_field(), has_version: false, version: [0; 8], has_mic: false };
    let h = header_ok(m, MSG_AUTHENTICATE, 64);
    if h != OK { return a, h; }
    var f: Field[6] = [no_field(); 6];
    for i in 6 {
        let x, ok = read_field(m, 12 + 8 * i, 64);
        if !ok { return a, ERR_MALFORMED; }
        f[i] = x;
    }
    for i in 6 { for j in i + 1..6 { if overlaps(f[i], f[j]) { return a, ERR_MALFORMED; } } }
    var min = m.len;
    for x in f { if x.len > 0 { min = ::min(min, x.off); } }
    a.lm = f[0];
    a.nt = f[1];
    a.domain = f[2];
    a.user = f[3];
    a.workstation = f[4];
    a.key = f[5];
    a.flags = get32(m, 60);
    if min >= 72 {
        a.has_version = true;
        for i in 8 { a.version[i] = m[64 + i]; }
    }
    a.has_mic = min >= 88;
    return a, OK;
}
