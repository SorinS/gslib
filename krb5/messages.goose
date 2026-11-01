// krb5.messages: the messages of RFC 4120 §5 as structs, each with a
// decoder and an encoder. Encoders write DER (§5.1.1); decoders read DER,
// and BER's long-form lengths too (§5.1.1 lets them), but no indefinite
// lengths. A decoded struct owns copies of its strings; a ticket inside
// another message stays in its DER, as clients pass tickets on unread.
//
// Names. A PrincipalName holds its components joined by '/', a '/', '@',
// '\' or control character inside a component escaped as MIT's
// krb5_unparse_name does ("\/", "\@", "\\", "\n", "\t", "\b", "\0"); the
// realm is kept apart, as the messages keep it. parse_principal reads
// "comp/comp@REALM".
//
// Optional fields have a has_ flag; an absent one's value is zero or
// empty. Flags (KDCOptions, TicketFlags, APOptions) are u32s, bit n as
// krb5::flag(n) gives it; fewer than 32 bits on the wire read as zeros
// (§5.2.8 lets a reader be lenient there). UInt32 fields (nonces, key
// versions, sequence numbers) also read negative INTEGERs, which MIT and
// Windows send for values of 2^31 and up; they are written as RFC 4120
// defines them, unsigned.
//
// Structs with strings are frozen once built (Goose's variable-size
// values): a decoder finds its fields first and builds the struct at once.

namespace krb5;

import std;
import encoding.asn1;
import krb5.crypto;

let GENERAL_STRING: u32 = 0x1b;

// --- Names ------------------------------------------------------------------

struct PrincipalName { name_type: i32, name: u8[] }

fn principal_name(name_type: i32, name: const u8[:]) -> PrincipalName { PrincipalName { name_type: name_type, name: name } }

fn no_principal() -> PrincipalName { PrincipalName { name_type: 0, name: "" } }

// Appends a component, escaped.
fn name_escape(out: u8[>..]&, s: const u8[:]) {
    for c in s {
        if c == '/' || c == '@' || c == '\\' { out.push('\\'); out.push(c); }
        else if c == '\n' { out.append("\\n"); }
        else if c == '\t' { out.append("\\t"); }
        else if c == 8 { out.append("\\b"); }
        else if c == 0 { out.append("\\0"); }
        else { out.push(c); }
    }
}

// The components of a name (escaped, joined by '/'), unescaped.
fn name_parts(name: const u8[:]) -> u8[][>..] {
    var parts: u8[][>..] = [];
    var cur: u8[>..] = [];
    var i = 0;
    while i < name.len {
        let c = name[i];
        if c == '\\' && i + 1 < name.len {
            let d = name[i + 1];
            cur.push(if d == 'n' { '\n' } else if d == 't' { '\t' } else if d == 'b' { 8 } else if d == '0' { 0 } else { d });
            i += 2;
            continue;
        }
        if c == '/' {
            parts.push(copy(cur));
            cur.clear();
        } else {
            cur.push(c);
        }
        i++;
    }
    parts.push(copy(cur));
    return parts;
}

fn name_count(name: const u8[:]) -> i64 {
    var n = 0;
    for p in name_parts(name) { n++; }
    return n;
}

// Component i (from 0), unescaped; empty past the end.
fn name_part(name: const u8[:], i: i64) -> u8[>..] {
    var k = 0;
    var out: u8[>..] = [];
    for p in name_parts(name) {
        if k == i { out.append(p); }
        k++;
    }
    return out;
}

// A two-component name, each escaped.
fn name_join(a: const u8[:], b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    name_escape(out, a);
    out.push('/');
    name_escape(out, b);
    return out;
}

// "name@REALM", the realm's '@' and '\' escaped.
fn principal_string(name: const u8[:], realm: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(name);
    out.push('@');
    for c in realm {
        if c == '@' || c == '\\' { out.push('\\'); }
        out.push(c);
    }
    return out;
}

// Splits "comp/comp@REALM" at its last unescaped '@': the name (still
// escaped) and the realm (unescaped), and whether there was a realm.
// False if the text ends in a lone '\' or has an empty name.
fn parse_principal(text: const u8[:]) -> u8[>..], u8[>..], bool, bool {
    var name: u8[>..] = [];
    var realm: u8[>..] = [];
    var at = -1;
    var i = 0;
    while i < text.len {
        if text[i] == '\\' {
            if i + 1 >= text.len { return name, realm, false, false; }
            i += 2;
            continue;
        }
        if text[i] == '@' { at = i; }
        i++;
    }
    if at < 0 {
        name.append(text);
        return name, realm, false, text.len > 0;
    }
    name.append(text[..at]);
    var j = at + 1;
    while j < text.len {
        if text[j] == '\\' && j + 1 < text.len { realm.push(text[j + 1]); j += 2; continue; }
        realm.push(text[j]);
        j++;
    }
    return name, realm, true, name.len > 0;
}

// --- Reading ------------------------------------------------------------------

fn no_tlv() -> asn1::Tlv { asn1::Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: 0, off: 0, end: 0 } }

// The fields of a SEQUENCE: [n] EXPLICIT elements in increasing order of
// n, each unwrapped. Numbers past 15 (none of RFC 4120's go that high) are
// skipped. `bad` collects every problem found while reading them.
struct Fields { bad: bool, mask: u32, t: asn1::Tlv[16] }

fn fields_at(buf: const u8[:], t: asn1::Tlv) -> Fields {
    var fs = Fields { bad: false, mask: 0, t: [no_tlv(); 16] };
    if t.tag != asn1::SEQUENCE { fs.bad = true; return fs; }
    let kids, ok = asn1::children(buf, t, true);
    if !ok { fs.bad = true; return fs; }
    var last: i64 = -1;
    for k in kids {
        if k.cls != asn1::CLASS_CONTEXT || !k.constructed || k.number <= last { fs.bad = true; return fs; }
        last = k.number;
        if k.number >= 16 { continue; }
        let inner, iok = asn1::explicit(buf, k, true);
        if !iok { fs.bad = true; return fs; }
        fs.t[k.number] = inner;
        fs.mask = fs.mask | (1 as u32) << k.number;
    }
    return fs;
}

// The fields of a message: [APPLICATION n] around a SEQUENCE. With
// `prefix`, the buffer may go on past it in zeros (the padding left after
// a decrypted DES3 part).
fn app_fields(buf: const u8[:], app_n: u32, prefix: bool) -> Fields {
    var fs = Fields { bad: true, mask: 0, t: [no_tlv(); 16] };
    let t, ok = asn1::read(buf, 0, buf.len, true);
    if !ok || t.tag != app(app_n) { return fs; }
    if t.end != buf.len {
        if !prefix { return fs; }
        for b in buf[t.end..] { if b != 0 { return fs; } }
    }
    let inner, ok2 = asn1::explicit(buf, t, true);
    if !ok2 { return fs; }
    return fields_at(buf, inner);
}

fn has(fs: const Fields&, n: i64) -> bool { fs.mask & (1 as u32) << (n as! u32) != 0 }

// Marks the fields bad unless every field in `mask` is there.
fn require(fs: Fields&, mask: u32) { if fs.mask & mask != mask { fs.bad = true; } }

fn result(fs: const Fields&) -> i64 { if fs.bad { ERR_MALFORMED } else { OK } }

fn int32_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> i64 {
    let v, ok = asn1::read_i64(buf, t, asn1::INTEGER, true);
    if !ok || v < -(1 << 31) || v >= 1 << 31 { bad = true; return 0; }
    return v;
}

fn uint32_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> u32 {
    let v, ok = asn1::read_i64(buf, t, asn1::INTEGER, true);
    if !ok || v < -(1 << 31) || v >= 1 << 32 { bad = true; return 0; }
    return (if v < 0 { v + (1 << 32) } else { v }) as! u32;
}

fn kstring_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> u8[>..] {
    var out: u8[>..] = [];
    if t.tag != GENERAL_STRING { bad = true; return out; }
    out.append(buf[t.off..t.end]);
    return out;
}

fn octets_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> u8[>..] {
    var out: u8[>..] = [];
    if t.tag != asn1::OCTET_STRING { bad = true; return out; }
    out.append(buf[t.off..t.end]);
    return out;
}

fn two(s: const u8[:], at: i64) -> i64 {
    let a = s[at];
    let b = s[at + 1];
    if a < '0' || a > '9' || b < '0' || b > '9' { return -1; }
    return (a - '0') * 10 + (b - '0');
}

// KerberosTime (§5.2.3): GeneralizedTime "YYYYMMDDHHMMSSZ", no fractions.
fn ktime_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> i64 {
    let s = buf[t.off..t.end];
    if t.tag != asn1::GENERALIZED_TIME || s.len != 15 || s[14] != 'Z' { bad = true; return 0; }
    let y1 = two(s, 0);
    let y2 = two(s, 2);
    let mo = two(s, 4);
    let d = two(s, 6);
    let h = two(s, 8);
    let mi = two(s, 10);
    let se = two(s, 12);
    if y1 < 0 || y2 < 0 || mo < 1 || mo > 12 || d < 1 || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60 {
        bad = true;
        return 0;
    }
    let y = y1 * 100 + y2;
    if d > asn1::days_in_month(y, mo) { bad = true; return 0; }
    return asn1::days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
}

// KerberosFlags (§5.2.8): the first 32 bits, missing ones zero.
fn flags_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> u32 {
    let s = buf[t.off..t.end];
    if t.tag != asn1::BIT_STRING || s.len < 1 || s[0] > 7 || (s.len == 1 && s[0] != 0) { bad = true; return 0; }
    var v: u32 = 0;
    for i in 4 {
        let b: u32 = if i + 1 < s.len { s[i + 1] } else { 0 };
        v = v | b << ((24 - 8 * i) as! u32);
    }
    return v;
}

fn principal_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> PrincipalName {
    var fs = fields_at(buf, t);
    require(fs, 3);
    var name: u8[>..] = [];
    let nt = if has(fs, 0) { int32_at(buf, fs.t[0], fs.bad) } else { 0 };
    if has(fs, 1) {
        let s = fs.t[1];
        if s.tag != asn1::SEQUENCE { fs.bad = true; }
        else {
            let kids, ok = asn1::children(buf, s, true);
            if !ok { fs.bad = true; }
            var first = true;
            for k in kids {
                let comp = kstring_at(buf, k, fs.bad);
                if !first { name.push('/'); }
                name_escape(name, comp);
                first = false;
            }
        }
    }
    if fs.bad { bad = true; }
    return PrincipalName { name_type: nt as! i32, name: name };
}

// Field n of fs, read by type; zero or empty when absent.
fn f_int32(buf: const u8[:], fs: Fields&, n: i64) -> i64 { if has(fs, n) { int32_at(buf, fs.t[n], fs.bad) } else { 0 } }
fn f_uint32(buf: const u8[:], fs: Fields&, n: i64) -> u32 { if has(fs, n) { uint32_at(buf, fs.t[n], fs.bad) } else { 0 } }
fn f_ktime(buf: const u8[:], fs: Fields&, n: i64) -> i64 { if has(fs, n) { ktime_at(buf, fs.t[n], fs.bad) } else { 0 } }
fn f_flags(buf: const u8[:], fs: Fields&, n: i64) -> u32 { if has(fs, n) { flags_at(buf, fs.t[n], fs.bad) } else { 0 } }

fn f_kstring(buf: const u8[:], fs: Fields&, n: i64) -> u8[>..] {
    if has(fs, n) { return kstring_at(buf, fs.t[n], fs.bad); }
    var e: u8[>..] = [];
    return e;
}

fn f_octets(buf: const u8[:], fs: Fields&, n: i64) -> u8[>..] {
    if has(fs, n) { return octets_at(buf, fs.t[n], fs.bad); }
    var e: u8[>..] = [];
    return e;
}

fn f_principal(buf: const u8[:], fs: Fields&, n: i64) -> PrincipalName {
    if has(fs, n) { return principal_at(buf, fs.t[n], fs.bad); }
    return no_principal();
}

// The DER of field n (a ticket, say), which must have the tag.
fn f_raw(buf: const u8[:], fs: Fields&, n: i64, tag: u32) -> u8[>..] {
    var out: u8[>..] = [];
    if has(fs, n) {
        let t = fs.t[n];
        if t.tag != tag { fs.bad = true; }
        out.append(buf[t.start..t.end]);
    }
    return out;
}

// The elements of a SEQUENCE OF.
fn seq_items(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> asn1::Tlv[>..] {
    if t.tag != asn1::SEQUENCE { bad = true; var e: asn1::Tlv[>..] = []; return e; }
    let kids, ok = asn1::children(buf, t, true);
    if !ok { bad = true; }
    return kids;
}

fn pvno(buf: const u8[:], fs: Fields&, n: i64) { if f_int32(buf, fs, n) != 5 { fs.bad = true; } }

fn msg_type_is(buf: const u8[:], fs: Fields&, n: i64, want: i64) { if f_int32(buf, fs, n) != want { fs.bad = true; } }

// --- Writing ----------------------------------------------------------------

// [n] EXPLICIT around DER already made.
fn put_field(out: u8[>..]&, n: u32, der: const u8[:]) { asn1::put(out, asn1::ctx(n, true), der); }

fn put_int_f(out: u8[>..]&, n: u32, v: i64) {
    var t: u8[>..] = [];
    asn1::put_i64(t, v);
    put_field(out, n, t);
}

fn put_kstring_f(out: u8[>..]&, n: u32, s: const u8[:]) {
    var t: u8[>..] = [];
    asn1::put(t, GENERAL_STRING, s);
    put_field(out, n, t);
}

fn put_octets_f(out: u8[>..]&, n: u32, b: const u8[:]) {
    var t: u8[>..] = [];
    asn1::put_octets(t, b);
    put_field(out, n, t);
}

fn put_ktime(out: u8[>..]&, unix: i64) {
    let days = if unix >= 0 { unix / 86400 } else { (unix - 86399) / 86400 };
    let secs = unix - days * 86400;
    let y, m, d = asn1::civil_from_days(days);
    var s: u8[>..] = [];
    format_int(s, y, 10, 4, '0');
    format_int(s, m, 10, 2, '0');
    format_int(s, d, 10, 2, '0');
    format_int(s, secs / 3600, 10, 2, '0');
    format_int(s, secs / 60 % 60, 10, 2, '0');
    format_int(s, secs % 60, 10, 2, '0');
    s.push('Z');
    asn1::put(out, asn1::GENERALIZED_TIME, s);
}

fn put_ktime_f(out: u8[>..]&, n: u32, unix: i64) {
    var t: u8[>..] = [];
    put_ktime(t, unix);
    put_field(out, n, t);
}

// KerberosFlags: always 32 bits (§5.2.8).
fn put_flags_f(out: u8[>..]&, n: u32, v: u32) {
    let b: u8[4] = [(v >> 24) as! u8, (v >> 16) as! u8, (v >> 8) as! u8, v as! u8];
    var t: u8[>..] = [];
    asn1::put_bits(t, b);
    put_field(out, n, t);
}

fn put_seq(out: u8[>..]&, content: const u8[:]) { asn1::put(out, asn1::SEQUENCE, content); }

fn put_principal(out: u8[>..]&, p: const PrincipalName&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, p.name_type);
    var comps: u8[>..] = [];
    for part in name_parts(p.name) { asn1::put(comps, GENERAL_STRING, part); }
    var t: u8[>..] = [];
    put_seq(t, comps);
    put_field(s, 1, t);
    put_seq(out, s);
}

fn put_principal_f(out: u8[>..]&, n: u32, p: const PrincipalName&) {
    var t: u8[>..] = [];
    put_principal(t, p);
    put_field(out, n, t);
}

fn put_app(out: u8[>..]&, app_n: u32, seq_content: const u8[:]) {
    var t: u8[>..] = [];
    put_seq(t, seq_content);
    asn1::put(out, app(app_n), t);
}

// --- Small types (§5.2) -----------------------------------------------------

struct EncryptedData { etype: i32, has_kvno: bool, kvno: u32, cipher: u8[] }
struct Checksum { ctype: i32, sum: u8[] }
struct HostAddress { addr_type: i32, address: u8[] }
struct AuthData { ad_type: i32, data: u8[] }
struct PaData { pa_type: i32, value: u8[] }
struct LastReq { lr_type: i32, value: i64 }

fn no_enc_data() -> EncryptedData { EncryptedData { etype: 0, has_kvno: false, kvno: 0, cipher: "" } }
fn no_checksum() -> Checksum { Checksum { ctype: 0, sum: "" } }
fn no_address() -> HostAddress { HostAddress { addr_type: 0, address: "" } }
fn no_key() -> Key { Key { etype: 0, value: [] } }

fn enc_data_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> EncryptedData {
    var fs = fields_at(buf, t);
    require(fs, 5);
    let d = EncryptedData {
        etype: f_int32(buf, fs, 0) as! i32, has_kvno: has(fs, 1), kvno: f_uint32(buf, fs, 1), cipher: f_octets(buf, fs, 2),
    };
    if fs.bad { bad = true; }
    return d;
}

fn f_enc_data(buf: const u8[:], fs: Fields&, n: i64) -> EncryptedData {
    if has(fs, n) { return enc_data_at(buf, fs.t[n], fs.bad); }
    return no_enc_data();
}

fn put_enc_data(out: u8[>..]&, d: const EncryptedData&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, d.etype);
    if d.has_kvno { put_int_f(s, 1, d.kvno); }
    put_octets_f(s, 2, d.cipher);
    put_seq(out, s);
}

fn put_enc_data_f(out: u8[>..]&, n: u32, d: const EncryptedData&) {
    var t: u8[>..] = [];
    put_enc_data(t, d);
    put_field(out, n, t);
}

fn key_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> Key {
    var fs = fields_at(buf, t);
    require(fs, 3);
    var k = Key { etype: f_int32(buf, fs, 0) as! i32, value: [] };
    let v = f_octets(buf, fs, 1);
    if v.len > 32 { fs.bad = true; } else { k.value.append(v); }
    if fs.bad { bad = true; }
    return k;
}

fn f_key(buf: const u8[:], fs: Fields&, n: i64) -> Key { if has(fs, n) { key_at(buf, fs.t[n], fs.bad) } else { no_key() } }

fn put_key(out: u8[>..]&, k: Key) {
    var s: u8[>..] = [];
    put_int_f(s, 0, k.etype);
    put_octets_f(s, 1, k.value);
    put_seq(out, s);
}

fn put_key_f(out: u8[>..]&, n: u32, k: Key) {
    var t: u8[>..] = [];
    put_key(t, k);
    put_field(out, n, t);
}

fn checksum_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> Checksum {
    var fs = fields_at(buf, t);
    require(fs, 3);
    let c = Checksum { ctype: f_int32(buf, fs, 0) as! i32, sum: f_octets(buf, fs, 1) };
    if fs.bad { bad = true; }
    return c;
}

fn f_checksum(buf: const u8[:], fs: Fields&, n: i64) -> Checksum {
    if has(fs, n) { return checksum_at(buf, fs.t[n], fs.bad); }
    return no_checksum();
}

fn put_checksum_f(out: u8[>..]&, n: u32, k: const Checksum&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, k.ctype);
    put_octets_f(s, 1, k.sum);
    var t: u8[>..] = [];
    put_seq(t, s);
    put_field(out, n, t);
}

fn host_address_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> HostAddress {
    var fs = fields_at(buf, t);
    require(fs, 3);
    let a = HostAddress { addr_type: f_int32(buf, fs, 0) as! i32, address: f_octets(buf, fs, 1) };
    if fs.bad { bad = true; }
    return a;
}

fn f_host_address(buf: const u8[:], fs: Fields&, n: i64) -> HostAddress {
    if has(fs, n) { return host_address_at(buf, fs.t[n], fs.bad); }
    return no_address();
}

// A SEQUENCE OF { [a] Int32, [a+1] OCTET STRING }: HostAddresses and
// AuthorizationData (0, 1), and PA-DATA (1, 2).
fn pair_at(buf: const u8[:], t: asn1::Tlv, first: i64, bad: bool&) -> i64, u8[>..] {
    var fs = fields_at(buf, t);
    require(fs, (3 as u32) << (first as! u32));
    let ty = f_int32(buf, fs, first);
    let v = f_octets(buf, fs, first + 1);
    if fs.bad { bad = true; }
    return ty, v;
}

fn addresses_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> HostAddress[>..] {
    var out: HostAddress[>..] = [];
    for k in seq_items(buf, t, bad) {
        let ty, v = pair_at(buf, k, 0, bad);
        out.push(HostAddress { addr_type: ty as! i32, address: copy(v) });
    }
    return out;
}

fn authdata_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> AuthData[>..] {
    var out: AuthData[>..] = [];
    for k in seq_items(buf, t, bad) {
        let ty, v = pair_at(buf, k, 0, bad);
        out.push(AuthData { ad_type: ty as! i32, data: copy(v) });
    }
    return out;
}

fn padata_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> PaData[>..] {
    var out: PaData[>..] = [];
    for k in seq_items(buf, t, bad) {
        let ty, v = pair_at(buf, k, 1, bad);
        out.push(PaData { pa_type: ty as! i32, value: copy(v) });
    }
    return out;
}

fn f_addresses(buf: const u8[:], fs: Fields&, n: i64) -> HostAddress[>..] {
    if has(fs, n) { return addresses_at(buf, fs.t[n], fs.bad); }
    var e: HostAddress[>..] = [];
    return e;
}

fn f_authdata(buf: const u8[:], fs: Fields&, n: i64) -> AuthData[>..] {
    if has(fs, n) { return authdata_at(buf, fs.t[n], fs.bad); }
    var e: AuthData[>..] = [];
    return e;
}

fn f_padata(buf: const u8[:], fs: Fields&, n: i64) -> PaData[>..] {
    if has(fs, n) { return padata_at(buf, fs.t[n], fs.bad); }
    var e: PaData[>..] = [];
    return e;
}

// A SEQUENCE OF Ticket, each kept as its DER.
fn f_tickets(buf: const u8[:], fs: Fields&, n: i64) -> u8[][>..] {
    var out: u8[][>..] = [];
    if !has(fs, n) { return out; }
    for k in seq_items(buf, fs.t[n], fs.bad) {
        if k.tag != app(APP_TICKET) { fs.bad = true; }
        out.push(buf[k.start..k.end]);
    }
    return out;
}

fn put_pair(out: u8[>..]&, first: u32, ty: i64, v: const u8[:]) {
    var s: u8[>..] = [];
    put_int_f(s, first, ty);
    put_octets_f(s, first + 1, v);
    put_seq(out, s);
}

fn put_host_address_f(out: u8[>..]&, n: u32, a: const HostAddress&) {
    var t: u8[>..] = [];
    put_pair(t, 0, a.addr_type, a.address);
    put_field(out, n, t);
}

fn put_addresses_f(out: u8[>..]&, n: u32, a: const HostAddress[:]) {
    var s: u8[>..] = [];
    for x in a { put_pair(s, 0, x.addr_type, x.address); }
    var t: u8[>..] = [];
    put_seq(t, s);
    put_field(out, n, t);
}

fn put_authdata(out: u8[>..]&, a: const AuthData[:]) {
    var s: u8[>..] = [];
    for x in a { put_pair(s, 0, x.ad_type, x.data); }
    put_seq(out, s);
}

fn put_authdata_f(out: u8[>..]&, n: u32, a: const AuthData[:]) {
    var t: u8[>..] = [];
    put_authdata(t, a);
    put_field(out, n, t);
}

fn put_padata(out: u8[>..]&, a: const PaData[:]) {
    var s: u8[>..] = [];
    for x in a { put_pair(s, 1, x.pa_type, x.value); }
    put_seq(out, s);
}

fn put_padata_f(out: u8[>..]&, n: u32, a: const PaData[:]) {
    var t: u8[>..] = [];
    put_padata(t, a);
    put_field(out, n, t);
}

fn put_tickets_f(out: u8[>..]&, n: u32, tickets: const u8[][:]) {
    var ts: u8[>..] = [];
    for t in tickets { ts.append(t); }
    var tt: u8[>..] = [];
    put_seq(tt, ts);
    put_field(out, n, tt);
}

// --- Ticket (§5.3) ----------------------------------------------------------

struct Ticket { realm: u8[], sname: PrincipalName, enc_part: EncryptedData }

fn decode_ticket(buf: const u8[:]) -> Ticket, i64 {
    var fs = app_fields(buf, APP_TICKET, false);
    require(fs, 0xf);
    pvno(buf, fs, 0);
    let t = Ticket { realm: f_kstring(buf, fs, 1), sname: f_principal(buf, fs, 2), enc_part: f_enc_data(buf, fs, 3) };
    let err = result(fs);
    return t, err;
}

fn encode_ticket(out: u8[>..]&, t: const Ticket&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_kstring_f(s, 1, t.realm);
    put_principal_f(s, 2, t.sname);
    put_enc_data_f(s, 3, t.enc_part);
    put_app(out, APP_TICKET, s);
}

struct EncTicketPart {
    flags: u32,
    key: Key,
    crealm: u8[],
    cname: PrincipalName,
    tr_type: i32,
    transited: u8[],
    authtime: i64,
    has_starttime: bool,
    starttime: i64,
    endtime: i64,
    has_renew_till: bool,
    renew_till: i64,
    has_caddr: bool,
    caddr: HostAddress[],
    has_authz: bool,
    authz: AuthData[],
}

fn decode_enc_ticket_part(buf: const u8[:]) -> EncTicketPart, i64 {
    var fs = app_fields(buf, APP_ENC_TICKET_PART, true);
    require(fs, 0xbf);
    var tr = fields_at(buf, if has(fs, 4) { fs.t[4] } else { no_tlv() });
    require(tr, 3);
    let p = EncTicketPart {
        flags: f_flags(buf, fs, 0), key: f_key(buf, fs, 1), crealm: f_kstring(buf, fs, 2), cname: f_principal(buf, fs, 3),
        tr_type: f_int32(buf, tr, 0) as! i32, transited: f_octets(buf, tr, 1),
        authtime: f_ktime(buf, fs, 5), has_starttime: has(fs, 6), starttime: f_ktime(buf, fs, 6), endtime: f_ktime(buf, fs, 7),
        has_renew_till: has(fs, 8), renew_till: f_ktime(buf, fs, 8), has_caddr: has(fs, 9), caddr: f_addresses(buf, fs, 9),
        has_authz: has(fs, 10), authz: f_authdata(buf, fs, 10),
    };
    if tr.bad { fs.bad = true; }
    let err = result(fs);
    return p, err;
}

fn encode_enc_ticket_part(out: u8[>..]&, t: const EncTicketPart&) {
    var s: u8[>..] = [];
    put_flags_f(s, 0, t.flags);
    put_key_f(s, 1, t.key);
    put_kstring_f(s, 2, t.crealm);
    put_principal_f(s, 3, t.cname);
    var tr: u8[>..] = [];
    put_int_f(tr, 0, t.tr_type);
    put_octets_f(tr, 1, t.transited);
    var trs: u8[>..] = [];
    put_seq(trs, tr);
    put_field(s, 4, trs);
    put_ktime_f(s, 5, t.authtime);
    if t.has_starttime { put_ktime_f(s, 6, t.starttime); }
    put_ktime_f(s, 7, t.endtime);
    if t.has_renew_till { put_ktime_f(s, 8, t.renew_till); }
    if t.has_caddr { put_addresses_f(s, 9, t.caddr); }
    if t.has_authz { put_authdata_f(s, 10, t.authz); }
    put_app(out, APP_ENC_TICKET_PART, s);
}

// --- KDC-REQ (§5.4.1) -------------------------------------------------------

struct KdcReqBody {
    kdc_options: u32,
    has_cname: bool,
    cname: PrincipalName,
    realm: u8[],
    has_sname: bool,
    sname: PrincipalName,
    has_from: bool,
    from: i64,
    till: i64,
    has_rtime: bool,
    rtime: i64,
    nonce: u32,
    etypes: i32[],
    has_addresses: bool,
    addresses: HostAddress[],
    has_enc_authz: bool,
    enc_authz: EncryptedData,
    has_tickets: bool,
    tickets: u8[][],       // each a Ticket's DER
}

struct KdcReq { msg_type: i64, has_padata: bool, padata: PaData[], body: KdcReqBody }

fn f_etypes(buf: const u8[:], fs: Fields&, n: i64) -> i32[>..] {
    var out: i32[>..] = [];
    if !has(fs, n) { return out; }
    for k in seq_items(buf, fs.t[n], fs.bad) { out.push(int32_at(buf, k, fs.bad) as! i32); }
    return out;
}

fn req_body_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> KdcReqBody {
    var fs = fields_at(buf, t);
    require(fs, 0x1a5);
    let b = KdcReqBody {
        kdc_options: f_flags(buf, fs, 0), has_cname: has(fs, 1), cname: f_principal(buf, fs, 1), realm: f_kstring(buf, fs, 2),
        has_sname: has(fs, 3), sname: f_principal(buf, fs, 3), has_from: has(fs, 4), from: f_ktime(buf, fs, 4),
        till: f_ktime(buf, fs, 5), has_rtime: has(fs, 6), rtime: f_ktime(buf, fs, 6), nonce: f_uint32(buf, fs, 7),
        etypes: f_etypes(buf, fs, 8), has_addresses: has(fs, 9), addresses: f_addresses(buf, fs, 9),
        has_enc_authz: has(fs, 10), enc_authz: f_enc_data(buf, fs, 10), has_tickets: has(fs, 11), tickets: f_tickets(buf, fs, 11),
    };
    if fs.bad { bad = true; }
    return b;
}

fn decode_req_body(buf: const u8[:]) -> KdcReqBody, i64 {
    let t, ok = asn1::parse(buf, true);
    var bad = !ok;
    let b = req_body_at(buf, if ok { t } else { no_tlv() }, bad);
    return b, if bad { ERR_MALFORMED } else { OK };
}

fn encode_req_body(out: u8[>..]&, b: const KdcReqBody&) {
    var s: u8[>..] = [];
    put_flags_f(s, 0, b.kdc_options);
    if b.has_cname { put_principal_f(s, 1, b.cname); }
    put_kstring_f(s, 2, b.realm);
    if b.has_sname { put_principal_f(s, 3, b.sname); }
    if b.has_from { put_ktime_f(s, 4, b.from); }
    put_ktime_f(s, 5, b.till);
    if b.has_rtime { put_ktime_f(s, 6, b.rtime); }
    put_int_f(s, 7, b.nonce);
    var es: u8[>..] = [];
    for e in b.etypes { asn1::put_i64(es, e); }
    var et: u8[>..] = [];
    put_seq(et, es);
    put_field(s, 8, et);
    if b.has_addresses { put_addresses_f(s, 9, b.addresses); }
    if b.has_enc_authz { put_enc_data_f(s, 10, b.enc_authz); }
    if b.has_tickets { put_tickets_f(s, 11, b.tickets); }
    put_seq(out, s);
}

// An AS-REQ (msg_type 10) or TGS-REQ (12).
fn decode_kdc_req(buf: const u8[:]) -> KdcReq, i64 {
    let is_as = message_type(buf) == MSG_AS_REQ;
    var fs = app_fields(buf, if is_as { APP_AS_REQ } else { APP_TGS_REQ }, false);
    require(fs, 0x16);
    pvno(buf, fs, 1);
    msg_type_is(buf, fs, 2, if is_as { MSG_AS_REQ } else { MSG_TGS_REQ });
    var bad = false;
    let r = KdcReq {
        msg_type: f_int32(buf, fs, 2), has_padata: has(fs, 3), padata: f_padata(buf, fs, 3),
        body: req_body_at(buf, fs.t[4], bad),
    };
    if bad { fs.bad = true; }
    let err = result(fs);
    return r, err;
}

fn encode_kdc_req(out: u8[>..]&, r: const KdcReq&) {
    var s: u8[>..] = [];
    put_int_f(s, 1, 5);
    put_int_f(s, 2, r.msg_type);
    if r.has_padata { put_padata_f(s, 3, r.padata); }
    var b: u8[>..] = [];
    encode_req_body(b, r.body);
    put_field(s, 4, b);
    put_app(out, if r.msg_type == MSG_AS_REQ { APP_AS_REQ } else { APP_TGS_REQ }, s);
}

// --- KDC-REP (§5.4.2) -------------------------------------------------------

struct KdcRep {
    msg_type: i64,
    has_padata: bool,
    padata: PaData[],
    crealm: u8[],
    cname: PrincipalName,
    ticket: u8[],          // the Ticket's DER
    enc_part: EncryptedData,
}

fn decode_kdc_rep(buf: const u8[:]) -> KdcRep, i64 {
    let is_as = message_type(buf) == MSG_AS_REP;
    var fs = app_fields(buf, if is_as { APP_AS_REP } else { APP_TGS_REP }, false);
    require(fs, 0x7b);
    pvno(buf, fs, 0);
    msg_type_is(buf, fs, 1, if is_as { MSG_AS_REP } else { MSG_TGS_REP });
    let r = KdcRep {
        msg_type: f_int32(buf, fs, 1), has_padata: has(fs, 2), padata: f_padata(buf, fs, 2), crealm: f_kstring(buf, fs, 3),
        cname: f_principal(buf, fs, 4), ticket: f_raw(buf, fs, 5, app(APP_TICKET)), enc_part: f_enc_data(buf, fs, 6),
    };
    let err = result(fs);
    return r, err;
}

fn encode_kdc_rep(out: u8[>..]&, r: const KdcRep&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_int_f(s, 1, r.msg_type);
    if r.has_padata { put_padata_f(s, 2, r.padata); }
    put_kstring_f(s, 3, r.crealm);
    put_principal_f(s, 4, r.cname);
    put_field(s, 5, r.ticket);
    put_enc_data_f(s, 6, r.enc_part);
    put_app(out, if r.msg_type == MSG_AS_REP { APP_AS_REP } else { APP_TGS_REP }, s);
}

struct EncKdcRepPart {
    tag: u32,              // APP_ENC_AS_REP_PART or APP_ENC_TGS_REP_PART, as received
    key: Key,
    last_req: LastReq[],
    nonce: u32,
    has_key_expiration: bool,
    key_expiration: i64,
    flags: u32,
    authtime: i64,
    has_starttime: bool,
    starttime: i64,
    endtime: i64,
    has_renew_till: bool,
    renew_till: i64,
    srealm: u8[],
    sname: PrincipalName,
    has_caddr: bool,
    caddr: HostAddress[],
    has_enc_padata: bool,
    enc_padata: PaData[],
}

fn f_last_req(buf: const u8[:], fs: Fields&, n: i64) -> LastReq[>..] {
    var out: LastReq[>..] = [];
    if !has(fs, n) { return out; }
    for k in seq_items(buf, fs.t[n], fs.bad) {
        var e = fields_at(buf, k);
        require(e, 3);
        out.push(LastReq { lr_type: f_int32(buf, e, 0) as! i32, value: f_ktime(buf, e, 1) });
        if e.bad { fs.bad = true; }
    }
    return out;
}

// The decrypted part of an AS-REP or TGS-REP. Either tag is taken for
// either reply: some KDCs send EncTGSRepPart in an AS-REP (§5.4.2), and
// the caller knows which reply it decrypted.
fn decode_enc_kdc_rep_part(buf: const u8[:]) -> EncKdcRepPart, i64 {
    let tag: u32 = if message_type(buf) == APP_ENC_AS_REP_PART { APP_ENC_AS_REP_PART } else { APP_ENC_TGS_REP_PART };
    var fs = app_fields(buf, tag, true);
    require(fs, 0x6b7);
    let p = EncKdcRepPart {
        tag: tag, key: f_key(buf, fs, 0), last_req: f_last_req(buf, fs, 1), nonce: f_uint32(buf, fs, 2),
        has_key_expiration: has(fs, 3), key_expiration: f_ktime(buf, fs, 3), flags: f_flags(buf, fs, 4),
        authtime: f_ktime(buf, fs, 5), has_starttime: has(fs, 6), starttime: f_ktime(buf, fs, 6), endtime: f_ktime(buf, fs, 7),
        has_renew_till: has(fs, 8), renew_till: f_ktime(buf, fs, 8), srealm: f_kstring(buf, fs, 9), sname: f_principal(buf, fs, 10),
        has_caddr: has(fs, 11), caddr: f_addresses(buf, fs, 11), has_enc_padata: has(fs, 12), enc_padata: f_padata(buf, fs, 12),
    };
    let err = result(fs);
    return p, err;
}

fn encode_enc_kdc_rep_part(out: u8[>..]&, p: const EncKdcRepPart&) {
    var s: u8[>..] = [];
    put_key_f(s, 0, p.key);
    var lr: u8[>..] = [];
    for x in p.last_req {
        var e: u8[>..] = [];
        put_int_f(e, 0, x.lr_type);
        put_ktime_f(e, 1, x.value);
        put_seq(lr, e);
    }
    var lrs: u8[>..] = [];
    put_seq(lrs, lr);
    put_field(s, 1, lrs);
    put_int_f(s, 2, p.nonce);
    if p.has_key_expiration { put_ktime_f(s, 3, p.key_expiration); }
    put_flags_f(s, 4, p.flags);
    put_ktime_f(s, 5, p.authtime);
    if p.has_starttime { put_ktime_f(s, 6, p.starttime); }
    put_ktime_f(s, 7, p.endtime);
    if p.has_renew_till { put_ktime_f(s, 8, p.renew_till); }
    put_kstring_f(s, 9, p.srealm);
    put_principal_f(s, 10, p.sname);
    if p.has_caddr { put_addresses_f(s, 11, p.caddr); }
    if p.has_enc_padata { put_padata_f(s, 12, p.enc_padata); }
    put_app(out, p.tag, s);
}

// --- AP-REQ, Authenticator, AP-REP (§5.5) ---------------------------------------

struct ApReq { ap_options: u32, ticket: u8[], authenticator: EncryptedData }

fn decode_ap_req(buf: const u8[:]) -> ApReq, i64 {
    var fs = app_fields(buf, APP_AP_REQ, false);
    require(fs, 0x1f);
    pvno(buf, fs, 0);
    msg_type_is(buf, fs, 1, MSG_AP_REQ);
    let r = ApReq { ap_options: f_flags(buf, fs, 2), ticket: f_raw(buf, fs, 3, app(APP_TICKET)), authenticator: f_enc_data(buf, fs, 4) };
    let err = result(fs);
    return r, err;
}

fn encode_ap_req(out: u8[>..]&, r: const ApReq&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_int_f(s, 1, MSG_AP_REQ);
    put_flags_f(s, 2, r.ap_options);
    put_field(s, 3, r.ticket);
    put_enc_data_f(s, 4, r.authenticator);
    put_app(out, APP_AP_REQ, s);
}

struct Authenticator {
    crealm: u8[],
    cname: PrincipalName,
    has_cksum: bool,
    cksum: Checksum,
    cusec: i64,
    ctime: i64,
    has_subkey: bool,
    subkey: Key,
    has_seq_number: bool,
    seq_number: u32,
    has_authz: bool,
    authz: AuthData[],
}

fn f_usec(buf: const u8[:], fs: Fields&, n: i64) -> i64 {
    let v = f_int32(buf, fs, n);
    if v < 0 || v > 999999 { fs.bad = true; }
    return v;
}

fn decode_authenticator(buf: const u8[:]) -> Authenticator, i64 {
    var fs = app_fields(buf, APP_AUTHENTICATOR, true);
    require(fs, 0x37);
    pvno(buf, fs, 0);
    let a = Authenticator {
        crealm: f_kstring(buf, fs, 1), cname: f_principal(buf, fs, 2), has_cksum: has(fs, 3), cksum: f_checksum(buf, fs, 3),
        cusec: f_usec(buf, fs, 4), ctime: f_ktime(buf, fs, 5), has_subkey: has(fs, 6), subkey: f_key(buf, fs, 6),
        has_seq_number: has(fs, 7), seq_number: f_uint32(buf, fs, 7), has_authz: has(fs, 8), authz: f_authdata(buf, fs, 8),
    };
    let err = result(fs);
    return a, err;
}

fn encode_authenticator(out: u8[>..]&, a: const Authenticator&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_kstring_f(s, 1, a.crealm);
    put_principal_f(s, 2, a.cname);
    if a.has_cksum { put_checksum_f(s, 3, a.cksum); }
    put_int_f(s, 4, a.cusec);
    put_ktime_f(s, 5, a.ctime);
    if a.has_subkey { put_key_f(s, 6, a.subkey); }
    if a.has_seq_number { put_int_f(s, 7, a.seq_number); }
    if a.has_authz { put_authdata_f(s, 8, a.authz); }
    put_app(out, APP_AUTHENTICATOR, s);
}

struct ApRep { enc_part: EncryptedData }

fn decode_ap_rep(buf: const u8[:]) -> ApRep, i64 {
    var fs = app_fields(buf, APP_AP_REP, false);
    require(fs, 0x7);
    pvno(buf, fs, 0);
    msg_type_is(buf, fs, 1, MSG_AP_REP);
    let r = ApRep { enc_part: f_enc_data(buf, fs, 2) };
    let err = result(fs);
    return r, err;
}

fn encode_ap_rep(out: u8[>..]&, r: const ApRep&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_int_f(s, 1, MSG_AP_REP);
    put_enc_data_f(s, 2, r.enc_part);
    put_app(out, APP_AP_REP, s);
}

struct EncApRepPart { ctime: i64, cusec: i64, has_subkey: bool, subkey: Key, has_seq_number: bool, seq_number: u32 }

fn decode_enc_ap_rep_part(buf: const u8[:]) -> EncApRepPart, i64 {
    var fs = app_fields(buf, APP_ENC_AP_REP_PART, true);
    require(fs, 0x3);
    let p = EncApRepPart {
        ctime: f_ktime(buf, fs, 0), cusec: f_usec(buf, fs, 1), has_subkey: has(fs, 2), subkey: f_key(buf, fs, 2),
        has_seq_number: has(fs, 3), seq_number: f_uint32(buf, fs, 3),
    };
    return p, result(fs);
}

fn encode_enc_ap_rep_part(out: u8[>..]&, p: EncApRepPart) {
    var s: u8[>..] = [];
    put_ktime_f(s, 0, p.ctime);
    put_int_f(s, 1, p.cusec);
    if p.has_subkey { put_key_f(s, 2, p.subkey); }
    if p.has_seq_number { put_int_f(s, 3, p.seq_number); }
    put_app(out, APP_ENC_AP_REP_PART, s);
}

// --- KRB-SAFE, KRB-PRIV, KRB-CRED (§5.6 to §5.8) ----------------------------------

// KRB-SAFE-BODY; EncKrbPrivPart has the same fields.
struct KrbSafeBody {
    user_data: u8[],
    has_timestamp: bool,
    timestamp: i64,
    has_usec: bool,
    usec: i64,
    has_seq_number: bool,
    seq_number: u32,
    s_address: HostAddress,
    has_r_address: bool,
    r_address: HostAddress,
}

struct KrbSafe { body: KrbSafeBody, cksum: Checksum }

fn safe_body_of(buf: const u8[:], fs: Fields&) -> KrbSafeBody {
    require(fs, 0x11);
    return KrbSafeBody {
        user_data: f_octets(buf, fs, 0), has_timestamp: has(fs, 1), timestamp: f_ktime(buf, fs, 1),
        has_usec: has(fs, 2), usec: f_int32(buf, fs, 2), has_seq_number: has(fs, 3), seq_number: f_uint32(buf, fs, 3),
        s_address: f_host_address(buf, fs, 4), has_r_address: has(fs, 5), r_address: f_host_address(buf, fs, 5),
    };
}

fn put_safe_body(s: u8[>..]&, b: const KrbSafeBody&) {
    put_octets_f(s, 0, b.user_data);
    if b.has_timestamp { put_ktime_f(s, 1, b.timestamp); }
    if b.has_usec { put_int_f(s, 2, b.usec); }
    if b.has_seq_number { put_int_f(s, 3, b.seq_number); }
    put_host_address_f(s, 4, b.s_address);
    if b.has_r_address { put_host_address_f(s, 5, b.r_address); }
}

fn decode_krb_safe(buf: const u8[:]) -> KrbSafe, i64 {
    var fs = app_fields(buf, APP_KRB_SAFE, false);
    require(fs, 0xf);
    pvno(buf, fs, 0);
    msg_type_is(buf, fs, 1, MSG_KRB_SAFE);
    var bs = fields_at(buf, if has(fs, 2) { fs.t[2] } else { no_tlv() });
    let m = KrbSafe { body: safe_body_of(buf, bs), cksum: f_checksum(buf, fs, 3) };
    if bs.bad { fs.bad = true; }
    let err = result(fs);
    return m, err;
}

// The DER of a KRB-SAFE-BODY, which the checksum covers.
fn encode_krb_safe_body(out: u8[>..]&, b: const KrbSafeBody&) {
    var s: u8[>..] = [];
    put_safe_body(s, b);
    put_seq(out, s);
}

fn encode_krb_safe(out: u8[>..]&, m: const KrbSafe&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_int_f(s, 1, MSG_KRB_SAFE);
    var b: u8[>..] = [];
    encode_krb_safe_body(b, m.body);
    put_field(s, 2, b);
    put_checksum_f(s, 3, m.cksum);
    put_app(out, APP_KRB_SAFE, s);
}

struct KrbPriv { enc_part: EncryptedData }

fn decode_krb_priv(buf: const u8[:]) -> KrbPriv, i64 {
    var fs = app_fields(buf, APP_KRB_PRIV, false);
    require(fs, 0xb);
    pvno(buf, fs, 0);
    msg_type_is(buf, fs, 1, MSG_KRB_PRIV);
    let m = KrbPriv { enc_part: f_enc_data(buf, fs, 3) };
    let err = result(fs);
    return m, err;
}

fn encode_krb_priv(out: u8[>..]&, m: const KrbPriv&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_int_f(s, 1, MSG_KRB_PRIV);
    put_enc_data_f(s, 3, m.enc_part);
    put_app(out, APP_KRB_PRIV, s);
}

fn decode_enc_krb_priv_part(buf: const u8[:]) -> KrbSafeBody, i64 {
    var fs = app_fields(buf, APP_ENC_KRB_PRIV_PART, true);
    let b = safe_body_of(buf, fs);
    return b, result(fs);
}

fn encode_enc_krb_priv_part(out: u8[>..]&, b: const KrbSafeBody&) {
    var s: u8[>..] = [];
    put_safe_body(s, b);
    put_app(out, APP_ENC_KRB_PRIV_PART, s);
}

struct KrbCred { tickets: u8[][], enc_part: EncryptedData }

fn decode_krb_cred(buf: const u8[:]) -> KrbCred, i64 {
    var fs = app_fields(buf, APP_KRB_CRED, false);
    require(fs, 0xf);
    pvno(buf, fs, 0);
    msg_type_is(buf, fs, 1, MSG_KRB_CRED);
    let m = KrbCred { tickets: f_tickets(buf, fs, 2), enc_part: f_enc_data(buf, fs, 3) };
    let err = result(fs);
    return m, err;
}

fn encode_krb_cred(out: u8[>..]&, m: const KrbCred&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_int_f(s, 1, MSG_KRB_CRED);
    put_tickets_f(s, 2, m.tickets);
    put_enc_data_f(s, 3, m.enc_part);
    put_app(out, APP_KRB_CRED, s);
}

struct KrbCredInfo {
    key: Key,
    has_prealm: bool,
    prealm: u8[],
    has_pname: bool,
    pname: PrincipalName,
    has_flags: bool,
    flags: u32,
    has_authtime: bool,
    authtime: i64,
    has_starttime: bool,
    starttime: i64,
    has_endtime: bool,
    endtime: i64,
    has_renew_till: bool,
    renew_till: i64,
    has_srealm: bool,
    srealm: u8[],
    has_sname: bool,
    sname: PrincipalName,
    has_caddr: bool,
    caddr: HostAddress[],
}

struct EncKrbCredPart {
    ticket_info: KrbCredInfo[],
    has_nonce: bool,
    nonce: u32,
    has_timestamp: bool,
    timestamp: i64,
    has_usec: bool,
    usec: i64,
    has_s_address: bool,
    s_address: HostAddress,
    has_r_address: bool,
    r_address: HostAddress,
}

fn cred_info_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> KrbCredInfo {
    var fs = fields_at(buf, t);
    require(fs, 1);
    let i = KrbCredInfo {
        key: f_key(buf, fs, 0), has_prealm: has(fs, 1), prealm: f_kstring(buf, fs, 1), has_pname: has(fs, 2),
        pname: f_principal(buf, fs, 2), has_flags: has(fs, 3), flags: f_flags(buf, fs, 3), has_authtime: has(fs, 4),
        authtime: f_ktime(buf, fs, 4), has_starttime: has(fs, 5), starttime: f_ktime(buf, fs, 5), has_endtime: has(fs, 6),
        endtime: f_ktime(buf, fs, 6), has_renew_till: has(fs, 7), renew_till: f_ktime(buf, fs, 7), has_srealm: has(fs, 8),
        srealm: f_kstring(buf, fs, 8), has_sname: has(fs, 9), sname: f_principal(buf, fs, 9), has_caddr: has(fs, 10),
        caddr: f_addresses(buf, fs, 10),
    };
    if fs.bad { bad = true; }
    return i;
}

fn put_cred_info(out: u8[>..]&, i: const KrbCredInfo&) {
    var s: u8[>..] = [];
    put_key_f(s, 0, i.key);
    if i.has_prealm { put_kstring_f(s, 1, i.prealm); }
    if i.has_pname { put_principal_f(s, 2, i.pname); }
    if i.has_flags { put_flags_f(s, 3, i.flags); }
    if i.has_authtime { put_ktime_f(s, 4, i.authtime); }
    if i.has_starttime { put_ktime_f(s, 5, i.starttime); }
    if i.has_endtime { put_ktime_f(s, 6, i.endtime); }
    if i.has_renew_till { put_ktime_f(s, 7, i.renew_till); }
    if i.has_srealm { put_kstring_f(s, 8, i.srealm); }
    if i.has_sname { put_principal_f(s, 9, i.sname); }
    if i.has_caddr { put_addresses_f(s, 10, i.caddr); }
    put_seq(out, s);
}

fn f_cred_infos(buf: const u8[:], fs: Fields&, n: i64) -> KrbCredInfo[>..] {
    var out: KrbCredInfo[>..] = [];
    if !has(fs, n) { return out; }
    for k in seq_items(buf, fs.t[n], fs.bad) { out.push(cred_info_at(buf, k, fs.bad)); }
    return out;
}

fn decode_enc_krb_cred_part(buf: const u8[:]) -> EncKrbCredPart, i64 {
    var fs = app_fields(buf, APP_ENC_KRB_CRED_PART, true);
    require(fs, 1);
    let p = EncKrbCredPart {
        ticket_info: f_cred_infos(buf, fs, 0), has_nonce: has(fs, 1), nonce: f_uint32(buf, fs, 1),
        has_timestamp: has(fs, 2), timestamp: f_ktime(buf, fs, 2), has_usec: has(fs, 3), usec: f_int32(buf, fs, 3),
        has_s_address: has(fs, 4), s_address: f_host_address(buf, fs, 4), has_r_address: has(fs, 5),
        r_address: f_host_address(buf, fs, 5),
    };
    let err = result(fs);
    return p, err;
}

fn encode_enc_krb_cred_part(out: u8[>..]&, p: const EncKrbCredPart&) {
    var s: u8[>..] = [];
    var is: u8[>..] = [];
    for i in p.ticket_info { put_cred_info(is, i); }
    var it: u8[>..] = [];
    put_seq(it, is);
    put_field(s, 0, it);
    if p.has_nonce { put_int_f(s, 1, p.nonce); }
    if p.has_timestamp { put_ktime_f(s, 2, p.timestamp); }
    if p.has_usec { put_int_f(s, 3, p.usec); }
    if p.has_s_address { put_host_address_f(s, 4, p.s_address); }
    if p.has_r_address { put_host_address_f(s, 5, p.r_address); }
    put_app(out, APP_ENC_KRB_CRED_PART, s);
}

// --- KRB-ERROR (§5.9.1) -------------------------------------------------------

struct KrbError {
    has_ctime: bool,
    ctime: i64,
    has_cusec: bool,
    cusec: i64,
    stime: i64,
    susec: i64,
    error_code: i64,
    has_crealm: bool,
    crealm: u8[],
    has_cname: bool,
    cname: PrincipalName,
    realm: u8[],
    sname: PrincipalName,
    has_etext: bool,
    etext: u8[],
    has_edata: bool,
    edata: u8[],
}

fn decode_krb_error(buf: const u8[:]) -> KrbError, i64 {
    var fs = app_fields(buf, APP_KRB_ERROR, false);
    require(fs, 0x673);
    pvno(buf, fs, 0);
    msg_type_is(buf, fs, 1, MSG_KRB_ERROR);
    let e = KrbError {
        has_ctime: has(fs, 2), ctime: f_ktime(buf, fs, 2), has_cusec: has(fs, 3), cusec: f_int32(buf, fs, 3),
        stime: f_ktime(buf, fs, 4), susec: f_int32(buf, fs, 5), error_code: f_int32(buf, fs, 6),
        has_crealm: has(fs, 7), crealm: f_kstring(buf, fs, 7), has_cname: has(fs, 8), cname: f_principal(buf, fs, 8),
        realm: f_kstring(buf, fs, 9), sname: f_principal(buf, fs, 10), has_etext: has(fs, 11), etext: f_kstring(buf, fs, 11),
        has_edata: has(fs, 12), edata: f_octets(buf, fs, 12),
    };
    let err = result(fs);
    return e, err;
}

fn encode_krb_error(out: u8[>..]&, e: const KrbError&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, 5);
    put_int_f(s, 1, MSG_KRB_ERROR);
    if e.has_ctime { put_ktime_f(s, 2, e.ctime); }
    if e.has_cusec { put_int_f(s, 3, e.cusec); }
    put_ktime_f(s, 4, e.stime);
    put_int_f(s, 5, e.susec);
    put_int_f(s, 6, e.error_code);
    if e.has_crealm { put_kstring_f(s, 7, e.crealm); }
    if e.has_cname { put_principal_f(s, 8, e.cname); }
    put_kstring_f(s, 9, e.realm);
    put_principal_f(s, 10, e.sname);
    if e.has_etext { put_kstring_f(s, 11, e.etext); }
    if e.has_edata { put_octets_f(s, 12, e.edata); }
    put_app(out, APP_KRB_ERROR, s);
}

// The APPLICATION tag number of a message (its type for the protocol's
// messages), or 0.
fn message_type(buf: const u8[:]) -> i64 {
    let t, ok = asn1::read(buf, 0, buf.len, true);
    if !ok || t.cls != asn1::CLASS_APPLICATION { return 0; }
    return t.number;
}

// --- Pre-authentication data (§5.2.7) ---------------------------------------------

// PA-ENC-TS-ENC: the client's time, encrypted for PA-ENC-TIMESTAMP.
fn encode_pa_enc_ts(out: u8[>..]&, unix: i64, has_usec: bool, usec: i64) {
    var s: u8[>..] = [];
    put_ktime_f(s, 0, unix);
    if has_usec { put_int_f(s, 1, usec); }
    put_seq(out, s);
}

// The time, whether there are microseconds and how many, and the error.
fn decode_pa_enc_ts(buf: const u8[:]) -> i64, bool, i64, i64 {
    let t, ok = asn1::read(buf, 0, buf.len, true);
    var fs = fields_at(buf, if ok { t } else { no_tlv() });
    require(fs, 1);
    let ts = f_ktime(buf, fs, 0);
    let us = f_usec(buf, fs, 1);
    return ts, has(fs, 1), us, result(fs);
}

struct EtypeInfo2 { etype: i32, has_salt: bool, salt: u8[], has_s2kparams: bool, s2kparams: u8[] }

// ETYPE-INFO2 (19), or the older ETYPE-INFO (11) when `old`, whose salt is
// an OCTET STRING and which has no s2kparams.
fn decode_etype_info(buf: const u8[:], old: bool) -> EtypeInfo2[>..], i64 {
    var out: EtypeInfo2[>..] = [];
    let t, pok = asn1::parse(buf, true);
    var bad = !pok;
    if !pok { return out, ERR_MALFORMED; }
    for k in seq_items(buf, t, bad) {
        var fs = fields_at(buf, k);
        require(fs, 1);
        out.push(EtypeInfo2 {
            etype: f_int32(buf, fs, 0) as! i32, has_salt: has(fs, 1),
            salt: if old { f_octets(buf, fs, 1) } else { f_kstring(buf, fs, 1) },
            has_s2kparams: !old && has(fs, 2), s2kparams: if old { f_octets(buf, fs, 15) } else { f_octets(buf, fs, 2) },
        });
        if fs.bad { bad = true; }
    }
    return out, if bad { ERR_MALFORMED } else { OK };
}

fn encode_etype_info(out: u8[>..]&, infos: const EtypeInfo2[:], old: bool) {
    var s: u8[>..] = [];
    for i in infos {
        var e: u8[>..] = [];
        put_int_f(e, 0, i.etype);
        if i.has_salt { if old { put_octets_f(e, 1, i.salt); } else { put_kstring_f(e, 1, i.salt); } }
        if !old && i.has_s2kparams { put_octets_f(e, 2, i.s2kparams); }
        put_seq(s, e);
    }
    put_seq(out, s);
}

// KERB-PA-PAC-REQUEST (MS-KILE §2.2.3): { include-pac [0] BOOLEAN }.
fn encode_pa_pac_request(out: u8[>..]&, include: bool) {
    var b: u8[>..] = [];
    asn1::put_bool(b, include);
    var s: u8[>..] = [];
    put_field(s, 0, b);
    put_seq(out, s);
}

// A SEQUENCE OF PA-DATA: METHOD-DATA, a KRB-ERROR's e-data when
// pre-authentication is required, or a message's padata.
fn decode_padata(buf: const u8[:]) -> PaData[>..], i64 {
    let t, ok = asn1::parse(buf, true);
    var bad = !ok;
    if !ok { var e: PaData[>..] = []; return e, ERR_MALFORMED; }
    let pa = padata_at(buf, t, bad);
    return pa, if bad { ERR_MALFORMED } else { OK };
}

fn encode_padata(out: u8[>..]&, pa: const PaData[:]) { put_padata(out, pa); }

// TYPED-DATA (§5.9.1): a SEQUENCE OF { data-type [0], data-value [1] OPTIONAL }.
struct TypedData { data_type: i32, has_value: bool, value: u8[] }

fn decode_typed_data(buf: const u8[:]) -> TypedData[>..], i64 {
    var out: TypedData[>..] = [];
    let t, pok = asn1::parse(buf, true);
    var bad = !pok;
    if !pok { return out, ERR_MALFORMED; }
    for k in seq_items(buf, t, bad) {
        var fs = fields_at(buf, k);
        require(fs, 1);
        out.push(TypedData { data_type: f_int32(buf, fs, 0) as! i32, has_value: has(fs, 1), value: f_octets(buf, fs, 1) });
        if fs.bad { bad = true; }
    }
    return out, if bad { ERR_MALFORMED } else { OK };
}

fn encode_typed_data(out: u8[>..]&, td: const TypedData[:]) {
    var s: u8[>..] = [];
    for x in td {
        var e: u8[>..] = [];
        put_int_f(e, 0, x.data_type);
        if x.has_value { put_octets_f(e, 1, x.value); }
        put_seq(s, e);
    }
    put_seq(out, s);
}

// AuthorizationData on its own (AD-IF-RELEVANT's content, for one).
fn decode_authdata(buf: const u8[:]) -> AuthData[>..], i64 {
    let t, ok = asn1::parse(buf, true);
    var bad = !ok;
    if !ok { var e: AuthData[>..] = []; return e, ERR_MALFORMED; }
    let a = authdata_at(buf, t, bad);
    return a, if bad { ERR_MALFORMED } else { OK };
}

fn encode_authdata(out: u8[>..]&, a: const AuthData[:]) { put_authdata(out, a); }

// EncryptedData, EncryptionKey and PrincipalName on their own.
fn decode_enc_data(buf: const u8[:]) -> EncryptedData, i64 {
    let t, ok = asn1::parse(buf, true);
    var bad = !ok;
    let d = enc_data_at(buf, if ok { t } else { no_tlv() }, bad);
    return d, if bad { ERR_MALFORMED } else { OK };
}

fn encode_enc_data(out: u8[>..]&, d: const EncryptedData&) { put_enc_data(out, d); }

fn decode_key(buf: const u8[:]) -> Key, i64 {
    let t, ok = asn1::parse(buf, true);
    var bad = !ok;
    let k = key_at(buf, if ok { t } else { no_tlv() }, bad);
    return k, if bad { ERR_MALFORMED } else { OK };
}

fn encode_key(out: u8[>..]&, k: Key) { put_key(out, k); }

fn decode_principal(buf: const u8[:]) -> PrincipalName, i64 {
    let t, ok = asn1::parse(buf, true);
    var bad = !ok;
    let p = principal_at(buf, if ok { t } else { no_tlv() }, bad);
    return p, if bad { ERR_MALFORMED } else { OK };
}

fn encode_principal(out: u8[>..]&, p: const PrincipalName&) { put_principal(out, p); }
