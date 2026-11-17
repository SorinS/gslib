// dns.msg: resource records and messages.
//
// A record is held as its uncompressed wire form: owner name, type, class,
// TTL, rdata length and rdata, its names uncompressed too. A list of
// records (a section, a zone, an RRset) is such records back to back in a
// u8[>..]; an Rr is where one of them is in its list, read with rr_at or
// each_rr, and its parts are read through the list:
//
//   dns::each_rr(m.answer) { rr =>
//       print(rr.name_text(m.answer), " ", rr.rtype, " ", rr.rdata(m.answer));
//   };
//
// A Msg is miekg's Msg: the header's fields, and the question and the
// three sections as such lists. pack writes the message (with name
// compression when compress is set), unpack reads one into a Msg.

namespace dns;

import std;
import os;
import dns;
import dns.rdata;
import dns.edns;
import entropy;

// --- Records -------------------------------------------------------------------

// Where a record is in its list: the owner name at off, the fixed fields,
// the rdata at rd..end.
struct Rr { off: i64, rtype: u16, class: u16, ttl: u32, rd: i64, end: i64 }

fn rr_at(list: const u8[:], off: i64) -> Rr {
    let nl = name_len_at(list, off);
    let p = off + nl;
    let rdlen = get16(list, p + 8) as i64;
    return Rr { off, get16(list, p), get16(list, p + 2), get32(list, p + 4), p + 10, p + 10 + rdlen };
}

fn each_rr<F>(list: const u8[:]) {
    var i = 0;
    while i < list.len {
        let rr = rr_at(list, i);
        F(rr);
        i = rr.end;
    }
}

fn rr_count(list: const u8[:]) -> i64 {
    var n = 0;
    each_rr(list) { rr => n++; };
    return n;
}

// The offset of the k-th record of the list, -1 if it has fewer.
fn rr_index(list: const u8[:], k: i64) -> i64 {
    var n = 0;
    each_rr(list) { rr => if n == k { return rr.off; } n++; };
    return -1;
}

fn name(rr: Rr, list: const u8[:]) -> const u8[:] { list[rr.off .. rr.rd - 10] }
fn rdata(rr: Rr, list: const u8[:]) -> const u8[:] { list[rr.rd .. rr.end] }
fn bytes(rr: Rr, list: const u8[:]) -> const u8[:] { list[rr.off .. rr.end] }
fn name_text(rr: Rr, list: const u8[:]) -> u8[>..] { dns::name_text(list[rr.off .. rr.rd - 10]) }

// Appends a record; ERR_NAME for a bad owner, ERR_BUF for rdata over 65535
// bytes. The rdata is not checked against its type: rr_valid does that.
fn rr_append(list: u8[>..]&, owner: const u8[:], t: u16, class: u16, ttl: u32, rd: const u8[:]) -> i64 {
    if !name_valid(owner) { return ERR_NAME; }
    if rd.len > 65535 { return ERR_BUF; }
    list.append(owner);
    put16(list, t);
    put16(list, class);
    put32(list, ttl);
    put16(list, rd.len as! u16);
    list.append(rd);
    return OK;
}

// Appends the record at rr in from.
fn rr_copy(list: u8[>..]&, from: const u8[:], rr: Rr) { list.append(from[rr.off .. rr.end]); }

fn rr_set_ttl(list: u8[:], rr: Rr, ttl: u32) {
    let p = rr.rd - 6;
    list[p] = (ttl >> 24) as! u8; list[p + 1] = (ttl >> 16) as! u8;
    list[p + 2] = (ttl >> 8) as! u8; list[p + 3] = ttl as! u8;
}

fn rr_set_class(list: u8[:], rr: Rr, class: u16) { set16(list, rr.rd - 8, class); }

// Whether every record of the list is well formed: names, lengths and
// each rdata against its type.
fn list_valid(list: const u8[:]) -> bool {
    var i = 0;
    while i < list.len {
        let nl = name_len_at(list, i);
        if nl < 0 || i + nl + 10 > list.len { return false; }
        let rr = rr_at(list, i);
        if rr.end > list.len { return false; }
        if rr.end == rr.rd && !rdata_empty_ok(rr.rtype, rr.class) { return false; }
        if rr.end > rr.rd && !rdata_valid(rr.rtype, rr.rdata(list)) { return false; }
        i = rr.end;
    }
    return true;
}

// The header part of a record's text, as miekg's RR_Header.String():
// "name<TAB>ttl<TAB>class<TAB>type<TAB>".
fn rr_header_append(out: u8[>..]&, list: const u8[:], rr: Rr) {
    let known = known_type(rr.rtype);
    if rr.rtype == TYPE_OPT || rr.rtype == TYPE_NULL { out.push(';'); }
    name_append(out, rr.name(list));
    out.push('\t');
    format(out, rr.ttl);
    out.push('\t');
    if known { class_append(out, rr.class); } else { out.append("CLASS"); format(out, rr.class); }
    out.push('\t');
    if known { type_append(out, rr.rtype); } else { out.append("TYPE"); format(out, rr.rtype); }
    out.push('\t');
}

// A record's text, as miekg's String(): the header, then the rdata.
fn rr_append_text(out: u8[>..]&, list: const u8[:], rr: Rr) {
    if rr.rtype == TYPE_TSIG { tsig_text(out, list, rr); return; }
    if rr.rtype == TYPE_OPT { opt_append_text(out, list, rr); return; }       // miekg's OPT.String()
    if rr.rtype == TYPE_TKEY { tkey_text(out, list, rr); return; }
    rr_header_append(out, list, rr);
    rdata_append(out, rr.rtype, rr.rdata(list), time_ns() / 1000000000);
}

fn rr_string(list: const u8[:], rr: Rr) -> u8[>..] {
    var out: u8[>..] = [];
    rr_append_text(out, list, rr);
    return out;
}

fn tsig_text(out: u8[>..]&, list: const u8[:], rr: Rr) {
    out.append("\n;; TSIG PSEUDOSECTION:\n; ");
    rr_header_append(out, list, rr);
    let rd = rr.rdata(list);
    let al = name_len_at(rd, 0);
    if al < 0 || al + 10 > rd.len { return; }
    out.push(' ');
    name_append(out, rd[..al]);
    out.push(' ');
    utc_append(out, get48(rd, al) as i64);
    out.push(' ');
    format(out, get16(rd, al + 6));
    let ms = get16(rd, al + 8) as i64;
    out.push(' ');
    format(out, ms);
    var p = al + 10;
    if p + ms + 6 > rd.len { return; }
    out.push(' ');
    hex_append(out, rd[p .. p + ms], true);
    p += ms;
    out.push(' ');
    format(out, get16(rd, p));
    out.push(' ');
    format(out, get16(rd, p + 2));
    let ol = get16(rd, p + 4) as i64;
    out.push(' ');
    format(out, ol);
    out.push(' ');
    if p + 6 + ol <= rd.len { hex_append(out, rd[p + 6 .. p + 6 + ol], false); }
}

fn tkey_text(out: u8[>..]&, list: const u8[:], rr: Rr) {
    out.push(';');
    rr_header_append(out, list, rr);
    let rd = rr.rdata(list);
    let al = name_len_at(rd, 0);
    if al < 0 || al + 16 > rd.len { return; }
    out.push(' ');
    name_append(out, rd[..al]);
    out.push(' ');
    time_append(out, get32(rd, al), time_ns() / 1000000000);
    out.push(' ');
    time_append(out, get32(rd, al + 4), time_ns() / 1000000000);
    out.push(' ');
    format(out, get16(rd, al + 8));
    out.push(' ');
    format(out, get16(rd, al + 10));
    let kl = get16(rd, al + 12) as i64;
    out.push(' ');
    format(out, kl);
    out.push(' ');
    var p = al + 14;
    if p + kl + 2 > rd.len { return; }
    hex_append(out, rd[p .. p + kl], false);
    p += kl;
    let ol = get16(rd, p) as i64;
    out.push(' ');
    format(out, ol);
    out.push(' ');
    if p + 2 + ol <= rd.len { hex_append(out, rd[p + 2 .. p + 2 + ol], false); }
}

// Two records equal as miekg's IsDuplicate has it: owner names equal
// ignoring case, type and class equal, rdata equal (names in it ignoring
// case). The TTL does not count.
fn rr_duplicate(la: const u8[:], a: Rr, lb: const u8[:], b: Rr) -> bool {
    if a.rtype != b.rtype || a.class != b.class { return false; }
    if !name_equal(a.name(la), b.name(lb)) { return false; }
    let ra = a.rdata(la);
    let rb = b.rdata(lb);
    if ra.len != rb.len { return false; }
    let names, ok = rdata_names(a.rtype, ra);
    var i = 0;
    while i < ra.len {
        var in_name = false;
        for p in names {
            if i >= p && i < p + name_len_at(ra, p) { in_name = true; }
        }
        if in_name { if lower(ra[i]) != lower(rb[i]) { return false; } }
        else if ra[i] != rb[i] { return false; }
        i++;
    }
    return true;
}

// The list without duplicates (miekg's Dedup), the first of each kept.
fn dedup(list: const u8[:], out: u8[>..]&) {
    let start = out.len;
    each_rr(list) { rr =>
        var dup = false;
        var j = start;
        while j < out.len {
            let o = rr_at(out, j);
            if rr_duplicate(list, rr, out, o) { dup = true; break; }
            j = o.end;
        }
        if !dup { rr_copy(out, list, rr); }
    };
}

// --- Questions -----------------------------------------------------------------

struct Question { off: i64, qtype: u16, qclass: u16, end: i64 }

fn question_at(list: const u8[:], off: i64) -> Question {
    let p = off + name_len_at(list, off);
    return Question { off, get16(list, p), get16(list, p + 2), p + 4 };
}

fn each_question<F>(list: const u8[:]) {
    var i = 0;
    while i < list.len { let q = question_at(list, i); F(q); i = q.end; }
}

fn name(q: Question, list: const u8[:]) -> const u8[:] { list[q.off .. q.end - 4] }

fn question_append(list: u8[>..]&, qname: const u8[:], qtype: u16, qclass: u16) -> i64 {
    if !name_valid(qname) { return ERR_NAME; }
    list.append(qname);
    put16(list, qtype);
    put16(list, qclass);
    return OK;
}

// ";name.<TAB>IN<TAB> A", as miekg's Question.String().
fn question_append_text(out: u8[>..]&, list: const u8[:], q: Question) {
    out.push(';');
    name_append(out, q.name(list));
    out.push('\t');
    class_append(out, q.qclass);
    out.append("\t ");
    type_append(out, q.qtype);
}

// --- Messages ------------------------------------------------------------------

struct Header {
    id: u16 = 0,
    response: bool = false,
    opcode: u8 = 0,
    authoritative: bool = false,
    truncated: bool = false,
    recursion_desired: bool = false,
    recursion_available: bool = false,
    zero: bool = false,
    authenticated_data: bool = false,
    checking_disabled: bool = false,
    rcode: u16 = 0,              // with the extended bits from OPT: 0..4095
}

root struct Msg {
    hdr: Header = Header { .. },
    compress: bool = false,
    question: u8[>..] = [],
    answer: u8[>..] = [],
    ns: u8[>..] = [],
    extra: u8[>..] = [],
}

fn clear(m: Msg&) {
    m.hdr = Header { .. };
    m.compress = false;
    m.question.clear();
    m.answer.clear();
    m.ns.clear();
    m.extra.clear();
}

// Copies from into m, which is cleared first (miekg's Msg.Copy).
fn copy_msg(m: Msg&, from: const Msg&) {
    clear(m);
    m.hdr = from.hdr;
    m.compress = from.compress;
    m.question.append(from.question);
    m.answer.append(from.answer);
    m.ns.append(from.ns);
    m.extra.append(from.extra);
}

fn flags_word(h: Header) -> u16 {
    var b: u16 = ((h.opcode as u16) & 15) << 11 | (h.rcode & 15);
    if h.response { b |= 0x8000; }
    if h.authoritative { b |= 0x0400; }
    if h.truncated { b |= 0x0200; }
    if h.recursion_desired { b |= 0x0100; }
    if h.recursion_available { b |= 0x0080; }
    if h.zero { b |= 0x0040; }
    if h.authenticated_data { b |= 0x0020; }
    if h.checking_disabled { b |= 0x0010; }
    return b;
}

fn header_from(id: u16, b: u16) -> Header {
    return Header {
        id: id,
        response: b & 0x8000 != 0,
        opcode: ((b >> 11) & 15) as! u8,
        authoritative: b & 0x0400 != 0,
        truncated: b & 0x0200 != 0,
        recursion_desired: b & 0x0100 != 0,
        recursion_available: b & 0x0080 != 0,
        zero: b & 0x0040 != 0,
        authenticated_data: b & 0x0020 != 0,
        checking_disabled: b & 0x0010 != 0,
        rcode: b & 15,
    };
}

// The offset of the OPT record in the additional section, -1 if none
// (miekg's IsEdns0 looks there only).
fn opt_offset(m: const Msg&) -> i64 {
    each_rr(m.extra) { rr => if rr.rtype == TYPE_OPT { return rr.off; } };
    return -1;
}

// --- Compression -----------------------------------------------------------------
//
// The names written so far, by where they start in the message: each name
// and each of its suffixes below the first 16 KB (pointers have 14 bits).
// Matched byte for byte, as miekg matches its text, case and all.

struct CompEntry { pos: u16, len: u8, next: i32 }

let COMP_SLOTS: i64 = 4096;

fn comp_hash(n: const u8[:]) -> i64 {
    var h: u32 = 2166136261;
    for c in n { h = (h ^ c) * 16777619; }
    return h % COMP_SLOTS as! u32;
}

// The suffix name n as it is in out at pos: its wire bytes, read through
// pointers. Equal to n when that is what was written there.
fn comp_match(out: const u8[:], pos: i64, n: const u8[:]) -> bool {
    var i = pos;
    var j = 0;
    while true {
        let c = out[i] as i64;
        if c & 0xC0 == 0xC0 { i = ((c & 0x3F) << 8) | out[i + 1]; continue; }
        if j >= n.len || n[j] != c { return false; }
        if c == 0 { return j + 1 == n.len; }
        for k in c { if out[i + 1 + k] != n[j + 1 + k] { return false; } }
        i += 1 + c;
        j += 1 + c;
    }
    return false;
}

// Writes the name n at the end of out: with a pointer for its longest
// suffix already written if compress, recording each suffix it writes.
fn put_name(out: u8[>..]&, n: const u8[:], slots: i32[:], entries: CompEntry[>..]&, compress: bool) {
    var i = 0;
    while n[i] != 0 {
        let suf = n[i..];
        let h = comp_hash(suf);
        var e = slots[h];
        var found = -1;
        while e >= 0 {
            let ent = entries[e];
            if ent.len == suf.len && comp_match(out, ent.pos, suf) { found = ent.pos; break; }
            e = ent.next;
        }
        if found >= 0 && compress {
            out.push((0xC0 | (found >> 8)) as! u8);
            out.push(found as! u8);
            return;
        }
        if found < 0 && out.len < 0x3FFF {
            entries.push(CompEntry { out.len as! u16, suf.len as! u8, slots[h] });
            slots[h] = (entries.len - 1) as! i32;
        }
        let l = n[i] as i64;
        out.append(n[i .. i + 1 + l]);
        i += 1 + l;
    }
    out.push(0);
}

// Writes uncompressed rdata, its names through put_name: compressed where
// the type allows ('c'), recorded for later names in any case.
fn put_rdata(out: u8[>..]&, t: u16, rd: const u8[:], slots: i32[:], entries: CompEntry[>..]&) {
    let lay, known = layout(t);
    if !known || rd.len == 0 { out.append(rd); return; }
    let names, ok = rdata_names(t, rd);
    if !ok { out.append(rd); return; }
    var i = 0;
    for p in names {
        out.append(rd[i..p]);
        let l = name_len_at(rd, p);
        var compress = false;
        // Is the name at p a 'c' field? Walk the layout to find out.
        var j = 0;
        for k in lay.f {
            if j == p && k == 'c' { compress = true; }
            if j >= rd.len { break; }
            let e = field_end(rd, j, k);
            if e < 0 { break; }
            j = e;
        }
        put_name(out, rd[p .. p + l], slots, entries, compress);
        i = p + l;
    }
    out.append(rd[i..]);
}

// Packs m onto out (miekg's Msg.Pack). The OPT record, if any, takes the
// rcode's upper bits; without one an rcode over 15 is ERR_EXTENDED_RCODE.
fn pack(m: Msg&, out: u8[>..]&) -> i64 {
    if m.hdr.rcode > 0xFFF { return ERR_RCODE; }
    let opt = opt_offset(m);
    if opt >= 0 {
        let rr = rr_at(m.extra, opt);
        let ttl = (rr.ttl & 0x00FFFFFF) | ((m.hdr.rcode as u32 >> 4) << 24);
        rr_set_ttl(m.extra, rr, ttl);
    } else if m.hdr.rcode > 0xF {
        return ERR_EXTENDED_RCODE;
    }
    let qd = question_count(m.question);
    let an = rr_count(m.answer);
    let ns = rr_count(m.ns);
    let ar = rr_count(m.extra);
    if qd > 65535 || an > 65535 || ns > 65535 || ar > 65535 { return ERR_BUF; }
    let start = out.len;
    put16(out, m.hdr.id);
    put16(out, flags_word(m.hdr));
    put16(out, qd as! u16);
    put16(out, an as! u16);
    put16(out, ns as! u16);
    put16(out, ar as! u16);
    if !m.compress {
        out.append(m.question);
        out.append(m.answer);
        out.append(m.ns);
        out.append(m.extra);
        return OK;
    }
    var slots: i32[4096] = [-1; 4096];
    var entries: CompEntry[>..] = [];
    var body: u8[>..] = [];
    body.append(out[start..]);     // pointers count from the message's start
    each_question(m.question) { q =>
        put_name(body, q.name(m.question), slots, entries, true);
        put16(body, q.qtype);
        put16(body, q.qclass);
    };
    pack_list(body, m.answer, slots, entries);
    pack_list(body, m.ns, slots, entries);
    pack_list(body, m.extra, slots, entries);
    out.append(body[12..]);
    return OK;
}

fn pack_list(body: u8[>..]&, list: const u8[:], slots: i32[:], entries: CompEntry[>..]&) {
    each_rr(list) { rr =>
        put_name(body, rr.name(list), slots, entries, true);
        put16(body, rr.rtype);
        put16(body, rr.class);
        put32(body, rr.ttl);
        let lp = body.len;
        put16(body, 0);
        put_rdata(body, rr.rtype, rr.rdata(list), slots, entries);
        set16(body, lp, (body.len - lp - 2) as! u16);
    };
}

fn question_count(list: const u8[:]) -> i64 {
    var n = 0;
    each_question(list) { q => n++; };
    return n;
}

fn pack_msg(m: Msg&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let e = pack(m, out);
    return out, e;
}

// Reads one record at off in msg onto list: its names decompressed. The
// offset after it, and OK.
fn unpack_rr(msg: const u8[:], off: i64, list: u8[>..]&) -> i64, i64 {
    let nm, p, e = read_name(msg, off);
    if e != OK { return off, e; }
    if p + 10 > msg.len { return off, ERR_SHORT; }
    let t = get16(msg, p);
    let rdlen = get16(msg, p + 8) as i64;
    if p + 10 + rdlen > msg.len { return off, ERR_SHORT; }
    if rdlen == 0 && !rdata_empty_ok(t, get16(msg, p + 2)) { return off, ERR_RDATA; }
    let start = list.len;
    list.append(nm);
    list.append(msg[p .. p + 10]);
    let lp = list.len - 2;
    let e2 = rdata_unpack(msg, p + 10, rdlen, t, list);
    if e2 != OK { list.resize(start); return off, e2; }
    // Decompressed, rdata can pass what its length field holds (HIP with
    // many pointers): ERR_BUF, as rr_append has it.
    if list.len - lp - 2 > 65535 { list.resize(start); return off, ERR_BUF; }
    set16(list, lp, (list.len - lp - 2) as! u16);
    return p + 10 + rdlen, OK;
}

fn unpack_section(msg: const u8[:], off0: i64, count: i64, list: u8[>..]&) -> i64, i64 {
    var off = off0;
    for i in count {
        if off >= msg.len { break; }        // the count was a lie
        let next, e = unpack_rr(msg, off, list);
        if e != OK { list.clear(); return msg.len, e; }
        off = next;
    }
    return off, OK;
}

// Reads the wire message msg into m (miekg's Msg.Unpack). Counts larger
// than what is there are believed only as far as the message goes; bytes
// after the last record are ignored. On an error in a section, that
// section and the ones after it are empty.
fn unpack(msg: const u8[:], m: Msg&) -> i64 {
    clear(m);
    if msg.len < 12 { return ERR_SHORT; }
    m.hdr = header_from(get16(msg, 0), get16(msg, 2));
    let qd = get16(msg, 4) as i64;
    let an = get16(msg, 6) as i64;
    let ns = get16(msg, 8) as i64;
    let ar = get16(msg, 10) as i64;
    var off = 12;
    for i in qd {
        if off >= msg.len { break; }
        let nm, p, e = read_name(msg, off);
        if e != OK { return e; }
        if p + 4 > msg.len { return ERR_SHORT; }
        m.question.append(nm);
        m.question.append(msg[p .. p + 4]);
        off = p + 4;
    }
    var e: i64 = OK;
    off, e = unpack_section(msg, off, an, m.answer);
    if e == OK { off, e = unpack_section(msg, off, ns, m.ns); }
    if e == OK { off, e = unpack_section(msg, off, ar, m.extra); }
    let opt = opt_offset(m);
    if opt >= 0 { m.hdr.rcode |= ((rr_at(m.extra, opt).ttl >> 24) as! u16) << 4; }
    return e;
}

// --- Text ------------------------------------------------------------------------

fn header_append_text(out: u8[>..]&, h: Header) {
    out.append(";; opcode: ");
    out.append(opcode_name(h.opcode));
    out.append(", status: ");
    out.append(rcode_name(h.rcode));
    out.append(", id: ");
    format(out, h.id);
    out.append("\n;; flags:");
    if h.response { out.append(" qr"); }
    if h.authoritative { out.append(" aa"); }
    if h.truncated { out.append(" tc"); }
    if h.recursion_desired { out.append(" rd"); }
    if h.recursion_available { out.append(" ra"); }
    if h.zero { out.append(" z"); }
    if h.authenticated_data { out.append(" ad"); }
    if h.checking_disabled { out.append(" cd"); }
    out.push(';');
}

// The message as miekg's Msg.String() writes it, dig's layout.
fn msg_string(m: const Msg&) -> u8[>..] {
    var out: u8[>..] = [];
    header_append_text(out, m.hdr);
    out.push(' ');
    let update = m.hdr.opcode == OPCODE_UPDATE;
    out.append(if update { "ZONE: " } else { "QUERY: " });
    format(out, question_count(m.question));
    out.append(if update { ", PREREQ: " } else { ", ANSWER: " });
    format(out, rr_count(m.answer));
    out.append(if update { ", UPDATE: " } else { ", AUTHORITY: " });
    format(out, rr_count(m.ns));
    out.append(", ADDITIONAL: ");
    format(out, rr_count(m.extra));
    out.push('\n');
    let opt = opt_offset(m);
    if opt >= 0 {
        opt_append_text(out, m.extra, rr_at(m.extra, opt));
        out.push('\n');
    }
    if m.question.len > 0 {
        out.append(if update { "\n;; ZONE SECTION:\n" } else { "\n;; QUESTION SECTION:\n" });
        each_question(m.question) { q => question_append_text(out, m.question, q); out.push('\n'); };
    }
    if m.answer.len > 0 {
        out.append(if update { "\n;; PREREQUISITE SECTION:\n" } else { "\n;; ANSWER SECTION:\n" });
        each_rr(m.answer) { rr => rr_append_text(out, m.answer, rr); out.push('\n'); };
    }
    if m.ns.len > 0 {
        out.append(if update { "\n;; UPDATE SECTION:\n" } else { "\n;; AUTHORITY SECTION:\n" });
        each_rr(m.ns) { rr => rr_append_text(out, m.ns, rr); out.push('\n'); };
    }
    if m.extra.len > 0 && (opt < 0 || rr_count(m.extra) > 1) {
        out.append("\n;; ADDITIONAL SECTION:\n");
        each_rr(m.extra) { rr => if rr.rtype != TYPE_OPT { rr_append_text(out, m.extra, rr); out.push('\n'); } };
    }
    return out;
}

// --- Helpers ---------------------------------------------------------------------

// A random message ID (miekg's Id), from the OS's entropy: an ID an
// off-path attacker could guess is how forged answers get accepted.
fn new_id() -> u16 {
    var b: u8[2] = [0; 2];
    entropy::random_bytes(b);
    return (b[0] as u16 << 8) | b[1];
}

// Makes m a query for the text name and type, class IN, recursion desired
// and a fresh ID (miekg's SetQuestion).
fn set_question(m: Msg&, qname: const u8[:], qtype: u16) -> i64 {
    let n, e = name_parse(qname, []);
    if e != OK { return e; }
    m.hdr.id = new_id();
    m.hdr.recursion_desired = true;
    m.hdr.opcode = OPCODE_QUERY;
    m.question.clear();
    return question_append(m.question, n, qtype, CLASS_INET);
}

// Makes m a reply to req (miekg's SetReply): its ID, opcode, RD and CD
// flags and question, response set, rcode NOERROR (NOTIMP for an opcode
// other than QUERY... as miekg does, only the opcode is copied).
fn set_reply(m: Msg&, req: const Msg&) {
    clear(m);
    m.hdr.id = req.hdr.id;
    m.hdr.response = true;
    m.hdr.opcode = req.hdr.opcode;
    if m.hdr.opcode == OPCODE_QUERY {
        m.hdr.recursion_desired = req.hdr.recursion_desired;
        m.hdr.checking_disabled = req.hdr.checking_disabled;
    }
    m.hdr.rcode = RCODE_SUCCESS;
    each_question(req.question) { q => m.question.append(req.question[q.off .. q.end]); return; };
}

fn set_rcode(m: Msg&, req: const Msg&, rcode: u16) {
    set_reply(m, req);
    m.hdr.rcode = rcode;
}

// The size the sender says it can take over UDP: from its OPT, else 512.
fn udp_size(m: const Msg&) -> i64 {
    let o = opt_offset(m);
    if o < 0 { return 512; }
    let c = rr_at(m.extra, o).class as i64;
    return if c < 512 { 512 } else { c };
}

// Cuts the message to size bytes (at least 512), as miekg's Truncate:
// compressed, the OPT record kept, then as many answer records as fit,
// then authority, then additional ones, each section a prefix and none
// after the first that did not fit; truncated is set when any record had
// to go. A message with a TSIG is left alone, as in miekg.
fn truncate(m: Msg&, size0: i64) {
    var size = if size0 < 512 { 512 } else { size0 };
    var has_tsig = false;
    each_rr(m.extra) { rr => if rr.rtype == TYPE_TSIG { has_tsig = true; } };
    if has_tsig { return; }
    m.compress = true;
    var w: u8[>..] = [];
    pack(m, w);
    if w.len <= size { return; }
    var opt: u8[>..] = [];
    let o = opt_offset(m);
    if o >= 0 { rr_copy(opt, m.extra, rr_at(m.extra, o)); size -= opt.len; }
    var all: u8[>..] = [];
    var ends: i64[3] = [0, 0, 0];
    all.append(m.answer);
    ends[0] = all.len;
    all.append(m.ns);
    ends[1] = all.len;
    each_rr(m.extra) { rr => if rr.rtype != TYPE_OPT { rr_copy(all, m.extra, rr); } };
    ends[2] = all.len;
    m.answer.clear();
    m.ns.clear();
    m.extra.clear();
    var full = false;
    var dropped = false;
    var i = 0;
    while i < all.len {
        let rr = rr_at(all, i);
        if !full {
            if i < ends[0] { rr_copy(m.answer, all, rr); } else if i < ends[1] { rr_copy(m.ns, all, rr); } else { rr_copy(m.extra, all, rr); }
            w.clear();
            pack(m, w);
            if w.len > size {
                full = true;
                if i < ends[0] { m.answer.resize(m.answer.len - (rr.end - rr.off)); }
                else if i < ends[1] { m.ns.resize(m.ns.len - (rr.end - rr.off)); }
                else { m.extra.resize(m.extra.len - (rr.end - rr.off)); }
            }
        }
        if full { dropped = true; }
        i = rr.end;
    }
    if dropped { m.hdr.truncated = true; }
    m.extra.append(opt);
}
