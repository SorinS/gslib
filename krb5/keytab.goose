// krb5.keytab: MIT's keytab files (the format of
// doc/formats/keytab_file_format.rst), versions 1 (native byte order) and
// 2 (big-endian), read; version 2 written. A keytab holds long-term keys:
// a service's, to accept tickets, or a user's, to get a TGT without a
// password.
//
// Records may be holes (negative lengths, skipped) and may be longer than
// their entry; an entry's optional trailing 32-bit key version, when
// nonzero, overrides its 8-bit one (MIT 1.14 and later write it, as we do).

namespace krb5;

import std;
import os;
import krb5.crypto;
import krb5.messages;
import krb5.sys;

struct KeytabEntry { name_type: i32, name: u8[], realm: u8[], timestamp: u32, kvno: u32, key: Key }

// A cursor over a binary file, big-endian unless `le`.
struct Rd { pos: i64, end: i64, le: bool, bad: bool }

fn rd_u8(b: const u8[:], r: Rd&) -> u32 {
    if r.pos + 1 > r.end { r.bad = true; return 0; }
    let v: u32 = b[r.pos];
    r.pos++;
    return v;
}

fn rd_u16(b: const u8[:], r: Rd&) -> u32 {
    if r.pos + 2 > r.end { r.bad = true; return 0; }
    let x: u32 = b[r.pos];
    let y: u32 = b[r.pos + 1];
    r.pos += 2;
    return if r.le { y << 8 | x } else { x << 8 | y };
}

fn rd_u32(b: const u8[:], r: Rd&) -> u32 {
    if r.pos + 4 > r.end { r.bad = true; return 0; }
    var v: u32 = 0;
    for i in 4 {
        let x: u32 = b[r.pos + (if r.le { 3 - i } else { i })];
        v = v << 8 | x;
    }
    r.pos += 4;
    return v;
}

fn rd_bytes(b: const u8[:], r: Rd&, n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    if n < 0 || r.pos + n > r.end { r.bad = true; return out; }
    out.append(b[r.pos..r.pos + n]);
    r.pos += n;
    return out;
}

fn put_u16(out: u8[>..]&, v: u32) { out.push((v >> 8) as! u8); out.push(v as! u8); }

fn put_u32(out: u8[>..]&, v: u32) {
    out.push((v >> 24) as! u8);
    out.push((v >> 16) as! u8);
    out.push((v >> 8) as! u8);
    out.push(v as! u8);
}

// --- Reading ------------------------------------------------------------------

// One entry, from r.pos to r.end (its record).
fn keytab_entry_at(b: const u8[:], r: Rd&, version: u32) -> KeytabEntry {
    var n = rd_u16(b, r) as i64;
    if version == 1 { n -= 1; }
    let realm = rd_bytes(b, r, rd_u16(b, r));
    var name: u8[>..] = [];
    for i in n {
        let comp = rd_bytes(b, r, rd_u16(b, r));
        if i > 0 { name.push('/'); }
        name_escape(name, comp);
    }
    let nt = if version == 1 { NT_PRINCIPAL as! u32 } else { rd_u32(b, r) };
    let ts = rd_u32(b, r);
    var kvno = rd_u8(b, r);
    let etype = rd_u16(b, r);
    let klen = rd_u16(b, r);
    var key = Key { etype: etype as! i32, value: [] };
    let kv = rd_bytes(b, r, klen);
    if kv.len > 32 { r.bad = true; } else { key.value.append(kv); }
    if r.end - r.pos >= 4 {
        let k32 = rd_u32(b, r);
        if k32 != 0 { kvno = k32; }
    }
    if n < 1 { r.bad = true; }
    return KeytabEntry { name_type: nt as! i32, name: name, realm: realm, timestamp: ts, kvno: kvno, key: key };
}

fn keytab_parse(b: const u8[:]) -> KeytabEntry[>..], i64 {
    var out: KeytabEntry[>..] = [];
    if b.len < 2 || b[0] != 5 || (b[1] != 1 && b[1] != 2) { return out, ERR_FORMAT; }
    let version: u32 = b[1];
    var r = Rd { pos: 2, end: b.len, le: version == 1 && native_le(), bad: false };
    while r.pos < b.len {
        // A file may end without the zero length.
        if b.len - r.pos < 4 { break; }
        let size = rd_u32(b, r) as! i32 as i64;
        if size == 0 { break; }
        if size < 0 {
            if r.pos - size > b.len { return out, ERR_MALFORMED; }
            r.pos -= size;
            continue;
        }
        if r.pos + size > b.len { return out, ERR_MALFORMED; }
        var e = Rd { pos: r.pos, end: r.pos + size, le: r.le, bad: false };
        let entry = keytab_entry_at(b, e, version);
        if e.bad { return out, ERR_MALFORMED; }
        out.push(copy(entry));
        r.pos += size;
    }
    return out, OK;
}

// Version 1's byte order is the writer's; we take it as ours.
fn native_le() -> bool {
    let x: u32[1] = [1];
    return (x[0] & 0xff) == 1;
}

fn keytab_load(path: const u8[:]) -> KeytabEntry[>..], i64 {
    var b: u8[>..] = [];
    if !read_file(path, b) { var e: KeytabEntry[>..] = []; return e, ERR_FILE; }
    return keytab_parse(b);
}

// --- Writing ------------------------------------------------------------------

fn keytab_encode_entry(out: u8[>..]&, e: const KeytabEntry&) {
    var b: u8[>..] = [];
    var n: u32 = 0;
    for p in name_parts(e.name) { n++; }
    put_u16(b, n);
    put_u16(b, e.realm.len as! u32);
    b.append(e.realm);
    for p in name_parts(e.name) {
        put_u16(b, p.len as! u32);
        b.append(p);
    }
    put_u32(b, e.name_type as! u32);
    put_u32(b, e.timestamp);
    b.push((e.kvno & 0xff) as! u8);
    put_u16(b, e.key.etype as! u16);
    put_u16(b, e.key.value.len as! u32);
    b.append(e.key.value);
    put_u32(b, e.kvno);
    put_u32(out, b.len as! u32);
    out.append(b);
}

// A version 2 keytab of the entries.
fn keytab_encode(out: u8[>..]&, entries: const KeytabEntry[:]) {
    out.push(5);
    out.push(2);
    for e in entries { keytab_encode_entry(out, e); }
}

// Writes the keytab whole (to a new file renamed over the old).
fn keytab_save(path: const u8[:], entries: const KeytabEntry[:]) -> i64 {
    var b: u8[>..] = [];
    keytab_encode(b, entries);
    return if write_file_atomic(path, b) { OK } else { ERR_FILE };
}

// --- Using ----------------------------------------------------------------------

// The key for a principal (name escaped as krb5.messages keeps it) of an
// encryption type and version, kvno 0 meaning the highest there is. Also
// the version found. Realm and name compare exactly, as MIT's do.
fn keytab_key(entries: const KeytabEntry[:], name: const u8[:], realm: const u8[:], etype: i32, kvno: u32) -> Key, u32, i64 {
    var best = Key { etype: 0, value: [] };
    var best_kvno: u32 = 0;
    var found = false;
    for e in entries {
        if e.name != name || e.realm != realm || e.key.etype != etype { continue; }
        if kvno != 0 && e.kvno != kvno { continue; }
        // Key versions wrap at 8 bits in old files; the highest is newest
        // unless a wrap shows (MIT compares the same way, by value).
        if !found || e.kvno > best_kvno {
            best = e.key;
            best_kvno = e.kvno;
            found = true;
        }
    }
    return best, best_kvno, if found { OK } else { ERR_NO_KEY };
}

// The encryption types the keytab has for a principal, highest version
// first in each type, in the order of `prefer`.
fn keytab_etypes(entries: const KeytabEntry[:], name: const u8[:], realm: const u8[:], prefer: const i32[:]) -> i32[>..] {
    var out: i32[>..] = [];
    for p in prefer {
        for e in entries {
            if e.name == name && e.realm == realm && e.key.etype == p {
                out.push(p);
                break;
            }
        }
    }
    return out;
}

// Entries for a principal with a password: one per encryption type, with
// the default salt (realm and components) unless `salt` is given, as
// ktutil's addent -password does.
fn keytab_entries_from_password(name_type: i32, name: const u8[:], realm: const u8[:], password: const u8[:], kvno: u32,
                                etypes: const i32[:], timestamp: u32, salt: const u8[:] = "", has_salt: bool = false)
    -> KeytabEntry[>..], i64 {
    var out: KeytabEntry[>..] = [];
    var s: u8[>..] = [];
    if has_salt { s.append(salt); } else { s.append(realm); for p in name_parts(name) { s.append(p); } }
    for e in etypes {
        let k, err = string_to_key(e, password, s);
        if err != OK { return out, err; }
        out.push(KeytabEntry { name_type: name_type, name: name, realm: realm, timestamp: timestamp, kvno: kvno, key: k });
    }
    return out, OK;
}

// Like keytab_save, the file readable by its owner only (as kadmin's
// ktadd writes them).
fn keytab_save_private(path: const u8[:], entries: const KeytabEntry[:]) -> i64 {
    var b: u8[>..] = [];
    keytab_encode(b, entries);
    return if krb5sys_write_private(path, b) == 0 { OK } else { ERR_FILE };
}
