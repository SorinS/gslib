// krb5.ccache: MIT's FILE credential caches (the format of
// doc/formats/ccache_file_format.rst): versions 1 and 2 (native byte
// order) and 3 and 4 (big-endian) read; version 4 written, as MIT writes
// it. A cache holds a default principal and its credentials: the TGT and
// service tickets with their session keys.
//
// Configuration entries (server realm "X-CACHECONF:") are kept as they
// are and left out of lookups.

namespace krb5;

import std;
import os;
import krb5.crypto;
import krb5.messages;
import krb5.keytab;
import krb5.sys;

let CONF_REALM = "X-CACHECONF:";

struct Credential {
    client_type: i32,
    client: u8[],          // escaped, without the realm (krb5.messages' form)
    client_realm: u8[],
    server_type: i32,
    server: u8[],
    server_realm: u8[],
    key: Key,
    authtime: i64,
    starttime: i64,
    endtime: i64,
    renew_till: i64,
    is_skey: bool,
    flags: u32,
    addresses: HostAddress[],
    authdata: AuthData[],
    ticket: u8[],          // the Ticket's DER (a configuration entry's value)
    second_ticket: u8[],
}

struct CCache {
    version: i64,
    has_time_offset: bool,
    time_offset: i64,      // KDC time minus ours, seconds
    time_offset_usec: i64,
    principal_type: i32,
    principal: u8[],
    realm: u8[],
    creds: Credential[],
}

fn is_config_cred(c: const Credential&) -> bool { c.server_realm == CONF_REALM }

// --- Reading ------------------------------------------------------------------

fn cc_principal(b: const u8[:], r: Rd&, version: i64, nt: i32&, realm: u8[>..]&) -> u8[>..] {
    var name: u8[>..] = [];
    nt = if version == 1 { NT_UNKNOWN } else { rd_u32(b, r) as! i32 };
    var n = rd_u32(b, r) as i64;
    if version == 1 { n -= 1; }
    if n < 0 || n > 64 { r.bad = true; return name; }
    realm.clear();
    realm.append(rd_bytes(b, r, rd_u32(b, r)));
    for i in n {
        let c = rd_bytes(b, r, rd_u32(b, r));
        if i > 0 { name.push('/'); }
        name_escape(name, c);
    }
    return name;
}

fn cc_cred(b: const u8[:], r: Rd&, version: i64) -> Credential {
    var cnt: i32 = 0;
    var cr: u8[>..] = [];
    let cn = cc_principal(b, r, version, cnt, cr);
    var snt: i32 = 0;
    var sr: u8[>..] = [];
    let sn = cc_principal(b, r, version, snt, sr);
    let et = rd_u16(b, r);
    if version == 3 { let et2 = rd_u16(b, r); }
    var key = Key { etype: et as! i32, value: [] };
    let kv = rd_bytes(b, r, rd_u32(b, r));
    if kv.len > 32 { r.bad = true; } else { key.value.append(kv); }
    let at = rd_u32(b, r);
    let st = rd_u32(b, r);
    let en = rd_u32(b, r);
    let rt = rd_u32(b, r);
    let skey = rd_u8(b, r);
    let flags = rd_u32(b, r);
    var addrs: HostAddress[>..] = [];
    let na = rd_u32(b, r) as i64;
    if na > 1024 { r.bad = true; }
    for i in (if r.bad { 0 } else { na }) {
        let ty = rd_u16(b, r);
        let a = rd_bytes(b, r, rd_u32(b, r));
        addrs.push(HostAddress { addr_type: ty as! i32, address: copy(a) });
    }
    var ads: AuthData[>..] = [];
    let nd = rd_u32(b, r) as i64;
    if nd > 1024 { r.bad = true; }
    for i in (if r.bad { 0 } else { nd }) {
        let ty = rd_u16(b, r);
        let d = rd_bytes(b, r, rd_u32(b, r));
        ads.push(AuthData { ad_type: ty as! i32, data: copy(d) });
    }
    let tk = rd_bytes(b, r, rd_u32(b, r));
    let tk2 = rd_bytes(b, r, rd_u32(b, r));
    return Credential {
        client_type: cnt, client: cn, client_realm: cr, server_type: snt, server: sn, server_realm: sr, key: key,
        authtime: at, starttime: st, endtime: en, renew_till: rt, is_skey: skey != 0, flags: flags,
        addresses: addrs, authdata: ads, ticket: tk, second_ticket: tk2,
    };
}

fn ccache_parse(b: const u8[:]) -> CCache, i64 {
    var creds: Credential[>..] = [];
    var nt: i32 = 0;
    var realm: u8[>..] = [];
    var bad_cc = CCache { version: 0, has_time_offset: false, time_offset: 0, time_offset_usec: 0, principal_type: 0,
                          principal: "", realm: "", creds: [] };
    if b.len < 2 || b[0] != 5 || b[1] < 1 || b[1] > 4 { return bad_cc, ERR_FORMAT; }
    let version: i64 = b[1];
    var r = Rd { pos: 2, end: b.len, le: version <= 2 && native_le(), bad: false };
    var has_off = false;
    var off: i64 = 0;
    var off_us: i64 = 0;
    if version == 4 {
        let hlen = rd_u16(b, r) as i64;
        let hend = r.pos + hlen;
        if hend > b.len { return bad_cc, ERR_MALFORMED; }
        while r.pos + 4 <= hend {
            let tag = rd_u16(b, r);
            let len = rd_u16(b, r) as i64;
            if r.pos + len > hend { return bad_cc, ERR_MALFORMED; }
            if tag == 1 && len == 8 {
                has_off = true;
                off = rd_u32(b, r) as! i32;
                off_us = rd_u32(b, r) as! i32;
            } else {
                r.pos += len;
            }
        }
        r.pos = hend;
    }
    let name = cc_principal(b, r, version, nt, realm);
    if r.bad { return bad_cc, ERR_MALFORMED; }
    while r.pos < b.len {
        let c = cc_cred(b, r, version);
        if r.bad { return bad_cc, ERR_MALFORMED; }
        creds.push(copy(c));
    }
    return CCache {
        version: version, has_time_offset: has_off, time_offset: off, time_offset_usec: off_us, principal_type: nt,
        principal: name, realm: realm, creds: creds,
    }, OK;
}

// --- Writing ------------------------------------------------------------------

fn cc_put_principal(out: u8[>..]&, nt: i32, name: const u8[:], realm: const u8[:]) {
    put_u32(out, nt as! u32);
    var n: u32 = 0;
    for p in name_parts(name) { n++; }
    put_u32(out, n);
    put_u32(out, realm.len as! u32);
    out.append(realm);
    for p in name_parts(name) {
        put_u32(out, p.len as! u32);
        out.append(p);
    }
}

fn cc_put_data(out: u8[>..]&, d: const u8[:]) {
    put_u32(out, d.len as! u32);
    out.append(d);
}

fn cc_time(t: i64) -> u32 { if t <= 0 { 0 } else if t >= 1 << 32 { 0xffffffff } else { t as! u32 } }

fn ccache_encode_cred(out: u8[>..]&, c: const Credential&) {
    cc_put_principal(out, c.client_type, c.client, c.client_realm);
    cc_put_principal(out, c.server_type, c.server, c.server_realm);
    put_u16(out, c.key.etype as! u16);
    cc_put_data(out, c.key.value);
    put_u32(out, cc_time(c.authtime));
    put_u32(out, cc_time(c.starttime));
    put_u32(out, cc_time(c.endtime));
    put_u32(out, cc_time(c.renew_till));
    out.push(if c.is_skey { 1 } else { 0 });
    put_u32(out, c.flags);
    var na: u32 = 0;
    for a in c.addresses { na++; }
    put_u32(out, na);
    for a in c.addresses { put_u16(out, a.addr_type as! u16); cc_put_data(out, a.address); }
    var nd: u32 = 0;
    for a in c.authdata { nd++; }
    put_u32(out, nd);
    for a in c.authdata { put_u16(out, a.ad_type as! u16); cc_put_data(out, a.data); }
    cc_put_data(out, c.ticket);
    cc_put_data(out, c.second_ticket);
}

// A version 4 cache.
fn ccache_encode(out: u8[>..]&, cc: const CCache&) {
    out.push(5);
    out.push(4);
    if cc.has_time_offset {
        put_u16(out, 12);
        put_u16(out, 1);
        put_u16(out, 8);
        put_u32(out, cc.time_offset as! i32 as! u32);
        put_u32(out, cc.time_offset_usec as! i32 as! u32);
    } else {
        put_u16(out, 0);
    }
    cc_put_principal(out, cc.principal_type, cc.principal, cc.realm);
    for c in cc.creds { ccache_encode_cred(out, c); }
}

// --- Building -------------------------------------------------------------------

// A cache holding only its principal.
fn ccache_new(nt: i32, name: const u8[:], realm: const u8[:]) -> CCache {
    return CCache { version: 4, has_time_offset: false, time_offset: 0, time_offset_usec: 0, principal_type: nt,
                    principal: name, realm: realm, creds: [] };
}

// The cache with `c` added, replacing a credential for the same client
// and server (MIT's krb5_cc_store does not replace, but its lookups take
// the first match; we keep one, the newest).
fn ccache_add(cc: const CCache&, c: const Credential&) -> CCache {
    var creds: Credential[>..] = [];
    for x in cc.creds {
        let same = !is_config_cred(x) && x.client == c.client && x.client_realm == c.client_realm &&
                   x.server == c.server && x.server_realm == c.server_realm && x.is_skey == c.is_skey;
        if !same { creds.push(copy(x)); }
    }
    creds.push(copy(c));
    return CCache { version: 4, has_time_offset: cc.has_time_offset, time_offset: cc.time_offset,
                    time_offset_usec: cc.time_offset_usec, principal_type: cc.principal_type, principal: copy(cc.principal),
                    realm: copy(cc.realm), creds: creds };
}

// The cache with every credential of `more` added, as ccache_add does.
fn ccache_add_all(cc: const CCache&, more: const Credential[:]) -> CCache {
    var creds: Credential[>..] = [];
    for x in cc.creds {
        var replaced = false;
        for c in more {
            if !is_config_cred(x) && x.client == c.client && x.client_realm == c.client_realm &&
               x.server == c.server && x.server_realm == c.server_realm && x.is_skey == c.is_skey { replaced = true; }
        }
        if !replaced { creds.push(copy(x)); }
    }
    for c in more { creds.push(copy(c)); }
    return CCache { version: 4, has_time_offset: cc.has_time_offset, time_offset: cc.time_offset,
                    time_offset_usec: cc.time_offset_usec, principal_type: cc.principal_type, principal: copy(cc.principal),
                    realm: copy(cc.realm), creds: creds };
}

// The cache with a time offset (the KDC's clock minus ours).
fn ccache_with_offset(cc: const CCache&, offset: i64) -> CCache {
    var creds: Credential[>..] = [];
    for x in cc.creds { creds.push(copy(x)); }
    return CCache { version: 4, has_time_offset: true, time_offset: offset, time_offset_usec: 0,
                    principal_type: cc.principal_type, principal: copy(cc.principal), realm: copy(cc.realm), creds: creds };
}

// The credential for a server (name escaped, realm), not a configuration
// entry, not expired at `now` (0: any). The newest if several.
fn ccache_find(cc: const CCache&, server: const u8[:], server_realm: const u8[:], now: i64) -> Credential, bool {
    var found = false;
    var best_end: i64 = -1;
    for x in cc.creds {
        if is_config_cred(x) || x.server != server || x.server_realm != server_realm || x.is_skey { continue; }
        if now != 0 && x.endtime <= now { continue; }
        if !found || x.endtime > best_end { found = true; best_end = x.endtime; }
    }
    for x in cc.creds {
        if found && !is_config_cred(x) && x.server == server && x.server_realm == server_realm && !x.is_skey && x.endtime == best_end {
            return copy(x), true;
        }
    }
    return empty_credential(), false;
}

fn empty_credential() -> Credential {
    return Credential {
        client_type: 0, client: "", client_realm: "", server_type: 0, server: "", server_realm: "",
        key: Key { etype: 0, value: [] }, authtime: 0, starttime: 0, endtime: 0, renew_till: 0, is_skey: false, flags: 0,
        addresses: [], authdata: [], ticket: "", second_ticket: "",
    };
}

// A configuration entry's value for `key` (and the principal it applies
// to, or empty), as MIT stores fast_avail, pa_type and the like.
fn ccache_config(cc: const CCache&, key: const u8[:], principal: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    for x in cc.creds {
        if !is_config_cred(x) { continue; }
        if name_part(x.server, 0) != "krb5_ccache_conf_data" || name_part(x.server, 1) != key { continue; }
        if name_part(x.server, 2) != principal { continue; }
        out.append(x.ticket);
        return out, true;
    }
    return out, false;
}

// --- Files ----------------------------------------------------------------------

// The path in a cache name: "FILE:/path" or a plain path. Other types
// (MEMORY:, KEYRING:, KCM:, API:, DIR:) are not files we can read.
fn ccache_path(name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if name.starts_with("FILE:") { out.append(name[5..]); return out, true; }
    var colon = -1;
    for i in name.len { if name[i] == ':' { colon = i; break; } }
    // A Windows drive letter is a path; a longer prefix is a cache type.
    if colon > 1 { return out, false; }
    out.append(name);
    return out, true;
}

fn ccache_load(name: const u8[:]) -> CCache, i64 {
    let path, ok = ccache_path(name);
    if !ok { return ccache_new(0, "", ""), ERR_FORMAT; }
    var b: u8[>..] = [];
    if !read_file(path, b) { return ccache_new(0, "", ""), ERR_FILE; }
    return ccache_parse(b);
}

// Writes the cache whole, readable by its owner only (as MIT's are).
fn ccache_save(name: const u8[:], cc: const CCache&) -> i64 {
    let path, ok = ccache_path(name);
    if !ok { return ERR_FORMAT; }
    var b: u8[>..] = [];
    ccache_encode(b, cc);
    return if krb5sys_write_private(path, b) == 0 { OK } else { ERR_FILE };
}

// The default cache: $KRB5CCNAME, else FILE:/tmp/krb5cc_<uid> (MIT's
// default; on Windows, %TEMP%\krb5cc).
fn default_ccache_name() -> u8[>..] {
    var out: u8[>..] = [];
    if env("KRB5CCNAME", out) && out.len > 0 { return out; }
    out.clear();
    let uid = krb5sys_uid();
    if uid >= 0 {
        out.append("FILE:/tmp/krb5cc_");
        format_int(out, uid, 10, 0, ' ');
        return out;
    }
    var tmp: u8[>..] = [];
    if !env("TEMP", tmp) { tmp.append("."); }
    out.append("FILE:");
    out.append(tmp);
    out.append("\\krb5cc");
    return out;
}
