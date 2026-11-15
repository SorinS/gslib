// dns.tsig: transaction signatures, TSIG (RFC 8945), on packed messages,
// as miekg's TsigGenerate and TsigVerify make and check them. (SIG(0) is
// dns.sig0: it needs DNSSEC's keys, which this does not.)
//
//   var w: u8[>..] = [];
//   dns::pack(m, w);
//   let mac, e = dns::tsig_sign(w, key_name, dns::HMAC_SHA256, secret, 300, now, "", false);
//   ... send w ...
//   let reply_mac, e2 = dns::tsig_verify(reply, secret, mac, false, now);
//
// The secret is the key's bytes (miekg takes them in base64: decode with
// tsig_secret). A reply's MAC covers the request's MAC; the messages of a
// zone transfer after the first cover the one before and only the timers
// (timers_only). HMAC-MD5, -SHA1, -SHA224, -SHA256, -SHA384 and -SHA512.

namespace dns;

import std;
import base64;
import dns;
import dns.rdata;
import dns.msg;
import crypto.bignum.hmac;
import crypto.bignum.md5;
import crypto.bignum.sha1;
import crypto.bignum.sha256;
import crypto.bignum.sha512;

let HMAC_MD5 = "hmac-md5.sig-alg.reg.int.";
let HMAC_SHA1 = "hmac-sha1.";
let HMAC_SHA224 = "hmac-sha224.";
let HMAC_SHA256 = "hmac-sha256.";
let HMAC_SHA384 = "hmac-sha384.";
let HMAC_SHA512 = "hmac-sha512.";

// The HMAC's hash for an algorithm name (text, any case), as a
// bignum.hmac id; 0 for none.
fn tsig_hash(alg: const u8[:]) -> i64 {
    let n, e = name_parse(alg, []);
    if e != OK { return 0; }
    let t = name_text(name_lower(n));
    if t == HMAC_MD5 { return 128; }
    if t == HMAC_SHA1 { return 160; }
    if t == HMAC_SHA224 { return 224; }
    if t == HMAC_SHA256 { return 256; }
    if t == HMAC_SHA384 { return 384; }
    if t == HMAC_SHA512 { return 512; }
    return 0;
}

// A secret in base64, as miekg's TsigSecret holds it; false if it is not.
fn tsig_secret(b64: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let ok = base64::decode(out, b64);
    return out, ok;
}

// Where things are in a packed message: the offset of its last additional
// record (a TSIG or SIG(0) must be there), its end; -1 for a malformed one.
fn last_record_offset(w: const u8[:]) -> i64 {
    if w.len < 12 { return -1; }
    let qd = get16(w, 4) as i64;
    let total = get16(w, 6) as i64 + get16(w, 8) + get16(w, 10);
    var off = 12;
    for i in qd {
        let n, next, e = read_name(w, off);
        if e != OK || next + 4 > w.len { return -1; }
        off = next + 4;
    }
    var last = -1;
    for i in total {
        last = off;
        let n, next, e = read_name(w, off);
        if e != OK || next + 10 > w.len { return -1; }
        let end = next + 10 + get16(w, next + 8);
        if end > w.len { return -1; }
        off = end;
    }
    return last;
}

// The data a TSIG MAC covers: the request's MAC (with its length) if any,
// the message without its TSIG (its ID the original one), then the TSIG
// variables, or only the timers.
fn tsig_data(stripped: const u8[:], orig_id: u16, key_name: const u8[:], alg: const u8[:], time_signed: u64,
             fudge: u16, error: u16, other: const u8[:], request_mac: const u8[:], timers_only: bool, out: u8[>..]&) {
    if request_mac.len > 0 { put16(out, request_mac.len as! u16); out.append(request_mac); }
    let m0 = out.len;
    out.append(stripped);
    set16(out[m0..], 0, orig_id);
    if !timers_only {
        out.append(name_lower(key_name));
        put16(out, CLASS_ANY);
        put32(out, 0);
        out.append(name_lower(alg));
    }
    put48(out, time_signed);
    put16(out, fudge);
    if !timers_only {
        put16(out, error);
        put16(out, other.len as! u16);
        out.append(other);
    }
}

// Signs the packed message w (miekg's TsigGenerate): appends a TSIG
// record for the key and bumps the additional count. The MAC, which a
// reply's signature covers, and OK; ERR_ALG for an algorithm not done.
// time_signed is seconds since the epoch.
fn tsig_sign(w: u8[>..]&, key_name: const u8[:], alg: const u8[:], secret: const u8[:], fudge: u16,
             time_signed: i64, request_mac: const u8[:], timers_only: bool) -> u8[>..], i64 {
    return tsig_sign_error(w, key_name, alg, secret, fudge, time_signed, request_mac, timers_only, 0, []);
}

// The same with an error (BADKEY and BADSIG get no MAC, as RFC 8945 §5.3.2
// has it) and other data (BADTIME's server time).
fn tsig_sign_error(w: u8[>..]&, key_name0: const u8[:], alg0: const u8[:], secret: const u8[:], fudge: u16,
                   time_signed: i64, request_mac: const u8[:], timers_only: bool, error: u16, other: const u8[:]) -> u8[>..], i64 {
    var mac: u8[>..] = [];
    let h = tsig_hash(alg0);
    // BADKEY carries no MAC, so it can answer an algorithm not done here.
    if h == 0 && error != RCODE_BAD_KEY { return mac, ERR_ALG; }
    let key_name, e1 = name_parse(key_name0, []);
    let alg, e2 = name_parse(alg0, []);
    if e1 != OK || e2 != OK || w.len < 12 { return mac, ERR_NAME; }
    let orig_id = get16(w, 0);
    if error != RCODE_BAD_KEY && error != RCODE_BAD_SIG {
        var data: u8[>..] = [];
        tsig_data(w, orig_id, key_name, alg, time_signed as! u64, fudge, error, other, request_mac, timers_only, data);
        mac.append(bignum::hmac(h, secret, data));
    }
    var rd: u8[>..] = [];
    rd.append(alg);
    put48(rd, if mac.len > 0 { time_signed as! u64 } else { 0 });
    put16(rd, fudge);
    put16(rd, mac.len as! u16);
    rd.append(mac);
    put16(rd, orig_id);
    put16(rd, error);
    put16(rd, other.len as! u16);
    rd.append(other);
    rr_append(w, key_name, TYPE_TSIG, CLASS_ANY, 0, rd);
    set16(w, 10, get16(w, 10) + 1);
    return mac, OK;
}

// The TSIG record of a packed message: where it starts, its rdata's
// offset, OK; ERR_NO_SIG without one.
fn find_tsig(w: const u8[:]) -> i64, i64, i64 {
    if w.len < 12 || get16(w, 10) == 0 { return 0, 0, ERR_NO_SIG; }
    let off = last_record_offset(w);
    if off < 0 { return 0, 0, ERR_RDATA; }
    let n, next, e = read_name(w, off);
    if get16(w, next) != TYPE_TSIG { return 0, 0, ERR_NO_SIG; }
    return off, next + 10, OK;
}

// The key name and algorithm of a message's TSIG, to find its secret.
fn tsig_key(w: const u8[:]) -> Name, Name, i64 {
    let off, rd, e = find_tsig(w);
    var none: Name = [0];
    if e != OK { return none, none, e; }
    let kn, n1, e1 = read_name(w, off);
    let an, n2, e2 = read_name(w, rd);
    if e1 != OK || e2 != OK { return none, none, ERR_RDATA; }
    return kn, an, OK;
}

// Verifies a packed message's TSIG with the secret (miekg's TsigVerify):
// the MAC (ERR_SIG), then the time against now within the fudge
// (ERR_TIME). The MAC, for the reply, and OK. A message whose rcode is
// NOTAUTH is ERR_AUTH, as in miekg.
fn tsig_verify(w: const u8[:], secret: const u8[:], request_mac: const u8[:], timers_only: bool, now: i64) -> u8[>..], i64 {
    return tsig_verify_fudge(w, secret, request_mac, timers_only, now, 65535);
}

// The same with the fudge the message gives capped at max_fudge: a server
// checks a request's time against its own fudge, not one the sender chose.
fn tsig_verify_fudge(w: const u8[:], secret: const u8[:], request_mac: const u8[:], timers_only: bool, now: i64,
                     max_fudge: u16) -> u8[>..], i64 {
    var mac: u8[>..] = [];
    if w.len >= 12 && get16(w, 2) & 15 == RCODE_NOT_AUTH { return mac, ERR_AUTH; }
    let off, rd, e = find_tsig(w);
    if e != OK { return mac, e; }
    let key_name, n1, e1 = read_name(w, off);
    let alg, p, e2 = read_name(w, rd);
    if e1 != OK || e2 != OK || p + 10 > w.len { return mac, ERR_RDATA; }
    let h = tsig_hash(name_text(alg));
    if h == 0 { return mac, ERR_ALG; }
    let time_signed = get48(w, p);
    let fudge = get16(w, p + 6);
    let ms = get16(w, p + 8) as i64;
    if p + 10 + ms + 6 > w.len { return mac, ERR_RDATA; }
    mac.append(w[p + 10 .. p + 10 + ms]);
    let q = p + 10 + ms;
    let orig_id = get16(w, q);
    let error = get16(w, q + 2);
    let ol = get16(w, q + 4) as i64;
    if q + 6 + ol > w.len { return mac, ERR_RDATA; }
    var stripped: u8[>..] = [];
    stripped.append(w[..off]);
    set16(stripped, 10, get16(stripped, 10) - 1);
    var data: u8[>..] = [];
    tsig_data(stripped, orig_id, key_name, alg, time_signed, fudge, error, w[q + 6 .. q + 6 + ol], request_mac, timers_only, data);
    let want = bignum::hmac(h, secret, data);
    // Compared in constant time; a truncated MAC (RFC 8945 §5.2.2.1) is not accepted.
    if want.len != mac.len { return mac, ERR_SIG; }
    var diff: u8 = 0;
    for i in mac.len { diff |= want[i] ^ mac[i]; }
    if diff != 0 { return mac, ERR_SIG; }
    let t = time_signed as i64;
    let d = if now >= t { now - t } else { t - now };
    if d > fudge || d > max_fudge { return mac, ERR_TIME; }
    return mac, OK;
}

// The packed message without its TSIG: the record cut off, the count down
// one, the ID the original one (what a server answers, or what was sent).
fn tsig_strip(w: const u8[:], out: u8[>..]&) -> i64 {
    let off, rd, e = find_tsig(w);
    if e != OK { return e; }
    let start = out.len;
    out.append(w[..off]);
    set16(out[start..], 10, get16(out, start + 10) - 1);
    let alg, p, e2 = read_name(w, rd);
    if e2 != OK || p + 10 > w.len || p + 12 + get16(w, p + 8) > w.len { out.resize(start); return ERR_RDATA; }
    let ms = get16(w, p + 8) as i64;
    set16(out[start..], 0, get16(w, p + 10 + ms));
    return OK;
}
