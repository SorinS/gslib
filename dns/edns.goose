// dns.edns: EDNS0 (RFC 6891): the OPT pseudo-record and its options.
//
// The OPT record's class is the sender's UDP payload size, its TTL the
// extended rcode (8 bits), the version (8 bits), DO, CO and Z; its rdata
// is options, each a code, a length and data. Options are read with
// each_option and built with option_append and the builders below, as
// miekg's EDNS0_* types are.

namespace dns;

import std;
import base64;
import dns;
import dns.rdata;
import dns.msg;

let EDNS0_LLQ: u16 = 1;
let EDNS0_UL: u16 = 2;
let EDNS0_NSID: u16 = 3;
let EDNS0_ESU: u16 = 4;
let EDNS0_DAU: u16 = 5;
let EDNS0_DHU: u16 = 6;
let EDNS0_N3U: u16 = 7;
let EDNS0_SUBNET: u16 = 8;
let EDNS0_EXPIRE: u16 = 9;
let EDNS0_COOKIE: u16 = 10;
let EDNS0_TCP_KEEPALIVE: u16 = 11;
let EDNS0_PADDING: u16 = 12;
let EDNS0_EDE: u16 = 15;
let EDNS0_REPORTING: u16 = 18;
let EDNS0_ZONEVERSION: u16 = 19;
let EDNS0_LOCAL_START: u16 = 0xFDE9;
let EDNS0_LOCAL_END: u16 = 0xFFFE;

let DEFAULT_MSG_SIZE: u16 = 4096;     // miekg's DefaultMsgSize

struct Option { code: u16, off: i64, end: i64 }   // data at off..end in the rdata

fn each_option<F>(rd: const u8[:]) {
    var i = 0;
    while i + 4 <= rd.len {
        let len = get16(rd, i + 2) as i64;
        if i + 4 + len > rd.len { return; }
        F(Option { get16(rd, i), i + 4, i + 4 + len });
        i += 4 + len;
    }
}

fn data(o: Option, rd: const u8[:]) -> const u8[:] { rd[o.off .. o.end] }

fn option_append(rd: u8[>..]&, code: u16, data: const u8[:]) {
    put16(rd, code);
    put16(rd, data.len as! u16);
    rd.append(data);
}

// The OPT record's fields, from its class and TTL.
fn opt_udp_size(rr: Rr) -> u16 { rr.class }
fn opt_version(rr: Rr) -> u8 { ((rr.ttl >> 16) & 0xff) as! u8 }
fn opt_do(rr: Rr) -> bool { rr.ttl & 0x8000 != 0 }
fn opt_co(rr: Rr) -> bool { rr.ttl & 0x4000 != 0 }
fn opt_z(rr: Rr) -> u16 { (rr.ttl & 0x3FFF) as! u16 }
fn opt_extended_rcode(rr: Rr) -> u16 { ((rr.ttl >> 24) as! u16) << 4 }

// Adds an OPT record to the additional section (miekg's SetEdns0), or, if
// there is one, sets its size and DO bit.
fn set_edns0(m: Msg&, udp_size: u16, do_bit: bool) {
    let o = opt_offset(m);
    if o >= 0 {
        let rr = rr_at(m.extra, o);
        rr_set_class(m.extra, rr, udp_size);
        rr_set_ttl(m.extra, rr, if do_bit { rr.ttl | 0x8000 } else { rr.ttl & ~0x8000 });
        return;
    }
    rr_append(m.extra, [0], TYPE_OPT, udp_size, if do_bit { 0x8000 } else { 0 }, []);
}

// Adds an option to the message's OPT record, which must be there.
fn add_option(m: Msg&, code: u16, data: const u8[:]) -> i64 {
    let o = opt_offset(m);
    if o < 0 { return ERR_RDATA; }
    let rr = rr_at(m.extra, o);
    var rest: u8[>..] = [];
    rest.append(m.extra[rr.end..]);
    var rd: u8[>..] = [];
    rd.append(rr.rdata(m.extra));
    option_append(rd, code, data);
    if rd.len > 65535 { return ERR_BUF; }
    m.extra.resize(rr.rd - 2);
    put16(m.extra, rd.len as! u16);
    m.extra.append(rd);
    m.extra.append(rest);
    return OK;
}

// The data of the message's first option with the code; found or not.
fn find_option(m: const Msg&, code: u16) -> i64, i64, bool {
    let o = opt_offset(m);
    if o < 0 { return 0, 0, false; }
    let rr = rr_at(m.extra, o);
    each_option(rr.rdata(m.extra)) { op => if op.code == code { return rr.rd + op.off, rr.rd + op.end, true; } };
    return 0, 0, false;
}

// --- Option data -------------------------------------------------------------------

// RFC 7871 client subnet: family 1 or 2, the address cut to the source
// prefix length.
fn subnet_data(out: u8[>..]&, ip: const u8[:], source: u8, scope: u8) {
    let fam: u16 = if ip.len == 4 { 1 } else { 2 };
    put16(out, fam);
    out.push(source);
    out.push(scope);
    let n = (source as i64 + 7) / 8;
    for i in n {
        var b = ip[i];
        if i == n - 1 && source % 8 != 0 { b &= (0xff << (8 - source % 8)) as! u8; }
        out.push(b);
    }
}

// TCP keepalive (RFC 7828) in units of 100 ms; 0 leaves the timeout out.
fn keepalive_data(out: u8[>..]&, timeout: u16) { if timeout != 0 { put16(out, timeout); } }

// Extended DNS error (RFC 8914).
fn ede_data(out: u8[>..]&, info: u16, text: const u8[:]) { put16(out, info); out.append(text); }

let EDE_NAMES: u8[..40][31] = [
    "Other", "Unsupported DNSKEY Algorithm", "Unsupported DS Digest Type", "Stale Answer", "Forged Answer",
    "DNSSEC Indeterminate", "DNSSEC Bogus", "Signature Expired", "Signature Not Yet Valid", "DNSKEY Missing",
    "RRSIGs Missing", "No Zone Key Bit Set", "NSEC Missing", "Cached Error", "Not Ready", "Blocked", "Censored",
    "Filtered", "Prohibited", "Stale NXDOMAIN Answer", "Not Authoritative", "Not Supported",
    "No Reachable Authority", "Network Error", "Invalid Data", "Signature Expired Before Valid", "Too Early",
    "Unsupported NSEC3 Iterations Value", "Unable To Conform To Policy", "Synthesized", "Invalid Query Type",
];

fn hash_name_append(out: u8[>..]&, h: u8) {
    if h == 1 { out.append("SHA1"); } else if h == 2 { out.append("SHA256"); } else if h == 3 { out.append("GOST94"); }
    else if h == 4 { out.append("SHA384"); } else if h == 5 { out.append("SHA512"); } else { format(out, h); }
}

// One option as miekg's OPT.String() writes it, from its "\n; NAME: ".
fn option_append_text(out: u8[>..]&, code: u16, d: const u8[:]) {
    if code == EDNS0_NSID {
        out.append("\n; NSID: ");
        hex_append(out, d, false);
        out.append("  ");
        for c in d { out.push('('); out.push(c); out.push(')'); }
    } else if code == EDNS0_SUBNET {
        out.append("\n; SUBNET: ");
        if d.len < 4 { return; }
        let fam = get16(d, 0);
        var ip: u8[16] = [0; 16];
        let n = d.len - 4;
        for i in n { if i < 16 { ip[i] = d[4 + i]; } }
        if fam == 2 { out.push('['); ip6_append(out, ip); out.push(']'); } else { ip4_append(out, ip[..4]); }
        out.push('/'); format(out, d[2]); out.push('/'); format(out, d[3]);
    } else if code == EDNS0_COOKIE {
        out.append("\n; COOKIE: ");
        hex_append(out, d, false);
    } else if code == EDNS0_EXPIRE {
        out.append("\n; EXPIRE: ");
        if d.len == 4 { format(out, get32(d, 0)); }
    } else if code == EDNS0_TCP_KEEPALIVE {
        out.append("\n; KEEPALIVE: use tcp keep-alive");
        if d.len < 2 || get16(d, 0) == 0 { out.append(", timeout omitted"); }
        else { out.append(", timeout "); format(out, get16(d, 0) as i64 * 100); out.append("ms"); }
    } else if code == EDNS0_UL {
        out.append("\n; UPDATE LEASE: ");
        if d.len >= 4 { format(out, get32(d, 0)); } else { out.push('0'); }
        out.push(' ');
        if d.len >= 8 { format(out, get32(d, 4)); } else { out.push('0'); }
    } else if code == EDNS0_LLQ {
        out.append("\n; LONG LIVED QUERIES: ");
        if d.len == 18 {
            format(out, get16(d, 0)); out.push(' '); format(out, get16(d, 2)); out.push(' ');
            format(out, get16(d, 4)); out.push(' '); format(out, get64(d, 6)); out.push(' '); format(out, get32(d, 14));
        }
    } else if code == EDNS0_DAU || code == EDNS0_DHU || code == EDNS0_N3U {
        out.append(if code == EDNS0_DAU { "\n; DNSSEC ALGORITHM UNDERSTOOD: " }
                   else if code == EDNS0_DHU { "\n; DS HASH UNDERSTOOD: " } else { "\n; NSEC3 HASH UNDERSTOOD: " });
        for c in d {
            out.push(' ');
            if code == EDNS0_DAU { alg_append(out, c); } else { hash_name_append(out, c); }
        }
    } else if code == EDNS0_PADDING {
        out.append("\n; PADDING: ");
        hex_append(out, d, true);
    } else if code == EDNS0_EDE {
        out.append("\n; EDE: ");
        if d.len < 2 { return; }
        let info = get16(d, 0);
        format(out, info);
        if info < 31 { out.append(" ("); out.append(EDE_NAMES[info]); out.push(')'); }
        out.append(": (");
        out.append(d[2..]);
        out.push(')');
    } else if code == EDNS0_ESU {
        out.append("\n; ESU: ");
        out.append(d);
    } else if code == EDNS0_REPORTING {
        out.append("\n; REPORT-CHANNEL: ");
        if name_len_at(d, 0) == d.len { name_append(out, d); }
    } else if code == EDNS0_ZONEVERSION {
        out.append("\n; ZONEVERSION: ");
        if d.len > 2 { out.append(d[2..]); }
    } else {
        out.append("\n; LOCAL OPT: ");
        format(out, code);
        out.append(":0x");
        hex_append(out, d, false);
    }
}

// The OPT record as miekg's OPT.String(): the pseudosection.
fn opt_append_text(out: u8[>..]&, list: const u8[:], rr: Rr) {
    out.append("\n;; OPT PSEUDOSECTION:\n; EDNS: version ");
    format(out, opt_version(rr));
    out.append("; flags:");
    if opt_do(rr) { out.append(" do"); }
    if opt_co(rr) { out.append(" co"); }
    out.append("; ");
    let z = opt_z(rr);
    if z != 0 { out.append("MBZ: 0x"); format_uint(out, z, 16, 4, '0'); out.append(", "); }
    out.append("udp: ");
    format(out, opt_udp_size(rr));
    let rd = rr.rdata(list);
    each_option(rd) { o => option_append_text(out, o.code, o.data(rd)); };
}
