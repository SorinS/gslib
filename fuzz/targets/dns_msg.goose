// Fuzz target: dns_msg. The first byte picks a side:
//   0: a reply as a client reads it: unpack, every record walked and
//      written as text (msg_string's parts, a fixed clock), the rdata
//      accessors (SOA serial, RRSIG fields and verify_rrsig against the
//      message's own DNSKEYs, NSEC3 match/cover, DS, EDNS options), TSIG
//      and SIG(0) verification with fixed keys and clock, then pack,
//      unpack again, dedup and truncate.
//   1: a request as goose-dnsd takes it, with no socket: dns::server's
//      accept_check, unpack, error_reply and TSIG check (fixed secret and
//      clock), then dnsd's handler (its answer, transfer and apply_update,
//      copied from dns/tools/dnsd.goose, unkeyed as dnsd runs without -y)
//      over a fixed zone, and the reply truncated and packed.

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.rdata;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.tsig;
import gslib.dns.sig0;
import gslib.dns.dnssec;
import gslib.dns.update;
import gslib.dns.zone;
import gslib.dns.client;
import gslib.dns.server;

let NOW: i64 = 1800000000;

// "c2VjcmV0IGtleSBmb3IgZnV6eg==": "secret key for fuzz".
let TSIG_SECRET: const u8[:] = "secret key for fuzz";

let ZONE_TEXT: const u8[:] = "$TTL 3600\n@       IN SOA ns1 hostmaster 2024010101 7200 3600 1209600 300\n@       IN NS  ns1\n@       IN NS  ns2.example.net.\n@       IN MX  10 mail\n@       IN TXT \"v=spf1 -all\"\nns1     IN A   192.0.2.1\nmail    IN A   192.0.2.2\nmail    IN AAAA 2001:db8::2\nwww     IN CNAME web\nweb     IN A   192.0.2.3\n*.wild  IN A   192.0.2.4\nsub     IN NS  ns.sub\nns.sub  IN A   192.0.2.5\nsub     IN DS  12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n_sip._tcp IN SRV 0 5 5060 web\na.b.c   IN A   192.0.2.6\n";

var ZONE: u8[>..]   = [];
var APEX: dns::Name = [];

// --- Client side -------------------------------------------------------------------

fn text_of(list: const u8[:], out: u8[>..]&) {
    dns::each_rr(list) { rr =>
        if rr.rtype == dns::TYPE_TSIG || rr.rtype == dns::TYPE_OPT || rr.rtype == dns::TYPE_TKEY {
            dns::rr_append_text(out, list, rr);
        } else {
            dns::rr_header_append(out, list, rr);
            dns::rdata_append(out, rr.rtype, rr.rdata(list), NOW);
        }
        out.push('\n');
    };
}

fn probe_list(list: const u8[:], whole: const u8[:]) {
    var canon: u8[>..] = [];
    var sigs = 0;
    dns::each_rr(list) { rr =>
        let rd = rr.rdata(list);
        let owner = rr.name(list);
        let _ = dns::rdata_valid(rr.rtype, rd);
        canon.clear();
        dns::rdata_canonical(rr.rtype, rd, canon);
        let _ = dns::name_text(owner);
        let _ = dns::label_count(owner);
        if rr.rtype == dns::TYPE_SOA && rd.len > 0 { let _ = dns::soa_serial(rd); }
        if rr.rtype == dns::TYPE_RRSIG && rd.len > 0 {
            let _ = dns::rrsig_type_covered(rd);
            let _ = dns::rrsig_signer(rd);
            let _ = dns::rrsig_signature(rd);
            let _ = dns::validity_period(rd, NOW);
            // Against each DNSKEY of the whole message, over the records it covers.
            var set: u8[>..] = [];
            dns::each_rr(list) { x =>
                if x.rtype == dns::rrsig_type_covered(rd) && dns::name_equal(x.name(list), owner) { dns::rr_copy(set, list, x); }
            };
            dns::each_rr(whole) { k =>
                if k.rtype == dns::TYPE_DNSKEY && sigs < 4 {
                    sigs++;
                    let _ = dns::verify_rrsig(rd, set, k.name(whole), k.rdata(whole));
                }
            };
        }
        if (rr.rtype == dns::TYPE_DNSKEY || rr.rtype == dns::TYPE_KEY) && rd.len >= 4 {
            let _ = dns::key_tag(rd);
            let _ = dns::dnskey_flags(rd);
            var ds: u8[>..] = [];
            let _ = dns::ds_rdata(owner, rd, 2, ds);
        }
        if rr.rtype == dns::TYPE_NSEC3 && rd.len > 0 {
            // Iterations capped: uncapped NSEC3 iterations are a known finding (dnssec.goose:476).
            if rd.len >= 4 && dns::get16(rd, 2) <= 10 {
                let _ = dns::nsec3_match(owner, rd, owner);
                let _ = dns::nsec3_cover(owner, rd, APEX);
            }
        }
        if rr.rtype == dns::TYPE_OPT {
            dns::each_option(rd) { o => let _ = dns::data(o, rd); };
            let _ = dns::opt_version(rr);
            let _ = dns::opt_do(rr);
        }
    };
    var dd: u8[>..] = [];
    dns::dedup(list, dd);
    let _ = dns::list_valid(list);
}

fn client_side(w: const u8[:]) {
    var m = dns::Msg { .. };
    let e = dns::unpack(w, m);
    var out: u8[>..] = [];
    dns::header_append_text(out, m.hdr);
    dns::each_question(m.question) { q => dns::question_append_text(out, m.question, q); };
    text_of(m.answer, out);
    text_of(m.ns, out);
    text_of(m.extra, out);
    let opt = dns::opt_offset(m);
    if opt >= 0 { dns::opt_append_text(out, m.extra, dns::rr_at(m.extra, opt)); }
    let _ = dns::udp_size(m);
    let fo, fl, fok = dns::find_option(m, dns::EDNS0_COOKIE);
    probe_list(m.answer, m.answer);
    probe_list(m.ns, m.answer);
    probe_list(m.extra, m.answer);
    // Signatures over the raw message.
    let tk, ta, tke = dns::tsig_key(w);
    let mac, te = dns::tsig_verify(w, TSIG_SECRET, [], false, NOW);
    var stripped: u8[>..] = [];
    let _ = dns::tsig_strip(w, stripped);
    let key_rd = dns::dnskey_rdata(0x100, dns::ALG_ED25519, "0123456789abcdef0123456789abcdef");
    let _ = dns::sig0_verify(w, APEX, key_rd, NOW);
    // Round trip.
    if e == dns::OK {
        m.compress = true;
        var p: u8[>..] = [];
        if dns::pack(m, p) == dns::OK {
            var back = dns::Msg { .. };
            let _ = dns::unpack(p, back);
        }
        var r = dns::Msg { .. };
        dns::set_reply(r, m);
        r.answer.append(m.answer);
        r.ns.append(m.ns);
        r.extra.append(m.extra);
        dns::truncate(r, 512);
    }
}

// --- Server side: dnsd's handler -----------------------------------------------------

fn copy_set(list: const u8[:], owner: const u8[:], t: u16, as_owner: const u8[:], out: u8[>..]&) -> i64 {
    var n = 0;
    dns::each_rr(list) { rr =>
        if dns::name_equal(rr.name(list), owner) && (rr.rtype == t || (t == dns::TYPE_ANY && rr.rtype != dns::TYPE_RRSIG)) {
            dns::rr_append(out, as_owner, rr.rtype, rr.class, rr.ttl, rr.rdata(list));
            n++;
        }
    };
    return n;
}

fn copy_sigs(list: const u8[:], owner: const u8[:], t: u16, as_owner: const u8[:], out: u8[>..]&) {
    dns::each_rr(list) { rr =>
        if rr.rtype == dns::TYPE_RRSIG && dns::name_equal(rr.name(list), owner) && dns::get16(rr.rdata(list), 0) == t {
            dns::rr_append(out, as_owner, rr.rtype, rr.class, rr.ttl, rr.rdata(list));
        }
    };
}

fn has_name(list: const u8[:], n: const u8[:]) -> bool {
    dns::each_rr(list) { rr => if dns::name_equal(rr.name(list), n) { return true; } };
    return false;
}

fn has_below(list: const u8[:], n: const u8[:]) -> bool {
    dns::each_rr(list) { rr => if dns::is_subdomain(n, rr.name(list)) { return true; } };
    return false;
}

fn has_type(list: const u8[:], n: const u8[:], t: u16) -> bool {
    dns::each_rr(list) { rr => if rr.rtype == t && dns::name_equal(rr.name(list), n) { return true; } };
    return false;
}

fn add_soa(list: const u8[:], apex: const u8[:], out: u8[>..]&, dnssec: bool) {
    dns::each_rr(list) { rr =>
        if rr.rtype == dns::TYPE_SOA && dns::name_equal(rr.name(list), apex) {
            let rd = rr.rdata(list);
            let a = dns::name_len_at(rd, 0);
            let b = dns::name_len_at(rd, a);
            let minimum = dns::get32(rd, a + b + 16);
            dns::rr_append(out, rr.name(list), rr.rtype, rr.class, if minimum < rr.ttl { minimum } else { rr.ttl }, rd);
        }
    };
    if dnssec { copy_sigs(list, apex, dns::TYPE_SOA, apex, out); }
}

fn add_glue(list: const u8[:], from: const u8[:], out: u8[>..]&) {
    dns::each_rr(from) { rr =>
        let rd = rr.rdata(from);
        var p = -1;
        if rr.rtype == dns::TYPE_NS { p = 0; } else if rr.rtype == dns::TYPE_MX { p = 2; } else if rr.rtype == dns::TYPE_SRV { p = 6; }
        if p >= 0 && p < rd.len {
            let target = rd[p..p + dns::name_len_at(rd, p)];
            copy_set(list, target, dns::TYPE_A, target, out);
            copy_set(list, target, dns::TYPE_AAAA, target, out);
        }
    };
}

fn answer(list: const u8[:], apex: const u8[:], req: const dns::Msg&, resp: dns::Msg&, qname0: const u8[:], qtype: u16) {
    let dnssec = dns::opt_offset(req) >= 0 && dns::opt_do(dns::rr_at(req.extra, dns::opt_offset(req)));
    resp.hdr.authoritative = true;
    var qname: dns::Name = [];
    qname.append(qname0);
    var hops = 0;
    while hops < 8 {
        hops++;
        let n = dns::label_count(qname);
        let an = dns::label_count(apex);
        var k = an + 1;
        while k <= n {
            let cut = dns::name_suffix(qname, n - k);
            if has_type(list, cut, dns::TYPE_NS) && !(qtype == dns::TYPE_DS && k == n) {
                if resp.answer.len == 0 { resp.hdr.authoritative = false; }
                copy_set(list, cut, dns::TYPE_NS, cut, resp.ns);
                if dnssec { copy_set(list, cut, dns::TYPE_DS, cut, resp.ns); copy_sigs(list, cut, dns::TYPE_DS, cut, resp.ns); }
                add_glue(list, resp.ns, resp.extra);
                return;
            }
            k++;
        }
        var owner: dns::Name = [];
        owner.append(qname);
        if !has_name(list, qname) {
            if has_below(list, qname) { add_soa(list, apex, resp.ns, dnssec); return; }
            var ce = 1;
            while ce < n - an && !has_below(list, dns::name_suffix(qname, ce)) { ce++; }
            let w = dns::wildcard_of_labels(qname, n - ce);
            if !has_name(list, w) {
                if resp.answer.len == 0 { resp.hdr.rcode = dns::RCODE_NAME_ERROR; }
                add_soa(list, apex, resp.ns, dnssec);
                return;
            }
            owner = w;
        }
        if copy_set(list, owner, qtype, qname, resp.answer) > 0 {
            if dnssec { copy_sigs(list, owner, qtype, qname, resp.answer); }
            add_glue(list, resp.answer, resp.extra);
            return;
        }
        if qtype != dns::TYPE_CNAME && copy_set(list, owner, dns::TYPE_CNAME, qname, resp.answer) > 0 {
            if dnssec { copy_sigs(list, owner, dns::TYPE_CNAME, qname, resp.answer); }
            var target: dns::Name = [];
            dns::each_rr(list) { rr => if rr.rtype == dns::TYPE_CNAME && dns::name_equal(rr.name(list), owner) { target.clear(); target.append(rr.rdata(list)); } };
            if !dns::is_subdomain(apex, target) { return; }
            qname = target;
            continue;
        }
        add_soa(list, apex, resp.ns, dnssec);
        return;
    }
}

fn transfer(list: const u8[:], apex: const u8[:], resp: dns::Msg&) {
    var soa: u8[>..] = [];
    copy_set(list, apex, dns::TYPE_SOA, apex, soa);
    resp.answer.append(soa);
    dns::each_rr(list) { rr => if rr.rtype != dns::TYPE_SOA || !dns::name_equal(rr.name(list), apex) { dns::rr_copy(resp.answer, list, rr); } };
    resp.answer.append(soa);
    resp.hdr.authoritative = true;
}

// dnsd's apply_update, over a copy of the zone (zone_out takes the result).
fn apply_update(zone: const u8[:], apex: const u8[:], req: const dns::Msg&, zone_out: u8[>..]&) -> u16 {
    var list: u8[>..] = [];
    list.append(zone);
    var zclass = dns::CLASS_INET;
    dns::each_question(req.question) { q => zclass = q.qclass; };
    var rc = dns::RCODE_SUCCESS;
    dns::each_rr(req.answer) { p =>
        if rc == dns::RCODE_SUCCESS {
            let n = p.name(req.answer);
            if !dns::is_subdomain(apex, n) { rc = dns::RCODE_NOT_ZONE; }
            else if p.class == dns::CLASS_ANY {
                let ok = if p.rtype == dns::TYPE_ANY { has_name(list, n) } else { has_type(list, n, p.rtype) };
                if !ok { rc = if p.rtype == dns::TYPE_ANY { dns::RCODE_NAME_ERROR } else { dns::RCODE_NXRRSET }; }
            } else if p.class == dns::CLASS_NONE {
                let bad = if p.rtype == dns::TYPE_ANY { has_name(list, n) } else { has_type(list, n, p.rtype) };
                if bad { rc = if p.rtype == dns::TYPE_ANY { dns::RCODE_YXDOMAIN } else { dns::RCODE_YXRRSET }; }
            } else {
                var found = false;
                dns::each_rr(list) { rr => if dns::rr_duplicate(list, rr, req.answer, p) { found = true; } };
                if !found { rc = dns::RCODE_NXRRSET; }
            }
        }
    };
    if rc != dns::RCODE_SUCCESS { return rc; }
    dns::each_rr(req.ns) { u =>
        let n = u.name(req.ns);
        if !dns::is_subdomain(apex, n) { rc = dns::RCODE_NOT_ZONE; }
    };
    if rc != dns::RCODE_SUCCESS { return rc; }
    dns::each_rr(req.ns) { u =>
        let n = u.name(req.ns);
        var next: u8[>..] = [];
        if u.class == zclass {
            next.append(list);
            var dup = false;
            dns::each_rr(list) { rr => if dns::rr_duplicate(list, rr, req.ns, u) { dup = true; } };
            if !dup { dns::rr_copy(next, req.ns, u); }
        } else {
            dns::each_rr(list) { rr =>
                let same_name = dns::name_equal(rr.name(list), n);
                let apex_keep = dns::name_equal(n, apex) && (rr.rtype == dns::TYPE_SOA || rr.rtype == dns::TYPE_NS);
                var drop = false;
                if u.class == dns::CLASS_ANY && u.rtype == dns::TYPE_ANY { drop = same_name && !apex_keep; }
                else if u.class == dns::CLASS_ANY { drop = same_name && rr.rtype == u.rtype && !apex_keep; }
                else if u.class == dns::CLASS_NONE {
                    drop = rr.rtype == u.rtype && rr.class == zclass && same_name &&
                           rr.rdata(list) == u.rdata(req.ns) && !(apex_keep && rr.rtype == dns::TYPE_SOA);
                }
                if !drop { dns::rr_copy(next, list, rr); }
            };
        }
        list.clear();
        list.append(next);
    };
    zone_out.clear();
    zone_out.append(list);
    return dns::RCODE_SUCCESS;
}

// dns::server's handle, without a socket, a clock or a random ID.
fn server_side(w: const u8[:]) {
    var out: u8[>..] = [];
    let ac = dns::accept_check(w);
    if ac == 0xFFFF { return; }
    if ac != dns::RCODE_SUCCESS { dns::error_reply(w, ac, out); return; }
    var req = dns::Msg { .. };
    let ue = dns::unpack(w, req);
    if ue != dns::OK { dns::error_reply(w, dns::RCODE_FORMAT_ERROR, out); return; }
    let toff, trd, te = dns::find_tsig(w);
    if te == dns::OK {
        let kn, an, ke = dns::tsig_key(w);
        let _ = dns::tsig_hash(dns::name_text(an));
        let mac, ve = dns::tsig_verify(w, TSIG_SECRET, [], false, NOW);
        var ex: u8[>..] = [];
        dns::each_rr(req.extra) { rr => if rr.rtype != dns::TYPE_TSIG { dns::rr_copy(ex, req.extra, rr); } };
        req.extra.clear();
        req.extra.append(ex);
        if ve != dns::OK {
            var r = dns::Msg { .. };
            dns::set_reply(r, req);
            r.hdr.rcode = dns::RCODE_NOT_AUTH;
            dns::pack(r, out);
            var other: u8[>..] = [];
            let m2, e2 = dns::tsig_sign_error(out, dns::name_text(kn), dns::name_text(an), TSIG_SECRET, 300, NOW, mac, false,
                                              dns::RCODE_BAD_SIG, other);
            return;
        }
    }
    var resp = dns::Msg { .. };
    dns::set_reply(resp, req);
    // dnsd's handler.
    var qname: dns::Name = [];
    var qtype: u16       = 0;
    dns::each_question(req.question) { q => qname.clear(); qname.append(q.name(req.question)); qtype = q.qtype; };
    if dns::opt_offset(req) >= 0 {
        let o = dns::rr_at(req.extra, dns::opt_offset(req));
        dns::set_edns0(resp, 1232, dns::opt_do(o));
    }
    if !dns::is_subdomain(APEX, qname) { resp.hdr.rcode = dns::RCODE_REFUSED; }
    else if req.hdr.opcode == dns::OPCODE_NOTIFY { resp.hdr.authoritative = true; }
    else if req.hdr.opcode == dns::OPCODE_UPDATE {
        if !dns::name_equal(qname, APEX) { resp.hdr.rcode = dns::RCODE_NOT_AUTH; }
        else {
            var z: u8[>..] = [];
            resp.hdr.rcode = apply_update(ZONE, APEX, req, z);
            // The zone after it, as dnsd then answers from it.
            if resp.hdr.rcode == dns::RCODE_SUCCESS {
                var r2 = dns::Msg { .. };
                answer(z, APEX, req, r2, APEX, dns::TYPE_SOA);
                var r3 = dns::Msg { .. };
                transfer(z, APEX, r3);
                var p3: u8[>..] = [];
                let _ = dns::pack(r3, p3);
                var t: u8[>..] = [];
                text_of(z, t);
            }
        }
    }
    else if qtype == dns::TYPE_AXFR || qtype == dns::TYPE_IXFR {
        if !dns::name_equal(qname, APEX) { resp.hdr.rcode = dns::RCODE_REFUSED; }
        else { transfer(ZONE, APEX, resp); }
    }
    else { answer(ZONE, APEX, req, resp, qname, qtype); }
    dns::truncate(resp, dns::udp_size(req));
    let e = dns::pack(resp, out);
    if e != dns::OK { out.clear(); dns::error_reply(w, dns::RCODE_SERVER_FAILURE, out); }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let rest = data[1..];
    if data[0] % 2 == 0 { client_side(rest); } else { server_side(rest); }
    return 0;
}

fn main() {
    let o, oe = dns::name_parse("example.org.", []);
    APEX.append(o);
    var opts = dns::ZoneOptions { .. };
    opts.origin = o;
    let r = dns::parse_zone(ZONE_TEXT, opts, ZONE);
    assert(r.err == dns::OK);
}
