// goose-dnsd: an authoritative server for zone files, on dns.server:
//
//   goose-dnsd [-a address] [-p port] [-y [alg:]name:secret] [-u] [-n requests] [-v] origin=file ...
//
// Answers from the zones it was given (the longest origin that holds the
// name; REFUSED for others): the records of the name and type, CNAMEs
// followed within the zone, wildcards (RFC 4592), referrals at zone cuts
// with glue, NXDOMAIN and NODATA with the SOA (its TTL capped by its
// minimum), RRSIGs from the zone when the query has the DO bit, A and AAAA
// of in-zone MX, NS and SRV targets. AXFR and IXFR (always the whole zone,
// as RFC 1995 §4 allows) over TCP; NOTIFY acknowledged; dynamic updates
// (RFC 2136) applied in memory. Transfers and updates must be signed with
// the TSIG key -y gives (base64 secret; the algorithm, hmac-sha256 and the
// others tsig knows, pins it when given); without -y they are REFUSED,
// unless -u allows them unsigned from anyone. Signed queries are checked.
// Port 53 unless -p (0 for any: the port taken is printed as "listening
// on <port>"). -n stops after that many requests.
import std;
import os;
import gslib from "../..";
import gslib.dns;
import gslib.dns.rdata;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;
import gslib.dns.server;
import gslib.dns.update;

struct ZoneAt { origin: dns::Name, start: i64, end: i64 }

root struct Zones {
    data: u8[>..] = [],
    at: ZoneAt[..16] = [],
    verbose: bool = false,
}

fn usage() -> i32 {
    write_stderr("usage: goose-dnsd [-a address] [-p port] [-y [alg:]name:secret] [-u] [-n requests] [-v] origin=file ...\n");
    return 2;
}

fn fail(s: const u8[:]) -> i32 {
    write_stderr(str("goose-dnsd: ", s, "\n"));
    return 1;
}

// The zone holding name: its index, -1 for none.
fn zone_of(z: const Zones&, n: const u8[:]) -> i64 {
    var best = -1;
    var best_labels = -1;
    for i in z.at.len {
        if dns::is_subdomain(z.at[i].origin, n) && dns::label_count(z.at[i].origin) > best_labels {
            best = i;
            best_labels = dns::label_count(z.at[i].origin);
        }
    }
    return best;
}

fn records(z: const Zones&, zi: i64) -> const u8[:] { z.data[z.at[zi].start .. z.at[zi].end] }

// Copies the records of owner (and type t, or every type for TYPE_ANY;
// RRSIGs only when t is RRSIG) onto out, their owner replaced by as_owner.
// How many.
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

// The RRSIGs over owner's RRset of type t.
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

// Whether some record is at or below n (an empty non-terminal has some below).
fn has_below(list: const u8[:], n: const u8[:]) -> bool {
    dns::each_rr(list) { rr => if dns::is_subdomain(n, rr.name(list)) { return true; } };
    return false;
}

fn has_type(list: const u8[:], n: const u8[:], t: u16) -> bool {
    dns::each_rr(list) { rr => if rr.rtype == t && dns::name_equal(rr.name(list), n) { return true; } };
    return false;
}

// The SOA, its TTL capped by its minimum, for a negative answer.
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

// A and AAAA for the in-zone targets of MX, NS and SRV records in from.
fn add_glue(list: const u8[:], from: const u8[:], out: u8[>..]&) {
    dns::each_rr(from) { rr =>
        let rd = rr.rdata(from);
        var p = -1;
        if rr.rtype == dns::TYPE_NS { p = 0; } else if rr.rtype == dns::TYPE_MX { p = 2; } else if rr.rtype == dns::TYPE_SRV { p = 6; }
        if p >= 0 && p < rd.len {
            let target = rd[p .. p + dns::name_len_at(rd, p)];
            copy_set(list, target, dns::TYPE_A, target, out);
            copy_set(list, target, dns::TYPE_AAAA, target, out);
        }
    };
}

// The answer to an ordinary query.
fn answer(z: const Zones&, zi: i64, req: const dns::Msg&, resp: dns::Msg&, qname0: const u8[:], qtype: u16) {
    let list = records(z, zi);
    let apex = z.at[zi].origin;
    let dnssec = dns::opt_offset(req) >= 0 && dns::opt_do(dns::rr_at(req.extra, dns::opt_offset(req)));
    resp.hdr.authoritative = true;
    var qname: dns::Name = [];
    qname.append(qname0);
    var hops = 0;
    while hops < 8 {
        hops++;
        // A zone cut on the way down: a referral (but DS at the cut is the parent's).
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
            if has_below(list, qname) { add_soa(list, apex, resp.ns, dnssec); return; }      // NODATA
            // A wildcard at the closest encloser?
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
            if dnssec {
                if qtype == dns::TYPE_ANY {
                    dns::each_rr(list) { rr => if rr.rtype == dns::TYPE_RRSIG && dns::name_equal(rr.name(list), owner) { dns::rr_append(resp.answer, qname, rr.rtype, rr.class, rr.ttl, rr.rdata(list)); } };
                } else {
                    copy_sigs(list, owner, qtype, qname, resp.answer);
                }
            }
            add_glue(list, resp.answer, resp.extra);
            return;
        }
        if qtype != dns::TYPE_CNAME && copy_set(list, owner, dns::TYPE_CNAME, qname, resp.answer) > 0 {
            if dnssec { copy_sigs(list, owner, dns::TYPE_CNAME, qname, resp.answer); }
            // Follow it if it stays in the zone.
            var target: dns::Name = [];
            dns::each_rr(list) { rr => if rr.rtype == dns::TYPE_CNAME && dns::name_equal(rr.name(list), owner) { target.clear(); target.append(rr.rdata(list)); } };
            if !dns::is_subdomain(apex, target) { return; }
            qname = target;
            continue;
        }
        add_soa(list, apex, resp.ns, dnssec);       // NODATA
        return;
    }
}

// The whole zone, SOA first and last.
fn transfer(z: const Zones&, zi: i64, resp: dns::Msg&) {
    let list = records(z, zi);
    let apex = z.at[zi].origin;
    var soa: u8[>..] = [];
    copy_set(list, apex, dns::TYPE_SOA, apex, soa);
    resp.answer.append(soa);
    dns::each_rr(list) { rr => if rr.rtype != dns::TYPE_SOA || !dns::name_equal(rr.name(list), apex) { dns::rr_copy(resp.answer, list, rr); } };
    resp.answer.append(soa);
    resp.hdr.authoritative = true;
}

// Replaces zone zi's records with list.
fn set_zone(z: Zones&, zi: i64, list: const u8[:]) {
    var data: u8[>..] = [];
    for i in z.at.len {
        let start = data.len;
        if i == zi { data.append(list); } else { data.append(z.data[z.at[i].start .. z.at[i].end]); }
        z.at[i].start = start;
        z.at[i].end = data.len;
    }
    z.data.clear();
    z.data.append(data);
}

// Query and meta types (RFC 6895 §3.1), which no record in a zone has.
fn is_meta(t: u16) -> bool { t == dns::TYPE_OPT || (t >= 128 && t <= 255) }

// RFC 1982's serial a > b.
fn serial_gt(a: u32, b: u32) -> bool { a != b && (b - a) & 0x80000000 != 0 }

fn soa_serial(rd: const u8[:]) -> u32 {
    let a = dns::name_len_at(rd, 0);
    return dns::get32(rd, a + dns::name_len_at(rd, a));
}

// RFC 2136 §3.2's checks of a prerequisite's form: FORMERR or NOERROR.
fn prereq_form(p: dns::Rr, zclass: u16) -> u16 {
    if p.ttl != 0 { return dns::RCODE_FORMAT_ERROR; }
    if p.class == dns::CLASS_ANY || p.class == dns::CLASS_NONE {
        if p.end != p.rd || (is_meta(p.rtype) && p.rtype != dns::TYPE_ANY) { return dns::RCODE_FORMAT_ERROR; }
    } else if p.class != zclass || is_meta(p.rtype) {
        return dns::RCODE_FORMAT_ERROR;
    }
    return dns::RCODE_SUCCESS;
}

// RFC 2136 §3.4.1's prescan of one update: FORMERR or NOERROR.
fn update_form(list: const u8[:], u: dns::Rr, zclass: u16) -> u16 {
    if u.class == zclass {
        if is_meta(u.rtype) || u.end == u.rd || !dns::rdata_valid(u.rtype, u.rdata(list)) { return dns::RCODE_FORMAT_ERROR; }
    } else if u.class == dns::CLASS_ANY {
        if u.ttl != 0 || u.end != u.rd || (is_meta(u.rtype) && u.rtype != dns::TYPE_ANY) { return dns::RCODE_FORMAT_ERROR; }
    } else if u.class == dns::CLASS_NONE {
        if u.ttl != 0 || is_meta(u.rtype) { return dns::RCODE_FORMAT_ERROR; }
    } else {
        return dns::RCODE_FORMAT_ERROR;
    }
    return dns::RCODE_SUCCESS;
}

fn count_type(list: const u8[:], n: const u8[:], t: u16) -> i64 {
    var k = 0;
    dns::each_rr(list) { rr => if rr.rtype == t && dns::name_equal(rr.name(list), n) { k++; } };
    return k;
}

// RFC 2136 §3: the prerequisites checked, every update prescanned, then the
// updates applied; the rcode. The zone keeps one SOA (an added one replaces
// it when its serial is newer, §3.4.2.2) and at least one NS at its apex.
fn apply_update(z: Zones&, zi: i64, req: const dns::Msg&) -> u16 {
    let apex = z.at[zi].origin;
    var list: u8[>..] = [];
    list.append(records(z, zi));
    var zclass = dns::CLASS_INET;
    dns::each_question(req.question) { q => zclass = q.qclass; };
    var rc = dns::RCODE_SUCCESS;
    dns::each_rr(req.answer) { p =>
        if rc == dns::RCODE_SUCCESS {
            let n = p.name(req.answer);
            rc = prereq_form(p, zclass);
            if rc != dns::RCODE_SUCCESS {}
            else if !dns::is_subdomain(apex, n) { rc = dns::RCODE_NOT_ZONE; }
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
        if rc == dns::RCODE_SUCCESS {
            if !dns::is_subdomain(apex, u.name(req.ns)) { rc = dns::RCODE_NOT_ZONE; }
            else { rc = update_form(req.ns, u, zclass); }
        }
    };
    if rc != dns::RCODE_SUCCESS { return rc; }
    dns::each_rr(req.ns) { u =>
        let n = u.name(req.ns);
        let at_apex = dns::name_equal(n, apex);
        var next: u8[>..] = [];
        if u.class == zclass && u.rtype == dns::TYPE_SOA {
            // Only the apex's, and only a newer one, which replaces the old.
            var newer = false;
            dns::each_rr(list) { rr => if rr.rtype == dns::TYPE_SOA && serial_gt(soa_serial(u.rdata(req.ns)), soa_serial(rr.rdata(list))) { newer = true; } };
            if at_apex && newer {
                dns::each_rr(list) { rr => if rr.rtype != dns::TYPE_SOA || !dns::name_equal(rr.name(list), apex) { dns::rr_copy(next, list, rr); } };
                dns::rr_copy(next, req.ns, u);
            } else {
                next.append(list);
            }
        } else if u.class == zclass {
            next.append(list);
            var dup = false;
            dns::each_rr(list) { rr => if dns::rr_duplicate(list, rr, req.ns, u) { dup = true; } };
            if !dup { dns::rr_copy(next, req.ns, u); }
        } else {
            var apex_ns = count_type(list, apex, dns::TYPE_NS);
            dns::each_rr(list) { rr =>
                let same_name = dns::name_equal(rr.name(list), n);
                let apex_keep = at_apex && (rr.rtype == dns::TYPE_SOA || rr.rtype == dns::TYPE_NS);
                var drop = false;
                if u.class == dns::CLASS_ANY && u.rtype == dns::TYPE_ANY { drop = same_name && !apex_keep; }
                else if u.class == dns::CLASS_ANY { drop = same_name && rr.rtype == u.rtype && !apex_keep; }
                else if u.class == dns::CLASS_NONE {
                    drop = rr.rtype == u.rtype && rr.class == zclass && same_name && rr.rdata(list) == u.rdata(req.ns) &&
                           !(at_apex && rr.rtype == dns::TYPE_SOA) && !(at_apex && rr.rtype == dns::TYPE_NS && apex_ns <= 1);
                    if drop && at_apex && rr.rtype == dns::TYPE_NS { apex_ns--; }
                }
                if !drop { dns::rr_copy(next, list, rr); }
            };
        }
        list.clear();
        list.append(next);
    };
    set_zone(z, zi, list);
    return dns::RCODE_SUCCESS;
}

// Who may change a zone, or take all of it: the key's holder (with -y);
// without a key, anyone if -u says so, else no one.
fn may_write(keyed: bool, unsigned_ok: bool, peer: const dns::Peer&) -> bool {
    return if keyed { peer.tsig == dns::OK } else { unsigned_ok };
}

fn run() -> i32 {
    let a = args();
    var cfg = dns::ServerConfig { .. };
    var z = Zones { .. };
    var unsigned_ok = false;
    var i = 1;
    while i < a.len {
        let s = a[i];
        if s == "-a" && i + 1 < a.len { i++; cfg.addr.clear(); cfg.addr.append(a[i]); }
        else if s == "-p" && i + 1 < a.len { i++; let n, ok = parse_int(a[i]); if !ok || n < 0 || n > 65535 { return usage(); } cfg.port = n as! i32; }
        else if s == "-n" && i + 1 < a.len { i++; let n, ok = parse_int(a[i]); if !ok || n < 0 { return usage(); } cfg.max_requests = n; }
        else if s == "-y" && i + 1 < a.len {
            i++;
            // [alg:]name:secret, as dig's -y.
            let first, rest, ok = split_once(a[i], ':');
            if !ok { return usage(); }
            var kn = first;
            var sec = rest;
            let k2, s2, three = split_once(rest, ':');
            if three {
                if dns::tsig_hash(first) == 0 || first.len + 1 > 64 { return fail(str("unknown TSIG algorithm ", first)); }
                cfg.tsig_alg.append(first);
                if !dns::is_fqdn(first) { cfg.tsig_alg.push('.'); }
                kn = k2;
                sec = s2;
            }
            if kn.len == 0 || kn.len + 1 > 255 { return fail("bad TSIG key name"); }
            let sb, sok = dns::tsig_secret(sec);
            if !sok || sec.len > 128 { return fail("bad TSIG secret (base64, at most 128 characters)"); }
            cfg.tsig_name.append(kn);
            if !dns::is_fqdn(kn) { cfg.tsig_name.push('.'); }
            cfg.tsig_secret.append(sec);
        }
        else if s == "-u" { unsigned_ok = true; }
        else if s == "-v" { z.verbose = true; }
        else {
            let origin, file, ok = split_once(s, '=');
            if !ok || z.at.len >= 16 { return usage(); }
            var opts = dns::ZoneOptions { .. };
            let on, oe = dns::name_parse(origin, []);
            if oe != dns::OK { return fail(str("bad origin ", origin)); }
            opts.origin = on;
            opts.include = true;
            opts.file.append(file);
            var text: u8[>..] = [];
            if !read_file(file, text) { return fail(str("cannot read ", file)); }
            let start = z.data.len;
            let r = dns::parse_zone(text, opts, z.data);
            if r.err != dns::OK { return fail(str(file, ":", r.line, ": ", r.msg)); }
            z.at.push(ZoneAt { on, start, z.data.len });
            if !has_type(records(z, z.at.len - 1), on, dns::TYPE_SOA) { return fail(str(file, ": no SOA at ", origin)); }
        }
        i++;
    }
    if z.at.len == 0 { return usage(); }
    var srv = dns::server_open(cfg);
    if srv.err != dns::OK { return fail("cannot listen"); }
    print(str("listening on ", srv.port));
    flush_stdout();
    let keyed = cfg.tsig_name.len > 0;
    dns::serve(srv, cfg) { req, resp, peer =>
        var qname: dns::Name = [];
        var qtype: u16 = 0;
        dns::each_question(req.question) { q => qname.clear(); qname.append(q.name(req.question)); qtype = q.qtype; };
        if dns::opt_offset(req) >= 0 {
            let o = dns::rr_at(req.extra, dns::opt_offset(req));
            dns::set_edns0(resp, 1232, dns::opt_do(o));
        }
        let zi = zone_of(z, qname);
        if z.verbose { write_stderr(str(if peer.tcp { "tcp " } else { "udp " }, peer.addr, " ", dns::name_text(qname), " ", dns::type_string(qtype), "\n")); }
        if zi < 0 { resp.hdr.rcode = dns::RCODE_REFUSED; }
        else if req.hdr.opcode == dns::OPCODE_NOTIFY { resp.hdr.authoritative = true; }
        else if req.hdr.opcode == dns::OPCODE_UPDATE {
            if !may_write(keyed, unsigned_ok, peer) { resp.hdr.rcode = dns::RCODE_REFUSED; }
            else if !dns::name_equal(qname, z.at[zi].origin) { resp.hdr.rcode = dns::RCODE_NOT_AUTH; }
            else { resp.hdr.rcode = apply_update(z, zi, req); }
        }
        else if qtype == dns::TYPE_AXFR || qtype == dns::TYPE_IXFR {
            if !peer.tcp || !may_write(keyed, unsigned_ok, peer) || !dns::name_equal(qname, z.at[zi].origin) { resp.hdr.rcode = dns::RCODE_REFUSED; }
            else { transfer(z, zi, resp); }
        }
        else { answer(z, zi, req, resp, qname, qtype); }
    };
    return 0;
}

fn main() { exit(run()); }
