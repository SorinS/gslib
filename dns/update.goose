// dns.update: dynamic update (RFC 2136) messages, as miekg's Msg methods
// make them. The zone is the question; prerequisites go in the answer
// section, updates in the authority section, each from a list of records
// whose owners (and types and rdata, where they count) say what is meant.
//
//   var u = dns::Msg { .. };
//   dns::set_update(u, "example.org.");
//   dns::insert(u, rrs);              // add these records
//   dns::remove_rrset(u, old);        // delete these owners' RRsets of these types

namespace dns;

import std;
import dns;
import dns.msg;

// Makes m an update of the zone (miekg's SetUpdate): a fresh ID, opcode
// UPDATE, the zone's SOA as the question, class IN.
fn set_update(m: Msg&, zone: const u8[:]) -> i64 {
    let n, e = name_parse(zone, []);
    if e != OK { return e; }
    clear(m);
    m.hdr.id = new_id();
    m.hdr.opcode = OPCODE_UPDATE;
    return question_append(m.question, n, TYPE_SOA, CLASS_INET);
}

fn zone_class(m: const Msg&) -> u16 {
    each_question(m.question) { q => return q.qclass; };
    return CLASS_INET;
}

// A record with no rdata: owner, type, class, TTL 0.
fn empty_rr(list: u8[>..]&, owner: const u8[:], t: u16, class: u16) { rr_append(list, owner, t, class, 0, []); }

// The record with its class and TTL replaced.
fn rr_as(list: u8[>..]&, from: const u8[:], rr: Rr, class: u16, ttl: u32) {
    rr_append(list, rr.name(from), rr.rtype, class, ttl, rr.rdata(from));
}

// Prerequisite: each owner has some record (RFC 2136 §2.4.4).
fn name_used(m: Msg&, rrs: const u8[:]) { each_rr(rrs) { rr => empty_rr(m.answer, rr.name(rrs), TYPE_ANY, CLASS_ANY); }; }

// Prerequisite: each owner has no record (§2.4.5).
fn name_not_used(m: Msg&, rrs: const u8[:]) { each_rr(rrs) { rr => empty_rr(m.answer, rr.name(rrs), TYPE_ANY, CLASS_NONE); }; }

// Prerequisite: these exact records exist, value-dependent (§2.4.2).
fn used(m: Msg&, rrs: const u8[:]) {
    let c = zone_class(m);
    each_rr(rrs) { rr => rr_as(m.answer, rrs, rr, c, 0); };
}

// Prerequisite: each owner has an RRset of the type, value-independent (§2.4.1).
fn rrset_used(m: Msg&, rrs: const u8[:]) { each_rr(rrs) { rr => empty_rr(m.answer, rr.name(rrs), rr.rtype, CLASS_ANY); }; }

// Prerequisite: each owner has no RRset of the type (§2.4.3).
fn rrset_not_used(m: Msg&, rrs: const u8[:]) { each_rr(rrs) { rr => empty_rr(m.answer, rr.name(rrs), rr.rtype, CLASS_NONE); }; }

// Update: add the records (§2.5.1), in the zone's class.
fn insert(m: Msg&, rrs: const u8[:]) {
    let c = zone_class(m);
    each_rr(rrs) { rr => rr_as(m.ns, rrs, rr, c, rr.ttl); };
}

// Update: delete each owner's RRset of the type (§2.5.2).
fn remove_rrset(m: Msg&, rrs: const u8[:]) { each_rr(rrs) { rr => empty_rr(m.ns, rr.name(rrs), rr.rtype, CLASS_ANY); }; }

// Update: delete every RRset of each owner (§2.5.3).
fn remove_name(m: Msg&, rrs: const u8[:]) { each_rr(rrs) { rr => empty_rr(m.ns, rr.name(rrs), TYPE_ANY, CLASS_ANY); }; }

// Update: delete these exact records (§2.5.4).
fn remove(m: Msg&, rrs: const u8[:]) { each_rr(rrs) { rr => rr_as(m.ns, rrs, rr, CLASS_NONE, 0); }; }
