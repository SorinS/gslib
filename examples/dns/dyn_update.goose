// dyn_update: a dynamic update (RFC 2136), as nsupdate sends one. The
// client builds it: the zone, prerequisites (a name must be free, an
// RRset must exist), then records added, one removed, an RRset and a
// whole name deleted; packs it and prints it. The server unpacks it,
// checks the prerequisites against its zone, and applies the changes
// record by record, reading each one's class as RFC 2136 §2.5 says.
//
//   goose examples/dns/dyn_update.goose

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.update;

// The records of list that match name, type (TYPE_ANY: every type) and,
// when rd is given, rdata; the rest are kept.
fn remove_matching(list: u8[>..]&, name: const u8[:], t: u16, rd: const u8[:], whole_rrset: bool) {
    var kept: u8[>..] = [];
    dns::each_rr(list) { rr =>
        let hit = dns::name_equal(rr.name(list), name) && (t == dns::TYPE_ANY || rr.rtype == t)
                  && (whole_rrset || rr.rdata(list) == rd);
        if !hit { dns::rr_copy(kept, list, rr); }
    };
    list.clear();
    list.append(kept);
}

fn exists(list: const u8[:], name: const u8[:], t: u16) -> bool {
    var found = false;
    dns::each_rr(list) { rr => if dns::name_equal(rr.name(list), name) && (t == dns::TYPE_ANY || rr.rtype == t) { found = true; } };
    return found;
}

fn main() {
    // The server's zone.
    var zone: u8[>..] = [];
    var opts = dns::ZoneOptions { .. };
    let origin, oe = dns::name_parse("example.com.", []);
    opts.origin = origin;
    let zr = dns::parse_zone("$TTL 300\n@ SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ NS ns1\nns1 A 192.0.2.1\nwww A 192.0.2.80\nwww A 192.0.2.81\nold A 192.0.2.9\nold TXT \"to go\"\n", opts, zone);
    guard zr.err == dns::OK else { print("dyn_update: zone: ", zr.msg); exit(1); }

    // Client: the update.
    var newhost: u8[>..] = [];
    dns::new_rr(newhost, "api.example.com. 300 IN A 192.0.2.50");
    dns::new_rr(newhost, "api.example.com. 300 IN AAAA 2001:db8::50");
    var www: u8[>..] = [];
    dns::new_rr(www, "www.example.com. 300 IN A 192.0.2.81");
    var old: u8[>..] = [];
    dns::new_rr(old, "old.example.com. 300 IN A 192.0.2.9");
    var m = dns::Msg { .. };
    dns::set_update(m, "example.com.");
    // Each helper makes one entry per record given: one record names api.
    let first = newhost[..dns::rr_at(newhost, 0).end];
    dns::name_not_used(m, first);      // prerequisite: api.example.com. has no records yet
    dns::rrset_used(m, www);           // prerequisite: www.example.com. has an A RRset
    dns::insert(m, newhost);           // add api's A and AAAA
    dns::remove(m, www);               // remove that one A record of www
    dns::remove_name(m, old);          // remove everything at old.example.com.
    var w: u8[>..] = [];
    guard dns::pack(m, w) == dns::OK else { print("dyn_update: pack"); exit(1); }
    print(dns::msg_string(m));
    print("packed: ", w.len, " bytes");

    // Server: the zone section names the zone; the prerequisites (in the
    // answer section) are checked first; then the updates (in authority).
    var u = dns::Msg { .. };
    guard dns::unpack(w, u) == dns::OK && u.hdr.opcode == dns::OPCODE_UPDATE else { print("dyn_update: unpack"); exit(1); }
    var ok = true;
    dns::each_rr(u.answer) { rr =>
        let n = rr.name(u.answer);
        if rr.class == dns::CLASS_ANY { ok = ok && exists(zone, n, rr.rtype); }        // must exist
        else if rr.class == dns::CLASS_NONE { ok = ok && !exists(zone, n, rr.rtype); } // must not
    };
    guard ok else { print("dyn_update: a prerequisite failed (the server would answer NXRRSET or YXDOMAIN)"); exit(1); }
    var added = 0;
    var removed = dns::rr_count(zone);
    dns::each_rr(u.ns) { rr =>
        let n = rr.name(u.ns);
        if rr.class == dns::zone_class(u) { dns::rr_copy(zone, u.ns, rr); added++; }              // add
        else if rr.class == dns::CLASS_ANY { remove_matching(zone, n, rr.rtype, [], true); }     // delete an RRset, or all
        else if rr.class == dns::CLASS_NONE { remove_matching(zone, n, rr.rtype, rr.rdata(u.ns), false); } // delete one
    };
    removed = removed + added - dns::rr_count(zone);
    print("applied: ", added, " records added, ", removed, " removed; the zone now:");
    dns::each_rr(zone) { rr => print("  ", dns::rr_string(zone, rr)); };
    let api, ae = dns::name_parse("api.example.com.", []);
    let oldn, ole = dns::name_parse("old.example.com.", []);
    guard added == 2 && removed == 3 && exists(zone, api, dns::TYPE_AAAA) && !exists(zone, oldn, dns::TYPE_ANY) else {
        print("dyn_update: the zone is not as it should be");
        exit(1);
    }
}
