// Name functions, resolv.conf, dynamic update messages and EDNS0 options
// against miekg/dns (vectors/misc.txt, from scripts/oracle): label counts,
// splitting, Fqdn, CanonicalName, IsDomainName, CompareDomainName,
// IsSubDomain, ReverseAddr, ClientConfig and NameList; an update made
// with every helper packed into miekg's bytes and written as its text;
// an OPT record with subnet, keepalive, EDE, padding, expire and local
// options the same bytes and text; messages truncated to the same bytes.
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;
import gslib.dns.client;
import gslib.dns.update;
import tv;

fn unhex(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i + 1 < s.len { out.push((tv::unhex(s[i]) << 4) | tv::unhex(s[i + 1])); i += 2; }
}

fn check_name(r: tv::Row&) {
    let n = r.next();
    let count = r.next_int();
    let split = r.next();
    let fq = r.next();
    let canon = r.next();
    let isd = r.next() == "true";
    let labels, ok = dns::is_domain_name(n);
    tv::check(str("is domain name: ", n), ok == isd);
    if !isd { return; }
    tv::check_int(str("labels: ", n), labels, count);
    var joined: u8[>..] = [];
    var first = true;
    for l in dns::split_domain_name(n) { if !first { joined.push(','); } first = false; joined.append(l); }
    tv::check_eq(str("split: ", n), joined, split);
    tv::check_eq(str("fqdn: ", n), dns::fqdn(n), fq);
    tv::check_eq(str("canonical: ", n), dns::canonical_name(n), canon);
}

fn check_pair(r: tv::Row&) {
    let a, e1 = dns::name_parse(r.next(), []);
    let b, e2 = dns::name_parse(r.next(), []);
    tv::check_int("compare", dns::common_labels(a, b), r.next_int());
    tv::check(str("subdomain ", dns::name_text(a), " ", dns::name_text(b)), dns::is_subdomain(a, b) == (r.next() == "true"));
}

fn check_rev(r: tv::Row&) {
    let a = r.next();
    let want = r.next();
    let v4, ok4 = dns::ip4_parse(a);
    let v6, ok6 = dns::ip6_parse(a);
    if ok4 { tv::check_eq(str("reverse ", a), dns::reverse_addr(v4), want); }
    else { tv::check_eq(str("reverse ", a), dns::reverse_addr(v6), want); }
}

fn check_namelist(r: tv::Row&) {
    let conf = r.next();
    let n = r.next();
    let want = r.next();
    let c = dns::client_config(conf);
    var joined: u8[>..] = [];
    var first = true;
    for l in dns::name_list(c, n) { if !first { joined.push(','); } first = false; joined.append(l); }
    tv::check_eq(str("name list ", n), joined, want);
    tv::check_int("ndots", c.ndots, r.next_int());
    tv::check_int("timeout", c.timeout, r.next_int());
    tv::check_int("attempts", c.attempts, r.next_int());
    var servers: u8[>..] = [];
    first = true;
    for s in c.servers { if !first { servers.push(','); } first = false; servers.append(s); }
    tv::check_eq("servers", servers, r.next());
}

fn check_update(r: tv::Row&) {
    var want: u8[>..] = [];
    unhex(want, r.next());
    let text = r.next();
    var rr1: u8[>..] = [];
    dns::new_rr(rr1, "a.example. 300 IN A 192.0.2.1");
    var rr2: u8[>..] = [];
    dns::new_rr(rr2, "b.example. 300 IN TXT \"x\"");
    var both: u8[>..] = [];
    both.append(rr1);
    both.append(rr2);
    var m = dns::Msg { .. };
    dns::set_update(m, "example.");
    m.hdr.id = 99;
    dns::name_used(m, rr1);
    dns::name_not_used(m, rr2);
    dns::rrset_used(m, rr1);
    dns::rrset_not_used(m, rr2);
    dns::used(m, rr1);
    dns::insert(m, both);
    dns::remove_rrset(m, rr1);
    dns::remove_name(m, rr2);
    dns::remove(m, rr1);
    var got: u8[>..] = [];
    dns::pack(m, got);
    tv::check_eq("update packed", got, want);
    tv::check_eq("update text", dns::msg_string(m), text);
}

fn check_opt(r: tv::Row&) {
    var want: u8[>..] = [];
    unhex(want, r.next());
    let text = r.next();
    var m = dns::Msg { .. };
    dns::set_edns0(m, 4096, true);
    var d: u8[>..] = [];
    dns::subnet_data(d, [192, 0, 2, 129], 22, 0);
    dns::add_option(m, dns::EDNS0_SUBNET, d);
    d.clear();
    dns::subnet_data(d, [0x20, 1, 0xd, 0xb8, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 1], 48, 0);
    dns::add_option(m, dns::EDNS0_SUBNET, d);
    d.clear();
    dns::keepalive_data(d, 150);
    dns::add_option(m, dns::EDNS0_TCP_KEEPALIVE, d);
    d.clear();
    dns::keepalive_data(d, 0);
    dns::add_option(m, dns::EDNS0_TCP_KEEPALIVE, d);
    d.clear();
    dns::ede_data(d, 6, "bad");
    dns::add_option(m, dns::EDNS0_EDE, d);
    dns::add_option(m, dns::EDNS0_PADDING, [0, 0, 0, 0, 0]);
    dns::add_option(m, dns::EDNS0_EXPIRE, [0, 0, 0x0e, 0x10]);
    dns::add_option(m, 65001, [1, 2, 3]);
    tv::check_eq("OPT packed", m.extra, want);
    tv::check_eq("OPT text", dns::rr_string(m.extra, dns::rr_at(m.extra, 0)), text);
    let s, e, found = dns::find_option(m, dns::EDNS0_EDE);
    let ede: u8[5] = [0, 6, 'b', 'a', 'd'];
    tv::check("find EDE", found && m.extra[s..e] == ede);
}

// The vectors' directory: vectors/, or the argument (scripts/differential.py's fresh ones).
fn vectors_dir() -> u8[>..] {
    let a = args();
    return if a.len > 1 { str(a[1]) } else { str("vectors") };
}

fn check_truncate(r: tv::Row&) {
    let size = r.next_int();
    var want: u8[>..] = [];
    unhex(want, r.next());
    var m = dns::Msg { .. };
    dns::set_question(m, "many.example.", dns::TYPE_A);
    m.hdr.id = 7;
    for i in 40 { dns::new_rr(m.answer, str("many.example. 60 IN A 192.0.2.", i)); }
    for i in 5 { dns::new_rr(m.ns, str("example. 60 IN NS ns", i, ".example.")); }
    for i in 5 { dns::new_rr(m.extra, str("ns", i, ".example. 60 IN A 192.0.2.", 100 + i)); }
    dns::set_edns0(m, 1232, false);
    dns::truncate(m, size);
    var got: u8[>..] = [];
    dns::pack(m, got);
    tv::check_eq(str("truncate to ", size), got, want);
}

fn main() {
    tv::each_row(str(vectors_dir(), "/misc.txt")) { r =>
        let kind = r.next();
        if kind == "name" { check_name(r); }
        else if kind == "pair" { check_pair(r); }
        else if kind == "rev" { check_rev(r); }
        else if kind == "namelist" { check_namelist(r); }
        else if kind == "update" { check_update(r); }
        else if kind == "opt" { check_opt(r); }
        else if kind == "truncate" { check_truncate(r); }
    };
    tv::done("misc");
}
