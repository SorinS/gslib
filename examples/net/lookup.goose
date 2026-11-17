// lookup: a host's addresses as the system resolver gives them (the
// hosts file, DNS), each with what kind it is, and the name an address
// has back. For DNS itself, record by record, see examples/dns.
//
//   goose examples/net/lookup.goose -- [name or address...]

import std;
import os;
import gslib from "../..";
import gslib.net;
import gslib.net.ip;

fn kind(a: const net::Addr&) -> const u8[:] {
    if net::is_loopback(a) { return "loopback"; }
    if net::is_private(a) { return "private"; }
    if net::is_link_local_unicast(a) { return "link-local"; }
    if net::is_global_unicast(a) { return "global"; }
    return "other";
}

fn main() {
    let argv = args();
    var names: u8[][>..] = [];
    for i in 1..argv.len { names.push(argv[i]); }
    if names.len == 0 { names.push("localhost"); }
    for name in names {
        let addrs, e = net::lookup_host(name);
        if e < 0 { print(name, ": does not resolve"); continue; }
        for a in addrs {
            let back, be = net::lookup_addr(a);
            let named: u8[>..] = if be == 0 { str(" <- ", back) } else { "" };
            print(name, ": ", a, " (IPv", a.kind, ", ", kind(a), ")", named);
        }
    }
}
