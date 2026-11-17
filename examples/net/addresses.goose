// addresses: IP addresses without the network: parsed and printed the
// canonical way (RFC 5952), classified, with ports, and checked against
// prefixes, as an allow list would be.
//
//   goose examples/net/addresses.goose

import std;
import gslib from "../..";
import gslib.net.ip;

fn main() {
    for text in ["192.0.2.10", "2001:DB8:0:0:0:0:0:1", "::ffff:10.0.0.1", "fe80::1%eth0", "300.1.1.1"] {
        let a, ok = net::parse_addr(text);
        if !ok { print(text, ": not an address"); continue; }
        print(text, " -> ", a, "  private=", net::is_private(a), " loopback=", net::is_loopback(a),
              " link-local=", net::is_link_local_unicast(a));
    }

    let ap, ok = net::parse_addr_port("[2001:db8::1]:8443");
    print("address ", ap.addr, " port ", ap.port, " -> ", ap);
    let host, port, oks = net::split_host_port("example.com:443");
    print("split: ", host, " and ", port, "; joined: ", net::join_host_port("2001:db8::1", "443"));

    // An allow list of networks.
    var allow: net::Prefix[>..] = [];
    for p in ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"] {
        let pre, okp = net::parse_prefix(p);
        allow.push(pre);
    }
    for text in ["10.20.30.40", "192.169.0.1", "2001:db8:1::5", "2001:db9::5"] {
        let a, oka = net::parse_addr(text);
        var allowed = false;
        for pre in allow { if net::prefix_contains(pre, a) { allowed = true; } }
        print(text, if allowed { " allowed" } else { " refused" });
    }
}
