// query: the client side, against a real server: a query for a name and
// type (A unless given) over UDP, asked again over TCP if the reply comes
// back truncated, printed as dig prints it; AXFR transfers the zone over
// TCP, message by message. Without @server it asks the first nameserver
// of /etc/resolv.conf, and shows the names its search list would try.
//
//   goose examples/dns/query.goose -- [@SERVER[:PORT]] NAME [TYPE] [+tcp]
//
// e.g. against serve.goose: `-- @127.0.0.1:5353 www.example.com` or
// `-- @127.0.0.1:5353 example.com AXFR`. It needs a server, so it is not
// run as a test.

import std;
import os;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;
import gslib.dns.client;

fn main() {
    let a = args();
    var server: u8[>..] = [];
    var name:   u8[>..] = [];
    var qtype:  i64     = dns::TYPE_A;
    var c = dns::Client { .. };
    c.tcp_fallback = true;
    for i in 1..a.len {
        let s = a[i];
        if s.len > 1 && s[0] == '@' { server.append(s[1..]); }
        else if s == "+tcp" { c.net = dns::NET_TCP; }
        else if name.len == 0 { name.append(s); }
        else if dns::type_from_string(s) >= 0 { qtype = dns::type_from_string(s); }
        else { print("query: unknown type ", s); exit(2); }
    }
    guard name.len > 0 else { print("usage: query [@SERVER[:PORT]] NAME [TYPE] [+tcp]"); exit(2); }

    // No server given: resolv.conf's, and its search list for a short name.
    if server.len == 0 {
        let cfg, ok = dns::client_config_file("/etc/resolv.conf");
        guard ok && cfg.servers.len > 0 else { print("query: no @SERVER and no nameserver in /etc/resolv.conf"); exit(2); }
        server.append(cfg.servers[0]);
        var tries: u8[>..] = [];
        for n in dns::name_list(cfg, name) { tries.append(" "); tries.append(n); }
        print(";; resolv.conf: server ", server, ", ndots ", cfg.ndots, ", names to try:", tries);
    }
    let fq = dns::fqdn(name);

    var m = dns::Msg { .. };
    let e = dns::set_question(m, fq, qtype as! u16);
    guard e == dns::OK else { print("query: bad name ", name, ": ", dns::error_text(e)); exit(2); }

    // A zone transfer: each message as it arrives.
    if qtype == dns::TYPE_AXFR {
        m.hdr.recursion_desired = false;
        var count = 0;
        let te = dns::transfer_in(c, m, server) { r =>
            dns::each_rr(r.answer) { rr => print(dns::rr_string(r.answer, rr)); count++; };
        };
        guard te == dns::OK else { print("query: transfer: ", dns::error_text(te)); exit(1); }
        print(";; ", count, " records from ", server);
        return;
    }

    dns::set_edns0(m, 1232, false);
    var r = dns::Msg { .. };
    let t0 = clock_ns();
    let xe = dns::exchange(c, m, server, r);
    guard xe == dns::OK else { print("query: ", dns::error_text(xe), " (", server, ")"); exit(1); }
    print(dns::msg_string(r));
    print(";; Query time: ", (clock_ns() - t0) / 1000000, " msec");
    print(";; SERVER: ", server);
}
