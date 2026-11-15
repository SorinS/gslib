// serve: an authoritative server for one zone file, the server side of
// query.goose: dns.server listening on UDP and TCP, the handler a block
// that answers from the zone. The records of the name and type asked for,
// a CNAME and what it points to, wildcards (*.dev.example.com), NXDOMAIN
// and NODATA with the SOA, and AXFR (over TCP, split into messages by the
// server when the zone is large). tools/dnsd.goose is the full version.
//
//   goose examples/dns/serve.goose -- [-p PORT] [-n REQUESTS] [FILE [ORIGIN]]
//
// It listens on 127.0.0.1, port 5353 unless -p (0: any free one), and
// stops after -n requests (never, without). It waits for clients, so it
// is not run as a test; try `goose query.goose -- @127.0.0.1:5353 www.example.com`.

import std;
import os;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.server;

// The records of name in the zone of the given type (every type for ANY)
// onto out, under the owner as_owner (for a wildcard's).
fn copy_set(zone: const u8[:], name: const u8[:], t: u16, as_owner: const u8[:], out: u8[>..]&) -> i64 {
    var n = 0;
    dns::each_rr(zone) { rr =>
        if dns::name_equal(rr.name(zone), name) && (rr.rtype == t || t == dns::TYPE_ANY) {
            dns::rr_append(out, as_owner, rr.rtype, rr.class, rr.ttl, rr.rdata(zone));
            n++;
        }
    };
    return n;
}

fn has_name(zone: const u8[:], name: const u8[:]) -> bool {
    var found = false;
    dns::each_rr(zone) { rr => if dns::name_equal(rr.name(zone), name) { found = true; } };
    return found;
}

// The answer to qname and qtype from the zone, into resp.
fn answer(zone: const u8[:], origin: const u8[:], qname: const u8[:], qtype: u16, resp: dns::Msg&) {
    // The name itself, or else the wildcard that covers it.
    var owner: dns::Name = [];
    owner.append(qname);
    if !has_name(zone, owner) {
        let wild = dns::wildcard_of(qname);
        if has_name(zone, wild) { owner = wild; }
    }
    var n = copy_set(zone, owner, qtype, qname, resp.answer);
    if n == 0 && qtype != dns::TYPE_CNAME && copy_set(zone, owner, dns::TYPE_CNAME, qname, resp.answer) > 0 {
        // A CNAME, and its target's records when they are in the zone.
        let target = dns::name_lower(dns::rdata(dns::rr_at(resp.answer, 0), resp.answer));
        n = 1 + copy_set(zone, target, qtype, target, resp.answer);
    }
    if n == 0 {
        // NODATA when the name exists, NXDOMAIN when not; the SOA says for how long.
        if !has_name(zone, owner) { resp.hdr.rcode = dns::RCODE_NAME_ERROR; }
        copy_set(zone, origin, dns::TYPE_SOA, origin, resp.ns);
    }
}

fn main() {
    let a = args();
    var port:         i64     = 5353;
    var max_requests: i64     = 0;
    var path:         u8[>..] = str(resource_dir(), "example.zone");
    var origin_text:  u8[>..] = "example.com.";
    var files = 0;
    var i = 1;
    while i < a.len {
        if (a[i] == "-p" || a[i] == "-n") && i + 1 < a.len {
            let v, ok = parse_int(a[i + 1]);
            guard ok && v >= 0 else { print("serve: bad number ", a[i + 1]); exit(2); }
            if a[i] == "-p" { port = v; } else { max_requests = v; }
            i += 2;
            continue;
        }
        if files == 0 { path.clear(); path.append(a[i]); } else { origin_text.clear(); origin_text.append(a[i]); }
        files++;
        i++;
    }

    var text: u8[>..] = [];
    guard read_file(path, text) else { print("serve: cannot read ", path); exit(1); }
    var opts = dns::ZoneOptions { .. };
    let origin, oe = dns::name_parse(origin_text, []);
    guard oe == dns::OK else { print("serve: bad origin ", origin_text); exit(2); }
    opts.origin = origin;
    opts.file.append(path);
    var zone: u8[>..] = [];
    let zr = dns::parse_zone(text, opts, zone);
    guard zr.err == dns::OK else { print(path, ":", zr.line, ": ", zr.msg); exit(1); }

    var cfg = dns::ServerConfig { .. };
    cfg.addr.append("127.0.0.1");
    cfg.port = port as! i32;
    cfg.max_requests = max_requests;
    // The limits, at their defaults: no UDP reply over 1232 bytes, whatever
    // the client's EDNS0 says (a forged query draws no large reply); 8 s for
    // each query on a TCP connection, all of its bytes, and 128 of them on
    // one connection, so a slow client holds up only itself.
    cfg.max_udp_size = 1232;
    cfg.idle_ms = 8000;
    cfg.tcp_queries = 128;
    var srv = dns::server_open(cfg);
    guard srv.err == dns::OK else { print("serve: cannot listen on port ", port); exit(1); }
    print("serving ", dns::name_text(origin), " (", dns::rr_count(zone), " records) on 127.0.0.1:", srv.port);

    // The handler: resp is already a reply to req (set_reply). A `return`
    // in it would return from main, ending the server, so it has none.
    dns::serve(srv, cfg) { req, resp, peer =>
        resp.hdr.authoritative = true;
        dns::each_question(req.question) { q =>
            let qname = dns::name_lower(q.name(req.question));
            print(if peer.tcp { "tcp " } else { "udp " }, peer.addr, " ", dns::name_text(qname), " ", dns::type_string(q.qtype));
            if !dns::is_subdomain(origin, qname) || (q.qtype == dns::TYPE_AXFR && !peer.tcp) {
                resp.hdr.rcode = dns::RCODE_REFUSED;
                resp.hdr.authoritative = false;
            } else if q.qtype == dns::TYPE_AXFR {
                // The zone between two copies of its SOA.
                copy_set(zone, origin, dns::TYPE_SOA, origin, resp.answer);
                dns::each_rr(zone) { rr => if rr.rtype != dns::TYPE_SOA { dns::rr_copy(resp.answer, zone, rr); } };
                copy_set(zone, origin, dns::TYPE_SOA, origin, resp.answer);
            } else {
                answer(zone, origin, qname, q.qtype, resp);
            }
        };
    };
    dns::server_close(srv);
}
