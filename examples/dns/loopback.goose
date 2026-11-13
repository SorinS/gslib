// loopback: a DNS server and its client in one program, over UDP on
// 127.0.0.1. The server (dns.server) listens on a port the OS picks and
// answers from example.zone in its handler block: the records asked for,
// a CNAME, NXDOMAIN with the SOA. It also has a TSIG key, so it checks a
// signed query and signs its reply itself. The client packs each query
// (signed when its Client has the key), sends it, and checks the reply.
//
//   goose examples/dns/loopback.goose
//
// dns::serve handles one request at a time from its own loop, and Goose
// threads need a native build, so under the JIT client and server take
// turns here: the query is sent first (it waits in the socket), serve
// handles one request, then the client reads the reply. That is why this
// uses the client module's parts (pack_query, the dnsnet sockets,
// check_reply_tsig) rather than exchange, which would wait for a reply
// no one is there to send. query.goose and serve.goose are the two halves
// as separate programs.

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;
import gslib.dns.tsig;
import gslib.dns.client;
import gslib.dns.server;

let KEY_NAME = "loopback.example.com.";
let SECRET = "bG9vcGJhY2sgZXhhbXBsZSBzZWNyZXQ=";

fn main() {
    var text: u8[>..] = [];
    guard read_file(str(resource_dir(), "example.zone"), text) else { print("loopback: no example.zone beside this file"); exit(1); }
    var opts = dns::ZoneOptions { .. };
    let origin, oe = dns::name_parse("example.com.", []);
    opts.origin = origin;
    var zone: u8[>..] = [];
    let zr = dns::parse_zone(text, opts, zone);
    guard zr.err == dns::OK else { print("loopback: example.zone:", zr.line, ": ", zr.msg); exit(1); }

    var cfg = dns::ServerConfig { .. };
    cfg.addr.append("127.0.0.1");
    cfg.port = 0;                        // any free port
    cfg.tcp = false;
    cfg.max_requests = 1;                // serve returns after each request
    cfg.tsig_name.append(KEY_NAME);
    cfg.tsig_secret.append(SECRET);
    var srv = dns::server_open(cfg);
    guard srv.err == dns::OK else { print("loopback: cannot listen: ", dns::error_text(srv.err)); exit(1); }
    print("server on 127.0.0.1:", srv.port);

    let names = ["www.example.com.", "ftp.example.com.", "mail.example.com.", "nope.example.com.", "www.example.com."];
    let types = [dns::TYPE_A, dns::TYPE_A, dns::TYPE_AAAA, dns::TYPE_A, dns::TYPE_A];
    let signed = [false, false, false, false, true];
    let want = [2, 3, 1, 0, 2];
    for i in names.len {
        var c = dns::Client { .. };
        if signed[i] { c.tsig_name.append(KEY_NAME); c.tsig_secret.append(SECRET); }
        var q = dns::Msg { .. };
        dns::set_question(q, names[i], types[i]);
        dns::set_edns0(q, 1232, false);
        var w: u8[>..] = [];
        let mac, pe = dns::pack_query(c, q, w);
        guard pe == dns::OK else { print("loopback: pack: ", dns::error_text(pe)); exit(1); }
        let fd = dns::dnsnet_udp_open("127.0.0.1", srv.port);
        guard fd >= 0 && dns::dnsnet_send(fd, w) == w.len else { print("loopback: cannot send"); exit(1); }

        // The server's turn: one request, answered from the zone.
        var seen_tsig = false;
        dns::serve(srv, cfg) { req, resp, peer =>
            seen_tsig = peer.tsig == dns::OK;
            resp.hdr.authoritative = true;
            dns::each_question(req.question) { qq =>
                var qname = dns::name_lower(qq.name(req.question));
                // A CNAME is answered, and followed within the zone.
                dns::each_rr(zone) { rr =>
                    if dns::name_equal(rr.name(zone), qname) && rr.rtype == dns::TYPE_CNAME {
                        dns::rr_copy(resp.answer, zone, rr);
                        qname = dns::name_lower(rr.rdata(zone));
                    }
                };
                var any = false;
                dns::each_rr(zone) { rr =>
                    if dns::name_equal(rr.name(zone), qname) {
                        any = true;
                        if rr.rtype == qq.qtype { dns::rr_copy(resp.answer, zone, rr); }
                    }
                };
                if !any && resp.answer.len == 0 {
                    resp.hdr.rcode = dns::RCODE_NAME_ERROR;
                    dns::each_rr(zone) { rr => if rr.rtype == dns::TYPE_SOA { dns::rr_copy(resp.ns, zone, rr); } };
                }
            };
        };

        // The client's turn: the reply, matched to the query and checked.
        var buf: u8[>..] = [];
        buf.resize(1232, 0);
        let n = dns::dnsnet_recv(fd, buf, 2000);
        dns::dnsnet_close(fd);
        guard n > 0 && dns::reply_matches(w, buf[..n]) else { print("loopback: no reply"); exit(1); }
        let raw = buf[..n];
        let rmac, te = dns::check_reply_tsig(c, raw, mac, false);
        guard te == dns::OK else { print("loopback: reply TSIG: ", dns::error_text(te)); exit(1); }
        var r = dns::Msg { .. };
        guard dns::unpack(raw, r) == dns::OK else { print("loopback: unpack"); exit(1); }
        print(names[i], " ", dns::type_string(types[i]), if signed[i] { " (TSIG)" } else { "" }, ": ",
              dns::rcode_name(r.hdr.rcode), ", ", dns::rr_count(r.answer), " answers");
        dns::each_rr(r.answer) { rr => print("  ", dns::rr_string(r.answer, rr)); };
        dns::each_rr(r.ns) { rr => print("  ; ", dns::rr_string(r.ns, rr)); };
        guard dns::rr_count(r.answer) == want[i] && seen_tsig == signed[i] else { print("loopback: wrong answer"); exit(1); }
    }
    dns::server_close(srv);
}
