// needs: dnsd
// dns.client against goose-dnsd (tools/dnsd.goose) serving
// vectors/zones/served.zone, which scripts/run_tests.py starts on a free
// port and passes as the argument: queries over UDP and TCP, CNAME
// chains, NXDOMAIN and NODATA with the SOA, wildcards, referrals with
// glue, a truncated UDP reply asked again over TCP, a zone transfer in
// several messages signed with TSIG (refused unsigned), a dynamic update
// signed with TSIG and seen by the next query, a query signed with the
// wrong key answered NOTAUTH, NOTIFY, and DO bringing RRSIGs.
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;
import gslib.dns.client;
import gslib.dns.update;
import gslib.dns.tsig;
import tv;

let SECRET = "c2VjcmV0IGtleSBmb3IgdGVzdGluZyBUU0lHIDEyMzQ1Ng==";

fn ask(server: const u8[:], net: u8, qname: const u8[:], qtype: u16, r: dns::Msg&) -> i64 {
    var c = dns::Client { .. };
    c.net = net;
    var m = dns::Msg { .. };
    dns::set_question(m, qname, qtype);
    dns::set_edns0(m, 1232, false);
    return dns::exchange(c, m, server, r);
}

fn texts(list: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    dns::each_rr(list) { rr => if rr.rtype != dns::TYPE_OPT { out.append(dns::rr_string(list, rr)); out.push('\n'); } };
    return out;
}

fn main() {
    let a = args();
    if a.len < 2 { abort("usage: client <port>"); }
    let server = str("127.0.0.1:", a[1]);
    var r = dns::Msg { .. };

    for net in [dns::NET_UDP, dns::NET_TCP] {
        let what = if net == dns::NET_UDP { "udp" } else { "tcp" };
        let e = ask(server, net, "ns1.example.org.", dns::TYPE_A, r);
        tv::check_int(str("A over ", what), e, dns::OK);
        tv::check_eq(str("A answer ", what), texts(r.answer), "ns1.example.org.\t3600\tIN\tA\t192.0.2.1\n");
        tv::check(str("aa ", what), r.hdr.authoritative && r.hdr.response);
    }
    ask(server, dns::NET_UDP, "alias.example.org.", dns::TYPE_A, r);
    tv::check_eq("CNAME chain", texts(r.answer),
        "alias.example.org.\t3600\tIN\tCNAME\twww.example.org.\nwww.example.org.\t3600\tIN\tCNAME\tweb.example.org.\nweb.example.org.\t3600\tIN\tCNAME\thost.example.net.\n");
    ask(server, dns::NET_UDP, "nope.example.org.", dns::TYPE_A, r);
    tv::check_int("NXDOMAIN", r.hdr.rcode, dns::RCODE_NAME_ERROR);
    tv::check_eq("NXDOMAIN SOA", texts(r.ns), "example.org.\t300\tIN\tSOA\tns1.example.org. hostmaster.example.org. 2024010101 7200 3600 1209600 300\n");
    ask(server, dns::NET_UDP, "b.c.example.org.", dns::TYPE_A, r);
    tv::check("empty non-terminal: NODATA", r.hdr.rcode == dns::RCODE_SUCCESS && r.answer.len == 0 && dns::rr_count(r.ns) == 1);
    ask(server, dns::NET_UDP, "mail.example.org.", dns::TYPE_TXT, r);
    tv::check("NODATA", r.hdr.rcode == dns::RCODE_SUCCESS && r.answer.len == 0 && dns::rr_count(r.ns) == 1);
    ask(server, dns::NET_UDP, "x.y.wild.example.org.", dns::TYPE_TXT, r);
    tv::check_eq("wildcard", texts(r.answer), "x.y.wild.example.org.\t3600\tIN\tTXT\t\"wildcard\"\n");
    ask(server, dns::NET_UDP, "host.sub.example.org.", dns::TYPE_A, r);
    tv::check("referral: not authoritative", !r.hdr.authoritative && r.answer.len == 0);
    tv::check_eq("referral NS", texts(r.ns), "sub.example.org.\t3600\tIN\tNS\tns.sub.example.org.\n");
    tv::check_eq("referral glue", texts(r.extra), "ns.sub.example.org.\t3600\tIN\tA\t192.0.2.4\n");
    ask(server, dns::NET_UDP, "example.org.", dns::TYPE_MX, r);
    tv::check("MX target's address added", texts(r.extra) == "mail.example.org.\t3600\tIN\tA\t192.0.2.2\nmail.example.org.\t3600\tIN\tAAAA\t2001:db8::2\n");
    ask(server, dns::NET_UDP, "www.example.com.", dns::TYPE_A, r);
    tv::check_int("not ours: REFUSED", r.hdr.rcode, dns::RCODE_REFUSED);

    // Truncation: 600 bytes of TXT in 512 bytes, then TCP.
    var c = dns::Client { .. };
    var m = dns::Msg { .. };
    dns::set_question(m, "big.example.org.", dns::TYPE_TXT);
    tv::check_int("big over UDP", dns::exchange(c, m, server, r), dns::OK);
    tv::check("truncated", r.hdr.truncated);
    c.tcp_fallback = true;
    tv::check_int("big again", dns::exchange(c, m, server, r), dns::OK);
    tv::check("TCP fallback: all six", !r.hdr.truncated && dns::rr_count(r.answer) == 6);

    // DO: the RRSIG with the SOA.
    var m2 = dns::Msg { .. };
    dns::set_question(m2, "example.org.", dns::TYPE_SOA);
    dns::set_edns0(m2, 1232, true);
    var c2 = dns::Client { .. };
    dns::exchange(c2, m2, server, r);
    tv::check_int("DO: SOA and RRSIG", dns::rr_count(r.answer), 2);

    // AXFR: refused unsigned, then signed: 5024 records in several messages.
    var x = dns::Msg { .. };
    dns::set_question(x, "example.org.", dns::TYPE_AXFR);
    var cx = dns::Client { .. };
    var records = 0;
    let e0 = dns::transfer_in(cx, x, server) { msg => records += dns::rr_count(msg.answer); };
    tv::check_int("AXFR unsigned refused", e0, dns::ERR_XFR);
    cx.tsig_name.append("xfr.example.");
    cx.tsig_secret.append(SECRET);
    var messages = 0;
    records = 0;
    let e1 = dns::transfer_in(cx, x, server) { msg => records += dns::rr_count(msg.answer); messages++; };
    tv::check_int("AXFR signed", e1, dns::OK);
    tv::check_int("AXFR records", records, 5024);
    tv::check(str("AXFR in several messages: ", messages), messages > 1);

    // A dynamic update, signed: a new A record, then the query sees it.
    var u = dns::Msg { .. };
    dns::set_update(u, "example.org.");
    var add: u8[>..] = [];
    dns::new_rr(add, "new.example.org. 300 IN A 203.0.113.9");
    dns::insert(u, add);
    var gone: u8[>..] = [];
    dns::new_rr(gone, "mail.example.org. 0 IN AAAA ::");
    dns::remove_rrset(u, gone);
    tv::check_int("update", dns::exchange(cx, u, server, r), dns::OK);
    tv::check_int("update rcode", r.hdr.rcode, dns::RCODE_SUCCESS);
    ask(server, dns::NET_UDP, "new.example.org.", dns::TYPE_A, r);
    tv::check_eq("updated", texts(r.answer), "new.example.org.\t300\tIN\tA\t203.0.113.9\n");
    ask(server, dns::NET_UDP, "mail.example.org.", dns::TYPE_AAAA, r);
    tv::check("RRset removed", r.answer.len == 0 && r.hdr.rcode == dns::RCODE_SUCCESS);
    // A prerequisite that fails: the name must not exist, but it does.
    var u2 = dns::Msg { .. };
    dns::set_update(u2, "example.org.");
    dns::name_not_used(u2, add);
    dns::insert(u2, add);
    dns::exchange(cx, u2, server, r);
    tv::check_int("prerequisite YXDOMAIN", r.hdr.rcode, dns::RCODE_YXDOMAIN);
    // Unsigned updates are refused.
    tv::check_int("unsigned update", dns::exchange(c2, u, server, r), dns::OK);
    tv::check_int("unsigned update refused", r.hdr.rcode, dns::RCODE_REFUSED);

    // A query signed with the wrong secret: NOTAUTH, which the client refuses.
    var cw = dns::Client { .. };
    cw.tsig_name.append("xfr.example.");
    cw.tsig_secret.append("d3Jvbmcgc2VjcmV0");
    var q = dns::Msg { .. };
    dns::set_question(q, "ns1.example.org.", dns::TYPE_A);
    tv::check_int("wrong TSIG secret", dns::exchange(cw, q, server, r), dns::ERR_AUTH);
    // A query signed with the right one: answered, the reply verified.
    tv::check_int("signed query", dns::exchange(cx, q, server, r), dns::OK);

    // NOTIFY: acknowledged.
    var n = dns::Msg { .. };
    dns::set_question(n, "example.org.", dns::TYPE_SOA);
    n.hdr.opcode = dns::OPCODE_NOTIFY;
    n.hdr.recursion_desired = false;
    dns::exchange(c2, n, server, r);
    tv::check("NOTIFY acknowledged", r.hdr.opcode == dns::OPCODE_NOTIFY && r.hdr.authoritative && r.hdr.rcode == 0);
    tv::done("client");
}
