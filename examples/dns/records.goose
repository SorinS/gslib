// records: resource records in their two forms. Text in (new_rr), wire
// bytes held, text out (rr_string), for common types and some with their
// own grammar (TXT escapes, CAA, TLSA, LOC, HTTPS), each read back to the
// same bytes; a record built from wire rdata; an unknown type in RFC
// 3597's \# form; a bad line refused with its reason; and domain names:
// parsing, escapes, labels, subdomains, canonical order, reverse names.
//
//   goose examples/dns/records.goose

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.rdata;
import gslib.dns.msg;
import gslib.dns.zone;

fn main() {
    let lines = [
        "example.com. 300 IN A 192.0.2.1",
        "example.com. 300 IN AAAA 2001:db8::1",
        "www.example.com. 300 IN CNAME example.com.",
        "example.com. 300 IN TXT \"v=spf1 -all\" \"a \\\"quoted\\\" word\"",
        "_sip._tcp.example.com. 300 IN SRV 10 60 5060 sip.example.com.",
        "example.com. 300 IN CAA 0 issue \"ca.example.net\"",
        "_443._tcp.www.example.com. 300 IN TLSA 3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6",
        "example.com. 300 IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
        "example.com. 300 IN HTTPS 1 . alpn=h2,h3 ipv4hint=192.0.2.1",
        "example.com. 300 IN TYPE65280 \\# 4 0A0B0C0D",
    ];
    var rrs: u8[>..] = [];
    for l in lines {
        let r = dns::new_rr_result(rrs, l);
        guard r.err == dns::OK else { print("records: ", l, ": ", r.msg); exit(1); }
    }
    // Each record is its uncompressed wire form, back to back in one list.
    print(dns::rr_count(rrs), " records in ", rrs.len, " bytes:");
    dns::each_rr(rrs) { rr =>
        let text = dns::rr_string(rrs, rr);
        print("  ", text, "    [", rr.end - rr.off, " bytes]");
        // Text out, read in again: the same bytes.
        var again: u8[>..] = [];
        dns::new_rr(again, text);
        guard again[..] == rr.bytes(rrs) else { print("records: no round trip for ", text); exit(1); }
    };

    // A record from wire rdata (an A's 4 bytes), its rdata alone as text.
    let owner, ne = dns::name_parse("host.example.com.", []);
    var made: u8[>..] = [];
    dns::rr_append(made, owner, dns::TYPE_A, dns::CLASS_INET, 60, [198, 51, 100, 7]);
    let m = dns::rr_at(made, 0);
    var rdtext: u8[>..] = [];
    dns::rdata_append(rdtext, m.rtype, m.rdata(made), 0);
    print("built: ", dns::rr_string(made, m), " (rdata \"", rdtext, "\", ", dns::type_string(m.rtype), " ",
          dns::class_string(m.class), ")");
    guard dns::rdata_valid(dns::TYPE_A, [1, 2, 3, 4]) && !dns::rdata_valid(dns::TYPE_A, [1, 2, 3]) else {
        print("records: rdata_valid");
        exit(1);
    }

    // A line that does not parse says why.
    var junk: u8[>..] = [];
    let bad = dns::new_rr_result(junk, "example.com. 300 IN A 192.0.2.300");
    print("refused: ", dns::error_text(bad.err), ": ", bad.msg);
    guard bad.err != dns::OK else { print("records: a bad address accepted"); exit(1); }

    // Names: wire form with escapes, labels, relations, canonical order.
    let n, e = dns::name_parse("a\\.b.Example.COM.", []);
    guard e == dns::OK else { print("records: name_parse"); exit(1); }
    print("\"", dns::name_text(n), "\": ", dns::label_count(n), " labels, ", n.len, " bytes of wire");
    var labels: u8[>..] = [];
    for l in dns::split_domain_name("mail.eu.example.com") { if labels.len > 0 { labels.append("|"); } labels.append(l); }
    print("split: ", labels, " fqdn: ", dns::fqdn("mail.eu.example.com"), " canonical: ", dns::canonical_name("WWW.Example.COM"));
    let parent, pe = dns::name_parse("example.com.", []);
    let child, ce = dns::name_parse("mail.eu.example.com.", []);
    print("subdomain: ", dns::is_subdomain(parent, child), ", common labels: ", dns::common_labels(parent, child));
    guard dns::is_subdomain(parent, child) && !dns::is_subdomain(child, parent) else { print("records: is_subdomain"); exit(1); }
    let za, zae = dns::name_parse("z.example.com.", []);
    let ya, yae = dns::name_parse("yy.a.example.com.", []);
    print("canonical order (RFC 4034 6.1): yy.a.example.com. ", if dns::name_compare(ya, za) < 0 { "<" } else { ">" }, " z.example.com.");
    let v4, ok4 = dns::ip4_parse("192.0.2.25");
    let v6, ok6 = dns::ip6_parse("2001:db8::567:89ab");
    print("reverse: ", dns::reverse_addr(v4));
    print("reverse: ", dns::reverse_addr(v6));
    guard dns::reverse_addr(v4) == "25.2.0.192.in-addr.arpa." else { print("records: reverse_addr"); exit(1); }
}
