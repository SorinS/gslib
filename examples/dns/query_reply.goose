// query_reply: a DNS exchange in memory, as client and server see it: a
// query built (question, RD, EDNS0) and packed to its wire bytes; those
// unpacked on the other side, and a reply made with set_reply and filled
// in; the reply packed with name compression, unpacked, printed as dig
// prints it, and its answers read record by record; then cut to fit 512
// bytes, as a UDP reply must be.
//
//   goose examples/dns/query_reply.goose

import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;

fn check(what: const u8[:], e: i64) {
    guard e == dns::OK else { print("query_reply: ", what, ": ", dns::error_text(e)); exit(1); }
}

fn main() {
    // The client's query: www.example.com MX, with EDNS0 (a 1232-byte
    // buffer, DNSSEC records wanted).
    var q = dns::Msg { .. };
    check("set_question", dns::set_question(q, "www.example.com.", dns::TYPE_MX));
    dns::set_edns0(q, 1232, true);
    var wire: u8[>..] = [];
    check("pack", dns::pack(q, wire));
    print("query: ", wire.len, " bytes, id ", q.hdr.id);

    // The server: the bytes back into a message, and a reply to it.
    var req = dns::Msg { .. };
    check("unpack", dns::unpack(wire, req));
    var question: u8[>..] = [];
    dns::each_question(req.question) { qq =>
        question.append(dns::name_text(qq.name(req.question)));
        question.append(" ");
        question.append(dns::type_string(qq.qtype));
    };
    print("server got: ", question, ", udp size ", dns::udp_size(req));

    var resp = dns::Msg { .. };
    dns::set_reply(resp, req);
    resp.hdr.authoritative = true;
    for pref in [10, 20, 30] {
        check("new_rr", dns::new_rr(resp.answer, str("www.example.com. 3600 IN MX ", pref, " mx", pref / 10, ".example.com.")));
    }
    dns::new_rr(resp.ns, "example.com. 3600 IN NS ns1.example.com.");
    for i in 3 { dns::new_rr(resp.extra, str("mx", i + 1, ".example.com. 3600 IN A 192.0.2.", 10 + i)); }
    dns::set_edns0(resp, 1232, false);
    // Compression points repeated names at their first copy.
    resp.compress = false;
    var plain: u8[>..] = [];
    dns::pack(resp, plain);
    resp.compress = true;
    var packed: u8[>..] = [];
    check("pack reply", dns::pack(resp, packed));
    print("reply: ", plain.len, " bytes, ", packed.len, " compressed");

    // The client: the reply unpacked and checked against the query.
    var r = dns::Msg { .. };
    check("unpack reply", dns::unpack(packed, r));
    guard r.hdr.response && r.hdr.id == q.hdr.id && r.hdr.rcode == dns::RCODE_SUCCESS else {
        print("query_reply: the reply does not answer the query");
        exit(1);
    }
    print();
    print(dns::msg_string(r));
    var mx = 0;
    dns::each_rr(r.answer) { rr =>
        if rr.rtype == dns::TYPE_MX {
            // MX rdata: a 2-byte preference, then the exchange's name.
            let rd = rr.rdata(r.answer);
            print("MX ", dns::get16(rd, 0), " -> ", dns::name_text(rd[2..]), " (TTL ", rr.ttl, ")");
            mx++;
        }
    };
    guard mx == 3 && dns::rr_count(r.extra) == 4 else { print("query_reply: records lost"); exit(1); }

    // A big reply cut for a client without EDNS0: answers kept as far as
    // they fit, the TC bit set so it asks again over TCP.
    var big = dns::Msg { .. };
    dns::set_reply(big, req);
    for i in 60 { dns::new_rr(big.answer, str("www.example.com. 60 IN TXT \"record number ", i, "\"")); }
    dns::truncate(big, 512);
    var cut: u8[>..] = [];
    dns::pack(big, cut);
    print("60 TXT records cut to ", dns::rr_count(big.answer), " in ", cut.len, " bytes, truncated: ", big.hdr.truncated);
    guard cut.len <= 512 && big.hdr.truncated else { print("query_reply: truncate"); exit(1); }
}
